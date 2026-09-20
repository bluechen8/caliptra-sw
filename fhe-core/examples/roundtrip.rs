// Licensed under the Apache-2.0 license

//! Host driver for the WP1 round trip: Rust-encrypt -> Lattigo-eval -> Rust-decrypt.
//!
//! This is the same `fhe-core` code the firmware runs, exercised on the host
//! so the pipeline can be validated before any of it is on Caliptra.  The
//! floating-point halves of the flow -- CKKS encode before, decode after --
//! stay where plan §2.1 puts them: on the user's machine, in
//! `caliptra-wrapper/software/fhe/roundtrip.py`, which drives this binary.
//!
//! Usage:
//!   roundtrip encrypt <set> <seed_hex> <in_dir> <out_dir>
//!       reads  <in_dir>/pt_NNN.bin   (L*N u32, coefficient domain, per pixel)
//!       writes <out_dir>/ct_NNN.bin  (2*L*N u32, plan §4.1 layout)
//!   roundtrip decrypt <set> <seed_hex> <dir>
//!       reads  <dir>/res_K.bin, writes <dir>/dec_K.bin (L*N u32)
//!
//! The secret key is regenerated from `seed_hex` on both sides, exactly as the
//! firmware regenerates it from its stored packed secret.

use std::env;
use std::fs;
use std::path::Path;
use std::process::exit;

use caliptra_fhe_core::format;
use caliptra_fhe_core::ntt::{gen_twiddles_fwd, gen_twiddles_inv, twiddle_words};
use caliptra_fhe_core::params::{self, ParamSet};
use caliptra_fhe_core::prg::ChaCha20Prg;
use caliptra_fhe_core::rlwe::{decrypt_limb, encrypt_limb, keygen, secret_ntt_limb};
use caliptra_fhe_core::sample::{packed_secret_bytes, sample_cbd, sample_uniform};

fn die(msg: &str) -> ! {
    eprintln!("roundtrip: {msg}");
    exit(2)
}

fn read_u32(path: &Path, want: usize) -> Vec<u32> {
    let raw = fs::read(path).unwrap_or_else(|e| die(&format!("{}: {e}", path.display())));
    if raw.len() != want * 4 {
        die(&format!(
            "{}: expected {} bytes, got {}",
            path.display(),
            want * 4,
            raw.len()
        ));
    }
    raw.chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

fn write_u32(path: &Path, words: &[u32]) {
    let mut raw = vec![0u8; words.len() * 4];
    format::le_from_words(words, &mut raw).unwrap();
    fs::write(path, raw).unwrap_or_else(|e| die(&format!("{}: {e}", path.display())));
}

fn parse_seed(hex: &str) -> [u8; 32] {
    if hex.len() != 64 {
        die("seed must be 64 hex characters");
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
            .unwrap_or_else(|_| die("seed is not hex"));
    }
    out
}

/// Tables for every limb, built once: the host has memory to spare, the
/// firmware will decide per WP3 whether to keep them in ICCM `.rodata`.
struct Ctx {
    ps: &'static ParamSet,
    packed: Vec<u8>,
    fwd: Vec<Vec<u32>>,
    inv: Vec<Vec<u32>>,
    s_ntt: Vec<Vec<u32>>,
}

impl Ctx {
    fn new(set: &str, seed: &[u8; 32]) -> Self {
        let ps = params::by_name(set).unwrap_or_else(|| die("unknown parameter set"));
        let mut prg = ChaCha20Prg::new(seed);
        let mut packed = vec![0u8; packed_secret_bytes(ps.n)];
        keygen(&mut prg, ps.n, &mut packed).unwrap();

        let mut fwd = Vec::with_capacity(ps.level);
        let mut inv = Vec::with_capacity(ps.level);
        let mut s_ntt = Vec::with_capacity(ps.level);
        for p in ps.primes {
            let mut f = vec![0u32; twiddle_words(ps.n)];
            let mut i = vec![0u32; twiddle_words(ps.n)];
            gen_twiddles_fwd(ps.n, p, &mut f).unwrap();
            gen_twiddles_inv(ps.n, p, &mut i).unwrap();
            let mut s = vec![0u32; ps.n];
            secret_ntt_limb(&packed, p, &f, &mut s).unwrap();
            fwd.push(f);
            inv.push(i);
            s_ntt.push(s);
        }
        Ctx {
            ps,
            packed,
            fwd,
            inv,
            s_ntt,
        }
    }
}

fn cmd_encrypt(set: &str, seed_hex: &str, indir: &Path, outdir: &Path, npix: usize) {
    let seed = parse_seed(seed_hex);
    let ctx = Ctx::new(set, &seed);
    let ps = ctx.ps;
    // The PRG continues past keygen, matching the firmware's stream order:
    // per ciphertext, e once then a once per limb.
    let mut prg = ChaCha20Prg::new(&seed);
    let mut scratch = vec![0u8; packed_secret_bytes(ps.n)];
    keygen(&mut prg, ps.n, &mut scratch).unwrap();

    fs::create_dir_all(outdir).unwrap_or_else(|e| die(&format!("{}: {e}", outdir.display())));
    let mut e = vec![0i8; ps.n];
    let mut a = vec![0u32; ps.n];
    let mut ct = vec![0u32; ps.ct_words()];
    let mut c0 = vec![0u32; ps.n];
    let mut c1 = vec![0u32; ps.n];

    for i in 0..npix {
        let pt = read_u32(&indir.join(format!("pt_{i:03}.bin")), ps.pt_words());
        sample_cbd(&mut prg, &mut e);
        for li in 0..ps.level {
            let p = &ps.primes[li];
            sample_uniform(&mut prg, p.q, &mut a);
            encrypt_limb(
                &pt[li * ps.n..(li + 1) * ps.n],
                &e,
                &a,
                &ctx.s_ntt[li],
                p,
                &ctx.fwd[li],
                &mut c0,
                &mut c1,
            )
            .unwrap_or_else(|err| die(&format!("encrypt_limb: {err:?}")));
            let o0 = format::c0_limb_off(ps, li);
            let o1 = format::c1_limb_off(ps, li);
            ct[o0..o0 + ps.n].copy_from_slice(&c0);
            ct[o1..o1 + ps.n].copy_from_slice(&c1);
        }
        write_u32(&outdir.join(format!("ct_{i:03}.bin")), &ct);
    }
    // plan §9: erase every key and plaintext-derived buffer before returning
    caliptra_fhe_core::zeroize_i8(&mut e);
    caliptra_fhe_core::zeroize_u32(&mut c0);
    caliptra_fhe_core::zeroize_u32(&mut c1);
    caliptra_fhe_core::zeroize_u8(&mut scratch);
    println!(
        "[roundtrip] encrypted {npix} ciphertexts at {} -> {}",
        set,
        outdir.display()
    );
}

fn cmd_decrypt(set: &str, seed_hex: &str, dir: &Path, nclass: usize) {
    let seed = parse_seed(seed_hex);
    let mut ctx = Ctx::new(set, &seed);
    let ps = ctx.ps;
    let mut out = vec![0u32; ps.pt_words()];
    for k in 0..nclass {
        let ct = read_u32(&dir.join(format!("res_{k}.bin")), ps.ct_words());
        for li in 0..ps.level {
            let o0 = format::c0_limb_off(ps, li);
            let o1 = format::c1_limb_off(ps, li);
            decrypt_limb(
                &ct[o0..o0 + ps.n],
                &ct[o1..o1 + ps.n],
                &ctx.s_ntt[li],
                &ps.primes[li],
                &ctx.inv[li],
                &mut out[li * ps.n..(li + 1) * ps.n],
            )
            .unwrap_or_else(|err| die(&format!("decrypt_limb: {err:?}")));
        }
        write_u32(&dir.join(format!("dec_{k}.bin")), &out);
    }
    caliptra_fhe_core::zeroize_u32(&mut out);
    for s in ctx.s_ntt.iter_mut() {
        caliptra_fhe_core::zeroize_u32(s);
    }
    caliptra_fhe_core::zeroize_u8(&mut ctx.packed);
    println!(
        "[roundtrip] decrypted {nclass} result ciphertexts in {}",
        dir.display()
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("encrypt") if args.len() >= 6 => {
            let npix = args
                .get(6)
                .map(|s| s.parse().unwrap_or_else(|_| die("bad npix")))
                .unwrap_or(format::PIXELS_LEN);
            cmd_encrypt(
                &args[2],
                &args[3],
                Path::new(&args[4]),
                Path::new(&args[5]),
                npix,
            );
        }
        Some("decrypt") if args.len() >= 5 => {
            let nclass = args
                .get(5)
                .map(|s| s.parse().unwrap_or_else(|_| die("bad nclass")))
                .unwrap_or(format::LOGITS_LEN / 4);
            cmd_decrypt(&args[2], &args[3], Path::new(&args[4]), nclass);
        }
        _ => {
            eprintln!(
                "usage:\n  roundtrip encrypt <set> <seed_hex> <in_dir> <out_dir> [npix]\n\
                 \x20 roundtrip decrypt <set> <seed_hex> <dir> [nclass]"
            );
            exit(2)
        }
    }
}
