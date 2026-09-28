// Licensed under the Apache-2.0 license

//! `fhe-core` against the WP0 golden vectors (plan §6/WP1 exit criterion).
//!
//! The vectors in `tests/vectors/<set>/` are produced by
//! `caliptra-wrapper/software/fhe/gen_vectors.py` from the Python reference,
//! which is itself checked bit-exactly against Lattigo.  Matching them here
//! pins, in one go: the ChaCha20 PRG, the sampler stream order, the ternary
//! packing, the NTT layout and root convention, the RLWE formulas and the
//! wire format.
//!
//! A failure in `prg`/`sampler` means we disagree about randomness; a failure
//! in `ntt`/`encrypt`/`decrypt` with those passing means we disagree about the
//! arithmetic.  The tests are ordered so the first failure says which.

use std::fs;
use std::path::PathBuf;

use caliptra_fhe_core::format::{self, BlobHdr};
use caliptra_fhe_core::ntt::{gen_twiddles_fwd, gen_twiddles_inv, intt, ntt, twiddle_words};
use caliptra_fhe_core::params::{self, ParamSet};
use caliptra_fhe_core::prg::ChaCha20Prg;
use caliptra_fhe_core::rlwe::{encrypt_limb, keygen, secret_ntt_limb};
use caliptra_fhe_core::sample::{packed_secret_bytes, sample_cbd, sample_uniform, CBD_ETA};

const SETS: [&str; 3] = ["ps", "pl", "pleq"];

fn vec_dir(set: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join(set)
}

fn read(set: &str, name: &str) -> Vec<u8> {
    let p = vec_dir(set).join(name);
    fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn read_u32(set: &str, name: &str) -> Vec<u32> {
    read(set, name)
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

fn read_i32(set: &str, name: &str) -> Vec<i32> {
    read(set, name)
        .chunks_exact(4)
        .map(|c| i32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

fn seed(set: &str) -> [u8; 32] {
    read(set, "seed.bin").try_into().expect("seed must be 32 B")
}

fn param(set: &str) -> &'static ParamSet {
    params::by_name(set).unwrap_or_else(|| panic!("unknown set {set}"))
}

/// Forward and inverse twiddle tables for one limb.
fn tables(ps: &ParamSet, li: usize) -> (Vec<u32>, Vec<u32>) {
    let p = &ps.primes[li];
    let mut f = vec![0u32; twiddle_words(ps.n)];
    let mut i = vec![0u32; twiddle_words(ps.n)];
    gen_twiddles_fwd(ps.n, p, &mut f).unwrap();
    gen_twiddles_inv(ps.n, p, &mut i).unwrap();
    (f, i)
}

#[test]
fn prg_keystream() {
    for set in SETS {
        let mut prg = ChaCha20Prg::new(&seed(set));
        let mut got = vec![0u8; 256];
        prg.fill(&mut got);
        assert_eq!(got, read(set, "prg_keystream.bin"), "{set}: PRG keystream");
    }
}

#[test]
fn samplers_match_stream_order() {
    for set in SETS {
        let ps = param(set);
        let mut prg = ChaCha20Prg::new(&seed(set));

        // 1. keygen consumes the stream first
        let mut packed = vec![0u8; packed_secret_bytes(ps.n)];
        keygen(&mut prg, ps.n, &mut packed).unwrap();
        assert_eq!(packed, read(set, "s_packed.bin"), "{set}: packed secret");

        // 2. then the error, once per command
        let mut e = vec![0i8; ps.n];
        sample_cbd(&mut prg, &mut e);
        let want_e = read_i32(set, "e_i32.bin");
        assert_eq!(e.len(), want_e.len());
        for (i, (g, w)) in e.iter().zip(want_e.iter()).enumerate() {
            assert_eq!(*g as i32, *w, "{set}: e[{i}]");
        }
        assert!(e.iter().all(|v| (*v as i32).unsigned_abs() <= CBD_ETA));

        // 3. then the uniform mask, once per limb, limb 0 first
        let want_a = read_u32(set, "a.bin");
        for li in 0..ps.level {
            let mut a = vec![0u32; ps.n];
            sample_uniform(&mut prg, ps.primes[li].q, &mut a);
            assert_eq!(a, want_a[li * ps.n..(li + 1) * ps.n], "{set}: a limb {li}");
        }
    }
}

#[test]
fn secret_ntt_matches() {
    for set in SETS {
        let ps = param(set);
        let packed = read(set, "s_packed.bin");
        let want = read_u32(set, "s_ntt.bin");
        for li in 0..ps.level {
            let (f, _) = tables(ps, li);
            let mut got = vec![0u32; ps.n];
            secret_ntt_limb(&packed, &ps.primes[li], &f, &mut got).unwrap();
            assert_eq!(
                got,
                want[li * ps.n..(li + 1) * ps.n],
                "{set}: NTT(s) limb {li}"
            );
        }
    }
}

#[test]
fn transforms_match() {
    for set in SETS {
        let ps = param(set);
        let (f, i) = tables(ps, 0);
        let input = read_u32(set, "ntt_in.bin");

        let mut a = input.clone();
        ntt(&mut a, &f, &ps.primes[0]).unwrap();
        assert_eq!(a, read_u32(set, "ntt_out.bin"), "{set}: NTT");

        let mut b = input.clone();
        intt(&mut b, &i, &ps.primes[0]).unwrap();
        assert_eq!(b, read_u32(set, "intt_out.bin"), "{set}: INTT");
    }
}

#[test]
fn encrypt_matches() {
    for set in SETS {
        let ps = param(set);
        let packed = read(set, "s_packed.bin");
        let pt = read_u32(set, "pt.bin");
        let a = read_u32(set, "a.bin");
        let e: Vec<i8> = read_i32(set, "e_i32.bin")
            .iter()
            .map(|v| *v as i8)
            .collect();
        let want = read_u32(set, "ct.bin");

        let mut got = vec![0u32; ps.ct_words()];
        for li in 0..ps.level {
            let p = &ps.primes[li];
            let (f, _) = tables(ps, li);
            let mut s_ntt = vec![0u32; ps.n];
            secret_ntt_limb(&packed, p, &f, &mut s_ntt).unwrap();
            let mut c0 = vec![0u32; ps.n];
            let mut c1 = vec![0u32; ps.n];
            encrypt_limb(
                &pt[li * ps.n..(li + 1) * ps.n],
                &e,
                &a[li * ps.n..(li + 1) * ps.n],
                &s_ntt,
                p,
                &f,
                &mut c0,
                &mut c1,
            )
            .unwrap();
            let o0 = format::c0_limb_off(ps, li);
            let o1 = format::c1_limb_off(ps, li);
            let mut inplace = pt[li * ps.n..(li + 1) * ps.n].to_vec();
            caliptra_fhe_core::rlwe::encrypt_limb_in_place(&mut inplace, &e, &c1, &s_ntt, p, &f)
                .unwrap();
            assert_eq!(&inplace, &want[o0..o0 + ps.n], "{set}: in-place limb {li}");
            got[o0..o0 + ps.n].copy_from_slice(&c0);
            got[o1..o1 + ps.n].copy_from_slice(&c1);
        }
        assert_eq!(got, want, "{set}: ciphertext");
    }
}

#[test]
fn decrypt_matches() {
    use caliptra_fhe_core::rlwe::decrypt_limb;
    for set in SETS {
        let ps = param(set);
        let packed = read(set, "s_packed.bin");
        let ct = read_u32(set, "ct.bin");
        let want = read_u32(set, "dec.bin");

        let mut got = vec![0u32; ps.pt_words()];
        for li in 0..ps.level {
            let p = &ps.primes[li];
            let (f, inv) = tables(ps, li);
            let mut s_ntt = vec![0u32; ps.n];
            secret_ntt_limb(&packed, p, &f, &mut s_ntt).unwrap();
            let o0 = format::c0_limb_off(ps, li);
            let o1 = format::c1_limb_off(ps, li);
            decrypt_limb(
                &ct[o0..o0 + ps.n],
                &ct[o1..o1 + ps.n],
                &s_ntt,
                p,
                &inv,
                &mut got[li * ps.n..(li + 1) * ps.n],
            )
            .unwrap();
        }
        assert_eq!(got, want, "{set}: decryption");

        // and the decryption really is m + e, limb by limb
        let pt = read_u32(set, "pt.bin");
        let e = read_i32(set, "e_i32.bin");
        for li in 0..ps.level {
            let q = ps.primes[li].q;
            for j in 0..ps.n {
                let ei = caliptra_fhe_core::arith::from_i32(e[j], q);
                let want = caliptra_fhe_core::arith::add_mod(pt[li * ps.n + j], ei, q);
                assert_eq!(got[li * ps.n + j], want, "{set}: limb {li} coeff {j}");
            }
        }
    }
}

#[test]
fn blob_headers_parse() {
    for set in SETS {
        let ps = param(set);
        for (name, want_op, want_enc) in [
            (
                "blob_ingress.bin",
                format::op::INGRESS,
                format::enc::POLY_INT_32,
            ),
            (
                "blob_egress.bin",
                format::op::EGRESS,
                format::enc::POLY_INT_32,
            ),
            (
                "blob_pixels.bin",
                format::op::INFER_CLEAR,
                format::enc::PIXELS_U8,
            ),
            (
                "blob_logits.bin",
                format::op::INFER_CLEAR,
                format::enc::LOGITS_I32,
            ),
        ] {
            let blob = read(set, name);
            let h = BlobHdr::parse(&blob, ps).unwrap_or_else(|e| panic!("{set}/{name}: {e:?}"));
            assert_eq!(h.op, want_op, "{set}/{name}: op");
            assert_eq!(h.enc, want_enc, "{set}/{name}: enc");
            assert_eq!(h.log2n as u32, ps.log_n);
            assert_eq!(h.limbs as usize, ps.level);
            assert_eq!(
                blob.len(),
                format::HDR_LEN + h.payload_len as usize,
                "{set}/{name}: length"
            );
        }

        // a replayed blob must be refused
        let blob = read(set, "blob_egress.bin");
        let h = BlobHdr::parse(&blob, ps).unwrap();
        assert!(h.check_seq(h.seq - 1).is_ok());
        assert!(h.check_seq(h.seq).is_err());
    }
}
