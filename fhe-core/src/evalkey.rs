// Licensed under the Apache-2.0 license
//! Evaluation keys with hybrid key switching: an auxiliary prime P and RNS
//! decomposition, compatible with Lattigo's default keys (one digit per Q prime).
//!
//! A key has one row per Q prime. Each row is a degree-one RLWE ciphertext mod
//! P*Q (limbs q_0..q_{L-1}, P). Row j encrypts P*m only in limb q_j, the CRT
//! gadget P*(Q/q_j)*[(Q/q_j)^-1]_{q_j}. Rotation keys use m = s under
//! sigma_g^-1(s); relinearization keys use m = s^2 under s. Outputs are
//! standard (not Montgomery) bit-reversed NTT residues, like the other kernels.
//! Rows are generated limb by limb with `stream::key_limb`.
use crate::params::{ParamSet, PrimeParams};
use crate::prg::ChaCha20Prg;
use crate::{stream, Result};

/// Rows in one evaluation key: one per Q prime.
pub const fn rows(ps: &ParamSet) -> usize {
    ps.level
}
/// Limbs per row polynomial: the Q primes, then P.
pub const fn limbs(ps: &ParamSet) -> usize {
    ps.level + 1
}
/// Words per row, laid out `[c0 q_0.., c0 P, c1 q_0.., c1 P]`, N words each.
pub const fn row_words(ps: &ParamSet) -> usize {
    2 * limbs(ps) * ps.n
}
/// Words in one whole key.
pub const fn key_words(ps: &ParamSet) -> usize {
    rows(ps) * row_words(ps)
}
/// Prime of row limb `li`: a Q prime, or P for the last limb.
pub fn limb_prime(ps: &ParamSet, li: usize) -> &PrimeParams {
    ps.primes.get(li).unwrap_or(&ps.aux)
}

/// Stream row `row` of one key, limb by limb, to `emit(offset_in_row, words)`:
/// each c1 chunk as it is drawn, then the limb's c0. `error` (shared by the
/// row's limbs) and `prg` come from the caller's per-key seed; `s`, `c0` are
/// N-word scratch and `tw` N/2 words, all erased by the caller.
#[allow(clippy::too_many_arguments)]
pub fn stream_row(
    ps: &ParamSet,
    packed: &[u8],
    galois: u32,
    row: usize,
    error: &[u8; 32],
    prg: &mut ChaCha20Prg,
    s: &mut [u32],
    c0: &mut [u32],
    tw: &mut [u32],
    mut emit: impl FnMut(usize, &[u32]) -> Result<()>,
) -> Result<()> {
    let (n, limbs) = (ps.n, limbs(ps));
    for li in 0..limbs {
        let p = limb_prime(ps, li);
        stream::key_limb(
            packed,
            galois,
            li == row,
            ps.aux.q,
            error,
            prg,
            p,
            s,
            c0,
            tw,
            |at, c1| emit((limbs + li) * n + at, c1),
        )?;
        emit(li * n, c0)?;
    }
    Ok(())
}

/// Whether `galois` names a supported key: 0 is relinearization, otherwise a
/// non-identity odd Galois element modulo 2N.
pub const fn valid(galois: u32, n: usize) -> bool {
    galois == 0 || (galois > 1 && (galois as usize) < 2 * n && galois & 1 == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntt::{self, stage_twiddle_words};
    use crate::{params, rlwe, sample};

    #[test]
    fn galois_rule() {
        assert!(valid(0, 256) && valid(5, 256) && valid(511, 256) && valid(32767, 16384));
        for g in [1, 2, 512] {
            assert!(!valid(g, 256), "g={g}");
        }
    }

    /// One row as the runtime streams it, plus the row's error for checking.
    fn row(
        ps: &ParamSet,
        packed: &[u8],
        g: u32,
        j: usize,
        prg: &mut ChaCha20Prg,
    ) -> (Vec<u32>, Vec<i8>) {
        let n = ps.n;
        let mut seed = [0u8; 32];
        prg.fill(&mut seed);
        let mut out = vec![0u32; row_words(ps)];
        let (mut s, mut c0, mut tw) = (
            vec![0u32; n],
            vec![0u32; n],
            vec![0u32; stage_twiddle_words(n)],
        );
        stream_row(
            ps,
            packed,
            g,
            j,
            &seed,
            prg,
            &mut s,
            &mut c0,
            &mut tw,
            |at, w| {
                out[at..at + w.len()].copy_from_slice(w);
                Ok(())
            },
        )
        .unwrap();
        let mut e = vec![0i8; n];
        sample::sample_cbd(&mut ChaCha20Prg::new(&seed), &mut e);
        (out, e)
    }

    /// Every row limb decrypts, under the independently transformed secret, to
    /// the gadget message plus the row's shared error.
    #[test]
    fn rows_decrypt_to_gadget_message_plus_error() {
        for ps in [&params::PS, &params::PLEQ, &params::P16, &params::PLR] {
            check_rows(ps);
        }
    }

    fn check_rows(ps: &ParamSet) {
        let n = ps.n;
        let mut prg = ChaCha20Prg::new(&[0x47; 32]);
        let mut packed = vec![0u8; n / 4];
        rlwe::keygen(&mut prg, n, &mut packed).unwrap();
        let signed: Vec<i64> = (0..n)
            .map(|i| sample::unpack_ternary(&packed, i) as i64)
            .collect();
        let fixture = std::env::var_os("FHE_EVALKEY_FIXTURE_DIR")
            .filter(|_| ps.name == "ps")
            .map(std::path::PathBuf::from);
        if let Some(dir) = &fixture {
            std::fs::create_dir_all(dir).unwrap();
            let bytes: Vec<u8> = signed
                .iter()
                .flat_map(|v| (*v as i32).to_le_bytes())
                .collect();
            std::fs::write(dir.join("secret.bin"), bytes).unwrap();
        }
        // Independent schoolbook negacyclic square, outside the NTT kernel (P-S only).
        let squared: Vec<i64> = if n == 256 {
            let mut sq = vec![0i64; n];
            for i in 0..n {
                for j in 0..n {
                    sq[(i + j) % n] += signed[i] * signed[j] * if i + j < n { 1 } else { -1 };
                }
            }
            sq
        } else {
            Vec::new()
        };
        // Relinearization (P-S), conjugation, and rotation steps 2^i (g = 5^(2^i)).
        let two_n = 2 * n as u64;
        let mut galois = if n == 256 {
            vec![0u32, 511]
        } else {
            vec![(two_n - 1) as u32]
        };
        let mut g = 5u64;
        for _ in 0..if n == 256 { 7 } else { 2 } {
            galois.push(g as u32);
            g = g * g % two_n;
        }
        let mut tw = vec![0u32; stage_twiddle_words(n)];
        for g in galois {
            for j in 0..rows(ps) {
                let (output, error) = row(ps, &packed, g, j, &mut prg);
                if let Some(dir) = &fixture {
                    // Production format: one file per key, rows in order.
                    use std::io::Write;
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(j > 0)
                        .write(true)
                        .truncate(j == 0)
                        .open(dir.join(format!("key_{g}.bin")))
                        .unwrap()
                        .write_all(
                            &output
                                .iter()
                                .flat_map(|v| v.to_le_bytes())
                                .collect::<Vec<_>>(),
                        )
                        .unwrap();
                }
                for li in 0..limbs(ps) {
                    let p = limb_prime(ps, li);
                    // Independently apply sigma_g to s; it must decrypt every row.
                    let mut transformed: Vec<u32> = (0..n)
                        .map(|i| {
                            let power = if g == 0 {
                                i as u64
                            } else {
                                i as u64 * g as u64 % two_n
                            } as usize;
                            let value = signed[power % n] * if power < n { 1 } else { -1 };
                            value.rem_euclid(p.q as i64) as u32
                        })
                        .collect();
                    ntt::ntt_staged(&mut transformed, p, &mut tw).unwrap();
                    let mut c1 = output[(li + limbs(ps)) * n..(li + limbs(ps) + 1) * n].to_vec();
                    let mut c0 = output[li * n..(li + 1) * n].to_vec();
                    stream::mul_assign(&mut c1, &transformed, p);
                    stream::decrypt_finish(&mut c0, &c1, p, &mut tw).unwrap();
                    for i in 0..n {
                        let message = if g == 0 { squared[i] } else { signed[i] };
                        let gadget = if li == j { ps.aux.q as i64 } else { 0 };
                        let expected =
                            (message * gadget + error[i] as i64).rem_euclid(p.q as i64) as u32;
                        assert_eq!(
                            c0[i], expected,
                            "{} g={g} row={j} limb={li} coefficient={i}",
                            ps.name
                        );
                    }
                }
            }
        }
    }
}
