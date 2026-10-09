// Licensed under the Apache-2.0 license
//! P-S evaluation keys with hybrid key switching: an auxiliary prime P and
//! RNS decomposition, compatible with Lattigo's default (dnum = 2) keys.
//!
//! A key has one row per Q prime. Each row is a degree-one RLWE ciphertext mod
//! P*Q (limbs q0, q1, P). Row j encrypts P*m only in limb q_j, the CRT gadget
//! P*(Q/q_j)*[(Q/q_j)^-1]_{q_j}. Rotation keys use m = s under
//! sigma_g^-1(s); relinearization keys use m = s^2 under s. Outputs are
//! standard (not Montgomery) bit-reversed NTT residues, like the other kernels.
use crate::params::{PrimeParams, PS_AUX, PS_PRIMES};
use crate::{arith, ntt, prg::ChaCha20Prg, rlwe, sample, Error, Result};

/// Row limb primes: the Q primes, then the auxiliary key-switching prime P.
pub const LIMBS: [PrimeParams; 3] = [PS_PRIMES[0], PS_PRIMES[1], PS_AUX];
/// Rows in one evaluation key: one per Q prime.
pub const ROWS: usize = 2;
/// Serialized words per row: two polynomials, three limbs, 256 coefficients,
/// laid out `[c0 q0, c0 q1, c0 P, c1 q0, c1 q1, c1 P]`.
pub const ROW_WORDS: usize = 2 * LIMBS.len() * 256;
/// Polynomial scratch words, to be erased by the caller after use.
pub const SCRATCH_WORDS: usize = 768;

/// Whether `galois` names a supported key: 0 is relinearization, otherwise a
/// non-identity odd Galois element modulo 2N=512.
pub const fn valid(galois: u32) -> bool {
    galois == 0 || (galois > 1 && galois < 512 && galois & 1 == 1)
}

/// Generate row `row` of one evaluation key into caller-owned private memory.
///
/// The caller supplies fresh randomness and zeroizes output/scratch/errors on
/// every exit. `error` must be shared across the three limbs of this row and
/// independently sampled per row.
pub fn generate_row(
    packed: &[u8],
    galois: u32,
    row: usize,
    prg: &mut ChaCha20Prg,
    error: &[i8],
    output: &mut [u32],
    scratch: &mut [u32],
) -> Result<()> {
    if packed.len() != 64
        || !valid(galois)
        || row >= ROWS
        || error.len() != 256
        || output.len() != ROW_WORDS
        || scratch.len() != SCRATCH_WORDS
    {
        return Err(Error::BadLength);
    }
    let (secret, rest) = scratch.split_at_mut(256);
    let (tw, message) = rest.split_at_mut(256);
    let (c0s, c1s) = output.split_at_mut(LIMBS.len() * 256);
    for (li, p) in LIMBS.iter().enumerate() {
        // The gadget message lives only in limb q_row; P*m vanishes mod P.
        let gadget = li == row;
        ntt::gen_twiddles_fwd(256, p, tw)?;
        if galois == 0 {
            rlwe::secret_ntt_limb(packed, p, tw, secret)?;
            if gadget {
                ntt::mul_pointwise(secret, secret, message, p)?;
            }
        } else {
            if gadget {
                rlwe::secret_ntt_limb(packed, p, tw, message)?;
            }
            // sigma_{g^-1}(s) has s[j*g mod 2N] at X^j, negated past N.
            for (j, v) in secret.iter_mut().enumerate() {
                let m = (j as u32 * galois) & 511;
                let t = sample::unpack_ternary(packed, (m & 255) as usize);
                *v = arith::from_i32(if m < 256 { t } else { -t }, p.q);
            }
            ntt::ntt(secret, tw, p)?;
        }
        let c0 = &mut c0s[li * 256..(li + 1) * 256];
        let c1 = &mut c1s[li * 256..(li + 1) * 256];
        c0.fill(0);
        sample::sample_uniform(prg, p.q, c1);
        rlwe::encrypt_limb_in_place(c0, error, c1, secret, p, tw)?;
        if gadget {
            // P < q_row, so P mod q_row is P itself.
            let factor = arith::to_mont(PS_AUX.q, p);
            for (c, &m) in c0.iter_mut().zip(message.iter()) {
                *c = arith::add_mod(*c, arith::mont_mul(factor, m, p.q, p.q_inv_neg), p.q);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn galois_rule() {
        assert!(valid(0) && valid(5) && valid(511));
        for g in [1, 2, 512] {
            assert!(!valid(g), "g={g}");
        }
    }

    #[test]
    fn rows_decrypt_to_gadget_message_plus_error() {
        let mut prg = ChaCha20Prg::new(&[0x47; 32]);
        let mut packed = [0u8; 64];
        rlwe::keygen(&mut prg, 256, &mut packed).unwrap();
        let signed: [i64; 256] =
            core::array::from_fn(|i| sample::unpack_ternary(&packed, i) as i64);
        let fixture = std::env::var_os("FHE_EVALKEY_FIXTURE_DIR").map(std::path::PathBuf::from);
        if let Some(dir) = &fixture {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(
                dir.join("secret.bin"),
                signed
                    .iter()
                    .flat_map(|v| (*v as i32).to_le_bytes())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        }
        // Independent schoolbook negacyclic square, outside the NTT kernel.
        let mut squared = [0i64; 256];
        for i in 0..256 {
            for j in 0..256 {
                squared[(i + j) % 256] += signed[i] * signed[j] * if i + j < 256 { 1 } else { -1 };
            }
        }
        // Relinearization, conjugation, and every rotation step 2^i (g = 5^(2^i)).
        let mut galois = vec![0u32, 511];
        let mut g = 5u32;
        for _ in 0..7 {
            galois.push(g);
            g = g * g % 512;
        }
        for g in galois {
            for row in 0..ROWS {
                let mut error = [0i8; 256];
                sample::sample_cbd(&mut prg, &mut error);
                let mut output = [0u32; ROW_WORDS];
                let mut scratch = [0u32; SCRATCH_WORDS];
                generate_row(&packed, g, row, &mut prg, &error, &mut output, &mut scratch).unwrap();
                if let Some(dir) = &fixture {
                    // Production format: one file per key, rows in order.
                    use std::io::Write;
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(row > 0)
                        .write(true)
                        .truncate(row == 0)
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
                for (li, p) in LIMBS.iter().enumerate() {
                    let mut transformed = [0u32; 256];
                    // Independently apply sigma_g to s; it must decrypt every row.
                    for i in 0..256 {
                        let power = if g == 0 { i } else { (i * g as usize) % 512 };
                        let value = signed[power % 256] * if power < 256 { 1 } else { -1 };
                        transformed[i] = value.rem_euclid(p.q as i64) as u32;
                    }
                    let mut tw = [0u32; 256];
                    ntt::gen_twiddles_fwd(256, p, &mut tw).unwrap();
                    ntt::ntt(&mut transformed, &tw, p).unwrap();
                    ntt::gen_twiddles_inv(256, p, &mut tw).unwrap();
                    let mut result = [0u32; 256];
                    rlwe::decrypt_limb(
                        &output[li * 256..(li + 1) * 256],
                        &output[(li + LIMBS.len()) * 256..(li + LIMBS.len() + 1) * 256],
                        &transformed,
                        p,
                        &tw,
                        &mut result,
                    )
                    .unwrap();
                    for i in 0..256 {
                        let message = if g == 0 { squared[i] } else { signed[i] };
                        let gadget = if li == row { PS_AUX.q as i64 } else { 0 };
                        let expected =
                            (message * gadget + error[i] as i64).rem_euclid(p.q as i64) as u32;
                        assert_eq!(
                            result[i], expected,
                            "g={g} row={row} limb={li} coefficient={i}"
                        );
                    }
                }
            }
        }
    }
}
