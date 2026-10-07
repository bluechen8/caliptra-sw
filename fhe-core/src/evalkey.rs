// Licensed under the Apache-2.0 license
//! P-S evaluation-key rows, compatible with Q-only RLWE gadget switching.
//!
//! A key has 2 RNS decomposition components, each with eight base-16 digits.
//! Each row is an ordinary degree-one RLWE ciphertext (4096 bytes). Rotation
//! keys encrypt s under sigma_g^-1(s); relinearization keys encrypt s^2 under s.
//! Only the selected RNS component carries the gadget message. Outputs are
//! standard (not Montgomery) bit-reversed NTT residues, like the other kernels.
use crate::{arith, ntt, params::PS, prg::ChaCha20Prg, rlwe, sample, Error, Result};

/// Number of independently generated rows in one evaluation key.
pub const ROWS: usize = 16;
/// Serialized words per row: two polynomials, two primes, 256 coefficients.
pub const ROW_WORDS: usize = 1024;
/// Polynomial scratch words, to be erased by the caller after use.
pub const SCRATCH_WORDS: usize = 768;

/// Generate one evaluation-key row into caller-owned private memory.
///
/// `galois=0` selects relinearization; otherwise it is an odd element modulo
/// 512. The caller authenticates/authorizes the key identifier and row, supplies
/// fresh randomness, and zeroizes scratch/errors on every exit. `error` must be
/// shared across the two limbs of this row and independently sampled per row.
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
        || row >= ROWS
        || error.len() != 256
        || output.len() != ROW_WORDS
        || scratch.len() != SCRATCH_WORDS
        || (galois != 0 && (galois >= 512 || galois & 1 == 0))
    {
        return Err(Error::BadLength);
    }
    // An odd element has an inverse modulo 2N. Fixed bounded search, public data.
    let inverse = if galois == 0 {
        1
    } else {
        (1..512)
            .step_by(2)
            .find(|v| (v * galois) & 511 == 1)
            .ok_or(Error::BadHeader)?
    };
    let (secret, rest) = scratch.split_at_mut(256);
    let (tw, message) = rest.split_at_mut(256);
    for (li, p) in PS.primes.iter().enumerate() {
        ntt::gen_twiddles_fwd(256, p, tw)?;
        rlwe::secret_ntt_limb(packed, p, tw, secret)?;
        for i in 0..256 {
            message[i] = if galois == 0 {
                arith::mont_mul(arith::to_mont(secret[i], p), secret[i], p.q, p.q_inv_neg)
            } else {
                secret[i]
            };
        }
        if galois != 0 {
            // Build sigma_inverse(s) in coefficient form, using c0 as scratch.
            sample::secret_to_limb(packed, p.q, &mut output[li * 256..(li + 1) * 256])?;
            for i in 0..256 {
                let index = (i as u32 * inverse) & 511;
                secret[(index & 255) as usize] = if index < 256 {
                    output[li * 256 + i]
                } else {
                    arith::neg_mod(output[li * 256 + i], p.q)
                };
            }
            ntt::ntt(secret, tw, p)?;
        }
        let (c0, c1) = output.split_at_mut(512);
        let c0 = &mut c0[li * 256..(li + 1) * 256];
        let c1 = &mut c1[li * 256..(li + 1) * 256];
        c0.fill(0);
        sample::sample_uniform(prg, p.q, c1);
        rlwe::encrypt_limb_in_place(c0, error, c1, secret, p, tw)?;
        if li == row / 8 {
            let factor = arith::to_mont(1 << (4 * (row % 8)), p);
            for i in 0..256 {
                c0[i] = arith::add_mod(
                    c0[i],
                    arith::mont_mul(factor, message[i], p.q, p.q_inv_neg),
                    p.q,
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_decrypt_to_gadget_message_plus_error() {
        let mut prg = ChaCha20Prg::new(&[0x47; 32]);
        let mut packed = [0u8; 64];
        rlwe::keygen(&mut prg, 256, &mut packed).unwrap();
        let mut signed = [0i64; 256];
        let mut coefficients = [0u32; 256];
        sample::secret_to_limb(&packed, PS.primes[0].q, &mut coefficients).unwrap();
        for (v, c) in signed.iter_mut().zip(coefficients) {
            *v = if c == PS.primes[0].q - 1 {
                -1
            } else {
                c as i64
            };
        }
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
        for g in [0u32, 5, 25, 511] {
            for row in 0..ROWS {
                let mut error = [0i8; 256];
                sample::sample_cbd(&mut prg, &mut error);
                let mut output = [0u32; ROW_WORDS];
                let mut scratch = [0u32; SCRATCH_WORDS];
                generate_row(&packed, g, row, &mut prg, &error, &mut output, &mut scratch).unwrap();
                if let Some(dir) = &fixture {
                    std::fs::write(
                        dir.join(format!("key_{g}_{row}.bin")),
                        output
                            .iter()
                            .flat_map(|v| v.to_le_bytes())
                            .collect::<Vec<_>>(),
                    )
                    .unwrap();
                }
                for (li, p) in PS.primes.iter().enumerate() {
                    let mut transformed = [0u32; 256];
                    // Compose sigma_g(output-secret) = s to recover each
                    // coefficient without reusing generation's inverse search.
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
                        &output[(li + 2) * 256..(li + 3) * 256],
                        &transformed,
                        p,
                        &tw,
                        &mut result,
                    )
                    .unwrap();
                    for i in 0..256 {
                        let message = if g == 0 { squared[i] } else { signed[i] };
                        let gadget = if li == row / 8 {
                            1i64 << (4 * (row % 8))
                        } else {
                            0
                        };
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
