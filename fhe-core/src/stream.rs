// Licensed under the Apache-2.0 license
//! Limb-at-a-time kernels whose working set does not grow with L.
//!
//! A limb needs at most two N-word polynomials plus `N/2` words of stage
//! twiddles. The centered-binomial error is shared by every limb of one
//! ciphertext (or key row) without being stored: each limb re-draws it from
//! the same 32-byte error seed. The uniform mask is drawn in chunks and handed
//! to `emit(offset, chunk)` as soon as it is used, so `c1` never needs a buffer.
use crate::arith::{add_mod, from_i32, mont_mul, sub_mod, to_mont};
use crate::ntt::{intt_staged, ntt_staged};
use crate::params::PrimeParams;
use crate::prg::ChaCha20Prg;
use crate::sample::{sample_cbd, sample_uniform, secret_to_limb, unpack_ternary};
use crate::{Error, Result};
use zeroize::Zeroize;

/// Words per mask chunk handed to `emit` (one DMA transfer each).
pub const CHUNK: usize = 256;

/// Ingress plaintext is one limb: residues mod `q0` of an integer polynomial
/// with `|m| < q0/2`. Lift each centered value into limb `p`.
pub fn lift_limb(m0: &[u32], q0: u32, p: &PrimeParams, out: &mut [u32]) -> Result<()> {
    if m0.len() != out.len() {
        return Err(Error::BadLength);
    }
    for (o, &v) in out.iter_mut().zip(m0) {
        if v >= q0 {
            return Err(Error::NotReduced);
        }
        let signed = if v > q0 / 2 {
            v as i64 - q0 as i64
        } else {
            v as i64
        };
        *o = from_i32(signed as i32, p.q);
    }
    Ok(())
}

/// `c += e mod q`, with `e` drawn afresh from `seed` (the same `e` every call).
pub fn add_error(seed: &[u8; 32], c: &mut [u32], q: u32) {
    let mut prg = ChaCha20Prg::new(seed);
    let mut e = [0i8; CHUNK];
    for chunk in c.chunks_mut(CHUNK) {
        let e = &mut e[..chunk.len()];
        sample_cbd(&mut prg, e);
        for (c, &v) in chunk.iter_mut().zip(e.iter()) {
            *c = add_mod(*c, from_i32(v as i32, q), q);
        }
    }
    e.zeroize();
}

/// `NTT(s)` for limb `p` into `out`.
pub fn secret_ntt(packed: &[u8], p: &PrimeParams, tw: &mut [u32], out: &mut [u32]) -> Result<()> {
    secret_to_limb(packed, p.q, out)?;
    ntt_staged(out, p, tw)
}

/// `c0 -= a . s` for a fresh uniform NTT-domain mask `a`, chunk by chunk;
/// each chunk of `a` (the public `c1` limb) goes to `emit` after use.
pub fn mask(
    prg: &mut ChaCha20Prg,
    s: &[u32],
    c0: &mut [u32],
    p: &PrimeParams,
    mut emit: impl FnMut(usize, &[u32]) -> Result<()>,
) -> Result<()> {
    if s.len() != c0.len() {
        return Err(Error::BadLength);
    }
    let mut a = [0u32; CHUNK];
    for (k, chunk) in c0.chunks_mut(CHUNK).enumerate() {
        let a = &mut a[..chunk.len()];
        sample_uniform(prg, p.q, a);
        for (i, c) in chunk.iter_mut().enumerate() {
            let am = mont_mul(a[i], p.r2, p.q, p.q_inv_neg);
            *c = sub_mod(*c, mont_mul(am, s[k * CHUNK + i], p.q, p.q_inv_neg), p.q);
        }
        emit(k * CHUNK, a)?;
    }
    Ok(())
}

/// Encrypt one limb. `c0` holds the lifted plaintext limb and becomes the NTT
/// `c0` limb; `s` is scratch for `NTT(s)`. The caller erases `s` and `c0`.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_limb(
    packed: &[u8],
    error_seed: &[u8; 32],
    prg: &mut ChaCha20Prg,
    p: &PrimeParams,
    c0: &mut [u32],
    s: &mut [u32],
    tw: &mut [u32],
    emit: impl FnMut(usize, &[u32]) -> Result<()>,
) -> Result<()> {
    add_error(error_seed, c0, p.q);
    ntt_staged(c0, p, tw)?;
    secret_ntt(packed, p, tw, s)?;
    mask(prg, s, c0, p, emit)
}

/// Reject unreduced residues of an untrusted limb.
pub fn check_reduced(poly: &[u32], q: u32) -> Result<()> {
    if poly.iter().any(|&v| v >= q) {
        Err(Error::NotReduced)
    } else {
        Ok(())
    }
}

/// `b = b . a`, both standard (non-Montgomery) residues.
pub fn mul_assign(b: &mut [u32], a: &[u32], p: &PrimeParams) {
    for (x, &y) in b.iter_mut().zip(a) {
        *x = mont_mul(mont_mul(*x, p.r2, p.q, p.q_inv_neg), y, p.q, p.q_inv_neg);
    }
}

/// Finish decrypting one limb: `a = INTT(a + b)` with `a = c0`, `b = c1 . NTT(s)`.
pub fn decrypt_finish(a: &mut [u32], b: &[u32], p: &PrimeParams, tw: &mut [u32]) -> Result<()> {
    for (x, &y) in a.iter_mut().zip(b) {
        *x = add_mod(*x, y, p.q);
    }
    intt_staged(a, p, tw)
}

/// One limb of one hybrid evaluation-key row (see `evalkey`). `gadget` marks
/// the row's own Q limb, which carries `P*m`. `s` and `c0` are N-word scratch;
/// `c0` holds the NTT `c0` limb on return and `c1` goes out through `emit`.
#[allow(clippy::too_many_arguments)]
pub fn key_limb(
    packed: &[u8],
    galois: u32,
    gadget: bool,
    aux: u32,
    error_seed: &[u8; 32],
    prg: &mut ChaCha20Prg,
    p: &PrimeParams,
    s: &mut [u32],
    c0: &mut [u32],
    tw: &mut [u32],
    emit: impl FnMut(usize, &[u32]) -> Result<()>,
) -> Result<()> {
    let n = s.len();
    if galois == 0 {
        secret_ntt(packed, p, tw, s)?;
    } else {
        // sigma_{g^-1}(s) has s[j*g mod 2N] at X^j, negated past N (2N is a
        // power of two, and j*g < 2^32 for every supported N).
        for (j, v) in s.iter_mut().enumerate() {
            let m = (j as u32).wrapping_mul(galois) as usize & (2 * n - 1);
            let t = unpack_ternary(packed, m & (n - 1));
            *v = from_i32(if m < n { t } else { -t }, p.q);
        }
        ntt_staged(s, p, tw)?;
    }
    c0.fill(0);
    add_error(error_seed, c0, p.q);
    // P < q_row, so P mod q_row is P itself. A rotation key's message s is
    // added before the (linear) NTT, which saves recomputing NTT(s).
    if gadget && galois != 0 {
        for (j, c) in c0.iter_mut().enumerate() {
            let m = match unpack_ternary(packed, j) {
                0 => 0,
                1 => aux,
                _ => p.q - aux,
            };
            *c = add_mod(*c, m, p.q);
        }
    }
    ntt_staged(c0, p, tw)?;
    mask(prg, s, c0, p, emit)?;
    if gadget && galois == 0 {
        // Relinearization: P * NTT(s)^2, with s still holding NTT(s).
        let factor = to_mont(aux, p);
        for (c, &v) in c0.iter_mut().zip(s.iter()) {
            let m = mont_mul(mont_mul(v, p.r2, p.q, p.q_inv_neg), v, p.q, p.q_inv_neg);
            *c = add_mod(*c, mont_mul(factor, m, p.q, p.q_inv_neg), p.q);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntt::stage_twiddle_words;
    use crate::{params, rlwe, sample};

    /// Streamed encryption of a one-limb input decrypts, limb by limb, to the
    /// lifted plaintext plus one shared error.
    #[test]
    fn encrypt_then_decrypt_every_limb() {
        for ps in params::ALL {
            let n = ps.n;
            let q0 = ps.primes[0].q;
            let mut prg = ChaCha20Prg::new(&[0x33; 32]);
            let mut packed = vec![0u8; n / 4];
            rlwe::keygen(&mut prg, n, &mut packed).unwrap();
            let m0: Vec<u32> = (0..n)
                .map(|i| from_i32((i as i32 * 7919) % 100_000 - 50_000, q0))
                .collect();
            let seed = [0x44; 32];
            let mut e = vec![0i8; n];
            sample::sample_cbd(&mut ChaCha20Prg::new(&seed), &mut e);
            let mut tw = vec![0u32; stage_twiddle_words(n)];
            for p in ps.primes {
                let mut c0 = vec![0u32; n];
                let mut s = vec![0u32; n];
                let mut c1 = vec![0u32; n];
                lift_limb(&m0, q0, p, &mut c0).unwrap();
                let want: Vec<u32> = c0
                    .iter()
                    .zip(&e)
                    .map(|(&m, &e)| add_mod(m, from_i32(e as i32, p.q), p.q))
                    .collect();
                encrypt_limb(
                    &packed,
                    &seed,
                    &mut prg,
                    p,
                    &mut c0,
                    &mut s,
                    &mut tw,
                    |o, a| {
                        c1[o..o + a.len()].copy_from_slice(a);
                        Ok(())
                    },
                )
                .unwrap();
                // Decrypt as the runtime does: s into A, c1 into B, c0 into A.
                let mut a = vec![0u32; n];
                secret_ntt(&packed, p, &mut tw, &mut a).unwrap();
                mul_assign(&mut c1, &a, p);
                decrypt_finish(&mut c0, &c1, p, &mut tw).unwrap();
                assert_eq!(c0, want, "{} q={}", ps.name, p.q);
            }
        }
    }

    #[test]
    fn lift_rejects_unreduced() {
        let p = &params::PS.primes[1];
        let q0 = params::PS.primes[0].q;
        let mut out = [0u32; 2];
        assert_eq!(lift_limb(&[0, q0], q0, p, &mut out), Err(Error::NotReduced));
        lift_limb(&[1, q0 - 1], q0, p, &mut out).unwrap();
        assert_eq!(out, [1, p.q - 1]);
    }
}
