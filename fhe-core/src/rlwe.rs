/*++

Licensed under the Apache-2.0 license.

File Name:

    rlwe.rs

Abstract:

    Secret-key RLWE encrypt and decrypt, per limb, exactly as plan §4.4
    specifies for `FHE_INGRESS` and `FHE_EGRESS`:

        INGRESS   e <- CBD;  t = NTT(m + e);  a <- uniform (NTT domain);
                  c1 = a;    c0 = t - a . NTT(s)
        EGRESS    p = INTT(c0 + c1 . NTT(s))

    Everything is per limb and in place on caller-supplied slices, so the
    runtime can drive it straight over mailbox SRAM without a copy and
    without ever materialising a whole ciphertext in DCCM.

    Evaluation-key generation is in evalkey.rs. Ciphertext evaluation, including
    rotation and relinearization using exported keys, runs on the untrusted server.

--*/

use crate::arith::{add_mod, mont_mul, sub_mod};
use crate::ntt::{intt, ntt};
use crate::params::PrimeParams;
use crate::prg::ChaCha20Prg;
use crate::sample::{sample_ternary_packed, secret_to_limb};
use crate::{Error, Result};

/// Sample the ternary secret (plan §4.4 `KEYGEN`).
///
/// The caller is responsible for zeroizing any previous secret *before*
/// calling this, and for keeping `packed` in DCCM, never in the mailbox.
pub fn keygen(prg: &mut ChaCha20Prg, n: usize, packed: &mut [u8]) -> Result<()> {
    sample_ternary_packed(prg, n, packed)
}

/// Compute `NTT(s)` for one limb into `out`.
///
/// At P-L this is 64 KiB for all limbs, which does not fit the runtime's
/// 36 KiB DCCM data region, so the default is to call this per limb inside
/// each command rather than cache it (see the progress log, check 1).
pub fn secret_ntt_limb(
    packed: &[u8],
    p: &PrimeParams,
    tw_fwd: &[u32],
    out: &mut [u32],
) -> Result<()> {
    secret_to_limb(packed, p.q, out)?;
    ntt(out, tw_fwd, p)
}

/// Encrypt one RNS limb.
///
/// * `pt` -- plaintext limb, coefficient domain, reduced mod `p.q`
/// * `e` -- the centered-binomial error, shared by every limb
/// * `a` -- the uniform mask for *this* limb, already in NTT domain
/// * `s_ntt` -- `NTT(s)` for this limb
/// * `c0`, `c1` -- outputs, NTT domain, bit-reversed order
///
/// `c0` doubles as the scratch for `NTT(m + e)`, so no extra buffer is
/// needed; the caller must zeroize `pt`, `e` and `s_ntt` afterwards.
///
/// The argument list is long on purpose: every buffer is caller-owned so the
/// runtime can point them straight at mailbox SRAM (plan §6/WP1, "every
/// function operates on caller-supplied slices").
#[allow(clippy::too_many_arguments)]
pub fn encrypt_limb(
    pt: &[u32],
    e: &[i8],
    a: &[u32],
    s_ntt: &[u32],
    p: &PrimeParams,
    tw_fwd: &[u32],
    c0: &mut [u32],
    c1: &mut [u32],
) -> Result<()> {
    let n = pt.len();
    if e.len() != n || a.len() != n || s_ntt.len() != n || c0.len() != n || c1.len() != n {
        return Err(Error::BadLength);
    }
    let (q, qi) = (p.q, p.q_inv_neg);
    for v in pt.iter() {
        if *v >= q {
            return Err(Error::NotReduced);
        }
    }
    // c0 <- m + e, coefficient domain
    for i in 0..n {
        let ei = crate::arith::from_i32(e[i] as i32, q);
        c0[i] = add_mod(pt[i], ei, q);
    }
    // c0 <- NTT(m + e)
    ntt(c0, tw_fwd, p)?;
    // c1 <- a ; c0 <- c0 - a . s_ntt
    for i in 0..n {
        let am = mont_mul(a[i], p.r2, q, qi); // lift a into Montgomery form
        let prod = mont_mul(am, s_ntt[i], q, qi);
        c0[i] = sub_mod(c0[i], prod, q);
        c1[i] = a[i];
    }
    Ok(())
}

/// Encrypt in place: `c0` initially contains reduced coefficient-domain plaintext;
/// `c1` contains the sampled uniform NTT mask and is unchanged. Disjoint buffers
/// let the runtime retain one protected input snapshot and stream each result.
pub fn encrypt_limb_in_place(
    c0: &mut [u32],
    e: &[i8],
    c1: &[u32],
    s_ntt: &[u32],
    p: &PrimeParams,
    tw_fwd: &[u32],
) -> Result<()> {
    let n = c0.len();
    if e.len() != n || c1.len() != n || s_ntt.len() != n {
        return Err(Error::BadLength);
    }
    if c0.iter().any(|&v| v >= p.q) || c1.iter().any(|&v| v >= p.q) {
        return Err(Error::NotReduced);
    }
    for (word, &error) in c0.iter_mut().zip(e) {
        *word = add_mod(*word, crate::arith::from_i32(error as i32, p.q), p.q);
    }
    ntt(c0, tw_fwd, p)?;
    for i in 0..n {
        let am = mont_mul(c1[i], p.r2, p.q, p.q_inv_neg);
        let prod = mont_mul(am, s_ntt[i], p.q, p.q_inv_neg);
        c0[i] = sub_mod(c0[i], prod, p.q);
    }
    Ok(())
}

/// Decrypt one RNS limb: `out = INTT(c0 + c1 . NTT(s))`.
///
/// `out` may alias neither `c0` nor `c1`; the caller must zeroize `out` and
/// `s_ntt` on every exit path once the plaintext has been wrapped.
pub fn decrypt_limb(
    c0: &[u32],
    c1: &[u32],
    s_ntt: &[u32],
    p: &PrimeParams,
    tw_inv: &[u32],
    out: &mut [u32],
) -> Result<()> {
    let n = c0.len();
    if c1.len() != n || s_ntt.len() != n || out.len() != n {
        return Err(Error::BadLength);
    }
    let (q, qi) = (p.q, p.q_inv_neg);
    for i in 0..n {
        let cm = mont_mul(c1[i], p.r2, q, qi);
        let prod = mont_mul(cm, s_ntt[i], q, qi);
        out[i] = add_mod(c0[i], prod, q);
    }
    intt(out, tw_inv, p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntt::{gen_twiddles_fwd, gen_twiddles_inv, twiddle_words};
    use crate::params;
    use crate::sample::{packed_secret_bytes, sample_cbd, sample_uniform};

    #[test]
    fn encrypt_decrypt_recovers_m_plus_e() {
        for ps in params::ALL {
            let n = ps.n;
            let mut prg = ChaCha20Prg::new(&[0x5au8; 32]);
            let mut packed = vec![0u8; packed_secret_bytes(n)];
            keygen(&mut prg, n, &mut packed).unwrap();

            let mut e = vec![0i8; n];
            sample_cbd(&mut prg, &mut e);

            for p in ps.primes {
                let mut fwd = vec![0u32; twiddle_words(n)];
                let mut inv = vec![0u32; twiddle_words(n)];
                gen_twiddles_fwd(n, p, &mut fwd).unwrap();
                gen_twiddles_inv(n, p, &mut inv).unwrap();

                let mut s_ntt = vec![0u32; n];
                secret_ntt_limb(&packed, p, &fwd, &mut s_ntt).unwrap();

                let mut a = vec![0u32; n];
                sample_uniform(&mut prg, p.q, &mut a);

                // a deterministic "plaintext"
                let pt: Vec<u32> = (0..n)
                    .map(|i| ((i as u64 * 7919) % p.q as u64) as u32)
                    .collect();

                let mut c0 = vec![0u32; n];
                let mut c1 = vec![0u32; n];
                encrypt_limb(&pt, &e, &a, &s_ntt, p, &fwd, &mut c0, &mut c1).unwrap();

                let mut got = vec![0u32; n];
                decrypt_limb(&c0, &c1, &s_ntt, p, &inv, &mut got).unwrap();

                for i in 0..n {
                    let want = add_mod(pt[i], crate::arith::from_i32(e[i] as i32, p.q), p.q);
                    assert_eq!(got[i], want, "{} q={} coeff {}", ps.name, p.q, i);
                }
            }
        }
    }

    #[test]
    fn rejects_unreduced_plaintext() {
        let ps = &params::PS;
        let p = &ps.primes[0];
        let n = ps.n;
        let mut fwd = vec![0u32; twiddle_words(n)];
        gen_twiddles_fwd(n, p, &mut fwd).unwrap();
        let mut pt = vec![0u32; n];
        pt[3] = p.q; // not reduced
        let (e, a, s) = (vec![0i8; n], vec![0u32; n], vec![0u32; n]);
        let (mut c0, mut c1) = (vec![0u32; n], vec![0u32; n]);
        assert_eq!(
            encrypt_limb(&pt, &e, &a, &s, p, &fwd, &mut c0, &mut c1),
            Err(Error::NotReduced)
        );
    }
}
