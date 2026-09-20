/*++

Licensed under the Apache-2.0 license.

File Name:

    ntt.rs

Abstract:

    Negacyclic number-theoretic transform in the wire layout of plan §4.1:

        NTT(x)[bitrev(k)] = sum_j x[j] * g^(j*(2k+1))  mod q

    i.e. natural-order input, **bit-reversed-order output**, `g` the minimum
    primitive 2N-th root of unity.  This is the layout Lattigo produces once
    its twiddle tables are pinned to our root, which is how the Python
    reference was validated (see software/fhe/oracle_check.py).

    Forward is Cooley-Tukey (decimation in time), inverse is Gentleman-Sande,
    both fully in place on a caller-supplied slice.  Twiddles live in a
    caller-supplied table so the firmware can keep them in ICCM `.rodata`
    while the host tests build them on the stack.

--*/

use crate::arith::{add_mod, bit_reverse, mont_mul, pow_mod, sub_mod, to_mont};
use crate::params::PrimeParams;
use crate::{Error, Result};

/// Number of `u32` entries a twiddle table needs for ring degree `n`.
///
/// A radix-2 transform consumes `1 + 2 + ... + N/2 = N-1` distinct twiddles,
/// addressed by bit-reversed index, so the table is `N` words -- not `N/2`.
pub const fn twiddle_words(n: usize) -> usize {
    n
}

fn gen_table(root: u32, n: usize, p: &PrimeParams, out: &mut [u32]) -> Result<()> {
    if out.len() != twiddle_words(n) || !n.is_power_of_two() {
        return Err(Error::BadLength);
    }
    let bits = n.trailing_zeros();
    let mut x: u32 = 1;
    for j in 0..n {
        out[bit_reverse(j, bits)] = to_mont(x, p);
        x = crate::arith::mul_mod(x, root, p.q);
    }
    Ok(())
}

/// Fill the forward twiddle table: `out[bitrev(j)] = to_mont(g^j)`.
pub fn gen_twiddles_fwd(n: usize, p: &PrimeParams, out: &mut [u32]) -> Result<()> {
    gen_table(p.root, n, p, out)
}

/// Fill the inverse twiddle table: `out[bitrev(j)] = to_mont(g^-j)`.
pub fn gen_twiddles_inv(n: usize, p: &PrimeParams, out: &mut [u32]) -> Result<()> {
    gen_table(p.root_inv, n, p, out)
}

/// Forward transform, in place: natural order in, bit-reversed order out.
///
/// `tw` must come from [`gen_twiddles_fwd`] for the same `n` and prime.
pub fn ntt(a: &mut [u32], tw: &[u32], p: &PrimeParams) -> Result<()> {
    let n = a.len();
    if !n.is_power_of_two() || tw.len() != twiddle_words(n) {
        return Err(Error::BadLength);
    }
    let (q, qi) = (p.q, p.q_inv_neg);
    let mut t = n;
    let mut m = 1usize;
    while m < n {
        t >>= 1;
        for i in 0..m {
            let j1 = 2 * i * t;
            let s = tw[m + i];
            for j in j1..j1 + t {
                let u = a[j];
                let v = mont_mul(a[j + t], s, q, qi);
                a[j] = add_mod(u, v, q);
                a[j + t] = sub_mod(u, v, q);
            }
        }
        m <<= 1;
    }
    Ok(())
}

/// Inverse transform, in place: bit-reversed order in, natural order out.
///
/// `tw` must come from [`gen_twiddles_inv`] for the same `n` and prime.
pub fn intt(a: &mut [u32], tw: &[u32], p: &PrimeParams) -> Result<()> {
    let n = a.len();
    if !n.is_power_of_two() || tw.len() != twiddle_words(n) {
        return Err(Error::BadLength);
    }
    let (q, qi) = (p.q, p.q_inv_neg);
    let mut t = 1usize;
    let mut m = n;
    while m > 1 {
        let mut j1 = 0usize;
        let h = m >> 1;
        for i in 0..h {
            let s = tw[h + i];
            for j in j1..j1 + t {
                let u = a[j];
                let v = a[j + t];
                a[j] = add_mod(u, v, q);
                a[j + t] = mont_mul(sub_mod(u, v, q), s, q, qi);
            }
            j1 += 2 * t;
        }
        t <<= 1;
        m >>= 1;
    }
    let n_inv = to_mont(p.n_inv, p);
    for x in a.iter_mut() {
        *x = mont_mul(*x, n_inv, q, qi);
    }
    Ok(())
}

/// Pointwise `a[i] * b[i] mod q`, writing into `out`.
///
/// Both inputs are plain (non-Montgomery) residues, so one operand is lifted
/// on the fly; this is the shape `INGRESS`/`EGRESS` need (`a . NTT(s)`).
pub fn mul_pointwise(a: &[u32], b: &[u32], out: &mut [u32], p: &PrimeParams) -> Result<()> {
    if a.len() != b.len() || a.len() != out.len() {
        return Err(Error::BadLength);
    }
    let (q, qi) = (p.q, p.q_inv_neg);
    for i in 0..a.len() {
        // (a*R) * b * R^-1 = a*b
        let am = mont_mul(a[i], p.r2, q, qi);
        out[i] = mont_mul(am, b[i], q, qi);
    }
    Ok(())
}

/// `g^(j*(2k+1))` evaluated directly, for the O(N^2) reference check.
#[doc(hidden)]
pub fn reference_ntt(x: &[u32], p: &PrimeParams, out: &mut [u32]) {
    let n = x.len();
    let bits = n.trailing_zeros();
    let two_n = 2 * n as u32;
    for k in 0..n {
        let e = 2 * k as u32 + 1;
        let mut acc: u64 = 0;
        for (j, xj) in x.iter().enumerate() {
            let t = pow_mod(p.root, (j as u32).wrapping_mul(e) % two_n, p.q);
            acc += (*xj as u64) * (t as u64);
            acc %= p.q as u64;
        }
        out[bit_reverse(k, bits)] = acc as u32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params;

    fn tables(n: usize, p: &PrimeParams) -> (Vec<u32>, Vec<u32>) {
        let mut f = vec![0u32; twiddle_words(n)];
        let mut i = vec![0u32; twiddle_words(n)];
        gen_twiddles_fwd(n, p, &mut f).unwrap();
        gen_twiddles_inv(n, p, &mut i).unwrap();
        (f, i)
    }

    #[test]
    fn fast_matches_definition() {
        let ps = &params::PS;
        let p = &ps.primes[0];
        let (f, _) = tables(ps.n, p);
        let x: Vec<u32> = (0..ps.n)
            .map(|i| ((i as u64 * 2_654_435_761 + 12345) % p.q as u64) as u32)
            .collect();
        let mut fast = x.clone();
        ntt(&mut fast, &f, p).unwrap();
        let mut slow = vec![0u32; ps.n];
        reference_ntt(&x, p, &mut slow);
        assert_eq!(fast, slow);
    }

    #[test]
    fn inverse_round_trip() {
        for ps in params::ALL {
            for p in ps.primes {
                let (f, i) = tables(ps.n, p);
                let x: Vec<u32> = (0..ps.n)
                    .map(|k| {
                        ((k as u64).wrapping_mul(6_364_136_223_846_793_005) % p.q as u64) as u32
                    })
                    .collect();
                let mut a = x.clone();
                ntt(&mut a, &f, p).unwrap();
                intt(&mut a, &i, p).unwrap();
                assert_eq!(a, x, "{} limb q={}", ps.name, p.q);
            }
        }
    }

    #[test]
    fn rejects_mismatched_tables() {
        let ps = &params::PS;
        let mut a = vec![0u32; ps.n];
        let tw = vec![0u32; ps.n - 1];
        assert_eq!(ntt(&mut a, &tw, &ps.primes[0]), Err(Error::BadLength));
    }
}
