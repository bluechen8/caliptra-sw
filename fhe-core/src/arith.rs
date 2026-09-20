/*++

Licensed under the Apache-2.0 license.

File Name:

    arith.rs

Abstract:

    Modular arithmetic for RNS primes q < 2^31, in Montgomery form with
    R = 2^32 (plan §2.2).

    Keeping every prime below 2^31 means `a + b` cannot overflow a `u32`, so
    addition and subtraction reduce with a single conditional; and a 32x32
    product fits `u64`, so Montgomery reduction needs only the `mul`/`mulhu`
    pair that RV32IMC provides.  There is no division anywhere on the hot
    path: VeeR has no divider worth using and `u64 % u64` would be a libcall.

--*/

use crate::params::PrimeParams;

/// `a + b mod q`, for `a, b < q < 2^31`.
#[inline(always)]
pub const fn add_mod(a: u32, b: u32, q: u32) -> u32 {
    let t = a + b;
    if t >= q {
        t - q
    } else {
        t
    }
}

/// `a - b mod q`, for `a, b < q < 2^31`.
#[inline(always)]
pub const fn sub_mod(a: u32, b: u32, q: u32) -> u32 {
    if a >= b {
        a - b
    } else {
        a + q - b
    }
}

/// `-a mod q`.
#[inline(always)]
pub const fn neg_mod(a: u32, q: u32) -> u32 {
    if a == 0 {
        0
    } else {
        q - a
    }
}

/// Montgomery reduction: `t * R^-1 mod q` for `t < q * R`.
///
/// `q_inv_neg` is `-q^-1 mod 2^32`.  With `q < 2^31` the intermediate
/// `t + m*q` stays below `2*q*R < 2^64`, so the `u64` never wraps and the
/// single conditional subtraction is enough.
#[inline(always)]
pub const fn mont_reduce(t: u64, q: u32, q_inv_neg: u32) -> u32 {
    let m = (t as u32).wrapping_mul(q_inv_neg);
    let u = ((t.wrapping_add((m as u64) * (q as u64))) >> 32) as u32;
    if u >= q {
        u - q
    } else {
        u
    }
}

/// `a * b * R^-1 mod q`.  Both operands must already be reduced.
#[inline(always)]
pub const fn mont_mul(a: u32, b: u32, q: u32, q_inv_neg: u32) -> u32 {
    mont_reduce((a as u64) * (b as u64), q, q_inv_neg)
}

/// Enter Montgomery form: `a * R mod q`.
#[inline(always)]
pub const fn to_mont(a: u32, p: &PrimeParams) -> u32 {
    mont_mul(a, p.r2, p.q, p.q_inv_neg)
}

/// Leave Montgomery form: `a * R^-1 mod q`.
#[inline(always)]
pub const fn from_mont(a: u32, p: &PrimeParams) -> u32 {
    mont_reduce(a as u64, p.q, p.q_inv_neg)
}

/// Plain `a * b mod q`.  Used for table setup, never on the hot path.
#[inline]
pub const fn mul_mod(a: u32, b: u32, q: u32) -> u32 {
    (((a as u64) * (b as u64)) % (q as u64)) as u32
}

/// `base^exp mod q` by square-and-multiply.  Table setup only.
pub const fn pow_mod(base: u32, exp: u32, q: u32) -> u32 {
    let mut acc: u32 = 1;
    let mut b = base % q;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            acc = mul_mod(acc, b, q);
        }
        b = mul_mod(b, b, q);
        e >>= 1;
    }
    acc
}

/// Reduce a signed value into `[0, q)`.  Used for the ternary secret and the
/// centered-binomial error, whose magnitudes are tiny.
#[inline(always)]
pub const fn from_i32(v: i32, q: u32) -> u32 {
    let r = v % (q as i32);
    if r < 0 {
        (r + q as i32) as u32
    } else {
        r as u32
    }
}

/// Reverse the low `bits` bits of `i`.
#[inline]
pub const fn bit_reverse(i: usize, bits: u32) -> usize {
    let mut r = 0usize;
    let mut x = i;
    let mut k = 0;
    while k < bits {
        r = (r << 1) | (x & 1);
        x >>= 1;
        k += 1;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params;

    #[test]
    fn montgomery_round_trip() {
        for p in params::ALL {
            for prime in p.primes {
                assert_eq!(prime.q_inv_neg.wrapping_mul(prime.q), u32::MAX);
                assert_eq!(to_mont(1, prime), prime.r1);
                for a in [0u32, 1, 2, 12345, prime.q - 1] {
                    assert_eq!(from_mont(to_mont(a, prime), prime), a);
                }
                // mont_mul(to_mont(a), b) == a*b mod q
                let (a, b) = (0x0123_4567 % prime.q, 0x0765_4321 % prime.q);
                assert_eq!(
                    mont_mul(to_mont(a, prime), b, prime.q, prime.q_inv_neg),
                    mul_mod(a, b, prime.q)
                );
            }
        }
    }

    #[test]
    fn root_has_correct_order() {
        for p in params::ALL {
            for prime in p.primes {
                // g^N == -1, so g has order exactly 2N
                assert_eq!(pow_mod(prime.root, p.n as u32, prime.q), prime.q - 1);
                assert_eq!(mul_mod(prime.root, prime.root_inv, prime.q), 1);
                assert_eq!(mul_mod(prime.n_inv, p.n as u32, prime.q), 1);
            }
        }
    }

    #[test]
    fn bit_reverse_is_an_involution() {
        for bits in 1..=13u32 {
            for i in 0..(1usize << bits) {
                assert_eq!(bit_reverse(bit_reverse(i, bits), bits), i);
            }
        }
    }
}
