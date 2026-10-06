// Licensed under the Apache-2.0 license
//! Integer-only coefficient recovery for Aloha profile 0xa108.
//! No CKKS slot decoding, scale change, rounding, or noise removal is performed.
//! The caller must authenticate the ciphertext and choose its active basis.
//! The centered representative is unique only modulo the input basis product;
//! callers must establish that the intended coefficient has not wrapped.

pub const Q: [u64; 2] = [(1 << 46) - (9 << 24) + 1, (1 << 47) - (1 << 24) + 1];
const Q0_INV_Q1: u128 = 123_694_035_699_709;

/// Recover a coefficient from the prefix basis [q0] or [q0,q1].
/// A level is a limb count, not an index; arbitrary subsets are not supported.
pub fn centered(residues: &[u64]) -> Option<i128> {
    if residues.is_empty() || residues.len() > Q.len() {
        return None;
    }
    if residues.iter().zip(Q).any(|(&r, q)| r >= q) {
        return None;
    }
    let mut x = u128::from(residues[0]);
    let mut modulus = u128::from(Q[0]);
    if residues.len() == 2 {
        let q1 = u128::from(Q[1]);
        let difference = (u128::from(residues[1]) + q1 - x) % q1;
        let t = difference * Q0_INV_Q1 % q1;
        x += modulus * t;
        modulus *= q1;
    }
    Some(if x > modulus / 2 {
        x as i128 - modulus as i128
    } else {
        x as i128
    })
}

/// Reduce a recovered signed coefficient into a target modulus without changing
/// scale. This supports basis extension; it is not CKKS rescaling or encryption.
/// Uses integer remainder; no constant-time implementation is claimed.
pub fn residue(coefficient: i128, modulus: u64) -> Option<u64> {
    if modulus < 2 {
        return None;
    }
    Some(coefficient.rem_euclid(i128::from(modulus)) as u64)
}

/// Convert limb-major LE-u64 words from the recovery command to centered i128
/// coefficients. All sizes and residues are checked before modifying output.
pub fn reconstruct(words: &[u32], limbs: usize, output: &mut [i128]) -> Option<()> {
    if !(1..=2).contains(&limbs) || output.is_empty() {
        return None;
    }
    let stride = output.len().checked_mul(2)?;
    if words.len() != stride.checked_mul(limbs)? {
        return None;
    }
    let read = |limb: usize, i: usize| {
        let base = limb * stride + 2 * i;
        u64::from(words[base]) | u64::from(words[base + 1]) << 32
    };
    for (limb, &q) in Q.iter().enumerate().take(limbs) {
        if (0..output.len()).any(|i| read(limb, i) >= q) {
            return None;
        }
    }
    for (i, dst) in output.iter_mut().enumerate() {
        let r = [read(0, i), if limbs == 2 { read(1, i) } else { 0 }];
        *dst = centered(&r[..limbs])?;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crt_boundaries_and_values_beyond_one_limb() {
        let product = i128::from(Q[0]) * i128::from(Q[1]);
        assert_eq!(u128::from(Q[0]) * Q0_INV_Q1 % u128::from(Q[1]), 1);
        for m in [1, i128::from(Q[0]), product] {
            for x in [0, 1, -1, m / 2, -(m / 2)] {
                let limbs = if m == product { 2 } else { 1 };
                let r = [residue(x, Q[0]).unwrap(), residue(x, Q[1]).unwrap()];
                assert_eq!(centered(&r[..limbs]), Some(x));
            }
        }
        for x in [i128::from(Q[0]) + 123, -i128::from(Q[0]) - 456, product / 3] {
            let r = [residue(x, Q[0]).unwrap(), residue(x, Q[1]).unwrap()];
            assert_eq!(centered(&r), Some(x));
            assert_ne!(centered(&r[..1]), Some(x));
        }
    }

    #[test]
    fn randomized_roundtrip_and_basis_extension() {
        let product = i128::from(Q[0]) * i128::from(Q[1]);
        let mut state = 7u128;
        for _ in 0..4096 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let x = (state % product as u128) as i128 - product / 2;
            let r = [residue(x, Q[0]).unwrap(), residue(x, Q[1]).unwrap()];
            assert_eq!(centered(&r), Some(x));
        }
        // A negative q0 representative must extend as negative, not as q0-7.
        let x = centered(&[Q[0] - 7]).unwrap();
        assert_eq!(residue(x, Q[1]), Some(Q[1] - 7));
    }

    #[test]
    fn limb_major_wire_layout_and_rejection_are_atomic() {
        let values = [0, -1, i128::from(Q[0]) + 77, -i128::from(Q[0]) - 91];
        let mut words = [0u32; 16];
        for (limb, q) in Q.into_iter().enumerate() {
            for (i, x) in values.into_iter().enumerate() {
                let r = residue(x, q).unwrap();
                words[limb * 8 + i * 2] = r as u32;
                words[limb * 8 + i * 2 + 1] = (r >> 32) as u32;
            }
        }
        let mut out = [99; 4];
        assert_eq!(reconstruct(&words, 2, &mut out), Some(()));
        assert_eq!(out, values);
        words[8] = Q[1] as u32;
        words[9] = (Q[1] >> 32) as u32;
        assert_eq!(reconstruct(&words, 2, &mut out), None);
        assert_eq!(out, values);
        assert_eq!(reconstruct(&words[..15], 2, &mut out), None);
        assert_eq!(reconstruct(&words, 0, &mut out), None);
        assert_eq!(reconstruct(&words, 3, &mut out), None);
        assert_eq!(centered(&[]), None);
        assert_eq!(centered(&[Q[0]]), None);
        assert_eq!(residue(1, 0), None);
    }
}
