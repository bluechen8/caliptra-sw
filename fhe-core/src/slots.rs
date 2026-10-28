// Licensed under the Apache-2.0 license
//! CKKS slot encoding and decoding in fixed point: VeeR has no FPU.
//!
//! Slots are N/2 complex binary64 values (real, imaginary pairs) on the wire,
//! as on the Aloha accelerator. Decoding evaluates the polynomial at
//! zeta^(5^j), zeta = e^(2 pi i / 2N), the convention of `ckks_ref.py` and
//! Lattigo; both directions use the HEAAN "special" FFT over N/2 points.
//!
//! Values are i64 in fixed point, stored as little-endian word pairs in u32
//! slices (mailbox words have no 8-byte alignment). Twiddles are Q62 and come
//! from two small tables seeded by the generated `ParamSet::zeta`, so neither
//! trigonometry nor a twiddle table ships in firmware.
use crate::arith::{center, from_i32};
use crate::params::ParamSet;
use crate::{Error, Result};

/// Element `i` (an i64) of a word slice.
#[inline(always)]
fn get(w: &[u32], i: usize) -> i64 {
    (w[2 * i] as u64 | ((w[2 * i + 1] as u64) << 32)) as i64
}

#[inline(always)]
fn set(w: &mut [u32], i: usize, v: i64) {
    w[2 * i] = v as u32;
    w[2 * i + 1] = (v as u64 >> 32) as u32;
}

/// a * b / 2^62 within 4 units, for |a| < 2^62 and b a Q62 twiddle component,
/// from three 32x32 products: RV32 lowers an i128 multiply to a slow generic
/// routine. The dropped low x low product adds 0 to 4 units, so the rounding
/// constant adds its mean (one unit) back: unbiased errors keep decode's
/// accumulated error near the exact product's.
#[inline(always)]
fn mulq(a: i64, b: i64) -> i64 {
    let (ah, al) = (i64::from((a >> 32) as i32), i64::from(a as u32));
    let (bh, bl) = (i64::from((b >> 32) as i32), i64::from(b as u32));
    // Each cross product is below 2^63; halve them so the sum cannot overflow.
    let cross = ((ah * bl) >> 1) + ((al * bh) >> 1);
    ((ah * bh) << 2) + ((cross + (3 << 28)) >> 29)
}

/// One shared copy: inlining it into the butterflies saves about 3% of a P-16
/// encode but costs about 900 B of ICCM.
#[inline(never)]
fn cmul(ar: i64, ai: i64, br: i64, bi: i64) -> (i64, i64) {
    (mulq(ar, br) - mulq(ai, bi), mulq(ar, bi) + mulq(ai, br))
}

/// log2 of the twiddle table split: zeta^k = B2[k >> A] * B1[k & (2^A - 1)].
const fn split(n: usize) -> u32 {
    (2 * n).trailing_zeros() / 2
}

/// Words of the twiddle tables B1 (2^A powers) and B2 (2N >> A powers).
const fn table_words(n: usize) -> usize {
    4 * ((1 << split(n)) + ((2 * n) >> split(n)))
}

/// Scratch words `encode` and `decode` need beyond the data: an N-word stage
/// table (also the stash for half the coefficients) and the twiddle tables.
pub const fn scratch_words(n: usize) -> usize {
    n + table_words(n)
}

/// Powers of zeta = e^(2 pi i / 2N), from B1 and B2 built by repeated
/// multiplication (error about 2N * 2^-62).
struct Twiddles<'a> {
    t: &'a [u32],
    a: u32,
    mask: usize,
}

impl<'a> Twiddles<'a> {
    fn new(ps: &ParamSet, t: &'a mut [u32]) -> Self {
        let n = ps.n;
        let a = split(n);
        let b1 = 1usize << a;
        let (z0, z1) = (ps.zeta[0], ps.zeta[1]);
        let (b1t, b2t) = t.split_at_mut(4 * b1);
        powers(b1t, z0, z1);
        // B2 holds the powers of zeta^(2^A).
        let (s0, s1) = cmul(get(b1t, 2 * b1 - 2), get(b1t, 2 * b1 - 1), z0, z1);
        powers(b2t, s0, s1);
        Self {
            t,
            a,
            mask: 2 * n - 1,
        }
    }

    /// zeta^idx.
    fn w(&self, idx: usize) -> (i64, i64) {
        let idx = idx & self.mask;
        let (hi, lo) = (idx >> self.a, idx & ((1 << self.a) - 1));
        let b2 = 2 * ((1 << self.a) + hi);
        cmul(
            get(self.t, b2),
            get(self.t, b2 + 1),
            get(self.t, 2 * lo),
            get(self.t, 2 * lo + 1),
        )
    }
}

/// t[k] = (s0 + i s1)^k for every complex element of `t`, by repeated multiplication.
fn powers(t: &mut [u32], s0: i64, s1: i64) {
    set(t, 0, 1 << 62);
    set(t, 1, 0);
    for k in 1..t.len() / 4 {
        let (r, i) = cmul(get(t, 2 * k - 2), get(t, 2 * k - 1), s0, s1);
        set(t, 2 * k, r);
        set(t, 2 * k + 1, i);
    }
}

/// Swap complex elements into bit-reversed order.
fn bit_reverse(v: &mut [u32], slots: usize) {
    let bits = slots.trailing_zeros();
    for i in 0..slots {
        let r = i.reverse_bits() >> (usize::BITS - bits);
        if i < r {
            for k in 0..4 {
                v.swap(4 * i + k, 4 * r + k);
            }
        }
    }
}

/// Fill `stage` with this stage's twiddles: zeta^((±5^j mod 4·len) · gap), j < len/2.
fn stage_twiddles(tw: &Twiddles, stage: &mut [u32], len: usize, slots: usize, inverse: bool) {
    let m = 4 * slots; // 2N
    let lenq = 4 * len;
    let gap = m / lenq;
    let mut rot = 1usize;
    for j in 0..len / 2 {
        let r = rot & (lenq - 1);
        let (wr, wi) = tw.w(if inverse { lenq - r } else { r } * gap);
        set(stage, 2 * j, wr);
        set(stage, 2 * j + 1, wi);
        rot = (rot * 5) & (m - 1);
    }
}

/// Inverse special FFT, unnormalized: the output is N/2 times the inverse, so
/// the input needs log2(N/2) bits of headroom. Each block is split once so the
/// butterflies index slices of known length (most bounds checks fold away).
fn ifft(v: &mut [u32], slots: usize, tw: &Twiddles, stage: &mut [u32]) {
    let mut len = slots;
    while len >= 2 {
        let lenh = len / 2;
        stage_twiddles(tw, stage, len, slots, true);
        let w = &stage[..2 * len];
        for blk in v[..4 * slots].chunks_exact_mut(4 * len) {
            let (x, y) = blk.split_at_mut(2 * len);
            for j in 0..lenh {
                let (ar, ai, br, bi) = (
                    get(x, 2 * j),
                    get(x, 2 * j + 1),
                    get(y, 2 * j),
                    get(y, 2 * j + 1),
                );
                let (wr, wi) = cmul(ar - br, ai - bi, get(w, 2 * j), get(w, 2 * j + 1));
                set(x, 2 * j, ar + br);
                set(x, 2 * j + 1, ai + bi);
                set(y, 2 * j, wr);
                set(y, 2 * j + 1, wi);
            }
        }
        len >>= 1;
    }
    bit_reverse(v, slots);
}

/// Forward special FFT (evaluation at zeta^(5^j)).
fn fft(v: &mut [u32], slots: usize, tw: &Twiddles, stage: &mut [u32]) {
    bit_reverse(v, slots);
    let mut len = 2;
    while len <= slots {
        let lenh = len / 2;
        stage_twiddles(tw, stage, len, slots, false);
        let w = &stage[..2 * len];
        for blk in v[..4 * slots].chunks_exact_mut(4 * len) {
            let (x, y) = blk.split_at_mut(2 * len);
            for j in 0..lenh {
                let (tr, ti) = cmul(
                    get(y, 2 * j),
                    get(y, 2 * j + 1),
                    get(w, 2 * j),
                    get(w, 2 * j + 1),
                );
                let (ur, ui) = (get(x, 2 * j), get(x, 2 * j + 1));
                set(x, 2 * j, ur + tr);
                set(x, 2 * j + 1, ui + ti);
                set(y, 2 * j, ur - tr);
                set(y, 2 * j + 1, ui - ti);
            }
        }
        len <<= 1;
    }
}

/// round(x * 2^frac) of a finite binary64 `x` with |x| < 2^limit, where
/// limit + frac <= 62; None for NaN, infinity or an out-of-range value.
/// Subnormals (exp 0) shift out to 0.
fn from_f64_bits(bits: u64, frac: u32, limit: u32) -> Option<i64> {
    let exp = ((bits >> 52) & 0x7ff) as i32;
    if exp == 0x7ff || exp - 1023 >= limit as i32 {
        return None;
    }
    let m = (bits & ((1 << 52) - 1)) | (1 << 52); // x = m * 2^(exp - 1075)
    let shift = exp - 1075 + frac as i32;
    let v = if shift >= 0 {
        m << shift
    } else if shift > -64 {
        let s = -shift as u32;
        (m + (1 << (s - 1))) >> s
    } else {
        0
    };
    Some(if bits >> 63 != 0 {
        -(v as i64)
    } else {
        v as i64
    })
}

/// The binary64 nearest to x / 2^frac (ties to even).
fn to_f64_bits(x: i64, frac: u32) -> u64 {
    if x == 0 {
        return 0;
    }
    let a = x.unsigned_abs();
    let mut e = 63 - a.leading_zeros(); // a in [2^e, 2^(e+1))
    let mut mant = if e > 52 {
        let s = e - 52;
        let (q, rem, half) = (a >> s, a & ((1 << s) - 1), 1u64 << (s - 1));
        q + (rem > half || (rem == half && q & 1 == 1)) as u64
    } else {
        a << (52 - e)
    };
    if mant == 1 << 53 {
        mant >>= 1;
        e += 1;
    }
    let exp = (e as i64 - frac as i64 + 1023) as u64;
    (((x < 0) as u64) << 63) | (exp << 52) | (mant & ((1 << 52) - 1))
}

/// Bits of q0: |m| < q0/2 < 2^(qbits - 1).
const fn qbits(ps: &ParamSet) -> u32 {
    32 - ps.primes[0].q.leading_zeros()
}

/// `encode` takes log_delta below this (Δ = 2^log_delta below q0/2); the
/// session also refuses 0, which the codec itself handles.
pub const fn max_log_delta(ps: &ParamSet) -> u32 {
    qbits(ps) - 1
}

/// Encode N/2 complex binary64 slots (`v`, 2N words of real/imaginary pairs)
/// as round(Δ·m), Δ = 2^log_delta, and leave its limb-0 residues mod q0 in
/// v[..N]. Every slot needs |z| < 2^(qbits - 1 - log_delta), and every
/// coefficient |m| < q0/2; otherwise `OutOfRange`.
pub fn encode(ps: &ParamSet, v: &mut [u32], log_delta: u32, scratch: &mut [u32]) -> Result<()> {
    let (n, q0, qb) = (ps.n, ps.primes[0].q, qbits(ps));
    if v.len() != 2 * n || scratch.len() < scratch_words(n) {
        return Err(Error::BadLength);
    }
    if log_delta >= max_log_delta(ps) {
        return Err(Error::OutOfRange);
    }
    let slots = n / 2;
    let zbits = qb - 1 - log_delta;
    let ls = slots.trailing_zeros();
    let frac = 60 - zbits - ls; // |x| < 2^(60 - ls): the unnormalized IFFT stays below 2^60
    for k in 0..n {
        let x = from_f64_bits(get(v, k) as u64, frac, zbits).ok_or(Error::OutOfRange)?;
        set(v, k, x);
    }
    let (stage, rest) = scratch.split_at_mut(n);
    ifft(
        v,
        slots,
        &Twiddles::new(ps, &mut rest[..table_words(n)]),
        stage,
    );
    // m_j = Re, m_(j + N/2) = Im, times Δ / (2^frac · N/2): a right shift by 61 - qbits.
    let shift = frac + ls - log_delta;
    let residue = |x: i64| -> Result<u32> {
        let m = (x + (1 << (shift - 1))) >> shift;
        if m.unsigned_abs() > u64::from(q0 / 2) {
            return Err(Error::OutOfRange);
        }
        Ok(from_i32(m as i32, q0))
    };
    for (j, out) in stage[..slots].iter_mut().enumerate() {
        *out = residue(get(v, 2 * j + 1))?;
    }
    // Word j lies at or before complex j's first word, so nothing unread is lost.
    for j in 0..slots {
        v[j] = residue(get(v, 2 * j))?;
    }
    v[slots..n].copy_from_slice(&stage[..slots]);
    Ok(())
}

/// Decode limb-0 residues of round(Δ·m) (v[..N], each below q0; v[N..2N] is
/// free) into N/2 complex binary64 slots, real/imaginary pairs in v[..2N].
/// log_delta only sets the binary64 exponents: at 0 the slots come out as Δ·z,
/// for a caller that divides by its own (non-power-of-two) scale.
pub fn decode(ps: &ParamSet, v: &mut [u32], log_delta: u32, scratch: &mut [u32]) -> Result<()> {
    let (n, q0, qb) = (ps.n, ps.primes[0].q, qbits(ps));
    if v.len() != 2 * n || scratch.len() < scratch_words(n) {
        return Err(Error::BadLength);
    }
    let slots = n / 2;
    // The forward FFT grows values by up to N/2: keep one bit of margin.
    let g = 62 - (qb - 1) - slots.trailing_zeros() - 1;
    let (stage, rest) = scratch.split_at_mut(n);
    stage[..slots].copy_from_slice(&v[slots..n]);
    // Descending, complex j's words (4j..4j+3) only overwrite consumed residues.
    for j in (0..slots).rev() {
        let (re, im) = (
            i64::from(center(v[j], q0)) << g,
            i64::from(center(stage[j], q0)) << g,
        );
        set(v, 2 * j, re);
        set(v, 2 * j + 1, im);
    }
    fft(
        v,
        slots,
        &Twiddles::new(ps, &mut rest[..table_words(n)]),
        stage,
    );
    for k in 0..n {
        set(v, k, to_f64_bits(get(v, k), g + log_delta) as i64);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params;

    fn words(z: &[(f64, f64)]) -> Vec<u32> {
        z.iter()
            .flat_map(|&(r, i)| [r.to_bits(), i.to_bits()])
            .flat_map(|b| [b as u32, (b >> 32) as u32])
            .collect()
    }

    /// z_j = sum_k m_k zeta^(k 5^j) / Δ, straight from the definition.
    fn evaluate(m: &[i64], j: usize, delta: f64) -> (f64, f64) {
        let n = m.len();
        let mut e = 1usize;
        for _ in 0..j {
            e = e * 5 % (2 * n);
        }
        let (mut re, mut im) = (0.0, 0.0);
        for (k, &c) in m.iter().enumerate() {
            let a = std::f64::consts::PI * ((k * e) % (2 * n)) as f64 / n as f64;
            re += c as f64 * a.cos();
            im += c as f64 * a.sin();
        }
        (re / delta, im / delta)
    }

    #[test]
    fn mulq_matches_i128() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let edges = [
            0,
            1,
            -1,
            1 << 62,
            -(1 << 62),
            (1 << 61) - 1,
            i64::MAX >> 1,
            i64::MIN >> 1,
        ];
        let reference = |a: i64, b: i64| ((a as i128 * b as i128 + (1 << 61)) >> 62) as i64;
        for &a in &edges {
            for &b in &edges {
                assert!((mulq(a, b) - reference(a, b)).abs() <= 4, "{a} {b}");
            }
        }
        for _ in 0..100_000 {
            // |a| < 2^62, |b| <= 2^62 (twiddle components).
            let (a, b) = ((next() as i64) >> 2, (next() as i64) >> 1);
            assert!((mulq(a, b) - reference(a, b)).abs() <= 4, "{a} {b}");
        }
    }

    #[test]
    fn f64_conversions_round_trip() {
        for &x in &[
            0.0,
            1.0,
            -1.0,
            0.5,
            std::f64::consts::PI,
            -1234.5678,
            1e-9,
            255.999,
        ] {
            let f = from_f64_bits(f64::to_bits(x), 40, 11).unwrap();
            assert_eq!(f, (x * 2f64.powi(40)).round() as i64, "{x}");
            assert_eq!(f64::from_bits(to_f64_bits(f, 40)), f as f64 / 2f64.powi(40));
        }
        assert_eq!(from_f64_bits(f64::NAN.to_bits(), 40, 9), None);
        assert_eq!(from_f64_bits(f64::INFINITY.to_bits(), 40, 9), None);
        assert_eq!(from_f64_bits(512f64.to_bits(), 40, 9), None);
        assert_eq!(
            f64::from_bits(to_f64_bits((1 << 60) + 1, 0)),
            (1u64 << 60) as f64
        );
    }

    /// Encoding then evaluating at zeta^(5^j) gives the slots back, at every
    /// set (the definition is O(N^2), so P-16 checks a few slots).
    #[test]
    fn encode_matches_definition() {
        for ps in params::ALL {
            let (n, q0, log_delta) = (ps.n, ps.primes[0].q, 20);
            let z: Vec<(f64, f64)> = (0..n / 2)
                .map(|j| {
                    (
                        (j % 37) as f64 / 7.0 - 2.5,
                        ((j * 13) % 29) as f64 / 11.0 - 1.0,
                    )
                })
                .collect();
            let mut v = words(&z);
            let mut scratch = vec![0u32; scratch_words(n)];
            encode(ps, &mut v, log_delta, &mut scratch).unwrap();
            let m: Vec<i64> = v[..n].iter().map(|&r| i64::from(center(r, q0))).collect();
            for j in (0..n / 2).step_by(if n > 1024 { 997 } else { 1 }) {
                let (re, im) = evaluate(&m, j, (1u64 << log_delta) as f64);
                assert!(
                    (re - z[j].0).abs() < 1e-4 && (im - z[j].1).abs() < 1e-4,
                    "{} slot {j}",
                    ps.name
                );
            }
        }
    }

    /// Decoding equals the definition, and decode(encode(z)) returns z.
    #[test]
    fn decode_matches_definition_and_inverts_encode() {
        for ps in params::ALL {
            let (n, q0, log_delta) = (ps.n, ps.primes[0].q, 18);
            let z: Vec<(f64, f64)> = (0..n / 2)
                .map(|j| {
                    (
                        ((j * 7919) % 1000) as f64 / 100.0 - 5.0,
                        ((j * 31) % 977) as f64 / 97.0 - 5.0,
                    )
                })
                .collect();
            let mut v = words(&z);
            let mut scratch = vec![0u32; scratch_words(n)];
            encode(ps, &mut v, log_delta, &mut scratch).unwrap();
            let m: Vec<i64> = v[..n].iter().map(|&r| i64::from(center(r, q0))).collect();
            decode(ps, &mut v, log_delta, &mut scratch).unwrap();
            let slot = |j: usize| {
                let w = |k: usize| f64::from_bits(v[2 * k] as u64 | ((v[2 * k + 1] as u64) << 32));
                (w(2 * j), w(2 * j + 1))
            };
            let mut worst = 0f64;
            for (j, &(zr, zi)) in z.iter().enumerate() {
                let (gr, gi) = slot(j);
                worst = worst.max((gr - zr).abs()).max((gi - zi).abs());
                if n <= 1024 || j % 997 == 0 {
                    let (re, im) = evaluate(&m, j, (1u64 << log_delta) as f64);
                    assert!(
                        (re - gr).abs() < 1e-7 && (im - gi).abs() < 1e-7,
                        "{} slot {j} {} {}",
                        ps.name,
                        re - gr,
                        im - gi
                    );
                }
            }
            // Rounding m to integers costs about sqrt(N)/Δ per slot.
            assert!(
                worst < 1e-3,
                "{}: decode(encode(z)) off by {worst}",
                ps.name
            );
        }
    }

    #[test]
    fn encode_refuses_out_of_range() {
        let ps = &params::PS;
        let mut scratch = vec![0u32; scratch_words(ps.n)];
        for bad in [f64::NAN, f64::INFINITY, 1e6] {
            let mut v = words(&vec![(bad, 0.0); ps.n / 2]);
            assert_eq!(encode(ps, &mut v, 20, &mut scratch), Err(Error::OutOfRange));
        }
        let mut v = words(&vec![(1.0, 0.0); ps.n / 2]);
        assert_eq!(encode(ps, &mut v, 29, &mut scratch), Err(Error::OutOfRange));
        // Constant slots encode to the constant Δ·c: ±floor(q0/2) fit, one more does not.
        let (q0, half) = (ps.primes[0].q, ps.primes[0].q / 2);
        for (m, ok) in [
            (half as i64, true),
            (-(half as i64), true),
            (half as i64 + 1, false),
        ] {
            let mut v = words(&vec![(m as f64 / f64::from(1 << 20), 0.0); ps.n / 2]);
            let r = encode(ps, &mut v, 20, &mut scratch);
            assert_eq!(r.is_ok(), ok, "{m}");
            if ok {
                assert_eq!(i64::from(center(v[0], q0)), m);
                assert!(v[1..ps.n].iter().all(|&r| r == 0));
            }
        }
    }
}
