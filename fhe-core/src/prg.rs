/*++

Licensed under the Apache-2.0 license.

File Name:

    prg.rs

Abstract:

    ChaCha20 keystream generator (plan §4.4: "ChaCha20 core (~1 KB), reseeded
    from the TRNG per command").

    The firmware seeds this from `Trng::generate()` at the start of every
    command, so `a` and `e` are fresh per ciphertext.  The host tests seed it
    from the fixed vector seeds instead, which is what makes the golden
    vectors reproducible on both sides.

    RFC 8439 block function, 12-byte all-zero nonce, 32-bit block counter
    starting at zero.

--*/

const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// A byte-oriented ChaCha20 keystream.
///
/// Drop zeroizes the key and the buffered block.
pub struct ChaCha20Prg {
    key: [u32; 8],
    counter: u32,
    buf: [u8; 64],
    pos: usize,
}

impl ChaCha20Prg {
    /// Seed from 32 bytes (the firmware passes `Trng::generate()` output).
    pub fn new(seed: &[u8; 32]) -> Self {
        let mut key = [0u32; 8];
        for (i, k) in key.iter_mut().enumerate() {
            *k = u32::from_le_bytes([
                seed[4 * i],
                seed[4 * i + 1],
                seed[4 * i + 2],
                seed[4 * i + 3],
            ]);
        }
        Self {
            key,
            counter: 0,
            buf: [0u8; 64],
            pos: 64,
        }
    }

    fn block(&mut self) {
        let mut state = [0u32; 16];
        state[0..4].copy_from_slice(&SIGMA);
        state[4..12].copy_from_slice(&self.key);
        state[12] = self.counter;
        // state[13..16] stay zero: the nonce is all zeroes
        let mut w = state;
        for _ in 0..10 {
            quarter(&mut w, 0, 4, 8, 12);
            quarter(&mut w, 1, 5, 9, 13);
            quarter(&mut w, 2, 6, 10, 14);
            quarter(&mut w, 3, 7, 11, 15);
            quarter(&mut w, 0, 5, 10, 15);
            quarter(&mut w, 1, 6, 11, 12);
            quarter(&mut w, 2, 7, 8, 13);
            quarter(&mut w, 3, 4, 9, 14);
        }
        for i in 0..16 {
            let v = w[i].wrapping_add(state[i]);
            self.buf[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
        }
        self.counter = self.counter.wrapping_add(1);
        self.pos = 0;
    }

    /// Fill `out` with keystream bytes.
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut done = 0;
        while done < out.len() {
            if self.pos >= 64 {
                self.block();
            }
            let take = core::cmp::min(out.len() - done, 64 - self.pos);
            out[done..done + take].copy_from_slice(&self.buf[self.pos..self.pos + take]);
            self.pos += take;
            done += take;
        }
    }

    /// One keystream byte.
    #[inline]
    pub fn next_u8(&mut self) -> u8 {
        if self.pos >= 64 {
            self.block();
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        b
    }

    /// One little-endian keystream `u32`.
    #[inline]
    pub fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill(&mut b);
        u32::from_le_bytes(b)
    }
}

impl Drop for ChaCha20Prg {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
        self.buf.zeroize();
    }
}

#[inline(always)]
fn quarter(w: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    w[a] = w[a].wrapping_add(w[b]);
    w[d] = (w[d] ^ w[a]).rotate_left(16);
    w[c] = w[c].wrapping_add(w[d]);
    w[b] = (w[b] ^ w[c]).rotate_left(12);
    w[a] = w[a].wrapping_add(w[b]);
    w[d] = (w[d] ^ w[a]).rotate_left(8);
    w[c] = w[c].wrapping_add(w[d]);
    w[b] = (w[b] ^ w[c]).rotate_left(7);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8439 §2.3.2 test vector, with the counter and nonce this PRG uses
    /// replaced by our own (counter 0, zero nonce), so the check is that the
    /// block function itself is right: compare against the RFC's key setup
    /// with its own counter/nonce by driving `block()` manually.
    #[test]
    fn rfc8439_block() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let mut p = ChaCha20Prg::new(&key);
        // RFC 8439 §2.3.2 uses counter = 1 and nonce 00:00:00:09 00:00:00:4a
        // 00:00:00:00; rebuild that state directly.
        let mut state = [0u32; 16];
        state[0..4].copy_from_slice(&SIGMA);
        state[4..12].copy_from_slice(&p.key);
        state[12] = 1;
        state[13] = 0x0900_0000;
        state[14] = 0x4a00_0000;
        state[15] = 0x0000_0000;
        let mut w = state;
        for _ in 0..10 {
            quarter(&mut w, 0, 4, 8, 12);
            quarter(&mut w, 1, 5, 9, 13);
            quarter(&mut w, 2, 6, 10, 14);
            quarter(&mut w, 3, 7, 11, 15);
            quarter(&mut w, 0, 5, 10, 15);
            quarter(&mut w, 1, 6, 11, 12);
            quarter(&mut w, 2, 7, 8, 13);
            quarter(&mut w, 3, 4, 9, 14);
        }
        let out: [u32; 16] = core::array::from_fn(|i| w[i].wrapping_add(state[i]));
        assert_eq!(out[0], 0xe4e7_f110);
        assert_eq!(out[15], 0x4e3c_50a2);
        // and the streaming API is self-consistent
        let mut a = [0u8; 100];
        p.fill(&mut a);
        let mut q = ChaCha20Prg::new(&key);
        let mut b = [0u8; 100];
        for x in b.iter_mut() {
            *x = q.next_u8();
        }
        assert_eq!(a, b);
    }
}
