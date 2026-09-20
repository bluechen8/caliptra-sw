/*++

Licensed under the Apache-2.0 license.

File Name:

    format.rs

Abstract:

    The wire formats of plan §4.1: the wrapped-blob header, and the
    little-endian `u32` polynomial layout shared by firmware, the Rocket
    orchestrator, the Python user tool and the Go evaluation server.

    Parsing here is deliberately total: every field is range-checked against
    the parameter set before any payload is touched (plan §9, "every new
    mailbox command validates session_id, seq, sizes against N/L, and pointer
    ranges before touching data").  The AES-GCM tag is checked by the caller,
    which owns the key; this module never sees key material.

--*/

use crate::params::ParamSet;
use crate::{Error, Result};

/// `'FHEB'` little-endian.
pub const MAGIC: u32 = 0x4245_4846;
/// The only blob version this build understands.
pub const VER: u16 = 1;
/// Bytes in a blob header, including `iv` and `tag`.
pub const HDR_LEN: usize = 56;
/// Bytes of the header that are authenticated as AAD (everything but `iv`/`tag`).
pub const AAD_LEN: usize = 28;
/// Offset of the 12-byte IV inside the header.
pub const IV_OFF: usize = 28;
/// Offset of the 16-byte GCM tag inside the header.
pub const TAG_OFF: usize = 40;

/// Payload encodings (plan §4.1).
pub mod enc {
    /// `L` limbs of `N` `u32`, coefficient domain.
    pub const POLY_INT_32: u16 = 1;
    /// Slot vector of `f64` -- accelerator branch only, never accepted here.
    pub const SLOTS_F64: u16 = 2;
    /// 196 pixels, values 0..15.
    pub const PIXELS_U8: u16 = 3;
    /// 10 `i32` logits.
    pub const LOGITS_I32: u16 = 4;
}

/// Operations, used both as the header `op` field and as bit indices in the
/// session policy's `allowed_ops` bitmap.
pub mod op {
    /// No operation.
    pub const NONE: u16 = 0;
    /// Unwrap then encrypt (`FHE_INGRESS`).
    pub const INGRESS: u16 = 1;
    /// Decrypt then wrap (`FHE_EGRESS`).
    pub const EGRESS: u16 = 2;
    /// Cleartext model evaluation (`ML_INFER_CLEAR`).
    pub const INFER_CLEAR: u16 = 3;
}

/// IV direction bit: user -> Caliptra.
pub const DIR_TO_CALIPTRA: u8 = 0;
/// IV direction bit: Caliptra -> user.
pub const DIR_FROM_CALIPTRA: u8 = 1;

/// A parsed, range-checked blob header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobHdr {
    /// Payload encoding, one of [`enc`].
    pub enc: u16,
    /// Session this blob belongs to.
    pub session_id: u32,
    /// Monotonic sequence number; Caliptra rejects `seq <= last_seq`.
    pub seq: u32,
    /// `log2(N)` the sender used.
    pub log2n: u16,
    /// Number of RNS limbs.
    pub limbs: u16,
    /// Remaining multiplicative level.
    pub level: u16,
    /// Operation, one of [`op`].
    pub op: u16,
    /// Ciphertext length in bytes, excluding the header.
    pub payload_len: u32,
}

#[inline(always)]
fn rd16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

#[inline(always)]
fn rd32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

impl BlobHdr {
    /// Parse and validate a header against the active parameter set.
    ///
    /// Rejects: a wrong magic or version, `SLOTS_F64` (that encoding needs
    /// floating point, which plan §9 forbids on Caliptra), a `log2n`/`L` that
    /// disagrees with `ps`, a payload longer than the buffer, and a
    /// `payload_len` that does not match the encoding's fixed size.
    pub fn parse(buf: &[u8], ps: &ParamSet) -> Result<Self> {
        if buf.len() < HDR_LEN {
            return Err(Error::BadLength);
        }
        if rd32(buf, 0) != MAGIC || rd16(buf, 4) != VER {
            return Err(Error::BadHeader);
        }
        let h = BlobHdr {
            enc: rd16(buf, 6),
            session_id: rd32(buf, 8),
            seq: rd32(buf, 12),
            log2n: rd16(buf, 16),
            limbs: rd16(buf, 18),
            level: rd16(buf, 20),
            op: rd16(buf, 22),
            payload_len: rd32(buf, 24),
        };
        if h.enc == enc::SLOTS_F64 || h.enc == 0 || h.enc > enc::LOGITS_I32 {
            return Err(Error::BadHeader);
        }
        if h.log2n as u32 != ps.log_n || h.limbs as usize != ps.level {
            return Err(Error::BadHeader);
        }
        if h.level as usize > ps.level {
            return Err(Error::BadHeader);
        }
        let want = match h.enc {
            enc::POLY_INT_32 => ps.pt_bytes(),
            enc::PIXELS_U8 => crate::format::PIXELS_LEN,
            enc::LOGITS_I32 => crate::format::LOGITS_LEN,
            _ => return Err(Error::BadHeader),
        };
        if h.payload_len as usize != want {
            return Err(Error::BadHeader);
        }
        if buf.len() < HDR_LEN + want {
            return Err(Error::BadLength);
        }
        Ok(h)
    }

    /// Serialize the authenticated part of the header (the GCM AAD).
    pub fn write_aad(&self, out: &mut [u8]) -> Result<()> {
        if out.len() < AAD_LEN {
            return Err(Error::BadLength);
        }
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&VER.to_le_bytes());
        out[6..8].copy_from_slice(&self.enc.to_le_bytes());
        out[8..12].copy_from_slice(&self.session_id.to_le_bytes());
        out[12..16].copy_from_slice(&self.seq.to_le_bytes());
        out[16..18].copy_from_slice(&self.log2n.to_le_bytes());
        out[18..20].copy_from_slice(&self.limbs.to_le_bytes());
        out[20..22].copy_from_slice(&self.level.to_le_bytes());
        out[22..24].copy_from_slice(&self.op.to_le_bytes());
        out[24..28].copy_from_slice(&self.payload_len.to_le_bytes());
        Ok(())
    }

    /// Reject a replayed or reordered blob (plan §4.1).
    pub fn check_seq(&self, last_seq: u32) -> Result<()> {
        if self.seq <= last_seq {
            return Err(Error::StaleSeq);
        }
        Ok(())
    }
}

/// `iv_salt(32b) || direction(1b) || counter(63b)`, 12 bytes (plan §4.1).
pub fn make_iv(iv_salt: u32, direction: u8, counter: u64, out: &mut [u8; 12]) {
    out[0..4].copy_from_slice(&iv_salt.to_le_bytes());
    let w = ((direction as u64) << 63) | (counter & ((1u64 << 63) - 1));
    out[4..12].copy_from_slice(&w.to_le_bytes());
}

/// Bytes in a `PIXELS_U8` payload (plan §2.11: MNIST 14x14).
pub const PIXELS_LEN: usize = 196;
/// Bytes in a `LOGITS_I32` payload (10 classes).
pub const LOGITS_LEN: usize = 40;

/// Read a little-endian `u32` polynomial into `out`.
pub fn words_from_le(buf: &[u8], out: &mut [u32]) -> Result<()> {
    if buf.len() != out.len() * 4 {
        return Err(Error::BadLength);
    }
    for (i, o) in out.iter_mut().enumerate() {
        *o = rd32(buf, 4 * i);
    }
    Ok(())
}

/// Write a `u32` polynomial as little-endian bytes.
pub fn le_from_words(words: &[u32], out: &mut [u8]) -> Result<()> {
    if out.len() != words.len() * 4 {
        return Err(Error::BadLength);
    }
    for (i, w) in words.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    Ok(())
}

/// Word offset of limb `i` of `c0` inside a serialized ciphertext.
pub const fn c0_limb_off(ps: &ParamSet, i: usize) -> usize {
    i * ps.n
}

/// Word offset of limb `i` of `c1` inside a serialized ciphertext.
pub const fn c1_limb_off(ps: &ParamSet, i: usize) -> usize {
    (ps.level + i) * ps.n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params;

    fn hdr(ps: &ParamSet) -> BlobHdr {
        BlobHdr {
            enc: enc::POLY_INT_32,
            session_id: 0xdead_beef,
            seq: 7,
            log2n: ps.log_n as u16,
            limbs: ps.level as u16,
            level: ps.level as u16 - 1,
            op: op::INGRESS,
            payload_len: ps.pt_bytes() as u32,
        }
    }

    fn buf(ps: &ParamSet, h: &BlobHdr) -> Vec<u8> {
        let mut b = vec![0u8; HDR_LEN + ps.pt_bytes()];
        h.write_aad(&mut b).unwrap();
        b
    }

    #[test]
    fn round_trip() {
        let ps = &params::PS;
        let h = hdr(ps);
        let b = buf(ps, &h);
        assert_eq!(BlobHdr::parse(&b, ps).unwrap(), h);
    }

    #[test]
    fn rejects_floating_point_encoding() {
        let ps = &params::PS;
        let mut h = hdr(ps);
        h.enc = enc::SLOTS_F64;
        let b = buf(ps, &h);
        assert_eq!(BlobHdr::parse(&b, ps), Err(Error::BadHeader));
    }

    #[test]
    fn rejects_wrong_parameters() {
        let ps = &params::PS;
        let mut h = hdr(ps);
        h.log2n += 1;
        assert_eq!(BlobHdr::parse(&buf(ps, &h), ps), Err(Error::BadHeader));

        let mut h = hdr(ps);
        h.limbs += 1;
        assert_eq!(BlobHdr::parse(&buf(ps, &h), ps), Err(Error::BadHeader));

        let mut h = hdr(ps);
        h.payload_len += 4;
        assert_eq!(BlobHdr::parse(&buf(ps, &h), ps), Err(Error::BadHeader));
    }

    #[test]
    fn rejects_truncated_payload() {
        let ps = &params::PS;
        let h = hdr(ps);
        let mut b = buf(ps, &h);
        b.truncate(HDR_LEN + 4);
        assert_eq!(BlobHdr::parse(&b, ps), Err(Error::BadLength));
    }

    #[test]
    fn seq_must_advance() {
        let ps = &params::PS;
        let h = hdr(ps);
        assert!(h.check_seq(6).is_ok());
        assert_eq!(h.check_seq(7), Err(Error::StaleSeq));
        assert_eq!(h.check_seq(9), Err(Error::StaleSeq));
    }

    #[test]
    fn iv_layout() {
        let mut iv = [0u8; 12];
        make_iv(0x0badc0de, DIR_FROM_CALIPTRA, 1, &mut iv);
        assert_eq!(&iv[0..4], &0x0badc0deu32.to_le_bytes());
        assert_eq!(iv[11] & 0x80, 0x80);
    }
}
