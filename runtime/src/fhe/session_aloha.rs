// Licensed under the Apache-2.0 license
//! Aloha PSK open v6, command v5 (docs/fhe/16-register-map-v2.md, "Session
//! protocol on the DMA path"); compiled only with fhe-aloha. The software
//! backend (session.rs) keeps v3/v4; OPEN is shared, so open fixes must be
//! reviewed in both service implementations.
//!
//! Only Rocket sends mailbox commands, and it is trusted for integrity but
//! must not see plaintext. Headers are in clear and unauthenticated. The
//! ENCRYPT message is GCM-sealed under the request key and checked by its tag
//! before Aloha commits it; the DECRYPT output is GCM-sealed under the
//! response key by the DMA. FHE ciphertexts bypass AES. Bulk data stays in
//! DRAM: VeeR never reads it.
use crate::fhe_aloha::Done;
use crate::Drivers;
use caliptra_drivers::{AesKey, CaliptraError, CaliptraResult};
use caliptra_registers::mbox::enums::MboxStatusE;
use zeroize::{Zeroize, Zeroizing};
#[cfg(any(feature = "fhe-debug", feature = "fhe-pl", feature = "fhe-pleq"))]
compile_error!("fhe-psk supports P-S only and must not be combined with raw debug commands");
const INVALID: CaliptraError = CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS;
const PSK: [u8; 32] = [
    0xa7, 0xb1, 0xc3, 0xd5, 0xe7, 0xf9, 0x01, 0x24, 0x36, 0x48, 0x5a, 0x6c, 0x7e, 0x90, 0xa2, 0xb4,
    0xc6, 0xd8, 0xea, 0xf1, 0x03, 0x15, 0x27, 0x49, 0x61, 0x73, 0x85, 0x97, 0xa9, 0xbb, 0xcd, 0xdf,
];
const VERSION: u32 = 5;
const REQUEST_BYTES: usize = 64;
const RESPONSE_BYTES: usize = 44;
const OPEN_BYTES: usize = 76;
const OPEN_RESPONSE_BYTES: usize = 60;
const KEYGEN: u32 = 1;
const ENCRYPT: u32 = 2;
const DECRYPT: u32 = 3;
const CLOSE: u32 = 5;
const REFRESH: u32 = 6;
/// Aloha profile: 0xa100 | log2(N) of the engine's build.
const PARAM_ID_BASE: u32 = 0xa100;
const OPEN: u32 = 0x4648534f;
const IDS: [u32; 6] = [
    0x46484b47, 0x4648494e, 0x46484547, 0x4d4c4943, 0x46485343, 0x46485246,
];
fn word(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap())
}
fn put(b: &mut [u8], i: usize, v: u32) {
    b[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
}
fn nonce(seq: u32, direction: u32) -> [u8; 12] {
    let mut n = [0; 12];
    put(&mut n, 0, direction);
    put(&mut n, 1, seq);
    n
}
fn cycles() -> u64 {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        let (mut h, mut l, mut e): (u32, u32, u32);
        loop {
            core::arch::asm!("csrr {0}, mcycleh", "csrr {1}, mcycle", "csrr {2}, mcycleh",out(reg) h,out(reg) l,out(reg) e,options(nomem,nostack));
            if h == e {
                return (u64::from(h) << 32) | u64::from(l);
            }
        }
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        0
    }
}
pub struct State {
    id: u32,
    active: bool,
    request_key: [u8; 32],
    response_key: [u8; 32],
    policy: [u8; 20],
    next: u32,
    egress: u32,
    keyed: bool,
}
impl State {
    pub fn new() -> Self {
        Self {
            id: 0,
            active: false,
            request_key: [0; 32],
            response_key: [0; 32],
            policy: [0; 20],
            next: 1,
            egress: 0,
            keyed: false,
        }
    }
    fn erase(&mut self) {
        crate::fhe_aloha::clear();
        self.active = false;
        self.request_key.zeroize();
        self.response_key.zeroize();
        self.policy.zeroize();
        self.keyed = false;
        self.next = 1;
        self.egress = 0;
    }
}
impl Drop for State {
    fn drop(&mut self) {
        self.erase();
    }
}
pub fn handles(id: u32) -> bool {
    id == OPEN || IDS.contains(&id)
}
/// Only owned metadata survives Packet.
pub struct Request {
    bytes: [u8; OPEN_BYTES],
    open: bool,
    src: u64,
    dst: u64,
    /// ENCRYPT / REFRESH output level, chosen by the orchestrator (Rocket).
    level: u32,
    /// The engine's geometry, read once per request (unset for OPEN).
    g: crate::fhe_aloha::Geometry,
}
impl Request {
    pub fn parse(id: u32, b: &[u8]) -> CaliptraResult<Self> {
        let open = id == OPEN;
        let len = if open { OPEN_BYTES } else { REQUEST_BYTES };
        if b.len() != len {
            return Err(INVALID);
        }
        let mut bytes = [0; OPEN_BYTES];
        bytes[..len].copy_from_slice(b);
        if open {
            if word(b, 1) != 6 {
                return Err(INVALID);
            }
            return Ok(Self {
                bytes,
                open,
                src: 0,
                dst: 0,
                level: 0,
                g: Default::default(),
            });
        }
        let op = word(b, 2);
        if word(b, 1) != VERSION || !(1..=6).contains(&op) || IDS[(op - 1) as usize] != id {
            return Err(INVALID);
        }
        // Word 11: [7:0] log2 of the decode scale (DECRYPT, REFRESH),
        // [11:8] output level (ENCRYPT, REFRESH), the rest zero.
        let g = crate::fhe_aloha::geometry().map_err(|_| INVALID)?;
        let log_scale = word(b, 11) & 0xff;
        let level = word(b, 11) >> 8;
        let leveled = matches!(op, ENCRYPT | REFRESH);
        if leveled != g.level_ok(level) || (!leveled && level != 0) {
            return Err(INVALID);
        }
        let (input, output) = match op {
            KEYGEN | CLOSE => (0, 0),
            ENCRYPT => (g.message_bytes(), g.ciphertext_bytes(level)),
            DECRYPT => (g.q0_bytes(), g.message_bytes()),
            REFRESH => (g.q0_bytes(), g.ciphertext_bytes(level)),
            _ => return Err(INVALID),
        };
        let src = (u64::from(word(b, 6)) << 32) | u64::from(word(b, 5));
        let dst = (u64::from(word(b, 8)) << 32) | u64::from(word(b, 7));
        let scaled = matches!(op, DECRYPT | REFRESH);
        if word(b, 9) as usize != input
            || word(b, 10) as usize != output
            || scaled != (1..=40).contains(&log_scale)
            || (!scaled && log_scale != 0)
            || (op != ENCRYPT && b[48..64].iter().any(|&v| v != 0))
        {
            return Err(INVALID);
        }
        if input == 0 {
            if src != 0 || dst != 0 {
                return Err(INVALID);
            }
        } else {
            // Aloha's slots need 16-byte alignment.
            for (addr, n) in [(src, input), (dst, output)] {
                crate::fhe_transport::validate_range(addr, n as u64).map_err(|_| INVALID)?;
                if addr & 15 != 0 {
                    return Err(INVALID);
                }
            }
            if src < dst + output as u64 && dst < src + input as u64 {
                return Err(INVALID);
            }
        }
        Ok(Self {
            bytes,
            open,
            src,
            dst,
            level,
            g,
        })
    }
}
fn open(d: &mut Drivers, r: &Request, header: &mut [u8; OPEN_RESPONSE_BYTES]) -> CaliptraResult<usize> {
    let s = &mut d.fhe_session;
    if s.active {
        return Err(INVALID);
    }
    // Domain-separated v6 request, session ID and fresh server nonce are all
    // authenticated by the confirmation and bound into both traffic keys.
    let mut transcript = Zeroizing::new([0u8; 96]);
    transcript[4..60].copy_from_slice(&r.bytes[4..60]);
    let tag = d.aes.cmac(AesKey::Array(&PSK), &transcript[..60])?;
    if !constant_time_eq::constant_time_eq(&tag, &r.bytes[60..76]) {
        return Err(INVALID);
    }
    // KEYGEN, ENCRYPT, DECRYPT, REFRESH.
    let supported = 0x4e;
    if word(&r.bytes, 2) & !supported != 0
        || word(&r.bytes, 4) != PARAM_ID_BASE | crate::fhe_aloha::geometry()?.logn
        || word(&r.bytes, 5) != 2
        || word(&r.bytes, 6) != 0
    {
        return Err(INVALID);
    }
    s.erase();
    s.id = s.id.checked_add(1).ok_or(INVALID)?;
    put(&mut transcript[..], 15, s.id);
    for chunk in transcript[64..96].chunks_exact_mut(16) {
        let (a, b, c, e) = d.trng.generate4()?;
        for (dest, value) in chunk.chunks_exact_mut(4).zip([a, b, c, e]) {
            dest.copy_from_slice(&value.to_le_bytes());
        }
    }
    header[12..44].copy_from_slice(&transcript[64..96]);
    for i in 1..=4 {
        put(&mut transcript[..], 0, i);
        let mut key = d.aes.cmac(AesKey::Array(&PSK), &transcript[..])?;
        let dest = if i <= 2 {
            &mut s.request_key
        } else {
            &mut s.response_key
        };
        let offset = ((i - 1) % 2 * 16) as usize;
        dest[offset..offset + 16].copy_from_slice(&key);
        key.zeroize();
    }
    put(&mut transcript[..], 0, 5);
    header[44..60].copy_from_slice(&d.aes.cmac(AesKey::Array(&PSK), &transcript[..])?);
    put(header, 2, s.id);
    s.policy.copy_from_slice(&r.bytes[8..28]);
    s.active = true;
    Ok(OPEN_RESPONSE_BYTES)
}
/// Runs an authorized data command; `Ok` carries how the engine ended.
fn kernel(d: &mut Drivers, r: &Request, op: u32, seq: u32) -> CaliptraResult<Done> {
    let s = &d.fhe_session;
    let log_scale = word(&r.bytes, 11) & 0xff;
    Ok(match op {
        KEYGEN => {
            // After DisableAttestation the RT CDI is a public constant, so a
            // seed derived from it would depend only on the visible nonce.
            if d.persistent_data.get().attestation_disabled.get() {
                return Err(CaliptraError::RUNTIME_FHE_ATTESTATION_DISABLED);
            }
            let rt_cdi = Drivers::get_key_id_rt_cdi(d)?;
            crate::fhe_aloha::keygen(r.g, &mut d.hmac, &mut d.trng, &mut d.key_vault, rt_cdi)?;
            Done::ok(true)
        }
        ENCRYPT => {
            let tag: [u8; 16] = r.bytes[48..64].try_into().unwrap();
            crate::fhe_aloha::encrypt(
                r.g,
                &mut d.aes,
                &mut d.trng,
                &s.request_key,
                &nonce(seq, 0),
                &tag,
                r.level,
                r.src,
                r.dst,
            )?
        }
        DECRYPT => crate::fhe_aloha::decrypt(
            r.g,
            &mut d.aes,
            &mut d.trng,
            &s.response_key,
            &nonce(seq, 1),
            log_scale,
            r.src,
            r.dst,
        )?,
        _ => crate::fhe_aloha::refresh(r.g, r.level, r.src, r.dst)?,
    })
}

pub fn execute(d: &mut Drivers, r: Request) -> CaliptraResult<MboxStatusE> {
    let start = cycles();
    let mut header = Zeroizing::new([0u8; OPEN_RESPONSE_BYTES]);
    let result = (|| {
        if r.open {
            return open(d, &r, &mut header);
        }
        let op = word(&r.bytes, 2);
        let seq = word(&r.bytes, 4);
        let s = &mut d.fhe_session;
        // Checks that leave the sequence number unconsumed.
        if !s.active || word(&r.bytes, 3) != s.id || seq != s.next || seq == u32::MAX {
            return Err(INVALID);
        }
        if op != CLOSE && word(&s.policy, 0) & (1 << op) == 0 {
            return Err(INVALID);
        }
        if (op == KEYGEN) == s.keyed && op != CLOSE {
            return Err(INVALID);
        }
        if op == DECRYPT {
            if s.egress >= word(&s.policy, 1) {
                return Err(INVALID);
            }
            s.egress += 1;
        }
        s.next += 1;
        let done = if op == CLOSE {
            Done::ok(false)
        } else {
            kernel(d, &r, op, seq)?
        };
        // A tag mismatch or abort drops the resident key; KEYGEN may follow.
        d.fhe_session.keyed = done.key_valid;
        put(&mut header[..], 2, d.fhe_session.id);
        put(&mut header[..], 3, seq);
        put(&mut header[..], 4, done.cause);
        header[20..28].copy_from_slice(&cycles().wrapping_sub(start).to_le_bytes());
        header[28..44].copy_from_slice(&done.tag);
        if op == CLOSE {
            d.fhe_session.erase();
        }
        Ok(RESPONSE_BYTES)
    })();
    match result {
        Ok(len) => {
            let sum = caliptra_common::checksum::calc_checksum(0, &header[4..len]);
            put(&mut header[..], 0, sum);
            d.mbox.write_response(&header[..len])?;
            Ok(MboxStatusE::DataReady)
        }
        Err(e) => {
            // SAFETY: this synchronous command exclusively owns the AES engine.
            // Driver early-error paths may precede its normal internal zeroization.
            unsafe { caliptra_drivers::Aes::zeroize() };
            if e != INVALID {
                d.fhe_session.erase();
            }
            Err(e)
        }
    }
}
