// Licensed under the Apache-2.0 license
//! Aloha PSK protocol v3 plus v4 scale/refresh; compiled only with fhe-aloha.
//! Kept separate from session.rs because the legacy firmware embeds panic line
//! numbers: any shared-file edit changes its image. Security/protocol fixes
//! must be reviewed in both service implementations.
use crate::{fhe_transport::Transport, Drivers};
use caliptra_drivers::memory_layout::MBOX_ORG;
use caliptra_drivers::{AesKey, CaliptraError, CaliptraResult};
use caliptra_registers::mbox::enums::MboxStatusE;
use zerocopy::IntoBytes;
use zeroize::{Zeroize, Zeroizing};
#[cfg(feature = "ml-clear")]
#[path = "model.rs"]
mod model;
#[cfg(any(feature = "fhe-debug", feature = "fhe-pl", feature = "fhe-pleq"))]
compile_error!("fhe-psk supports P-S only and must not be combined with raw debug commands");
const INVALID: CaliptraError = CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS;
const PSK: [u8; 32] = [
    0xa7, 0xb1, 0xc3, 0xd5, 0xe7, 0xf9, 0x01, 0x24, 0x36, 0x48, 0x5a, 0x6c, 0x7e, 0x90, 0xa2, 0xb4,
    0xc6, 0xd8, 0xea, 0xf1, 0x03, 0x15, 0x27, 0x49, 0x61, 0x73, 0x85, 0x97, 0xa9, 0xbb, 0xcd, 0xdf,
];
const BUFFER_WORDS: usize = 2048;
const WORK_WORDS: usize = 8192;
const PARAM_ID: u32 = 0xa108;
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
    transport: Transport<()>,
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
            transport: Transport::session(1_000_000),
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
/// Only owned metadata survives Packet; payload is copied after its references die.
pub struct Request {
    bytes: [u8; 88],
    open: bool,
    input: usize,
    output: usize,
    src: u64,
    dst: u64,
    pointer: bool,
}
impl Request {
    pub fn parse(id: u32, b: &[u8]) -> CaliptraResult<Self> {
        let open = id == OPEN;
        let len = if open { 76 } else { 88 };
        if b.len() < len || !matches!(word(b, 1), 3 | 4) {
            return Err(INVALID);
        }
        let mut bytes = [0; 88];
        bytes[..len].copy_from_slice(&b[..len]);
        if open {
            if b.len() != 76 || word(b, 1) != 3 {
                return Err(INVALID);
            }
            return Ok(Self {
                bytes,
                open,
                input: 0,
                output: 0,
                src: 0,
                dst: 0,
                pointer: false,
            });
        }
        let op = word(b, 2);
        if !(1..=6).contains(&op) || IDS[(op - 1) as usize] != id {
            return Err(INVALID);
        }
        // v3 remains byte-for-byte compatible. v4 adds an authenticated
        // log2(scale) for refresh and decode; no general non-power-of-two scale.
        let version = word(b, 1);
        if (version == 3 && (op == 6 || word(b, 17) != 0))
            || (version == 4 && (!matches!(op, 3 | 6) || !(1..=40).contains(&word(b, 17))))
        {
            return Err(INVALID);
        }
        if op == 4 && !cfg!(feature = "ml-clear") {
            return Err(INVALID);
        }
        let (input, output) = match op {
            2 => (2048, BUFFER_WORDS * 4),
            3 => (BUFFER_WORDS * 4, 2048),
            4 => (196, 40),
            6 => (4096, BUFFER_WORDS * 4),
            _ => (0, 0),
        };
        let mode = word(b, 10);
        let src = (u64::from(word(b, 12)) << 32) | u64::from(word(b, 11));
        let dst = (u64::from(word(b, 14)) << 32) | u64::from(word(b, 13));
        if mode > 1 || word(b, 15) as usize != input || word(b, 16) as usize != output {
            return Err(INVALID);
        }
        // Word 17 is authenticated: reserved in v3, log2(scale) in v4.
        if mode == 0 {
            if src != 0 || dst != 0 || b.len() != len + input {
                return Err(INVALID);
            }
        } else {
            if input == 0 || b.len() != len {
                return Err(INVALID);
            }
            crate::fhe_transport::validate_range(src, input as u64).map_err(|_| INVALID)?;
            crate::fhe_transport::validate_range(dst, output as u64).map_err(|_| INVALID)?;
            if src < dst + output as u64 && dst < src + input as u64 {
                return Err(INVALID);
            }
        }
        Ok(Self {
            bytes,
            open,
            input,
            output,
            src,
            dst,
            pointer: mode == 1,
        })
    }
}
fn open(d: &mut Drivers, r: &Request, header: &mut [u8; 100]) -> CaliptraResult<usize> {
    let s = &mut d.fhe_session;
    if s.active || s.transport.is_poisoned() {
        return Err(INVALID);
    }
    // WIP single-flight open: authenticates policy, but has no server freshness.
    let mut transcript = Zeroizing::new([0u8; 64]);
    transcript[4..60].copy_from_slice(&r.bytes[4..60]);
    let tag = d.aes.cmac(AesKey::Array(&PSK), &transcript[..60])?;
    if !constant_time_eq::constant_time_eq(&tag, &r.bytes[60..76]) {
        return Err(INVALID);
    }
    let supported = if cfg!(feature = "ml-clear") {
        0x5e
    } else {
        0x4e
    };
    if word(&r.bytes, 2) & !supported != 0
        || word(&r.bytes, 4) != PARAM_ID
        || word(&r.bytes, 5) != 2
        || word(&r.bytes, 6) != 0
    {
        return Err(INVALID);
    }
    s.erase();
    s.id = s.id.checked_add(1).ok_or(INVALID)?;
    put(&mut transcript[..], 15, s.id);
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
    header[12..28].copy_from_slice(&d.aes.cmac(AesKey::Array(&PSK), &transcript[..])?);
    put(header, 2, s.id);
    s.policy.copy_from_slice(&r.bytes[8..28]);
    s.active = true;
    caliptra_drivers::cprintln!("FHE PSK WIP: NO OPEN REPLAY PROTECTION");
    Ok(28)
}
fn kernel(
    d: &mut Drivers,
    op: u32,
    log_scale: u32,
    plain: &mut [u32],
    input: &mut [u32],
) -> CaliptraResult<()> {
    let keyed = d.fhe_session.keyed;
    match op {
        1 if keyed => Err(INVALID),
        1 => {
            crate::fhe_aloha::keygen(&mut d.trng)?;
            d.fhe_session.keyed = true;
            Ok(())
        }
        #[cfg(feature = "ml-clear")]
        4 => {
            let pixels = &plain.as_bytes()[..196];
            if pixels.iter().any(|&v| v > 15) {
                return Err(INVALID);
            }
            for k in 0..10 {
                let mut v = model::B[k] as i32;
                for i in 0..196 {
                    v += model::W[k][i] as i32 * pixels[i] as i32;
                }
                input[k] = v as u32;
            }
            Ok(())
        }
        2 | 3 | 6 if !keyed => Err(INVALID),
        2 => crate::fhe_aloha::encrypt(&mut d.trng, plain),
        3 => crate::fhe_aloha::decrypt_with_scale(plain, input, log_scale),
        6 => crate::fhe_aloha::refresh(&mut d.trng, plain),
        // Op 5: erasure follows authenticated response generation. Parse
        // rejects op 4 without ml-clear.
        _ => Ok(()),
    }
}

pub fn execute(d: &mut Drivers, r: Request) -> CaliptraResult<MboxStatusE> {
    let start = cycles();
    let mut header = [0u8; 100];
    // AES handles partial blocks with byte stores. Mailbox SRAM requires word
    // stores, so keep driver output in DCCM until it can be copied as words.
    let mut aes_output = Zeroizing::new([0u32; BUFFER_WORDS]);
    // SAFETY: Packet is dropped, SoC command owns SRAM, no direct mailbox DMA.
    // Header + three reusable payload regions. Aloha uses 32 KiB of existing
    // mailbox, software P-S 16 KiB; no new SRAM bank.
    let work = unsafe { core::slice::from_raw_parts_mut(MBOX_ORG as *mut u32, WORK_WORDS) };
    if !r.open && !r.pointer {
        work.copy_within(22..22 + r.input / 4, 32);
    }
    let result = (|| {
        if r.open {
            return open(d, &r, &mut header);
        }
        let op = word(&r.bytes, 2);
        let seq = word(&r.bytes, 4);
        let s = &d.fhe_session;
        if !s.active
            || s.transport.is_poisoned()
            || word(&r.bytes, 3) != s.id
            || seq != s.next
            || seq == u32::MAX
            || r.bytes[20..40] != s.policy
        {
            return Err(INVALID);
        }
        let (input, rest) = work[32..].split_at_mut(BUFFER_WORDS);
        let (plain, rest) = rest.split_at_mut(BUFFER_WORDS);
        let out = &mut rest[..BUFFER_WORDS];
        if r.pointer {
            d.fhe_session
                .transport
                .with_fifo(&mut d.dma, |t| t.read(r.src, &mut input[..r.input / 4]))
                .map_err(|_| CaliptraError::RUNTIME_FHE_DECRYPT_FAILED)?;
        }
        // Driver may write unverified plaintext; no consumer observes it on failure.
        let auth = d.aes.aes_256_gcm_decrypt(
            &mut d.trng,
            &nonce(seq, 0),
            AesKey::Array(&d.fhe_session.request_key),
            &r.bytes[4..72],
            &input.as_bytes()[..r.input],
            &mut aes_output.as_mut_bytes()[..r.input],
            &r.bytes[72..88],
        );
        if let Err(e) = auth {
            return Err(if e == CaliptraError::RUNTIME_DRIVER_AES_INVALID_TAG {
                INVALID
            } else {
                e
            });
        }
        for i in 0..r.input / 4 {
            // SAFETY: aligned, exclusively owned mailbox workspace.
            unsafe { core::ptr::write_volatile(&mut plain[i], aes_output[i]) };
        }
        aes_output.zeroize();
        let s = &mut d.fhe_session;
        s.next += 1;
        if op != 5 && word(&s.policy, 0) & (1 << op) == 0 {
            return Err(INVALID);
        }
        if op == 3 || op == 4 {
            if s.egress >= word(&s.policy, 1) {
                return Err(INVALID);
            }
            s.egress += 1;
        }
        let log_scale = if word(&r.bytes, 1) == 4 {
            word(&r.bytes, 17)
        } else {
            25
        };
        kernel(d, op, log_scale, plain, input)?;
        header[8..76].copy_from_slice(&r.bytes[4..72]);
        header[76..84].copy_from_slice(&cycles().wrapping_sub(start).to_le_bytes());
        let source = if op == 2 || op == 6 {
            plain.as_bytes()
        } else {
            input.as_bytes()
        };
        let (_, tag) = d.aes.aes_256_gcm_encrypt(
            &mut d.trng,
            (&nonce(seq, 1)).into(),
            AesKey::Array(&d.fhe_session.response_key),
            &header[8..84],
            &source[..r.output],
            &mut aes_output.as_mut_bytes()[..r.output],
            16,
        )?;
        for i in 0..r.output / 4 {
            // SAFETY: aligned, exclusively owned mailbox workspace.
            unsafe { core::ptr::write_volatile(&mut out[i], aes_output[i]) };
        }
        aes_output.zeroize();
        header[84..100].copy_from_slice(&tag);
        if r.pointer {
            d.fhe_session
                .transport
                .with_fifo(&mut d.dma, |t| t.write(r.dst, &out[..r.output / 4]))
                .map_err(|_| CaliptraError::RUNTIME_FHE_ENCRYPT_FAILED)?;
        }
        if op == 5 {
            d.fhe_session.erase();
        }
        Ok(100)
    })();
    if result.is_err() {
        // SAFETY: this synchronous command exclusively owns the AES engine.
        // Driver early-error paths may precede its normal internal zeroization.
        unsafe { caliptra_drivers::Aes::zeroize() };
    }
    // Only encrypted output is retained for DATAIN streaming. Scrub on all errors.
    if let Ok(len) = result {
        let payload = if !r.open && !r.pointer { r.output } else { 0 };
        if payload > 0 {
            work.copy_within(
                32 + 2 * BUFFER_WORDS..32 + 2 * BUFFER_WORDS + payload / 4,
                len / 4,
            );
        }
        work[(len + payload) / 4..].zeroize();
        let sum = caliptra_common::checksum::calc_checksum(0, &header[4..len]).wrapping_add(
            caliptra_common::checksum::calc_checksum(0, &work.as_bytes()[len..len + payload]),
        );
        put(&mut header, 0, sum);
        // End the SRAM borrow before DATAIN overwrites its source.
        if let Err(error) = d.mbox.write_response_from_mailbox(&header[..len], payload) {
            d.fhe_session.erase();
            // SAFETY: no DMA targets mailbox; still exclusively command-owned.
            unsafe { core::slice::from_raw_parts_mut(MBOX_ORG as *mut u32, WORK_WORDS) }.zeroize();
            return Err(error);
        }
        Ok(MboxStatusE::DataReady)
    } else {
        work.zeroize();
        let e = result.unwrap_err();
        if e != INVALID || d.fhe_session.transport.is_poisoned() {
            d.fhe_session.erase();
        }
        Err(e)
    }
}
