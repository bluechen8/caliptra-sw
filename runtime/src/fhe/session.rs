// Licensed under the Apache-2.0 license
//! P-S protected protocol v5. Rocket schedules plain commands; only user input
//! blobs and result blobs are sealed. See software/fhe/RUNTIME.md in the wrapper.
use crate::{fhe_transport::Transport, Drivers};
use caliptra_drivers::memory_layout::MBOX_ORG;
use caliptra_drivers::{CaliptraError, CaliptraResult};
use caliptra_fhe_core::{evalkey, ntt, params::PS, prg::ChaCha20Prg, rlwe, sample};
use caliptra_registers::mbox::enums::MboxStatusE;
use zerocopy::IntoBytes;
use zeroize::{Zeroize, Zeroizing};
#[cfg(feature = "ml-clear")]
#[path = "model.rs"]
mod model;
/// Session-open profile: `open`, `session_key` and `erase_keys`.
#[cfg_attr(feature = "fhe-ecdh", path = "ecdh.rs")]
#[cfg_attr(feature = "fhe-test-key", path = "testkey.rs")]
mod profile;
use profile::session_key;
const INVALID: CaliptraError = CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS;
const VERSION: u32 = 5;
const OPEN_LEN: usize = if cfg!(feature = "fhe-ecdh") { 136 } else { 8 };
/// Open response (268 B ECDH, 12 B test key) or the 16-B command response.
const HEADER_LEN: usize = if cfg!(feature = "fhe-ecdh") { 268 } else { 16 };
const COMMAND_LEN: usize = 48;
const RESPONSE_LEN: usize = 16;
const REQUEST_LEN: usize = if OPEN_LEN > COMMAND_LEN {
    OPEN_LEN
} else {
    COMMAND_LEN
};
/// Sealed blob: header (version, session, op, counter, length), body, tag.
const BLOB_HEADER: usize = 20;
const TAG: usize = 16;
const OPEN: u32 = 0x4648534f;
const IDS: [u32; 7] = [
    0x46484b47, 0x4648494e, 0x46484547, 0x4d4c4943, 0x46485343, 0x46485254, 0x4648524c,
];
/// Workspace base in mailbox words: inputs start right after the command.
const BASE: usize = COMMAND_LEN / 4;
/// Bytes of one evaluation key: every row, as one key command exports them.
const KEY_BYTES: usize = evalkey::ROWS * evalkey::ROW_WORDS * 4;
/// Mailbox words used and scrubbed: input, plaintext/output, 2-KiB scratch.
const WORK: usize = BASE + 2 * 1024 + 512;
const fn blob(body: usize) -> usize {
    BLOB_HEADER + body + TAG
}
/// Ops 2 and 4 take a user blob; ops 3 and 4 return a result blob.
const fn sealed_in(op: u32) -> bool {
    op == 2 || op == 4
}
const fn sealed_out(op: u32) -> bool {
    op == 3 || op == 4
}
fn word(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap())
}
fn put(b: &mut [u8], i: usize, v: u32) {
    b[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
}
fn nonce(counter: u32, direction: u32) -> [u8; 12] {
    let mut n = [0; 12];
    put(&mut n, 0, direction);
    put(&mut n, 1, counter);
    n
}
/// Word-store copy: mailbox SRAM has no byte write enables.
fn copy_words(dst: &mut [u32], src: &[u32]) {
    for (d, &s) in dst.iter_mut().zip(src) {
        // SAFETY: aligned, exclusively owned workspace word.
        unsafe { core::ptr::write_volatile(d, s) };
    }
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
    #[cfg(feature = "fhe-ecdh")]
    crypto_failed: bool,
    id: u32,
    active: bool,
    /// Next result-blob counter, never reused (0 is the ECDH open confirmation).
    counter: u32,
    secret: [u8; 64],
    keyed: bool,
    transport: Transport<()>,
}
impl State {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "fhe-ecdh")]
            crypto_failed: false,
            id: 0,
            active: false,
            counter: 1,
            secret: [0; 64],
            keyed: false,
            transport: Transport::session(1_000_000),
        }
    }
    fn erase(&mut self) {
        self.active = false;
        self.secret.zeroize();
        self.keyed = false;
        self.counter = 1;
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
    bytes: [u8; REQUEST_LEN],
    /// 0 for session open, else 1..7.
    op: u32,
    arg: u32,
    input: usize,
    output: usize,
    src: u64,
    dst: u64,
    pointer: bool,
}
impl Request {
    pub fn parse(id: u32, b: &[u8]) -> CaliptraResult<Self> {
        let open = id == OPEN;
        let len = if open { OPEN_LEN } else { COMMAND_LEN };
        if b.len() < len || word(b, 1) != VERSION {
            return Err(INVALID);
        }
        let mut bytes = [0; REQUEST_LEN];
        bytes[..len].copy_from_slice(&b[..len]);
        // Built once; an open keeps op 0 and the zero transport fields.
        let mut r = Self {
            bytes,
            op: 0,
            arg: 0,
            input: 0,
            output: 0,
            src: 0,
            dst: 0,
            pointer: false,
        };
        if open {
            return if b.len() == OPEN_LEN {
                Ok(r)
            } else {
                Err(INVALID)
            };
        }
        let op = word(b, 2);
        if !(1..=7).contains(&op)
            || IDS[(op - 1) as usize] != id
            || (op == 4 && !cfg!(feature = "ml-clear"))
            || (op >= 6 && !cfg!(feature = "fhe-eval-keys"))
        {
            return Err(INVALID);
        }
        let (input, output) = match op {
            2 => (blob(2048), 4096),
            3 => (4096, blob(2048)),
            4 => (blob(196), blob(40)),
            6 | 7 => (0, KEY_BYTES),
            _ => (0, 0),
        };
        let mode = word(b, 4);
        let src = (u64::from(word(b, 6)) << 32) | u64::from(word(b, 5));
        let dst = (u64::from(word(b, 8)) << 32) | u64::from(word(b, 7));
        let arg = word(b, 11);
        // Keys: arg is the Galois element; op 6 needs one, op 7 (relin) uses 0.
        let key = op >= 6;
        let arg_ok = if key {
            (op == 7) == (arg == 0) && evalkey::valid(arg)
        } else {
            arg == 0
        };
        if mode > 1
            || !arg_ok
            || (key && mode != 1)
            || word(b, 9) as usize != input
            || word(b, 10) as usize != output
        {
            return Err(INVALID);
        }
        if mode == 0 {
            if src != 0 || dst != 0 || b.len() != len + input {
                return Err(INVALID);
            }
        } else {
            // Controls have no payload and use mode 0.
            if output == 0 || b.len() != len {
                return Err(INVALID);
            }
            if input == 0 {
                if src != 0 {
                    return Err(INVALID);
                }
            } else {
                crate::fhe_transport::validate_range(src, input as u64).map_err(|_| INVALID)?;
            }
            crate::fhe_transport::validate_range(dst, output as u64).map_err(|_| INVALID)?;
            if input != 0 && src < dst + output as u64 && dst < src + input as u64 {
                return Err(INVALID);
            }
        }
        r.op = op;
        r.arg = arg;
        r.input = input;
        r.output = output;
        r.src = src;
        r.dst = dst;
        r.pointer = mode == 1;
        Ok(r)
    }
}
fn fresh_prg(d: &mut Drivers) -> CaliptraResult<ChaCha20Prg> {
    let entropy = Zeroizing::new(d.trng.generate()?);
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&entropy.as_bytes()[..32]);
    Ok(ChaCha20Prg::new(&seed))
}
/// Authenticate a user blob for `op` and copy its body into `plain`.
fn open_blob(
    d: &mut Drivers,
    op: u32,
    blob: &[u32],
    plain: &mut [u32],
    aes_output: &mut [u32; 512],
) -> CaliptraResult<()> {
    let n = plain.len() * 4;
    let (header, rest) = blob.as_bytes().split_at(BLOB_HEADER);
    let (body, tag) = rest.split_at(n);
    if word(header, 0) != VERSION
        || word(header, 1) != d.fhe_session.id
        || word(header, 2) != op
        || word(header, 4) as usize != n
    {
        return Err(INVALID);
    }
    // Any user counter is accepted: a replay only re-encrypts the same data.
    // The caller's Zeroizing buffer scrubs aes_output on every exit.
    let auth = d.aes.aes_256_gcm_decrypt(
        &mut d.trng,
        &nonce(word(header, 3), 0),
        session_key(false),
        header,
        body,
        &mut aes_output.as_mut_bytes()[..n],
        tag,
    );
    if let Err(e) = auth {
        return Err(if e == CaliptraError::RUNTIME_DRIVER_AES_INVALID_TAG {
            INVALID
        } else {
            e
        });
    }
    copy_words(plain, &aes_output[..]);
    Ok(())
}
/// Seal `plain` to the user as a result blob in `out`.
fn seal_blob(
    d: &mut Drivers,
    op: u32,
    plain: &[u32],
    out: &mut [u32],
    aes_output: &mut [u32; 512],
) -> CaliptraResult<()> {
    let s = &mut d.fhe_session;
    let counter = s.counter;
    if counter == u32::MAX {
        return Err(INVALID);
    }
    // Consumed before sealing, so no failure path can reuse a nonce.
    s.counter += 1;
    let n = plain.len() * 4;
    let header = [VERSION, s.id, op, counter, n as u32];
    let (_, tag) = d.aes.aes_256_gcm_encrypt(
        &mut d.trng,
        (&nonce(counter, 1)).into(),
        session_key(true),
        header.as_bytes(),
        plain.as_bytes(),
        &mut aes_output.as_mut_bytes()[..n],
        TAG,
    )?;
    let (head, rest) = out.split_at_mut(5);
    let (body, rest) = rest.split_at_mut(n / 4);
    copy_words(head, &header);
    copy_words(body, &aes_output[..]);
    let tag: [u32; 4] = zerocopy::transmute!(tag);
    copy_words(rest, &tag);
    Ok(())
}
/// Ops 1-4. Unsealed input (the egress ciphertext) is read from `input`; sealed
/// input has been opened into `plain`. Every output is left in `plain`.
#[inline(never)]
fn kernel(
    d: &mut Drivers,
    op: u32,
    plain: &mut [u32],
    input: &[u32],
    scratch: &mut [u32],
) -> CaliptraResult<()> {
    if op == 1 {
        if d.fhe_session.keyed {
            return Err(INVALID);
        }
        let mut prg = fresh_prg(d)?;
        let s = &mut d.fhe_session;
        rlwe::keygen(&mut prg, 256, &mut s.secret).map_err(|_| INVALID)?;
        s.keyed = true;
        return Ok(());
    }
    #[cfg(feature = "ml-clear")]
    if op == 4 {
        let pixels = &plain.as_bytes()[..196];
        if pixels.iter().any(|&v| v > 15) {
            return Err(INVALID);
        }
        let mut logits = [0u32; 10];
        for (k, logit) in logits.iter_mut().enumerate() {
            let mut v = model::B[k] as i32;
            for i in 0..196 {
                v += model::W[k][i] as i32 * pixels[i] as i32;
            }
            *logit = v as u32;
        }
        copy_words(plain, &logits);
        return Ok(());
    }
    // Ingress residues are range-checked by encrypt_limb_in_place.
    if op == 3 {
        for (li, p) in PS.primes.iter().enumerate() {
            for c in [li, li + 2] {
                if input[c * 256..(c + 1) * 256].iter().any(|&v| v >= p.q) {
                    return Err(INVALID);
                }
            }
        }
    }
    let mut prg = fresh_prg(d)?;
    let mut error = Zeroizing::new([0i8; 256]);
    if op == 2 {
        sample::sample_cbd(&mut prg, &mut error[..]);
    }
    let secret_key = &d.fhe_session.secret;
    let (secret, tw) = scratch.split_at_mut(256);
    for (li, p) in PS.primes.iter().enumerate() {
        let limb = li * 256..(li + 1) * 256;
        ntt::gen_twiddles_fwd(256, p, tw).map_err(|_| INVALID)?;
        rlwe::secret_ntt_limb(secret_key, p, tw, secret).map_err(|_| INVALID)?;
        if op == 2 {
            let (c0, c1) = plain.split_at_mut(512);
            let c1 = &mut c1[limb.clone()];
            sample::sample_uniform(&mut prg, p.q, c1);
            rlwe::encrypt_limb_in_place(&mut c0[limb], &error[..], c1, secret, p, tw)
                .map_err(|_| INVALID)?;
        } else {
            let (c0, c1) = input.split_at(512);
            ntt::gen_twiddles_inv(256, p, tw).map_err(|_| INVALID)?;
            rlwe::decrypt_limb(
                &c0[limb.clone()],
                &c1[limb.clone()],
                secret,
                p,
                tw,
                &mut plain[limb],
            )
            .map_err(|_| INVALID)?;
        }
    }
    Ok(())
}
/// Generate one public evaluation key, row by row, in DCCM and DMA each row
/// out from there to consecutive addresses; neither the rows nor any secret
/// intermediate touch mailbox SRAM. Cycles include every row's DMA.
#[cfg(feature = "fhe-eval-keys")]
#[inline(never)]
fn key(d: &mut Drivers, r: &Request, header: &mut [u8], start: u64) -> CaliptraResult<()> {
    let mut work = Zeroizing::new([0u32; evalkey::ROW_WORDS + evalkey::SCRATCH_WORDS]);
    let (row, scratch) = work.split_at_mut(evalkey::ROW_WORDS);
    let mut prg = fresh_prg(d)?;
    let mut error = Zeroizing::new([0i8; 256]);
    for i in 0..evalkey::ROWS {
        // A fresh error and mask per row, from the same per-key TRNG seed.
        sample::sample_cbd(&mut prg, &mut error[..]);
        evalkey::generate_row(
            &d.fhe_session.secret,
            r.arg,
            i,
            &mut prg,
            &error[..],
            row,
            scratch,
        )
        .map_err(|_| INVALID)?;
        let dst = r.dst + (i * evalkey::ROW_WORDS * 4) as u64;
        d.fhe_session
            .transport
            .with_fifo(&mut d.dma, |t| t.write(dst, row))
            .map_err(|_| CaliptraError::RUNTIME_FHE_ENCRYPT_FAILED)?;
    }
    header[8..16].copy_from_slice(&cycles().wrapping_sub(start).to_le_bytes());
    Ok(())
}
/// Run one plain scheduler command. Returns the word offset of its output in
/// `work`, which is always the `plain` buffer.
fn command(
    d: &mut Drivers,
    r: &Request,
    header: &mut [u8; HEADER_LEN],
    work: &mut [u32],
    start: u64,
) -> CaliptraResult<usize> {
    let op = r.op;
    let s = &d.fhe_session;
    if !s.active || word(&r.bytes, 3) != s.id {
        return Err(INVALID);
    }
    let (poisoned, keyed) = (s.transport.is_poisoned(), s.keyed);
    if op == 5 {
        erase(d)?;
        return Ok(0);
    }
    // A poisoned transport may still target external buffers: only close runs.
    if poisoned || (op != 1 && !keyed) {
        return Err(INVALID);
    }
    #[cfg(feature = "fhe-eval-keys")]
    if op >= 6 {
        key(d, r, &mut header[..], start)?;
        return Ok(0);
    }
    let (input, rest) = work[BASE..].split_at_mut(1024);
    let (plain, scratch) = rest.split_at_mut(1024);
    if r.pointer && r.input != 0 {
        // Snapshot external input once; every later read uses this copy.
        d.fhe_session
            .transport
            .with_fifo(&mut d.dma, |t| t.read(r.src, &mut input[..r.input / 4]))
            .map_err(|_| CaliptraError::RUNTIME_FHE_DECRYPT_FAILED)?;
    }
    // Largest sealed body is 2048 B in either direction.
    let mut aes_output = Zeroizing::new([0u32; 512]);
    if sealed_in(op) {
        let body = (r.input - BLOB_HEADER - TAG) / 4;
        open_blob(
            d,
            op,
            &input[..r.input / 4],
            &mut plain[..body],
            &mut aes_output,
        )?;
    }
    kernel(d, op, plain, input, scratch)?;
    let offset = if sealed_out(op) {
        // The input is fully consumed, so its buffer receives the result blob.
        let body = (r.output - BLOB_HEADER - TAG) / 4;
        seal_blob(d, op, &plain[..body], input, &mut aes_output)?;
        BASE
    } else {
        BASE + 1024
    };
    header[8..16].copy_from_slice(&cycles().wrapping_sub(start).to_le_bytes());
    if r.pointer {
        d.fhe_session
            .transport
            .with_fifo(&mut d.dma, |t| {
                t.write(r.dst, &work[offset..offset + r.output / 4])
            })
            .map_err(|_| CaliptraError::RUNTIME_FHE_ENCRYPT_FAILED)?;
    }
    Ok(offset)
}

pub fn execute(d: &mut Drivers, r: Request) -> CaliptraResult<MboxStatusE> {
    let start = cycles();
    let mut header = [0u8; HEADER_LEN];
    // SAFETY: Packet is dropped, SoC command owns SRAM, no DMA targets mailbox.
    // 48-B command, then input (mode-0 payload in place) and plaintext/output
    // buffers of 4 KiB each, then 2-KiB polynomial scratch: WORK < 16 KiB.
    let work = unsafe { core::slice::from_raw_parts_mut(MBOX_ORG as *mut u32, WORK) };
    let open = r.op == 0;
    // Keys stay in DCCM; their mailbox use ends at the command header.
    let used = if cfg!(feature = "fhe-eval-keys") && r.op >= 6 {
        COMMAND_LEN / 4
    } else {
        work.len()
    };
    let result = if open {
        profile::open(d, &r, &mut header).map(|len| (len, 0))
    } else {
        command(d, &r, &mut header, work, start).map(|offset| (RESPONSE_LEN, offset))
    };
    let (len, offset) = match result {
        Ok(v) => v,
        Err(e) => {
            // SAFETY: this synchronous command exclusively owns the AES engine.
            // Driver early-error paths may precede its normal internal zeroization.
            unsafe { caliptra_drivers::Aes::zeroize() };
            // A failed command never ends the session; only close does.
            work[..used].zeroize();
            return Err(e);
        }
    };
    // Only the declared output is retained for DATAIN streaming.
    let payload = if !open && !r.pointer { r.output } else { 0 };
    if payload > 0 {
        work.copy_within(offset..offset + payload / 4, len / 4);
    }
    let end = core::cmp::min((len + payload) / 4, used);
    work[end..used].zeroize();
    let sum = caliptra_common::checksum::calc_checksum(0, &header[4..len]).wrapping_add(
        caliptra_common::checksum::calc_checksum(0, &work.as_bytes()[len..len + payload]),
    );
    put(&mut header, 0, sum);
    // End the SRAM borrow before DATAIN overwrites its source.
    if let Err(error) = d.mbox.write_response_from_mailbox(&header[..len], payload) {
        // SAFETY: no DMA targets mailbox; still exclusively command-owned.
        unsafe { core::slice::from_raw_parts_mut(MBOX_ORG as *mut u32, 4096) }.zeroize();
        return Err(error);
    }
    Ok(MboxStatusE::DataReady)
}

#[inline(never)]
pub(crate) fn erase(d: &mut Drivers) -> CaliptraResult<()> {
    d.fhe_session.erase();
    profile::erase_keys(d)
}
