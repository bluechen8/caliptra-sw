// Licensed under the Apache-2.0 license
//! Protected protocol v5 at the selected parameter set. Rocket schedules plain
//! commands; only user input blobs and result blobs are sealed. Polynomial
//! commands work one limb at a time in mailbox SRAM and stream their output, so
//! their footprint does not grow with L. See software/fhe/RUNTIME.md in the wrapper.
use crate::{fhe_transport::Transport, Drivers};
use caliptra_drivers::memory_layout::{MBOX_ORG, MBOX_SIZE};
use caliptra_drivers::{Aes, AesGcmContext, AesKey, CaliptraError, CaliptraResult, Dma, Trng};
use caliptra_fhe_core::{evalkey, ntt, params, prg::ChaCha20Prg, rlwe, slots, stream};
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
const PARAMS: &params::ParamSet = crate::FHE_PARAMS;
const N: usize = PARAMS.n;
const INVALID: CaliptraError = CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS;
const READ_FAILED: CaliptraError = CaliptraError::RUNTIME_FHE_DECRYPT_FAILED;
const WRITE_FAILED: CaliptraError = CaliptraError::RUNTIME_FHE_ENCRYPT_FAILED;
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
const HEADER_WORDS: usize = BLOB_HEADER / 4;
const TAG: usize = 16;
const OPEN: u32 = 0x4648534f;
/// Ops 1..8, numbered as the Aloha accelerator's commands (KEYGEN, ENCRYPT,
/// DECRYPT, -, CLOSE, REFRESH), then this client's clear reference (4) and
/// key exports (7, 8).
const IDS: [u32; 8] = [
    0x46484b47, 0x4648494e, 0x46484547, 0x4d4c4943, 0x46485343, 0x46485246, 0x46485254, 0x4648524c,
];
/// Workspace base in mailbox words: inputs start right after the command.
const BASE: usize = COMMAND_LEN / 4;
const MBOX_WORDS: usize = MBOX_SIZE as usize / 4;
/// One limb (N words); user data is N/2 complex binary64 slots, two limbs' worth.
const LIMB_BYTES: usize = N * 4;
const SLOT_BYTES: usize = 2 * LIMB_BYTES;
const SLOT_WORDS: usize = SLOT_BYTES / 4;
const KEY_BYTES: usize = evalkey::key_words(PARAMS) * 4;
/// Per-limb polynomial work: A and B (N words each), then stage twiddles.
const POLY_WORDS: usize = 2 * N + ntt::stage_twiddle_words(N);
/// ENCRYPT's area: the blob header, the slots, then the encoder's scratch over
/// the (verified) tag; once encoded, limb 0 (N words) and one limb of work
/// overlap them.
const ENC_WORDS: usize = HEADER_WORDS + max(SLOT_WORDS + slots::scratch_words(N), N + POLY_WORDS);
/// DECRYPT's work: one limb of work, then the decoder's slots and scratch.
const DEC_WORDS: usize = max(POLY_WORDS, SLOT_WORDS + slots::scratch_words(N));
const fn max(a: usize, b: usize) -> usize {
    if a > b {
        a
    } else {
        b
    }
}
/// DCCM staging for AES-GCM: mailbox SRAM has no byte write enables.
const AES_WORDS: usize = 256;
const fn blob(body: usize) -> usize {
    BLOB_HEADER + body + TAG
}
/// (input, output) wire lengths of op 1..8; ENCRYPT and REFRESH output
/// `level` limbs, DECRYPT and REFRESH read limb 0 (the server rescales first).
const fn lengths(op: u32, level: usize) -> (usize, usize) {
    match op {
        2 => (blob(SLOT_BYTES), 2 * level * LIMB_BYTES),
        3 => (2 * LIMB_BYTES, blob(SLOT_BYTES)),
        4 => (blob(196), blob(40)),
        6 => (2 * LIMB_BYTES, 2 * level * LIMB_BYTES),
        7 | 8 => (0, KEY_BYTES),
        _ => (0, 0),
    }
}
/// A whole external input or output range: at most one key or ciphertext.
fn validate(addr: u64, bytes: usize) -> CaliptraResult<()> {
    let max = if KEY_BYTES > PARAMS.ct_bytes() {
        KEY_BYTES
    } else {
        PARAMS.ct_bytes()
    };
    crate::fhe_transport::validate_extent(addr, bytes as u64, max as u64).map_err(|_| INVALID)
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
    /// Packed ternary FHE secret, two bits per coefficient.
    secret: [u8; N / 4],
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
            secret: [0; N / 4],
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
    /// 0 for session open, else 1..8.
    op: u32,
    arg: u32,
    src: u64,
    dst: u64,
    pointer: bool,
    /// Mailbox words of the input snapshot and of mode-0 output.
    in_words: usize,
    out_words: usize,
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
            src: 0,
            dst: 0,
            pointer: false,
            in_words: 0,
            out_words: 0,
        };
        if open {
            return if b.len() == OPEN_LEN {
                Ok(r)
            } else {
                Err(INVALID)
            };
        }
        let op = word(b, 2);
        if !(1..=8).contains(&op)
            || IDS[(op - 1) as usize] != id
            || (op == 4 && !cfg!(feature = "ml-clear"))
            || (op >= 7 && !cfg!(feature = "fhe-eval-keys"))
        {
            return Err(INVALID);
        }
        let mode = word(b, 4);
        let src = (u64::from(word(b, 6)) << 32) | u64::from(word(b, 5));
        let dst = (u64::from(word(b, 8)) << 32) | u64::from(word(b, 7));
        // arg, as Aloha's header word 11: [7:0] log2 of the scale for ENCRYPT
        // (required) and DECRYPT (optional: 0 returns Δ·z), [11:8] the output
        // level of ENCRYPT and REFRESH; keys take the Galois element (0 for
        // relinearization).
        let arg = word(b, 11);
        let level = (arg >> 8) as usize;
        let key = op >= 7;
        let levels = (1..=PARAMS.level).contains(&level); // also refuses bits above [11:8]
        let arg_ok = match op {
            2 => (1..slots::max_log_delta(PARAMS)).contains(&(arg & 0xff)) && levels,
            3 => arg >> 8 == 0,
            6 => arg & 0xff == 0 && levels,
            7 | 8 => (op == 8) == (arg == 0) && evalkey::valid(arg, N),
            _ => arg == 0,
        };
        let (input, output) = lengths(op, level);
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
                validate(src, input)?;
            }
            validate(dst, output)?;
            if input != 0 && src < dst + output as u64 && dst < src + input as u64 {
                return Err(INVALID);
            }
        }
        // Pointer DECRYPT and REFRESH read their public limb once each, with no
        // snapshot; REFRESH keeps the decrypted limb in its input area. Every
        // other input is snapshotted once. ENCRYPT's area holds its input and
        // all its work; other polynomial ops add one limb of work after the output.
        let pointer = mode == 1;
        r.op = op;
        r.in_words = match (pointer, op) {
            (_, 2) => ENC_WORDS,
            (true, 3) => 0,
            (true, 6) => N,
            _ => input / 4,
        };
        r.out_words = if pointer { 0 } else { output / 4 };
        if r.words() > MBOX_WORDS {
            return Err(INVALID);
        }
        r.arg = arg;
        r.src = src;
        r.dst = dst;
        r.pointer = pointer;
        Ok(r)
    }
    /// Output limbs of ENCRYPT and REFRESH (arg [11:8]).
    fn level(&self) -> usize {
        (self.arg >> 8) as usize
    }
    /// log2 of the slot scale of ENCRYPT and DECRYPT (arg [7:0]).
    fn log_delta(&self) -> u32 {
        self.arg & 0xff
    }
    /// Mailbox words this command uses and scrubs.
    fn words(&self) -> usize {
        let poly = match self.op {
            3 => DEC_WORDS,
            6..=8 => POLY_WORDS,
            _ => 0,
        };
        BASE + self.in_words + self.out_words + poly
    }
}
fn fresh_prg(trng: &mut Trng) -> CaliptraResult<ChaCha20Prg> {
    let entropy = Zeroizing::new(trng.generate()?);
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&entropy.as_bytes()[..32]);
    Ok(ChaCha20Prg::new(&seed))
}
/// Where a command's output goes: its mailbox output area (mode 0) or DRAM
/// at `dst` (mode 1). Outputs are written as they are produced.
struct Sink<'a> {
    mailbox: &'a mut [u32],
    dst: u64,
    pointer: bool,
    dma: &'a mut Dma,
    transport: &'a mut Transport<()>,
}
impl<'a> Sink<'a> {
    fn new(
        mailbox: &'a mut [u32],
        r: &Request,
        dma: &'a mut Dma,
        transport: &'a mut Transport<()>,
    ) -> Self {
        Self {
            mailbox,
            dst: r.dst,
            pointer: r.pointer,
            dma,
            transport,
        }
    }
    fn put(&mut self, at: usize, data: &[u32]) -> CaliptraResult<()> {
        if self.pointer {
            let dst = self.dst + (at * 4) as u64;
            self.transport
                .with_fifo(&mut *self.dma, |t| t.write(dst, data))
                .map_err(|_| WRITE_FAILED)
        } else {
            copy_words(
                self.mailbox.get_mut(at..at + data.len()).ok_or(INVALID)?,
                data,
            );
            Ok(())
        }
    }
    /// `put` for a kernel's `emit` callback.
    fn emit(&mut self, at: usize, data: &[u32]) -> caliptra_fhe_core::Result<()> {
        self.put(at, data)
            .map_err(|_| caliptra_fhe_core::Error::Sink)
    }
}
/// Map a kernel error: an output write failed, or the input was invalid.
fn kernel(r: caliptra_fhe_core::Result<()>) -> CaliptraResult<()> {
    r.map_err(|e| {
        if e == caliptra_fhe_core::Error::Sink {
            WRITE_FAILED
        } else {
            INVALID
        }
    })
}
/// One limb of work: polynomials A and B (N words each), then stage twiddles.
fn limb_work(poly: &mut [u32]) -> (&mut [u32], &mut [u32], &mut [u32]) {
    let (a, rest) = poly.split_at_mut(N);
    let (b, rest) = rest.split_at_mut(N);
    (a, b, &mut rest[..ntt::stage_twiddle_words(N)])
}
/// Authenticate a user blob for `op` and decrypt its body in place.
/// The body is used only once the tag verifies; callers scrub on failure.
fn open_blob(
    aes: &mut Aes,
    trng: &mut Trng,
    id: u32,
    op: u32,
    blob: &mut [u32],
) -> CaliptraResult<()> {
    let body = blob.len() - (BLOB_HEADER + TAG) / 4;
    let header = <[u32; 5]>::try_from(&blob[..5]).unwrap();
    // Any user counter is accepted: a replay only re-encrypts the same data.
    if header[0] != VERSION || header[1] != id || header[2] != op || header[4] as usize != body * 4
    {
        return Err(INVALID);
    }
    let tag = <[u32; 4]>::try_from(&blob[5 + body..]).unwrap();
    let key = session_key(false);
    let iv = nonce(header[3], 0);
    let mut ctx = aes.aes_256_gcm_init_with_key(trng, key, (&iv).into(), header.as_bytes())?;
    let mut input = Zeroizing::new([0u32; AES_WORDS]);
    let mut out = Zeroizing::new([0u32; AES_WORDS + 4]);
    // Output lags input by under one block, so it only overwrites consumed words.
    // The last chunk goes through the final call: the RTL's GCM phase register
    // refuses RESTORE -> TAG, so a final with no text after a restore hangs.
    let last = (body - 1) / AES_WORDS * AES_WORDS;
    let mut at = 5;
    for start in (0..last).step_by(AES_WORDS) {
        input.copy_from_slice(&blob[5 + start..5 + start + AES_WORDS]);
        let (written, next) = aes.aes_256_gcm_decrypt_update_with_key(
            key,
            &ctx,
            input.as_bytes(),
            out.as_mut_bytes(),
        )?;
        ctx = next;
        copy_words(&mut blob[at..at + written / 4], &out[..written / 4]);
        at += written / 4;
    }
    let n = body - last;
    input[..n].copy_from_slice(&blob[5 + last..5 + body]);
    let (written, _, ok) = aes.aes_256_gcm_decrypt_final_with_key(
        key,
        &ctx,
        input[..n].as_bytes(),
        out.as_mut_bytes(),
        tag.as_bytes(),
    )?;
    copy_words(&mut blob[at..at + written / 4], &out[..written / 4]);
    if !ok {
        return Err(INVALID);
    }
    Ok(())
}
/// A result blob being sealed to the user, streamed through a sink.
struct Seal {
    key: AesKey<'static>,
    ctx: AesGcmContext,
    at: usize,
}
impl Seal {
    /// Consume a result counter and write the blob header for `bytes` of body.
    #[allow(clippy::too_many_arguments)]
    fn begin(
        aes: &mut Aes,
        trng: &mut Trng,
        id: u32,
        next: &mut u32,
        op: u32,
        bytes: usize,
        out: &mut Sink,
    ) -> CaliptraResult<Self> {
        let counter = *next;
        if counter == u32::MAX {
            return Err(INVALID);
        }
        // Consumed before sealing, so no failure path can reuse a nonce.
        *next += 1;
        let header = [VERSION, id, op, counter, bytes as u32];
        let key = session_key(true);
        let iv = nonce(counter, 1);
        let ctx = aes.aes_256_gcm_init_with_key(trng, key, (&iv).into(), header.as_bytes())?;
        out.put(0, &header)?;
        Ok(Self { key, ctx, at: 5 })
    }
    /// Seal `plain` (not empty) and write the tag after it. The last chunk goes
    /// through the final call, as in `open_blob`: the RTL refuses RESTORE -> TAG.
    fn finish(mut self, aes: &mut Aes, plain: &[u32], out: &mut Sink) -> CaliptraResult<()> {
        let mut sealed = Zeroizing::new([0u32; AES_WORDS + 4]);
        let last = (plain.len() - 1) / AES_WORDS * AES_WORDS;
        for chunk in plain[..last].chunks(AES_WORDS) {
            let (written, next) = aes.aes_256_gcm_encrypt_update_with_key(
                self.key,
                &self.ctx,
                chunk.as_bytes(),
                sealed.as_mut_bytes(),
            )?;
            self.ctx = next;
            out.put(self.at, &sealed[..written / 4])?;
            self.at += written / 4;
        }
        let (written, tag) = aes.aes_256_gcm_encrypt_final_with_key(
            self.key,
            &self.ctx,
            plain[last..].as_bytes(),
            sealed[..AES_WORDS].as_mut_bytes(),
        )?;
        let words = written / 4;
        let tag: [u32; 4] = zerocopy::transmute!(tag);
        sealed[words..words + 4].copy_from_slice(&tag);
        out.put(self.at, &sealed[..words + 4])
    }
}
/// Encrypt limb-0 residues `m0` (|m| < q0/2) to `level` limbs and emit the
/// ciphertext: c0 limbs, then c1 limbs. Each limb is checked as it is lifted,
/// limb 0 before any output.
fn encrypt_to(
    trng: &mut Trng,
    secret: &[u8],
    m0: &[u32],
    level: usize,
    poly: &mut [u32],
    out: &mut Sink,
) -> CaliptraResult<()> {
    let q0 = PARAMS.primes[0].q;
    let mut prg = fresh_prg(trng)?;
    let mut error = Zeroizing::new([0u8; 32]);
    prg.fill(&mut error[..]);
    let (a, b, tw) = limb_work(poly);
    for (li, p) in PARAMS.primes[..level].iter().enumerate() {
        kernel(stream::lift_limb(m0, q0, p, a))?;
        kernel(stream::encrypt_limb(
            secret,
            &error,
            &mut prg,
            p,
            a,
            b,
            tw,
            |at, c1| out.emit((level + li) * N + at, c1),
        ))?;
        out.put(li * N, a)?;
    }
    Ok(())
}
/// Decrypt the limb-0 ciphertext (c0, c1 at q0) into the first polynomial of
/// `poly`: from `input` in mode 0, else each limb read once by DMA and checked.
fn decrypt0(
    r: &Request,
    input: &[u32],
    secret: &[u8],
    poly: &mut [u32],
    out: &mut Sink,
) -> CaliptraResult<()> {
    let p = &PARAMS.primes[0];
    let (a, b, tw) = limb_work(poly);
    let mut limb = |at: usize, dst: &mut [u32], out: &mut Sink| -> CaliptraResult<()> {
        if r.pointer {
            let src = r.src + (at * 4) as u64;
            out.transport
                .with_fifo(&mut *out.dma, |t| t.read(src, dst))
                .map_err(|_| READ_FAILED)?;
        } else {
            copy_words(dst, &input[at..at + N]);
        }
        kernel(stream::check_reduced(dst, p.q))
    };
    // b = c1 . NTT(s), then a = INTT(c0 + b).
    limb(N, b, out)?;
    kernel(stream::secret_ntt(secret, p, tw, a))?;
    stream::mul_assign(b, a, p);
    limb(0, a, out)?;
    kernel(stream::decrypt_finish(a, b, p, tw))
}
/// ENCRYPT: authenticate the slots, encode them at scale 2^log_delta into
/// limb-0 residues, then encrypt to the chosen level. Slot range errors
/// surface only after the tag verifies.
#[inline(never)]
fn ingress(
    d: &mut Drivers,
    r: &Request,
    area: &mut [u32],
    output: &mut [u32],
) -> CaliptraResult<()> {
    let Drivers {
        aes,
        trng,
        dma,
        fhe_session: s,
        ..
    } = d;
    open_blob(aes, trng, s.id, 2, &mut area[..blob(SLOT_BYTES) / 4])?;
    let (body, scratch) = area[HEADER_WORDS..].split_at_mut(SLOT_WORDS);
    kernel(slots::encode(PARAMS, body, r.log_delta(), scratch))?;
    let (m0, poly) = area[HEADER_WORDS..].split_at_mut(N);
    let mut out = Sink::new(output, r, dma, &mut s.transport);
    encrypt_to(trng, &s.secret, m0, r.level(), poly, &mut out)
}
/// DECRYPT: decrypt limb 0, decode it at scale 2^log_delta and seal the slots
/// to the user.
#[inline(never)]
fn egress(
    d: &mut Drivers,
    r: &Request,
    input: &[u32],
    output: &mut [u32],
    poly: &mut [u32],
) -> CaliptraResult<()> {
    let Drivers {
        aes,
        trng,
        dma,
        fhe_session: s,
        ..
    } = d;
    let mut out = Sink::new(output, r, dma, &mut s.transport);
    decrypt0(r, input, &s.secret, poly, &mut out)?;
    let (slot_words, scratch) = poly.split_at_mut(SLOT_WORDS);
    kernel(slots::decode(PARAMS, slot_words, r.log_delta(), scratch))?;
    Seal::begin(aes, trng, s.id, &mut s.counter, 3, SLOT_BYTES, &mut out)?
        .finish(aes, slot_words, &mut out)
}
/// REFRESH: decrypt limb 0 and re-encrypt it, at its scale, to the chosen
/// level with fresh randomness; no plaintext leaves Caliptra.
#[inline(never)]
fn refresh(
    d: &mut Drivers,
    r: &Request,
    input: &mut [u32],
    output: &mut [u32],
    poly: &mut [u32],
) -> CaliptraResult<()> {
    let Drivers {
        trng,
        dma,
        fhe_session: s,
        ..
    } = d;
    let mut out = Sink::new(output, r, dma, &mut s.transport);
    decrypt0(r, input, &s.secret, poly, &mut out)?;
    // The input area (c0 consumed, or reserved in pointer mode) holds m + e.
    copy_words(&mut input[..N], &poly[..N]);
    encrypt_to(trng, &s.secret, &input[..N], r.level(), poly, &mut out)
}
/// Clear-reference inference on authenticated pixels, sealed to the user.
#[cfg(feature = "ml-clear")]
#[inline(never)]
fn clear_reference(
    d: &mut Drivers,
    r: &Request,
    input: &mut [u32],
    output: &mut [u32],
) -> CaliptraResult<()> {
    let Drivers {
        aes,
        trng,
        dma,
        fhe_session: s,
        ..
    } = d;
    open_blob(aes, trng, s.id, 4, input)?;
    let pixels = &input.as_bytes()[20..20 + 196];
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
    let mut out = Sink::new(output, r, dma, &mut s.transport);
    Seal::begin(aes, trng, s.id, &mut s.counter, 4, 40, &mut out)?.finish(aes, &logits, &mut out)
}
/// Generate one public evaluation key, row by row and limb by limb, and DMA
/// each limb to its place in the key as it is produced. Cycles include DMA.
#[cfg(feature = "fhe-eval-keys")]
#[inline(never)]
fn key(d: &mut Drivers, r: &Request, poly: &mut [u32]) -> CaliptraResult<()> {
    let Drivers {
        trng,
        dma,
        fhe_session: s,
        ..
    } = d;
    let mut prg = fresh_prg(trng)?;
    let (a, b, tw) = limb_work(poly);
    // Key commands are pointer-only, so the sink never touches the mailbox.
    let mut out = Sink::new(&mut [], r, dma, &mut s.transport);
    for row in 0..evalkey::rows(PARAMS) {
        // A fresh error per row, shared by its limbs, from the per-key seed.
        let mut error = Zeroizing::new([0u8; 32]);
        prg.fill(&mut error[..]);
        let base = row * evalkey::row_words(PARAMS);
        kernel(evalkey::stream_row(
            PARAMS,
            &s.secret,
            r.arg,
            row,
            &error,
            &mut prg,
            a,
            b,
            tw,
            |at, w| out.emit(base + at, w),
        ))?;
    }
    Ok(())
}
/// Run one plain scheduler command; its mode-0 output is left in `output`.
fn command(
    d: &mut Drivers,
    r: &Request,
    header: &mut [u8; HEADER_LEN],
    work: &mut [u32],
    start: u64,
) -> CaliptraResult<()> {
    let op = r.op;
    let s = &mut d.fhe_session;
    if !s.active || word(&r.bytes, 3) != s.id {
        return Err(INVALID);
    }
    if op == 5 {
        return erase(d);
    }
    // A poisoned transport may still target external buffers: only close runs.
    if s.transport.is_poisoned() || (op != 1 && !s.keyed) {
        return Err(INVALID);
    }
    if op == 1 {
        if s.keyed {
            return Err(INVALID);
        }
        let mut prg = fresh_prg(&mut d.trng)?;
        let s = &mut d.fhe_session;
        rlwe::keygen(&mut prg, N, &mut s.secret).map_err(|_| INVALID)?;
        s.keyed = true;
        return Ok(());
    }
    let (input, rest) = work[BASE..].split_at_mut(r.in_words);
    let (output, poly) = rest.split_at_mut(r.out_words);
    if r.pointer && matches!(op, 2 | 4) {
        // Snapshot sealed input once; every later read uses this copy.
        let words = lengths(op, r.level()).0 / 4;
        s.transport
            .with_fifo(&mut d.dma, |t| t.read(r.src, &mut input[..words]))
            .map_err(|_| READ_FAILED)?;
    }
    match op {
        2 => ingress(d, r, input, output)?,
        3 => egress(d, r, input, output, poly)?,
        6 => refresh(d, r, input, output, poly)?,
        #[cfg(feature = "ml-clear")]
        4 => clear_reference(d, r, input, output)?,
        #[cfg(feature = "fhe-eval-keys")]
        7 | 8 => key(d, r, poly)?,
        _ => return Err(INVALID),
    }
    header[8..16].copy_from_slice(&cycles().wrapping_sub(start).to_le_bytes());
    Ok(())
}

pub fn execute(d: &mut Drivers, r: Request) -> CaliptraResult<MboxStatusE> {
    let start = cycles();
    let mut header = [0u8; HEADER_LEN];
    // SAFETY: Packet is dropped, SoC command owns SRAM, no DMA targets mailbox.
    // Layout: 48-B command, input (mode-0 payload in place, or the DMA
    // snapshot), mode-0 output, then one limb of polynomial work.
    // An open uses only its request and response, the larger of the two.
    let used = core::cmp::max(r.words(), core::cmp::max(REQUEST_LEN, HEADER_LEN) / 4);
    let work = unsafe { core::slice::from_raw_parts_mut(MBOX_ORG as *mut u32, used) };
    let open = r.op == 0;
    let result = if open {
        profile::open(d, &r, &mut header)
    } else {
        command(d, &r, &mut header, work, start).map(|_| RESPONSE_LEN)
    };
    let len = match result {
        Ok(len) => len,
        Err(e) => {
            // SAFETY: this synchronous command exclusively owns the AES engine.
            // Driver early-error paths may precede its normal internal zeroization.
            unsafe { caliptra_drivers::Aes::zeroize() };
            // A failed command never ends the session; only close does.
            work.zeroize();
            return Err(e);
        }
    };
    // Only the declared output is retained for DATAIN streaming (none for an open).
    let payload = r.out_words * 4;
    let at = BASE + r.in_words;
    work.copy_within(at..at + payload / 4, len / 4);
    work[(len + payload) / 4..].zeroize();
    let sum = caliptra_common::checksum::calc_checksum(0, &header[4..len]).wrapping_add(
        caliptra_common::checksum::calc_checksum(0, &work.as_bytes()[len..len + payload]),
    );
    put(&mut header, 0, sum);
    // End the SRAM borrow before DATAIN overwrites its source.
    if let Err(error) = d.mbox.write_response_from_mailbox(&header[..len], payload) {
        // SAFETY: no DMA targets mailbox; still exclusively command-owned.
        unsafe { core::slice::from_raw_parts_mut(MBOX_ORG as *mut u32, used) }.zeroize();
        return Err(error);
    }
    Ok(MboxStatusE::DataReady)
}

#[inline(never)]
pub(crate) fn erase(d: &mut Drivers) -> CaliptraResult<()> {
    d.fhe_session.erase();
    profile::erase_keys(d)
}
