// Licensed under the Apache-2.0 license
//! N=256 Aloha backend on the DMA stream: Aloha moves every buffer between
//! DRAM and the engine through Caliptra's axi_dma, and VeeR never reads the
//! data. VeeR sets up and finishes AES-GCM around the DMA's text phase.
//! Profile 0xa108: 128 interleaved complex f64 slots; c0 then c1, two N-word
//! residue limbs per component, each coefficient serialized as LE u64.
use caliptra_common::keyids::KEY_ID_FHE_SEED;
use caliptra_drivers::{
    hmac_kdf, Aes, AesKey, AesOperation, CaliptraError, CaliptraResult, Hmac, HmacMode, KeyId,
    KeyReadArgs, KeyUsage, KeyVault, KeyWriteArgs, Trng,
};
const BASE: usize = 0x1005_0000;
const N: usize = 256;
const LOGN: i32 = 8;
const LOG_SCALE: i32 = 25;
const POLL: usize = 20_000_000;
const FAILED: CaliptraError = CaliptraError::RUNTIME_FHE_DECRYPT_FAILED;

// fhe_top register map v2 (fhe_reg.rdl; docs/fhe/16-register-map-v2.md).
const REG_NAME0: usize = 0x00;
const REG_CTRL: usize = 0x10;
const REG_STATUS: usize = 0x14;
const REG_CONFIG: usize = 0x18;
const REG_CAP: usize = 0x1c;
const REG_KV_RD_SEED_CTRL: usize = 0x20;
const REG_KV_RD_SEED_STATUS: usize = 0x24;
const REG_SLOT0: usize = 0x30;

const NAME0: u32 = 0x534b4b43; // "CKKS"
/// CAP fields firmware depends on: N, two limbs, DMA stream, map version 2.
/// Other capability bits (build options) are ignored.
const CAP_CHECKED: u32 = 0xffff | 0xf << 16 | 1 << 24 | 0xf << 28;
const CAP_EXPECTED: u32 = N as u32 | 2 << 16 | 1 << 24 | 2 << 28;
const CMD_ENCRYPT: u32 = 1;
const CMD_KEYGEN: u32 = 2;
const CMD_DECRYPT: u32 = 4;
const CMD_REFRESH: u32 = 6;
const CTRL_ZEROIZE: u32 = 1 << 3;
const CTRL_INPUT_COMMIT: u32 = 1 << 4;
const STATUS_READY: u32 = 1 << 0;
const STATUS_VALID: u32 = 1 << 1;
const STATUS_ERROR: u32 = 1 << 2;
const STATUS_KEY_VALID: u32 = 1 << 3;
const STATUS_CAUSE_SHIFT: u32 = 4;
const STATUS_COMMIT_WAIT: u32 = 1 << 8;
// kv_read_ctrl_reg / kv_status_reg fields.
const KV_READ_EN: u32 = 1 << 0;
const KV_STATUS_VALID: u32 = 1 << 1;
const KV_STATUS_ERROR_SHIFT: u32 = 2;
/// Both RNS limbs.
const LIMBS: u32 = 2;
/// 12-bit RNS encode scale field for 2^LOG_SCALE at this N; signed decode field.
const RNS_SCALE: u32 = ((LOG_SCALE - 52 - 1023 - LOGN) & 0xfff) as u32;
/// KDF label binding the derived seed to this use of the runtime CDI.
const SEED_LABEL: &[u8] = b"ALOHA-FHE-SEED";
/// One limb of one component: N LE u64 coefficients.
const LIMB_BYTES: u64 = 8 * N as u64;
/// The slot vector: N/2 complex f64.
pub const MESSAGE_BYTES: usize = 8 * N;
/// One component, both limbs.
const COMPONENT_BYTES: u64 = LIMBS as u64 * LIMB_BYTES;
/// Ciphertext, both limbs of c0 then c1.
pub const CIPHERTEXT_BYTES: usize = 2 * COMPONENT_BYTES as usize;
/// c0 and c1 limb 0.
pub const Q0_BYTES: usize = 2 * LIMB_BYTES as usize;

/// CONFIG = {SCALE[27:16], LOGN[7:4], L[3:0]}.
fn config(limbs: u32, scale: u32) {
    wr(REG_CONFIG, (scale & 0xfff) << 16 | (LOGN as u32) << 4 | (limbs & 0xf));
}

fn rd(off: usize) -> u32 {
    unsafe { core::ptr::read_volatile((BASE + off) as *const u32) }
}
fn wr(off: usize, value: u32) {
    unsafe { core::ptr::write_volatile((BASE + off) as *mut u32, value) }
}
pub fn clear() {
    wr(REG_CTRL, CTRL_ZEROIZE);
}
fn present() -> CaliptraResult<()> {
    if rd(REG_NAME0) != NAME0 || rd(REG_CAP) & CAP_CHECKED != CAP_EXPECTED {
        return Err(CaliptraError::RUNTIME_FHE_ABSENT);
    }
    Ok(())
}
/// Polls `reg` until a bit of `mask` is set; returns the register value.
fn poll(reg: usize, mask: u32) -> CaliptraResult<u32> {
    (0..POLL)
        .map(|_| rd(reg))
        .find(|v| v & mask != 0)
        .ok_or(FAILED)
}
fn ready() -> CaliptraResult<()> {
    poll(REG_STATUS, STATUS_READY).map(|_| ())
}
/// Aborts a command that stopped responding and waits for the lease to drain.
fn abort() {
    clear();
    let _ = ready();
}

/// How a data command ended. `cause` is Aloha's ERR_CAUSE (0 on success);
/// `key_valid` is KEY_VALID afterwards (ZEROIZE drops the resident key).
pub struct Done {
    pub cause: u32,
    pub key_valid: bool,
    /// DECRYPT: GCM tag of the sealed output. Zero otherwise or on failure.
    pub tag: [u8; 16],
}
impl Done {
    /// A command that ran no engine operation.
    pub fn ok(key_valid: bool) -> Self {
        Self {
            cause: 0,
            key_valid,
            tag: [0; 16],
        }
    }
    fn new(status: u32) -> Self {
        Self {
            cause: status >> STATUS_CAUSE_SHIFT & 0xf,
            key_valid: status & STATUS_KEY_VALID != 0,
            tag: [0; 16],
        }
    }
}

/// Configures and starts one command. Slot bases come from the caller's
/// validated DRAM ranges; hardware checks only alignment and wraparound.
fn start(cmd: u32, limbs: u32, scale: u32, slots: &[(usize, u64)]) -> CaliptraResult<()> {
    ready()?;
    config(limbs, scale);
    for &(slot, base) in slots {
        wr(REG_SLOT0 + 8 * slot, base as u32);
        wr(REG_SLOT0 + 8 * slot + 4, (base >> 32) as u32);
    }
    wr(REG_CTRL, cmd);
    Ok(())
}
/// Waits for a bit of `mask` in STATUS; aborts the command on timeout.
fn wait(mask: u32) -> CaliptraResult<u32> {
    poll(REG_STATUS, mask).inspect_err(|_| abort())
}
/// The engine holds a GCM context the DMA did not finish. Clear it.
fn discard_gcm() {
    // SAFETY: this synchronous command owns the AES engine and the lease has
    // ended; the context's result is never used.
    unsafe { Aes::zeroize() };
}
/// Derive a fresh 160-bit seed into KeyVault and generate the resident key.
/// The seed is HMAC-384 KDF(KV[rt_cdi], label, TRNG nonce), written only to the
/// FHE seed slot with the ML-DSA-seed read permission: FHE reads KeyVault
/// through Adams Bridge's ML-DSA seed client, free when ML-DSA is absent.
/// VeeR sees the nonce, never the seed. The slot is cleared afterwards.
pub fn keygen(
    hmac: &mut Hmac,
    trng: &mut Trng,
    key_vault: &mut KeyVault,
    rt_cdi: KeyId,
) -> CaliptraResult<()> {
    present()?;
    clear();
    ready()?;
    let result = (|| {
        // Context: the full 384-bit TRNG nonce.
        let nonce: [u8; 48] = trng.generate()?.into();
        hmac_kdf(
            hmac,
            KeyReadArgs::new(rt_cdi).into(),
            SEED_LABEL,
            Some(&nonce),
            trng,
            KeyWriteArgs::new(KEY_ID_FHE_SEED, KeyUsage::default().set_mldsa_key_gen_seed_en()).into(),
            HmacMode::Hmac384,
        )?;
        wr(REG_KV_RD_SEED_CTRL, (KEY_ID_FHE_SEED as u32) << 1 | KV_READ_EN);
        let status = poll(REG_KV_RD_SEED_STATUS, KV_STATUS_VALID)?;
        if status >> KV_STATUS_ERROR_SHIFT & 0xff != 0 {
            return Err(FAILED);
        }
        start(CMD_KEYGEN, LIMBS, RNS_SCALE, &[])?;
        let status = wait(STATUS_VALID)?;
        if status & (STATUS_ERROR | STATUS_KEY_VALID) != STATUS_KEY_VALID {
            return Err(FAILED);
        }
        Ok(())
    })();
    // The hardware keeps no copy after KEYGEN; drop the KeyVault copy too.
    let erased = key_vault.erase_key(KEY_ID_FHE_SEED);
    result.and(erased)
}
/// ENCRYPT the sealed slot vector at `src` into c0, c1 at `dst` (8 KiB,
/// component-major). The DMA GCM-decrypts the message into Aloha under `key`
/// and `iv`; at COMMIT_WAIT the tag decides INPUT_COMMIT or ZEROIZE, so no
/// arithmetic sees an unauthenticated message. The ciphertext bypasses AES.
pub fn encrypt(
    aes: &mut Aes,
    trng: &mut Trng,
    key: &[u8; 32],
    iv: &[u8; 12],
    tag: &[u8; 16],
    src: u64,
    dst: u64,
) -> CaliptraResult<Done> {
    present()?;
    aes.aes_256_gcm_begin(trng, iv, AesKey::Array(key), &[], AesOperation::Decrypt)?;
    // a and e0 continue the resident key's sampling stream: no seed here.
    start(
        CMD_ENCRYPT,
        LIMBS,
        RNS_SCALE,
        &[(0, src), (2, dst), (3, dst + COMPONENT_BYTES)],
    )?;
    let status = wait(STATUS_VALID | STATUS_COMMIT_WAIT)?;
    if status & STATUS_VALID != 0 {
        // Rejected before ingress (precondition, slot address, lease).
        discard_gcm();
        return Ok(Done::new(status));
    }
    let computed = aes.aes_256_gcm_end(0, MESSAGE_BYTES)?;
    let commit = constant_time_eq::constant_time_eq(&computed, tag);
    wr(REG_CTRL, if commit { CTRL_INPUT_COMMIT } else { CTRL_ZEROIZE });
    wait(STATUS_VALID).map(Done::new)
}
/// DECRYPT c0, c1 limb 0 at `src` (4 KiB) into the slot vector at `dst`,
/// GCM-encrypted by the DMA under `key` and `iv`; returns the tag. Decode uses
/// the power-of-two scale exponent; the evaluator supplies the actual scale.
pub fn decrypt(
    aes: &mut Aes,
    trng: &mut Trng,
    key: &[u8; 32],
    iv: &[u8; 12],
    log_scale: u32,
    src: u64,
    dst: u64,
) -> CaliptraResult<Done> {
    present()?;
    if !(1..=40).contains(&log_scale) {
        return Err(FAILED);
    }
    aes.aes_256_gcm_begin(trng, iv, AesKey::Array(key), &[], AesOperation::Encrypt)?;
    let scale = (-(log_scale as i32)) as u32;
    start(
        CMD_DECRYPT,
        LIMBS,
        scale,
        &[(0, src), (1, src + LIMB_BYTES), (2, dst)],
    )?;
    let mut done = Done::new(wait(STATUS_VALID)?);
    if done.cause != 0 {
        // A failed DECRYPT writes no output.
        discard_gcm();
        return Ok(done);
    }
    done.tag = aes.aes_256_gcm_end(0, MESSAGE_BYTES)?;
    Ok(done)
}
/// Trusted q0 -> q0*q1 level refresh, with no slot decode/re-encode: c0, c1
/// at q0 from `src` (4 KiB), both limbs to `dst` (8 KiB). Call only after
/// authorizing refresh. The output keeps the input's scale. No AES.
pub fn refresh(src: u64, dst: u64) -> CaliptraResult<Done> {
    present()?;
    start(
        CMD_REFRESH,
        LIMBS,
        0,
        &[(0, src), (1, src + LIMB_BYTES), (2, dst), (3, dst + COMPONENT_BYTES)],
    )?;
    wait(STATUS_VALID).map(Done::new)
}
