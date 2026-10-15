// Licensed under the Apache-2.0 license
//! N=256 Aloha backend. Data remains in command-owned mailbox/DCCM.
//! The generic Caliptra DMA transfers only GCM-wrapped request/response bodies.
//! Profile 0xa108: 128 interleaved complex f64 slots; c0 then c1, two N-word
//! residue limbs per component, each coefficient serialized as LE u64.
use caliptra_common::keyids::KEY_ID_FHE_SEED;
use caliptra_drivers::{
    hmac_kdf, CaliptraError, CaliptraResult, Hmac, HmacMode, KeyId, KeyReadArgs, KeyUsage,
    KeyVault, KeyWriteArgs, Trng,
};
const BASE: usize = 0x1005_0000;
const N: usize = 256;
const LOGN: i32 = 8;
const LOG_SCALE: i32 = 25;
/// Profile 0xa108 limb moduli, in limb order.
#[path = "recovery.rs"]
pub mod recovery;
use recovery::Q;
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
const REG_XFER_STATUS: usize = 0x28;
const REG_XFER_LEFT: usize = 0x2c;
const REG_XFER_DATA: usize = 0x50;

const NAME0: u32 = 0x534b4b43; // "CKKS"
/// CAP fields firmware depends on: N, two limbs, firmware-forward stream, map
/// version 2. Other capability bits (build options, later transports) are ignored.
const CAP_CHECKED: u32 = 0xffff | 0xf << 16 | 1 << 25 | 0xf << 28;
const CAP_EXPECTED: u32 = N as u32 | 2 << 16 | 1 << 25 | 2 << 28;
const CMD_ENCRYPT: u32 = 1;
const CMD_KEYGEN: u32 = 2;
const CMD_DECRYPT: u32 = 4;
const CMD_RECOVER: u32 = 5;
const CMD_REFRESH: u32 = 6;
const CTRL_ZEROIZE: u32 = 1 << 3;
const STATUS_READY: u32 = 1 << 0;
const STATUS_VALID: u32 = 1 << 1;
const STATUS_ERROR: u32 = 1 << 2;
const STATUS_KEY_VALID: u32 = 1 << 3;
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
// XFER_STATUS fields (fhe_local_stream.sv). Both ready bits imply active.
const STREAM_OUTPUT: u32 = 1 << 1;
const STREAM_IN_READY: u32 = 1 << 2;
const STREAM_OUT_VALID: u32 = 1 << 3;
const STREAM_HIGH_HALF: u32 = 1 << 12;

/// CONFIG = {SCALE[27:16], LOGN[7:4], L[3:0]}.
fn config(limbs: u32, scale: u32) {
    wr(REG_CONFIG, (scale & 0xfff) << 16 | (LOGN as u32) << 4 | (limbs & 0xf));
}

/// One walker descriptor a command may issue. It moves N coefficients (2N
/// words) at word offset `base` of the command's buffer.
struct Transfer {
    output: bool,
    ptr: u32,
    limb: u32,
    base: usize,
}
const fn xfer(output: bool, ptr: u32, limb: u32, base: usize) -> Transfer {
    Transfer {
        output,
        ptr,
        limb,
        base,
    }
}
/// Plaintext in; c0 limbs 0/1 then c1 limbs 0/1 out, over the same buffer.
const ENCRYPT: &[Transfer] = &[
    xfer(false, 0, 0, 0),
    xfer(true, 2, 0, 0),
    xfer(true, 2, 1, 2 * N),
    xfer(true, 3, 0, 4 * N),
    xfer(true, 3, 1, 6 * N),
];
/// c0 and c1 limb 0 in; plaintext out to the separate output buffer.
const DECRYPT: &[Transfer] = &[
    xfer(false, 0, 0, 0),
    xfer(false, 1, 0, 4 * N),
    xfer(true, 2, 0, 0),
];

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
/// Configures and runs one command, clearing the controller on any failure after
/// it starts; returns the completion STATUS. Descriptor metadata comes from the
/// walker, never from an external address; session.rs has already authenticated
/// the complete input snapshot.
fn run(
    cmd: u32,
    limbs: u32,
    scale: u32,
    transfers: &[Transfer],
    data: &mut [u32],
    output: Option<&mut [u32]>,
) -> CaliptraResult<u32> {
    ready()?;
    config(limbs, scale);
    wr(REG_CTRL, cmd);
    let result = stream(transfers, data, output);
    if result.is_err() {
        clear();
    }
    result
}
fn stream(
    transfers: &[Transfer],
    data: &mut [u32],
    mut output: Option<&mut [u32]>,
) -> CaliptraResult<u32> {
    // Every descriptor must make monotonic progress; reject replayed or skipped
    // words, even if the aggregate transfer count could otherwise look correct.
    let mut progress = [0usize; 6];
    if transfers.len() > progress.len() {
        return Err(FAILED);
    }
    let words = |dir| transfers.iter().filter(|t| t.output == dir).count() * N;
    let (want_in, want_out) = (words(false), words(true));
    let (mut moved_in, mut moved_out) = (0, 0);
    for _ in 0..POLL {
        let s = rd(REG_XFER_STATUS);
        // Completion and errors leave the stream idle, so STATUS is read only
        // when no word is pending.
        if s & (STREAM_IN_READY | STREAM_OUT_VALID) == 0 {
            let status = rd(REG_STATUS);
            if status & STATUS_ERROR != 0 {
                return Err(FAILED);
            }
            if status & STATUS_VALID != 0 {
                // A short transfer would leave stale buffer contents in the result.
                if (moved_in, moved_out) != (want_in, want_out) {
                    return Err(FAILED);
                }
                return Ok(status);
            }
            // Normal completion exposes READY and VALID together; ZEROIZE reports
            // VALID with ERROR. Reset leaves READY without VALID: cancelled.
            if status & STATUS_READY != 0 {
                return Err(FAILED);
            }
            continue;
        }
        let left = rd(REG_XFER_LEFT) as usize;
        let dir = s & STREAM_OUTPUT != 0;
        let (ptr, limb) = ((s >> 4) & 7, (s >> 8) & 15);
        let ti = transfers
            .iter()
            .position(|t| (t.output, t.ptr, t.limb) == (dir, ptr, limb))
            .ok_or(FAILED)?;
        let t = &transfers[ti];
        if left == 0 || left > N || s & STREAM_HIGH_HALF != 0 || progress[ti] != N - left {
            return Err(FAILED);
        }
        let i = t.base + 2 * (N - left);
        if !dir {
            if moved_in == want_in {
                return Err(FAILED);
            }
            wr(REG_XFER_DATA, data[i]);
            wr(REG_XFER_DATA, data[i + 1]);
            moved_in += 1;
        } else {
            // In-place encrypt must consume all input before writing output.
            // Separate-output recovery may drain one limb before loading the next,
            // but only after all inputs for that limb have been consumed.
            if transfers
                .iter()
                .enumerate()
                .any(|(i, input)| !input.output && input.limb <= limb && progress[i] != N)
            {
                return Err(FAILED);
            }
            if (output.is_none() && moved_in != want_in) || moved_out == want_out {
                return Err(FAILED);
            }
            let buf = match output.as_deref_mut() {
                Some(o) => o,
                None => &mut *data,
            };
            buf[i] = rd(REG_XFER_DATA);
            buf[i + 1] = rd(REG_XFER_DATA);
            moved_out += 1;
        }
        progress[ti] += 1;
    }
    Err(FAILED)
}
/// Derive a fresh 160-bit seed into KeyVault and generate the resident key.
/// The seed is HMAC-512 KDF(KV[rt_cdi], label, TRNG nonce), written only to the
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
            HmacMode::Hmac512,
        )?;
        wr(REG_KV_RD_SEED_CTRL, (KEY_ID_FHE_SEED as u32) << 1 | KV_READ_EN);
        let status = poll(REG_KV_RD_SEED_STATUS, KV_STATUS_VALID)?;
        if status >> KV_STATUS_ERROR_SHIFT & 0xff != 0 {
            return Err(FAILED);
        }
        let status = run(CMD_KEYGEN, LIMBS, RNS_SCALE, &[], &mut [], None)?;
        if status & STATUS_KEY_VALID == 0 {
            return Err(FAILED);
        }
        Ok(())
    })();
    // The hardware keeps no copy after KEYGEN; drop the KeyVault copy too.
    let erased = key_vault.erase_key(KEY_ID_FHE_SEED);
    result.and(erased)
}
pub fn encrypt(data: &mut [u32]) -> CaliptraResult<()> {
    present()?;
    if data.len() < 8 * N {
        return Err(FAILED);
    }
    // Reject NaN/Inf slot encodings before touching the arithmetic engine.
    if data[..2 * N]
        .chunks_exact(2)
        .any(|v| v[1] & 0x7ff00000 == 0x7ff00000)
    {
        return Err(FAILED);
    }
    // a and e0 continue the resident key's sampling stream: no seed here.
    run(CMD_ENCRYPT, LIMBS, RNS_SCALE, ENCRYPT, data, None).map(|_| ())
}
pub fn decrypt(data: &mut [u32], output: &mut [u32]) -> CaliptraResult<()> {
    decrypt_with_scale(data, output, LOG_SCALE as u32)
}
/// Decode using the authenticated power-of-two scale exponent. This changes
/// decoding units only; the evaluator must supply the ciphertext's actual scale.
pub fn decrypt_with_scale(
    data: &mut [u32],
    output: &mut [u32],
    log_scale: u32,
) -> CaliptraResult<()> {
    present()?;
    if data.len() < 8 * N || output.len() < 2 * N || !(1..=40).contains(&log_scale) {
        return Err(FAILED);
    }
    // Reject non-canonical residues, as the software P-S backend does. Limb 1
    // is validated too, although decryption currently consumes limb 0 only.
    // Layout: c0 limb 0, c0 limb 1, c1 limb 0, c1 limb 1; LE u64 per coefficient.
    for (index, limb) in data[..8 * N].chunks_exact(2 * N).enumerate() {
        let q = Q[index % 2];
        if limb
            .chunks_exact(2)
            .any(|w| (u64::from(w[1]) << 32 | u64::from(w[0])) >= q)
        {
            return Err(FAILED);
        }
    }
    let scale = (-(log_scale as i32)) as u32;
    run(CMD_DECRYPT, LIMBS, scale, DECRYPT, data, Some(output)).map(|_| ())
}

/// Recover coefficient-domain residues without FFT/I2F/Project. Ciphertext keeps
/// the full profile layout (c0[0],c0[1],c1[0],c1[1]); `limbs` selects the prefix.
/// Input must already be authenticated. Output is private scratch, not a response.
/// Recovery needs a resident key covering the requested limbs. No scale change.
pub fn recover_residues(data: &mut [u32], limbs: usize, output: &mut [u32]) -> CaliptraResult<()> {
    present()?;
    if !(1..=2).contains(&limbs) || data.len() != 8 * N || output.len() != 2 * N * limbs {
        return Err(FAILED);
    }
    // Validate even unused limbs: a profile ciphertext has canonical residues.
    for (index, limb) in data.chunks_exact(2 * N).enumerate() {
        if limb
            .chunks_exact(2)
            .any(|w| (u64::from(w[1]) << 32 | u64::from(w[0])) >= Q[index % 2])
        {
            return Err(FAILED);
        }
    }
    let transfers = [
        xfer(false, 0, 0, 0),
        xfer(false, 1, 0, 4 * N),
        xfer(true, 2, 0, 0),
        xfer(false, 0, 1, 2 * N),
        xfer(false, 1, 1, 6 * N),
        xfer(true, 2, 1, 2 * N),
    ];
    let result = run(CMD_RECOVER, limbs as u32, 0, &transfers[..3 * limbs], data, Some(output)).map(|_| ());
    if result.is_err() {
        use zeroize::Zeroize;
        output.zeroize();
    }
    result
}

/// Reconstruct centered integer coefficients in caller-owned storage. The active
/// basis determines the unambiguous range; this cannot detect prior wraparound.
pub fn recover_coefficients(
    data: &mut [u32],
    limbs: usize,
    residue_scratch: &mut [u32],
    coefficients: &mut [i128],
) -> CaliptraResult<()> {
    use zeroize::Zeroize;
    let result = (|| {
        if coefficients.len() != N {
            return Err(FAILED);
        }
        recover_residues(data, limbs, residue_scratch)?;
        recovery::reconstruct(residue_scratch, limbs, coefficients).ok_or(FAILED)
    })();
    residue_scratch.zeroize();
    if result.is_err() {
        coefficients.zeroize();
    }
    result
}

/// Trusted q0 -> q0*q1 level refresh, with no slot decode/re-encode. The first
/// 4N words contain c0[q0],c1[q0]; output replaces the full 8N-word buffer.
/// Call only after authenticating the body and authorizing refresh. The caller
/// preserves the authenticated scale; hardware operates on integer coefficients.
pub fn refresh(data: &mut [u32]) -> CaliptraResult<()> {
    present()?;
    if data.len() != 8 * N
        || data[..4 * N]
            .chunks_exact(2)
            .any(|w| (u64::from(w[1]) << 32 | u64::from(w[0])) >= Q[0])
    {
        return Err(FAILED);
    }
    let transfers = [
        xfer(false, 0, 0, 0),
        xfer(false, 1, 0, 2 * N),
        xfer(true, 2, 0, 0),
        xfer(true, 2, 1, 2 * N),
        xfer(true, 3, 0, 4 * N),
        xfer(true, 3, 1, 6 * N),
    ];
    let result = run(CMD_REFRESH, LIMBS, 0, &transfers, data, None).map(|_| ());
    if result.is_err() {
        use zeroize::Zeroize;
        data.zeroize();
    }
    result
}
