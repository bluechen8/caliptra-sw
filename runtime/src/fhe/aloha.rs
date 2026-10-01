// Licensed under the Apache-2.0 license
//! N=256 Aloha backend. Data remains in command-owned mailbox/DCCM.
//! The generic Caliptra DMA transfers only GCM-wrapped request/response bodies.
//! Profile 0xa108: 128 interleaved complex f64 slots; c0 then c1, two N-word
//! residue limbs per component, each coefficient serialized as LE u64.
use caliptra_drivers::{CaliptraError, CaliptraResult, Trng};
const BASE: usize = 0x1005_0000;
const N: usize = 256;
const LOGN: i32 = 8;
const LOG_SCALE: i32 = 25;
/// Profile 0xa108 limb moduli, in limb order.
const Q: [u64; 2] = [(1 << 46) - (9 << 24) + 1, (1 << 47) - (1 << 24) + 1];
const POLL: usize = 20_000_000;
const FAILED: CaliptraError = CaliptraError::RUNTIME_FHE_DECRYPT_FAILED;

// fhe_top register map (OFF_* in fhe_top.sv).
const REG_NAME0: usize = 0x00;
const REG_CTRL: usize = 0x10;
const REG_STATUS: usize = 0x14;
const REG_CONFIG: usize = 0x30;
const REG_KGSEED0: usize = 0x34;
const REG_KGSEED1: usize = 0x38;
const REG_KGSCALE: usize = 0x4c;
const REG_ENCSCALE: usize = 0x50;
const REG_I2FSCALE: usize = 0x54;
const REG_KGKV_CTRL: usize = 0x78;
const REG_ENTSEED0: usize = 0x7c;
const REG_ENTSEED1: usize = 0x80;
const REG_RNG_CTRL: usize = 0x84;
const REG_STREAM_STATUS: usize = 0x88;
const REG_STREAM_LEFT: usize = 0x8c;
const REG_STREAM_DATA: usize = 0x90;
const REG_STREAM_CAP: usize = 0x94;

const NAME0: u32 = 0x534b4b43; // "CKKS"
const STREAM_CAP: u32 = 0x8000_0000 | N as u32;
const CMD_ENCRYPT: u32 = 1;
const CMD_KEYGEN: u32 = 2;
const CMD_DECRYPT: u32 = 4;
const CTRL_ZEROIZE: u32 = 1 << 3;
const STATUS_READY: u32 = 1 << 0;
const STATUS_VALID: u32 = 1 << 1;
const STATUS_ERROR: u32 = 1 << 3;
const KGKV_EN: u32 = 1 << 0;
const RNG_FREERUN: u32 = 1 << 0;
const RNG_RESEED: u32 = 1 << 1;
/// CONFIG.target_level: both RNS limbs.
const CONFIG_LIMBS: u32 = 2;
/// 12-bit RNS encode scale field for 2^LOG_SCALE at this N; signed decode scale.
const RNS_SCALE: u32 = ((LOG_SCALE - 52 - 1023 - LOGN) & 0xfff) as u32;
const I2F_SCALE: u32 = (-LOG_SCALE) as u32;
// STREAM_STATUS fields (fhe_local_stream.sv). Both ready bits imply active.
const STREAM_OUTPUT: u32 = 1 << 1;
const STREAM_IN_READY: u32 = 1 << 2;
const STREAM_OUT_VALID: u32 = 1 << 3;
const STREAM_HIGH_HALF: u32 = 1 << 12;

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
    if rd(REG_NAME0) != NAME0 || rd(REG_STREAM_CAP) != STREAM_CAP {
        return Err(CaliptraError::RUNTIME_FHE_ABSENT);
    }
    Ok(())
}
fn ready() -> CaliptraResult<()> {
    for _ in 0..POLL {
        if rd(REG_STATUS) & STATUS_READY != 0 {
            return Ok(());
        }
    }
    Err(FAILED)
}
/// Runs one command, clearing the controller on any failure after it starts.
/// Descriptor metadata comes from the walker, never from an external address;
/// session.rs has already authenticated the complete input snapshot.
fn run(
    cmd: u32,
    transfers: &[Transfer],
    data: &mut [u32],
    output: Option<&mut [u32]>,
) -> CaliptraResult<()> {
    ready()?;
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
) -> CaliptraResult<()> {
    let words = |dir| transfers.iter().filter(|t| t.output == dir).count() * N;
    let (want_in, want_out) = (words(false), words(true));
    let (mut moved_in, mut moved_out) = (0, 0);
    for _ in 0..POLL {
        let s = rd(REG_STREAM_STATUS);
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
                return Ok(());
            }
            continue;
        }
        let left = rd(REG_STREAM_LEFT) as usize;
        let dir = s & STREAM_OUTPUT != 0;
        let (ptr, limb) = ((s >> 4) & 7, (s >> 8) & 15);
        let t = transfers
            .iter()
            .find(|t| (t.output, t.ptr, t.limb) == (dir, ptr, limb))
            .ok_or(FAILED)?;
        if left == 0 || left > N || s & STREAM_HIGH_HALF != 0 {
            return Err(FAILED);
        }
        let i = t.base + 2 * (N - left);
        if !dir {
            if moved_in == want_in {
                return Err(FAILED);
            }
            wr(REG_STREAM_DATA, data[i]);
            wr(REG_STREAM_DATA, data[i + 1]);
            moved_in += 1;
        } else {
            // Encrypt writes ciphertext over its own input slots, so all input
            // must have been consumed before the first output word is accepted.
            if moved_in != want_in || moved_out == want_out {
                return Err(FAILED);
            }
            let buf = match output.as_deref_mut() {
                Some(o) => o,
                None => &mut *data,
            };
            buf[i] = rd(REG_STREAM_DATA);
            buf[i + 1] = rd(REG_STREAM_DATA);
            moved_out += 1;
        }
    }
    Err(FAILED)
}
pub fn keygen(trng: &mut Trng) -> CaliptraResult<()> {
    present()?;
    clear();
    ready()?;
    // The bring-up profile uses a firmware-generated seed on the internal AHB.
    // No mailbox field can choose it. KV-only hardware requires a KV provisioning
    // backend and is rejected rather than silently using an uninitialized slot.
    if rd(REG_KGKV_CTRL) & KGKV_EN != 0 {
        return Err(FAILED);
    }
    let (lo, hi, _, _) = trng.generate4()?;
    wr(REG_KGSEED0, lo);
    wr(REG_KGSEED1, hi);
    wr(REG_KGSCALE, RNS_SCALE);
    wr(REG_ENCSCALE, RNS_SCALE);
    wr(REG_I2FSCALE, I2F_SCALE);
    wr(REG_CONFIG, CONFIG_LIMBS);
    wr(REG_RNG_CTRL, RNG_FREERUN);
    run(CMD_KEYGEN, &[], &mut [], None)
}
pub fn encrypt(trng: &mut Trng, data: &mut [u32]) -> CaliptraResult<()> {
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
    let (lo, hi, _, _) = trng.generate4()?;
    wr(REG_ENTSEED0, lo);
    wr(REG_ENTSEED1, hi);
    wr(REG_RNG_CTRL, RNG_FREERUN | RNG_RESEED);
    run(CMD_ENCRYPT, ENCRYPT, data, None)
}
pub fn decrypt(data: &mut [u32], output: &mut [u32]) -> CaliptraResult<()> {
    present()?;
    if data.len() < 8 * N || output.len() < 2 * N {
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
    run(CMD_DECRYPT, DECRYPT, data, Some(output))
}
