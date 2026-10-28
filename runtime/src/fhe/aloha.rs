// Licensed under the Apache-2.0 license
//! Aloha backend on the DMA stream: Aloha moves every buffer between DRAM and
//! the engine through Caliptra's axi_dma, and VeeR never reads the data. VeeR
//! sets up and finishes AES-GCM around the DMA's text phase.
//! The build fixes N and the largest level L_max (CAP); each ENCRYPT and
//! REFRESH picks a level 1..=L_max. Message: N/2 interleaved complex f64 slots.
//! Ciphertext: c0 then c1, `level` N-word residue limbs per component, each
//! coefficient serialized as LE u64.
//! Evaluation keys (docs/fhe/21): L = L_max - 1 rows, each c0 then c1 with
//! L + 1 limbs (q_0..q_{L-1}, then P = q_{L_max-1}), one EVKGEN per row.
use caliptra_common::keyids::KEY_ID_FHE_SEED;
use caliptra_drivers::{
    hmac_kdf, Aes, AesKey, AesOperation, CaliptraError, CaliptraResult, Hmac, HmacMode, KeyId,
    KeyReadArgs, KeyUsage, KeyVault, KeyWriteArgs, Trng,
};
const BASE: usize = 0x1005_0000;
/// KEYGEN's RNS encode scale (its value does not reach the key).
const KEYGEN_LOG_SCALE: u32 = 25;
/// log2 of the slot scale ENCRYPT accepts is below this: qbits(q0) - 1, q0 of
/// 46 bits (fhe_profiles.py), as fhe-core's slots::max_log_delta. The CROM
/// manifest pins the prime catalog (CROM_CATALOG), so a new catalog bumps
/// that byte and this bound together.
pub const MAX_LOG_DELTA: u32 = 45;
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
const REG_EVK: usize = 0x54;
/// CROM window (docs/fhe/19): word w, lane k at REG_CROM + 16*w + 4*k. The
/// lane-3 store writes the word; stores are taken only while the engine is idle.
const REG_CROM: usize = 0x4000;

const NAME0: u32 = 0x534b4b43; // "CKKS"
/// CAP fields: [15:0] N, [19:16] L_max, [21] EVKGEN, [24] DMA stream,
/// [31:28] map version. Other capability bits (build options) are ignored.
const CAP_CHECKED: u32 = 1 << 24 | 0xf << 28;
const CAP_EXPECTED: u32 = 1 << 24 | 2 << 28;
const CAP_EVKGEN: u32 = 1 << 21;
const CMD_ENCRYPT: u32 = 1;
const CMD_KEYGEN: u32 = 2;
const CMD_EVKGEN: u32 = 3;
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
/// KDF label binding the derived seed to this use of the runtime CDI.
const SEED_LABEL: &[u8] = b"ALOHA-FHE-SEED";
/// The CROM table this image carries, from gen_aloha_tables.py: a 16-byte
/// manifest ("FHE2", layout 2, catalog 1, log2 N, L_max, word count, 0), then
/// the 128-bit words as LE u32 lanes, low lane first.
static CROM_IMAGE: &[u8] = include_bytes!(env!("FHE_CROM"));
const CROM_MAGIC: u32 = 0x4648_4532; // "FHE2"
const CROM_LAYOUT: u8 = 2;
const CROM_CATALOG: u8 = 1;

/// The engine's build: ring dimension N = 2^logn and largest level L_max.
#[derive(Clone, Copy)]
pub struct Geometry {
    pub logn: u32,
    pub l_max: u32,
    /// The engine generates evaluation keys (CAP.EVKGEN; needs L_max >= 2).
    pub eval_keys: bool,
}
impl Geometry {
    /// One limb of one component: N LE u64 coefficients.
    pub fn limb_bytes(self) -> u64 {
        8 << self.logn
    }
    /// The slot vector: N/2 complex f64, the same size as a limb.
    pub fn message_bytes(self) -> usize {
        self.limb_bytes() as usize
    }
    /// c0 and c1, `level` limbs each.
    fn ciphertext_bytes(self, level: u32) -> usize {
        2 * level as usize * self.limb_bytes() as usize
    }
    /// Evaluation keys are at level L_max - 1, with P = q_{L_max-1}.
    fn key_level(self) -> u32 {
        self.l_max - 1
    }
    /// The largest ciphertext level: the Q primes, without P when the engine
    /// serves evaluation keys (as the parameter sets count levels).
    pub fn levels(self) -> u32 {
        if self.eval_keys {
            self.key_level()
        } else {
            self.l_max
        }
    }
    /// One key row: c0 then c1, L + 1 limbs each.
    fn key_row_bytes(self) -> u64 {
        self.ciphertext_bytes(self.key_level() + 1) as u64
    }
    /// A Galois or relinearization key: L rows.
    pub fn eval_key_bytes(self) -> usize {
        self.key_level() as usize * self.key_row_bytes() as usize
    }
    /// 12-bit RNS encode scale field for 2^log_delta at this N.
    fn rns_scale(self, log_delta: u32) -> u32 {
        ((log_delta as i32 - 52 - 1023 - self.logn as i32) & 0xfff) as u32
    }
    /// CONFIG = {SCALE[27:16], LOGN[7:4], L[3:0]}.
    fn config(self, limbs: u32, scale: u32) {
        wr(
            REG_CONFIG,
            (scale & 0xfff) << 16 | self.logn << 4 | (limbs & 0xf),
        );
    }
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
/// KEY_VALID: the engine holds a resident key.
pub fn key_valid() -> bool {
    rd(REG_STATUS) & STATUS_KEY_VALID != 0
}
/// Whether VeeR may halt. FHE runs on Caliptra's gated clock and does not hold
/// it open, so the runtime halts only while the engine is absent or READY.
/// Presence is read from NAME0, not the boot's table flag: a failed table
/// install can leave an earlier image's command draining.
pub fn idle() -> bool {
    rd(REG_NAME0) != NAME0 || rd(REG_STATUS) & STATUS_READY != 0
}
/// The engine's geometry, if it is present and speaks map v2 on the DMA stream.
pub fn geometry() -> CaliptraResult<Geometry> {
    let cap = rd(REG_CAP);
    let n = cap & 0xffff;
    let g = Geometry {
        logn: n.trailing_zeros(),
        l_max: cap >> 16 & 0xf,
        eval_keys: cap & CAP_EVKGEN != 0,
    };
    if rd(REG_NAME0) != NAME0
        || cap & CAP_CHECKED != CAP_EXPECTED
        || !n.is_power_of_two()
        || !(128..=16384).contains(&n)
        || g.l_max == 0
    {
        return Err(CaliptraError::RUNTIME_FHE_ABSENT);
    }
    Ok(g)
}
/// Runtime boot (every reset flow): ZEROIZE drops the key and any state an
/// earlier image left, since an update reset does not reset the engine. Then
/// this image's table is copied into the CROM. Fails, leaving FHE unusable,
/// if the engine is absent or the table was built for another geometry.
pub fn install_tables() -> CaliptraResult<Geometry> {
    let g = geometry()?;
    // gen_aloha_tables.py checked the word count against (log2 N, L_max).
    let (manifest, table) = CROM_IMAGE.split_at(CROM_IMAGE.len().min(16));
    if manifest.len() != 16
        || le32(manifest, 0) != CROM_MAGIC
        || manifest[4] != CROM_LAYOUT
        || manifest[5] != CROM_CATALOG
        || u32::from(manifest[6]) != g.logn
        || u32::from(manifest[7]) != g.l_max
        || table.len() != le32(manifest, 8) as usize * 16
    {
        return Err(CaliptraError::RUNTIME_FHE_ABSENT);
    }
    clear();
    ready()?;
    for i in 0..table.len() / 4 {
        wr(REG_CROM + 4 * i, le32(table, 4 * i));
    }
    Ok(g)
}
/// The LE u32 at byte offset `i`.
fn le32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
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
fn start(
    g: Geometry,
    cmd: u32,
    limbs: u32,
    scale: u32,
    slots: &[(usize, u64)],
) -> CaliptraResult<()> {
    ready()?;
    launch(g, cmd, limbs, scale, slots);
    Ok(())
}
/// `start` without the READY wait, for a caller that wrote other
/// READY-gated registers (EVK) after its own wait.
fn launch(g: Geometry, cmd: u32, limbs: u32, scale: u32, slots: &[(usize, u64)]) {
    g.config(limbs, scale);
    for &(slot, base) in slots {
        wr(REG_SLOT0 + 8 * slot, base as u32);
        wr(REG_SLOT0 + 8 * slot + 4, (base >> 32) as u32);
    }
    wr(REG_CTRL, cmd);
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
    g: Geometry,
    hmac: &mut Hmac,
    trng: &mut Trng,
    key_vault: &mut KeyVault,
    rt_cdi: KeyId,
) -> CaliptraResult<()> {
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
            KeyWriteArgs::new(
                KEY_ID_FHE_SEED,
                KeyUsage::default().set_mldsa_key_gen_seed_en(),
            )
            .into(),
            HmacMode::Hmac384,
        )?;
        wr(
            REG_KV_RD_SEED_CTRL,
            (KEY_ID_FHE_SEED as u32) << 1 | KV_READ_EN,
        );
        let status = poll(REG_KV_RD_SEED_STATUS, KV_STATUS_VALID)?;
        if status >> KV_STATUS_ERROR_SHIFT & 0xff != 0 {
            return Err(FAILED);
        }
        // KEYGEN fills every installed limb.
        // READY since the wait above; the KV read does not start the engine.
        launch(g, CMD_KEYGEN, g.l_max, g.rns_scale(KEYGEN_LOG_SCALE), &[]);
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
/// ENCRYPT the sealed slot vector at `src` into c0, c1 at `dst`, `level`
/// limbs each (component-major), encoded at 2^`log_delta`; both are checked
/// by the caller and the engine. The DMA GCM-decrypts the message into Aloha
/// under `key`, `iv` and `aad`; at COMMIT_WAIT the tag decides INPUT_COMMIT or
/// ZEROIZE, so no arithmetic sees an unauthenticated message. The ciphertext
/// bypasses AES.
#[allow(clippy::too_many_arguments)]
pub fn encrypt(
    g: Geometry,
    aes: &mut Aes,
    trng: &mut Trng,
    key: AesKey,
    iv: &[u8; 12],
    aad: &[u8],
    tag: &[u8; 16],
    log_delta: u32,
    level: u32,
    src: u64,
    dst: u64,
) -> CaliptraResult<Done> {
    aes.aes_256_gcm_begin(trng, iv, key, aad, AesOperation::Decrypt)?;
    // a and e0 continue the resident key's sampling stream: no seed here.
    start(
        g,
        CMD_ENCRYPT,
        level,
        g.rns_scale(log_delta),
        &[(0, src), (2, dst), (3, dst + level as u64 * g.limb_bytes())],
    )?;
    let status = wait(STATUS_VALID | STATUS_COMMIT_WAIT)?;
    if status & STATUS_VALID != 0 {
        // Rejected before ingress (precondition, slot address, lease).
        discard_gcm();
        return Ok(Done::new(status));
    }
    let computed = aes.aes_256_gcm_end(aad.len(), g.message_bytes())?;
    let commit = constant_time_eq::constant_time_eq(&computed, tag);
    wr(
        REG_CTRL,
        if commit {
            CTRL_INPUT_COMMIT
        } else {
            CTRL_ZEROIZE
        },
    );
    wait(STATUS_VALID).map(Done::new)
}
/// DECRYPT c0 and c1 limb 0 at `src` (2N words) into the slot vector at `dst`,
/// GCM-encrypted by the DMA under `key`, `iv` and `aad`; returns the tag.
/// Decode divides by 2^`log_delta` (0 returns Δ·z, for a host holding a
/// scale that is not a power of two).
#[allow(clippy::too_many_arguments)]
pub fn decrypt(
    g: Geometry,
    aes: &mut Aes,
    trng: &mut Trng,
    key: AesKey,
    iv: &[u8; 12],
    aad: &[u8],
    log_delta: u32,
    src: u64,
    dst: u64,
) -> CaliptraResult<Done> {
    aes.aes_256_gcm_begin(trng, iv, key, aad, AesOperation::Encrypt)?;
    let scale = (-(log_delta as i32)) as u32;
    // DECRYPT reads limb 0 only.
    start(
        g,
        CMD_DECRYPT,
        1,
        scale,
        &[(0, src), (1, src + g.limb_bytes()), (2, dst)],
    )?;
    let mut done = Done::new(wait(STATUS_VALID)?);
    if done.cause != 0 {
        // A failed DECRYPT writes no output.
        discard_gcm();
        return Ok(done);
    }
    done.tag = aes.aes_256_gcm_end(aad.len(), g.message_bytes())?;
    Ok(done)
}
/// Trusted level refresh from q0 to `level` limbs, with no slot
/// decode/re-encode: c0, c1 limb 0 from `src`, `level` limbs each to `dst`.
/// Call only after authorizing refresh; `level` is checked by the caller and
/// the engine. The output keeps the input's scale. No AES.
pub fn refresh(g: Geometry, level: u32, src: u64, dst: u64) -> CaliptraResult<Done> {
    let limb = g.limb_bytes();
    start(
        g,
        CMD_REFRESH,
        level,
        0,
        &[
            (0, src),
            (1, src + limb),
            (2, dst),
            (3, dst + level as u64 * limb),
        ],
    )?;
    wait(STATUS_VALID).map(Done::new)
}
/// h = g^-1 mod 2N for odd g (0 stays 0, the relinearization key). Odd g is
/// invertible mod 2^k and each Newton step doubles the correct bits.
fn galois_inverse(galois: u32, logn: u32) -> u32 {
    let mut h = galois;
    // g*g = 1 mod 8, so g starts 3 bits right; 3 steps reach 24 >= log2(2N).
    for _ in 0..3 {
        h = h.wrapping_mul(2u32.wrapping_sub(galois.wrapping_mul(h)));
    }
    h & ((2 << logn) - 1)
}
/// Generate one evaluation key into `dst` (`Geometry::eval_key_bytes`), one
/// EVKGEN per row: the relinearization key for `galois` = 0, else the Galois
/// key for g = `galois` (checked by the caller). The engine applies h = g^-1
/// mod 2N to the secret, as Lattigo's GenGaloisKey does. Rows are public; a
/// failed row leaves a partial key, which the caller discards.
pub fn eval_key(g: Geometry, galois: u32, dst: u64) -> CaliptraResult<Done> {
    let l = g.key_level();
    let h = galois_inverse(galois, g.logn);
    let c1 = u64::from(l + 1) * g.limb_bytes();
    let mut status = 0;
    for row in 0..l {
        let c0 = dst + u64::from(row) * g.key_row_bytes();
        // EVK, like CONFIG and the slots, is written only while READY.
        ready()?;
        wr(REG_EVK, row << 16 | h);
        launch(g, CMD_EVKGEN, l, 0, &[(2, c0), (3, c0 + c1)]);
        status = wait(STATUS_VALID)?;
        if status & STATUS_ERROR != 0 {
            break;
        }
    }
    Ok(Done::new(status))
}

#[cfg(test)]
mod tests {
    use super::galois_inverse;
    #[test]
    fn galois_inverse_mod_2n() {
        for logn in [7, 8, 10, 13, 14] {
            let m = 2u32 << logn;
            for g in (1..m).step_by(2) {
                let h = galois_inverse(g, logn);
                assert!(h < m && g * h % m == 1, "logn {logn} g {g} h {h}");
            }
        }
        assert_eq!(galois_inverse(0, 8), 0);
    }
}
