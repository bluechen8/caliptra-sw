/*++

Licensed under the Apache-2.0 license.

File Name:

    fhe.rs

Abstract:

    Runtime firmware service for the CKKS FHE accelerator.

    This is the production counterpart of the bare-metal `libs/fhe_ckks` driver
    and the `smoke_test_fhe_freerun` test in the caliptra-rtl tree. It drives the
    FHE hardware block, which is an AHB responder at the VeeR-internal base
    0x1005_0000 (CALIPTRA_SLAVE_SEL_FHE), via raw volatile MMIO. The register
    offsets and command/status bit layout mirror `fhe_ckks.h` exactly.

    FIXME: there is no generated caliptra-registers module for this block yet, so
    the register map is hand-maintained in lockstep across this file, `fhe_ckks.h`,
    and the RTL register block — nothing enforces they agree. The proper fix is to
    author `fhe_reg.rdl`, add it to `reg_gen.sh`, and regenerate so both the SV
    register block and `caliptra_reg.h` come from that single source.

    Reseed policy (owned here, per the C'-2 free-run design):
      - KEYGEN materializes the resident secret key and marks the per-ciphertext
        a/e0 keystream "unseeded"; the hardware then STALLS the first ENCRYPT
        (STATUS.RESEED_REQ_PENDING) until firmware supplies fresh entropy.
      - This handler reseeds the a/e0 stream with a fresh 64-bit TRNG draw before
        EVERY ENCRYPT. Writing ENTSEED + RNG_CTRL.RESEED_REQ arms the pending
        reseed, which both satisfies the mandatory-reseed enforcement (first
        encrypt after keygen) and gives per-ciphertext forward secrecy on every
        subsequent encrypt. This is the stronger "reseed every encrypt" policy;
        a periodic "reseed every K" cadence would be a strict relaxation of it.

--*/

use crate::{mutrefbytes, Drivers};
use caliptra_common::mailbox_api::{
    FheDecryptReq, FheEncryptReq, FheKeygenReq, FheStatusResp, MailboxRespHeader,
};
use caliptra_drivers::{CaliptraError, CaliptraResult, Trng};
use zerocopy::FromBytes;

// ---- Register map (byte offsets from CLP_FHE_REG_BASE_ADDR); see fhe_ckks.h ----
const FHE_BASE: usize = 0x1005_0000;

const REG_NAME0: usize = 0x00;
const REG_CTRL: usize = 0x10;
const REG_STATUS: usize = 0x14;
const REG_CONFIG: usize = 0x30;
const REG_KGSEED0: usize = 0x34; // + KGSEED1 @0x38 (written as a lo/hi pair)
const REG_KGSCALE: usize = 0x4C;
const REG_ENCSCALE: usize = 0x50;
const REG_I2FSCALE: usize = 0x54;
const REG_PTR0_LO: usize = 0x58; // PTR0..3 are contiguous, 8 bytes each
const REG_KGKV_CTRL: usize = 0x78;
const REG_ENTSEED0: usize = 0x7C; // + ENTSEED1 @0x80 (written as a lo/hi pair)
const REG_RNG_CTRL: usize = 0x84;

// Commands (CTRL[2:0]) + control bits.
const CMD_ENCRYPT: u32 = 0x1;
const CMD_KEYGEN: u32 = 0x2;
const CMD_DECRYPT: u32 = 0x4;
const CTRL_ZEROIZE: u32 = 1 << 3;

// STATUS bits.
const STATUS_READY: u32 = 1 << 0;
const STATUS_VALID: u32 = 1 << 1;
const STATUS_ERROR: u32 = 1 << 3;
const STATUS_RESEED_REQ_PENDING: u32 = 1 << 4;

// RNG_CTRL bits.
const RNG_CTRL_FREERUN_EN: u32 = 1 << 0;
const RNG_CTRL_RESEED_REQ: u32 = 1 << 1;

// Identity ("CKKS").
const NAME0_EXP: u32 = 0x534B_4B43;

// Generous poll bound so a wedged block surfaces as an error instead of hanging
// the runtime command loop (the WDT would otherwise fire).
const POLL_GUARD: u32 = 200_000_000;

#[inline(always)]
fn rd(off: usize) -> u32 {
    // SAFETY: fixed MMIO aperture of the FHE AHB responder, VeeR-internal view.
    unsafe { core::ptr::read_volatile((FHE_BASE + off) as *const u32) }
}

#[inline(always)]
fn wr(off: usize, val: u32) {
    // SAFETY: fixed MMIO aperture of the FHE AHB responder, VeeR-internal view.
    unsafe { core::ptr::write_volatile((FHE_BASE + off) as *mut u32, val) }
}

/// Write a 64-bit value as a lo/hi u32 pair at `off_lo` / `off_lo+4`.
fn wr64(off_lo: usize, lo: u32, hi: u32) {
    wr(off_lo, lo);
    wr(off_lo + 4, hi);
}

/// Write DMA base-pointer register `idx` (0..=3) with a 64-bit DRAM byte address.
fn set_ptr(idx: usize, lo: u32, hi: u32) {
    wr64(REG_PTR0_LO + idx * 8, lo, hi);
}

/// Spin until STATUS.READY, then write CTRL = `cmd` (fire, no completion poll).
fn issue(cmd: u32) -> CaliptraResult<()> {
    let mut guard = POLL_GUARD;
    while (rd(REG_STATUS) & STATUS_READY) == 0 {
        guard -= 1;
        if guard == 0 {
            return Err(CaliptraError::RUNTIME_INTERNAL);
        }
    }
    wr(REG_CTRL, cmd);
    Ok(())
}

/// Poll STATUS until VALID (or a stall/timeout); returns the final STATUS word.
fn poll_valid(stall_bit: u32) -> CaliptraResult<u32> {
    let mut guard = POLL_GUARD;
    loop {
        let st = rd(REG_STATUS);
        if (st & (STATUS_VALID | stall_bit)) != 0 {
            return Ok(st);
        }
        guard -= 1;
        if guard == 0 {
            return Err(CaliptraError::RUNTIME_INTERNAL);
        }
    }
}

/// Publish a fresh 64-bit seed and ring the reseed doorbell (FREERUN_EN|RESEED_REQ).
/// This arms the pending reseed and releases an encrypt stalled in RESEED_REQ_PENDING.
fn reseed(lo: u32, hi: u32) {
    wr64(REG_ENTSEED0, lo, hi);
    wr(REG_RNG_CTRL, RNG_CTRL_FREERUN_EN | RNG_CTRL_RESEED_REQ);
}

/// Draw a fresh 64-bit seed (as a lo/hi u32 pair) from the runtime TRNG/CSRNG.
fn trng_seed64(trng: &mut Trng) -> CaliptraResult<(u32, u32)> {
    let (w0, w1, _, _) = trng.generate4()?;
    Ok((w0, w1))
}

/// Verify the block identity before touching it.
fn check_present() -> CaliptraResult<()> {
    if rd(REG_NAME0) != NAME0_EXP {
        return Err(CaliptraError::RUNTIME_FHE_ABSENT);
    }
    Ok(())
}

fn status_resp(resp: &mut [u8], status: u32) -> CaliptraResult<usize> {
    let out = mutrefbytes::<FheStatusResp>(resp)?;
    out.hdr = MailboxRespHeader::default();
    out.status = status;
    Ok(core::mem::size_of::<FheStatusResp>())
}

pub struct FheCmd;
impl FheCmd {
    /// FHE_KEYGEN: program the microsequencer, enable free-run, run KEYGEN.
    pub(crate) fn keygen(
        _drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let req = FheKeygenReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        check_present()?;

        // Clean slate.
        wr(REG_CTRL, CTRL_ZEROIZE);

        // Seeds + scales + CONFIG (CONFIG = target_level[3:0] | param_set_id<<4).
        // FIXME(fhe-security): the KGSEED mailbox path lets an EXTERNAL caller
        // supply the CKKS secret-key root seed — unacceptable for production (the
        // secret key must originate and stay on-chip). Strip this in the secure
        // build: (1) remove kg_seed_lo/hi from FheKeygenReq (api/src/mailbox.rs)
        // and force kv_en, (2) drop this wr64(REG_KGSEED0,...) so the seed only
        // ever comes from the firmware-provisioned KeyVault entry, (3) compile the
        // HW with `+define+FHE_KV_SEED_ONLY` (fhe_top.sv already gates the KGSEED
        // register path out under that define — kg_seed_eff := kv_seed only). The
        // register path stays only for DPI cosim / unit-TB determinism. Picked up
        // in a future session.
        wr64(REG_KGSEED0, req.kg_seed_lo, req.kg_seed_hi);
        wr(REG_KGSCALE, req.kg_scale);
        wr(REG_ENCSCALE, req.enc_scale);
        wr(REG_I2FSCALE, req.i2f_scale);
        // FIXME: param_set_id is a reserved selector — the HW latches and echoes
        // it but decodes nothing (fhe_top.sv). The parameter set is fixed today:
        // N is compile-time (`FHE_N`) and the RNS q-set is baked into the ROMs, so
        // only param_set_id==0 is valid. Callers must pass 0 until the HW grows a
        // (q-set, N) table + decode + unsupported-id ERROR path.
        wr(
            REG_CONFIG,
            (req.target_level & 0xF) | ((req.param_set_id & 0xF) << 4),
        );

        // Optional KeyVault-sourced keygen seed (KGKV_CTRL: bit0=KV_EN, [8:4]=entry).
        if req.kv_en != 0 {
            wr(REG_KGKV_CTRL, ((req.kv_entry & 0x1F) << 4) | 1);
        } else {
            wr(REG_KGKV_CTRL, 0);
        }

        // Enable free-run PRNG for the a/e0 stream (per-ciphertext reseed at encrypt).
        wr(REG_RNG_CTRL, RNG_CTRL_FREERUN_EN);

        issue(CMD_KEYGEN).map_err(|_| CaliptraError::RUNTIME_FHE_KEYGEN_FAILED)?;
        let st = poll_valid(0).map_err(|_| CaliptraError::RUNTIME_FHE_KEYGEN_FAILED)?;
        if (st & STATUS_ERROR) != 0 {
            return Err(CaliptraError::RUNTIME_FHE_KEYGEN_FAILED);
        }
        status_resp(resp, st)
    }

    /// FHE_ENCRYPT: reseed a/e0 with fresh TRNG entropy, then ENCRYPT.
    pub(crate) fn encrypt(
        drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let req = FheEncryptReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        check_present()?;

        // DMA pointers: PTR0 = plaintext src, PTR2 = c0 dst, PTR3 = c1 dst.
        set_ptr(0, req.src_lo, req.src_hi);
        set_ptr(2, req.c0_lo, req.c0_hi);
        set_ptr(3, req.c1_lo, req.c1_hi);

        // Reseed BEFORE issuing: arms the pending reseed so the mandatory-reseed
        // enforcement (first encrypt after keygen) is satisfied and every encrypt
        // gets fresh per-ciphertext entropy (forward secrecy).
        let (lo, hi) = trng_seed64(&mut drivers.trng)?;
        reseed(lo, hi);

        issue(CMD_ENCRYPT).map_err(|_| CaliptraError::RUNTIME_FHE_ENCRYPT_FAILED)?;

        // Poll for completion or a stall (in case the pre-issue reseed edge was
        // missed); a stall is serviced with a fresh reseed doorbell.
        let mut st = poll_valid(STATUS_RESEED_REQ_PENDING)
            .map_err(|_| CaliptraError::RUNTIME_FHE_ENCRYPT_FAILED)?;
        if (st & STATUS_VALID) == 0 && (st & STATUS_RESEED_REQ_PENDING) != 0 {
            let (lo, hi) = trng_seed64(&mut drivers.trng)?;
            reseed(lo, hi);
            st = poll_valid(0).map_err(|_| CaliptraError::RUNTIME_FHE_RESEED_TIMEOUT)?;
        }
        if (st & STATUS_ERROR) != 0 {
            return Err(CaliptraError::RUNTIME_FHE_ENCRYPT_FAILED);
        }
        status_resp(resp, st)
    }

    /// FHE_DECRYPT: no sampling, so no reseed/stall.
    pub(crate) fn decrypt(
        _drivers: &mut Drivers,
        cmd_bytes: &[u8],
        resp: &mut [u8],
    ) -> CaliptraResult<usize> {
        let req = FheDecryptReq::ref_from_bytes(cmd_bytes)
            .map_err(|_| CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
        check_present()?;

        // PTR0 = c0 src, PTR1 = c1 src, PTR2 = recovered dst.
        set_ptr(0, req.c0_lo, req.c0_hi);
        set_ptr(1, req.c1_lo, req.c1_hi);
        set_ptr(2, req.out_lo, req.out_hi);

        issue(CMD_DECRYPT).map_err(|_| CaliptraError::RUNTIME_FHE_DECRYPT_FAILED)?;
        let st = poll_valid(0).map_err(|_| CaliptraError::RUNTIME_FHE_DECRYPT_FAILED)?;
        if (st & STATUS_ERROR) != 0 {
            return Err(CaliptraError::RUNTIME_FHE_DECRYPT_FAILED);
        }
        status_resp(resp, st)
    }
}
