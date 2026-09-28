// Licensed under the Apache-2.0 license
//! Real RV32 runtime dispatch on the software SoC model; no RTL claims.
#![cfg(not(any(
    feature = "verilator",
    feature = "fpga_realtime",
    feature = "fpga_subsystem"
)))]
use caliptra_api::{
    mailbox::{CommandId, FheRawDecryptReq, FheRawEncryptReq, FheSwKeygenReq, FheSwResp},
    SocManager,
};
use caliptra_builder::{firmware, FwId, ImageOptions};
use caliptra_hw_model::{BootParams, DefaultHwModel, Fuses, HwModel, InitParams};
use caliptra_image_types::FwVerificationPqcKeyType;
use zerocopy::{FromBytes, IntoBytes};

fn boot(fwid: &'static FwId<'static>) -> DefaultHwModel {
    let rom = caliptra_builder::build_firmware_rom(&firmware::ROM_WITH_UART_NO_MLDSA).unwrap();
    let mut opts = ImageOptions::default();
    opts.pqc_key_type = FwVerificationPqcKeyType::LMS;
    opts.vendor_config.pl0_pauser = Some(1);
    let image =
        caliptra_builder::build_and_sign_image(&firmware::FMC_WITH_UART_NO_MLDSA, fwid, opts)
            .unwrap();
    fn hash_words(bytes: &[u8]) -> [u32; 12] {
        use sha2::{Digest, Sha384};
        let hash = Sha384::digest(bytes);
        core::array::from_fn(|i| u32::from_be_bytes(hash[i * 4..i * 4 + 4].try_into().unwrap()))
    }
    let vendor_pk_hash = hash_words(image.manifest.preamble.vendor_pub_key_info.as_bytes());
    let owner_pk_hash = hash_words(image.manifest.preamble.owner_pub_keys.as_bytes());
    let image = image.to_bytes().unwrap();
    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            fuses: Fuses {
                vendor_pk_hash,
                owner_pk_hash,
                fuse_pqc_key_type: FwVerificationPqcKeyType::LMS as u32,
                ..Default::default()
            },
            ..Default::default()
        },
        BootParams {
            fw_image: Some(&image),
            ..Default::default()
        },
    )
    .unwrap();
    let mut ready = false;
    for _ in 0..20_000_000 {
        assert_eq!(
            model.soc_ifc().cptra_fw_error_fatal().read(),
            0,
            "boot failed"
        );
        if model
            .soc_ifc()
            .cptra_flow_status()
            .read()
            .ready_for_runtime()
        {
            ready = true;
            break;
        }
        model.step();
    }
    assert!(ready, "runtime boot timed out");
    model
}
fn wire(id: u32, data: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    out.extend_from_slice(payload);
    let sum = caliptra_common::checksum::calc_checksum(id, &out[4..]);
    out[..4].copy_from_slice(&sum.to_le_bytes());
    out
}
fn send(model: &mut DefaultHwModel, id: CommandId, data: &[u8], payload: &[u8]) -> Vec<u8> {
    let id: u32 = id.into();
    // P-L-eq software kernels exceed the model helper's fixed 40M-cycle
    // command deadline. Keep a bounded, explicit 120M observation budget here.
    // Expiry is a test failure, never a DMA cancellation or buffer reclamation.
    model
        .start_mailbox_execute(id, &wire(id, data, payload))
        .unwrap();
    let mut done = false;
    for _ in 0..120_000_000 {
        if !model.soc_mbox().status().read().status().cmd_busy() {
            done = true;
            break;
        }
        model.step();
    }
    assert!(done, "FHE command exceeded its emulator observation budget");
    let out = model.finish_mailbox_execute().unwrap().unwrap();
    assert!(caliptra_common::checksum::verify_checksum(
        u32::from_le_bytes(out[..4].try_into().unwrap()),
        0,
        &out[4..]
    ));
    out
}
fn key_req() -> FheSwKeygenReq {
    FheSwKeygenReq {
        version: 1,
        seed_mode: 1,
        seed: *include_bytes!("../../fhe-core/tests/vectors/ps/seed.bin"),
        ..Default::default()
    }
}
fn keygen(model: &mut DefaultHwModel) -> u32 {
    let resp = send(model, CommandId::FHE_KEYGEN, key_req().as_bytes(), &[]);
    FheSwResp::ref_from_bytes(&resp).unwrap().session_id
}
fn req(id: u32, seq: u32) -> FheRawDecryptReq {
    FheRawDecryptReq {
        version: 1,
        session_id: id,
        seq,
        input_len: 4096,
        ..Default::default()
    }
}
const CT: &[u8] = include_bytes!("../../fhe-core/tests/vectors/ps/ct.bin");
const DEC: &[u8] = include_bytes!("../../fhe-core/tests/vectors/ps/dec.bin");
fn reject(model: &mut DefaultHwModel, id: CommandId, data: &[u8], payload: &[u8]) {
    let id: u32 = id.into();
    let err = model
        .mailbox_execute(id, &wire(id, data, payload))
        .unwrap_err();
    let expected = if matches!(id, 0x4648_454e | 0x4648_4445) {
        caliptra_api::error::CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND
    } else {
        caliptra_api::error::CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS
    };
    assert!(
        matches!(err, caliptra_hw_model::ModelError::MailboxCmdFailed(code) if code == u32::from(expected)),
        "{err:?}"
    );
}
#[test]
fn ps_decrypt_mailbox_and_pointer_golden() {
    let mut model = boot(&firmware::APP_FHE_DEBUG);
    model.paint_runtime_stack_canary();
    reject(
        &mut model,
        CommandId::FHE_DECRYPT_RAW,
        req(1, 1).as_bytes(),
        CT,
    );
    let id = keygen(&mut model);
    assert_ne!(id, 0);
    let mut r = req(id, 1);
    r.param_set = 1;
    reject(&mut model, CommandId::FHE_DECRYPT_RAW, r.as_bytes(), CT);
    r.param_set = 0;
    reject(
        &mut model,
        CommandId::FHE_DECRYPT_RAW,
        r.as_bytes(),
        &CT[..CT.len() - 4],
    );
    let result = send(&mut model, CommandId::FHE_DECRYPT_RAW, r.as_bytes(), CT);
    let (hdr, payload) = FheSwResp::ref_from_prefix(&result).unwrap();
    assert_eq!(hdr.output_len, 2048);
    assert_eq!(hdr.status, 0);
    assert!(hdr.cycles_lo != 0 || hdr.cycles_hi != 0);
    assert_eq!(payload, DEC);
    reject(&mut model, CommandId::FHE_DECRYPT_RAW, r.as_bytes(), CT); // replay
    r.seq = 2;
    r.mode = 1;
    r.src_lo = 0x8000_0000;
    r.dst_lo = 0x8000_2000;
    model.soc_dram_mut().unwrap()[..4096].copy_from_slice(CT);
    model.soc_dram_mut().unwrap()[8192..10240].fill(0xa5);
    r.dst_hi = 2;
    r.src_lo = 0x8100_0000; // unmapped in model: invalid output must reject before DMA
    reject(&mut model, CommandId::FHE_DECRYPT_RAW, r.as_bytes(), &[]);
    r.dst_hi = 0;
    r.src_lo = 0x8000_0000;
    let result = send(&mut model, CommandId::FHE_DECRYPT_RAW, r.as_bytes(), &[]);
    assert_eq!(result.len(), core::mem::size_of::<FheSwResp>());
    assert_eq!(&model.soc_dram_mut().unwrap()[8192..10240], DEC);
    assert_eq!(&model.soc_dram_mut().unwrap()[..4096], CT);
    // Each streamed limb is validated before its write. Late invalid input
    // fails the command; any previously written output is invalid as a whole.
    r.seq = 3;
    model.soc_dram_mut().unwrap()[4092..4096].fill(0xff);
    model.soc_dram_mut().unwrap()[8192..10240].fill(0xa5);
    reject(&mut model, CommandId::FHE_DECRYPT_RAW, r.as_bytes(), &[]);
    assert_eq!(&model.soc_dram_mut().unwrap()[8192..9216], &DEC[..1024]);
    assert!(model.soc_dram_mut().unwrap()[9216..10240]
        .iter()
        .all(|&b| b == 0xa5));
    model.soc_dram_mut().unwrap()[..4096].copy_from_slice(CT);
    r.seq = 4;
    send(&mut model, CommandId::FHE_DECRYPT_RAW, r.as_bytes(), &[]);
    let new_id = keygen(&mut model);
    assert_ne!(id, new_id);
    r.seq = 1;
    reject(&mut model, CommandId::FHE_DECRYPT_RAW, r.as_bytes(), &[]);
    r.session_id = new_id;
    send(&mut model, CommandId::FHE_DECRYPT_RAW, r.as_bytes(), &[]);
    // Fresh entropy path also materializes a key (not a vector equality check).
    let random = FheSwKeygenReq {
        version: 1,
        ..Default::default()
    };
    let result = send(&mut model, CommandId::FHE_KEYGEN, random.as_bytes(), &[]);
    let random_id = FheSwResp::ref_from_bytes(&result).unwrap().session_id;
    // Address is legal in the 4-GiB fabric window but unmapped in the 8-MiB
    // emulator RAM. Exercise the real register adapter's sticky error path.
    r.session_id = random_id;
    r.seq = 1;
    r.src_lo = 0x8100_0000;
    let err = model
        .mailbox_execute(
            CommandId::FHE_DECRYPT_RAW.into(),
            &wire(CommandId::FHE_DECRYPT_RAW.into(), r.as_bytes(), &[]),
        )
        .unwrap_err();
    assert!(
        matches!(err, caliptra_hw_model::ModelError::MailboxCmdFailed(code)
        if code == u32::from(caliptra_api::error::CaliptraError::RUNTIME_FHE_DECRYPT_FAILED)),
        "{err:?}"
    );
    r.src_lo = 0x8000_0000;
    r.seq = 2;
    reject(&mut model, CommandId::FHE_DECRYPT_RAW, r.as_bytes(), &[]);
    reject(&mut model, CommandId::FHE_KEYGEN, key_req().as_bytes(), &[]);
    println!(
        "P-S debug command stack canary extent: {} bytes",
        model.runtime_stack_canary_used()
    );
    assert!(
        model.runtime_stack_canary_used() < caliptra_common::memory_layout::STACK_SIZE as usize
    );
}

#[test]
fn raw_and_legacy_commands_disabled_without_debug() {
    let mut model = boot(&firmware::APP_FHE);
    for id in [
        CommandId::FHE_KEYGEN,
        CommandId::FHE_ENCRYPT_RAW,
        CommandId::FHE_DECRYPT_RAW,
        CommandId::FHE_ENCRYPT,
        CommandId::FHE_DECRYPT,
    ] {
        let id: u32 = id.into();
        let err = model
            .mailbox_execute(id, &wire(id, key_req().as_bytes(), &[]))
            .unwrap_err();
        assert!(
            matches!(err, caliptra_hw_model::ModelError::MailboxCmdFailed(code)
            if code == u32::from(caliptra_api::error::CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND)),
            "{err:?}"
        );
    }
}

#[test]
fn pointer_partial_write_fails_and_poison_blocks_rekey() {
    let mut model = boot(&firmware::APP_FHE_DEBUG);
    let id = keygen(&mut model);
    model.soc_dram_mut().unwrap()[..4096].copy_from_slice(CT);
    let mut r = req(id, 1);
    r.mode = 1;
    r.src_lo = 0x8000_0000;
    let len = model.soc_dram_mut().unwrap().len();
    r.dst_lo = 0x8000_0000 + len as u32 - 4;
    let err = model
        .mailbox_execute(
            CommandId::FHE_DECRYPT_RAW.into(),
            &wire(CommandId::FHE_DECRYPT_RAW.into(), r.as_bytes(), &[]),
        )
        .unwrap_err();
    assert!(
        matches!(err, caliptra_hw_model::ModelError::MailboxCmdFailed(code)
        if code == u32::from(caliptra_api::error::CaliptraError::RUNTIME_FHE_DECRYPT_FAILED)),
        "{err:?}"
    );
    assert_eq!(&model.soc_dram_mut().unwrap()[len - 4..], &DEC[..4]);
    reject(&mut model, CommandId::FHE_KEYGEN, key_req().as_bytes(), &[]);
    r.seq = 2;
    r.dst_lo = 0x8000_2000;
    reject(&mut model, CommandId::FHE_DECRYPT_RAW, r.as_bytes(), &[]);
}

fn raw_golden(
    param: u32,
    fwid: &'static FwId<'static>,
    seed: &[u8; 32],
    pt: &[u8],
    ct: &[u8],
    dec: &[u8],
) {
    let mut model = boot(fwid);
    model.paint_runtime_stack_canary();
    let k = FheSwKeygenReq {
        version: 1,
        param_set: param,
        seed_mode: 1,
        seed: *seed,
        ..Default::default()
    };
    let result = send(&mut model, CommandId::FHE_KEYGEN, k.as_bytes(), &[]);
    let id = FheSwResp::ref_from_bytes(&result).unwrap().session_id;
    let mut seq = 1;
    for mode in [0, 1] {
        let mut enc = FheRawEncryptReq {
            common: FheRawDecryptReq {
                version: 1,
                param_set: param,
                session_id: id,
                seq,
                input_len: pt.len() as u32,
                mode,
                ..Default::default()
            },
            seed_mode: 1,
            seed: *seed,
        };
        if mode == 0 && param == 2 {
            reject(&mut model, CommandId::FHE_ENCRYPT_RAW, enc.as_bytes(), pt);
            continue;
        }
        let input = if mode == 0 {
            pt
        } else {
            model.soc_dram_mut().unwrap()[..pt.len()].copy_from_slice(pt);
            model.soc_dram_mut().unwrap()[0x3fffc..0x40000 + ct.len() + 4].fill(0xa5);
            enc.common.src_lo = 0x8000_0000;
            enc.common.dst_lo = 0x8004_0000;
            &[]
        };
        let result = send(
            &mut model,
            CommandId::FHE_ENCRYPT_RAW,
            enc.as_bytes(),
            input,
        );
        let (hdr, payload) = FheSwResp::ref_from_prefix(&result).unwrap();
        assert_eq!(hdr.output_len as usize, ct.len());
        println!(
            "param={param} mode={mode} encrypt cycles={}",
            (u64::from(hdr.cycles_hi) << 32) | u64::from(hdr.cycles_lo)
        );
        if mode == 0 {
            assert_eq!(payload, ct);
        } else {
            let ram = model.soc_dram_mut().unwrap();
            assert_eq!(&ram[0x40000..0x40000 + ct.len()], ct);
            assert_eq!(&ram[..pt.len()], pt);
            assert_eq!(&ram[0x3fffc..0x40000], &[0xa5; 4]);
            assert_eq!(&ram[0x40000 + ct.len()..0x40000 + ct.len() + 4], &[0xa5; 4]);
        }
        seq += 1;
        let decrypt = FheRawDecryptReq {
            version: 1,
            param_set: param,
            session_id: id,
            seq,
            mode,
            input_len: ct.len() as u32,
            src_lo: if mode == 1 { 0x8004_0000 } else { 0 },
            dst_lo: if mode == 1 { 0x8009_0000 } else { 0 },
            ..Default::default()
        };
        let result = send(
            &mut model,
            CommandId::FHE_DECRYPT_RAW,
            decrypt.as_bytes(),
            if mode == 0 { ct } else { &[] },
        );
        let (hdr, payload) = FheSwResp::ref_from_prefix(&result).unwrap();
        assert_eq!(hdr.output_len as usize, dec.len());
        println!(
            "param={param} mode={mode} decrypt cycles={}",
            (u64::from(hdr.cycles_hi) << 32) | u64::from(hdr.cycles_lo)
        );
        if mode == 0 {
            assert_eq!(payload, dec);
        } else {
            assert_eq!(
                &model.soc_dram_mut().unwrap()[0x90000..0x90000 + dec.len()],
                dec
            );
        }
        seq += 1;
    }
    println!(
        "param={param} stack canary extent={}",
        model.runtime_stack_canary_used()
    );
    assert!(
        model.runtime_stack_canary_used() < caliptra_common::memory_layout::STACK_SIZE as usize
    );
}

macro_rules! golden_case {
    ($name:ident, $param:expr, $fw:ident, $set:literal) => {
        #[test]
        fn $name() {
            raw_golden(
                $param,
                &firmware::$fw,
                include_bytes!(concat!("../../fhe-core/tests/vectors/", $set, "/seed.bin")),
                include_bytes!(concat!("../../fhe-core/tests/vectors/", $set, "/pt.bin")),
                include_bytes!(concat!("../../fhe-core/tests/vectors/", $set, "/ct.bin")),
                include_bytes!(concat!("../../fhe-core/tests/vectors/", $set, "/dec.bin")),
            );
        }
    };
}
golden_case!(ps_raw_kernels_golden, 0, APP_FHE_DEBUG, "ps");
golden_case!(pl_raw_kernels_golden, 1, APP_FHE_DEBUG_PL, "pl");
golden_case!(pleq_raw_kernels_golden, 2, APP_FHE_DEBUG_PLEQ, "pleq");

#[test]
fn encrypt_reseeds_and_rejects_invalid_input() {
    let mut model = boot(&firmware::APP_FHE_DEBUG);
    let id = keygen(&mut model);
    let pt = include_bytes!("../../fhe-core/tests/vectors/ps/pt.bin");
    let mut enc = FheRawEncryptReq {
        common: req(id, 1),
        ..Default::default()
    };
    enc.common.input_len = pt.len() as u32;
    // Random mode cannot smuggle a deterministic seed.
    enc.seed[0] = 1;
    reject(&mut model, CommandId::FHE_ENCRYPT_RAW, enc.as_bytes(), pt);
    enc.seed[0] = 0;
    let first = send(&mut model, CommandId::FHE_ENCRYPT_RAW, enc.as_bytes(), pt);
    enc.common.seq += 1;
    let second = send(&mut model, CommandId::FHE_ENCRYPT_RAW, enc.as_bytes(), pt);
    let (_, first) = FheSwResp::ref_from_prefix(&first).unwrap();
    let (_, second) = FheSwResp::ref_from_prefix(&second).unwrap();
    assert_ne!(
        first, second,
        "TRNG reseeding must produce fresh ciphertexts"
    );
    enc.common.seq += 1;
    enc.common.mode = 1;
    enc.common.src_lo = 0x8000_0000;
    enc.common.dst_lo = 0x8000_2000;
    model.soc_dram_mut().unwrap()[..pt.len()].copy_from_slice(pt);
    model.soc_dram_mut().unwrap()[pt.len() - 4..pt.len()].fill(0xff);
    model.soc_dram_mut().unwrap()[8192..12288].fill(0xa5);
    reject(&mut model, CommandId::FHE_ENCRYPT_RAW, enc.as_bytes(), &[]);
    assert!(model.soc_dram_mut().unwrap()[8192..12288]
        .iter()
        .all(|&b| b == 0xa5));
}
