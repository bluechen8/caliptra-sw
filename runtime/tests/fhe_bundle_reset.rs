// Licensed under the Apache-2.0 license
//! Preflight the exact ROM and firmware bundle intended for full-SoC reset tests.
//! CPU and peripherals are emulator models; this does not replace Xcelium.
#![cfg(all(
    feature = "fhe-aloha",
    not(any(
        feature = "verilator",
        feature = "fpga_realtime",
        feature = "fpga_subsystem"
    ))
))]

use caliptra_api::SocManager;
use caliptra_hw_model::{
    BootParams, DefaultHwModel, DeviceLifecycle, Fuses, HwModel, InitParams, SecurityState,
};
use caliptra_image_types::{FwVerificationPqcKeyType, ImageManifest};
use sha2::{Digest, Sha384};
use zerocopy::{FromBytes, IntoBytes};

fn wait_idle(model: &mut DefaultHwModel) {
    for _ in 0..20_000_000 {
        assert_eq!(
            model.soc_ifc().cptra_fw_error_fatal().read(),
            0,
            "boot failed"
        );
        let flow = model.soc_ifc().cptra_flow_status().read();
        if flow.ready_for_runtime() && flow.mailbox_flow_done() {
            return;
        }
        model.step();
    }
    panic!("runtime did not become idle");
}

#[test]
#[ignore = "requires FHE_SOC_BUNDLE containing rom.bin and firmware.bin"]
fn bundle_recovers_interrupted_command() {
    let bundle = std::path::PathBuf::from(std::env::var("FHE_SOC_BUNDLE").unwrap());
    let rom = std::fs::read(bundle.join("rom.bin")).unwrap();
    let image = std::fs::read(bundle.join("firmware.bin")).unwrap();
    let (manifest, _) = ImageManifest::read_from_prefix(&image).unwrap();
    let hash = Sha384::digest(manifest.preamble.vendor_pub_key_info.as_bytes());
    let vendor_pk_hash =
        core::array::from_fn(|i| u32::from_be_bytes(hash[i * 4..i * 4 + 4].try_into().unwrap()));
    let mut model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            security_state: *SecurityState::default()
                .set_device_lifecycle(DeviceLifecycle::Manufacturing)
                .set_debug_locked(true),
            fuses: Fuses {
                vendor_pk_hash,
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
    wait_idle(&mut model);

    // Same ordinary command as the full-SoC monitor: GET_IDEV_ECC384_CSR.
    let command = 0x4944_4352;
    let checksum = caliptra_common::checksum::calc_checksum(command, &[]);
    model
        .start_mailbox_execute(command, &checksum.to_le_bytes())
        .unwrap();
    let mut active = false;
    for _ in 0..20_000_000 {
        if !model
            .soc_ifc()
            .cptra_flow_status()
            .read()
            .mailbox_flow_done()
        {
            active = true;
            break;
        }
        model.step();
    }
    assert!(active, "command was not dispatched");
    // Allow the following persistent runtime_cmd_active store to retire.
    for _ in 0..200 {
        model.step();
    }
    assert!(!model
        .soc_ifc()
        .cptra_flow_status()
        .read()
        .mailbox_flow_done());
    model.warm_reset_flow().unwrap();
    wait_idle(&mut model);
    assert_eq!(
        model.soc_ifc().cptra_fw_error_non_fatal().read(),
        u32::from(caliptra_error::CaliptraError::RUNTIME_CMD_BUSY_DURING_WARM_RESET),
        "upstream interrupted-command policy missing"
    );
}
