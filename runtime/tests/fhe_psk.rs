// Licensed under the Apache-2.0 license
//! Real RV32 runtime dispatch on the software SoC model; no RTL claims.
#![cfg(not(any(
    feature = "verilator",
    feature = "fpga_realtime",
    feature = "fpga_subsystem"
)))]
use caliptra_api::{mailbox::CommandId, SocManager};
use caliptra_builder::{firmware, FwId, ImageOptions};
use caliptra_hw_model::{BootParams, DefaultHwModel, Fuses, HwModel, InitParams};
use caliptra_image_types::FwVerificationPqcKeyType;
use zerocopy::IntoBytes;

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
    model.require_mailbox_word_writes();
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
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn crypto(op: &str, key: &[u8], data: &[u8], aad: &[u8], iv: &[u8]) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fhe/psk.py");
    let mut cmd = std::process::Command::new("python3");
    cmd.arg(path).arg(op).arg(hex(key)).arg(hex(data));
    if op != "mac" {
        cmd.arg(hex(aad)).arg(hex(iv));
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    unhex(String::from_utf8(out.stdout).unwrap().trim())
}
fn words(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|v| v.to_le_bytes()).collect()
}
fn word(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap())
}
const IDS: [u32; 5] = [0x46484b47, 0x4648494e, 0x46484547, 0x4d4c4943, 0x46485343];
/// Authenticated parameter-set ID of the Aloha N=256 profile.
#[cfg(feature = "fhe-aloha")]
const ALOHA_PROFILE: u32 = 0xa108;
struct User {
    open_request: Vec<u8>,
    id: u32,
    seq: u32,
    policy: [u32; 5],
    rx: Vec<u8>,
    tx: Vec<u8>,
}
impl User {
    fn opening(policy: [u32; 5]) -> Vec<u8> {
        let mut req = words(&[0, 3]);
        req.extend(words(&policy));
        req.extend([0x36; 32]);
        let mut transcript = words(&[0]);
        transcript.extend(&req[4..]);
        let psk = unhex("a7b1c3d5e7f9012436485a6c7e90a2b4c6d8eaf10315274961738597a9bbcddf");
        req.extend(crypto("mac", &psk, &transcript, &[], &[]));
        req
    }
    fn open(m: &mut DefaultHwModel, policy: [u32; 5]) -> Self {
        let req = Self::opening(policy);
        let response = send(m, CommandId::FHE_SESSION_OPEN, &req, &[]);
        assert_eq!(response.len(), 28);
        let id = word(&response, 2);
        let mut transcript = req[4..60].to_vec();
        transcript.extend(words(&[id]));
        let psk = unhex("a7b1c3d5e7f9012436485a6c7e90a2b4c6d8eaf10315274961738597a9bbcddf");
        let k = |i| {
            let mut b = words(&[i]);
            b.extend(&transcript);
            crypto("mac", &psk, &b, &[], &[])
        };
        assert_eq!(&response[12..], k(5));
        let mut rx = k(1);
        rx.extend(k(2));
        let mut tx = k(3);
        tx.extend(k(4));
        Self {
            open_request: req,
            id,
            seq: 1,
            policy,
            rx,
            tx,
        }
    }
    fn packet(&self, op: u32, body: &[u8], pointer: bool) -> (Vec<u8>, Vec<u8>) {
        let output = match op {
            // P-S (profile 0) returns 4096 ciphertext bytes; Aloha returns 8192.
            2 if self.policy[2] != 0 => 8192,
            2 => 4096,
            3 => 2048,
            4 => 40,
            _ => 0,
        };
        let mut h = words(&[0, 3, op, self.id, self.seq]);
        h.extend(words(&self.policy));
        h.extend(words(&[
            pointer as u32,
            if pointer { 0x80000000 } else { 0 },
            0,
            if pointer { 0x80010000 } else { 0 },
            0,
            body.len() as u32,
            output,
            0,
        ]));
        let ct = crypto(
            "encrypt",
            &self.rx,
            body,
            &h[4..],
            &words(&[0, self.seq, 0]),
        );
        h.extend(&ct[ct.len() - 16..]);
        (h, ct[..ct.len() - 16].to_vec())
    }
    fn call(&mut self, m: &mut DefaultHwModel, op: u32, body: &[u8], pointer: bool) -> Vec<u8> {
        let (h, ct) = self.packet(op, body, pointer);
        if pointer {
            m.soc_dram_mut().unwrap()[..ct.len()].copy_from_slice(&ct);
        }
        let result = send(
            m,
            CommandId::from(IDS[(op - 1) as usize]),
            &h,
            if pointer { &[] } else { &ct },
        );
        assert_eq!(&result[8..76], &h[4..72]);
        let olen = word(&h, 16) as usize;
        let mut body = if pointer {
            m.soc_dram_mut().unwrap()[0x10000..0x10000 + olen].to_vec()
        } else {
            result[100..].to_vec()
        };
        body.extend(&result[84..100]);
        let pt = crypto(
            "decrypt",
            &self.tx,
            &body,
            &result[8..84],
            &words(&[1, self.seq, 0]),
        );
        self.seq += 1;
        pt
    }
    fn reject(&self, m: &mut DefaultHwModel, op: u32, h: &[u8], body: &[u8]) {
        let id: u32 = IDS[(op - 1) as usize].into();
        assert!(m.mailbox_execute(id, &wire(id, h, body)).is_err());
    }
}
#[test]
fn protected_flow_and_security() {
    let mut m = boot(&firmware::APP_FHE_PSK_ML_CLEAR);
    m.paint_runtime_stack_canary();
    let mut u = User::open(&mut m, [0x1e, 8, 0, 2, 0]);
    let (h, ct) = u.packet(1, &[], false);
    let mut bad = h.clone();
    bad[72] ^= 1;
    u.reject(&mut m, 1, &bad, &ct);
    u.call(&mut m, 1, &[], false);
    u.reject(&mut m, 1, &h, &ct); // replay cannot regenerate secret
    let (h, ct) = u.packet(1, &[], false);
    u.reject(&mut m, 1, &h, &ct);
    u.seq += 1; // authenticated rekey refused, sequence consumed
    let pt = include_bytes!("../../fhe-core/tests/vectors/ps/pt.bin");
    for pointer in [false, true] {
        let ct = u.call(&mut m, 2, pt, pointer);
        assert_eq!(ct.len(), 4096);
        let dec = u.call(&mut m, 3, &ct, pointer);
        for limb in 0..2 {
            let q = [1073738753i64, 1073732609][limb];
            for i in 0..256 {
                let diff =
                    (word(&dec, limb * 256 + i) as i64 - word(pt, limb * 256 + i) as i64 + q) % q;
                assert!(
                    diff <= 20 || diff >= q - 20,
                    "decryption outside CBD support"
                );
            }
        }
        // Fresh encryption must not repeat the uniform component.
        assert_ne!(u.call(&mut m, 2, pt, pointer), ct);
        let pixels: Vec<u8> = (0..196).map(|i| (i % 16) as u8).collect();
        let logits = u.call(&mut m, 4, &pixels, pointer);
        #[path = "../src/fhe/model.rs"]
        mod model;
        for k in 0..10 {
            let want = model::B[k] as i32
                + (0..196)
                    .map(|i| model::W[k][i] as i32 * pixels[i] as i32)
                    .sum::<i32>();
            assert_eq!(word(&logits, k) as i32, want);
        }
    }
    // Bind policy, command, pointers, ciphertext, tag; no failed authentication advances sequence.
    let (h, ct) = u.packet(2, pt, false);
    for offset in [
        12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 87,
    ] {
        let mut bad = h.clone();
        bad[offset] ^= 1;
        u.reject(&mut m, 2, &bad, &ct);
    }
    let mut bad = ct.clone();
    bad[17] ^= 1;
    u.reject(&mut m, 2, &h, &bad);
    u.reject(&mut m, 3, &h, &ct);
    u.call(&mut m, 2, pt, false);
    let old = u.packet(5, &[], false);
    u.call(&mut m, 5, &[], false);
    u.reject(&mut m, 5, &old.0, &old.1);
    let mut v = User::open(&mut m, [0x1e, 1, 0, 2, 0]);
    assert_ne!(u.rx, v.rx);
    v.reject(&mut m, 5, &old.0, &old.1);
    // No secret survives close/open; authenticated refusal consumes sequence.
    let (h, ct) = v.packet(2, pt, false);
    v.reject(&mut m, 2, &h, &ct);
    v.seq += 1;
    v.call(&mut m, 4, &[0; 196], false);
    let (h, ct) = v.packet(4, &[0; 196], false);
    v.reject(&mut m, 4, &h, &ct);
    v.seq += 1;
    v.call(&mut m, 5, &[], false);
    println!("protected stack extent {}", m.runtime_stack_canary_used());
    assert!(m.runtime_stack_canary_used() < caliptra_common::memory_layout::STACK_SIZE as usize);
}

/// Runs the actual trusted Python client against real runtime commands. The
/// same directory protocol is used by the Rocket HTIF relay; no simulator here.
#[test]
fn protected_host_demo() {
    run_host_demo(&firmware::APP_FHE_PSK_ML_CLEAR, "protected_demo.py", false);
}

/// Requires a local-stream N=256 RTL RPC executable and initialized table cwd.
#[test]
#[cfg(feature = "fhe-aloha")]
#[ignore = "requires FHE_ALOHA_RTL and FHE_ALOHA_RTL_CWD"]
fn protected_aloha_host_demo() {
    run_host_demo(&firmware::APP_FHE_ALOHA, "aloha_demo.py", true);
}

/// `mnist_data` forwards FHE_MNIST_DATA as the client's cached --data-dir.
fn run_host_demo(fwid: &'static FwId<'static>, script: &str, mnist_data: bool) {
    use std::{
        fs,
        process::Command,
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    let mut m = boot(fwid);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("fhe-protected-demo-{}-{stamp}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    fs::write(
        dir.join("hello"),
        [0x80000000u64.to_le_bytes(), 0x80010000u64.to_le_bytes()].concat(),
    )
    .unwrap();
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fhe")
        .join(script);
    let mut cmd = Command::new("python3");
    cmd.arg(script).arg(&dir).arg("--timeout").arg("120");
    if std::env::var_os("FHE_FULL_DEMO").is_some() {
        cmd.arg("--full");
    }
    if mnist_data {
        if let Some(path) = std::env::var_os("FHE_MNIST_DATA") {
            cmd.arg("--data-dir").arg(path);
        }
    }
    let transport = if mnist_data {
        None
    } else {
        std::env::var_os("FHE_DEMO_TRANSPORT")
    };
    let mailbox_only = transport.as_deref() == Some(std::ffi::OsStr::new("mailbox"));
    if let Some(transport) = transport {
        cmd.arg("--transport").arg(transport);
    }
    let mut user = cmd.spawn().unwrap();
    for i in 0..1000 {
        let file = dir.join(format!("req-{i}"));
        let deadline = Instant::now() + Duration::from_secs(120);
        while !file.exists() {
            assert!(Instant::now() < deadline, "user stalled: {dir:?}");
            assert!(
                user.try_wait().unwrap().is_none(),
                "user exited before completion"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let data = fs::read(file).unwrap();
        let id = word(&data, 0);
        if id == 0 {
            assert!(user.wait().unwrap().success());
            return;
        }
        let len = word(&data, 1) as usize;
        let ext = word(&data, 2) as usize;
        if mailbox_only {
            assert_eq!(ext, 0, "mailbox-only request {i} used an external buffer");
        }
        let h = &data[12..12 + len];
        if ext > 0 {
            m.soc_dram_mut().unwrap()[..ext].copy_from_slice(&data[12 + len..]);
        }
        let result = send(&mut m, CommandId::from(id), h, &[]);
        let outlen = if ext > 0 { word(h, 16) as usize } else { 0 };
        let mut packet = words(&[result.len() as u32, outlen as u32]);
        packet.extend(result);
        if outlen > 0 {
            packet.extend_from_slice(&m.soc_dram_mut().unwrap()[0x10000..0x10000 + outlen]);
        }
        fs::write(dir.join(format!("resp-{i}")), packet).unwrap();
    }
    panic!("demo exceeded request limit");
}

#[test]
fn protected_snapshot_and_cleanup() {
    let mut m = boot(&firmware::APP_FHE_PSK_ML_CLEAR);
    let mut u = User::open(&mut m, [0x1e, 4, 0, 2, 0]);
    u.call(&mut m, 1, &[], false);
    let pt = include_bytes!("../../fhe-core/tests/vectors/ps/pt.bin");
    let (h, ct) = u.packet(2, pt, true);
    m.soc_dram_mut().unwrap()[..ct.len()].copy_from_slice(&ct);
    let id = IDS[1];
    m.start_mailbox_execute(id, &wire(id, &h, &[])).unwrap();
    let mut retained = false;
    for _ in 0..100_000 {
        for _ in 0..20 {
            m.step();
        }
        if m.mailbox_sram_snapshot(128, ct.len()) == ct {
            retained = true;
            break;
        }
    }
    assert!(retained, "snapshot not observed");
    m.soc_dram_mut().unwrap()[..ct.len()].fill(0xa5); // mutate only external source after snapshot
    for _ in 0..5_000_000 {
        if !m.soc_mbox().status().read().status().cmd_busy() {
            break;
        }
        m.step();
    }
    let response = m.finish_mailbox_execute().unwrap().unwrap();
    let mut wrapped = m.soc_dram_mut().unwrap()[0x10000..0x11000].to_vec();
    wrapped.extend(&response[84..100]);
    let ciphertext = crypto(
        "decrypt",
        &u.tx,
        &wrapped,
        &response[8..84],
        &words(&[1, u.seq, 0]),
    );
    u.seq += 1;
    assert!(m
        .mailbox_sram_snapshot(100, 16384 - 100)
        .iter()
        .all(|&v| v == 0));
    let dec = u.call(&mut m, 3, &ciphertext, false);
    for li in 0..2 {
        let q = [1073738753i64, 1073732609][li];
        for i in 0..256 {
            let d = (word(&dec, li * 256 + i) as i64 - word(pt, li * 256 + i) as i64 + q) % q;
            assert!(d <= 20 || d >= q - 20);
        }
    }
    let (mut h, ct) = u.packet(2, pt, false);
    h[75] ^= 1;
    u.reject(&mut m, 2, &h, &ct);
    assert!(m
        .mailbox_sram_snapshot(128, 16384 - 128)
        .iter()
        .all(|&v| v == 0));
    // Invalid authenticated pixels consume both sequence and reserved quota.
    let (h, ct) = u.packet(4, &[16; 196], false);
    u.reject(&mut m, 4, &h, &ct);
    u.seq += 1;
    assert!(m
        .mailbox_sram_snapshot(128, 16384 - 128)
        .iter()
        .all(|&v| v == 0));
    u.call(&mut m, 5, &[], false);
}

#[test]
fn protected_policy_exhaustion_and_dma_poison() {
    let mut m = boot(&firmware::APP_FHE_PSK_ML_CLEAR);
    let mut u = User::open(&mut m, [1 << 4, 1, 0, 2, 0]);
    let (h, ct) = u.packet(1, &[], false);
    u.reject(&mut m, 1, &h, &ct);
    u.seq += 1; // disallowed, authenticated
    let save = u.seq;
    u.seq = u32::MAX;
    let (h, ct) = u.packet(5, &[], false);
    u.reject(&mut m, 5, &h, &ct);
    u.seq = save;
    let (h, ct) = u.packet(4, &[16; 196], false);
    u.reject(&mut m, 4, &h, &ct);
    u.seq += 1;
    let (h, ct) = u.packet(4, &[0; 196], false);
    u.reject(&mut m, 4, &h, &ct);
    u.seq += 1;
    u.call(&mut m, 5, &[], false);
    let mut u = User::open(&mut m, [0x1e, 4, 0, 2, 0]);
    u.call(&mut m, 1, &[], false);
    let pt = include_bytes!("../../fhe-core/tests/vectors/ps/pt.bin");
    let (mut h, _) = u.packet(2, pt, true);
    // Valid fabric range but beyond emulator RAM: partial read then DMA fault.
    let end = m.soc_dram_mut().unwrap().len();
    h[44..48].copy_from_slice(&(0x80000000u32 + end as u32 - 4).to_le_bytes());
    let ct = crypto("encrypt", &u.rx, pt, &h[4..72], &words(&[0, u.seq, 0]));
    h[72..88].copy_from_slice(&ct[ct.len() - 16..]);
    m.soc_dram_mut().unwrap()[end - 4..].copy_from_slice(&ct[..4]);
    m.soc_dram_mut().unwrap()[0x10000..0x11000].fill(0x5a);
    u.reject(&mut m, 2, &h, &[]);
    assert!(m.soc_dram_mut().unwrap()[0x10000..0x11000]
        .iter()
        .all(|&v| v == 0x5a));
    assert!(m
        .mailbox_sram_snapshot(128, 16384 - 128)
        .iter()
        .all(|&v| v == 0));
    let open = User::opening([0x1e, 4, 0, 2, 0]);
    for _ in 0..2 {
        let id: u32 = CommandId::FHE_SESSION_OPEN.into();
        assert!(m.mailbox_execute(id, &wire(id, &open, &[])).is_err());
    }
    let (h, ct) = u.packet(5, &[], false);
    u.reject(&mut m, 5, &h, &ct);
}

#[test]
fn protected_open_authentication_and_lifetime() {
    let mut m = boot(&firmware::APP_FHE_PSK_ML_CLEAR);
    let id: u32 = CommandId::FHE_SESSION_OPEN.into();
    let mut bad = User::opening([0x1e, 4, 0, 2, 0]);
    bad[60] ^= 1;
    assert!(m.mailbox_execute(id, &wire(id, &bad, &[])).is_err());
    let mut u = User::open(&mut m, [0x1e, 4, 0, 2, 0]);
    assert!(m
        .mailbox_execute(id, &wire(id, &u.open_request, &[]))
        .is_err());
    let (old_command, body) = u.packet(1, &[], false);
    u.call(&mut m, 1, &[], false);
    u.call(&mut m, 5, &[], false);
    // Deliberate WIP limitation: a recorded open is accepted after close.
    let response = send(&mut m, CommandId::FHE_SESSION_OPEN, &u.open_request, &[]);
    assert_eq!(word(&response, 2), u.id + 1);
    // Within one boot, the increasing ID still prevents old command reuse.
    u.reject(&mut m, 1, &old_command, &body);
    let mut m = boot(&firmware::APP_FHE_PSK_ML_CLEAR);
    // After reboot, the same open recreates the ID and communication keys.
    let response = send(&mut m, CommandId::FHE_SESSION_OPEN, &u.open_request, &[]);
    assert_eq!(word(&response, 2), u.id);
    u.seq = 1;
    u.call(&mut m, 1, &[], false);
    u.call(&mut m, 5, &[], false);
    // Raw and accelerator IDs remain unavailable in a protected build.
    for command in [0x46484552u32, 0x46484452, 0x4648454e, 0x46484445] {
        assert!(m
            .mailbox_execute(command, &wire(command, &[0; 88], &[]))
            .is_err());
    }
}

#[test]
fn protected_failed_egress_write() {
    let mut m = boot(&firmware::APP_FHE_PSK_ML_CLEAR);
    let mut u = User::open(&mut m, [0x1e, 4, 0, 2, 0]);
    u.call(&mut m, 1, &[], false);
    let pt = include_bytes!("../../fhe-core/tests/vectors/ps/pt.bin");
    let ct = u.call(&mut m, 2, pt, false);
    let dec = u.call(&mut m, 3, &ct, false);
    let (mut h, _) = u.packet(3, &ct, true);
    let end = m.soc_dram_mut().unwrap().len();
    h[52..56].copy_from_slice(&(0x80000000u32 + end as u32 - 16).to_le_bytes());
    let input = crypto("encrypt", &u.rx, &ct, &h[4..72], &words(&[0, u.seq, 0]));
    h[72..88].copy_from_slice(&input[input.len() - 16..]);
    m.soc_dram_mut().unwrap()[..ct.len()].copy_from_slice(&input[..ct.len()]);
    m.soc_dram_mut().unwrap()[end - 16..].fill(0xa5);
    // GCM ciphertext is independent of AAD. Even a partial failed write must
    // contain wrapped bytes, never the internally decrypted polynomial.
    let expected = crypto("encrypt", &u.tx, &dec, &[], &words(&[1, u.seq, 0]));
    u.reject(&mut m, 3, &h, &[]);
    assert_eq!(&m.soc_dram_mut().unwrap()[end - 16..], &expected[..16]);
    assert!(m
        .mailbox_sram_snapshot(128, 16384 - 128)
        .iter()
        .all(|&v| v == 0));
    let open = User::opening([0x1e, 4, 0, 2, 0]);
    let id: u32 = CommandId::FHE_SESSION_OPEN.into();
    assert!(m.mailbox_execute(id, &wire(id, &open, &[])).is_err());
}

/// The ordinary protected build must neither expose MLIC nor include its model.
#[test]
fn protected_without_clear_reference() {
    let mut m = boot(&firmware::APP_FHE_PSK);
    let mut u = User::open(&mut m, [0x0e, 2, 0, 2, 0]);
    for pointer in [false, true] {
        let (h, ct) = u.packet(4, &[0; 196], pointer);
        u.reject(&mut m, 4, &h, if pointer { &[] } else { &ct });
    }
    // Unsupported commands are rejected before authentication/accounting.
    u.call(&mut m, 1, &[], false);
    let pt = include_bytes!("../../fhe-core/tests/vectors/ps/pt.bin");
    let ct = u.call(&mut m, 2, pt, false);
    let dec = u.call(&mut m, 3, &ct, false);
    for (limb, q) in [1073738753i64, 1073732609].into_iter().enumerate() {
        for i in 0..256 {
            let diff =
                (word(&dec, limb * 256 + i) as i64 - word(pt, limb * 256 + i) as i64 + q) % q;
            assert!(diff <= 20 || diff >= q - 20);
        }
    }
    u.call(&mut m, 5, &[], false);
    // A correctly authenticated open cannot grant the compiled-out operation.
    let req = User::opening([0x1e, 2, 0, 2, 0]);
    let id = CommandId::FHE_SESSION_OPEN.into();
    assert!(m.mailbox_execute(id, &wire(id, &req, &[])).is_err());
}

/// Bad authentication leaves external output untouched and consumes no sequence;
/// authenticated non-canonical ciphertext is rejected.
#[test]
#[cfg(feature = "fhe-aloha")]
#[ignore = "requires FHE_ALOHA_RTL and FHE_ALOHA_RTL_CWD"]
fn protected_aloha_bad_tag() {
    let mut m = boot(&firmware::APP_FHE_ALOHA);
    m.paint_runtime_stack_canary();
    for pointer in [false, true] {
        let mut u = User::open(&mut m, [0x0e, 8, ALOHA_PROFILE, 2, 0]);
        u.call(&mut m, 1, &[], false);
        let (h, ct) = u.packet(2, &[0; 2048], pointer);
        let mut bad = h.clone();
        bad[72] ^= 1;
        m.soc_dram_mut().unwrap()[0x10000..0x12000].fill(0xa5);
        if pointer {
            m.soc_dram_mut().unwrap()[..ct.len()].copy_from_slice(&ct);
        }
        u.reject(&mut m, 2, &bad, if pointer { &[] } else { &ct });
        assert!(m.soc_dram_mut().unwrap()[0x10000..0x12000]
            .iter()
            .all(|v| *v == 0xa5));
        // A valid retry succeeds, then replay is rejected.
        assert_eq!(u.call(&mut m, 2, &[0; 2048], pointer).len(), 8192);
        u.reject(&mut m, 2, &h, if pointer { &[] } else { &ct });
        u.call(&mut m, 5, &[], false);
    }
    // An authenticated but non-canonical residue is rejected before Aloha runs,
    // including in limb 1, which decryption does not otherwise consume.
    let mut u = User::open(&mut m, [0x0e, 8, ALOHA_PROFILE, 2, 0]);
    u.call(&mut m, 1, &[], false);
    let mut ct = u.call(&mut m, 2, &[0; 2048], false);
    assert_eq!(u.call(&mut m, 3, &ct, false).len(), 2048);
    // c0 limb 0, c0 limb 1, c1 limb 0, c1 limb 1: 2048 bytes each.
    let q1 = (1u64 << 47) - (1 << 24) + 1;
    ct[3 * 2048..3 * 2048 + 8].copy_from_slice(&q1.to_le_bytes());
    let (h, body) = u.packet(3, &ct, false);
    u.reject(&mut m, 3, &h, &body);
    assert!(m.runtime_stack_canary_used() < caliptra_common::memory_layout::STACK_SIZE as usize);
}
