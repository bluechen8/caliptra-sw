// Licensed under the Apache-2.0 license
//! Protocol v5 runtime dispatch on the software SoC model; no RTL claims.
//! Shared helpers and test-key coverage here; ECDH and key rows in fhe_ecdh.rs.
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
    boot_with_measurement(fwid, false).0
}
/// Returns the runtime SHA-384 for ECDH builds, whose host pins it.
fn boot_with_measurement(
    fwid: &'static FwId<'static>,
    wrapper_fixture: bool,
) -> (DefaultHwModel, Option<String>) {
    // Only ECDH builds run debug-locked; the test-key build requires unlocked.
    let ecdh = fwid.features.contains(&"fhe-ecdh");
    boot_state(fwid, wrapper_fixture, ecdh)
}
fn boot_state(
    fwid: &'static FwId<'static>,
    wrapper_fixture: bool,
    debug_locked: bool,
) -> (DefaultHwModel, Option<String>) {
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
    let ecdh = fwid.features.contains(&"fhe-ecdh");
    let runtime_digest = ecdh.then(|| {
        hex(&hash_words(&image.runtime)
            .iter()
            .flat_map(|v| v.to_be_bytes())
            .collect::<Vec<_>>())
    });
    let image = image.to_bytes().unwrap();
    let mut init = InitParams {
        rom: &rom,
        security_state: *caliptra_hw_model::SecurityState::default().set_debug_locked(debug_locked),
        fuses: Fuses {
            vendor_pk_hash,
            owner_pk_hash,
            fuse_pqc_key_type: FwVerificationPqcKeyType::LMS as u32,
            ..Default::default()
        },
        ..Default::default()
    };
    if wrapper_fixture {
        // Public fixture values from wrapper Caliptra.scala and caliptra.h.
        // The independent Python pin is derived without querying the device.
        init.cptra_obf_key = [
            0xcfe891e7, 0x28b07f11, 0xfb41700d, 0x334714bf, 0x5c8fb33c, 0x1c958bbd, 0xf34d6ac3,
            0x31358e8a,
        ];
        init.fuses.uds_seed = [
            0xe4046d05, 0x385ab789, 0xc6a72866, 0xe08350f9, 0x3f583e2a, 0x005ca0fa, 0xecc32b5c,
            0xfc323d46, 0x1c76c107, 0x307654db, 0x5566a5bd, 0x693e227c, 0x14451624, 0x6a752c32,
            0x9056d884, 0xdaf3c89d,
        ];
        init.fuses.field_entropy = [
            0xb32e2b17, 0x1b638270, 0x34ebb0d1, 0x909f7ef1, 0xd51c5f82, 0xc1bb9bc2, 0x6bc4ac4d,
            0xccdee835,
        ];
        init.security_state
            .set_device_lifecycle(caliptra_hw_model::DeviceLifecycle::Manufacturing);
    }
    let mut model = caliptra_hw_model::new(
        init,
        BootParams {
            fw_image: Some(&image),
            ..Default::default()
        },
    )
    .unwrap();
    wait_runtime_ready(&mut model);
    model.require_mailbox_word_writes();
    (model, runtime_digest)
}
fn wait_runtime_ready(model: &mut DefaultHwModel) {
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
            return;
        }
        model.step();
    }
    panic!("runtime boot timed out");
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
fn reject(m: &mut DefaultHwModel, id: u32, data: &[u8], payload: &[u8]) {
    assert!(m.mailbox_execute(id, &wire(id, data, payload)).is_err());
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
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fhe/protocol.py");
    let mut cmd = std::process::Command::new("python3");
    cmd.arg(path).arg(op).arg(hex(key)).arg(hex(data));
    if op != "mac" {
        cmd.arg(hex(aad)).arg(hex(iv));
    }
    run_python(&mut cmd)
}
fn run_python(cmd: &mut std::process::Command) -> Vec<u8> {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    unhex(String::from_utf8(out.stdout).unwrap().trim())
}
/// P-S RNS primes and the auxiliary key-switching prime (fhe-core PS_AUX).
const PS_Q: [u32; 2] = [1073738753, 1073732609];
const PS_AUX: u32 = 0x3fffd601;
/// One hybrid evaluation key: 2 rows x 2 polynomials x 3 limbs x 256 words.
const KEY_BYTES: usize = 2 * 2 * 3 * 256 * 4;
/// P-S decryption must stay within the CBD error support of the plaintext.
fn ps_close(dec: &[u8], pt: &[u8]) -> bool {
    PS_Q.into_iter().enumerate().all(|(limb, q)| {
        let q = i64::from(q);
        (0..256).all(|i| {
            let diff = (word(dec, limb * 256 + i) as i64 - word(pt, limb * 256 + i) as i64 + q) % q;
            diff <= 20 || diff >= q - 20
        })
    })
}
fn words(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|v| v.to_le_bytes()).collect()
}
fn word(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap())
}
/// Bytes of mailbox SRAM the FHE commands use and scrub (session.rs WORK).
/// Beyond it lies only data the SoC itself wrote, e.g. at boot.
const WORKSPACE: usize = 4 * (12 + 2 * 1024 + 512);
fn mailbox_scrubbed(m: &mut DefaultHwModel, from: usize) -> bool {
    m.mailbox_sram_snapshot(from, WORKSPACE - from)
        .iter()
        .all(|&v| v == 0)
}

const OPEN: u32 = 0x4648534f;
/// Relay job frame ("FJOB"): the scheduler builds the command.
const JOB: u32 = 0x424f4a46;
const IDS: [u32; 7] = [
    0x46484b47, 0x4648494e, 0x46484547, 0x4d4c4943, 0x46485343, 0x46485254, 0x4648524c,
];
const PT: &[u8] = include_bytes!("../../fhe-core/tests/vectors/ps/pt.bin");
const SRC: u64 = 0x8000_0000;
const DST: u64 = 0x8001_0000;
/// (input, output) wire lengths; sealed blobs add a 20-B header and 16-B tag.
fn lengths(op: u32) -> (usize, usize) {
    match op {
        2 => (2084, 4096),
        3 => (4096, 2084),
        4 => (232, 76),
        6 | 7 => (0, KEY_BYTES),
        _ => (0, 0),
    }
}
/// Plain 48-byte scheduler command.
fn command(id: u32, op: u32, pointer: bool, arg: u32) -> Vec<u8> {
    let (input, output) = lengths(op);
    let src = if pointer && input > 0 { SRC } else { 0 };
    let dst = if pointer && output > 0 { DST } else { 0 };
    words(&[
        0,
        5,
        op,
        id,
        pointer as u32,
        src as u32,
        (src >> 32) as u32,
        dst as u32,
        (dst >> 32) as u32,
        input as u32,
        output as u32,
        arg,
    ])
}
fn reject_open(m: &mut DefaultHwModel, request: &[u8]) {
    reject(m, OPEN, request, &[]);
}

/// Trusted user (keys, blobs) and scheduler (plain commands) in one harness.
struct Client {
    open_request: Vec<u8>,
    id: u32,
    rx: Vec<u8>,
    tx: Vec<u8>,
    /// Next user blob counter.
    counter: u32,
    /// Next expected device result counter.
    results: u32,
}
impl Client {
    fn new(open_request: Vec<u8>, id: u32, rx: Vec<u8>, tx: Vec<u8>) -> Self {
        Self {
            open_request,
            id,
            rx,
            tx,
            counter: 1,
            results: 1,
        }
    }
    fn test_key(m: &mut DefaultHwModel) -> Self {
        use sha2::{Digest, Sha256};
        let request = words(&[0, 5]);
        let response = send(m, CommandId::FHE_SESSION_OPEN, &request, &[]);
        assert_eq!(response.len(), 12);
        let key = |name: &str| Sha256::digest(format!("Caliptra FHE v5 TEST {name} key")).to_vec();
        Self::new(request, word(&response, 2), key("request"), key("response"))
    }
    fn seal_as(&self, id: u32, op: u32, counter: u32, body: &[u8]) -> Vec<u8> {
        let header = words(&[5, id, op, counter, body.len() as u32]);
        let sealed = crypto("encrypt", &self.rx, body, &header, &words(&[0, counter, 0]));
        [header, sealed].concat()
    }
    fn seal(&mut self, op: u32, body: &[u8]) -> Vec<u8> {
        self.counter += 1;
        self.seal_as(self.id, op, self.counter - 1, body)
    }
    fn open_result(&mut self, op: u32, blob: &[u8]) -> Vec<u8> {
        let header = words(&[5, self.id, op, self.results, blob.len() as u32 - 36]);
        assert_eq!(&blob[..20], &header[..], "result header or counter");
        let body = crypto(
            "decrypt",
            &self.tx,
            &blob[20..],
            &header,
            &words(&[1, self.results, 0]),
        );
        self.results += 1;
        body
    }
    /// Issue `op` with already-formed wire input; returns its output bytes.
    fn exec(&mut self, m: &mut DefaultHwModel, op: u32, data: &[u8], pointer: bool) -> Vec<u8> {
        let (_, output) = lengths(op);
        if pointer {
            m.soc_dram_mut().unwrap()[..data.len()].copy_from_slice(data);
        }
        let h = command(self.id, op, pointer, 0);
        let response = send(
            m,
            CommandId::from(IDS[(op - 1) as usize]),
            &h,
            if pointer { &[] } else { data },
        );
        assert_eq!(response.len(), 16 + if pointer { 0 } else { output });
        if pointer {
            m.soc_dram_mut().unwrap()[0x10000..0x10000 + output].to_vec()
        } else {
            response[16..].to_vec()
        }
    }
    fn call(&mut self, m: &mut DefaultHwModel, op: u32, body: &[u8], pointer: bool) -> Vec<u8> {
        let data = if op == 2 || op == 4 {
            self.seal(op, body)
        } else {
            body.to_vec()
        };
        let output = self.exec(m, op, &data, pointer);
        if op == 3 || op == 4 {
            self.open_result(op, &output)
        } else {
            output
        }
    }
    fn reject(&self, m: &mut DefaultHwModel, op: u32, h: &[u8], payload: &[u8]) {
        reject(m, IDS[(op - 1) as usize], h, payload);
    }
}
type Open = fn(&mut DefaultHwModel) -> Client;

#[path = "../src/fhe/model.rs"]
#[allow(dead_code)]
mod model;
fn check_logits(pixels: &[u8], logits: &[u8]) {
    for k in 0..10 {
        let want = model::B[k] as i32
            + (0..196)
                .map(|i| model::W[k][i] as i32 * pixels[i] as i32)
                .sum::<i32>();
        assert_eq!(word(logits, k) as i32, want);
    }
}

/// End-to-end plain scheduling: keygen once, ingress/egress/clear reference in
/// both transports, replayed user blobs, and close ending the session.
fn flow_and_lifecycle(fwid: &'static FwId<'static>, open: Open) {
    let mut m = boot(fwid);
    m.paint_runtime_stack_canary();
    let mut u = open(&mut m);
    reject_open(&mut m, &u.open_request); // a live session cannot be replaced
    let blob = u.seal(2, PT);
    u.reject(&mut m, 2, &command(u.id, 2, false, 0), &blob); // before keygen
    u.call(&mut m, 1, &[], false);
    u.reject(&mut m, 1, &command(u.id, 1, false, 0), &[]); // one secret per session
    for pointer in [false, true] {
        let ct = u.call(&mut m, 2, PT, pointer);
        assert_eq!(ct.len(), 4096);
        assert!(ps_close(&u.call(&mut m, 3, &ct, pointer), PT));
        assert_ne!(u.call(&mut m, 2, PT, pointer), ct, "fresh encryption");
        let pixels: Vec<u8> = (0..196).map(|i| (i % 16) as u8).collect();
        check_logits(&pixels, &u.call(&mut m, 4, &pixels, pointer));
    }
    // A replayed user blob is accepted and only re-encrypts the same data.
    let first = u.exec(&mut m, 2, &blob, false);
    let second = u.exec(&mut m, 2, &blob, false);
    assert_ne!(first, second);
    assert!(ps_close(&u.call(&mut m, 3, &second, false), PT));
    // Close is a plain scheduler command; nothing survives it.
    u.call(&mut m, 5, &[], false);
    u.reject(&mut m, 1, &command(u.id, 1, false, 0), &[]);
    let mut v = open(&mut m);
    assert_eq!(v.id, u.id + 1);
    v.reject(&mut m, 3, &command(v.id, 3, false, 0), &first);
    v.call(&mut m, 1, &[], false);
    assert!(
        !ps_close(&v.call(&mut m, 3, &first, false), PT),
        "old secret survived"
    );
    v.reject(&mut m, 2, &command(v.id, 2, false, 0), &blob); // old session's blob
    v.call(&mut m, 5, &[], false);
    // Raw and accelerator IDs remain unavailable in a protected build.
    for id in [0x46484552u32, 0x46484452, 0x4648454e, 0x46484445] {
        reject(&mut m, id, &[0; 48], &[]);
    }
    println!(
        "{:?} stack extent {}",
        fwid.features,
        m.runtime_stack_canary_used()
    );
    assert!(m.runtime_stack_canary_used() < caliptra_common::memory_layout::STACK_SIZE as usize);
}

/// Malformed commands and tampered blobs fail without ending the session or
/// consuming a result counter; failures leave the mailbox scrubbed.
fn validation(fwid: &'static FwId<'static>, open: Open) {
    let mut m = boot(fwid);
    let mut u = open(&mut m);
    u.call(&mut m, 1, &[], false);
    let blob = u.seal(2, PT);
    let h = command(u.id, 2, false, 0);
    // Every blob header word, the body and the tag are authenticated.
    for offset in [0, 4, 8, 12, 16, 20, 2083] {
        let mut bad = blob.clone();
        bad[offset] ^= 1;
        u.reject(&mut m, 2, &h, &bad);
        assert!(mailbox_scrubbed(&mut m, 0));
    }
    u.reject(&mut m, 2, &h, &u.seal_as(u.id + 1, 2, 99, PT)); // other session
                                                              // A blob sealed for one op is refused by another (header op, then tag).
    let pixels = [0u8; 196];
    u.reject(
        &mut m,
        4,
        &command(u.id, 4, false, 0),
        &u.seal_as(u.id, 2, 98, &pixels),
    );
    // Command fields: version, session, mode, lengths, arg; ID must match op.
    for (offset, value) in [
        (4, 4),
        (12, u.id + 1),
        (16, 2),
        (36, 2048),
        (40, 0),
        (44, 1),
    ] {
        let mut bad = h.clone();
        bad[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        u.reject(&mut m, 2, &bad, &blob);
    }
    reject(&mut m, IDS[2], &h, &blob);
    let mut bad = h.clone();
    bad[20..24].copy_from_slice(&0x80000000u32.to_le_bytes()); // src in mailbox mode
    u.reject(&mut m, 2, &bad, &blob);
    // Pointer ranges: out of window, overlapping; controls never use pointers.
    for (offset, value) in [(20, 0x7fff_f000u32), (28, 0x8000_0400), (24, 1)] {
        let mut bad = command(u.id, 2, true, 0);
        bad[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        u.reject(&mut m, 2, &bad, &[]);
    }
    u.reject(&mut m, 5, &command(u.id, 5, true, 0), &[]);
    // The session and result counter are untouched by all of the above.
    let ct = u.exec(&mut m, 2, &blob, false);
    assert!(ps_close(&u.call(&mut m, 3, &ct, false), PT));
    assert_eq!(u.results, 2);
    u.call(&mut m, 5, &[], false);
}

/// A partial external write consumes its result counter, never exposes
/// plaintext, and poisons DMA: only close runs, and no new session opens.
fn failed_write_and_poison(fwid: &'static FwId<'static>, open: Open) {
    let mut m = boot(fwid);
    let mut u = open(&mut m);
    u.call(&mut m, 1, &[], false);
    let ct = u.call(&mut m, 2, PT, false);
    assert!(ps_close(&u.call(&mut m, 3, &ct, false), PT));
    let end = m.soc_dram_mut().unwrap().len();
    let mut h = command(u.id, 3, true, 0);
    h[28..32].copy_from_slice(&(0x80000000u32 + end as u32 - 16).to_le_bytes());
    m.soc_dram_mut().unwrap()[..4096].copy_from_slice(&ct);
    m.soc_dram_mut().unwrap()[end - 16..].fill(0xa5);
    u.reject(&mut m, 3, &h, &[]);
    // The first 16 bytes are the clear result header, with counter 2 consumed.
    assert_eq!(
        &m.soc_dram_mut().unwrap()[end - 16..],
        &words(&[5, u.id, 3, 2])[..]
    );
    assert!(mailbox_scrubbed(&mut m, 0));
    let blob = u.seal(2, PT);
    u.reject(&mut m, 2, &command(u.id, 2, false, 0), &blob);
    reject_open(&mut m, &u.open_request);
    u.call(&mut m, 5, &[], false);
    reject_open(&mut m, &u.open_request);
}

/// Valid fabric range beyond emulator RAM: partial read, then DMA fault.
fn read_poison(fwid: &'static FwId<'static>, open: Open) {
    let mut m = boot(fwid);
    let mut u = open(&mut m);
    u.call(&mut m, 1, &[], false);
    let end = m.soc_dram_mut().unwrap().len();
    let mut h = command(u.id, 2, true, 0);
    h[20..24].copy_from_slice(&(0x80000000u32 + end as u32 - 4).to_le_bytes());
    m.soc_dram_mut().unwrap()[0x10000..0x11000].fill(0x5a);
    u.reject(&mut m, 2, &h, &[]);
    assert!(m.soc_dram_mut().unwrap()[0x10000..0x11000]
        .iter()
        .all(|&v| v == 0x5a));
    assert!(mailbox_scrubbed(&mut m, 0));
    for _ in 0..2 {
        u.reject(&mut m, 1, &command(u.id, 1, false, 0), &[]);
        reject_open(&mut m, &u.open_request);
    }
    u.call(&mut m, 5, &[], false);
}

/// External input is snapshotted once before authentication; later changes
/// to the source buffer cannot affect the result.
fn snapshot_and_cleanup(fwid: &'static FwId<'static>, open: Open) {
    let mut m = boot(fwid);
    let mut u = open(&mut m);
    u.call(&mut m, 1, &[], false);
    let blob = u.seal(2, PT);
    m.soc_dram_mut().unwrap()[..blob.len()].copy_from_slice(&blob);
    m.start_mailbox_execute(IDS[1], &wire(IDS[1], &command(u.id, 2, true, 0), &[]))
        .unwrap();
    let mut retained = false;
    for _ in 0..100_000 {
        for _ in 0..20 {
            m.step();
        }
        if m.mailbox_sram_snapshot(48, blob.len()) == blob {
            retained = true;
            break;
        }
    }
    assert!(retained, "snapshot not observed");
    m.soc_dram_mut().unwrap()[..blob.len()].fill(0xa5);
    for _ in 0..5_000_000 {
        if !m.soc_mbox().status().read().status().cmd_busy() {
            break;
        }
        m.step();
    }
    assert_eq!(m.finish_mailbox_execute().unwrap().unwrap().len(), 16);
    assert!(mailbox_scrubbed(&mut m, 16));
    let ct = m.soc_dram_mut().unwrap()[0x10000..0x11000].to_vec();
    assert!(ps_close(&u.call(&mut m, 3, &ct, false), PT));
    if fwid.features.contains(&"ml-clear") {
        // Authenticated but invalid pixels are refused and scrubbed.
        let bad = u.seal(4, &[16; 196]);
        u.reject(&mut m, 4, &command(u.id, 4, false, 0), &bad);
        assert!(mailbox_scrubbed(&mut m, 0));
    }
    u.call(&mut m, 5, &[], false);
}

#[test]
fn testkey_flow_and_lifecycle() {
    flow_and_lifecycle(&firmware::APP_FHE_TEST_KEY_ML_CLEAR, Client::test_key);
}
#[test]
fn testkey_validation() {
    validation(&firmware::APP_FHE_TEST_KEY_ML_CLEAR, Client::test_key);
}
#[test]
fn testkey_failed_write_and_poison() {
    failed_write_and_poison(&firmware::APP_FHE_TEST_KEY_ML_CLEAR, Client::test_key);
}
#[test]
fn testkey_read_poison() {
    read_poison(&firmware::APP_FHE_TEST_KEY_ML_CLEAR, Client::test_key);
}
#[test]
fn testkey_snapshot_and_cleanup() {
    snapshot_and_cleanup(&firmware::APP_FHE_TEST_KEY_ML_CLEAR, Client::test_key);
}
/// The fixed public keys are refused once debug access is locked.
#[test]
fn testkey_requires_debug_unlocked() {
    let (mut m, _) = boot_state(&firmware::APP_FHE_TEST_KEY_ML_CLEAR, false, true);
    reject_open(&mut m, &words(&[0, 5]));
}

/// Runs the actual Python user/scheduler against real runtime commands. The
/// same directory protocol is used by the Rocket HTIF relay; no simulator here.
#[test]
fn testkey_host_demo() {
    run_host_demo(
        &firmware::APP_FHE_TEST_KEY_ML_CLEAR,
        "protected_demo.py",
        false,
    );
}
#[test]
fn testkey_evalkey_host_demo() {
    run_host_demo(
        &firmware::APP_FHE_TEST_KEY_EVAL_KEYS,
        "evalkey_demo.py",
        false,
    );
}
/// Packed MNIST: one rotation key, two ingress per image, one egress.
#[test]
fn testkey_packed_host_demo() {
    run_host_demo(
        &firmware::APP_FHE_TEST_KEY_EVAL_KEYS,
        "packed_demo.py",
        false,
    );
}
#[test]
fn packed_host_demo() {
    run_host_demo(&firmware::APP_FHE_EVAL_KEYS, "packed_demo.py", false);
}
#[test]
fn evalkey_host_demo() {
    run_host_demo(&firmware::APP_FHE_EVAL_KEYS, "evalkey_demo.py", false);
}
#[test]
fn ecdh_host_demo() {
    run_host_demo(&firmware::APP_FHE_ECDH_ML_CLEAR, "protected_demo.py", false);
}
#[test]
fn ecdh_host_verifier_tampering() {
    run_host_demo(&firmware::APP_FHE_ECDH_ML_CLEAR, "test_ecdh.py", false);
}
#[test]
fn ecdh_wrapper_fixture() {
    run_host_demo_fixture(
        &firmware::APP_FHE_ECDH_ML_CLEAR,
        "protected_demo.py",
        false,
        true,
    );
}

/// `mnist_data` forwards FHE_MNIST_DATA as the client's cached --data-dir.
fn run_host_demo(fwid: &'static FwId<'static>, script: &str, mnist_data: bool) {
    run_host_demo_fixture(fwid, script, mnist_data, false);
}
fn run_host_demo_fixture(
    fwid: &'static FwId<'static>,
    script_name: &str,
    mnist_data: bool,
    wrapper_fixture: bool,
) {
    use std::{
        fs,
        process::Command,
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    let (mut m, runtime_digest) = boot_with_measurement(fwid, wrapper_fixture);
    m.paint_runtime_stack_canary();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("fhe-protected-demo-{}-{stamp}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    fs::write(
        dir.join("hello"),
        [SRC.to_le_bytes(), DST.to_le_bytes()].concat(),
    )
    .unwrap();
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fhe")
        .join(script_name);
    let mut cmd = Command::new("python3");
    cmd.arg(script).arg(&dir).arg("--timeout").arg("120");
    if let Some(runtime_digest) = runtime_digest {
        let root = dir.join("device-root.pem");
        if wrapper_fixture {
            let out = Command::new("python3")
                .arg(
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fhe/demo_root.py"),
                )
                .output()
                .unwrap();
            assert!(out.status.success());
            fs::write(&root, out.stdout).unwrap();
        } else {
            // Provision from the repository's independent golden device CSR, never
            // from the relay/command under test. Its key is checked by ROM tests.
            let csr = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../test/tests/caliptra_integration_tests/smoke_testdata/idevid_csr_ecc.der");
            assert!(Command::new("python3").arg("-c").arg(
                "from pathlib import Path; import sys; from cryptography import x509; from cryptography.hazmat.primitives import serialization as s; Path(sys.argv[2]).write_bytes(x509.load_der_x509_csr(Path(sys.argv[1]).read_bytes()).public_key().public_bytes(s.Encoding.PEM,s.PublicFormat.SubjectPublicKeyInfo))"
            ).arg(csr).arg(&root).status().unwrap().success());
        }
        cmd.arg("--session")
            .arg("ecdh")
            .arg("--device-root")
            .arg(root)
            .arg("--runtime-sha384")
            .arg(runtime_digest);
    } else if !mnist_data {
        cmd.arg("--session").arg("testkey");
    }
    if std::env::var_os("FHE_FULL_DEMO").is_some() && script_name == "protected_demo.py" {
        cmd.arg("--full");
    }
    if mnist_data {
        if let Some(path) = std::env::var_os("FHE_MNIST_DATA") {
            cmd.arg("--data-dir").arg(path);
        }
    }
    let transport = if mnist_data || script_name != "protected_demo.py" {
        None
    } else {
        std::env::var_os("FHE_DEMO_TRANSPORT")
    };
    let mailbox_only = transport.as_deref() == Some(std::ffi::OsStr::new("mailbox"));
    if let Some(transport) = transport {
        cmd.arg("--transport").arg(transport);
    }
    let mut user = cmd.spawn().unwrap();
    let mut session = 0;
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
        // Relay frame: command, request bytes, external input, external output.
        // A job frame (op, mode, arg) is scheduled here exactly as Rocket's
        // protected-demo.c does: this harness builds the plain command.
        let id = word(&data, 0);
        if id == 0 {
            assert!(user.wait().unwrap().success());
            println!(
                "host demo {:?} stack extent {}",
                fwid.features,
                m.runtime_stack_canary_used()
            );
            assert!(
                m.runtime_stack_canary_used() < caliptra_common::memory_layout::STACK_SIZE as usize
            );
            return;
        }
        let len = word(&data, 1) as usize;
        let ext = word(&data, 2) as usize;
        let body = &data[16 + len..16 + len + ext];
        let (id, h, payload, outlen) = if id == JOB {
            let (op, mode, arg) = (word(&data, 4), word(&data, 5), word(&data, 6));
            let outlen = if mode == 1 { lengths(op).1 } else { 0 };
            assert_eq!(len, 12, "malformed job {i}");
            assert_eq!(
                (ext, word(&data, 3) as usize),
                (lengths(op).0, outlen),
                "job {i} lengths"
            );
            if mailbox_only {
                assert_eq!(mode, 0, "mailbox-only job {i} used an external buffer");
            }
            if mode == 1 {
                m.soc_dram_mut().unwrap()[..ext].copy_from_slice(body);
            }
            let payload = if mode == 1 { &[][..] } else { body };
            (
                IDS[(op - 1) as usize],
                command(session, op, mode == 1, arg),
                payload,
                outlen,
            )
        } else {
            // Raw frames (open, certificates) carry no external data.
            assert_eq!(
                (ext, word(&data, 3)),
                (0, 0),
                "raw frame {i} with external data"
            );
            (id, data[16..16 + len].to_vec(), &[][..], 0)
        };
        // Keys must never touch mailbox SRAM past the command header.
        let key = IDS[5..].contains(&id);
        if key {
            m.limit_direct_mailbox_access(Some(48));
        }
        let result = send(&mut m, CommandId::from(id), &h, payload);
        if key {
            m.limit_direct_mailbox_access(None);
        }
        if id == OPEN {
            session = word(&result, 2);
        }
        let mut packet = words(&[result.len() as u32, outlen as u32]);
        packet.extend(result);
        packet.extend_from_slice(&m.soc_dram_mut().unwrap()[0x10000..0x10000 + outlen]);
        fs::write(dir.join(format!("resp-{i}")), packet).unwrap();
    }
    panic!("demo exceeded request limit");
}

#[cfg(feature = "fhe-aloha")]
#[path = "fhe_aloha.rs"]
mod aloha_tests;
#[path = "fhe_ecdh.rs"]
mod ecdh_tests;
