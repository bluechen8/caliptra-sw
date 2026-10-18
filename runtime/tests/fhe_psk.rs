// Licensed under the Apache-2.0 license
//! RV32 runtime on the software SoC model; optional Aloha RTL RPC tests.
//! These hybrid tests do not validate full-SoC RTL.
#![cfg(not(any(
    feature = "verilator",
    feature = "fpga_realtime",
    feature = "fpga_subsystem"
)))]
// Integer reconstruction of Aloha residues, used to check ciphertexts.
#[cfg(feature = "fhe-aloha")]
#[path = "aloha_recovery/mod.rs"]
mod coefficient_recovery;

use caliptra_api::{mailbox::CommandId, SocManager};
use caliptra_builder::{firmware, FwId, ImageOptions};
use caliptra_hw_model::{BootParams, DefaultHwModel, Fuses, HwModel, InitParams};
use caliptra_image_types::FwVerificationPqcKeyType;
use zerocopy::IntoBytes;

fn boot(fwid: &'static FwId<'static>) -> DefaultHwModel {
    boot_with(&firmware::ROM_WITH_UART_NO_MLDSA, &firmware::FMC_WITH_UART_NO_MLDSA, fwid)
}
fn boot_with(rom: &FwId<'static>, fmc: &FwId<'static>, fwid: &'static FwId<'static>) -> DefaultHwModel {
    let rom = caliptra_builder::build_firmware_rom(rom).unwrap();
    let mut opts = ImageOptions::default();
    opts.pqc_key_type = FwVerificationPqcKeyType::LMS;
    opts.vendor_config.pl0_pauser = Some(1);
    let image = caliptra_builder::build_and_sign_image(fmc, fwid, opts).unwrap();
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
const IDS: [u32; 6] = [
    0x46484b47, 0x4648494e, 0x46484547, 0x4d4c4943, 0x46485343, 0x46485246,
];
/// Authenticated parameter-set ID of the Aloha N=256 profile.
#[cfg(feature = "fhe-aloha")]
const ALOHA_PROFILE: u32 = 0xa108;
const DEMO_PSK_HEX: &str = "a7b1c3d5e7f9012436485a6c7e90a2b4c6d8eaf10315274961738597a9bbcddf";
struct User {
    open_request: Vec<u8>,
    id: u32,
    seq: u32,
    policy: [u32; 5],
    rx: Vec<u8>,
    tx: Vec<u8>,
    log_scale: Option<u32>,
}
impl User {
    fn opening(policy: [u32; 5]) -> Vec<u8> {
        let mut req = words(&[0, if policy[2] == 0xa108 { 6 } else { 3 }]);
        req.extend(words(&policy));
        req.extend([0x36; 32]);
        let mut transcript = words(&[0]);
        transcript.extend(&req[4..]);
        let psk = unhex(DEMO_PSK_HEX);
        req.extend(crypto("mac", &psk, &transcript, &[], &[]));
        req
    }
    fn open(m: &mut DefaultHwModel, policy: [u32; 5]) -> Self {
        let req = Self::opening(policy);
        let response = send(m, CommandId::FHE_SESSION_OPEN, &req, &[]);
        let aloha = policy[2] == 0xa108;
        assert_eq!(response.len(), if aloha { 60 } else { 28 });
        let id = word(&response, 2);
        let mut transcript = req[4..60].to_vec();
        transcript.extend(words(&[id]));
        if aloha {
            transcript.extend(&response[12..44]);
        }
        let psk = unhex(DEMO_PSK_HEX);
        let k = |i| {
            let mut b = words(&[i]);
            b.extend(&transcript);
            crypto("mac", &psk, &b, &[], &[])
        };
        assert_eq!(&response[if aloha { 44 } else { 12 }..], k(5));
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
            log_scale: None,
        }
    }
    fn packet(&self, op: u32, body: &[u8], pointer: bool) -> (Vec<u8>, Vec<u8>) {
        let output = match op {
            // P-S (profile 0) returns 4096 ciphertext bytes; Aloha returns 8192.
            6 => 8192,
            2 if self.policy[2] != 0 => 8192,
            2 => 4096,
            3 => 2048,
            4 => 40,
            _ => 0,
        };
        let scale = if op == 6 {
            Some(self.log_scale.unwrap_or(25))
        } else if op == 3 {
            self.log_scale
        } else {
            None
        };
        let mut h = words(&[
            0,
            if scale.is_some() { 4 } else { 3 },
            op,
            self.id,
            self.seq,
        ]);
        h.extend(words(&self.policy));
        h.extend(words(&[
            pointer as u32,
            if pointer { 0x80000000 } else { 0 },
            0,
            if pointer { 0x80010000 } else { 0 },
            0,
            body.len() as u32,
            output,
            scale.unwrap_or(0),
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

/// Aloha v5 client (docs/fhe/16 "Session protocol on the DMA path"). Headers
/// are in clear; only the ENCRYPT message and the DECRYPT output are sealed.
/// Buffers live in the RTL testbench memory, the only memory Aloha's DMA reaches.
#[cfg(feature = "fhe-aloha")]
mod v5 {
    use super::*;
    pub const SRC: u64 = super::DRAM_BASE;
    pub const DST: u64 = super::DRAM_BASE + 0x1_0000;
    pub const CT: usize = 8192;
    pub const Q0: usize = 4096;
    pub const MSG: usize = 2048;
    /// ERR_CAUSE values firmware reports in the response status word.
    pub const BAD_INPUT: u32 = 8;
    pub const ABORTED: u32 = 11;
    pub fn lengths(op: u32) -> (usize, usize) {
        match op {
            2 => (MSG, CT),
            3 => (Q0, MSG),
            6 => (Q0, CT),
            _ => (0, 0),
        }
    }
    /// One decoded response.
    pub struct Reply {
        pub status: u32,
        pub tag: Vec<u8>,
    }
    impl User {
        /// The request header; `tag` is the ENCRYPT message tag.
        pub fn header(&self, op: u32, tag: &[u8], log_scale: u32) -> Vec<u8> {
            let (input, output) = lengths(op);
            let (src, dst) = if input == 0 { (0, 0) } else { (SRC, DST) };
            let mut h = words(&[
                0,
                5,
                op,
                self.id,
                self.seq,
                src as u32,
                (src >> 32) as u32,
                dst as u32,
                (dst >> 32) as u32,
                input as u32,
                output as u32,
                log_scale,
            ]);
            h.extend(tag);
            h.resize(64, 0);
            h
        }
        /// Seals an ENCRYPT message for the next sequence number.
        pub fn seal(&self, msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
            let ct = crypto("encrypt", &self.rx, msg, &[], &words(&[0, self.seq, 0]));
            let (body, tag) = ct.split_at(ct.len() - 16);
            (body.to_vec(), tag.to_vec())
        }
        /// Sends a header; the response must be for this session and sequence.
        pub fn send5(&mut self, m: &mut DefaultHwModel, h: &[u8]) -> Reply {
            let op = word(h, 2);
            let r = send(m, CommandId::from(IDS[(op - 1) as usize]), h, &[]);
            assert_eq!(r.len(), 44);
            assert_eq!((word(&r, 2), word(&r, 3)), (self.id, word(h, 4)));
            self.seq += 1;
            Reply {
                status: word(&r, 4),
                tag: r[28..44].to_vec(),
            }
        }
        pub fn keygen(&mut self, m: &mut DefaultHwModel) {
            let h = self.header(1, &[], 0);
            assert_eq!(self.send5(m, &h).status, 0);
        }
        pub fn close(&mut self, m: &mut DefaultHwModel) {
            let h = self.header(5, &[], 0);
            assert_eq!(self.send5(m, &h).status, 0);
        }
        /// ENCRYPT; returns the status and, on success, the 8 KiB ciphertext.
        pub fn encrypt5(&mut self, m: &mut DefaultHwModel, msg: &[u8]) -> (u32, Vec<u8>) {
            let (body, tag) = self.seal(msg);
            dram_write(m, SRC, &body);
            let h = self.header(2, &tag, 0);
            let r = self.send5(m, &h);
            (r.status, dram_read(m, DST, CT))
        }
        /// DECRYPT c0, c1 limb 0 (4 KiB); returns the status and the opened slots.
        pub fn decrypt5(&mut self, m: &mut DefaultHwModel, q0: &[u8], log_scale: u32) -> (u32, Vec<u8>) {
            dram_write(m, SRC, q0);
            let h = self.header(3, &[], log_scale);
            let seq = self.seq;
            let r = self.send5(m, &h);
            if r.status != 0 {
                return (r.status, Vec::new());
            }
            let mut body = dram_read(m, DST, MSG);
            body.extend(&r.tag);
            (0, crypto("decrypt", &self.tx, &body, &[], &words(&[1, seq, 0])))
        }
        pub fn refresh5(&mut self, m: &mut DefaultHwModel, q0: &[u8], log_scale: u32) -> (u32, Vec<u8>) {
            dram_write(m, SRC, q0);
            let h = self.header(6, &[], log_scale);
            let r = self.send5(m, &h);
            (r.status, dram_read(m, DST, CT))
        }
    }
    /// c0, c1 limb 0 of a full ciphertext.
    pub fn q0(ct: &[u8]) -> Vec<u8> {
        [&ct[..2048], &ct[4096..6144]].concat()
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
    run_host_demo(
        &firmware::APP_FHE_PSK_ML_CLEAR,
        "protected_demo.py",
        false,
        false,
    );
}

/// Requires a local-stream N=256 RTL RPC executable and initialized table cwd.
#[test]
#[cfg(feature = "fhe-aloha")]
#[ignore = "requires FHE_ALOHA_RTL and FHE_ALOHA_RTL_CWD"]
fn protected_aloha_host_demo() {
    run_host_demo(&firmware::APP_FHE_ALOHA, "aloha_demo.py", true, false);
}

/// Replaying the identical authenticated open after warm reset must not
/// recreate transport keys, even when the firmware session ID restarts at one.
#[test]
#[cfg(feature = "fhe-aloha")]
#[ignore = "requires FHE_ALOHA_RTL and FHE_ALOHA_RTL_CWD"]
fn protected_aloha_open_freshness() {
    let mut m = boot(&firmware::APP_FHE_ALOHA);
    // A correctly MACed legacy Aloha open must not permit a downgrade.
    let mut legacy = User::opening([0x4e, 64, 0, 2, 0]);
    legacy[16..20].copy_from_slice(&ALOHA_PROFILE.to_le_bytes());
    let mut auth = words(&[0]);
    auth.extend(&legacy[4..60]);
    let psk = unhex(DEMO_PSK_HEX);
    legacy[60..76].copy_from_slice(&crypto("mac", &psk, &auth, &[], &[]));
    let open_id: u32 = CommandId::FHE_SESSION_OPEN.into();
    assert!(m
        .mailbox_execute(open_id, &wire(open_id, &legacy, &[]))
        .is_err());
    let mut old = User::open(&mut m, [0x4e, 64, ALOHA_PROFILE, 2, 0]);
    old.keygen(&mut m);
    // A message sealed under the old session's request key, for seq 2.
    let (old_body, old_tag) = old.seal(&[0; v5::MSG]);
    let old_header = old.header(2, &old_tag, 0);
    // Let runtime finish the command and enter idle before warm reset.
    for _ in 0..10000 {
        m.step();
    }
    m.warm_reset_flow().unwrap();
    let mut ready = false;
    for _ in 0..20_000_000 {
        assert_eq!(m.soc_ifc().cptra_fw_error_fatal().read(), 0);
        if m.soc_ifc().cptra_flow_status().read().ready_for_runtime() {
            ready = true;
            break;
        }
        m.step();
    }
    assert!(ready, "warm reset did not reboot");
    let mut fresh = User::open(&mut m, [0x4e, 64, ALOHA_PROFILE, 2, 0]);
    assert_eq!(old.open_request, fresh.open_request);
    assert_eq!(old.id, fresh.id, "test must exercise repeated session ID");
    assert_ne!(old.rx, fresh.rx);
    assert_ne!(old.tx, fresh.tx);
    fresh.keygen(&mut m);
    // Session ID and sequence match the replay: only the fresh request key
    // stops it. The tag fails at COMMIT_WAIT, so Aloha aborts and writes nothing.
    assert_eq!(word(&old_header, 4), fresh.seq);
    dram_write(&mut m, v5::SRC, &old_body);
    dram_write(&mut m, v5::DST, &[0xa5; v5::CT]);
    assert_eq!(fresh.send5(&mut m, &old_header).status, v5::ABORTED);
    assert!(dram_read(&mut m, v5::DST, v5::CT).iter().all(|&v| v == 0xa5));
    fresh.close(&mut m);
}

/// Quick boot (fake ROM and fake FMC, as the SoC smoke bundle uses) skips the
/// key ladder; KEYGEN still needs a usable RT CDI in KeyVault.
#[test]
#[cfg(feature = "fhe-aloha")]
#[ignore = "requires FHE_ALOHA_RTL and FHE_ALOHA_RTL_CWD"]
fn protected_aloha_quick_boot_keygen() {
    let mut m = boot_with(
        &firmware::ROM_FAKE_WITH_UART_NO_MLDSA,
        &firmware::FMC_FAKE_WITH_UART_NO_MLDSA,
        &firmware::APP_FHE_ALOHA,
    );
    let mut u = User::open(&mut m, [0x0e, 8, ALOHA_PROFILE, 2, 0]);
    u.keygen(&mut m);
    let (status, ct) = u.encrypt5(&mut m, &[0; v5::MSG]);
    assert_eq!(status, 0);
    assert_eq!(u.decrypt5(&mut m, &v5::q0(&ct), 25).0, 0);
    u.close(&mut m);
}

/// After DisableAttestation the RT CDI is a public constant: KEYGEN is
/// refused, while a key generated before it stays usable.
#[test]
#[cfg(feature = "fhe-aloha")]
#[ignore = "requires FHE_ALOHA_RTL and FHE_ALOHA_RTL_CWD"]
fn protected_aloha_keygen_after_disable_attestation() {
    let mut m = boot(&firmware::APP_FHE_ALOHA);
    let mut u = User::open(&mut m, [0x0e, 8, ALOHA_PROFILE, 2, 0]);
    u.keygen(&mut m);
    let disable: u32 = CommandId::DISABLE_ATTESTATION.into();
    m.mailbox_execute(disable, &wire(disable, &[0; 4], &[])).unwrap();
    let (status, ct) = u.encrypt5(&mut m, &[0; v5::MSG]);
    assert_eq!(status, 0);
    assert_eq!(u.decrypt5(&mut m, &v5::q0(&ct), 25).0, 0);
    u.close(&mut m);
    let u = User::open(&mut m, [0x0e, 8, ALOHA_PROFILE, 2, 0]);
    let id: u32 = IDS[0];
    match m.mailbox_execute(id, &wire(id, &u.header(1, &[], 0), &[])) {
        Err(caliptra_hw_model::ModelError::MailboxCmdFailed(code)) => {
            assert_eq!(code, 0x000e_0105) // RUNTIME_FHE_ATTESTATION_DISABLED
        }
        other => panic!("KEYGEN after DisableAttestation: {other:?}"),
    }
}

/// Validate the SoC negative client quickly before a long full-SoC run.
#[test]
#[cfg(feature = "fhe-aloha")]
#[ignore = "requires FHE_ALOHA_RTL and FHE_ALOHA_RTL_CWD"]
fn protected_aloha_negative_host_demo() {
    run_host_demo(
        &firmware::APP_FHE_ALOHA,
        "aloha_soc_validation.py",
        false,
        false,
    );
}

/// Point FHE_ALOHA_RTL to an RPC launcher adding +RPC_ZEROIZE_REFRESH.
#[test]
#[cfg(feature = "fhe-aloha")]
#[ignore = "requires RTL RPC with +RPC_ZEROIZE_REFRESH injection"]
fn interrupted_aloha_host_demo() {
    run_host_demo(
        &firmware::APP_FHE_ALOHA,
        "aloha_soc_validation.py",
        false,
        true,
    );
}

/// SoC DRAM, based at 0x8000_0000: the Aloha RTL's testbench memory when its
/// link is up, else the model's SoC DRAM.
const DRAM_BASE: u64 = 0x8000_0000;
fn dram_write(m: &mut DefaultHwModel, addr: u64, data: &[u8]) {
    #[cfg(feature = "fhe-aloha")]
    if let Some(rtl) = m.fhe_rtl() {
        return rtl.dram_write(addr, data);
    }
    let off = (addr - DRAM_BASE) as usize;
    m.soc_dram_mut().unwrap()[off..off + data.len()].copy_from_slice(data);
}
fn dram_read(m: &mut DefaultHwModel, addr: u64, len: usize) -> Vec<u8> {
    #[cfg(feature = "fhe-aloha")]
    if let Some(rtl) = m.fhe_rtl() {
        return rtl.dram_read(addr, len);
    }
    let off = (addr - DRAM_BASE) as usize;
    m.soc_dram_mut().unwrap()[off..off + len].to_vec()
}

/// `mnist_data` forwards FHE_MNIST_DATA as the client's cached --data-dir.
fn run_host_demo(fwid: &'static FwId<'static>, script: &str, mnist_data: bool, interrupt: bool) {
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
    let negative = script == "aloha_soc_validation.py";
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fhe")
        .join(script);
    let mut cmd = Command::new("python3");
    cmd.arg(script).arg(&dir).arg("--timeout").arg("120");
    if interrupt {
        cmd.arg("--interrupt-only");
    }
    if !negative && std::env::var_os("FHE_FULL_DEMO").is_some() {
        cmd.arg("--full");
    }
    if mnist_data {
        // Exercise the same refresh client used by the full-SoC relay.
        cmd.arg("--refresh");
        if let Some(path) = std::env::var_os("FHE_MNIST_DATA") {
            cmd.arg("--data-dir").arg(path);
        }
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
        let h = &data[12..12 + len];
        if ext > 0 {
            dram_write(&mut m, DRAM_BASE, &data[12 + len..]);
        }
        if negative {
            dram_write(&mut m, DRAM_BASE + 0x10000, &[0xa5; 0x2000]);
        }
        let result = if !negative {
            send(&mut m, CommandId::from(id), h, &[])
        } else {
            match m.mailbox_execute(id, &wire(id, h, &[])) {
                Ok(Some(result)) => result,
                Err(caliptra_hw_model::ModelError::MailboxCmdFailed(code)) => {
                    assert!(
                        dram_read(&mut m, DRAM_BASE + 0x10000, 0x2000)
                            .iter()
                            .all(|&value| value == 0xa5),
                        "rejection changed output"
                    );
                    fs::write(dir.join(format!("resp-{i}")), words(&[0xffffffff, code])).unwrap();
                    continue;
                }
                other => panic!("unexpected relay response: {other:?}"),
            }
        };
        // Output bytes: request word 10 in v5, word 16 in v3/v4.
        let outlen = match (ext, word(h, 1)) {
            (0, _) => 0,
            (_, 5) => word(h, 10) as usize,
            _ => word(h, 16) as usize,
        };
        let mut packet = words(&[result.len() as u32, outlen as u32]);
        packet.extend(result);
        if outlen > 0 {
            packet.extend(dram_read(&mut m, DRAM_BASE + 0x10000, outlen));
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

/// A forged ENCRYPT message is caught at COMMIT_WAIT: Aloha aborts, writes
/// nothing and drops the resident key; the session needs a new KEYGEN. Bad
/// input words (ciphertext residues, non-finite slots) fail only their command.
#[test]
#[cfg(feature = "fhe-aloha")]
#[ignore = "requires FHE_ALOHA_RTL and FHE_ALOHA_RTL_CWD"]
fn protected_aloha_bad_tag() {
    let mut m = boot(&firmware::APP_FHE_ALOHA);
    m.paint_runtime_stack_canary();
    let mut u = User::open(&mut m, [0x0e, 8, ALOHA_PROFILE, 2, 0]);
    u.keygen(&mut m);
    let (body, tag) = u.seal(&[0; v5::MSG]);
    let mut forged = tag.clone();
    forged[0] ^= 1;
    dram_write(&mut m, v5::SRC, &body);
    dram_write(&mut m, v5::DST, &[0xa5; v5::CT]);
    let h = u.header(2, &forged, 0);
    assert_eq!(u.send5(&mut m, &h).status, v5::ABORTED);
    assert!(dram_read(&mut m, v5::DST, v5::CT).iter().all(|&v| v == 0xa5));
    // The key is gone: ENCRYPT is refused without consuming the sequence.
    let (_, tag) = u.seal(&[0; v5::MSG]);
    u.reject(&mut m, 2, &u.header(2, &tag, 0), &[]);
    // Replaying the forged command's sequence number is refused too.
    let mut replay = h.clone();
    replay[48..64].copy_from_slice(&tag);
    u.reject(&mut m, 2, &replay, &[]);
    u.keygen(&mut m);
    let (status, ct) = u.encrypt5(&mut m, &[0; v5::MSG]);
    assert_eq!(status, 0);
    let (status, slots) = u.decrypt5(&mut m, &v5::q0(&ct), 25);
    assert_eq!(status, 0);
    assert!(slots.chunks_exact(8).all(|b| f64::from_le_bytes(b.try_into().unwrap()).abs() < 0.01));
    // A non-canonical residue: the command fails and writes nothing; the
    // session and the key survive.
    let mut bad = v5::q0(&ct);
    bad[..8].copy_from_slice(&coefficient_recovery::Q[0].to_le_bytes());
    dram_write(&mut m, v5::DST, &[0xa5; v5::MSG]);
    assert_eq!(u.decrypt5(&mut m, &bad, 25).0, v5::BAD_INPUT);
    assert!(dram_read(&mut m, v5::DST, v5::MSG).iter().all(|&v| v == 0xa5));
    // A NaN slot is reported only after the tag check commits the message.
    let mut nan = vec![0u8; v5::MSG];
    nan[16..24].copy_from_slice(&f64::NAN.to_le_bytes());
    assert_eq!(u.encrypt5(&mut m, &nan).0, v5::BAD_INPUT);
    assert_eq!(u.decrypt5(&mut m, &v5::q0(&ct), 25).0, 0);
    // Malformed headers are refused without consuming the sequence.
    let mut h = u.header(3, &[], 25);
    h[44..48].copy_from_slice(&41u32.to_le_bytes());
    u.reject(&mut m, 3, &h, &[]);
    let mut h = u.header(3, &[], 25);
    h[20..24].copy_from_slice(&(v5::SRC as u32 + 8).to_le_bytes());
    u.reject(&mut m, 3, &h, &[]);
    let mut h = u.header(3, &[], 25);
    h[48] = 1; // tag on a DECRYPT request
    u.reject(&mut m, 3, &h, &[]);
    u.close(&mut m);
    assert!(m.runtime_stack_canary_used() < caliptra_common::memory_layout::STACK_SIZE as usize);
}

/// Real RV32 firmware + Aloha RTL, AES and DMA: retain coefficients and scale
/// while restoring the two-prime chain. The mailbox remains an emulator model.
#[test]
#[cfg(feature = "fhe-aloha")]
#[ignore = "requires FHE_ALOHA_RTL and FHE_ALOHA_RTL_CWD"]
fn protected_aloha_level_refresh() {
    let mut m = boot(&firmware::APP_FHE_ALOHA);
    m.paint_runtime_stack_canary();
    let values: Vec<f64> = (0..256)
        .map(|i| {
            if i % 2 == 1 {
                0.0
            } else {
                (i as f64 - 128.0) / 64.0
            }
        })
        .collect();
    let pt: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
    let mut u = User::open(&mut m, [0x4e, 8, ALOHA_PROFILE, 2, 0]);
    u.keygen(&mut m);
    let (status, mut ct) = u.encrypt5(&mut m, &pt);
    assert_eq!(status, 0);
    // A real numerical scale change: multiply the integer polynomial AND
    // scale by two. Merely relabeling the metadata would change the value.
    for (li, block) in ct.chunks_exact_mut(2048).enumerate() {
        let q = coefficient_recovery::Q[li % 2];
        for v in block.chunks_exact_mut(8) {
            let x = u64::from_le_bytes(v.try_into().unwrap());
            v.copy_from_slice(&((2 * x) % q).to_le_bytes());
        }
    }
    for invalid in [0, 41] {
        u.reject(&mut m, 6, &u.header(6, &[], invalid), &[]);
    }
    let mut single = v5::q0(&ct);
    let mut previous = Vec::new();
    for iteration in 0..2 {
        let (status, refreshed) = u.refresh5(&mut m, &single, 26);
        assert_eq!(status, 0);
        if iteration > 0 {
            assert_ne!(
                &refreshed[4096..],
                &previous[4096..],
                "refresh repeated uniform a"
            );
        }
        let (status, decoded) = u.decrypt5(&mut m, &v5::q0(&refreshed), 26);
        assert_eq!(status, 0);
        let max_error = decoded
            .chunks_exact(8)
            .zip(&values)
            .map(|(b, v)| (f64::from_le_bytes(b.try_into().unwrap()) - v).abs())
            .fold(0.0, f64::max);
        assert!(
            max_error < 0.001,
            "refresh scale/precision mismatch: {max_error}"
        );
        println!("refresh iteration={iteration} log_scale=26 max_error={max_error}");
        single = v5::q0(&refreshed);
        previous = refreshed;
    }
    // An out-of-range source residue fails the command; nothing is written.
    single[..8].copy_from_slice(&coefficient_recovery::Q[0].to_le_bytes());
    dram_write(&mut m, v5::DST, &[0xa5; v5::CT]);
    assert_eq!(u.refresh5(&mut m, &single, 26).0, v5::BAD_INPUT);
    assert!(dram_read(&mut m, v5::DST, v5::CT).iter().all(|&v| v == 0xa5));
    u.close(&mut m);
    // Refresh needs an explicit policy grant.
    let mut u = User::open(&mut m, [0x0e, 8, ALOHA_PROFILE, 2, 0]);
    u.keygen(&mut m);
    u.reject(&mut m, 6, &u.header(6, &[], 26), &[]);
    u.close(&mut m);
    assert!(m.runtime_stack_canary_used() < caliptra_common::memory_layout::STACK_SIZE as usize);
}
