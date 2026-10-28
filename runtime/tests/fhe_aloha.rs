// Licensed under the Apache-2.0 license
//! Protocol v5 on the Aloha accelerator (`fhe-aloha`): the same commands,
//! blobs, client and host demos as the software backend, against the Aloha
//! RTL over the emulator's RTL link. Run with FHE_ALOHA_RTL and
//! FHE_ALOHA_RTL_CWD from `run_fhe_top_dma_tb.sh` (BUILD_ONLY=1) and FHE_CROM
//! from `gen_aloha_tables.py` for the same N and L_max; the geometry below is
//! read from that table, as the firmware checks it against CAP.
use super::*;

/// Aloha's prime catalog (caliptra-rtl src/fhe/aloha/vendor/Scripts/fhe_profiles.py);
/// a build installs the first L_max, and keys use the top one as P.
const PRIMES: [u64; 8] = [
    0x3ffff7000001,
    0x7fffff000001,
    0xffffd8000001,
    0x1fffffb000001,
    0x3ffffe4000001,
    0x7fffff9000001,
    0xffffff3000001,
    0x1ffffff6000001,
];
use caliptra_api::error::CaliptraError;

/// The engine's wire sizes, from the FHE_CROM manifest (log2 N, L_max).
/// The host tools know A-S (N = 256, L_max 3) and A-LR (N = 1024, L_max 8);
/// other builds run the command tests only.
pub(super) fn aloha_wire() -> Wire {
    use std::io::Read;
    let mut manifest = [0u8; 16];
    std::fs::File::open(std::env::var("FHE_CROM").expect("FHE_CROM"))
        .and_then(|mut f| f.read_exact(&mut manifest))
        .unwrap();
    let (n, l_max) = (1usize << manifest[6], manifest[7] as usize);
    // With L_max >= 2 the engine serves evaluation keys, and the top prime is
    // their P: ciphertexts use the L_max - 1 primes below it.
    let level = if l_max >= 2 { l_max - 1 } else { 1 };
    let name = match (n, l_max) {
        (256, 3) => "aps",
        (1024, 8) => "alr",
        (256, 8) => "alrs",
        _ => "aloha",
    };
    Wire {
        name,
        n,
        limb: 8 * n,
        level,
        key: if l_max >= 2 {
            level * 2 * (level + 1) * 8 * n
        } else {
            0
        },
        aloha: true,
    }
}
fn client(m: &mut DefaultHwModel) -> Client {
    let mut c = Client::test_key(m);
    c.wire = aloha_wire();
    c
}
/// Largest slot error of a DECRYPT result against `z`, divided by `scale`.
fn slot_error(dec: &[u8], z: &[(f64, f64)], scale: f64) -> f64 {
    let f = |k: usize| f64::from_le_bytes(dec[8 * k..8 * k + 8].try_into().unwrap()) / scale;
    assert_eq!(dec.len(), 16 * z.len());
    z.iter()
        .enumerate()
        .map(|(j, &(r, i))| (f(2 * j) - r).abs().max((f(2 * j + 1) - i).abs()))
        .fold(0.0, f64::max)
}
/// Every residue of a component-major ciphertext or key row set is below its
/// prime: `limbs` limbs per component, limb i over PRIMES[i].
fn reduced(data: &[u8], limb: usize, limbs: usize) -> bool {
    data.chunks_exact(limb).enumerate().all(|(i, l)| {
        let q = PRIMES[i % limbs];
        l.chunks_exact(8)
            .all(|b| u64::from_le_bytes(b.try_into().unwrap()) < q)
    })
}
/// Run `op` in pointer mode with `arg` as given; dst is pre-filled with 0xa5.
fn run(m: &mut DefaultHwModel, c: &Client, op: u32, arg: u32, input: &[u8]) -> Vec<u8> {
    let (_, out) = lengths_for(c.wire, op, (arg >> 8) as usize);
    dram_put(m, 0, input);
    dram_put(m, OUT, &vec![0xa5; out]);
    let id = IDS[(op - 1) as usize];
    let r = send(
        m,
        CommandId::from(id),
        &command_for(c.wire, c.id, op, true, arg),
        &[],
    );
    assert_eq!(r.len(), 16);
    dram_get(m, OUT, out)
}
fn refuse(m: &mut DefaultHwModel, c: &Client, op: u32, h: &[u8], input: &[u8]) {
    dram_put(m, 0, input);
    c.reject(m, op, h, &[]);
}
fn encrypt(m: &mut DefaultHwModel, c: &mut Client, body: &[u8], arg: u32) -> Vec<u8> {
    let blob = c.seal(2, body);
    run(m, c, 2, arg, &blob)
}
fn decrypt(m: &mut DefaultHwModel, c: &mut Client, ct: &[u8], log_delta: u32) -> Vec<u8> {
    let blob = run(m, c, 3, log_delta, &limb0(c.wire, ct));
    c.open_result(3, &blob)
}
/// ENCRYPT at level 1 and DECRYPT: the slots come back.
fn roundtrip(m: &mut DefaultHwModel, c: &mut Client, z: &[(f64, f64)]) {
    let ct = encrypt(m, c, &slot_bytes(z), 1 << 8 | LOG);
    let e = slot_error(&decrypt(m, c, &ct, LOG), z, 1.0);
    assert!(e < 1e-3, "slot error {e}");
}
fn error_code(m: &mut DefaultHwModel, id: u32, h: &[u8]) -> u32 {
    match m.mailbox_execute(id, &wire(id, h, &[])) {
        Err(caliptra_hw_model::ModelError::MailboxCmdFailed(code)) => code,
        other => panic!("expected a mailbox error, got {other:?}"),
    }
}
const LOG: u32 = 25;

/// KEYGEN, ENCRYPT, DECRYPT and REFRESH at every ciphertext level, DECRYPT
/// at scale 0 (Δ·z), fresh randomness, and the refusals: a second KEYGEN,
/// level 0 and the level above the largest (P's limb when the engine serves
/// keys), a wrong output length, mailbox payloads, and data after CLOSE.
#[test]
#[ignore = "requires FHE_ALOHA_RTL, FHE_ALOHA_RTL_CWD and FHE_CROM"]
fn aloha_flow() {
    let mut m = boot(&firmware::APP_FHE_ALOHA);
    let mut c = client(&mut m);
    let w = c.wire;
    let z = slots_for(w);
    let body = slot_bytes(&z);
    c.exec(&mut m, 1, &[], false);
    c.reject(&mut m, 1, &command_for(w, c.id, 1, false, 0), &[]);
    for level in 1..=w.level {
        let arg = (level as u32) << 8 | LOG;
        let ct = encrypt(&mut m, &mut c, &body, arg);
        assert_eq!(ct.len(), 2 * level * w.limb);
        assert!(
            reduced(&ct, w.limb, level),
            "level {level}: unreduced residue"
        );
        let e = slot_error(&decrypt(&mut m, &mut c, &ct, LOG), &z, 1.0);
        assert!(e < 1e-3, "level {level} ENCRYPT: slot error {e}");
        let fresh = run(&mut m, &c, 6, (level as u32) << 8, &limb0(w, &ct));
        assert_eq!(fresh.len(), 2 * level * w.limb);
        assert_ne!(fresh, ct);
        let e = slot_error(&decrypt(&mut m, &mut c, &fresh, LOG), &z, 1.0);
        assert!(e < 1e-3, "level {level} REFRESH: slot error {e}");
    }
    let ct = encrypt(&mut m, &mut c, &body, (w.level as u32) << 8 | LOG);
    assert_ne!(
        ct,
        encrypt(&mut m, &mut c, &body, (w.level as u32) << 8 | LOG)
    );
    let e = slot_error(&decrypt(&mut m, &mut c, &ct, 0), &z, (1u64 << LOG) as f64);
    assert!(e < 1e-3, "DECRYPT at scale 0: slot error {e}");
    // Level 0 and the one above the largest, a level-1 REFRESH with a level-2 output length,
    // and the data commands in mode 0.
    let blob = c.seal(2, &body);
    for level in [0, w.level as u32 + 1] {
        refuse(
            &mut m,
            &c,
            2,
            &command_for(w, c.id, 2, true, level << 8 | LOG),
            &blob,
        );
        refuse(
            &mut m,
            &c,
            6,
            &command_for(w, c.id, 6, true, level << 8),
            &limb0(w, &ct),
        );
    }
    let mut h = command_for(w, c.id, 6, true, 1 << 8);
    h[40..44].copy_from_slice(&(4 * w.limb as u32).to_le_bytes());
    refuse(&mut m, &c, 6, &h, &limb0(w, &ct));
    c.reject(
        &mut m,
        2,
        &command_for(w, c.id, 2, false, 1 << 8 | LOG),
        &blob,
    );
    c.reject(
        &mut m,
        3,
        &command_for(w, c.id, 3, false, LOG),
        &limb0(w, &ct),
    );
    c.reject(
        &mut m,
        6,
        &command_for(w, c.id, 6, false, 1 << 8),
        &limb0(w, &ct),
    );
    c.exec(&mut m, 5, &[], false);
    refuse(
        &mut m,
        &c,
        3,
        &command_for(w, c.id, 3, true, LOG),
        &limb0(w, &ct),
    );
}

/// The tag covers the body and the blob header (extra data): a changed body or
/// counter makes Aloha abort at COMMIT_WAIT, write nothing and drop the key,
/// so the session needs a new KEYGEN. A blob for another session is refused
/// before the engine runs and keeps the key.
#[test]
#[ignore = "requires FHE_ALOHA_RTL, FHE_ALOHA_RTL_CWD and FHE_CROM"]
fn aloha_bad_tag() {
    let mut m = boot(&firmware::APP_FHE_ALOHA);
    let mut c = client(&mut m);
    let w = c.wire;
    let z = slots_for(w);
    let body = slot_bytes(&z);
    let arg = 1 << 8 | LOG;
    c.exec(&mut m, 1, &[], false);
    let h = command_for(w, c.id, 2, true, arg);
    let other = c.seal_as(c.id + 1, 2, 9, &body);
    refuse(&mut m, &c, 2, &h, &other);
    c.reject(&mut m, 1, &command_for(w, c.id, 1, false, 0), &[]); // still keyed
    for tamper in [30usize, 12] {
        // A body byte, then the header's counter.
        let mut blob = c.seal(2, &body);
        blob[tamper] ^= 1;
        dram_put(&mut m, OUT, &vec![0xa5; 2 * w.limb]);
        refuse(&mut m, &c, 2, &h, &blob);
        assert!(dram_get(&mut m, OUT, 2 * w.limb).iter().all(|&v| v == 0xa5));
        c.exec(&mut m, 1, &[], false); // the abort dropped the key
    }
    roundtrip(&mut m, &mut c, &z);
}

/// Evaluation keys (ops 7 and 8, docs/fhe/21): L_max - 1 rows over L_max
/// limbs (the ciphertext primes and P), residues below their primes, three
/// distinct keys, the malformed requests refused, and the secret still usable
/// afterwards. Lattigo uses them in the host demos.
#[test]
#[ignore = "requires FHE_ALOHA_RTL, FHE_ALOHA_RTL_CWD and FHE_CROM with L_max >= 2"]
fn aloha_eval_keys() {
    let mut m = boot(&firmware::APP_FHE_ALOHA);
    let mut c = client(&mut m);
    let w = c.wire;
    assert!(w.key > 0, "evaluation keys need L_max >= 2");
    c.exec(&mut m, 1, &[], false);
    let mut keys = Vec::new();
    for (op, g) in [(8, 0), (7, 5), (7, 2 * w.n as u32 - 1)] {
        let key = run(&mut m, &c, op, g, &[]);
        assert_eq!(key.len(), w.key);
        assert!(
            reduced(&key, w.limb, w.level + 1),
            "op {op} g {g}: unreduced residue"
        );
        assert!(key
            .chunks_exact(w.limb)
            .all(|l| l.chunks_exact(8).any(|b| b != &l[..8])));
        keys.push(key);
    }
    assert!(keys[0] != keys[1] && keys[1] != keys[2]);
    for (op, g) in [(7, 0), (7, 4), (7, 1), (7, 2 * w.n as u32), (8, 5)] {
        refuse(&mut m, &c, op, &command_for(w, c.id, op, true, g), &[]);
    }
    let mut h = command_for(w, c.id, 8, true, 0);
    h[40..44].copy_from_slice(&(w.key as u32 - 16).to_le_bytes());
    refuse(&mut m, &c, 8, &h, &[]);
    let mut h = command_for(w, c.id, 8, true, 0);
    h[20..24].copy_from_slice(&(SRC as u32).to_le_bytes());
    refuse(&mut m, &c, 8, &h, &[]);
    let z = slots_for(w);
    roundtrip(&mut m, &mut c, &z);
}

/// After DisableAttestation the RT CDI is a public constant: KEYGEN is
/// refused, while a key generated before it stays usable.
#[test]
#[ignore = "requires FHE_ALOHA_RTL, FHE_ALOHA_RTL_CWD and FHE_CROM"]
fn aloha_keygen_after_disable_attestation() {
    let mut m = boot(&firmware::APP_FHE_ALOHA);
    let mut c = client(&mut m);
    let w = c.wire;
    c.exec(&mut m, 1, &[], false);
    let disable: u32 = CommandId::DISABLE_ATTESTATION.into();
    m.mailbox_execute(disable, &wire(disable, &[0; 4], &[]))
        .unwrap();
    let z = slots_for(w);
    roundtrip(&mut m, &mut c, &z);
    c.exec(&mut m, 5, &[], false);
    let c = client(&mut m);
    let keygen = command_for(w, c.id, 1, false, 0);
    assert_eq!(
        error_code(&mut m, IDS[0], &keygen),
        u32::from(CaliptraError::RUNTIME_FHE_ATTESTATION_DISABLED)
    );
}

/// An update reset restarts only VeeR, not the engine: the new runtime
/// zeroizes the engine and copies its CROM table again (docs/fhe/19). The old
/// session ends with the old runtime.
#[test]
#[ignore = "requires FHE_ALOHA_RTL, FHE_ALOHA_RTL_CWD and FHE_CROM"]
fn aloha_update_reset() {
    let mut m = boot(&firmware::APP_FHE_ALOHA);
    let mut c = client(&mut m);
    let w = c.wire;
    c.exec(&mut m, 1, &[], false);
    let mut opts = ImageOptions::default();
    opts.pqc_key_type = FwVerificationPqcKeyType::LMS;
    opts.vendor_config.pl0_pauser = Some(1);
    let image = caliptra_builder::build_and_sign_image(
        &firmware::FMC_WITH_UART_NO_MLDSA,
        &firmware::APP_FHE_ALOHA,
        opts,
    )
    .unwrap()
    .to_bytes()
    .unwrap();
    m.mailbox_execute(u32::from(CommandId::FIRMWARE_LOAD), &image)
        .unwrap();
    let z = slots_for(w);
    let blob = c.seal(2, &slot_bytes(&z));
    refuse(
        &mut m,
        &c,
        2,
        &command_for(w, c.id, 2, true, 1 << 8 | LOG),
        &blob,
    );
    let mut c = client(&mut m);
    c.exec(&mut m, 1, &[], false);
    roundtrip(&mut m, &mut c, &z);
}

/// A runtime built with a CROM table for another geometry boots, installs
/// nothing and refuses every FHE request, the open included.
#[test]
#[ignore = "requires FHE_ALOHA_RTL, FHE_ALOHA_RTL_CWD and FHE_CROM built for another N or L_max"]
fn aloha_wrong_table() {
    let mut m = boot(&firmware::APP_FHE_ALOHA);
    assert_eq!(
        error_code(&mut m, OPEN, &words(&[0, 5])),
        u32::from(CaliptraError::RUNTIME_FHE_ABSENT)
    );
}

/// The fhe-sw-client host demos, unchanged, through the same scheduler as the
/// Rocket relay (protected-demo.c): A-S (N = 256, L_max 3) for the
/// evaluation-key and packed-MNIST demos.
#[test]
#[ignore = "requires FHE_ALOHA_RTL, FHE_ALOHA_RTL_CWD and FHE_CROM for N = 256, L_max = 3"]
fn aloha_evalkey_host_demo() {
    run_host_demo(&firmware::APP_FHE_ALOHA, "evalkey_demo.py", false);
}
#[test]
#[ignore = "requires FHE_ALOHA_RTL, FHE_ALOHA_RTL_CWD and FHE_CROM for N = 256, L_max = 3"]
fn aloha_packed_host_demo() {
    run_host_demo(&firmware::APP_FHE_ALOHA, "packed_demo.py", false);
}
/// Encrypted logistic-regression training at A-LR (N = 1024, L_max 8), with a
/// REFRESH between steps; FHE_LR_STEPS sets the number of steps (default 4).
#[test]
#[ignore = "requires FHE_ALOHA_RTL, FHE_ALOHA_RTL_CWD and FHE_CROM for N = 1024, L_max = 8"]
fn aloha_lr_host_demo() {
    run_host_demo(&firmware::APP_FHE_ALOHA, "lr_demo.py", false);
}
