// Licensed under the Apache-2.0 license
//! Actual runtime-command negative/lifetime coverage. The separate Python host
//! demo verifies the DICE chain and trusted measurement. This command harness
//! deliberately reuses a fixed client private key/nonce to test device freshness.
use super::*;

fn python(script: &str, args: &[String]) -> Vec<u8> {
    run_python(
        std::process::Command::new("python3")
            .arg("-c")
            .arg(script)
            .args(args),
    )
}
/// Public key (x||y) of the fixed client scalar 1: the P-384 base point G.
const CLIENT_PUBLIC: &str = "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f";
fn opening(policy: [u32; 5]) -> Vec<u8> {
    [
        words(&[0, 4]),
        words(&policy),
        vec![0x36; 32],
        unhex(CLIENT_PUBLIC),
    ]
    .concat()
}
fn open(m: &mut DefaultHwModel, policy: [u32; 5]) -> User {
    let request = opening(policy);
    let response = send(m, CommandId::FHE_SESSION_OPEN, &request, &[]);
    assert_eq!(response.len(), 268);
    let keys = python(
        r#"
import sys, hashlib, hmac, struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
request, response = map(bytes.fromhex, sys.argv[1:])
digest = hashlib.sha384(b'Caliptra FHE ECDH v4' + request[4:] + response[8:156]).digest()
peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), b'\x04' + response[12:108])
z = ec.derive_private_key(1, ec.SECP384R1()).exchange(ec.ECDH(), peer)
def k(label):
    return hmac.new(z, b'\0\0\0\1' + label + b'\0' + digest + struct.pack('>I',256), hashlib.sha384).digest()[:32]
rx, tx = k(b'FHE-v4-request'), k(b'FHE-v4-response')
AESGCM(tx).decrypt(struct.pack('<IQ',1,0),response[252:],digest)
print((rx+tx).hex())
"#,
        &[hex(&request), hex(&response)],
    );
    assert_eq!(m.key_vault_usage(13), 0);
    assert_eq!(m.key_vault_usage(14), 0);
    assert_eq!(m.key_vault_usage(15), 1 << 5);
    assert_eq!(m.key_vault_usage(16), 1 << 5);
    User {
        version: 4,
        open_request: request,
        id: word(&response, 2),
        seq: 1,
        policy,
        rx: keys[..32].to_vec(),
        tx: keys[32..].to_vec(),
    }
}
fn erased(m: &mut DefaultHwModel) {
    for slot in 13..=16 {
        assert_eq!(m.key_vault_usage(slot), 0, "slot {slot} retained");
    }
}
fn reject_open(m: &mut DefaultHwModel, request: &[u8]) {
    let id = CommandId::FHE_SESSION_OPEN.into();
    assert!(m.mailbox_execute(id, &wire(id, request, &[])).is_err());
}

#[test]
fn ecdh_control_lifetime_and_freshness() {
    let mut m = boot(&firmware::APP_FHE_ECDH_ML_CLEAR);
    m.paint_runtime_stack_canary();
    let policy = [0x1e, 2, 0, 2, 0];
    let mut u = open(&mut m, policy);
    reject_open(&mut m, &u.open_request); // pending/live cannot be replaced
    let (h, ct) = u.packet(4, &[0; 196], false);
    u.reject(&mut m, 4, &h, &ct); // no clear reference before keygen confirmation
    u.seq += 1; // authenticated failure consumes sequence and one egress
    let (h, ct) = u.packet(1, &[], false);
    let mut bad = h.clone();
    bad[72] ^= 1;
    u.reject(&mut m, 1, &bad, &ct);
    u.call(&mut m, 1, &[], false);
    u.reject(&mut m, 1, &h, &ct); // replay
    u.call(&mut m, 4, &[0; 196], false);
    let (h, ct) = u.packet(4, &[0; 196], false);
    u.reject(&mut m, 4, &h, &ct); // quota
    u.seq += 1;
    let old_close = u.packet(5, &[], false);
    u.call(&mut m, 5, &[], false);
    erased(&mut m);
    let mut v = open(&mut m, policy);
    assert_eq!(u.open_request, v.open_request); // device, not caller, supplies freshness
    assert_ne!(u.rx, v.rx);
    assert_ne!(u.tx, v.tx);
    v.reject(&mut m, 5, &old_close.0, &old_close.1);
    let seq = v.seq;
    v.seq = u32::MAX;
    let (h, ct) = v.packet(5, &[], false);
    v.reject(&mut m, 5, &h, &ct);
    v.seq = seq;
    v.call(&mut m, 5, &[], false);
    erased(&mut m);
    println!("ECDH stack extent {}", m.runtime_stack_canary_used());
    assert!(m.runtime_stack_canary_used() < caliptra_common::memory_layout::STACK_SIZE as usize);
    // Fresh cold boot repeats session ID 1, but not communication keys. An old
    // keygen with matching ID/seq/policy still must fail authentication.
    let mut m = boot(&firmware::APP_FHE_ECDH_ML_CLEAR);
    let mut fresh = open(&mut m, policy);
    assert_eq!(u.id, fresh.id);
    assert_ne!(u.rx, fresh.rx);
    u.seq = 1;
    let (h, ct) = u.packet(1, &[], false);
    fresh.reject(&mut m, 1, &h, &ct);
    fresh.call(&mut m, 1, &[], false);
    fresh.call(&mut m, 5, &[], false);
    erased(&mut m);
}

#[test]
fn ecdh_bad_points_and_policy() {
    let mut m = boot(&firmware::APP_FHE_ECDH_ML_CLEAR);
    let original = opening([0x1e, 4, 0, 2, 0]);
    for offset in [4, 8, 16, 20, 24] {
        let mut bad = original.clone();
        bad[offset] ^= 0x80;
        reject_open(&mut m, &bad);
        erased(&mut m);
    }
    for point in [vec![0; 96], vec![0xff; 96]] {
        let mut bad = original.clone();
        bad[60..].copy_from_slice(&point);
        reject_open(&mut m, &bad);
        erased(&mut m);
        assert_eq!(m.soc_ifc().cptra_fw_error_fatal().read(), 0);
    }
    let mut u = open(&mut m, [0x1e, 4, 0, 2, 0]);
    u.call(&mut m, 1, &[], false);
    let pt = include_bytes!("../../fhe-core/tests/vectors/ps/pt.bin");
    let (h, ct) = u.packet(2, pt, false);
    for offset in [
        12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 87,
    ] {
        let mut bad = h.clone();
        bad[offset] ^= 1;
        u.reject(&mut m, 2, &bad, &ct);
    }
    let mut bad = ct.clone();
    bad[3] ^= 1;
    u.reject(&mut m, 2, &h, &bad);
    assert!(m
        .mailbox_sram_snapshot(128, 16384 - 128)
        .iter()
        .all(|&v| v == 0));
    u.call(&mut m, 2, pt, false);
    u.call(&mut m, 5, &[], false);
    erased(&mut m);
}

#[test]
fn ecdh_dma_failure_poison_and_cleanup() {
    let mut m = boot(&firmware::APP_FHE_ECDH_ML_CLEAR);
    let mut u = open(&mut m, [0x1e, 4, 0, 2, 0]);
    dma_poison(&mut m, &mut u, erased);
}

#[test]
fn ecdh_snapshot_and_cleanup() {
    snapshot_and_cleanup(&firmware::APP_FHE_ECDH_ML_CLEAR, open);
}
#[test]
fn ecdh_failed_egress_write() {
    failed_egress_write(&firmware::APP_FHE_ECDH_ML_CLEAR, open);
}
#[test]
fn ecdh_without_clear_reference() {
    let mut m = boot(&firmware::APP_FHE_ECDH);
    reject_open(&mut m, &opening([0x1e, 4, 0, 2, 0]));
    let mut u = open(&mut m, [0x0e, 4, 0, 2, 0]);
    let (h, ct) = u.packet(4, &[0; 196], false);
    u.reject(&mut m, 4, &h, &ct);
    u.call(&mut m, 1, &[], false);
    let pt = include_bytes!("../../fhe-core/tests/vectors/ps/pt.bin");
    let ct = u.call(&mut m, 2, pt, false);
    let dec = u.call(&mut m, 3, &ct, false);
    assert_ps_close(&dec, pt);
    u.call(&mut m, 5, &[], false);
    erased(&mut m);
}

#[test]
fn ecdh_warm_reset_erases_slots() {
    let mut m = boot(&firmware::APP_FHE_ECDH_ML_CLEAR);
    let mut old = open(&mut m, [0x1e, 4, 0, 2, 0]);
    old.call(&mut m, 1, &[], false);
    m.warm_reset_flow().unwrap();
    wait_runtime_ready(&mut m);
    erased(&mut m);
    let mut fresh = open(&mut m, old.policy);
    assert_eq!(old.id, fresh.id);
    assert_ne!(old.rx, fresh.rx);
    old.seq = 1;
    let (h, ct) = old.packet(1, &[], false);
    fresh.reject(&mut m, 1, &h, &ct);
    fresh.call(&mut m, 1, &[], false);
    fresh.call(&mut m, 5, &[], false);
    erased(&mut m);
}

const ROTATE_KEY: u32 = 0x46485254;
const RELIN_KEY: u32 = 0x4648524c;
fn eval_request(u: &User, op: u32, descriptor: u32, dst: u64) -> Vec<u8> {
    let mut h = words(&[0, 4, op, u.id, u.seq]);
    h.extend(words(&u.policy));
    h.extend(words(&[
        1,
        0,
        0,
        dst as u32,
        (dst >> 32) as u32,
        0,
        4096,
        descriptor,
    ]));
    let tag = crypto("encrypt", &u.rx, &[], &h[4..], &words(&[0, u.seq, 0]));
    h.extend(tag);
    h
}
fn reject_eval(m: &mut DefaultHwModel, id: u32, h: &[u8]) {
    assert!(m.mailbox_execute(id, &wire(id, h, &[])).is_err());
}

#[test]
fn evaluation_key_security_and_dma() {
    let mut m = boot(&firmware::APP_FHE_EVAL_KEYS);
    let mut u = open(&mut m, [0xce, 2, 0, 2, 0]);
    // Authenticated generation before keygen is rejected, and counts the attempt.
    reject_eval(&mut m, ROTATE_KEY, &eval_request(&u, 6, 5 << 8, 0x80010000));
    u.seq += 1;
    u.call(&mut m, 1, &[], false);
    let request = eval_request(&u, 6, 5 << 8, 0x80010000);
    let mut bad = request.clone();
    bad[72] ^= 1;
    reject_eval(&mut m, ROTATE_KEY, &bad);
    for offset in [8usize, 20, 52, 68] {
        // operation, policy, address, descriptor
        let mut bad = request.clone();
        bad[offset] ^= 1;
        reject_eval(&mut m, ROTATE_KEY, &bad);
    }
    for dst in [u64::MAX - 3, 0x1_8000_0000 - 4, 0x1_0000_8001_0000] {
        reject_eval(&mut m, ROTATE_KEY, &eval_request(&u, 6, 5 << 8, dst));
    }
    for descriptor in [16, 2 << 8, 512 << 8] {
        reject_eval(
            &mut m,
            ROTATE_KEY,
            &eval_request(&u, 6, descriptor, 0x80010000),
        );
    }
    m.limit_direct_mailbox_access(Some(128));
    let response = send(&mut m, ROTATE_KEY.into(), &request, &[]);
    m.limit_direct_mailbox_access(None);
    assert_eq!(response.len(), 100);
    let mut wrapped = m.soc_dram_mut().unwrap()[0x10000..0x11000].to_vec();
    wrapped.extend_from_slice(&response[84..100]);
    assert_eq!(
        crypto(
            "decrypt",
            &u.tx,
            &wrapped,
            &response[8..84],
            &words(&[1, u.seq, 0])
        )
        .len(),
        4096
    );
    u.seq += 1;
    reject_eval(&mut m, ROTATE_KEY, &request); // replay
    let h = eval_request(&u, 7, 0, 0x80010000);
    reject_eval(&mut m, RELIN_KEY, &h); // quota: pre-keygen attempt + successful row
    u.seq += 1;
    u.call(&mut m, 5, &[], false);
    erased(&mut m);
    let mut v = open(&mut m, [0x0e, 8, 0, 2, 0]);
    v.call(&mut m, 1, &[], false);
    reject_eval(&mut m, RELIN_KEY, &eval_request(&v, 7, 0, 0x80010000)); // policy
    v.seq += 1;
    v.call(&mut m, 5, &[], false);
    let mut v = open(&mut m, [0xce, 8, 0, 2, 0]);
    v.call(&mut m, 1, &[], false);
    let end = m.soc_dram_mut().unwrap().len();
    let h = eval_request(&v, 7, 0, 0x80000000 + end as u64 - 4);
    reject_eval(&mut m, RELIN_KEY, &h); // partial DMA write must poison permanently
    erased(&mut m);
    reject_open(&mut m, &v.open_request);
    reject_eval(&mut m, RELIN_KEY, &h);
}

#[test]
fn evaluation_keys_are_gated() {
    let mut m = boot(&firmware::APP_FHE_ECDH);
    reject_open(&mut m, &opening([0xce, 8, 0, 2, 0]));
    let mut u = open(&mut m, [0x0e, 8, 0, 2, 0]);
    u.call(&mut m, 1, &[], false);
    reject_eval(&mut m, RELIN_KEY, &eval_request(&u, 7, 0, 0x80010000));
    u.call(&mut m, 5, &[], false);
}
