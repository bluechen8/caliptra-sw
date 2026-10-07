// Licensed under the Apache-2.0 license
//! Protocol v5 with the attested ECDH open, and evaluation-key rows. The
//! Python host demo verifies the DICE chain and trusted measurement. This
//! harness deliberately reuses a fixed client private key/nonce to test device
//! freshness.
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
fn opening() -> Vec<u8> {
    [words(&[0, 5]), vec![0x36; 32], unhex(CLIENT_PUBLIC)].concat()
}
fn open(m: &mut DefaultHwModel) -> Client {
    let request = opening();
    let response = send(m, CommandId::FHE_SESSION_OPEN, &request, &[]);
    assert_eq!(response.len(), 268);
    let keys = python(
        r#"
import sys, hashlib, hmac, struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
request, response = map(bytes.fromhex, sys.argv[1:])
digest = hashlib.sha384(b'Caliptra FHE ECDH v5' + request[4:] + response[8:156]).digest()
peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), b'\x04' + response[12:108])
z = ec.derive_private_key(1, ec.SECP384R1()).exchange(ec.ECDH(), peer)
def k(label):
    return hmac.new(z, b'\0\0\0\1' + label + b'\0' + digest + struct.pack('>I',256), hashlib.sha384).digest()[:32]
rx, tx = k(b'FHE-v5-request'), k(b'FHE-v5-response')
AESGCM(tx).decrypt(struct.pack('<IQ',1,0),response[252:],digest)
print((rx+tx).hex())
"#,
        &[hex(&request), hex(&response)],
    );
    assert_eq!(m.key_vault_usage(13), 0);
    assert_eq!(m.key_vault_usage(14), 0);
    assert_eq!(m.key_vault_usage(15), 1 << 5);
    assert_eq!(m.key_vault_usage(16), 1 << 5);
    Client::new(
        request,
        word(&response, 2),
        keys[..32].to_vec(),
        keys[32..].to_vec(),
    )
}
fn erased(m: &mut DefaultHwModel) {
    for slot in 13..=16 {
        assert_eq!(m.key_vault_usage(slot), 0, "slot {slot} retained");
    }
}

#[test]
fn ecdh_flow_and_lifecycle() {
    flow_and_lifecycle(&firmware::APP_FHE_ECDH_ML_CLEAR, open);
}
#[test]
fn ecdh_validation() {
    validation(&firmware::APP_FHE_ECDH_ML_CLEAR, open);
}
#[test]
fn ecdh_failed_write_and_poison() {
    failed_write_and_poison(&firmware::APP_FHE_ECDH_ML_CLEAR, open);
}
#[test]
fn ecdh_read_poison() {
    read_poison(&firmware::APP_FHE_ECDH_ML_CLEAR, open);
}
#[test]
fn ecdh_snapshot_and_cleanup() {
    snapshot_and_cleanup(&firmware::APP_FHE_ECDH_ML_CLEAR, open);
}

/// The device, not the caller, supplies freshness; close and resets erase
/// every key slot, and old blobs never authenticate in a new session.
#[test]
fn ecdh_freshness_and_key_erasure() {
    let mut m = boot(&firmware::APP_FHE_ECDH_ML_CLEAR);
    let mut u = open(&mut m);
    u.call(&mut m, 1, &[], false);
    let old = u.seal(2, PT);
    u.call(&mut m, 5, &[], false);
    erased(&mut m);
    let mut v = open(&mut m);
    assert_eq!(u.open_request, v.open_request);
    assert_ne!(u.rx, v.rx);
    assert_ne!(u.tx, v.tx);
    v.call(&mut m, 1, &[], false);
    let mut forged = old.clone();
    forged[4..8].copy_from_slice(&v.id.to_le_bytes()); // current ID, old keys
    v.reject(&mut m, 2, &command(v.id, 2, false, 0), &forged);
    v.call(&mut m, 5, &[], false);
    erased(&mut m);
    // Warm reset erases a live session; the same request then yields new keys.
    let mut w = open(&mut m);
    w.call(&mut m, 1, &[], false);
    m.warm_reset_flow().unwrap();
    wait_runtime_ready(&mut m);
    erased(&mut m);
    let fresh = open(&mut m);
    assert_ne!(w.rx, fresh.rx);
    // A cold boot repeats session ID 1, but not communication keys.
    let mut m = boot(&firmware::APP_FHE_ECDH_ML_CLEAR);
    let mut cold = open(&mut m);
    assert_eq!(cold.id, u.id);
    assert_ne!(cold.rx, u.rx);
    cold.call(&mut m, 1, &[], false);
    cold.reject(&mut m, 2, &command(cold.id, 2, false, 0), &old);
    cold.call(&mut m, 5, &[], false);
    erased(&mut m);
}

#[test]
fn ecdh_bad_open() {
    let mut m = boot(&firmware::APP_FHE_ECDH_ML_CLEAR);
    let original = opening();
    let mut bad = original.clone();
    bad[4] ^= 0x80; // version
    reject_open(&mut m, &bad);
    reject_open(&mut m, &original[..original.len() - 4]);
    for point in [vec![0; 96], vec![0xff; 96]] {
        let mut bad = original.clone();
        bad[40..].copy_from_slice(&point);
        reject_open(&mut m, &bad);
        erased(&mut m);
        assert_eq!(m.soc_ifc().cptra_fw_error_fatal().read(), 0);
    }
    let mut u = open(&mut m);
    u.call(&mut m, 1, &[], false);
    u.call(&mut m, 5, &[], false);
    erased(&mut m);
}

/// The ordinary protected build neither exposes MLIC nor includes its model.
#[test]
fn ecdh_without_clear_reference() {
    let mut m = boot(&firmware::APP_FHE_ECDH);
    let mut u = open(&mut m);
    u.call(&mut m, 1, &[], false);
    let pixels = u.seal(4, &[0; 196]);
    u.reject(&mut m, 4, &command(u.id, 4, false, 0), &pixels);
    let ct = u.call(&mut m, 2, PT, false);
    assert!(ps_close(&u.call(&mut m, 3, &ct, false), PT));
    u.call(&mut m, 5, &[], false);
    erased(&mut m);
}

/// Row commands are pointer-only plain commands; rows are public, fresh per
/// request, fully reduced, and never staged in mailbox SRAM.
#[test]
fn evaluation_key_rows() {
    let mut m = boot(&firmware::APP_FHE_EVAL_KEYS);
    let mut u = open(&mut m);
    let row = |id, op, arg| command(id, op, true, arg);
    u.reject(&mut m, 6, &row(u.id, 6, 5 << 8), &[]); // before keygen
    u.call(&mut m, 1, &[], false);
    // Galois element must be odd, non-identity, < 512; row < 16; op 7 needs g = 0.
    for (op, arg) in [
        (6, 16),
        (6, 0),
        (6, 1 << 8),
        (6, 2 << 8),
        (6, 512 << 8),
        (7, 5 << 8),
        (7, 16),
    ] {
        u.reject(&mut m, op, &row(u.id, op, arg), &[]);
    }
    u.reject(&mut m, 6, &command(u.id, 6, false, 5 << 8), &[]); // mailbox mode
    for dst in [0x7fff_f000u64, 0x1_8000_0000 - 4, 0x1_0000_8001_0000] {
        let mut h = row(u.id, 6, 5 << 8);
        h[28..36].copy_from_slice(&dst.to_le_bytes());
        u.reject(&mut m, 6, &h, &[]);
    }
    let mut rows = Vec::new();
    for _ in 0..2 {
        m.limit_direct_mailbox_access(Some(48));
        let response = send(&mut m, CommandId::from(IDS[5]), &row(u.id, 6, 5 << 8), &[]);
        m.limit_direct_mailbox_access(None);
        assert_eq!(response.len(), 16);
        rows.push(m.soc_dram_mut().unwrap()[0x10000..0x11000].to_vec());
    }
    assert_ne!(rows[0], rows[1], "rows must use fresh randomness");
    for (i, q) in [PS_Q, PS_Q].concat().into_iter().enumerate() {
        assert!(
            (0..256).all(|j| word(&rows[0], i * 256 + j) < q),
            "unreduced residue"
        );
    }
    m.limit_direct_mailbox_access(Some(48));
    send(&mut m, CommandId::from(IDS[6]), &row(u.id, 7, 15), &[]);
    m.limit_direct_mailbox_access(None);
    // A partial DMA write poisons transport: only close runs afterwards.
    let end = m.soc_dram_mut().unwrap().len() as u64;
    let mut h = row(u.id, 7, 0);
    h[28..36].copy_from_slice(&(0x8000_0000 + end - 4).to_le_bytes());
    u.reject(&mut m, 7, &h, &[]);
    u.reject(&mut m, 7, &row(u.id, 7, 0), &[]);
    u.call(&mut m, 5, &[], false);
    erased(&mut m);
    reject_open(&mut m, &u.open_request);
}

#[test]
fn evaluation_keys_are_gated() {
    let mut m = boot(&firmware::APP_FHE_ECDH);
    let mut u = open(&mut m);
    u.call(&mut m, 1, &[], false);
    u.reject(&mut m, 7, &command(u.id, 7, true, 0), &[]);
    u.call(&mut m, 5, &[], false);
}
