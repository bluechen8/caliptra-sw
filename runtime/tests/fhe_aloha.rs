// Licensed under the Apache-2.0 license
//! Aloha PSK test protocol v3 (session_aloha.rs). Requires the hw-model
//! `fhe-aloha` feature; protocol v5 tests are in fhe_protected.rs/fhe_ecdh.rs.
use super::*;

const PSK: &str = "a7b1c3d5e7f9012436485a6c7e90a2b4c6d8eaf10315274961738597a9bbcddf";
/// Authenticated parameter-set ID of the Aloha N=256 profile.
const ALOHA_PROFILE: u32 = 0xa108;
struct User {
    version: u32,
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
        let psk = unhex(PSK);
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
        let psk = unhex(PSK);
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
            version: 3,
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
        let mut h = words(&[0, self.version, op, self.id, self.seq]);
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
        reject(m, IDS[(op - 1) as usize], h, body);
    }
}

/// Requires a local-stream N=256 RTL RPC executable and initialized table cwd.
#[test]
#[ignore = "requires FHE_ALOHA_RTL and FHE_ALOHA_RTL_CWD"]
fn protected_aloha_host_demo() {
    run_host_demo(&firmware::APP_FHE_ALOHA, "aloha_demo.py", true);
}

/// Bad authentication leaves external output untouched and consumes no sequence;
/// authenticated non-canonical ciphertext is rejected.
#[test]
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
