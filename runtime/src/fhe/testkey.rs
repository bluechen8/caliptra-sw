// Licensed under the Apache-2.0 license
//! Fixed public test keys (the `fhe-test-key` profile) for fast fake-ROM runs.
//! No security: open is refused unless debug-unlocked, where debug access
//! already exposes every secret.
use super::{put, Request, HEADER_LEN, INVALID};
use crate::Drivers;
use caliptra_drivers::{AesKey, CaliptraResult};

/// SHA-256 of "Caliptra FHE v5 TEST {request,response} key".
const KEYS: [[u8; 32]; 2] = [
    [
        0x82, 0x77, 0x32, 0x08, 0x4e, 0x2b, 0x46, 0xa5, 0xdf, 0x57, 0xe7, 0xef, 0x66, 0xd3, 0x0c,
        0x80, 0xb7, 0x17, 0xd8, 0xb8, 0x2f, 0x85, 0xac, 0x5e, 0x5f, 0x83, 0x37, 0x6e, 0x9e, 0x41,
        0x27, 0x39,
    ],
    [
        0x5d, 0xae, 0xca, 0x85, 0xb6, 0x53, 0xe1, 0xfc, 0xf0, 0x15, 0x0f, 0x0e, 0xa0, 0x3c, 0x07,
        0x1e, 0x1f, 0x08, 0x1e, 0x4c, 0x51, 0x26, 0x4c, 0xb0, 0x15, 0xa8, 0xe6, 0x2f, 0x8a, 0x55,
        0xea, 0x2c,
    ],
];

/// An inactive session is already erased, so open only allocates the next ID.
pub(super) fn open(
    d: &mut Drivers,
    _r: &Request,
    header: &mut [u8; HEADER_LEN],
) -> CaliptraResult<usize> {
    let s = &mut d.fhe_session;
    if s.active || s.transport.is_poisoned() || d.soc_ifc.debug_locked() {
        return Err(INVALID);
    }
    s.id = s.id.checked_add(1).ok_or(INVALID)?;
    s.active = true;
    put(header, 2, s.id);
    caliptra_drivers::cprintln!("FHE TEST KEY: NOT SECURE");
    Ok(12)
}

pub(super) fn session_key(response: bool) -> AesKey<'static> {
    AesKey::Array(&KEYS[response as usize])
}

/// Fixed keys live in rodata; there is nothing to erase.
pub(super) fn erase_keys(_d: &mut Drivers) -> CaliptraResult<()> {
    Ok(())
}
