// Licensed under the Apache-2.0 license
//! Protocol v5's kernels on the Aloha accelerator (`fhe-aloha`): the same
//! commands, blobs and checks as the software backend in session.rs, with the
//! engine's N and L_max from CAP. Aloha moves every buffer between DRAM and
//! the engine through the DMA, so data commands are pointer-only and VeeR
//! reads only blob headers and tags: the engine streams an ENCRYPT body from
//! src + 20 through AES-GCM (the header is the extra data, the tag decides
//! INPUT_COMMIT) and seals a DECRYPT body at dst + 20. Ciphertexts and keys
//! carry LE u64 residues; the resident key never leaves the engine.
use super::profile::session_key;
use super::{
    blob_iv, result_header, Request, BLOB_HEADER, HEADER_WORDS, INVALID, READ_FAILED, WRITE_FAILED,
};
use crate::fhe_aloha::{self, Done};
use crate::Drivers;
use caliptra_drivers::{CaliptraError, CaliptraResult};
use zerocopy::IntoBytes;

/// Reads `words` from DRAM at `src` through the session transport.
fn read(d: &mut Drivers, src: u64, words: &mut [u32]) -> CaliptraResult<()> {
    let s = &mut d.fhe_session;
    s.transport
        .with_fifo(&mut d.dma, |t| t.read(src, words))
        .map_err(|_| READ_FAILED)
}
fn write(d: &mut Drivers, dst: u64, words: &[u32]) -> CaliptraResult<()> {
    let s = &mut d.fhe_session;
    s.transport
        .with_fifo(&mut d.dma, |t| t.write(dst, words))
        .map_err(|_| WRITE_FAILED)
}
/// On an error, the engine's KEY_VALID decides whether the session is still keyed.
fn synced<T>(d: &mut Drivers, result: CaliptraResult<T>) -> CaliptraResult<T> {
    result.inspect_err(|_| d.fhe_session.keyed = fhe_aloha::key_valid())
}
/// The geometry the boot flow validated against this image's CROM table
/// (`execute` refuses every command without it).
fn engine(d: &Drivers) -> CaliptraResult<fhe_aloha::Geometry> {
    d.fhe_session
        .engine
        .ok_or(CaliptraError::RUNTIME_FHE_ABSENT)
}
/// Records whether the key survived; an engine failure fails the command.
/// A tag mismatch aborts ENCRYPT at COMMIT_WAIT (cause 11) and a timeout
/// aborts with ZEROIZE: both drop the resident key, so the session needs a
/// new KEYGEN.
fn finish(d: &mut Drivers, done: CaliptraResult<Done>) -> CaliptraResult<Done> {
    let done = synced(d, done)?;
    d.fhe_session.keyed = done.key_valid;
    match done.cause {
        0 => Ok(done),
        11 => Err(INVALID),
        _ => Err(CaliptraError::RUNTIME_FHE_DECRYPT_FAILED),
    }
}

pub(super) fn keygen(d: &mut Drivers) -> CaliptraResult<()> {
    // After DisableAttestation the RT CDI is a public constant, so a seed
    // derived from it would depend only on the visible nonce.
    if d.persistent_data.get().attestation_disabled.get() {
        return Err(CaliptraError::RUNTIME_FHE_ATTESTATION_DISABLED);
    }
    let g = engine(d)?;
    let rt_cdi = Drivers::get_key_id_rt_cdi(d)?;
    let result = fhe_aloha::keygen(g, &mut d.hmac, &mut d.trng, &mut d.key_vault, rt_cdi);
    synced(d, result)?;
    d.fhe_session.keyed = true;
    Ok(())
}

/// ENCRYPT: the user blob at src (header, N/2 complex slots, tag) into a
/// ciphertext at `level` limbs at dst.
pub(super) fn ingress(d: &mut Drivers, r: &Request) -> CaliptraResult<()> {
    let g = engine(d)?;
    let body = g.message_bytes();
    let mut header = [0u32; HEADER_WORDS];
    let mut tag = [0u32; 4];
    read(d, r.src, &mut header)?;
    read(d, r.src + (BLOB_HEADER + body) as u64, &mut tag)?;
    let iv = blob_iv(&header, d.fhe_session.id, 2, body)?;
    let done = fhe_aloha::encrypt(
        g,
        &mut d.aes,
        &mut d.trng,
        session_key(false),
        &iv,
        header.as_bytes(),
        &tag.as_bytes().try_into().unwrap(),
        r.log_delta(),
        r.level() as u32,
        r.src + BLOB_HEADER as u64,
        r.dst,
    );
    finish(d, done).map(|_| ())
}

/// DECRYPT: the limb-0 ciphertext at src into a result blob at dst.
pub(super) fn egress(d: &mut Drivers, r: &Request) -> CaliptraResult<()> {
    let g = engine(d)?;
    let body = g.message_bytes();
    let s = &mut d.fhe_session;
    let (header, iv) = result_header(s.id, &mut s.counter, 3, body)?;
    let done = fhe_aloha::decrypt(
        g,
        &mut d.aes,
        &mut d.trng,
        session_key(true),
        &iv,
        header.as_bytes(),
        r.log_delta(),
        r.src,
        r.dst + BLOB_HEADER as u64,
    );
    let done = finish(d, done)?;
    // Header and tag frame the body only once the engine sealed it.
    let tag: [u32; 4] = zerocopy::transmute!(done.tag);
    write(d, r.dst, &header)?;
    write(d, r.dst + (BLOB_HEADER + body) as u64, &tag)
}

/// REFRESH: limb 0 at src re-encrypted inside the engine to `level` limbs.
pub(super) fn refresh(d: &mut Drivers, r: &Request) -> CaliptraResult<()> {
    let g = engine(d)?;
    let done = fhe_aloha::refresh(g, r.level() as u32, r.src, r.dst);
    finish(d, done).map(|_| ())
}

/// Galois (arg = g) or relinearization (arg = 0) key, one EVKGEN per row.
pub(super) fn key(d: &mut Drivers, r: &Request) -> CaliptraResult<()> {
    let g = engine(d)?;
    let done = fhe_aloha::eval_key(g, r.arg, r.dst);
    finish(d, done).map(|_| ())
}
