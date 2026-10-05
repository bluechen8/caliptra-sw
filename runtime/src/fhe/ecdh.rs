// Licensed under the Apache-2.0 license
//! Device-only attested P-384 session establishment. No caller authorization.
use super::{nonce, policy_supported, put, Request, HEADER_LEN, INVALID};
use crate::Drivers;
use caliptra_drivers::sha2_512_384::Sha2DigestOpTrait;
use caliptra_drivers::{
    hmac_kdf, AesKey, Array4x12, CaliptraResult, Ecc384PubKey, HmacMode, KeyId, KeyReadArgs,
    KeyUsage, KeyVault, KeyWriteArgs,
};
use zeroize::Zeroizing;

// Runtime's common key allocation ends at slot 12. These slots belong solely
// to this feature; no user handle or mailbox command exposes them.
const PRIVATE: KeyId = KeyId::KeyId13;
const SHARED: KeyId = KeyId::KeyId14;
pub(super) const REQUEST_KEY: KeyId = KeyId::KeyId15;
pub(super) const RESPONSE_KEY: KeyId = KeyId::KeyId16;
const DOMAIN: &[u8] = b"Caliptra FHE ECDH v4";

#[inline(never)]
pub(super) fn erase_keys(kv: &mut KeyVault) -> CaliptraResult<()> {
    // Try every slot even when an earlier erase fails.
    let mut result = Ok(());
    for id in [PRIVATE, SHARED, REQUEST_KEY, RESPONSE_KEY] {
        if let Err(e) = kv.erase_key(id) {
            result = Err(e);
        }
    }
    result
}

pub(super) fn open(
    d: &mut Drivers,
    r: &Request,
    header: &mut [u8; HEADER_LEN],
) -> CaliptraResult<usize> {
    let s = &d.fhe_session;
    if s.active || s.crypto_failed || s.transport.is_poisoned() || !policy_supported(r) {
        return Err(INVALID);
    }
    let id = s.id.checked_add(1).ok_or(INVALID)?;
    super::erase(d)?;
    d.fhe_session.id = id;
    let result = establish(d, r, header, id);
    // The private scalar and shared secret are never needed after derivation.
    let private = d.key_vault.erase_key(PRIVATE);
    let shared = d.key_vault.erase_key(SHARED);
    if result.is_err() || private.is_err() || shared.is_err() {
        // ECC/HMAC driver error exits may precede their normal register wipe.
        unsafe {
            caliptra_drivers::Ecc384::zeroize();
            caliptra_drivers::Hmac::zeroize();
        }
        super::erase(d)?;
        result?;
        private?;
        shared?;
    }
    d.fhe_session.policy.copy_from_slice(&r.bytes[8..28]);
    d.fhe_session.active = true;
    Ok(HEADER_LEN)
}

#[inline(never)]
fn establish(
    d: &mut Drivers,
    r: &Request,
    header: &mut [u8; HEADER_LEN],
    id: u32,
) -> CaliptraResult<()> {
    let seed = Zeroizing::new(d.trng.generate()?);
    let device = d.ecc384.key_pair(
        (&*seed).into(),
        &Array4x12::default(),
        &mut d.trng,
        KeyWriteArgs::new(PRIVATE, KeyUsage::default().set_ecc_private_key_en()).into(),
    )?;
    let client = Ecc384PubKey {
        x: Array4x12::from(<[u8; 48]>::try_from(&r.bytes[60..108]).unwrap()),
        y: Array4x12::from(<[u8; 48]>::try_from(&r.bytes[108..156]).unwrap()),
    };
    d.ecc384.ecdh(
        KeyReadArgs::new(PRIVATE).into(),
        &client,
        &mut d.trng,
        KeyWriteArgs::new(SHARED, KeyUsage::default().set_hmac_key_en()).into(),
    )?;
    put(header, 2, id);
    header[12..108].copy_from_slice(&device.to_der()[1..]);
    // Bind the already-retained LDevID/FMC/RT certificate chain assembled at
    // boot. This avoids reconstructing DER or allocating another 2-KiB buffer.
    let cert_hash: [u8; 48] = d.sha2_512_384.sha384_digest(&d.ecc_cert_chain)?.into();
    header[108..156].copy_from_slice(&cert_hash);
    let mut transcript = d.sha2_512_384.sha384_digest_init()?;
    transcript.update(DOMAIN)?;
    transcript.update(&r.bytes[4..156])?;
    transcript.update(&header[8..156])?;
    let mut hash = Array4x12::default();
    transcript.finalize(&mut hash)?;
    let signing_key = Drivers::get_key_id_rt_priv_key(d)?;
    let public_key = d.persistent_data.get().fht.rt_dice_ecc_pub_key;
    let sig = d.ecc384.sign(
        KeyReadArgs::new(signing_key).into(),
        &public_key,
        &hash,
        &mut d.trng,
    )?;
    header[156..204].copy_from_slice(&<[u8; 48]>::from(sig.r));
    header[204..252].copy_from_slice(&<[u8; 48]>::from(sig.s));
    let mut context = [0u8; 52];
    context[..48].copy_from_slice(&<[u8; 48]>::from(hash));
    context[48..].copy_from_slice(&256u32.to_be_bytes());
    for (slot, label) in [
        (REQUEST_KEY, b"FHE-v4-request".as_slice()),
        (RESPONSE_KEY, b"FHE-v4-response".as_slice()),
    ] {
        hmac_kdf(
            &mut d.hmac,
            KeyReadArgs::new(SHARED).into(),
            label,
            Some(&context),
            &mut d.trng,
            KeyWriteArgs::new(slot, KeyUsage::default().set_aes_key_en()).into(),
            HmacMode::Hmac384,
        )?;
    }
    let (_, tag) = d.aes.aes_256_gcm_encrypt(
        &mut d.trng,
        (&nonce(0, 1)).into(),
        AesKey::KV(KeyReadArgs::new(RESPONSE_KEY)),
        &context[..48],
        &[],
        &mut [],
        16,
    )?;
    header[252..268].copy_from_slice(&tag);
    Ok(())
}
