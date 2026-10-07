/*++

Licensed under the Apache-2.0 license.

File Name:

    lib.rs

Abstract:

    Portable, `no_std`, allocation-free CKKS client kernels shared by the
    Caliptra firmware and the host-side tests.

    Everything here works on caller-supplied slices, so the same code runs on
    a host `Vec` in tests and in place inside Caliptra's 256 KB mailbox SRAM
    on VeeR (plan §3.2: the microcontroller may read *and* write mailbox SRAM
    while a SoC command is executing).

    Scope: encrypt/decrypt and evaluation-key generation. There are no
    user-ciphertext evaluation operations here, no refresh, and no path that returns a decryption to the
    SoC in the clear -- that is the runtime's job, and only `FHE_EGRESS`
    (decrypt fused with AES-GCM to the user) may do it.

    No floating point (plan §9): VeeR and the stripped Rocket both trap on it.

--*/

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! CKKS client kernels for the Caliptra FHE offload baseline.

/// Modular arithmetic mod q < 2^31, Montgomery form with R = 2^32.
pub mod arith;
/// Streamable rotation/relinearization evaluation-key generation.
pub mod evalkey;
/// Wrapped-blob header and the little-endian polynomial wire layout.
pub mod format;
/// Negacyclic NTT in the plan §4.1 layout.
pub mod ntt;
/// Generated parameter points and their RNS primes.
pub mod params;
/// ChaCha20 keystream, reseeded from the TRNG per command.
pub mod prg;
/// Secret-key RLWE encrypt and decrypt, per limb.
pub mod rlwe;
/// Ternary / centered-binomial / uniform samplers.
pub mod sample;

pub use params::{ParamSet, PrimeParams};

/// Errors that a kernel can report to its caller.
///
/// Every one of these is a *validation* failure on untrusted input; the
/// runtime maps them onto mailbox error codes and zeroizes before returning
/// (plan §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A caller-supplied buffer has the wrong length for `N`/`L`.
    BadLength,
    /// A coefficient was not reduced modulo its prime.
    NotReduced,
    /// A blob header failed validation (magic, version, sizes, encoding).
    BadHeader,
    /// A blob's sequence number did not advance.
    StaleSeq,
}

/// Result alias for the kernels.
pub type Result<T> = core::result::Result<T, Error>;

/// Overwrite a scratch buffer, resisting dead-store elimination.
///
/// Plan §9 requires every key, plaintext and error polynomial to be erased on
/// every exit path; call this on each scratch slice before returning.
pub fn zeroize_u32(buf: &mut [u32]) {
    use zeroize::Zeroize;
    buf.zeroize();
}

/// Overwrite a byte scratch buffer.  See [`zeroize_u32`].
pub fn zeroize_u8(buf: &mut [u8]) {
    use zeroize::Zeroize;
    buf.zeroize();
}

/// Overwrite a signed scratch buffer (sampled error polynomials).
pub fn zeroize_i8(buf: &mut [i8]) {
    use zeroize::Zeroize;
    buf.zeroize();
}
