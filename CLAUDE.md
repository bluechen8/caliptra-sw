# Caliptra SW - Area Optimization Branch

## Branch: `area-optimized` (fork: bluechen8/caliptra-sw)
Base commit: `8efce033`

## Goal
Support configurable removal of Adams Bridge (MLDSA) hardware from Caliptra, allowing the ROM and firmware to build and run without the post-quantum crypto accelerator.

## Feature Flag: `no-mldsa`
Propagated through the crate dependency chain:
- `caliptra-rom` (rom/dev) -> `caliptra-kat`, `caliptra_common`
- `caliptra_common` (common/) -> used by verifier, debug_unlock
- `caliptra-kat` (kat/) -> gates MLDSA KAT

Build with: `make NO_MLDSA=1` (see rom/dev/Makefile lines 23-30)
This sets `--features no-mldsa` and forces `PQC_KEY_TYPE=3` (LMS only).

## Changes Made

### KAT (kat/)
- [x] `Cargo.toml`: Added `no-mldsa` feature
- [x] `src/lib.rs`: Gated `mldsa87_kat` module, pub use, and execute_kat call
- [x] `src/kats_env.rs`: Gated `mldsa87` field and import

### Common (common/)
- [x] `Cargo.toml`: Added `no-mldsa` feature
- [x] `src/verifier.rs`: Gated `mldsa87` field in `FirmwareImageVerificationEnv`; split `mldsa87_verify` impl (returns error when no-mldsa)
- [x] `src/debug_unlock.rs`: Refactored `validate_debug_unlock_token` into two cfg-gated versions (with/without mldsa87 param) sharing a common `validate_debug_unlock_token_ecc` helper

### ROM (rom/dev/)
- [x] `Cargo.toml`: Feature propagation `no-mldsa = ["caliptra-kat/no-mldsa", "caliptra_common/no-mldsa"]`
- [x] `src/rom_env.rs`: Gated `Mldsa87` import, `MldsaReg` import, struct field, and constructor
- [x] `src/main.rs`: Gated `mldsa87` in KatsEnv construction
- [x] `src/flow/update_reset.rs`: Gated `mldsa87` in FirmwareImageVerificationEnv and FakeRomImageVerificationEnv
- [x] `src/flow/fake.rs`: Gated `mldsa87` field; split `mldsa87_verify` impl
- [x] `src/flow/debug_unlock.rs`: Two cfg-gated calls to `validate_debug_unlock_token` (with/without mldsa87 arg)
- [x] `src/flow/cold_reset/idev_id.rs`: Gated `derive_key_pair` and `make_mldsa_csr` function definitions
- [x] `src/flow/cold_reset/ldev_id.rs`: Gated `derive_key_pair` and `generate_cert_sig_mldsa` function definitions
- [x] `src/flow/cold_reset/fmc_alias.rs`: Gated `derive_key_pair` and `generate_cert_sig_mldsa` function definitions
- [x] `src/flow/cold_reset/fw_processor.rs`: Gated `mldsa87` fields in KatsEnv, FirmwareImageVerificationEnv, FakeRomImageVerificationEnv constructions; gated `mldsa_verify` function definition

## TODO
- [ ] Test ROM build with `NO_MLDSA=1` and verify it compiles cleanly
- [ ] Measure ROM binary size with and without MLDSA to determine IMEM savings
- [ ] Adjust linker scripts if memory map changes for reduced SRAMs
- [ ] Verify firmware runs correctly with reduced SRAMs (Part 2 of area optimization)

## Related
- RTL changes tracked in: `/scratch/boru/chipyard/generators/caliptra-wrapper/src/main/resources/caliptra/vsrc/caliptra/CLAUDE.md`
