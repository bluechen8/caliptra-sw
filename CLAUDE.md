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

## Linker Script Adjustments

Rust/linker files use **default 256KB ICCM/DCCM** values (upstream defaults).
ICCM/DCCM shrinking is tested via both RTL simulation and SW emulator by caliptra-sw.

Use `gen_memory_layout.py` to regenerate for reduced SRAM sizes when needed:
```
python3 rom/dev/tools/scripts/gen_memory_layout.py \
    --iccm-kb 32 --dccm-kb 256 \
    --fmc-kb 8 --rt-kb 24 \
    --total-stack-kb 40 --rom-stack-kb 40 --fmc-rt-stack-kb 14 \
    --lib-fmc-kb 8 --lib-rt-kb 24
```

Files affected by gen_memory_layout.py:
- `drivers/src/memory_layout.rs`
- `rom/dev/src/rom.ld`
- `rom/dev/tools/test-fmc/src/fmc.ld`
- `rom/dev/tools/test-rt/src/rt.ld`
- `common/src/lib.rs`

### Key constraint: DCCM cannot be reduced below 256K
- `PersistentData` struct is ~110K (manifests 34K, datavault 15K, MLDSA keys/certs 20K, cert buffers, DPE, auth manifest metadata, CSR envelopes)
- ROM DICE chain requires ~40K stack for crypto operations (ECC, SHA, certificate generation)
- At 128K DCCM: only ~14K available for stack → stack overflow corrupts PersistentData.dot_owner_pk_hash → fatal error `0x000B005E` (DOT owner public key digest mismatch)
- Future optimization: gate MLDSA fields in PersistentData with `no-mldsa` feature (~20K savings)

## Feature Flag: `minimal-demo`
Enables a minimal test-fmc that prints a banner and jumps directly to RT (skipping mailbox command processing).

Build with: `make MINIMAL_DEMO=1` (see rom/dev/Makefile)

### Changes
- [x] `rom/dev/Makefile`: Added `MINIMAL_DEMO` variable, passes `minimal-demo` feature to test-fmc build; removed `--fw /dev/null` from no-mldsa builder invocation
- [x] `rom/dev/tools/test-fmc/Cargo.toml`: Added `minimal-demo` feature
- [x] `rom/dev/tools/test-fmc/src/main.rs`: Added `minimal-demo` gated path that reads RT entry point from DataVault and jumps via inline `transfer_control` asm

## TODO
- [x] Test ROM build with `NO_MLDSA=1` and verify it compiles cleanly
- [x] Adjust linker scripts for reduced ICCM (32K) — tested via RTL sim and SW emulator, rolled back to defaults in source
- [ ] Measure ROM binary size with and without MLDSA to determine IMEM savings
- [ ] Verify firmware runs correctly with reduced ICCM (Part 2 of area optimization)
- [ ] (future) Gate MLDSA fields in PersistentData to enable DCCM reduction

## Related
- RTL changes tracked in: `/scratch/boru/chipyard/generators/caliptra-wrapper/src/main/resources/caliptra/vsrc/caliptra/CLAUDE.md`
