##
#
# Licensed under the Apache-2.0 license.
#
# File Name:
#
#    Makefile
#
# Abstract:
#
#    File contains helper routines for building debugging Caliptra ROM.
#
##

TARGET_DIR=../../target/riscv32imc-unknown-none-elf/firmware
CURRENT_DIR = $(shell pwd)
GIT_REV = $(shell git rev-parse HEAD)
EXTRA_CARGO_CONFIG = target.'cfg(all())'.rustflags = [\"-Dwarnings\"]
# MLDSA (default): 1, LMS: 3.
PQC_KEY_TYPE ?= 1
# Device lifecycle state: unprovisioned, manufacturing, production
DEVICE_LIFECYCLE ?= production
# Set to 1 to disable MLDSA in the ROM DICE chain (ECC-only mode).
# When enabled, PQC_KEY_TYPE is forced to 3 (LMS) for firmware image signing
# since MLDSA firmware signatures would still be checked by the image verifier.
NO_MLDSA ?= 0
MLDSA_FEATURE = $(if $(filter 1,$(NO_MLDSA)),no-mldsa,)
ifeq ($(NO_MLDSA),1)
  override PQC_KEY_TYPE = 3
endif
# Set to 1 to build test-fmc in minimal-demo mode (print banner + jump to RT)
MINIMAL_DEMO ?= 0
MINIMAL_DEMO_FEATURE = $(if $(filter 1,$(MINIMAL_DEMO)),minimal-demo,)

# Set to 1 to compile software-client support. Raw commands require FHE_DEBUG.
# FHE=1 builds protocol v5 with device-attested ECDH; FHE_TEST_KEY=1 uses fixed
# public test keys (debug-unlocked fake-ROM runs only). Off builds are unchanged.
# FHE_ALOHA selects the separate Aloha PSK profile; FHE_DEBUG the raw test commands.
FHE ?= 0
FHE_DEBUG ?= 0
FHE_TEST_KEY ?= 0
FHE_ALOHA ?= 0
FHE_EVAL_KEYS ?= 0
ifeq ($(FHE_PSK),1)
$(error FHE_PSK is retired; use FHE_TEST_KEY=1, or FHE_ALOHA=1 for Aloha)
endif
# Optional clear-reference model/command for FHE comparisons.
ML_CLEAR ?= 0
FHE_PARAMS ?= ps
FHE_FEATURE = $(if $(filter 1,$(FHE_DEBUG)),fhe-debug,$(if $(filter 1,$(FHE)),fhe-ecdh,))
ifneq ($(filter 1,$(FHE_TEST_KEY) $(FHE_ALOHA)),)
ifeq ($(FHE_DEBUG),1)
$(error FHE_TEST_KEY/FHE_ALOHA and FHE_DEBUG are mutually exclusive)
endif
ifneq ($(words $(filter 1,$(FHE) $(FHE_TEST_KEY) $(FHE_ALOHA))),1)
$(error choose one of FHE=1, FHE_TEST_KEY=1 or FHE_ALOHA=1)
endif
FHE_FEATURE := $(if $(filter 1,$(FHE_ALOHA)),fhe-aloha,fhe-test-key)
endif
# Evaluated before params/ml-clear suffixes are comma-joined onto FHE_FEATURE.
FHE_PROTECTED := $(filter fhe-test-key fhe-ecdh fhe-aloha,$(FHE_FEATURE))
ifneq ($(FHE_PROTECTED),)
ifneq ($(FHE_PARAMS),ps)
$(error protected FHE builds currently support FHE_PARAMS=ps only)
endif
endif
ifneq ($(filter 1,$(FHE) $(FHE_DEBUG) $(FHE_TEST_KEY) $(FHE_ALOHA)),)
ifeq ($(filter $(FHE_PARAMS),ps pl pleq),)
$(error FHE_PARAMS must be ps, pl or pleq)
endif
ifneq ($(FHE_PARAMS),ps)
FHE_FEATURE := $(FHE_FEATURE),fhe-$(FHE_PARAMS)
endif
endif

ifeq ($(ML_CLEAR),1)
ifeq ($(FHE_PROTECTED),)
$(error ML_CLEAR requires a protected FHE build)
endif
FHE_FEATURE := $(FHE_FEATURE),ml-clear
endif

ifeq ($(FHE_EVAL_KEYS),1)
ifeq ($(filter fhe-ecdh fhe-test-key,$(FHE_PROTECTED)),)
$(error FHE_EVAL_KEYS requires protocol v5 (FHE=1 or FHE_TEST_KEY=1))
endif
ifeq ($(ML_CLEAR),1)
$(error FHE_EVAL_KEYS excludes ML_CLEAR in the frozen runtime allocation)
endif
FHE_FEATURE := $(FHE_FEATURE),fhe-eval-keys
endif

comma := ,

default: build

build:
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		build \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu$(if $(MLDSA_FEATURE),$(comma)$(MLDSA_FEATURE),)"

build-emu:
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		build \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu$(if $(MLDSA_FEATURE),$(comma)$(MLDSA_FEATURE),)"

build-asm:
	cargo build \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu" \
		--bin asm_tests

run-asm: build-asm
	rust-objcopy -O binary \
		$(TARGET_DIR)/asm_tests \
		$(TARGET_DIR)/asm_tests.bin
	truncate -s 96K $(TARGET_DIR)/asm_tests.bin
	cargo run -p caliptra-emu -- \
		--rom $(TARGET_DIR)/asm_tests.bin \
		--pqc-key-type 1

build-jtag:
	cargo build \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu" \
		--bin jtag_tests

run-jtag: build-jtag
	rust-objcopy -O binary \
		$(TARGET_DIR)/jtag_tests \
		$(TARGET_DIR)/jtag_tests.bin
	truncate -s 96K $(TARGET_DIR)/jtag_tests.bin
	cargo run -p caliptra-emu -- \
		--rom $(TARGET_DIR)/jtag_tests.bin \
		--pqc-key-type 1

# Like run-jtag but stops after producing jtag_tests.bin (no emulator run).
# Used by the host one-shot build (software/build.sh) to fetch the JTAG ROM
# binary without launching the hanging emulator.
build-jtag-bin: build-jtag
	rust-objcopy -O binary \
		$(TARGET_DIR)/jtag_tests \
		$(TARGET_DIR)/jtag_tests.bin
	truncate -s 96K $(TARGET_DIR)/jtag_tests.bin

# DMA smoke-test ROM (FHE offload plan §6/WP2).  Built from this crate's
# test-fw, not drivers/test-fw, because it must run on RTL: only rom/dev's
# start.S zeroes ICCM/DCCM to initialize their ECC, and without that the first
# DCCM read raises CPTRA_HW_ERROR_FATAL.dccm_ecc_unc.  Like build-jtag-bin this
# stops at the .bin: the Chipyard host test loads it into IMEM itself.
build-dma-dram-bin:
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		build \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu" \
		--bin dma_dram_rom
	rust-objcopy -O binary \
		$(TARGET_DIR)/dma_dram_rom \
		$(TARGET_DIR)/dma_dram.bin
	truncate -s 96K $(TARGET_DIR)/dma_dram.bin

build-peak-stress-bin:
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		build \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu" \
		--bin peak_stress_rom
	rust-objcopy -O binary \
		$(TARGET_DIR)/peak_stress_rom \
		$(TARGET_DIR)/peak_stress.bin
	python3 -c 'from pathlib import Path; p=Path("$(TARGET_DIR)/peak_stress.bin"); b=p.read_bytes(); assert len(b)<=96*1024; p.write_bytes(b + bytes((-len(b)) % 8))'

build-fmc:
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		build \
		--profile firmware \
		--manifest-path ../../fmc/Cargo.toml \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu,riscv$(if $(MLDSA_FEATURE),$(comma)$(MLDSA_FEATURE),)" \
		--bin caliptra-fmc

build-test-fmc:
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		build \
		--profile firmware \
		--manifest-path tools/test-fmc/Cargo.toml \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu$(if $(MINIMAL_DEMO_FEATURE),$(comma)$(MINIMAL_DEMO_FEATURE),)"

build-rt:
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		build \
		--profile firmware \
		--manifest-path ../../runtime/Cargo.toml \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu,riscv$(if $(MLDSA_FEATURE),$(comma)$(MLDSA_FEATURE),)$(if $(FHE_FEATURE),$(comma)$(FHE_FEATURE),)" \
		--bin caliptra-runtime

build-test-rt:
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		build \
		--profile firmware \
		--manifest-path tools/test-rt/Cargo.toml \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features emu

gen-certs:
	$(shell bash $(CURRENT_DIR)/tools/scripts/gen_test_certs.sh $(TARGET_DIR))
	$(shell cp $(CURRENT_DIR)/tools/keys.toml $(TARGET_DIR))

build-fw-test-image: gen-certs build-test-fmc build-test-rt
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run \
		--manifest-path ../../image/app/Cargo.toml \
		-- \
		create \
		--pqc-key-type $(PQC_KEY_TYPE) \
		--key-config $(TARGET_DIR)/keys.toml \
		--ecc-pk-idx 1 \
		--pqc-pk-idx 0 \
		--fmc $(TARGET_DIR)/caliptra-rom-test-fmc \
		--fmc-version 0 \
		--fmc-rev $(GIT_REV) \
		--rt $(TARGET_DIR)/caliptra-rom-test-rt \
		--rt-version 0 \
		--rt-rev $(GIT_REV) \
		--fw-svn 0 \
		--out $(TARGET_DIR)/caliptra-rom-test-fw \
		--print-hashes

build-fw-image: gen-certs build-fmc build-rt
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run \
		--manifest-path ../../image/app/Cargo.toml \
		-- \
		create \
		--pqc-key-type $(PQC_KEY_TYPE) \
		--key-config $(TARGET_DIR)/keys.toml \
		--ecc-pk-idx 1 \
		--pqc-pk-idx 0 \
		--fmc $(TARGET_DIR)/caliptra-fmc \
		--fmc-version 0 \
		--fmc-rev $(GIT_REV) \
		--rt $(TARGET_DIR)/caliptra-runtime \
		--rt-version 0 \
		--rt-rev $(GIT_REV) \
		--fw-svn 0 \
		--pl0-pauser 0 \
		--out $(TARGET_DIR)/caliptra-fw \
		--print-hashes

build-fake-fmc:
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		build \
		--profile firmware \
		--manifest-path ../../fmc/Cargo.toml \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu,riscv,fake-fmc$(if $(MLDSA_FEATURE),$(comma)$(MLDSA_FEATURE),)" \
		--bin caliptra-fmc

build-fw-quick-image: gen-certs build-fake-fmc build-rt
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run \
		--manifest-path ../../image/app/Cargo.toml \
		-- \
		create \
		--pqc-key-type $(PQC_KEY_TYPE) \
		--key-config $(TARGET_DIR)/keys.toml \
		--ecc-pk-idx 1 \
		--pqc-pk-idx 0 \
		--fmc $(TARGET_DIR)/caliptra-fmc \
		--fmc-version 0 \
		--fmc-rev $(GIT_REV) \
		--rt $(TARGET_DIR)/caliptra-runtime \
		--rt-version 0 \
		--rt-rev $(GIT_REV) \
		--fw-svn 0 \
		--pl0-pauser 0 \
		--out $(TARGET_DIR)/caliptra-quick-fw \
		--print-hashes

run-quick: build-fw-quick-image build-fake-rom
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run \
		-p caliptra-emu \
		-- \
		--rom $(TARGET_DIR)/caliptra-fake-rom.bin \
		--recovery-image-fw $(TARGET_DIR)/caliptra-quick-fw \
		--device-lifecycle manufacturing \
		--pqc-key-type $(PQC_KEY_TYPE) \
		--mfg-pk-hash \
			$$(dd if=$(TARGET_DIR)/caliptra-quick-fw bs=1 skip=12 count=1736 status=none | sha384sum | cut -d' ' -f1)

bloat: build
	 cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		bloat \
		--bin caliptra-rom \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu" \
		-n 1000 \

objdump:
	 cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		objdump \
		--bin caliptra-rom \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--features "emu" \
		-- \
		-d \
		--no-print-imm-hex \
		--disassembler-options=no-aliases \

build-fake-rom:
ifeq ($(NO_MLDSA),1)
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run -p caliptra-builder -- \
		--fake-rom-no-mldsa $(TARGET_DIR)/caliptra-fake-rom.bin \
		--fw /dev/null
else
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run -p caliptra-builder -- \
		--fake-rom $(TARGET_DIR)/caliptra-fake-rom.bin \
		--fw /dev/null
endif

run-fake: build-fw-test-image build-fake-rom
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run \
		-p caliptra-emu \
		-- \
		--rom $(TARGET_DIR)/caliptra-fake-rom.bin \
		--recovery-image-fw $(TARGET_DIR)/caliptra-rom-test-fw \
		--device-lifecycle manufacturing \
		--pqc-key-type $(PQC_KEY_TYPE) \
		--mfg-pk-hash \
			$$(dd if=$(TARGET_DIR)/caliptra-rom-test-fw bs=1 skip=12 count=1736 status=none | sha384sum | cut -d' ' -f1)

build-rom:
ifeq ($(NO_MLDSA),1)
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run -p caliptra-builder -- \
		--rom-with-log-no-mldsa $(TARGET_DIR)/caliptra-rom.bin
else
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run -p caliptra-builder -- \
		--rom-with-log $(TARGET_DIR)/caliptra-rom.bin \
		--fw /dev/null
endif

run: build-emu build-fw-test-image build-rom
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run \
		-p caliptra-emu \
		-- \
		--req-idevid-csr \
		--idevid-key-id-algo sha1 \
		--rom $(TARGET_DIR)/caliptra-rom.bin \
		--recovery-image-fw $(TARGET_DIR)/caliptra-rom-test-fw \
		--device-lifecycle $(DEVICE_LIFECYCLE) \
		--pqc-key-type $(PQC_KEY_TYPE) \
		$(if $(filter production manufacturing,$(DEVICE_LIFECYCLE)),--mfg-pk-hash \
			$$(dd if=$(TARGET_DIR)/caliptra-rom-test-fw bs=1 skip=12 count=1736 status=none | sha384sum | cut -d' ' -f1),)
# See image/types/src/lib.rs ImageManifest for offsets and lenghts of vendor_pub_key_info

# Run with full runtime firmware (no subsystem mode) — for attestation/crypto demos
run-full-runtime: build-emu build-fw-image build-rom
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run \
		-p caliptra-emu \
		-- \
		--req-idevid-csr \
		--idevid-key-id-algo sha1 \
		--rom $(TARGET_DIR)/caliptra-rom.bin \
		--recovery-image-fw $(TARGET_DIR)/caliptra-fw \
		--device-lifecycle $(DEVICE_LIFECYCLE) \
		--pqc-key-type $(PQC_KEY_TYPE) \
		$(if $(filter production manufacturing,$(DEVICE_LIFECYCLE)),--mfg-pk-hash \
			$$(dd if=$(TARGET_DIR)/caliptra-fw bs=1 skip=12 count=1736 status=none | sha384sum | cut -d' ' -f1),)

run-active: build-emu build-fw-image build-rom
	cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run \
		-p caliptra-emu \
		-- \
		--req-idevid-csr \
		--idevid-key-id-algo sha1 \
		--rom $(TARGET_DIR)/caliptra-rom.bin \
		--recovery-image-fw $(TARGET_DIR)/caliptra-rom-test-fw \
		--device-lifecycle $(DEVICE_LIFECYCLE) \
		--subsystem-mode \
		--pqc-key-type $(PQC_KEY_TYPE) \
		$(if $(filter production manufacturing,$(DEVICE_LIFECYCLE)),--mfg-pk-hash \
			$$(dd if=$(TARGET_DIR)/caliptra-rom-test-fw bs=1 skip=12 count=1736 status=none | sha384sum | cut -d' ' -f1),)
# See image/types/src/lib.rs ImageManifest for offsets and lenghts of vendor_pub_key_info


run-update: build-emu build-fw-test-image build-rom
		cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		run \
		-p caliptra-emu \
		-- \
		--req-idevid-csr \
		--idevid-key-id-algo sha1 \
		--rom $(TARGET_DIR)/caliptra-rom.bin \
		--recovery-image-fw $(TARGET_DIR)/caliptra-rom-test-fw \
		--update-recovery-image-fw $(TARGET_DIR)/caliptra-rom-test-fw \
		--device-lifecycle unprovisioned \


size:
	 cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		size \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		--bin caliptra-rom \

nm:
	 cargo \
		"--config=$(EXTRA_CARGO_CONFIG)" \
		nm \
		--bin caliptra-rom \
		--profile firmware \
		--target=riscv32imc-unknown-none-elf \
		--no-default-features \
		-- \
		-v \

hexdump: build-rom
	xxd $(TARGET_DIR)/caliptra-rom.bin \

clean:
	cargo clean
