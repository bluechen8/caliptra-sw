/*++

Licensed under the Apache-2.0 license.

File Name:

    dma_dram_tests.rs

Abstract:

    DMA smoke test against plain SoC DRAM.

    This is the WP2 smoke test of the FHE offload plan
    (caliptra-wrapper design-review/fhe-offload-plan.md §6): prove that the
    Caliptra DMA manager, once it is attached to the SoC fabric, can read and
    write ordinary memory at DRAM addresses over the AHB-FIFO route -- the
    route plan §4.5 selects for pointer mode, because the direct-to-mailbox
    route needs `uc_has_lock` and is therefore unavailable while a SoC command
    is executing (mbox.sv:545).

    Everything here goes through `Dma::write_dword` / `Dma::read_buffer`, which
    are exactly the calls the FHE runtime's pointer-mode transport will make.

--*/

#![no_std]
#![no_main]

use caliptra_cfi_lib::CfiCounter;
use caliptra_drivers::{AxiAddr, Dma};
use caliptra_test_harness::test_suite;

/// Scratch base inside the SoC DRAM window (plan §4.5: pointers must lie in
/// `[0x8000_0000, 0x8000_0000 + 4 GiB)`).
///
/// 4 MiB in, which clears the Rocket host image and heap in the Chipyard
/// simulation (`test.riscv` ends at ~0x8005_B000) while staying inside the
/// emulator's modelled DRAM window.  The Rocket-side smoke test
/// (`caliptra-wrapper/software/caliptra-dma-test.c`) uses the same constants.
const DRAM_BASE: u64 = 0x8040_0000;
/// 1 KiB, the transfer size plan §6/WP2 names for the smoke test.
const XFER_WORDS: usize = 256;
/// Second buffer, deliberately not adjacent, so a copy cannot pass by aliasing.
const DST_OFFSET: u64 = 0x1000;
/// Status words the SoC polls, past both buffers.
const STATUS_OFFSET: u64 = 0x2000;
/// Written before the first transfer: "the ROM is running".
const STATUS_STARTED: u32 = 0x5A17_0001;
/// Written only after every check has passed.
const STATUS_PASSED: u32 = 0x5A17_600D;

/// `CPTRA_FLOW_STATUS`, VeeR-side address.
const FLOW_STATUS: *mut u32 = 0x3003_003C as *mut u32;
/// `ready_for_mb_processing` inside `CPTRA_FLOW_STATUS`.
const FLOW_READY_FOR_MB_PROCESSING: u32 = 1 << 28;

/// Tell the SoC that VeeR is up.
///
/// A test-harness ROM does not run Caliptra's boot flow, so nothing else sets
/// this bit; without it a SoC-side `caliptra_boot_to_ready()` would spin
/// forever.  `rom/dev/test-fw/jtag_tests.rs` does the same thing for the same
/// reason.  Harmless on the emulator, where nobody reads it.
fn signal_ready() {
    unsafe {
        let v = FLOW_STATUS.read_volatile();
        FLOW_STATUS.write_volatile(v | FLOW_READY_FOR_MB_PROCESSING);
    }
}

fn pattern(i: usize) -> u32 {
    (i as u32)
        .wrapping_mul(0x9E37_79B9)
        .wrapping_add(0x1234_5678)
}

/// Write 1 KiB word by word, read it back through the AHB FIFO, compare.
fn test_dma_dram_round_trip() {
    CfiCounter::reset(&mut || Ok((0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)));

    signal_ready();

    let dma = Dma::default();
    let src = AxiAddr::from(DRAM_BASE);
    // Announce liveness before touching anything, so a SoC-side poller can tell
    // "never started" from "started and failed".
    dma.write_dword(AxiAddr::from(DRAM_BASE + STATUS_OFFSET), STATUS_STARTED);

    for i in 0..XFER_WORDS {
        dma.write_dword(src + (i * 4) as u32, pattern(i));
    }

    let mut buf = [0u32; XFER_WORDS];
    dma.read_buffer(src, &mut buf);

    for (i, got) in buf.iter().enumerate() {
        assert_eq!(*got, pattern(i));
    }
}

/// Read 1 KiB from one DRAM address and write it back to another, then verify
/// the destination independently.  This is the shape of a pointer-mode
/// ingress/egress transfer: AXI -> AHB FIFO -> (compute) -> AHB FIFO -> AXI.
fn test_dma_dram_copy() {
    let dma = Dma::default();
    let src = AxiAddr::from(DRAM_BASE);
    let dst = AxiAddr::from(DRAM_BASE + DST_OFFSET);

    let mut buf = [0u32; XFER_WORDS];
    dma.read_buffer(src, &mut buf);

    for (i, word) in buf.iter().enumerate() {
        dma.write_dword(dst + (i * 4) as u32, *word);
    }

    let mut back = [0u32; XFER_WORDS];
    dma.read_buffer(dst, &mut back);
    for (i, got) in back.iter().enumerate() {
        assert_eq!(*got, pattern(i));
    }
}

/// Publish the verdict where the SoC can see it.
///
/// The Chipyard integration has no console capture (it was removed for PnR, see
/// `software/caliptra.h`), so in RTL simulation DRAM is how Caliptra reports
/// back.  Runs last, so reaching it means every check above passed.
fn test_dma_dram_publish_status() {
    let dma = Dma::default();
    dma.write_dword(AxiAddr::from(DRAM_BASE + STATUS_OFFSET + 4), STATUS_PASSED);
    assert_eq!(
        dma.read_dword(AxiAddr::from(DRAM_BASE + STATUS_OFFSET + 4)),
        STATUS_PASSED
    );
}

/// A single dword read must agree with the buffered read of the same address,
/// so the FIFO drain path is not reordering or dropping the first beat.
fn test_dma_dram_dword() {
    let dma = Dma::default();
    let src = AxiAddr::from(DRAM_BASE);
    for i in [0usize, 1, 7, XFER_WORDS - 1] {
        assert_eq!(dma.read_dword(src + (i * 4) as u32), pattern(i));
    }
}

test_suite! {
    test_dma_dram_round_trip,
    test_dma_dram_copy,
    test_dma_dram_dword,
    test_dma_dram_publish_status,
}
