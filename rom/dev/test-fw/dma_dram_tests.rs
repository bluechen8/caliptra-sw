// Licensed under the Apache-2.0 license
//
// Minimal ROM for the WP2 DMA smoke test (caliptra-wrapper
// design-review/fhe-offload-plan.md §6).
//
// Exercises Caliptra's DMA manager against plain SoC DRAM over the AHB-FIFO
// route -- the route plan §4.5 selects for pointer mode, because the
// direct-to-mailbox route is gated on `uc_has_lock` (mbox.sv:546) and is
// therefore unavailable while a SoC command is executing.
//
// Why this exists alongside drivers/test-fw/src/bin/dma_dram_tests.rs: that one
// runs under `caliptra_test_harness`, whose start.S does NOT zero ICCM/DCCM.
// The emulator does not model ECC so it passes there, but on RTL the first read
// of uninitialized DCCM raises an uncorrectable ECC error and the SoC sees
// CPTRA_HW_ERROR_FATAL = 0x2 (dccm_ecc_unc).  This binary uses the real ROM
// start.S (rom/dev/src/start.S:98-120), which zeroes both TCMs to initialize
// their ECC, so it runs on hardware.
//
// The verdict is published in DRAM, not on the console: console capture was
// removed for PnR in the Chipyard integration (caliptra-wrapper
// software/caliptra.h).  The SoC-side half is software/caliptra-dma-test.c.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

#[cfg(feature = "std")]
pub fn main() {}

#[cfg(not(feature = "std"))]
core::arch::global_asm!(include_str!("../src/start.S"));

#[path = "../src/exception.rs"]
mod exception;

use caliptra_drivers::cprintln;
use caliptra_drivers::{AxiAddr, Dma, ExitCtrl};

const FLOW_READY_FOR_MB_PROCESSING: u32 = 1 << 28;
const FLOW_STATUS: *mut u32 = 0x3003_003C as *mut u32;

/// Scratch base inside the SoC DRAM window; must match caliptra-dma-test.c.
const DRAM_BASE: u64 = 0x8040_0000;
/// 1 KiB, the transfer size plan §6/WP2 names for the smoke test.
const XFER_WORDS: usize = 256;
/// Second buffer, deliberately not adjacent, so a copy cannot pass by aliasing.
const DST_OFFSET: u64 = 0x1000;
/// Status words the SoC polls, past both buffers.
const STATUS_OFFSET: u64 = 0x2000;
const STATUS_STARTED: u32 = 0x5A17_0001;
const STATUS_PASSED: u32 = 0x5A17_600D;
/// Phase marker, so the SoC can say *where* a stall is rather than infer it.
const PHASE_OFFSET: u64 = 0x2008;

/// Bytes per AXI -> AHB-FIFO read.  Plan §4.5 specifies programming that route
/// "in 256 B blocks", and the engine's FIFO is 512 B
/// (caliptra/src/axi/rtl/axi_dma_ctrl.sv), so a single 1 KiB `read_buffer` asks
/// the FIFO to hold more than it can while VeeR drains it.  Stay inside the
/// FIFO and issue one transfer per block.
const FIFO_BLOCK_BYTES: usize = 256;
const FIFO_BLOCK_WORDS: usize = FIFO_BLOCK_BYTES / 4;

/// Publish which stage we are in; the SoC prints this with every poll.
fn phase(dma: &Dma, p: u32) {
    dma.write_dword(AxiAddr::from(DRAM_BASE + PHASE_OFFSET), p);
}

/// Read `out` from `addr` in FIFO-sized blocks (see `FIFO_BLOCK_BYTES`).
fn read_blocks(dma: &Dma, addr: AxiAddr, out: &mut [u32]) {
    let mut off = 0usize;
    while off < out.len() {
        let n = core::cmp::min(FIFO_BLOCK_WORDS, out.len() - off);
        dma.read_buffer(addr + (off * 4) as u32, &mut out[off..off + n]);
        off += n;
    }
}

fn pattern(i: usize) -> u32 {
    (i as u32)
        .wrapping_mul(0x9E37_79B9)
        .wrapping_add(0x1234_5678)
}

#[no_mangle]
#[inline(never)]
extern "C" fn exception_handler(exception: &exception::ExceptionRecord) {
    cprintln!(
        "EXCEPTION mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc
    );
    ExitCtrl::exit(1);
}

#[no_mangle]
#[inline(never)]
extern "C" fn nmi_handler(exception: &exception::ExceptionRecord) {
    cprintln!(
        "NMI mcause=0x{:08X} mscause=0x{:08X} mepc=0x{:08X}",
        exception.mcause,
        exception.mscause,
        exception.mepc
    );
    ExitCtrl::exit(1);
}

#[panic_handler]
#[inline(never)]
#[cfg(not(feature = "std"))]
fn handle_panic(pi: &core::panic::PanicInfo) -> ! {
    if let Some(loc) = pi.location() {
        cprintln!("Panic at file {} line {}", loc.file(), loc.line())
    }
    ExitCtrl::exit(1);
}

/// Returns false on the first mismatch; the SoC then sees `started` but never
/// `passed`, and reports which buffer is wrong from its own side.
fn run_dma_checks(dma: &Dma) -> bool {
    let src = AxiAddr::from(DRAM_BASE);
    let dst = AxiAddr::from(DRAM_BASE + DST_OFFSET);

    // 1. write 1 KiB word by word, read it back through the AHB FIFO
    phase(dma, 1);
    for i in 0..XFER_WORDS {
        dma.write_dword(src + (i * 4) as u32, pattern(i));
    }
    phase(dma, 2);
    let mut buf = [0u32; XFER_WORDS];
    read_blocks(dma, src, &mut buf);
    phase(dma, 3);
    for (i, got) in buf.iter().enumerate() {
        if *got != pattern(i) {
            cprintln!("[dma_dram] src[{}] mismatch: 0x{:08X}", i, *got);
            return false;
        }
    }

    // 2. copy to a second, non-adjacent buffer: the shape of a pointer-mode
    //    transfer (AXI -> FIFO -> compute -> FIFO -> AXI)
    for (i, word) in buf.iter().enumerate() {
        dma.write_dword(dst + (i * 4) as u32, *word);
    }
    phase(dma, 4);
    let mut back = [0u32; XFER_WORDS];
    read_blocks(dma, dst, &mut back);
    phase(dma, 5);
    for (i, got) in back.iter().enumerate() {
        if *got != pattern(i) {
            cprintln!("[dma_dram] dst[{}] mismatch: 0x{:08X}", i, *got);
            return false;
        }
    }

    // 3. single-dword reads must agree with the buffered read, so the FIFO
    //    drain path is not reordering or dropping the first beat
    for i in [0usize, 1, 7, XFER_WORDS - 1] {
        if dma.read_dword(src + (i * 4) as u32) != pattern(i) {
            cprintln!("[dma_dram] read_dword[{}] mismatch", i);
            return false;
        }
    }
    phase(dma, 6);
    true
}

#[no_mangle]
pub extern "C" fn rom_entry() -> ! {
    cprintln!("[dma_dram] DMA smoke test starting");

    // Tell the SoC that VeeR is up.  A test ROM does not run Caliptra's boot
    // flow, so nothing else sets this and the SoC-side boot helper would wait
    // for it forever (same reason as test-fw/jtag_tests.rs).
    unsafe {
        let v = FLOW_STATUS.read_volatile();
        FLOW_STATUS.write_volatile(v | FLOW_READY_FOR_MB_PROCESSING);
    }

    let dma = Dma::default();
    dma.write_dword(AxiAddr::from(DRAM_BASE + STATUS_OFFSET), STATUS_STARTED);

    if run_dma_checks(&dma) {
        dma.write_dword(AxiAddr::from(DRAM_BASE + STATUS_OFFSET + 4), STATUS_PASSED);
        cprintln!("[dma_dram] all checks passed");
    } else {
        cprintln!("[dma_dram] FAILED");
    }

    // Spin rather than exit: the SoC still has to read the buffers back.
    loop {
        unsafe { core::arch::asm!("nop") };
    }
}
