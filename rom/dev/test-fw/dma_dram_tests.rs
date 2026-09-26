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
use caliptra_drivers::{AxiAddr, Dma, DmaReadTarget, DmaReadTransaction, ExitCtrl};
use caliptra_registers::mbox::MboxCsr;

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

// ---------------------------------------------------------------------------
// WP10.0 -- transport benchmark (plan §6/WP10.0, go/no-go for WP10)
//
// Measures DRAM -> mailbox-SRAM cost three ways, with the mailbox lock held by
// VeeR.  Holding the lock is the whole point: `uc_has_lock` is what opens the
// DMA's direct-to-mailbox route (mbox.sv:546), and it is false while a SoC
// command is executing -- so variant 1 is exactly the route that synchronous
// pointer mode CANNOT use and that a uC-initiated job CAN.  A test ROM is
// uC-initiated by nature, so it can time both today, with no RTL change and no
// commitment to WP10.
//
//   v1  DMA direct into mailbox SRAM      (DmaReadTarget::Mbox)
//   v2  DMA -> AHB FIFO, VeeR drains word by word, polling fifo_depth per word
//       (what Dma::read_buffer does today, i.e. what pointer mode costs)
//   v3  as v2, but the fifo_depth poll is hoisted out of the per-word loop --
//       isolates register-poll overhead from irreducible per-word cost
//
// Each variant is checksummed against the expected pattern, because a route
// that is fast and wrong is worthless (see the WP2 AXI-width bug).
// ---------------------------------------------------------------------------

/// Bench source buffer, clear of the smoke test's buffers above.
const BENCH_SRC_OFFSET: u64 = 0x10_0000;
/// Results block the SoC polls and prints.
const BENCH_RES_OFFSET: u64 = 0x12_0000;
/// 256 B, 4 KiB, 64 KiB -- the three sizes plan §6/WP10.0 names.
const BENCH_SIZES_WORDS: [usize; 3] = [64, 1024, 16384];
/// Dwords drained per fifo_depth poll in v3.  The engine's FIFO is 512 B = 128
/// dwords (axi_dma_ctrl.sv), so 64 stays comfortably inside it.
const BENCH_HOIST_CHUNK: usize = 64;
/// Written last, so the SoC cannot read a half-filled results block.
const BENCH_MAGIC: u32 = 0x5A17_B001;
/// Results-block layout, mirrored as #defines in caliptra-dma-test.c.
/// [0] magic (last written) · [1] mcycle sanity · then one slot per
/// (size, variant) pair: [cycles, ok].
const BENCH_SANITY_OFF: u32 = 4;
const BENCH_SLOTS_OFF: u32 = 8;
const BENCH_SLOT_STRIDE: u32 = 8;
const BENCH_NUM_VARIANTS: usize = 3;

/// Mailbox SRAM as seen by VeeR (memory_layout.rs::MBOX_ORG).  Direct access
/// needs `uc_has_lock | MBOX_EXECUTE_UC` (mbox.sv:550-552); we hold the lock.
const MBOX_SRAM: *mut u32 = 0x3004_0000 as *mut u32;

/// VeeR's own cycle counter.  Rocket's `rdcycle` traps in these configs
/// (haveBasicCounters = false), which is why timing lives on this side.
#[inline(always)]
fn rdmcycle() -> u32 {
    let v: u32;
    unsafe { core::arch::asm!("csrr {0}, mcycle", out(reg) v, options(nomem, nostack)) };
    v
}

/// Is `mcycle` actually counting?  If it is not, every number below would be a
/// convincing-looking zero, so publish the answer rather than assume it.
fn mcycle_sanity() -> u32 {
    let t0 = rdmcycle();
    for _ in 0..64 {
        unsafe { core::arch::asm!("nop", options(nomem, nostack)) };
    }
    rdmcycle().wrapping_sub(t0)
}

fn setup_read(dma: &Dma, src: AxiAddr, words: usize, target: DmaReadTarget) {
    dma.flush();
    dma.setup_dma_read(
        DmaReadTransaction {
            read_addr: src,
            fixed_addr: false,
            length: (words * 4) as u32,
            target,
        },
        0,
    );
}

fn bench_direct(dma: &Dma, src: AxiAddr, words: usize) -> u32 {
    let t0 = rdmcycle();
    setup_read(dma, src, words, DmaReadTarget::Mbox(0));
    dma.with_dma(|d| while d.status0().read().busy() {});
    rdmcycle().wrapping_sub(t0)
}

fn bench_fifo_perword(dma: &Dma, src: AxiAddr, words: usize) -> u32 {
    let t0 = rdmcycle();
    setup_read(dma, src, words, DmaReadTarget::AhbFifo);
    dma.with_dma(|d| {
        for i in 0..words {
            while d.status0().read().fifo_depth() == 0 {}
            let w = d.read_data().read();
            unsafe { MBOX_SRAM.add(i).write_volatile(w) };
        }
        while d.status0().read().busy() {}
    });
    rdmcycle().wrapping_sub(t0)
}

fn bench_fifo_hoisted(dma: &Dma, src: AxiAddr, words: usize) -> u32 {
    let t0 = rdmcycle();
    setup_read(dma, src, words, DmaReadTarget::AhbFifo);
    dma.with_dma(|d| {
        let mut done = 0usize;
        while done < words {
            let chunk = core::cmp::min(BENCH_HOIST_CHUNK, words - done);
            while (d.status0().read().fifo_depth() as usize) < chunk {}
            for i in 0..chunk {
                let w = d.read_data().read();
                unsafe { MBOX_SRAM.add(done + i).write_volatile(w) };
            }
            done += chunk;
        }
        while d.status0().read().busy() {}
    });
    rdmcycle().wrapping_sub(t0)
}

/// Running hash over `words` values drawn from `get`.  Both callers are
/// outside the timed region -- folding this into the drain loops would inflate
/// the very cycle counts WP10.0 exists to measure.
fn checksum(words: usize, get: impl Fn(usize) -> u32) -> u32 {
    let mut s = 0u32;
    for i in 0..words {
        s = s.wrapping_mul(31).wrapping_add(get(i));
    }
    s
}

fn mbox_checksum(words: usize) -> u32 {
    checksum(words, |i| unsafe { MBOX_SRAM.add(i).read_volatile() })
}

/// Scrub the mailbox window so a variant cannot pass on the previous one's data.
fn mbox_scrub(words: usize) {
    for i in 0..words {
        unsafe { MBOX_SRAM.add(i).write_volatile(0xDEAD_BEEF) };
    }
}

fn run_transport_bench(dma: &Dma) {
    let res = AxiAddr::from(DRAM_BASE + BENCH_RES_OFFSET);
    let src = AxiAddr::from(DRAM_BASE + BENCH_SRC_OFFSET);

    // Take the mailbox lock.  This is what sets `uc_has_lock`
    // (mbox.sv: uc_has_lock_nxt = ~req_data_soc_req & lock.swmod), which the
    // direct route in variant 1 requires.  Same idiom as
    // Mailbox::recovery_recv_txn(), which takes the lock for the same reason.
    let mut mbox = unsafe { MboxCsr::new() };
    while mbox.regs().lock().read().lock() {}
    cprintln!("[wp10.0] mailbox lock acquired (uc_has_lock set)");

    dma.write_dword(res + BENCH_SANITY_OFF, mcycle_sanity());

    for (si, &words) in BENCH_SIZES_WORDS.iter().enumerate() {
        let want = checksum(words, pattern);
        for variant in 0..BENCH_NUM_VARIANTS {
            mbox_scrub(words);
            let cycles = match variant {
                0 => bench_direct(dma, src, words),
                1 => bench_fifo_perword(dma, src, words),
                _ => bench_fifo_hoisted(dma, src, words),
            };
            let ok = (mbox_checksum(words) == want) as u32;
            let slot = (si * BENCH_NUM_VARIANTS + variant) as u32;
            let slot_at = BENCH_SLOTS_OFF + slot * BENCH_SLOT_STRIDE;
            dma.write_dword(res + slot_at, cycles);
            dma.write_dword(res + slot_at + 4u32, ok);
            cprintln!(
                "[wp10.0] size[{}] v{} cycles={} ok={}",
                si,
                variant + 1,
                cycles,
                ok
            );
        }
    }

    // Done marker last, so a partially written block is never mistaken for one.
    dma.write_dword(res, BENCH_MAGIC);

    // Release the lock we took above.  Nothing here needs it afterwards -- the
    // ROM only spins from now on -- but leaving the mailbox locked would make
    // this ROM unusable as a starting point for anything that does.
    mbox.regs_mut().unlock().write(|w| w.unlock(true));
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

        // WP10.0: the go/no-go measurement for WP10.  Runs after the smoke test
        // so a benchmark failure can never be confused with a broken DMA, and
        // only when it passed: the benchmark waits on DMA completion and on the
        // mailbox lock without a bound, so against a DMA already shown to be
        // broken it would hang here instead of letting the SoC read its verdict.
        run_transport_bench(&dma);
    } else {
        cprintln!("[dma_dram] FAILED");
    }

    // Spin rather than exit: the SoC still has to read the buffers back.
    loop {
        unsafe { core::arch::asm!("nop") };
    }
}
