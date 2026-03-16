// Licensed under the Apache-2.0 license
//
// Minimal ROM for JTAG debug tests.
//
// Primes GPRs and DCCM with known values, then signals ready_for_mb_processing
// and spins. The SOC-side JTAG test halts VeeR and reads back the primed values.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

#[cfg(feature = "std")]
pub fn main() {}

#[cfg(not(feature = "std"))]
core::arch::global_asm!(include_str!("../src/start.S"));

#[path = "../src/exception.rs"]
mod exception;

use caliptra_drivers::cprintln;
use caliptra_drivers::ExitCtrl;

/// SOC IFC registers (VeeR-side addresses)

const FLOW_READY_FOR_MB_PROCESSING: u32 = 1 << 28;

/// DCCM test area — 4 words at DCCM base + 0x100 (well away from stack)
const DCCM_TEST_BASE: *mut u32 = 0x5000_0100 as *mut u32;

/// Known test patterns for DCCM (JTAG mem test reads these back)
const DCCM_PATTERN: [u32; 4] = [0xCAFEBABE, 0x12345678, 0xA5A5A5A5, 0xDEAD0001];

/// Known GPR values — JTAG reads these via abstract register commands.
///   t0 (x5)  = 0x0BAD_C0DE
///   t1 (x6)  = 0x1234_ABCD
///   a0 (x10) = 0xFACE_FEED
const GPR_T0_VAL: u32 = 0x0BAD_C0DE;
const GPR_T1_VAL: u32 = 0x1234_ABCD;
const GPR_A0_VAL: u32 = 0xFACE_FEED;

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

#[no_mangle]
pub extern "C" fn rom_entry() -> ! {
    cprintln!("[jtag_tests] Priming known values for JTAG verification");

    // ── Step 1: Write known patterns to DCCM ────────────────────────────
    unsafe {
        for (i, &pat) in DCCM_PATTERN.iter().enumerate() {
            DCCM_TEST_BASE.add(i).write_volatile(pat);
        }
    }
    cprintln!("[jtag_tests] DCCM primed: 4 words at 0x{:08X}", DCCM_TEST_BASE as u32);

    // ── Step 2: Load known values into GPRs, signal ready, and spin ─────
    // Use inline asm so t0/t1/a0 are guaranteed to hold our values in the
    // spin loop. We signal ready_for_mb_processing from inside the asm
    // block after loading GPRs, so everything is primed before the SOC
    // side knows VeeR is ready.
    cprintln!("[jtag_tests] Loading GPRs, signaling ready, and spinning");
    unsafe {
        core::arch::asm!(
            // Load test values into GPRs
            "li t0, {t0_val}",
            "li t1, {t1_val}",
            "li a0, {a0_val}",
            // Signal ready_for_mb_processing: read-modify-write CPTRA_FLOW_STATUS
            "li t2, {flow_status_addr}",
            "lw t3, 0(t2)",
            "li t4, {ready_bit}",
            "or t3, t3, t4",
            "sw t3, 0(t2)",
            // Restore t0 (clobbered t2-t4 as scratch, but t0/t1/a0 are intact)
            // Spin forever
            "1: nop",
            "   j 1b",
            t0_val = const GPR_T0_VAL,
            t1_val = const GPR_T1_VAL,
            a0_val = const GPR_A0_VAL,
            flow_status_addr = const 0x3003_003cu32,
            ready_bit = const FLOW_READY_FOR_MB_PROCESSING,
            options(noreturn),
        );
    }
}
