// Licensed under the Apache-2.0 license
//
// Single-run, two-phase peak-power stress. No runtime upload.
// Phase A: AES-256-ECB + SHA-512 (+ optional DMA) for a cycle budget.
// Phase B: one complete ECC-P384 verify + SHA-512 (+ optional DMA).
// AES and ECC never overlap: frozen caliptra_top raises fatal crypto_error.
// Prepare operands first; each phase has its own BOOT_STATUS window for a
// separate SAIF; drain and check results afterwards. All hardware waits have
// cycle deadlines. This is public test data, not a production cryptographic
// service. Host protocol: caliptra-peak-stress.c.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

#[cfg(feature = "std")]
pub fn main() {}

#[cfg(not(feature = "std"))]
core::arch::global_asm!(include_str!("../src/start.S"));

#[path = "../src/exception.rs"]
mod exception;

use caliptra_drivers::{cprintln, Dma, ExitCtrl};
use caliptra_registers::{aes::AesReg, ecc::EccReg, mbox::MboxCsr, sha512::Sha512Reg};

const FLOW_STATUS: *mut u32 = 0x3003_003c as *mut u32;
const BOOT_STATUS: *mut u32 = 0x3003_0038 as *mut u32;
const SHARED: *mut u32 = 0x3003_0018 as *mut u32;
const MARK: u32 = 0x5a17_5000;
const PHASE_A_CAPTURE: u32 = 2;
const PHASE_DONE: u32 = 3;
const PHASE_A_END: u32 = 4;
const PHASE_ARMED: u32 = 5;
const PHASE_B_CAPTURE: u32 = 6;
const PHASE_B_END: u32 = 7;
const PHASE_FAIL: u32 = 15;
// Versioned protocol: incompatible with the single-window profile ROM.
const CTRL_MAGIC: u32 = 0x5a17_c7a5;
const RES_MAGIC: u32 = 0x5a17_d0e8;
const LEG_AES: u32 = 1;
const LEG_SHA: u32 = 2;
const LEG_DMA: u32 = 4;
// Bit 3 belongs to Rocket, which the host runs independently.
const LEG_ECC: u32 = 16;
const REQUIRED: u32 = LEG_AES | LEG_SHA | LEG_ECC;
const ENGINE_MASK: u32 = REQUIRED | LEG_DMA;
const DEFAULT_WINDOW: u32 = 4096;
const MIN_WINDOW: u32 = 1024;
const MAX_WINDOW: u32 = 65536;
const WAIT_CYCLES: u32 = 2_000_000;
// One P-384 verify is roughly 1M cycles; phase B waits for it to finish.
const ECC_WAIT_CYCLES: u32 = 8_000_000;
const ACK_START: u32 = 0x53544152;
const ACK_END: u32 = 0x454e4421;
const DMA_SOURCE: u32 = 0x8050_0000;
const DMA_WORDS: usize = 1024;
const MBOX_SRAM: *const u32 = 0x3004_0000 as *const u32;

// AES-256-ECB: key bytes 0..31, 16 public pattern bytes. SHA-512: 64 pattern
// bytes, one pre-padded block. Expected values independently computed with
// Python cryptography/hashlib. ECB deliberately measures AES rounds, not GHASH.
const AES_EXPECT: [u32; 4] = [0x07f7bdba, 0xf330b1cf, 0x28e1e549, 0xea79c3f1];
const SHA_EXPECT: [u32; 16] = [
    0xbe7cccda, 0xcc7551d4, 0x0828f4f3, 0x568f741a, 0x224ec5e5, 0x274ca547, 0xe06ad5dc, 0x83134567,
    0x06033259, 0xaa46937a, 0x061bc30f, 0x9913597e, 0x0b591c64, 0x92da5334, 0xe9148bbb, 0x91ce805b,
];
// Public P-384 verification vector from kat/src/ecc384_kat.rs, zero digest.
const ECC_X: [u32; 12] = [
    0xd7dd94e0, 0xbffc4cad, 0xe9902b7f, 0xdb154260, 0xd5ec5dfd, 0x57950e83, 0x59015a30, 0x2c8bf7bb,
    0xa7e5f6df, 0xfc168516, 0x2bdd35f9, 0xf5c1b0ff,
];
const ECC_Y: [u32; 12] = [
    0xbb9c3a2f, 0x061e8d70, 0x14278dd5, 0x1e66a918, 0xa6b6f9f1, 0xc1937312, 0xd4e7a921, 0xb18ef0f4,
    0x1fdd401d, 0x9e771850, 0x9f8731e9, 0xeec9c31d,
];
const ECC_R: [u32; 12] = [
    0x93799D55, 0x12263628, 0x34F60F7B, 0x945290B7, 0xCCE6E996, 0x01FB7EBD, 0x026C2E3C, 0x445D3CD9,
    0xB65068DA, 0xC0A848BE, 0x9F0560AA, 0x758FDA27,
];
const ECC_S: [u32; 12] = [
    0xE548E535, 0xA1CC600E, 0x133B5591, 0xAEBAAD78, 0x054006D7, 0x52D0E1DF, 0x94FBFA95, 0xD78F0B3F,
    0x8E81B911, 0x9C2BE008, 0xBF6D6F4E, 0x4185F87D,
];

fn shared_read(i: usize) -> u32 {
    unsafe { SHARED.add(i).read_volatile() }
}
fn shared_write(i: usize, v: u32) {
    unsafe { SHARED.add(i).write_volatile(v) }
}
#[inline(always)]
fn rdmcycle() -> u32 {
    let v;
    unsafe { core::arch::asm!("csrr {0}, mcycle", out(reg) v, options(nomem, nostack)) };
    v
}
fn mark(phase: u32) {
    unsafe { BOOT_STATUS.write_volatile(MARK | phase) }
}
fn fail(stage: u32) -> ! {
    mark((stage << 4) | PHASE_FAIL);
    cprintln!("[stress] FAIL stage=0x{:x}", stage);
    ExitCtrl::exit(1);
}
fn check_fatal() {
    if unsafe { (0x3003_0000 as *const u32).read_volatile() } != 0 {
        fail(0xf0);
    }
}
fn deadline_for(start: u32, limit: u32, stage: u32) {
    check_fatal();
    if rdmcycle().wrapping_sub(start) >= limit {
        fail(stage);
    }
}
fn deadline(start: u32, stage: u32) {
    deadline_for(start, WAIT_CYCLES, stage);
}
fn await_ack(ack: u32) {
    let start = rdmcycle();
    while shared_read(7) != ack {
        deadline(start, 0xd3);
    }
}
fn dma_busy(dma: &Dma) -> bool {
    dma.with_dma(|d| {
        let s = d.status0().read();
        if s.error() {
            fail(0xd0);
        }
        s.busy() || d.ctrl().read().go()
    })
}
fn pattern(i: usize) -> u8 {
    (i.wrapping_mul(37).wrapping_add(11) & 255) as u8
}
fn dma_pattern(i: usize) -> u32 {
    (i as u32).wrapping_mul(0x9e3779b9).wrapping_add(0x12345678)
}
fn saturate(count: u32) -> u32 {
    count.min(0xffff)
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
    mark(PHASE_FAIL);
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
    mark(PHASE_FAIL);
    ExitCtrl::exit(1);
}

/// Required by the linked driver crate; this ROM uses register-level AES.
#[no_mangle]
#[inline(never)]
extern "C" fn cfi_panic_handler(code: u32) -> ! {
    cprintln!("[stress] CFI panic code=0x{:08X}", code);
    mark(PHASE_FAIL);
    ExitCtrl::exit(1);
}

#[panic_handler]
#[inline(never)]
#[cfg(not(feature = "std"))]
fn handle_panic(pi: &core::panic::PanicInfo) -> ! {
    if let Some(loc) = pi.location() {
        cprintln!("Panic at file {} line {}", loc.file(), loc.line())
    }
    mark(PHASE_FAIL);
    ExitCtrl::exit(1);
}

struct Engines {
    legs: u32,
    aes: AesReg,
    sha: Sha512Reg,
    ecc: EccReg,
    dma: Dma,
    aes_in: [u32; 4],
    aes_last: [u32; 4],
    counts: [u32; 4], // AES, SHA, DMA, ECC; includes final drain completion
    pending: u32,
    slot: u32,
}
impl Engines {
    fn prepare(&mut self) {
        let start = rdmcycle();
        while !self.aes.regs().status().read().idle() {
            deadline(start, 0xa4);
        }
        for _ in 0..2 {
            self.aes.regs_mut().ctrl_shadowed().write(|w| {
                w.key_len(4)
                    .mode(1)
                    .operation(1)
                    .manual_operation(false)
                    .sideload(false)
            });
        }
        for i in 0..8 {
            let word = u32::from_le_bytes(core::array::from_fn(|j| (4 * i + j) as u8));
            self.aes
                .regs_mut()
                .key_share0()
                .at(i)
                .write(|_| word ^ 0x12345678);
            self.aes.regs_mut().key_share1().at(i).write(|_| 0x12345678);
        }
        self.aes_in =
            core::array::from_fn(|i| u32::from_le_bytes(core::array::from_fn(|j| pattern(4 * i + j))));
        // The fourth write starts automatic AES; defer it until launch.
        for i in 0..3 {
            self.aes
                .regs_mut()
                .data_in()
                .at(i)
                .write(|_| self.aes_in[i]);
        }
        while !self.sha.regs().status().read().ready() {
            deadline(start, 0xb0);
        }
        for i in 0..32 {
            let word = match i {
                0..=15 => u32::from_be_bytes(core::array::from_fn(|j| pattern(4 * i + j))),
                16 => 0x80000000,
                31 => 512,
                _ => 0,
            };
            self.sha.regs_mut().block().at(i).write(|_| word);
        }
        // Loading ECC operands does not make ECC busy; only the command does.
        while !self.ecc.regs().status().read().ready() {
            deadline(start, 0xe0);
        }
        for i in 0..12 {
            self.ecc.regs_mut().pubkey_x().at(i).write(|_| ECC_X[i]);
            self.ecc.regs_mut().pubkey_y().at(i).write(|_| ECC_Y[i]);
            self.ecc.regs_mut().msg().at(i).write(|_| 0);
            self.ecc.regs_mut().sign_r().at(i).write(|_| ECC_R[i]);
            self.ecc.regs_mut().sign_s().at(i).write(|_| ECC_S[i]);
        }
        if self.legs & LEG_DMA != 0 {
            while dma_busy(&self.dma) {
                deadline(start, 0xd1);
            }
            // Fixed public address, wholly within the fabric's 33-bit range.
            // Preload everything except GO; no DMA register is touched otherwise.
            self.dma.with_dma(|d| {
                d.src_addr_l().write(|_| DMA_SOURCE);
                d.src_addr_h().write(|_| 0);
                d.dst_addr_l().write(|_| 0);
                d.dst_addr_h().write(|_| 0);
                d.byte_count().write(|_| (DMA_WORDS * 4) as u32);
                d.block_size().write(|w| w.size(0));
            });
        }
    }
    fn start_aes(&mut self) {
        for i in 0..4 {
            self.aes
                .regs_mut()
                .data_in()
                .at(i)
                .write(|_| self.aes_in[i]);
        }
        self.pending |= LEG_AES;
    }
    fn start_sha(&mut self) {
        self.sha
            .regs_mut()
            .ctrl()
            .write(|w| w.mode(3).init(true).last(true));
        self.pending |= LEG_SHA;
    }
    fn start_ecc(&mut self) {
        self.ecc
            .regs_mut()
            .ctrl()
            .write(|w| w.ctrl(|w| w.verifying()));
        self.pending |= LEG_ECC;
    }
    fn start_dma(&mut self) {
        self.dma.with_dma(|d| {
            d.ctrl()
                .write(|w| w.rd_route(|w| w.mbox()).wr_route(|w| w.disable()).go(true))
        });
        self.pending |= LEG_DMA;
    }
    fn launch_a(&mut self) {
        // Start the long DMA first; only command writes remain.
        if self.legs & LEG_DMA != 0 {
            self.start_dma();
        }
        self.aes
            .regs_mut()
            .data_in()
            .at(3)
            .write(|_| self.aes_in[3]);
        self.pending |= LEG_AES;
        self.start_sha();
    }
    // One nonblocking engine step, round-robin. Engines in `restart` are
    // reissued on completion. No digest comparisons, data generation,
    // printing, or waiting for an entire operation inside a window.
    fn step(&mut self, restart: u32) {
        let slot = self.slot;
        self.slot = (slot + 1) & 3;
        match slot {
            0 if self.pending & LEG_AES != 0 => {
                let status: u32 = self.aes.regs().status().read().into();
                if status & 0x60 != 0 {
                    fail(0xa3);
                }
                if status & 8 != 0 {
                    for i in 0..4 {
                        self.aes_last[i] = self.aes.regs().data_out().at(i).read();
                    }
                    self.counts[0] += 1;
                    self.pending &= !LEG_AES;
                    if restart & LEG_AES != 0 {
                        self.start_aes();
                    }
                }
            }
            1 if self.pending & LEG_SHA != 0 => {
                let status = self.sha.regs().status().read();
                if status.ready() && status.valid() {
                    self.counts[1] += 1;
                    self.pending &= !LEG_SHA;
                    if restart & LEG_SHA != 0 {
                        self.start_sha();
                    }
                }
            }
            2 if self.pending & LEG_DMA != 0 => {
                if !dma_busy(&self.dma) {
                    self.counts[2] += 1;
                    self.pending &= !LEG_DMA;
                    if restart & LEG_DMA != 0 {
                        self.start_dma();
                    }
                }
            }
            3 if self.pending & LEG_ECC != 0 => {
                let status = self.ecc.regs().status().read();
                if status.ready() && status.valid() {
                    self.counts[3] += 1;
                    self.pending &= !LEG_ECC;
                    if restart & LEG_ECC != 0 {
                        self.start_ecc();
                    }
                }
            }
            _ => {}
        }
    }
    fn check(&self) -> u32 {
        // Check the final result of each repeated fixed vector, after capture.
        // Counts are completions, not a separate correctness check per operation.
        let aes_ok = self.counts[0] > 0 && self.aes_last == AES_EXPECT;
        let mut sha_ok = self.counts[1] > 0;
        for i in 0..16 {
            sha_ok &= self.sha.regs().digest().at(i).read() == SHA_EXPECT[i];
        }
        // Exactly one ECC pass by construction: phase B never reissues it.
        let mut ecc_ok = self.counts[3] == 1;
        for i in 0..12 {
            ecc_ok &= self.ecc.regs().verify_r().at(i).read() == ECC_R[i];
        }
        let mut dma_ok = self.legs & LEG_DMA == 0 || self.counts[2] > 0;
        if self.legs & LEG_DMA != 0 {
            for i in 0..DMA_WORDS {
                dma_ok &= unsafe { MBOX_SRAM.add(i).read_volatile() } == dma_pattern(i);
            }
        }
        (aes_ok as u32) | ((sha_ok as u32) << 1) | ((dma_ok as u32) << 2) | ((ecc_ok as u32) << 3)
    }
}

#[no_mangle]
pub extern "C" fn rom_entry() -> ! {
    unsafe { FLOW_STATUS.write_volatile(FLOW_STATUS.read_volatile() | (1 << 28)) };
    let external = shared_read(0) == CTRL_MAGIC;
    let (legs, window) = if external {
        (shared_read(1), shared_read(2))
    } else {
        (REQUIRED, DEFAULT_WINDOW)
    };
    // AES, SHA and ECC are mandatory; DMA follows the hardware configuration.
    if legs & REQUIRED != REQUIRED
        || legs & !ENGINE_MASK != 0
        || !(MIN_WINDOW..=MAX_WINDOW).contains(&window)
    {
        fail(0xc0);
    }
    let mut mbox = unsafe { MboxCsr::new() };
    if legs & LEG_DMA != 0 {
        let start = rdmcycle();
        while mbox.regs().lock().read().lock() {
            deadline(start, 0xc1);
        }
    }
    let mut engines = Engines {
        legs,
        aes: unsafe { AesReg::new() },
        sha: unsafe { Sha512Reg::new() },
        ecc: unsafe { EccReg::new() },
        dma: Dma::default(),
        aes_in: [0; 4],
        aes_last: [0; 4],
        counts: [0; 4],
        pending: 0,
        slot: 0,
    };
    let keep = LEG_SHA | LEG_DMA;
    engines.prepare();
    if external {
        mark(PHASE_ARMED);
        await_ack(ACK_START);
    }

    // Phase A: AES + SHA (+ DMA) for the cycle budget.
    engines.launch_a();
    mark(PHASE_A_CAPTURE);
    let a_start = rdmcycle();
    while rdmcycle().wrapping_sub(a_start) < window {
        check_fatal();
        engines.step(keep | LEG_AES);
    }
    let a_end = rdmcycle();
    mark(PHASE_A_END); // SAIF A ends immediately.

    // Handoff: finish AES without reissuing it; SHA/DMA keep running. ECC
    // starts only once AES reports idle, so aes/ecc busy never coincide.
    let handoff = rdmcycle();
    while engines.pending & LEG_AES != 0 {
        engines.step(keep);
        deadline(handoff, 0x81);
    }
    while !engines.aes.regs().status().read().idle() {
        deadline(handoff, 0xa5);
    }

    // Phase B: one complete ECC verify + SHA (+ DMA).
    engines.start_ecc();
    mark(PHASE_B_CAPTURE);
    let b_start = rdmcycle();
    while engines.pending & LEG_ECC != 0 {
        engines.step(keep);
        deadline_for(b_start, ECC_WAIT_CYCLES, 0x90);
    }
    let b_end = rdmcycle();
    mark(PHASE_B_END); // SAIF B ends immediately; drain/check/ACK are outside.

    let drain_start = rdmcycle();
    while engines.pending != 0 {
        engines.step(0);
        deadline(drain_start, 0x80 | engines.pending);
    }
    let flags = engines.check();
    if legs & LEG_DMA != 0 {
        mbox.regs_mut().unlock().write(|w| w.unlock(true));
    }
    let pass = flags == 15;
    let counts = engines.counts.map(saturate);
    shared_write(1, legs | (flags << 16) | ((pass as u32) << 20));
    shared_write(2, a_start);
    shared_write(3, a_end);
    shared_write(4, counts[0] | (counts[1] << 16));
    shared_write(5, counts[2] | (counts[3] << 16));
    shared_write(6, b_end.wrapping_sub(b_start));
    shared_write(0, RES_MAGIC);
    if external {
        await_ack(ACK_END);
    }
    mark(if pass { PHASE_DONE } else { PHASE_FAIL });
    // Host prints results. Keep this ROM small and avoid boot console latency.
    loop {
        unsafe { core::arch::asm!("nop") };
    }
}
