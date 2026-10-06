// Licensed under the Apache-2.0 license
// Run against the actual two-phase stress ROM, including its DMA-independent host
// scratch-register protocol.
// cargo run --release -p caliptra-emu --example peak_stress_check -- <peak_stress.bin>
// This checks functional results/deadlines/phase ordering, not RTL timing or power.
use caliptra_emu_bus::{Bus, BusError, Clock, ReadWriteMemory};
use caliptra_emu_cpu::{Cpu, CpuArgs, Pic, StepAction};
use caliptra_emu_periph::{CaliptraRootBus, CaliptraRootBusArgs};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::rc::Rc;

const AES: u32 = 1;
const SHA: u32 = 2;
const DMA: u32 = 4;
const ECC: u32 = 16;
const REQUIRED: u32 = AES | SHA | ECC;

struct TestBus {
    inner: CaliptraRootBus,
    stall_aes: u32,
    deny_dma: bool,
    legs: u32,
    launched: u32,
    phase: u32,
    saw_a: bool,
    saw_b: bool,
    aes_active: bool,
    ecc_launches: u32,
    bad_engine: u32,
}
impl Bus for TestBus {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        assert!(
            !(self.deny_dma && (0x3002_2000..0x3002_2a14).contains(&addr)),
            "DMA read on non-DMA test"
        );
        if self.bad_engine == 32 && self.saw_a && addr == 0x3003_0000 {
            return Ok(8); // Fatal crypto-error injection during phase A
        }
        if self.bad_engine == 33 && self.saw_b && addr == 0x3003_0000 {
            return Ok(8); // Fatal crypto-error injection during phase B
        }
        // AES STATUS: suppress readiness to exercise the ROM's bounded wait.
        if (self.stall_aes == 1 || (self.stall_aes == 2 && self.saw_a)) && addr == 0x1001_1084
        {
            return Ok(0);
        }
        if addr == 0x1002_0100 || addr == 0x1000_8400 {
            assert!(
                self.phase != 2 && self.phase != 6,
                "digest verification must be outside both windows"
            );
        }
        if addr == 0x1001_1070 {
            self.aes_active = false; // Last AES output word read
        }
        let value = self.inner.read(size, addr)?;
        let corrupt = matches!(
            (self.bad_engine, addr),
            (1, 0x1001_1064) | (2, 0x1002_0100) | (16, 0x1000_8400)
        );
        Ok(value ^ u32::from(corrupt))
    }
    fn write(&mut self, size: RvSize, addr: RvAddr, val: RvData) -> Result<(), BusError> {
        assert!(
            !(self.deny_dma && (0x3002_2000..0x3002_2a14).contains(&addr)),
            "DMA write on non-DMA test"
        );
        let command = match addr {
            0x1001_1060 => AES, // Fourth AES input word starts encryption
            0x1002_0010 => SHA,
            0x3002_2008 => DMA,
            0x1000_8010 => ECC,
            _ => 0,
        };
        match command {
            0 => {}
            AES => {
                // ARMED here means the launch right after the host's START.
                assert!(
                    matches!(self.phase, 5 | 2),
                    "AES launched outside phase A (phase {})",
                    self.phase
                );
                assert_eq!(self.ecc_launches, 0, "AES reissued after ECC started");
                self.aes_active = true;
            }
            ECC => {
                assert_eq!(self.phase, 4, "ECC must launch in the A->B handoff");
                assert!(!self.aes_active, "ECC launched while AES was busy");
                self.ecc_launches += 1;
                assert_eq!(self.ecc_launches, 1, "phase B runs exactly one ECC verify");
            }
            _ => assert!(
                matches!(self.phase, 5 | 2 | 4 | 6),
                "engine launched outside the stress phases (phase {})",
                self.phase
            ),
        }
        self.launched |= command;
        if addr == 0x3003_0038 {
            self.phase = val & 15;
            match self.phase {
                2 => {
                    assert_eq!(
                        self.launched,
                        self.legs & (AES | SHA | DMA),
                        "phase A engines must launch before its window"
                    );
                    self.saw_a = true;
                }
                6 => {
                    assert!(self.saw_a, "phase B before phase A");
                    assert_eq!(self.ecc_launches, 1);
                    self.saw_b = true;
                }
                _ => {}
            }
        }
        // The standalone baseline has a 4-KiB test SRAM, not Chipyard DRAM.
        // Check the firmware address, then map it only inside this test adapter.
        // Real fabric addressing is validated by RTL, not this emulator fixture.
        let val = if addr == 0x3002_2014 {
            assert_eq!(val, 0x8050_0000);
            0x0050_0000
        } else {
            val
        };
        self.inner.write(size, addr, val)
    }
    fn poll(&mut self) {
        self.inner.poll();
    }
}
const SHARED: u32 = 0x3003_0018;
fn wr(bus: &mut CaliptraRootBus, index: u32, val: u32) {
    bus.write(RvSize::Word, SHARED + index * 4, val).unwrap();
}
fn rd(bus: &mut CaliptraRootBus, index: u32) -> u32 {
    bus.read(RvSize::Word, SHARED + index * 4).unwrap()
}
fn run(
    rom: &[u8],
    legs: u32,
    window: u32,
    stall: u32,
    acknowledge: u32,
    bad_engine: u32,
    poll_stride: usize,
) {
    let clock = Rc::new(Clock::new());
    let pic = Rc::new(Pic::new());
    let mut bus = CaliptraRootBus::new(CaliptraRootBusArgs {
        rom: rom.to_vec(),
        clock: clock.clone(),
        pic: pic.clone(),
        log_dir: std::env::temp_dir(),
        ..Default::default()
    });
    if legs & DMA != 0 {
        bus.dma.axi.test_sram = Some(ReadWriteMemory::new());
        for i in 0..1024u32 {
            bus.dma
                .axi
                .write(
                    RvSize::Word,
                    0x0050_0000 + u64::from(i) * 4,
                    i.wrapping_mul(0x9e3779b9).wrapping_add(0x12345678)
                        ^ u32::from(bad_engine == 4),
                )
                .unwrap();
        }
    }
    wr(&mut bus, 0, 0x5a17c7a5);
    wr(&mut bus, 1, legs);
    wr(&mut bus, 2, window);
    let mut cpu = Cpu::new(
        TestBus {
            inner: bus,
            stall_aes: stall,
            deny_dma: legs & DMA == 0,
            legs,
            launched: 0,
            phase: 0,
            saw_a: false,
            saw_b: false,
            aes_active: false,
            ecc_launches: 0,
            bad_engine,
        },
        clock.clone(),
        pic,
        CpuArgs::default(),
    );
    let expect_pass = legs & REQUIRED == REQUIRED
        && legs & !(REQUIRED | DMA) == 0
        && (1024..=65536).contains(&window)
        && stall == 0
        && acknowledge == 2
        && bad_engine == 0;
    let mut saw_armed = false;
    let mut saw_a_steady = false;
    let mut saw_b_end = false;
    let mut terminal = 0;
    let mut fault_cycle = None;
    for step in 0..40_000_000u64 {
        let action = cpu.step(None);
        let injected = (bad_engine == 32 && cpu.bus.saw_a) || (bad_engine == 33 && cpu.bus.saw_b);
        if injected && fault_cycle.is_none() {
            fault_cycle = Some(clock.now());
        }
        if step % poll_stride as u64 == 0 {
            let marker = cpu.bus.inner.read(RvSize::Word, 0x3003_0038).unwrap();
            if marker & 0xfffff000 == 0x5a175000 {
                match marker & 15 {
                    5 => {
                        saw_armed = true;
                        if acknowledge >= 1 {
                            wr(&mut cpu.bus.inner, 7, 0x53544152);
                        }
                    }
                    2 => {
                        assert!(saw_armed);
                        saw_a_steady = true;
                    }
                    7 => {
                        saw_b_end = true;
                        if acknowledge == 2 {
                            wr(&mut cpu.bus.inner, 7, 0x454e4421);
                        }
                    }
                    3 | 15 => {
                        terminal = marker;
                        break;
                    }
                    _ => {}
                }
            }
        }
        if !matches!(action, StepAction::Continue) {
            terminal = cpu.bus.inner.read(RvSize::Word, 0x3003_0038).unwrap();
            break;
        }
    }
    assert_ne!(terminal, 0, "ROM exceeded instruction budget");
    assert_eq!(
        terminal & 15 == 3,
        expect_pass,
        "legs={legs} terminal={terminal:x}"
    );
    if expect_pass {
        assert!(saw_armed && cpu.bus.saw_a && cpu.bus.saw_b && saw_b_end);
        if poll_stride == 64 {
            assert!(saw_a_steady);
        }
        let bus = &mut cpu.bus.inner;
        assert_eq!(rd(bus, 0), 0x5a17d0e8);
        let config = rd(bus, 1);
        assert_eq!(config & 0xff, legs);
        assert_eq!((config >> 16) & 31, 31); // Four checks + overall pass
        let counts = [
            rd(bus, 4) & 0xffff,
            rd(bus, 4) >> 16,
            rd(bus, 5) & 0xffff,
            rd(bus, 5) >> 16,
        ];
        assert!(counts[0] > 0 && counts[1] > 0);
        assert_eq!(counts[2] > 0, legs & DMA != 0);
        assert_eq!(counts[3], 1, "exactly one ECC pass");
        let a_cycles = rd(bus, 3).wrapping_sub(rd(bus, 2));
        assert!(
            (window..window + 2048).contains(&a_cycles),
            "window={window} phase A={a_cycles}"
        );
        let b_cycles = rd(bus, 6);
        assert!(b_cycles > 0);
        println!(
            "PASS legs={legs} a_cycles={a_cycles} b_cycles={b_cycles} counts={counts:?} total_cycles={}",
            clock.now()
        );
    } else {
        if bad_engine == 32 || bad_engine == 33 {
            assert_eq!((terminal >> 4) & 255, 0xf0);
            assert!(
                clock.now() - fault_cycle.unwrap() < 100_000,
                "fatal error must fail promptly"
            );
        }
        if stall == 2 {
            assert!(cpu.bus.saw_a && !cpu.bus.saw_b);
        }
        println!(
            "PASS refusal/timeout legs={legs} stage={:x} cycles={}",
            (terminal >> 4) & 255,
            clock.now()
        );
    }
}
fn main() {
    let rom = std::fs::read(std::env::args().nth(1).expect("ROM path")).unwrap();
    let all = REQUIRED | DMA;
    // Non-DMA and DMA configurations.
    for legs in [REQUIRED, all] {
        run(&rom, legs, 4096, 0, 2, 0, 64);
    }
    for window in [1024, 65536] {
        run(&rom, all, window, 0, 2, 0, 64);
    }
    // Host can miss the short phase-A markers: ARMED/B_END acknowledgements still work.
    run(&rom, all, 1024, 0, 2, 0, 20000);
    // AES never ready during prepare; AES stalls inside phase A (handoff must time out).
    run(&rom, all, 4096, 1, 2, 0, 64);
    run(&rom, all, 4096, 2, 2, 0, 64);
    // Missing START or END acknowledgement.
    run(&rom, all, 4096, 0, 0, 0, 64);
    run(&rom, all, 4096, 0, 1, 0, 64);
    // AES, SHA and ECC are mandatory; unknown bits (including Rocket) are refused.
    for legs in [0, AES, SHA | ECC, AES | ECC, AES | SHA | DMA, REQUIRED | 8, all | 32] {
        run(&rom, legs, 4096, 0, 2, 0, 64);
    }
    for window in [0, 1023, 65537] {
        run(&rom, all, window, 0, 2, 0, 64);
    }
    // Fatal hardware error in either window.
    run(&rom, all, 4096, 0, 2, 32, 64);
    run(&rom, all, 4096, 0, 2, 33, 64);
    // Corrupt final result of each engine.
    for bad_engine in [1, 2, 4, 16] {
        run(&rom, all, 4096, 0, 2, bad_engine, 64);
    }
}
