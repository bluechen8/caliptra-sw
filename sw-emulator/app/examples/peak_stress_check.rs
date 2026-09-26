// Licensed under the Apache-2.0 license
// Run against the actual stress ROM, including its DMA-independent host scratch-register protocol.
// cargo run --release -p caliptra-emu --example peak_stress_check -- <peak_stress.bin>
// This checks functional results/deadlines, not RTL FIFO timing or power.
use caliptra_emu_bus::{Bus, BusError, Clock, ReadWriteMemory};
use caliptra_emu_cpu::{Cpu, CpuArgs, Pic, StepAction};
use caliptra_emu_periph::{CaliptraRootBus, CaliptraRootBusArgs};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::rc::Rc;

struct TestBus {
    inner: CaliptraRootBus,
    stall_aes: u32,
    deny_dma: bool,
    legs: u32,
    launched: u32,
    phase: u32,
    saw_capture: bool,
    bad_engine: u32,
}
impl Bus for TestBus {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        assert!(
            !(self.deny_dma && (0x3002_2000..0x3002_2a14).contains(&addr)),
            "DMA read on non-DMA test"
        );
        if self.bad_engine == 32 && self.saw_capture && addr == 0x3003_0000 {
            return Ok(8); // Fatal crypto-error injection
        }
        // AES STATUS: suppress readiness to exercise the ROM's bounded wait.
        if (self.stall_aes == 1 || (self.stall_aes == 2 && self.saw_capture)) && addr == 0x1001_1084
        {
            return Ok(0);
        }
        if addr == 0x1002_0100 || addr == 0x1000_8400 {
            assert_ne!(self.phase, 2, "digest verification must be outside capture");
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
            0x1001_1060 => 1, // Fourth AES input word starts encryption
            0x1002_0010 => 2,
            0x3002_2008 => 4,
            0x1000_8010 => 16,
            _ => 0,
        };
        if command != 0 {
            assert!(
                self.phase == 5 || self.phase == 2,
                "engine launched outside prepared/capture phase"
            );
            self.launched |= command;
        }
        if addr == 0x3003_0038 {
            self.phase = val & 15;
            if self.phase == 2 {
                assert_eq!(
                    self.launched, self.legs,
                    "all engines must launch before capture"
                );
                self.saw_capture = true;
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
    if legs & 4 != 0 {
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
    wr(&mut bus, 0, 0x5a17c7a4);
    wr(&mut bus, 1, legs);
    wr(&mut bus, 2, window);
    let mut cpu = Cpu::new(
        TestBus {
            inner: bus,
            stall_aes: stall,
            deny_dma: legs & 4 == 0,
            legs,
            launched: 0,
            phase: 0,
            saw_capture: false,
            bad_engine,
        },
        clock.clone(),
        pic,
        CpuArgs::default(),
    );
    let expect_pass = legs != 0
        && legs & !23 == 0
        && legs & 17 != 17
        && (1024..=65536).contains(&window)
        && stall == 0
        && acknowledge == 2
        && bad_engine == 0;
    let mut saw_armed = false;
    let mut saw_steady = false;
    let mut saw_drain = false;
    let mut terminal = 0;
    let mut capture_cycle = None;
    for step in 0..4_000_000 {
        let action = cpu.step(None);
        if cpu.bus.saw_capture && capture_cycle.is_none() {
            capture_cycle = Some(clock.now());
        }
        if step % poll_stride == 0 {
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
                        saw_steady = true;
                    }
                    4 => {
                        saw_drain = true;
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
        assert!(saw_armed && cpu.bus.saw_capture && saw_drain);
        if poll_stride == 64 {
            assert!(saw_steady);
        }
        let bus = &mut cpu.bus.inner;
        assert_eq!(rd(bus, 0), 0x5a17d0e7);
        let config = rd(bus, 1);
        assert_eq!(config & 0xff, legs);
        assert_eq!((config >> 16) & 31, 31); // Four checks + overall pass
        assert_eq!(rd(bus, 6), window);
        let counts = [
            rd(bus, 4) & 0xffff,
            rd(bus, 4) >> 16,
            rd(bus, 5) & 0xffff,
            rd(bus, 5) >> 16,
        ];
        for (bit, count) in [1, 2, 4, 16].into_iter().zip(counts) {
            assert_eq!(count > 0, legs & bit != 0);
        }
        let elapsed = rd(bus, 3).wrapping_sub(rd(bus, 2));
        assert!(
            (window..window + 2048).contains(&elapsed),
            "window={window} elapsed={elapsed}"
        );
        println!(
            "PASS legs={legs} capture_cycles={elapsed} total_cycles={}",
            clock.now()
        );
    } else {
        if bad_engine == 32 {
            assert_eq!((terminal >> 4) & 255, 0xf0);
            assert!(
                clock.now() - capture_cycle.unwrap() < 100_000,
                "fatal error must fail promptly"
            );
        }
        if stall == 2 {
            assert!(cpu.bus.saw_capture && saw_drain);
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
    for legs in [1, 2, 4, 16, 3, 7, 18, 22] {
        run(&rom, legs, 4096, 0, 2, 0, 64);
    }
    for window in [1024, 65536] {
        run(&rom, 7, window, 0, 2, 0, 64);
    }
    // Host can miss CAPTURE entirely: ARMED/DRAIN acknowledgements still work.
    run(&rom, 7, 1024, 0, 2, 0, 20000);
    run(&rom, 1, 4096, 1, 2, 0, 64);
    run(&rom, 1, 4096, 2, 2, 0, 64);
    run(&rom, 7, 4096, 0, 0, 0, 64);
    run(&rom, 7, 4096, 0, 1, 0, 64);
    run(&rom, 0, 4096, 0, 2, 0, 64);
    run(&rom, 8, 4096, 0, 2, 0, 64);
    for legs in [17, 19, 23] {
        run(&rom, legs, 4096, 0, 2, 0, 64);
    }
    for window in [0, 1023, 65537] {
        run(&rom, 7, window, 0, 2, 0, 64);
    }
    run(&rom, 7, 4096, 0, 2, 32, 64);
    for bad_engine in [1, 2, 4, 16] {
        run(&rom, bad_engine, 4096, 0, 2, bad_engine, 64);
    }
}
