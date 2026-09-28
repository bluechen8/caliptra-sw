// Licensed under the Apache-2.0 license
// Standalone: rustc --edition=2021 --test runtime/tests/fhe_transport.rs -o /tmp/fhe-transport-tests
#[path = "../src/fhe/transport.rs"]
mod transport;

use std::collections::VecDeque;
use transport::{Error, Fifo, Status, Transport};

#[derive(Default)]
struct Model {
    memory: Vec<u32>,
    fifo: VecDeque<u32>,
    total: usize,
    moved: usize,
    active: bool,
    write: bool,
    polls: usize,
    starts: usize,
    addr: u64,
    stall: bool,
    fail_after: Option<usize>,
    completion_error: bool,
    hold_completion: bool,
}

impl Fifo for &mut Model {
    fn status(&mut self) -> Status {
        self.polls += 1;
        if self.fail_after.is_some_and(|n| self.moved >= n) {
            return Status {
                error: true,
                ..Status::default()
            };
        }
        if self.active && !self.stall {
            if self.write {
                // Slow consumer: at most 16 words per poll.
                for _ in 0..16 {
                    if let Some(w) = self.fifo.pop_front() {
                        self.memory.push(w);
                        self.moved += 1;
                    }
                }
            } else {
                // Slow producer, bounded by the physical 128-word FIFO.
                for _ in 0..16 {
                    if self.moved < self.total && self.fifo.len() < 128 {
                        self.fifo.push_back(self.memory[self.moved]);
                        self.moved += 1;
                    }
                }
            }
            self.active = self.moved < self.total;
        }
        Status {
            busy: self.active,
            depth: self.fifo.len(),
            error: self.completion_error && self.starts != 0 && !self.active,
            pending: self.hold_completion && self.starts != 0,
        }
    }
    fn start(&mut self, addr: u64, bytes: u32, write: bool) {
        self.starts += 1;
        self.addr = addr;
        self.total = bytes as usize / 4;
        self.moved = 0;
        self.active = true;
        self.write = write;
    }
    fn read_word(&mut self) -> u32 {
        self.fifo.pop_front().expect("FIFO underflow")
    }
    fn write_word(&mut self, word: u32) {
        assert!(self.fifo.len() < 128, "FIFO overflow");
        self.fifo.push_back(word);
    }
}

#[test]
fn range_boundaries_and_high_bit_aliases() {
    for (addr, bytes) in [
        (0x8000_0000, 4),
        (0x1_7fff_fffc, 4),
        (0xffff_fffc, 8),
        (0x8000_0000, 262144),
    ] {
        assert_eq!(transport::validate_range(addr, bytes), Ok(()));
    }
    for (addr, bytes) in [
        (0x7fff_fffc, 4),
        (0x1_8000_0000, 4),
        (0x1_7fff_fffc, 8),
        (0x2_8000_0000, 4),
        (0x1_0000_8000_0000, 4),
        (u64::MAX - 3, 8),
        (0x8000_0000, u64::MAX),
        (0x8000_0000, 0),
        (0x8000_0001, 4),
        (0x8000_0000, 3),
        (0x8000_0000, 262148),
    ] {
        assert_eq!(
            transport::validate_range(addr, bytes),
            Err(Error::InvalidRange)
        );
    }
}

#[test]
fn invalid_request_never_touches_dma_and_scrubs_destination() {
    let mut m = Model::default();
    let mut out = [9; 16];
    let mut t = Transport::new(&mut m, 8);
    assert_eq!(t.read(0x2_8000_0000, &mut out), Err(Error::InvalidRange));
    assert_eq!(out, [0; 16]);
    assert_eq!(t.write(0x4000_0000, &[1]), Err(Error::InvalidRange));
    assert_eq!(m.polls, 0);
    assert_eq!(m.starts, 0);
}

#[test]
fn reads_and_writes_cover_tails_limbs_and_full_mailbox() {
    for words in [1, 63, 64, 65, 128, 129, 1024, 8192, 32768, 65536] {
        let data: Vec<u32> = (0..words)
            .map(|i| (i as u32).wrapping_mul(0x1234567))
            .collect();
        let mut r = Model {
            memory: data.clone(),
            ..Model::default()
        };
        let mut out = vec![0; words];
        Transport::new(&mut r, 32)
            .read(0xffff_fffc, &mut out)
            .unwrap();
        assert_eq!(out, data);
        assert_eq!(r.addr, 0xffff_fffc);
        if words >= 64 {
            assert!(r.polls < words, "poll was not hoisted");
        }
        let mut w = Model::default();
        Transport::new(&mut w, 32)
            .write(0x1_0000_0000, &out)
            .unwrap();
        assert_eq!(w.memory, data);
        assert!(!w.active);
        assert!(w.fifo.is_empty());
    }
}

#[test]
fn partial_read_fault_scrubs_and_poison_prevents_restart() {
    let mut m = Model {
        memory: vec![7; 256],
        fail_after: Some(80),
        ..Model::default()
    };
    let mut out = [9; 256];
    let mut t = Transport::new(&mut m, 8);
    assert_eq!(t.read(0x8000_0000, &mut out), Err(Error::Hardware));
    assert_eq!(out, [0; 256]);
    assert_eq!(t.write(0x8000_1000, &[1]), Err(Error::Poisoned));
    assert_eq!(m.starts, 1);
}

#[test]
fn stalled_read_and_full_write_fifo_have_bounded_waits() {
    for write in [false, true] {
        let mut m = Model {
            stall: true,
            ..Model::default()
        };
        let mut t = Transport::new(&mut m, 5);
        let mut data = [42; 256];
        let result = if write {
            t.write(0x8000_0000, &data)
        } else {
            t.read(0x8000_0000, &mut data)
        };
        assert_eq!(result, Err(Error::Timeout));
        assert_eq!(t.write(0x8000_1000, &[1]), Err(Error::Poisoned));
        assert!(m.polls <= 8);
        assert_eq!(m.starts, 1);
    }
}

#[test]
fn completion_errors_override_apparent_success() {
    for write in [false, true] {
        let mut m = Model {
            memory: if write { vec![] } else { vec![7; 64] },
            completion_error: true,
            ..Model::default()
        };
        let mut t = Transport::new(&mut m, 8);
        let mut data = [42; 64];
        let result = if write {
            t.write(0x8000_0000, &data)
        } else {
            t.read(0x8000_0000, &mut data)
        };
        assert_eq!(result, Err(Error::Hardware));
        if !write {
            assert_eq!(data, [0; 64]);
        }
    }
}

#[test]
fn refuses_preexisting_busy_or_dirty_engine() {
    let mut m = Model {
        active: true,
        stall: true,
        ..Model::default()
    };
    assert_eq!(
        Transport::new(&mut m, 8).write(0x8000_0000, &[1]),
        Err(Error::Busy)
    );
    assert_eq!(m.starts, 0);
    let mut m = Model {
        fifo: VecDeque::from([1]),
        ..Model::default()
    };
    assert_eq!(
        Transport::new(&mut m, 8).write(0x8000_0000, &[1]),
        Err(Error::Hardware)
    );
    assert_eq!(m.starts, 0);
}

#[test]
fn waits_for_go_clear_after_last_word() {
    let mut m = Model {
        memory: vec![7; 64],
        hold_completion: true,
        ..Model::default()
    };
    let mut out = [9; 64];
    assert_eq!(
        Transport::new(&mut m, 5).read(0x8000_0000, &mut out),
        Err(Error::Timeout)
    );
    assert_eq!(out, [0; 64]);
    assert_eq!(m.polls, 10); // initial idle + four fill polls + five completion polls
}

#[test]
fn session_poison_survives_register_driver_reborrowing() {
    let mut session = Transport::session(3);
    let mut stalled = Model {
        memory: vec![1; 64],
        stall: true,
        ..Model::default()
    };
    let mut out = [9; 64];
    assert_eq!(
        session.with_fifo(&mut stalled, |t| t.read(0x8000_0000, &mut out)),
        Err(Error::Timeout)
    );
    assert!(session.is_poisoned());
    assert_eq!(out, [0; 64]);
    // Even an apparently recovered, clean device cannot clear session poison.
    let mut clean = Model::default();
    assert_eq!(
        session.with_fifo(&mut clean, |t| t.write(0x8000_1000, &[1])),
        Err(Error::Poisoned)
    );
    assert_eq!(clean.polls, 0);
    assert_eq!(clean.starts, 0);
}
