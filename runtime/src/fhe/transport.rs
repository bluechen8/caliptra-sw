// Licensed under the Apache-2.0 license

//! Synchronous software-client pointer transport through the AHB FIFO (v3).
//!
//! The caller owns the DMA engine exclusively for the session and supplies
//! disjoint, protected local slices (DCCM or mailbox during MBOX_EXECUTE_UC).
//! This module never takes the mailbox lock or uses the direct DMA mailbox route.
//! Copy/validate the request out of Packet before lending mailbox SRAM mutably.
//! Returned mailbox payloads still require DATAIN streaming by the command layer.
//!
//! A read is an untrusted snapshot, not authentication. Authenticate these exact
//! retained bytes before kernel use; never authenticate DRAM and then reread it.
//! On hardware failure the transport is poisoned. The caller must fail the
//! session, scrub local secrets, and reset/quiesce DMA before reclaiming external
//! output buffers. A timeout does not cancel outstanding AXI writes.

const DRAM_START: u64 = 0x8000_0000;
const DRAM_END: u64 = 0x1_8000_0000;
const MAX_BYTES: u64 = 256 * 1024;
const CHUNK_WORDS: usize = 64;
const FIFO_WORDS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidRange,
    Busy,
    Hardware,
    Timeout,
    Poisoned,
}

/// Validate the full host-supplied address before any narrowing or MMIO.
/// Empty transfers are rejected; callers handle optional empty payloads locally.
pub fn validate_range(addr: u64, bytes: u64) -> Result<(), Error> {
    let end = addr.checked_add(bytes).ok_or(Error::InvalidRange)?;
    if bytes == 0
        || bytes > MAX_BYTES
        || (addr | bytes) & 3 != 0
        || addr < DRAM_START
        || end > DRAM_END
    {
        return Err(Error::InvalidRange);
    }
    Ok(())
}

#[derive(Clone, Copy, Default)]
pub struct Status {
    pub busy: bool,
    pub error: bool,
    pub depth: usize,
    // Include GO to avoid mistaking the pre-start idle cycle for completion.
    pub pending: bool,
}

/// Register seam for fault injection. Implementations must perform bounded MMIO
/// operations only. `start` uses incrementing addresses and AHB FIFO exclusively.
pub trait Fifo {
    fn status(&mut self) -> Status;
    fn start(&mut self, addr: u64, bytes: u32, write: bool);
    fn read_word(&mut self) -> u32;
    fn write_word(&mut self, word: u32);
}

pub struct Transport<F> {
    fifo: F,
    poll_limit: u32,
    poisoned: bool,
}

// Keep this owner in runtime state across commands, borrowing the shared DMA
// register driver only for an operation. Rebinding never clears poison.
impl Transport<()> {
    pub fn session(poll_limit: u32) -> Self {
        Self {
            fifo: (),
            poll_limit,
            poisoned: false,
        }
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub fn with_fifo<F: Fifo, T>(&mut self, fifo: F, op: impl FnOnce(&mut Transport<F>) -> T) -> T {
        let mut active = Transport {
            fifo,
            poll_limit: self.poll_limit,
            poisoned: self.poisoned,
        };
        let result = op(&mut active);
        self.poisoned = active.poisoned;
        result
    }
}

impl<F: Fifo> Transport<F> {
    /// Poll limit applies to each wait, in status observations, not clock cycles.
    /// It must be calibrated on independent 20 MHz core/link clocks later.
    pub fn new(fifo: F, poll_limit: u32) -> Self {
        Self {
            fifo,
            poll_limit,
            poisoned: false,
        }
    }

    fn wait(&mut self, ready: impl Fn(Status) -> bool) -> Result<(), Error> {
        for _ in 0..self.poll_limit {
            let s = self.fifo.status();
            if s.error || s.depth > FIFO_WORDS {
                return Err(Error::Hardware);
            }
            if ready(s) {
                return Ok(());
            }
        }
        Err(Error::Timeout)
    }

    fn begin(&mut self, addr: u64, words: usize, write: bool) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let bytes = (words as u64).checked_mul(4).ok_or(Error::InvalidRange)?;
        validate_range(addr, bytes)?;
        let s = self.fifo.status();
        if s.error || s.depth != 0 {
            self.poisoned = true;
            return Err(Error::Hardware);
        }
        if s.busy || s.pending {
            self.poisoned = true;
            return Err(Error::Busy);
        }
        self.fifo.start(addr, bytes as u32, write);
        Ok(())
    }

    fn finish(&mut self) -> Result<(), Error> {
        self.wait(|s| !s.busy && !s.pending && s.depth == 0)
    }

    /// On any failure erase the entire destination, including a partial read.
    pub fn read(&mut self, addr: u64, out: &mut [u32]) -> Result<(), Error> {
        let result = self.read_inner(addr, out);
        if result.is_err() {
            for word in out {
                // SAFETY: exclusive destination; volatile prevents dead-store
                // removal when the command immediately discards the scratch.
                unsafe { core::ptr::write_volatile(word, 0) };
            }
        }
        result
    }

    fn read_inner(&mut self, addr: u64, out: &mut [u32]) -> Result<(), Error> {
        self.begin(addr, out.len(), false)?;
        let result = (|| {
            for chunk in out.chunks_mut(CHUNK_WORDS) {
                self.wait(|s| s.depth >= chunk.len())?;
                for word in chunk {
                    *word = self.fifo.read_word();
                }
            }
            self.finish()
        })();
        self.poisoned |= result.is_err();
        result
    }

    /// Write caller-owned words; output may be partial on error and must not be
    /// published as a valid ciphertext/blob. Source zeroization is caller-owned.
    pub fn write(&mut self, addr: u64, input: &[u32]) -> Result<(), Error> {
        self.begin(addr, input.len(), true)?;
        let result = (|| {
            for chunk in input.chunks(CHUNK_WORDS) {
                self.wait(|s| FIFO_WORDS - s.depth >= chunk.len())?;
                for &word in chunk {
                    self.fifo.write_word(word);
                }
            }
            self.finish()
        })();
        self.poisoned |= result.is_err();
        result
    }
}

// The host fault-injection tests include this source without firmware crates.
// Firmware cargo checks compile this adapter against the generated registers.
#[cfg(not(test))]
impl Fifo for &mut caliptra_drivers::Dma {
    fn status(&mut self) -> Status {
        self.with_dma(|d| {
            let s = d.status0().read();
            let c = d.ctrl().read();
            let errors: u32 = d.intr_block_rf().error_internal_intr_r().read().into();
            Status {
                busy: s.busy(),
                error: s.error() || errors != 0,
                depth: s.fifo_depth() as usize,
                pending: c.go() || c.flush(),
            }
        })
    }

    fn start(&mut self, addr: u64, bytes: u32, write: bool) {
        use caliptra_registers::axi_dma::enums::{RdRouteE, WrRouteE};
        self.with_dma(|d| {
            d.src_addr_l()
                .write(|_| if write { 0 } else { addr as u32 });
            d.src_addr_h()
                .write(|_| if write { 0 } else { (addr >> 32) as u32 });
            d.dst_addr_l()
                .write(|_| if write { addr as u32 } else { 0 });
            d.dst_addr_h()
                .write(|_| if write { (addr >> 32) as u32 } else { 0 });
            d.byte_count().write(|_| bytes);
            // Nonzero BLOCK_SIZE selects subsystem recovery handshaking.
            // 256-byte chunks here are software drain/feed batches, not that mode.
            d.block_size().write(|w| w.size(0));
            d.ctrl().write(|w| {
                w.rd_route(|_| {
                    if write {
                        RdRouteE::Disable
                    } else {
                        RdRouteE::AhbFifo
                    }
                })
                .wr_route(|_| {
                    if write {
                        WrRouteE::AhbFifo
                    } else {
                        WrRouteE::Disable
                    }
                })
                .rd_fixed(false)
                .wr_fixed(false)
                .go(true)
            });
        });
    }
    fn read_word(&mut self) -> u32 {
        self.with_dma(|d| d.read_data().read())
    }
    fn write_word(&mut self, word: u32) {
        self.with_dma(|d| d.write_data().write(|_| word));
    }
}
