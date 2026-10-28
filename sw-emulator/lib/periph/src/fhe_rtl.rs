// Licensed under the Apache-2.0 license
//! Optional functional bridge to the real Aloha RTL testbench. No timing model.
//!
//! The testbench holds Aloha, Caliptra's axi_dma and AES engine, and an AXI
//! memory. One RPC address space reaches all three: the FHE window at its
//! offset, the AES window at `RPC_AES` plus its offset, and the memory at its
//! SoC DRAM address (`RPC_DRAM` and up). While the link is up, firmware's AES
//! accesses go to the RTL engine, which the DMA drives during Aloha commands,
//! and the host reads and writes DRAM buffers in the testbench memory.
use crate::Aes;
use caliptra_emu_bus::{Bus, BusError, Event};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::cell::RefCell;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::ops::Range;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::rc::Rc;
use std::sync::mpsc;

const RPC_AES: u32 = 0x0001_0000;
/// The testbench memory: SoC DRAM addresses below 4 GiB.
pub const RPC_DRAM: Range<u64> = 0x8000_0000..1 << 32;
/// DRAM words per pipelined batch: the requests and their replies each stay
/// well inside the pipe buffers, so neither side blocks mid-batch.
const BATCH: usize = 1024;

/// Inactive (no link) by default.
#[derive(Clone, Default)]
pub struct FheRtl(Option<Rc<RefCell<Link>>>);
struct Link {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    line: String,
}
impl Drop for Link {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Link {
    /// One AHB access; `None` for an AHB ERROR response.
    fn transaction(&mut self, write: bool, addr: u32, value: u32) -> std::io::Result<Option<u32>> {
        let request = format!("{} {addr:08x} {value:08x}\n", u8::from(write));
        self.input.write_all(request.as_bytes())?;
        self.reply()
    }
    /// Independent accesses sent `BATCH` at a time before their replies are
    /// read; DRAM accesses take no simulated time and do not interact.
    fn batch(&mut self, requests: &[(bool, u32, u32)]) -> std::io::Result<Vec<Option<u32>>> {
        let mut replies = Vec::with_capacity(requests.len());
        let mut text = String::new();
        for chunk in requests.chunks(BATCH) {
            text.clear();
            for &(write, addr, value) in chunk {
                let _ = writeln!(text, "{} {addr:08x} {value:08x}", u8::from(write));
            }
            self.input.write_all(text.as_bytes())?;
            for _ in chunk {
                replies.push(self.reply()?);
            }
        }
        Ok(replies)
    }
    fn reply(&mut self) -> std::io::Result<Option<u32>> {
        let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidData);
        loop {
            self.line.clear();
            if self.output.read_line(&mut self.line)? == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            // Reply: "RPC <read data> <1 if AHB ERROR>"; anything else is RTL log.
            let Some(reply) = self.line.trim().strip_prefix("RPC ") else {
                eprint!("[Aloha RTL] {}", self.line);
                continue;
            };
            let (data, error) = reply.split_once(' ').ok_or_else(invalid)?;
            let data = u32::from_str_radix(data, 16).map_err(|_| invalid())?;
            return match error {
                "0" => Ok(Some(data)),
                "1" => Ok(None),
                _ => Err(invalid()),
            };
        }
    }
}
impl FheRtl {
    pub fn new() -> Self {
        let Some(exe) = std::env::var_os("FHE_ALOHA_RTL") else {
            return Self(None);
        };
        let cwd = std::env::var_os("FHE_ALOHA_RTL_CWD").expect("RTL table directory required");
        let mut child = Command::new(exe)
            .arg("+RPC")
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start Aloha RTL");
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self(Some(Rc::new(RefCell::new(Link {
            child,
            input,
            output,
            line: String::new(),
        }))))
    }
    pub fn active(&self) -> bool {
        self.0.is_some()
    }
    /// Word-aligned 32-bit accesses only; errors and a missing link fault.
    fn access(&mut self, size: RvSize, addr: RvAddr, write: bool, value: u32) -> Option<u32> {
        if size != RvSize::Word || addr & 3 != 0 {
            return None;
        }
        match self
            .0
            .as_ref()?
            .borrow_mut()
            .transaction(write, addr, value)
        {
            Ok(reply) => reply,
            Err(e) => {
                eprintln!("[Aloha RTL] link failed: {e}");
                None
            }
        }
    }
    /// Word accesses to `len` bytes of testbench memory at a DRAM address.
    fn dram(&mut self, addr: u64, len: usize, write: Option<&[u8]>) -> Vec<u32> {
        assert!(
            RPC_DRAM.contains(&addr)
                && addr % 4 == 0
                && len % 4 == 0
                && addr + len as u64 <= RPC_DRAM.end,
            "testbench DRAM access out of range"
        );
        let requests: Vec<_> = (0..len / 4)
            .map(|i| {
                let value = write.map_or(0, |d| {
                    u32::from_le_bytes(d[4 * i..4 * i + 4].try_into().unwrap())
                });
                (write.is_some(), addr as u32 + 4 * i as u32, value)
            })
            .collect();
        let link = self.0.as_ref().expect("Aloha RTL link");
        let replies = link.borrow_mut().batch(&requests).expect("Aloha RTL link");
        replies
            .into_iter()
            .map(|r| r.expect("testbench DRAM access"))
            .collect()
    }
    /// Host write of a buffer into the testbench memory at a DRAM address.
    pub fn dram_write(&mut self, addr: u64, data: &[u8]) {
        self.dram(addr, data.len(), Some(data));
    }
    /// Host read of a buffer from the testbench memory at a DRAM address.
    pub fn dram_read(&mut self, addr: u64, len: usize) -> Vec<u8> {
        self.dram(addr, len, None)
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect()
    }
}

/// Caliptra's AES window: the RTL engine while the link is up, else the model.
pub struct AesRoute {
    model: Aes,
    rtl: FheRtl,
}
impl AesRoute {
    pub fn new(model: Aes, rtl: FheRtl) -> Self {
        Self { model, rtl }
    }
}
impl Bus for AesRoute {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        if !self.rtl.active() {
            return self.model.read(size, addr);
        }
        Bus::read(&mut self.rtl, size, RPC_AES + addr)
    }
    fn write(&mut self, size: RvSize, addr: RvAddr, value: RvData) -> Result<(), BusError> {
        if !self.rtl.active() {
            return self.model.write(size, addr, value);
        }
        Bus::write(&mut self.rtl, size, RPC_AES + addr, value)
    }
    fn poll(&mut self) {
        self.model.poll()
    }
    fn warm_reset(&mut self) {
        self.model.warm_reset()
    }
    fn update_reset(&mut self) {
        self.model.update_reset()
    }
    fn incoming_event(&mut self, event: Rc<Event>) {
        self.model.incoming_event(event)
    }
    fn register_outgoing_events(&mut self, sender: mpsc::Sender<Event>) {
        self.model.register_outgoing_events(sender)
    }
}
impl Bus for FheRtl {
    fn read(&mut self, size: RvSize, addr: RvAddr) -> Result<RvData, BusError> {
        self.access(size, addr, false, 0)
            .ok_or(BusError::LoadAccessFault)
    }
    fn write(&mut self, size: RvSize, addr: RvAddr, value: RvData) -> Result<(), BusError> {
        self.access(size, addr, true, value)
            .map(|_| ())
            .ok_or(BusError::StoreAccessFault)
    }
}
