// Licensed under the Apache-2.0 license
//! Optional functional bridge to the real Aloha RTL testbench. No timing model.
use caliptra_emu_bus::{Bus, BusError};
use caliptra_emu_types::{RvAddr, RvData, RvSize};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

pub struct FheRtl(Option<Link>);
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
        Self(Some(Link {
            child,
            input,
            output,
            line: String::new(),
        }))
    }
    /// Word-aligned 32-bit accesses only; errors and a missing link fault.
    fn access(&mut self, size: RvSize, addr: RvAddr, write: bool, value: u32) -> Option<u32> {
        if size != RvSize::Word || addr & 3 != 0 {
            return None;
        }
        match self.0.as_mut()?.transaction(write, addr, value) {
            Ok(reply) => reply,
            Err(e) => {
                eprintln!("[Aloha RTL] link failed: {e}");
                None
            }
        }
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
