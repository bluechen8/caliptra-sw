// Licensed under the Apache-2.0 license

//! Debug software-client kernels with synchronous mailbox/FIFO transport.
//! Polynomial scratch lives in command-owned mailbox SRAM; pointer output is
//! streamed by limb. No accelerator MMIO or authenticated session protocol.
use crate::{fhe_transport::Transport, mutrefbytes, Drivers};
use caliptra_common::mailbox_api::{
    CommandId, FheRawDecryptReq, FheRawEncryptReq, FheSwKeygenReq, FheSwResp, MailboxRespHeader,
};
use caliptra_drivers::memory_layout::{MBOX_ORG, MBOX_SIZE};
use caliptra_drivers::{CaliptraError, CaliptraResult};
use caliptra_fhe_core::{ntt, params, prg::ChaCha20Prg, rlwe, sample};
use caliptra_registers::mbox::enums::MboxStatusE;
use zerocopy::{FromBytes, IntoBytes};
use zeroize::{Zeroize, Zeroizing};

const INVALID: CaliptraError = CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS;
const FAILED: CaliptraError = CaliptraError::RUNTIME_FHE_DECRYPT_FAILED;
#[cfg(all(feature = "fhe-pl", feature = "fhe-pleq"))]
compile_error!("Select only one FHE parameter set");
#[cfg(feature = "fhe-pleq")]
const PARAM_ID: u32 = 2;
#[cfg(all(feature = "fhe-pl", not(feature = "fhe-pleq")))]
const PARAM_ID: u32 = 1;
#[cfg(not(any(feature = "fhe-pl", feature = "fhe-pleq")))]
const PARAM_ID: u32 = 0;
const PARAMS: &params::ParamSet = match PARAM_ID {
    1 => &params::PL,
    2 => &params::PLEQ,
    _ => &params::PS,
};
const N: usize = PARAMS.n;
const L: usize = PARAMS.level;
const PT_WORDS: usize = L * N;
const CT_WORDS: usize = 2 * PT_WORDS;
const RESP_BYTES: usize = core::mem::size_of::<FheSwResp>();

pub struct State {
    key: [u8; N / 4],
    session_id: u32,
    next_seq: u32,
    valid: bool,
    // Lifetime is the runtime, not one mailbox request or key generation.
    transport: Transport<()>,
}
impl State {
    pub fn new() -> Self {
        Self {
            key: [0; N / 4],
            session_id: 0,
            next_seq: 1,
            valid: false,
            transport: Transport::session(1_000_000),
        }
    }
    fn invalidate(&mut self) {
        self.key.zeroize();
        self.valid = false;
    }
}
impl Drop for State {
    fn drop(&mut self) {
        self.invalidate();
    }
}

fn cycles() -> u64 {
    #[cfg(target_arch = "riscv32")]
    unsafe {
        let (mut hi, mut lo, mut end): (u32, u32, u32);
        loop {
            core::arch::asm!("csrr {0}, mcycleh", "csrr {1}, mcycle", "csrr {2}, mcycleh",
                out(reg) hi, out(reg) lo, out(reg) end, options(nomem, nostack));
            if hi == end {
                return ((hi as u64) << 32) | lo as u64;
            }
        }
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        0
    }
}

fn response(resp: &mut [u8], session_id: u32, start: u64, output_len: usize) -> CaliptraResult<()> {
    let elapsed = cycles().wrapping_sub(start);
    let out = mutrefbytes::<FheSwResp>(resp)?;
    *out = FheSwResp {
        hdr: MailboxRespHeader::default(),
        status: 0,
        session_id,
        cycles_lo: elapsed as u32,
        cycles_hi: (elapsed >> 32) as u32,
        output_len: output_len as u32,
    };
    Ok(())
}

pub fn keygen(drivers: &mut Drivers, cmd: &[u8], resp: &mut [u8]) -> CaliptraResult<usize> {
    let start = cycles();
    let req = FheSwKeygenReq::ref_from_bytes(cmd).map_err(|_| INVALID)?;
    if req.version != 1
        || req.param_set != PARAM_ID
        || req.session_id != 0
        || req.seq != 0
        || req.seed_mode > 1
        || (req.seed_mode == 0 && req.seed != [0; 32])
        || drivers.fhe.transport.is_poisoned()
        || resp.len() < RESP_BYTES
    {
        return Err(INVALID);
    }
    let id = drivers.fhe.session_id.checked_add(1).ok_or(INVALID)?;
    drivers.fhe.invalidate();
    {
        let mut seed = Zeroizing::new(req.seed);
        if req.seed_mode == 0 {
            let entropy = Zeroizing::new(drivers.trng.generate()?);
            seed.copy_from_slice(&entropy.as_bytes()[..32]);
        }
        let mut prg = ChaCha20Prg::new(&seed);
        rlwe::keygen(&mut prg, N, &mut drivers.fhe.key).map_err(|_| INVALID)?;
    }
    drivers.fhe.session_id = id;
    drivers.fhe.next_seq = 1;
    drivers.fhe.valid = true;
    response(resp, id, start, 0)?;
    Ok(RESP_BYTES)
}

/// Owned metadata: parsing cannot keep a reference into command SRAM.
pub struct RawRequest {
    header: FheRawDecryptReq,
    encrypt: bool,
    seed_mode: u32,
    seed: Zeroizing<[u8; 32]>,
    header_words: usize,
}
impl RawRequest {
    pub fn parse(cmd: u32, bytes: &[u8]) -> CaliptraResult<Self> {
        let encrypt = cmd == u32::from(CommandId::FHE_ENCRYPT_RAW);
        let (header, seed_mode, seed, header_len) = if encrypt {
            let (r, _) = FheRawEncryptReq::read_from_prefix(bytes).map_err(|_| INVALID)?;
            (
                r.common,
                r.seed_mode,
                r.seed,
                core::mem::size_of::<FheRawEncryptReq>(),
            )
        } else {
            let (r, _) = FheRawDecryptReq::read_from_prefix(bytes).map_err(|_| INVALID)?;
            (r, 0, [0; 32], core::mem::size_of::<FheRawDecryptReq>())
        };
        let input_len = if encrypt { PT_WORDS * 4 } else { CT_WORDS * 4 };
        let output_len = if encrypt { CT_WORDS * 4 } else { PT_WORDS * 4 };
        if header.version != 1
            || header.param_set != PARAM_ID
            || header.mode > 1
            || header.input_len as usize != input_len
            || seed_mode > 1
            || (seed_mode == 0 && seed != [0; 32])
        {
            return Err(INVALID);
        }
        if header.mode == 0 {
            if bytes.len() != header_len + input_len
                || RESP_BYTES + output_len > MBOX_SIZE as usize
                || header.src_lo != 0
                || header.src_hi != 0
                || header.dst_lo != 0
                || header.dst_hi != 0
            {
                return Err(INVALID);
            }
        } else {
            if bytes.len() != header_len {
                return Err(INVALID);
            }
            let src = (u64::from(header.src_hi) << 32) | u64::from(header.src_lo);
            let dst = (u64::from(header.dst_hi) << 32) | u64::from(header.dst_lo);
            crate::fhe_transport::validate_range(src, input_len as u64).map_err(|_| INVALID)?;
            crate::fhe_transport::validate_range(dst, output_len as u64).map_err(|_| INVALID)?;
            if src < dst + output_len as u64 && dst < src + input_len as u64 {
                return Err(INVALID);
            }
        }
        Ok(Self {
            header,
            encrypt,
            seed_mode,
            seed: Zeroizing::new(seed),
            header_words: header_len / 4,
        })
    }
}

fn reduced(poly: &[u32], q: u32) -> CaliptraResult<()> {
    if poly.iter().any(|&v| v >= q) {
        Err(INVALID)
    } else {
        Ok(())
    }
}

/// Consumes the parsed request after Packet is dropped. Only this single-threaded
/// command owns SRAM; no mailbox reference survives to the DATAIN response phase.
pub fn raw(drivers: &mut Drivers, mut request: RawRequest) -> CaliptraResult<MboxStatusE> {
    let start = cycles();
    let state = &mut drivers.fhe;
    let req = &request.header;
    if !state.valid
        || state.transport.is_poisoned()
        || req.session_id != state.session_id
        || req.seq != state.next_seq
    {
        return Err(INVALID);
    }
    state.next_seq = state.next_seq.checked_add(1).ok_or(INVALID)?;
    let pointer = req.mode == 1;
    let src = (u64::from(req.src_hi) << 32) | u64::from(req.src_lo);
    let dst = (u64::from(req.dst_hi) << 32) | u64::from(req.dst_lo);
    let input_words = if request.encrypt { PT_WORDS } else { CT_WORDS };
    let output_words = if request.encrypt { CT_WORDS } else { PT_WORDS };
    let offset = if pointer { 0 } else { RESP_BYTES / 4 };
    // P-L-eq pointer encrypt: 128-KiB retained plaintext + three 32-KiB
    // scratches (c1, secret NTT, twiddles) = 224 KiB. Error stays on stack.
    // Pointer decrypt streams c0/c1 per limb: five polynomials = 160 KiB.
    // Mailbox P-L: encrypt 192 KiB + header; decrypt 224 KiB + header.
    let work_words = if pointer {
        if request.encrypt {
            PT_WORDS + 3 * N
        } else {
            5 * N
        }
    } else {
        offset + CT_WORDS + if request.encrypt { 2 * N } else { 3 * N }
    };
    if work_words * 4 > MBOX_SIZE as usize {
        return Err(INVALID);
    }
    let failure = if request.encrypt {
        CaliptraError::RUNTIME_FHE_ENCRYPT_FAILED
    } else {
        FAILED
    };
    let result = {
        // SAFETY: Packet and all its slices were consumed by handle_command;
        // addresses are aligned, within SRAM, and exclusively owned by the SoC
        // command's firmware phase. No direct-mailbox DMA is ever started.
        let workspace =
            unsafe { core::slice::from_raw_parts_mut(MBOX_ORG as *mut u32, work_words) };
        if !pointer {
            workspace.copy_within(
                request.header_words..request.header_words + input_words,
                offset,
            );
        }
        let result = (|| {
            if request.encrypt {
                if request.seed_mode == 0 {
                    let entropy = Zeroizing::new(drivers.trng.generate()?);
                    request.seed.copy_from_slice(&entropy.as_bytes()[..32]);
                }
                let mut prg = ChaCha20Prg::new(&request.seed);
                if request.seed_mode == 1 {
                    // Match WP0's seed->s->e->a stream without modifying the key.
                    let mut discarded = Zeroizing::new([0u8; N / 4]);
                    rlwe::keygen(&mut prg, N, &mut discarded[..]).map_err(|_| failure)?;
                }
                let mut error = Zeroizing::new([0i8; N]);
                sample::sample_cbd(&mut prg, &mut error[..]);
                let (c0, rest) = workspace[offset..].split_at_mut(PT_WORDS);
                let (c1, rest) = rest.split_at_mut(if pointer { N } else { PT_WORDS });
                let (secret, tw) = rest.split_at_mut(N);
                if pointer {
                    state
                        .transport
                        .with_fifo(&mut drivers.dma, |t| t.read(src, c0))
                        .map_err(|_| failure)?;
                }
                // Validate the entire retained input before any external write.
                for (li, p) in PARAMS.primes.iter().enumerate() {
                    reduced(&c0[li * N..(li + 1) * N], p.q)?;
                }
                for (li, p) in PARAMS.primes.iter().enumerate() {
                    let c0 = &mut c0[li * N..(li + 1) * N];
                    let c1 = if pointer {
                        &mut c1[..N]
                    } else {
                        &mut c1[li * N..(li + 1) * N]
                    };
                    ntt::gen_twiddles_fwd(N, p, tw).map_err(|_| failure)?;
                    rlwe::secret_ntt_limb(&state.key, p, tw, secret).map_err(|_| failure)?;
                    sample::sample_uniform(&mut prg, p.q, c1);
                    rlwe::encrypt_limb_in_place(c0, &error[..], c1, secret, p, tw)
                        .map_err(|_| failure)?;
                    if pointer {
                        state
                            .transport
                            .with_fifo(&mut drivers.dma, |t| {
                                t.write(dst + (li * N * 4) as u64, c0)?;
                                t.write(dst + ((L + li) * N * 4) as u64, c1)
                            })
                            .map_err(|_| failure)?;
                    }
                }
            } else {
                let (ct, rest) =
                    workspace[offset..].split_at_mut(if pointer { 2 * N } else { CT_WORDS });
                let (secret, rest) = rest.split_at_mut(N);
                let (tw, out) = rest.split_at_mut(N);
                if !pointer {
                    for (li, p) in PARAMS.primes.iter().enumerate() {
                        reduced(&ct[li * N..(li + 1) * N], p.q)?;
                        reduced(&ct[(L + li) * N..(L + li + 1) * N], p.q)?;
                    }
                }
                for (li, p) in PARAMS.primes.iter().enumerate() {
                    if pointer {
                        let (c0, c1) = ct.split_at_mut(N);
                        state
                            .transport
                            .with_fifo(&mut drivers.dma, |t| {
                                t.read(src + (li * N * 4) as u64, c0)?;
                                t.read(src + ((L + li) * N * 4) as u64, c1)
                            })
                            .map_err(|_| failure)?;
                        reduced(c0, p.q)?;
                        reduced(c1, p.q)?;
                    }
                    ntt::gen_twiddles_fwd(N, p, tw).map_err(|_| failure)?;
                    rlwe::secret_ntt_limb(&state.key, p, tw, secret).map_err(|_| failure)?;
                    ntt::gen_twiddles_inv(N, p, tw).map_err(|_| failure)?;
                    let (c0, c1) = if pointer {
                        (&ct[..N], &ct[N..])
                    } else {
                        (
                            &ct[li * N..(li + 1) * N],
                            &ct[(L + li) * N..(L + li + 1) * N],
                        )
                    };
                    rlwe::decrypt_limb(c0, c1, secret, p, tw, out).map_err(|_| failure)?;
                    if pointer {
                        state
                            .transport
                            .with_fifo(&mut drivers.dma, |t| {
                                t.write(dst + (li * N * 4) as u64, out)
                            })
                            .map_err(|_| failure)?;
                    } else {
                        ct[li * N..(li + 1) * N].copy_from_slice(out);
                    }
                }
            }
            Ok(())
        })();
        let keep = if !pointer && result.is_ok() {
            offset + output_words
        } else {
            0
        };
        workspace[keep..].zeroize();
        result
    };
    request.seed.zeroize();
    if let Err(error) = result {
        if state.transport.is_poisoned() {
            state.invalidate();
        }
        return Err(error);
    }
    let mut header = FheSwResp::default();
    response(
        header.as_mut_bytes(),
        state.session_id,
        start,
        output_words * 4,
    )?;
    let payload_len = if pointer { 0 } else { output_words * 4 };
    let payload_checksum = caliptra_common::checksum::calc_checksum(
        0,
        &drivers.mbox.raw_mailbox_contents()[RESP_BYTES..RESP_BYTES + payload_len],
    );
    header.hdr.chksum = caliptra_common::checksum::calc_checksum(0, &header.as_bytes()[4..])
        .wrapping_add(payload_checksum);
    drivers
        .mbox
        .write_response_from_mailbox(header.as_bytes(), payload_len)?;
    Ok(MboxStatusE::DataReady)
}
