//! Hash-bound, one-shot hardware diagnostics for the fixed lab probe only.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::{
    Foundation::*, Security::Cryptography::CryptHashCertificate2, System::Diagnostics::Debug::*,
};
// windows-sys 0.52 models x64 CONTEXT with natural alignment only. Windows
// context APIs require a 16-byte-aligned buffer, including debug-only writes.
#[repr(C, align(16))]
struct AlignedContext {
    context: CONTEXT,
}
const _: () = assert!(std::mem::align_of::<AlignedContext>() >= 16);
const _: () = assert!(std::mem::offset_of!(AlignedContext, context) == 0);

const ENTRY: u64 = 0x1de80;
const SITES: [u64; 4] = [0x1df09, 0x1df3a, 0x1ec25, 0x1dfc4];
const HASH: &str = "9e91b726a67d75fbe3cc9e74fbe70332c8d9f8726cffba49370a5e6bc73e4635";
#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Evidence {
    pub status: String,
    pub hits: Vec<Hit>,
    pub failure_stage: Option<String>,
    pub win32: Option<u32>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Hit {
    site_rva: u64,
    eax: u32,
}
#[derive(Default)]
pub(crate) struct State {
    thread: HANDLE,
    tid: u32,
    base: u64,
    saved: Option<[u64; 6]>,
    active: u8,
    attach: bool,
    stack: u64,
    finished: bool,
}
fn file_offset(bytes: &[u8], rva: usize) -> Result<usize> {
    fn u16at(b: &[u8], n: usize) -> Result<u16> {
        Ok(u16::from_le_bytes(
            b.get(n..n + 2)
                .ok_or_else(|| anyhow::anyhow!("image bounds"))?
                .try_into()?,
        ))
    }
    fn u32at(b: &[u8], n: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(
            b.get(n..n + 4)
                .ok_or_else(|| anyhow::anyhow!("image bounds"))?
                .try_into()?,
        ))
    }
    ensure!(bytes.get(..2) == Some(b"MZ"), "image format");
    let pe = u32at(bytes, 60)? as usize;
    ensure!(
        bytes.get(pe..pe + 4) == Some(b"PE\0\0") && u16at(bytes, pe + 4)? == 0x8664,
        "image architecture"
    );
    let count = u16at(bytes, pe + 6)? as usize;
    let table = pe + 24 + u16at(bytes, pe + 20)? as usize;
    ensure!((1..=96).contains(&count), "image sections");
    let mut result = None;
    for i in 0..count {
        let at = table + i * 40;
        let start = u32at(bytes, at + 12)? as usize;
        let size = u32at(bytes, at + 16)? as usize;
        let raw = u32at(bytes, at + 20)? as usize;
        if rva >= start && rva - start < size {
            ensure!(
                u32at(bytes, at + 36)? & 0x20000000 != 0 && result.is_none(),
                "image executable mapping"
            );
            let offset = raw
                .checked_add(rva - start)
                .ok_or_else(|| anyhow::anyhow!("image overflow"))?;
            ensure!(offset < bytes.len(), "image file bounds");
            result = Some(offset);
        }
    }
    result.ok_or_else(|| anyhow::anyhow!("image RVA unavailable"))
}
pub(crate) fn validate_image(bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= 8 * 1024 * 1024, "image size");
    let mut digest = [0u8; 32];
    let mut len = 32;
    ensure!(
        unsafe {
            CryptHashCertificate2(
                crate::winutil::to_wide("SHA256").as_ptr(),
                0,
                std::ptr::null_mut(),
                bytes.as_ptr(),
                bytes.len() as u32,
                digest.as_mut_ptr(),
                &mut len,
            )
        } != 0
            && len == 32,
        "image digest"
    );
    ensure!(
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            == HASH,
        "image hash mismatch"
    );
    for (call, target) in [
        (0x1df04usize, 0x1dd88i64),
        (0x1df35, 0x1ec1c),
        (0x1ec20, 0x10910),
    ] {
        let at = file_offset(bytes, call)?;
        let instruction = bytes
            .get(at..at + 5)
            .ok_or_else(|| anyhow::anyhow!("call bounds"))?;
        ensure!(
            instruction[0] == 0xe8
                && call as i64 + 5 + i32::from_le_bytes(instruction[1..].try_into()?) as i64
                    == target,
            "call identity mismatch"
        );
    }
    ensure!(
        bytes[file_offset(bytes, SITES[3] as usize)?] == 0xc3,
        "return identity mismatch"
    );
    file_offset(bytes, ENTRY as usize)?;
    for site in SITES {
        file_offset(bytes, site as usize)?;
    }
    Ok(())
}
impl State {
    pub fn created(&mut self, thread: HANDLE, tid: u32) {
        self.thread = thread;
        self.tid = tid;
    }
    unsafe fn context(&self, evidence: &mut Evidence) -> Result<CONTEXT> {
        ensure!(self.thread != 0, "primary thread unavailable");
        let mut aligned: AlignedContext = std::mem::zeroed();
        let context = &mut aligned.context;
        ensure!(
            (context as *mut CONTEXT as usize) % 16 == 0,
            "context buffer alignment"
        );
        context.ContextFlags =
            CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64 | CONTEXT_DEBUG_REGISTERS_AMD64;
        if GetThreadContext(self.thread, context) == 0 {
            let code = GetLastError();
            evidence.failure_stage = Some("get_thread_context".into());
            evidence.win32 = Some(code);
            anyhow::bail!("diagnostic GetThreadContext failed win32={code}");
        }
        Ok(*context)
    }
    unsafe fn set_debug(&self, values: [u64; 6], evidence: &mut Evidence) -> Result<()> {
        let mut aligned: AlignedContext = std::mem::zeroed();
        let context = &mut aligned.context;
        ensure!(
            (context as *mut CONTEXT as usize) % 16 == 0,
            "context buffer alignment"
        );
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
        [
            context.Dr0,
            context.Dr1,
            context.Dr2,
            context.Dr3,
            context.Dr6,
            context.Dr7,
        ] = values;
        if SetThreadContext(self.thread, context) == 0 {
            let code = GetLastError();
            evidence.failure_stage = Some("set_thread_debug_context".into());
            evidence.win32 = Some(code);
            anyhow::bail!("diagnostic SetThreadContext failed win32={code}");
        }
        let readback = self.context(evidence)?;
        evidence.failure_stage = Some("debug_register_readback".into());
        ensure!(
            [readback.Dr0, readback.Dr1, readback.Dr2, readback.Dr3] == values[..4]
                && (readback.Dr7 ^ values[5]) & 0xffff00ff == 0
                && (readback.Dr6 ^ values[4]) & 0xe00f == 0,
            "diagnostic debug-register readback mismatch"
        );
        evidence.failure_stage = None;
        Ok(())
    }
    pub unsafe fn arm(
        &mut self,
        tid: u32,
        base: u64,
        bytes: &[u8],
        evidence: &mut Evidence,
    ) -> Result<()> {
        ensure!(
            !self.finished && self.base == 0 && self.saved.is_none() && tid == self.tid,
            "diagnostic load/thread mismatch"
        );
        evidence.failure_stage = Some("image_or_thread_validation".into());
        validate_image(bytes)?;
        ensure!(
            base.checked_add(0x8000000).is_some(),
            "diagnostic image overflow"
        );
        let c = self.context(evidence)?;
        ensure!(
            c.Dr7 & 0xff == 0 && c.Dr7 & (1 << 13) == 0 && c.EFlags & 0x100 == 0,
            "preexisting debug state"
        );
        self.saved = Some([c.Dr0, c.Dr1, c.Dr2, c.Dr3, c.Dr6, c.Dr7]);
        self.base = base;
        self.set_debug(
            [
                base + ENTRY,
                0,
                0,
                0,
                c.Dr6 & !15,
                (c.Dr7 & !0xffff00ff) | 1,
            ],
            evidence,
        )?;
        self.active = 1;
        evidence.status = "entry_armed".into();
        evidence.failure_stage = None;
        Ok(())
    }
    pub unsafe fn exception(
        &mut self,
        tid: u32,
        address: u64,
        evidence: &mut Evidence,
    ) -> Result<bool> {
        evidence.failure_stage = Some("trap_or_frame_validation".into());
        ensure!(self.active != 0, "unowned single-step diagnostic event");
        ensure!(tid == self.tid, "diagnostic trap thread mismatch");
        let c = self.context(evidence)?;
        let hit = (c.Dr6 & 15) as u8;
        ensure!(
            hit.count_ones() == 1 && hit & self.active == hit && c.Dr6 & 0xe000 == 0,
            "diagnostic trap status mismatch"
        );
        let index = hit.trailing_zeros() as usize;
        let site = if self.attach { SITES[index] } else { ENTRY };
        ensure!(
            address == self.base + site && c.Rip == self.base + site,
            "diagnostic trap address mismatch"
        );
        if !self.attach {
            ensure!(c.Rdx == 1, "diagnostic callback is not process attach");
            self.stack = c.Rsp;
            self.attach = true;
            self.active = 15;
            let saved = self.saved.unwrap();
            self.set_debug(
                [
                    self.base + SITES[0],
                    self.base + SITES[1],
                    self.base + SITES[2],
                    self.base + SITES[3],
                    c.Dr6 & !15,
                    (saved[5] & !0xffff00ff) | 0x55,
                ],
                evidence,
            )?;
            evidence.status = "attach_sites_armed".into();
        } else {
            ensure!(evidence.hits.len() < 4, "diagnostic hit limit");
            if index == 3 {
                ensure!(c.Rsp == self.stack, "diagnostic return frame mismatch");
            }
            evidence.hits.push(Hit {
                site_rva: site,
                eax: c.Rax as u32,
            });
            self.active &= !hit;
            if index == 3 {
                self.restore(evidence)?;
                self.finished = true;
                evidence.status = "attach_return_observed".into();
            } else {
                self.set_debug(
                    [
                        c.Dr0,
                        c.Dr1,
                        c.Dr2,
                        c.Dr3,
                        c.Dr6 & !15,
                        c.Dr7 & !(3u64 << (index * 2)),
                    ],
                    evidence,
                )?;
            }
        }
        evidence.failure_stage = None;
        Ok(true)
    }
    pub unsafe fn restore(&mut self, evidence: &mut Evidence) -> Result<()> {
        if let Some(saved) = self.saved {
            let prior = if evidence.status == "diagnostic_failed" {
                Some((evidence.failure_stage.clone(), evidence.win32))
            } else {
                None
            };
            self.set_debug(saved, evidence)?;
            if let Some((stage, code)) = prior {
                evidence.failure_stage = stage;
                evidence.win32 = code;
            }
            self.saved = None;
            self.active = 0;
            if evidence.status != "diagnostic_failed" {
                evidence.status = "debug_registers_restored".into();
            }
        }
        Ok(())
    }
    pub fn primary_exited(&mut self, tid: u32) {
        if tid == self.tid {
            self.thread = 0;
            self.saved = None;
            self.active = 0;
        }
    }
    pub fn process_exited(&mut self, evidence: &mut Evidence) {
        if !self.finished && evidence.status != "diagnostic_failed" {
            evidence.status = "process_exited_without_verified_attach_return".into();
        }
        self.thread = 0;
        self.saved = None;
        self.active = 0;
    }
    pub fn is_module(&self, base: u64) -> bool {
        self.base != 0 && base == self.base
    }
}
