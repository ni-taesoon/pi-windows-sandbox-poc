//! Product credential store: atomic protected object creation and handle-relative,
//! no-reparse access. Machine DPAPI requires this DACL; encryption alone is not
//! authorization. Existing directories are never adopted during provisioning.
use super::{no_reparse_dir as nr, to_wide};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::windows::io::{AsRawHandle, OwnedHandle},
    path::Path,
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{LocalFree, HLOCAL},
    Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_FILE_OBJECT,
    },
    Security::{DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR},
    Storage::FileSystem::{
        FILE_READ_DATA, FILE_SHARE_READ, FILE_TRAVERSE, FILE_WRITE_DATA, READ_CONTROL, SYNCHRONIZE,
    },
};

const FILE_NAME: &str = "offline-account.json";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub version: u32,
    pub ready: bool,
    pub account: String,
    pub account_sid: String,
    pub owner_sid: String,
    pub password_dpapi: Vec<u8>,
}
struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0 as HLOCAL);
        }
    }
}
fn descriptor(owner_sid: &str) -> Result<Descriptor> {
    // Sid input is parsed by Windows, preventing SDDL injection. Also require an
    // ordinary local/domain user SID, never world/everyone/a built-in group.
    ensure!(
        owner_sid.starts_with("S-1-5-21-")
            && owner_sid[9..]
                .split('-')
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
        "invalid broker owner SID"
    );
    let sddl = to_wide(format!(
        "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;{owner_sid})"
    ));
    let mut sd = null_mut();
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        } != 0,
        "invalid protected store descriptor: {}",
        std::io::Error::last_os_error()
    );
    Ok(Descriptor(sd))
}
fn normalized(sd: PSECURITY_DESCRIPTOR) -> Result<String> {
    let mut text = null_mut();
    ensure!(
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut text,
                null_mut(),
            )
        } != 0,
        "cannot serialize store DACL"
    );
    let out = unsafe {
        let mut n = 0;
        while *text.add(n) != 0 {
            n += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, n));
        LocalFree(text as _);
        s
    };
    Ok(out)
}
fn verify(handle: &OwnedHandle, owner_sid: &str) -> Result<()> {
    let mut sd = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle() as _,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        )
    };
    ensure!(
        status == 0,
        "cannot inspect credential store security: {status}"
    );
    let actual = Descriptor(sd);
    ensure!(
        normalized(actual.0)? == normalized(descriptor(owner_sid)?.0)?,
        "credential store owner/DACL mismatch"
    );
    Ok(())
}
pub(super) struct NewStore {
    directory: OwnedHandle,
    owner_sid: String,
}
impl NewStore {
    pub fn create(path: &Path, owner_sid: &str) -> Result<Self> {
        let sd = descriptor(owner_sid)?;
        let mut name = nr::local_directory_nt_path(path)?;
        // FILE_CREATE (2), DIRECTORY_FILE (1). Existing directory => failure.
        let directory = nr::open_no_reparse(
            0,
            &mut name,
            FILE_TRAVERSE | FILE_WRITE_DATA | READ_CONTROL,
            FILE_SHARE_READ,
            2,
            1,
            sd.0,
        )?;
        verify(&directory, owner_sid)?;
        Ok(Self {
            directory,
            owner_sid: owner_sid.to_owned(),
        })
    }
    pub fn write(&self, record: &Record) -> Result<File> {
        let sd = descriptor(&self.owner_sid)?;
        let mut name = to_wide(FILE_NAME);
        let handle = nr::open_no_reparse(
            self.directory.as_raw_handle() as _,
            &mut name,
            FILE_WRITE_DATA | READ_CONTROL | SYNCHRONIZE,
            0,
            2,
            0x40 | 0x20,
            sd.0,
        )?;
        verify(&handle, &self.owner_sid)?;
        let mut file = File::from(handle);
        file.write_all(&serde_json::to_vec(record)?)?;
        file.sync_all()?;
        Ok(file)
    }
}
pub(super) fn read(path: &Path, owner_sid: &str) -> Result<Record> {
    let directory = nr::open_directory_no_reparse(
        path,
        FILE_TRAVERSE | READ_CONTROL,
        FILE_SHARE_READ,
        nr::DirectoryOpenDisposition::OpenExisting,
    )?;
    verify(&directory, owner_sid)?;
    let mut name = to_wide(FILE_NAME);
    let handle = nr::open_no_reparse(
        directory.as_raw_handle() as _,
        &mut name,
        FILE_READ_DATA | READ_CONTROL | SYNCHRONIZE,
        FILE_SHARE_READ,
        1,
        0x40 | 0x20,
        null(),
    )?;
    verify(&handle, owner_sid)?;
    let file = File::from(handle);
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65536, "credential store record too large");
    let record: Record = serde_json::from_slice(&bytes).context("invalid credential store")?;
    ensure!(
        record.version == 1
            && record.account == super::OFFLINE_ACCOUNT
            && record.owner_sid == owner_sid,
        "credential record identity/version mismatch"
    );
    Ok(record)
}

pub(super) fn commit(file: &mut File, record: &mut Record) -> Result<()> {
    record.ready = true;
    let bytes = serde_json::to_vec(record)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&bytes)?;
    file.set_len(bytes.len() as u64)?;
    file.sync_all()?;
    Ok(())
}
