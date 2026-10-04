//! Read-only, value-whitelisted startup access diagnostics. Never exports SDs/SIDs.
use crate::{process::Handle, winutil};
use serde::{Deserialize, Serialize};
use std::ptr::null_mut;
use windows_sys::Win32::{Foundation::*, Security::*, System::StationsAndDesktops::*};
const RC: u32 = 0x0002_0000;
const STANDARD_REQUIRED: u32 = 0x000f_0000;
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum ObjectKind {
    WindowStation,
    PrivateDesktop,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum AccessKind {
    ReadAttributes,
    GlobalAtoms,
    EnumerateDesktops,
    Clipboard,
    CreateDesktop,
    WriteAttributes,
    ReadObjects,
    WriteObjects,
    CreateWindow,
    CreateMenu,
    Enumerate,
    SwitchDesktop,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum ApiStage {
    DescriptorSize,
    DescriptorRead,
    DuplicateToken,
    AccessCheck,
    TokenSession,
    StationName,
    CurrentWindowStation,
    OpenPrivateDesktop,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum DiagnosticError {
    Api { stage: ApiStage, win32: u32 },
    InvalidData,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Decision {
    allowed: Option<bool>,
    error: Option<DiagnosticError>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccessProbe {
    kind: AccessKind,
    desired_mask: u32,
    base: Decision,
    restricted: Decision,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ObjectProbe {
    object: ObjectKind,
    descriptor_available: bool,
    error: Option<DiagnosticError>,
    access: Vec<AccessProbe>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StartupDiagnostics {
    same_token_session: Option<bool>,
    session_error: Option<DiagnosticError>,
    window_station_is_expected: Option<bool>,
    window_station_name_error: Option<DiagnosticError>,
    objects: Vec<ObjectProbe>,
}
type DResult<T> = Result<T, DiagnosticError>;
fn error(stage: ApiStage) -> DiagnosticError {
    DiagnosticError::Api {
        stage,
        win32: unsafe { GetLastError() },
    }
}
unsafe fn descriptor(handle: HANDLE) -> DResult<Vec<usize>> {
    let requested =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut needed = 0;
    let first = GetUserObjectSecurity(handle, &requested, null_mut(), 0, &mut needed);
    if first == 0 && GetLastError() != ERROR_INSUFFICIENT_BUFFER {
        return Err(error(ApiStage::DescriptorSize));
    }
    if !(20..=65536).contains(&needed) {
        return Err(DiagnosticError::InvalidData);
    }
    let mut bytes = vec![
        0usize;
        (needed as usize + std::mem::size_of::<usize>() - 1)
            / std::mem::size_of::<usize>()
    ];
    let capacity = (bytes.len() * std::mem::size_of::<usize>()) as u32;
    if GetUserObjectSecurity(
        handle,
        &requested,
        bytes.as_mut_ptr().cast(),
        capacity,
        &mut needed,
    ) == 0
    {
        return Err(error(ApiStage::DescriptorRead));
    }
    if needed > capacity || IsValidSecurityDescriptor(bytes.as_ptr() as *mut _) == 0 {
        return Err(DiagnosticError::InvalidData);
    }
    Ok(bytes)
}
unsafe fn duplicate_for_check(token: HANDLE) -> DResult<Handle> {
    let mut duplicate = 0;
    if DuplicateToken(token, SecurityImpersonation, &mut duplicate) == 0 {
        return Err(error(ApiStage::DuplicateToken));
    }
    Handle::from_raw(duplicate).map_err(|_| DiagnosticError::InvalidData)
}
unsafe fn decision(
    sd: &[usize],
    token: HANDLE,
    desired: u32,
    mapping: &GENERIC_MAPPING,
) -> Decision {
    let attempted = (|| -> DResult<bool> {
        let duplicate = duplicate_for_check(token)?;
        let mut mapping = *mapping;
        let mut privileges = [0usize; 512];
        let mut length = std::mem::size_of_val(&privileges) as u32;
        let mut granted = 0;
        let mut allowed = 0;
        if AccessCheck(
            sd.as_ptr() as *mut _,
            duplicate.raw(),
            desired,
            &mut mapping,
            privileges.as_mut_ptr().cast(),
            &mut length,
            &mut granted,
            &mut allowed,
        ) == 0
        {
            return Err(error(ApiStage::AccessCheck));
        }
        Ok(allowed != 0)
    })();
    match attempted {
        Ok(allowed) => Decision {
            allowed: Some(allowed),
            error: None,
        },
        Err(error) => Decision {
            allowed: None,
            error: Some(error),
        },
    }
}
fn mapping(kind: ObjectKind) -> GENERIC_MAPPING {
    // Microsoft interactive-window-station and desktop generic-rights tables.
    match kind {
        ObjectKind::WindowStation => GENERIC_MAPPING {
            GenericRead: RC | 0x0001 | 0x0100 | 0x0002 | 0x0200,
            GenericWrite: RC | 0x0004 | 0x0008 | 0x0010,
            GenericExecute: RC | 0x0020 | 0x0040,
            GenericAll: STANDARD_REQUIRED | 0x037f,
        },
        ObjectKind::PrivateDesktop => GENERIC_MAPPING {
            GenericRead: RC | DESKTOP_ENUMERATE | DESKTOP_READOBJECTS,
            GenericWrite: RC
                | DESKTOP_CREATEMENU
                | DESKTOP_CREATEWINDOW
                | DESKTOP_HOOKCONTROL
                | DESKTOP_JOURNALPLAYBACK
                | DESKTOP_JOURNALRECORD
                | DESKTOP_WRITEOBJECTS,
            GenericExecute: RC | DESKTOP_SWITCHDESKTOP,
            GenericAll: STANDARD_REQUIRED | 0x01ff,
        },
    }
}
unsafe fn object_probe(
    kind: ObjectKind,
    handle: DResult<HANDLE>,
    base: HANDLE,
    restricted: HANDLE,
) -> ObjectProbe {
    let sd = handle.and_then(|handle| descriptor(handle));
    match sd {
        Err(error) => ObjectProbe {
            object: kind,
            descriptor_available: false,
            error: Some(error),
            access: vec![],
        },
        Ok(sd) => {
            let rights: &[(AccessKind, u32)] = match kind {
                ObjectKind::WindowStation => &[
                    (AccessKind::ReadAttributes, 0x0002),
                    (AccessKind::GlobalAtoms, 0x0020),
                    (AccessKind::EnumerateDesktops, 0x0001),
                    (AccessKind::Clipboard, 0x0004),
                    (AccessKind::CreateDesktop, 0x0008),
                    (AccessKind::WriteAttributes, 0x0010),
                ],
                ObjectKind::PrivateDesktop => &[
                    (AccessKind::ReadObjects, DESKTOP_READOBJECTS),
                    (AccessKind::WriteObjects, DESKTOP_WRITEOBJECTS),
                    (AccessKind::CreateWindow, DESKTOP_CREATEWINDOW),
                    (AccessKind::CreateMenu, DESKTOP_CREATEMENU),
                    (AccessKind::Enumerate, DESKTOP_ENUMERATE),
                    (AccessKind::SwitchDesktop, DESKTOP_SWITCHDESKTOP),
                ],
            };
            let mapping = mapping(kind);
            ObjectProbe {
                object: kind,
                descriptor_available: true,
                error: None,
                access: rights
                    .iter()
                    .map(|(kind, mask)| AccessProbe {
                        kind: *kind,
                        desired_mask: *mask,
                        base: decision(&sd, base, *mask, &mapping),
                        restricted: decision(&sd, restricted, *mask, &mapping),
                    })
                    .collect(),
            }
        }
    }
}
unsafe fn token_session(token: HANDLE) -> DResult<u32> {
    let mut session = 0u32;
    let mut size = 0;
    if GetTokenInformation(
        token,
        TokenSessionId,
        (&mut session as *mut u32).cast(),
        4,
        &mut size,
    ) == 0
    {
        return Err(error(ApiStage::TokenSession));
    }
    if size != 4 {
        return Err(DiagnosticError::InvalidData);
    }
    Ok(session)
}
unsafe fn station_expected(handle: HANDLE) -> DResult<bool> {
    let mut buffer = [0u16; 256];
    let mut needed = 0;
    if GetUserObjectInformationW(
        handle,
        UOI_NAME,
        buffer.as_mut_ptr().cast(),
        512,
        &mut needed,
    ) == 0
    {
        return Err(error(ApiStage::StationName));
    }
    if needed > 512 {
        return Err(DiagnosticError::InvalidData);
    }
    let length = buffer
        .iter()
        .position(|v| *v == 0)
        .ok_or(DiagnosticError::InvalidData)?;
    let name = String::from_utf16(&buffer[..length]).map_err(|_| DiagnosticError::InvalidData)?;
    Ok(name.eq_ignore_ascii_case("Winsta0"))
}
/// Read-only diagnostics, not admission authority or permission to grant access.
pub(crate) unsafe fn inspect(
    base: HANDLE,
    restricted: HANDLE,
    desktop: &str,
) -> StartupDiagnostics {
    let session = token_session(base).and_then(|base_session| {
        token_session(restricted).map(|restricted_session| base_session == restricted_session)
    });
    let (same_token_session, session_error) = match session {
        Ok(equal) => (Some(equal), None),
        Err(error) => (None, Some(error)),
    };
    let station = GetProcessWindowStation();
    let station_status = if station == 0 {
        Err(error(ApiStage::CurrentWindowStation))
    } else {
        station_expected(station)
    };
    let (window_station_is_expected, window_station_name_error) = match station_status {
        Ok(equal) => (Some(equal), None),
        Err(error) => (None, Some(error)),
    };
    let station_probe = object_probe(
        ObjectKind::WindowStation,
        if window_station_is_expected == Some(true) {
            Ok(station)
        } else {
            Err(DiagnosticError::InvalidData)
        },
        base,
        restricted,
    );
    // Only the already-created per-run private desktop, never Default or a user-selected object.
    let name = desktop.strip_prefix("Winsta0\\PiSandboxDesktop-");
    let desktop_handle = match name {
        Some(suffix)
            if window_station_is_expected == Some(true)
                && suffix.len() == 32
                && suffix.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            let name = format!("PiSandboxDesktop-{suffix}");
            let handle = OpenDesktopW(
                winutil::to_wide(&name).as_ptr(),
                0,
                0,
                DESKTOP_READ_CONTROL | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS,
            );
            if handle == 0 {
                Err(error(ApiStage::OpenPrivateDesktop))
            } else {
                Ok(handle)
            }
        }
        _ => Err(DiagnosticError::InvalidData),
    };
    let desktop_probe = match desktop_handle {
        Ok(handle) => {
            let result = object_probe(ObjectKind::PrivateDesktop, Ok(handle), base, restricted);
            CloseDesktop(handle);
            result
        }
        Err(error) => object_probe(ObjectKind::PrivateDesktop, Err(error), base, restricted),
    };
    StartupDiagnostics {
        same_token_session,
        session_error,
        window_station_is_expected,
        window_station_name_error,
        objects: vec![station_probe, desktop_probe],
    }
}
