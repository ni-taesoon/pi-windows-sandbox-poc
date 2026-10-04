//! Portable source contracts only; native metadata behavior needs the Windows run.
const ADMISSION: &str = include_str!("../src/admission.rs");
#[test]
fn guarded_identity_query_requests_read_attributes() {
    assert!(ADMISSION.contains(
        "const GUARDED_DIRECTORY_QUERY_ACCESS: u32 = FILE_TRAVERSE | FILE_READ_ATTRIBUTES;"
    ));
    let guarded = ADMISSION
        .split("// Reject a path converted to a reparse before the guard existed.")
        .nth(1)
        .unwrap()
        .split("pins.push(pin)")
        .next()
        .unwrap();
    assert!(guarded.contains("nr::open_directory_no_reparse("));
    assert!(guarded.contains("GUARDED_DIRECTORY_QUERY_ACCESS"));
    assert!(guarded.contains("nr::DirectoryOpenDisposition::OpenExisting"));
    assert!(guarded.contains("GetFileInformationByHandle(pin.as_raw_handle()"));
    assert!(guarded.contains("phase=guarded-directory-identity"));
    assert!(guarded.contains("win32={}"));
}
#[test]
fn unavailable_or_changed_identity_still_fails_with_all_guards_retained() {
    assert!(ADMISSION.contains("const SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;"));
    assert!(
        ADMISSION.contains("guards.push(nr::create_directory_guard(target.handle.as_handle())?)")
    );
    for field in ["dwVolumeSerialNumber", "nFileIndexHigh", "nFileIndexLow"] {
        assert!(ADMISSION.contains(&format!("info.{field}")));
        assert!(ADMISSION.contains(&format!("current.{field}")));
    }
    assert!(ADMISSION.contains("policy target changed during admission"));
    assert!(ADMISSION.contains("phase=initial-directory-identity"));
    assert!(!ADMISSION.contains("FILE_SHARE_DELETE"));
}
