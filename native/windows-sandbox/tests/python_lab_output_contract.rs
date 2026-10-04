#[path = "../examples/python_lab/output_contract.rs"]
mod output_contract;
#[test]
fn accepts_only_complete_fixed_stdout_with_consistent_platform_newlines() {
    let full = b"PI_LAB_SCRIPT_ENTERED\nPI_LAB_IMPORTS_READY\nPI_WINDOWS_PYTHON_LAB_OK\n";
    assert!(output_contract::matches_stdout(full));
    assert!(output_contract::matches_stdout(
        &String::from_utf8(full.to_vec())
            .unwrap()
            .replace('\n', "\r\n")
            .into_bytes()
    ));
    for partial in [
        &b""[..],
        &b"PI_LAB_SCRIPT_ENTERED\n"[..],
        &b"PI_LAB_SCRIPT_ENTERED\nPI_LAB_IMPORTS_READY\n"[..],
        &b"PI_WINDOWS_PYTHON_LAB_OK\n"[..],
    ] {
        assert!(!output_contract::matches_stdout(partial));
    }
    let mut extra = full.to_vec();
    extra.extend_from_slice(b"extra\n");
    assert!(!output_contract::matches_stdout(&extra));
    assert!(!output_contract::matches_stdout(
        b"PI_LAB_IMPORTS_READY\nPI_LAB_SCRIPT_ENTERED\nPI_WINDOWS_PYTHON_LAB_OK\n"
    ));
    assert!(!output_contract::matches_stdout(
        b"PI_LAB_SCRIPT_ENTERED\r\nPI_LAB_IMPORTS_READY\nPI_WINDOWS_PYTHON_LAB_OK\n"
    ));
}
