//! Fixed fixture output only; progress markers alone are never success.
pub(crate) fn matches_stdout(bytes: &[u8]) -> bool {
    const LF: &[u8] = b"PI_LAB_SCRIPT_ENTERED\nPI_LAB_IMPORTS_READY\nPI_WINDOWS_PYTHON_LAB_OK\n";
    const CRLF: &[u8] =
        b"PI_LAB_SCRIPT_ENTERED\r\nPI_LAB_IMPORTS_READY\r\nPI_WINDOWS_PYTHON_LAB_OK\r\n";
    bytes == LF || bytes == CRLF
}
