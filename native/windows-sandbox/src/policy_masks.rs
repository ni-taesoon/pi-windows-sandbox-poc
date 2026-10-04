//! Portable Win32 access masks for regression tests without Windows execution.
//! WRITE_DATA | APPEND_DATA | WRITE_EA | WRITE_ATTRIBUTES | DELETE | DELETE_CHILD.
pub const WRITE_DENY: u32 = 0x0002 | 0x0004 | 0x0010 | 0x0100 | 0x0001_0000 | 0x0040;
#[cfg(test)]
mod tests {
    #[test]
    fn deny_write_does_not_deny_shared_read_rights() {
        assert_eq!(
            super::WRITE_DENY & (0x0002_0000 | 0x0010_0000 | 0x0001 | 0x0008 | 0x0080),
            0
        );
    }
}
