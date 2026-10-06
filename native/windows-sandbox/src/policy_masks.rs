//! Portable Win32 access masks for regression tests without Windows execution.

pub const DELETE: u32 = 0x0001_0000;
pub const FILE_DELETE_CHILD: u32 = 0x0040;
/// FILE_GENERIC_WRITE | DELETE. Grant DELETE to inheriting descendants, never
/// DELETE_CHILD to their parent, which could bypass a protected child's deny.
pub const WRITE_ALLOW: u32 = 0x0012_0116 | DELETE;
/// WRITE_DATA | APPEND_DATA | WRITE_EA | WRITE_ATTRIBUTES | DELETE | DELETE_CHILD.
pub const WRITE_DENY: u32 = 0x0002 | 0x0004 | 0x0010 | 0x0100 | 0x0001_0000 | 0x0040;
#[cfg(test)]
mod tests {
    #[test]
    fn write_allow_retains_object_delete_without_parent_delete_child() {
        assert_eq!(super::WRITE_ALLOW & super::FILE_DELETE_CHILD, 0);
        assert_ne!(super::WRITE_ALLOW & super::DELETE, 0);
        assert_ne!(super::WRITE_DENY & super::FILE_DELETE_CHILD, 0);
    }

    #[test]
    fn deny_write_does_not_deny_shared_read_rights() {
        assert_eq!(
            super::WRITE_DENY & (0x0002_0000 | 0x0010_0000 | 0x0001 | 0x0008 | 0x0080),
            0
        );
    }
}
