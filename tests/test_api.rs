//! API Tests for exacl module.

use ctor::ctor;
use exacl::{Acl, AclEntry, AclEntryKind, AclOption, Flag, Perm};
use log::debug;
use std::io;

#[ctor]
fn init() {
    env_logger::init();
}

fn log_acl(acl: &[AclEntry]) {
    for entry in acl {
        if entry.allow {
            debug!(
                "{:?}:{} allow {:?} {:?}",
                entry.kind, entry.name, entry.perms, entry.flags
            );
        } else {
            debug!(
                "{:?}:{} deny {:?} {:?}",
                entry.kind, entry.name, entry.perms, entry.flags
            );
        }
    }
}

#[test]
fn test_read_acl() -> io::Result<()> {
    let file = tempfile::NamedTempFile::new()?;
    let acl = Acl::read(&file.path(), AclOption::default())?;
    let entries = acl.entries()?;

    #[cfg(target_os = "macos")]
    assert_eq!(entries.len(), 0);

    #[cfg(target_os = "linux")]
    assert_eq!(entries.len(), 3);

    log_acl(&entries);

    Ok(())
}

#[test]
#[cfg(target_os = "macos")]
fn test_write_acl_macos() -> io::Result<()> {
    use AclEntryKind::*;

    let mut entries = Vec::<AclEntry>::new();
    let rwx = Perm::READ | Perm::WRITE | Perm::EXECUTE;

    entries.push(AclEntry::allow(Group, "_spotlight", rwx));
    entries.push(AclEntry::allow(User, "11501", rwx));
    entries.push(AclEntry::allow(User, "11502", rwx));
    entries.push(AclEntry::allow(User, "11503", rwx));
    entries.push(AclEntry::deny(Group, "11504", rwx));
    entries[4].flags = Flag::FILE_INHERIT | Flag::DIRECTORY_INHERIT;

    log_acl(&entries);

    let file = tempfile::NamedTempFile::new()?;
    let acl = Acl::from_entries(&entries)?;
    acl.write(&file.path(), AclOption::default())?;

    // Even though the last entry is a group, the `acl_to_text` representation
    // displays it as `user`.
    assert_eq!(
        acl.to_platform_text(),
        r#"!#acl 1
group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000059:_spotlight:89:allow:read,write,execute
user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00002CED:::allow:read,write,execute
user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00002CEE:::allow:read,write,execute
user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00002CEF:::allow:read,write,execute
user:AAAABBBB-CCCC-DDDD-EEEE-FFFF00002CF0:::deny,file_inherit,directory_inherit:read,write,execute
"#
    );

    let acl2 = Acl::read(&file.path(), AclOption::default())?;
    let entries2 = acl2.entries()?;

    assert_eq!(entries2, entries);

    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn test_write_acl_linux() -> io::Result<()> {
    use AclEntryKind::*;

    let mut entries = Vec::<AclEntry>::new();
    let rwx = Perm::READ | Perm::WRITE | Perm::EXECUTE;

    entries.push(AclEntry::allow(Group, "bin", rwx));
    entries.push(AclEntry::allow(User, "11501", rwx));
    entries.push(AclEntry::allow(User, "11502", rwx));
    entries.push(AclEntry::allow(User, "11503", rwx));
    entries.push(AclEntry::allow(User, "@owner", rwx));
    entries.push(AclEntry::allow(Group, "@owner", rwx));
    entries.push(AclEntry::allow(User, "@other", rwx));
    entries.push(AclEntry::allow(Group, "@mask", rwx));

    log_acl(&entries);

    let file = tempfile::NamedTempFile::new()?;
    let acl = Acl::from_entries(&entries)?;
    acl.write(&file.path(), AclOption::default())?;

    assert_eq!(
        acl.to_platform_text(),
        r#"user::rwx
user:11501:rwx
user:11502:rwx
user:11503:rwx
group::rwx
group:bin:rwx
mask::rwx
other::rwx
"#
    );

    let acl2 = Acl::read(&file.path(), AclOption::default())?;
    let mut entries2 = acl2.entries()?;

    entries.sort();
    entries2.sort();
    assert_eq!(entries2, entries);

    Ok(())
}
#[test]
#[cfg(target_os = "macos")]
fn test_write_acl_big() -> io::Result<()> {
    use AclEntryKind::*;

    let mut entries = Vec::<AclEntry>::new();
    let rwx = Perm::READ | Perm::WRITE | Perm::EXECUTE;

    for _ in 0..128 {
        entries.push(AclEntry::allow(User, "11501", rwx));
    }

    let file = tempfile::NamedTempFile::new()?;
    let acl = Acl::from_entries(&entries)?;
    acl.write(&file.path(), AclOption::default())?;

    let acl2 = Acl::read(&file.path(), AclOption::default())?;
    let entries2 = acl2.entries()?;

    assert_eq!(entries2, entries);

    Ok(())
}

#[test]
#[cfg(target_os = "macos")]
fn test_write_acl_too_big() {
    use AclEntryKind::*;

    let mut entries = Vec::<AclEntry>::new();
    let rwx = Perm::READ | Perm::WRITE | Perm::EXECUTE;

    for _ in 0..129 {
        entries.push(AclEntry::allow(User, "11501", rwx));
    }

    let err = Acl::from_entries(&entries).err().unwrap();
    assert_eq!(err.to_string(), "Too many ACL entries");
}

#[test]
#[cfg(target_os = "macos")]
fn test_from_platform_text() {
    let text = r#"!#acl 1
user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00002CED:::allow:read,write,execute
user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00002CEE:::allow:read,write,execute
user:FFFFEEEE-DDDD-CCCC-BBBB-AAAA00002CEF:::allow:read,write,execute
user:AAAABBBB-CCCC-DDDD-EEEE-FFFF00002CF0:::deny,file_inherit,directory_inherit:read,write,execute
"#;

    let acl = Acl::from_platform_text(text).unwrap();
    assert_eq!(acl.to_platform_text(), text);

    let input = r#"!#acl 1
group::_spotlight::allow:read,write,execute
"#;
    let output = r#"!#acl 1
group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000059:_spotlight:89:allow:read,write,execute
"#;
    let acl = Acl::from_platform_text(input).unwrap();
    assert_eq!(acl.to_platform_text(), output);

    // Giving bad input can result in bad output.
    let bad_input = r#"!#acl 1
group:_spotlight:::allow:read,write,execute
"#;
    let bad_output = r#"!#acl 1
user:00000000-0000-0000-0000-000000000000:::allow:read,write,execute
"#;
    let acl = Acl::from_platform_text(bad_input).unwrap();
    assert_eq!(acl.to_platform_text(), bad_output);

    log_acl(&acl.entries().unwrap());
}

#[test]
#[cfg(target_os = "linux")]
fn test_from_platform_text() {
    let text = r#"user::rwx
user:11501:rwx
user:11502:rwx
user:11503:rwx
group::rwx
group:bin:rwx
mask::rwx
other::rwx
"#;

    let acl = Acl::from_platform_text(text).unwrap();
    assert_eq!(acl.to_platform_text(), text);
}
