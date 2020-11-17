//! API Tests for exacl module.

use ctor::ctor;
use exacl::{getfacl, Acl, AclEntry, AclOption, Flag, Perm};
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
    let acl = Acl::read(&file, AclOption::empty())?;
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
    let mut entries = Vec::<AclEntry>::new();
    let rwx = Perm::READ | Perm::WRITE | Perm::EXECUTE;

    entries.push(AclEntry::allow_group("_spotlight", rwx, None));
    entries.push(AclEntry::allow_user("11501", rwx, None));
    entries.push(AclEntry::allow_user("11502", rwx, None));
    entries.push(AclEntry::allow_user("11503", rwx, None));
    entries.push(AclEntry::deny_group(
        "11504",
        rwx,
        Flag::FILE_INHERIT | Flag::DIRECTORY_INHERIT,
    ));

    log_acl(&entries);

    let file = tempfile::NamedTempFile::new()?;
    let acl = Acl::from_entries(&entries)?;
    assert!(!acl.is_empty());
    acl.write(&file, AclOption::empty())?;

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

    let acl2 = Acl::read(&file, AclOption::empty())?;
    let entries2 = acl2.entries()?;

    assert_eq!(entries2, entries);

    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn test_write_acl_linux() -> io::Result<()> {
    use exacl::{MASK, OTHER, OWNER};

    let mut entries = Vec::<AclEntry>::new();
    let rwx = Perm::READ | Perm::WRITE | Perm::EXECUTE;

    entries.push(AclEntry::allow_group("bin", rwx, None));
    entries.push(AclEntry::allow_user("11501", rwx, None));
    entries.push(AclEntry::allow_user("11502", rwx, None));
    entries.push(AclEntry::allow_user("11503", rwx, None));
    entries.push(AclEntry::allow_user(OWNER, rwx, None));
    entries.push(AclEntry::allow_group(OWNER, rwx, None));
    entries.push(AclEntry::allow_user(OTHER, rwx, None));
    entries.push(AclEntry::allow_group(MASK, rwx, None));

    log_acl(&entries);

    let file = tempfile::NamedTempFile::new()?;
    let acl = Acl::from_entries(&entries)?;
    acl.write(&file, AclOption::empty())?;

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

    let acl2 = Acl::read(&file, AclOption::empty())?;
    let mut entries2 = acl2.entries()?;

    entries.sort();
    entries2.sort();
    assert_eq!(entries2, entries);

    Ok(())
}
#[test]
#[cfg(target_os = "macos")]
fn test_write_acl_big() -> io::Result<()> {
    let mut entries = Vec::<AclEntry>::new();
    let rwx = Perm::READ | Perm::WRITE | Perm::EXECUTE;

    for _ in 0..128 {
        entries.push(AclEntry::allow_user("11501", rwx, None));
    }

    let file = tempfile::NamedTempFile::new()?;
    let acl = Acl::from_entries(&entries)?;
    acl.write(&file, AclOption::empty())?;

    let acl2 = Acl::read(&file, AclOption::empty())?;
    let entries2 = acl2.entries()?;

    assert_eq!(entries2, entries);

    Ok(())
}

#[test]
#[cfg(target_os = "macos")]
fn test_write_acl_too_big() {
    let mut entries = Vec::<AclEntry>::new();
    let rwx = Perm::READ | Perm::WRITE | Perm::EXECUTE;

    for _ in 0..129 {
        entries.push(AclEntry::allow_user("11501", rwx, None));
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

#[test]
#[cfg(target_os = "linux")]
fn test_read_default_acl() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let default_acl = Acl::read(&dir, AclOption::DEFAULT_ACL)?;
    assert!(default_acl.is_empty());

    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn test_write_default_acl() -> io::Result<()> {
    let mut entries = Vec::<AclEntry>::new();
    let rwx = Perm::READ | Perm::WRITE | Perm::EXECUTE;

    entries.push(AclEntry::allow_user(Acl::OWNER, rwx, None));
    entries.push(AclEntry::allow_group(Acl::OWNER, rwx, None));
    entries.push(AclEntry::allow_user(Acl::OTHER, rwx, None));
    entries.push(AclEntry::allow_group("bin", rwx, None));
    entries.push(AclEntry::allow_group(Acl::MASK, rwx, None));

    let dir = tempfile::tempdir()?;
    let acl = Acl::from_entries(&entries)?;
    acl.write(&dir, AclOption::DEFAULT_ACL)?;

    let acl2 = Acl::read(&dir, AclOption::empty())?;
    assert_ne!(acl.to_platform_text(), acl2.to_platform_text());

    let default_acl = Acl::read(&dir, AclOption::DEFAULT_ACL)?;
    assert_eq!(default_acl.to_platform_text(), acl.to_platform_text());

    let default_entries = default_acl.entries()?;
    for entry in &default_entries {
        assert_eq!(entry.flags, Flag::DEFAULT);
    }

    // Test deleting a default ACL by passing an empty acl.
    let empty_acl = Acl::from_entries(&[])?;
    empty_acl.write(&dir, AclOption::DEFAULT_ACL)?;
    assert!(Acl::read(&dir, AclOption::DEFAULT_ACL)?.is_empty());

    Ok(())
}

#[test]
fn test_empty_acl() -> io::Result<()> {
    let acl = Acl::from_entries(&[])?;
    assert!(acl.is_empty());
    Ok(())
}

#[test]
fn test_getfacl() -> io::Result<()> {
    let file = tempfile::NamedTempFile::new()?;
    let entries = getfacl(&file, None)?;

    #[cfg(target_os = "macos")]
    assert_eq!(entries.len(), 0);

    #[cfg(target_os = "linux")]
    assert_eq!(entries.len(), 3);

    log_acl(&entries);

    // Test default ACL on macOS (should fail).
    #[cfg(target_os = "macos")]
    {
        let result = getfacl(&file, AclOption::DEFAULT_ACL);
        assert_eq!(
            result.err().unwrap().to_string(),
            "macOS does not support default ACL"
        );
    }

    // Test default ACL on linux (should be empty).
    #[cfg(target_os = "linux")]
    {
        let entries = getfacl(&file, AclOption::DEFAULT_ACL)?;
        assert_eq!(entries.len(), 0);
    }

    Ok(())
}
