//! API Tests for exacl module.

use ctor::ctor;
use env_logger;
use exacl::{Acl, AclEntry, AclEntryKind, Flag, Perm};
use log::debug;
use std::io;
use tempfile;

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
    let acl = Acl::read(&file.path())?;
    let entries = acl.entries()?;

    log_acl(&entries);
    assert_eq!(Acl::validate_entries(&entries), None);

    Ok(())
}

#[test]
fn test_write_acl() -> io::Result<()> {
    use AclEntryKind::*;

    let mut entries = Vec::<AclEntry>::new();
    let rwx = Perm::READ_DATA | Perm::WRITE_DATA | Perm::EXECUTE;

    entries.push(AclEntry::allow(User, "11501", rwx));
    entries.push(AclEntry::allow(User, "11502", rwx));
    entries.push(AclEntry::allow(User, "11503", rwx));
    entries.push(AclEntry::deny(User, "11504", rwx));
    entries[3].flags = Flag::ENTRY_FILE_INHERIT | Flag::ENTRY_DIRECTORY_INHERIT;

    log_acl(&entries);
    assert_eq!(Acl::validate_entries(&entries), None);

    let file = tempfile::NamedTempFile::new()?;
    let acl = Acl::from_entries(&entries)?;
    acl.write(&file.path())?;

    let acl2 = Acl::read(&file.path())?;
    let entries2 = acl2.entries()?;

    assert_eq!(entries2, entries);

    Ok(())
}

#[test]
fn test_write_acl_big() -> io::Result<()> {
    use AclEntryKind::*;

    let mut entries = Vec::<AclEntry>::new();
    let rwx = Perm::READ_DATA | Perm::WRITE_DATA | Perm::EXECUTE;

    for _ in 0..128 {
        entries.push(AclEntry::allow(User, "11501", rwx));
    }
    assert_eq!(Acl::validate_entries(&entries), None);

    let file = tempfile::NamedTempFile::new()?;
    let acl = Acl::from_entries(&entries)?;
    acl.write(&file.path())?;

    let acl2 = Acl::read(&file.path())?;
    let entries2 = acl2.entries()?;

    assert_eq!(entries2, entries);

    Ok(())
}

#[test]
fn test_write_acl_too_big() {
    use AclEntryKind::*;

    let mut entries = Vec::<AclEntry>::new();
    let rwx = Perm::READ_DATA | Perm::WRITE_DATA | Perm::EXECUTE;

    for _ in 0..129 {
        entries.push(AclEntry::allow(User, "11501", rwx));
    }
    assert_eq!(Acl::validate_entries(&entries), None);

    let err = Acl::from_entries(&entries).err().unwrap();
    assert!(err.to_string().contains("Cannot allocate memory"));
}
