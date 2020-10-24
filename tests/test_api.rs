//! API Tests for exacl module.

use ctor::ctor;
use env_logger;
use exacl::{self, read_acl, validate_acl, write_acl, Acl, AclEntry, AclEntryKind, Perm};
use log::debug;
use std::io;
use tempfile;

#[ctor]
fn init() {
    env_logger::init();
}

fn log_acl(acl: &exacl::Acl) {
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
    let acl = read_acl(&file.path())?;

    log_acl(&acl);
    assert_eq!(validate_acl(&acl), None);

    Ok(())
}

#[test]
fn test_write_acl() -> io::Result<()> {
    let mut acl: Acl = Acl::new();
    let rwx = Perm::READ_DATA | Perm::WRITE_DATA | Perm::EXECUTE;

    use AclEntryKind::*;
    acl.push(AclEntry::allow(User, "11501", rwx));
    acl.push(AclEntry::allow(User, "11502", rwx));
    acl.push(AclEntry::allow(User, "11503", rwx));
    acl.push(AclEntry::deny(User, "11504", rwx));

    log_acl(&acl);
    assert_eq!(validate_acl(&acl), None);

    let file = tempfile::NamedTempFile::new()?;
    write_acl(&file.path(), &acl)?;

    let acl2 = read_acl(&file.path())?;
    assert_eq!(acl2, acl);

    Ok(())
}
