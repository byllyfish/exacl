//! Test example code used in documentation.

use std::io;

#[test]
fn test_string_format() -> io::Result<()> {
    let file = tempfile::NamedTempFile::new()?;

    let acl = exacl::getfacl(&file, None)?;
    let result = exacl::to_string(&acl)?;
    println!("test_string_format: {:?}", result);

    Ok(())
}

#[test]
fn test_json_format() -> io::Result<()> {
    let file = tempfile::NamedTempFile::new()?;

    let acl = exacl::getfacl(&file, None)?;
    let result = serde_json::to_string(&acl)?;
    println!("test_json_format: {:?}", result);

    Ok(())
}

#[test]
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn test_linux_acl() -> io::Result<()> {
    use exacl::{AclEntry, Perm};

    let mut acl = exacl::from_mode(0o660);
    acl.push(AclEntry::allow_user("fred", Perm::READ | Perm::WRITE, None));

    assert_eq!(
        exacl::to_string(&acl)?,
        "allow::user::read,write\nallow::group::read,write\nallow::other::\nallow::user:fred:read,write\n"
    );
    //exacl::setfacl(&["/tmp/file"], &acl, None)?;

    Ok(())
}

#[test]
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn test_linux_acl_default() -> io::Result<()> {
    use exacl::{AclEntry, Flag, Perm};

    let mut acl = exacl::from_mode(0o770);
    acl.push(AclEntry::allow_group(
        "accounting",
        Perm::READ | Perm::WRITE | Perm::EXECUTE,
        None,
    ));

    // Make default_acl a copy of access_acl.
    let mut default_acl: Vec<AclEntry> = acl.clone();
    for entry in &mut default_acl {
        entry.flags |= Flag::DEFAULT;
    }
    acl.append(&mut default_acl);

    assert_eq!(exacl::to_string(&acl)?, "allow::user::read,write,execute\nallow::group::read,write,execute\nallow::other::\nallow::group:accounting:read,write,execute\nallow:default:user::read,write,execute\nallow:default:group::read,write,execute\nallow:default:other::\nallow:default:group:accounting:read,write,execute\n");
    //exacl::setfacl(&["./tmp/dir"], &acl, None)?;

    Ok(())
}
