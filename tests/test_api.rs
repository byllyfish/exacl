//! API Tests for exacl module.

use ctor::ctor;
use exacl::{getfacl, setfacl, AclEntry, AclOption, Flag, Perm};
use log::debug;
use std::io;

#[ctor]
fn init() {
    env_logger::init();
}

#[test]
fn test_getfacl_file() -> io::Result<()> {
    let file = tempfile::NamedTempFile::new()?;
    let entries = getfacl(&file, None)?;

    #[cfg(target_os = "macos")]
    assert_eq!(entries.len(), 0);

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    assert_eq!(entries.len(), 3);

    // Test default ACL on macOS (should fail).
    #[cfg(target_os = "macos")]
    {
        let result = getfacl(&file, AclOption::DEFAULT_ACL);
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("macOS does not support default ACL"));
    }

    // Test default ACL (should be error; files don't have default ACL).
    #[cfg(target_os = "linux")]
    {
        let result = getfacl(&file, AclOption::DEFAULT_ACL);
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Permission denied"));
    }

    // Test default ACL (should be error; files don't have default ACL).
    #[cfg(target_os = "freebsd")]
    {
        let result = getfacl(&file, AclOption::DEFAULT_ACL);
        // If file is using NFSv4 ACL, the error message will be
        // "Default ACL not supported", otherwise the error message will be
        // "Invalid argument".
        let errmsg = result.unwrap_err().to_string();
        assert!(
            errmsg.contains("Default ACL not supported") || errmsg.contains("Invalid argument")
        );
    }

    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn test_too_many_entries() -> io::Result<()> {
    use exacl::setfacl;

    // This test depends on the type of file system. With ext* systems, we
    // expect ACL's with 508 entries to fail.
    let mut entries = vec![
        AclEntry::allow_user("", Perm::READ, None),
        AclEntry::allow_group("", Perm::READ, None),
        AclEntry::allow_other(Perm::empty(), None),
        AclEntry::allow_mask(Perm::READ, None),
    ];

    for i in 500..1003 {
        entries.push(AclEntry::allow_user(&i.to_string(), Perm::READ, None));
    }

    let files = [tempfile::NamedTempFile::new()?];

    // 507 entries are okay.
    setfacl(&files, &entries, None)?;
    debug!("{} entries is okay", entries.len());

    // Add 508th entry.
    entries.push(AclEntry::allow_user("1500", Perm::READ, None));

    // 508th entry is one too many.
    let err = setfacl(&files, &entries, None).unwrap_err();
    assert!(err.to_string().contains("No space left on device"));

    Ok(())
}

#[test]
fn test_reader_writer() -> io::Result<()> {
    let input = r#"
    u:aaa:rwx#comment
    g:bbb:rwx
    u:ccc:rx
    "#;

    let entries = exacl::from_str(input)?;
    let actual = exacl::to_string(&entries)?;

    let expected = r#"allow::user:aaa:read,write,execute
allow::group:bbb:read,write,execute
allow::user:ccc:read,execute
"#;
    assert_eq!(expected, actual);

    Ok(())
}

#[test]
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn test_exclusive_acloptions() {
    let path = "/tmp";

    let err1 = getfacl(&path, AclOption::ACCESS_ACL | AclOption::DEFAULT_ACL).unwrap_err();
    assert_eq!(
        err1.to_string(),
        "ACCESS_ACL and DEFAULT_ACL are mutually exclusive options"
    );

    let err2 = setfacl(&[path], &[], AclOption::ACCESS_ACL | AclOption::DEFAULT_ACL).unwrap_err();
    assert_eq!(
        err2.to_string(),
        "ACCESS_ACL and DEFAULT_ACL are mutually exclusive options"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn test_exclusive_acloptions() {
    let path = "/tmp";

    let err1 = getfacl(&path, AclOption::ACCESS_ACL | AclOption::DEFAULT_ACL).unwrap_err();
    assert_eq!(
        err1.to_string(),
        "File \"/tmp\": macOS does not support default ACL"
    );

    let err2 = setfacl(&[path], &[], AclOption::ACCESS_ACL | AclOption::DEFAULT_ACL).unwrap_err();
    assert_eq!(
        err2.to_string(),
        "File \"/tmp\": macOS does not support default ACL"
    );
}

#[test]
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn test_from_mode() {
    let acl_7777 = exacl::to_string(&exacl::from_mode(0o7777)).unwrap();
    assert_eq!(acl_7777, "allow::user::read,write,execute\nallow::group::read,write,execute\nallow::other::read,write,execute\n");

    let acl_000 = exacl::to_string(&exacl::from_mode(0o000)).unwrap();
    assert_eq!(acl_000, "allow::user::\nallow::group::\nallow::other::\n");

    let acl_123 = exacl::to_string(&exacl::from_mode(0o123)).unwrap();
    assert_eq!(
        acl_123,
        "allow::user::execute\nallow::group::write\nallow::other::write,execute\n"
    );

    let acl_12345 = exacl::to_string(&exacl::from_mode(0o12345)).unwrap();
    assert_eq!(
        acl_12345,
        "allow::user::write,execute\nallow::group::read\nallow::other::read,execute\n"
    );
}
