//! API Tests for exacl module.

use ctor::ctor;
use exacl::{getfacl, setfacl, Acl, AclEntry, AclOption, Flag, Perm};
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
    let acl = Acl::read(file.as_ref(), AclOption::empty())?;
    let entries = acl.entries()?;

    #[cfg(target_os = "macos")]
    assert_eq!(entries.len(), 0);

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
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
    acl.write(file.as_ref(), AclOption::empty())?;

    // Even though the last entry is a group, the `acl_to_text` representation
    // displays it as `user`.
    assert_eq!(
        acl.to_string()?,
        r#"allow::group:_spotlight:read,write,execute
allow::user:11501:read,write,execute
allow::user:11502:read,write,execute
allow::user:11503:read,write,execute
deny:file_inherit,directory_inherit:group:11504:read,write,execute
"#
    );

    let acl2 = Acl::read(file.as_ref(), AclOption::empty())?;
    let entries2 = acl2.entries()?;

    assert_eq!(entries2, entries);

    Ok(())
}

#[test]
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn test_write_acl_posix() -> io::Result<()> {
    let file = tempfile::NamedTempFile::new()?;

    // Skip the rest of the test if file uses NFSv4 ACL (FIXME).
    #[cfg(target_os = "freebsd")]
    if Acl::is_nfs4(file.as_ref(), AclOption::empty())? {
        return Ok(());
    }

    let mut entries = Vec::<AclEntry>::new();
    let rwx = Perm::READ | Perm::WRITE | Perm::EXECUTE;

    entries.push(AclEntry::allow_group("bin", rwx, None));
    entries.push(AclEntry::allow_user("11501", rwx, None));
    entries.push(AclEntry::allow_user("11502", rwx, None));
    entries.push(AclEntry::allow_user("11503", rwx, None));
    entries.push(AclEntry::allow_user("", rwx, None));
    entries.push(AclEntry::allow_group("", rwx, None));
    entries.push(AclEntry::allow_other(rwx, None));
    // We do not add a mask entry. One will be automatically added.

    log_acl(&entries);

    let acl = Acl::from_entries(&entries)?;
    acl.write(file.as_ref(), AclOption::empty())?;

    assert_eq!(
        acl.to_string()?,
        r#"allow::user::read,write,execute
allow::user:11501:read,write,execute
allow::user:11502:read,write,execute
allow::user:11503:read,write,execute
allow::group::read,write,execute
allow::group:bin:read,write,execute
allow::mask::read,write,execute
allow::other::read,write,execute
"#
    );

    let acl2 = Acl::read(file.as_ref(), AclOption::empty())?;
    let mut entries2 = acl2.entries()?;

    // Before doing the comparison, add the mask entry.
    entries.push(AclEntry::allow_mask(rwx, None));

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
    acl.write(file.as_ref(), AclOption::empty())?;

    let acl2 = Acl::read(file.as_ref(), AclOption::empty())?;
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
#[cfg(target_os = "linux")]
fn test_read_default_acl() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let default_acl = Acl::read(dir.as_ref(), AclOption::DEFAULT_ACL)?;

    assert!(default_acl.is_empty());

    Ok(())
}

#[test]
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn test_write_default_acl() -> io::Result<()> {
    let dir = tempfile::tempdir()?;

    // Skip the rest of the test if file uses NFSv4 ACL (FIXME).
    #[cfg(target_os = "freebsd")]
    if Acl::is_nfs4(dir.as_ref(), AclOption::empty())? {
        return Ok(());
    }

    let mut entries = Vec::<AclEntry>::new();
    let rwx = Perm::READ | Perm::WRITE | Perm::EXECUTE;

    entries.push(AclEntry::allow_user("", rwx, None));
    entries.push(AclEntry::allow_group("", rwx, None));
    entries.push(AclEntry::allow_other(rwx, None));
    entries.push(AclEntry::allow_group("bin", rwx, None));
    entries.push(AclEntry::allow_mask(rwx, None));

    let path = dir.as_ref();
    let acl = Acl::from_entries(&entries)?;
    acl.write(path, AclOption::DEFAULT_ACL)?;

    let acl2 = Acl::read(path, AclOption::empty())?;
    assert_ne!(acl.to_string()?, acl2.to_string()?);

    let default_acl = Acl::read(path, AclOption::DEFAULT_ACL)?;
    let default_entries = default_acl.entries()?;
    for entry in &default_entries {
        assert_eq!(entry.flags, Flag::DEFAULT);
    }

    // Test deleting a default ACL by passing an empty acl.
    debug!("Test deleting a default ACL");
    let empty_acl = Acl::from_entries(&[])?;
    empty_acl.write(path, AclOption::DEFAULT_ACL)?;
    assert!(Acl::read(path, AclOption::DEFAULT_ACL)?.is_empty());

    Ok(())
}

#[test]
fn test_empty_acl() -> io::Result<()> {
    let acl = Acl::from_entries(&[])?;
    assert!(acl.is_empty());
    Ok(())
}

#[test]
fn test_getfacl_file() -> io::Result<()> {
    let file = tempfile::NamedTempFile::new()?;
    let entries = getfacl(&file, None)?;

    #[cfg(target_os = "macos")]
    assert_eq!(entries.len(), 0);

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    assert_eq!(entries.len(), 3);

    log_acl(&entries);

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
        if Acl::is_nfs4(&file.as_ref(), AclOption::empty())? {
            assert!(result.unwrap_err().to_string().contains("Default ACL not supported"));
        } else {
            assert!(result.unwrap_err().to_string().contains("Invalid argument"));
        }
    }

    Ok(())
}

#[test]
fn test_from_entries() {
    // 0 entries should result in empty acl.
    let acl = Acl::from_entries(&[]).unwrap();
    assert!(acl.is_empty());

    // Test named user on MacOS.
    #[cfg(target_os = "macos")]
    {
        let entries = vec![AclEntry::allow_user("500", Perm::EXECUTE, None)];
        let acl = Acl::from_entries(&entries).unwrap();
        assert_eq!(acl.to_string().unwrap(), "allow::user:500:execute\n");
    }

    // Test named user on Linux. It should add correct mask.
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    {
        let mut entries = vec![
            AclEntry::allow_group("", Perm::READ, None),
            AclEntry::allow_other(Perm::READ, None),
            AclEntry::allow_user("500", Perm::EXECUTE, None),
        ];

        let err = Acl::from_entries(&entries).err().unwrap();
        assert_eq!(err.to_string(), "missing required entry \"user\"");

        entries.push(AclEntry::allow_user("", Perm::READ, None));
        let acl = Acl::from_entries(&entries).unwrap();

        #[cfg(target_os = "linux")]
        let expected =
            "allow::user::read\nallow::user:500:execute\nallow::group::read\nallow::mask::read,execute\nallow::other::read\n";
        #[cfg(target_os = "freebsd")]
        let expected =
            "allow::group::read\nallow::other::read\nallow::user:500:execute\nallow::user::read\nallow::mask::read,execute\n";
        assert_eq!(acl.to_string().unwrap(), expected);

        entries.push(AclEntry::allow_group("", Perm::WRITE, None));
        let err = Acl::from_entries(&entries).err().unwrap();
        assert_eq!(err.to_string(), "entry 4: duplicate entry for \"group\"");
    }
}

#[test]
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn test_from_unified_entries() {
    // 0 entries should result in empty acls.
    let (a, d) = Acl::from_unified_entries(&[]).unwrap();
    assert!(a.is_empty());
    assert!(d.is_empty());

    let mut entries = vec![
        AclEntry::allow_user("500", Perm::EXECUTE, None),
        AclEntry::allow_user("501", Perm::EXECUTE, Flag::DEFAULT),
    ];

    // Missing required entries.
    let err = Acl::from_unified_entries(&entries).err().unwrap();
    assert_eq!(err.to_string(), "missing required entry \"user\"");

    entries.push(AclEntry::allow_group("", Perm::WRITE, None));
    entries.push(AclEntry::allow_user("", Perm::READ, None));
    entries.push(AclEntry::allow_other(Perm::empty(), None));

    // Missing required default entries.
    let err = Acl::from_unified_entries(&entries).err().unwrap();
    assert_eq!(err.to_string(), "missing required default entry \"user\"");

    entries.push(AclEntry::allow_group("", Perm::WRITE, Flag::DEFAULT));
    entries.push(AclEntry::allow_user("", Perm::READ, Flag::DEFAULT));
    entries.push(AclEntry::allow_other(Perm::empty(), Flag::DEFAULT));

    let (a, d) = Acl::from_unified_entries(&entries).unwrap();

    #[cfg(target_os = "linux")]
    let expected1 = "allow::user::read\nallow::user:500:execute\nallow::group::write\nallow::mask::write,execute\nallow::other::\n";
    #[cfg(target_os = "freebsd")]
    let expected1 = "allow::user:500:execute\nallow::group::write\nallow::user::read\nallow::other::\nallow::mask::write,execute\n";
    assert_eq!(a.to_string().unwrap(), expected1);

    #[cfg(target_os = "linux")]
    let expected2 = "allow:default:user::read\nallow:default:user:501:execute\nallow:default:group::write\nallow:default:mask::write,execute\nallow:default:other::\n";
    #[cfg(target_os = "freebsd")]
    let expected2 = "allow:default:user:501:execute\nallow:default:group::write\nallow:default:user::read\nallow:default:other::\nallow:default:mask::write,execute\n";
    assert_eq!(d.to_string().unwrap(), expected2);

    entries.push(AclEntry::allow_group("", Perm::WRITE, Flag::DEFAULT));

    let err = Acl::from_unified_entries(&entries).err().unwrap();
    assert_eq!(
        err.to_string(),
        "entry 8: duplicate default entry for \"group\""
    );
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
