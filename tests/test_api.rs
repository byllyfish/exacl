//! API Tests for exacl module.

use ctor::ctor;
use exacl::{getfacl, setfacl, AclEntry, AclOption, Perm};
use log::{debug, warn};
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

    debug!("test_getfacl_file: {}", exacl::to_string(&entries)?);

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
fn test_setfacl_file() -> io::Result<()> {
    let file = tempfile::NamedTempFile::new()?;
    let mut entries = getfacl(&file, None)?;

    entries.push(AclEntry::allow_user("500", Perm::READ, None));
    setfacl(&[file], &entries, None)?;

    Ok(())
}

/// Get the type of filesystem from `df -Th` command output.
#[cfg(target_os = "linux")]
fn get_filesystem(path: &std::path::PathBuf) -> String {
    let df = std::process::Command::new("df")
        .arg("-Th")
        .arg(path)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("df is a valid unix command");
    let sed = std::process::Command::new("sed")
        .arg("1d")
        .stdin(df.stdout.unwrap())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("sed is a valid unix command");
    let tr = std::process::Command::new("tr")
        .arg("-s")
        .arg(" ")
        .stdin(sed.stdout.unwrap())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("tr is a valid unix command");
    let cut = std::process::Command::new("cut")
        .arg("-d")
        .arg(" ")
        .arg("-f2")
        .stdin(tr.stdout.unwrap())
        .output()
        .expect("cut is a valid unix command");
    String::from_utf8(cut.stdout)
        .expect("FS should be valid utf8")
        .trim_end()
        .to_string()
}

#[test]
#[cfg(target_os = "linux")]
fn test_too_many_entries() -> io::Result<()> {
    use std::collections::HashMap;
    const UNTESTED: u32 = 65535;

    let path = std::env::temp_dir();
    let fs = get_filesystem(&path);
    debug!("Running on filesystem: {{{}}} TMPDIR={:?}", fs, path);

    let supported_fs = HashMap::from([
        ("brtfs", UNTESTED),
        // FIXME: xfs is not tested. -wwf
        // https://elixir.bootlin.com/linux/latest/source/fs/xfs/libxfs/xfs_format.h#L1809
        ("xfs", 5461), // max ext attr size = 64KB
        ("tmpfs", 8191),
        ("ext2", 507),
        ("ext3", 507),
        ("ext4", 507),
        ("gpfs", UNTESTED),
        ("nss", UNTESTED),
    ]);
    assert!(
        supported_fs.contains_key(fs.as_str()),
        "Not a supported filesystem: {fs}"
    );
    let max_entries = supported_fs[fs.as_str()];
    if max_entries == UNTESTED {
        warn!("Filesystem {} is not tested!", fs);
    }

    let mut entries = vec![
        AclEntry::allow_user("", Perm::READ, None),
        AclEntry::allow_group("", Perm::READ, None),
        AclEntry::allow_other(Perm::empty(), None),
        AclEntry::allow_mask(Perm::READ, None),
    ];
    let max_entries = max_entries.saturating_sub(u32::try_from(entries.len()).unwrap());

    let offset = 500;
    for i in 0..max_entries {
        entries.push(AclEntry::allow_user(
            &(offset + i as usize).to_string(),
            Perm::READ,
            None,
        ));
    }

    let files = [tempfile::NamedTempFile::new_in(path)?];
    debug!("Call setfacl with {} entries...", entries.len());
    setfacl(&files, &entries, None)?;
    debug!("{} entries were added and it is okay", entries.len());

    // Add last entry.
    entries.push(AclEntry::allow_user(
        (u32::MAX - 1).to_string().as_str(),
        Perm::READ,
        None,
    ));

    // Last entry is one too many.
    let err = setfacl(&files, &entries, None).unwrap_err();
    debug!("Got error as expected: {}", err);
    assert!(
        err.to_string().contains("No space left on device")
            || err.to_string().contains("Argument list too long")
    );

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

    let err1 = getfacl(path, AclOption::ACCESS_ACL | AclOption::DEFAULT_ACL).unwrap_err();
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

    let err1 = getfacl(path, AclOption::ACCESS_ACL | AclOption::DEFAULT_ACL).unwrap_err();
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
