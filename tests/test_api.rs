//! API Tests for exacl module.

use ctor::ctor;
use exacl::{AclEntry, AclOption, Perm, getfacl, setfacl};
use log::debug;
use std::io;

#[cfg(target_os = "macos")]
use exacl::{ExtendedAclPresence, Flag, extended_acl_presence};
#[cfg(target_os = "macos")]
use std::fs::File;
#[cfg(target_os = "macos")]
use std::os::fd::AsFd;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::time::{SystemTime, UNIX_EPOCH};

#[ctor]
fn init() {
    env_logger::init();
}

#[cfg(target_os = "macos")]
fn persistent_acl_fixture(label: &str) -> PathBuf {
    let timestamp_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should follow the Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "exacl-fd-presence-{}-{timestamp_nanos}-{label}",
        std::process::id()
    ))
}

#[test]
#[cfg(target_os = "macos")]
#[ignore = "physical macOS ACL receipt; retains its unique fixtures for inspection"]
fn physical_extended_acl_presence_is_bound_to_the_retained_fd() -> io::Result<()> {
    let principal = std::env::var("USER").map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("USER must identify an ACL principal: {error}"),
        )
    })?;
    let original_path = persistent_acl_fixture("original");
    let retained_path = persistent_acl_fixture("retained");
    let inverse_original_path = persistent_acl_fixture("inverse-original");
    let inverse_retained_path = persistent_acl_fixture("inverse-retained");
    let inherited_dir = persistent_acl_fixture("inherited-dir");
    let inherited_child = inherited_dir.join("child");
    let inherited_child_dir = inherited_dir.join("child-dir");

    eprintln!(
        "physical ACL receipt platform: os={} arch={}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    eprintln!(
        "retained physical ACL fixtures: {}, {}, {}, {}, {}",
        original_path.display(),
        retained_path.display(),
        inverse_original_path.display(),
        inverse_retained_path.display(),
        inherited_dir.display()
    );

    let _original_creator = File::create_new(&original_path)?;
    let retained = File::open(&original_path)?;
    assert_eq!(
        extended_acl_presence(retained.as_fd())?,
        ExtendedAclPresence::Absent,
        "a clean read-only regular-file descriptor must report Absent"
    );

    let allow = AclEntry::allow_user(&principal, Perm::READ, None::<Flag>);
    setfacl(&[&original_path], std::slice::from_ref(&allow), None)?;
    assert_eq!(
        extended_acl_presence(retained.as_fd())?,
        ExtendedAclPresence::Present,
        "an ALLOW ACL must report Present through the retained read-only descriptor"
    );
    retained.metadata()?;

    let deny = AclEntry::deny_user(&principal, Perm::WRITE, None::<Flag>);
    setfacl(&[&original_path], &[deny], None)?;
    assert_eq!(
        extended_acl_presence(retained.as_fd())?,
        ExtendedAclPresence::Present,
        "a DENY ACL must report Present through the retained read-only descriptor"
    );

    setfacl(&[&original_path], &[], None)?;
    assert_eq!(
        extended_acl_presence(retained.as_fd())?,
        ExtendedAclPresence::Absent,
        "clearing the ACL must return the retained descriptor to Absent"
    );

    setfacl(&[&original_path], &[allow], None)?;
    std::fs::rename(&original_path, &retained_path)?;
    let _replacement_creator = File::create_new(&original_path)?;
    let replacement = File::open(&original_path)?;
    assert_eq!(
        extended_acl_presence(retained.as_fd())?,
        ExtendedAclPresence::Present,
        "the retained descriptor must not follow a replacement at its old pathname"
    );
    assert_eq!(
        extended_acl_presence(replacement.as_fd())?,
        ExtendedAclPresence::Absent,
        "the read-only replacement descriptor must remain ACL-free"
    );

    std::fs::create_dir(&inherited_dir)?;
    let clean_directory = File::open(&inherited_dir)?;
    assert_eq!(
        extended_acl_presence(clean_directory.as_fd())?,
        ExtendedAclPresence::Absent,
        "a clean read-only directory descriptor must report Absent"
    );
    let inheritable = AclEntry::allow_user(
        &principal,
        Perm::READ,
        Flag::FILE_INHERIT | Flag::DIRECTORY_INHERIT,
    );
    setfacl(&[&inherited_dir], &[inheritable], None)?;
    let _child_creator = File::create_new(&inherited_child)?;
    let child = File::open(&inherited_child)?;
    assert_eq!(
        extended_acl_presence(child.as_fd())?,
        ExtendedAclPresence::Present,
        "a read-only child-file descriptor must observe its inherited ACL"
    );
    std::fs::create_dir(&inherited_child_dir)?;
    let child_directory = File::open(&inherited_child_dir)?;
    assert_eq!(
        extended_acl_presence(child_directory.as_fd())?,
        ExtendedAclPresence::Present,
        "a read-only child-directory descriptor must observe its inherited ACL"
    );

    let _inverse_creator = File::create_new(&inverse_original_path)?;
    let inverse_retained = File::open(&inverse_original_path)?;
    std::fs::rename(&inverse_original_path, &inverse_retained_path)?;
    let _inverse_replacement_creator = File::create_new(&inverse_original_path)?;
    let inverse_replacement = File::open(&inverse_original_path)?;
    let inverse_allow = AclEntry::allow_user(&principal, Perm::READ, None::<Flag>);
    setfacl(
        &[&inverse_original_path],
        &[inverse_allow],
        None::<AclOption>,
    )?;
    assert_eq!(
        extended_acl_presence(inverse_retained.as_fd())?,
        ExtendedAclPresence::Absent,
        "an ACL-bearing replacement must not alter the retained original descriptor"
    );
    assert_eq!(
        extended_acl_presence(inverse_replacement.as_fd())?,
        ExtendedAclPresence::Present,
        "the ACL-bearing read-only replacement descriptor must report Present"
    );
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

    debug!("test_getfacl_file: {}", exacl::to_string(&entries)?);

    // Test default ACL on macOS (should fail).
    #[cfg(target_os = "macos")]
    {
        let result = getfacl(&file, AclOption::DEFAULT_ACL);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("macOS does not support default ACL")
        );
    }

    // Test default ACL (should be error; files don't have default ACL).
    #[cfg(target_os = "linux")]
    {
        let result = getfacl(&file, AclOption::DEFAULT_ACL);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Permission denied")
        );
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
    let mut df = std::process::Command::new("df")
        .arg("-Th")
        .arg(path)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("df is a valid unix command");
    let mut sed = std::process::Command::new("sed")
        .arg("1d")
        .stdin(df.stdout.take().unwrap())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("sed is a valid unix command");
    let mut tr = std::process::Command::new("tr")
        .arg("-s")
        .arg(" ")
        .stdin(sed.stdout.take().unwrap())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("tr is a valid unix command");
    let cut = std::process::Command::new("cut")
        .arg("-d")
        .arg(" ")
        .arg("-f2")
        .stdin(tr.stdout.take().unwrap())
        .output()
        .expect("cut is a valid unix command");

    df.wait().expect("df wait");
    sed.wait().expect("sed wait");
    tr.wait().expect("tr wait");

    String::from_utf8(cut.stdout)
        .expect("FS should be valid utf8")
        .trim_end()
        .to_string()
}

#[test]
#[cfg(target_os = "linux")]
fn test_too_many_entries() -> io::Result<()> {
    use std::collections::HashMap;
    const UNTESTED: usize = 65535;

    let path = std::env::temp_dir();
    let fs = get_filesystem(&path);
    debug!("Running on filesystem: {{{fs}}} TMPDIR={path:?}");

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
        ("overlay", 507), // assume ext4 is underlying filesystem (Github Action)
    ]);
    assert!(
        supported_fs.contains_key(fs.as_str()),
        "Not a supported filesystem: {fs}"
    );
    let max_entries = supported_fs[fs.as_str()];
    if max_entries == UNTESTED {
        debug!("Filesystem {fs} is not tested!");
    }

    let mut entries = vec![
        AclEntry::allow_user("", Perm::READ, None),
        AclEntry::allow_group("", Perm::READ, None),
        AclEntry::allow_other(Perm::empty(), None),
        AclEntry::allow_mask(Perm::READ, None),
    ];
    let max_entries = max_entries.saturating_sub(entries.len());

    let offset = 500;
    for i in 0..max_entries {
        entries.push(AclEntry::allow_user(
            (offset + i).to_string().as_str(),
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
        (offset + max_entries + 1).to_string().as_str(),
        Perm::READ,
        None,
    ));

    // Last entry is one too many.
    let err = setfacl(&files, &entries, None).unwrap_err();
    debug!("Got error as expected: {err}");
    assert!(
        err.to_string().contains("No space left on device")
            || err.to_string().contains("Argument list too long")
    );

    Ok(())
}

#[test]
fn test_reader_writer() -> io::Result<()> {
    let input = r"
    u:aaa:rwx#comment
    g:bbb:rwx
    u:ccc:rx
    ";

    let entries = exacl::from_str(input)?;
    let actual = exacl::to_string(&entries)?;

    let expected = r"allow::user:aaa:read,write,execute
allow::group:bbb:read,write,execute
allow::user:ccc:read,execute
";
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
    assert_eq!(
        acl_7777,
        "allow::user::read,write,execute\nallow::group::read,write,execute\nallow::other::read,write,execute\n"
    );

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
