use crate::qualifier::Qualifier;
use crate::sys::*;
use crate::util::util_freebsd::xacl_set_qualifier;
use crate::util::*;

#[test]
fn test_acl_api_misuse() {
    // Create empty list and add an entry.
    let mut acl = xacl_init(1).unwrap();
    let entry = xacl_create_entry(&mut acl).unwrap();

    // Setting tag other than 1 or 2 results in EINVAL error.
    let err = xacl_set_tag_type(entry, 0).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(sg::EINVAL));

    // Setting qualifier without first setting tag to a valid value results in EINVAL.
    let err = xacl_set_qualifier(entry, 500).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(sg::EINVAL));

    // Try to set entry using unknown qualifier -- this should fail.
    let err =
        xacl_set_tag_qualifier(entry, true, &Qualifier::Unknown("x".to_string())).unwrap_err();
    assert!(err.to_string().contains("unknown tag: x"));

    // Even though ACL contains 1 invalid entry, the platform text still
    // results in empty string.
    #[cfg(target_os = "linux")]
    assert_eq!(xacl_to_text(acl).unwrap(), "");

    // Add another entry and set it to a valid value.
    let entry2 = xacl_create_entry(&mut acl).unwrap();
    xacl_set_tag_type(entry2, sg::ACL_USER_OBJ).unwrap();

    // ACL only prints the one valid entry; no sign of other entry.
    #[cfg(target_os = "linux")]
    assert_eq!(xacl_to_text(acl).unwrap(), "\nuser::---\n");

    // There are still two entries... one is corrupt.
    assert_eq!(xacl_entry_count(acl), 2);

    xacl_free(acl);
}

#[test]
fn test_empty_acl() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let dir = tempfile::TempDir::new().unwrap();

    let acl = xacl_init(1).unwrap();
    assert!(xacl_is_empty(acl));

    // Empty acl is not "valid".
    let ret = unsafe { acl_valid(acl) };
    assert_eq!(ret, -1);

    // Not on FreeBSD.
    let err = xacl_set_file(file.as_ref(), acl, false, false)
        .err()
        .unwrap();
    assert_eq!(err.to_string(), "Invalid argument (os error 22)");

    // Write an empty default ACL to a file. Still works?
    #[cfg(target_os = "linux")]
    xacl_set_file(file.as_ref(), acl, false, true).ok().unwrap();

    // Write an empty access ACL to a directory. Still works?
    #[cfg(target_os = "linux")]
    xacl_set_file(dir.as_ref(), acl, false, false).ok().unwrap();

    // Write an empty default ACL to a directory. Okay on Linux, FreeBSD.
    xacl_set_file(dir.as_ref(), acl, false, true).ok().unwrap();

    xacl_free(acl);
}
