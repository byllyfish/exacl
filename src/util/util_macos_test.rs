use crate::qualifier::Qualifier;
use crate::sys::*;
use crate::util::util_macos::xacl_set_qualifier;
use crate::util::*;

use ctor::ctor;
use uuid::Uuid;

#[ctor]
fn init() {
    env_logger::init();
}

#[test]
fn test_acl_init() {
    use std::convert::TryInto;
    let max_entries: usize = ACL_MAX_ENTRIES.try_into().unwrap();

    let acl = xacl_init(max_entries).ok().unwrap();
    assert!(!acl.is_null());
    xacl_free(acl);

    // Custom error if we try to allocate MAX_ENTRIES + 1.
    let err = xacl_init(max_entries + 1).unwrap_err();
    assert_eq!(err.to_string(), "Too many ACL entries");
}

#[test]
fn test_acl_too_big() {
    let mut acl = xacl_init(3).ok().unwrap();
    assert!(!acl.is_null());

    for _ in 0..ACL_MAX_ENTRIES {
        xacl_create_entry(&mut acl).unwrap();
    }

    // Memory error if we try to allocate MAX_ENTRIES + 1.
    let err = xacl_create_entry(&mut acl).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(sg::ENOMEM));

    xacl_free(acl);
}

#[test]
fn test_acl_api_misuse() {
    let mut acl = xacl_init(1).unwrap();
    let entry = xacl_create_entry(&mut acl).unwrap();

    // Setting tag other than 1 or 2 results in EINVAL error.
    let err = xacl_set_tag_type(entry, 0).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(sg::EINVAL));

    // Setting qualifier without first setting tag to a valid value results in EINVAL.
    let err = xacl_set_qualifier(entry, &Qualifier::Guid(Uuid::nil())).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(sg::EINVAL));

    assert_eq!(xacl_to_text(acl).unwrap(), "!#acl 1\n");

    let entry2 = xacl_create_entry(&mut acl).unwrap();
    xacl_set_tag_type(entry2, 1).unwrap();

    assert_eq!(
        xacl_to_text(acl).unwrap(),
        "!#acl 1\nuser:00000000-0000-0000-0000-000000000000:::allow\n"
    );

    // There are still two entries... one is corrupt.
    assert_eq!(xacl_entry_count(acl), 2);
    xacl_free(acl);
}
