var searchIndex = JSON.parse('{\
"exacl":{"doc":"exacl","t":[3,3,3,12,12,12,12,12,4,13,13,13,13,13,13,3,3,5,5,5,5,5,5,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,18,18,18,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,18,18,18,18,18,18,18,11,11,11,11,11,11,11,11,11,11,11,11,11,11,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,11,11,11,11,11,11,11,11,11,11,11,11,11,11],"n":["Acl","AclOption","AclEntry","kind","name","perms","flags","allow","AclEntryKind","User","Group","Mask","Other","Everyone","Unknown","Flag","Perm","getfacl","setfacl","to_writer","from_reader","to_string","from_str","from","into","to_owned","clone_into","borrow","borrow_mut","try_from","try_into","type_id","from","into","borrow","borrow_mut","try_from","try_into","type_id","from","into","to_owned","clone_into","to_string","borrow","borrow_mut","try_from","try_into","type_id","from","into","to_owned","clone_into","to_string","borrow","borrow_mut","try_from","try_into","type_id","from","into","to_owned","clone_into","to_string","borrow","borrow_mut","try_from","try_into","type_id","from","into","to_owned","clone_into","to_string","borrow","borrow_mut","try_from","try_into","type_id","drop","extend","extend","extend","clone","clone","clone","clone","clone","default","default","default","cmp","cmp","cmp","cmp","cmp","eq","ne","eq","eq","ne","eq","ne","eq","ne","partial_cmp","partial_cmp","partial_cmp","partial_cmp","partial_cmp","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","sub","sub","sub","sub_assign","sub_assign","sub_assign","not","not","not","bitand","bitand","bitand","bitor","bitor","bitor","bitxor","bitxor","bitxor","bitand_assign","bitand_assign","bitand_assign","bitor_assign","bitor_assign","bitor_assign","bitxor_assign","bitxor_assign","bitxor_assign","hash","hash","hash","from_str","from_str","from_str","from_str","from_iter","from_iter","from_iter","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","serialize","serialize","serialize","serialize","deserialize","deserialize","deserialize","deserialize","ACCESS_ACL","DEFAULT_ACL","SYMLINK_ACL","empty","all","bits","from_bits","from_bits_truncate","from_bits_unchecked","is_empty","is_all","intersects","contains","insert","remove","toggle","set","read","write","from_entries","from_unified_entries","entries","to_string","is_empty","is_posix","is_nfs4","allow_user","allow_group","allow_mask","allow_other","deny_user","deny_group","INHERITED","FILE_INHERIT","DIRECTORY_INHERIT","LIMIT_INHERIT","ONLY_INHERIT","DEFAULT","NFS4_SPECIFIC","empty","all","bits","from_bits","from_bits_truncate","from_bits_unchecked","is_empty","is_all","intersects","contains","insert","remove","toggle","set","READ","WRITE","EXECUTE","DELETE","APPEND","DELETE_CHILD","READATTR","WRITEATTR","READEXTATTR","WRITEEXTATTR","READSECURITY","WRITESECURITY","CHOWN","SYNC","READ_DATA","WRITE_DATA","POSIX_SPECIFIC","NFS4_SPECIFIC","empty","all","bits","from_bits","from_bits_truncate","from_bits_unchecked","is_empty","is_all","intersects","contains","insert","remove","toggle","set"],"q":["exacl","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","",""],"d":["Access Control List native object wrapper.","Controls how ACL’s are accessed.","ACL entry with allow/deny semantics.","Kind of entry (User, Group, Other, Mask, Everyone, or …","Name of the principal being given access. You can use a …","Permission bits for the entry.","Flags indicating whether an entry is inherited, etc.","True if entry is allowed; false means deny. Linux only …","Kind of ACL entry (User, Group, Mask, Other, or Unknown).","Entry represents a user.","Entry represents a group.","Entry represents a Posix.1e “mask” entry.","Entry represents a Posix.1e “other” entry.","Entry represents a NFS “everyone” entry.","Entry represents a possibly corrupt ACL entry, caused by …","Represents ACL entry inheritance flags.","Represents file access permissions.","Get access control list (ACL) for a file or directory.","Set access control list (ACL) for specified files and …","Write ACL entries to text.","Read ACL entries from text.","Write ACL entries to text.","Read ACL entries from text.","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","Format an <code>AclEntry</code> 5-tuple: ::::","","","Returns the set difference of the two sets of flags.","Returns the set difference of the two sets of flags.","Returns the set difference of the two sets of flags.","Disables all flags enabled in the set.","Disables all flags enabled in the set.","Disables all flags enabled in the set.","Returns the complement of this set of flags.","Returns the complement of this set of flags.","Returns the complement of this set of flags.","Returns the intersection between the two sets of flags.","Returns the intersection between the two sets of flags.","Returns the intersection between the two sets of flags.","Returns the union of the two sets of flags.","Returns the union of the two sets of flags.","Returns the union of the two sets of flags.","Returns the left flags, but with all the right flags …","Returns the left flags, but with all the right flags …","Returns the left flags, but with all the right flags …","Disables all flags disabled in the set.","Disables all flags disabled in the set.","Disables all flags disabled in the set.","Adds the set of flags.","Adds the set of flags.","Adds the set of flags.","Toggles the set of flags.","Toggles the set of flags.","Toggles the set of flags.","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","Get/set the access ACL only (Linux and FreeBSD only).","Get/set the default ACL only (Linux and FreeBSD only).","Get/set the ACL of the symlink itself (macOS only).","Returns an empty set of flags","Returns the set containing all flags.","Returns the raw value of the flags currently stored.","Convert from underlying bit representation, unless that …","Convert from underlying bit representation, dropping any …","Convert from underlying bit representation, preserving all…","Returns <code>true</code> if no flags are currently stored.","Returns <code>true</code> if all flags are currently set.","Returns <code>true</code> if there are flags common to both <code>self</code> and …","Returns <code>true</code> all of the flags in <code>other</code> are contained …","Inserts the specified flags in-place.","Removes the specified flags in-place.","Toggles the specified flags in-place.","Inserts or removes the specified flags depending on the …","Read ACL for the specified file.","Write ACL for the specified file.","Return an ACL from a slice of [<code>AclEntry</code>].","Return pair of ACL’s from slice of [<code>AclEntry</code>]. This …","Return ACL as a vector of [<code>AclEntry</code>].","Return ACL as a string.","Return true if ACL is empty.","Return true if ACL is a Posix.1e ACL on Linux or <code>FreeBSD</code>.","Return true if file uses an NFSv4 ACL (<code>FreeBSD</code> only).","Construct an ALLOW access control entry for a user.","Construct an ALLOW access control entry for a group.","Construct an ALLOW access control entry for mask.","Construct an ALLOW access control entry for other.","Construct a DENY access control entry for a user.","Construct a DENY access control entry for a group.","ACL entry was inherited.","Inherit to files.","Inherit to directories.","Clear the DIRECTORY_INHERIT flag in the ACL entry that is …","Don’t consider this entry when processing the ACL. Just …","Specifies a default ACL entry on Linux.","NFSv4 Specific Flags on FreeBSD.","Returns an empty set of flags","Returns the set containing all flags.","Returns the raw value of the flags currently stored.","Convert from underlying bit representation, unless that …","Convert from underlying bit representation, dropping any …","Convert from underlying bit representation, preserving all…","Returns <code>true</code> if no flags are currently stored.","Returns <code>true</code> if all flags are currently set.","Returns <code>true</code> if there are flags common to both <code>self</code> and …","Returns <code>true</code> all of the flags in <code>other</code> are contained …","Inserts the specified flags in-place.","Removes the specified flags in-place.","Toggles the specified flags in-place.","Inserts or removes the specified flags depending on the …","READ_DATA permission for a file. Same as LIST_DIRECTORY …","WRITE_DATA permission for a file. Same as ADD_FILE …","EXECUTE permission for a file. Same as SEARCH permission …","DELETE permission for a file.","APPEND_DATA permission for a file. Same as …","DELETE_CHILD permission for a directory.","READ_ATTRIBUTES permission for file or directory.","WRITE_ATTRIBUTES permission for a file or directory.","READ_EXTATTRIBUTES permission for a file or directory.","WRITE_EXTATTRIBUTES permission for a file or directory.","READ_SECURITY permission for a file or directory.","WRITE_SECURITY permission for a file or directory.","CHANGE_OWNER permission for a file or directory.","SYNCHRONIZE permission (unsupported).","NFSv4 READ_DATA permission.","NFSv4 WRITE_DATA permission.","Posix specific permissions.","All NFSv4 specific permissions.","Returns an empty set of flags","Returns the set containing all flags.","Returns the raw value of the flags currently stored.","Convert from underlying bit representation, unless that …","Convert from underlying bit representation, dropping any …","Convert from underlying bit representation, preserving all…","Returns <code>true</code> if no flags are currently stored.","Returns <code>true</code> if all flags are currently set.","Returns <code>true</code> if there are flags common to both <code>self</code> and …","Returns <code>true</code> all of the flags in <code>other</code> are contained …","Inserts the specified flags in-place.","Removes the specified flags in-place.","Toggles the specified flags in-place.","Inserts or removes the specified flags depending on the …"],"i":[0,0,0,1,1,1,1,1,0,2,2,2,2,2,2,0,0,0,0,0,0,0,0,3,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,2,2,2,2,2,2,2,2,2,2,1,1,1,1,1,1,1,1,1,1,5,5,5,5,5,5,5,5,5,5,6,6,6,6,6,6,6,6,6,6,4,3,5,6,3,2,1,5,6,3,5,6,3,2,1,5,6,3,3,2,1,1,5,5,6,6,3,2,1,5,6,3,2,1,5,6,2,1,5,6,3,5,6,3,5,6,3,5,6,3,5,6,3,5,6,3,5,6,3,5,6,3,5,6,3,5,6,3,5,6,2,1,5,6,3,5,6,3,5,6,3,5,6,3,5,6,3,5,6,2,1,5,6,2,1,5,6,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,4,1,1,1,1,1,1,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6],"f":[null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,[[],[["result",6],["vec",3]]],[[],["result",6]],[[["write",8]],["result",6]],[[["read",8]],[["result",6],["vec",3]]],[[],[["result",6],["string",3]]],[[["str",15]],[["result",6],["vec",3]]],[[]],[[]],[[]],[[]],[[]],[[]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[]],[[]],[[]],[[]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[]],[[]],[[]],[[]],[[],["string",3]],[[]],[[]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[]],[[]],[[]],[[]],[[],["string",3]],[[]],[[]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[]],[[]],[[]],[[]],[[],["string",3]],[[]],[[]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[]],[[]],[[]],[[]],[[],["string",3]],[[]],[[]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[]],[[["intoiterator",8]]],[[["intoiterator",8]]],[[["intoiterator",8]]],[[],["acloption",3]],[[],["aclentrykind",4]],[[],["aclentry",3]],[[],["flag",3]],[[],["perm",3]],[[],["acloption",3]],[[],["flag",3]],[[],["perm",3]],[[["acloption",3]],["ordering",4]],[[["aclentrykind",4]],["ordering",4]],[[],["ordering",4]],[[["flag",3]],["ordering",4]],[[["perm",3]],["ordering",4]],[[["acloption",3]],["bool",15]],[[["acloption",3]],["bool",15]],[[["aclentrykind",4]],["bool",15]],[[["aclentry",3]],["bool",15]],[[["aclentry",3]],["bool",15]],[[["flag",3]],["bool",15]],[[["flag",3]],["bool",15]],[[["perm",3]],["bool",15]],[[["perm",3]],["bool",15]],[[["acloption",3]],[["option",4],["ordering",4]]],[[["aclentrykind",4]],[["option",4],["ordering",4]]],[[],[["option",4],["ordering",4]]],[[["flag",3]],[["option",4],["ordering",4]]],[[["perm",3]],[["option",4],["ordering",4]]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["acloption",3]],["acloption",3]],[[["flag",3]],["flag",3]],[[["perm",3]],["perm",3]],[[["acloption",3]]],[[["flag",3]]],[[["perm",3]]],[[],["acloption",3]],[[],["flag",3]],[[],["perm",3]],[[["acloption",3]],["acloption",3]],[[["flag",3]],["flag",3]],[[["perm",3]],["perm",3]],[[["acloption",3]],["acloption",3]],[[["flag",3]],["flag",3]],[[["perm",3]],["perm",3]],[[["acloption",3]],["acloption",3]],[[["flag",3]],["flag",3]],[[["perm",3]],["perm",3]],[[["acloption",3]]],[[["flag",3]]],[[["perm",3]]],[[["acloption",3]]],[[["flag",3]]],[[["perm",3]]],[[["acloption",3]]],[[["flag",3]]],[[["perm",3]]],[[]],[[]],[[]],[[["str",15]],["result",4]],[[["str",15]],["result",4]],[[["str",15]],["result",4]],[[["str",15]],["result",4]],[[["intoiterator",8]],["acloption",3]],[[["intoiterator",8]],["flag",3]],[[["intoiterator",8]],["perm",3]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],null,null,null,[[],["acloption",3]],[[],["acloption",3]],[[],["u32",15]],[[["u32",15]],[["option",4],["acloption",3]]],[[["u32",15]],["acloption",3]],[[["u32",15]],["acloption",3]],[[],["bool",15]],[[],["bool",15]],[[["acloption",3]],["bool",15]],[[["acloption",3]],["bool",15]],[[["acloption",3]]],[[["acloption",3]]],[[["acloption",3]]],[[["bool",15],["acloption",3]]],[[["path",3],["acloption",3]],[["result",6],["acl",3]]],[[["path",3],["acloption",3]],["result",6]],[[],[["result",6],["acl",3]]],[[],["result",6]],[[],[["result",6],["vec",3]]],[[],[["result",6],["string",3]]],[[],["bool",15]],[[],["bool",15]],[[["path",3],["acloption",3]],[["bool",15],["result",6]]],[[["perm",3],["str",15]],["aclentry",3]],[[["perm",3],["str",15]],["aclentry",3]],[[["perm",3]],["aclentry",3]],[[["perm",3]],["aclentry",3]],[[["perm",3],["str",15]],["aclentry",3]],[[["perm",3],["str",15]],["aclentry",3]],null,null,null,null,null,null,null,[[],["flag",3]],[[],["flag",3]],[[],["u32",15]],[[["u32",15]],[["flag",3],["option",4]]],[[["u32",15]],["flag",3]],[[["u32",15]],["flag",3]],[[],["bool",15]],[[],["bool",15]],[[["flag",3]],["bool",15]],[[["flag",3]],["bool",15]],[[["flag",3]]],[[["flag",3]]],[[["flag",3]]],[[["flag",3],["bool",15]]],null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,[[],["perm",3]],[[],["perm",3]],[[],["c_uint",6]],[[["c_uint",6]],[["option",4],["perm",3]]],[[["c_uint",6]],["perm",3]],[[["c_uint",6]],["perm",3]],[[],["bool",15]],[[],["bool",15]],[[["perm",3]],["bool",15]],[[["perm",3]],["bool",15]],[[["perm",3]]],[[["perm",3]]],[[["perm",3]]],[[["bool",15],["perm",3]]]],"p":[[3,"AclEntry"],[4,"AclEntryKind"],[3,"AclOption"],[3,"Acl"],[3,"Flag"],[3,"Perm"]]}\
}');
initSearch(searchIndex);