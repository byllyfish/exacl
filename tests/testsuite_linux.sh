#! /usr/bin/env bash

# Basic test suite for exacl tool (Linux).

set -u -o pipefail

EXACL='../target/debug/examples/exacl'

# Add memcheck command if defined.
if [ -n "${MEMCHECK+x}" ]; then
    echo "# MEMCHECK=$MEMCHECK"
    EXACL="$MEMCHECK $EXACL"
fi

ME=$(id -un)
ME_NUM=$(id -u)
MY_GROUP=$(id -gn)
MY_GROUP_NUM=$(id -g)

# Return true if file is readable.
isReadable() {
    cat "$1" >/dev/null 2>&1
    return $?
}

# Return true if file is writable (tries to overwrite file).
isWritable() {
    echo "x" 2>/dev/null >"$1"
    # shellcheck disable=SC2320
    return $?
}

# Return true if directory is readable.
isReadableDir() {
    ls "$1" >/dev/null 2>&1
    return $?
}

# Return true if link is readable.
isReadableLink() {
    readlink "$1" >/dev/null 2>&1
    return $?
}

fileperms() {
    stat -c "%A" "$1"
}

# Put quotes back on JSON text.
quotifyJson() {
    echo "$1" | sed -E -e 's/([@A-Za-z0-9_-]+)/"\1"/g' -e 's/:"false"/:false/g' -e 's/:"true"/:true/g' -e 's/:,/:"",/g'
}

# Called by shunit2 before all tests run.
oneTimeSetUp() {
    # Check that getfacl is installed.
    if ! hash getfacl; then
        echo "FAILURE: Linux tests require the getfacl and setfacl commands. Please install the acl package."
        exit 1
    fi

    # Use temp directory managed by shunit2.
    DIR="$SHUNIT_TMPDIR"
    FILE1="$DIR/file1"
    DIR1="$DIR/dir1"
    LINK1="$DIR/link1"

    # Create empty file, dir, and link.
    umask 077
    touch "$FILE1"
    mkdir "$DIR1"
    ln -s link1_to_nowhere "$LINK1"
}

REQUIRED_ENTRIES="{kind:user,name:,perms:[read,write],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}"

testReadAclFromMissingFile() {
    msg=$($EXACL $DIR/non_existant 2>&1)
    assertEquals 1 $?
    assertEquals \
        "File \"$DIR/non_existant\": No such file or directory (os error 2)" \
        "$msg"
}

testReadAclForFile1() {
    msg=$($EXACL $FILE1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read,write],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"

    assertEquals "-rw-------" "$(fileperms $FILE1)"
    isReadable "$FILE1" && isWritable "$FILE1"
    assertEquals 0 $?

    # Add ACL entry for current user to "write-only". (Note: owner still has read access)
    setfacl -m "u:$ME:w" "$FILE1"

    msg=$($EXACL $FILE1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read,write],flags:[],allow:true},{kind:user,name:$ME,perms:[write],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:mask,name:,perms:[write],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"

    assertEquals "-rw--w----" "$(fileperms $FILE1)"
    isReadable "$FILE1" && isWritable "$FILE1"
    assertEquals 0 $?

    # Remove owner read perm.
    chmod u-rw "$FILE1"

    assertEquals "-----w----" "$(fileperms $FILE1)"
    ! isReadable "$FILE1" && ! isWritable "$FILE1"
    assertEquals 0 $?

    # Add ACL entry for current group to "allow write".
    setfacl -m "g:$MY_GROUP:w" "$FILE1"

    msg=$($EXACL $FILE1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[],flags:[],allow:true},{kind:user,name:$ME,perms:[write],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:group,name:$MY_GROUP,perms:[write],flags:[],allow:true},{kind:mask,name:,perms:[write],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"

    assertEquals "-----w----" "$(fileperms $FILE1)"
    ! isReadable "$FILE1" && ! isWritable "$FILE1"
    assertEquals 0 $?

    # Reset permissions.
    chmod 600 "$FILE1"
    setfacl -b "$FILE1"
}

testReadAclForDir1() {
    msg=$($EXACL $DIR1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read,write,execute],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"

    # Add ACL entry for current user to "write-only". (Note: owner still has read access)
    setfacl -m "u:$ME:w" "$DIR1"

    msg=$($EXACL $DIR1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read,write,execute],flags:[],allow:true},{kind:user,name:$ME,perms:[write],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:mask,name:,perms:[write],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"

    assertEquals "drwx-w----" "$(fileperms $DIR1)"
    isReadableDir "$DIR1"
    assertEquals 0 $?

    # TODO: test default ACL in a separate test.

    # Clear directory ACL's so we can delete them.
    setfacl -b "$DIR1"
}

testReadAclForLink1() {
    # Test symlink with no ACL. Not supported on Linux.
    msg=$($EXACL $LINK1 2>&1)
    assertEquals 1 $?
    assertEquals "File \"$LINK1\": No such file or directory (os error 2)" "$msg"

    # Test symlink with no ACL. Not supported on Linux.
    msg=$($EXACL --symlink $LINK1 2>&1)
    assertEquals 1 $?
    assertEquals "File \"$LINK1\": Linux does not support symlinks with ACL's." "$msg"
}

testWriteAclToMissingFile() {
    input="[]"
    msg=$(echo "$input" | $EXACL --set $DIR/non_existant 2>&1)
    assertEquals 1 $?
    assertEquals \
        "Invalid ACL: missing required entries" \
        "$msg"

    input=$(quotifyJson "[{kind:user,name:,perms:[read,write],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $DIR/non_existant 2>&1)
    assertEquals 1 $?
    assertEquals \
        "File \"$DIR/non_existant\": No such file or directory (os error 2)" \
        "$msg"
}

testWriteAclToFile1() {
    # Set ACL to empty.
    input="[]"
    msg=$(echo "$input" | $EXACL --set $FILE1 2>&1)
    assertEquals "set acl to empty" 1 $?
    assertEquals \
        "Invalid ACL: missing required entries" \
        "$msg"

    # Verify ACL.
    msg=$($EXACL $FILE1)
    assertEquals "verify acl" 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read,write],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"

    assertEquals "-rw-------" "$(fileperms $FILE1)"
    isReadable "$FILE1" && isWritable "$FILE1"
    assertEquals "is readable" 0 $?

    # Set ACL for current user to "allow:false". This fails on Linux.
    input=$(quotifyJson "[{kind:user,name:$ME,perms:[read],flags:[],allow:false}]")
    msg=$(echo "$input" | $EXACL --set $FILE1 2>&1)
    assertEquals "check failure" 1 $?
    assertEquals \
        "Invalid ACL: entry 0: allow=false is not supported on Linux" \
        "$msg"

    # Set ACL for current user specifically.
    input=$(quotifyJson "[{kind:user,name:$ME,perms:[read],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $FILE1 2>&1)
    assertEquals "check required entry" 1 $?
    assertEquals \
        'Invalid ACL: missing required entry "user"' \
        "$msg"

    # Set ACL for current user specifically, with required entries.
    input=$(quotifyJson "[{kind:user,name:,perms:[read,write],flags:[],allow:true},{kind:group,name:,perms:[read,write],flags:[], allow:true},{kind:mask,name:,perms:[read],flags:[], allow:true},{kind:other,name:,perms:[],flags:[], allow:true},{kind:user,name:$ME,perms:[read],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $FILE1 2>&1)
    assertEquals "check set acl" 0 $?
    assertEquals \
        "" \
        "${msg//\"/}"

    # Check ACL again.
    msg=$($EXACL $FILE1)
    assertEquals "check acl again" 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read,write],flags:[],allow:true},{kind:user,name:$ME,perms:[read],flags:[],allow:true},{kind:group,name:,perms:[read,write],flags:[],allow:true},{kind:mask,name:,perms:[read],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"

    # Check ACL with getfacl.
    msg=$(getfacl -cE $FILE1 2>/dev/null)
    assertEquals "check acl getfacl" 0 $?
    assertEquals \
        "user::rw-
user:$ME:r--
group::rw-
mask::r--
other::---" \
        "${msg}"
}

testWriteAclToDir1() {
    # Set ACL to empty.
    input="[]"
    msg=$(echo "$input" | $EXACL --set $DIR1 2>&1)
    assertEquals 1 $?
    assertEquals \
        "Invalid ACL: missing required entries" \
        "$msg"

    # Verify directory ACL.
    msg=$($EXACL $DIR1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read,write,execute],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"

    assertEquals "drwx------" "$(fileperms $DIR1)"
    isReadableDir "$DIR1"
    assertEquals 0 $?

    # Set ACL for current user to "deny read". Fails on Linux.
    input=$(quotifyJson "[{kind:user,name:$ME,perms:[read],flags:[],allow:false}]")
    msg=$(echo "$input" | $EXACL --set $DIR1 2>&1)
    assertEquals 1 $?
    assertEquals \
        "Invalid ACL: entry 0: allow=false is not supported on Linux" \
        "$msg"

    # Set ACL without mask entry.
    input=$(quotifyJson "[{kind:user,name:$ME,perms:[read],flags:[],allow:true},{kind:user,name:,perms:[read,write,execute],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $DIR1 2>&1)
    assertEquals 0 $?
    assertEquals \
        "" \
        "$msg"

    # Read ACL back.
    msg=$($EXACL $DIR1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read,write,execute],flags:[],allow:true},{kind:user,name:$ME,perms:[read],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:mask,name:,perms:[read],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"

    # Set ACL with mask entry.
    input=$(quotifyJson "[{kind:mask,name:,perms:[read],flags:[],allow:true},{kind:user,name:$ME,perms:[read],flags:[],allow:true},{kind:user,name:,perms:[read,write,execute],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $DIR1 2>&1)
    assertEquals 0 $?
    assertEquals \
        "" \
        "$msg"

    # Read ACL back.
    msg=$($EXACL $DIR1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read,write,execute],flags:[],allow:true},{kind:user,name:$ME,perms:[read],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:mask,name:,perms:[read],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"

    assertEquals "drwxr-----" "$(fileperms $DIR1)"

    # Check ACL with getfacl.
    msg=$(getfacl -cE $DIR1 2>/dev/null)
    assertEquals "check acl getfacl" 0 $?
    assertEquals \
        "user::rwx
user:$ME:r--
group::---
mask::r--
other::---" \
        "${msg}"

    # Reset ACL back to the original.
    input=$(quotifyJson "[{kind:user,name:,perms:[read,write,execute],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $DIR1 2>&1)
    assertEquals 0 $?
    assertEquals \
        "" \
        "$msg"
}

testWriteAclToLink1() {
    # Set ACL to empty.
    input="[]"
    msg=$(echo "$input" | $EXACL --set $LINK1 2>&1)
    assertEquals 1 $?
    assertEquals \
        "Invalid ACL: missing required entries" \
        "$msg"

    input=$(quotifyJson "[{kind:mask,name:,perms:[read],flags:[],allow:true},{kind:user,name:$ME,perms:[read],flags:[],allow:true},{kind:user,name:,perms:[read,write,execute],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $LINK1 2>&1)
    assertEquals 1 $?
    assertEquals \
        "File \"$LINK1\": No such file or directory (os error 2)" \
        "$msg"

    input=$(quotifyJson "[{kind:mask,name:,perms:[read],flags:[],allow:true},{kind:user,name:$ME,perms:[read],flags:[],allow:true},{kind:user,name:,perms:[read,write,execute],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set --symlink $LINK1 2>&1)
    assertEquals 1 $?
    assertEquals \
        "File \"$LINK1\": Linux does not support symlinks with ACL's" \
        "$msg"
}

testWriteAclNumericUID() {
    # Set ACL for current user to "deny read".
    input=$(quotifyJson "[{kind:user,name:$ME_NUM,perms:[read],flags:[],allow:true},$REQUIRED_ENTRIES,{kind:mask,name:,perms:[read],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $FILE1 2>&1)
    assertEquals 0 $?
    assertEquals "" "$msg"

    # Check ACL again.
    msg=$($EXACL $FILE1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read,write],flags:[],allow:true},{kind:user,name:$ME,perms:[read],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:mask,name:,perms:[read],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"

    # Check ACL with getfacl.
    msg=$(getfacl -cE $FILE1 2>/dev/null)
    assertEquals "check acl getfacl" 0 $?
    assertEquals \
        "user::rw-
user:$ME:r--
group::---
mask::r--
other::---" \
        "${msg}"
}

testWriteAclNumericGID() {
    # Set ACL for current group to "read".
    input=$(quotifyJson "[{kind:group,name:$MY_GROUP_NUM,perms:[read],flags:[],allow:true},$REQUIRED_ENTRIES,{kind:mask,name:,perms:[read],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $FILE1 2>&1)
    assertEquals 0 $?
    assertEquals "" "$msg"

    # Check ACL again.
    msg=$($EXACL $FILE1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read,write],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:group,name:$MY_GROUP,perms:[read],flags:[],allow:true},{kind:mask,name:,perms:[read],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"
}

testReadDefaultAcl() {
    # Reading default acl for a file should fail.
    msg=$($EXACL --default $FILE1 2>&1)
    assertEquals 1 $?
    assertEquals \
        "File \"$FILE1\": Permission denied (os error 13)" \
        "$msg"

    # Reading default acl for a directory.
    msg=$($EXACL --default $DIR1 2>&1)
    assertEquals 0 $?
    assertEquals "[]" "$msg"
}

testWriteDefaultAcl() {
    input=$(quotifyJson "[{kind:group,name:$MY_GROUP_NUM,perms:[read],flags:[],allow:true},$REQUIRED_ENTRIES,{kind:mask,name:,perms:[read],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set --default $DIR1 2>&1)
    assertEquals 0 $?
    assertEquals "" "$msg"

    # Check ACL again.
    msg=$($EXACL --default $DIR1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read,write],flags:[default],allow:true},{kind:group,name:,perms:[],flags:[default],allow:true},{kind:group,name:$MY_GROUP,perms:[read],flags:[default],allow:true},{kind:mask,name:,perms:[read],flags:[default],allow:true},{kind:other,name:,perms:[],flags:[default],allow:true}]" \
        "${msg//\"/}"

    # Check ACL without --default.
    msg=$($EXACL $DIR1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read,write,execute],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true},{kind:user,name:,perms:[read,write],flags:[default],allow:true},{kind:group,name:,perms:[],flags:[default],allow:true},{kind:group,name:$MY_GROUP,perms:[read],flags:[default],allow:true},{kind:mask,name:,perms:[read],flags:[default],allow:true},{kind:other,name:,perms:[],flags:[default],allow:true}]" \
        "${msg//\"/}"

    # Check ACL with getfacl.
    msg=$(getfacl -cE $DIR1 2>/dev/null)
    assertEquals "check acl getfacl" 0 $?
    assertEquals \
        "user::rwx
group::---
other::---
default:user::rw-
default:group::---
default:group:$MY_GROUP:r--
default:mask::r--
default:other::---" \
        "${msg}"

    # Create subfile in DIR1.
    subfile="$DIR1/subfile"
    touch "$subfile"

    msg=$($EXACL $subfile 2>&1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read,write],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:group,name:$MY_GROUP,perms:[read],flags:[],allow:true},{kind:mask,name:,perms:[read],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"

    rm -f "$subfile"

    # Delete the default ACL.
    input="[]"
    msg=$(echo "$input" | $EXACL --set --default $DIR1 2>&1)
    assertEquals 0 $?
    assertEquals \
        "" \
        "$msg"

    # Default acl should now be empty.
    msg=$($EXACL --default $DIR1 2>&1)
    assertEquals 0 $?
    assertEquals "[]" "$msg"
}

testWriteUnifiedAclToFile1() {
    # Set ACL with required entries.
    input=$(quotifyJson "[{kind:user,name:,perms:[read,write],flags:[],allow:true},{kind:group,name:,perms:[read,write],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true},{kind:user,name:,perms:[read,write],flags:[default],allow:true},{kind:group,name:,perms:[read,write],flags:[default],allow:true},{kind:other,name:,perms:[],flags:[default],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $FILE1 2>&1)
    assertEquals "set unified acl" 1 $?
    assertEquals \
        "File \"$FILE1\": Non-directory does not have default ACL" \
        "$msg"

    # Check ACL is unchanged.
    msg=$($EXACL $FILE1)
    assertEquals "check acl again" 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read,write],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:group,name:$MY_GROUP,perms:[read],flags:[],allow:true},{kind:mask,name:,perms:[read],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"
}

testWriteUnifiedAclToMissingFile() {
    # Set ACL with required entries.
    input=$(quotifyJson "[{kind:user,name:,perms:[read,write],flags:[],allow:true},{kind:group,name:,perms:[read,write],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true},{kind:user,name:,perms:[read,write],flags:[default],allow:true},{kind:group,name:,perms:[read,write],flags:[default],allow:true},{kind:other,name:,perms:[],flags:[default],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $DIR/non_existant 2>&1)
    assertEquals "set unified acl" 1 $?
    assertEquals \
        "File \"$DIR/non_existant\": No such file or directory (os error 2)" \
        "$msg"
}

testWriteUnifiedAclToDir1() {
    # Set ACL with required entries.
    input=$(quotifyJson "[{kind:user,name:,perms:[read,write],flags:[],allow:true},{kind:group,name:,perms:[read,write],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true},{kind:user,name:,perms:[read,write],flags:[default],allow:true},{kind:group,name:,perms:[read,write],flags:[default],allow:true},{kind:other,name:,perms:[],flags:[default],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $DIR1 2>&1)
    assertEquals "set unified acl" 0 $?
    assertEquals \
        "" \
        "$msg"

    # Check ACL is updated.
    msg=$($EXACL $DIR1)
    assertEquals "check acl again" 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read,write],flags:[],allow:true},{kind:group,name:,perms:[read,write],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true},{kind:user,name:,perms:[read,write],flags:[default],allow:true},{kind:group,name:,perms:[read,write],flags:[default],allow:true},{kind:other,name:,perms:[],flags:[default],allow:true}]" \
        "${msg//\"/}"

    # Check ACL with getfacl.
    msg=$(getfacl -cE $DIR1 2>/dev/null)
    assertEquals "check acl getfacl" 0 $?
    assertEquals \
        "user::rw-
group::rw-
other::---
default:user::rw-
default:group::rw-
default:other::---" \
        "${msg}"
}

testWriteAccessAclToDir1() {
    # Check access ACL.
    msg=$($EXACL --access $DIR1)
    assertEquals "check acl" 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read,write],flags:[],allow:true},{kind:group,name:,perms:[read,write],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"

    # Set access ACL.
    input=$(quotifyJson "[{kind:user,name:,perms:[execute],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set --access $DIR1 2>&1)
    assertEquals "set access acl" 0 $?
    assertEquals \
        "" \
        "$msg"

    # Check access ACL is updated, and default ACL is unchanged.
    msg=$($EXACL $DIR1)
    assertEquals "check acl again" 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[execute],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true},{kind:user,name:,perms:[read,write],flags:[default],allow:true},{kind:group,name:,perms:[read,write],flags:[default],allow:true},{kind:other,name:,perms:[],flags:[default],allow:true}]" \
        "${msg//\"/}"
}

testSetDefault() {
    # Set ACL with both access and default entries.
    input=$(quotifyJson "[{kind:user,name:,perms:[execute],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:other,name:,perms:[execute],flags:[],allow:true},{kind:user,name:,perms:[read,write],flags:[default],allow:true},{kind:group,name:,perms:[read,write],flags:[default],allow:true},{kind:other,name:,perms:[],flags:[default],allow:true}]")
    msg=$(echo "$input" | $EXACL --set --default $DIR1 2>&1)
    assertEquals "set default acl" 1 $?
    assertEquals \
        'Invalid ACL: entry 3: duplicate default entry for "user"' \
        "$msg"

    # Set ACL with default entries.
    input=$(quotifyJson "[{kind:user,name:,perms:[read,write],flags:[default],allow:true},{kind:group,name:,perms:[read,write],flags:[default],allow:true},{kind:other,name:,perms:[],flags:[default],allow:true}]")
    msg=$(echo "$input" | $EXACL --set --default $DIR1 2>&1)
    assertEquals 0 $?
    assertEquals \
        '' \
        "$msg"

    # Check ACL.
    msg=$($EXACL $DIR1)
    assertEquals "check acl again" 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[execute],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true},{kind:user,name:,perms:[read,write],flags:[default],allow:true},{kind:group,name:,perms:[read,write],flags:[default],allow:true},{kind:other,name:,perms:[],flags:[default],allow:true}]" \
        "${msg//\"/}"

    # Remove the default ACL.
    input="[]"
    msg=$(echo "$input" | $EXACL --set --default $DIR1 2>&1)
    assertEquals "remove default acl" 0 $?
    assertEquals \
        "" \
        "$msg"

    # Check ACL is updated.
    msg=$($EXACL $DIR1)
    assertEquals "check acl again" 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[execute],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"
}

testMissingFlags() {
    input=$(quotifyJson "[{kind:user,name:501,perms:[execute],allow:true}]")
    msg=$(echo "$input" | $EXACL --set non_existant 2>&1)
    assertEquals 1 $?
    assertEquals \
        'Invalid ACL: missing required entry "user"' \
        "${msg//\`/}"
}

testMissingAllow() {
    input=$(quotifyJson "[{kind:user,name:501,perms:[execute],flags:[]}]")
    msg=$(echo "$input" | $EXACL --set non_existant 2>&1)
    assertEquals 1 $?
    assertEquals \
        'Invalid ACL: missing required entry "user"' \
        "${msg//\`/}"
}

# Multiple ACL entries with the same user/group ID.
testDuplicateEntry() {
    input=$(quotifyJson "[{kind:user,name:501,perms:[execute]},$REQUIRED_ENTRIES,{kind:user,name:501,perms:[execute]}]")
    msg=$(echo "$input" | $EXACL --set non_existant 2>&1)
    assertEquals 1 $?
    assertEquals \
        'Invalid ACL: entry 4: duplicate entry for "user:501"' \
        "${msg//\`/}"

    # daemon is uid 1.
    input=$(quotifyJson "[{kind:user,name:1,perms:[execute]},$REQUIRED_ENTRIES,{kind:user,name:daemon,perms:[read]}]")
    msg=$(echo "$input" | $EXACL --set non_existant 2>&1)
    assertEquals 1 $?
    assertEquals \
        'Invalid ACL: entry 4: duplicate entry for "user:1"' \
        "${msg//\`/}"

    # Test duplicate entry in default entries.
    input=$(quotifyJson "[$REQUIRED_ENTRIES,{kind:user,name:,perms:[execute],flags:[default]},{kind:group,name:,perms:[execute],flags:[default]},{kind:other,name:,perms:[execute],flags:[default]},{kind:other,name:,perms:[execute],flags:[default]}]")
    msg=$(echo "$input" | $EXACL --set non_existant 2>&1)
    assertEquals 1 $?
    assertEquals \
        'Invalid ACL: entry 6: duplicate default entry for "other"' \
        "${msg//\`/}"
}

# shellcheck disable=SC1091
. shunit2
