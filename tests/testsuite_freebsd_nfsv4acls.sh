#! /usr/bin/env bash

# Basic test suite for exacl tool (FreeBSD).

set -u -o pipefail

EXACL='../target/debug/examples/exacl'

ME=$(id -un)
ME_NUM=$(id -u)
MY_GROUP=$(id -gn)
MY_GROUP_NUM=$(id -g)

fileperms() {
    stat -f "%Sp" "$1"
}

# Put quotes back on JSON text.
quotifyJson() {
    echo "$1" | sed -E -e 's/([@A-Za-z0-9_-]+)/"\1"/g' -e 's/:"false"/:false/g' -e 's/:"true"/:true/g' -e 's/:,/:"",/g'
}

# Called by shunit2 before all tests run.
oneTimeSetUp() {
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
    msg=$($EXACL -f std $FILE1)
    assertEquals 0 $?
    assertEquals \
        "allow::user::read_data,write_data,append,readextattr,writeextattr,readattr,writeattr,readsecurity,writesecurity,chown,sync
allow::group::readextattr,readattr,readsecurity,sync
allow::everyone::readextattr,readattr,readsecurity,sync" \
        "${msg//\"/}"

    assertEquals "-rw-------" "$(fileperms $FILE1)"

    # Add ACL entry for current user to "write-only".
    setfacl -m "u:$ME:w::allow" "$FILE1"
    assertEquals 0 $?

    msg=$($EXACL -f std $FILE1)
    assertEquals 0 $?
    assertEquals \
        "allow::user:$ME:write_data
allow::user::read_data,write_data,append,readextattr,writeextattr,readattr,writeattr,readsecurity,writesecurity,chown,sync
allow::group::readextattr,readattr,readsecurity,sync
allow::everyone::readextattr,readattr,readsecurity,sync" \
        "${msg//\"/}"

    assertEquals "-rw-------" "$(fileperms $FILE1)"

    # Deny execute access for user "777"
    setfacl -m "g:777:execute::deny" "$FILE1"

    msg=$($EXACL -f std $FILE1)
    assertEquals 0 $?
    assertEquals \
        "deny::group:777:execute
allow::user:$ME:write_data
allow::user::read_data,write_data,append,readextattr,writeextattr,readattr,writeattr,readsecurity,writesecurity,chown,sync
allow::group::readextattr,readattr,readsecurity,sync
allow::everyone::readextattr,readattr,readsecurity,sync" \
        "${msg//\"/}"

    # Remove owner read perm.
    chmod u-rw "$FILE1"
    assertEquals "----------" "$(fileperms $FILE1)"

    msg=$($EXACL -f std $FILE1)
    assertEquals 0 $?
    assertEquals \
        "allow::user::readextattr,writeextattr,readattr,writeattr,readsecurity,writesecurity,chown,sync
allow::group::readextattr,readattr,readsecurity,sync
allow::everyone::readextattr,readattr,readsecurity,sync" \
        "${msg//\"/}"

    # Add ACL entry for current group to "allow write".
    setfacl -m "g:$MY_GROUP:w::allow" "$FILE1"

    msg=$($EXACL -f std $FILE1)
    assertEquals 0 $?
    assertEquals \
        "allow::group:$MY_GROUP:write_data
allow::user::readextattr,writeextattr,readattr,writeattr,readsecurity,writesecurity,chown,sync
allow::group::readextattr,readattr,readsecurity,sync
allow::everyone::readextattr,readattr,readsecurity,sync" \
        "${msg//\"/}"

    assertEquals "----------" "$(fileperms $FILE1)"

    # Reset permissions.
    chmod 600 "$FILE1"

    msg=$($EXACL -f std $FILE1)
    assertEquals 0 $?
    assertEquals \
        "allow::user::read_data,write_data,append,readextattr,writeextattr,readattr,writeattr,readsecurity,writesecurity,chown,sync
allow::group::readextattr,readattr,readsecurity,sync
allow::everyone::readextattr,readattr,readsecurity,sync" \
        "${msg//\"/}"
}

testReadAclForDir1() {
    msg=$($EXACL -f std $DIR1)
    assertEquals 0 $?
    assertEquals \
        "allow::user::execute,read_data,write_data,append,readextattr,writeextattr,readattr,writeattr,readsecurity,writesecurity,chown,sync
allow::group::readextattr,readattr,readsecurity,sync
allow::everyone::readextattr,readattr,readsecurity,sync" \
        "${msg//\"/}"

    # Add ACL entry for current user to "write-only". (Note: owner still has read access)
    setfacl -m "u:$ME:w::allow" "$DIR1"

    msg=$($EXACL -f std $DIR1)
    assertEquals 0 $?
    assertEquals \
        "allow::user:$ME:write_data
allow::user::execute,read_data,write_data,append,readextattr,writeextattr,readattr,writeattr,readsecurity,writesecurity,chown,sync
allow::group::readextattr,readattr,readsecurity,sync
allow::everyone::readextattr,readattr,readsecurity,sync" \
        "${msg//\"/}"

    assertEquals "drwx------" "$(fileperms $DIR1)"
    assertEquals 0 $?

    # Clear extended ACL entries.
    setfacl -b "$DIR1"

    msg=$($EXACL -f std $DIR1)
    assertEquals 0 $?
    assertEquals \
        "allow::user::execute,read_data,write_data,append,readextattr,writeextattr,readattr,writeattr,readsecurity,writesecurity,chown,sync
allow::group::readextattr,readattr,readsecurity,sync
allow::everyone::readextattr,readattr,readsecurity,sync" \
        "${msg//\"/}"
}

testReadAclForLink1() {
    # Test symlink with no ACL.
    msg=$($EXACL -f std $LINK1 2>&1)
    assertEquals 1 $?
    assertEquals "File \"$LINK1\": No such file or directory (os error 2)" "$msg"

    # Test symlink with no ACL.
    msg=$($EXACL --symlink -f std $LINK1 2>&1)
    assertEquals 0 $?
    assertEquals \
        "allow::user::execute,read_data,write_data,append,readextattr,writeextattr,readattr,writeattr,readsecurity,writesecurity,chown,sync
allow::group::readextattr,readattr,readsecurity,sync
allow::everyone::readextattr,readattr,readsecurity,sync" \
        "${msg//\"/}"
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
    msg=$($EXACL -f std $FILE1)
    assertEquals "verify acl" 0 $?
    assertEquals \
        "allow::user::read_data,write_data,append,readextattr,writeextattr,readattr,writeattr,readsecurity,writesecurity,chown,sync
allow::group::readextattr,readattr,readsecurity,sync
allow::everyone::readextattr,readattr,readsecurity,sync" \
        "${msg//\"/}"

    assertEquals "-rw-------" "$(fileperms $FILE1)"

    # Set ACL for current user to "allow:false".
    input=$(quotifyJson "[{kind:user,name:$ME,perms:[read_data],flags:[],allow:false}]")
    msg=$(echo "$input" | $EXACL --set $FILE1 2>&1)
    assertEquals "check failure" 0 $?
    assertEquals \
        "" \
        "$msg"

    # Set ACL for current user specifically.
    input=$(quotifyJson "[{kind:user,name:$ME,perms:[read],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $FILE1 2>&1)
    assertEquals "check required entry" 1 $?
    assertEquals \
        'Invalid ACL: missing required entry "user"' \
        "$msg"

    # Set ACL for current user specifically, with required entries.
    input=$(quotifyJson "[{kind:user,name:,perms:[read_data,write_data],flags:[],allow:true},{kind:group,name:,perms:[read_data,write_data],flags:[],allow:true},{kind:everyone,name:,perms:[],flags:[], allow:true},{kind:user,name:$ME,perms:[read_data],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $FILE1 2>&1)
    assertEquals "check set acl" 0 $?
    assertEquals \
        "" \
        "${msg//\"/}"

    # Check ACL again.
    msg=$($EXACL $FILE1)
    assertEquals "check acl again" 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read_data,write_data],flags:[],allow:true},{kind:group,name:,perms:[read_data,write_data],flags:[],allow:true},{kind:everyone,name:,perms:[],flags:[],allow:true},{kind:user,name:$ME,perms:[read_data],flags:[],allow:true}]" \
        "${msg//\"/}"

    # Check ACL with getfacl.
    msg=$(getfacl -q $FILE1 2>/dev/null | sed -e 's/ *//')
    assertEquals "check acl getfacl" 0 $?
    assertEquals \
        "owner@:rw------------:-------:allow
group@:rw------------:-------:allow
everyone@:--------------:-------:allow
user:$ME:r-------------:-------:allow" \
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
        "[{kind:user,name:,perms:[execute,read_data,write_data,append,readextattr,writeextattr,readattr,writeattr,readsecurity,writesecurity,chown,sync],flags:[],allow:true},{kind:group,name:,perms:[readextattr,readattr,readsecurity,sync],flags:[],allow:true},{kind:everyone,name:,perms:[readextattr,readattr,readsecurity,sync],flags:[],allow:true}]" \
        "${msg//\"/}"

    assertEquals "drwx------" "$(fileperms $DIR1)"

    # Set ACL for current user to "deny read".
    input=$(quotifyJson "[{kind:user,name:$ME,perms:[read_data],flags:[],allow:false}]")
    msg=$(echo "$input" | $EXACL --set $DIR1 2>&1)
    assertEquals 0 $?
    assertEquals \
        "" \
        "$msg"

    # Set ACL without mask entry.
    input=$(quotifyJson "[{kind:user,name:$ME,perms:[read_data],flags:[],allow:true},{kind:user,name:,perms:[execute,read_data,write_data],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:everyone,name:,perms:[],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $DIR1 2>&1)
    assertEquals 0 $?
    assertEquals \
        "" \
        "$msg"

    # Read ACL back.
    msg=$($EXACL $DIR1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:$ME,perms:[read_data],flags:[],allow:true},{kind:user,name:,perms:[execute,read_data,write_data],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:everyone,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"

    # Set ACL with mask entry (not valid).
    input=$(quotifyJson "[{kind:mask,name:,perms:[read_data],flags:[],allow:true},{kind:user,name:$ME,perms:[read_data],flags:[],allow:true},{kind:user,name:,perms:[execute,read_data,write_data],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:everyone,name:,perms:[],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $DIR1 2>&1)
    assertEquals 1 $?
    assertEquals \
        "Invalid ACL: entry 0: Invalid argument (os error 22)" \
        "$msg"

    # Read ACL back.
    msg=$($EXACL $DIR1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:$ME,perms:[read_data],flags:[],allow:true},{kind:user,name:,perms:[execute,read_data,write_data],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:everyone,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"

    assertEquals "drwx------" "$(fileperms $DIR1)"

    # Check ACL with getfacl.
    msg=$(getfacl -q $DIR1 2>/dev/null | sed -e 's/ *//')
    assertEquals "check acl getfacl" 0 $?
    assertEquals \
        "user:$ME:r-------------:-------:allow
owner@:rwx-----------:-------:allow
group@:--------------:-------:allow
everyone@:--------------:-------:allow" \
        "${msg}"

    # Reset ACL back to the original.
    chmod 0700 $DIR1
    assertEquals 0 $?
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

    input=$(quotifyJson "[{kind:user,name:$ME,perms:[read_data],flags:[],allow:true},{kind:user,name:,perms:[read_data,write_data,execute],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:everyone,name:,perms:[],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set --symlink $LINK1 2>&1)
    assertEquals 0 $?
    assertEquals \
        "" \
        "$msg"

    msg=$($EXACL --symlink $LINK1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:$ME,perms:[read_data],flags:[],allow:true},{kind:user,name:,perms:[execute,read_data,write_data],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:everyone,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"
}

testWriteAclNumericUID() {
    # Set ACL for current user to "deny read".
    input=$(quotifyJson "[{kind:user,name:$ME_NUM,perms:[read_data],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $FILE1 2>&1)
    assertEquals 0 $?
    assertEquals "" "$msg"

    # Check ACL again.
    msg=$($EXACL $FILE1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:$ME,perms:[read_data],flags:[],allow:true}]" \
        "${msg//\"/}"

    # Check ACL with getfacl.
    msg=$(getfacl -q $FILE1 2>/dev/null | sed -e 's/ *//')
    assertEquals "check acl getfacl" 0 $?
    assertEquals \
        "user:$ME:r-------------:-------:allow" \
        "${msg}"
}

testWriteAclNumericGID() {
    # Set ACL for current group to "read".
    input=$(quotifyJson "[{kind:group,name:$MY_GROUP_NUM,perms:[read_data],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $FILE1 2>&1)
    assertEquals 0 $?
    assertEquals "" "$msg"

    # Check ACL again.
    msg=$($EXACL $FILE1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:group,name:$MY_GROUP,perms:[read_data],flags:[],allow:true}]" \
        "${msg//\"/}"
}

testReadDefaultAcl() {
    # Reading default acl for a file should fail.
    msg=$($EXACL --default $FILE1 2>&1)
    assertEquals 1 $?
    assertEquals \
        "File \"$FILE1\": Default ACL not supported" \
        "${msg}"

    # Reading default acl for a directory.
    msg=$($EXACL --default $DIR1 2>&1)
    assertEquals 1 $?
    assertEquals \
        "File \"$DIR1\": Default ACL not supported" \
        "${msg}"
}

testWriteDefaultAcl() {
    # This is wrong. (FIXME)
    input=$(quotifyJson "[{kind:group,name:$MY_GROUP_NUM,perms:[read_data],flags:[],allow:true}]")
    msg=$(echo "$input" | $EXACL --set --default $DIR1 2>&1)
    assertEquals 1 $?
    assertEquals \
        "Invalid ACL: missing required entry \"user\"" \
        "$msg"

    # Check ACL again.
    msg=$($EXACL --default $DIR1 2>&1)
    assertEquals 1 $?
    assertEquals \
        "File \"$DIR1\": Default ACL not supported" \
        "${msg}"

    # Check ACL without --default.
    msg=$($EXACL $DIR1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[execute,read_data,write_data,append,readextattr,writeextattr,readattr,writeattr,readsecurity,writesecurity,chown,sync],flags:[],allow:true},{kind:group,name:,perms:[readextattr,readattr,readsecurity,sync],flags:[],allow:true},{kind:everyone,name:,perms:[readextattr,readattr,readsecurity,sync],flags:[],allow:true}]" \
        "${msg//\"/}"

    # Check ACL with getfacl.
    msg=$(getfacl -q $DIR1 2>/dev/null | sed -e 's/ *//')
    assertEquals "check acl getfacl" 0 $?
    assertEquals \
        "owner@:rwxp--aARWcCos:-------:allow
group@:------a-R-c--s:-------:allow
everyone@:------a-R-c--s:-------:allow" \
        "${msg}"

    # Check default ACL with getfacl.
    msg=$(getfacl -dq $DIR1 2>&1)
    assertEquals "check default acl getfacl" 1 $?
    assertEquals \
        "getfacl: $DIR1: there are no default entries in NFSv4 ACLs" \
        "${msg}"

    # Create subfile in DIR1. (FIXME)
    subfile="$DIR1/subfile"
    touch "$subfile"

    msg=$($EXACL $subfile 2>&1)
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read_data,write_data,append,readextattr,writeextattr,readattr,writeattr,readsecurity,writesecurity,chown,sync],flags:[],allow:true},{kind:group,name:,perms:[readextattr,readattr,readsecurity,sync],flags:[],allow:true},{kind:everyone,name:,perms:[readextattr,readattr,readsecurity,sync],flags:[],allow:true}]" \
        "${msg//\"/}"

    rm -f "$subfile"

    # Delete the default ACL. (FIXME)
    input="[]"
    msg=$(echo "$input" | $EXACL --set --default $DIR1 2>&1)
    assertEquals 1 $?
    assertEquals \
        "File \"$DIR1\": Default ACL not supported" \
        "$msg"

    # Default acl should now be empty.
    msg=$($EXACL --default $DIR1 2>&1)
    assertEquals 1 $?
    assertEquals \
        "File \"$DIR1\": Default ACL not supported" \
        "${msg}"
}

testWriteUnifiedAclToFile1() {
    # Set ACL with required entries.
    input=$(quotifyJson "[{kind:user,name:,perms:[read,write],flags:[],allow:true},{kind:group,name:,perms:[read,write],flags:[],allow:true},{kind:other,name:,perms:[],flags:[],allow:true},{kind:user,name:,perms:[read,write],flags:[default],allow:true},{kind:group,name:,perms:[read,write],flags:[default],allow:true},{kind:other,name:,perms:[],flags:[default],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $FILE1 2>&1)
    assertEquals "set unified acl" 1 $?
    assertEquals \
        "File \"$FILE1\": Non-directory does not have default ACL" \
        "$msg"

    # Check ACL is unchanged. (FIXME)
    msg=$($EXACL $FILE1)
    assertEquals "check acl again" 0 $?
    assertEquals \
        "[{kind:group,name:$MY_GROUP,perms:[read_data],flags:[],allow:true}]" \
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
    # Set ACL with required entries. (FIXME)
    input=$(quotifyJson "[{kind:user,name:,perms:[read_data,write_data],flags:[],allow:true},{kind:group,name:,perms:[read_data,write_data],flags:[],allow:true},{kind:everyone,name:,perms:[],flags:[],allow:true},{kind:user,name:,perms:[read,write],flags:[default],allow:true},{kind:group,name:,perms:[read,write],flags:[default],allow:true},{kind:other,name:,perms:[],flags:[default],allow:true}]")
    msg=$(echo "$input" | $EXACL --set $DIR1 2>&1)
    assertEquals "set unified acl" 0 $?
    assertEquals \
        "" \
        "$msg"

    # Check ACL is updated. (FIXME)
    msg=$($EXACL $DIR1)
    assertEquals "check acl again" 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read_data,write_data],flags:[],allow:true},{kind:group,name:,perms:[read_data,write_data],flags:[],allow:true},{kind:everyone,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"

    # Check ACL with getfacl.
    msg=$(getfacl -q $DIR1 2>/dev/null | sed -e 's/ *//')
    assertEquals "check acl getfacl" 0 $?
    assertEquals \
        "owner@:rw------------:-------:allow
group@:rw------------:-------:allow
everyone@:--------------:-------:allow" \
        "${msg}"

    # Check default ACL with getfacl.
    msg=$(getfacl -dq $DIR1 2>&1)
    assertEquals "check default acl getfacl" 1 $?
    assertEquals \
        "getfacl: $DIR1: there are no default entries in NFSv4 ACLs" \
        "${msg}"
}

testSetDefault() {
    # Set ACL with both access and default entries.
    input=$(quotifyJson "[{kind:user,name:,perms:[execute],flags:[],allow:true},{kind:group,name:,perms:[],flags:[],allow:true},{kind:other,name:,perms:[execute],flags:[],allow:true},{kind:user,name:,perms:[read,write],flags:[default],allow:true},{kind:group,name:,perms:[read,write],flags:[default],allow:true},{kind:other,name:,perms:[],flags:[default],allow:true}]")
    msg=$(echo "$input" | $EXACL --set --default $DIR1 2>&1)
    assertEquals "set default acl" 1 $?
    assertEquals \
        'Invalid ACL: entry 3: duplicate default entry for "user"' \
        "$msg"

    # Check ACL is updated. (FIXME)
    msg=$($EXACL $DIR1)
    assertEquals "check acl again" 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read_data,write_data],flags:[],allow:true},{kind:group,name:,perms:[read_data,write_data],flags:[],allow:true},{kind:everyone,name:,perms:[],flags:[],allow:true}]" \
        "${msg//\"/}"

    # Remove the default ACL. (FIXME)
    input="[]"
    msg=$(echo "$input" | $EXACL --set --default $DIR1 2>&1)
    assertEquals "remove default acl" 1 $?
    assertEquals \
        "File \"$DIR1\": Default ACL not supported" \
        "$msg"

    # Check ACL is updated. (FIXME)
    msg=$($EXACL $DIR1)
    assertEquals "check acl again" 0 $?
    assertEquals \
        "[{kind:user,name:,perms:[read_data,write_data],flags:[],allow:true},{kind:group,name:,perms:[read_data,write_data],flags:[],allow:true},{kind:everyone,name:,perms:[],flags:[],allow:true}]" \
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
}

# shellcheck disable=SC1091
. shunit2
