#!/bin/bash

# Basic test suite for exacl tool.

set -u -o pipefail

EXACL='../target/debug/exacl'

DIR="test_dir-mac_os-test_dir"
FILE1="$DIR/file1"
DIR1="$DIR/dir1"
LINK1="$DIR/link1"

ME=`id -un`
ME_NUM=`id -u`
MY_GROUP=`id -gn`
MY_GROUP_NUM=`id -g`

# Return true if file is readable.
isReadable() {
    cat "$1" > /dev/null 2>&1 
    return $?
}

# Return true if file is writable (tries to overwrite file).
isWritable() {
    echo "x" 2> /dev/null > "$1" 
    return $?
}

# Return true if directory is readable.
isReadableDir() {
    ls "$1" > /dev/null 2>&1
    return $?
}

# Return true if link is readable.
isReadableLink() {
    readlink "$1" > /dev/null 2>&1
    return $?
}

fileperms() {
    stat -c "%A" "$1" 
}

oneTimeSetUp() {
    # Create an empty temporary directory.
    if [ -d "$DIR" ]; then
        rm -rf "$DIR"
    fi

    mkdir "$DIR"

    # Create empty file, dir, and link.
    umask 077
    touch "$FILE1"
    mkdir "$DIR1"
    ln -s link1_to_nowhere "$LINK1"
}

# Put quotes back on JSON text.
quotifyJson() { 
    echo "$1" | sed -E -e 's/([@A-Za-z0-9_-]+)/"\1"/g' -e 's/:"false"/:false/g' -e 's/:"true"/:true/g'
}

oneTimeTearDown() {
    # Delete our temporary directory.
    rm -rf "$DIR"
}

REQUIRED_ENTRIES="{kind:user,name:@owner,perms:[write,read],flags:[],allow:true},{kind:group,name:@owner,perms:[],flags:[],allow:true},{kind:user,name:@other,perms:[],flags:[],allow:true}"

testReadAclFromMissingFile() {
    msg=`$EXACL $DIR/non_existant 2>&1`
    assertEquals 1 $?
    assertEquals \
        "File \"$DIR/non_existant\": No such file or directory (os error 2)" \
        "$msg"
}

testReadAclForFile1() {
    msg=`$EXACL $FILE1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:@owner,perms:[write,read],flags:[],allow:true},{kind:group,name:@owner,perms:[],flags:[],allow:true},{kind:user,name:@other,perms:[],flags:[],allow:true}]" \
        "${msg//\"}"

    assertEquals "-rw-------" `fileperms "$FILE1"`
    isReadable "$FILE1" && isWritable "$FILE1"
    assertEquals 0 $?
    
    # Add ACL entry for current user to "write-only". (Note: @owner still has read access)
    setfacl -m "u:$ME:w" "$FILE1"

    msg=`$EXACL $FILE1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:@owner,perms:[write,read],flags:[],allow:true},{kind:user,name:$ME,perms:[write],flags:[],allow:true},{kind:group,name:@owner,perms:[],flags:[],allow:true},{kind:group,name:@mask,perms:[write],flags:[],allow:true},{kind:user,name:@other,perms:[],flags:[],allow:true}]" \
        "${msg//\"}"

    assertEquals "-rw--w----" `fileperms "$FILE1"`
    isReadable "$FILE1" && isWritable "$FILE1"
    assertEquals 0 $?

    # Remove owner read perm.
    chmod u-rw "$FILE1"

    assertEquals "-----w----" `fileperms "$FILE1"`
    ! isReadable "$FILE1" && ! isWritable "$FILE1"
    assertEquals 0 $?

    # Add ACL entry for current group to "allow write".
    setfacl -m "g:$MY_GROUP:w" "$FILE1"

    msg=`$EXACL $FILE1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:@owner,perms:[],flags:[],allow:true},{kind:user,name:$ME,perms:[write],flags:[],allow:true},{kind:group,name:@owner,perms:[],flags:[],allow:true},{kind:group,name:$MY_GROUP,perms:[write],flags:[],allow:true},{kind:group,name:@mask,perms:[write],flags:[],allow:true},{kind:user,name:@other,perms:[],flags:[],allow:true}]" \
        "${msg//\"}"

    assertEquals "-----w----" `fileperms "$FILE1"`
    ! isReadable "$FILE1" && ! isWritable "$FILE1"
    assertEquals 0 $?

    # Reset permissions.
    chmod 600 "$FILE1"
    setfacl -b "$FILE1"
}

testReadAclForDir1() {
    msg=`$EXACL $DIR1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:@owner,perms:[execute,write,read],flags:[],allow:true},{kind:group,name:@owner,perms:[],flags:[],allow:true},{kind:user,name:@other,perms:[],flags:[],allow:true}]" \
        "${msg//\"}"

    # Add ACL entry for current user to "write-only". (Note: @owner still has read access)
    setfacl -m "u:$ME:w" "$DIR1"

    msg=`$EXACL $DIR1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:@owner,perms:[execute,write,read],flags:[],allow:true},{kind:user,name:$ME,perms:[write],flags:[],allow:true},{kind:group,name:@owner,perms:[],flags:[],allow:true},{kind:group,name:@mask,perms:[write],flags:[],allow:true},{kind:user,name:@other,perms:[],flags:[],allow:true}]" \
        "${msg//\"}"

    assertEquals "drwx-w----" `fileperms "$DIR1"`
    isReadableDir "$DIR1"
    assertEquals 0 $?

    # TODO: test default ACL in a separate test.

    # Clear directory ACL's so we can delete them.
    setfacl -b "$DIR1"
}

testReadAclForLink1() {
    # Test symlink with no ACL. Not supported on Linux.
    msg=`$EXACL $LINK1 2>&1`
    assertEquals 1 $?
    assertEquals "File \"$LINK1\": No such file or directory (os error 2)" "$msg"
}

testWriteAclToMissingFile() {
    input="[]"
    msg=`echo "$input" | $EXACL --set $DIR/non_existant 2>&1`
    assertEquals 1 $?
    assertEquals \
        "File \"$DIR/non_existant\": required ACL entry is missing" \
        "$msg"
}

testWriteAclToFile1() {
    # Set ACL to empty.
    input="[]"
    msg=`echo "$input" | $EXACL --set $FILE1 2>&1`
    assertEquals 1 $?
    assertEquals \
        "File \"$FILE1\": required ACL entry is missing" \
        "$msg"

    # Verify ACL.
    msg=`$EXACL $FILE1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:@owner,perms:[write,read],flags:[],allow:true},{kind:group,name:@owner,perms:[],flags:[],allow:true},{kind:user,name:@other,perms:[],flags:[],allow:true}]" \
        "${msg//\"}"

    assertEquals "-rw-------" `fileperms "$FILE1"`
    isReadable "$FILE1" && isWritable "$FILE1"
    assertEquals 0 $?

    # Set ACL for current user to "allow:false". This fails on Linux.
    input=`quotifyJson "[{kind:user,name:$ME,perms:[read],flags:[],allow:false}]"`
    msg=`echo "$input" | $EXACL --set $FILE1 2>&1`
    assertEquals 1 $?
    assertEquals \
        "Invalid ACL: entry 0: allow=false is not supported on Linux" \
        "$msg"

    # Set ACL for current user specifically.
    input=`quotifyJson "[{kind:user,name:$ME,perms:[read],flags:[],allow:true}]"`
    msg=`echo "$input" | $EXACL --set $FILE1 2>&1`
    assertEquals 1 $?
    assertEquals \
        "File \"$FILE1\": required ACL entry is missing" \
        "$msg"

    # Set ACL for current user specifically, with required entries.
    input=`quotifyJson "[{kind:user,name:@owner,perms:[read,write],flags:[],allow:true},{kind:group,name:@owner,perms:[read,write],flags:[], allow:true},{kind:group,name:@mask,perms:[read],flags:[], allow:true},{kind:user,name:@other,perms:[],flags:[], allow:true},{kind:user,name:$ME,perms:[read],flags:[],allow:true}]"`
    msg=`echo "$input" | $EXACL --set $FILE1 2>&1`
    assertEquals 0 $?
    assertEquals \
        "" \
        "${msg//\"}"

    # Check ACL again.
    msg=`$EXACL $FILE1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:@owner,perms:[write,read],flags:[],allow:true},{kind:user,name:$ME,perms:[read],flags:[],allow:true},{kind:group,name:@owner,perms:[write,read],flags:[],allow:true},{kind:group,name:@mask,perms:[read],flags:[],allow:true},{kind:user,name:@other,perms:[],flags:[],allow:true}]" \
        "${msg//\"}"
}

testWriteAclToDir1() {
    # Set ACL to empty.
    input="[]"
    msg=`echo "$input" | $EXACL --set $DIR1 2>&1`
    assertEquals 1 $?
    assertEquals \
        "File \"$DIR1\": required ACL entry is missing" \
        "$msg"

    # Verify directory ACL.
    msg=`$EXACL $DIR1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:@owner,perms:[execute,write,read],flags:[],allow:true},{kind:group,name:@owner,perms:[],flags:[],allow:true},{kind:user,name:@other,perms:[],flags:[],allow:true}]" \
        "${msg//\"}"

    assertEquals "drwx------" `fileperms "$DIR1"`
    isReadableDir "$DIR1"
    assertEquals 0 $?

    # Set ACL for current user to "deny read". Fails on Linux.
    input=`quotifyJson "[{kind:user,name:$ME,perms:[read],flags:[],allow:false}]"`
    msg=`echo "$input" | $EXACL --set $DIR1 2>&1`
    assertEquals 1 $?
    assertEquals \
        "Invalid ACL: entry 0: allow=false is not supported on Linux" \
        "$msg"

    input=`quotifyJson "[{kind:user,name:$ME,perms:[read],flags:[],allow:true},{kind:user,name:@owner,perms:[execute,write,read],flags:[],allow:true},{kind:group,name:@owner,perms:[],flags:[],allow:true},{kind:user,name:@other,perms:[],flags:[],allow:true}]"`
    msg=`echo "$input" | $EXACL --set $DIR1 2>&1`
    assertEquals 1 $?
    assertEquals \
        "File \"$DIR1\": required ACL entry is missing" \
        "$msg"

    input=`quotifyJson "[{kind:group,name:@mask,perms:[read],flags:[],allow:true},{kind:user,name:$ME,perms:[read],flags:[],allow:true},{kind:user,name:@owner,perms:[execute,write,read],flags:[],allow:true},{kind:group,name:@owner,perms:[],flags:[],allow:true},{kind:user,name:@other,perms:[],flags:[],allow:true}]"`
    msg=`echo "$input" | $EXACL --set $DIR1 2>&1`
    assertEquals 0 $?
    assertEquals \
        "" \
        "$msg"
    
    # Read ACL back.
    msg=`$EXACL $DIR1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:@owner,perms:[execute,write,read],flags:[],allow:true},{kind:user,name:$ME,perms:[read],flags:[],allow:true},{kind:group,name:@owner,perms:[],flags:[],allow:true},{kind:group,name:@mask,perms:[read],flags:[],allow:true},{kind:user,name:@other,perms:[],flags:[],allow:true}]" \
        "${msg//\"}"

    assertEquals "drwxr-----" `fileperms "$DIR1"`
}

testWriteAclToLink1() {
    # Set ACL to empty.
    input="[]"
    msg=`echo "$input" | $EXACL --set $LINK1 2>&1`
    assertEquals 1 $?
    assertEquals \
        "File \"$LINK1\": required ACL entry is missing" \
        "$msg"

    input=`quotifyJson "[{kind:group,name:@mask,perms:[read],flags:[],allow:true},{kind:user,name:$ME,perms:[read],flags:[],allow:true},{kind:user,name:@owner,perms:[execute,write,read],flags:[],allow:true},{kind:group,name:@owner,perms:[],flags:[],allow:true},{kind:user,name:@other,perms:[],flags:[],allow:true}]"`
    msg=`echo "$input" | $EXACL --set $LINK1 2>&1`
    assertEquals 1 $?
    assertEquals \
        "File \"$LINK1\": No such file or directory (os error 2)" \
        "$msg"
}

testWriteAclNumericUID() {
    # Set ACL for current user to "deny read".
    input=`quotifyJson "[{kind:user,name:$ME_NUM,perms:[read],flags:[],allow:true},$REQUIRED_ENTRIES,{kind:group,name:@mask,perms:[read],flags:[],allow:true}]"`
    msg=`echo "$input" | $EXACL --set $FILE1 2>&1`
    assertEquals 0 $?
    assertEquals "" "$msg"

    # Check ACL again.
    msg=`$EXACL $FILE1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:@owner,perms:[write,read],flags:[],allow:true},{kind:user,name:$ME,perms:[read],flags:[],allow:true},{kind:group,name:@owner,perms:[],flags:[],allow:true},{kind:group,name:@mask,perms:[read],flags:[],allow:true},{kind:user,name:@other,perms:[],flags:[],allow:true}]" \
        "${msg//\"}"
}

testWriteAclNumericGID() {
    # Set ACL for current group to "deny read".
    input=`quotifyJson "[{kind:group,name:$MY_GROUP_NUM,perms:[read],flags:[],allow:true},$REQUIRED_ENTRIES,{kind:group,name:@mask,perms:[read],flags:[],allow:true}]"`
    msg=`echo "$input" | $EXACL --set $FILE1 2>&1`
    assertEquals 0 $?
    assertEquals "" "$msg"

    # Check ACL again.
    msg=`$EXACL $FILE1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:@owner,perms:[write,read],flags:[],allow:true},{kind:group,name:@owner,perms:[],flags:[],allow:true},{kind:group,name:$MY_GROUP,perms:[read],flags:[],allow:true},{kind:group,name:@mask,perms:[read],flags:[],allow:true},{kind:user,name:@other,perms:[],flags:[],allow:true}]" \
        "${msg//\"}"
}

. shunit2
