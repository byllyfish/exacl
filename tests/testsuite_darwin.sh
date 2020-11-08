#!/bin/bash

# Basic test suite for exacl tool.

set -u -o pipefail

EXACL='../target/debug/exacl'

DIR="test_dir-mac_os-test_dir"
FILE1="$DIR/file1"
DIR1="$DIR/dir1"
LINK1="$DIR/link1"
LINK2="$DIR/link2"

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
    ln -s file1 "$LINK2"
}

# Put quotes back on JSON text.
quotifyJson() { 
    echo "$1" | sed -E -e 's/([A-Za-z0-9_-]+)/"\1"/g' -e 's/:"false"/:false/g' -e 's/:"true"/:true/g'
}

oneTimeTearDown() {
    # Delete our temporary directory.
    rm -rf "$DIR"
}

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
    assertEquals "[]" "$msg"

    isReadable "$FILE1" && isWritable "$FILE1"
    assertEquals 0 $?
    
    # Add ACL entry for current user to "deny read".
    chmod +a "$ME deny read" "$FILE1"

    msg=`$EXACL $FILE1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:$ME,perms:[read],flags:[],allow:false}]" \
        "${msg//\"}"

    ! isReadable "$FILE1" && isWritable "$FILE1"
    assertEquals 0 $?

    # Remove user write perm.
    chmod u-w "$FILE1"
    ! isReadable "$FILE1" && ! isWritable "$FILE1"
    assertEquals 0 $?

    # Add ACL entry for current group to "allow write".
    chmod +a "$MY_GROUP allow write" "$FILE1"

    msg=`$EXACL $FILE1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:$ME,perms:[read],flags:[],allow:false},{kind:group,name:$MY_GROUP,perms:[write],flags:[],allow:true}]" \
        "${msg//\"}"

    ! isReadable "$FILE1" && isWritable "$FILE1"
    assertEquals 0 $?

    # Re-add user write perm that we removed above. Clear the ACL.
    chmod u+w "$FILE1"
    chmod -N "$FILE1"
}

testReadAclForDir1() {
    msg=`$EXACL $DIR1`
    assertEquals 0 $?
    assertEquals "[]" "$msg"

    # Add ACL entry for current user to "deny read" with inheritance flags.
    chmod +a "$ME deny read,file_inherit,directory_inherit,only_inherit" "$DIR1"

    msg=`$EXACL $DIR1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:$ME,perms:[read],flags:[file_inherit,directory_inherit,only_inherit],allow:false}]" \
        "${msg//\"}"

    isReadableDir "$DIR1"
    assertEquals 0 $?

    # Create subfile in DIR1.
    subfile="$DIR1/subfile"
    touch "$subfile"

    ! isReadable "$subfile" && isWritable "$subfile"
    assertEquals 0 $?

    msg=`$EXACL $subfile`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:$ME,perms:[read],flags:[inherited],allow:false}]" \
        "${msg//\"}"

    # Create subdirectory in DIR1.
    subdir="$DIR1/subdir"
    mkdir "$subdir"

    msg=`$EXACL $subdir`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:$ME,perms:[read],flags:[inherited,file_inherit,directory_inherit],allow:false}]" \
        "${msg//\"}"

    # Clear directory ACL's so we can delete them.
    chmod -a# 0 "$subdir"
    chmod -a# 0 "$DIR1"

    rmdir "$subdir"
    rm "$subfile"
}

testReadAclForLink1() {
    # Test symlink that goes nowhere.
    msg=`$EXACL $LINK1 2>&1`
    assertEquals 1 $?
    assertEquals "File \"$LINK1\": No such file or directory (os error 2)" "$msg"

    # Test symlink with no ACL.
    msg=`$EXACL -h $LINK1`
    assertEquals 0 $?
    assertEquals "[]" "$msg"

    # Add ACL entry for current user to "deny read".
    chmod -h +a "$ME deny read" "$LINK1"
    assertEquals 0 $?

    ! isReadableLink "$LINK1"
    assertEquals 0 $?

    msg=`$EXACL -h $LINK1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:$ME,perms:[read],flags:[],allow:false}]" \
        "${msg//\"}"

    # It appears that you can't further modify the ACL of a symbolic link if
    # you don't have 'read' access to the link anymore.
    msg=`chmod -h -a# 0 "$LINK1" 2>&1`
    assertEquals 1 $?
    assertEquals \
        "chmod: No ACL present 'test_dir-mac_os-test_dir/link1'
chmod: Failed to set ACL on file 'test_dir-mac_os-test_dir/link1': Permission denied" \
        "$msg"

    # Recreate the symlink here.
    ln -fs link1_to_nowhere "$LINK1"
}

testReadAclForLink2() {
    # Test symlink to file1.
    msg=`$EXACL $LINK2`
    assertEquals 0 $?
    assertEquals "[]" "$msg"

    # Add ACL entry for current user to "deny read".
    chmod +a "$ME deny read" "$LINK2"

    msg=`$EXACL $LINK2`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:$ME,perms:[read],flags:[],allow:false}]" \
        "${msg//\"}"
}

testWriteAclToMissingFile() {
    input="[]"
    msg=`echo "$input" | $EXACL --set $DIR/non_existant 2>&1`
    assertEquals 1 $?
    assertEquals \
        "File \"$DIR/non_existant\": No such file or directory (os error 2)" \
        "$msg"
}

testWriteAclToFile1() {
    # Set ACL to empty.
    input="[]"
    msg=`echo "$input" | $EXACL --set $FILE1 2>&1`
    assertEquals 0 $?
    assertEquals "" "$msg"

    # Verify it's empty.
    msg=`$EXACL $FILE1`
    assertEquals 0 $?
    assertEquals "[]" "$msg"

    isReadable "$FILE1" && isWritable "$FILE1"
    assertEquals 0 $?

    # Set ACL for current user to "deny read".
    input=`quotifyJson "[{kind:user,name:$ME,perms:[read],flags:[],allow:false}]"`
    msg=`echo "$input" | $EXACL --set $FILE1 2>&1`
    assertEquals 0 $?
    assertEquals "" "$msg"

    ! isReadable "$FILE1" && isWritable "$FILE1"
    assertEquals 0 $?

    # Check ACL using ls.
    msg=`ls -le $FILE1 | grep -E '^ \d+: '`
    assertEquals \
        " 0: user:$ME deny read" \
        "$msg"

    # Check ACL again.
    msg=`$EXACL $FILE1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:$ME,perms:[read],flags:[],allow:false}]" \
        "${msg//\"}"
}

testWriteAclToDir1() {
    # Set ACL to empty.
    input="[]"
    msg=`echo "$input" | $EXACL --set $DIR1 2>&1`
    assertEquals 0 $?
    assertEquals "" "$msg"

    # Verify it's empty.
    msg=`$EXACL $DIR1`
    assertEquals 0 $?
    assertEquals "[]" "$msg"

    isReadableDir "$DIR1"
    assertEquals 0 $?

    # Set ACL for current user to "deny read".
    input=`quotifyJson "[{kind:user,name:$ME,perms:[read],flags:[],allow:false}]"`
    msg=`echo "$input" | $EXACL --set $DIR1 2>&1`
    assertEquals 0 $?
    assertEquals "" "$msg"

    ! isReadable "$DIR1"
    assertEquals 0 $?

    # Read ACL back.
    msg=`$EXACL $DIR1`
    assertEquals 0 $?
    assertEquals "$input" "$msg"
}

testWriteAclToLink1() {
    # Set ACL to empty.
    input="[]"
    msg=`echo "$input" | $EXACL -h --set $LINK1 2>&1`
    assertEquals 0 $?
    assertEquals \
        "" \
        "$msg"

    isReadableLink "$LINK1"
    assertEquals 0 $?

    # Set ACL for current user to "deny read".
    input=`quotifyJson "[{kind:user,name:$ME,perms:[read],flags:[],allow:false}]"`
    msg=`echo "$input" | $EXACL -h --set $LINK1 2>&1`
    assertEquals 0 $?
    assertEquals \
        "" \
        "$msg"

    ! isReadableLink "$LINK1"
    assertEquals 0 $?

    # Check ACL using ls.
    msg=`ls -le $LINK1 2> /dev/null | grep -E '^ \d+: '`
    assertEquals \
        " 0: user:$ME deny read" \
        "$msg"

    # Check ACL again.
    msg=`$EXACL -h $LINK1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:$ME,perms:[read],flags:[],allow:false}]" \
        "${msg//\"}"

    # Set ACL back to empty. We've removed READ permission for the link, so
    # this will fail.
    input="[]"
    msg=`echo "$input" | $EXACL -h --set $LINK1 2>&1`
    assertEquals 1 $?
    assertEquals \
        "File \"$LINK1\": Permission denied (os error 13)" \
        "$msg"
}

testWriteAllFilePerms() {
    all="read,write,execute,delete,append,delete_child,readattr,writeattr,readextattr,writeextattr,readsecurity,writesecurity,chown,sync"
    input=`quotifyJson "[{kind:user,name:$ME,perms:[$all],flags:[],allow:true}]"`
    msg=`echo "$input" | $EXACL --set $FILE1`
    assertEquals 0 $?
    assertEquals "" "$msg"

    msg=`$EXACL $FILE1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:$ME,perms:[$all],flags:[],allow:true}]" \
        "${msg//\"}"

    # ls output omits delete_child and sync.
    ls_perms="read,write,execute,delete,append,readattr,writeattr,readextattr,writeextattr,readsecurity,writesecurity,chown"
    msg=`ls -le $FILE1 | grep -E '^ \d+: '`
    assertEquals \
        " 0: user:$ME allow $ls_perms" \
        "$msg"
}

testWriteAllFileFlags() {
    entry_flags="inherited,file_inherit,directory_inherit,limit_inherit,only_inherit"
    all="defer_inherit,no_inherit,$entry_flags"
    input=`quotifyJson "[{kind:user,name:$ME,perms:[read],flags:[$all],allow:true}]"`
    msg=`echo "$input" | $EXACL --set $FILE1`
    assertEquals 0 $?
    assertEquals "" "$msg"

    # N.B. "defer_inherit" flag is not returned.
    msg=`$EXACL $FILE1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:$ME,perms:[read],flags:[$entry_flags,no_inherit],allow:true}]" \
        "${msg//\"}"

    # ls output only shows inherited and limit_inherit.
    ls_perms="read,limit_inherit"
    msg=`ls -le $FILE1 | grep -E '^ \d+: '`
    assertEquals \
        " 0: user:$ME inherited allow $ls_perms" \
        "$msg"
}

testWriteAllDirPerms() {
    all="read,write,execute,delete,append,delete_child,readattr,writeattr,readextattr,writeextattr,readsecurity,writesecurity,chown,sync"
    input=`quotifyJson "[{kind:user,name:$ME,perms:[$all],flags:[],allow:true}]"`
    msg=`echo "$input" | $EXACL --set $DIR1`
    assertEquals 0 $?
    assertEquals "" "$msg"

    msg=`$EXACL $DIR1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:$ME,perms:[$all],flags:[],allow:true}]" \
        "${msg//\"}"
}

testWriteAllDirFlags() {
    entry_flags="inherited,file_inherit,directory_inherit,limit_inherit,only_inherit"
    all="defer_inherit,no_inherit,$entry_flags"
    input=`quotifyJson "[{kind:user,name:$ME,perms:[read],flags:[$all],allow:true}]"`
    msg=`echo "$input" | $EXACL --set $DIR1`
    assertEquals 0 $?
    assertEquals "" "$msg"

    # N.B. "defer_inherit" flag is not returned.
    msg=`$EXACL $DIR1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:$ME,perms:[read],flags:[$entry_flags,no_inherit],allow:true}]" \
        "${msg//\"}"
}


testWriteAclNumericUID() {
    # Set ACL for current user to "deny read".
    input=`quotifyJson "[{kind:user,name:$ME_NUM,perms:[read],flags:[],allow:false}]"`
    msg=`echo "$input" | $EXACL --set $FILE1 2>&1`
    assertEquals 0 $?
    assertEquals "" "$msg"

    ! isReadable "$FILE1" && isWritable "$FILE1"
    assertEquals 0 $?

    # Check ACL again.
    msg=`$EXACL $FILE1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:$ME,perms:[read],flags:[],allow:false}]" \
        "${msg//\"}"
}

testWriteAclNumericGID() {
    # Set ACL for current group to "deny read".
    input=`quotifyJson "[{kind:group,name:$MY_GROUP_NUM,perms:[read],flags:[],allow:false}]"`
    msg=`echo "$input" | $EXACL --set $FILE1 2>&1`
    assertEquals 0 $?
    assertEquals "" "$msg"

    ! isReadable "$FILE1" && isWritable "$FILE1"
    assertEquals 0 $?

    # Check ACL again.
    msg=`$EXACL $FILE1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:group,name:$MY_GROUP,perms:[read],flags:[],allow:false}]" \
        "${msg//\"}"
}

testWriteAclGUID() {
    # Set ACL for _spotlight group to "deny read" using GUID.
    spotlight_group="ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000059"
    input=`quotifyJson "[{kind:group,name:$spotlight_group,perms:[read],flags:[],allow:false}]"`
    msg=`echo "$input" | $EXACL --set $FILE1 2>&1`
    assertEquals 0 $?
    assertEquals "" "$msg"

    # Check ACL again.
    msg=`$EXACL $FILE1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:group,name:_spotlight,perms:[read],flags:[],allow:false}]" \
        "${msg//\"}"
}

testWriteAclGUID_nil() {
    # Set ACL for _spotlight group to "deny read" using GUID.
    nil_uuid="00000000-0000-0000-0000-000000000000"
    input=`quotifyJson "[{kind:group,name:$nil_uuid,perms:[read],flags:[],allow:false}]"`
    msg=`echo "$input" | $EXACL --set $FILE1 2>&1`
    assertEquals 0 $?
    assertEquals "" "$msg"

    # Check ACL again. Note: change in kind.
    msg=`$EXACL $FILE1`
    assertEquals 0 $?
    assertEquals \
        "[{kind:user,name:$nil_uuid,perms:[read],flags:[],allow:false}]" \
        "${msg//\"}"
}

. shunit2
