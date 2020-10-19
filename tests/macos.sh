#!/bin/sh
#
# Run MacOS-based tests.

set -eu

bold=`tput bold`
underline=`tput smul`
reset=`tput sgr0`

log() {
    echo ""
    echo "${bold}${underline}${1}${reset}"
}

perms() {
    stat -f "%Sp" "$1"
}

check_read_file_fails() {
    if cat "$1" > /dev/null ; then
        exit 1
    fi
}

check_read_file_succeeds() {
    if ! cat "$1" > /dev/null ; then
        exit 1
    fi
}

check_write_file_succeeds() {
    if ! echo "foo" > "$1" ; then
        exit 1
    fi
}

check_write_file_fails() {
    if echo "foo" > "$1" ; then
        exit 1
    fi
}

check_read_dir_succeeds() {
    if ! ls "$1" ; then
        exit 1
    fi
}

check_read_dir_fails() {
    if ls "$1" ; then
        exit 1
    fi
}

check_read_link_succeeds() {
    if ! readlink "$1" ; then
        exit 1
    fi
}

check_read_link_fails() {
    if readlink "$1" ; then
        exit 1
    fi
}

alias exacl=../../target/debug/exacl
export RUST_LOG=debug

# Create an empty temp directory.
tempdir="test_dir-mac_os-test_dir"
if [ -d "$tempdir" ]; then
    rm -rf "$tempdir"
fi
mkdir "$tempdir"
cd "$tempdir"
umask 077

log "Test non-existant file."
if exacl non_existant ; then
    exit 1    # Expect it to fail.
fi

log "Test new file with no ACL."
touch file1
perms file1
exacl file1
check_read_file_succeeds file1
check_write_file_succeeds file1

log "Test file with one deny ACE."
chmod +a "bfish deny read" file1
perms file1
exacl file1
check_read_file_fails file1
check_write_file_succeeds file1
chmod -a# 0 file1
perms file1
exacl file1
check_read_file_succeeds file1

log "Test file with one allow ACE and mode -w"
chmod u-w file1
chmod +a "bfish allow write" file1
perms file1
exacl file1
check_read_file_succeeds file1
check_write_file_succeeds file1

log "Test file with redundant allow ACE's"
chmod u-rwx file1
chmod -N file1
chmod +a# 0 "bfish allow execute" file1
chmod +a# 1 "bfish allow write" file1
chmod +a# 2 "bfish allow read" file1
perms file1
exacl file1
check_read_file_succeeds file1
check_write_file_succeeds file1
chmod -a# 2 file1
exacl file1
check_read_file_fails file1
check_write_file_succeeds file1

# Done with file1
rm file1

log "Test new directory with no ACL."
mkdir dir1
exacl dir1
check_read_dir_succeeds dir1

log "Test directory with one deny ACE."
chmod +a "bfish deny read" dir1
ls -le .
exacl dir1
check_read_dir_fails dir1

# Done with dir1
rmdir dir1

log "Test new symlink to nowhere with no ACL."
ln -s link1_to_nowhere link1
ls -le .
exacl link1
stat link1
readlink link1

log "Test new symlink with one DENY ACE."
chmod -h +a "bfish deny read" link1
ls -le .
exacl link1
stat link1
check_read_link_fails link1
## It appears that you can't further modify the ACL of a symbolic link if you
## don't have 'read' access to the link anymore...
#chmod -h +a "bfish deny write" link1
#chmod -h -a# 0 link1

log "Test symlink with one allow ACE and no r mode"
# Mac OS can't remove the ACL entry?  Recreate the link instead.
#chmod -h -N link1
ln -fs link1_to_nowhere link1
chmod -h +a "bfish allow read" link1
chmod -h u-rwx link1
ls -le .
exacl link1 
check_read_link_succeeds link1

# Test this later... getting err=Operation not supported (os error 45) from acl_set_link_np.
#exacl link1 | exacl --set link1

# Done with link1
rm link1

log "Copy ACL from file1 to file2"

touch file1
touch file2
chmod +a# 0 "bfish allow execute" file1
chmod +a# 1 "bfish allow write" file1
chmod +a# 2 "bfish allow read" file1
exacl file1 | exacl --set file2
exacl file1
exacl file2

# Done with both files.
rm file1 file2

log "Done."

exit 0
