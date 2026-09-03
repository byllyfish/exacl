#! /usr/bin/env bash

# This script adds a group named "é" (Latin1) to a FreeBSD system
# as gid=777775. This group name is not valid UTF-8.

NAME="\xe9"
GID=777775

# Append the /etc/group entry: NAME:*:GID:USERS
printf "%b:*:%d:\n" "$NAME" "$GID" >>/etc/group

echo "Added non-UTF8 group name."
exit 0
