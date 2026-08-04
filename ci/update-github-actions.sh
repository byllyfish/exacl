#!/bin/bash
#
# Update github actions from dependabot.
# (Compatible with bash 3.2 on macos.)

IFS=$'\n' read -r -d '' -a branches < <(git branch -r --list "origin/dependabot/github_actions/*" | sed 's~[ ]*origin/~~')

if [ ${#branches[@]} -eq 0 ]; then
    echo "No dependabot github_actions."
    exit 1
fi

git pull --no-rebase origin "${branches[@]}"
exit 0
