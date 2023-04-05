#!/bin/bash

old=""
new=""

if [[ $(git diff --stat) != '' ]]; then
  echo 'error: git state (dirty)'
  exit 0
fi

read -p "Are you sure? " -n 1 -r
echo    # (optional)
if [[ $REPLY =~ ^[Yy]$ ]]
then
    old=$(gobump show | cut -d'"' -f4)
    gobump $1 -w
    new=$(gobump show | cut -d'"' -f4)
    git add version.go
    git commit -m "chore(version): bump"
    git tag v$new
    git push v$new
    goreleaser --clean --skip-announce
    git-chglog -o CHANGELOG.md
    git add CHANGELOG.md
    git commit -m "chore(changelog): update"
    git push
fi

echo "v$old -> v$new"

if [ -z "$1" ] || [ "$1" == "-h" ]; then
    echo "usage: $0 major|minor|patch"
    exit 0
fi