#!/bin/sh
# Check out the wireguard-go submodule and apply the external DH patch.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
cd "$root"

reset=0
if [ "${1:-}" = "--reset" ]; then
	reset=1
elif [ -n "${1:-}" ]; then
	echo "usage: ./sync-wireguard.sh [--reset]" >&2
	exit 2
fi

if [ ! -e wireguard-go/go.mod ] || [ "$reset" -eq 1 ]; then
	git submodule update --init -- wireguard-go
fi

if [ "$reset" -eq 1 ]; then
	git -C wireguard-go reset --hard
	git -C wireguard-go clean -fd
	git submodule update --checkout --force -- wireguard-go
fi

patch=$root/0001-external-static-dh.patch
if git -C wireguard-go apply --reverse --check "$patch" >/dev/null 2>&1; then
	exit 0
fi

if ! git -C wireguard-go diff --quiet || [ -n "$(git -C wireguard-go status --porcelain)" ]; then
	echo "wireguard-go has changes other than 0001-external-static-dh.patch" >&2
	echo "rerun with --reset to discard them and reapply the patch" >&2
	exit 1
fi

git -C wireguard-go apply "$patch"
