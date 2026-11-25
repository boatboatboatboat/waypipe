#!/bin/sh
set -eu

printf 'waypipe URI-list remapper: type=%s direction=%s\n' "$1" "$2" >&2
exec tee /dev/stderr
