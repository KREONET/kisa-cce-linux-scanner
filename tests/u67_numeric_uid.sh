#!/bin/bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

# shellcheck disable=SC2034

set -u

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent=. ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2

KISA_CCE_VERSION=0.1.0

# shellcheck source=../lib/core.sh
. "$project_directory/lib/core.sh"
# shellcheck source=../lib/checks_system.sh
. "$project_directory/lib/checks_system.sh"

assert_status() {
    local expected="$1"
    local description="$2"
    shift 2
    local actual=0

    "$@" || actual=$?
    [ "$actual" -eq "$expected" ] ||
        fail "$description: expected status $expected, received $actual"
}

assert_status 0 "numeric root UID and mode 0644" system_u67_file_metadata_state 0 644
assert_status 0 "numeric root UID and stricter mode" system_u67_file_metadata_state 0 600
assert_status 1 "non-root numeric UID" system_u67_file_metadata_state 1 600
assert_status 1 "group-writable log file" system_u67_file_metadata_state 0 664
assert_status 2 "NSS owner name is not accepted" system_u67_file_metadata_state root 600
assert_status 2 "missing numeric UID" system_u67_file_metadata_state '' 600
assert_status 2 "malformed mode" system_u67_file_metadata_state 0 64x

assert_status 0 "numeric root directory" system_u67_directory_metadata_state 0 755
assert_status 1 "non-root directory" system_u67_directory_metadata_state 42 700
assert_status 1 "group-writable directory" system_u67_directory_metadata_state 0 775
assert_status 2 "malformed directory UID" system_u67_directory_metadata_state 00 755
assert_status 2 "malformed directory mode" system_u67_directory_metadata_state 0 invalid

printf 'PASS: U-67 numeric UID metadata\n'
