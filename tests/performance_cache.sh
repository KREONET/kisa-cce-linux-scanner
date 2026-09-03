#!/bin/bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

# shellcheck disable=SC2034 # Sourced scanner modules consume these test globals.

set -u

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
LC_ALL=C
export LC_ALL
umask 077

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent="." ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-performance-cache.XXXXXXXX")" || exit 2
root="$test_directory/root"
scratch="$test_directory/scratch"
find_count_file="$test_directory/find-count"
awk_count_file="$test_directory/awk-count"
debug_file="$test_directory/debug-events"
debug_fd=""

cleanup() {
    rm -rf -- "$test_directory"
}
trap cleanup EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_equal() {
    local expected="$1"
    local actual="$2"
    local description="$3"

    [ "$expected" = "$actual" ] || fail "$description: expected=[$expected] actual=[$actual]"
}

mkdir -p -- \
    "$root/etc/sysctl.d" \
    "$root/run/sysctl.d" \
    "$root/usr/local/lib/sysctl.d" \
    "$root/usr/lib/sysctl.d" \
    "$scratch"
printf '0\n' > "$find_count_file"
printf '0\n' > "$awk_count_file"

SCAN_ROOT="$root"
RUNTIME_MODE="off"
SCAN_EPOCH=1
SCAN_EPOCH_ACTIVE=1
IFS= read -r KISA_CCE_VERSION < "$project_directory/data/VERSION" || exit 2

# shellcheck source=../lib/core.sh
. "$project_directory/lib/core.sh"
# shellcheck source=../lib/resolvers.sh
. "$project_directory/lib/resolvers.sh"
SCRATCH_DIR="$scratch"
DEBUG=1
exec {debug_fd}> "$debug_file" || fail "debug capture descriptor could not be opened"
DEBUG_OUTPUT_FD="$debug_fd"

find() {
    local count=0

    IFS= read -r count < "$find_count_file" || return 2
    printf '%s\n' "$((count + 1))" > "$find_count_file" || return 2
    command find "$@"
}

awk() {
    local count=0

    IFS= read -r count < "$awk_count_file" || return 2
    printf '%s\n' "$((count + 1))" > "$awk_count_file" || return 2
    command awk "$@"
}

printf '%s\n' \
    'net.ipv4.ip_forward = 0' \
    'net.ipv4.conf.*.rp_filter = 2' > "$root/usr/lib/sysctl.d/20-vendor.conf"
printf '%s\n' \
    'net/ipv4/ip_forward = 1' \
    '-net.ipv4.conf.all.rp_filter' > "$root/etc/sysctl.d/90-local.conf"

sysctl_prepare_static_snapshot filesystem || fail "filesystem snapshot preparation failed"
IFS= read -r count < "$find_count_file"
assert_equal 1 "$count" "layered directories use one find invocation"
IFS= read -r count < "$awk_count_file"
assert_equal 2 "$count" "each selected sysctl file is parsed once"

value=""
sysctl_static_value_into net.ipv4.ip_forward value || fail "exact sysctl lookup failed"
assert_equal $'1\t/etc/sysctl.d/90-local.conf:1' "$value" "exact value and provenance"
sysctl_static_value_into net.ipv4.conf.eth0.rp_filter value || fail "glob sysctl lookup failed"
assert_equal $'2\t/usr/lib/sysctl.d/20-vendor.conf:2' "$value" "glob value and provenance"
status=0
sysctl_static_value_into net.ipv4.conf.all.rp_filter value || status=$?
assert_equal 1 "$status" "exact exclusion status"
status=0
sysctl_static_value_into kernel.missing value || status=$?
assert_equal 1 "$status" "absent key status"
status=0
sysctl_static_value_into kernel.missing value || status=$?
assert_equal 1 "$status" "absent key memoization status"
IFS= read -r count < "$find_count_file"
assert_equal 1 "$count" "queries reuse layered snapshot"
IFS= read -r count < "$awk_count_file"
assert_equal 2 "$count" "queries reuse parsed directive stream"

printf '%s\n' 'net.ipv4.ip_forward = 9' > "$root/etc/sysctl.d/90-local.conf"
sysctl_static_value_into net.ipv4.ip_forward value || fail "immutable epoch lookup failed"
assert_equal $'1\t/etc/sysctl.d/90-local.conf:1' "$value" "epoch snapshot remains immutable"

SCAN_EPOCH=2
sysctl_static_value_into net.ipv4.ip_forward value || fail "epoch refresh lookup failed"
assert_equal $'9\t/etc/sysctl.d/90-local.conf:1' "$value" "new epoch observes file mutation"
IFS= read -r count < "$find_count_file"
assert_equal 2 "$count" "new epoch refreshes layered selection"
IFS= read -r count < "$awk_count_file"
assert_equal 4 "$count" "new epoch reparses each selected file once"

printf '%s\n' 'kernel.kptr_restrict = 1' > "$root/usr/lib/sysctl.d/50-mask.conf"
ln -s -- /dev/null "$root/etc/sysctl.d/50-mask.conf"
SCAN_EPOCH=3
status=0
sysctl_static_value_into kernel.kptr_restrict value || status=$?
assert_equal 1 "$status" "higher-priority mask suppresses vendor basename"

printf '%s\n' 'kernel.escape_probe = 3' > "$test_directory/outside.conf"
ln -s -- ../../../outside.conf "$root/etc/sysctl.d/70-escape.conf"
SCAN_EPOCH=4
status=0
sysctl_static_value_into kernel.escape_probe value || status=$?
assert_equal 2 "$status" "escaping sysctl source status"
rm -f -- "$root/etc/sysctl.d/70-escape.conf"
printf '%s\n' 'kernel.escape_probe = 4' > "$root/etc/sysctl.d/70-escape.conf"
status=0
sysctl_static_value_into kernel.escape_probe value || status=$?
assert_equal 2 "$status" "snapshot error is memoized for the epoch"
IFS= read -r count < "$find_count_file"
assert_equal 4 "$count" "snapshot error does not repeat enumeration"

SCAN_EPOCH=5
sysctl_static_value_into kernel.escape_probe value || fail "restored sysctl source lookup failed"
assert_equal $'4\t/etc/sysctl.d/70-escape.conf:1' "$value" "new epoch clears snapshot error"

runtime_count=0
runtime_failure=0
capture_command() {
    local command_name="$1"

    shift
    [ "$command_name" = sysctl ] || return 127
    runtime_count=$((runtime_count + 1))
    [ "$runtime_failure" -eq 0 ] || return 42
    printf '7\n'
}

SCAN_EPOCH=6
sysctl_runtime_value_into kernel.test value || fail "runtime sysctl collection failed"
assert_equal 7 "$value" "runtime sysctl value"
sysctl_runtime_value_into kernel.test value || fail "runtime sysctl cache lookup failed"
assert_equal 1 "$runtime_count" "runtime key is collected once per epoch"

SCAN_EPOCH=7
runtime_failure=1
status=0
sysctl_runtime_value_into kernel.test value || status=$?
assert_equal 42 "$status" "runtime collection failure status"
status=0
sysctl_runtime_value_into kernel.test value || status=$?
assert_equal 42 "$status" "runtime failure memoization status"
assert_equal 2 "$runtime_count" "runtime failure is collected once in its epoch"

exec {debug_fd}>&-
DEBUG_OUTPUT_FD=""
grep -Fq -- "DEBUG: schema=1 event=sysctl_snapshot namespace=filesystem cache=miss" "$debug_file" ||
    fail "sysctl snapshot cache-miss debug event"
grep -Fq -- "DEBUG: schema=1 event=sysctl_snapshot namespace=filesystem cache=build status=0 files=2 directives=4" "$debug_file" ||
    fail "sysctl snapshot build debug event"
grep -Fq -- "DEBUG: schema=1 event=sysctl_snapshot namespace=filesystem cache=hit status=0" "$debug_file" ||
    fail "sysctl snapshot cache-hit debug event"
grep -Fq -- "DEBUG: schema=1 event=sysctl_query source=static namespace=filesystem cache=hit status=1" "$debug_file" ||
    fail "absent sysctl query cache-hit debug event"
grep -Fq -- "DEBUG: schema=1 event=sysctl_query source=runtime namespace=runtime cache=hit status=0" "$debug_file" ||
    fail "runtime sysctl cache-hit debug event"
grep -Fq -- "DEBUG: schema=1 event=sysctl_query source=runtime namespace=runtime cache=hit status=42" "$debug_file" ||
    fail "failed runtime sysctl cache-hit debug event"

printf 'PASS: sysctl epoch cache\n'
