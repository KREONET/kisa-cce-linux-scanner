#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck disable=SC2034

set -u

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

assert_contains() {
    local actual="$1"
    local expected="$2"
    local description="$3"

    case "$actual" in *"$expected"*) ;; *) fail "$description: missing=[$expected] actual=[$actual]" ;; esac
}

status_of() {
    local status_value=0

    "$@" || status_value=$?
    printf '%s\n' "$status_value"
}

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent=. ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-runtime-fallback.XXXXXXXX")" || exit 2
proc_root="$test_directory/proc"
run_root="$test_directory/run"

cleanup() {
    chmod -R u+rwX "$test_directory" 2>/dev/null || :
    rm -rf -- "$test_directory"
}
trap cleanup EXIT

mkdir -p "$proc_root/net" "$proc_root/1/fd" "$proc_root/100/fd" "$proc_root/200/fd" \
    "$run_root/systemd/system"
printf 'systemd\n' > "$proc_root/1/comm"
ln -s /usr/lib/systemd/systemd "$proc_root/1/exe"
printf 'web-worker\n' > "$proc_root/100/comm"
ln -s /usr/bin/web "$proc_root/100/exe"
ln -s 'socket:[1001]' "$proc_root/100/fd/3"
ln -s 'socket:[1002]' "$proc_root/100/fd/4"
printf 'dns-worker\n' > "$proc_root/200/comm"
ln -s /usr/sbin/dns "$proc_root/200/exe"
ln -s 'socket:[2001]' "$proc_root/200/fd/3"
ln -s 'socket:[2002]' "$proc_root/200/fd/4"

printf '%s\n' \
    '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode' \
    '   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1001' \
    '   1: 0100007F:1770 0100007F:0035 01 00000000:00000000 00:00000000 00000000 0 0 9999' \
    > "$proc_root/net/tcp"
printf '%s\n' \
    '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode' \
    '   0: 00000000000000000000000001000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1002' \
    > "$proc_root/net/tcp6"
printf '%s\n' \
    '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode' \
    '   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 2001' \
    '   1: 0100007F:14E9 0100007F:0035 01 00000000:00000000 00:00000000 00000000 0 0 2999' \
    > "$proc_root/net/udp"
printf '%s\n' \
    '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode' \
    '   0: 00000000000000000000000001000000:007B 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 2002' \
    > "$proc_root/net/udp6"

RUNTIME_FALLBACK_PROC_ROOT="$proc_root"
RUNTIME_FALLBACK_RUN_ROOT="$run_root"
RUNTIME_FALLBACK_FIND_COMMAND="$(command -v find)"
SCAN_EPOCH_ID=1

# shellcheck source=../lib/runtime_fallback.sh disable=SC1091
. "$project_directory/lib/runtime_fallback.sh"

process_rows=""
status=0
runtime_process_snapshot_into process_rows || status=$?
assert_equal 0 "$status" "complete process snapshot"
assert_contains "$process_rows" $'100\tweb-worker\t/usr/bin/web' \
    "bounded process row"
assert_equal 0 "$(status_of runtime_process_state web-worker)" "process lookup by comm"
assert_equal 0 "$(status_of runtime_process_state web)" "process lookup by executable"
assert_equal 1 "$(status_of runtime_process_state absent-process)" "complete process absence"
assert_equal 0 "$(status_of runtime_systemd_manager_state)" "running systemd manager"

listener_rows=""
status=0
runtime_listener_snapshot_into listener_rows || status=$?
assert_equal 0 "$status" "complete listener snapshot"
assert_contains "$listener_rows" $'tcp\t127.0.0.1\t8080\tweb-worker\t100\t1001\tlisten' \
    "IPv4 TCP listener"
assert_contains "$listener_rows" $'tcp\t0000:0000:0000:0000:0000:0000:0000:0001\t443\tweb-worker\t100\t1002\tlisten' \
    "IPv6 TCP listener"
assert_contains "$listener_rows" $'udp\t0.0.0.0\t53\tdns-worker\t200\t2001\tbound' \
    "IPv4 UDP socket"
assert_contains "$listener_rows" $'udp\t0000:0000:0000:0000:0000:0000:0000:0001\t123\tdns-worker\t200\t2002\tbound' \
    "IPv6 UDP socket"
case "$listener_rows" in *$'\t6000\t'*) fail "non-listening TCP socket was retained" ;; esac
case "$listener_rows" in *$'\t5353\t'*) fail "connected UDP socket was retained" ;; esac

port_rows=""
status=0
runtime_listener_facts_for_port_into port_rows 443 tcp || status=$?
assert_equal 0 "$status" "positive listener query"
assert_contains "$port_rows" $'\t443\tweb-worker\t' "listener query rows"
assert_equal 1 "$(status_of runtime_listener_facts_for_port_into port_rows 9999 any)" \
    "complete listener absence"

# A scan epoch is immutable even when procfs fixtures change underneath it.
sed 's/:1F90 /:2382 /' "$proc_root/net/tcp" > "$proc_root/net/tcp.next"
mv "$proc_root/net/tcp.next" "$proc_root/net/tcp"
printf 'bash\n' > "$proc_root/1/comm"
assert_equal 0 "$(status_of runtime_listener_facts_for_port_into port_rows 8080 tcp)" \
    "same-epoch listener cache"
assert_equal 0 "$(status_of runtime_systemd_manager_state)" "same-epoch manager cache"

SCAN_EPOCH_ID=2
assert_equal 1 "$(status_of runtime_listener_facts_for_port_into port_rows 8080 tcp)" \
    "new epoch listener refresh"
assert_equal 0 "$(status_of runtime_listener_facts_for_port_into port_rows 9090 tcp)" \
    "new epoch listener value"
assert_equal 1 "$(status_of runtime_systemd_manager_state)" "non-systemd PID 1"

# Malformed and unreadable tables preserve positive facts but make absence unknown.
printf '%s\n' 'header local_address' 'malformed socket row' > "$proc_root/net/tcp"
chmod 000 "$proc_root/net/tcp6"
SCAN_EPOCH_ID=3
status=0
runtime_listener_snapshot_into listener_rows || status=$?
assert_equal 3 "$status" "partial listener snapshot"
assert_equal 1 "$PROCFS_RUNTIME_SOCKET_MALFORMED_ROWS" "malformed socket row count"
if [ -r "$proc_root/net/tcp6" ]; then
    assert_equal 0 "$PROCFS_RUNTIME_SOCKET_TABLE_ERRORS" "privileged socket table access"
else
    assert_equal 1 "$PROCFS_RUNTIME_SOCKET_TABLE_ERRORS" "unreadable socket table count"
fi
assert_equal 0 "$(status_of runtime_listener_facts_for_port_into port_rows 53 udp)" \
    "positive fact from partial snapshot"
assert_equal 2 "$(status_of runtime_listener_facts_for_port_into port_rows 9090 tcp)" \
    "partial snapshot absence"

chmod 600 "$proc_root/net/tcp6"
rm -rf "$proc_root/net"
mkdir "$proc_root/net" "$proc_root/net/tcp" "$proc_root/net/tcp6" \
    "$proc_root/net/udp" "$proc_root/net/udp6"
SCAN_EPOCH_ID=4
assert_equal 2 "$(status_of runtime_listener_snapshot_into listener_rows)" "listener snapshot error"

# An unreadable process record makes negative process lookup indeterminate.
rm -rf "$proc_root/100/comm"
mkdir "$proc_root/100/comm"
SCAN_EPOCH_ID=5
status=0
runtime_process_snapshot_into process_rows || status=$?
assert_equal 3 "$status" "partial process snapshot"
assert_equal 2 "$(status_of runtime_process_state web-worker)" "partial process absence"
assert_equal 0 "$(status_of runtime_process_state dns-worker)" "positive process in partial snapshot"

# Explicit reset refreshes a snapshot without changing the epoch identifier.
rm -rf "$proc_root/100/comm"
printf 'web-restored\n' > "$proc_root/100/comm"
runtime_fallback_reset_epoch_cache
assert_equal 0 "$(status_of runtime_process_state web-restored)" "explicit process cache reset"

printf 'systemd\n' > "$proc_root/1/comm"
rm -rf "$run_root/systemd/system"
SCAN_EPOCH_ID=6
assert_equal 2 "$(status_of runtime_systemd_manager_state)" "ambiguous systemd marker"

RUNTIME_FALLBACK_PROC_ROOT="$test_directory/missing-proc"
SCAN_EPOCH_ID=7
assert_equal 2 "$(status_of runtime_process_snapshot_into process_rows)" "missing procfs process error"
assert_equal 2 "$(status_of runtime_listener_snapshot_into listener_rows)" "missing procfs listener error"

printf 'runtime fallback tests passed\n'
