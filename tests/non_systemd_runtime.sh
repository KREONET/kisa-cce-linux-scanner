#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

# Verifies conclusive procfs runtime fallback on a non-systemd Linux root.

# shellcheck disable=SC1091,SC2034

set -u

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_status() {
    local expected="$1"
    local description="$2"

    [ "$RESULT_STATUS" = "$expected" ] ||
        fail "$description: expected=$expected actual=$RESULT_STATUS evidence=$RESULT_EVIDENCE"
}

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent=. ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-nonsystemd.XXXXXXXX")" || exit 2
root_directory="$test_directory/root"
proc_root="$test_directory/proc"
run_root="$test_directory/run"
scratch_directory="$test_directory/scratch"
trap 'rm -rf -- "$test_directory"' EXIT

mkdir -p -- "$root_directory/etc" "$root_directory/var/log" \
    "$proc_root/1/fd" "$proc_root/net" "$run_root" "$scratch_directory"
printf '%s\n' bash > "$proc_root/1/comm"
ln -s /bin/bash "$proc_root/1/exe"
for table_name in tcp tcp6 udp udp6; do
    printf '%s\n' \
        '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode' \
        > "$proc_root/net/$table_name"
done
printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' > "$root_directory/etc/passwd"
printf '%s\n' 'root:x:0:' > "$root_directory/etc/group"

KISA_CCE_VERSION="test"
SCAN_ROOT="$root_directory"
RUNTIME_MODE=on
SCRATCH_DIR="$scratch_directory"
SCAN_EPOCH_ID=1
SCAN_EPOCH_ACTIVE=1
SCAN_INCREMENTAL_REEVALUATION_ACTIVE=0
PLATFORM_ID=ubuntu
PLATFORM_VERSION=26.04
PLATFORM_FAMILY=debian
PLATFORM_BASE_ID=ubuntu
PLATFORM_BASE_VERSION=26.04
RUNTIME_FALLBACK_PROC_ROOT="$proc_root"
RUNTIME_FALLBACK_RUN_ROOT="$run_root"
RUNTIME_FALLBACK_FIND_COMMAND="$(command -v find)"

. "$project_directory/lib/core.sh"
. "$project_directory/lib/scan_epoch.sh"
. "$project_directory/lib/runtime_fallback.sh"
. "$project_directory/lib/resolvers.sh"
. "$project_directory/lib/checks_account_file.sh"
. "$project_directory/lib/checks_service.sh"
. "$project_directory/lib/checks_system.sh"

PLATFORM_ID=ubuntu
PLATFORM_VERSION=26.04
PLATFORM_FAMILY=debian
PLATFORM_BASE_ID=ubuntu
PLATFORM_BASE_VERSION=26.04
runtime_enabled() { return 0; }
runtime_snapshot_available() { return 0; }
trusted_command() { return 127; }
scanner_u28_tcp_wrapper_probe() { SCANNER_U28_PROBE_EVIDENCE=wrapper_policy=absent; return 1; }
scanner_u28_ufw_probe() { SCANNER_U28_PROBE_EVIDENCE=ufw_state=inactive; return 1; }
scanner_u28_nftables_probe() { SCANNER_U28_PROBE_EVIDENCE=nftables_state=inactive; return 1; }
scanner_u28_xtables_probe() { SCANNER_U28_PROBE_EVIDENCE="${1}_state=inactive"; return 1; }
rsyslog_configuration_evidence() { return 1; }

runtime_systemd_manager_state
[ "$?" -eq 1 ] || fail "non-systemd PID 1 was not recognized"
service_state ssh.service sshd.service >/dev/null 2>&1
[ "$?" -eq 3 ] || fail "systemd unit state was treated as a collection error"
listener_output="$(port_listener_facts 22 tcp)" || fail "procfs listener absence was not conclusive"
[ -z "$listener_output" ] || fail "empty procfs fixture produced an SSH listener"

check_u_01
assert_status GOOD "U-01 non-systemd service absence"
check_u_28
assert_status VULNERABLE "U-28 absent firewall policy"
check_u_34
assert_status GOOD "U-34 absent Finger service"
check_u_35
assert_status NOT_APPLICABLE "U-35 absent sharing services"
check_u_39
assert_status GOOD "U-39 absent NFS service"
check_u_42
assert_status GOOD "U-42 absent RPC services"
check_u_43
assert_status GOOD "U-43 absent NIS services"
check_u_45
assert_status NOT_APPLICABLE "U-45 absent mail service"
check_u_49
assert_status NOT_APPLICABLE "U-49 absent DNS service"
check_u_58
assert_status GOOD "U-58 absent SNMP service"
check_u_65
assert_status VULNERABLE "U-65 absent time service"
check_u_66
assert_status VULNERABLE "U-66 absent logging provider"

printf 'PASS: non-systemd procfs runtime integration\n'
