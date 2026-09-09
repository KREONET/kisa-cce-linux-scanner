#!/bin/bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

# Verifies that firewall collection failures cannot be reported as inactivity.

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
SCAN_ROOT=/
RUNTIME_MODE=on

# shellcheck source=../lib/kisa-cce-core/_core.sh
. "$project_directory/lib/kisa-cce-core/_core.sh"
# shellcheck source=../lib/kisa-cce-checks/_account-file.sh
. "$project_directory/lib/kisa-cce-checks/_account-file.sh"

runtime_enabled() { return 0; }
scanner_u28_firewalld_runtime_probe() { return 2; }

status=0
scanner_u28_firewalld_probe || status=$?
[ "$status" -eq 2 ] || fail "collection error status changed: $status"
[ "$SCANNER_U28_RULE_COUNT" -eq 0 ] || fail "collection error retained a rule count"
case "$SCANNER_U28_PROBE_EVIDENCE" in
    'firewalld_state=unavailable,collection_error=true') ;;
    *) fail "collection error evidence is misleading: $SCANNER_U28_PROBE_EVIDENCE" ;;
esac

scanner_u28_firewalld_runtime_probe() { return 1; }
status=0
scanner_u28_firewalld_probe || status=$?
[ "$status" -eq 1 ] || fail "inactive status changed: $status"
[ "$SCANNER_U28_PROBE_EVIDENCE" = firewalld_state=inactive ] ||
    fail "inactive evidence changed: $SCANNER_U28_PROBE_EVIDENCE"

scanner_u28_firewalld_runtime_probe() {
    SCANNER_U28_RULE_COUNT=1
    SCANNER_U28_PROBE_EVIDENCE='firewalld_state=active,restricted_objects=1,open_objects=0,uncertain_objects=0'
    return 0
}
scanner_u28_firewalld_probe || fail "successful probe was rejected"
case "$SCANNER_U28_PROBE_EVIDENCE" in
    firewalld_state=active,*) ;;
    *) fail "successful probe evidence was overwritten" ;;
esac

# Bash exposes its invocation name through $0, as native multicall tools do.
output_file="$(mktemp "${TMPDIR:-/tmp}/kisa-cce-u28-dispatch.XXXXXXXX")" || exit 2
trap 'rm -f -- "$output_file"' EXIT
trusted_command() { printf '%s\n' "$BASH"; }
for command_name in iptables ip6tables; do
    scanner_u28_capture_command "$output_file" "$command_name" -c 'printf "%s\n" "$0"' ||
        fail "multicall dispatch failed for $command_name"
    [ "$(cat "$output_file")" = "$command_name" ] ||
        fail "resolved command lost the $command_name invocation name"
done
status=0
scanner_u28_capture_command "$output_file" iptables -c 'exit 4' || status=$?
[ "$status" -eq 2 ] || fail "native command failure was not retained: $status"

printf 'PASS: U-28 firewall evidence states\n'
