#!/bin/bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

# shellcheck disable=SC2034

set -u

test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-scan-epoch.XXXXXXXX")" || exit 2
debug_file="$test_directory/debug-events"
trap 'rm -rf -- "$test_directory"' EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent=. ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2

SCRATCH_DIR="$test_directory"
KISA_CCE_VERSION=0.1.0
PLATFORM_ID=ubuntu
PLATFORM_VERSION=26.04
PLATFORM_BASE_ID=ubuntu
PLATFORM_BASE_VERSION=26.04
POLICY_SET_DIGEST=sha256:policy-a
EVIDENCE_BUNDLE_DIGEST=sha256:evidence-a
reset_count=0

resolver_reset_epoch_caches() { reset_count=$((reset_count + 1)); }
debug_emit() { printf '%s\n' "$*" >> "$debug_file"; }

# shellcheck source=../lib/kisa-cce-core/_scan-epoch.sh
. "$project_directory/lib/kisa-cce-core/_scan-epoch.sh"
SCAN_INCREMENTAL_REEVALUATION_ACTIVE=1

scan_epoch_begin || fail "first epoch failed"
[ "$SCAN_EPOCH_ID" -eq 1 ] || fail "first epoch ID"
SCAN_ACTIVE_CRITERION=U-01
scan_dependency_register file:/etc/pam.d/sshd pam:sshd:auth || fail "dependency registration"
scan_resolver_commit pam:sshd:auth output-a >/dev/null || fail "first resolver output"
[ "${SCAN_CRITERION_DIRTY[U-01]-0}" -eq 1 ] || fail "initial output marks consumer"

scan_epoch_begin || fail "second epoch failed"
SCAN_ACTIVE_CRITERION=U-01
scan_dependency_register file:/etc/pam.d/sshd pam:sshd:auth || fail "repeat dependency registration"
scan_source_mark_dirty file:/etc/pam.d/sshd || fail "source dirty mark"
[ "${SCAN_RESOLVER_DIRTY[pam:sshd:auth]-0}" -eq 1 ] || fail "source dirties resolver"
[ "${SCAN_CRITERION_DIRTY[U-01]-0}" -eq 0 ] || fail "source change propagated before resolver output changed"
status=0
scan_resolver_commit pam:sshd:auth output-a >/dev/null || status=$?
[ "$status" -eq 1 ] || fail "unchanged resolver status"
[ "${SCAN_CRITERION_DIRTY[U-01]-0}" -eq 0 ] || fail "unchanged resolver dirtied criterion"

scan_epoch_begin || fail "third epoch failed"
SCAN_ACTIVE_CRITERION=U-01
scan_source_mark_dirty file:/etc/pam.d/sshd || fail "second source dirty mark"
scan_resolver_commit pam:sshd:auth output-b >/dev/null || fail "changed resolver output"
[ "${SCAN_CRITERION_DIRTY[U-01]-0}" -eq 1 ] || fail "changed resolver did not dirty criterion"

scan_epoch_begin || fail "fourth epoch failed"
SCAN_ACTIVE_CRITERION=U-01
PLATFORM_VERSION=24.04
scan_epoch_begin || fail "context-change epoch failed"
[ "${SCAN_RESOLVER_DIRTY[pam:sshd:auth]-0}" -eq 1 ] || fail "platform context did not dirty resolver"
[ "$reset_count" -eq 5 ] || fail "epoch reset hook count"
scan_epoch_end
grep -Fq -- "scan_epoch phase begin epoch 1 resolver_schema 2 incremental 1 policy active evidence inactive" "$debug_file" ||
    fail "scan epoch begin debug event"
grep -Fq -- "scan_epoch phase end epoch 5" "$debug_file" || fail "scan epoch end debug event"

printf 'PASS: scan epoch dependency graph\n'
