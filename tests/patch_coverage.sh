#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

# shellcheck disable=SC2034

set -u

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
LC_ALL=C
export LC_ALL
umask 077

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_equal() {
    local expected="$1"
    local actual="$2"
    local context="$3"

    [ "$expected" = "$actual" ] || fail "$context: expected=[$expected] actual=[$actual]"
}

assert_contains() {
    local actual="$1"
    local expected="$2"
    local context="$3"

    case "$actual" in *"$expected"*) ;; *) fail "$context: missing=[$expected] actual=[$actual]" ;; esac
}

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent=. ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-patch-coverage.XXXXXXXX")" || exit 2
trap 'chmod -R u+rwX "$test_directory" 2>/dev/null || :; rm -rf -- "$test_directory"' EXIT

# shellcheck source=../lib/kisa-cce-patcher/_coverage.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_coverage.sh"
# shellcheck source=../lib/kisa-cce-patcher/_metadata-rules.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_metadata-rules.sh"
# shellcheck source=../lib/kisa-cce-patcher/_engine.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_engine.sh"
# shellcheck source=../lib/kisa-cce-patcher/_account-transaction.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_account-transaction.sh"
# shellcheck source=../lib/kisa-cce-patcher/_filesystem-transaction.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_filesystem-transaction.sh"
# shellcheck source=../lib/kisa-cce-patcher/_inventory-transaction.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_inventory-transaction.sh"
# shellcheck source=../lib/kisa-cce-patcher/_network-service-transaction.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_network-service-transaction.sh"
# shellcheck source=../lib/kisa-cce-patcher/_pam-transaction.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_pam-transaction.sh"
# shellcheck source=../lib/kisa-cce-patcher/_service-transaction.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_service-transaction.sh"
# shellcheck source=../lib/kisa-cce-patcher/_system-transaction.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_system-transaction.sh"
# shellcheck source=../lib/kisa-cce-patcher/_edge-service-transaction.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_edge-service-transaction.sh"
# shellcheck source=../lib/kisa-cce-patcher/_orchestrator.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_orchestrator.sh"
# shellcheck source=../lib/kisa-cce-patcher/_orchestrator-domains.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_orchestrator-domains.sh"

declare -F patch_configuration_verify >/dev/null || fail "configuration public validator is absent"
declare -F patch_configuration_rollback >/dev/null || fail "configuration rollback API is absent"
declare -F patch_engine_verify >/dev/null || fail "metadata public validator is absent"
declare -F patch_engine_rollback >/dev/null || fail "metadata rollback API is absent"
declare -F patch_account_verify >/dev/null || fail "account public validator is absent"
declare -F patch_account_rollback >/dev/null || fail "account rollback API is absent"
declare -F patch_filesystem_verify >/dev/null || fail "filesystem public validator is absent"
declare -F patch_filesystem_rollback >/dev/null || fail "filesystem rollback API is absent"
declare -F patch_inventory_verify >/dev/null || fail "inventory public validator is absent"
declare -F patch_inventory_rollback >/dev/null || fail "inventory rollback API is absent"
declare -F patch_network_service_verify >/dev/null || fail "network-service public validator is absent"
declare -F patch_network_service_rollback >/dev/null || fail "network-service rollback API is absent"
declare -F pam_transaction_verify >/dev/null || fail "PAM public validator is absent"
declare -F pam_transaction_rollback >/dev/null || fail "PAM rollback API is absent"
declare -F patch_service_verify >/dev/null || fail "service public validator is absent"
declare -F patch_service_rollback >/dev/null || fail "service rollback API is absent"
declare -F patch_system_verify >/dev/null || fail "system public validator is absent"
declare -F patch_system_rollback >/dev/null || fail "system rollback API is absent"
declare -F validate_u64_patch_management_v2 >/dev/null || fail "package plan validator is absent"
declare -F validate_u01_remote_root_access_v2 >/dev/null || fail "edge-service validator is absent"
declare -F patch_edge_rollback >/dev/null || fail "edge-service rollback API is absent"

patch_coverage_validate || fail "built-in coverage contract is invalid: $PATCH_COVERAGE_ERROR_DETAIL"

contract="$test_directory/coverage.tsv"
patch_coverage_records > "$contract"
chmod 0600 "$contract"
patch_coverage_validate_file "$contract" ||
    fail "materialized coverage contract is invalid: $PATCH_COVERAGE_ERROR_DETAIL"
assert_equal 68 "$(wc -l < "$contract" | tr -d '[:space:]')" "coverage line count"
assert_equal 67 "$(awk -F '\t' 'NR > 1 {count++} END {print count+0}' "$contract")" \
    "coverage record count"
assert_equal 67 "$(awk -F '\t' 'NR > 1 {seen[$2]++} END {for (key in seen) count++} END {print count+0}' "$contract")" \
    "unique primary adapter count"
assert_equal 'U-12,U-16,U-18,U-19,U-22,U-29,U-37,U-62,U-67' \
    "$(awk -F '\t' 'NR > 1 && $7 == "fixed" {values=values separator $1; separator=","} END {print values}' "$contract")" \
    "fixed criterion set"
assert_equal 58 "$(awk -F '\t' 'NR > 1 && $7 == "conditional" {count++} END {print count+0}' "$contract")" \
    "conditional criterion count"
assert_equal 0 "$(awk -F '\t' 'NR > 1 && $7 == "gated" {count++} END {print count+0}' "$contract")" \
    "gated criterion count"
assert_equal 'conditional,conditional,conditional' \
    "$(awk -F '\t' '$1 ~ /^U-6[456]$/ {values=values separator $7; separator=","} END {print values}' "$contract")" \
    "U-64 through U-66 conditional status"

index=1
while [ "$index" -le 67 ]; do
    printf -v code 'U-%02d' "$index"
    row=""
    patch_coverage_record_into "$code" row || fail "coverage lookup failed: $code"
    assert_equal "$code" "${row%%$'\t'*}" "coverage lookup code"
    index=$((index + 1))
done

typed_input=""
validator=""
rollback_domain=""
patch_coverage_conditional_requirements_into U-01 typed_input validator rollback_domain ||
    fail "edge conditional requirement lookup failed"
assert_equal root_remote_access_policy "$typed_input" "U-01 typed input"
assert_equal validate_u01_remote_root_access_v2 "$validator" "U-01 validator"
assert_equal edge-service "$rollback_domain" "U-01 rollback domain"
patch_coverage_conditional_requirements_into U-02 typed_input validator rollback_domain ||
    fail "PAM conditional requirement lookup failed"
assert_equal pam_password_policy "$typed_input" "U-02 conditional typed input"
assert_equal pam_transaction_verify "$validator" "U-02 conditional validator"
assert_equal pam "$rollback_domain" "U-02 conditional rollback domain"
patch_coverage_conditional_requirements_into U-34 typed_input validator rollback_domain ||
    fail "service conditional requirement lookup failed"
assert_equal service_disable_approval "$typed_input" "U-34 conditional typed input"
assert_equal patch_service_verify "$validator" "U-34 conditional validator"
assert_equal service "$rollback_domain" "U-34 conditional rollback domain"
patch_coverage_conditional_requirements_into U-17 typed_input validator rollback_domain ||
    fail "filesystem conditional requirement lookup failed"
assert_equal startup_object_policy "$typed_input" "U-17 conditional typed input"
assert_equal patch_filesystem_verify "$validator" "U-17 conditional validator"
assert_equal filesystem "$rollback_domain" "U-17 conditional rollback domain"

PATCH_DOMAIN_REQUEST_CODES=(U-17)
PATCH_FILESYSTEM_SELECTED_CRITERIA=([U-17]=1 [U-20]=1)
status=0
_patch_domains_selected_criteria_match_requests filesystem >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "filesystem child scope expansion rejection"
PATCH_DOMAIN_REQUEST_CODES=(U-14)
PATCH_INVENTORY_SELECTED_CRITERIA=([U-14]=1 [U-23]=1)
status=0
_patch_domains_selected_criteria_match_requests inventory >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "inventory child scope expansion rejection"
patch_coverage_conditional_requirements_into U-30 typed_input validator rollback_domain ||
    fail "inventory conditional requirement lookup failed"
assert_equal umask_policy_parameters "$typed_input" "U-30 conditional typed input"
assert_equal patch_inventory_verify "$validator" "U-30 conditional validator"
assert_equal inventory "$rollback_domain" "U-30 conditional rollback domain"
patch_coverage_conditional_requirements_into U-65 typed_input validator rollback_domain ||
    fail "system conditional requirement lookup failed"
assert_equal approved_time_sources "$typed_input" "U-65 conditional typed input"
assert_equal patch_system_verify "$validator" "U-65 conditional validator"
assert_equal system "$rollback_domain" "U-65 conditional rollback domain"
status=0
patch_coverage_gated_requirements_into U-12 typed_input validator rollback_domain \
    >/dev/null 2>&1 || status=$?
assert_equal 1 "$status" "fixed criterion has no gated requirement"

missing="$test_directory/missing.tsv"
awk -F '\t' '$1 != "U-10"' "$contract" > "$missing"
status=0
patch_coverage_validate_file "$missing" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "missing criterion rejection"
assert_contains "$PATCH_COVERAGE_ERROR_DETAIL" "missing, duplicated, or out of order" \
    "missing criterion diagnostic"

duplicate="$test_directory/duplicate.tsv"
awk -F '\t' '{print; if ($1 == "U-10") print}' "$contract" > "$duplicate"
status=0
patch_coverage_validate_file "$duplicate" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "duplicate criterion rejection"
assert_contains "$PATCH_COVERAGE_ERROR_DETAIL" "missing, duplicated, or out of order" \
    "duplicate criterion diagnostic"

unknown_adapter="$test_directory/unknown-adapter.tsv"
awk -F '\t' 'BEGIN {OFS="\t"} {$2=($1 == "U-01" ? "unknown_adapter" : $2); print}' \
    "$contract" > "$unknown_adapter"
status=0
patch_coverage_validate_file "$unknown_adapter" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "unknown adapter rejection"
assert_contains "$PATCH_COVERAGE_ERROR_DETAIL" "unknown primary adapter" "unknown adapter diagnostic"

duplicate_adapter="$test_directory/duplicate-adapter.tsv"
awk -F '\t' 'BEGIN {OFS="\t"} {$2=($1 == "U-02" ? "remote_root_access" : $2); print}' \
    "$contract" > "$duplicate_adapter"
status=0
patch_coverage_validate_file "$duplicate_adapter" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "duplicate adapter rejection"
assert_contains "$PATCH_COVERAGE_ERROR_DETAIL" "duplicates primary adapter" "duplicate adapter diagnostic"

invalid_risk="$test_directory/invalid-risk.tsv"
awk -F '\t' 'BEGIN {OFS="\t"} {$3=($1 == "U-02" ? "R5" : $3); print}' \
    "$contract" > "$invalid_risk"
status=0
patch_coverage_validate_file "$invalid_risk" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "invalid risk rejection"

invalid_domain="$test_directory/invalid-domain.tsv"
awk -F '\t' 'BEGIN {OFS="\t"} {$5=($1 == "U-02" ? "database" : $5); print}' \
    "$contract" > "$invalid_domain"
status=0
patch_coverage_validate_file "$invalid_domain" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "invalid transaction domain rejection"

unknown_validator="$test_directory/unknown-validator.tsv"
awk -F '\t' 'BEGIN {OFS="\t"} {$9=($1 == "U-02" ? "generic_validator" : $9); print}' \
    "$contract" > "$unknown_validator"
status=0
patch_coverage_validate_file "$unknown_validator" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "unknown conditional validator rejection"

missing_conditional_input="$test_directory/missing-conditional-input.tsv"
awk -F '\t' 'BEGIN {OFS="\t"} {$8=($1 == "U-02" ? "none" : $8); print}' \
    "$contract" > "$missing_conditional_input"
status=0
patch_coverage_validate_file "$missing_conditional_input" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "conditional typed input rejection"

wrong_status="$test_directory/wrong-status.tsv"
awk -F '\t' 'BEGIN {OFS="\t"} {$7=($1 == "U-12" ? "gated" : $7); print}' \
    "$contract" > "$wrong_status"
status=0
patch_coverage_validate_file "$wrong_status" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "fixed set drift rejection"

ln -s "$contract" "$test_directory/coverage-link.tsv"
status=0
patch_coverage_validate_file "$test_directory/coverage-link.tsv" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "coverage symlink rejection"

printf 'PASS: patch coverage contract\n'
