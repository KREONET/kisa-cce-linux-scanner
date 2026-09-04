#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

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

file_mode() {
    local path="$1"

    if stat -c '%a' -- "$path" >/dev/null 2>&1; then
        stat -c '%a' -- "$path"
    else
        stat -f '%Lp' "$path"
    fi
}

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent=. ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-desired-state-policy.XXXXXXXX")" || exit 2
trap 'chmod -R u+rwX "$test_directory" 2>/dev/null || :; rm -rf -- "$test_directory"' EXIT

# shellcheck source=../lib/kisa-cce-patcher/_coverage.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_coverage.sh"
# shellcheck source=../lib/kisa-cce-patcher/_desired-state-policy.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_desired-state-policy.sh"

valid_policy="$test_directory/valid.yml"
printf '%s\n' \
    'schema_version: 2' \
    'profile_id: kisa-baseline' \
    'max_risk: R4' \
    'desired_states:' \
    '  - code: U-12' \
    '    adapter: session_timeout' \
    '    postcondition: GOOD' \
    '    input_type: none' \
    '    input_value: -' \
    '  - code: U-28' \
    '    adapter: network_access' \
    '    postcondition: GOOD' \
    '    input_type: network_service_allowlist' \
    '    input_value: ssh@192.0.2.0/24' \
    '  - code: U-34' \
    '    adapter: finger_service' \
    '    postcondition: GOOD' \
    '    input_type: service_disable_approval' \
    '    input_value: CHG-123' \
    '  - code: U-45' \
    '    adapter: mail_version' \
    '    postcondition: NOT_APPLICABLE' \
    '    input_type: vendor_mail_advisory_snapshot' \
    '    input_value: sha256:0000000000000000000000000000000000000000000000000000000000000000' \
    > "$valid_policy"
chmod 0600 "$valid_policy"

compiled_policy="$test_directory/compiled.tsv"
patch_desired_state_policy_compile "$valid_policy" "$compiled_policy" ||
    fail "valid desired-state policy was rejected: $PATCH_DESIRED_STATE_ERROR_DETAIL"
assert_equal 600 "$(file_mode "$compiled_policy")" "compiled policy mode"
assert_equal "$PATCH_DESIRED_STATE_TSV_HEADER" "$(sed -n '1p' "$compiled_policy")" \
    "compiled policy header"
assert_equal 5 "$(wc -l < "$compiled_policy" | tr -d '[:space:]')" \
    "compiled policy line count"
assert_equal 13 "$(awk -F '\t' 'NR == 2 {print NF}' "$compiled_policy")" \
    "compiled policy field count"
grep -Fqx $'kisa-baseline\tR4\tU-12\tsession_timeout\tR1\ttechnical\tconfiguration\tGOOD\tfixed\tnone\t-\tpatch_configuration_verify\tconfiguration' \
    "$compiled_policy" || fail "fixed desired-state row differs"
grep -Fqx $'kisa-baseline\tR4\tU-28\tnetwork_access\tR4\tpolicy\tedge-service\tGOOD\tconditional\tnetwork_service_allowlist\tssh@192.0.2.0/24\tvalidate_u28_network_access_v2\tedge-service' \
    "$compiled_policy" || fail "edge-service desired-state row differs"
grep -Fqx $'kisa-baseline\tR4\tU-34\tfinger_service\tR3\truntime\tservice\tGOOD\tconditional\tservice_disable_approval\tCHG-123\tpatch_service_verify\tservice' \
    "$compiled_policy" || fail "conditional desired-state row differs"

example_output="$test_directory/example.tsv"
patch_desired_state_policy_compile \
    "$project_directory/examples/desired-state-policy-v2.yml" "$example_output" ||
    fail "repository desired-state example was rejected: $PATCH_DESIRED_STATE_ERROR_DETAIL"
assert_equal 10 "$(wc -l < "$example_output" | tr -d '[:space:]')" \
    "implemented example line count"
assert_equal 9 "$(awk -F '\t' 'NR > 1 && $9 == "fixed" {count++} END {print count+0}' "$example_output")" \
    "fixed example criterion count"

status=0
patch_desired_state_policy_compile "$valid_policy" "$compiled_policy" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "compiled output overwrite rejection"

low_risk_policy="$test_directory/low-risk.yml"
sed 's/max_risk: R4/max_risk: R1/' "$valid_policy" > "$low_risk_policy"
chmod 0600 "$low_risk_policy"
status=0
patch_desired_state_policy_compile "$low_risk_policy" "$test_directory/low-risk.tsv" \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "risk ceiling rejection"
assert_contains "$PATCH_DESIRED_STATE_ERROR_DETAIL" "risk exceeds" "risk ceiling diagnostic"
[ ! -e "$test_directory/low-risk.tsv" ] || fail "risk rejection published output"

adapter_policy="$test_directory/adapter.yml"
awk '{if (!changed && $0 == "    adapter: session_timeout") {print "    adapter: login_warning"; changed=1} else print}' \
    "$valid_policy" > "$adapter_policy"
chmod 0600 "$adapter_policy"
status=0
patch_desired_state_policy_compile "$adapter_policy" "$test_directory/adapter.tsv" \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "adapter mismatch rejection"
assert_contains "$PATCH_DESIRED_STATE_ERROR_DETAIL" "adapter does not match" "adapter mismatch diagnostic"

fixed_input_policy="$test_directory/fixed-input.yml"
awk '{if (!changed && $0 == "    input_value: -") {print "    input_value: custom"; changed=1} else print}' \
    "$valid_policy" > "$fixed_input_policy"
chmod 0600 "$fixed_input_policy"
status=0
patch_desired_state_policy_compile "$fixed_input_policy" "$test_directory/fixed-input.tsv" \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "fixed adapter input rejection"

missing_input_policy="$test_directory/missing-input.yml"
awk '{if ($0 == "    input_value: ssh@192.0.2.0/24") print "    input_value: -"; else print}' \
    "$valid_policy" > "$missing_input_policy"
chmod 0600 "$missing_input_policy"
status=0
patch_desired_state_policy_compile "$missing_input_policy" "$test_directory/missing-input.tsv" \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "gated typed input rejection"
assert_contains "$PATCH_DESIRED_STATE_ERROR_DETAIL" "requires a typed input value" \
    "gated typed input diagnostic"

missing_conditional_policy="$test_directory/missing-conditional.yml"
awk '{if ($0 == "    input_value: CHG-123") print "    input_value: -"; else print}' \
    "$valid_policy" > "$missing_conditional_policy"
chmod 0600 "$missing_conditional_policy"
status=0
patch_desired_state_policy_compile "$missing_conditional_policy" \
    "$test_directory/missing-conditional.tsv" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "conditional typed input rejection"
assert_contains "$PATCH_DESIRED_STATE_ERROR_DETAIL" "conditional adapter requires" \
    "conditional typed input diagnostic"

for unsafe_path in /tmp//domain.tsv /tmp/./domain.tsv /tmp/../domain.tsv; do
    unsafe_name="$(printf '%s' "$unsafe_path" | tr '/.' '__')"
    unsafe_policy="$test_directory/path-$unsafe_name.yml"
    awk -v replacement="    input_value: $unsafe_path" \
        '{if ($0 == "    input_value: ssh@192.0.2.0/24") print replacement; else print}' \
        "$valid_policy" > "$unsafe_policy"
    chmod 0600 "$unsafe_policy"
    status=0
    patch_desired_state_policy_compile "$unsafe_policy" "$test_directory/path-$unsafe_name.tsv" \
        >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "unsafe absolute desired-state path rejection: $unsafe_path"
done

duplicate_policy="$test_directory/duplicate.yml"
printf '%s\n' \
    'schema_version: 2' \
    'profile_id: duplicate' \
    'max_risk: R1' \
    'desired_states:' \
    '  - code: U-12' \
    '    adapter: session_timeout' \
    '    postcondition: GOOD' \
    '    input_type: none' \
    '    input_value: -' \
    '  - code: U-12' \
    '    adapter: session_timeout' \
    '    postcondition: GOOD' \
    '    input_type: none' \
    '    input_value: -' > "$duplicate_policy"
chmod 0600 "$duplicate_policy"
status=0
patch_desired_state_policy_compile "$duplicate_policy" "$test_directory/duplicate.tsv" \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "duplicate desired-state rejection"

unknown_policy="$test_directory/unknown.yml"
awk '{if (!changed && $0 == "  - code: U-12") {print "  - code: U-99"; changed=1} else print}' \
    "$valid_policy" > "$unknown_policy"
chmod 0600 "$unknown_policy"
status=0
patch_desired_state_policy_compile "$unknown_policy" "$test_directory/unknown.tsv" \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "unknown criterion rejection"

injection_marker="$test_directory/injection-executed"
injection_policy="$test_directory/injection.yml"
awk -v replacement="    input_value: \$(touch $injection_marker)" \
    '{if (!changed && $0 == "    input_value: -") {print replacement; changed=1} else print}' \
    "$valid_policy" > "$injection_policy"
chmod 0600 "$injection_policy"
status=0
patch_desired_state_policy_compile "$injection_policy" "$test_directory/injection.tsv" \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "shell syntax scalar rejection"
[ ! -e "$injection_marker" ] || fail "desired-state scalar executed shell syntax"

anchor_policy="$test_directory/anchor.yml"
sed 's/  - code: U-12/  - \&entry/' "$valid_policy" > "$anchor_policy"
chmod 0600 "$anchor_policy"
status=0
patch_desired_state_policy_compile "$anchor_policy" "$test_directory/anchor.tsv" \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "YAML anchor rejection"

control_policy="$test_directory/control.yml"
printf 'schema_version: 2\nprofile_id: control\nmax_risk: R0\ndesired_states: []\000\n' \
    > "$control_policy"
chmod 0600 "$control_policy"
status=0
patch_desired_state_policy_compile "$control_policy" "$test_directory/control.tsv" \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "control byte rejection"

ln -s "$valid_policy" "$test_directory/policy-link.yml"
status=0
patch_desired_state_policy_compile "$test_directory/policy-link.yml" "$test_directory/link.tsv" \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "policy symlink rejection"

untrusted_policy="$test_directory/untrusted.yml"
cp "$valid_policy" "$untrusted_policy"
chmod 0666 "$untrusted_policy"
status=0
patch_desired_state_policy_compile "$untrusted_policy" "$test_directory/untrusted.tsv" \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "group-writable policy rejection"

writable_parent="$test_directory/writable-parent"
mkdir -m 0777 "$writable_parent"
cp "$valid_policy" "$writable_parent/policy.yml"
chmod 0600 "$writable_parent/policy.yml"
status=0
patch_desired_state_policy_compile "$writable_parent/policy.yml" \
    "$test_directory/writable-parent.tsv" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "replaceable desired-state parent rejection"

# Schema version 1 keeps its existing compiler and output contract.
# shellcheck source=../lib/kisa-cce-policy/_policy-yaml.sh disable=SC1091
. "$project_directory/lib/kisa-cce-policy/_policy-yaml.sh"
legacy_policy="$test_directory/legacy.yml"
printf '%s\n' 'schema_version: 1' 'attestations: []' > "$legacy_policy"
chmod 0600 "$legacy_policy"
legacy_attestations="$test_directory/legacy-attestations.tsv"
legacy_time_sources="$test_directory/legacy-time-sources.tsv"
legacy_errors="$test_directory/legacy-errors.txt"
policy_yaml_compile "$legacy_policy" "$legacy_attestations" "$legacy_time_sources" "$legacy_errors" ||
    fail "schema version 1 compatibility failed"
assert_equal $'code\tdecision\treview_id\tticket\tapprover\texpires' \
    "$(sed -n '1p' "$legacy_attestations")" "schema version 1 output header"

printf 'PASS: desired-state policy v2\n'
