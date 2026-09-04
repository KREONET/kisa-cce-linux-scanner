#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

set -u

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_equal() { [ "$1" = "$2" ] || fail "$3: expected=[$1] actual=[$2]"; }
assert_contains() { case "$1" in *"$2"*) ;; *) fail "$3: missing=[$2]" ;; esac; }

case "${BASH_SOURCE[0]}" in */*) test_parent="${BASH_SOURCE[0]%/*}" ;; *) test_parent=. ;; esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-automation.XXXXXXXX")" || exit 2
scanner_copy="$test_directory/scanner"
scan_root="$test_directory/root"
policy_directory="$test_directory/policy"
bundle="$test_directory/evidence"
override_file="$scanner_copy/lib/kisa-cce-checks/_z-override.sh"
trap 'chmod -R u+rwX "$test_directory" 2>/dev/null || :; rm -rf -- "$test_directory"' EXIT

mkdir -p "$scanner_copy/bin" \
    "$scanner_copy/lib/kisa-cce-checks" \
    "$scanner_copy/lib/kisa-cce-cli" \
    "$scanner_copy/lib/kisa-cce-core" \
    "$scanner_copy/lib/kisa-cce-policy" \
    "$scanner_copy/lib/kisa-cce-resolvers" \
    "$scanner_copy/lib/kisa-cce-runtime" \
    "$scanner_copy/data" \
    "$scanner_copy/share/kisa-cce-linux-scanner/locale" "$scan_root/etc" \
    "$policy_directory" "$bundle/identity" "$bundle/runtime"
chmod 0700 "$policy_directory" "$bundle" "$bundle/identity" "$bundle/runtime"
cp "$project_directory/bin/kisa-cce-scan" "$scanner_copy/bin/kisa-cce-scan"
cp "$project_directory/lib/kisa-cce-core/_core.sh" "$scanner_copy/lib/kisa-cce-core/"
cp "$project_directory/lib/kisa-cce-core/_i18n.sh" "$scanner_copy/lib/kisa-cce-core/"
cp "$project_directory/lib/kisa-cce-core/_scan-epoch.sh" "$scanner_copy/lib/kisa-cce-core/"
cp "$project_directory/lib/kisa-cce-cli/_scan-main.sh" "$scanner_copy/lib/kisa-cce-cli/"
cp "$project_directory/lib/kisa-cce-policy/_policy.sh" "$scanner_copy/lib/kisa-cce-policy/"
cp "$project_directory/lib/kisa-cce-resolvers/_resolvers.sh" "$scanner_copy/lib/kisa-cce-resolvers/"
cp "$project_directory/lib/kisa-cce-runtime/_evidence.sh" "$scanner_copy/lib/kisa-cce-runtime/"
cp "$project_directory/lib/kisa-cce-runtime/_runtime-fallback.sh" "$scanner_copy/lib/kisa-cce-runtime/"
cp "$project_directory/data/criteria.tsv" "$project_directory/data/VERSION" "$scanner_copy/data/"
cp -R "$project_directory/share/kisa-cce-linux-scanner/locale/en" \
    "$project_directory/share/kisa-cce-linux-scanner/locale/ko" \
    "$scanner_copy/share/kisa-cce-linux-scanner/locale/"
chmod 0755 "$scanner_copy/bin/kisa-cce-scan"

{
    printf '%s\n' '# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause'
    printf '%s\n' 'i18n_summary_into() { printf -v "$2" "%s" "$1"; }'
    printf '%s\n' 'i18n_criterion_title_into() { printf -v "$3" "%s" "$2"; }'
    for ((number = 1; number <= 67; number++)); do
        printf -v function_name 'check_u_%02d' "$number"
        case "$number" in
            2) printf '%s() { set_result VULNERABLE "fixture vulnerable" "fixture=vulnerable"; }\n' "$function_name" ;;
            3) printf '%s() { set_result NOT_APPLICABLE "fixture absent" "fixture=absent" false; }\n' "$function_name" ;;
            *) printf '%s() { set_result GOOD "fixture good" "fixture=good"; }\n' "$function_name" ;;
        esac
    done
} > "$scanner_copy/lib/kisa-cce-checks/_fixture.sh"

printf '%s\n' 'ID=ubuntu' 'VERSION_ID="26.04"' 'PRETTY_NAME="Ubuntu 26.04 LTS"' > "$scan_root/etc/os-release"
machine_id=0123456789abcdef0123456789abcdef
boot_id=01234567-89ab-cdef-0123-456789abcdef
printf '%s\n' "$machine_id" > "$scan_root/etc/machine-id"
cp "$scan_root/etc/os-release" "$bundle/identity/os-release"
printf '%s\n' "$machine_id" > "$bundle/identity/machine-id"
printf '%s\n' "$boot_id" > "$bundle/identity/boot-id"
printf '%s\n' '6.8.0-test' > "$bundle/identity/kernel-release"
printf 'unit\tload_state\tactive_state\tsub_state\tunit_file_state\n' > "$bundle/runtime/systemd-units.tsv"
printf 'unit\tunit_file_state\tpreset\n' > "$bundle/runtime/systemd-unit-files.tsv"
printf 'transport\tlocal_address\tport\tprocess\n' > "$bundle/runtime/listeners.tsv"
printf '%s\n' '36 25 8:1 / / rw,relatime - ext4 /dev/root rw' > "$bundle/runtime/mountinfo"
printf '%s\n' 'status=unavailable' > "$bundle/runtime/firewall.txt"
printf '%s\n' '[unavailable]' > "$bundle/runtime/time-sync.txt"
captured_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "$bundle/manifest.tsv" <<EOF
schema_version	1
captured_at	$captured_at
machine_id	$machine_id
boot_id	$boot_id
kernel_release	6.8.0-test
identity_os_release_status	collected
identity_machine_id_status	collected
identity_boot_id_status	collected
identity_kernel_release_status	collected
runtime_systemd_units_status	collected
runtime_systemd_unit_files_status	collected
runtime_listeners_status	collected
runtime_mountinfo_status	collected
runtime_firewall_status	unavailable
runtime_time_sync_status	unavailable
EOF
: > "$bundle/checksums.sha256"
for relative_path in manifest.tsv identity/os-release identity/machine-id identity/boot-id \
    identity/kernel-release runtime/systemd-units.tsv runtime/systemd-unit-files.tsv \
    runtime/listeners.tsv runtime/mountinfo runtime/firewall.txt runtime/time-sync.txt; do
    printf '%s  %s\n' "$(sha256sum "$bundle/$relative_path" | awk '{print $1}')" "$relative_path" \
        >> "$bundle/checksums.sha256"
done
chmod 0600 "$bundle/manifest.tsv" "$bundle/checksums.sha256" "$bundle"/identity/* "$bundle"/runtime/*

run_scanner() {
    local stdout_file="$1" stderr_file="$2"
    shift 2
    "$scanner_copy/bin/kisa-cce-scan" "$@" > "$stdout_file" 2> "$stderr_file"
}

assert_empty_output_directory() {
    local directory="$1" entry="" nullglob_was_set=0 dotglob_was_set=0
    local -a entries=()
    [ -d "$directory" ] || fail "automation output directory was not created: $directory"
    shopt -q nullglob && nullglob_was_set=1
    shopt -q dotglob && dotglob_was_set=1
    shopt -s nullglob dotglob
    entries=("$directory"/*)
    [ "$nullglob_was_set" -eq 1 ] || shopt -u nullglob
    [ "$dotglob_was_set" -eq 1 ] || shopt -u dotglob
    for entry in "${entries[@]}"; do fail "blocked automation scan published an artifact: $entry"; done
}

preflight_stdout="$test_directory/preflight.stdout"
preflight_stderr="$test_directory/preflight.stderr"
status=0
run_scanner "$preflight_stdout" "$preflight_stderr" --root "$scan_root" --mode automation \
    --output-dir "$test_directory/preflight-output" || status=$?
assert_equal 2 "$status" "automation policy precondition"
assert_contains "$(< "$preflight_stderr")" "automation mode requires --policy-dir" "automation policy error"
[ ! -e "$test_directory/preflight-output" ] || fail "preflight failure created an output directory"

status=0
run_scanner "$preflight_stdout" "$preflight_stderr" --root "$scan_root" --mode automation \
    --policy-dir "$policy_directory" --checks U-01 --output-dir "$test_directory/selection-output" || status=$?
assert_equal 2 "$status" "automation selection precondition"
assert_contains "$(< "$preflight_stderr")" "automation mode requires all checks" "automation selection error"

printf '%s\n' 'check_u_67() { set_result MANUAL "fixture runtime" "fixture=runtime" true runtime; }' > "$override_file"
runtime_output="$test_directory/runtime-output"
runtime_stdout="$test_directory/runtime.stdout"
runtime_stderr="$test_directory/runtime.stderr"
status=0
run_scanner "$runtime_stdout" "$runtime_stderr" --root "$scan_root" --mode automation \
    --policy-dir "$policy_directory" --evidence-bundle "$bundle" --output-dir "$runtime_output" || status=$?
assert_equal 2 "$status" "runtime-incomplete automation blocker"
assert_empty_output_directory "$runtime_output"
assert_contains "$(< "$runtime_stderr")" "automation mode did not publish reports" \
    "runtime-incomplete automation diagnostic"

printf '%s\n' 'check_u_67() { set_result MANUAL "fixture manual" "fixture=manual" true policy; }' > "$override_file"
blocked_output="$test_directory/manual-output"
blocked_stdout="$test_directory/manual.stdout"
blocked_stderr="$test_directory/manual.stderr"
status=0
run_scanner "$blocked_stdout" "$blocked_stderr" --root "$scan_root" --mode automation \
    --policy-dir "$policy_directory" --evidence-bundle "$bundle" --output-dir "$blocked_output" -v || status=$?
assert_equal 1 "$status" "unattested policy automation result"
blocked_json="$(sed -n 's/^\[[^]]*\] kisa-cce-scan: jsonl_report=//p' "$blocked_stdout")"
[ -f "$blocked_json" ] || fail "unattested policy automation JSONL report is absent"
blocked_record="$(grep -F '"code":"U-67"' "$blocked_json")"
assert_contains "$blocked_record" '"status":"VULNERABLE","technical_status":"VULNERABLE"' \
    "unattested policy automation status"
assert_contains "$blocked_record" '"decision_basis":"fail_closed_policy"' \
    "unattested policy automation decision basis"
assert_contains "$blocked_record" '"resolution_class":"policy","remediation_eligible":false' \
    "unattested policy automation eligibility"
if grep -Eq '"status":"(MANUAL|ERROR)"' "$blocked_json"; then
    fail "unattested policy automation retained a blocked status"
fi

audit_output="$test_directory/audit-output"
audit_stdout="$test_directory/audit.stdout"
audit_stderr="$test_directory/audit.stderr"
status=0
run_scanner "$audit_stdout" "$audit_stderr" --root "$scan_root" --mode audit \
    --evidence-bundle "$bundle" --output-dir "$audit_output" || status=$?
assert_equal 1 "$status" "manual review-ID audit scan"
audit_json="$(sed -n 's/^\[[^]]*\] kisa-cce-scan: jsonl_report=//p' "$audit_stdout")"
manual_review_id="$(awk -F '"' '/"code":"U-67"/ {
    for (field = 1; field <= NF; field++) if ($field == "review_id") {print $(field + 2); exit}
}' "$audit_json")"
case "$manual_review_id" in sha256:????????????????????????????????????????????????????????????????) ;; *)
    fail "audit did not produce a U-67 review ID" ;;
esac
{
    printf 'code\tdecision\treview_id\tticket\tapprover\texpires\n'
    printf 'U-67\tGOOD\t%s\tAUTO-67\tautomation-test\t2099-12-31\n' "$manual_review_id"
} > "$policy_directory/50-automation.tsv"
chmod 0600 "$policy_directory/50-automation.tsv"

resolved_output="$test_directory/resolved-output"
resolved_stdout="$test_directory/resolved.stdout"
resolved_stderr="$test_directory/resolved.stderr"
status=0
run_scanner "$resolved_stdout" "$resolved_stderr" --root "$scan_root" --mode automation \
    --policy-dir "$policy_directory" --evidence-bundle "$bundle" --output-dir "$resolved_output" || status=$?
assert_equal 1 "$status" "policy-resolved automation scan"
resolved_json="$(sed -n 's/^\[[^]]*\] kisa-cce-scan: jsonl_report=//p' "$resolved_stdout")"
resolved_record="$(grep -F '"code":"U-67"' "$resolved_json")"
assert_contains "$resolved_record" '"status":"GOOD","technical_status":"GOOD"' \
    "policy-resolved automation statuses"
assert_contains "$resolved_record" '"decision_basis":"policy_attestation"' \
    "policy-resolved automation provenance"
assert_contains "$resolved_record" "\"review_id\":\"$manual_review_id\"" \
    "policy-resolved automation review ID"

printf '%s\n' 'check_u_67() { set_result ERROR "fixture error" "fixture=error"; }' > "$override_file"
error_output="$test_directory/error-output"
status=0
run_scanner "$blocked_stdout" "$blocked_stderr" --root "$scan_root" --mode automation \
    --policy-dir "$policy_directory" --evidence-bundle "$bundle" --output-dir "$error_output" || status=$?
assert_equal 2 "$status" "error automation blocker"
assert_empty_output_directory "$error_output"

rm -f "$override_file"
success_output="$test_directory/success-output"
success_stdout="$test_directory/success.stdout"
success_stderr="$test_directory/success.stderr"
status=0
run_scanner "$success_stdout" "$success_stderr" --root "$scan_root" --mode automation \
    --policy-dir "$policy_directory" --evidence-bundle "$bundle" --output-dir "$success_output" || status=$?
assert_equal 1 "$status" "successful vulnerable automation scan: $(< "$success_stderr")"
markdown_report="$(sed -n 's/^\[[^]]*\] kisa-cce-scan: markdown_report=//p' "$success_stdout")"
jsonl_report="$(sed -n 's/^\[[^]]*\] kisa-cce-scan: jsonl_report=//p' "$success_stdout")"
[ -f "$markdown_report" ] || fail "successful automation Markdown report is absent"
[ -f "$jsonl_report" ] || fail "successful automation JSONL report is absent"
assert_contains "$(< "$markdown_report")" '| `scan_mode` | automation |' "automation report mode"
assert_equal 68 "$(wc -l < "$jsonl_report" | tr -d '[:space:]')" "automation JSONL line count"
if grep -Eq '"status":"(MANUAL|ERROR)"' "$jsonl_report"; then fail "automation retained a blocked status"; fi
awk '
    /^\{"code":"U-[0-9][0-9]"/ {
        count++
        if ($0 !~ /"status":"(GOOD|VULNERABLE|NOT_APPLICABLE)"/) exit 1
        if ($0 !~ /"technical_status":"(GOOD|VULNERABLE|NOT_APPLICABLE)"/) exit 1
    }
    END {exit(count == 67 ? 0 : 1)}
' "$jsonl_report" || fail "automation result status contract"
tail -n 1 "$jsonl_report" | grep -Fq '"manual":0,"not_applicable":1,"error":0' || \
    fail "automation summary retained unresolved results"
assert_equal 2 "$(find "$success_output" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d '[:space:]')" \
    "automation published file count"
if find "$success_output" -mindepth 1 -maxdepth 1 -name '.run.*' | grep -q .; then
    fail "automation scratch directory remained published"
fi
for terminal_file in \
    "$success_stdout" "$success_stderr" "$blocked_stdout" "$blocked_stderr" \
    "$runtime_stdout" "$runtime_stderr"; do
    if grep -Ev '^\[[[:space:]]*[0-9]+\.[0-9]{6}\] kisa-cce-scan: .*$' "$terminal_file" | grep -q .; then
        fail "automation terminal output is not dmesg framed: $terminal_file"
    fi
done

printf 'automation mode tests passed\n'
