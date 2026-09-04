#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck disable=SC2034

set -u
PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
LC_ALL=C
export LC_ALL
umask 077

[ "$(uname -s 2>/dev/null)" = Linux ] || { printf 'SKIP: full automatic CLI requires Linux\n'; exit 0; }
[ "${EUID:-$(id -u)}" -eq 0 ] || { printf 'SKIP: full automatic CLI requires root\n'; exit 0; }

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_equal() { [ "$1" = "$2" ] || fail "$3: expected=[$1] actual=[$2]"; }
assert_contains() { case "$1" in *"$2"*) ;; *) fail "$3: missing=[$2]" ;; esac; }

case "${BASH_SOURCE[0]}" in */*) test_parent="${BASH_SOURCE[0]%/*}" ;; *) test_parent=. ;; esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d /root/kisa-cce-full-automatic.XXXXXXXX)" || exit 2
trap 'chmod -R u+rwX "$test_directory" 2>/dev/null || :; rm -rf -- "$test_directory"' EXIT
chmod 0700 "$test_directory"

install_root="$test_directory/install"
mkdir -p "$install_root/bin" "$install_root/lib/kisa-cce-cli" "$install_root/lib/kisa-cce-patcher" "$install_root/data"
cp "$project_directory/bin/kisa-cce-patch" "$install_root/bin/kisa-cce-patch"
cp "$project_directory/lib/kisa-cce-cli/_patch-main.sh" "$install_root/lib/kisa-cce-cli/_patch-main.sh"
cp "$project_directory"/lib/kisa-cce-patcher/*.sh "$install_root/lib/kisa-cce-patcher/"
cp "$project_directory/data/VERSION" "$install_root/data/VERSION"
chmod 0755 "$install_root/bin/kisa-cce-patch"

scenario_file="$test_directory/scenario"
fake_scanner="$install_root/bin/kisa-cce-scan"
cat > "$fake_scanner" <<EOF
#!/bin/bash
set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
output=""
while [ "\$#" -gt 0 ]; do
    case "\$1" in
        --output-dir) output="\$2"; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "\$output" ] || exit 2
mkdir -m 0700 "\$output" || exit 2
scenario="\$(< '$scenario_file')"
phase=pre
case "\$output" in */post-scan) phase=post ;; esac
json="\$output/report.jsonl"
markdown="\$output/report.md"
: > "\$json"
good=0; vulnerable=0; manual=0; not_applicable=0; error=0; number=0
while [ "\$number" -lt 67 ]; do
    number=\$((number + 1)); printf -v code 'U-%02d' "\$number"
    status=GOOD; eligible=false; rule=""; resolution=technical
    case "\$scenario:\$phase:\$code" in
        fixed:pre:U-12) status=VULNERABLE; eligible=true; rule=configuration.u12.v1 ;;
        fixed:pre:U-16) status=VULNERABLE; eligible=true; rule=metadata.u16.v1 ;;
        postbad:*:U-12) status=VULNERABLE; eligible=true; rule=configuration.u12.v1 ;;
        postbad:pre:U-16) status=VULNERABLE; eligible=true; rule=metadata.u16.v1 ;;
        error:pre:U-10) status=ERROR ;;
        external:pre:U-64) status=MANUAL; resolution=external ;;
        gated:pre:U-01) status=MANUAL; resolution=runtime ;;
        pam-prerequisite:pre:U-02) status=MANUAL; resolution=policy ;;
    esac
    printf '{"code":"%s","category":"fixture","severity":"fixture","title":"fixture","status":"%s","technical_status":"%s","decision_basis":"technical","applicable":true,"review_id":"","attestation_ticket":"","attestation_approver":"","attestation_expires":"","resolution_class":"%s","remediation_eligible":%s,"remediation_rule_id":"%s","criterion_url":"https://example.invalid/%s","summary":"fixture","evidence":"fixture"}\n' \
        "\$code" "\$status" "\$status" "\$resolution" "\$eligible" "\$rule" "\$code" >> "\$json"
    case "\$status" in
        GOOD) good=\$((good + 1)) ;; VULNERABLE) vulnerable=\$((vulnerable + 1)) ;;
        MANUAL) manual=\$((manual + 1)) ;; NOT_APPLICABLE) not_applicable=\$((not_applicable + 1)) ;;
        ERROR) error=\$((error + 1)) ;;
    esac
done
printf '{"type":"summary","total":67,"good":%s,"vulnerable":%s,"manual":%s,"not_applicable":%s,"error":%s,"policy_resolved":0}\n' \
    "\$good" "\$vulnerable" "\$manual" "\$not_applicable" "\$error" >> "\$json"
printf '# fake scan\n' > "\$markdown"
chmod 0600 "\$json" "\$markdown"
printf '[     0.000001] kisa-cce-scan: scan_status=complete\n' >&2
printf '[     0.000002] kisa-cce-scan: markdown_report=%s\n' "\$markdown"
printf '[     0.000003] kisa-cce-scan: jsonl_report=%s\n' "\$json"
[ "\$vulnerable" -eq 0 ] && [ "\$manual" -eq 0 ] && [ "\$error" -eq 0 ]
EOF
chmod 0755 "$fake_scanner"

# shellcheck source=../lib/kisa-cce-patcher/_coverage.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_coverage.sh"

domain_input="$test_directory/domain-input.tsv"
printf '%s\n' 'schema	criterion	record_type	value_one	value_two	value_three	value_four	value_five	value_six	value_seven	approval' > "$domain_input"
package_repository="$test_directory/repository.evidence"
package_repository_signature="$test_directory/repository.signature"
package_advisory="$test_directory/advisory.evidence"
package_advisory_signature="$test_directory/advisory.signature"
signature_callback="$test_directory/signature-verifier"
snapshot_callback="$test_directory/snapshot-verifier"
simulator_callback="$test_directory/package-simulator"
printf '%s\n' repository > "$package_repository"
printf '%s\n' repository-signature > "$package_repository_signature"
printf '%s\n' advisory > "$package_advisory"
printf '%s\n' advisory-signature > "$package_advisory_signature"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$signature_callback"
printf '%s\n' '#!/bin/sh' 'cat >/dev/null' > "$snapshot_callback"
printf '%s\n' '#!/bin/sh' 'printf "%s\\n" "verified package simulation"' > "$simulator_callback"
chmod 0600 "$package_repository" "$package_repository_signature" "$package_advisory" "$package_advisory_signature"
chmod 0700 "$signature_callback" "$snapshot_callback" "$simulator_callback"
while IFS=$'\t' read -r code adapter risk resolution domain postcondition implementation input_type validator rollback; do
    [ "$implementation" = conditional ] || continue
    case "$code" in U-02|U-03|U-06|U-64) continue ;; esac
    printf '1\t%s\tplaceholder\t-\t-\t-\t-\t-\t-\t-\t-\n' "$code" >> "$domain_input"
done < <(patch_coverage_records | sed -n '2,$p')
printf '1\tU-02\tpassword-policy\tkisa-cce-2026\t-\t-\t-\t-\t-\t-\tPAM-02\n' >> "$domain_input"
printf '1\tU-03\tlockout-policy\tkisa-cce-2026\t-\t-\t-\t-\t-\t-\tPAM-03\n' >> "$domain_input"
printf '1\tU-06\tapproved-group\tsudo\t-\t-\t-\t-\t-\t-\tPAM-06\n' >> "$domain_input"
printf '1\tU-64\tpackage-evidence\tapt\t%s\t%s\t%s\t%s\tSNAPSHOT-1\tROLLBACK-1\tPACKAGE-APPROVAL\n' \
    "$package_repository" "$package_repository_signature" "$package_advisory" "$package_advisory_signature" >> "$domain_input"
printf '1\tU-64\tcallback\tsignature_verifier\t%s\t-\t-\t-\t-\t-\t-\n' "$signature_callback" >> "$domain_input"
printf '1\tU-64\tcallback\tsnapshot_verifier\t%s\t-\t-\t-\t-\t-\t-\n' "$snapshot_callback" >> "$domain_input"
printf '1\tU-64\tcallback\tpackage_simulator\t%s\t-\t-\t-\t-\t-\t-\n' "$simulator_callback" >> "$domain_input"
chmod 0600 "$domain_input"
writable_input_parent="$test_directory/writable-input-parent"
mkdir -m 0777 "$writable_input_parent"
cp "$domain_input" "$writable_input_parent/domain-input.tsv"
chmod 0600 "$writable_input_parent/domain-input.tsv"
unsafe_domain_input="$writable_input_parent/domain-input.tsv"

write_profile() {
    local path="$1" variant="$2"
    local header="" row="" code="" adapter="" risk="" resolution="" domain=""
    local postcondition="" implementation="" input_type="" validator="" rollback="" input_value=""

    {
        printf '%s\n' 'schema_version: 2' 'profile_id: full-automatic-test' 'max_risk: R4' 'desired_states:'
        IFS= read -r header
        while IFS= read -r row; do
            IFS=$'\t' read -r code adapter risk resolution domain postcondition implementation input_type validator rollback <<< "$row"
            [ "$variant:$code" != missing:U-33 ] || continue
            if [ "$implementation" = fixed ]; then
                input_value=-
            elif [ "$variant" = unsafe-input ]; then
                input_value="$unsafe_domain_input"
            elif [ "$variant:$code" = gated:U-01 ]; then
                input_value="$test_directory/missing-domain-input.tsv"
            else
                input_value="$domain_input"
            fi
            printf '  - code: %s\n    adapter: %s\n    postcondition: %s\n    input_type: %s\n    input_value: %s\n' \
                "$code" "$adapter" "$postcondition" "$input_type" "$input_value"
        done
    } < <(patch_coverage_records) > "$path"
    chmod 0600 "$path"
}

write_root() {
    local root="$1"
    mkdir -p "$root/etc/profile.d"
    chmod 0700 "$root"
    printf 'root:x:0:0:root:/root:/bin/bash\n' > "$root/etc/passwd"
    chmod 0666 "$root/etc/passwd"
}

run_full() {
    local name="$1" scenario="$2" profile="$3" root="$4"
    local output="$test_directory/$name-transaction"
    printf '%s\n' "$scenario" > "$scenario_file"
    RUN_STATUS=0
    "$install_root/bin/kisa-cce-patch" --automatic --desired-state "$profile" \
        --root "$root" --output-dir "$output" > "$test_directory/$name.stdout" \
        2> "$test_directory/$name.stderr" || RUN_STATUS=$?
    RUN_OUTPUT="$output"
}

load_full_transaction() {
    /bin/bash -c '
        set -u
        library_directory="$1"
        for library in \
            _configuration-transaction.sh _coverage.sh _metadata-rules.sh _engine.sh \
            _desired-state-policy.sh _account-transaction.sh _filesystem-transaction.sh \
            _inventory-transaction.sh _pam-transaction.sh _service-transaction.sh \
            _system-transaction.sh _network-service-transaction.sh _edge-service-transaction.sh \
            _orchestrator.sh _orchestrator-domains.sh; do
            . "$library_directory/$library"
        done
        patch_orchestrator_register_builtin_domains
        patch_orchestrator_load_transaction "$2" "$3"
    ' transaction-load "$install_root/lib/kisa-cce-patcher" "$1" "$2"
}

root="$test_directory/root"
write_root "$root"
full_profile="$test_directory/full.yml"
missing_profile="$test_directory/missing.yml"
gated_profile="$test_directory/gated.yml"
unsafe_input_profile="$test_directory/unsafe-input.yml"
write_profile "$full_profile" full
write_profile "$missing_profile" missing
write_profile "$gated_profile" gated
write_profile "$unsafe_input_profile" unsafe-input

run_full noop noop "$full_profile" "$root"
assert_equal 0 "$RUN_STATUS" "all-67 no-op status"
assert_equal verified "$(< "$RUN_OUTPUT/orchestrator/state")" "all-67 no-op state"
assert_contains "$(< "$test_directory/noop.stdout")" 'automatic_status=verified' "all-67 no-op output"

run_full fixed fixed "$full_profile" "$root"
[ "$RUN_STATUS" -eq 0 ] || {
    sed -n '1,200p' "$test_directory/fixed.stderr" >&2
    find "$RUN_OUTPUT" -maxdepth 9 -type f -print -exec sh -c 'echo "--- $1"; sed -n "1,20p" "$1"' _ {} \; >&2
}
assert_equal 0 "$RUN_STATUS" "fixed mixed apply status"
assert_equal 644 "$(stat -c %a "$root/etc/passwd")" "fixed metadata apply"
[ -f "$root/etc/profile.d/99-kisa-cce-session-timeout.sh" ] || fail "fixed configuration apply missing"
assert_equal verified "$(< "$RUN_OUTPUT/orchestrator/state")" "fixed mixed state"

fixed_transaction="$RUN_OUTPUT"
ROLLBACK_STATUS=0
"$install_root/bin/kisa-cce-patch" --rollback "$fixed_transaction" --root "$root" \
    > "$test_directory/rollback.stdout" 2> "$test_directory/rollback.stderr" || ROLLBACK_STATUS=$?
assert_equal 0 "$ROLLBACK_STATUS" "full transaction rollback"
assert_equal 666 "$(stat -c %a "$root/etc/passwd")" "full rollback metadata"
[ ! -e "$root/etc/profile.d/99-kisa-cce-session-timeout.sh" ] || fail "full rollback retained configuration"

run_full missing noop "$missing_profile" "$root"
assert_equal 2 "$RUN_STATUS" "missing profile status"
assert_contains "$(< "$test_directory/missing.stderr")" 'desired-state domain preflight failed' "missing profile diagnostic"

run_full gated gated "$gated_profile" "$root"
assert_equal 3 "$RUN_STATUS" "missing gated prerequisite status"
assert_contains "$(< "$test_directory/gated.stdout")" 'automatic_status=external_action_required' "gated prerequisite output"

run_full unsafe-input noop "$unsafe_input_profile" "$root"
assert_equal 3 "$RUN_STATUS" "replaceable domain-input parent status"
assert_contains "$(< "$test_directory/unsafe-input.stdout")" 'root_owned_0600_domain_input' \
    "replaceable domain-input parent diagnostic"
[ ! -e "$RUN_OUTPUT/pre-scan" ] || fail "unsafe domain input reached the scanner"

run_full error error "$full_profile" "$root"
assert_equal 2 "$RUN_STATUS" "scanner ERROR status"
assert_contains "$(< "$test_directory/error.stderr")" 'U-10 scanner result is ERROR' "scanner ERROR diagnostic"

run_full pam-prerequisite pam-prerequisite "$full_profile" "$root"
assert_equal 3 "$RUN_STATUS" "grouped PAM prerequisite status"
assert_equal external_action_required "$(< "$RUN_OUTPUT/orchestrator/state")" \
    "grouped PAM prerequisite state"
[ -f "$RUN_OUTPUT/orchestrator/domains/pam/plan.tsv" ] || fail "grouped PAM prerequisite plan is missing"

run_full external external "$full_profile" "$root"
assert_equal 3 "$RUN_STATUS" "U-64 external status"
assert_equal external_action_required "$(< "$RUN_OUTPUT/orchestrator/state")" "U-64 external state"
[ -x "$RUN_OUTPUT/orchestrator/domains/package/callbacks/signature_verifier" ] ||
    fail "U-64 signature callback snapshot is missing"
[ -x "$RUN_OUTPUT/orchestrator/domains/package/callbacks/snapshot_verifier" ] ||
    fail "U-64 snapshot callback snapshot is missing"
[ -x "$RUN_OUTPUT/orchestrator/domains/package/callbacks/package_simulator" ] ||
    fail "U-64 simulator callback snapshot is missing"
load_full_transaction "$root" "$RUN_OUTPUT" || fail "U-64 external transaction failed integrity reload"
simulation_path="$RUN_OUTPUT/orchestrator/domains/package/transactions/U-64/system/simulation.txt"
simulation_backup="$test_directory/simulation.backup"
cp "$simulation_path" "$simulation_backup"
printf '%s\n' tampered >> "$simulation_path"
status=0
load_full_transaction "$root" "$RUN_OUTPUT" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "U-64 simulation tamper rejection"
cp "$simulation_backup" "$simulation_path"
chmod 0600 "$simulation_path"
printf '%s\n' tampered >> "$RUN_OUTPUT/orchestrator/domains/package/callbacks/package_simulator"
status=0
load_full_transaction "$root" "$RUN_OUTPUT" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "callback snapshot tamper rejection"

run_full postbad postbad "$full_profile" "$root"
assert_equal 2 "$RUN_STATUS" "nonconforming post-scan status"
assert_equal rolled_back "$(< "$RUN_OUTPUT/orchestrator/state")" "post-scan rollback state"
assert_equal 666 "$(stat -c %a "$root/etc/passwd")" "post-scan rollback metadata"
[ ! -e "$root/etc/profile.d/99-kisa-cce-session-timeout.sh" ] || fail "post-scan rollback retained configuration"

printf 'PASS: full automatic patch CLI\n'
