#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

set -u
PATH="/usr/sbin:/usr/bin:/sbin:/bin"; export PATH
LC_ALL=C; export LC_ALL
umask 077

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_equal() { [ "$1" = "$2" ] || fail "$3: expected=[$1] actual=[$2]"; }
assert_contains() { case "$1" in *"$2"*) ;; *) fail "$3: missing=[$2]" ;; esac; }

case "${BASH_SOURCE[0]}" in */*) test_parent="${BASH_SOURCE[0]%/*}" ;; *) test_parent=. ;; esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-orchestrator.XXXXXXXX")" || exit 2
trap 'chmod -R u+rwX "$test_directory" 2>/dev/null || :; rm -rf -- "$test_directory"' EXIT

# shellcheck source=../lib/kisa-cce-patcher/_orchestrator.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_orchestrator.sh"

FAKE_EVENT_LOG="$test_directory/events.log"
FAKE_FAIL_DOMAIN=""

fake_domain_plan() {
    local root="$1" directory="$2" request="$3"
    local domain="${directory##*/}"
    [ -d "$root" ] && [ -f "$request" ] || return 2
    printf 'domain\trequest_sha256\n%s\t%s\n' "$domain" "$(sha256sum "$request" | awk '{print $1}')" > "$directory/plan.tsv"
    chmod 0600 "$directory/plan.tsv"
    printf 'plan:%s\n' "$domain" >> "$FAKE_EVENT_LOG"
    [ "$domain" != package ] || return 3
}

fake_domain_apply() {
    local root="$1" directory="$2"
    local domain="${directory##*/}"
    [ -d "$root" ] || return 2
    printf 'applied\n' > "$directory/domain-state"
    chmod 0600 "$directory/domain-state"
    printf 'apply:%s\n' "$domain" >> "$FAKE_EVENT_LOG"
    [ "$FAKE_FAIL_DOMAIN" != "$domain" ]
}

fake_domain_verify() {
    local root="$1" directory="$2"
    local domain="${directory##*/}"
    [ -d "$root" ] && [ "$(< "$directory/domain-state")" = applied ] || return 2
    printf 'verify:%s\n' "$domain" >> "$FAKE_EVENT_LOG"
}

fake_domain_rollback() {
    local root="$1" directory="$2" mode="$3"
    local domain="${directory##*/}"
    [ -d "$root" ] || return 2
    rm -f "$directory/domain-state"
    printf 'rollback:%s:%s\n' "$domain" "$mode" >> "$FAKE_EVENT_LOG"
}

for domain in "${PATCH_ORCHESTRATOR_DOMAIN_ORDER[@]}"; do
    patch_orchestrator_register_domain "$domain" fake_domain_plan fake_domain_apply \
        fake_domain_verify fake_domain_rollback || fail "domain registration failed: $domain"
done

write_profile() {
    local path="$1" header="" row="" code="" adapter="" risk="" resolution="" domain=""
    local postcondition="" implementation="" input_type="" validator="" rollback="" input_value=""
    {
        printf '%s\n' "$PATCH_ORCHESTRATOR_PROFILE_HEADER"
        IFS= read -r header
        [ "$header" = "$PATCH_COVERAGE_HEADER" ] || return 2
        while IFS= read -r row; do
            IFS=$'\t' read -r code adapter risk resolution domain postcondition implementation \
                input_type validator rollback <<< "$row"
            if [ "$implementation" = fixed ]; then input_value=-; else input_value="input-${code,,}"; fi
            printf 'full-profile\tR4\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$code" "$adapter" "$risk" "$resolution" "$domain" "$postcondition" \
                "$implementation" "$input_type" "$input_value" "$validator" "$rollback"
        done
    } < <(patch_coverage_records) > "$path"
    chmod 0600 "$path"
}

write_scan() {
    local path="$1" variant="$2" number=0 code="" status=GOOD resolution=technical eligible=false rule=""
    local good=0 vulnerable=0 manual=0 not_applicable=0 error=0
    : > "$path"
    while [ "$number" -lt 67 ]; do
        number=$((number + 1)); printf -v code 'U-%02d' "$number"
        status=GOOD; resolution=technical; eligible=false; rule=""
        case "$variant:$code" in
            mixed:U-02) status=MANUAL; resolution=policy ;;
            mixed:U-12) status=VULNERABLE; eligible=true; rule=configuration.u12.v1 ;;
            mixed:U-65) status=MANUAL; resolution=runtime ;;
            gated:U-01) status=VULNERABLE; resolution=runtime ;;
            error:U-10) status=ERROR ;;
            external:U-64) status=MANUAL; resolution=external ;;
            resolution-mismatch:U-06) status=MANUAL; resolution=external ;;
            eligible-resolution:U-12) status=VULNERABLE; resolution=policy; eligible=true; rule=configuration.u12.v1 ;;
            mismatch:U-12) status=VULNERABLE; eligible=true; rule=metadata.u12.v1 ;;
            postbad:U-12) status=VULNERABLE ;;
        esac
        printf '{"code":"%s","status":"%s","resolution_class":"%s","remediation_eligible":%s,"remediation_rule_id":"%s"}\n' \
            "$code" "$status" "$resolution" "$eligible" "$rule" >> "$path"
        case "$status" in
            GOOD) good=$((good + 1)) ;;
            VULNERABLE) vulnerable=$((vulnerable + 1)) ;;
            MANUAL) manual=$((manual + 1)) ;;
            NOT_APPLICABLE) not_applicable=$((not_applicable + 1)) ;;
            ERROR) error=$((error + 1)) ;;
        esac
    done
    printf '{"type":"summary","total":67,"good":%s,"vulnerable":%s,"manual":%s,"not_applicable":%s,"error":%s,"policy_resolved":0}\n' \
        "$good" "$vulnerable" "$manual" "$not_applicable" "$error" >> "$path"
    chmod 0600 "$path"
}

new_transaction() {
    local name="$1"
    local path="$test_directory/$name"
    mkdir -m 0700 "$path"
    printf '%s\n' "$path"
}

root="$test_directory/root"
mkdir -m 0700 "$root"
profile="$test_directory/profile.tsv"
write_profile "$profile"

good_scan="$test_directory/good.jsonl"
write_scan "$good_scan" good
noop_transaction="$(new_transaction noop)"
patch_orchestrator_plan "$profile" "$good_scan" "$root" "$noop_transaction" || fail "all-noop plan failed"
assert_equal planned "$PATCH_ORCHESTRATOR_STATE" "all-noop state"
assert_equal 0 "${#PATCH_ORCHESTRATOR_ACTIONABLE_DOMAINS[@]}" "all-noop domain count"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    status=0; patch_orchestrator_apply >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "non-root apply rejection"
    printf 'PASS: non-root orchestrator guards\n'
    exit 0
fi

patch_orchestrator_apply || fail "all-noop apply failed"
assert_equal awaiting_post_scan "$PATCH_ORCHESTRATOR_STATE" "all-noop awaits post-scan"
fresh_good="$test_directory/fresh-good.jsonl"
write_scan "$fresh_good" good
patch_orchestrator_accept_post_scan "$fresh_good" || fail "fresh all-good post-scan rejected"
assert_equal verified "$PATCH_ORCHESTRATOR_STATE" "all-noop verified state"

mixed_scan="$test_directory/mixed.jsonl"
write_scan "$mixed_scan" mixed
mixed_transaction="$(new_transaction mixed)"
: > "$FAKE_EVENT_LOG"
patch_orchestrator_plan "$profile" "$mixed_scan" "$root" "$mixed_transaction" || fail "mixed plan failed: $PATCH_ORCHESTRATOR_ERROR_DETAIL"
assert_equal 3 "${#PATCH_ORCHESTRATOR_ACTIONABLE_DOMAINS[@]}" "mixed domain count"
assert_equal 'plan:configuration plan:pam plan:system' "$(tr '\n' ' ' < "$FAKE_EVENT_LOG" | sed 's/ $//')" \
    "domain plan order"

FAKE_FAIL_DOMAIN=pam
status=0; patch_orchestrator_apply >/dev/null 2>&1 || status=$?
FAKE_FAIL_DOMAIN=""
assert_equal 2 "$status" "partial apply failure"
assert_equal rolled_back "$PATCH_ORCHESTRATOR_STATE" "partial apply rollback state"
events="$(tr '\n' ' ' < "$FAKE_EVENT_LOG")"
assert_contains "$events" 'apply:configuration apply:pam rollback:pam:transition rollback:configuration:transition' \
    "reverse transition rollback order"

for variant in error mismatch resolution-mismatch eligible-resolution; do
    scan="$test_directory/$variant.jsonl"; write_scan "$scan" "$variant"
    transaction="$(new_transaction "blocked-$variant")"
    status=0; patch_orchestrator_plan "$profile" "$scan" "$root" "$transaction" >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "$variant preflight status"
    [ ! -e "$transaction/orchestrator" ] || fail "$variant blocker created transaction data"
done

missing_summary_scan="$test_directory/missing-summary.jsonl"
sed '$d' "$good_scan" > "$missing_summary_scan"; chmod 0600 "$missing_summary_scan"
missing_summary_transaction="$(new_transaction missing-summary)"
status=0
patch_orchestrator_plan "$profile" "$missing_summary_scan" "$root" "$missing_summary_transaction" \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "missing scan summary rejection"
[ ! -e "$missing_summary_transaction/orchestrator" ] || fail "missing scan summary created transaction data"

gated_scan="$test_directory/gated.jsonl"; write_scan "$gated_scan" gated
gated_profile="$test_directory/gated-profile.tsv"
awk -F '\t' 'BEGIN {OFS="\t"} {$9=($3 == "U-01" ? "gated" : $9); print}' "$profile" > "$gated_profile"
chmod 0600 "$gated_profile"
gated_transaction="$(new_transaction blocked-gated)"
status=0; patch_orchestrator_plan "$gated_profile" "$gated_scan" "$root" "$gated_transaction" \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "gated profile preflight status"
[ ! -e "$gated_transaction/orchestrator" ] || fail "gated profile created transaction data"

external_scan="$test_directory/external.jsonl"; write_scan "$external_scan" external
external_transaction="$(new_transaction external)"
: > "$FAKE_EVENT_LOG"
status=0; patch_orchestrator_plan "$profile" "$external_scan" "$root" "$external_transaction" || status=$?
assert_equal 3 "$status" "U-64 external action status"
assert_equal external_action_required "$PATCH_ORCHESTRATOR_STATE" "U-64 external state"
assert_equal plan:package "$(< "$FAKE_EVENT_LOG")" "U-64 package simulation plan"
[ -f "$external_transaction/orchestrator/manifest.tsv" ] || fail "U-64 external manifest is missing"

post_transaction="$(new_transaction post-reject)"
patch_orchestrator_plan "$profile" "$mixed_scan" "$root" "$post_transaction" || fail "post-reject plan failed"
patch_orchestrator_apply || fail "post-reject apply failed"
post_bad="$test_directory/post-bad.jsonl"; write_scan "$post_bad" postbad
status=0; patch_orchestrator_accept_post_scan "$post_bad" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "vulnerable post-scan rejection"
assert_equal rolled_back "$PATCH_ORCHESTRATOR_STATE" "post-scan rejection rollback"

policy_summary_transaction="$(new_transaction policy-summary-reject)"
patch_orchestrator_plan "$profile" "$good_scan" "$root" "$policy_summary_transaction" ||
    fail "policy-summary plan failed"
patch_orchestrator_apply || fail "policy-summary apply failed"
policy_summary_bad="$test_directory/policy-summary-bad.jsonl"
sed 's/"policy_resolved":0/"policy_resolved":999/' "$fresh_good" > "$policy_summary_bad"
chmod 0600 "$policy_summary_bad"
status=0
patch_orchestrator_accept_post_scan "$policy_summary_bad" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "post-scan policy summary rejection"
assert_equal rolled_back "$PATCH_ORCHESTRATOR_STATE" "policy-summary rollback state"

cross_transaction="$(new_transaction cross-rollback)"
: > "$FAKE_EVENT_LOG"
patch_orchestrator_plan "$profile" "$mixed_scan" "$root" "$cross_transaction" || fail "cross rollback plan failed"
patch_orchestrator_apply || fail "cross rollback apply failed"
patch_orchestrator_rollback_transaction "$root" "$cross_transaction" strict ||
    fail "cross-process rollback failed: $PATCH_ORCHESTRATOR_ERROR_DETAIL"
assert_equal rolled_back "$PATCH_ORCHESTRATOR_STATE" "cross-process rollback state"
cross_events="$(tr '\n' ' ' < "$FAKE_EVENT_LOG")"
assert_contains "$cross_events" 'rollback:system:strict rollback:pam:strict rollback:configuration:strict' \
    "cross-process reverse rollback order"

tamper_transaction="$(new_transaction tamper)"
patch_orchestrator_plan "$profile" "$mixed_scan" "$root" "$tamper_transaction" || fail "tamper plan failed"
patch_orchestrator_apply || fail "tamper apply failed"
printf 'tampered\n' >> "$tamper_transaction/orchestrator/manifest.tsv"
events_before="$(wc -l < "$FAKE_EVENT_LOG")"
status=0; patch_orchestrator_rollback_transaction "$root" "$tamper_transaction" strict >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "cross-process manifest tamper rejection"
assert_equal "$events_before" "$(wc -l < "$FAKE_EVENT_LOG")" "tamper rejection avoids callbacks"

duplicate_scan="$test_directory/duplicate.jsonl"
/bin/cp "$good_scan" "$duplicate_scan"; sed -n '1p' "$good_scan" >> "$duplicate_scan"; chmod 0600 "$duplicate_scan"
duplicate_transaction="$(new_transaction duplicate)"
status=0; patch_orchestrator_plan "$profile" "$duplicate_scan" "$root" "$duplicate_transaction" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "duplicate scan rejection"
[ ! -e "$duplicate_transaction/orchestrator" ] || fail "duplicate scan created transaction data"

missing_profile="$test_directory/missing-profile.tsv"
awk -F '\t' '$3 != "U-33"' "$profile" > "$missing_profile"; chmod 0600 "$missing_profile"
missing_transaction="$(new_transaction missing-profile)"
status=0; patch_orchestrator_plan "$missing_profile" "$good_scan" "$root" "$missing_transaction" \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "missing profile criterion rejection"
[ ! -e "$missing_transaction/orchestrator" ] || fail "missing profile created transaction data"

printf 'PASS: patch orchestrator\n'
