#!/bin/bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

set -u

test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-typed-policy.XXXXXXXX")" || exit 2
trap 'chmod -R u+rwX "$test_directory" 2>/dev/null || :; rm -rf "$test_directory"' EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_equal() {
    local expected="$1"
    local actual="$2"
    local context="$3"

    [ "$expected" = "$actual" ] || fail "$context: expected '$expected', got '$actual'"
}

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent=. ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2

# shellcheck source=../lib/kisa-cce-policy/_policy.sh disable=SC1091
. "$project_directory/lib/kisa-cce-policy/_policy.sh"

write_attestation() {
    local directory="$1"

    {
        printf 'code\tdecision\treview_id\tticket\tapprover\texpires\n'
        printf 'U-65\tGOOD\tsha256:%064d\tTIME-REVIEW\tsecurity-governance\t2099-12-31\n' 0
    } > "$directory/50-review.tsv"
    chmod 0600 "$directory/50-review.tsv"
}

write_time_sources() {
    local directory="$1"
    shift

    mkdir -p "$directory/facts"
    chmod 0700 "$directory/facts"
    {
        printf 'provider\thost\taddress\tticket\tapprover\texpires\n'
        [ "$#" -eq 0 ] || printf '%s\n' "$@"
    } > "$directory/facts/time-sources.tsv"
    chmod 0600 "$directory/facts/time-sources.tsv"
}

status=0
empty_policy="$test_directory/empty"
mkdir -p "$empty_policy"
chmod 0700 "$empty_policy"
policy_load_dir "$empty_policy" || fail "empty legacy policy directory was rejected"
policy_time_source_match chrony time.example - || status=$?
assert_equal 3 "$status" "absent fact-set status"
assert_equal absent "$POLICY_TIME_SOURCE_MATCH_STATE" "absent fact-set state"
assert_equal facts_absent "$POLICY_TIME_SOURCE_MATCH_REASON" "absent fact-set reason"
baseline_digest="$POLICY_SET_DIGEST"

policy_directory="$test_directory/valid"
mkdir -p "$policy_directory"
chmod 0700 "$policy_directory"
write_attestation "$policy_directory"
policy_load_dir "$policy_directory" || fail "legacy attestation was rejected without typed facts"
attestation_only_digest="$POLICY_SET_DIGEST"
status=0
policy_lookup U-65 "sha256:$(printf '%064d' 0)" >/dev/null || status=$?
assert_equal 0 "$status" "legacy attestation lookup"
assert_equal GOOD "$POLICY_MATCH_DECISION" "legacy attestation decision"

write_time_sources "$policy_directory"
policy_load_dir "$policy_directory" || fail "explicit empty time-source fact set was rejected"
assert_equal 1 "$POLICY_TIME_SOURCE_FACTS_PRESENT" "empty fact-set presence"
assert_equal 0 "$POLICY_TIME_SOURCE_COUNT" "empty fact-set count"
[ "$POLICY_SET_DIGEST" != "$attestation_only_digest" ] || fail "empty fact set did not affect the policy digest"
status=0
policy_time_source_match chrony time.example - || status=$?
assert_equal 1 "$status" "explicit empty fact-set status"
assert_equal not_approved "$POLICY_TIME_SOURCE_MATCH_STATE" "explicit empty fact-set state"

write_time_sources "$policy_directory" \
    $'chrony\tTime.Example.\t-\tTIME-001\ttime-owners\t2099-12-31' \
    $'systemd-timesyncd\t-\t192.000.002.010\tTIME-002\ttime-owners\t2099-12-31' \
    $'ntpsec\tpaired.example\t2001:DB8::123\tTIME-003\ttime-owners\t2099-12-31'
policy_load_dir "$policy_directory" || fail "valid typed time-source policy was rejected"
assert_equal 1 "$POLICY_TIME_SOURCE_FACTS_PRESENT" "typed fact-set presence"
assert_equal 3 "$POLICY_TIME_SOURCE_COUNT" "typed fact count"
[ "$POLICY_SET_DIGEST" != "$attestation_only_digest" ] || fail "typed facts did not affect the policy digest"

status=0
policy_time_source_match chrony time.example - || status=$?
assert_equal 0 "$status" "hostname approval status"
assert_equal approved "$POLICY_TIME_SOURCE_MATCH_STATE" "hostname approval state"
assert_equal TIME-001 "$POLICY_TIME_SOURCE_MATCH_TICKET" "hostname approval ticket"
assert_equal time.example "$POLICY_TIME_SOURCE_MATCH_HOST" "hostname normalization"
case "$POLICY_TIME_SOURCE_MATCH_EVIDENCE" in
    time_source_policy=approved,provider=chrony,host=time.example,address=-,expires=2099-12-31) ;;
    *) fail "approved evidence is not bounded and normalized" ;;
esac
[ "${#POLICY_TIME_SOURCE_MATCH_EVIDENCE}" -le 512 ] || fail "approved evidence exceeded 512 characters"

status=0
policy_time_source_match systemd-timesyncd '' 192.0.2.10 || status=$?
assert_equal 0 "$status" "address approval status"
assert_equal 192.0.2.10 "$POLICY_TIME_SOURCE_MATCH_ADDRESS" "address normalization"

status=0
policy_time_source_match ntpsec PAIRED.EXAMPLE. 2001:db8::123 || status=$?
assert_equal 0 "$status" "bound hostname and address approval"
status=0
policy_time_source_match ntpsec paired.example 2001:db8::124 || status=$?
assert_equal 1 "$status" "bound hostname rejects another address"
assert_equal not_approved "$POLICY_TIME_SOURCE_MATCH_STATE" "not-approved state"
assert_equal no_match "$POLICY_TIME_SOURCE_MATCH_REASON" "not-approved reason"
assert_equal '' "$POLICY_TIME_SOURCE_MATCH_TICKET" "not-approved metadata reset"

status=0
policy_time_source_match unknown time.example - || status=$?
assert_equal 2 "$status" "invalid provider status"
assert_equal error "$POLICY_TIME_SOURCE_MATCH_STATE" "invalid provider state"
assert_equal invalid_query "$POLICY_TIME_SOURCE_MATCH_REASON" "invalid provider reason"

write_time_sources "$policy_directory" \
    $'ntpsec\tz.example\t-\tTIME-Z\ttime-owners\t2099-12-31' \
    $'chrony\ta.example\t-\tTIME-A\ttime-owners\t2099-12-31'
policy_load_dir "$policy_directory" || fail "first digest-order policy was rejected"
ordered_digest="$POLICY_SET_DIGEST"
write_time_sources "$policy_directory" \
    $'chrony\ta.example\t-\tTIME-A\ttime-owners\t2099-12-31' \
    $'ntpsec\tz.example\t-\tTIME-Z\ttime-owners\t2099-12-31'
policy_load_dir "$policy_directory" || fail "second digest-order policy was rejected"
assert_equal "$ordered_digest" "$POLICY_SET_DIGEST" "typed fact digest ordering"

write_time_sources "$policy_directory" \
    $'chrony\thost-only.example\t-\tTIME-H\ttime-owners\t2099-12-31' \
    $'chrony\t-\t192.0.2.30\tTIME-A\ttime-owners\t2099-12-31'
policy_load_dir "$policy_directory" || fail "overlapping typed facts were rejected at load"
status=0
policy_time_source_match chrony host-only.example 192.0.2.30 || status=$?
assert_equal 2 "$status" "ambiguous match status"
assert_equal ambiguous_match "$POLICY_TIME_SOURCE_MATCH_REASON" "ambiguous match reason"

write_time_sources "$policy_directory" \
    $'chrony\texpired.example\t-\tTIME-OLD\ttime-owners\t2000-01-01'
policy_load_dir "$policy_directory" || fail "syntactically valid expired fact was rejected at load"
status=0
policy_time_source_match chrony expired.example - || status=$?
assert_equal 2 "$status" "expired approval status"
assert_equal expired "$POLICY_TIME_SOURCE_MATCH_REASON" "expired approval reason"
assert_equal TIME-OLD "$POLICY_TIME_SOURCE_MATCH_TICKET" "expired approval metadata"

write_time_sources "$policy_directory" \
    $'chrony\tDUPLICATE.EXAMPLE.\t-\tTIME-1\ttime-owners\t2099-12-31' \
    $'chrony\tduplicate.example\t-\tTIME-2\ttime-owners\t2099-12-31'
status=0
policy_load_dir "$policy_directory" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "canonical duplicate rejection"
assert_equal 0 "$POLICY_TIME_SOURCE_COUNT" "failed load clears typed facts"
assert_equal '' "$POLICY_SET_DIGEST" "failed load clears policy digest"

write_time_sources "$policy_directory" \
    $'chrony\t-\t-\tTIME-EMPTY\ttime-owners\t2099-12-31'
status=0
policy_load_dir "$policy_directory" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "empty source identity rejection"

write_time_sources "$policy_directory" \
    $'chrony\tinvalid_host.example\t-\tTIME-BAD\ttime-owners\t2099-12-31'
status=0
policy_load_dir "$policy_directory" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "invalid hostname rejection"

write_time_sources "$policy_directory" \
    $'chrony\ttime.example\t999.0.2.1\tTIME-BAD\ttime-owners\t2099-12-31'
status=0
policy_load_dir "$policy_directory" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "invalid address rejection"

write_time_sources "$policy_directory" \
    $'chrony\ttime.example\t2001:db8::1::2\tTIME-BAD\ttime-owners\t2099-12-31'
status=0
policy_load_dir "$policy_directory" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "multiply compressed IPv6 rejection"

write_time_sources "$policy_directory" \
    $'chrony\ttime.example\t-\tTIME-OK\ttime-owners\t2099-12-31'
printf 'unexpected\n' > "$policy_directory/facts/other.tsv"
chmod 0600 "$policy_directory/facts/other.tsv"
status=0
policy_load_dir "$policy_directory" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "unknown fact type rejection"
rm "$policy_directory/facts/other.tsv"

real_fact_file="$test_directory/real-time-sources.tsv"
mv "$policy_directory/facts/time-sources.tsv" "$real_fact_file"
ln -s "$real_fact_file" "$policy_directory/facts/time-sources.tsv"
status=0
policy_load_dir "$policy_directory" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "time-source file symlink rejection"
rm "$policy_directory/facts/time-sources.tsv"
mv "$real_fact_file" "$policy_directory/facts/time-sources.tsv"

real_facts="$test_directory/real-facts"
mv "$policy_directory/facts" "$real_facts"
ln -s "$real_facts" "$policy_directory/facts"
status=0
policy_load_dir "$policy_directory" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "facts directory symlink rejection"
rm "$policy_directory/facts"
mv "$real_facts" "$policy_directory/facts"

policy_load_dir "$policy_directory" || fail "policy did not recover after rejected inputs"
[ "$POLICY_SET_DIGEST" != "$baseline_digest" ] || fail "attestation and facts were omitted from the digest"

printf 'PASS: typed policy time-source facts\n'
