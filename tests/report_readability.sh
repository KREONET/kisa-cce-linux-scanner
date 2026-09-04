#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

# shellcheck disable=SC2034

set -u

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_contains() {
    local file="$1"
    local expected="$2"
    local context="$3"

    grep -Fq -- "$expected" "$file" || fail "$context: missing '$expected'"
}

line_number() {
    local file="$1"
    local pattern="$2"
    local matched_line=""

    matched_line="$(grep -nF -m 1 -- "$pattern" "$file")" || return 1
    printf '%s\n' "${matched_line%%:*}"
}

test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-report-readability.XXXXXXXX")" || exit 2
trap 'rm -rf -- "$test_directory"' EXIT

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent=. ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2

mkdir -p -- "$test_directory/root"
KISA_CCE_VERSION='test'
SCAN_ROOT="$test_directory/root"
RUNTIME_MODE=off
OUTPUT_PARENT="$test_directory/output"
SELECTED_CHECKS=""
VERBOSE=0
DEBUG=0
SCAN_MODE=audit

# shellcheck source=../lib/core.sh
. "$project_directory/lib/core.sh"

PLATFORM_NAME='Test Linux <unsafe>'
PLATFORM_ID='test'
PLATFORM_ID_LIKE='debian'
PLATFORM_VERSION=1
PLATFORM_FAMILY='debian'
PLATFORM_BASE_ID='debian'
PLATFORM_BASE_VERSION=13

initialize_workspace
write_report_header || fail "report header failed"

set_result GOOD "good summary" $'good_key=value\n## injected\n<script>alert(1)</script>\n[host link](https://invalid.example)'
record_result U-01 account high "good title" || fail "GOOD result failed"
set_result VULNERABLE "vulnerable summary" "mode=0666"
record_result U-02 account high "vulnerable title" || fail "VULNERABLE result failed"
set_result MANUAL "manual summary" "runtime=unavailable"
record_result U-03 account medium "manual title" || fail "MANUAL result failed"
set_result ERROR "error summary" "read=failed"
record_result U-04 file high "error title" || fail "ERROR result failed"
set_result NOT_APPLICABLE "not applicable summary" "service=absent" false
record_result U-05 service low "not applicable title" || fail "NOT_APPLICABLE result failed"
write_report_summary || fail "report summary failed"
validate_reports || fail "redesigned reports failed validation"

assert_contains "$REPORT_TEXT" '| `scanner_version` | test |' "header metadata table"
assert_contains "$REPORT_TEXT" 'Test Linux \<unsafe\>' "header Markdown escaping"
assert_contains "$REPORT_TEXT" '| 오류 | 1 |' "overview error count"
assert_contains "$REPORT_TEXT" '### `ERROR` (1)' "ERROR priority group"
assert_contains "$REPORT_TEXT" '- [U-04: error title](#u-04) - `high`' "ERROR priority link"
assert_contains "$REPORT_TEXT" '- [U-02: vulnerable title](#u-02) - `high`' "VULNERABLE priority link"
assert_contains "$REPORT_TEXT" '- [U-03: manual title](#u-03) - `medium`' "MANUAL priority link"

overview_line="$(line_number "$REPORT_TEXT" "## $REPORT_LABEL_RESULT_SUMMARY")" || fail "overview heading is absent"
error_index_line="$(line_number "$REPORT_TEXT" '- [U-04: error title](#u-04)')" || fail "ERROR index link is absent"
vulnerable_index_line="$(line_number "$REPORT_TEXT" '- [U-02: vulnerable title](#u-02)')" || fail "VULNERABLE index link is absent"
manual_index_line="$(line_number "$REPORT_TEXT" '- [U-03: manual title](#u-03)')" || fail "MANUAL index link is absent"
first_result_line="$(line_number "$REPORT_TEXT" '## U-01: good title')" || fail "first result heading is absent"
[ "$overview_line" -lt "$error_index_line" ] || fail "overview does not precede the priority index"
[ "$error_index_line" -lt "$vulnerable_index_line" ] || fail "ERROR does not precede VULNERABLE"
[ "$vulnerable_index_line" -lt "$manual_index_line" ] || fail "VULNERABLE does not precede MANUAL"
[ "$manual_index_line" -lt "$first_result_line" ] || fail "priority index does not precede result details"

[ "$(grep -Ec '^- \[U-[0-9]{2}:' "$REPORT_TEXT")" -eq 3 ] ||
    fail "priority index contains a non-review result or omits a review result"
assert_contains "$REPORT_TEXT" '<a id="u-02"></a>' "stable criterion anchor"
assert_contains "$REPORT_TEXT" '> **최종 판정:** `VULNERABLE`' "status callout"
[ "$(grep -Fxc -- '> vulnerable summary' "$REPORT_TEXT")" -eq 1 ] ||
    fail "criterion summary is duplicated"
if grep -Fq -- '### 요약' "$REPORT_TEXT"; then
    fail "criterion retained the redundant summary section"
fi
assert_contains "$REPORT_TEXT" '<details>' "collapsible evidence container"
assert_contains "$REPORT_TEXT" '<summary>근거</summary>' "evidence disclosure label"
assert_contains "$REPORT_TEXT" '<pre><code>good_key=value' "inert evidence code container"
assert_contains "$REPORT_TEXT" '&lt;script&gt;alert(1)&lt;/script&gt;' "HTML evidence escaping"
if grep -Fq -- '<script>alert(1)</script>' "$REPORT_TEXT"; then
    fail "assessed HTML remained active in the Markdown report"
fi

first_json_line="$(sed -n '1p' "$REPORT_JSONL")"
case "$first_json_line" in
    '{"code":"U-01","category":"account","severity":"high","title":"good title","status":"GOOD","technical_status":"GOOD","decision_basis":"technical","review_id":"","attestation_ticket":"","attestation_approver":"","attestation_expires":"","applicable":true,"summary":"good summary","evidence":'*'"criterion_url":"https://kreonet.github.io/kisa-cce-guide-web/unix/u-01/"}') ;;
    *) fail "JSONL result schema or field order changed" ;;
esac
[ "$(wc -l < "$REPORT_JSONL" | tr -d '[:space:]')" -eq 6 ] || fail "JSONL line count changed"
assert_contains "$REPORT_JSONL" '{"type":"summary","total":5,"good":1,"vulnerable":1,"manual":1,"not_applicable":1,"error":1,"policy_resolved":0}' \
    "JSONL summary schema"

cleanup_workspace
printf 'PASS: Markdown report readability regressions\n'
