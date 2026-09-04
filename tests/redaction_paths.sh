#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

set -u

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

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent=. ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2

export KISA_CCE_VERSION="test"
# shellcheck source=../lib/kisa-cce-core/_core.sh disable=SC1091
. "$project_directory/lib/kisa-cce-core/_core.sh"

assert_redaction() {
    local expected="$1"
    local input_value="$2"
    local context="$3"
    local output_value=""

    redact_evidence_into "$input_value" output_value || fail "$context: redactor failed"
    assert_equal "$expected" "$output_value" "$context"
}

path_evidence=$'/usr/bin/passwd:mode=4755\n/usr/bin/gpasswd:mode=4755\npath=/etc/passwd:database_status=invalid'
assert_redaction "$path_evidence" "$path_evidence" "passwd path evidence"
if evidence_requires_redaction "$path_evidence"; then
    fail "passwd paths unnecessarily selected the evidence redactor"
fi

mixed_evidence=$'/usr/bin/passwd:mode=4755 password=plainSecret\n/usr/bin/gpasswd:mode=4755,api_token="quoted secret" suffix=safe'
mixed_expected=$'/usr/bin/passwd:mode=4755 password=[REDACTED]\n/usr/bin/gpasswd:mode=4755,api_token=[REDACTED] suffix=safe'
assert_redaction "$mixed_expected" "$mixed_evidence" "mixed path and credential evidence"

credential_evidence=$'password=plainSecret\nPASSWD:anotherSecret\ndatabase_password="quoted secret" suffix=safe\napi-token=\'single quoted secret\' suffix=safe\nmysecret=embeddedPrefix\npassphrase="unterminated secret\ncontrol=retained'
credential_expected=$'password=[REDACTED]\nPASSWD:[REDACTED]\ndatabase_password=[REDACTED] suffix=safe\napi-token=[REDACTED] suffix=safe\nmysecret=[REDACTED]\npassphrase=[REDACTED]\ncontrol=retained'
assert_redaction "$credential_expected" "$credential_evidence" "credential key redaction"

delimited_evidence='context=(password=parenthesizedSecret)'
delimited_expected='context=(password=[REDACTED]'
assert_redaction "$delimited_expected" "$delimited_evidence" "punctuation-delimited credential keys"

boundary_evidence=$'binary=/opt/token-helper\nsource=/var/lib/secret/store\naccount=passwd:service\npolicy=password-required'
assert_redaction "$boundary_evidence" "$boundary_evidence" "noncredential boundary evidence"

metric_evidence='pam_unix_password_modules=2 empty_password_fields=0 password_history_module_present=1 secret_values=redacted'
assert_redaction "$metric_evidence" "$metric_evidence" "password metric evidence"

snmp_evidence='rocommunity hostileCommunity 192.0.2.0/24'
assert_redaction 'rocommunity [REDACTED] 192.0.2.0/24' "$snmp_evidence" "SNMP directive redaction"

printf 'redaction path tests passed\n'
