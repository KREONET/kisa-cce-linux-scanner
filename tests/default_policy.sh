#!/bin/bash

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

file_mode() {
    stat -Lc '%a' -- "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null
}

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent=. ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-default-policy.XXXXXXXX")" || exit 2
stage_directory="$test_directory/stage"
scan_root="$test_directory/root"
stderr_file="$test_directory/scanner.stderr"
stdout_file="$test_directory/scanner.stdout"
trap 'chmod -R u+rwX "$test_directory" 2>/dev/null || :; rm -rf -- "$test_directory"' EXIT

# shellcheck source=../lib/kisa-cce-policy/_policy.sh disable=SC1091
. "$project_directory/lib/kisa-cce-policy/_policy.sh"

source_policy="$project_directory/etc/kisa-cce-scanner/policy.d"
policy_load_dir "$source_policy" || fail "repository default policy was rejected"
assert_equal 0 "${#POLICY_DECISION[@]}" "default attestation count"
assert_equal 0 "$POLICY_TIME_SOURCE_FACTS_PRESENT" "default time-source fact-set absence"
assert_equal 0 "$POLICY_TIME_SOURCE_COUNT" "default approved time-source count"
status=0
policy_time_source_match chrony time.example - >/dev/null || status=$?
assert_equal 3 "$status" "default time-source fact-set absence"

make -s -C "$project_directory" install DESTDIR="$stage_directory" prefix=/usr sysconfdir=/etc
installed_policy="$stage_directory/etc/kisa-cce-scanner/policy.d"
cmp "$source_policy/00-default.tsv" "$installed_policy/00-default.tsv" >/dev/null ||
    fail "installed default attestation file differs"
assert_equal 700 "$(file_mode "$installed_policy")" "installed policy directory mode"
assert_equal 600 "$(file_mode "$installed_policy/00-default.tsv")" "installed attestation mode"
[ ! -e "$installed_policy/facts/time-sources.tsv" ] ||
    fail "installation created a non-neutral empty time-source allowlist"

printf '%s\n' preserved-local-policy > "$installed_policy/00-default.tsv"
make -s -C "$project_directory" install DESTDIR="$stage_directory" prefix=/usr sysconfdir=/etc
assert_equal preserved-local-policy "$(< "$installed_policy/00-default.tsv")" \
    "make install preserves an existing local policy file"

mkdir -p "$scan_root/etc"
printf '%s\n' 'ID=ubuntu' 'VERSION_ID="26.04"' 'PRETTY_NAME="Ubuntu 26.04 LTS"' > "$scan_root/etc/os-release"
status=0
"$project_directory/bin/kisa-cce-scan" --root "$scan_root" --mode automation \
    --output-dir "$test_directory/output" > "$stdout_file" 2> "$stderr_file" || status=$?
assert_equal 2 "$status" "source-tree default policy preflight"
grep -Fq 'automation mode requires --policy-dir' "$stderr_file" ||
    fail "source-tree automation unexpectedly selected an untrusted repository policy"

status=0
"$project_directory/bin/kisa-cce-scan" --root "$scan_root" --mode automation \
    --policy-dir "$source_policy" --output-dir "$test_directory/explicit-output" \
    > "$stdout_file" 2> "$stderr_file" || status=$?
assert_equal 2 "$status" "explicit source policy preflight"
grep -Fq 'offline automation scan requires --evidence-bundle' "$stderr_file" ||
    fail "explicit source policy was not accepted"

printf 'PASS: default policy directory\n'
