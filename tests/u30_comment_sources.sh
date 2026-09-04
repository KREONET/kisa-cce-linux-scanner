#!/bin/bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

# Verifies that U-30 ignores commented source directives without hiding active ones.

# shellcheck disable=SC1091,SC2034

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

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent=. ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-u30-comments.XXXXXXXX")" || exit 2
root_directory="$test_directory/root"
scratch_directory="$test_directory/scratch"
trap 'rm -rf -- "$test_directory"' EXIT

mkdir -p -- "$root_directory/etc/profile.d" "$scratch_directory"
KISA_CCE_VERSION="test"
SCAN_ROOT="$root_directory"
RUNTIME_MODE=off

# shellcheck source=../lib/kisa-cce-core/_core.sh
. "$project_directory/lib/kisa-cce-core/_core.sh"
# shellcheck source=../lib/kisa-cce-resolvers/_resolvers.sh
. "$project_directory/lib/kisa-cce-resolvers/_resolvers.sh"
# shellcheck source=../lib/kisa-cce-checks/_account-file.sh
. "$project_directory/lib/kisa-cce-checks/_account-file.sh"
SCRATCH_DIR="$scratch_directory"

assert_source_token() {
    local expected_status="$1"
    local expected_token="$2"
    local input_line="$3"
    local actual_token=""
    local actual_status=0

    actual_token="$(scanner_u30_shell_source_token "$input_line")" || actual_status=$?
    [ "$actual_status" -eq "$expected_status" ] ||
        fail "source token status for [$input_line]: expected=$expected_status actual=$actual_status"
    [ "$actual_token" = "$expected_token" ] ||
        fail "source token for [$input_line]: expected=[$expected_token] actual=[$actual_token]"
}

assert_source_token 0 /etc/direct-source 'source /etc/direct-source'
assert_source_token 0 /etc/dot-source '. /etc/dot-source;'
assert_source_token 0 /etc/builtin-source 'builtin source /etc/builtin-source # comment'
assert_source_token 3 '' 'if true; then source /etc/conditional-source; fi'
assert_source_token 3 '' 'command . /etc/indirect-source'
assert_source_token 1 '' '# source /etc/commented-source'
assert_source_token 1 '' 'printf "%s" source'

cat > "$root_directory/etc/profile" <<'EOF'
umask 027
# . /etc/commented-dot
    # source /etc/commented-source
# for iterator in /etc/profile.d/*.sh; do
#     . "$iterator"
# done
: # source /etc/commented-inline
EOF

records="$(scanner_u30_shell_file_records /etc/profile global:test)" ||
    fail "comment-only profile could not be parsed"
case "$records" in
    *unknown*|*commented*) fail "commented source directive produced conditional evidence: $records" ;;
esac
case "$records" in
    *$'027\t/etc/profile:1\tresolved\tglobal:test\toctal'*) ;;
    *) fail "resolved UMASK record was not preserved: $records" ;;
esac

printf '%s\n' 'umask 002' > "$root_directory/etc/active-source"
cat > "$root_directory/etc/profile" <<'EOF'
umask 027
if [ -r /etc/active-source ]; then
    . /etc/active-source
fi
EOF
records="$(scanner_u30_shell_file_records /etc/profile global:test)" ||
    fail "active conditional source could not be parsed"
case "$records" in
    *$'002\t/etc/active-source:1\tconditional\tglobal:test\toctal'*) ;;
    *) fail "active conditional source was not retained: $records" ;;
esac

cat > "$root_directory/etc/profile" <<'EOF'
umask 027
if true; then
    source /etc/missing-source
fi
EOF
records="$(scanner_u30_shell_file_records /etc/profile global:test)" ||
    fail "missing active conditional source could not be represented"
case "$records" in
    *$'unknown\t/etc/profile:3\tconditional\tglobal:test\toctal'*) ;;
    *) fail "active unresolved source was incorrectly ignored: $records" ;;
esac

scanner_umask_records() {
    printf '%s\n' \
        $'027\t/etc/profile:1\tresolved\tglobal:test\toctal' \
        $'027\t/etc/profile:1\tresolved\tglobal:test\toctal'
}
scanner_u30_pam_records() { return 1; }
scanner_capture_optional_value() { printf -v "$1" '%s' ""; return 0; }
scanner_u30_ftp_records() { return 0; }
check_u_30
[ "$RESULT_STATUS" = GOOD ] || fail "deduplicated U-30 result was not GOOD: $RESULT_STATUS"
case "$RESULT_EVIDENCE" in
    *'global_records=1'*) ;;
    *) fail "duplicate U-30 records were counted more than once: $RESULT_EVIDENCE" ;;
esac
record_occurrences="$(printf '%s\n' "$RESULT_EVIDENCE" | grep -Fc 'umask=027,source=/etc/profile:1,scope=global:test,certainty=resolved')"
[ "$record_occurrences" -eq 1 ] || fail "duplicate U-30 evidence was not removed"

printf 'PASS: U-30 commented source directives\n'
