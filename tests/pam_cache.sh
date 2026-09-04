#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck disable=SC1091,SC2034

# Verifies run-scoped PAM parsing and expansion cache semantics.

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
LC_ALL=C
export LC_ALL
umask 077

case "${BASH_SOURCE[0]}" in
    */*) source_parent="${BASH_SOURCE[0]%/*}" ;;
    *) source_parent="." ;;
esac
TEST_DIRECTORY="$(CDPATH='' cd -P -- "$source_parent" && pwd)" || exit 2
PROJECT_DIRECTORY="$(CDPATH='' cd -P -- "$TEST_DIRECTORY/.." && pwd)" || exit 2
TEST_TEMPORARY_DIRECTORY="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-pam-cache.XXXXXXXX")" || exit 2
ROOT_DIRECTORY="$TEST_TEMPORARY_DIRECTORY/root"
SCRATCH_DIR="$TEST_TEMPORARY_DIRECTORY/scratch"
CAPTURE_FILE="$TEST_TEMPORARY_DIRECTORY/capture"
DEBUG_FILE="$TEST_TEMPORARY_DIRECTORY/debug-events"
DEBUG_FD=""

cleanup() {
    rm -rf -- "$TEST_TEMPORARY_DIRECTORY"
}
trap cleanup EXIT

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

assert_contains_file() {
    local file="$1"
    local expected="$2"
    local context="$3"

    grep -Fq -- "$expected" "$file" || fail "$context: missing=[$expected]"
}

advance_epoch() {
    SCAN_EPOCH_ID=$((SCAN_EPOCH_ID + 1))
    pam_reset_epoch_cache
}

capture_expansion() {
    local service="$1"
    local facility="$2"
    local destination="$3"
    local status=0

    pam_expand_service "$service" "$facility" > "$destination" || status=$?
    return "$status"
}

mkdir -p -- "$ROOT_DIRECTORY/etc/pam.d" "$SCRATCH_DIR"
KISA_CCE_VERSION="test"

# shellcheck source=../lib/kisa-cce-core/_core.sh
. "$PROJECT_DIRECTORY/lib/kisa-cce-core/_core.sh"
# shellcheck source=../lib/kisa-cce-resolvers/_resolvers.sh
. "$PROJECT_DIRECTORY/lib/kisa-cce-resolvers/_resolvers.sh"

DEBUG=1
exec {DEBUG_FD}> "$DEBUG_FILE" || fail "debug capture descriptor could not be opened"
DEBUG_OUTPUT_FD="$DEBUG_FD"

SCAN_ROOT="$ROOT_DIRECTORY"
SCRATCH_DIR="$TEST_TEMPORARY_DIRECTORY/scratch"
RUNTIME_MODE="off"
SCAN_EPOCH_ACTIVE=1
SCAN_EPOCH_ID=1
PLATFORM_FAMILY="debian"
PLATFORM_BASE_ID="debian"
PLATFORM_BASE_VERSION="13"

cat > "$ROOT_DIRECTORY/etc/pam.d/shared" <<'EOF'
auth required pam_unix.so
account required pam_unix.so
EOF
cat > "$ROOT_DIRECTORY/etc/pam.d/base" <<'EOF'
auth include shared
account substack shared
EOF

capture_expansion base auth "$CAPTURE_FILE" || fail "auth expansion failed"
assert_contains_file "$CAPTURE_FILE" "auth required pam_unix.so" "auth include output"
assert_equal 2 "$PAM_FILE_PARSE_COUNT" "initial unique file parse count"
capture_expansion base account "$CAPTURE_FILE" || fail "account expansion failed"
assert_contains_file "$CAPTURE_FILE" "account required pam_unix.so" "account substack output"
assert_equal 2 "$PAM_FILE_PARSE_COUNT" "cross-facility file parse count"
capture_expansion base auth "$CAPTURE_FILE" || fail "cached auth expansion failed"
assert_equal 2 "$PAM_EXPANSION_BUILD_COUNT" "effective expansion memoization"

base_file="$(pam_service_file base)" || fail "base service path resolution failed"
pam_pair_key_into pamd "$base_file" base_file_key || fail "base file cache key failed"
base_intermediate="${PAM_FILE_INTERMEDIATE_PATH[$base_file_key]}"
tr '\000' '\n' < "$base_intermediate" > "$TEST_TEMPORARY_DIRECTORY/base-intermediate.txt"
assert_contains_file "$TEST_TEMPORARY_DIRECTORY/base-intermediate.txt" include "typed include record"
assert_contains_file "$TEST_TEMPORARY_DIRECTORY/base-intermediate.txt" substack "typed substack record"

advance_epoch
: > "$ROOT_DIRECTORY/etc/pam.d/empty"
status=0
capture_expansion empty auth "$CAPTURE_FILE" || status=$?
assert_equal 1 "$status" "empty service without other"
build_count="$PAM_EXPANSION_BUILD_COUNT"
status=0
capture_expansion empty auth "$CAPTURE_FILE" || status=$?
assert_equal 1 "$status" "cached absent expansion"
assert_equal "$build_count" "$PAM_EXPANSION_BUILD_COUNT" "absent expansion memoization"

: > "$ROOT_DIRECTORY/etc/pam.d/other"
advance_epoch
capture_expansion empty auth "$CAPTURE_FILE" || fail "empty other fallback failed"
[ ! -s "$CAPTURE_FILE" ] || fail "empty other fallback produced output"

printf '%s\n' 'auth include' > "$ROOT_DIRECTORY/etc/pam.d/malformed"
advance_epoch
status=0
capture_expansion malformed auth "$CAPTURE_FILE" || status=$?
assert_equal 2 "$status" "malformed include status"
build_count="$PAM_EXPANSION_BUILD_COUNT"
status=0
capture_expansion malformed auth "$CAPTURE_FILE" || status=$?
assert_equal 2 "$status" "cached malformed include status"
assert_equal "$build_count" "$PAM_EXPANSION_BUILD_COUNT" "ambiguous expansion memoization"

printf '%s\n' 'auth required pam_permit.so' > "$TEST_TEMPORARY_DIRECTORY/outside-pam"
ln -s -- ../../../outside-pam "$ROOT_DIRECTORY/etc/pam.d/unsafe"
advance_epoch
status=0
capture_expansion unsafe auth "$CAPTURE_FILE" || status=$?
assert_equal 2 "$status" "unsafe service source status"
build_count="$PAM_EXPANSION_BUILD_COUNT"
status=0
capture_expansion unsafe auth "$CAPTURE_FILE" || status=$?
assert_equal 2 "$status" "cached unsafe service source status"
assert_equal "$build_count" "$PAM_EXPANSION_BUILD_COUNT" "error expansion memoization"

printf '%s\n' 'auth include cycle-b' > "$ROOT_DIRECTORY/etc/pam.d/cycle-a"
printf '%s\n' 'auth include cycle-a' > "$ROOT_DIRECTORY/etc/pam.d/cycle-b"
advance_epoch
status=0
capture_expansion cycle-a auth "$CAPTURE_FILE" || status=$?
assert_equal 2 "$status" "cycle status"

for index_value in $(seq 0 15); do
    if [ "$index_value" -eq 15 ]; then
        printf '%s\n' 'auth required pam_permit.so' > "$ROOT_DIRECTORY/etc/pam.d/depth-$index_value"
    else
        printf 'auth include depth-%d\n' "$((index_value + 1))" > "$ROOT_DIRECTORY/etc/pam.d/depth-$index_value"
    fi
done
advance_epoch
capture_expansion depth-0 auth "$CAPTURE_FILE" || fail "depth 15 boundary expansion failed"

printf '%s\n' 'auth include prewarmed-1' > "$ROOT_DIRECTORY/etc/pam.d/prewarmed-0"
for index_value in $(seq 1 16); do
    if [ "$index_value" -eq 16 ]; then
        printf '%s\n' 'auth required pam_permit.so' > "$ROOT_DIRECTORY/etc/pam.d/prewarmed-$index_value"
    else
        printf 'auth include prewarmed-%d\n' "$((index_value + 1))" > "$ROOT_DIRECTORY/etc/pam.d/prewarmed-$index_value"
    fi
done
advance_epoch
capture_expansion prewarmed-1 auth "$CAPTURE_FILE" || fail "prewarmed child expansion failed"
status=0
capture_expansion prewarmed-0 auth "$CAPTURE_FILE" || status=$?
assert_equal 2 "$status" "cached child depth enforcement"
capture_expansion prewarmed-1 auth "$CAPTURE_FILE" || fail "depth failure poisoned shallow child"

printf '%s\n' '@include shared' > "$ROOT_DIRECTORY/etc/pam.d/at-include"
advance_epoch
capture_expansion at-include auth "$CAPTURE_FILE" || fail "Debian at-include expansion failed"
PLATFORM_FAMILY="rhel"
advance_epoch
status=0
capture_expansion at-include auth "$CAPTURE_FILE" || status=$?
assert_equal 2 "$status" "RHEL at-include rejection"

rm -rf -- "$ROOT_DIRECTORY/etc/pam.d"
cat > "$ROOT_DIRECTORY/etc/pam.conf" <<'EOF'
login auth required pam_permit.so
other auth required pam_deny.so
EOF
PLATFORM_FAMILY="debian"
advance_epoch
capture_expansion login auth "$CAPTURE_FILE" || fail "pam.conf service expansion failed"
assert_contains_file "$CAPTURE_FILE" "auth required pam_permit.so" "pam.conf selected service"

printf '%s\n' 'auth required pam_permit.so' > "$ROOT_DIRECTORY/etc/pam-extra"
printf '%s\n' 'login auth include /etc/pam-extra' > "$ROOT_DIRECTORY/etc/pam.conf"
advance_epoch
capture_expansion login auth "$CAPTURE_FILE" || fail "absolute pam.conf include failed"
assert_contains_file "$CAPTURE_FILE" "auth required pam_permit.so" "absolute pam.conf include output"

printf '%s\n' 'login auth include relative-target' > "$ROOT_DIRECTORY/etc/pam.conf"
advance_epoch
status=0
capture_expansion login auth "$CAPTURE_FILE" || status=$?
assert_equal 2 "$status" "relative pam.conf include rejection"

mkdir -p -- "$ROOT_DIRECTORY/etc/pam.d"
printf '%s\n' 'login auth required pam_permit.so' > "$ROOT_DIRECTORY/etc/pam.conf"
advance_epoch
status=0
capture_expansion login auth "$CAPTURE_FILE" || status=$?
assert_equal 1 "$status" "PAM directory suppresses pam.conf"

printf '%s\n' 'auth required pam_permit.so' > "$ROOT_DIRECTORY/etc/pam.d/mutable"
SCAN_EPOCH_ACTIVE=0
capture_expansion mutable auth "$CAPTURE_FILE" || fail "uncached mutable expansion failed"
printf '%s\n' 'auth required pam_deny.so' > "$ROOT_DIRECTORY/etc/pam.d/mutable"
capture_expansion mutable auth "$CAPTURE_FILE" || fail "uncached mutable re-expansion failed"
assert_contains_file "$CAPTURE_FILE" "pam_deny.so" "inactive epoch cache bypass"

exec {DEBUG_FD}>&-
DEBUG_OUTPUT_FD=""
assert_contains_file "$DEBUG_FILE" \
    "DEBUG: schema=1 event=pam_file mode=pamd cache=miss" \
    "PAM file cache-miss debug event"
assert_contains_file "$DEBUG_FILE" \
    "DEBUG: schema=1 event=pam_file mode=pamd cache=build status=ready" \
    "PAM file build debug event"
assert_contains_file "$DEBUG_FILE" \
    "DEBUG: schema=1 event=pam_expansion service=base facility=auth cache=hit status=ready" \
    "PAM expansion cache-hit debug event"
assert_contains_file "$DEBUG_FILE" \
    "DEBUG: schema=1 event=pam_expansion service=empty facility=auth cache=hit status=absent" \
    "absent PAM expansion cache-hit debug event"
assert_contains_file "$DEBUG_FILE" \
    "DEBUG: schema=1 event=pam_expansion service=malformed facility=auth cache=hit status=ambiguous" \
    "ambiguous PAM expansion cache-hit debug event"
assert_contains_file "$DEBUG_FILE" \
    "DEBUG: schema=1 event=pam_expansion service=unsafe facility=auth cache=hit status=error" \
    "failed PAM expansion cache-hit debug event"

printf 'PASS pam cache tests\n'
