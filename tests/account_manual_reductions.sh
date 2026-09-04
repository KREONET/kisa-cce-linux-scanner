#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

# shellcheck disable=SC2034

set -u

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_equal() {
    local expected="$1"
    local actual="$2"
    local context="$3"

    [ "$expected" = "$actual" ] || fail "$context: expected '$expected', received '$actual'"
}

assert_contains() {
    local value="$1"
    local expected="$2"
    local context="$3"

    case "$value" in
        *"$expected"*) ;;
        *) fail "$context: missing '$expected'" ;;
    esac
}

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent=. ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-account-manual.XXXXXXXX")" || exit 2
trap 'rm -rf -- "$test_directory"' EXIT

root="$test_directory/root"
scratch_directory="$test_directory/scratch"
mkdir -p -- "$root/etc" "$root/usr/bin" "$scratch_directory"

KISA_CCE_VERSION='test'
DATA_DIR="$project_directory/data"
SCAN_ROOT="$root"
RUNTIME_MODE='off'
SELECTED_CHECKS=''

# shellcheck source=../lib/kisa-cce-core/_core.sh
. "$project_directory/lib/kisa-cce-core/_core.sh"
# shellcheck source=../lib/kisa-cce-resolvers/_resolvers.sh
. "$project_directory/lib/kisa-cce-resolvers/_resolvers.sh"
# shellcheck source=../lib/kisa-cce-checks/_account-file.sh
. "$project_directory/lib/kisa-cce-checks/_account-file.sh"

PLATFORM_ID='debian'
PLATFORM_VERSION='13'
PLATFORM_NAME='Debian GNU/Linux 13'
PLATFORM_FAMILY='debian'
PLATFORM_BASE_ID='debian'
PLATFORM_BASE_VERSION='13'
SCRATCH_DIR="$scratch_directory"

printf '%s\n' 'UID_MIN 1000' > "$root/etc/login.defs"
printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' > "$root/etc/passwd"
: > "$root/usr/bin/su"
chmod 0755 -- "$root/usr/bin/su"

printf '%s\n' 'passwd: files # local identities' 'group: files' > "$root/etc/nsswitch.conf"
check_u_06
assert_equal NOT_APPLICABLE "$RESULT_STATUS" "U-06 files-only NSS with no general account"
assert_equal false "$RESULT_APPLICABLE" "U-06 files-only applicability"
assert_contains "$RESULT_EVIDENCE" 'nss_account_sources=files_only' "U-06 files-only evidence"

printf '%s\n' 'passwd: files sss' 'group: files' > "$root/etc/nsswitch.conf"
check_u_06
assert_equal MANUAL "$RESULT_STATUS" "U-06 external NSS remains manual"
assert_contains "$RESULT_EVIDENCE" 'nss_account_sources=external_or_unresolved' "U-06 external NSS evidence"

printf '%s\n' 'passwd: files' 'passwd: files' 'group: files' > "$root/etc/nsswitch.conf"
check_u_06
assert_equal MANUAL "$RESULT_STATUS" "U-06 duplicate NSS database remains manual"

rm -f -- "$root/etc/nsswitch.conf"
check_u_06
assert_equal MANUAL "$RESULT_STATUS" "U-06 absent NSS configuration remains manual"
assert_contains "$RESULT_EVIDENCE" 'nss_account_sources=absent' "U-06 absent NSS evidence"

ln -s -- /missing-nsswitch "$root/etc/nsswitch.conf"
check_u_06
assert_equal ERROR "$RESULT_STATUS" "U-06 unsafe NSS path fails closed"
assert_contains "$RESULT_EVIDENCE" 'nss_account_sources=path_error' "U-06 unsafe NSS evidence"
rm -f -- "$root/etc/nsswitch.conf"

printf '%s\n' \
    'root:x:0:0:root:/root:/bin/bash' \
    'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin' > "$root/etc/passwd"
printf '%s\n' \
    'root:!:20000:0:99999:7:::' \
    'daemon:*:20000:0:99999:7:::' > "$root/etc/shadow"
chmod 0600 -- "$root/etc/shadow"
check_u_07
assert_equal GOOD "$RESULT_STATUS" "U-07 complete root-only account set"
assert_contains "$RESULT_EVIDENCE" 'root_only_login_capable=true' "U-07 root-only evidence"
assert_contains "$RESULT_EVIDENCE" 'shadow_status=complete' "U-07 complete shadow evidence"

printf '%s\n' 'root:!:20000:0:99999:7:::' > "$root/etc/shadow"
check_u_07
assert_equal MANUAL "$RESULT_STATUS" "U-07 incomplete shadow set remains manual"
assert_contains "$RESULT_EVIDENCE" 'missing_shadow_accounts=1' "U-07 incomplete shadow count"

rm -f -- "$root/etc/shadow"
check_u_07
assert_equal MANUAL "$RESULT_STATUS" "U-07 absent shadow remains manual"
assert_contains "$RESULT_EVIDENCE" 'shadow_status=absent' "U-07 absent shadow evidence"

printf '%s\n' 'root:malformed' > "$root/etc/shadow"
check_u_07
assert_equal ERROR "$RESULT_STATUS" "U-07 malformed shadow fails closed"
assert_contains "$RESULT_EVIDENCE" 'shadow_status=invalid' "U-07 malformed shadow evidence"

printf '%s\n' \
    'root:x:0:0:root:/root:/bin/bash' \
    'operator:x:1000:1000::/home/operator:/bin/bash' > "$root/etc/passwd"
printf '%s\n' \
    'root:!:20000:0:99999:7:::' \
    'operator:!:20000:0:99999:7:::' > "$root/etc/shadow"
check_u_07
assert_equal MANUAL "$RESULT_STATUS" "U-07 additional login account remains manual"
assert_contains "$RESULT_EVIDENCE" 'root_only_login_capable=false' "U-07 additional account evidence"

printf 'PASS: U-06 and U-07 conservative MANUAL reductions\n'
