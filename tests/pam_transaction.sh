#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

set -u

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
LC_ALL=C
export LC_ALL
umask 077

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_equal() { [ "$1" = "$2" ] || fail "$3: expected=[$1] actual=[$2]"; }
assert_contains() { case "$1" in *"$2"*) ;; *) fail "$3: missing=[$2]" ;; esac; }
assert_not_contains() { case "$1" in *"$2"*) fail "$3: unexpected=[$2]" ;; esac; }

file_sha256() {
    local output=""
    if command -v sha256sum >/dev/null 2>&1; then output="$(sha256sum "$1")"; else output="$(shasum -a 256 "$1")"; fi
    printf '%s\n' "${output%% *}"
}

file_metadata() {
    stat -Lc '%u:%g:%a' -- "$1" 2>/dev/null || stat -f '%u:%g:%Lp' "$1" 2>/dev/null
}

case "${BASH_SOURCE[0]}" in */*) test_parent="${BASH_SOURCE[0]%/*}" ;; *) test_parent=. ;; esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-pam-transaction.XXXXXXXX")" || exit 2
test_directory="$(CDPATH='' cd -P -- "$test_directory" && pwd)" || exit 2
trap 'chmod -R u+rwX "$test_directory" 2>/dev/null || :; rm -rf -- "$test_directory"' EXIT

# shellcheck source=../lib/kisa-cce-patcher/_configuration-transaction.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_configuration-transaction.sh"
# shellcheck source=../lib/kisa-cce-patcher/_pam-transaction.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_pam-transaction.sh"

write_common_fixture() {
    local root="$1"
    local group_name="$2"

    mkdir -p "$root/etc/pam.d" "$root/etc/security" "$root/usr/lib/security" "$root/usr/sbin" "$root/usr/bin"
    printf 'root:x:0:0:root:/root:/bin/bash\noperator:x:1000:1000:operator:/home/operator:/bin/bash\n' > "$root/etc/passwd"
    printf 'root:x:0:\n%s:x:27:operator\noperator:x:1000:\n' "$group_name" > "$root/etc/group"
    printf 'PASS_MAX_DAYS 99999\nPASS_MIN_DAYS 0\n' > "$root/etc/login.defs"
    printf '# pwquality defaults\n' > "$root/etc/security/pwquality.conf"
    printf '# pwhistory defaults\n' > "$root/etc/security/pwhistory.conf"
    printf '# faillock defaults\n' > "$root/etc/security/faillock.conf"
    for module in pam_pwquality.so pam_pwhistory.so pam_faillock.so pam_wheel.so; do
        printf 'fixture module\n' > "$root/usr/lib/security/$module"
    done
    printf '#!/bin/sh\nexit 0\n' > "$root/usr/sbin/pam-auth-update"
    chmod 0755 "$root/usr/sbin/pam-auth-update"
    chmod 0644 "$root/etc/passwd" "$root/etc/group" "$root/etc/login.defs" \
        "$root/etc/security/pwquality.conf" "$root/etc/security/pwhistory.conf" \
        "$root/etc/security/faillock.conf" "$root/usr/lib/security"/*.so
}

write_debian_fixture() {
    local root="$1"

    write_common_fixture "$root" sudo
    printf 'ID=debian\nVERSION_ID="13"\n' > "$root/etc/os-release"
    printf 'password required pam_unix.so yescrypt\n' > "$root/etc/pam.d/common-password"
    printf 'auth required pam_unix.so\n' > "$root/etc/pam.d/common-auth"
    printf 'account required pam_unix.so\n' > "$root/etc/pam.d/common-account"
    printf '%s\n' \
        'auth sufficient pam_rootok.so' \
        '@include common-auth' \
        '@include common-account' > "$root/etc/pam.d/su"
    chmod 0644 "$root/etc/os-release" "$root/etc/pam.d"/*
}

write_rhel_fixture() {
    local root="$1"

    write_common_fixture "$root" wheel
    mkdir -p "$root/etc/authselect"
    printf 'ID=rocky\nID_LIKE="rhel centos fedora"\nVERSION_ID="10.2"\n' > "$root/etc/os-release"
    printf 'local\n' > "$root/etc/authselect/authselect.conf"
    printf 'auth required pam_unix.so\naccount required pam_unix.so\npassword requisite pam_pwquality.so\npassword sufficient pam_unix.so yescrypt\n' \
        > "$root/etc/authselect/system-auth"
    cp "$root/etc/authselect/system-auth" "$root/etc/authselect/password-auth"
    printf '%s\n' \
        'auth required pam_env.so' \
        'auth sufficient pam_rootok.so' \
        'auth substack system-auth' > "$root/etc/pam.d/su"
    chmod 0644 "$root/etc/os-release" "$root/etc/authselect"/* "$root/etc/pam.d/su"
}

debian_root="$test_directory/debian/root"
debian_transaction="$test_directory/debian/transaction"
mkdir -p "$debian_root" "$debian_transaction"
chmod 0700 "$test_directory/debian" "$debian_root" "$debian_transaction"
write_debian_fixture "$debian_root"

common_password_before="$(file_sha256 "$debian_root/etc/pam.d/common-password")"
common_auth_before="$(file_sha256 "$debian_root/etc/pam.d/common-auth")"
login_defs_before="$(file_sha256 "$debian_root/etc/login.defs")"

pam_transaction_plan "$debian_root" "$debian_transaction" sudo ||
    fail "Debian PAM plan failed: $PAM_TRANSACTION_ERROR_DETAIL"
assert_equal ready "$PAM_TRANSACTION_PREREQUISITE_RESULT" "Debian prerequisite state"
assert_equal 8 "${#PATCH_CONFIGURATION_LOGICAL_PATHS[@]}" "Debian PAM target count"
[ -d "$debian_transaction/pam/backups" ] || fail "Debian backups are absent"
[ -d "$debian_transaction/pam/payloads" ] || fail "Debian payloads are absent"
assert_equal "$common_password_before" "$(file_sha256 "$debian_root/etc/pam.d/common-password")" \
    "Debian planning preserves common-password"
assert_equal "$common_auth_before" "$(file_sha256 "$debian_root/etc/pam.d/common-auth")" \
    "Debian planning preserves common-auth"
for artifact in "$debian_transaction/pam/manifest.tsv" "$debian_transaction/pam/context.tsv"; do
    assert_equal 600 "$(file_metadata "$artifact" | awk -F: '{print $3}')" "protected PAM artifact"
done
for ((artifact_index = 1; artifact_index <= 8; artifact_index++)); do
    printf -v artifact_name '%06d' "$artifact_index"
    for artifact in "$debian_transaction/pam/backups/$artifact_name" \
        "$debian_transaction/pam/payloads/$artifact_name"; do
        [ -f "$artifact" ] || fail "PAM content artifact is absent: $artifact"
        assert_equal 600 "$(file_metadata "$artifact" | awk -F: '{print $3}')" "protected PAM content artifact"
    done
done
debian_state=""
pam_transaction_state_into U-02 debian_state || fail "Debian U-02 state failed"
assert_equal ready "$debian_state" "Debian U-02 planned state"

u02_root="$test_directory/u02/root"
u02_transaction="$test_directory/u02/transaction"
mkdir -p "$u02_root" "$u02_transaction"
chmod 0700 "$test_directory/u02" "$u02_root" "$u02_transaction"
write_debian_fixture "$u02_root"
rm -f "$u02_root/usr/lib/security/pam_faillock.so" \
    "$u02_root/usr/lib/security/pam_wheel.so" \
    "$u02_root/etc/security/faillock.conf" \
    "$u02_root/etc/pam.d/common-auth" \
    "$u02_root/etc/pam.d/common-account" \
    "$u02_root/etc/pam.d/su"
pam_transaction_plan "$u02_root" "$u02_transaction" ignored U-02 ||
    fail "U-02-only PAM plan failed: $PAM_TRANSACTION_ERROR_DETAIL"
assert_equal U-02 "$PAM_TRANSACTION_CRITERIA" "U-02-only selected criteria"
assert_equal - "$PAM_TRANSACTION_APPROVED_GROUP" "U-02-only group normalization"
assert_equal 4 "${#PATCH_CONFIGURATION_LOGICAL_PATHS[@]}" "U-02-only target count"
assert_not_contains "$(< "$u02_transaction/pam/manifest.tsv")" U-03 \
    "U-02-only manifest excludes U-03"
assert_not_contains "$(< "$u02_transaction/pam/manifest.tsv")" U-06 \
    "U-02-only manifest excludes U-06"
if pam_transaction_state_into U-03 debian_state; then
    fail "U-02-only transaction exposed U-03 state"
fi

u03_root="$test_directory/u03/root"
u03_transaction="$test_directory/u03/transaction"
mkdir -p "$u03_root" "$u03_transaction"
chmod 0700 "$test_directory/u03" "$u03_root" "$u03_transaction"
write_debian_fixture "$u03_root"
rm -f "$u03_root/usr/lib/security/pam_pwquality.so" \
    "$u03_root/usr/lib/security/pam_pwhistory.so" \
    "$u03_root/usr/lib/security/pam_wheel.so" \
    "$u03_root/etc/login.defs" \
    "$u03_root/etc/security/pwquality.conf" \
    "$u03_root/etc/security/pwhistory.conf" \
    "$u03_root/etc/pam.d/common-password" \
    "$u03_root/etc/pam.d/su"
pam_transaction_plan "$u03_root" "$u03_transaction" ignored U-03 ||
    fail "U-03-only PAM plan failed: $PAM_TRANSACTION_ERROR_DETAIL"
assert_equal U-03 "$PAM_TRANSACTION_CRITERIA" "U-03-only selected criteria"
assert_equal 3 "${#PATCH_CONFIGURATION_LOGICAL_PATHS[@]}" "U-03-only target count"

u06_root="$test_directory/u06/root"
u06_transaction="$test_directory/u06/transaction"
mkdir -p "$u06_root" "$u06_transaction"
chmod 0700 "$test_directory/u06" "$u06_root" "$u06_transaction"
write_debian_fixture "$u06_root"
rm -f "$u06_root/usr/lib/security/pam_pwquality.so" \
    "$u06_root/usr/lib/security/pam_pwhistory.so" \
    "$u06_root/usr/lib/security/pam_faillock.so" \
    "$u06_root/usr/sbin/pam-auth-update" \
    "$u06_root/etc/login.defs" \
    "$u06_root/etc/security/pwquality.conf" \
    "$u06_root/etc/security/pwhistory.conf" \
    "$u06_root/etc/security/faillock.conf" \
    "$u06_root/etc/pam.d/common-password" \
    "$u06_root/etc/pam.d/common-auth" \
    "$u06_root/etc/pam.d/common-account"
u06_su_before="$(file_sha256 "$u06_root/etc/pam.d/su")"
pam_transaction_plan "$u06_root" "$u06_transaction" sudo U-06 ||
    fail "U-06-only PAM plan failed: $PAM_TRANSACTION_ERROR_DETAIL"
assert_equal U-06 "$PAM_TRANSACTION_CRITERIA" "U-06-only selected criteria"
assert_equal 1 "${#PATCH_CONFIGURATION_LOGICAL_PATHS[@]}" "U-06-only target count"
assert_contains "$(< "$u06_transaction/pam/context.tsv")" $'\tU-06' \
    "U-06-only context binding"

invalid_transaction="$test_directory/invalid-transaction"
mkdir "$invalid_transaction"
chmod 0700 "$invalid_transaction"
status=0
pam_transaction_plan "$debian_root" "$invalid_transaction" sudo U-02 U-02 \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "duplicate PAM criterion rejection"
rmdir "$invalid_transaction"
mkdir "$invalid_transaction"
chmod 0700 "$invalid_transaction"
status=0
pam_transaction_plan "$debian_root" "$invalid_transaction" sudo U-04 \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "unsupported PAM criterion rejection"

tamper_root="$test_directory/tamper/root"
tamper_transaction="$test_directory/tamper/transaction"
mkdir -p "$tamper_root" "$tamper_transaction"
chmod 0700 "$test_directory/tamper" "$tamper_root" "$tamper_transaction"
write_debian_fixture "$tamper_root"
pam_transaction_plan "$tamper_root" "$tamper_transaction" sudo U-06 ||
    fail "context-binding plan failed"
{
    printf '%s\n' "$PAM_TRANSACTION_CONTEXT_HEADER"
    printf '2\tdebian\t-\t-\t-\tU-02\n'
} > "$tamper_transaction/pam/context.tsv"
chmod 0600 "$tamper_transaction/pam/context.tsv"
status=0
pam_transaction_load_transaction "$tamper_root" "$tamper_transaction" planned \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "PAM criterion context substitution rejection"

missing_root="$test_directory/missing/root"
missing_transaction="$test_directory/missing/transaction"
mkdir -p "$missing_root" "$missing_transaction"
chmod 0700 "$test_directory/missing" "$missing_root" "$missing_transaction"
write_debian_fixture "$missing_root"
rm -f "$missing_root/usr/lib/security/pam_pwquality.so"
status=0
pam_transaction_plan "$missing_root" "$missing_transaction" sudo >/dev/null 2>&1 || status=$?
assert_equal 3 "$status" "missing module prerequisite status"
assert_equal missing_module:pam_pwquality.so "$PAM_TRANSACTION_PREREQUISITE_RESULT" \
    "missing module prerequisite detail"
[ ! -e "$missing_transaction/pam" ] || fail "missing prerequisite created PAM transaction data"

drift_root="$test_directory/drift/root"
drift_transaction="$test_directory/drift/transaction"
mkdir -p "$drift_root" "$drift_transaction"
chmod 0700 "$test_directory/drift" "$drift_root" "$drift_transaction"
write_debian_fixture "$drift_root"
pam_transaction_plan "$drift_root" "$drift_transaction" sudo || fail "drift plan failed"
printf '# changed after plan\n' >> "$drift_root/etc/security/faillock.conf"
status=0
pam_transaction_apply >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "all-target PAM drift rejection"
assert_equal "$common_password_before" "$(file_sha256 "$drift_root/etc/pam.d/common-password")" \
    "PAM drift prevents earlier mutation"

if [ "${EUID:-$(id -u)}" -eq 0 ]; then
    pam_transaction_load_transaction "$u06_root" "$u06_transaction" planned ||
        fail "U-06-only planned transaction load failed: $PAM_TRANSACTION_ERROR_DETAIL"
    assert_equal U-06 "$PAM_TRANSACTION_CRITERIA" "U-06-only loaded criteria"
    pam_transaction_apply || fail "U-06-only PAM apply failed: $PAM_TRANSACTION_ERROR_DETAIL"
    assert_contains "$(< "$u06_root/etc/pam.d/su")" \
        'auth required pam_wheel.so use_uid group=sudo' "U-06-only PAM insertion"
    [ ! -e "$u06_root/etc/pam.d/common-password" ] ||
        fail "U-06-only apply created an unselected PAM path"
    pam_transaction_reset
    pam_transaction_rollback_transaction "$u06_root" "$u06_transaction" ||
        fail "U-06-only cross-process rollback failed: $PAM_TRANSACTION_ERROR_DETAIL"
    assert_equal "$u06_su_before" "$(file_sha256 "$u06_root/etc/pam.d/su")" \
        "U-06-only rollback"

    pam_transaction_plan "$debian_root" "$debian_transaction-apply" sudo >/dev/null 2>&1 &&
        fail "nonexistent transaction directory was accepted"
    debian_apply="$test_directory/debian/apply"
    mkdir "$debian_apply"
    chmod 0700 "$debian_apply"
    pam_transaction_plan "$debian_root" "$debian_apply" sudo || fail "Debian apply plan failed"
    pam_transaction_apply || fail "Debian PAM apply failed: $PAM_TRANSACTION_ERROR_DETAIL"
    pam_transaction_state_into U-02 debian_state || fail "Debian verified state failed"
    assert_equal verified "$debian_state" "Debian U-02 verified state"
    assert_contains "$(< "$debian_root/etc/pam.d/common-password")" \
        'password requisite pam_pwquality.so retry=3' "Debian pwquality insertion"
    assert_contains "$(< "$debian_root/etc/pam.d/common-auth")" \
        'auth [default=die] pam_faillock.so authfail' "Debian faillock insertion"
    assert_contains "$(< "$debian_root/etc/pam.d/su")" \
        'auth required pam_wheel.so use_uid group=sudo' "Debian wheel insertion"
    assert_contains "$(< "$debian_root/etc/login.defs")" 'PASS_MAX_DAYS 90' "Debian aging policy"
    debian_idempotent="$test_directory/debian/idempotent"
    mkdir "$debian_idempotent"
    chmod 0700 "$debian_idempotent"
    pam_transaction_plan "$debian_root" "$debian_idempotent" sudo || fail "Debian idempotent plan failed"
    assert_equal 0 "$PATCH_CONFIGURATION_CHANGE_COUNT" "Debian idempotent change count"
    pam_transaction_reset
    pam_transaction_rollback_transaction "$debian_root" "$debian_apply" ||
        fail "Debian cross-process rollback failed: $PAM_TRANSACTION_ERROR_DETAIL"
    assert_equal "$common_password_before" "$(file_sha256 "$debian_root/etc/pam.d/common-password")" \
        "Debian common-password rollback"
    assert_equal "$common_auth_before" "$(file_sha256 "$debian_root/etc/pam.d/common-auth")" \
        "Debian common-auth rollback"
    assert_equal "$login_defs_before" "$(file_sha256 "$debian_root/etc/login.defs")" \
        "Debian login.defs rollback"

    rhel_root="$test_directory/rhel/root"
    rhel_transaction="$test_directory/rhel/transaction"
    mkdir -p "$rhel_root" "$rhel_transaction"
    chmod 0700 "$test_directory/rhel" "$rhel_root" "$rhel_transaction"
    write_rhel_fixture "$rhel_root"
    rhel_system_before="$(file_sha256 "$rhel_root/etc/authselect/system-auth")"
    rhel_conf_before="$(file_sha256 "$rhel_root/etc/authselect/authselect.conf")"

    _pam_transaction_run_authselect() {
        local destination_name="$1"
        local command_name="${2:-}"
        local selector="${*: -1}"
        local fixture_output=""
        local line=""

        shift
        case "$command_name" in
            check) fixture_output="" ;;
            current)
                while IFS= read -r line || [ -n "$line" ]; do
                    [ -n "$line" ] && fixture_output="${fixture_output:+$fixture_output }$line"
                done < "$PATCH_CONFIGURATION_ROOT/etc/authselect/authselect.conf"
                ;;
            test)
                case "$selector" in
                    -s) fixture_output=$'File /etc/pam.d/system-auth:\nauth required pam_faillock.so preauth silent\nauth sufficient pam_unix.so\nauth required pam_faillock.so authfail\naccount required pam_faillock.so\naccount required pam_unix.so\npassword requisite pam_pwquality.so\npassword requisite pam_pwhistory.so use_authtok\npassword sufficient pam_unix.so yescrypt\n' ;;
                    -p) fixture_output=$'File /etc/pam.d/password-auth:\nauth required pam_faillock.so preauth silent\nauth sufficient pam_unix.so\nauth required pam_faillock.so authfail\naccount required pam_faillock.so\naccount required pam_unix.so\npassword requisite pam_pwquality.so\npassword requisite pam_pwhistory.so use_authtok\npassword sufficient pam_unix.so yescrypt\n' ;;
                    *) return 2 ;;
                esac
                ;;
            *) return 2 ;;
        esac
        printf -v "$destination_name" '%s' "$fixture_output"
    }

    rhel_u02_root="$test_directory/rhel-u02/root"
    rhel_u02_transaction="$test_directory/rhel-u02/transaction"
    mkdir -p "$rhel_u02_root" "$rhel_u02_transaction"
    chmod 0700 "$test_directory/rhel-u02" "$rhel_u02_root" "$rhel_u02_transaction"
    write_rhel_fixture "$rhel_u02_root"
    rm -f "$rhel_u02_root/usr/lib/security/pam_faillock.so" \
        "$rhel_u02_root/usr/lib/security/pam_wheel.so" \
        "$rhel_u02_root/etc/security/faillock.conf" \
        "$rhel_u02_root/etc/pam.d/su"
    pam_transaction_plan "$rhel_u02_root" "$rhel_u02_transaction" ignored U-02 ||
        fail "RHEL U-02-only plan failed: $PAM_TRANSACTION_ERROR_DETAIL"
    assert_equal U-02 "$PAM_TRANSACTION_CRITERIA" "RHEL U-02-only selected criteria"
    assert_equal with-pwhistory "$PAM_TRANSACTION_AUTHSELECT_FEATURES" \
        "RHEL U-02-only authselect feature"
    assert_equal 6 "${#PATCH_CONFIGURATION_LOGICAL_PATHS[@]}" \
        "RHEL U-02-only target count"
    assert_not_contains "$(< "$rhel_u02_transaction/pam/manifest.tsv")" U-03 \
        "RHEL U-02-only manifest excludes U-03"

    rhel_u06_root="$test_directory/rhel-u06/root"
    rhel_u06_transaction="$test_directory/rhel-u06/transaction"
    mkdir -p "$rhel_u06_root" "$rhel_u06_transaction"
    chmod 0700 "$test_directory/rhel-u06" "$rhel_u06_root" "$rhel_u06_transaction"
    write_rhel_fixture "$rhel_u06_root"
    rm -rf "$rhel_u06_root/etc/authselect"
    rm -f "$rhel_u06_root/usr/lib/security/pam_pwquality.so" \
        "$rhel_u06_root/usr/lib/security/pam_pwhistory.so" \
        "$rhel_u06_root/usr/lib/security/pam_faillock.so" \
        "$rhel_u06_root/etc/login.defs" \
        "$rhel_u06_root/etc/security/pwquality.conf" \
        "$rhel_u06_root/etc/security/pwhistory.conf" \
        "$rhel_u06_root/etc/security/faillock.conf"
    rhel_u06_su_before="$(file_sha256 "$rhel_u06_root/etc/pam.d/su")"
    pam_transaction_plan "$rhel_u06_root" "$rhel_u06_transaction" wheel U-06 ||
        fail "RHEL U-06-only plan failed: $PAM_TRANSACTION_ERROR_DETAIL"
    assert_equal - "$PAM_TRANSACTION_AUTHSELECT_PROFILE" \
        "RHEL U-06-only authselect profile"
    assert_equal 1 "${#PATCH_CONFIGURATION_LOGICAL_PATHS[@]}" \
        "RHEL U-06-only target count"
    pam_transaction_apply ||
        fail "RHEL U-06-only apply failed: $PAM_TRANSACTION_ERROR_DETAIL"
    pam_transaction_reset
    pam_transaction_rollback_transaction "$rhel_u06_root" "$rhel_u06_transaction" ||
        fail "RHEL U-06-only rollback failed: $PAM_TRANSACTION_ERROR_DETAIL"
    assert_equal "$rhel_u06_su_before" "$(file_sha256 "$rhel_u06_root/etc/pam.d/su")" \
        "RHEL U-06-only rollback"

    pam_transaction_plan "$rhel_root" "$rhel_transaction" wheel ||
        fail "RHEL managed PAM plan failed: $PAM_TRANSACTION_ERROR_DETAIL"
    assert_equal local "$PAM_TRANSACTION_AUTHSELECT_PROFILE" "RHEL authselect profile"
    assert_contains "$PAM_TRANSACTION_AUTHSELECT_FEATURES" with-faillock "RHEL faillock feature"
    assert_contains "$PAM_TRANSACTION_AUTHSELECT_FEATURES" with-pwhistory "RHEL pwhistory feature"
    pam_transaction_apply || fail "RHEL managed PAM apply failed: $PAM_TRANSACTION_ERROR_DETAIL"
    assert_contains "$(< "$rhel_root/etc/authselect/authselect.conf")" with-faillock "RHEL authselect state"
    assert_contains "$(< "$rhel_root/etc/authselect/system-auth")" pam_faillock.so "RHEL generated faillock"
    assert_contains "$(< "$rhel_root/etc/authselect/password-auth")" pam_pwhistory.so "RHEL generated pwhistory"
    pam_transaction_reset
    pam_transaction_rollback_transaction "$rhel_root" "$rhel_transaction" ||
        fail "RHEL cross-process rollback failed: $PAM_TRANSACTION_ERROR_DETAIL"
    assert_equal "$rhel_system_before" "$(file_sha256 "$rhel_root/etc/authselect/system-auth")" \
        "RHEL system-auth rollback"
    assert_equal "$rhel_conf_before" "$(file_sha256 "$rhel_root/etc/authselect/authselect.conf")" \
        "RHEL authselect state rollback"
else
    status=0
    pam_transaction_apply >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "non-root PAM apply rejection"
fi

printf 'PASS: PAM transaction\n'
