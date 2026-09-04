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

case "${BASH_SOURCE[0]}" in */*) test_parent="${BASH_SOURCE[0]%/*}" ;; *) test_parent=. ;; esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-account-patch.XXXXXXXX")" || exit 2
test_directory="$(CDPATH='' cd -P -- "$test_directory" && pwd)" || exit 2
trap 'chmod -R u+rwX "$test_directory" 2>/dev/null || :; rm -rf -- "$test_directory"' EXIT

# shellcheck source=../lib/kisa-cce-patcher/_account-transaction.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_account-transaction.sh"

assert_equal $'U-04\nU-05\nU-07\nU-08\nU-09\nU-10\nU-11\nU-13\nU-32\nU-55' \
    "$(patch_account_supported_criteria)" "supported account criteria"

new_fixture() {
    local name="$1"
    local root="$test_directory/$name/root"
    local transaction="$test_directory/$name/transaction"

    mkdir -p "$root/etc" "$root/home" "$root/root" "$transaction"
    chmod 0700 "$root" "$transaction"
    printf '%s\n' \
        'root:x:0:0:root:/root:/bin/bash' \
        'admin:x:1000:100:Admin:/missing/admin:/bin/bash' \
        'daemon:x:1:1:Daemon:/usr/sbin:/bin/bash' \
        'ftp:x:14:14:FTP:/srv/ftp:/bin/bash' \
        'weak:x:1001:100:Weak:/home/weak:/usr/sbin/nologin' > "$root/etc/passwd"
    printf '%s\n' \
        'root:!:20000:0:99999:7:::' \
        'admin:$6$salt$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwx:20000:0:99999:7:::' \
        'daemon:!:20000:0:99999:7:::' \
        'ftp:!:20000:0:99999:7:::' \
        'weak:$1$salt$abcdefghijklmnopqrstuv:20000:0:99999:7:::' > "$root/etc/shadow"
    printf '%s\n' \
        'root:x:0:admin' \
        'daemon:x:1:' \
        'ftp:x:14:' \
        'users:x:100:admin,weak' \
        'unused:x:200:' > "$root/etc/group"
    printf '%s\n' \
        'root:!::admin' \
        'daemon:!::' \
        'ftp:!::' \
        'users:!::admin,weak' \
        'unused:!::' > "$root/etc/gshadow"
    printf '%s\n' 'passwd: files' 'group: files' 'shadow: files' 'gshadow: files' > "$root/etc/nsswitch.conf"
    printf '%s\n' 'ID=debian' 'ID_LIKE=debian' 'VERSION_ID="13"' > "$root/etc/os-release"
    printf '%s\n' 'UID_MIN 1000' > "$root/etc/login.defs"
    chmod 0644 "$root/etc/passwd" "$root/etc/group" "$root/etc/nsswitch.conf"
    chmod 0644 "$root/etc/os-release" "$root/etc/login.defs"
    chmod 0640 "$root/etc/shadow" "$root/etc/gshadow"
    printf '%s\t%s\n' "$root" "$transaction"
}

set_complete_evidence() {
    patch_account_evidence_reset
    patch_account_evidence_add nss complete TEST-NSS
    patch_account_evidence_add processes complete TEST-PROCESSES
    patch_account_evidence_add filesystem-ownership complete TEST-OWNERSHIP
}

IFS=$'\t' read -r root transaction < <(new_fixture main)
passwd_before="$(< "$root/etc/passwd")"
shadow_before="$(< "$root/etc/shadow")"
group_before="$(< "$root/etc/group")"
gshadow_before="$(< "$root/etc/gshadow")"

patch_account_decision_reset
set_complete_evidence
status=0
patch_account_plan "$root" "$transaction" U-07 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "missing exact account decision"
assert_contains "$PATCH_ACCOUNT_ERROR_DETAIL" "requires an exact typed decision" "missing decision detail"

rm -rf "$transaction/account"
patch_account_decision_reset
set_complete_evidence
patch_account_decision_add U-07 admin disable-login /usr/sbin/nologin APPROVE-07
patch_account_decision_add U-08 admin remove-root-membership - APPROVE-08
patch_account_decision_add U-11 daemon set-shell /usr/sbin/nologin APPROVE-11-DAEMON
patch_account_decision_add U-11 ftp set-shell /usr/sbin/nologin APPROVE-11-FTP
patch_account_decision_add U-32 admin disable-login /usr/sbin/nologin APPROVE-32
patch_account_decision_add U-55 ftp set-shell /usr/sbin/nologin APPROVE-55
patch_account_plan "$root" "$transaction" U-07 U-08 U-11 U-32 U-55 ||
    fail "safe account plan failed: $PATCH_ACCOUNT_ERROR_DETAIL"
state=""
patch_account_state_into U-07 state || fail "U-07 state missing"
assert_equal ready "$state" "U-07 ready state"
assert_equal planned "$(< "$transaction/account/state")" "planned transaction state"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    status=0
    patch_account_apply >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "non-root account apply rejection"
    printf 'PASS: account transaction adapter (non-root)\n'
    exit 0
fi

patch_account_apply || fail "safe account apply failed: $PATCH_ACCOUNT_ERROR_DETAIL"
assert_equal verified "$(< "$transaction/account/state")" "verified transaction state"
assert_equal /usr/sbin/nologin "$(awk -F: '$1=="admin" {print $7}' "$root/etc/passwd")" "admin shell"
assert_equal /usr/sbin/nologin "$(awk -F: '$1=="daemon" {print $7}' "$root/etc/passwd")" "daemon shell"
assert_equal /usr/sbin/nologin "$(awk -F: '$1=="ftp" {print $7}' "$root/etc/passwd")" "ftp shell"
case "$(awk -F: '$1=="root" {print $4}' "$root/etc/group")" in *admin*) fail "root group retained admin" ;; esac

tamper="$test_directory/tamper"
cp -a "$transaction" "$tamper"
printf '%s\n' tamper >> "$tamper/account/operations.tsv"
status=0
patch_account_load_transaction "$root" "$tamper" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "operations checksum tamper rejection"

printf '%s\n' drift >> "$root/etc/passwd"
status=0
patch_account_rollback_transaction "$root" "$transaction" strict >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "account content drift rejection"
cp "$transaction/account/payloads/passwd" "$root/etc/passwd"
chmod 0644 "$root/etc/passwd"

/bin/bash -c '
    set -eu
    . "$1"
    patch_account_rollback_transaction "$2" "$3" strict
' account-rollback "$project_directory/lib/kisa-cce-patcher/_account-transaction.sh" "$root" "$transaction" ||
    fail "cross-process account rollback failed"
assert_equal "$passwd_before" "$(< "$root/etc/passwd")" "passwd rollback"
assert_equal "$shadow_before" "$(< "$root/etc/shadow")" "shadow rollback"
assert_equal "$group_before" "$(< "$root/etc/group")" "group rollback"
assert_equal "$gshadow_before" "$(< "$root/etc/gshadow")" "gshadow rollback"
patch_account_reset
patch_account_rollback_transaction "$root" "$transaction" strict || fail "rolled-back idempotency failed"

IFS=$'\t' read -r uid_root uid_transaction < <(new_fixture uid-minimum)
printf '%s\n' 'ID=rocky' 'ID_LIKE="rhel centos fedora"' 'VERSION_ID="10.2"' > "$uid_root/etc/os-release"
mkdir -p "$uid_root/etc/login.defs.d"
printf '%s\n' 'UID_MIN 2000' > "$uid_root/etc/login.defs.d/90-local.defs"
patch_account_decision_reset
set_complete_evidence
patch_account_plan "$uid_root" "$uid_transaction" U-32 ||
    fail "RHEL 10 libeconf UID_MIN plan failed: $PATCH_ACCOUNT_ERROR_DETAIL"
patch_account_state_into U-32 state || fail "U-32 state missing"
assert_equal compliant "$state" "RHEL 10 drop-in UID_MIN target scope"
assert_equal 2000 "$PATCH_ACCOUNT_UID_MINIMUM" "effective RHEL 10 UID_MIN"
printf '%s\n' 'UID_MIN 1000' > "$uid_root/etc/login.defs.d/90-local.defs"
status=0
patch_account_apply >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "UID_MIN drift rejection"
assert_contains "$PATCH_ACCOUNT_ERROR_DETAIL" "UID_MIN policy changed" "UID_MIN drift diagnostic"

yescrypt_hash='$y$j9T$saltsalt$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ'
IFS=$'\t' read -r debian_root debian_transaction < <(new_fixture yescrypt-debian)
sed "s|^weak:[^:]*:|weak:$yescrypt_hash:|" "$debian_root/etc/shadow" > "$debian_root/etc/shadow.new"
mv "$debian_root/etc/shadow.new" "$debian_root/etc/shadow"
chmod 0640 "$debian_root/etc/shadow"
patch_account_decision_reset
set_complete_evidence
patch_account_plan "$debian_root" "$debian_transaction" U-13 ||
    fail "Debian yescrypt plan failed: $PATCH_ACCOUNT_ERROR_DETAIL"
patch_account_state_into U-13 state || fail "Debian U-13 state missing"
assert_equal compliant "$state" "Debian yescrypt support"

IFS=$'\t' read -r rhel8_root rhel8_transaction < <(new_fixture yescrypt-rhel8)
printf '%s\n' 'ID=rocky' 'ID_LIKE="rhel centos fedora"' 'VERSION_ID="8.10"' > "$rhel8_root/etc/os-release"
sed "s|^weak:[^:]*:|weak:$yescrypt_hash:|" "$rhel8_root/etc/shadow" > "$rhel8_root/etc/shadow.new"
mv "$rhel8_root/etc/shadow.new" "$rhel8_root/etc/shadow"
chmod 0640 "$rhel8_root/etc/shadow"
patch_account_decision_reset
set_complete_evidence
patch_account_decision_add U-13 weak credential-reset - APPROVE-RHEL8-RESET
patch_account_plan "$rhel8_root" "$rhel8_transaction" U-13 ||
    fail "RHEL 8 yescrypt reset plan failed: $PATCH_ACCOUNT_ERROR_DETAIL"
patch_account_state_into U-13 state || fail "RHEL 8 U-13 state missing"
assert_equal external_action_required "$state" "RHEL 8 yescrypt reset requirement"

IFS=$'\t' read -r rhel10_root rhel10_transaction < <(new_fixture yescrypt-rhel10)
printf '%s\n' 'ID=rocky' 'ID_LIKE="rhel centos fedora"' 'VERSION_ID="10.2"' > "$rhel10_root/etc/os-release"
sed "s|^weak:[^:]*:|weak:$yescrypt_hash:|" "$rhel10_root/etc/shadow" > "$rhel10_root/etc/shadow.new"
mv "$rhel10_root/etc/shadow.new" "$rhel10_root/etc/shadow"
chmod 0640 "$rhel10_root/etc/shadow"
patch_account_decision_reset
set_complete_evidence
patch_account_plan "$rhel10_root" "$rhel10_transaction" U-13 ||
    fail "RHEL 10 yescrypt plan failed: $PATCH_ACCOUNT_ERROR_DETAIL"
patch_account_state_into U-13 state || fail "RHEL 10 U-13 state missing"
assert_equal compliant "$state" "RHEL 10 yescrypt support"

IFS=$'\t' read -r external_root external_transaction < <(new_fixture external)
patch_account_decision_reset
set_complete_evidence
patch_account_decision_add U-13 weak credential-reset - APPROVE-RESET
patch_account_plan "$external_root" "$external_transaction" U-13 ||
    fail "external-action plan failed: $PATCH_ACCOUNT_ERROR_DETAIL"
patch_account_state_into U-13 state || fail "external action state missing"
assert_equal external_action_required "$state" "weak hash reset state"
assert_equal external_action_required "$(< "$external_transaction/account/state")" "external transaction state"
status=0
patch_account_apply >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "credential generation refusal"
assert_contains "$PATCH_ACCOUNT_ERROR_DETAIL" "requires an external action" "external action diagnostic"

printf 'PASS: account transaction adapter (root)\n'
