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

file_mode() {
    if stat -c '%a' -- "$1" >/dev/null 2>&1; then stat -c '%a' -- "$1"; else stat -f '%Lp' "$1"; fi
}

file_uid() {
    if stat -c '%u' -- "$1" >/dev/null 2>&1; then stat -c '%u' -- "$1"; else stat -f '%u' "$1"; fi
}

case "${BASH_SOURCE[0]}" in */*) test_parent="${BASH_SOURCE[0]%/*}" ;; *) test_parent=. ;; esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-filesystem-transaction.XXXXXXXX")" || exit 2
trap 'chmod -R u+rwX "$test_directory" 2>/dev/null || :; rm -rf -- "$test_directory"' EXIT

# shellcheck source=../lib/kisa-cce-patcher/_filesystem-transaction.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_filesystem-transaction.sh"

callback_directory="$test_directory/callbacks"
mkdir -m 0700 "$callback_directory"
r_active_callback="$callback_directory/r-active"
printf '%s\n' '#!/bin/sh' 'printf "active\n"' > "$r_active_callback"
r_inactive_callback="$callback_directory/r-inactive"
printf '%s\n' '#!/bin/sh' 'printf "inactive\n"' > "$r_inactive_callback"
visudo_callback="$callback_directory/visudo"
printf '%s\n' '#!/bin/sh' '[ "$#" -eq 2 ] || exit 2' '! grep -Fq INVALID_SUDOERS "$2"' > "$visudo_callback"
chmod 0755 "$callback_directory"/*

unsafe_callback_directory="$test_directory/unsafe-callbacks"
mkdir -m 0777 "$unsafe_callback_directory"
unsafe_callback="$unsafe_callback_directory/r-active"
printf '%s\n' '#!/bin/sh' 'printf "active\n"' > "$unsafe_callback"
chmod 0755 "$unsafe_callback"
status=0
patch_filesystem_register_callback r_service_state "$unsafe_callback" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "attacker-writable callback parent rejection"

write_inventory() {
    local path="$1"

    {
        printf '%s\n' "$PATCH_FILESYSTEM_INVENTORY_HEADER"
        printf 'U-17\tfile\t/etc/init.d/boot\t-\t0\t-\n'
        printf 'U-17\tfile\t/etc/systemd/system/unit.service\t-\t0\t-\n'
        printf 'U-20\tfile\t/etc/inetd.conf\t-\t0\t-\n'
        printf 'U-20\tfile\t/etc/systemd/system.conf\t-\t0\t-\n'
        printf 'U-20\tfile\t/etc/systemd/system/unit.service\t-\t0\t-\n'
        printf 'U-21\tfile\t/etc/rsyslog.conf\t-\t0\t-\n'
        printf 'U-21\tfile\t/etc/rsyslog.d/10-target.conf\t-\t0\t-\n'
        printf 'U-24\tfile\t/home/alice/.profile\talice\t1000\t-\n'
        printf 'U-24\tfile\t/home/alice/.config/environment.d/app.conf\talice\t1000\t-\n'
        printf 'U-25\tfile\t/opt/approved\t-\tpreserve\tCHG-25\n'
        printf 'U-27\tfile\t/etc/hosts.equiv\t-\t0\tCHG-27\n'
        printf 'U-27\tfile\t/home/alice/.rhosts\talice\t0\tCHG-27\n'
        printf 'U-31\tdirectory\t/home/alice\talice\t1000\t-\n'
        printf 'U-63\tfile\t/etc/sudoers\t-\t0\t-\n'
        printf 'U-63\tfile\t/etc/sudoers.d/custom\t-\t0\t-\n'
    } > "$path"
    chmod 0600 "$path"
}

create_fixture() {
    local name="$1"
    local base="$test_directory/$name"
    local root="$base/root"
    local transaction="$base/transaction"
    local inventory="$base/inventory.tsv"

    mkdir -p "$root/etc/init.d" "$root/etc/systemd/system" "$root/etc/rsyslog.d" \
        "$root/etc/sudoers.d" "$root/home/alice/.config/environment.d" "$root/opt" "$transaction"
    chmod 0700 "$base" "$root" "$transaction"
    printf '%s\n' \
        'root:x:0:0:root:/root:/bin/bash' \
        'bin:x:1:1:bin:/bin:/usr/sbin/nologin' \
        'sys:x:3:3:sys:/dev:/usr/sbin/nologin' \
        'alice:x:1000:1000:Alice:/home/alice:/bin/bash' > "$root/etc/passwd"
    printf '%s\n' 'UID_MIN 1000' > "$root/etc/login.defs"
    printf '%s\n' boot > "$root/etc/init.d/boot"
    printf '%s\n' unit > "$root/etc/systemd/system/unit.service"
    printf '%s\n' inetd > "$root/etc/inetd.conf"
    printf '%s\n' manager > "$root/etc/systemd/system.conf"
    printf '%s\n' '$IncludeConfig /etc/rsyslog.d/*.conf' > "$root/etc/rsyslog.conf"
    printf '%s\n' 'authpriv.* /var/log/secure' > "$root/etc/rsyslog.d/10-target.conf"
    printf '%s\n' 'export SAFE=1' > "$root/home/alice/.profile"
    printf '%s\n' 'SAFE=1' > "$root/home/alice/.config/environment.d/app.conf"
    printf '%s\n' approved > "$root/opt/approved"
    printf '%s\n' '# retained comment' '+ +' 'safe.example user' > "$root/etc/hosts.equiv"
    printf '%s\n' '+trusted.example user' 'safe.example user' > "$root/home/alice/.rhosts"
    printf '%s\n' '@includedir /etc/sudoers.d' 'root ALL=(ALL) ALL' > "$root/etc/sudoers"
    printf '%s\n' 'alice ALL=(root) /usr/bin/id' > "$root/etc/sudoers.d/custom"
    chmod 0660 "$root/etc/init.d/boot" "$root/etc/systemd/system/unit.service" \
        "$root/etc/inetd.conf" "$root/etc/systemd/system.conf" "$root/etc/rsyslog.conf" \
        "$root/etc/rsyslog.d/10-target.conf" "$root/home/alice/.profile" \
        "$root/home/alice/.config/environment.d/app.conf" "$root/etc/sudoers" \
        "$root/etc/sudoers.d/custom"
    chmod 0666 "$root/opt/approved"
    chmod 0600 "$root/etc/hosts.equiv" "$root/home/alice/.rhosts"
    chmod 0700 "$root/home/alice"
    if [ "${EUID:-$(id -u)}" -eq 0 ]; then
        chown 0:0 "$root/home/alice"
    fi
    write_inventory "$inventory"
    printf '%s\t%s\t%s\n' "$root" "$transaction" "$inventory"
}

patch_filesystem_register_callback r_service_state "$r_active_callback" || fail "r-service callback registration failed"
patch_filesystem_register_callback visudo "$visudo_callback" || fail "visudo callback registration failed"

IFS=$'\t' read -r root transaction inventory < <(create_fixture main)
hosts_before="$(< "$root/etc/hosts.equiv")"
profile_before_mode="$(file_mode "$root/home/alice/.profile")"
home_before_uid="$(file_uid "$root/home/alice")"
patch_filesystem_plan "$root" "$transaction" "$inventory" ||
    fail "filesystem plan failed: $PATCH_FILESYSTEM_ERROR_DETAIL"
assert_equal 14 "${#PATCH_FILESYSTEM_TARGET_PATHS[@]}" "merged target count"
[ "$PATCH_FILESYSTEM_CHANGE_COUNT" -gt 0 ] || fail "plan contains no changes"
state=""
for criterion in U-17 U-20 U-21 U-24 U-25 U-27 U-31 U-63; do
    patch_filesystem_state_into "$criterion" state || fail "criterion state lookup failed: $criterion"
    expected_state=ready
    if [ "$criterion" = U-31 ] && [ "$(file_uid "$root/home/alice")" = 1000 ]; then
        expected_state=compliant
    fi
    assert_equal "$expected_state" "$state" "planned criterion state: $criterion"
done
plan="$transaction/plan.tsv"
patch_filesystem_write_plan_tsv "$plan" || fail "plan TSV write failed"
assert_equal 15 "$(wc -l < "$plan" | tr -d '[:space:]')" "plan line count"
assert_equal 600 "$(file_mode "$plan")" "plan mode"

missing_inventory="$test_directory/missing-inventory.tsv"
awk '$3 != "/etc/sudoers.d/custom"' FS='\t' OFS='\t' "$inventory" > "$missing_inventory"
chmod 0600 "$missing_inventory"
missing_transaction="$test_directory/missing-transaction"
mkdir -m 0700 "$missing_transaction"
status=0
patch_filesystem_plan "$root" "$missing_transaction" "$missing_inventory" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "incomplete inventory rejection"
assert_contains "$PATCH_FILESYSTEM_ERROR_DETAIL" "typed inventory" "inventory mismatch detail"

IFS=$'\t' read -r symlink_root symlink_transaction symlink_inventory < <(create_fixture symlink)
mv "$symlink_root/etc/sudoers.d/custom" "$symlink_root/etc/sudoers.d/custom.real"
ln -s custom.real "$symlink_root/etc/sudoers.d/custom"
status=0
patch_filesystem_plan "$symlink_root" "$symlink_transaction" "$symlink_inventory" \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "sudo include symlink rejection"

IFS=$'\t' read -r hardlink_root hardlink_transaction hardlink_inventory < <(create_fixture hardlink)
ln "$hardlink_root/opt/approved" "$hardlink_root/opt/approved.alias"
status=0
patch_filesystem_plan "$hardlink_root" "$hardlink_transaction" "$hardlink_inventory" \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "hard-linked U-25 target rejection"

if [ "${EUID:-$(id -u)}" -eq 0 ]; then
    IFS=$'\t' read -r unsafe_owner_root unsafe_owner_transaction unsafe_owner_inventory < \
        <(create_fixture unsafe-owner)
    chown 1000:1000 "$unsafe_owner_root/home/alice"
    status=0
    patch_filesystem_plan "$unsafe_owner_root" "$unsafe_owner_transaction" "$unsafe_owner_inventory" \
        >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "account-owned target parent rejection"

    IFS=$'\t' read -r unsafe_mode_root unsafe_mode_transaction unsafe_mode_inventory < \
        <(create_fixture unsafe-mode)
    chmod 0777 "$unsafe_mode_root/opt"
    status=0
    patch_filesystem_plan "$unsafe_mode_root" "$unsafe_mode_transaction" "$unsafe_mode_inventory" \
        >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "other-writable target parent rejection"
fi

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    IFS=$'\t' read -r nonroot_root nonroot_transaction nonroot_inventory < <(create_fixture nonroot)
    nonroot_mode="$(file_mode "$nonroot_root/home/alice/.profile")"
    patch_filesystem_plan "$nonroot_root" "$nonroot_transaction" "$nonroot_inventory" ||
        fail "non-root planning failed: $PATCH_FILESYSTEM_ERROR_DETAIL"
    status=0
    patch_filesystem_apply >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "non-root apply rejection"
    assert_equal "$nonroot_mode" "$(file_mode "$nonroot_root/home/alice/.profile")" \
        "non-root apply leaves profile unchanged"
    printf 'PASS: non-root filesystem transaction guards\n'
    exit 0
fi

IFS=$'\t' read -r replaced_root replaced_transaction replaced_inventory < <(create_fixture replaced-parent)
patch_filesystem_plan "$replaced_root" "$replaced_transaction" "$replaced_inventory" ||
    fail "replaceable-parent plan failed"
victim_mode="$(file_mode "$replaced_root/etc/sudoers")"
chmod 0777 "$replaced_root/opt"
mv "$replaced_root/opt/approved" "$replaced_root/opt/approved.original"
ln -s "$replaced_root/etc/sudoers" "$replaced_root/opt/approved"
status=0
patch_filesystem_apply >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "replaceable parent apply rejection"
assert_equal "$victim_mode" "$(file_mode "$replaced_root/etc/sudoers")" \
    "replaceable parent does not mutate symlink victim"
assert_equal 660 "$(file_mode "$replaced_root/etc/systemd/system/unit.service")" \
    "replaceable parent all-target preflight prevents mutation"

# The earlier negative plan reset the transaction state, so create a fresh apply fixture.
IFS=$'\t' read -r root transaction inventory < <(create_fixture apply)
hosts_before="$(< "$root/etc/hosts.equiv")"
profile_before_mode="$(file_mode "$root/home/alice/.profile")"
home_before_uid="$(file_uid "$root/home/alice")"
patch_filesystem_plan "$root" "$transaction" "$inventory" || fail "root plan failed"
patch_filesystem_apply || fail "filesystem apply failed: $PATCH_FILESYSTEM_ERROR_DETAIL"
assert_equal 600 "$(file_mode "$root/etc/systemd/system/unit.service")" "merged U-17/U-20 mode"
assert_equal 640 "$(file_mode "$root/etc/rsyslog.conf")" "U-21 mode"
assert_equal 640 "$(file_mode "$root/home/alice/.profile")" "U-24 mode"
assert_equal 1000 "$(file_uid "$root/home/alice/.profile")" "U-24 owner"
assert_equal 664 "$(file_mode "$root/opt/approved")" "U-25 removes only other write"
assert_equal 1000 "$(file_uid "$root/home/alice")" "U-31 owner"
assert_equal 640 "$(file_mode "$root/etc/sudoers")" "U-63 mode"
assert_contains "$(< "$root/etc/hosts.equiv")" "# retained comment" "U-27 preserves comments"
if grep -Eq '(^|[[:space:]])\+' "$root/etc/hosts.equiv" "$root/home/alice/.rhosts"; then
    fail "U-27 retained a plus trust rule"
fi
for criterion in U-17 U-20 U-21 U-24 U-25 U-27 U-31 U-63; do
    patch_filesystem_state_into "$criterion" state || fail "verified state lookup failed"
    assert_equal verified "$state" "verified criterion state: $criterion"
done

patch_filesystem_rollback || fail "in-process rollback failed: $PATCH_FILESYSTEM_ERROR_DETAIL"
assert_equal "$hosts_before" "$(< "$root/etc/hosts.equiv")" "U-27 rollback content"
assert_equal "$profile_before_mode" "$(file_mode "$root/home/alice/.profile")" "U-24 rollback mode"
assert_equal "$home_before_uid" "$(file_uid "$root/home/alice")" "U-31 rollback owner"

IFS=$'\t' read -r cross_root cross_transaction cross_inventory < <(create_fixture cross)
cross_hosts_before="$(< "$cross_root/etc/hosts.equiv")"
patch_filesystem_plan "$cross_root" "$cross_transaction" "$cross_inventory" || fail "cross-process plan failed"
patch_filesystem_apply || fail "cross-process apply failed"
patch_filesystem_rollback_transaction "$cross_root" "$cross_transaction" ||
    fail "cross-process rollback failed: $PATCH_FILESYSTEM_ERROR_DETAIL"
assert_equal "$cross_hosts_before" "$(< "$cross_root/etc/hosts.equiv")" \
    "cross-process U-27 rollback"
assert_equal 666 "$(file_mode "$cross_root/opt/approved")" "cross-process U-25 rollback"

IFS=$'\t' read -r drift_root drift_transaction drift_inventory < <(create_fixture drift)
patch_filesystem_plan "$drift_root" "$drift_transaction" "$drift_inventory" || fail "drift plan failed"
printf '%s\n' changed > "$drift_root/etc/sudoers.d/custom"
status=0
patch_filesystem_apply >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "content drift rejection"
assert_equal 666 "$(file_mode "$drift_root/opt/approved")" "all-target preflight prevents mutation"

printf 'PASS: filesystem transaction\n'
