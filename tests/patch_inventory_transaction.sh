#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

set -u
PATH="/usr/sbin:/usr/bin:/sbin:/bin"; export PATH
LC_ALL=C; export LC_ALL
umask 077

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_equal() { [ "$1" = "$2" ] || fail "$3: expected=[$1] actual=[$2]"; }
file_mode() { stat -c '%a' -- "$1"; }
file_uid_gid() { stat -c '%u:%g' -- "$1"; }
file_identity() { stat -c '%d:%i' -- "$1"; }
file_sha() { sha256sum "$1" | awk '{print $1}'; }

case "${BASH_SOURCE[0]}" in */*) test_parent="${BASH_SOURCE[0]%/*}" ;; *) test_parent=. ;; esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-inventory-transaction.XXXXXXXX")" || exit 2
trap 'chmod -R u+rwX "$test_directory" 2>/dev/null || :; rm -rf -- "$test_directory"' EXIT

# shellcheck source=../lib/kisa-cce-patcher/_inventory-transaction.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_inventory-transaction.sh"

callbacks="$test_directory/callbacks"
mkdir -m 0700 "$callbacks"
root_path_callback="$callbacks/root-path"
cat > "$root_path_callback" <<'EOF'
#!/bin/sh
[ "$#" -eq 2 ] || exit 2
grep -Fqx "PATH=$2" "$1/etc/profile.d/99-kisa-cce-root-path.sh"
EOF
umask_callback="$callbacks/umask"
cat > "$umask_callback" <<'EOF'
#!/bin/sh
[ "$#" -eq 4 ] || exit 2
grep -Eq "(umask|UMASK|umask=|Umask)[ =]+0?$4" "$2"
EOF
chmod 0755 "$callbacks"/*
patch_inventory_register_callback root_path_runtime "$root_path_callback" || fail "root PATH callback rejected"
patch_inventory_register_callback umask_native "$umask_callback" || fail "UMASK callback rejected"

create_root() {
    local root="$1"
    mkdir -p "$root/etc" "$root/var/lib/kisa-cce-quarantine/test"
    chmod 0700 "$root" "$root/var/lib/kisa-cce-quarantine/test"
    printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' 'alice:x:1000:1000:Alice:/home/alice:/bin/bash' > "$root/etc/passwd"
    printf '%s\n' 'root:x:0:' 'users:x:1000:alice' > "$root/etc/group"
    printf '%s\n' 'passwd: files' 'group: files' > "$root/etc/nsswitch.conf"
}

write_evidence() {
    local root="$1" inventory="$2" evidence="$3"
    local identity="" device="" inode="" digest=""
    identity="$(file_identity "$root")"
    device="${identity%%:*}"; inode="${identity#*:}"; digest="$(file_sha "$inventory")"
    {
        printf '%s\n' "$PATCH_INVENTORY_EVIDENCE_HEADER"
        printf '1\tsnapshot-001\t%s\t%s\tcomplete\tcomplete\tcomplete\t%s\n' "$device" "$inode" "$digest"
    } > "$evidence"
    chmod 0600 "$evidence"
}

new_case() {
    local name="$1"
    local base="$test_directory/$name"
    mkdir -m 0700 "$base" "$base/transaction"
    create_root "$base/root"
    printf '%s\t%s\t%s\t%s\n' "$base/root" "$base/transaction" "$base/inventory.tsv" "$base/evidence.tsv"
}

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    IFS=$'\t' read -r root transaction inventory evidence < <(new_case nonroot)
    mkdir -p "$root/etc/profile.d" "$root/etc/login.defs.d" "$root/etc/pam.d" \
        "$root/etc/vsftpd.conf.d"
    {
        printf '%s\n' "$PATCH_INVENTORY_HEADER"
        printf 'U-30\tfile\t/etc/profile.d/99-kisa-cce-umask.sh\tset_umask\t027\tsubsystem:shell\tCHG-30\n'
        printf 'U-30\tfile\t/etc/login.defs.d/99-kisa-cce-umask.defs\tset_umask\t027\tsubsystem:login_defs\tCHG-30\n'
        printf 'U-30\tfile\t/etc/pam.d/99-kisa-cce-umask\tset_umask\t027\tsubsystem:pam\tCHG-30\n'
        printf 'U-30\tfile\t/etc/vsftpd.conf.d/99-kisa-cce-umask.conf\tset_umask\t027\tsubsystem:ftp-vsftpd\tCHG-30\n'
    } > "$inventory"
    chmod 0600 "$inventory"; write_evidence "$root" "$inventory" "$evidence"
    patch_inventory_plan "$root" "$transaction" "$inventory" "$evidence" || fail "non-root plan failed"
    status=0; patch_inventory_apply >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "non-root apply rejection"
    [ ! -e "$root/etc/profile.d/99-kisa-cce-umask.sh" ] || fail "non-root apply changed target"
    printf 'PASS: non-root inventory transaction guards\n'
    exit 0
fi

IFS=$'\t' read -r unsafe_root unsafe_transaction unsafe_inventory unsafe_evidence < \
    <(new_case unsafe-owner)
mkdir -p "$unsafe_root/home/alice"
printf orphan > "$unsafe_root/home/alice/orphan"
chown 1000:1000 "$unsafe_root/home/alice"
chown 12345:12345 "$unsafe_root/home/alice/orphan"
printf '%s\n' "$PATCH_INVENTORY_HEADER" \
    $'U-15\tfile\t/home/alice/orphan\tset_owner\t0:0\tscan:orphan\tCHG-15' > "$unsafe_inventory"
chmod 0600 "$unsafe_inventory"
write_evidence "$unsafe_root" "$unsafe_inventory" "$unsafe_evidence"
status=0
patch_inventory_plan "$unsafe_root" "$unsafe_transaction" "$unsafe_inventory" "$unsafe_evidence" \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "account-owned inventory parent rejection"
assert_equal 12345:12345 "$(file_uid_gid "$unsafe_root/home/alice/orphan")" \
    "unsafe inventory parent leaves target unchanged"

IFS=$'\t' read -r drift_root drift_transaction drift_inventory drift_evidence < <(new_case parent-drift)
mkdir -p "$drift_root/opt"
printf orphan > "$drift_root/opt/orphan"
chown 12345:12345 "$drift_root/opt/orphan"
printf '%s\n' "$PATCH_INVENTORY_HEADER" \
    $'U-15\tfile\t/opt/orphan\tset_owner\t0:0\tscan:orphan\tCHG-15' > "$drift_inventory"
chmod 0600 "$drift_inventory"
write_evidence "$drift_root" "$drift_inventory" "$drift_evidence"
patch_inventory_plan "$drift_root" "$drift_transaction" "$drift_inventory" "$drift_evidence" ||
    fail "inventory parent-drift plan failed"
chmod 0777 "$drift_root/opt"
status=0
patch_inventory_apply >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "inventory parent mode drift rejection"
assert_equal 12345:12345 "$(file_uid_gid "$drift_root/opt/orphan")" \
    "inventory parent mode drift prevents mutation"

IFS=$'\t' read -r destination_root destination_transaction destination_inventory destination_evidence < \
    <(new_case destination-drift)
mkdir -p "$destination_root/dev"
printf suspicious > "$destination_root/dev/bad"
printf '%s\n' "$PATCH_INVENTORY_HEADER" \
    $'U-26\tfile\t/dev/bad\tquarantine\t/var/lib/kisa-cce-quarantine/test/dev-bad\tcontent:sha256:'"$(file_sha "$destination_root/dev/bad")"$'\tCHG-Q' > "$destination_inventory"
chmod 0600 "$destination_inventory"
write_evidence "$destination_root" "$destination_inventory" "$destination_evidence"
patch_inventory_plan "$destination_root" "$destination_transaction" "$destination_inventory" \
    "$destination_evidence" || fail "inventory destination-drift plan failed"
chmod 0777 "$destination_root/var/lib/kisa-cce-quarantine/test"
status=0
patch_inventory_apply >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "inventory quarantine destination drift rejection"
[ -f "$destination_root/dev/bad" ] &&
    [ ! -e "$destination_root/var/lib/kisa-cce-quarantine/test/dev-bad" ] ||
    fail "unsafe quarantine destination moved the source"

run_u14() {
    local root transaction inventory evidence path_value
    IFS=$'\t' read -r root transaction inventory evidence < <(new_case u14)
    mkdir -p "$root/etc/profile.d" "$root/usr/local/sbin" "$root/usr/local/bin" \
        "$root/usr/sbin" "$root/usr/bin" "$root/sbin" "$root/bin"
    path_value=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    {
        printf '%s\n' "$PATCH_INVENTORY_HEADER"
        printf 'U-14\tprofile\t/etc/profile.d/99-kisa-cce-root-path.sh\tset_root_path\t%s\truntime:path\tCHG-14\n' "$path_value"
        for component in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do
            printf 'U-14\tdirectory\t%s\ttrust_path_component\t-\tcomponent:trusted\tCHG-14\n' "$component"
        done
    } > "$inventory"
    chmod 0600 "$inventory"; write_evidence "$root" "$inventory" "$evidence"
    patch_inventory_plan "$root" "$transaction" "$inventory" "$evidence" || fail "U-14 plan failed: $PATCH_INVENTORY_ERROR_DETAIL"
    patch_inventory_apply || fail "U-14 apply failed"
    [ -f "$root/etc/profile.d/99-kisa-cce-root-path.sh" ] || fail "U-14 profile missing"
    patch_inventory_rollback || fail "U-14 rollback failed"
    [ ! -e "$root/etc/profile.d/99-kisa-cce-root-path.sh" ] || fail "U-14 rollback retained profile"
}

run_u15() {
    local root transaction inventory evidence before
    IFS=$'\t' read -r root transaction inventory evidence < <(new_case u15)
    mkdir -p "$root/opt"; printf orphan > "$root/opt/orphan"; chown 12345:12345 "$root/opt/orphan"
    printf '%s\n' "$PATCH_INVENTORY_HEADER" $'U-15\tfile\t/opt/orphan\tset_owner\t0:0\tscan:orphan\tCHG-15' > "$inventory"
    chmod 0600 "$inventory"; write_evidence "$root" "$inventory" "$evidence"; before="$(file_uid_gid "$root/opt/orphan")"
    patch_inventory_plan "$root" "$transaction" "$inventory" "$evidence" || fail "U-15 plan failed"
    patch_inventory_apply || fail "U-15 apply failed"; assert_equal 0:0 "$(file_uid_gid "$root/opt/orphan")" "U-15 owner"
    patch_inventory_rollback || fail "U-15 rollback failed"; assert_equal "$before" "$(file_uid_gid "$root/opt/orphan")" "U-15 rollback"
}

run_u23() {
    local root transaction inventory evidence
    IFS=$'\t' read -r root transaction inventory evidence < <(new_case u23)
    mkdir -p "$root/usr/bin"; printf tool > "$root/usr/bin/tool"; chmod 4755 "$root/usr/bin/tool"
    printf '%s\n' "$PATCH_INVENTORY_HEADER" $'U-23\tfile\t/usr/bin/tool\tremove_privileged_bits\t06000\tpackage:test\tCHG-23' > "$inventory"
    chmod 0600 "$inventory"; write_evidence "$root" "$inventory" "$evidence"
    patch_inventory_plan "$root" "$transaction" "$inventory" "$evidence" || fail "U-23 plan failed"
    patch_inventory_apply || fail "U-23 apply failed"; assert_equal 755 "$(file_mode "$root/usr/bin/tool")" "U-23 mode"
    patch_inventory_rollback || fail "U-23 rollback failed"; assert_equal 4755 "$(file_mode "$root/usr/bin/tool")" "U-23 rollback"
}

run_quarantine() {
    local criterion="$1" source="$2" destination="$3" name="$4"
    local root transaction inventory evidence identity
    IFS=$'\t' read -r root transaction inventory evidence < <(new_case "$name")
    mkdir -p "$(dirname "$root$source")"; printf suspicious > "$root$source"; identity="$(file_identity "$root$source")"
    printf '%s\n' "$PATCH_INVENTORY_HEADER" \
        "$criterion"$'\tfile\t'"$source"$'\tquarantine\t'"$destination"$'\tcontent:sha256:'"$(file_sha "$root$source")"$'\tCHG-Q' > "$inventory"
    chmod 0600 "$inventory"; write_evidence "$root" "$inventory" "$evidence"
    patch_inventory_plan "$root" "$transaction" "$inventory" "$evidence" || fail "$criterion plan failed: $PATCH_INVENTORY_ERROR_DETAIL"
    patch_inventory_apply || fail "$criterion apply failed"
    [ ! -e "$root$source" ] && [ -f "$root$destination" ] || fail "$criterion quarantine move failed"
    assert_equal "$identity" "$(file_identity "$root$destination")" "$criterion quarantine identity"
    patch_inventory_rollback || fail "$criterion rollback failed"
    [ -f "$root$source" ] && [ ! -e "$root$destination" ] || fail "$criterion rollback move failed"
}

run_u30() {
    local root transaction inventory evidence
    IFS=$'\t' read -r root transaction inventory evidence < <(new_case u30)
    mkdir -p "$root/etc/profile.d" "$root/etc/login.defs.d" "$root/etc/pam.d" "$root/etc/vsftpd.conf.d"
    {
        printf '%s\n' "$PATCH_INVENTORY_HEADER"
        printf 'U-30\tfile\t/etc/profile.d/99-kisa-cce-umask.sh\tset_umask\t027\tsubsystem:shell\tCHG-30\n'
        printf 'U-30\tfile\t/etc/login.defs.d/99-kisa-cce-umask.defs\tset_umask\t027\tsubsystem:login_defs\tCHG-30\n'
        printf 'U-30\tfile\t/etc/pam.d/99-kisa-cce-umask\tset_umask\t027\tsubsystem:pam\tCHG-30\n'
        printf 'U-30\tfile\t/etc/vsftpd.conf.d/99-kisa-cce-umask.conf\tset_umask\t027\tsubsystem:ftp-vsftpd\tCHG-30\n'
    } > "$inventory"
    chmod 0600 "$inventory"; write_evidence "$root" "$inventory" "$evidence"
    patch_inventory_plan "$root" "$transaction" "$inventory" "$evidence" || fail "U-30 plan failed: $PATCH_INVENTORY_ERROR_DETAIL"
    patch_inventory_apply || fail "U-30 apply failed: $PATCH_INVENTORY_ERROR_DETAIL"
    patch_inventory_rollback || fail "U-30 rollback failed"
    [ ! -e "$root/etc/profile.d/99-kisa-cce-umask.sh" ] || fail "U-30 rollback retained file"
}

run_u33() {
    run_quarantine U-33 /opt/.hidden /var/lib/kisa-cce-quarantine/test/hidden u33
}

run_u14
run_u15
run_u23
run_quarantine U-26 /dev/bad /var/lib/kisa-cce-quarantine/test/dev-bad u26
run_u30
run_u33

# Cross-process loader and rollback use a second U-15 transaction.
IFS=$'\t' read -r cross_root cross_transaction cross_inventory cross_evidence < <(new_case cross)
mkdir -p "$cross_root/opt"; printf orphan > "$cross_root/opt/orphan"; chown 12345:12345 "$cross_root/opt/orphan"
printf '%s\n' "$PATCH_INVENTORY_HEADER" $'U-15\tfile\t/opt/orphan\tset_owner\t0:0\tscan:orphan\tCHG-15' > "$cross_inventory"
chmod 0600 "$cross_inventory"; write_evidence "$cross_root" "$cross_inventory" "$cross_evidence"
patch_inventory_plan "$cross_root" "$cross_transaction" "$cross_inventory" "$cross_evidence" || fail "cross plan failed"
patch_inventory_apply || fail "cross apply failed"
patch_inventory_rollback_transaction "$cross_root" "$cross_transaction" || fail "cross rollback failed"
assert_equal 12345:12345 "$(file_uid_gid "$cross_root/opt/orphan")" "cross rollback owner"

# Incomplete evidence never reaches transaction creation.
IFS=$'\t' read -r blocked_root blocked_transaction blocked_inventory blocked_evidence < <(new_case blocked)
mkdir -p "$blocked_root/usr/bin"; printf tool > "$blocked_root/usr/bin/tool"; chmod 4755 "$blocked_root/usr/bin/tool"
printf '%s\n' "$PATCH_INVENTORY_HEADER" $'U-23\tfile\t/usr/bin/tool\tremove_privileged_bits\t06000\tpackage:test\tCHG-23' > "$blocked_inventory"
chmod 0600 "$blocked_inventory"; write_evidence "$blocked_root" "$blocked_inventory" "$blocked_evidence"
sed -i 's/complete\tcomplete\tcomplete/incomplete\tcomplete\tcomplete/' "$blocked_evidence"
status=0; patch_inventory_plan "$blocked_root" "$blocked_transaction" "$blocked_inventory" "$blocked_evidence" >/dev/null 2>&1 || status=$?
assert_equal 3 "$status" "incomplete evidence status"
assert_equal 4755 "$(file_mode "$blocked_root/usr/bin/tool")" "blocked evidence leaves target"

printf 'PASS: inventory transaction\n'
