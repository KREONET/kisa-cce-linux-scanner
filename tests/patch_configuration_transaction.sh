#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

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

assert_equal() {
    local expected="$1"
    local actual="$2"
    local context="$3"

    [ "$expected" = "$actual" ] || fail "$context: expected=[$expected] actual=[$actual]"
}

assert_contains() {
    local actual="$1"
    local expected="$2"
    local context="$3"

    case "$actual" in *"$expected"*) ;; *) fail "$context: missing=[$expected] actual=[$actual]" ;; esac
}

file_metadata() {
    local path="$1"

    if stat -c '%u:%g:%a' -- "$path" >/dev/null 2>&1; then
        stat -c '%u:%g:%a' -- "$path"
    else
        stat -f '%u:%g:%Lp' "$path"
    fi
}

file_inode() {
    local path="$1"

    if stat -c '%d:%i' -- "$path" >/dev/null 2>&1; then
        stat -c '%d:%i' -- "$path"
    else
        stat -f '%d:%i' "$path"
    fi
}

file_sha256() {
    local path="$1"
    local output=""

    if command -v sha256sum >/dev/null 2>&1; then
        output="$(sha256sum "$path")" || return 2
    else
        output="$(shasum -a 256 "$path")" || return 2
    fi
    printf '%s\n' "${output%% *}"
}

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent=. ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-configuration-patch.XXXXXXXX")" || exit 2
trap 'chmod -R u+rwX "$test_directory" 2>/dev/null || :; rm -rf -- "$test_directory"' EXIT

# shellcheck source=../lib/kisa-cce-patcher/_configuration-transaction.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_configuration-transaction.sh"

new_fixture() {
    local name="$1"
    local root="$test_directory/$name/root"
    local transaction="$test_directory/$name/transaction"

    mkdir -p "$root/etc/profile.d" "$transaction"
    chmod 0700 "$test_directory/$name" "$root" "$transaction"
    printf '%s\n' 'Ubuntu 26.04 LTS \n \l' > "$root/etc/issue"
    printf '%s\n' 'Ubuntu 26.04 LTS' > "$root/etc/issue.net"
    printf '%s\n' 'Welcome to Ubuntu 26.04 LTS' > "$root/etc/motd"
    chmod 0640 "$root/etc/issue"
    chmod 0600 "$root/etc/issue.net"
    chmod 0644 "$root/etc/motd"
    printf '%s\t%s\n' "$root" "$transaction"
}

supported="$(patch_configuration_supported_criteria)"
assert_equal $'U-12\nU-62' "$supported" "supported configuration criteria"

IFS=$'\t' read -r root transaction < <(new_fixture main)
issue_content_before="$(< "$root/etc/issue")"
issue_net_content_before="$(< "$root/etc/issue.net")"
motd_content_before="$(< "$root/etc/motd")"
issue_inode_before="$(file_inode "$root/etc/issue")"

patch_configuration_plan "$root" "$transaction" U-12 U-62 ||
    fail "configuration plan failed: $PATCH_CONFIGURATION_ERROR_DETAIL"
assert_equal 4 "${#PATCH_CONFIGURATION_CRITERIA[@]}" "planned file count"
assert_equal 4 "$PATCH_CONFIGURATION_CHANGE_COUNT" "planned target change count"
assert_equal 0 "$PATCH_CONFIGURATION_COMPLIANT_COUNT" "planned target compliant count"
criterion_state=""
patch_configuration_state_into U-12 criterion_state || fail "U-12 state lookup failed"
assert_equal ready "$criterion_state" "U-12 planned state"
patch_configuration_state_into U-62 criterion_state || fail "U-62 state lookup failed"
assert_equal ready "$criterion_state" "U-62 planned state"
assert_equal absent "${PATCH_CONFIGURATION_BEFORE_STATES[0]}" "new U-12 file state"
assert_equal present "${PATCH_CONFIGURATION_BEFORE_STATES[1]}" "existing issue state"
assert_equal "$issue_inode_before" \
    "${PATCH_CONFIGURATION_BEFORE_DEVICES[1]}:${PATCH_CONFIGURATION_BEFORE_INODES[1]}" \
    "issue backup inode"
manifest="$transaction/configuration/manifest.tsv"
[ -f "$manifest" ] || fail "configuration manifest is absent"
assert_equal 5 "$(wc -l < "$manifest" | tr -d '[:space:]')" "manifest row count"
assert_equal 23 "$(awk -F '\t' 'NR == 2 {print NF}' "$manifest")" "manifest field count"
for artifact in \
    "$manifest" \
    "$transaction/configuration/payloads/000001" \
    "$transaction/configuration/payloads/000002" \
    "$transaction/configuration/payloads/000003" \
    "$transaction/configuration/payloads/000004" \
    "$transaction/configuration/backups/000002" \
    "$transaction/configuration/backups/000003" \
    "$transaction/configuration/backups/000004"; do
    assert_equal 600 "${artifact:+$(file_metadata "$artifact" | awk -F: '{print $3}')}" \
        "private transaction artifact mode"
done
assert_equal "$issue_content_before" \
    "$(< "$transaction/configuration/backups/000002")" "issue content backup"
assert_equal "$(awk -F '\t' 'NR == 3 {print $17}' "$manifest")" \
    "$(file_sha256 "$transaction/configuration/backups/000002")" "issue backup digest"
assert_equal "$issue_net_content_before" \
    "$(< "$transaction/configuration/backups/000003")" "issue.net content backup"
assert_equal "$motd_content_before" \
    "$(< "$transaction/configuration/backups/000004")" "motd content backup"
public_plan="$transaction/configuration-plan.tsv"
patch_configuration_write_plan_tsv "$public_plan" || fail "protected plan write failed"
assert_equal 600 "$(file_metadata "$public_plan" | awk -F: '{print $3}')" "protected plan mode"
assert_equal "$PATCH_CONFIGURATION_PLAN_HEADER" "$(sed -n '1p' "$public_plan")" \
    "protected plan header"
assert_equal 5 "$(wc -l < "$public_plan" | tr -d '[:space:]')" "protected plan row count"
assert_equal 11 "$(awk -F '\t' 'NR == 2 {print NF}' "$public_plan")" \
    "protected plan field count"
assert_equal create "$(awk -F '\t' 'NR == 2 {print $2}' "$public_plan")" \
    "new target plan action"
assert_equal replace "$(awk -F '\t' 'NR == 3 {print $2}' "$public_plan")" \
    "existing target plan action"
assert_equal 0640 "$(awk -F '\t' 'NR == 3 {print $10}' "$public_plan")" \
    "existing issue monotonic mode"
assert_equal 0600 "$(awk -F '\t' 'NR == 4 {print $10}' "$public_plan")" \
    "existing issue.net monotonic mode"
if grep -Fq 'TMOUT=600' "$public_plan" || grep -Fq 'authorized use only' "$public_plan"; then
    fail "protected plan disclosed configuration content"
fi
public_plan_digest="$(file_sha256 "$public_plan")"
status=0
patch_configuration_write_plan_tsv "$public_plan" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "protected plan overwrite rejection"
assert_equal "$public_plan_digest" "$(file_sha256 "$public_plan")" \
    "protected plan remains unchanged after overwrite rejection"
plan_link_target="$transaction/plan-link-target"
printf '%s\n' sentinel > "$plan_link_target"
ln -s plan-link-target "$transaction/plan-link.tsv"
status=0
patch_configuration_write_plan_tsv "$transaction/plan-link.tsv" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "protected plan symlink rejection"
assert_equal sentinel "$(< "$plan_link_target")" "plan symlink target remains unchanged"
ln "$plan_link_target" "$transaction/plan-hardlink.tsv"
status=0
patch_configuration_write_plan_tsv "$transaction/plan-hardlink.tsv" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "protected plan hard-link rejection"
[ ! -e "$root/etc/profile.d/99-kisa-cce-session-timeout.sh" ] ||
    fail "planning created the U-12 target"

duplicate_transaction="$test_directory/duplicate-transaction"
mkdir "$duplicate_transaction"
status=0
patch_configuration_plan "$root" "$duplicate_transaction" U-12 U-12 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "duplicate criterion rejection"
[ ! -e "$duplicate_transaction/configuration" ] || fail "duplicate plan wrote transaction data"

unsupported_transaction="$test_directory/unsupported-transaction"
mkdir "$unsupported_transaction"
status=0
patch_configuration_plan "$root" "$unsupported_transaction" U-01 >/dev/null 2>&1 || status=$?
assert_equal 1 "$status" "unsupported criterion status"
[ ! -e "$unsupported_transaction/configuration" ] || fail "unsupported plan wrote transaction data"

IFS=$'\t' read -r symlink_root symlink_transaction < <(new_fixture symlink)
mv "$symlink_root/etc/issue" "$symlink_root/etc/issue.real"
ln -s issue.real "$symlink_root/etc/issue"
status=0
patch_configuration_plan "$symlink_root" "$symlink_transaction" U-62 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "final symlink rejection"
[ ! -e "$symlink_transaction/configuration" ] || fail "symlink plan retained transaction data"

component_directory="$test_directory/component-symlink"
component_root="$component_directory/root"
component_transaction="$component_directory/transaction"
mkdir -p "$component_root/etc/profile-real" "$component_transaction"
chmod 0700 "$component_directory" "$component_root" "$component_transaction"
ln -s profile-real "$component_root/etc/profile.d"
status=0
patch_configuration_plan "$component_root" "$component_transaction" U-12 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "component symlink rejection"

IFS=$'\t' read -r hardlink_root hardlink_transaction < <(new_fixture hardlink)
ln "$hardlink_root/etc/issue" "$hardlink_root/etc/issue.alias"
status=0
patch_configuration_plan "$hardlink_root" "$hardlink_transaction" U-62 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "hard-link rejection"
[ ! -e "$hardlink_transaction/configuration" ] || fail "hard-link plan retained transaction data"

IFS=$'\t' read -r drift_root drift_transaction < <(new_fixture drift)
patch_configuration_plan "$drift_root" "$drift_transaction" U-12 U-62 ||
    fail "drift plan failed"
mv "$drift_root/etc/issue.net" "$drift_root/etc/issue.net.original"
printf '%s\n' replacement > "$drift_root/etc/issue.net"
chmod 0600 "$drift_root/etc/issue.net"
status=0
patch_configuration_apply >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "inode drift apply rejection"
[ ! -e "$drift_root/etc/profile.d/99-kisa-cce-session-timeout.sh" ] ||
    fail "all-target preflight allowed an earlier mutation"
assert_equal replacement "$(< "$drift_root/etc/issue.net")" "drift target remains untouched"

if [ "${EUID:-$(id -u)}" -eq 0 ]; then
    IFS=$'\t' read -r apply_root apply_transaction < <(new_fixture apply)
    apply_issue_content_before="$(< "$apply_root/etc/issue")"
    apply_issue_net_content_before="$(< "$apply_root/etc/issue.net")"
    apply_motd_content_before="$(< "$apply_root/etc/motd")"
    apply_issue_metadata_before="$(file_metadata "$apply_root/etc/issue")"
    apply_issue_net_metadata_before="$(file_metadata "$apply_root/etc/issue.net")"
    apply_motd_metadata_before="$(file_metadata "$apply_root/etc/motd")"
    patch_configuration_plan "$apply_root" "$apply_transaction" U-12 U-62 ||
        fail "root configuration plan failed: $PATCH_CONFIGURATION_ERROR_DETAIL"
    patch_configuration_apply || fail "configuration apply failed: $PATCH_CONFIGURATION_ERROR_DETAIL"
    assert_equal $'TMOUT=600\nreadonly TMOUT\nexport TMOUT' \
        "$(< "$apply_root/etc/profile.d/99-kisa-cce-session-timeout.sh")" "U-12 content"
    expected_warning='WARNING: This system is for authorized use only. Unauthorized access is prohibited and may be monitored and recorded.'
    assert_equal "$expected_warning" "$(< "$apply_root/etc/issue")" "U-62 issue content"
    assert_equal "$expected_warning" "$(< "$apply_root/etc/issue.net")" "U-62 issue.net content"
    assert_equal "$expected_warning" "$(< "$apply_root/etc/motd")" "U-62 motd content"
    assert_equal 0:0:644 "$(file_metadata "$apply_root/etc/profile.d/99-kisa-cce-session-timeout.sh")" \
        "U-12 metadata"
    assert_equal 0:0:640 "$(file_metadata "$apply_root/etc/issue")" "U-62 issue metadata"
    assert_equal 0:0:600 "$(file_metadata "$apply_root/etc/issue.net")" "U-62 issue.net metadata"
    assert_equal 0:0:644 "$(file_metadata "$apply_root/etc/motd")" "U-62 motd metadata"
    patch_configuration_state_into U-12 criterion_state || fail "applied U-12 state lookup failed"
    assert_equal verified "$criterion_state" "applied U-12 state"
    patch_configuration_state_into U-62 criterion_state || fail "applied U-62 state lookup failed"
    assert_equal verified "$criterion_state" "applied U-62 state"
    for journal in "$apply_transaction"/configuration/journal/*.tsv; do
        assert_equal 0:0:600 "$(file_metadata "$journal")" "journal metadata"
    done

    patch_configuration_rollback ||
        fail "in-process configuration rollback failed: $PATCH_CONFIGURATION_ERROR_DETAIL"
    [ ! -e "$apply_root/etc/profile.d/99-kisa-cce-session-timeout.sh" ] ||
        fail "rollback did not remove the new U-12 file"
    assert_equal "$apply_issue_content_before" "$(< "$apply_root/etc/issue")" "issue rollback content"
    assert_equal "$apply_issue_net_content_before" "$(< "$apply_root/etc/issue.net")" "issue.net rollback content"
    assert_equal "$apply_motd_content_before" "$(< "$apply_root/etc/motd")" "motd rollback content"
    assert_equal "$apply_issue_metadata_before" "$(file_metadata "$apply_root/etc/issue")" \
        "issue rollback metadata"
    assert_equal "$apply_issue_net_metadata_before" "$(file_metadata "$apply_root/etc/issue.net")" \
        "issue.net rollback metadata"
    assert_equal "$apply_motd_metadata_before" "$(file_metadata "$apply_root/etc/motd")" \
        "motd rollback metadata"

    IFS=$'\t' read -r compliant_root compliant_transaction < <(new_fixture compliant)
    printf '%s\n' 'TMOUT=600' 'readonly TMOUT' 'export TMOUT' > \
        "$compliant_root/etc/profile.d/99-kisa-cce-session-timeout.sh"
    printf '%s\n' "$expected_warning" > "$compliant_root/etc/issue"
    printf '%s\n' "$expected_warning" > "$compliant_root/etc/issue.net"
    printf '%s\n' "$expected_warning" > "$compliant_root/etc/motd"
    chmod 0600 "$compliant_root/etc/profile.d/99-kisa-cce-session-timeout.sh" \
        "$compliant_root/etc/issue"
    chmod 0640 "$compliant_root/etc/issue.net"
    chmod 0644 "$compliant_root/etc/motd"
    compliant_profile_inode="$(file_inode "$compliant_root/etc/profile.d/99-kisa-cce-session-timeout.sh")"
    compliant_issue_inode="$(file_inode "$compliant_root/etc/issue")"
    patch_configuration_plan "$compliant_root" "$compliant_transaction" U-12 U-62 ||
        fail "compliant plan failed: $PATCH_CONFIGURATION_ERROR_DETAIL"
    assert_equal 0 "$PATCH_CONFIGURATION_CHANGE_COUNT" "compliant target change count"
    assert_equal 4 "$PATCH_CONFIGURATION_COMPLIANT_COUNT" "compliant target count"
    patch_configuration_state_into U-12 criterion_state || fail "compliant U-12 state lookup failed"
    assert_equal compliant "$criterion_state" "compliant U-12 state"
    patch_configuration_state_into U-62 criterion_state || fail "compliant U-62 state lookup failed"
    assert_equal compliant "$criterion_state" "compliant U-62 state"
    patch_configuration_apply || fail "compliant apply failed: $PATCH_CONFIGURATION_ERROR_DETAIL"
    assert_equal "$compliant_profile_inode" \
        "$(file_inode "$compliant_root/etc/profile.d/99-kisa-cce-session-timeout.sh")" \
        "compliant apply preserves profile inode"
    assert_equal "$compliant_issue_inode" "$(file_inode "$compliant_root/etc/issue")" \
        "compliant apply preserves issue inode"
    patch_configuration_state_into U-62 criterion_state || fail "verified compliant state lookup failed"
    assert_equal verified "$criterion_state" "verified compliant state"
    patch_configuration_rollback || fail "compliant rollback failed"
    assert_equal "$compliant_issue_inode" "$(file_inode "$compliant_root/etc/issue")" \
        "compliant rollback preserves issue inode"

    absent_directory="$test_directory/absent-u62"
    absent_root="$absent_directory/root"
    absent_transaction="$absent_directory/transaction"
    mkdir -p "$absent_root/etc/profile.d" "$absent_transaction"
    chmod 0700 "$absent_directory" "$absent_root" "$absent_transaction"
    patch_configuration_plan "$absent_root" "$absent_transaction" U-62 ||
        fail "absent U-62 plan failed: $PATCH_CONFIGURATION_ERROR_DETAIL"
    assert_equal 3 "$PATCH_CONFIGURATION_CHANGE_COUNT" "absent U-62 target count"
    patch_configuration_apply || fail "absent U-62 apply failed: $PATCH_CONFIGURATION_ERROR_DETAIL"
    for created_path in /etc/issue /etc/issue.net /etc/motd; do
        [ -f "$absent_root$created_path" ] || fail "absent U-62 target was not created: $created_path"
    done
    patch_configuration_rollback || fail "absent U-62 rollback failed"
    for created_path in /etc/issue /etc/issue.net /etc/motd; do
        [ ! -e "$absent_root$created_path" ] || fail "new U-62 target survived rollback: $created_path"
    done

    IFS=$'\t' read -r cross_root cross_transaction < <(new_fixture cross-process)
    cross_issue_before="$(< "$cross_root/etc/issue")"
    patch_configuration_plan "$cross_root" "$cross_transaction" U-12 U-62 ||
        fail "cross-process plan failed"
    patch_configuration_apply || fail "cross-process apply setup failed"
    patch_configuration_reset
    patch_configuration_rollback_transaction "$cross_root" "$cross_transaction" ||
        fail "cross-process rollback failed: $PATCH_CONFIGURATION_ERROR_DETAIL"
    [ ! -e "$cross_root/etc/profile.d/99-kisa-cce-session-timeout.sh" ] ||
        fail "cross-process rollback retained new U-12 file"
    assert_equal "$cross_issue_before" "$(< "$cross_root/etc/issue")" \
        "cross-process issue rollback"

    partial_directory="$test_directory/partial"
    partial_root="$partial_directory/root"
    partial_transaction="$partial_directory/transaction"
    mkdir -p "$partial_root/etc/profile.d" "$partial_transaction"
    chmod 0700 "$partial_directory" "$partial_root" "$partial_transaction"
    printf original-issue > "$partial_root/etc/issue"
    printf original-network-issue > "$partial_root/etc/issue.net"
    chmod 0644 "$partial_root/etc/issue" "$partial_root/etc/issue.net"
    patch_configuration_plan "$partial_root" "$partial_transaction" U-12 U-62 ||
        fail "partial apply plan failed"
    original_move_definition="$(declare -f _patch_configuration_move_into_place)"
    move_count=0
    _patch_configuration_move_into_place() {
        move_count=$((move_count + 1))
        [ "$move_count" -ne 2 ] || return 2
        /usr/bin/mv -f "$1" "$2"
    }
    status=0
    patch_configuration_apply >/dev/null 2>&1 || status=$?
    eval "$original_move_definition"
    assert_equal 2 "$status" "partial apply failure status"
    assert_contains "$PATCH_CONFIGURATION_ERROR_DETAIL" "automatic rollback completed" \
        "partial apply rollback result"
    [ ! -e "$partial_root/etc/profile.d/99-kisa-cce-session-timeout.sh" ] ||
        fail "partial apply rollback retained the new U-12 file"
    assert_equal original-issue "$(< "$partial_root/etc/issue")" \
        "partial apply rollback preserved issue"
    assert_equal original-network-issue "$(< "$partial_root/etc/issue.net")" \
        "partial apply rollback preserved issue.net"

    IFS=$'\t' read -r tamper_root tamper_transaction < <(new_fixture tamper)
    patch_configuration_plan "$tamper_root" "$tamper_transaction" U-12 U-62 ||
        fail "tamper plan failed"
    patch_configuration_apply || fail "tamper apply setup failed"
    printf '%s\n' changed-after-apply > "$tamper_root/etc/issue.net"
    status=0
    patch_configuration_rollback_transaction "$tamper_root" "$tamper_transaction" \
        >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "rollback content drift rejection"
    assert_equal "$expected_warning" "$(< "$tamper_root/etc/issue")" \
        "all-target rollback preflight prevents earlier restoration"
else
    IFS=$'\t' read -r nonroot_root nonroot_transaction < <(new_fixture nonroot)
    nonroot_issue_before="$(< "$nonroot_root/etc/issue")"
    patch_configuration_plan "$nonroot_root" "$nonroot_transaction" U-12 U-62 ||
        fail "non-root plan failed: $PATCH_CONFIGURATION_ERROR_DETAIL"
    status=0
    patch_configuration_apply >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "non-root apply rejection"
    [ ! -e "$nonroot_root/etc/profile.d/99-kisa-cce-session-timeout.sh" ] ||
        fail "non-root apply created the U-12 file"
    assert_equal "$nonroot_issue_before" "$(< "$nonroot_root/etc/issue")" \
        "non-root issue remains unchanged"
fi

printf 'PASS: configuration patch transaction\n'
