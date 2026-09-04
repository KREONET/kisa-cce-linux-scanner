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

    case "$actual" in
        *"$expected"*) ;;
        *) fail "$context: missing=[$expected] actual=[$actual]" ;;
    esac
}

file_metadata() {
    local path="$1"

    if stat -c '%d:%i:%u:%g:%a' -- "$path" >/dev/null 2>&1; then
        stat -c '%d:%i:%u:%g:%a' -- "$path"
    else
        stat -f '%d:%i:%u:%g:%Lp' "$path"
    fi
}

file_mode() {
    local path="$1"

    if stat -c '%a' -- "$path" >/dev/null 2>&1; then
        stat -c '%a' -- "$path"
    else
        stat -f '%Lp' "$path"
    fi
}

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent=. ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-patch-engine.XXXXXXXX")" || exit 2
trap 'chmod -R u+rwX "$test_directory" 2>/dev/null || :; rm -rf -- "$test_directory"' EXIT

# shellcheck source=../lib/kisa-cce-patcher/_metadata-rules.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_metadata-rules.sh"
# shellcheck source=../lib/kisa-cce-patcher/_engine.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_engine.sh"

required=""
logical_path=""
owner_uid=""
group_policy=""
maximum_mode=""
state=""
patch_metadata_rule_lookup_into U-16 required logical_path owner_uid group_policy maximum_mode ||
    fail "U-16 rule lookup failed"
assert_equal required "$required" "U-16 required state"
assert_equal /etc/passwd "$logical_path" "U-16 path"
assert_equal 0 "$owner_uid" "U-16 owner"
assert_equal preserve "$group_policy" "U-16 group policy"
assert_equal 0644 "$maximum_mode" "U-16 maximum mode"

patch_metadata_rule_lookup_into U-22 required logical_path owner_uid group_policy maximum_mode ||
    fail "U-22 rule lookup failed"
assert_equal optional "$required" "U-22 optional state"
assert_equal /etc/services "$logical_path" "U-22 path"
assert_equal 0644 "$maximum_mode" "U-22 maximum mode"

status=0
patch_metadata_rule_lookup_into U-01 required logical_path owner_uid group_policy maximum_mode || status=$?
assert_equal 1 "$status" "unsupported rule status"

root="$test_directory/root"
mkdir -p "$root/etc"
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$root/etc/passwd"
printf 'root:*:1:0:99999:7:::\n' > "$root/etc/shadow"
printf '127.0.0.1 localhost\n' > "$root/etc/hosts"
chmod 0666 "$root/etc/passwd" "$root/etc/hosts"
chmod 0640 "$root/etc/shadow"

passwd_before="$(file_metadata "$root/etc/passwd")"
shadow_before="$(file_metadata "$root/etc/shadow")"
hosts_before="$(file_metadata "$root/etc/hosts")"

patch_engine_reset
patch_engine_plan "$root" U-16 U-18 U-19 U-22 U-29 ||
    fail "metadata plan failed: $PATCH_ENGINE_ERROR_DETAIL"
assert_equal 3 "$PATCH_ENGINE_CHANGE_COUNT" "change count"
assert_equal 1 "$PATCH_ENGINE_COMPLIANT_COUNT" "compliant count"
assert_equal 1 "$PATCH_ENGINE_NOT_APPLICABLE_COUNT" "optional absence count"
patch_engine_state_into U-16 state || fail "U-16 state lookup failed"
assert_equal ready "$state" "U-16 plan state"
patch_engine_state_into U-22 state || fail "U-22 state lookup failed"
assert_equal not_applicable "$state" "U-22 plan state"
patch_engine_state_into U-29 state || fail "U-29 state lookup failed"
assert_equal compliant "$state" "U-29 absent-good plan state"

assert_equal "$passwd_before" "$(file_metadata "$root/etc/passwd")" "dry-run passwd metadata"
assert_equal "$shadow_before" "$(file_metadata "$root/etc/shadow")" "dry-run shadow metadata"
assert_equal "$hosts_before" "$(file_metadata "$root/etc/hosts")" "dry-run hosts metadata"

plan_path="$test_directory/plan.tsv"
metadata_path="$test_directory/metadata.tsv"
patch_engine_write_plan_tsv "$plan_path" || fail "plan artifact failed: $PATCH_ENGINE_ERROR_DETAIL"
patch_engine_write_transaction_tsv "$metadata_path" ||
    fail "transaction artifact failed: $PATCH_ENGINE_ERROR_DETAIL"
assert_equal 600 "$(file_mode "$plan_path")" "plan artifact mode"
assert_equal 600 "$(file_mode "$metadata_path")" "transaction artifact mode"
assert_equal 6 "$(wc -l < "$plan_path" | tr -d '[:space:]')" "plan row count"
assert_equal 4 "$(wc -l < "$metadata_path" | tr -d '[:space:]')" "transaction row count"
head -n 1 "$metadata_path" | grep -Fqx "$PATCH_ENGINE_TSV_HEADER" ||
    fail "transaction header differs"
assert_equal 19 "$(awk -F '\t' 'NR == 2 {print NF}' "$metadata_path")" "schema v2 field count"
assert_equal 2 "$(awk -F '\t' 'NR == 2 {print $1}' "$metadata_path")" "schema v2 record"
content_digest="$(awk -F '\t' 'NR == 2 {print $19}' "$metadata_path")"
assert_equal 64 "${#content_digest}" "content digest length"
case "$content_digest" in *[!0-9a-f]*) fail "content digest is not lowercase SHA-256" ;; esac

status=0
patch_engine_write_plan_tsv "$plan_path" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "existing plan is not overwritten"

patch_engine_reset
status=0
patch_engine_plan "$root" U-01 >/dev/null 2>&1 || status=$?
assert_equal 1 "$status" "unsupported plan status"
assert_contains "$PATCH_ENGINE_ERROR_DETAIL" "unsupported patch criterion" "unsupported plan detail"

missing_root="$test_directory/missing-root"
mkdir -p "$missing_root/etc"
patch_engine_reset
status=0
patch_engine_plan "$missing_root" U-16 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "required path absence"
assert_contains "$PATCH_ENGINE_ERROR_DETAIL" "required regular file is absent" "required absence detail"

symlink_root="$test_directory/symlink-root"
mkdir -p "$symlink_root/etc" "$symlink_root/targets"
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$symlink_root/targets/passwd"
ln -s ../targets/passwd "$symlink_root/etc/passwd"
patch_engine_reset
status=0
patch_engine_plan "$symlink_root" U-16 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "final symlink rejection"
assert_contains "$PATCH_ENGINE_ERROR_DETAIL" "path is unsafe" "final symlink detail"

component_symlink_root="$test_directory/component-symlink-root"
mkdir -p "$component_symlink_root/real-etc"
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$component_symlink_root/real-etc/passwd"
ln -s real-etc "$component_symlink_root/etc"
patch_engine_reset
status=0
patch_engine_plan "$component_symlink_root" U-16 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "component symlink rejection"

hardlink_root="$test_directory/hardlink-root"
mkdir -p "$hardlink_root/etc" "$hardlink_root/alias"
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$hardlink_root/etc/passwd"
ln "$hardlink_root/etc/passwd" "$hardlink_root/alias/passwd"
patch_engine_reset
status=0
patch_engine_plan "$hardlink_root" U-16 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "hard-link rejection"
assert_contains "$PATCH_ENGINE_ERROR_DETAIL" "hard-linked targets" "hard-link detail"

untrusted_parent="$test_directory/untrusted-parent"
untrusted_root="$untrusted_parent/root"
mkdir -p "$untrusted_root/etc"
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$untrusted_root/etc/passwd"
chmod 0777 "$untrusted_parent"
status=0
patch_engine_root_is_trusted "$untrusted_root" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "group-writable root ancestor rejection"
patch_engine_reset
status=0
patch_engine_plan "$untrusted_root" U-16 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "plan rejects a group-writable root ancestor"
chmod 1777 "$untrusted_parent"
status=0
patch_engine_root_is_trusted "$untrusted_root" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "unapproved sticky root ancestor rejection"
chmod 0700 "$untrusted_parent"

root_trust_drift_parent="$test_directory/root-trust-drift-parent"
root_trust_drift_root="$root_trust_drift_parent/root"
mkdir -p "$root_trust_drift_root/etc"
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$root_trust_drift_root/etc/passwd"
chmod 0666 "$root_trust_drift_root/etc/passwd"
patch_engine_reset
patch_engine_plan "$root_trust_drift_root" U-16 || fail "root trust drift plan failed"
root_trust_metadata="$test_directory/root-trust-metadata.tsv"
patch_engine_write_transaction_tsv "$root_trust_metadata" || fail "root trust transaction failed"
chmod 0777 "$root_trust_drift_parent"
status=0
patch_engine_apply >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "apply revalidates root ancestor trust"
assert_contains "$PATCH_ENGINE_ERROR_DETAIL" "apply preflight" "root trust drift detail"
assert_equal 666 "$(file_mode "$root_trust_drift_root/etc/passwd")" "root trust drift prevents mutation"
chmod 0700 "$root_trust_drift_parent"

SCRATCH_DIRECTORY="$test_directory/engine-scratch"
mkdir -p "$SCRATCH_DIRECTORY"
chmod 0700 "$SCRATCH_DIRECTORY"

cron_root="$test_directory/cron-root"
mkdir -p "$cron_root/usr/bin" "$cron_root/etc/cron.daily"
printf '#!/bin/sh\nexit 0\n' > "$cron_root/usr/bin/crontab"
printf '#!/bin/sh\nexit 0\n' > "$cron_root/usr/bin/at"
printf 'SHELL=/bin/sh\n' > "$cron_root/etc/crontab"
printf '#!/bin/sh\nexit 0\n' > "$cron_root/etc/cron.daily/package-job"
chmod 4755 "$cron_root/usr/bin/crontab"
chmod 0755 "$cron_root/usr/bin/at" "$cron_root/etc/cron.daily/package-job"
chmod 0644 "$cron_root/etc/crontab"
cron_crontab_before="$(file_metadata "$cron_root/usr/bin/crontab")"
cron_at_before="$(file_metadata "$cron_root/usr/bin/at")"
cron_file_before="$(file_metadata "$cron_root/etc/crontab")"
cron_job_before="$(file_metadata "$cron_root/etc/cron.daily/package-job")"
patch_engine_reset
patch_engine_plan "$cron_root" U-37 || fail "U-37 multi-target plan failed: $PATCH_ENGINE_ERROR_DETAIL"
patch_engine_state_into U-37 state || fail "U-37 aggregate state lookup failed"
assert_equal ready "$state" "U-37 aggregate plan state"
assert_equal 4 "$PATCH_ENGINE_CHANGE_COUNT" "U-37 target change count"
cron_plan="$test_directory/u37-plan.tsv"
cron_metadata="$test_directory/u37-metadata.tsv"
patch_engine_write_plan_tsv "$cron_plan" || fail "U-37 plan artifact failed"
patch_engine_write_transaction_tsv "$cron_metadata" || fail "U-37 transaction artifact failed"
assert_equal 5 "$(wc -l < "$cron_plan" | tr -d '[:space:]')" "U-37 plan row count"
assert_equal 5 "$(wc -l < "$cron_metadata" | tr -d '[:space:]')" "U-37 transaction row count"
assert_equal 4 "$(awk -F '\t' '$2 == "U-37" {seen[$5]++} END {for (path in seen) if (seen[path] == 1) count++; print count+0}' "$cron_plan")" \
    "U-37 unique target count"
assert_equal "$cron_crontab_before" "$(file_metadata "$cron_root/usr/bin/crontab")" "U-37 dry-run command metadata"
assert_equal "$cron_job_before" "$(file_metadata "$cron_root/etc/cron.daily/package-job")" "U-37 dry-run related metadata"

cron_symlink_root="$test_directory/cron-symlink-root"
mkdir -p "$cron_symlink_root/etc/cron.daily" "$cron_symlink_root/etc/cron-targets"
printf '#!/bin/sh\nexit 0\n' > "$cron_symlink_root/etc/cron-targets/package-job"
ln -s ../cron-targets/package-job "$cron_symlink_root/etc/cron.daily/package-job"
patch_engine_reset
status=0
patch_engine_plan "$cron_symlink_root" U-37 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "U-37 symlink rejection"

log_root="$test_directory/log-root"
mkdir -p "$log_root/var/log/archive"
printf 'failed login\n' > "$log_root/var/log/btmp"
printf 'login record\n' > "$log_root/var/log/lastlog"
chmod 0755 "$log_root/var/log"
chmod 0777 "$log_root/var/log/archive"
chmod 0660 "$log_root/var/log/btmp"
chmod 0664 "$log_root/var/log/lastlog"
log_directory_before="$(file_metadata "$log_root/var/log/archive")"
log_btmp_before="$(file_metadata "$log_root/var/log/btmp")"
log_lastlog_before="$(file_metadata "$log_root/var/log/lastlog")"
patch_engine_reset
patch_engine_plan "$log_root" U-67 || fail "U-67 multi-target plan failed: $PATCH_ENGINE_ERROR_DETAIL"
patch_engine_state_into U-67 state || fail "U-67 aggregate state lookup failed"
assert_equal ready "$state" "U-67 aggregate plan state"
if [ "${EUID:-$(id -u)}" -eq 0 ]; then
    assert_equal 3 "$PATCH_ENGINE_CHANGE_COUNT" "U-67 target change count"
    assert_equal 1 "$PATCH_ENGINE_COMPLIANT_COUNT" "U-67 compliant directory count"
else
    assert_equal 4 "$PATCH_ENGINE_CHANGE_COUNT" "U-67 non-root target change count"
    assert_equal 0 "$PATCH_ENGINE_COMPLIANT_COUNT" "U-67 non-root compliant count"
fi
log_plan="$test_directory/u67-plan.tsv"
log_metadata="$test_directory/u67-metadata.tsv"
patch_engine_write_plan_tsv "$log_plan" || fail "U-67 plan artifact failed"
patch_engine_write_transaction_tsv "$log_metadata" || fail "U-67 transaction artifact failed"
assert_equal 5 "$(wc -l < "$log_plan" | tr -d '[:space:]')" "U-67 plan row count"
assert_equal "$((PATCH_ENGINE_CHANGE_COUNT + 1))" \
    "$(wc -l < "$log_metadata" | tr -d '[:space:]')" "U-67 transaction row count"
assert_equal "$log_directory_before" "$(file_metadata "$log_root/var/log/archive")" "U-67 dry-run directory metadata"
assert_equal "$log_btmp_before" "$(file_metadata "$log_root/var/log/btmp")" "U-67 dry-run file metadata"

log_symlink_root="$test_directory/log-symlink-root"
mkdir -p "$log_symlink_root/var/log"
printf 'log\n' > "$log_symlink_root/var/log/application.log"
ln -s application.log "$log_symlink_root/var/log/current"
patch_engine_reset
status=0
patch_engine_plan "$log_symlink_root" U-67 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "U-67 symlink rejection"

log_hardlink_root="$test_directory/log-hardlink-root"
mkdir -p "$log_hardlink_root/var/log"
printf 'log\n' > "$log_hardlink_root/var/log/application.log"
ln "$log_hardlink_root/var/log/application.log" "$log_hardlink_root/var/log/application-copy.log"
patch_engine_reset
status=0
patch_engine_plan "$log_hardlink_root" U-67 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "U-67 hard-link rejection"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    unreadable_cron_root="$test_directory/unreadable-cron-root"
    mkdir -p "$unreadable_cron_root/etc"
    printf 'SHELL=/bin/sh\n' > "$unreadable_cron_root/etc/crontab"
    chmod 0000 "$unreadable_cron_root/etc/crontab"
    patch_engine_reset
    status=0
    patch_engine_plan "$unreadable_cron_root" U-37 >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "U-37 unreadable target rejection"
    chmod 0600 "$unreadable_cron_root/etc/crontab"
fi

if [ "${EUID:-$(id -u)}" -eq 0 ]; then
    patch_engine_reset
    patch_engine_plan "$cron_root" U-37 || fail "U-37 apply plan failed"
    cron_apply_metadata="$test_directory/u37-apply-metadata.tsv"
    patch_engine_write_transaction_tsv "$cron_apply_metadata" || fail "U-37 apply transaction failed"
    patch_engine_apply || fail "U-37 apply failed: $PATCH_ENGINE_ERROR_DETAIL"
    patch_engine_state_into U-37 state || fail "U-37 verified state lookup failed"
    assert_equal verified "$state" "U-37 aggregate verified state"
    assert_equal 750 "$(file_mode "$cron_root/usr/bin/crontab")" "U-37 removes setuid and tightens crontab"
    assert_equal 750 "$(file_mode "$cron_root/usr/bin/at")" "U-37 tightens at command"
    assert_equal 640 "$(file_mode "$cron_root/etc/crontab")" "U-37 tightens crontab file"
    assert_equal 640 "$(file_mode "$cron_root/etc/cron.daily/package-job")" "U-37 tightens related file"
    patch_engine_rollback_transaction "$cron_root" "$cron_apply_metadata" ||
        fail "U-37 rollback failed: $PATCH_ENGINE_ERROR_DETAIL"
    assert_equal "$cron_crontab_before" "$(file_metadata "$cron_root/usr/bin/crontab")" "U-37 command rollback"
    assert_equal "$cron_at_before" "$(file_metadata "$cron_root/usr/bin/at")" "U-37 at rollback"
    assert_equal "$cron_file_before" "$(file_metadata "$cron_root/etc/crontab")" "U-37 file rollback"
    assert_equal "$cron_job_before" "$(file_metadata "$cron_root/etc/cron.daily/package-job")" "U-37 job rollback"

    patch_engine_reset
    patch_engine_plan "$log_root" U-67 || fail "U-67 apply plan failed"
    log_apply_metadata="$test_directory/u67-apply-metadata.tsv"
    patch_engine_write_transaction_tsv "$log_apply_metadata" || fail "U-67 apply transaction failed"
    patch_engine_apply || fail "U-67 apply failed: $PATCH_ENGINE_ERROR_DETAIL"
    patch_engine_state_into U-67 state || fail "U-67 verified state lookup failed"
    assert_equal verified "$state" "U-67 aggregate verified state"
    assert_equal 755 "$(file_mode "$log_root/var/log/archive")" "U-67 removes directory write bits"
    assert_equal 640 "$(file_mode "$log_root/var/log/btmp")" "U-67 tightens btmp"
    assert_equal 644 "$(file_mode "$log_root/var/log/lastlog")" "U-67 tightens lastlog"
    patch_engine_rollback_transaction "$log_root" "$log_apply_metadata" ||
        fail "U-67 rollback failed: $PATCH_ENGINE_ERROR_DETAIL"
    assert_equal "$log_directory_before" "$(file_metadata "$log_root/var/log/archive")" "U-67 directory rollback"
    assert_equal "$log_btmp_before" "$(file_metadata "$log_root/var/log/btmp")" "U-67 btmp rollback"
    assert_equal "$log_lastlog_before" "$(file_metadata "$log_root/var/log/lastlog")" "U-67 lastlog rollback"

    patch_engine_reset
    patch_engine_plan "$root" U-16 U-18 U-19 U-22 U-29 ||
        fail "root apply plan failed: $PATCH_ENGINE_ERROR_DETAIL"
    apply_metadata="$test_directory/apply-metadata.tsv"
    patch_engine_write_transaction_tsv "$apply_metadata" || fail "root transaction write failed"
    patch_engine_apply || fail "metadata apply failed: $PATCH_ENGINE_ERROR_DETAIL"
    assert_equal 644 "$(file_mode "$root/etc/passwd")" "applied passwd mode"
    assert_equal 400 "$(file_mode "$root/etc/shadow")" "applied shadow mode"
    assert_equal 644 "$(file_mode "$root/etc/hosts")" "applied hosts mode"
    patch_engine_state_into U-16 state || fail "applied state lookup failed"
    assert_equal verified "$state" "applied verification state"

    passwd_applied="$(file_metadata "$root/etc/passwd")"
    assert_equal "${passwd_before%%:*}:$(printf '%s' "$passwd_before" | cut -d: -f2):0:$(printf '%s' "$passwd_before" | cut -d: -f4):644" \
        "$passwd_applied" "passwd inode and ownership after apply"

    patch_engine_rollback || fail "in-process rollback failed: $PATCH_ENGINE_ERROR_DETAIL"
    assert_equal "$passwd_before" "$(file_metadata "$root/etc/passwd")" "passwd rollback metadata"
    assert_equal "$shadow_before" "$(file_metadata "$root/etc/shadow")" "shadow rollback metadata"
    assert_equal "$hosts_before" "$(file_metadata "$root/etc/hosts")" "hosts rollback metadata"

    patch_engine_reset
    patch_engine_plan "$root" U-16 || fail "cross-process rollback plan failed"
    rollback_metadata="$test_directory/rollback-metadata.tsv"
    patch_engine_write_transaction_tsv "$rollback_metadata" || fail "rollback transaction write failed"
    patch_engine_apply || fail "cross-process setup apply failed"
    patch_engine_reset
    patch_engine_rollback_transaction "$root" "$rollback_metadata" ||
        fail "cross-process rollback failed: $PATCH_ENGINE_ERROR_DETAIL"
    assert_equal "$passwd_before" "$(file_metadata "$root/etc/passwd")" "cross-process rollback metadata"

    content_drift_root="$test_directory/content-drift-root"
    mkdir -p "$content_drift_root/etc"
    printf 'root:x:0:0:root:/root:/bin/sh\n' > "$content_drift_root/etc/passwd"
    printf 'root:*:1:0:99999:7:::\n' > "$content_drift_root/etc/shadow"
    chmod 0666 "$content_drift_root/etc/passwd"
    chmod 0640 "$content_drift_root/etc/shadow"
    patch_engine_reset
    patch_engine_plan "$content_drift_root" U-16 U-18 || fail "content drift plan failed"
    content_drift_metadata="$test_directory/content-drift-metadata.tsv"
    patch_engine_write_transaction_tsv "$content_drift_metadata" || fail "content drift transaction failed"
    printf 'root:!:1:0:99999:7:::\n' > "$content_drift_root/etc/shadow"
    status=0
    patch_engine_apply >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "apply rejects in-place content drift"
    assert_equal 666 "$(file_mode "$content_drift_root/etc/passwd")" \
        "all-target apply preflight prevents an earlier mutation"

    rollback_content_root="$test_directory/rollback-content-root"
    mkdir -p "$rollback_content_root/etc"
    printf 'root:x:0:0:root:/root:/bin/sh\n' > "$rollback_content_root/etc/passwd"
    printf 'root:*:1:0:99999:7:::\n' > "$rollback_content_root/etc/shadow"
    chmod 0666 "$rollback_content_root/etc/passwd"
    chmod 0640 "$rollback_content_root/etc/shadow"
    patch_engine_reset
    patch_engine_plan "$rollback_content_root" U-16 U-18 || fail "rollback content plan failed"
    rollback_content_metadata="$test_directory/rollback-content-metadata.tsv"
    patch_engine_write_transaction_tsv "$rollback_content_metadata" || fail "rollback content transaction failed"
    patch_engine_apply || fail "rollback content setup apply failed"
    printf 'root:!:1:0:99999:7:::\n' > "$rollback_content_root/etc/shadow"
    status=0
    patch_engine_rollback_transaction "$rollback_content_root" "$rollback_content_metadata" \
        >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "rollback rejects in-place content drift"
    assert_equal 644 "$(file_mode "$rollback_content_root/etc/passwd")" \
        "all-target rollback preflight prevents an earlier restoration"

    transition_root="$test_directory/transition-root"
    mkdir -p "$transition_root/etc" "$transition_root/alias"
    printf 'root:x:0:0:root:/root:/bin/sh\n' > "$transition_root/etc/passwd"
    chmod 0666 "$transition_root/etc/passwd"
    patch_engine_reset
    patch_engine_plan "$transition_root" U-16 || fail "transition state plan failed"
    chmod 0644 "$transition_root/etc/passwd"
    _patch_engine_transition_metadata_matches_index 0 || fail "recorded transition state was rejected"
    ln "$transition_root/etc/passwd" "$transition_root/alias/passwd"
    status=0
    _patch_engine_transition_metadata_matches_index 0 >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "transition state rejects a new hard link"
    rm -f "$transition_root/alias/passwd"
    printf 'changed:x:0:0:root:/root:/bin/sh\n' > "$transition_root/etc/passwd"
    status=0
    _patch_engine_transition_metadata_matches_index 0 >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "transition state rejects content drift"

    allowed_owner_root="$test_directory/allowed-owner-root"
    mkdir -p "$allowed_owner_root/etc"
    printf '%s\n' \
        'root:x:0:0:root:/root:/bin/sh' \
        'bin:x:1:1:bin:/bin:/usr/sbin/nologin' \
        'sys:x:3:3:sys:/dev:/usr/sbin/nologin' > "$allowed_owner_root/etc/passwd"
    printf 'ssh 22/tcp\n' > "$allowed_owner_root/etc/services"
    chown 1:1 "$allowed_owner_root/etc/services"
    chmod 0666 "$allowed_owner_root/etc/services"
    allowed_owner_before="$(file_metadata "$allowed_owner_root/etc/services")"
    patch_engine_reset
    patch_engine_plan "$allowed_owner_root" U-22 ||
        fail "U-22 allowed-owner plan failed: $PATCH_ENGINE_ERROR_DETAIL"
    allowed_owner_metadata="$test_directory/allowed-owner-metadata.tsv"
    patch_engine_write_transaction_tsv "$allowed_owner_metadata" || fail "U-22 transaction write failed"
    patch_engine_apply || fail "U-22 allowed-owner apply failed: $PATCH_ENGINE_ERROR_DETAIL"
    IFS=: read -r _ _ allowed_owner_uid allowed_owner_gid allowed_owner_mode <<< \
        "$(file_metadata "$allowed_owner_root/etc/services")"
    assert_equal 1 "$allowed_owner_uid" "U-22 preserves an allowed bin owner"
    assert_equal 1 "$allowed_owner_gid" "U-22 preserves the group"
    assert_equal 644 "$allowed_owner_mode" "U-22 tightens mode"
    patch_engine_rollback_transaction "$allowed_owner_root" "$allowed_owner_metadata" ||
        fail "U-22 allowed-owner rollback failed: $PATCH_ENGINE_ERROR_DETAIL"
    assert_equal "$allowed_owner_before" "$(file_metadata "$allowed_owner_root/etc/services")" \
        "U-22 allowed-owner rollback metadata"

    patch_engine_reset
    patch_engine_plan "$root" U-16 U-18 || fail "drift rollback plan failed"
    drift_metadata="$test_directory/drift-metadata.tsv"
    patch_engine_write_transaction_tsv "$drift_metadata" || fail "drift transaction write failed"
    patch_engine_apply || fail "drift setup apply failed"
    chmod 0600 "$root/etc/passwd"
    status=0
    patch_engine_rollback_transaction "$root" "$drift_metadata" >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "rollback metadata drift rejection"
    assert_equal 600 "$(file_mode "$root/etc/passwd")" "rollback leaves drift untouched"
    assert_equal 400 "$(file_mode "$root/etc/shadow")" "rollback preflight leaves every target untouched"
    chmod 0666 "$root/etc/passwd"
    patch_engine_rollback_transaction "$root" "$drift_metadata" ||
        fail "rollback after drift correction failed: $PATCH_ENGINE_ERROR_DETAIL"

    patch_engine_reset
    patch_engine_plan "$root" U-16 || fail "inode replacement plan failed"
    replacement_metadata="$test_directory/replacement-metadata.tsv"
    patch_engine_write_transaction_tsv "$replacement_metadata" || fail "replacement transaction write failed"
    mv "$root/etc/passwd" "$root/etc/passwd.original"
    printf 'replacement:x:0:0:replacement:/root:/bin/sh\n' > "$root/etc/passwd"
    chmod 0666 "$root/etc/passwd"
    status=0
    patch_engine_apply >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "apply inode replacement rejection"
    assert_equal 666 "$(file_mode "$root/etc/passwd")" "replacement inode remains untouched"
else
    patch_engine_reset
    patch_engine_plan "$root" U-16 || fail "non-root failure plan failed"
    nonroot_metadata="$test_directory/nonroot-metadata.tsv"
    patch_engine_write_transaction_tsv "$nonroot_metadata" || fail "non-root transaction write failed"
    status=0
    patch_engine_apply >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "non-root owner change fails closed"
    assert_equal "$passwd_before" "$(file_metadata "$root/etc/passwd")" "non-root apply restores metadata"
fi

printf 'PASS: patch engine\n'
