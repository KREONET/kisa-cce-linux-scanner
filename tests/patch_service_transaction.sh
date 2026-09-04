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

    case "$actual" in *"$expected"*) ;; *) fail "$context: missing=[$expected]" ;; esac
}

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent=. ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-service-patch.XXXXXXXX")" || exit 2
test_directory="$(CDPATH='' cd -P -- "$test_directory" && pwd)" || exit 2
trap 'chmod -R u+rwX "$test_directory" 2>/dev/null || :; rm -rf -- "$test_directory"' EXIT

# shellcheck source=../lib/kisa-cce-patcher/_service-transaction.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_service-transaction.sh"

assert_equal $'U-34\nU-36\nU-38\nU-41\nU-43\nU-44\nU-52\nU-54\nU-58' \
    "$(patch_service_supported_criteria)" "supported service criteria"
case "$(_patch_service_unit_seeds U-38)" in
    *ntp*|*named*|*snmp*|*smtp*) fail "U-38 legacy-only scope includes a configured service" ;;
esac

patch_service_intent_reset
status=0
patch_service_intent_add U-35 allow-disable TEST-35 >/dev/null 2>&1 || status=$?
assert_equal 1 "$status" "unsupported intent criterion"
status=0
patch_service_intent_add U-34 keep-enabled TEST-34 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "unsupported intent decision"
patch_service_intent_add U-34 allow-disable TEST-34 || fail "valid intent was rejected"
status=0
patch_service_intent_add U-34 allow-disable TEST-34-SECOND >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "duplicate intent rejection"

empty_root="$test_directory/empty/root"
empty_transaction="$test_directory/empty/transaction"
mkdir -p "$empty_root/etc" "$empty_transaction"
chmod 0700 "$empty_root" "$empty_transaction"
_patch_service_systemctl_list() { return 0; }
_patch_service_systemctl_show() { return 1; }
_patch_service_listener_active() { return 1; }
patch_service_plan "$empty_root" "$empty_transaction" U-34 ||
    fail "empty plan failed: $PATCH_SERVICE_ERROR_DETAIL"
state=""
patch_service_state_into U-34 state || fail "empty state lookup failed"
assert_equal compliant "$state" "empty service state"
assert_equal 0 "$PATCH_SERVICE_CHANGE_COUNT" "empty service change count"
[ -f "$empty_transaction/service/manifest.tsv" ] || fail "service manifest is absent"
plan_path="$empty_transaction/service-plan.tsv"
patch_service_write_plan_tsv "$plan_path" || fail "service plan write failed"
assert_equal compliant "$(awk -F '\t' 'NR == 2 {print $3}' "$plan_path")" "public compliant plan"

missing_intent_root="$test_directory/missing-intent/root"
missing_intent_transaction="$test_directory/missing-intent/transaction"
mkdir -p "$missing_intent_root" "$missing_intent_transaction"
chmod 0700 "$missing_intent_root" "$missing_intent_transaction"
patch_service_intent_reset
status=0
patch_service_plan "$missing_intent_root" "$missing_intent_transaction" U-52 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "missing explicit intent"
[ ! -e "$missing_intent_transaction/service" ] || fail "failed intent created transaction data"

multi_root="$test_directory/multi/root"
multi_transaction="$test_directory/multi/transaction"
mkdir -p "$multi_root/etc" "$multi_transaction"
chmod 0700 "$multi_root" "$multi_transaction"
printf '%s\n' \
    'finger stream tcp nowait nobody /usr/sbin/in.fingerd in.fingerd' \
    'telnet stream tcp nowait root /usr/sbin/in.telnetd in.telnetd' > "$multi_root/etc/inetd.conf"
patch_service_intent_reset
patch_service_intent_add U-34 allow-disable MULTI-34 || fail "multi U-34 intent failed"
patch_service_intent_add U-52 allow-disable MULTI-52 || fail "multi U-52 intent failed"
patch_service_plan "$multi_root" "$multi_transaction" U-34 U-52 ||
    fail "multi-criterion plan failed: $PATCH_SERVICE_ERROR_DETAIL"
assert_equal 1 "${#PATCH_SERVICE_FILE_PATHS[@]}" "shared inetd transaction record"
assert_contains "$(< "${PATCH_SERVICE_FILE_PAYLOADS[0]}")" '# kisa-cce-disabled finger' \
    "shared inetd finger payload"
assert_contains "$(< "${PATCH_SERVICE_FILE_PAYLOADS[0]}")" '# kisa-cce-disabled telnet' \
    "shared inetd telnet payload"

unmanaged_root="$test_directory/unmanaged/root"
unmanaged_transaction="$test_directory/unmanaged/transaction"
mkdir -p "$unmanaged_root" "$unmanaged_transaction"
chmod 0700 "$unmanaged_root" "$unmanaged_transaction"
patch_service_intent_reset
patch_service_intent_add U-52 allow-disable TEST-52 || fail "unmanaged-listener intent failed"
_patch_service_listener_active() { return 0; }
status=0
patch_service_plan "$unmanaged_root" "$unmanaged_transaction" U-52 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "unmanaged listener rejection"
assert_contains "$PATCH_SERVICE_ERROR_DETAIL" "listener is active without a managed activation path" \
    "unmanaged listener diagnostic"
[ ! -e "$unmanaged_transaction/service" ] || fail "unmanaged listener retained transaction data"
_patch_service_listener_active() { return 1; }

unmanaged_process_root="$test_directory/unmanaged-process/root"
unmanaged_process_transaction="$test_directory/unmanaged-process/transaction"
mkdir -p "$unmanaged_process_root" "$unmanaged_process_transaction"
chmod 0700 "$unmanaged_process_root" "$unmanaged_process_transaction"
patch_service_intent_reset
patch_service_intent_add U-41 allow-disable TEST-41 || fail "unmanaged-process intent failed"
_patch_service_process_active() { [ "$1" = automount ]; }
status=0
patch_service_plan "$unmanaged_process_root" "$unmanaged_process_transaction" U-41 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "unmanaged process rejection"
assert_contains "$PATCH_SERVICE_ERROR_DETAIL" "process is active without a managed activation path" \
    "unmanaged process diagnostic"
[ ! -e "$unmanaged_process_transaction/service" ] || fail "unmanaged process retained transaction data"
_patch_service_process_active() { return 1; }

symlink_root="$test_directory/symlink/root"
symlink_transaction="$test_directory/symlink/transaction"
mkdir -p "$symlink_root/real-etc" "$symlink_transaction"
chmod 0700 "$symlink_root" "$symlink_transaction"
printf '%s\n' 'finger stream tcp nowait nobody /usr/sbin/in.fingerd in.fingerd' > \
    "$symlink_root/real-etc/inetd.conf"
ln -s real-etc "$symlink_root/etc"
patch_service_intent_reset
patch_service_intent_add U-34 allow-disable TEST-SYMLINK || fail "symlink intent failed"
status=0
patch_service_plan "$symlink_root" "$symlink_transaction" U-34 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "legacy parent symlink rejection"
[ ! -e "$symlink_transaction/service" ] || fail "symlink failure retained transaction data"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    status=0
    patch_service_apply >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "non-root service apply rejection"
    status=0
    patch_service_rollback_transaction "$empty_root" "$empty_transaction" strict >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "non-root cross-process rollback rejection"
    assert_contains "$PATCH_SERVICE_ERROR_DETAIL" "requires root privileges" "non-root rollback diagnostic"
    printf 'PASS: service transaction adapter (non-root)\n'
    exit 0
fi

process_root="$test_directory/process-boundary/root"
process_transaction="$test_directory/process-boundary/transaction"
mkdir -p "$process_root/etc" "$process_transaction"
chmod 0700 "$process_root" "$process_transaction"
printf '%s\n' 'finger stream tcp nowait nobody /usr/sbin/in.fingerd in.fingerd' > \
    "$process_root/etc/inetd.conf"
process_inetd_before="$(< "$process_root/etc/inetd.conf")"
/bin/bash -c '
    set -eu
    . "$1"
    _patch_service_apply_root_allowed() { return 0; }
    _patch_service_systemctl_list() { return 0; }
    _patch_service_systemctl_show() { return 1; }
    _patch_service_listener_active() { return 1; }
    _patch_service_process_active() { return 1; }
    _patch_service_reload_legacy_supervisors() { return 0; }
    patch_service_intent_add U-34 allow-disable PROCESS-34
    patch_service_plan "$2" "$3" U-34
    patch_service_apply
' process-apply "$project_directory/lib/kisa-cce-patcher/_service-transaction.sh" \
    "$process_root" "$process_transaction" || fail "separate-process apply failed"
grep -Fq '# kisa-cce-disabled finger' "$process_root/etc/inetd.conf" ||
    fail "separate-process apply did not disable inetd"
/bin/bash -c '
    set -eu
    . "$1"
    _patch_service_apply_root_allowed() { return 0; }
    _patch_service_systemctl_list() { return 0; }
    _patch_service_systemctl_show() { return 1; }
    _patch_service_listener_active() { return 1; }
    _patch_service_process_active() { return 1; }
    _patch_service_reload_legacy_supervisors() { return 0; }
    patch_service_rollback_transaction "$2" "$3" strict
' process-rollback "$project_directory/lib/kisa-cce-patcher/_service-transaction.sh" \
    "$process_root" "$process_transaction" || fail "separate-process rollback failed"
assert_equal "$process_inetd_before" "$(< "$process_root/etc/inetd.conf")" \
    "separate-process rollback content"
assert_equal rolled_back "$(< "$process_transaction/service/state")" \
    "separate-process rollback state"

root="$test_directory/root-case/root"
transaction="$test_directory/root-case/transaction"
mkdir -p "$root/etc/init.d" "$root/etc/rc3.d" "$root/etc/xinetd.d" "$transaction"
chmod 0700 "$root" "$transaction"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$root/etc/init.d/finger"
chmod 0755 "$root/etc/init.d/finger"
ln -s ../init.d/finger "$root/etc/rc3.d/S20finger"
printf '%s\n' \
    'finger stream tcp nowait nobody /usr/sbin/in.fingerd in.fingerd' \
    '# retained comment' > "$root/etc/inetd.conf"
printf '%s\n' \
    'service finger' \
    '{' \
    '    socket_type = stream' \
    '    disable = no' \
    '}' > "$root/etc/xinetd.d/finger"
chmod 0644 "$root/etc/inetd.conf" "$root/etc/xinetd.d/finger"
inetd_before="$(< "$root/etc/inetd.conf")"
xinetd_before="$(< "$root/etc/xinetd.d/finger")"

declare -A fixture_unit_active=(
    [finger.path]=active
    [finger.timer]=active
    [finger.socket]=active
    [finger@tenant.service]=active
)
declare -A fixture_unit_sub=(
    [finger.path]=waiting
    [finger.timer]=waiting
    [finger.socket]=listening
    [finger@tenant.service]=running
)
declare -A fixture_unit_file=(
    [finger.path]=enabled
    [finger.timer]=enabled
    [finger.socket]=enabled
    [finger@tenant.service]=static
)
declare -A fixture_original_file=(
    [finger.path]=enabled
    [finger.timer]=enabled
    [finger.socket]=enabled
    [finger@tenant.service]=static
)
fixture_sysv_active=1
fixture_listener_active=1
fixture_action_log=""
fixture_fail_mask=0

_patch_service_apply_root_allowed() { return 0; }
_patch_service_systemctl_list() {
    printf '%s\n' finger.path finger.timer finger.socket finger@tenant.service fingerd.socket
}
_patch_service_systemctl_show() {
    local requested="$1"
    local canonical="$requested"
    local names="$requested"
    local triggered_by=""

    [ "$requested" != fingerd.socket ] || canonical=finger.socket
    [ "$canonical" != finger.socket ] || names='finger.socket fingerd.socket'
    [ "$canonical" != finger@tenant.service ] || triggered_by='finger.timer finger.path'
    [ "${fixture_unit_active[$canonical]+present}" = present ] || return 1
    printf 'Id=%s\nNames=%s\nLoadState=loaded\nActiveState=%s\nSubState=%s\nUnitFileState=%s\nFragmentPath=/usr/lib/systemd/system/%s\nDropInPaths=\nTriggers=\nTriggeredBy=%s\n' \
        "$canonical" "$names" "${fixture_unit_active[$canonical]}" "${fixture_unit_sub[$canonical]}" \
        "${fixture_unit_file[$canonical]}" "$canonical" "$triggered_by"
}
_patch_service_systemctl_change() {
    local action="$1"
    local unit="${2:-}"

    fixture_action_log+="${fixture_action_log:+ }$action:$unit"
    case "$action" in
        stop)
            fixture_unit_active["$unit"]=inactive
            fixture_unit_sub["$unit"]=dead
            fixture_listener_active=0
            ;;
        disable) fixture_unit_file["$unit"]=disabled ;;
        mask)
            if [ "$fixture_fail_mask" -eq 1 ]; then
                fixture_fail_mask=0
                return 2
            fi
            fixture_unit_file["$unit"]=masked
            ;;
        unmask) fixture_unit_file["$unit"]="${fixture_original_file[$unit]}" ;;
        enable|enable-runtime) fixture_unit_file["$unit"]=enabled ;;
        start)
            fixture_unit_active["$unit"]=active
            fixture_unit_sub["$unit"]="${unit##*.}"
            case "$unit" in *.socket) fixture_unit_sub["$unit"]=listening ;; *.timer|*.path) fixture_unit_sub["$unit"]=waiting ;; *.service) fixture_unit_sub["$unit"]=running ;; esac
            fixture_listener_active=1
            ;;
        daemon-reload) ;;
        *) return 2 ;;
    esac
}
_patch_service_sysv_is_active() { [ "$fixture_sysv_active" -eq 1 ]; }
_patch_service_sysv_change() {
    case "$1" in stop) fixture_sysv_active=0; fixture_listener_active=0 ;; start) fixture_sysv_active=1; fixture_listener_active=1 ;; *) return 2 ;; esac
}
_patch_service_listener_active() { [ "$fixture_listener_active" -eq 1 ]; }
_patch_service_reload_legacy_supervisors() { return 0; }

patch_service_intent_reset
patch_service_intent_add U-34 allow-disable CHANGE-34 || fail "root intent failed"
patch_service_plan "$root" "$transaction" U-34 || fail "root plan failed: $PATCH_SERVICE_ERROR_DETAIL"
patch_service_state_into U-34 state || fail "root state lookup failed"
assert_equal ready "$state" "root planned state"
[ "$PATCH_SERVICE_CHANGE_COUNT" -ge 7 ] || fail "root plan omitted activation surfaces"
manifest="$transaction/service/manifest.tsv"
assert_contains "$(< "$manifest")" $'systemd\tU-34\tfinger.path' "path activation snapshot"
assert_contains "$(< "$manifest")" 'aliases=finger.socket fingerd.socket' "alias snapshot"
assert_contains "$(< "$manifest")" $'sysv\tU-34\tfinger' "SysV snapshot"
assert_contains "$(< "$manifest")" $'inetd\tU-34' "inetd snapshot"
assert_contains "$(< "$manifest")" $'xinetd\tU-34' "xinetd snapshot"
assert_contains "$(< "$manifest")" $'listener\tU-34\ttcp:79\tactive' "listener snapshot"

patch_service_apply || fail "root apply failed: $PATCH_SERVICE_ERROR_DETAIL"
patch_service_state_into U-34 state || fail "verified state lookup failed"
assert_equal verified "$state" "verified service state"
assert_equal verified "$(< "$transaction/service/state")" "durable verified state"
assert_equal 7 "$(wc -l < "$transaction/service/checksums.sha256" | tr -d '[:space:]')" \
    "immutable checksum inventory"
assert_contains "$fixture_action_log" 'stop:finger.path' "path stopped"
assert_contains "$fixture_action_log" 'stop:finger.timer' "timer stopped"
assert_contains "$fixture_action_log" 'stop:finger.socket' "socket stopped"
assert_contains "$fixture_action_log" 'stop:finger@tenant.service' "template instance stopped"
[ ! -L "$root/etc/rc3.d/S20finger" ] || fail "SysV enablement link remains"
grep -Fq '# kisa-cce-disabled finger stream' "$root/etc/inetd.conf" || fail "inetd entry remains active"
grep -Eq '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$root/etc/xinetd.d/finger" || fail "xinetd entry remains active"

tamper_transaction="$test_directory/root-case/tamper-transaction"
cp -a "$transaction" "$tamper_transaction"
printf '%s\n' tamper >> "$tamper_transaction/service/plan.tsv"
status=0
patch_service_load_transaction "$root" "$tamper_transaction" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "plan checksum tamper rejection"

manifest_transaction="$test_directory/root-case/manifest-transaction"
cp -a "$transaction" "$manifest_transaction"
printf '%s\n' tamper >> "$manifest_transaction/service/manifest.tsv"
status=0
patch_service_load_transaction "$root" "$manifest_transaction" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "manifest checksum tamper rejection"

mode_transaction="$test_directory/root-case/mode-transaction"
cp -a "$transaction" "$mode_transaction"
chmod 0644 "$mode_transaction/service/snapshot.tsv"
status=0
patch_service_load_transaction "$root" "$mode_transaction" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "snapshot mode rejection"

owner_transaction="$test_directory/root-case/owner-transaction"
cp -a "$transaction" "$owner_transaction"
chown 1:1 "$owner_transaction/service/snapshot.tsv"
status=0
patch_service_load_transaction "$root" "$owner_transaction" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "snapshot owner rejection"

link_transaction="$test_directory/root-case/link-transaction"
cp -a "$transaction" "$link_transaction"
ln "$link_transaction/service/snapshot.tsv" "$link_transaction/service/snapshot-link.tsv"
status=0
patch_service_load_transaction "$root" "$link_transaction" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "snapshot hard-link rejection"

mv "$root/etc/inetd.conf" "$root/etc/inetd.conf.applied"
cp "$transaction/service/payloads/000001" "$root/etc/inetd.conf"
chmod 0644 "$root/etc/inetd.conf"
status=0
patch_service_rollback_transaction "$root" "$transaction" strict >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "inode drift rollback rejection"
rm "$root/etc/inetd.conf"
mv "$root/etc/inetd.conf.applied" "$root/etc/inetd.conf"

printf '%s\n' drift >> "$root/etc/inetd.conf"
status=0
patch_service_rollback_transaction "$root" "$transaction" strict >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "content drift rollback rejection"
cp "$transaction/service/payloads/000001" "$root/etc/inetd.conf"
chmod 0644 "$root/etc/inetd.conf"

patch_service_reset
patch_service_rollback_transaction "$root" "$transaction" strict ||
    fail "cross-process rollback failed: $PATCH_SERVICE_ERROR_DETAIL"
patch_service_state_into U-34 state || fail "rollback state lookup failed"
assert_equal rolled_back "$state" "rolled-back service state"
assert_equal "$inetd_before" "$(< "$root/etc/inetd.conf")" "inetd rollback content"
assert_equal "$xinetd_before" "$(< "$root/etc/xinetd.d/finger")" "xinetd rollback content"
[ -L "$root/etc/rc3.d/S20finger" ] || fail "SysV enablement link was not restored"
assert_equal 1 "$fixture_sysv_active" "SysV runtime restoration"
assert_equal 1 "$fixture_listener_active" "listener restoration"
for unit in finger.path finger.timer finger.socket finger@tenant.service; do
    assert_equal active "${fixture_unit_active[$unit]}" "$unit active restoration"
    assert_equal "${fixture_original_file[$unit]}" "${fixture_unit_file[$unit]}" "$unit enablement restoration"
done
patch_service_reset
patch_service_rollback_transaction "$root" "$transaction" strict ||
    fail "rolled-back idempotency failed: $PATCH_SERVICE_ERROR_DETAIL"
assert_equal rolled_back "$PATCH_SERVICE_TRANSACTION_STATE" "idempotent rolled-back state"

partial_transaction="$test_directory/root-case/partial-transaction"
mkdir "$partial_transaction"
chmod 0700 "$partial_transaction"
patch_service_plan "$root" "$partial_transaction" U-34 ||
    fail "partial transition plan failed: $PATCH_SERVICE_ERROR_DETAIL"
_patch_service_set_state applying || fail "partial transition state write failed"
_patch_service_apply_unit 0 || fail "partial unit apply failed"
patch_service_reset
status=0
patch_service_rollback_transaction "$root" "$partial_transaction" strict >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "strict transitional rollback rejection"
patch_service_rollback_transaction "$root" "$partial_transaction" transition ||
    fail "transition rollback retry failed: $PATCH_SERVICE_ERROR_DETAIL"
assert_equal rolled_back "$PATCH_SERVICE_TRANSACTION_STATE" "transition rollback state"

failure_transaction="$test_directory/root-case/failure-transaction"
mkdir "$failure_transaction"
chmod 0700 "$failure_transaction"
fixture_fail_mask=1
patch_service_plan "$root" "$failure_transaction" U-34 ||
    fail "failure rollback plan failed: $PATCH_SERVICE_ERROR_DETAIL"
status=0
patch_service_apply >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "injected apply failure"
patch_service_state_into U-34 state || fail "automatic rollback state lookup failed"
assert_equal rolled_back "$state" "automatic rollback criterion state"
for unit in finger.path finger.timer finger.socket finger@tenant.service; do
    assert_equal active "${fixture_unit_active[$unit]}" "$unit automatic rollback activity"
    assert_equal "${fixture_original_file[$unit]}" "${fixture_unit_file[$unit]}" \
        "$unit automatic rollback enablement"
done

printf 'PASS: service transaction adapter (root)\n'
