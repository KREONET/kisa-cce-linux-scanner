#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck disable=SC2034

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
    [ "$1" = "$2" ] || fail "$3: expected=[$1] actual=[$2]"
}

assert_contains() {
    case "$1" in *"$2"*) ;; *) fail "$3: missing=[$2]" ;; esac
}

case "${BASH_SOURCE[0]}" in */*) test_parent="${BASH_SOURCE[0]%/*}" ;; *) test_parent=. ;; esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
# shellcheck source=../lib/kisa-cce-patcher/_system-transaction.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_system-transaction.sh"

delegate=""
patch_system_u67_delegate_into delegate || fail "U-67 delegation failed"
assert_equal metadata.u67.v1 "$delegate" "U-67 metadata rule"
validate_u67_log_metadata_v2 || fail "U-67 delegation validator failed"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    nonroot_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-system-nonroot.XXXXXXXX")" || exit 2
    trap 'rm -rf -- "$nonroot_directory"' EXIT
    callback_path="$nonroot_directory/callback"
    printf '%s\n' '#!/bin/sh' 'exit 0' > "$callback_path"
    chmod 0755 "$callback_path"
    status=0
    patch_system_register_callback native_validator "$callback_path" >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "non-root callback trust rejection"
    PATCH_SYSTEM_PLAN_VALID=1
    PATCH_SYSTEM_CRITERION=U-65
    status=0
    patch_system_apply >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "non-root apply rejection"
    printf 'PASS: non-root system transaction guards\n'
    exit 0
fi

test_directory="$(mktemp -d /root/kisa-cce-system-transaction.XXXXXXXX)" || exit 2
trap 'rm -rf -- "$test_directory"' EXIT
chmod 0700 "$test_directory"
callback_directory="$test_directory/callbacks"
unit_state_directory="$test_directory/unit-state"
mkdir -m 0700 "$callback_directory" "$unit_state_directory"

unit_callback="$callback_directory/unit"
cat > "$unit_callback" <<EOF
#!/bin/bash
set -u
state_directory='$unit_state_directory'
action="\$1"
unit="\$2"
state_file="\$state_directory/\${unit//\//_}"
case "\$action" in
    query)
        if [ -f "\$state_file" ]; then cat "\$state_file"; else printf 'disabled\\tinactive\\n'; fi
        ;;
    enable_start) printf 'enabled\\tactive\\n' > "\$state_file" ;;
    restore)
        [ ! -e '$test_directory/unit-restore-fail' ] || exit 2
        printf '%s\\t%s\\n' "\$3" "\$4" > "\$state_file"
        ;;
    *) exit 2 ;;
esac
EOF

policy_callback="$callback_directory/policy"
cat > "$policy_callback" <<'EOF'
#!/bin/bash
set -u
[ "$#" -eq 5 ] || exit 2
case "$1" in
    U-65) [ "$5" = TIME-APPROVAL-1 ] || [ "$5" = TIME-APPROVAL-2 ] || [ "$5" = TIME-APPROVAL-3 ] ;;
    U-66) [ "$5" = LOG-APPROVAL-1 ] || [ "$5" = LOG-APPROVAL-2 ] ;;
    *) exit 2 ;;
esac
EOF

native_callback="$callback_directory/native"
cat > "$native_callback" <<'EOF'
#!/bin/bash
set -u
[ "$#" -eq 6 ] || exit 2
[ -f "$6" ] && [ ! -L "$6" ] || exit 2
case "$1:$3" in
    U-65:chrony|U-65:ntpsec) grep -Eq '^server [^[:space:]]+ iburst$' "$6" ;;
    U-65:systemd-timesyncd) grep -Fxq 'NTP=time.example' "$6" ;;
    U-65:ntpd-rs)
        grep -Fxq 'observation-path = "/run/ntpd-rs/observe"' "$6" &&
            grep -Fxq 'mode = "pool"' "$6" &&
            grep -Fxq 'address = "time.example"' "$6" &&
            grep -Fxq 'count = 4' "$6"
        ;;
    U-66:journald) grep -Fxq 'Storage=persistent' "$6" ;;
    U-66:rsyslog) grep -Fxq 'authpriv.*    /var/log/secure' "$6" ;;
    *) exit 2 ;;
esac
EOF

runtime_callback="$callback_directory/runtime"
cat > "$runtime_callback" <<EOF
#!/bin/bash
set -u
[ ! -e '$test_directory/runtime-fail' ] || exit 2
case "\$1" in
    U-65) [ "\$3" = time.example ] && [ "\$4" = 192.0.2.40 ] ;;
    U-66) [ "\$2" = journald ] || [ "\$2" = rsyslog ] ;;
    *) exit 2 ;;
esac
EOF

signature_callback="$callback_directory/signature"
cat > "$signature_callback" <<'EOF'
#!/bin/bash
set -u
[ "$#" -eq 3 ] || exit 2
grep -Fxq "valid-$1" "$3"
EOF

snapshot_callback="$callback_directory/snapshot"
cat > "$snapshot_callback" <<'EOF'
#!/bin/bash
set -u
IFS= read -r -d '' snapshot || exit 2
IFS= read -r -d '' rollback || exit 2
[ "$snapshot" = immutable-snapshot-42 ] && [ "$rollback" = rollback-token-42 ]
EOF

simulator_callback="$callback_directory/simulator"
cat > "$simulator_callback" <<'EOF'
#!/bin/bash
set -u
[ "$#" -eq 4 ] || exit 2
printf 'manager=%s\nsimulation=complete\nsecurity_updates=0\n' "$1"
EOF

chmod 0755 "$callback_directory"/*
for callback_registration in \
    "policy_verifier:$policy_callback" \
    "unit_query:$unit_callback" "unit_action:$unit_callback" \
    "native_validator:$native_callback" "runtime_probe:$runtime_callback" \
    "signature_verifier:$signature_callback" "snapshot_verifier:$snapshot_callback" \
    "package_simulator:$simulator_callback"; do
    patch_system_register_callback "${callback_registration%%:*}" "${callback_registration#*:}" ||
        fail "callback registration failed: $callback_registration"
done

create_root() {
    local root="$1"

    mkdir -p "$root/etc" "$root/usr/lib/systemd/system"
    chmod 0755 "$root" "$root/etc" "$root/usr" "$root/usr/lib" \
        "$root/usr/lib/systemd" "$root/usr/lib/systemd/system"
}

run_u65_provider() {
    local provider="$1"
    local root="$test_directory/root-$provider"
    local transaction="$test_directory/transaction-$provider"
    local config_path=""
    local status=0

    create_root "$root"
    mkdir -m 0700 "$transaction"
    case "$provider" in
        chrony)
            mkdir -p "$root/etc/chrony/sources.d"
            : > "$root/usr/lib/systemd/system/chrony.service"
            config_path="$root/etc/chrony/sources.d/99-kisa-cce.sources"
            ;;
        ntpsec)
            mkdir -p "$root/etc/ntpsec/ntp.d"
            config_path="$root/etc/ntpsec/ntp.d/99-kisa-cce.conf"
            ;;
        systemd-timesyncd)
            mkdir -p "$root/etc/systemd/timesyncd.conf.d"
            config_path="$root/etc/systemd/timesyncd.conf.d/99-kisa-cce.conf"
            ;;
        ntpd-rs)
            mkdir -p "$root/etc/ntpd-rs"
            config_path="$root/etc/ntpd-rs/ntp.toml"
            printf '%s\n' '[[source]]' 'mode = "server"' 'address = "old.example"' > "$config_path"
            chmod 0644 "$config_path"
            ;;
        *) fail "unexpected provider: $provider" ;;
    esac
    patch_system_u65_plan "$root" "$transaction" "$provider" time.example 192.0.2.40 TIME-APPROVAL-1 ||
        fail "U-65 $provider plan failed: $PATCH_SYSTEM_ERROR_DETAIL"
    assert_equal planned "$PATCH_SYSTEM_STATE" "U-65 $provider planned state"
    awk -F '\t' 'NR == 2 && NF == 15 && $4 ~ /_enable_start$/ && $9 == "disabled" && $10 == "inactive" {found=1} END {exit(found ? 0 : 1)}' \
        "$transaction/system/plan.tsv" || fail "U-65 $provider unit plan is incomplete"
    patch_system_apply || fail "U-65 $provider apply failed: $PATCH_SYSTEM_ERROR_DETAIL"
    assert_equal verified "$PATCH_SYSTEM_STATE" "U-65 $provider verified state"
    validate_u65_time_synchronization_v2 || fail "U-65 $provider validator failed"
    grep -Fq time.example "$config_path" || fail "U-65 $provider source was not installed"
    patch_system_rollback || fail "U-65 $provider rollback failed: $PATCH_SYSTEM_ERROR_DETAIL"
    assert_equal rolled_back "$PATCH_SYSTEM_STATE" "U-65 $provider rollback state"
    if [ "$provider" = ntpd-rs ]; then
        grep -Fq old.example "$config_path" || fail "U-65 ntpd-rs backup was not restored"
    elif [ -e "$config_path" ]; then
        fail "U-65 $provider created file remained after rollback"
    fi
    status=0
    patch_system_apply >/dev/null 2>&1 || status=$?
    [ "$status" -ne 0 ] || fail "U-65 reapplied a rolled-back transaction without replanning"
}

for provider in chrony ntpsec systemd-timesyncd ntpd-rs; do
    run_u65_provider "$provider"
done

run_cross_process_rollback() {
    local root="$1"
    local transaction="$2"
    local mode="$3"

    /bin/bash -c '
        set -u
        PATH=/usr/sbin:/usr/bin:/sbin:/bin
        export PATH
        . "$1"
        patch_system_register_callback unit_query "$2"
        patch_system_register_callback unit_action "$2"
        patch_system_rollback_transaction "$3" "$4" "$5" || {
            status=$?
            printf "rollback error: %s\n" "$PATCH_SYSTEM_ERROR_DETAIL" >&2
            exit "$status"
        }
    ' system-rollback "$project_directory/lib/kisa-cce-patcher/_system-transaction.sh" \
        "$unit_callback" "$root" "$transaction" "$mode"
}

cross_root="$test_directory/root-cross-process"
cross_transaction="$test_directory/transaction-cross-process"
create_root "$cross_root"
mkdir -p "$cross_root/etc/chrony/sources.d"
: > "$cross_root/usr/lib/systemd/system/chrony.service"
printf '%s\n' 'server old.example iburst' > \
    "$cross_root/etc/chrony/sources.d/99-kisa-cce.sources"
chmod 0644 "$cross_root/etc/chrony/sources.d/99-kisa-cce.sources"
mkdir -m 0700 "$cross_transaction"
patch_system_u65_plan "$cross_root" "$cross_transaction" chrony \
    time.example 192.0.2.40 TIME-APPROVAL-1 || fail "cross-process plan failed"
patch_system_apply || fail "cross-process apply failed: $PATCH_SYSTEM_ERROR_DETAIL"
run_cross_process_rollback "$cross_root" "$cross_transaction" strict ||
    fail "cross-process strict rollback failed"
[ "$(cat "$cross_transaction/system/state")" = rolled_back ] ||
    fail "cross-process strict rollback state"
grep -Fxq 'server old.example iburst' \
    "$cross_root/etc/chrony/sources.d/99-kisa-cce.sources" ||
    fail "cross-process strict rollback did not restore backup"

tamper_root="$test_directory/root-cross-tamper"
tamper_transaction="$test_directory/transaction-cross-tamper"
rm -f "$unit_state_directory/chrony.service"
create_root "$tamper_root"
mkdir -p "$tamper_root/etc/chrony/sources.d"
: > "$tamper_root/usr/lib/systemd/system/chrony.service"
mkdir -m 0700 "$tamper_transaction"
patch_system_u65_plan "$tamper_root" "$tamper_transaction" chrony \
    time.example 192.0.2.40 TIME-APPROVAL-1 || fail "tamper plan failed"
patch_system_apply || fail "tamper apply failed"
printf '# tampered\n' >> "$tamper_transaction/system/manifest.tsv"
status=0
run_cross_process_rollback "$tamper_root" "$tamper_transaction" strict >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "tampered recovery manifest rejection"
[ -e "$tamper_root/etc/chrony/sources.d/99-kisa-cce.sources" ] ||
    fail "tampered transaction changed configuration"

drift_root="$test_directory/root-cross-drift"
drift_transaction="$test_directory/transaction-cross-drift"
rm -f "$unit_state_directory/chrony.service"
create_root "$drift_root"
mkdir -p "$drift_root/etc/chrony/sources.d"
: > "$drift_root/usr/lib/systemd/system/chrony.service"
mkdir -m 0700 "$drift_transaction"
patch_system_u65_plan "$drift_root" "$drift_transaction" chrony \
    time.example 192.0.2.40 TIME-APPROVAL-1 || fail "drift plan failed"
patch_system_apply || fail "drift apply failed"
cp "$drift_root/etc/chrony/sources.d/99-kisa-cce.sources" \
    "$drift_root/etc/chrony/sources.d/replacement"
chmod 0644 "$drift_root/etc/chrony/sources.d/replacement"
mv -f "$drift_root/etc/chrony/sources.d/replacement" \
    "$drift_root/etc/chrony/sources.d/99-kisa-cce.sources"
status=0
run_cross_process_rollback "$drift_root" "$drift_transaction" strict >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "cross-process configuration drift rejection"
[ "$(cat "$drift_transaction/system/state")" = verified ] ||
    fail "drift rejection changed transaction state"

retry_root="$test_directory/root-cross-retry"
retry_transaction="$test_directory/transaction-cross-retry"
rm -f "$unit_state_directory/chrony.service"
create_root "$retry_root"
mkdir -p "$retry_root/etc/chrony/sources.d"
: > "$retry_root/usr/lib/systemd/system/chrony.service"
mkdir -m 0700 "$retry_transaction"
patch_system_u65_plan "$retry_root" "$retry_transaction" chrony \
    time.example 192.0.2.40 TIME-APPROVAL-1 || fail "retry plan failed"
patch_system_apply || fail "retry apply failed"
: > "$test_directory/unit-restore-fail"
status=0
run_cross_process_rollback "$retry_root" "$retry_transaction" transition >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "partial rollback failure status"
[ "$(cat "$retry_transaction/system/state")" = rollback_failed ] ||
    fail "partial rollback failure state"
[ ! -e "$retry_root/etc/chrony/sources.d/99-kisa-cce.sources" ] ||
    fail "partial rollback did not restore configuration"
rm -f "$test_directory/unit-restore-fail"
run_cross_process_rollback "$retry_root" "$retry_transaction" transition ||
    fail "partial rollback retry failed"
[ "$(cat "$retry_transaction/system/state")" = rolled_back ] ||
    fail "partial rollback retry state"

policy_rejection_root="$test_directory/root-u65-policy-rejection"
policy_rejection_transaction="$test_directory/transaction-u65-policy-rejection"
create_root "$policy_rejection_root"
mkdir -p "$policy_rejection_root/etc/chrony/sources.d"
: > "$policy_rejection_root/usr/lib/systemd/system/chrony.service"
mkdir -m 0700 "$policy_rejection_transaction"
status=0
patch_system_u65_plan "$policy_rejection_root" "$policy_rejection_transaction" chrony \
    unapproved.example 192.0.2.41 UNAPPROVED >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "U-65 typed policy rejection"
[ ! -e "$policy_rejection_transaction/system" ] ||
    fail "U-65 rejected policy created transaction artifacts"

u65_failure_root="$test_directory/root-u65-failure"
u65_failure_transaction="$test_directory/transaction-u65-failure"
create_root "$u65_failure_root"
mkdir -p "$u65_failure_root/etc/chrony/sources.d"
: > "$u65_failure_root/usr/lib/systemd/system/chrony.service"
mkdir -m 0700 "$u65_failure_transaction"
patch_system_u65_plan "$u65_failure_root" "$u65_failure_transaction" chrony \
    time.example 192.0.2.40 TIME-APPROVAL-2 || fail "U-65 failure plan failed"
: > "$test_directory/runtime-fail"
status=0
patch_system_apply >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "U-65 fresh runtime failure status"
assert_equal rolled_back "$PATCH_SYSTEM_STATE" "U-65 fresh runtime rollback state"
[ ! -e "$u65_failure_root/etc/chrony/sources.d/99-kisa-cce.sources" ] ||
    fail "U-65 failed runtime verification left configuration behind"
rm -f "$test_directory/runtime-fail"

secret_root="$test_directory/root-u65-secret"
secret_transaction="$test_directory/transaction-u65-secret"
create_root "$secret_root"
mkdir -p "$secret_root/etc/ntpd-rs"
printf '%s\n' 'password = "do-not-copy"' > "$secret_root/etc/ntpd-rs/ntp.toml"
chmod 0600 "$secret_root/etc/ntpd-rs/ntp.toml"
mkdir -m 0700 "$secret_transaction"
status=0
patch_system_u65_plan "$secret_root" "$secret_transaction" ntpd-rs \
    time.example 192.0.2.40 TIME-APPROVAL-3 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "U-65 secret-bearing backup rejection"
if grep -R -Fq 'do-not-copy' "$secret_transaction" 2>/dev/null; then
    fail "U-65 transaction copied a secret-bearing configuration"
fi

run_u66_backend() {
    local backend="$1"
    local root="$test_directory/root-u66-$backend"
    local transaction="$test_directory/transaction-u66-$backend"
    local config_path=""
    local selector=""
    local destination=""

    create_root "$root"
    mkdir -m 0700 "$transaction"
    if [ "$backend" = journald ]; then
        mkdir -p "$root/etc/systemd/journald.conf.d"
        config_path="$root/etc/systemd/journald.conf.d/99-kisa-cce.conf"
        selector=persistent
        destination=-
    else
        mkdir -p "$root/etc/rsyslog.d"
        config_path="$root/etc/rsyslog.d/99-kisa-cce.conf"
        selector='authpriv.*'
        destination=/var/log/secure
    fi
    patch_system_u66_plan "$root" "$transaction" "$backend" "$selector" "$destination" LOG-APPROVAL-1 ||
        fail "U-66 $backend plan failed: $PATCH_SYSTEM_ERROR_DETAIL"
    awk -F '\t' 'NR == 2 && NF == 15 && $4 ~ /_enable_start$/ && $9 == "disabled" && $10 == "inactive" {found=1} END {exit(found ? 0 : 1)}' \
        "$transaction/system/plan.tsv" || fail "U-66 $backend unit plan is incomplete"
    patch_system_apply || fail "U-66 $backend apply failed: $PATCH_SYSTEM_ERROR_DETAIL"
    validate_u66_logging_policy_v2 || fail "U-66 $backend validator failed"
    [ -f "$config_path" ] || fail "U-66 $backend configuration was not installed"
    patch_system_rollback || fail "U-66 $backend rollback failed: $PATCH_SYSTEM_ERROR_DETAIL"
    [ ! -e "$config_path" ] || fail "U-66 $backend configuration remained after rollback"
}

run_u66_backend journald
run_u66_backend rsyslog

u66_cross_root="$test_directory/root-u66-cross-process"
u66_cross_transaction="$test_directory/transaction-u66-cross-process"
rm -f "$unit_state_directory/systemd-journald.service"
create_root "$u66_cross_root"
mkdir -p "$u66_cross_root/etc/systemd/journald.conf.d"
mkdir -m 0700 "$u66_cross_transaction"
patch_system_u66_plan "$u66_cross_root" "$u66_cross_transaction" \
    journald persistent - LOG-APPROVAL-1 || fail "U-66 cross-process plan failed"
patch_system_apply || fail "U-66 cross-process apply failed"
run_cross_process_rollback "$u66_cross_root" "$u66_cross_transaction" strict ||
    fail "U-66 cross-process strict rollback failed"
[ ! -e "$u66_cross_root/etc/systemd/journald.conf.d/99-kisa-cce.conf" ] ||
    fail "U-66 cross-process rollback retained configuration"

failure_root="$test_directory/root-u66-failure"
failure_transaction="$test_directory/transaction-u66-failure"
create_root "$failure_root"
mkdir -p "$failure_root/etc/systemd/journald.conf.d"
mkdir -m 0700 "$failure_transaction"
patch_system_u66_plan "$failure_root" "$failure_transaction" journald persistent - LOG-APPROVAL-2 ||
    fail "U-66 failure plan failed"
: > "$test_directory/runtime-fail"
status=0
patch_system_apply >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "U-66 runtime failure status"
assert_equal rolled_back "$PATCH_SYSTEM_STATE" "U-66 automatic rollback state"
[ ! -e "$failure_root/etc/systemd/journald.conf.d/99-kisa-cce.conf" ] ||
    fail "U-66 failed verification left configuration behind"
rm -f "$test_directory/runtime-fail"

evidence_directory="$test_directory/evidence"
mkdir -m 0700 "$evidence_directory"
repository_evidence="$evidence_directory/repository.tsv"
repository_signature="$evidence_directory/repository.sig"
advisory_evidence="$evidence_directory/advisory.tsv"
advisory_signature="$evidence_directory/advisory.sig"
printf '%s\n' 'repository_snapshot=repo-42' > "$repository_evidence"
printf '%s\n' 'valid-repository' > "$repository_signature"
printf '%s\n' 'applicable_security_advisories=0' > "$advisory_evidence"
printf '%s\n' 'valid-advisory' > "$advisory_signature"
chmod 0600 "$evidence_directory"/*
u64_root="$test_directory/root-u64"
u64_transaction="$test_directory/transaction-u64"
create_root "$u64_root"
mkdir -m 0700 "$u64_transaction"
patch_system_u64_plan "$u64_root" "$u64_transaction" apt \
    "$repository_evidence" "$repository_signature" "$advisory_evidence" "$advisory_signature" \
    immutable-snapshot-42 rollback-token-42 || fail "U-64 simulation plan failed: $PATCH_SYSTEM_ERROR_DETAIL"
assert_equal external_action_required "$PATCH_SYSTEM_STATE" "U-64 external state"
awk -F '\t' 'NR == 2 && NF == 15 && $3 == "external_action_required" {found=1} END {exit(found ? 0 : 1)}' \
    "$u64_transaction/system/plan.tsv" || fail "U-64 simulation plan schema"
validate_u64_patch_management_v2 || fail "U-64 validator failed"
request=""
patch_system_u64_external_request_into request || fail "U-64 external request failed"
assert_contains "$request" 'state=external_action_required' "U-64 request state"
assert_contains "$request" 'simulation_sha256=' "U-64 simulation digest"
case "$request" in *immutable-snapshot-42*|*rollback-token-42*) fail "U-64 request leaked a raw token" ;; esac
status=0
patch_system_u64_apply >/dev/null 2>&1 || status=$?
assert_equal 3 "$status" "U-64 package apply boundary"

printf '%s\n' 'invalid-signature' > "$repository_signature"
chmod 0600 "$repository_signature"
invalid_transaction="$test_directory/transaction-u64-invalid"
mkdir -m 0700 "$invalid_transaction"
status=0
patch_system_u64_plan "$u64_root" "$invalid_transaction" apt \
    "$repository_evidence" "$repository_signature" "$advisory_evidence" "$advisory_signature" \
    immutable-snapshot-42 rollback-token-42 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "U-64 invalid signature rejection"

printf 'PASS: U-64 through U-67 system transaction adapters\n'
