#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck disable=SC2034

set -u

PATH=/usr/sbin:/usr/bin:/sbin:/bin
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

case "${BASH_SOURCE[0]}" in */*) test_parent="${BASH_SOURCE[0]%/*}" ;; *) test_parent=. ;; esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
# shellcheck source=../lib/kisa-cce-patcher/_edge-service-transaction.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_edge-service-transaction.sh"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    nonroot_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-edge-nonroot.XXXXXXXX")" || exit 2
    trap 'rm -rf -- "$nonroot_directory"' EXIT
    callback_path="$nonroot_directory/callback"
    printf '%s\n' '#!/bin/sh' 'exit 0' > "$callback_path"
    chmod 0755 "$callback_path"
    status=0
    patch_edge_register_callback apply "$callback_path" >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "non-root callback trust rejection"
    PATCH_EDGE_PLAN_VALID=1
    PATCH_EDGE_STATE=planned
    status=0
    patch_edge_apply >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "non-root apply rejection"
    printf 'PASS: non-root edge-service transaction guards\n'
    exit 0
fi

test_directory="$(mktemp -d /root/kisa-cce-edge-service.XXXXXXXX)" || exit 2
trap 'rm -rf -- "$test_directory"' EXIT
chmod 0700 "$test_directory"
callback_directory="$test_directory/callbacks"
external_state_directory="$test_directory/external-state"
mkdir -m 0700 "$callback_directory" "$external_state_directory"

provider_callback="$callback_directory/provider"
cat > "$provider_callback" <<EOF
#!/bin/bash
set -u
criterion="\$1"
provider="\$2"
case "\$criterion:\$provider" in
    *:*)
        [ ! -e '$test_directory/complex-'"\$criterion"'-'"\$provider" ] || { printf 'complex\n'; exit 0; }
        [ ! -e '$test_directory/absent-'"\$criterion"'-'"\$provider" ] || { printf 'absent\n'; exit 0; }
        printf 'present\n'
        ;;
esac
EOF

policy_callback="$callback_directory/policy"
cat > "$policy_callback" <<'EOF'
#!/bin/bash
set -u
[ "$#" -ge 3 ] || exit 2
case "$2" in APPROVED-*) exit 0 ;; *) exit 2 ;; esac
EOF

native_callback="$callback_directory/native"
cat > "$native_callback" <<'EOF'
#!/bin/bash
set -u
[ "$#" -eq 6 ] || exit 2
payload="$6"
[ -f "$payload" ] && [ ! -L "$payload" ] || exit 2
case "$1:$3" in
    U-01:openssh) grep -Fxq 'PermitRootLogin no' "$payload" ;;
    U-01:telnet) grep -Fxq 'action=disable' "$payload" ;;
    U-28:*|U-56:*) grep -Fq 'managed rules' "$payload" ;;
    U-53:vsftpd) grep -Eq '^ftpd_banner=.' "$payload" ;;
    U-53:proftpd) grep -Fxq 'ServerIdent off' "$payload" ;;
    U-57:vsftpd) grep -Fxq 'userlist_deny=YES' "$payload" ;;
    U-57:proftpd) grep -Fxq 'RootLogin off' "$payload" ;;
    U-59:net-snmp|U-60:net-snmp|U-61:net-snmp)
        grep -Eq '^rouser [^ ]+ authPriv -V [^ ]+$' "$payload" &&
            ! grep -Eiq 'authpass|privpass|password' "$payload"
        ;;
    *) exit 2 ;;
esac
EOF

snapshot_callback="$callback_directory/snapshot"
cat > "$snapshot_callback" <<EOF
#!/bin/bash
set -u
action="\$1"
transaction="\$7"
key="\${transaction##*/}"
state_file='$external_state_directory/'"\$key"'.state'
snapshot_file='$external_state_directory/'"\$key"'.snapshot'
case "\$action" in
    capture)
        printf 'before\n' > "\$snapshot_file"
        printf 'before\n' > "\$state_file"
        sha256sum "\$snapshot_file" | awk '{print \$1}'
        ;;
    verify)
        [ "\$8" = "\$(sha256sum "\$snapshot_file" | awk '{print \$1}')" ]
        grep -Fxq restored "\$state_file"
        ;;
    *) exit 2 ;;
esac
EOF

apply_callback="$callback_directory/apply"
cat > "$apply_callback" <<EOF
#!/bin/bash
set -u
IFS= read -r -d '' secret_reference || exit 2
criterion="\$1"
transaction="\$6"
payload="\$7"
key="\${transaction##*/}"
state_file='$external_state_directory/'"\$key"'.state'
[ -f "\$payload" ] || exit 2
case "\$criterion" in
    U-59|U-60|U-61) case "\$secret_reference" in secret://*) ;; *) exit 2 ;; esac ;;
    *) [ "\$secret_reference" = - ] || exit 2 ;;
esac
if [ -e '$test_directory/apply-partial' ]; then
    printf 'partial\n' > "\$state_file"
    exit 2
fi
printf 'applied\n' > "\$state_file"
sha256sum "\$state_file" | awk '{print \$1}'
EOF

live_callback="$callback_directory/live"
cat > "$live_callback" <<EOF
#!/bin/bash
set -u
transaction="\$5"
key="\${transaction##*/}"
[ ! -e '$test_directory/live-fail' ] || exit 2
grep -Fxq applied '$external_state_directory/'"\$key"'.state'
EOF

rollback_callback="$callback_directory/rollback"
cat > "$rollback_callback" <<EOF
#!/bin/bash
set -u
transaction="\$6"
mode="\$7"
applied_digest="\$9"
key="\${transaction##*/}"
state_file='$external_state_directory/'"\$key"'.state'
current="\$(cat "\$state_file")"
case "\$mode" in
    strict)
        [ "\$current" = applied ] || exit 2
        [ "\$applied_digest" = "\$(sha256sum "\$state_file" | awk '{print \$1}')" ] || exit 2
        ;;
    transition) case "\$current" in applied|partial|restored) ;; *) exit 2 ;; esac ;;
    *) exit 2 ;;
esac
[ ! -e '$test_directory/rollback-partial' ] || {
    printf 'restored\n' > "\$state_file"
    exit 2
}
printf 'restored\n' > "\$state_file"
printf 'restored\n'
EOF

chmod 0755 "$callback_directory"/*
for registration in \
    "provider_probe:$provider_callback" "policy_verifier:$policy_callback" \
    "native_validator:$native_callback" "snapshot:$snapshot_callback" \
    "apply:$apply_callback" "rollback:$rollback_callback" \
    "runtime_probe:$live_callback" "protocol_probe:$live_callback"; do
    patch_edge_register_callback "${registration%%:*}" "${registration#*:}" ||
        fail "callback registration failed: $registration"
done

root="$test_directory/root"
mkdir -p "$root/etc" "$root/usr"
chmod 0755 "$root" "$root/etc" "$root/usr"

run_cross_process_rollback() {
    local transaction="$1"
    local mode="$2"

    /bin/bash -c '
        set -u
        PATH=/usr/sbin:/usr/bin:/sbin:/bin
        export PATH
        . "$1"
        patch_edge_register_callback snapshot "$2"
        patch_edge_register_callback rollback "$3"
        patch_edge_rollback_transaction "$4" "$5" "$6"
    ' edge-rollback "$project_directory/lib/kisa-cce-patcher/_edge-service-transaction.sh" \
        "$snapshot_callback" "$rollback_callback" "$root" "$transaction" "$mode"
}

validate_current() {
    case "$PATCH_EDGE_CRITERION" in
        U-01) validate_u01_remote_root_access_v2 ;;
        U-28) validate_u28_network_access_v2 ;;
        U-53) validate_u53_ftp_banner_v2 ;;
        U-56) validate_u56_ftp_access_v2 ;;
        U-57) validate_u57_ftp_denied_users_v2 ;;
        U-59) validate_u59_snmp_version_v2 ;;
        U-60) validate_u60_snmp_community_v2 ;;
        U-61) validate_u61_snmp_access_v2 ;;
        *) return 2 ;;
    esac
}

run_case() {
    local name="$1"
    shift
    local transaction="$test_directory/transaction-$name"

    mkdir -m 0700 "$transaction"
    "$@" "$transaction" || fail "$name plan failed: $PATCH_EDGE_ERROR_DETAIL"
    assert_equal planned "$PATCH_EDGE_STATE" "$name planned state"
    patch_edge_apply || fail "$name apply failed: $PATCH_EDGE_ERROR_DETAIL"
    assert_equal verified "$PATCH_EDGE_STATE" "$name verified state"
    validate_current || fail "$name public validator failed"
    case "$PATCH_EDGE_CRITERION" in
        U-59|U-60|U-61)
            if grep -R -Fq 'secret://vault/edge-auth' "$transaction"; then
                fail "$name persisted a raw secret reference"
            fi
            ;;
    esac
    run_cross_process_rollback "$transaction" strict || fail "$name cross-process rollback failed"
    assert_equal rolled_back "$(cat "$transaction/edge/state")" "$name rollback state"
}

plan_u01() { local transaction="$1"; patch_edge_u01_plan "$root" "$transaction" openssh APPROVED-U01; }
plan_u01_telnet() { local transaction="$1"; patch_edge_u01_plan "$root" "$transaction" telnet APPROVED-U01-TELNET; }
plan_u28() { local transaction="$1"; patch_edge_u28_plan "$root" "$transaction" nftables 192.0.2.0/24 22 tcp APPROVED-U28; }
plan_u53() { local transaction="$1"; patch_edge_u53_plan "$root" "$transaction" vsftpd 'Authorized users only' APPROVED-U53; }
plan_u56() { local transaction="$1"; patch_edge_u56_plan "$root" "$transaction" vsftpd ufw 198.51.100.0/24 21 tcp APPROVED-U56; }
plan_u57() { local transaction="$1"; patch_edge_u57_plan "$root" "$transaction" proftpd root,daemon APPROVED-U57; }
plan_u59() { local transaction="$1"; patch_edge_u59_plan "$root" "$transaction" monitor secret://vault/edge-auth restricted APPROVED-U59; }
plan_u60() { local transaction="$1"; patch_edge_u60_plan "$root" "$transaction" monitor secret://vault/edge-auth restricted APPROVED-U60; }
plan_u61() { local transaction="$1"; patch_edge_u61_plan "$root" "$transaction" firewalld 203.0.113.0/24 161 udp monitor secret://vault/edge-auth restricted APPROVED-U61; }

for case_name in u01 u01_telnet u28 u53 u56 u57 u59 u60 u61; do
    run_case "$case_name" "plan_$case_name"
done

absent_transaction="$test_directory/transaction-absent"
mkdir -m 0700 "$absent_transaction"
: > "$test_directory/absent-U-53-vsftpd"
patch_edge_u53_plan "$root" "$absent_transaction" vsftpd \
    'Authorized users only' APPROVED-U53 || fail "absent provider plan failed"
assert_equal not_applicable "$PATCH_EDGE_STATE" "absent provider state"
patch_edge_apply || fail "not-applicable apply was not a no-op"
validate_u53_ftp_banner_v2 || fail "not-applicable validator failed"
rm -f "$test_directory/absent-U-53-vsftpd"

complex_transaction="$test_directory/transaction-complex"
mkdir -m 0700 "$complex_transaction"
: > "$test_directory/complex-U-01-openssh"
status=0
patch_edge_u01_plan "$root" "$complex_transaction" openssh APPROVED-U01 \
    >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "complex OpenSSH invocation rejection"
[ ! -e "$complex_transaction/edge" ] || fail "complex provider created a mutation plan"
rm -f "$test_directory/complex-U-01-openssh"

invalid_transaction="$test_directory/transaction-invalid-cidr"
mkdir -m 0700 "$invalid_transaction"
status=0
patch_edge_u28_plan "$root" "$invalid_transaction" nftables \
    999.0.2.0/24 22 tcp APPROVED-U28 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "invalid CIDR rejection"
[ ! -e "$invalid_transaction/edge" ] || fail "invalid CIDR created a mutation plan"

plaintext_transaction="$test_directory/transaction-plaintext"
mkdir -m 0700 "$plaintext_transaction"
status=0
patch_edge_u59_plan "$root" "$plaintext_transaction" monitor \
    literal-value restricted APPROVED-U59 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "plaintext SNMP credential rejection"
[ ! -e "$plaintext_transaction/edge" ] || fail "plaintext credential created a mutation plan"

tamper_transaction="$test_directory/transaction-tamper"
mkdir -m 0700 "$tamper_transaction"
patch_edge_u28_plan "$root" "$tamper_transaction" nftables \
    192.0.2.0/24 22 tcp APPROVED-U28 || fail "tamper plan failed"
patch_edge_apply || fail "tamper apply failed"
printf '# tampered\n' >> "$tamper_transaction/edge/manifest.tsv"
status=0
run_cross_process_rollback "$tamper_transaction" strict >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "tampered manifest rejection"

drift_transaction="$test_directory/transaction-drift"
mkdir -m 0700 "$drift_transaction"
patch_edge_u53_plan "$root" "$drift_transaction" vsftpd \
    'Authorized users only' APPROVED-U53 || fail "drift plan failed"
patch_edge_apply || fail "drift apply failed"
printf 'external-drift\n' > "$external_state_directory/transaction-drift.state"
status=0
run_cross_process_rollback "$drift_transaction" strict >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "external state drift rejection"
assert_equal rollback_failed "$(cat "$drift_transaction/edge/state")" \
    "external state drift transaction state"

retry_transaction="$test_directory/transaction-retry"
mkdir -m 0700 "$retry_transaction"
patch_edge_u56_plan "$root" "$retry_transaction" vsftpd ufw \
    198.51.100.0/24 21 tcp APPROVED-U56 || fail "retry plan failed"
patch_edge_apply || fail "retry apply failed"
: > "$test_directory/rollback-partial"
status=0
run_cross_process_rollback "$retry_transaction" transition >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "partial rollback failure"
assert_equal rollback_failed "$(cat "$retry_transaction/edge/state")" \
    "partial rollback state"
rm -f "$test_directory/rollback-partial"
run_cross_process_rollback "$retry_transaction" transition ||
    fail "partial rollback retry failed"
assert_equal rolled_back "$(cat "$retry_transaction/edge/state")" \
    "partial rollback retry state"

printf 'PASS: U-01/U-28/U-53/U-56/U-57/U-59/U-60/U-61 edge-service transactions\n'
