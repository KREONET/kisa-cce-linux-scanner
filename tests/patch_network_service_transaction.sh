#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck disable=SC2034

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

# shellcheck source=../lib/kisa-cce-patcher/_network-service-transaction.sh disable=SC1091
. "$project_directory/lib/kisa-cce-patcher/_network-service-transaction.sh"

assert_equal $'U-35\nU-39\nU-40\nU-42\nU-45\nU-46\nU-47\nU-48\nU-49\nU-50\nU-51' \
    "$(patch_network_service_supported_criteria)" "supported criteria"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    status=0
    patch_network_service_register_callback policy_verifier /bin/true >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "non-root callback registration"
    PATCH_NETWORK_SERVICE_PLAN_VALID=1
    PATCH_NETWORK_SERVICE_STATE=planned
    status=0
    patch_network_service_apply >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "non-root apply"
    status=0
    patch_network_service_rollback_transaction / /tmp/missing strict >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "non-root rollback"
    printf 'PASS: network service transaction adapter (non-root)\n'
    exit 0
fi

test_directory="$(mktemp -d /root/kisa-cce-network-service.XXXXXXXX)" || exit 2
trap 'chmod -R u+rwX "$test_directory" 2>/dev/null || :; rm -rf -- "$test_directory"' EXIT
chmod 0700 "$test_directory"
callback_directory="$test_directory/callbacks"
mkdir -m 0700 "$callback_directory"

unsafe_callback_directory="$test_directory/unsafe-callbacks"
mkdir -m 0777 "$unsafe_callback_directory"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$unsafe_callback_directory/policy"
chmod 0755 "$unsafe_callback_directory/policy"
status=0
patch_network_service_register_callback policy_verifier \
    "$unsafe_callback_directory/policy" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "replaceable callback parent rejection"

policy_callback="$callback_directory/policy"
cat > "$policy_callback" <<'EOF'
#!/bin/bash
set -u
[ "$#" -eq 6 ] || exit 2
case "$6" in APPROVE-*) exit 0 ;; *) exit 2 ;; esac
EOF

native_callback="$callback_directory/native"
cat > "$native_callback" <<'EOF'
#!/bin/bash
set -u
[ "$#" -eq 7 ] || exit 2
phase="$1"
criterion="$2"
provider="$3"
candidate="$6"
policy="$7"
[ -f "$policy" ] || exit 2
case "$criterion:$provider" in
    U-35:nfs|U-40:nfs)
        grep -Fq 'root_squash' "$candidate" && ! grep -Eq 'no_root_squash|anon(uid|gid)=0' "$candidate"
        ;;
    U-39:nfs) grep -Fq $'intent\tU-39\tnfs\trequired' "$policy" ;;
    U-42:rpcbind) grep -Fq $'rpc-allow\tU-42\trpcbind' "$policy" ;;
    U-45:postfix|U-49:bind) grep -Fq $'advisory\t' "$policy" ;;
    U-46:postfix|U-46:exim) [ -f "$candidate" ] ;;
    U-46:sendmail) grep -Eiq '^O PrivacyOptions=.*restrictqrun' "$candidate" ;;
    U-47:postfix)
        grep -Eq '^mynetworks = [^*]+$' "$candidate" &&
            grep -Fq 'reject_unauth_destination' "$candidate"
        ;;
    U-48:postfix) grep -Fxq 'disable_vrfy_command = yes' "$candidate" ;;
    U-48:sendmail) grep -Eiq '^O PrivacyOptions=.*noexpn.*novrfy|^O PrivacyOptions=.*novrfy.*noexpn' "$candidate" ;;
    U-50:bind) grep -Fq 'allow-transfer {' "$candidate" && ! grep -Eiq 'allow-transfer.*(any|0\.0\.0\.0/0)' "$candidate" ;;
    U-51:bind) grep -Fq 'allow-update { key "update-key";' "$candidate" && ! grep -Eiq 'secret[[:space:]]' "$candidate" ;;
    *) exit 2 ;;
esac
[ "$phase" != fail ]
EOF

runtime_callback="$callback_directory/runtime"
cat > "$runtime_callback" <<EOF
#!/bin/bash
set -u
[ "\$#" -eq 5 ] || exit 2
[ ! -e '$test_directory/runtime-fail' ] || [ "\$1" = rollback ]
EOF

service_callback="$callback_directory/service-graph"
cat > "$service_callback" <<'EOF'
#!/bin/bash
set -u
[ "$#" -eq 7 ] || exit 2
action="$1"
directory="$3"
case "$action" in
    plan)
        mkdir -m 0700 "$directory"
        printf 'enabled\n' > "$directory/state"
        chmod 0600 "$directory/state"
        ;;
    apply) printf 'disabled\n' > "$directory/state" ;;
    verify) grep -Fxq disabled "$directory/state" ;;
    rollback) printf 'enabled\n' > "$directory/state" ;;
    rollback-verify) grep -Fxq enabled "$directory/state" ;;
    *) exit 2 ;;
esac
EOF

chmod 0755 "$callback_directory"/*
patch_network_service_register_callback policy_verifier "$policy_callback" || fail "policy callback registration"
patch_network_service_register_callback native_validator "$native_callback" || fail "native callback registration"
patch_network_service_register_callback runtime_transition "$runtime_callback" || fail "runtime callback registration"
patch_network_service_register_callback service_graph "$service_callback" || fail "service callback registration"

new_fixture() {
    local name="$1"
    local root="$test_directory/$name/root"
    local transaction="$test_directory/$name/transaction"

    mkdir -p "$root/etc/postfix" "$root/etc/mail" "$root/etc/bind" "$root/usr/sbin" "$transaction"
    chmod 0700 "$test_directory/$name" "$root" "$transaction"
    printf '%s\n' '/srv/share *(rw,no_root_squash)' > "$root/etc/exports"
    printf '%s\n' 'myhostname = mail.example' 'mynetworks = 0.0.0.0/0' \
        'smtpd_relay_restrictions = permit' 'disable_vrfy_command = no' > "$root/etc/postfix/main.cf"
    printf '%s\n' 'V8' 'O PrivacyOptions=authwarnings' > "$root/etc/mail/sendmail.cf"
    printf '%s\n' \
        'options {' \
        '    directory "/var/cache/bind";' \
        '    allow-transfer { any; };' \
        '    allow-update { any; };' \
        '};' \
        'zone "example.test" {' \
        '    type primary;' \
        '    file "/var/lib/bind/example.test";' \
        '};' > "$root/etc/bind/named.conf"
    printf '#!/bin/sh\nexit 0\n' > "$root/usr/sbin/postsuper"
    chmod 0644 "$root/etc/exports" "$root/etc/postfix/main.cf" "$root/etc/mail/sendmail.cf" "$root/etc/bind/named.conf"
    chmod 0755 "$root/usr/sbin/postsuper"
    printf '%s\t%s\n' "$root" "$transaction"
}

reset_inputs() {
    patch_network_service_intent_reset
    patch_network_service_input_reset
}

cross_process_rollback() {
    local root="$1"
    local transaction="$2"

    /bin/bash -c '
        set -eu
        . "$1"
        patch_network_service_register_callback policy_verifier "$4"
        patch_network_service_register_callback native_validator "$5"
        patch_network_service_register_callback runtime_transition "$6"
        patch_network_service_register_callback service_graph "$7"
        patch_network_service_rollback_transaction "$2" "$3" strict
    ' network-rollback "$project_directory/lib/kisa-cce-patcher/_network-service-transaction.sh" \
        "$root" "$transaction" "$policy_callback" "$native_callback" "$runtime_callback" "$service_callback"
}

IFS=$'\t' read -r disabled_root disabled_transaction < <(new_fixture disabled)
reset_inputs
patch_network_service_intent_add U-39 disabled nfs APPROVE-DISABLE-NFS
patch_network_service_plan "$disabled_root" "$disabled_transaction" U-39 ||
    fail "disabled plan: $PATCH_NETWORK_SERVICE_ERROR_DETAIL"
state=""
patch_network_service_state_into U-39 state || fail "disabled state lookup"
assert_equal delegated "$state" "disabled delegated state"
patch_network_service_apply || fail "disabled apply: $PATCH_NETWORK_SERVICE_ERROR_DETAIL"
assert_equal disabled "$(< "$disabled_transaction/network-service/delegates/nfs/state")" "delegated disable"
cross_process_rollback "$disabled_root" "$disabled_transaction" || fail "delegated cross-process rollback"
assert_equal enabled "$(< "$disabled_transaction/network-service/delegates/nfs/state")" "delegated rollback"
patch_network_service_rollback_transaction "$disabled_root" "$disabled_transaction" strict ||
    fail "delegated rolled-back idempotency"

IFS=$'\t' read -r required_nfs_root required_nfs_transaction < <(new_fixture required-nfs)
reset_inputs
patch_network_service_intent_add U-39 required nfs APPROVE-NFS-SERVICE-REQUIRED
patch_network_service_plan "$required_nfs_root" "$required_nfs_transaction" U-39 ||
    fail "required NFS service plan: $PATCH_NETWORK_SERVICE_ERROR_DETAIL"
patch_network_service_apply || fail "required NFS service verification: $PATCH_NETWORK_SERVICE_ERROR_DETAIL"

tampered_transaction="$test_directory/tampered-transaction"
cp -a "$disabled_transaction" "$tampered_transaction"
printf 'tamper\n' >> "$tampered_transaction/network-service/policy.tsv"
status=0
patch_network_service_load_transaction "$disabled_root" "$tampered_transaction" >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "policy checksum tamper rejection"

IFS=$'\t' read -r nfs_root nfs_transaction < <(new_fixture nfs)
exports_before="$(< "$nfs_root/etc/exports")"
reset_inputs
patch_network_service_intent_add U-40 required nfs APPROVE-NFS-REQUIRED
patch_network_service_config_set nfs /etc/exports APPROVE-NFS-CONFIG
patch_network_service_nfs_export_add /srv/share 192.0.2.0/24 rw,sync,root_squash APPROVE-NFS-CLIENT
patch_network_service_plan "$nfs_root" "$nfs_transaction" U-40 || fail "NFS plan: $PATCH_NETWORK_SERVICE_ERROR_DETAIL"
assert_contains "$(< "$nfs_transaction/network-service/payloads/target")" \
    '192.0.2.0/24(rw,sync,root_squash)' "NFS rendered policy"
patch_network_service_apply || fail "NFS apply: $PATCH_NETWORK_SERVICE_ERROR_DETAIL"
assert_contains "$(< "$nfs_root/etc/exports")" 'root_squash' "NFS apply content"
cross_process_rollback "$nfs_root" "$nfs_transaction" || fail "NFS rollback"
assert_equal "$exports_before" "$(< "$nfs_root/etc/exports")" "NFS restored content"

IFS=$'\t' read -r anonymous_root anonymous_transaction < <(new_fixture anonymous)
reset_inputs
patch_network_service_intent_add U-35 required nfs APPROVE-ANON-REQUIRED
patch_network_service_config_set nfs /etc/exports APPROVE-ANON-CONFIG
patch_network_service_nfs_export_add /srv/share 198.51.100.10 ro,sync,root_squash APPROVE-ANON-CLIENT
patch_network_service_plan "$anonymous_root" "$anonymous_transaction" U-35 ||
    fail "U-35 NFS plan: $PATCH_NETWORK_SERVICE_ERROR_DETAIL"

IFS=$'\t' read -r rpc_root rpc_transaction < <(new_fixture rpc)
reset_inputs
patch_network_service_intent_add U-42 required rpcbind APPROVE-RPC-REQUIRED
patch_network_service_rpc_allow_add rpcbind 192.0.2.10 APPROVE-RPC-CLIENT
patch_network_service_plan "$rpc_root" "$rpc_transaction" U-42 || fail "RPC plan: $PATCH_NETWORK_SERVICE_ERROR_DETAIL"
patch_network_service_apply || fail "RPC required verification: $PATCH_NETWORK_SERVICE_ERROR_DETAIL"

IFS=$'\t' read -r advisory_root advisory_transaction < <(new_fixture advisory)
reset_inputs
patch_network_service_intent_add U-45 required postfix APPROVE-MAIL-REQUIRED
patch_network_service_advisory_set U-45 postfix 3.10.4 update-required SNAPSHOT-MAIL-20260904 APPROVE-MAIL-ADVISORY
patch_network_service_plan "$advisory_root" "$advisory_transaction" U-45 ||
    fail "mail advisory plan: $PATCH_NETWORK_SERVICE_ERROR_DETAIL"
assert_equal external_action_required "$PATCH_NETWORK_SERVICE_STATE" "mail package update state"
status=0
patch_network_service_apply >/dev/null 2>&1 || status=$?
assert_equal 3 "$status" "mail package update apply refusal"

IFS=$'\t' read -r command_root command_transaction < <(new_fixture command)
command_mode_before="$(stat -c %a "$command_root/usr/sbin/postsuper" 2>/dev/null || stat -f %Lp "$command_root/usr/sbin/postsuper")"
reset_inputs
patch_network_service_intent_add U-46 required postfix APPROVE-COMMAND-REQUIRED
patch_network_service_mail_command_set postfix /usr/sbin/postsuper APPROVE-COMMAND-PATH
patch_network_service_plan "$command_root" "$command_transaction" U-46 ||
    fail "mail command plan: $PATCH_NETWORK_SERVICE_ERROR_DETAIL"
patch_network_service_apply || fail "mail command apply: $PATCH_NETWORK_SERVICE_ERROR_DETAIL"
assert_equal 754 "$(stat -c %a "$command_root/usr/sbin/postsuper" 2>/dev/null || stat -f %Lp "$command_root/usr/sbin/postsuper")" \
    "mail command other-execute removal"
cross_process_rollback "$command_root" "$command_transaction" || fail "mail command rollback"
assert_equal "$command_mode_before" \
    "$(stat -c %a "$command_root/usr/sbin/postsuper" 2>/dev/null || stat -f %Lp "$command_root/usr/sbin/postsuper")" \
    "mail command mode restore"

IFS=$'\t' read -r relay_root relay_transaction < <(new_fixture relay)
postfix_before="$(< "$relay_root/etc/postfix/main.cf")"
reset_inputs
patch_network_service_intent_add U-47 required postfix APPROVE-RELAY-REQUIRED
patch_network_service_config_set postfix /etc/postfix/main.cf APPROVE-RELAY-CONFIG
patch_network_service_mail_relay_client_add 127.0.0.0/8 APPROVE-RELAY-LOOPBACK
patch_network_service_mail_relay_client_add 192.0.2.0/24 APPROVE-RELAY-CLIENT
patch_network_service_plan "$relay_root" "$relay_transaction" U-47 || fail "relay plan: $PATCH_NETWORK_SERVICE_ERROR_DETAIL"
touch "$test_directory/runtime-fail"
status=0
patch_network_service_apply >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "runtime failure apply result"
assert_equal rolled_back "$(< "$relay_transaction/network-service/state")" "automatic rollback state"
assert_equal "$postfix_before" "$(< "$relay_root/etc/postfix/main.cf")" "automatic rollback content"
rm -f "$test_directory/runtime-fail"

IFS=$'\t' read -r enumeration_root enumeration_transaction < <(new_fixture enumeration)
reset_inputs
patch_network_service_intent_add U-48 required sendmail APPROVE-ENUM-REQUIRED
patch_network_service_config_set sendmail /etc/mail/sendmail.cf APPROVE-ENUM-CONFIG
patch_network_service_plan "$enumeration_root" "$enumeration_transaction" U-48 ||
    fail "sendmail enumeration plan: $PATCH_NETWORK_SERVICE_ERROR_DETAIL"
assert_contains "$(< "$enumeration_transaction/network-service/payloads/target")" noexpn "sendmail noexpn"
assert_contains "$(< "$enumeration_transaction/network-service/payloads/target")" novrfy "sendmail novrfy"

IFS=$'\t' read -r dns_advisory_root dns_advisory_transaction < <(new_fixture dns-advisory)
reset_inputs
patch_network_service_intent_add U-49 required bind APPROVE-DNS-REQUIRED
patch_network_service_advisory_set U-49 bind 9.20.11 current SNAPSHOT-DNS-20260904 APPROVE-DNS-ADVISORY
patch_network_service_plan "$dns_advisory_root" "$dns_advisory_transaction" U-49 ||
    fail "DNS advisory plan: $PATCH_NETWORK_SERVICE_ERROR_DETAIL"
patch_network_service_apply || fail "DNS advisory verification: $PATCH_NETWORK_SERVICE_ERROR_DETAIL"

IFS=$'\t' read -r transfer_root transfer_transaction < <(new_fixture transfer)
reset_inputs
patch_network_service_intent_add U-50 required bind APPROVE-TRANSFER-REQUIRED
patch_network_service_config_set bind /etc/bind/named.conf APPROVE-TRANSFER-CONFIG
patch_network_service_bind_transfer_peer_add address 192.0.2.53 APPROVE-TRANSFER-PEER
patch_network_service_plan "$transfer_root" "$transfer_transaction" U-50 ||
    fail "zone transfer plan: $PATCH_NETWORK_SERVICE_ERROR_DETAIL"
assert_contains "$(< "$transfer_transaction/network-service/payloads/target")" 'allow-transfer { 192.0.2.53;' \
    "zone transfer rendered peer"
printf '// drift\n' >> "$transfer_root/etc/bind/named.conf"
status=0
patch_network_service_apply >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "BIND source drift rejection"

IFS=$'\t' read -r update_root update_transaction < <(new_fixture update)
reset_inputs
patch_network_service_intent_add U-51 required bind APPROVE-UPDATE-REQUIRED
patch_network_service_config_set bind /etc/bind/named.conf APPROVE-UPDATE-CONFIG
patch_network_service_bind_tsig_add update-key /etc/bind/keys/update.key APPROVE-TSIG-REFERENCE
patch_network_service_bind_update_key_add update-key APPROVE-UPDATE-KEY
patch_network_service_plan "$update_root" "$update_transaction" U-51 ||
    fail "dynamic update plan: $PATCH_NETWORK_SERVICE_ERROR_DETAIL"
assert_contains "$(< "$update_transaction/network-service/payloads/target")" \
    'include "/etc/bind/keys/update.key";' "TSIG reference"
if grep -Eiq 'secret[[:space:]]' "$update_transaction/network-service/policy.tsv"; then
    fail "TSIG secret value was stored in policy"
fi

IFS=$'\t' read -r unsupported_root unsupported_transaction < <(new_fixture unsupported)
reset_inputs
patch_network_service_intent_add U-47 required exim APPROVE-EXIM-REQUIRED
status=0
patch_network_service_plan "$unsupported_root" "$unsupported_transaction" U-47 >/dev/null 2>&1 || status=$?
assert_equal 1 "$status" "unsupported complex Exim relay provider"

IFS=$'\t' read -r missing_advisory_root missing_advisory_transaction < <(new_fixture missing-advisory)
reset_inputs
patch_network_service_intent_add U-49 required bind APPROVE-MISSING-ADVISORY
status=0
patch_network_service_plan "$missing_advisory_root" "$missing_advisory_transaction" U-49 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "missing advisory snapshot token"

IFS=$'\t' read -r complex_root complex_transaction < <(new_fixture complex-bind)
printf '%s\n' 'include "/etc/bind/other.conf";' >> "$complex_root/etc/bind/named.conf"
reset_inputs
patch_network_service_intent_add U-50 required bind APPROVE-COMPLEX-BIND
patch_network_service_config_set bind /etc/bind/named.conf APPROVE-COMPLEX-CONFIG
patch_network_service_bind_transfer_peer_add address 192.0.2.53 APPROVE-COMPLEX-PEER
status=0
patch_network_service_plan "$complex_root" "$complex_transaction" U-50 >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "unapproved BIND include rejection"

printf 'PASS: network service transaction adapter (root)\n'
