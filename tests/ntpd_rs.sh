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
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-ntpd-rs.XXXXXXXX")" || exit 2
trap 'rm -rf -- "$test_directory"' EXIT

KISA_CCE_VERSION=0.1.0
DATA_DIR="$project_directory/data"
KISA_CCE_LANGUAGE=ko
SCAN_ROOT="$test_directory/root"
RUNTIME_MODE=on
SCRATCH_DIR="$test_directory/scratch"
mkdir -p "$SCAN_ROOT/etc/ntpd-rs" "$SCRATCH_DIR"

# shellcheck source=../lib/kisa-cce-core/_core.sh disable=SC1091
. "$project_directory/lib/kisa-cce-core/_core.sh"
# shellcheck source=../lib/kisa-cce-resolvers/_resolvers.sh disable=SC1091
. "$project_directory/lib/kisa-cce-resolvers/_resolvers.sh"
# shellcheck source=../lib/kisa-cce-checks/_system.sh disable=SC1091
. "$project_directory/lib/kisa-cce-checks/_system.sh"

SCRATCH_DIR="$test_directory/scratch"
PLATFORM_ID=ubuntu
PLATFORM_VERSION=26.04
PLATFORM_NAME='Ubuntu 26.04 LTS'
PLATFORM_FAMILY=debian
PLATFORM_BASE_ID=ubuntu
PLATFORM_BASE_VERSION=26.04

printf '%s\n' \
    '[observability]' \
    'log-level = "info"' \
    '[[source]]' \
    'mode = "pool"' \
    'address = "time.example"' \
    'count = 4' > "$SCAN_ROOT/etc/ntpd-rs/ntp.toml"

config_facts="$(ntpd_rs_config_evidence)" || fail "valid ntpd-rs configuration was rejected"
assert_contains "$config_facts" 'persistent_config=/etc/ntpd-rs/ntp.toml' "ntpd-rs config path"
assert_contains "$config_facts" 'configured_sources=1' "ntpd-rs config source count"
assert_contains "$config_facts" 'configured_source=time.example' "ntpd-rs configured source"

printf '%s\n' \
    '[observability]' \
    'observation-path = "/run/ntpd-rs/observe"' \
    '[[source]]' \
    'mode = "nts-pool"' \
    'address = "secure-time.example"' \
    'count = 4' > "$SCAN_ROOT/etc/ntpd-rs/ntp.toml"
config_facts="$(ntpd_rs_config_evidence)" || fail "valid ntpd-rs nts-pool configuration was rejected"
assert_contains "$config_facts" 'configured_mode_1=nts-pool' "ntpd-rs nts-pool mode"

printf '%s\n' \
    '[observability]' \
    'observation-path = "/run/ntpd-rs/observe"' \
    '[[source]]' \
    'mode = "server"' \
    'address = "[2001:db8::1]:123"' \
    '[synchronization]' \
    'minimum-agreeing-sources = 1' > "$SCAN_ROOT/etc/ntpd-rs/ntp.toml"
ntpd_rs_config_evidence >/dev/null || fail "valid bracketed IPv6 ntpd-rs source was rejected"

printf '%s\n' \
    '[[source]]' \
    'address = "time.example"' \
    'address = "duplicate.example"' > "$SCAN_ROOT/etc/ntpd-rs/ntp.toml"
status=0
ntpd_rs_config_evidence >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "duplicate ntpd-rs source key"

printf '%s\n' '[[source]]' 'address = "time.example"' 'malformed directive' \
    > "$SCAN_ROOT/etc/ntpd-rs/ntp.toml"
status=0
ntpd_rs_config_evidence >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "malformed ntpd-rs TOML structure"

printf '%s\n' \
    '[[source]]' \
    'mode = "pool"' \
    'address = "time.example"' \
    'count = 4' \
    'bogus-key = "must-not-be-ignored"' > "$SCAN_ROOT/etc/ntpd-rs/ntp.toml"
status=0
ntpd_rs_config_evidence >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "unknown ntpd-rs source key"

printf '%s\n' \
    '[[source]]' \
    'mode = "pool"' \
    'address = "time.example"' \
    'count = 4' > "$SCAN_ROOT/etc/ntpd-rs/ntp.toml"

control_command="$test_directory/ntp-ctl"
printf '%s\n' \
    '#!/bin/sh' \
    '[ "$1" = status ] || exit 2' \
    'printf "%s\\n" "Synchronization status:" "Dispersion: 0.000299s, Delay: 0.007637s" "Stratum: 3" "" "Sources:" "time.example:123/192.0.2.40:123 (1): +0.000024" "    poll interval: 16s, missing polls: 0" "time.example:123/192.0.2.41:123 (2): +0.000025" "    poll interval: 16s, missing polls: 0" "" "Servers:"' \
    > "$control_command"
chmod 0755 "$control_command"

trusted_command() {
    [ "$1" = ntp-ctl ] || return 1
    printf '%s\n' "$control_command"
}

runtime_facts="$(ntpd_rs_runtime_evidence)" || fail "synchronized ntpd-rs status was rejected"
assert_contains "$runtime_facts" 'provider=ntpd-rs' "ntpd-rs runtime provider"
assert_contains "$runtime_facts" 'synchronized=yes' "ntpd-rs runtime synchronization"
assert_contains "$runtime_facts" 'source=time.example' "ntpd-rs runtime source"
assert_contains "$runtime_facts" 'source_count=2' "ntpd-rs runtime source count"
assert_contains "$runtime_facts" 'source_address_1=192.0.2.40' "ntpd-rs first runtime address"
assert_contains "$runtime_facts" 'source_address_2=192.0.2.41' "ntpd-rs second runtime address"

runtime_enabled() { return 0; }
runtime_snapshot_available() { return 0; }
service_state() {
    [ "$1" = ntpd-rs.service ]
}
time_service_persistence_state() { [ "$1" = ntpd-rs.service ]; }
policy_time_source_match() {
    [ "$1" = ntpd-rs ] || return 2
    case "$2:$3" in
        time.example:192.0.2.40|time.example:192.0.2.41|-:2001:db8::1) ;;
        *) return 2 ;;
    esac
    POLICY_TIME_SOURCE_MATCH_STATE=approved
    POLICY_TIME_SOURCE_MATCH_REASON=matched
    return 0
}

check_u_65
assert_equal GOOD "$RESULT_STATUS" "U-65 ntpd-rs provider"
assert_contains "$RESULT_EVIDENCE" 'expected_provider=chrony' "Ubuntu 26.04 expected provider"
assert_contains "$RESULT_EVIDENCE" 'active_provider=ntpd-rs' "U-65 active ntpd-rs provider"
assert_contains "$RESULT_EVIDENCE" 'provider_scope=operational-extension' "ntpd-rs provider scope"

printf '%s\n' \
    '[observability]' \
    'observation-path = "/run/ntpd-rs/observe"' \
    '[[source]]' \
    'mode = "server"' \
    'address = "[2001:db8::1]:123"' \
    '[synchronization]' \
    'minimum-agreeing-sources = 1' > "$SCAN_ROOT/etc/ntpd-rs/ntp.toml"
printf '%s\n' \
    '#!/bin/sh' \
    '[ "$1" = status ] || exit 2' \
    'printf "%s\\n" "Synchronization status:" "Stratum: 3" "" "Sources:" "[2001:db8::1]:123/[2001:db8::1]:123 (1): +0.000024" "" "Servers:"' \
    > "$control_command"
chmod 0755 "$control_command"
check_u_65
assert_equal GOOD "$RESULT_STATUS" "U-65 ntpd-rs IPv6 source policy"

printf 'PASS: ntpd-rs provider support\n'
