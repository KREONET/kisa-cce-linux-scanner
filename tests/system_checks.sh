#!/bin/bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

# Focused regressions for system-check failure precedence.

# shellcheck disable=SC2034

set -u

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent=. ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_temp="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-system-checks.XXXXXXXX")" || exit 2
trap 'rm -rf -- "$test_temp"' EXIT

KISA_CCE_VERSION=0.1.0
DATA_DIR="$project_directory/data"
KISA_CCE_LANGUAGE=ko
SCAN_ROOT="/"
RUNTIME_MODE="on"
SCRATCH_DIR="$test_temp/scratch"
mkdir -p -- "$SCRATCH_DIR" "$test_temp/root/etc" "$test_temp/root/var/log"

# shellcheck source=../lib/kisa-cce-core/_i18n.sh
. "$project_directory/lib/kisa-cce-core/_i18n.sh"
# shellcheck source=../lib/kisa-cce-core/_core.sh
. "$project_directory/lib/kisa-cce-core/_core.sh"
# shellcheck source=../lib/kisa-cce-checks/_system.sh
. "$project_directory/lib/kisa-cce-checks/_system.sh"

assert_summary_catalogued() {
    local source_summary="$1"
    local language=""
    local translated_summary=""

    for language in ko en; do
        KISA_CCE_LANGUAGE="$language"
        I18N_CATALOG_LOADED=0
        I18N_CATALOG=()
        i18n_load_catalog || fail "cannot load $language report catalog"
        i18n_summary_into "$source_summary" translated_summary ||
            fail "summary is absent from the $language report catalog: $source_summary"
        [ -n "$translated_summary" ] || fail "summary translation is empty for $language"
    done
}

runtime_enabled() { return 0; }
runtime_snapshot_available() { return 0; }
service_state() {
    case "$1" in
        rsyslog.service) return 0 ;;
        *) return 1 ;;
    esac
}
fs_path() {
    printf '%s%s\n' "$test_temp/root" "$1"
}
rsyslog_configuration_evidence() {
    printf '%s\n' 'rsyslog_configuration_files=1' 'resolution_errors=0'
    return 0
}
trusted_command() {
    [ "$1" = rsyslogd ] || return 1
    printf '%s\n' "$test_temp/rsyslogd"
}
printf '%s\n' '#!/bin/sh' 'exit 1' > "$test_temp/rsyslogd"
chmod 0755 "$test_temp/rsyslogd"
printf '%s\n' '*.* /var/log/messages' > "$test_temp/root/etc/rsyslog.conf"

check_u_66
[ "$RESULT_STATUS" = ERROR ] ||
    fail "U-66 invalid native configuration: expected ERROR, received $RESULT_STATUS"
assert_summary_catalogued "$RESULT_SUMMARY"
case "$RESULT_EVIDENCE" in
    *'rsyslog_native_validation=invalid'*) ;;
    *) fail "U-66 result omitted native validation evidence" ;;
esac

(
    PLATFORM_FAMILY=rhel
    PLATFORM_BASE_ID=rhel
    PLATFORM_BASE_VERSION=10.2
    EVIDENCE_BUNDLE_ACTIVE=1
    EVIDENCE_BUNDLE_DIRECTORY="$test_temp/evidence"
    policy_match_status=0

    runtime_enabled() { return 1; }
    runtime_snapshot_available() { return 0; }
    service_state() {
        case "$1" in
            chronyd.service) return 0 ;;
            *) return 3 ;;
        esac
    }
    evidence_time_sync_facts_into() {
        printf -v "$1" '%s' 'provider=chrony
synchronized=yes
source=-
source_address=192.0.2.10
stratum=2
leap=normal
source_origin=configured
source_type=network'
        return 0
    }
    chrony_config_evidence() {
        printf '%s\n' 'persistent_config=/etc/chrony.conf' 'configured_sources=1' 'resolution_errors=0'
        return 0
    }
    time_service_persistence_state() { return 0; }
    policy_time_source_match() {
        case "$policy_match_status" in
            0)
                POLICY_TIME_SOURCE_MATCH_STATE=approved
                POLICY_TIME_SOURCE_MATCH_REASON=matched_address
                ;;
            1)
                POLICY_TIME_SOURCE_MATCH_STATE=not_approved
                POLICY_TIME_SOURCE_MATCH_REASON=no_matching_entry
                ;;
            2)
                POLICY_TIME_SOURCE_MATCH_STATE=error
                POLICY_TIME_SOURCE_MATCH_REASON=expired_entry
                ;;
            *)
                POLICY_TIME_SOURCE_MATCH_STATE=absent
                POLICY_TIME_SOURCE_MATCH_REASON=facts_file_absent
                ;;
        esac
        return "$policy_match_status"
    }
    trusted_command() {
        fail "U-65 executed a live command while consuming bundle evidence: $1"
    }

    check_u_65
    [ "$RESULT_STATUS" = GOOD ] ||
        fail "U-65 approved bundled source: expected GOOD, received $RESULT_STATUS"
    assert_summary_catalogued "$RESULT_SUMMARY"
    case "$RESULT_EVIDENCE" in
        *'provider_consistency=matched'*'approved_source_evidence=approved'*) ;;
        *) fail "U-65 result omitted bundle or typed-policy evidence" ;;
    esac

    policy_match_status=1
    check_u_65
    [ "$RESULT_STATUS" = VULNERABLE ] ||
        fail "U-65 unapproved bundled source: expected VULNERABLE, received $RESULT_STATUS"
    assert_summary_catalogued "$RESULT_SUMMARY"

    policy_match_status=2
    check_u_65
    [ "$RESULT_STATUS" = ERROR ] ||
        fail "U-65 invalid typed policy lookup: expected ERROR, received $RESULT_STATUS"
    assert_summary_catalogued "$RESULT_SUMMARY"

    policy_match_status=3
    check_u_65
    [ "$RESULT_STATUS" = MANUAL ] ||
        fail "U-65 absent typed policy: expected MANUAL, received $RESULT_STATUS"
) || exit 1

(
    PLATFORM_FAMILY=debian
    PLATFORM_BASE_ID=ubuntu
    PLATFORM_BASE_VERSION=26.04
    EVIDENCE_BUNDLE_ACTIVE=1
    EVIDENCE_BUNDLE_DIRECTORY="$test_temp/evidence"

    runtime_enabled() { return 1; }
    runtime_snapshot_available() { return 0; }
    service_state() {
        case "$1" in
            systemd-timesyncd.service) return 0 ;;
            *) return 3 ;;
        esac
    }
    evidence_time_sync_facts_into() {
        printf -v "$1" '%s' 'provider=systemd-timesyncd
synchronized=yes
source=time.example
source_address=192.0.2.20
stratum=3
leap=normal
source_origin=system
source_type=network'
        return 0
    }
    time_service_persistence_state() { return 0; }
    policy_time_source_match() {
        POLICY_TIME_SOURCE_MATCH_STATE=approved
        POLICY_TIME_SOURCE_MATCH_REASON=matched
        return 0
    }

    check_u_65
    [ "$RESULT_STATUS" = GOOD ] ||
        fail "U-65 bundled timesyncd system source: expected GOOD, received $RESULT_STATUS"
) || exit 1

printf 'PASS: system-check failure precedence\n'
