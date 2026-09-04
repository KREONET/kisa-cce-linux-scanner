#!/bin/bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

# shellcheck disable=SC2034

set -u

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_equal() {
    local expected="$1"
    local actual="$2"
    local context="$3"

    [ "$expected" = "$actual" ] || fail "$context: expected '$expected', received '$actual'"
}

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent=. ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2

KISA_CCE_VERSION=0.1.0
SCAN_ROOT=/
RUNTIME_MODE=on

# shellcheck source=../lib/kisa-cce-core/_core.sh
. "$project_directory/lib/kisa-cce-core/_core.sh"
# shellcheck source=../lib/kisa-cce-checks/_service.sh
. "$project_directory/lib/kisa-cce-checks/_service.sh"

runtime_enabled() { return 0; }
trusted_command() { return 1; }
service_listener_state() { return 1; }
service_legacy_enabled() {
    SERVICE_LEGACY_UNCERTAIN=0
    return 1
}
platform_is_rhel_family() { return 1; }

activation_call=0
service_activation_state() {
    activation_call=$((activation_call + 1))
    case "$activation_call" in
        1)
            SERVICE_ACTIVATION_EVIDENCE='dangerous_unit=first\nshared_state=unavailable\n'
            return 2
            ;;
        2)
            SERVICE_ACTIVATION_EVIDENCE='nisplus_state=inactive\n'
            return 1
            ;;
        *)
            SERVICE_ACTIVATION_EVIDENCE='shared_state=unavailable\ngeneral_unit=last\n'
            return 2
            ;;
    esac
}

check_u_42
assert_equal MANUAL "$RESULT_STATUS" "U-42 result state"
assert_equal 'dangerous_unit=first\nshared_state=unavailable\ngeneral_unit=last\n' \
    "$RESULT_EVIDENCE" "U-42 ordered unique activation evidence"

activation_call=0
service_activation_state() {
    activation_call=$((activation_call + 1))
    case "$activation_call" in
        1)
            SERVICE_ACTIVATION_EVIDENCE='systemctl=unavailable\nunit=ypserv.service,runtime_state=unknown\n'
            return 2
            ;;
        *)
            SERVICE_ACTIVATION_EVIDENCE='systemctl=unavailable\nunit=nisplus.service,runtime_state=unknown\n'
            return 2
            ;;
    esac
}

check_u_43
assert_equal MANUAL "$RESULT_STATUS" "U-43 result state"
case "$RESULT_EVIDENCE" in
    *'nisplus_systemctl=unavailable\nnisplus_unit=nisplus.service,runtime_state=unknown\nrpcinfo_checked=0\nrpcbind_listener=inactive_or_unavailable'*) ;;
    *) fail "U-43 did not expose normalized NIS+ evidence lines: $RESULT_EVIDENCE" ;;
esac
case "$RESULT_EVIDENCE" in
    *'nisplus_evidence='*|*'\n\n'*) fail "U-43 retained nested or blank-line evidence" ;;
esac

printf 'PASS: service evidence quality regressions\n'
