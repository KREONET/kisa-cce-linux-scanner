#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

# shellcheck disable=SC1091,SC2034

set -u

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
LC_ALL=C
export LC_ALL
umask 077

case "${BASH_SOURCE[0]}" in
    */*) source_parent="${BASH_SOURCE[0]%/*}" ;;
    *) source_parent="." ;;
esac
test_directory="$(CDPATH='' cd -P -- "$source_parent" && pwd)" || exit 2
project_directory="$(CDPATH='' cd -P -- "$test_directory/.." && pwd)" || exit 2
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-evidence-v2.XXXXXXXX")" || exit 2
temporary_directory="$(CDPATH='' cd -P -- "$temporary_directory" && pwd)" || exit 2

cleanup() {
    rm -rf -- "$temporary_directory"
}
trap cleanup EXIT

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

# shellcheck source=../lib/evidence.sh
. "$project_directory/lib/evidence.sh"

write_checksums() {
    local bundle="$1"
    local schema_version="$2"
    local relative_path=""
    local time_sync_path="runtime/time-sync.txt"

    [ "$schema_version" = "1" ] || time_sync_path="runtime/time-sync.tsv"
    : > "$bundle/checksums.sha256"
    for relative_path in \
        manifest.tsv \
        identity/os-release identity/machine-id identity/boot-id identity/kernel-release \
        runtime/systemd-units.tsv runtime/systemd-unit-files.tsv runtime/listeners.tsv \
        runtime/mountinfo runtime/firewall.txt "$time_sync_path"; do
        printf '%s  %s\n' "$(evidence_sha256 "$bundle/$relative_path")" "$relative_path" >> "$bundle/checksums.sha256" || return 1
    done
    chmod 0600 "$bundle/checksums.sha256"
}

create_bundle() {
    local bundle="$1"
    local schema_version="$2"
    local time_sync_status="$3"
    local time_sync_rows="${4-}"
    local time_sync_path="runtime/time-sync.txt"

    mkdir -p -- "$bundle/identity" "$bundle/runtime"
    chmod 0700 "$bundle" "$bundle/identity" "$bundle/runtime"
    printf '%s\n' 'ID=ubuntu' 'VERSION_ID="26.04"' 'PRETTY_NAME="Ubuntu 26.04 LTS"' > "$bundle/identity/os-release"
    printf '%s\n' '0123456789abcdef0123456789abcdef' > "$bundle/identity/machine-id"
    printf '%s\n' '01234567-89ab-cdef-0123-456789abcdef' > "$bundle/identity/boot-id"
    printf '%s\n' '6.8.0-test' > "$bundle/identity/kernel-release"
    printf 'unit\tload_state\tactive_state\tsub_state\tunit_file_state\n' > "$bundle/runtime/systemd-units.tsv"
    printf 'unit\tunit_file_state\tpreset\n' > "$bundle/runtime/systemd-unit-files.tsv"
    printf 'transport\tlocal_address\tport\tprocess\n' > "$bundle/runtime/listeners.tsv"
    printf '%s\n' '36 25 8:1 / / rw,relatime - ext4 /dev/root rw' > "$bundle/runtime/mountinfo"
    printf '%s\n' 'status=unavailable' > "$bundle/runtime/firewall.txt"
    if [ "$schema_version" = "1" ]; then
        printf '%s\n' '[chrony]' 'Leap status     : Normal' '^* 192.0.2.10' > "$bundle/runtime/time-sync.txt"
    else
        time_sync_path="runtime/time-sync.tsv"
        printf 'provider\tsynchronized\tsource\tsource_address\tstratum\tleap\tsource_origin\tsource_type\n' > "$bundle/$time_sync_path"
        [ -z "$time_sync_rows" ] || printf '%s\n' "$time_sync_rows" >> "$bundle/$time_sync_path"
    fi
    cat > "$bundle/manifest.tsv" <<EOF
schema_version	$schema_version
captured_at	2026-09-03T12:00:00Z
machine_id	0123456789abcdef0123456789abcdef
boot_id	01234567-89ab-cdef-0123-456789abcdef
kernel_release	6.8.0-test
identity_os_release_status	collected
identity_machine_id_status	collected
identity_boot_id_status	collected
identity_kernel_release_status	collected
runtime_systemd_units_status	collected
runtime_systemd_unit_files_status	collected
runtime_listeners_status	collected
runtime_mountinfo_status	collected
runtime_firewall_status	unavailable
runtime_time_sync_status	$time_sync_status
EOF
    chmod 0600 "$bundle/manifest.tsv" "$bundle/identity"/* "$bundle/runtime"/*
    write_checksums "$bundle" "$schema_version" || return 1
}

expect_validation_failure() {
    local bundle="$1"
    local expected_error="$2"

    if validate_evidence_bundle "$bundle"; then
        fail "invalid bundle was accepted: $bundle"
    fi
    assert_contains "$EVIDENCE_VALIDATION_ERROR" "$expected_error" "validation error"
    assert_equal "" "$EVIDENCE_BUNDLE_DIRECTORY" "failed validation clears bundle directory"
    assert_equal "" "$EVIDENCE_RUNTIME_TIME_SYNC_PATH" "failed validation clears time-sync path"
}

v1_bundle="$temporary_directory/v1"
create_bundle "$v1_bundle" 1 collected || fail "schema 1 fixture creation failed"
validate_evidence_bundle "$v1_bundle" || fail "valid schema 1 bundle was rejected: $EVIDENCE_VALIDATION_ERROR"
assert_equal 1 "$EVIDENCE_SCHEMA_VERSION" "schema 1 version"
assert_equal "$v1_bundle/runtime/time-sync.txt" "$EVIDENCE_RUNTIME_TIME_SYNC_PATH" "schema 1 time-sync path"
facts="sentinel"
status=0
evidence_time_sync_facts_into facts || status=$?
assert_equal 2 "$status" "schema 1 normalized helper status"
assert_equal "" "$facts" "schema 1 normalized helper output"

v2_bundle="$temporary_directory/v2-synchronized"
create_bundle "$v2_bundle" 2 collected $'chrony\tyes\t192.0.2.10\t192.0.2.10\t2\tnormal\truntime\tnetwork' || fail "schema 2 synchronized fixture creation failed"
validate_evidence_bundle "$v2_bundle" || fail "valid schema 2 bundle was rejected: $EVIDENCE_VALIDATION_ERROR"
assert_equal 2 "$EVIDENCE_SCHEMA_VERSION" "schema 2 version"
assert_equal "$v2_bundle/runtime/time-sync.tsv" "$EVIDENCE_RUNTIME_TIME_SYNC_PATH" "schema 2 time-sync path"
facts=""
evidence_time_sync_facts_into facts || fail "synchronized network evidence was not conclusive"
assert_contains "$facts" "provider=chrony" "synchronized provider fact"
assert_contains "$facts" "synchronized=yes" "synchronized state fact"
assert_contains "$facts" "source=192.0.2.10" "synchronized source fact"
assert_contains "$facts" "stratum=2" "synchronized stratum fact"
assert_contains "$facts" "leap=normal" "synchronized leap fact"
assert_contains "$facts" "source_origin=runtime" "synchronized origin fact"

unsynchronized_bundle="$temporary_directory/v2-unsynchronized"
create_bundle "$unsynchronized_bundle" 2 collected $'ntpsec\tno\t-\t-\t-\tunsynchronized\truntime\tunknown' || fail "schema 2 unsynchronized fixture creation failed"
validate_evidence_bundle "$unsynchronized_bundle" || fail "valid unsynchronized bundle was rejected: $EVIDENCE_VALIDATION_ERROR"
facts=""
status=0
evidence_time_sync_facts_into facts || status=$?
assert_equal 1 "$status" "unsynchronized evidence status"
assert_contains "$facts" "provider=ntpsec" "unsynchronized provider fact"

reference_bundle="$temporary_directory/v2-reference"
create_bundle "$reference_bundle" 2 collected $'chrony\tyes\tPHC0\tPHC0\t0\tnormal\truntime\treference-clock' || fail "schema 2 reference-clock fixture creation failed"
validate_evidence_bundle "$reference_bundle" || fail "valid reference-clock bundle was rejected: $EVIDENCE_VALIDATION_ERROR"
facts=""
status=0
evidence_time_sync_facts_into facts || status=$?
assert_equal 3 "$status" "reference-clock ambiguity status"
assert_contains "$facts" "source_type=reference-clock" "reference-clock source type"

partial_bundle="$temporary_directory/v2-partial"
create_bundle "$partial_bundle" 2 partial $'systemd-timesyncd\tyes\ttime.example\t192.0.2.20\t3\tnormal\tsystem\tnetwork' || fail "schema 2 partial fixture creation failed"
validate_evidence_bundle "$partial_bundle" || fail "valid partial bundle was rejected: $EVIDENCE_VALIDATION_ERROR"
facts=""
status=0
evidence_time_sync_facts_into facts || status=$?
assert_equal 2 "$status" "partial evidence helper status"

unavailable_bundle="$temporary_directory/v2-unavailable"
create_bundle "$unavailable_bundle" 2 unavailable "" || fail "schema 2 unavailable fixture creation failed"
validate_evidence_bundle "$unavailable_bundle" || fail "valid unavailable bundle was rejected: $EVIDENCE_VALIDATION_ERROR"
facts=""
status=0
evidence_time_sync_facts_into facts || status=$?
assert_equal 2 "$status" "unavailable evidence helper status"

multiple_synchronized_bundle="$temporary_directory/v2-multiple-synchronized"
create_bundle "$multiple_synchronized_bundle" 2 collected $'chrony\tyes\t192.0.2.10\t192.0.2.10\t2\tnormal\truntime\tnetwork\nsystemd-timesyncd\tyes\ttime.example\t192.0.2.20\t3\tnormal\tsystem\tnetwork' || fail "schema 2 multiple-synchronized fixture creation failed"
validate_evidence_bundle "$multiple_synchronized_bundle" || fail "valid multiple-provider bundle was rejected: $EVIDENCE_VALIDATION_ERROR"
facts=""
status=0
evidence_time_sync_facts_into facts || status=$?
assert_equal 2 "$status" "multiple synchronized provider ambiguity status"

malformed_bundle="$temporary_directory/v2-malformed"
create_bundle "$malformed_bundle" 2 collected $'chrony\tyes\tbad source\t192.0.2.10\t2\tnormal\truntime\tnetwork' || fail "schema 2 malformed fixture creation failed"
expect_validation_failure "$malformed_bundle" "invalid time-sync.tsv data"

duplicate_bundle="$temporary_directory/v2-duplicate"
create_bundle "$duplicate_bundle" 2 collected $'chrony\tyes\t192.0.2.10\t192.0.2.10\t2\tnormal\truntime\tnetwork\nchrony\tno\t-\t-\t-\tunsynchronized\truntime\tunknown' || fail "schema 2 duplicate fixture creation failed"
expect_validation_failure "$duplicate_bundle" "invalid time-sync.tsv data"

empty_collected_bundle="$temporary_directory/v2-empty-collected"
create_bundle "$empty_collected_bundle" 2 collected "" || fail "schema 2 empty fixture creation failed"
expect_validation_failure "$empty_collected_bundle" "invalid time-sync.tsv data"

v1_extra_bundle="$temporary_directory/v1-extra-v2"
create_bundle "$v1_extra_bundle" 1 collected || fail "schema 1 extra-entry fixture creation failed"
printf 'provider\tsynchronized\tsource\tsource_address\tstratum\tleap\tsource_origin\tsource_type\n' > "$v1_extra_bundle/runtime/time-sync.tsv"
chmod 0600 "$v1_extra_bundle/runtime/time-sync.tsv"
expect_validation_failure "$v1_extra_bundle" "schema 1 requires runtime/time-sync.txt only"

v2_extra_bundle="$temporary_directory/v2-extra-v1"
create_bundle "$v2_extra_bundle" 2 collected $'systemd-timesyncd\tyes\ttime.example\t192.0.2.20\t3\tnormal\tsystem\tnetwork' || fail "schema 2 extra-entry fixture creation failed"
printf '%s\n' '[timedatectl]' 'NTPSynchronized=yes' > "$v2_extra_bundle/runtime/time-sync.txt"
chmod 0600 "$v2_extra_bundle/runtime/time-sync.txt"
expect_validation_failure "$v2_extra_bundle" "schema 2 requires runtime/time-sync.tsv only"

checksum_bundle="$temporary_directory/v2-checksum"
create_bundle "$checksum_bundle" 2 collected $'systemd-timesyncd\tyes\ttime.example\t192.0.2.20\t3\tnormal\tsystem\tnetwork' || fail "schema 2 checksum fixture creation failed"
printf '%s\n' $'chrony\tno\t-\t-\t-\tunsynchronized\truntime\tunknown' >> "$checksum_bundle/runtime/time-sync.tsv"
expect_validation_failure "$checksum_bundle" "evidence checksum mismatch: runtime/time-sync.tsv"

printf 'PASS: evidence bundle schema v2\n'
