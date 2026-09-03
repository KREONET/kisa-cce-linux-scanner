#!/bin/bash

# SPDX-License-Identifier: LGPL-3.0-or-later

# shellcheck disable=SC1091,SC2016,SC2030,SC2031,SC2034,SC2329

# Dependency-free regression tests for the scanner runtime and sysctl resolver.

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
LC_ALL=C
export LC_ALL
LANG=ko_KR.UTF-8
export LANG
umask 077

case "${BASH_SOURCE[0]}" in
    */*) source_parent="${BASH_SOURCE[0]%/*}" ;;
    *) source_parent="." ;;
esac
TEST_DIR="$(CDPATH='' cd -P -- "$source_parent" && pwd)" || exit 2
PROJECT_DIR="$(CDPATH='' cd -P -- "$TEST_DIR/.." && pwd)" || exit 2
IFS= read -r KISA_CCE_VERSION < "$PROJECT_DIR/data/VERSION" || exit 2
TEST_TEMP="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-tests.XXXXXXXX")" || exit 2
PASSED=0
FAILED=0

# BSD chmod does not accept the GNU-style option terminator used on the target platforms.
if ! /bin/chmod -- "$TEST_TEMP" 2>/dev/null; then
    chmod() {
        local mode="$1"
        shift
        if [ "${1:-}" = "--" ]; then
            shift
        fi
        /bin/chmod "$mode" "$@"
    }
    export -f chmod
fi

cleanup() {
    rm -rf -- "$TEST_TEMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
    printf '    %s\n' "$*" >&2
    exit 1
}

assert_equal() {
    local expected="$1"
    local actual="$2"
    local context="$3"

    [ "$expected" = "$actual" ] || fail "$context: expected=[$expected] actual=[$actual]"
}

assert_contains() {
    local value="$1"
    local expected_part="$2"
    local context="$3"

    case "$value" in
        *"$expected_part"*) ;;
        *) fail "$context: missing=[$expected_part]" ;;
    esac
}

scanner_console_value() {
    local key="$1"
    local output="$2"

    printf '%s\n' "$output" |
        sed -n "s/^\\[[^]]*\\] kisa-cce-scan: ${key}=//p"
}

assert_file_contains() {
    local file="$1"
    local expected_part="$2"
    local context="$3"

    grep -Fq -- "$expected_part" "$file" || fail "$context: missing=[$expected_part] file=[$file]"
}

assert_full_catalog_contract() {
    local text_report="$1"
    local jsonl_report="$2"
    local context="$3"

    result_count="$(grep -Ec '^## U-[0-9]{2}: ' "$text_report")"
    assert_equal 67 "$result_count" "$context Markdown result count"
    json_lines="$(wc -l < "$jsonl_report" | tr -d '[:space:]')"
    assert_equal 68 "$json_lines" "$context JSONL line count"
    assert_file_contains "$text_report" "| 오류 | 0 |" "$context Markdown error count"
    assert_file_contains "$jsonl_report" '"type":"summary","total":67' "$context JSONL summary"
    assert_file_contains "$jsonl_report" '"error":0' "$context JSONL error count"
    if grep -Fq -- '| 최종 판정 | `ERROR` |' "$text_report" ||
        grep -Fq -- '"status":"ERROR"' "$jsonl_report"; then
        fail "$context contains an error result"
    fi
    awk -F '"' '
        /"code":"U-[0-9][0-9]"/ {
            count++
            if ($4 != sprintf("U-%02d", count)) exit 1
        }
        END {exit(count == 67 ? 0 : 1)}
    ' "$jsonl_report" || fail "$context criterion order is not exactly U-01 through U-67"
    if command -v jq >/dev/null 2>&1; then
        jq -e -c . "$jsonl_report" >/dev/null || fail "$context JSONL report is not valid JSON"
    fi
}

mode_of() {
    stat -c '%a' -- "$1" 2>/dev/null || stat -f '%Lp' -- "$1" 2>/dev/null
}

write_os_release() {
    local root="$1"
    local platform_id="$2"
    local platform_version="$3"
    local platform_name="$4"
    local platform_id_like="${5:-}"
    local ubuntu_codename="${6:-}"

    mkdir -p -- "$root/etc"
    {
        printf 'ID=%s\n' "$platform_id"
        printf 'VERSION_ID="%s"\n' "$platform_version"
        printf 'PRETTY_NAME="%s"\n' "$platform_name"
        [ -z "$platform_id_like" ] || printf 'ID_LIKE="%s"\n' "$platform_id_like"
        [ -z "$ubuntu_codename" ] || printf 'UBUNTU_CODENAME=%s\n' "$ubuntu_codename"
    } > "$root/etc/os-release"
}

test_sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$1" | awk '{print $1}'
    else
        shasum -a 256 -- "$1" | awk '{print $1}'
    fi
}

write_evidence_bundle() {
    local bundle="$1"
    local root="$2"
    local machine_id="0123456789abcdef0123456789abcdef"
    local boot_id="01234567-89ab-cdef-0123-456789abcdef"
    local captured_at=""
    local relative_path=""

    captured_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    mkdir -p -- "$root/etc" "$bundle/identity" "$bundle/runtime"
    chmod 0700 -- "$bundle" "$bundle/identity" "$bundle/runtime"
    [ -s "$root/etc/os-release" ] || write_os_release "$root" ubuntu 26.04 "Ubuntu 26.04 LTS"
    printf '%s\n' "$machine_id" > "$root/etc/machine-id"
    cp -- "$root/etc/os-release" "$bundle/identity/os-release"
    printf '%s\n' "$machine_id" > "$bundle/identity/machine-id"
    printf '%s\n' "$boot_id" > "$bundle/identity/boot-id"
    printf '%s\n' '6.8.0-test' > "$bundle/identity/kernel-release"
    {
        printf 'unit\tload_state\tactive_state\tsub_state\tunit_file_state\n'
        printf 'ssh.service\tloaded\tactive\trunning\tenabled\n'
        printf 'telnet.service\tloaded\tinactive\tdead\tdisabled\n'
        printf 'chronyd.service\tloaded\tactive\trunning\tenabled\n'
        printf 'rsyslog.service\tloaded\tactive\trunning\tenabled\n'
        printf 'getty@.service\tloaded\tinactive\tdead\tdisabled\n'
    } > "$bundle/runtime/systemd-units.tsv"
    {
        printf 'unit\tunit_file_state\tpreset\n'
        printf 'ssh.service\tenabled\tenabled\n'
        printf 'telnet.service\tdisabled\tdisabled\n'
        printf 'chronyd.service\tenabled\tenabled\n'
        printf 'rsyslog.service\tenabled\tenabled\n'
        printf 'getty@.service\tdisabled\tdisabled\n'
    } > "$bundle/runtime/systemd-unit-files.tsv"
    {
        printf 'transport\tlocal_address\tport\tprocess\n'
        printf 'tcp\t0.0.0.0\t22\tsshd\n'
        printf 'udp\t0.0.0.0\t123\tchronyd\n'
    } > "$bundle/runtime/listeners.tsv"
    printf '%s\n' \
        '36 25 8:1 / / rw,relatime - ext4 /dev/root rw' \
        '37 36 8:1 /var/log /var/log rw,relatime - ext4 /dev/root rw' > "$bundle/runtime/mountinfo"
    printf '%s\n' 'collector=nft' 'table inet filter {}' > "$bundle/runtime/firewall.txt"
    printf '%s\n' '[chrony]' 'Leap status     : Normal' '^* 192.0.2.10' > "$bundle/runtime/time-sync.txt"
    cat > "$bundle/manifest.tsv" <<EOF
schema_version	1
captured_at	$captured_at
machine_id	$machine_id
boot_id	$boot_id
kernel_release	6.8.0-test
identity_os_release_status	collected
identity_machine_id_status	collected
identity_boot_id_status	collected
identity_kernel_release_status	collected
runtime_systemd_units_status	collected
runtime_systemd_unit_files_status	collected
runtime_listeners_status	collected
runtime_mountinfo_status	collected
runtime_firewall_status	collected
runtime_time_sync_status	collected
EOF
    : > "$bundle/checksums.sha256"
    for relative_path in \
        manifest.tsv \
        identity/os-release identity/machine-id identity/boot-id identity/kernel-release \
        runtime/systemd-units.tsv runtime/systemd-unit-files.tsv runtime/listeners.tsv \
        runtime/mountinfo runtime/firewall.txt runtime/time-sync.txt; do
        printf '%s  %s\n' "$(test_sha256_file "$bundle/$relative_path")" "$relative_path" >> "$bundle/checksums.sha256"
    done
    chmod 0600 -- "$bundle/manifest.tsv" "$bundle/checksums.sha256" \
        "$bundle"/identity/* "$bundle"/runtime/*
}

set_test_platform() {
    PLATFORM_ID="$1"
    PLATFORM_VERSION="$2"
    PLATFORM_NAME="${3:-}"
    PLATFORM_UBUNTU_CODENAME="${4:-}"
    classify_platform
}

test_shell_syntax() (
    local file=""

    for file in "$PROJECT_DIR"/bin/*; do
        /bin/sh -n "$file" || fail "CLI wrapper syntax check failed: $file"
    done
    for file in "$PROJECT_DIR"/lib/*.sh "$PROJECT_DIR"/tests/*.sh; do
        /bin/bash -n "$file" || fail "syntax check failed: $file"
    done
)

test_manpage_contract() (
    local manpage="$PROJECT_DIR/man/kisa-cce-scan.8"
    local collector_manpage="$PROJECT_DIR/man/kisa-cce-collect.8"
    local option=""

    [ -r "$manpage" ] || fail "manual page is missing"
    [ -r "$collector_manpage" ] || fail "collector manual page is missing"
    for option in \
        '\-\-root' \
        '\-\-output-dir' \
        '\-\-checks' \
        '\-\-no-runtime' \
        '\-\-explain-sysctl' \
        '\-\-allow-unsupported' \
        '\-v' \
        '\-\-verbose' \
        '\-\-help' \
        '\-\-version'; do
        grep -Fq -- "$option" "$manpage" || fail "manual page is missing option: $option"
    done
    for platform_name in Debian Ubuntu AlmaLinux Rocky Oracle CentOS "Linux Mint" "KDE neon"; do
        grep -Fq -- "$platform_name" "$manpage" || fail "manual page is missing platform: $platform_name"
    done
    grep -Fq -- 'markdown_report=' "$manpage" || fail "manual page is missing the Markdown output key"
    grep -Fq -- '.RANDOM.md' "$manpage" || fail "manual page is missing the Markdown filename"
    grep -Fq -- '\-\-evidence-bundle' "$manpage" || fail "manual page is missing evidence bundle option"
    grep -Fq -- '\-\-policy-dir' "$manpage" || fail "manual page is missing policy directory option"
    grep -Fq -- '\-\-output-dir' "$collector_manpage" || fail "collector manual page is missing output option"

    if command -v mandoc >/dev/null 2>&1; then
        mandoc -T lint "$manpage" >/dev/null || fail "manual page lint failed"
        mandoc -T lint "$collector_manpage" >/dev/null || fail "collector manual page lint failed"
    fi
)

test_policy_and_evidence_contracts() (
    local root="$TEST_TEMP/evidence-root"
    local bundle="$TEST_TEMP/evidence-bundle"
    local policy_directory="$TEST_TEMP/policy.d"
    local policy_file="$policy_directory/50-review.tsv"
    local scratch="$TEST_TEMP/policy-scratch"
    local audit_markdown="$TEST_TEMP/policy-audit.md"
    local audit_json="$TEST_TEMP/policy-audit.jsonl"
    local complete_markdown="$TEST_TEMP/policy-complete.md"
    local complete_json="$TEST_TEMP/policy-complete.jsonl"
    local review_id=""
    local listener_facts=""
    local mount_roots=""

    write_os_release "$root" ubuntu 26.04 "Ubuntu 26.04 LTS"
    mkdir -p -- "$root/var/log" "$scratch" "$policy_directory"
    chmod 0700 -- "$scratch" "$policy_directory"
    write_evidence_bundle "$bundle" "$root"

    SCAN_ROOT="$root"
    RUNTIME_MODE="bundle"
    SCAN_MODE="audit"
    SELECTED_CHECKS=""
    VERBOSE=0
    SCRATCH_DIR="$scratch"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/policy.sh
    . "$PROJECT_DIR/lib/policy.sh"
    # shellcheck source=../lib/evidence.sh
    . "$PROJECT_DIR/lib/evidence.sh"

    validate_evidence_bundle "$bundle" "$root" || fail "valid evidence bundle was rejected: $EVIDENCE_VALIDATION_ERROR"
    EVIDENCE_BUNDLE_ACTIVE=1
    evidence_service_state ssh.service || fail "active bundled service was not resolved"
    evidence_service_state telnet.service
    assert_equal 1 "$?" "inactive bundled service state"
    evidence_service_activation_state ssh.service || fail "enabled bundled service was not resolved"
    evidence_listener_state tcp 22 || fail "bundled TCP listener was not resolved"
    evidence_listener_state tcp 23
    assert_equal 1 "$?" "absent bundled TCP listener"
    listener_facts="$(evidence_listener_facts tcp 22)"
    assert_contains "$listener_facts" $'tcp\t0.0.0.0\t22\tsshd' "bundled listener facts"
    mount_roots="$(evidence_mount_roots)" || fail "bundled mount roots were not resolved"
    assert_contains "$mount_roots" $'/var/log\text4' "bundled /var/log mount"
    [ -n "$(evidence_capture_age_seconds)" ] || fail "evidence age was not calculated"

    : > "$audit_markdown"
    : > "$audit_json"
    REPORT_TEXT="$audit_markdown"
    REPORT_JSONL="$audit_json"
    COUNT_MANUAL=0
    COUNT_ERROR=0
    COUNT_GOOD=0
    COUNT_TOTAL=0
    COUNT_POLICY_RESOLVED=0
    set_result MANUAL "조직 정책 확인이 필요합니다." "policy_probe=complete"
    record_result U-64 patch high "주기적 보안 패치 및 벤더 권고사항 적용" || fail "audit manual result failed"
    review_id="$RESULT_REVIEW_ID"
    case "$review_id" in sha256:[0-9a-f][0-9a-f]*) ;; *) fail "audit review ID was not generated" ;; esac
    assert_equal MANUAL "$RESULT_STATUS" "audit mode preserves manual result"
    assert_file_contains "$audit_json" '"decision_basis":"manual_review"' "audit decision basis"

    {
        printf 'code\tdecision\treview_id\tticket\tapprover\texpires\n'
        printf 'U-64\tGOOD\t%s\tSEC-TEST-64\tsecurity-governance\t2099-12-31\n' "$review_id"
    } > "$policy_file"
    chmod 0600 -- "$policy_file"
    policy_load_dir "$policy_directory" || fail "valid policy directory was rejected"
    case "$POLICY_SET_DIGEST" in
        sha256:[0-9a-f][0-9a-f]*) ;;
        *) fail "policy set digest was not generated" ;;
    esac

    : > "$complete_markdown"
    : > "$complete_json"
    REPORT_TEXT="$complete_markdown"
    REPORT_JSONL="$complete_json"
    SCAN_MODE="complete"
    COUNT_MANUAL=0
    COUNT_ERROR=0
    COUNT_GOOD=0
    COUNT_TOTAL=0
    COUNT_POLICY_RESOLVED=0
    set_result MANUAL "조직 정책 확인이 필요합니다." "policy_probe=complete"
    record_result U-64 patch high "주기적 보안 패치 및 벤더 권고사항 적용" || fail "complete attestation result failed"
    assert_equal GOOD "$RESULT_STATUS" "matching attestation final decision"
    assert_equal MANUAL "$RESULT_TECHNICAL_STATUS" "matching attestation technical decision"
    assert_equal policy_attestation "$RESULT_DECISION_BASIS" "matching attestation basis"
    assert_equal 1 "$COUNT_POLICY_RESOLVED" "resolved policy count"
    assert_file_contains "$complete_json" '"technical_status":"MANUAL"' "complete technical status"
    assert_file_contains "$complete_json" '"attestation_ticket":"SEC-TEST-64"' "complete policy ticket"
    assert_file_contains "$complete_markdown" '| 최종 판정 | `GOOD` |' "complete Markdown decision"

    set_result MANUAL "다른 정책 확인이 필요합니다." "policy_probe=missing"
    record_result U-65 log medium "NTP 및 시각 동기화 설정" || fail "missing attestation result failed"
    assert_equal ERROR "$RESULT_STATUS" "missing attestation becomes error"
    assert_equal MANUAL "$RESULT_TECHNICAL_STATUS" "missing attestation technical status"
    assert_equal missing_policy_attestation "$RESULT_DECISION_BASIS" "missing attestation basis"

    printf 'tampered\n' >> "$bundle/runtime/listeners.tsv"
    if validate_evidence_bundle "$bundle" "$root"; then
        fail "tampered evidence bundle passed validation"
    fi
)

test_platform_support_matrix() (
    local root="$TEST_TEMP/platform-matrix"
    local platform_root=""
    local platform_id=""
    local platform_version=""
    local platform_name=""
    local platform_id_like=""
    local ubuntu_codename=""
    local expected_family=""
    local expected_base_id=""
    local expected_base_version=""
    local case_number=0

    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"

    while IFS='|' read -r platform_id platform_version platform_name platform_id_like ubuntu_codename expected_family expected_base_id expected_base_version; do
        case_number=$((case_number + 1))
        platform_root="$root/supported-$case_number"
        write_os_release "$platform_root" "$platform_id" "$platform_version" "$platform_name" "$platform_id_like" "$ubuntu_codename"
        SCAN_ROOT="$platform_root"
        detect_platform || fail "supported platform was rejected: $platform_id $platform_version"
        assert_equal "$platform_id" "$PLATFORM_ID" "platform ID for $platform_id $platform_version"
        assert_equal "$platform_version" "$PLATFORM_VERSION" "platform version for $platform_id $platform_version"
        assert_equal "$platform_name" "$PLATFORM_NAME" "platform name for $platform_id $platform_version"
        assert_equal "$ubuntu_codename" "$PLATFORM_UBUNTU_CODENAME" "Ubuntu codename for $platform_id $platform_version"
        assert_equal "$expected_family" "$PLATFORM_FAMILY" "platform family for $platform_id $platform_version"
        assert_equal "$expected_base_id" "$PLATFORM_BASE_ID" "platform base ID for $platform_id $platform_version"
        assert_equal "$expected_base_version" "$PLATFORM_BASE_VERSION" "platform base version for $platform_id $platform_version"
        # shellcheck disable=SC2153
        assert_equal "$platform_id_like" "$PLATFORM_ID_LIKE" "platform ID_LIKE for $platform_id $platform_version"
    done <<'EOF'
debian|12|Debian GNU/Linux 12|||debian|debian|12
debian|13|Debian GNU/Linux 13|||debian|debian|13
ubuntu|22.04|Ubuntu 22.04 LTS|debian||debian|ubuntu|22.04
ubuntu|24.04|Ubuntu 24.04 LTS|debian||debian|ubuntu|24.04
ubuntu|26.04|Ubuntu 26.04 LTS|debian||debian|ubuntu|26.04
rhel|8.10|Red Hat Enterprise Linux 8.10|fedora||rhel|rhel|8.10
rhel|9.8|Red Hat Enterprise Linux 9.8|fedora||rhel|rhel|9.8
rhel|10.2|Red Hat Enterprise Linux 10.2|fedora||rhel|rhel|10.2
almalinux|8.10|AlmaLinux 8.10|rhel centos fedora||rhel|rhel|8.10
almalinux|9.8|AlmaLinux 9.8|rhel centos fedora||rhel|rhel|9.8
almalinux|10.2|AlmaLinux 10.2|rhel centos fedora||rhel|rhel|10.2
rocky|8.10|Rocky Linux 8.10|rhel centos fedora||rhel|rhel|8.10
rocky|9.8|Rocky Linux 9.8|rhel centos fedora||rhel|rhel|9.8
rocky|10.2|Rocky Linux 10.2|rhel centos fedora||rhel|rhel|10.2
ol|8.10|Oracle Linux Server 8.10|fedora||rhel|rhel|8.10
ol|9.8|Oracle Linux Server 9.8|fedora||rhel|rhel|9.8
ol|10.2|Oracle Linux Server 10.2|fedora||rhel|rhel|10.2
centos|9|CentOS Stream 9|rhel fedora||rhel|rhel|9
centos|10|CentOS Stream 10 (Coughlan)|rhel fedora||rhel|rhel|10
linuxmint|21|Linux Mint 21|ubuntu debian|jammy|debian|ubuntu|22.04
linuxmint|21.1|Linux Mint 21.1|ubuntu debian|jammy|debian|ubuntu|22.04
linuxmint|21.2|Linux Mint 21.2|ubuntu debian|jammy|debian|ubuntu|22.04
linuxmint|21.3|Linux Mint 21.3|ubuntu debian|jammy|debian|ubuntu|22.04
linuxmint|22|Linux Mint 22|ubuntu debian|noble|debian|ubuntu|24.04
linuxmint|22.1|Linux Mint 22.1|ubuntu debian|noble|debian|ubuntu|24.04
linuxmint|22.2|Linux Mint 22.2|ubuntu debian|noble|debian|ubuntu|24.04
linuxmint|22.3|Linux Mint 22.3|ubuntu debian|noble|debian|ubuntu|24.04
pop|22.04|Pop!_OS 22.04 LTS|ubuntu debian|jammy|debian|ubuntu|22.04
pop|24.04|Pop!_OS 24.04 LTS|ubuntu debian|noble|debian|ubuntu|24.04
zorin|17|Zorin OS 17.3|ubuntu debian|jammy|debian|ubuntu|22.04
zorin|18|Zorin OS 18.1|ubuntu debian|noble|debian|ubuntu|24.04
elementary|7|elementary OS 7|ubuntu debian|jammy|debian|ubuntu|22.04
elementary|7.1|elementary OS 7.1|ubuntu debian|jammy|debian|ubuntu|22.04
elementary|8|elementary OS 8.1.1|ubuntu debian|noble|debian|ubuntu|24.04
neon|24.04|KDE neon User Edition|ubuntu debian|noble|debian|ubuntu|24.04
EOF

    while IFS='|' read -r platform_id platform_version platform_name platform_id_like ubuntu_codename; do
        case_number=$((case_number + 1))
        platform_root="$root/unsupported-$case_number"
        write_os_release "$platform_root" "$platform_id" "$platform_version" "$platform_name" "$platform_id_like" "$ubuntu_codename"
        SCAN_ROOT="$platform_root"
        if detect_platform; then
            fail "unsupported platform was accepted: $platform_id $platform_version"
        fi
    done <<'EOF'
debian|11|Debian GNU/Linux 11||
debian|12.1|Debian GNU/Linux 12.1||
debian|14|Debian GNU/Linux 14||
ubuntu|20.04|Ubuntu 20.04 LTS|debian|
ubuntu|24.04.1|Ubuntu 24.04.1 LTS|debian|
ubuntu|25.10|Ubuntu 25.10|debian|
rhel|7.9|Red Hat Enterprise Linux 7.9|fedora|
rhel|9.7|Red Hat Enterprise Linux 9.7|fedora|
rhel|10.|Red Hat Enterprise Linux 10|fedora|
rhel|10.2.1|Red Hat Enterprise Linux 10.2.1|fedora|
rhel|10.foo|Red Hat Enterprise Linux 10|fedora|
almalinux|9.7|AlmaLinux 9.7|rhel centos fedora|
rocky|10.1|Rocky Linux 10.1|rhel centos fedora|
ol|7.9|Oracle Linux Server 7.9|fedora|
centos|8|CentOS Stream 8|rhel fedora|
centos|9|CentOS Linux 9|rhel fedora|
linuxmint|20.3|Linux Mint 20.3|ubuntu debian|focal
linuxmint|22.3|Linux Mint 22.3|ubuntu debian|jammy
linuxmint|7|LMDE 7 Gigi|debian|
pop|20.04|Pop!_OS 20.04 LTS|ubuntu debian|focal
zorin|16.3|Zorin OS 16.3|ubuntu debian|focal
elementary|6.1|elementary OS 6.1|ubuntu debian|focal
neon|22.04|KDE neon User Edition 22.04|ubuntu debian|jammy
neon|24.04|KDE neon Testing Edition|ubuntu debian|noble
neon|24.04|KDE neon Unstable Edition|ubuntu debian|noble
neon|24.04|KDE neon Developer Edition|ubuntu debian|noble
exampleos|1|Example OS 1|ubuntu|
|1|Missing ID||
debian||Missing version||
EOF

    platform_root="$root/missing-os-release"
    mkdir -p -- "$platform_root/etc"
    SCAN_ROOT="$platform_root"
    if detect_platform; then
        fail "platform without os-release was accepted"
    fi
)

test_pam_facility_scoping_and_platform_capabilities() (
    local root="$TEST_TEMP/pam-platform-root"
    local scratch="$TEST_TEMP/pam-platform-scratch"
    local expanded=""
    local password_lines=""
    local status=0
    local pam_service=""

    mkdir -p -- "$root/etc/pam.d" "$root/etc/security/pwquality.conf.d" "$root/lib64/security" "$root/usr/bin" "$scratch"
    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_account_file.sh
    . "$PROJECT_DIR/lib/checks_account_file.sh"
    # shellcheck source=../lib/checks_service.sh
    . "$PROJECT_DIR/lib/checks_service.sh"
    SCRATCH_DIR="$scratch"
    set_test_platform rhel 8.10 "Red Hat Enterprise Linux 8.10"
    printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' 'operator:x:1000:1000::/home/operator:/bin/bash' > "$root/etc/passwd"
    printf '%s\n' 'root:x:0:' 'wheel:x:10:operator' > "$root/etc/group"
    printf '%s\n' 'UID_MIN 1000' > "$root/etc/login.defs"
    : > "$root/usr/bin/su"
    : > "$root/lib64/security/pam_wheel.so"
    chmod 0755 -- "$root/usr/bin/su"

    {
        printf '%s\n' 'auth [success=1 default=ignore] pam_unix.so'
        printf '%s\n' 'account required pam_unix.so'
        printf '%s\n' 'password requisite pam_pwquality.so'
        printf '%s\n' 'password required pam_pwhistory.so use_authtok'
        printf '%s\n' "PASSWORD SUFFICIENT \\"
        printf '%s\n' 'pam_unix.so use_authtok sha512'
        printf '%s\n' 'session required pam_unix.so'
    } > "$root/etc/pam.d/system-auth"
    cp -- "$root/etc/pam.d/system-auth" "$root/etc/pam.d/password-auth"
    {
        printf '%s\n' 'AUTH REQUIRED pam_wheel.so use_uid'
        printf '%s\n' 'auth substack system-auth'
        printf '%s\n' 'account include system-auth'
        printf '%s\n' 'password include system-auth'
        printf '%s\n' 'session include system-auth'
    } > "$root/etc/pam.d/su"

    expanded="$(pam_expand_service su auth)" || fail "facility-scoped PAM expansion failed"
    assert_contains "$expanded" "pam_wheel.so" "PAM auth expansion"
    assert_contains "$expanded" "auth [success=1 default=ignore] pam_unix.so" "PAM auth include expansion"
    case "$expanded" in
        *pam_pwquality.so*|*pam_pwhistory.so*|*'session required'*) fail "PAM auth expansion leaked another facility" ;;
    esac

    printf '%s\n' 'auth required pam_permit.so' > "$root/etc/pam.d/site+auth@local"
    printf '%s\n' 'auth include site+auth@local' > "$root/etc/pam.d/extended-service-name"
    expanded="$(pam_expand_service extended-service-name auth)" || fail "valid PAM service-name punctuation was rejected"
    assert_contains "$expanded" "pam_permit.so" "PAM punctuated service include"
    printf '%s\n' 'auth required pam_permit.so # pam_faillock.so preauth deny=3' > "$root/etc/pam.d/inline-comment"
    expanded="$(pam_expand_service inline-comment auth)" || fail "PAM inline comment fixture failed"
    case "$expanded" in *pam_faillock.so*) fail "PAM inline comment became an active module" ;; esac
    check_u_06
    assert_equal MANUAL "$RESULT_STATUS" "case-insensitive PAM wheel control"
    assert_contains "$RESULT_EVIDENCE" "pam_wheel_restriction=1" "case-insensitive PAM wheel evidence"

    password_lines="$(pam_expand_service system-auth password)" || fail "PAM password expansion failed"
    scanner_pam_module_precedes_unix <(printf '%s\n' "$password_lines") pam_pwquality.so password ||
        fail "pam_pwquality password order was misclassified"
    scanner_pam_module_precedes_unix <(printf '%s\n' "$password_lines") pam_pwhistory.so password ||
        fail "pam_pwhistory password order was misclassified"
    if scanner_pam_stack_has_bracket_control <(printf '%s\n' "$password_lines") password; then
        fail "an auth bracket control affected the password facility"
    fi

    printf '%s\n' 'auth include cycle-b' > "$root/etc/pam.d/cycle-a"
    printf '%s\n' 'auth include cycle-a' > "$root/etc/pam.d/cycle-b"
    pam_expand_service cycle-a auth >/dev/null 2>&1
    status=$?
    assert_equal 2 "$status" "PAM include cycle status"

    printf '%s\n' 'auth include' > "$root/etc/pam.d/malformed-include"
    pam_expand_service malformed-include auth >/dev/null 2>&1
    status=$?
    assert_equal 2 "$status" "PAM include without a service"
    printf '%s\n' '@include' > "$root/etc/pam.d/malformed-at-include"
    pam_expand_service malformed-at-include auth >/dev/null 2>&1
    status=$?
    assert_equal 2 "$status" "PAM at-include without a service"

    printf '%s\n' 'PASS_MAX_DAYS 90' 'PASS_MIN_DAYS 1' 'ENCRYPT_METHOD SHA512' > "$root/etc/login.defs"
    {
        printf '%s\n' 'minlen = 8'
        printf '%s\n' 'dcredit = -1'
        printf '%s\n' 'ucredit = -1'
        printf '%s\n' 'lcredit = -1'
        printf '%s\n' 'ocredit = -1'
        printf '%s\n' 'enforce_for_root'
    } > "$root/etc/security/pwquality.conf"
    printf '%s\n' 'remember = 4' 'enforce_for_root' 'file = /etc/security/opasswd' > "$root/etc/security/pwhistory.conf"
    : > "$root/etc/security/opasswd"
    check_u_02
    assert_equal GOOD "$RESULT_STATUS" "RHEL mixed-facility password policy"

    printf '%s\n' 'REMEMBER 0' 'remember = 4' 'enforce_for_root' 'file = /etc/security/opasswd' > "$root/etc/security/pwhistory.conf"
    printf '%s\n' 'remember = 4' 'enforce_for_root' 'file = /etc/security/opasswd' > "$root/etc/security/pwhistory-good.conf"
    sed -i 's/pam_pwhistory.so use_authtok/pam_pwhistory.so use_authtok CONF=\/etc\/security\/pwhistory-good.conf/' "$root/etc/pam.d/system-auth"
    check_u_02
    assert_equal VULNERABLE "$RESULT_STATUS" "pwhistory first value and case-sensitive conf option"
    sed -i 's/ CONF=\/etc\/security\/pwhistory-good.conf//' "$root/etc/pam.d/system-auth"
    printf '%s\n' 'remember = 4#policy' 'enforce_for_root' 'file = /etc/security/opasswd' > "$root/etc/security/pwhistory.conf"
    check_u_02
    assert_equal GOOD "$RESULT_STATUS" "pwhistory inline comment parsing"
    printf '%s\n' 'remember = 4' 'enforce_for_root' 'file = /etc/security/opasswd' > "$root/etc/security/pwhistory.conf"
    sed -i 's/pam_pwhistory.so use_authtok/pam_pwhistory.so use_authtok remember=4 REMEMBER=0/' "$root/etc/pam.d/system-auth"
    check_u_02
    assert_equal VULNERABLE "$RESULT_STATUS" "case-insensitive PAM history override"
    sed -i 's/ remember=4 REMEMBER=0//' "$root/etc/pam.d/system-auth"

    cp -- "$root/etc/pam.d/system-auth" "$root/etc/pam.d/password-auth"
    printf '%s\n' 'root:!!:20000:0:99999:7:::' 'operator:!!:20000:0:99999:7:::' > "$root/etc/shadow"
    check_u_13
    assert_equal GOOD "$RESULT_STATUS" "RHEL 8 SHA512 PAM hash policy"
    sed -i 's/ENCRYPT_METHOD SHA512/ENCRYPT_METHOD MD5/' "$root/etc/login.defs"
    check_u_13
    assert_equal VULNERABLE "$RESULT_STATUS" "weak login.defs method with secure PAM option"
    sed -i 's/ENCRYPT_METHOD MD5/ENCRYPT_METHOD SHA512/' "$root/etc/login.defs"
    sed -i 's/ENCRYPT_METHOD SHA512/encrypt_method=MD5/' "$root/etc/login.defs"
    check_u_13
    assert_equal VULNERABLE "$RESULT_STATUS" "case-insensitive equals PAM login.defs method"
    sed -i 's/encrypt_method=MD5/ENCRYPT_METHOD SHA512/' "$root/etc/login.defs"
    sed -i 's/sha512/blowfish/' "$root/etc/pam.d/system-auth"
    check_u_13
    assert_equal MANUAL "$RESULT_STATUS" "Blowfish PAM hash option"
    sed -i 's/blowfish/sha512/' "$root/etc/pam.d/system-auth"
    sed -i 's/sha512/yescrypt/' "$root/etc/pam.d/system-auth"
    sed -i 's/ENCRYPT_METHOD SHA512/ENCRYPT_METHOD YESCRYPT/' "$root/etc/login.defs"
    check_u_13
    assert_equal MANUAL "$RESULT_STATUS" "RHEL 8 unlisted yescrypt algorithm"
    sed -i 's/yescrypt/sha512/' "$root/etc/pam.d/system-auth"
    sed -i 's/ENCRYPT_METHOD YESCRYPT/ENCRYPT_METHOD SHA512/' "$root/etc/login.defs"
    set_test_platform rhel 10.2 "Red Hat Enterprise Linux 10.2"
    sed -i 's/sha512/yescrypt/' "$root/etc/pam.d/system-auth"
    sed -i 's/ENCRYPT_METHOD SHA512/ENCRYPT_METHOD YESCRYPT/' "$root/etc/login.defs"
    check_u_13
    assert_equal MANUAL "$RESULT_STATUS" "RHEL 10 unlisted yescrypt algorithm"
    sed -i 's/yescrypt/md5/' "$root/etc/pam.d/system-auth"
    check_u_13
    assert_equal VULNERABLE "$RESULT_STATUS" "weak PAM hash override"

    set_test_platform debian 12 "Debian GNU/Linux 12"
    cp -- "$root/etc/pam.d/system-auth" "$root/etc/pam.d/common-password"
    check_u_02
    assert_equal VULNERABLE "$RESULT_STATUS" "Debian 12 inactive pwhistory.conf"

    (
        set_test_platform rhel 10.2 "Red Hat Enterprise Linux 10.2"
        login_defs_value() { return 2; }
        pam_login_defs_value() { return 2; }
        check_u_02
        assert_equal ERROR "$RESULT_STATUS" "U-02 resolver failure preservation"
        check_u_13
        assert_equal ERROR "$RESULT_STATUS" "U-13 resolver failure preservation"
    )

    set_test_platform rhel 8.10 "Red Hat Enterprise Linux 8.10"
    for pam_service in system-auth password-auth; do
        {
            printf '%s\n' 'AUTH OPTIONAL pam_faillock.so preauth'
            printf '%s\n' 'AUTH REQUIRED pam_unix.so'
            printf '%s\n' 'AUTH OPTIONAL pam_faillock.so authfail'
            printf '%s\n' 'AUTH OPTIONAL pam_faillock.so authsucc'
            printf '%s\n' 'ACCOUNT OPTIONAL pam_faillock.so reset'
        } > "$root/etc/pam.d/$pam_service"
    done
    printf '%s\n' 'deny = 3' > "$root/etc/security/faillock.conf"
    : > "$root/lib64/security/pam_faillock.so"
    check_u_03
    assert_equal VULNERABLE "$RESULT_STATUS" "case-insensitive optional faillock control"
    assert_contains "$RESULT_EVIDENCE" "lock_flow_valid=0" "optional faillock flow evidence"

    printf '%s\n' 'UMASK 000' 'UMASK 027' > "$root/etc/login.defs"
    printf '%s\n' 'session optional pam_umask.so' > "$root/etc/pam.d/postlogin"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "RHEL 8 PAM UMASK first key"
    set_test_platform rhel 9.8 "Red Hat Enterprise Linux 9.8"
    printf '%s\n' 'UMASK 027' > "$root/etc/login.defs"
    mkdir -p -- "$root/etc/login.defs.d"
    printf '%s\n' 'UMASK 000' > "$root/etc/login.defs.d/99-local.defs"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "RHEL 9 PAM UMASK drop-in value"
)

test_time_and_sysctl_platform_adapters() (
    local root="$TEST_TEMP/platform-adapter-root"
    local scratch="$TEST_TEMP/platform-adapter-scratch"
    local output=""
    local status=0

    mkdir -p -- "$root/etc/bind" "$root/etc/chrony" "$root/etc/ntpsec/conf.d" "$root/etc/ntpsec/ntp.d" "$root/etc/sysctl.d" "$root/var/log/apt" "$scratch"
    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_system.sh
    . "$PROJECT_DIR/lib/checks_system.sh"
    # shellcheck source=../lib/checks_service.sh
    . "$PROJECT_DIR/lib/checks_service.sh"
    SCRATCH_DIR="$scratch"
    set_test_platform debian 13 "Debian GNU/Linux 13"

    printf '%s\n' 'kernel.domainname = example # literal-value' > "$root/etc/sysctl.d/90-domain.conf"
    output="$(sysctl_static_value kernel.domainname)" || fail "sysctl value with an inline comment character was not resolved"
    assert_contains "$output" "example # literal-value" "literal sysctl comment character"

    printf '%s\n' 'server 192.0.2.30' > "$root/etc/chrony/chrony.conf"
    output="$(chrony_config_evidence)" || fail "Debian Chrony configuration path was not resolved"
    assert_contains "$output" "/etc/chrony/chrony.conf" "Debian Chrony configuration path"
    printf '%s\n' 'fixture' > "$root/var/log/apt/history.log"
    check_u_64
    assert_contains "$RESULT_EVIDENCE" "/var/log/apt/history.log" "Debian APT evidence"
    printf '%s\n' 'options {};' > "$root/etc/bind/named.conf"
    printf '%s\n' 'options {};' > "$root/etc/named.conf"
    output="$(service_bind_main_configuration)" || fail "Debian BIND configuration path was not resolved"
    assert_equal "$root/etc/bind/named.conf" "$output" "Debian BIND configuration preference"
    set_test_platform rhel 10.2 "Red Hat Enterprise Linux 10.2"
    output="$(service_bind_main_configuration)" || fail "RHEL BIND configuration path was not resolved"
    assert_equal "$root/etc/named.conf" "$output" "RHEL BIND configuration preference"
    set_test_platform debian 13 "Debian GNU/Linux 13"

    printf '%s\n' 'includefile conf.d/site.conf' > "$root/etc/ntpsec/ntp.conf"
    printf '%s\n' 'pool 192.0.2.10 iburst' > "$root/etc/ntpsec/conf.d/site.conf"
    output="$(ntpsec_config_evidence)" || fail "NTPsec include file was not resolved"
    assert_contains "$output" "configured_sources=1" "NTPsec configured source count"

    printf '%s\n' 'includefile conf.d' > "$root/etc/ntpsec/ntp.conf"
    output="$(ntpsec_config_evidence)" || fail "NTPsec includefile directory was not expanded"
    assert_contains "$output" "configured_sources=1" "NTPsec includefile directory expansion"

    printf '%s\n' 'includefile missing.d' > "$root/etc/ntpsec/ntp.conf"
    ntpsec_config_evidence >/dev/null 2>&1
    status=$?
    assert_equal 2 "$status" "NTPsec missing includefile directory"

    rm -f -- "$root/etc/ntpsec/ntp.conf"
    printf '%s\n' 'server 192.0.2.40' > "$root/etc/ntpsec/ntp.d/site.conf"
    output="$(ntpsec_config_evidence)" || fail "NTPsec drop-in-only configuration was not resolved"
    assert_contains "$output" "configured_sources=1" "NTPsec packaged drop-in source count"
    rm -f -- "$root/etc/ntpsec/ntp.d/site.conf"

    printf '%s\n' 'server 192.0.2.41' > "$root/etc/ntpsec/real-source.conf"
    ln -s /etc/ntpsec/real-source.conf "$root/etc/ntpsec/ntp.d/in-root.conf"
    output="$(ntpsec_config_evidence)" || fail "NTPsec in-root drop-in symlink was not resolved"
    assert_contains "$output" "configured_sources=1" "NTPsec in-root symlink source count"
    rm -f -- "$root/etc/ntpsec/ntp.d/in-root.conf"

    printf '%s\n' 'server 192.0.2.42' > "$TEST_TEMP/ntpsec-outside.conf"
    ln -s ../../../../ntpsec-outside.conf "$root/etc/ntpsec/ntp.d/escape.conf"
    ntpsec_config_evidence >/dev/null 2>&1
    status=$?
    assert_equal 2 "$status" "NTPsec escaping drop-in symlink"
    rm -f -- "$root/etc/ntpsec/ntp.d/escape.conf"

    printf '%s\n' 'server 192.0.2.20 noselect' > "$root/etc/ntpsec/ntp.conf"
    ntpsec_config_evidence >/dev/null 2>&1
    status=$?
    assert_equal 3 "$status" "NTPsec noselect-only configuration"

    printf '%s\n' 'broadcast 192.0.2.255' > "$root/etc/ntpsec/ntp.conf"
    ntpsec_config_evidence >/dev/null 2>&1
    status=$?
    assert_equal 3 "$status" "unsupported NTPsec broadcast source"

    printf '%s\n' 'server 192.0.2.20 # noselect is not active' > "$root/etc/ntpsec/ntp.conf"
    output="$(ntpsec_config_evidence)" || fail "NTPsec inline comment changed a source directive"
    assert_contains "$output" "configured_sources=1" "NTPsec inline source comment"

    printf '%s\n' 'server 192.0.2.20' 'disable ntp#maintenance' 'enable monitor # ntp remains disabled' > "$root/etc/ntpsec/ntp.conf"
    ntpsec_config_evidence >/dev/null 2>&1
    status=$?
    assert_equal 3 "$status" "disabled NTPsec configuration"

    printf '%s\n' 'disable ntp' > "$root/etc/ntpsec/ntp.d/order.conf"
    printf '%s\n' 'includefile /etc/ntpsec/ntp.d/order.conf' 'enable ntp' 'server 192.0.2.20' > "$root/etc/ntpsec/ntp.conf"
    ntpsec_config_evidence >/dev/null 2>&1
    status=$?
    assert_equal 3 "$status" "NTPsec automatic drop-in reprocessing order"
    rm -f -- "$root/etc/ntpsec/ntp.d/order.conf"

    rm -f -- "$root/etc/ntpsec/ntp.conf"
    printf '%s\n' 'server 192.0.2.50' > "$root/etc/ntp.conf"
    printf '%s\n' 'disable ntp' > "$root/etc/ntpsec/ntp.d/unrelated.conf"
    output="$(ntpsec_config_evidence)" || fail "fallback NTP configuration was mixed with NTPsec drop-ins"
    assert_contains "$output" "persistent_config=/etc/ntp.conf" "fallback NTP configuration path"
    rm -f -- "$root/etc/ntp.conf" "$root/etc/ntpsec/ntp.d/unrelated.conf"

    printf '%s\n' 'includefile cycle.conf' > "$root/etc/ntpsec/ntp.conf"
    printf '%s\n' 'includefile ntp.conf' > "$root/etc/ntpsec/cycle.conf"
    ntpsec_config_evidence >/dev/null 2>&1
    status=$?
    assert_equal 2 "$status" "NTPsec include cycle"

    {
        printf '%s\n' '#!/bin/sh'
        printf 'exec /bin/cat %s\n' "$scratch/systemctl-properties"
    } > "$scratch/systemctl"
    chmod 0755 -- "$scratch/systemctl"
    runtime_enabled() { return 0; }
    trusted_command() { [ "$1" = systemctl ] && printf '%s\n' "$scratch/systemctl"; }

    printf '%s\n' \
        'LoadState=loaded' \
        'ExecStart={ path=/lib/systemd/systemd-sysctl ; argv[]=/lib/systemd/systemd-sysctl ; ignore_errors=no ; }' \
        > "$scratch/systemctl-properties"
    output="$(sysctl_loader_kind)" || fail "/lib systemd-sysctl unit was rejected"
    assert_equal systemd-sysctl "$output" "/lib systemd-sysctl loader"
    systemd_sysctl_binary() { printf 'validated:%s\n' "$1"; }
    output="$(systemd_sysctl_unit_binary)" || fail "unit systemd-sysctl path was not bound to validation"
    assert_equal "validated:/lib/systemd/systemd-sysctl" "$output" "unit systemd-sysctl binary binding"

    printf '%s\n' \
        'LoadState=loaded' \
        'ExecStart={ path=/usr/lib/systemd/systemd-sysctl ; argv[]=/usr/lib/systemd/systemd-sysctl ; ignore_errors=no ; }' \
        > "$scratch/systemctl-properties"
    output="$(sysctl_loader_kind)" || fail "/usr/lib systemd-sysctl unit was rejected"
    assert_equal systemd-sysctl "$output" "/usr/lib systemd-sysctl loader"

    printf '%s\n' \
        'LoadState=loaded' \
        'ExecStart={ path=/usr/lib/systemd/systemd-sysctl ; argv[]=/usr/lib/systemd/systemd-sysctl ; ignore_errors=no ; }' \
        'LoadCredential=sysctl.extra' \
        > "$scratch/systemctl-properties"
    output="$(sysctl_loader_kind)" || fail "stock systemd 252 sysctl.extra declaration was rejected"
    assert_equal systemd-sysctl "$output" "systemd 252 unpopulated sysctl.extra declaration"

    printf '%s\n' \
        'LoadState=loaded' \
        'ExecStart={ path=/opt/systemd-sysctl ; argv[]=/opt/systemd-sysctl ; ignore_errors=no ; }' \
        > "$scratch/systemctl-properties"
    sysctl_loader_kind >/dev/null 2>&1
    status=$?
    assert_equal 2 "$status" "untrusted systemd-sysctl loader path"

    printf '%s\n' \
        'LoadState=loaded' \
        'ExecStart={ path=/lib/systemd/systemd-sysctl ; argv[]=/usr/lib/systemd/systemd-sysctl ; ignore_errors=no ; }' \
        > "$scratch/systemctl-properties"
    sysctl_loader_kind >/dev/null 2>&1
    status=$?
    assert_equal 2 "$status" "mismatched systemd-sysctl path and argv"

    {
        printf '%s\n' '#!/bin/sh'
        printf '%s\n' 'printf "*192.0.2.10 .GPS. 1 u 8 64 377 1.0 0.1 0.1\\n"'
    } > "$scratch/ntpq"
    chmod 0755 -- "$scratch/ntpq"
    printf '%s\n' 'server 192.0.2.10' > "$root/etc/ntpsec/ntp.conf"
    trusted_command() {
        case "$1" in
            ntpq) printf '%s\n' "$scratch/ntpq" ;;
            *) return 1 ;;
        esac
    }
    service_state() {
        case "$1" in
            ntpsec.service) return 0 ;;
            *) return 3 ;;
        esac
    }
    time_service_persistence_state() { return 0; }
    check_u_65
    assert_equal MANUAL "$RESULT_STATUS" "active NTPsec synchronization requires approved source evidence"
    assert_contains "$RESULT_EVIDENCE" "provider=ntpsec" "NTPsec result evidence"
    assert_contains "$RESULT_EVIDENCE" "approved_source_evidence=unavailable" "NTPsec source approval evidence"

    service_state() {
        case "$1" in
            chronyd.service|ntpsec.service) return 0 ;;
            *) return 3 ;;
        esac
    }
    check_u_65
    assert_equal MANUAL "$RESULT_STATUS" "multiple active time providers"
)

test_core_report_counts_and_permissions() (
    local root="$TEST_TEMP/core-root"
    local output="$TEST_TEMP/core-reports"
    local bound_output="$TEST_TEMP/core-reports-bound"
    local json_lines=""
    local original_markdown_report=""
    local tampered_markdown_report="$TEST_TEMP/tampered-report.md"
    local text_basename=""

    write_os_release "$root" ubuntu 26.04 "Ubuntu 26.04 LTS"
    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    OUTPUT_PARENT="$output"
    SELECTED_CHECKS=""
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"

    detect_platform || fail "supported platform was not detected"
    initialize_workspace
    assert_equal 1 "$LISTENER_SNAPSHOT_CACHE_ENABLED" "scan listener cache enablement"
    write_report_header

    check_u_01() { set_result GOOD "good result" $'pass\bword=do-not-write-this'; }
    check_u_02() { set_result VULNERABLE "vulnerable result" 'mode=0666\nowner=root'; }
    check_u_03() { set_result MANUAL "manual result" "runtime=unavailable"; }
    check_u_04() { set_result NOT_APPLICABLE "not applicable result" "service=absent" false; }
    check_u_05() { set_result ERROR "error result" "read=failed"; }

    run_one_check U-01 account high "first"
    run_one_check U-02 account high "second"
    run_one_check U-03 account high "third"
    run_one_check U-04 account high "fourth"
    run_one_check U-05 account high "fifth"
    write_report_summary

    assert_equal 5 "$COUNT_TOTAL" "total count"
    assert_equal 1 "$COUNT_GOOD" "good count"
    assert_equal 1 "$COUNT_VULNERABLE" "vulnerable count"
    assert_equal 1 "$COUNT_MANUAL" "manual count"
    assert_equal 1 "$COUNT_NOT_APPLICABLE" "not-applicable count"
    assert_equal 1 "$COUNT_ERROR" "error count"
    assert_equal 700 "$(mode_of "$OUTPUT_PARENT")" "output directory mode"
    assert_equal 600 "$(mode_of "$REPORT_TEXT")" "Markdown report mode"
    assert_equal 600 "$(mode_of "$REPORT_JSONL")" "JSONL report mode"
    case "$REPORT_TEXT$REPORT_JSONL" in *XXXXXXXX*) fail "report filename was not randomized" ;; esac
    case "$REPORT_TEXT" in *.md) ;; *) fail "Markdown report filename does not end in .md" ;; esac
    assert_file_contains "$REPORT_TEXT" "| 전체 | 5 |" "Markdown summary"
    assert_file_contains "$REPORT_TEXT" "password=[REDACTED]" "evidence redaction"
    assert_file_contains "$REPORT_TEXT" "owner=root" "evidence line normalization"
    if grep -Fq -- "do-not-write-this" "$REPORT_TEXT"; then
        fail "Markdown report retained a secret"
    fi
    json_lines="$(wc -l < "$REPORT_JSONL" | tr -d '[:space:]')"
    assert_equal 6 "$json_lines" "JSONL result and summary line count"
    assert_file_contains "$REPORT_JSONL" '"type":"summary","total":5' "JSONL summary"
    validate_reports || fail "completed reports failed integrity validation"
    original_markdown_report="$REPORT_TEXT"
    awk '{if ($0 ~ /^## U-03:/) sub(/U-03/, "U-13"); print}' \
        "$original_markdown_report" > "$tampered_markdown_report"
    chmod 0600 -- "$tampered_markdown_report"
    REPORT_TEXT="$tampered_markdown_report"
    if validate_reports; then
        fail "criterion code drift passed Markdown report validation"
    fi
    REPORT_TEXT="$original_markdown_report"
    if command -v jq >/dev/null 2>&1; then
        jq -e -c . "$REPORT_JSONL" >/dev/null || fail "JSONL report is not valid JSON"
    fi
    # Reading the report on both sides verifies that sanitization is idempotent.
    # shellcheck disable=SC2094
    if ! LC_ALL=C tr -d '\000-\010\013\014\016-\037\177' < "$REPORT_JSONL" | cmp -s - "$REPORT_JSONL"; then
        fail "JSONL report contains an unescaped control byte"
    fi
    scanner_exit_code
    assert_equal 2 "$?" "scanner exit status when errors exist"

    text_basename="${REPORT_TEXT##*/}"
    mv -- "$OUTPUT_PARENT" "$bound_output"
    mkdir -- "$OUTPUT_PARENT"
    chmod 0700 -- "$OUTPUT_PARENT"
    if output_directory_binding_is_current; then
        fail "replaced output directory retained the original binding"
    fi
    printf '%s\n' 'descriptor-anchor-probe' >> "$REPORT_TEXT" || fail "FD-anchored report write failed"
    assert_file_contains "$bound_output/$text_basename" descriptor-anchor-probe "FD-anchored report target"
    [ ! -e "$OUTPUT_PARENT/$text_basename" ] || fail "report write followed the replacement output path"
    cleanup_workspace
    if find -P "$bound_output" -mindepth 1 -maxdepth 1 -type d -name '.run.*' -print -quit | grep -q .; then
        fail "FD-anchored scratch directory survived cleanup"
    fi
)

test_result_normalization_differential() (
    local result_directory="$TEST_TEMP/result-differential"
    local actual_text="$result_directory/actual.txt"
    local actual_json="$result_directory/actual.jsonl"
    local expected_text="$result_directory/expected.txt"
    local expected_json="$result_directory/expected.jsonl"
    local aggregate_json="$result_directory/all.jsonl"
    local boundary_value=""
    local random_evidence=""
    local random_title=""
    local random_summary=""
    local random_token=""
    local long_secret=""
    local dense_evidence=""
    local safe_dense_evidence=""
    local security_evidence=""
    local sed_counter="$result_directory/sed-count"
    local sed_call_count=0
    local counter_line=""
    local trim_input=""
    local expected_trim=""
    local actual_trim=""
    local case_number=0
    local token_number=0
    local repeat_number=0
    local -a random_tokens=(
        'alpha' ' ' $'\t' $'\r' $'\n' '\n' '\\n'
        'password=' 'PASSWORD : ' 'passwd=' 'secret:' 'token = ' 'passphrase='
        'rocommunity ' 'RWCOMMUNITY ' 'createUser ' 'CREATEUSER '
        '$6$salt$hashvalue' '$x$value' 'public' 'source' 'name' 'value'
        'plainquoted' '\path' $'\001' $'\007' $'\013' $'\014' $'\036' $'\177'
        $'\302' $'\251' $'\355' $'\225' $'\234' $'\377' '한글' '😀'
    )

    mkdir -p -- "$result_directory"
    : > "$aggregate_json"
    SCAN_ROOT="/"
    RUNTIME_MODE="off"
    OUTPUT_PARENT="$result_directory"
    SELECTED_CHECKS=""
    VERBOSE=0
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"

    legacy_normalize_utf8() {
        if [ -x /usr/bin/iconv ]; then
            /usr/bin/iconv -f UTF-8 -t UTF-8 -c
        else
            cat
        fi
    }

    legacy_normalize_evidence() {
        printf '%s' "$1" |
            awk '{gsub(/\\n/, "\n"); print}' |
            LC_ALL=C tr -d '\000-\010\013\014\016-\037\177' |
            legacy_normalize_utf8 |
            sed -E \
                -e 's/(\$[A-Za-z0-9./]+\$)[A-Za-z0-9./$]+/\1[REDACTED_HASH]/g' \
                -e 's/^([[:space:]]*(rocommunity|rwcommunity|com2sec)[[:space:]]+)[^[:space:]]+/\1[REDACTED]/I' \
                -e 's/^([[:space:]]*createUser[[:space:]]+[^[:space:]]+).*/\1 [REDACTED]/I' \
                -e 's/((password|passwd|secret|token|passphrase)[[:space:]]*[:=][[:space:]]*)[^[:space:]]+/\1[REDACTED]/Ig' |
            awk 'BEGIN { remaining = 8192 }
                {
                    if (remaining <= 0) next
                    line = $0
                    if (length(line) > remaining) line = substr(line, 1, remaining)
                    print line
                    remaining -= length(line) + 1
                }'
    }

    legacy_remove_control_bytes_into() {
        local input_value="$1"
        local destination_name="$2"
        local removable_control_bytes=$'[\001-\010\013\014\016-\037\177]'

        input_value="${input_value//$removable_control_bytes/}"
        printf -v "$destination_name" '%s' "$input_value"
    }

    legacy_json_escape_into() {
        local input_value="$1"
        local destination_name="$2"
        local escaped_value=""

        legacy_remove_control_bytes_into "$input_value" escaped_value
        case "$escaped_value" in
            *$'\n') escaped_value="${escaped_value%$'\n'}" ;;
        esac
        escaped_value="${escaped_value//\\/\\\\}"
        escaped_value="${escaped_value//\"/\\\"}"
        escaped_value="${escaped_value//$'\t'/\\t}"
        escaped_value="${escaped_value//$'\r'/\\r}"
        escaped_value="${escaped_value//$'\n'/\\n}"
        printf -v "$destination_name" '%s' "$escaped_value"
    }

    legacy_markdown_escape_into() {
        local input_value="$1"
        local destination_name="$2"

        input_value="${input_value//\\/\\\\}"
        input_value="${input_value//$'\n'/\\n}"
        input_value="${input_value//$'\r'/\\r}"
        input_value="${input_value//$'\t'/\\t}"
        input_value="${input_value//\`/\\\`}"
        input_value="${input_value//\*/\\*}"
        input_value="${input_value//_/\\_}"
        input_value="${input_value//\[/\\[}"
        input_value="${input_value//\]/\\]}"
        input_value="${input_value//#/\\#}"
        input_value="${input_value//+/\\+}"
        input_value="${input_value//-/\\-}"
        input_value="${input_value//|/\\|}"
        input_value="${input_value//</\\<}"
        input_value="${input_value//>/\\>}"
        printf -v "$destination_name" '%s' "$input_value"
    }

    write_legacy_record() {
        local title="$1"
        local summary="$2"
        local evidence="$3"
        local evidence_line=""
        local normalized_title="$title"
        local normalized_summary="$summary"
        local normalized_evidence="$evidence"
        local normalized_bundle=""
        local remaining_bundle=""
        local json_field_separator=$'\036'
        local escaped_title=""
        local escaped_summary=""
        local escaped_evidence=""
        local markdown_title=""
        local markdown_summary=""
        local criterion_url="${KISA_CCE_GUIDE_BASE}/unix/u-61/"
        local text_c1=$'\302[\200-\237]'

        legacy_remove_control_bytes_into "$normalized_title" normalized_title
        legacy_remove_control_bytes_into "$normalized_summary" normalized_summary
        legacy_remove_control_bytes_into "$normalized_evidence" normalized_evidence
        if [ -x /usr/bin/iconv ]; then
            normalized_bundle="$(/usr/bin/iconv -f UTF-8 -t UTF-8 -c <<< \
                "${normalized_title}${json_field_separator}${normalized_summary}${json_field_separator}${normalized_evidence}${json_field_separator}X")"
            case "$normalized_bundle" in
                *"${json_field_separator}X")
                    normalized_bundle="${normalized_bundle%"${json_field_separator}X"}"
                    normalized_title="${normalized_bundle%%"$json_field_separator"*}"
                    remaining_bundle="${normalized_bundle#*"$json_field_separator"}"
                    normalized_summary="${remaining_bundle%%"$json_field_separator"*}"
                    normalized_evidence="${remaining_bundle#*"$json_field_separator"}"
                    ;;
                *)
                    normalized_title=""
                    normalized_summary=""
                    normalized_evidence=""
                    ;;
            esac
        fi
        legacy_markdown_escape_into "$normalized_title" markdown_title
        legacy_markdown_escape_into "$normalized_summary" markdown_summary
        {
            printf '## U-61: %s\n\n' "$markdown_title"
            printf '| 항목 | 값 |\n'
            printf '|---|---|\n'
            printf '| 분류 | `service` |\n'
            printf '| 중요도 | `high` |\n'
            printf '| 기술 판정 | `GOOD` |\n'
            printf '| 최종 판정 | `GOOD` |\n'
            printf '| 판정 근거 | `technical` |\n'
            printf '| 적용 여부 | `true` |\n\n'
            printf '### 요약\n\n%s\n\n' "$markdown_summary"
            if [ -n "$evidence" ]; then
                printf '### 근거\n\n'
                while IFS= read -r evidence_line || [ -n "$evidence_line" ]; do
                    evidence_line="${evidence_line//$'\t'/\\t}"
                    evidence_line="${evidence_line//$'\r'/\\r}"
                    evidence_line="${evidence_line//$text_c1/?}"
                    printf '    %s\n' "$evidence_line"
                done <<< "$evidence"
                printf '\n'
            fi
            printf '### 기준\n\n'
            printf '[KISA CCE U-61](%s)\n\n' "$criterion_url"
            printf '%s\n\n' '---'
        } > "$expected_text"
        legacy_json_escape_into "$normalized_title" escaped_title
        legacy_json_escape_into "$normalized_summary" escaped_summary
        legacy_json_escape_into "$normalized_evidence" escaped_evidence
        printf '{"code":"U-61","category":"service","severity":"high","title":"%s","status":"GOOD","technical_status":"GOOD","decision_basis":"technical","review_id":"","attestation_ticket":"","attestation_approver":"","attestation_expires":"","applicable":true,"summary":"%s","evidence":"%s","criterion_url":"%s"}\n' \
            "$escaped_title" "$escaped_summary" "$escaped_evidence" "$criterion_url" > "$expected_json"
    }

    compare_result_case() {
        local case_name="$1"
        local title="$2"
        local summary="$3"
        local raw_evidence="$4"
        local legacy_evidence=""
        local json_line=""

        legacy_evidence="$(legacy_normalize_evidence "$raw_evidence")"
        write_legacy_record "$title" "$summary" "$legacy_evidence"
        : > "$actual_text"
        : > "$actual_json"
        REPORT_TEXT="$actual_text"
        REPORT_JSONL="$actual_json"
        REPORT_WRITE_ERROR=0
        COUNT_GOOD=0
        COUNT_VULNERABLE=0
        COUNT_MANUAL=0
        COUNT_NOT_APPLICABLE=0
        COUNT_ERROR=0
        COUNT_TOTAL=0

        set_result GOOD "$summary" "$raw_evidence"
        assert_equal "$raw_evidence" "$RESULT_EVIDENCE" "$case_name raw evidence retention"
        record_result U-61 service high "$title" || fail "$case_name result record failed"
        assert_equal "$legacy_evidence" "$RESULT_EVIDENCE" "$case_name normalized evidence"
        cmp -s "$expected_text" "$actual_text" || fail "$case_name Markdown report differs from expected output"
        cmp -s "$expected_json" "$actual_json" || fail "$case_name JSONL report differs from legacy output"
        IFS= read -r json_line < "$actual_json" || fail "$case_name JSONL record is unreadable"
        printf '%s\n' "$json_line" >> "$aggregate_json"
    }

    compare_result_case empty "plain title" "plain summary" ""
    compare_result_case separators "separator title" "separator summary" $'first\\nsecond\\\\nthird\n\n'
    compare_result_case controls "control title" "control summary" \
        $'a\001\002\003\004\005\006\007\010\tb\013\014c\rd\016\017\020\037\036\177e'
    compare_result_case secrets "secret title" "secret summary" \
        $'$6$salt$fixturehashbody\nrocommunity fixturecommunity 192.0.2.0/24\ncreateUser alice SHA fixturecreateauth AES fixtureprivate\npassword=fixturepassword token: fixturetoken'
    for random_token in fixturehashbody fixturecommunity fixturecreateauth fixtureprivate fixturepassword fixturetoken; do
        if grep -Fq -- "$random_token" "$actual_text" "$actual_json"; then
            fail "credential redaction retained $random_token"
        fi
    done
    compare_result_case invalid-keyword "invalid title" "invalid summary" \
        $'pass\377word=fixturepassword\ncreate\377User alice SHA fixtureauth\nleft\\\377nright'
    compare_result_case json-fields $'title\001\036\177\377 "한글"' \
        $'summary\002\036\377 \\ tab\t carriage\r line\n😀' $'evidence="quoted"\npath=\\root'
    compare_result_case markdown-structure \
        $'title | <script> [link](https://example.invalid) `code`' \
        $'summary\n## U-98: forged summary' \
        $'## U-99: forged evidence\n![remote](https://example.invalid/image)\n<script>alert(1)</script>\n| fake | table |\n```'
    if grep -Eq '^(## U-9[89]: forged|!\[remote\]|<script>|\| fake \|)' "$actual_text"; then
        fail "Markdown structure was injected by a dynamic report field"
    fi
    assert_file_contains "$actual_text" '    ## U-99: forged evidence' "Markdown evidence code indentation"
    assert_file_contains "$actual_text" '\<script\>' "Markdown title HTML escaping"
    compare_result_case trailing-line-feed "trailing title" $'summary\n\n' $'line one\nline two\n\n'

    printf -v boundary_value '%*s' 8193 ""
    boundary_value="${boundary_value// /a}"
    compare_result_case limit-8192 "boundary title" "boundary summary" "${boundary_value:0:8192}"
    compare_result_case limit-8193 "boundary title" "boundary summary" "$boundary_value"
    compare_result_case limit-valid-utf8 "boundary title" "boundary summary" "${boundary_value:0:8190}é"
    compare_result_case limit-split-utf8 "boundary title" "boundary summary" "${boundary_value:0:8191}é"
    compare_result_case limit-line-feed "boundary title" "boundary summary" "${boundary_value:0:8191}"$'\nnext'

    long_secret="longsecret"
    for ((repeat_number = 0; repeat_number < 12; repeat_number++)); do
        long_secret+="$long_secret"
    done
    compare_result_case long-secret "long secret title" "long secret summary" \
        "password=${long_secret}"$'\nsentinel=safe'
    assert_contains "$RESULT_EVIDENCE" "sentinel=safe" "long secret retains following safe evidence"

    RANDOM=619
    for ((case_number = 0; case_number < 24; case_number++)); do
        random_evidence=""
        for ((token_number = 0; token_number < 96; token_number++)); do
            random_evidence+="${random_tokens[RANDOM % ${#random_tokens[@]}]}"
        done
        random_title="title-${case_number}${random_tokens[RANDOM % ${#random_tokens[@]}]}"
        random_summary="summary-${case_number}${random_tokens[RANDOM % ${#random_tokens[@]}]}"
        compare_result_case "random-$case_number" "$random_title" "$random_summary" "$random_evidence"
    done

    sed() {
        printf 'call\n' >> "$sed_counter"
        /usr/bin/sed "$@"
    }

    dense_evidence='password=x '
    safe_dense_evidence='safevalue '
    for ((repeat_number = 0; repeat_number < 14; repeat_number++)); do
        dense_evidence+="$dense_evidence"
        safe_dense_evidence+="$safe_dense_evidence"
    done
    : > "$sed_counter"
    : > "$actual_text"
    : > "$actual_json"
    REPORT_TEXT="$actual_text"
    REPORT_JSONL="$actual_json"
    REPORT_WRITE_ERROR=0
    COUNT_GOOD=0
    COUNT_TOTAL=0
    set_result GOOD "dense summary" "$dense_evidence"
    record_result U-61 service high "dense title" || fail "dense redaction record failed"
    sed_call_count=0
    while IFS= read -r counter_line; do
        sed_call_count=$((sed_call_count + 1))
    done < "$sed_counter"
    assert_equal 1 "$sed_call_count" "dense redaction uses one external pass"
    assert_equal 8192 "${#RESULT_EVIDENCE}" "dense redaction output limit"
    case "$RESULT_EVIDENCE" in
        *'password=x'*) fail "dense redaction retained a password value" ;;
    esac

    : > "$sed_counter"
    : > "$actual_text"
    : > "$actual_json"
    REPORT_WRITE_ERROR=0
    COUNT_GOOD=0
    COUNT_TOTAL=0
    set_result GOOD "safe dense summary" "$safe_dense_evidence"
    record_result U-61 service high "safe dense title" || fail "safe dense record failed"
    sed_call_count=0
    while IFS= read -r counter_line; do
        sed_call_count=$((sed_call_count + 1))
    done < "$sed_counter"
    assert_equal 0 "$sed_call_count" "safe evidence bypasses the redactor process"
    assert_equal 8192 "${#RESULT_EVIDENCE}" "safe dense output limit"

    security_evidence=$'rocommunity roCommunitySecret 192.0.2.0/24\nrwcommunity6 rwCommunitySecret ::1\ncom2sec securityName 192.0.2.0/24 com2secCommunitySecret\ncom2sec -Cn contextName securityName 192.0.2.0/24 contextCommunitySecret\ncom2sec6 securityName ::1 com2sec6CommunitySecret\nauthcommunity log,execute authCommunitySecret default\ncreateUser alice SHA createUserAuthSecret AES createUserPrivateSecret\npassword="doubleQuotedSecret words" suffix=safe\ntoken='\''singleQuotedSecret words'\'' suffix=safe\npassphrase="unclosedQuotedSecret words\ncontrol_field=left\tright\rcarriage'
    security_evidence+=$'\nsecret='\''unclosedSingleQuotedSecret words'
    : > "$sed_counter"
    : > "$actual_text"
    : > "$actual_json"
    REPORT_WRITE_ERROR=0
    COUNT_GOOD=0
    COUNT_TOTAL=0
    set_result GOOD "security summary" "$security_evidence"
    record_result U-61 service high "security title" || fail "security redaction record failed"
    sed_call_count=0
    while IFS= read -r counter_line; do
        sed_call_count=$((sed_call_count + 1))
    done < "$sed_counter"
    assert_equal 1 "$sed_call_count" "security redaction uses one external pass"
    for random_token in \
        roCommunitySecret rwCommunitySecret com2secCommunitySecret contextCommunitySecret \
        com2sec6CommunitySecret authCommunitySecret createUserAuthSecret createUserPrivateSecret \
        doubleQuotedSecret singleQuotedSecret unclosedQuotedSecret unclosedSingleQuotedSecret; do
        if grep -Fq -- "$random_token" "$actual_text" "$actual_json"; then
            fail "security redaction retained $random_token"
        fi
    done
    assert_contains "$RESULT_EVIDENCE" "rocommunity [REDACTED] 192.0.2.0/24" "rocommunity field redaction"
    assert_contains "$RESULT_EVIDENCE" "rwcommunity6 [REDACTED] ::1" "rwcommunity6 field redaction"
    assert_contains "$RESULT_EVIDENCE" "com2sec securityName 192.0.2.0/24 [REDACTED]" "com2sec field redaction"
    assert_contains "$RESULT_EVIDENCE" "com2sec -Cn contextName securityName 192.0.2.0/24 [REDACTED]" "com2sec context field redaction"
    assert_contains "$RESULT_EVIDENCE" "com2sec6 securityName ::1 [REDACTED]" "com2sec6 field redaction"
    assert_contains "$RESULT_EVIDENCE" "authcommunity log,execute [REDACTED] default" "authcommunity field redaction"
    assert_contains "$RESULT_EVIDENCE" "password=[REDACTED] suffix=safe" "double-quoted credential redaction"
    assert_contains "$RESULT_EVIDENCE" "token=[REDACTED] suffix=safe" "single-quoted credential redaction"
    assert_contains "$RESULT_EVIDENCE" "passphrase=[REDACTED]" "unclosed credential redaction"
    assert_contains "$RESULT_EVIDENCE" "secret=[REDACTED]" "unclosed single-quoted credential redaction"
    # shellcheck disable=SC2094 # cmp only reads the original file.
    if ! LC_ALL=C tr -d '\000-\011\013-\037\177' < "$actual_text" | cmp -s - "$actual_text"; then
        fail "text evidence retained a non-newline control byte"
    fi
    unset -f sed

    trim_input=$'  alpha   beta\tgamma  \n\n delta\r value\v end \f '
    expected_trim="$(printf '%s' "$trim_input" | awk '{$1=$1; print}')"
    actual_trim="$(printf '%s' "$trim_input" | trim)"
    assert_equal "$expected_trim" "$actual_trim" "built-in whitespace trim"

    if command -v jq >/dev/null 2>&1; then
        jq -e -c . "$aggregate_json" >/dev/null || fail "differential JSONL records are not valid JSON"
    fi
)

test_report_write_failures() (
    local failure_directory="$TEST_TEMP/report-write-failure"
    local text_file="$TEST_TEMP/report-write-text"
    local json_file="$TEST_TEMP/report-write-json"
    local status=0

    mkdir -p -- "$failure_directory"
    : > "$text_file"
    : > "$json_file"
    SCAN_ROOT="/"
    RUNTIME_MODE="off"
    VERBOSE=0
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"

    REPORT_TEXT="$failure_directory"
    REPORT_JSONL="$json_file"
    set_result GOOD "summary" "evidence=value"
    status=0
    record_result U-01 account high title 2>/dev/null || status=$?
    assert_equal 1 "$status" "text report open failure status"
    assert_equal 1 "$REPORT_WRITE_ERROR" "text report open failure flag"
    assert_equal 0 "$COUNT_TOTAL" "text report open failure count"
    [ ! -s "$json_file" ] || fail "JSONL record was written after text report failure"
    scanner_exit_code
    assert_equal 2 "$?" "text report failure scanner status"

    REPORT_TEXT="$text_file"
    REPORT_JSONL="$failure_directory"
    REPORT_WRITE_ERROR=0
    : > "$text_file"
    status=0
    record_result U-01 account high title 2>/dev/null || status=$?
    assert_equal 1 "$status" "JSONL report open failure status"
    assert_equal 1 "$REPORT_WRITE_ERROR" "JSONL report open failure flag"
    assert_equal 0 "$COUNT_TOTAL" "JSONL report open failure count"
    [ -s "$text_file" ] || fail "text record was not written before JSONL failure"

    REPORT_TEXT="$failure_directory"
    REPORT_WRITE_ERROR=0
    status=0
    write_report_header 2>/dev/null || status=$?
    assert_equal 1 "$status" "report header open failure status"
    assert_equal 1 "$REPORT_WRITE_ERROR" "report header open failure flag"

    REPORT_TEXT="$failure_directory"
    REPORT_JSONL="$json_file"
    REPORT_WRITE_ERROR=0
    : > "$json_file"
    status=0
    write_report_summary 2>/dev/null || status=$?
    assert_equal 1 "$status" "text summary open failure status"
    assert_equal 1 "$REPORT_WRITE_ERROR" "text summary open failure flag"
    [ ! -s "$json_file" ] || fail "JSONL summary was written after text summary failure"

    REPORT_TEXT="$text_file"
    REPORT_JSONL="$failure_directory"
    REPORT_WRITE_ERROR=0
    : > "$text_file"
    status=0
    write_report_summary 2>/dev/null || status=$?
    assert_equal 1 "$status" "JSONL summary open failure status"
    assert_equal 1 "$REPORT_WRITE_ERROR" "JSONL summary open failure flag"
    [ -s "$text_file" ] || fail "text summary was not written before JSONL summary failure"
)

test_path_scratch_and_listener_cache_semantics() (
    local root_a="$TEST_TEMP/path-cache-root-a"
    local root_b="$TEST_TEMP/path-cache-root-b"
    local outside_directory="$TEST_TEMP/path-cache-outside-directory"
    local outside_file="$TEST_TEMP/path-cache-outside-file"
    local scratch="$TEST_TEMP/path-cache-scratch"
    local failure_scratch="$TEST_TEMP/listener-failure-scratch"
    local canonical_path=""
    local logical_path=""
    local resolved_path=""
    local stale_path=""
    local original_working_directory="$PWD"
    local original_oldpwd_state="${OLDPWD+x}:${OLDPWD:-}"
    local path_output_file="$TEST_TEMP/scratch-path-output"
    local collision_output_file="$TEST_TEMP/scratch-collision-output"
    local option_output_file="$TEST_TEMP/scratch-option-output"
    local stderr_probe_file="$TEST_TEMP/canonical-directory-stderr"
    local created_path=""
    local collision_path=""
    local first_random=""
    local status=0
    local listener_output=""
    local listener_failure=0
    local listener_count=0

    mkdir -p -- \
        "$root_a/etc" "$root_b/etc" "$outside_directory" "$scratch" "$failure_scratch"
    printf 'root-a\n' > "$root_a/etc/value"
    printf 'root-b\n' > "$root_b/etc/value"
    printf 'outside\n' > "$outside_file"
    printf 'outside\n' > "$outside_directory/value"
    ln -s ../../path-cache-outside-file "$root_a/etc/escape-file"
    ln -s "$outside_directory" "$root_a/escape-directory"
    ln -s ../.. "$root_a/etc/final-parent-escape"

    SCAN_ROOT="$root_a"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_service.sh
    . "$PROJECT_DIR/lib/checks_service.sh"
    SCRATCH_DIR="$scratch"

    canonical_directory_into "$root_a/etc/.." logical_path || fail "canonical directory output failed"
    assert_equal "$root_a" "$logical_path" "canonical directory output"
    assert_equal "$original_working_directory" "$PWD" "canonical directory working-directory restoration"
    assert_equal "$original_oldpwd_state" "${OLDPWD+x}:${OLDPWD:-}" "canonical directory OLDPWD restoration"
    status=0
    {
        canonical_directory_into "$root_a" logical_path || status=$?
        printf 'stderr-restored\n' >&2
    } 2> "$stderr_probe_file"
    assert_equal 0 "$status" "canonical directory stderr probe status"
    assert_file_contains "$stderr_probe_file" stderr-restored "canonical directory stderr restoration"

    PWD="$TEST_TEMP/nonexistent-logical-working-directory"
    canonical_directory_into "$root_a" logical_path || fail "canonical directory fallback restoration failed"
    assert_equal "$TEST_TEMP/nonexistent-logical-working-directory" "$PWD" "canonical directory fallback PWD restoration"
    assert_equal "$original_working_directory" "$(pwd -P)" "canonical directory fallback physical restoration"
    assert_equal "$original_oldpwd_state" "${OLDPWD+x}:${OLDPWD:-}" "canonical directory fallback OLDPWD restoration"
    PWD="$original_working_directory"

    fs_path_into /etc/value logical_path || fail "output-variable filesystem path failed"
    assert_equal "$root_a/etc/value" "$logical_path" "output-variable filesystem path"
    assert_equal "$logical_path" "$(fs_path /etc/value)" "filesystem path wrapper equivalence"
    resolve_rooted_path_into "$logical_path" file canonical_path || fail "output-variable rooted path failed"
    assert_equal "$root_a/etc/value" "$canonical_path" "output-variable rooted path"
    display_path_into "$canonical_path" resolved_path || fail "output-variable display path failed"
    assert_equal /etc/value "$resolved_path" "output-variable display path"

    stale_path="stale"
    status=0
    fs_path_into relative stale_path >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "invalid filesystem path status"
    assert_equal "" "$stale_path" "failed filesystem path clears its output"
    stale_path="stale"
    status=0
    resolve_rooted_path_into "$root_a/etc/missing" file stale_path >/dev/null 2>&1 || status=$?
    assert_equal 1 "$status" "missing rooted path status"
    assert_equal "" "$stale_path" "failed rooted path clears its output"

    status=0
    fs_path_into /etc/escape-file resolved_path >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "leaf symlink escape rejection"
    status=0
    fs_path_into /escape-directory/value resolved_path >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "intermediate symlink escape rejection"
    stale_path="stale"
    status=0
    resolve_rooted_path_into "$root_a/etc/final-parent-escape" directory stale_path >/dev/null 2>&1 || status=$?
    assert_equal 1 "$status" "final parent symlink escape rejection"
    assert_equal "" "$stale_path" "final parent symlink failure clears its output"

    SCAN_ROOT="$root_b"
    fs_path_into /etc/value logical_path || fail "filesystem path after root change failed"
    assert_equal "$root_b/etc/value" "$logical_path" "filesystem path cache invalidation"
    display_path_into "$root_b/etc/value" resolved_path || fail "display path after root change failed"
    assert_equal /etc/value "$resolved_path" "display path cache invalidation"
    display_path_into "$root_a/etc/value" resolved_path || fail "foreign display path failed"
    assert_equal "$root_a/etc/value" "$resolved_path" "display path does not reuse a stale root"
    resolve_rooted_path_into "$root_b/etc/value" file canonical_path || fail "rooted path after root change failed"
    assert_equal "$root_b/etc/value" "$canonical_path" "rooted path cache invalidation"

    set +C
    new_scratch_file "component name.+_-" > "$path_output_file" || fail "scratch file creation failed"
    case $- in *C*) fail "scratch creation enabled noclobber in its caller" ;; esac
    created_path="$(< "$path_output_file")"
    case "$created_path" in
        "$scratch"/*) ;;
        *) fail "scratch file escaped its private directory: $created_path" ;;
    esac
    [ -f "$created_path" ] && [ ! -L "$created_path" ] || fail "scratch path is not a regular file"
    assert_equal 600 "$(mode_of "$created_path")" "scratch file mode"

    RANDOM=619
    first_random="$RANDOM"
    collision_path="$scratch/collision.${BASHPID}.${first_random}.0"
    printf 'original\n' > "$collision_path"
    RANDOM=619
    new_scratch_file collision > "$collision_output_file" || fail "scratch collision retry failed"
    created_path="$(< "$collision_output_file")"
    [ "$created_path" != "$collision_path" ] || fail "scratch collision overwrote an existing path"
    assert_equal original "$(< "$collision_path")" "scratch collision content preservation"
    assert_equal 600 "$(mode_of "$created_path")" "scratch retry file mode"

    set -C
    new_scratch_file noclobber-enabled > "$option_output_file" || {
        set +C
        fail "scratch creation failed with inherited noclobber"
    }
    case $- in *C*) ;; *) fail "scratch creation disabled inherited noclobber" ;; esac
    set +C
    status=0
    new_scratch_file ../escape >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "unsafe scratch name rejection"

    SCAN_ROOT="/"
    RUNTIME_MODE="auto"
    printf '0\n' > "$scratch/listener-count"
    : > "$scratch/listener-arguments"
    capture_command() {
        local command_name="$1"
        local invocation_count=0

        shift
        [ "$command_name" = "ss" ] || return 127
        IFS= read -r invocation_count < "$SCRATCH_DIR/listener-count" || return 2
        printf '%s\n' "$((invocation_count + 1))" > "$SCRATCH_DIR/listener-count"
        printf '%s\n' "$*" >> "$SCRATCH_DIR/listener-arguments"
        [ "$listener_failure" -eq 0 ] || return 42
        case "$*" in
            '-H -lntp')
                printf '%s\n' \
                    'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))' \
                    'LISTEN 0 128 127.0.0.1:25 0.0.0.0:* users:(("smtp",pid=2,fd=4))'
                ;;
            '-H -lnup')
                printf '%s\n' 'UNCONN 0 0 127.0.0.1:53 0.0.0.0:* users:(("named",pid=3,fd=5))'
                ;;
            '-H -lntup')
                printf '%s\n' \
                    'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))' \
                    'udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* users:(("named",pid=3,fd=5))'
                ;;
            *) return 2 ;;
        esac
    }

    LISTENER_SNAPSHOT_CACHE_ENABLED=0
    listener_output="$(port_listener_facts 22 tcp)" || fail "uncached TCP listener collection failed"
    assert_contains "$listener_output" "0.0.0.0:22" "uncached TCP listener row"
    port_listener_facts 22 tcp >/dev/null || fail "second uncached TCP listener collection failed"
    IFS= read -r listener_count < "$scratch/listener-count"
    assert_equal 2 "$listener_count" "direct listener helpers remain uncached by default"

    LISTENER_SNAPSHOT_CACHE_ENABLED=1
    listener_output="$(port_listener_facts 22 tcp)" || fail "cached TCP listener collection failed"
    assert_contains "$listener_output" "0.0.0.0:22" "cached TCP listener row"
    listener_output="$(port_listener_facts 25 tcp)" || fail "cached TCP listener reuse failed"
    assert_contains "$listener_output" "127.0.0.1:25" "cached TCP second port"
    listener_output="$(port_listener_facts 53 udp)" || fail "cached UDP listener collection failed"
    assert_contains "$listener_output" "127.0.0.1:53" "cached UDP listener row"
    listener_output="$(port_listener_facts 22 any)" || fail "cached mixed listener collection failed"
    assert_contains "$listener_output" "tcp LISTEN" "cached mixed listener row"
    IFS= read -r listener_count < "$scratch/listener-count"
    assert_equal 5 "$listener_count" "one listener snapshot per requested transport"
    assert_equal 3 "$(grep -Fxc -- '-H -lntp' "$scratch/listener-arguments")" "TCP listener invocation count"
    assert_equal 1 "$(grep -Fxc -- '-H -lnup' "$scratch/listener-arguments")" "UDP listener invocation count"
    assert_equal 1 "$(grep -Fxc -- '-H -lntup' "$scratch/listener-arguments")" "mixed listener invocation count"
    assert_equal 600 "$(mode_of "$scratch/.listener-snapshot-any")" "successful listener snapshot mode"
    assert_equal 600 "$(mode_of "$scratch/.listener-snapshot-any.status")" "successful listener status mode"
    service_listener_state 22 || fail "service listener state did not reuse the mixed snapshot"
    IFS= read -r listener_count < "$scratch/listener-count"
    assert_equal 5 "$listener_count" "service listener snapshot reuse"

    printf '0\n' > "$scratch/listener-count"
    : > "$scratch/listener-arguments"
    LISTENER_SNAPSHOT_GENERATION=0
    SCAN_EPOCH_ACTIVE=1
    SCAN_EPOCH_ID=1
    listener_reset_epoch_cache
    record_result() { return 0; }
    check_u_01() {
        service_listener_state 80 22 || fail "same-criterion multi-port listener lookup failed"
        set_result GOOD "listener generation fixture"
    }
    check_u_02() {
        service_listener_state 22 || fail "next-criterion listener refresh failed"
        set_result GOOD "listener generation fixture"
    }
    run_one_check U-01 account high first
    IFS= read -r listener_count < "$scratch/listener-count"
    assert_equal 1 "$listener_count" "multiple ports in one criterion share a listener snapshot"
    run_one_check U-02 account high second
    IFS= read -r listener_count < "$scratch/listener-count"
    assert_equal 1 "$listener_count" "all criteria share one listener snapshot in an epoch"
    SCAN_EPOCH_ID=2
    listener_reset_epoch_cache
    run_one_check U-02 account high second
    IFS= read -r listener_count < "$scratch/listener-count"
    assert_equal 2 "$listener_count" "a new scan epoch refreshes the listener snapshot"
    assert_equal 0 "$LISTENER_SNAPSHOT_GENERATION" "listener cache is no longer criterion-generated"

    SCRATCH_DIR="$failure_scratch"
    SCAN_EPOCH_ACTIVE=0
    LISTENER_SNAPSHOT_GENERATION=0
    printf '0\n' > "$failure_scratch/listener-count"
    : > "$failure_scratch/listener-arguments"
    listener_failure=1
    status=0
    port_listener_facts 22 tcp >/dev/null 2>&1 || status=$?
    assert_equal 42 "$status" "listener command failure status"
    status=0
    port_listener_facts 22 tcp >/dev/null 2>&1 || status=$?
    assert_equal 42 "$status" "cached listener command failure status"
    IFS= read -r listener_count < "$failure_scratch/listener-count"
    assert_equal 1 "$listener_count" "listener failures are snapshotted once"
    assert_equal 600 "$(mode_of "$failure_scratch/.listener-snapshot-tcp")" "listener snapshot mode"
    assert_equal 600 "$(mode_of "$failure_scratch/.listener-snapshot-tcp.status")" "listener status mode"
    status=0
    service_listener_state 22 >/dev/null 2>&1 || status=$?
    assert_equal 2 "$status" "service listener failure mapping"
)

test_existing_output_directory_is_not_mutated() (
    local root="$TEST_TEMP/output-root"
    local output="$TEST_TEMP/existing-output"
    local before_mode=""
    local after_mode=""

    write_os_release "$root" ubuntu 26.04 "Ubuntu 26.04 LTS"
    mkdir -p -- "$output"
    /bin/chmod 0755 "$output"
    before_mode="$(mode_of "$output")"

    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    OUTPUT_PARENT="$output"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    if (initialize_workspace >/dev/null 2>&1); then
        fail "insecure existing output directory was accepted"
    fi
    after_mode="$(mode_of "$output")"
    assert_equal "$before_mode" "$after_mode" "existing output directory mode"
)

test_sysctl_layering_masks_and_drift() (
    local root="$TEST_TEMP/sysctl-root"
    local expected=""
    local actual=""
    local files=""
    local explanation=""

    mkdir -p -- \
        "$root/etc/sysctl.d" \
        "$root/etc/sysctl.conf.d" \
        "$root/run/sysctl.d" \
        "$root/usr/local/lib/sysctl.d" \
        "$root/usr/lib/sysctl.d" \
        "$root/lib/sysctl.d" \
        "$TEST_TEMP/sysctl-scratch"

    printf '%s\n' 'net.ipv4.ip_forward = 0' > "$root/usr/lib/sysctl.d/10-default.conf"
    printf '%s\n' 'net.ipv4.ip_forward = 1' > "$root/run/sysctl.d/40-runtime.conf"
    printf '%s\n' 'net/ipv4/ip_forward = 2' > "$root/etc/sysctl.d/90-local.conf"
    printf '%s\n' 'kernel.kptr_restrict = 0' > "$root/usr/lib/sysctl.d/50-same.conf"
    printf '%s\n' 'kernel.kptr_restrict = 2' > "$root/etc/sysctl.d/50-same.conf"
    printf '%s\n' 'vm.swappiness = 20' > "$root/etc/sysctl.d/20-local.conf"
    printf '%s\n' 'vm.swappiness = 90' > "$root/usr/lib/sysctl.d/95-vendor-late.conf"
    printf '%s\n' 'fs.protected_fifos = 2' > "$root/usr/lib/sysctl.d/60-masked.conf"
    ln -s /dev/null "$root/etc/sysctl.d/60-masked.conf"
    printf '%s\n' 'kernel.perf_event_paranoid = 3' > "$root/etc/sysctl-linked-source.conf"
    ln -s /etc/sysctl-linked-source.conf "$root/etc/sysctl.d/80-absolute-link.conf"
    {
        printf '%s\n' 'net.ipv4.conf.*.rp_filter = 2'
        printf '%s\n' '-net.ipv4.conf.all.rp_filter'
        printf '%s\n' 'net.ipv4.conf.eth0.rp_filter = 1'
    } > "$root/usr/lib/sysctl.d/70-network-glob.conf"
    printf '%s\n' 'net.ipv4.ip_forward = 999' > "$root/etc/sysctl.conf.d/99-inactive.conf"
    printf '%s\n' 'net.ipv4.ip_forward = 998' > "$root/lib/sysctl.d/99-legacy.conf"
    printf '%s\n' 'net.ipv4.ip_forward = 997' > "$root/etc/sysctl.conf"
    printf '%s\n' 'kernel.yama.ptrace_scope = 3' > "$root/etc/sysctl.d/96 custom Ω.conf"
    {
        printf '%s\n' 'net.ipv4.conf.eth0.rp_filter = 2'
        printf '%s\n' '-net.ipv4.conf.eth0.rp_filter'
        printf '%s\n' '-net.ipv4.conf.eth2.rp_filter'
        printf '%s\n' 'net.ipv4.conf.eth2.rp_filter = 3'
        printf '%s\n' 'net.ipv4.conf.eth3.rp_filter = 4'
        printf '%s\n' '-net.ipv4.conf.eth3.rp_filter'
        printf '%s\n' 'net.ipv4.conf.eth3.rp_filter = 5'
    } > "$root/etc/sysctl.d/97-explicit-and-exclusion.conf"

    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    SCRATCH_DIR="$TEST_TEMP/sysctl-scratch"

    actual="$(sysctl_static_value net.ipv4.ip_forward)" || fail "dotted sysctl key was unresolved"
    expected="2$(printf '\t')/etc/sysctl.d/90-local.conf:1"
    assert_equal "$expected" "$actual" "slash-form key normalization and lexical precedence"

    actual="$(sysctl_static_value kernel.kptr_restrict)" || fail "same-basename key was unresolved"
    expected="2$(printf '\t')/etc/sysctl.d/50-same.conf:1"
    assert_equal "$expected" "$actual" "same-basename directory precedence"

    actual="$(sysctl_static_value vm.swappiness)" || fail "global lexical ordering key was unresolved"
    expected="90$(printf '\t')/usr/lib/sysctl.d/95-vendor-late.conf:1"
    assert_equal "$expected" "$actual" "global lexical ordering"

    if sysctl_static_value fs.protected_fifos >/dev/null 2>&1; then
        fail "/dev/null mask did not suppress the lower-priority same-basename file"
    fi

    actual="$(sysctl_static_value kernel.yama.ptrace_scope)" || fail "sysctl filename with spaces or Unicode was ignored"
    assert_contains "$actual" $'3\t/etc/sysctl.d/96 custom Ω.conf:1' "non-ASCII sysctl filename"
    if sysctl_static_value net.ipv4.conf.eth0.rp_filter >/dev/null 2>&1; then
        fail "later exact exclusion did not replace an earlier assignment"
    fi
    actual="$(sysctl_static_value net.ipv4.conf.eth2.rp_filter)" || fail "assignment after exact exclusion was not applied"
    assert_contains "$actual" $'3\t/etc/sysctl.d/97-explicit-and-exclusion.conf:4' "assignment after exact exclusion"
    actual="$(sysctl_static_value net.ipv4.conf.eth3.rp_filter)" || fail "final assignment after exclusion was not applied"
    assert_contains "$actual" $'5\t/etc/sysctl.d/97-explicit-and-exclusion.conf:7' "assignment-exclusion-assignment order"

    actual="$(sysctl_static_value net.ipv4.conf.eth1.rp_filter)" || fail "matching sysctl glob was unresolved"
    expected="2$(printf '\t')/usr/lib/sysctl.d/70-network-glob.conf:1"
    assert_equal "$expected" "$actual" "sysctl glob resolution"

    if sysctl_static_value net.ipv4.conf.all.rp_filter >/dev/null 2>&1; then
        fail "explicit sysctl exclusion did not suppress a matching glob"
    fi

    actual="$(sysctl_static_value kernel.perf_event_paranoid)" || fail "offline-root absolute symlink was unresolved"
    expected="3$(printf '\t')/etc/sysctl.d/80-absolute-link.conf:1"
    assert_equal "$expected" "$actual" "offline-root absolute symlink resolution"

    printf '%s\n' 'kernel.randomize_va_space = 0' > "$TEST_TEMP/outside.conf"
    ln -s ../../../outside.conf "$root/etc/sysctl.d/85-escaping-link.conf"
    if sysctl_static_value kernel.randomize_va_space >/dev/null 2>&1; then
        fail "offline sysctl resolution escaped the selected root"
    fi
    rm -f -- "$root/etc/sysctl.d/85-escaping-link.conf"

    files="$(sysctl_static_files)"
    assert_contains "$files" "/etc/sysctl.d/50-same.conf" "selected sysctl files"
    if printf '%s\n' "$files" | grep -Fq -- "/usr/lib/sysctl.d/50-same.conf"; then
        fail "lower-priority same-basename file remained selected"
    fi
    if printf '%s\n' "$files" | grep -Fq -- "/lib/sysctl.d/99-legacy.conf"; then
        fail "legacy /lib directory was treated as an independent layer"
    fi

    runtime_enabled() { return 0; }
    sysctl_loader_kind() { printf '%s\n' systemd-sysctl; }
    systemd_sysctl_stream() { printf '%s\n' 'net.ipv4.ip_forward = 2'; }
    sysctl_runtime_value_into() { printf -v "$2" '%s' 1; }
    explanation="$(sysctl_explain net.ipv4.ip_forward)"
    assert_contains "$explanation" "runtime=1" "runtime sysctl explanation"
    assert_contains "$explanation" "drift=present" "runtime drift explanation"
    assert_contains "$explanation" "inactive_nonstandard_directory=/etc/sysctl.conf.d" "inactive sysctl directory warning"

    sysctl_runtime_value_into() { printf -v "$2" '%s' 2; }
    explanation="$(sysctl_explain net.ipv4.ip_forward)"
    assert_contains "$explanation" "drift=none" "matching runtime value"

    mkdir -p -- "$root/run/credentials/@system"
    printf '%s\n' 'net.ipv4.ip_forward=2' > "$root/run/credentials/@system/sysctl.extra"
    if sysctl_explain net.ipv4.ip_forward >/dev/null 2>&1; then
        fail "sysctl.extra credential override was silently accepted"
    fi
    rm -f -- "$root/run/credentials/@system/sysctl.extra"

    /bin/chmod 000 "$root/run/sysctl.d"
    if sysctl_static_files >/dev/null 2>&1; then
        fail "unreadable sysctl directory was silently accepted"
    fi
    /bin/chmod 0700 "$root/run/sysctl.d"

    printf '%s\n' 'net.ipv4.ip_forward = 1' > "$root/etc/sysctl.d/98-unreadable.conf"
    /bin/chmod 000 "$root/etc/sysctl.d/98-unreadable.conf"
    if sysctl_static_value net.ipv4.ip_forward >/dev/null 2>&1; then
        fail "unreadable selected sysctl file was silently skipped"
    fi
    /bin/chmod 0600 "$root/etc/sysctl.d/98-unreadable.conf"
)

test_offline_absolute_symlinks_stay_inside_scan_root() (
    local root="$TEST_TEMP/symlink-root"
    local scratch="$TEST_TEMP/symlink-scratch"
    local expanded=""
    local resolved=""

    mkdir -p -- "$root/etc/pam.d" "$root/etc/authselect" "$root/etc/sysctl.d" "$root/usr/lib/pam.d" "$scratch"
    printf '%s\n' 'auth required pam_faillock.so preauth' > "$root/etc/authselect/system-auth"
    ln -s /etc/authselect/system-auth "$root/etc/pam.d/system-auth"
    printf '%s\n' 'auth required pam_permit.so' > "$TEST_TEMP/outside-pam"
    ln -s ../../../outside-pam "$root/etc/pam.d/escape"
    printf '%s\n' 'auth required pam_permit.so' > "$root/usr/lib/pam.d/escape"
    printf '%s\n' 'kernel.kptr_restrict = 2' > "$root/etc/sysctl.conf"
    ln -s /etc/sysctl.conf "$root/etc/sysctl.d/99-sysctl.conf"

    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    SCRATCH_DIR="$scratch"

    expanded="$(pam_expand_service system-auth auth)" || fail "rooted PAM absolute symlink was not resolved"
    assert_contains "$expanded" "pam_faillock.so preauth" "rooted PAM symlink content"
    if pam_service_file escape >/dev/null 2>&1; then
        fail "PAM symlink escaped the offline scan root"
    fi
    resolved="$(sysctl_static_value kernel.kptr_restrict)" || fail "rooted sysctl absolute symlink was not resolved"
    assert_contains "$resolved" $'2\t/etc/sysctl.d/99-sysctl.conf:1' "rooted sysctl symlink source"
)

test_layered_consumer_errors_and_symlink_escape() (
    local root="$TEST_TEMP/layered-consumer-root"
    local scratch="$TEST_TEMP/layered-consumer-scratch"
    local status=0
    local resolved=""

    mkdir -p -- \
        "$root/etc/ssh/sshd_config.d" "$root/etc/security/pwquality.conf.d" \
        "$root/etc/login.defs.d" "$root/usr/lib/login.defs.d" "$scratch"
    printf '%s\n' 'PermitRootLogin no' > "$TEST_TEMP/outside-sshd.conf"
    printf '%s\n' 'minlen = 99' > "$TEST_TEMP/outside-pwquality.conf"
    ln -s ../../../../outside-sshd.conf "$root/etc/ssh/sshd_config.d/10-escape.conf"
    printf '%s\n' 'Include /etc/ssh/sshd_config.d/*.conf' > "$root/etc/ssh/sshd_config"
    ln -s ../../../../outside-pwquality.conf "$root/etc/security/pwquality.conf.d/10-escape.conf"
    {
        printf '%s\n' 'PASS_MAX_DAYS 90'
        printf '%s\n' 'PASS_MAX_DAYS 91'
    } > "$root/etc/login.defs"
    printf '%s\n' 'PASS_MAX_DAYS 120' > "$root/usr/lib/login.defs.d/50-role.defs"
    printf '%s\n' 'PASS_MAX_DAYS 60' > "$root/etc/login.defs.d/50-role.defs"
    {
        printf '%s\n' 'PASS_MAX_DAYS 45'
        printf '%s\n' 'PASS_MAX_DAYS 5'
    } > "$root/etc/login.defs.d/90-final.defs"

    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_account_file.sh
    . "$PROJECT_DIR/lib/checks_account_file.sh"
    SCRATCH_DIR="$scratch"

    set_test_platform rhel 10.2 "Red Hat Enterprise Linux 10.2"
    mv -- "$root/etc/login.defs.d" "$root/etc/login.defs.d.saved"
    resolved="$(login_defs_value PASS_MAX_DAYS)" || fail "RHEL main login.defs value was not resolved"
    assert_contains "$resolved" $'90\t/etc/login.defs:1' "RHEL main login.defs first value"
    mv -- "$root/etc/login.defs.d.saved" "$root/etc/login.defs.d"
    resolved="$(login_defs_value PASS_MAX_DAYS)" || fail "RHEL login.defs.d value was not resolved"
    assert_contains "$resolved" $'5\t/etc/login.defs.d/90-final.defs:2' "RHEL login.defs.d lexical override"
    resolved="$(pam_login_defs_value PASS_MAX_DAYS)" || fail "RHEL PAM login.defs.d value was not resolved"
    assert_contains "$resolved" $'45\t/etc/login.defs.d/90-final.defs:1' "RHEL PAM login.defs.d first key"
    set_test_platform rhel 9.8 "Red Hat Enterprise Linux 9.8"
    resolved="$(login_defs_value PASS_MAX_DAYS)" || fail "RHEL 9 login.defs value was not resolved"
    assert_contains "$resolved" $'91\t/etc/login.defs:2' "RHEL 9 legacy login.defs path"
    set_test_platform ubuntu 26.04 "Ubuntu 26.04 LTS"
    resolved="$(login_defs_value PASS_MAX_DAYS)" || fail "Ubuntu login.defs value was not resolved"
    assert_contains "$resolved" $'91\t/etc/login.defs:2' "Ubuntu legacy login.defs path"

    scanner_sshd_static_value PermitRootLogin >/dev/null 2>&1
    status=$?
    assert_equal 2 "$status" "escaping SSH drop-in rejection"
    pwquality_files >/dev/null 2>&1
    status=$?
    assert_equal 2 "$status" "escaping pwquality drop-in rejection"
    rm -f -- "$root/etc/security/pwquality.conf.d/10-escape.conf"
    mkdir -p -- "$root/usr/lib/security"
    printf '%s\n' 'minlen = 99' > "$root/usr/lib/security/pwquality.conf"
    ln -s ../../../outside-pwquality.conf "$root/etc/security/pwquality.conf"
    pwquality_files >/dev/null 2>&1
    status=$?
    assert_equal 2 "$status" "escaping local pwquality main must not fall back to vendor"
    rm -f -- "$root/etc/security/pwquality.conf"

    rm -f -- "$root/etc/ssh/sshd_config.d/10-escape.conf"
    /bin/chmod 000 "$root/etc/ssh/sshd_config.d"
    scanner_sshd_static_value PermitRootLogin >/dev/null 2>&1
    status=$?
    /bin/chmod 0700 "$root/etc/ssh/sshd_config.d"
    assert_equal 2 "$status" "unreadable SSH drop-in directory"
)

test_layered_directory_symlink_escape() (
    local root="$TEST_TEMP/layered-directory-root"
    local scratch="$TEST_TEMP/layered-directory-scratch"
    local outside="$TEST_TEMP/layered-directory-outside"
    local status=0

    mkdir -p -- "$root/etc/ssh" "$root/etc/security" "$outside" "$scratch"
    printf '%s\n' 'PermitRootLogin yes' > "$outside/10-escape.conf"
    ln -s "$outside" "$root/etc/ssh/sshd_config.d"
    ln -s "$outside" "$root/etc/security/pwquality.conf.d"
    ln -s "$outside" "$root/etc/sysctl.d"

    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    SCRATCH_DIR="$scratch"

    select_layered_files .conf /etc/ssh/sshd_config.d >/dev/null 2>&1
    status=$?
    assert_equal 2 "$status" "SSH drop-in directory escape"
    select_layered_files .conf /etc/security/pwquality.conf.d >/dev/null 2>&1
    status=$?
    assert_equal 2 "$status" "pwquality drop-in directory escape"
    select_layered_files .conf /etc/sysctl.d >/dev/null 2>&1
    status=$?
    assert_equal 2 "$status" "sysctl drop-in directory escape"
)

test_cli_platform_selection_and_reports() (
    local scanner_copy="$TEST_TEMP/scanner-copy"
    local supported_root="$TEST_TEMP/cli-supported-root"
    local unsupported_root="$TEST_TEMP/cli-unsupported-root"
    local output_dir="$TEST_TEMP/cli-output"
    local unsupported_output="$TEST_TEMP/cli-unsupported-output"
    local command_output=""
    local command_status=""
    local text_report=""
    local jsonl_report=""
    local short_verbose_output=""
    local short_verbose_stdout="$TEST_TEMP/cli-short-verbose.stdout"
    local short_verbose_stderr="$TEST_TEMP/cli-short-verbose.stderr"
    local matrix_id=""
    local matrix_version=""
    local matrix_name=""
    local matrix_id_like=""
    local matrix_codename=""
    local matrix_family=""
    local matrix_base=""
    local matrix_root=""
    local matrix_output=""
    local matrix_number=0
    local help_output=""
    local empty_option=""
    local direct_output_target="$TEST_TEMP/direct-output-target"
    local direct_output_link="$TEST_TEMP/direct-output-link"
    local ancestor_output_target="$TEST_TEMP/ancestor-output-target"
    local ancestor_output_link="$TEST_TEMP/ancestor-output-link"
    local nested_output="$TEST_TEMP/normal-output-parent/child/reports"
    local untrusted_output_parent="$TEST_TEMP/untrusted-output-parent"
    local catalog_backup="$TEST_TEMP/criteria.tsv.valid"
    local catalog_reordered="$TEST_TEMP/criteria.tsv.reordered"
    local explain_output_dir="$TEST_TEMP/explain-output-unused"
    local injection_root="$TEST_TEMP/evidence-injection-root"
    local injection_output_dir="$TEST_TEMP/evidence-injection-output"
    local injection_file=""
    local injection_result_count=""
    local control_root=""
    local header_root="$TEST_TEMP/header-control-root"
    local header_output="$TEST_TEMP/header-control-output"

    mkdir -p -- "$scanner_copy/bin" "$scanner_copy/lib" "$scanner_copy/data" \
        "$scanner_copy/share/kisa-cce-linux-scanner/locale"
    cp -- "$PROJECT_DIR/bin/kisa-cce-scan" "$scanner_copy/bin/kisa-cce-scan"
    cp -- "$PROJECT_DIR/lib/core.sh" "$scanner_copy/lib/core.sh"
    cp -- "$PROJECT_DIR/lib/evidence.sh" "$scanner_copy/lib/evidence.sh"
    cp -- "$PROJECT_DIR/lib/i18n.sh" "$scanner_copy/lib/i18n.sh"
    cp -- "$PROJECT_DIR/lib/kisa-cce-scan-main.sh" "$scanner_copy/lib/kisa-cce-scan-main.sh"
    cp -- "$PROJECT_DIR/lib/policy.sh" "$scanner_copy/lib/policy.sh"
    cp -- "$PROJECT_DIR/lib/scan_epoch.sh" "$scanner_copy/lib/scan_epoch.sh"
    cp -- "$PROJECT_DIR/lib/resolvers.sh" "$scanner_copy/lib/resolvers.sh"
    cp -- "$PROJECT_DIR/data/criteria.tsv" "$scanner_copy/data/criteria.tsv"
    cp -- "$PROJECT_DIR/data/VERSION" "$scanner_copy/data/VERSION"
    cp -R -- "$PROJECT_DIR/share/kisa-cce-linux-scanner/locale/en" \
        "$PROJECT_DIR/share/kisa-cce-linux-scanner/locale/ko" \
        "$scanner_copy/share/kisa-cce-linux-scanner/locale/"
    {
        printf '%s\n' '#!/bin/bash'
        printf '%s\n' 'check_u_01() { set_result GOOD "SSH의 root 직접 접속이 차단되어 있습니다." "fixture=true"; }'
    } > "$scanner_copy/lib/checks_fixture.sh"
    chmod 0755 -- "$scanner_copy/bin/kisa-cce-scan"

    write_os_release "$supported_root" ubuntu 26.04 "Ubuntu 26.04 LTS"
    write_os_release "$unsupported_root" alpine 3.22 "Alpine Linux 3.22"
    mkdir -p -- "$supported_root/etc/sysctl.d"
    printf '%s\n' 'net.ipv4.ip_forward = 0' > "$supported_root/etc/sysctl.d/90-local.conf"

    help_output="$("$scanner_copy/bin/kisa-cce-scan" --help)" || fail "CLI help failed"
    assert_contains "$help_output" "--root / keeps live collection" "live root help contract"
    assert_contains "$help_output" "validated but unused with --explain-sysctl" "explain output help contract"
    assert_contains "$help_output" "errors take precedence" "scanner error exit precedence help contract"
    if printf '%s\n' "$help_output" |
        grep -Ev '^\[[[:space:]]*[0-9]+\.[0-9]{6}\] kisa-cce-scan: .*$' >/dev/null; then
        fail "CLI help contains a line without the console prefix"
    fi

    for empty_option in --root --output-dir --checks --explain-sysctl; do
        command_status=0
        command_output="$("$scanner_copy/bin/kisa-cce-scan" "$empty_option" "" 2>&1)" || command_status=$?
        assert_equal 2 "$command_status" "$empty_option separated empty value rejection"
        assert_contains "$command_output" "$empty_option requires a value" "$empty_option separated empty value message"

        command_status=0
        command_output="$("$scanner_copy/bin/kisa-cce-scan" "${empty_option}=" 2>&1)" || command_status=$?
        assert_equal 2 "$command_status" "$empty_option attached empty value rejection"
        assert_contains "$command_output" "$empty_option requires a value" "$empty_option attached empty value message"
    done

    command_status=0
    command_output="$("$scanner_copy/bin/kisa-cce-scan" --root $'relative\nforged-line' 2>&1)" || command_status=$?
    assert_equal 2 "$command_status" "relative multiline root rejection"
    if printf '%s\n' "$command_output" |
        grep -Ev '^\[[[:space:]]*[0-9]+\.[0-9]{6}\] kisa-cce-scan: .*$' >/dev/null; then
        fail "multiline scanner error produced an unframed terminal line"
    fi
    if printf '%s\n' "$command_output" | grep -q '^forged-line$'; then
        fail "multiline scanner error injected a terminal line"
    fi

    for control_root in \
        "$TEST_TEMP/control-root"$'\n''## U-99: forged' \
        "$TEST_TEMP/control-root"$'\r''carriage' \
        "$TEST_TEMP/control-root"$'\t''tab'; do
        write_os_release "$control_root" ubuntu 26.04 "Ubuntu 26.04 LTS"
        command_status=0
        command_output="$("$scanner_copy/bin/kisa-cce-scan" \
            --root "$control_root" --checks U-01 --no-runtime 2>&1)" || command_status=$?
        assert_equal 2 "$command_status" "separated root control-character rejection"
        assert_contains "$command_output" "--root contains a disallowed control character" \
            "separated root control-character message"
        case "$command_output" in *markdown_report=*|*jsonl_report=*) fail "rejected root produced report paths" ;; esac

        command_status=0
        command_output="$("$scanner_copy/bin/kisa-cce-scan" \
            "--root=$control_root" --checks U-01 --no-runtime 2>&1)" || command_status=$?
        assert_equal 2 "$command_status" "attached root control-character rejection"
        assert_contains "$command_output" "--root contains a disallowed control character" \
            "attached root control-character message"
        case "$command_output" in *markdown_report=*|*jsonl_report=*) fail "rejected attached root produced report paths" ;; esac
    done

    command_output="$("$scanner_copy/bin/kisa-cce-scan" \
        --root "$supported_root" \
        --output-dir "$output_dir" \
        --checks u-01,U-01 \
        --verbose \
        --no-runtime 2>&1)"
    command_status="$?"
    assert_equal 0 "$command_status" "supported CLI scan exit status"
    text_report="$(scanner_console_value markdown_report "$command_output")"
    jsonl_report="$(scanner_console_value jsonl_report "$command_output")"
    [ -f "$text_report" ] || fail "CLI Markdown report was not created"
    [ -f "$jsonl_report" ] || fail "CLI JSONL report was not created"
    assert_file_contains "$text_report" "| 전체 | 1 |" "selected CLI result count"
    assert_file_contains "$text_report" "runtime_collection: off" "offline runtime state"
    assert_equal 600 "$(mode_of "$text_report")" "CLI Markdown report mode"
    assert_equal 600 "$(mode_of "$jsonl_report")" "CLI JSONL report mode"
    assert_contains "$command_output" "kisa-cce-scan: platform=ubuntu version=26.04 family=debian" "verbose platform line"
    assert_contains "$command_output" \
        "kisa-cce-scan: check=U-01 status=GOOD title=Restrict remote login for the root account" \
        "verbose check line"
    assert_contains "$command_output" "kisa-cce-scan: summary total=1 good=1" "verbose summary line"
    if ! printf '%s\n' "$command_output" |
        grep -Eq '^\[[[:space:]]*[0-9]+\.[0-9]{6}\] kisa-cce-scan: check=U-01 status=GOOD title=Restrict remote login for the root account$'; then
        fail "verbose output did not use the dmesg-style timestamp format"
    fi
    if printf '%s\n' "$command_output" |
        grep -Ev '^\[[[:space:]]*[0-9]+\.[0-9]{6}\] kisa-cce-scan: .*$' >/dev/null; then
        fail "scanner output contains a line without the console prefix"
    fi

    mkdir -p -- "$direct_output_target" "$ancestor_output_target/existing"
    ln -s -- "$direct_output_target" "$direct_output_link"
    ln -s -- "$ancestor_output_target" "$ancestor_output_link"
    for output_dir in "$direct_output_link" "$direct_output_link/" \
        "$ancestor_output_link/existing" "$ancestor_output_link/missing"; do
        command_status=0
        command_output="$("$scanner_copy/bin/kisa-cce-scan" \
            --root "$supported_root" --output-dir "$output_dir" --checks U-01 --no-runtime 2>&1)" || command_status=$?
        assert_equal 2 "$command_status" "output symlink rejection for $output_dir"
        assert_contains "$command_output" "output directory path contains a symbolic link" "output symlink rejection message for $output_dir"
    done
    [ ! -e "$ancestor_output_target/missing" ] || fail "ancestor output symlink created a missing target child"

    mkdir -p -- "$untrusted_output_parent"
    chmod 0777 -- "$untrusted_output_parent"
    command_status=0
    command_output="$("$scanner_copy/bin/kisa-cce-scan" \
        --root "$supported_root" --output-dir "$untrusted_output_parent/reports" \
        --checks U-01 --no-runtime 2>&1)" || command_status=$?
    assert_equal 2 "$command_status" "untrusted output ancestor rejection"
    assert_contains "$command_output" "output directory parent path is not trusted" "untrusted output ancestor message"
    [ ! -e "$untrusted_output_parent/reports" ] || fail "untrusted output ancestor created a report directory"

    command_status=0
    command_output="$("$scanner_copy/bin/kisa-cce-scan" \
        --root "$supported_root" --output-dir "$nested_output" --checks U-01 --no-runtime 2>&1)" || command_status=$?
    assert_equal 0 "$command_status" "normal nested output directory"
    text_report="$(scanner_console_value markdown_report "$command_output")"
    [ -f "$text_report" ] || fail "normal nested output report was not created"

    command_status=0
    "$scanner_copy/bin/kisa-cce-scan" \
        --root "$supported_root" \
        --output-dir "$TEST_TEMP/cli-short-verbose-output" \
        --checks U-01 \
        -v > "$short_verbose_stdout" 2> "$short_verbose_stderr" || command_status=$?
    short_verbose_output="$(< "$short_verbose_stderr")"
    assert_equal 0 "$command_status" "short verbose option exit status"
    assert_contains "$short_verbose_output" \
        "kisa-cce-scan: check=U-01 status=GOOD title=Restrict remote login for the root account" \
        "short verbose option output"
    if grep -Fq -- "kisa-cce-scan: check=" "$short_verbose_stdout"; then
        fail "verbose diagnostics were written to standard output"
    fi
    assert_file_contains "$short_verbose_stdout" "markdown_report=" "short verbose report path output"

    write_os_release "$injection_root" ubuntu 26.04 "Ubuntu 26.04 LTS"
    mkdir -p -- "$injection_root/data"
    injection_file="$injection_root/data/evil\\n## U-99: forged"
    : > "$injection_file"
    chmod 0666 -- "$injection_file"
    command_status=0
    command_output="$("$PROJECT_DIR/bin/kisa-cce-scan" \
        --root "$injection_root" --output-dir "$injection_output_dir" \
        --checks U-25 --no-runtime 2>&1)" || command_status=$?
    assert_equal 0 "$command_status" "literal backslash-n evidence scan exit status"
    text_report="$(scanner_console_value markdown_report "$command_output")"
    [ -f "$text_report" ] || fail "literal backslash-n evidence Markdown report was not created"
    injection_result_count="$(grep -Ec '^## U-[0-9]{2}: ' "$text_report")"
    assert_equal 1 "$injection_result_count" "literal backslash-n evidence result count"
    if grep -Fxq -- '## U-99: forged' "$text_report"; then
        fail "literal backslash-n evidence injected a Markdown heading"
    fi
    assert_file_contains "$text_report" '    ## U-99: forged' "literal backslash-n evidence indentation"

    mkdir -p -- "$header_root/etc"
    {
        printf '%s\n' 'ID=ubuntu' 'VERSION_ID="26.04"'
        printf 'PRETTY_NAME="Ubuntu \033[31mred <img src=https://example.invalid/pixel> | ## forged"\n'
        printf 'ID_LIKE="debian\tspoof"\n'
    } > "$header_root/etc/os-release"
    command_status=0
    command_output="$("$scanner_copy/bin/kisa-cce-scan" \
        --root "$header_root" --output-dir "$header_output" \
        --checks U-01 --no-runtime 2>&1)" || command_status=$?
    assert_equal 0 "$command_status" "header control-byte sanitization scan"
    text_report="$(scanner_console_value markdown_report "$command_output")"
    [ -f "$text_report" ] || fail "header control-byte Markdown report was not created"
    # shellcheck disable=SC2094 # cmp only reads the original file; it does not overwrite pipeline input.
    if ! LC_ALL=C tr -d '\000-\011\013-\037\177' < "$text_report" | cmp -s - "$text_report"; then
        fail "Markdown report header retained a non-newline control byte"
    fi
    if grep -Eq '^(<img|## forged)' "$text_report"; then
        fail "platform metadata injected Markdown structure"
    fi
    assert_file_contains "$text_report" '    platform: Ubuntu [31mred <img' "platform metadata code indentation"

    while IFS='|' read -r matrix_id matrix_version matrix_name matrix_id_like matrix_codename matrix_family matrix_base; do
        matrix_number=$((matrix_number + 1))
        matrix_root="$TEST_TEMP/cli-matrix-root-$matrix_number"
        matrix_output="$TEST_TEMP/cli-matrix-output-$matrix_number"
        write_os_release "$matrix_root" "$matrix_id" "$matrix_version" "$matrix_name" "$matrix_id_like" "$matrix_codename"
        command_output="$("$scanner_copy/bin/kisa-cce-scan" \
            --root "$matrix_root" --output-dir "$matrix_output" --checks U-01 --no-runtime 2>&1)"
        command_status=$?
        assert_equal 0 "$command_status" "$matrix_id $matrix_version CLI scan exit status"
        text_report="$(scanner_console_value markdown_report "$command_output")"
        jsonl_report="$(scanner_console_value jsonl_report "$command_output")"
        [ -f "$text_report" ] || fail "$matrix_id $matrix_version CLI Markdown report was not created"
        [ -f "$jsonl_report" ] || fail "$matrix_id $matrix_version CLI JSONL report was not created"
        assert_equal 600 "$(mode_of "$text_report")" "$matrix_id $matrix_version Markdown report mode"
        assert_equal 600 "$(mode_of "$jsonl_report")" "$matrix_id $matrix_version JSONL report mode"
        assert_file_contains "$text_report" "platform_id: $matrix_id" "$matrix_id platform report metadata"
        assert_file_contains "$text_report" "platform_version: $matrix_version" "$matrix_id version report metadata"
        assert_file_contains "$text_report" "platform_family: $matrix_family" "$matrix_id family report metadata"
        assert_file_contains "$text_report" "platform_base: $matrix_base" "$matrix_id base report metadata"
        assert_file_contains "$text_report" "| 전체 | 1 |" "$matrix_id selected result count"
    done <<'EOF'
debian|13|Debian GNU/Linux 13|||debian|debian 13
rhel|10.2|Red Hat Enterprise Linux 10.2|fedora||rhel|rhel 10.2
linuxmint|22.3|Linux Mint 22.3|ubuntu debian|noble|debian|ubuntu 24.04
rocky|10.2|Rocky Linux 10.2|rhel centos fedora||rhel|rhel 10.2
EOF

    command_output="$("$scanner_copy/bin/kisa-cce-scan" --root "$unsupported_root" --checks U-01 2>&1)"
    command_status="$?"
    assert_equal 2 "$command_status" "unsupported platform rejection"
    assert_contains "$command_output" "unsupported platform" "unsupported platform message"

    command_output="$("$scanner_copy/bin/kisa-cce-scan" \
        --root "$unsupported_root" \
        --output-dir "$unsupported_output" \
        --checks U-01 \
        --allow-unsupported 2>&1)"
    command_status="$?"
    assert_equal 0 "$command_status" "unsupported platform override"
    assert_contains "$command_output" "WARNING:" "unsupported platform warning"

    command_output="$("$scanner_copy/bin/kisa-cce-scan" \
        --root "$supported_root" \
        --output-dir "$explain_output_dir" \
        --explain-sysctl net.ipv4.ip_forward 2>&1)"
    command_status="$?"
    assert_equal 0 "$command_status" "sysctl explanation exit status"
    assert_contains "$command_output" "persistent=0" "sysctl persistent explanation"
    assert_contains "$command_output" "runtime=unavailable" "offline sysctl runtime explanation"
    if printf '%s\n' "$command_output" |
        grep -Ev '^\[[[:space:]]*[0-9]+\.[0-9]{6}\] kisa-cce-scan: .*$' >/dev/null; then
        fail "sysctl explanation contains a line without the console prefix"
    fi
    [ ! -e "$explain_output_dir" ] || fail "sysctl explanation created an output directory"
    case "$command_output" in *markdown_report=*|*jsonl_report=*) fail "sysctl explanation produced a report path" ;; esac

    command_output="$("$scanner_copy/bin/kisa-cce-scan" --root "$supported_root" --checks U-99 2>&1)"
    command_status="$?"
    assert_equal 2 "$command_status" "unknown check rejection"
    assert_contains "$command_output" "check code not found in the criteria file" "unknown check message"

    cp -- "$scanner_copy/data/criteria.tsv" "$catalog_backup"
    awk 'NR == 2 {first=$0; next} NR == 3 {print; print first; next} {print}' \
        "$catalog_backup" > "$catalog_reordered"
    cp -- "$catalog_reordered" "$scanner_copy/data/criteria.tsv"
    command_status=0
    command_output="$("$scanner_copy/bin/kisa-cce-scan" \
        --root "$supported_root" --checks U-01 --no-runtime 2>&1)" || command_status=$?
    assert_equal 2 "$command_status" "out-of-order criterion catalog rejection"
    assert_contains "$command_output" "invalid criteria file format" "out-of-order catalog message"
    cp -- "$catalog_backup" "$scanner_copy/data/criteria.tsv"
)

test_installed_layouts() (
    local layout_name=""
    local private_library_path=""
    local make_command=""
    local stage_root=""
    local installed_prefix=""
    local supported_root=""
    local output_dir=""
    local command_output=""
    local command_status=0
    local environment_file=""
    local environment_marker=""
    local text_report=""

    make_command="$(command -v make)" || fail "make is required for the installed-layout test"

    for layout_name in private-lib libexec; do
        stage_root="$TEST_TEMP/installed-$layout_name"
        installed_prefix="$stage_root/usr"
        supported_root="$TEST_TEMP/installed-$layout_name-root"
        output_dir="$TEST_TEMP/installed-$layout_name-output"
        case "$layout_name" in
            private-lib) private_library_path="$installed_prefix/lib/kisa-cce-linux-scanner" ;;
            libexec) private_library_path="$installed_prefix/libexec/kisa-cce-linux-scanner" ;;
        esac

        "$make_command" -s -C "$PROJECT_DIR" install \
            DESTDIR="$stage_root" \
            prefix=/usr \
            pkglibdir="${private_library_path#"$stage_root"}" ||
            fail "$layout_name staged installation failed"
        {
            printf '%s\n' '#!/bin/bash'
            printf '%s\n' 'check_u_01() { set_result GOOD "SSH의 root 직접 접속이 차단되어 있습니다." "layout=true"; }'
        } > "$private_library_path/checks_fixture.sh"

        assert_equal 755 "$(mode_of "$installed_prefix/bin/kisa-cce-scan")" \
            "$layout_name installed command mode"
        assert_equal 755 "$(mode_of "$installed_prefix/bin/kisa-cce-collect")" \
            "$layout_name installed collector mode"
        assert_equal 644 "$(mode_of "$private_library_path/kisa-cce-scan-main.sh")" \
            "$layout_name private main mode"
        assert_equal 644 "$(mode_of "$installed_prefix/share/kisa-cce-linux-scanner/criteria.tsv")" \
            "$layout_name criterion data mode"
        assert_equal 644 "$(mode_of "$installed_prefix/share/kisa-cce-linux-scanner/locale/en/LC_MESSAGES/kisa-cce-linux-scanner.po")" \
            "$layout_name English catalog mode"
        assert_equal 644 "$(mode_of "$installed_prefix/share/kisa-cce-linux-scanner/locale/ko/LC_MESSAGES/kisa-cce-linux-scanner.po")" \
            "$layout_name Korean catalog mode"
        assert_equal 644 "$(mode_of "$installed_prefix/share/man/man8/kisa-cce-scan.8")" \
            "$layout_name installed manual page mode"
        assert_equal 644 "$(mode_of "$installed_prefix/share/man/man8/kisa-cce-collect.8")" \
            "$layout_name installed collector manual mode"
        [ ! -e "$installed_prefix/share/doc/kisa-cce-linux-scanner" ] ||
            fail "$layout_name install unexpectedly copied repository documentation"
        command_output="$(CDPATH='' cd -P -- "$TEST_TEMP" &&
            env -u LANG "$installed_prefix/bin/kisa-cce-scan" --version 2>&1)" ||
            fail "$layout_name installed version command failed"
        assert_contains "$command_output" \
            "kisa-cce-scan: kisa-cce-scan $(sed -n '1p' "$PROJECT_DIR/data/VERSION")" \
            "$layout_name installed version"
        command_output="$("$installed_prefix/bin/kisa-cce-collect" --version 2>&1)" ||
            fail "$layout_name installed collector version command failed"
        assert_contains "$command_output" \
            "kisa-cce-collect: kisa-cce-collect evidence-schema-1" \
            "$layout_name installed collector version"
        command_status=0
        command_output="$("$installed_prefix/bin/kisa-cce-collect" \
            --output-dir $'relative\nforged-line' 2>&1)" || command_status=$?
        assert_equal 2 "$command_status" "$layout_name multiline collector path rejection"
        if printf '%s\n' "$command_output" |
            grep -Ev '^\[[[:space:]]*[0-9]+\.[0-9]{6}\] kisa-cce-collect: .*$' >/dev/null; then
            fail "$layout_name multiline collector error produced an unframed terminal line"
        fi

        environment_file="$stage_root/untrusted-environment.sh"
        environment_marker="$stage_root/environment-was-loaded"
        printf '/usr/bin/touch %s\n' "$environment_marker" > "$environment_file"
        command_output="$(BASH_ENV="$environment_file" ENV="$environment_file" \
            "$installed_prefix/bin/kisa-cce-scan" --version 2>&1)" ||
            fail "$layout_name clean-environment invocation failed"
        [ ! -e "$environment_marker" ] ||
            fail "$layout_name wrapper loaded a caller-controlled shell environment"

        write_os_release "$supported_root" ubuntu 26.04 "Ubuntu 26.04 LTS"
        command_status=0
        command_output="$(env -u LANG "$installed_prefix/bin/kisa-cce-scan" \
            --root "$supported_root" \
            --output-dir "$output_dir" \
            --checks U-01 \
            --no-runtime 2>&1)" || command_status=$?
        assert_equal 0 "$command_status" "$layout_name installed scan exit status"
        text_report="$(scanner_console_value markdown_report "$command_output")"
        [ -f "$text_report" ] || fail "$layout_name installed scan did not create a Markdown report"
        assert_file_contains "$text_report" "SSH의 root 직접 접속이 차단되어 있습니다." \
            "$layout_name installed Korean catalog lookup"

        rm -rf -- "$output_dir"
        command_status=0
        command_output="$(LANG=en_US.UTF-8 "$installed_prefix/bin/kisa-cce-scan" \
            --root "$supported_root" \
            --output-dir "$output_dir" \
            --checks U-01 \
            --no-runtime 2>&1)" || command_status=$?
        assert_equal 0 "$command_status" "$layout_name installed English scan exit status"
        text_report="$(scanner_console_value markdown_report "$command_output")"
        assert_file_contains "$text_report" "# KISA CCE 2026 Linux Security Assessment Report" \
            "$layout_name installed English report title"
        assert_file_contains "$text_report" "Restrict remote login for the root account" \
            "$layout_name installed English criterion title"
        assert_file_contains "$text_report" "Direct root login over SSH is disabled." \
            "$layout_name installed English summary"
    done
)

test_full_catalog_produces_one_result_per_criterion() (
    local root="$TEST_TEMP/full-root"
    local output_dir="$TEST_TEMP/full-output"
    local command_output=""
    local command_status=0
    local text_report=""
    local jsonl_report=""
    local result_count=""
    local json_lines=""
    local rhel_version=""
    local rhel_root=""
    local rhel_output_dir=""
    local bundle="$TEST_TEMP/full-evidence-bundle"
    local bundle_output="$TEST_TEMP/full-bundle-output"
    local policy_directory="$TEST_TEMP/full-policy.d"
    local policy_file="$policy_directory/50-complete.tsv"
    local complete_output="$TEST_TEMP/full-complete-output"
    local complete_json=""
    local complete_markdown=""
    local english_output="$TEST_TEMP/full-english-output"
    local english_markdown=""
    local english_json=""
    local policy_count=0

    write_os_release "$root" ubuntu 26.04 "Ubuntu 26.04 LTS"
    mkdir -p -- \
        "$root/etc/pam.d" "$root/etc/security/pwquality.conf.d" \
        "$root/etc/ssh/sshd_config.d" "$root/etc/profile.d" \
        "$root/etc/systemd/system" "$root/home/operator" \
        "$root/root" "$root/var/log" "$root/dev"
    {
        printf '%s\n' 'root:x:0:0:root:/root:/bin/bash'
        printf '%s\n' 'operator:x:1000:1000:Operator:/home/operator:/bin/bash'
    } > "$root/etc/passwd"
    {
        printf '%s\n' 'root:x:0:'
        printf '%s\n' 'operator:x:1000:'
    } > "$root/etc/group"
    {
        printf '%s\n' 'root:*:20000:0:99999:7:::'
        # shellcheck disable=SC2016
        printf '%s\n' 'operator:$y$j9T$fixture-secret-that-must-not-leak:20000:1:90:7:::'
    } > "$root/etc/shadow"
    printf '%s\n' '127.0.0.1 localhost' > "$root/etc/hosts"
    printf '%s\n' 'ssh 22/tcp' > "$root/etc/services"
    printf '%s\n' 'PermitRootLogin no' > "$root/etc/ssh/sshd_config"
    {
        printf '%s\n' 'PASS_MAX_DAYS 90'
        printf '%s\n' 'PASS_MIN_DAYS 1'
        printf '%s\n' 'ENCRYPT_METHOD YESCRYPT'
        printf '%s\n' 'UMASK 022'
        printf '%s\n' 'UID_MIN 1000'
    } > "$root/etc/login.defs"
    {
        printf '%s\n' 'minlen = 8'
        printf '%s\n' 'dcredit = -1'
        printf '%s\n' 'ucredit = -1'
        printf '%s\n' 'lcredit = -1'
        printf '%s\n' 'ocredit = -1'
        printf '%s\n' 'enforce_for_root'
    } > "$root/etc/security/pwquality.conf"
    {
        printf '%s\n' 'remember = 4'
        printf '%s\n' 'enforce_for_root'
    } > "$root/etc/security/pwhistory.conf"
    printf '%s\n' 'deny = 10' > "$root/etc/security/faillock.conf"
    {
        printf '%s\n' 'password requisite pam_pwquality.so retry=3'
        printf '%s\n' 'password required pam_pwhistory.so use_authtok remember=4'
        printf '%s\n' 'password required pam_unix.so use_authtok'
    } > "$root/etc/pam.d/common-password"
    {
        printf '%s\n' 'auth required pam_faillock.so preauth silent'
        printf '%s\n' 'auth required pam_unix.so'
        printf '%s\n' 'auth required pam_faillock.so authfail'
        printf '%s\n' 'auth required pam_faillock.so authsucc'
    } > "$root/etc/pam.d/common-auth"
    printf '%s\n' 'account required pam_faillock.so' > "$root/etc/pam.d/common-account"
    printf '%s\n' 'auth required pam_wheel.so use_uid' > "$root/etc/pam.d/su"
    {
        printf '%s\n' 'TMOUT=600'
        printf '%s\n' 'readonly TMOUT'
        printf '%s\n' 'export TMOUT'
    } > "$root/etc/profile"
    printf '%s\n' 'Authorized use only.' > "$root/etc/issue"
    printf '%s\n' 'Authorized use only.' > "$root/etc/motd"
    printf '%s\n' 'fixture log' > "$root/var/log/messages"

    command_output="$("$PROJECT_DIR/bin/kisa-cce-scan" \
        --root "$root" --output-dir "$output_dir" --no-runtime 2>&1)" || command_status=$?
    case "$command_status" in
        0|1) ;;
        *) fail "full catalog scan exited unexpectedly: $command_status" ;;
    esac
    text_report="$(scanner_console_value markdown_report "$command_output")"
    jsonl_report="$(scanner_console_value jsonl_report "$command_output")"
    [ -f "$text_report" ] || fail "full scan Markdown report was not created: $command_output"
    [ -f "$jsonl_report" ] || fail "full scan JSONL report was not created"
    assert_full_catalog_contract "$text_report" "$jsonl_report" "full catalog"
    if grep -Fq -- 'fixture-secret-that-must-not-leak' "$text_report" "$jsonl_report"; then
        fail "a fixture password hash escaped into a report"
    fi

    command_status=0
    command_output="$(LANG=en_US.UTF-8 "$PROJECT_DIR/bin/kisa-cce-scan" \
        --root "$root" --output-dir "$english_output" --no-runtime 2>&1)" || command_status=$?
    case "$command_status" in
        0|1) ;;
        *) fail "English full catalog scan exited unexpectedly: $command_status: $command_output" ;;
    esac
    english_markdown="$(scanner_console_value markdown_report "$command_output")"
    english_json="$(scanner_console_value jsonl_report "$command_output")"
    [ -f "$english_markdown" ] || fail "English full scan Markdown report was not created"
    [ -f "$english_json" ] || fail "English full scan JSONL report was not created"
    assert_file_contains "$english_markdown" '# KISA CCE 2026 Linux Security Assessment Report' \
        "English full report title"
    assert_file_contains "$english_markdown" '| Error | 0 |' "English full report error count"
    assert_file_contains "$english_json" '"type":"summary","total":67' "English full result count"

    write_evidence_bundle "$bundle" "$root"
    command_status=0
    command_output="$("$PROJECT_DIR/bin/kisa-cce-scan" \
        --root "$root" --evidence-bundle "$bundle" --output-dir "$bundle_output" 2>&1)" || command_status=$?
    case "$command_status" in 0|1|2) ;; *) fail "bundle audit exited unexpectedly: $command_status" ;; esac
    jsonl_report="$(scanner_console_value jsonl_report "$command_output")"
    [ -f "$jsonl_report" ] || fail "bundle audit JSONL report was not created: $command_output"

    mkdir -p -- "$policy_directory"
    chmod 0700 -- "$policy_directory"
    awk '
        BEGIN {OFS="\t"; print "code", "decision", "review_id", "ticket", "approver", "expires"}
        /"technical_status":"MANUAL"/ {
            code=$0
            sub(/^.*"code":"/, "", code)
            sub(/".*/, "", code)
            review=$0
            sub(/^.*"review_id":"/, "", review)
            sub(/".*/, "", review)
            if (review == "") exit 2
            print code, "GOOD", review, "TEST-" code, "test-governance", "2099-12-31"
            count++
        }
        END {if (count == 0) exit 3}
    ' "$jsonl_report" > "$policy_file" || fail "complete policy fixture was not generated"
    chmod 0600 -- "$policy_file"
    policy_count="$(awk 'END {print NR-1}' "$policy_file")"
    [ "$policy_count" -gt 0 ] || fail "complete policy fixture has no attestations"

    command_status=0
    command_output="$("$PROJECT_DIR/bin/kisa-cce-scan" \
        --root "$root" --mode complete --policy-dir "$policy_directory" \
        --evidence-bundle "$bundle" --output-dir "$complete_output" 2>&1)" || command_status=$?
    case "$command_status" in 0|1|2) ;; *) fail "complete scan exited unexpectedly: $command_status" ;; esac
    complete_markdown="$(scanner_console_value markdown_report "$command_output")"
    complete_json="$(scanner_console_value jsonl_report "$command_output")"
    [ -f "$complete_markdown" ] || fail "complete Markdown report was not created: $command_output"
    [ -f "$complete_json" ] || fail "complete JSONL report was not created: $command_output"
    assert_file_contains "$complete_json" '"type":"summary","total":67' "complete result count"
    assert_file_contains "$complete_json" '"manual":0' "complete manual count"
    assert_file_contains "$complete_json" "\"policy_resolved\":${policy_count}" "complete resolved policy count"
    if grep -Fq -- '"status":"MANUAL"' "$complete_json"; then
        fail "complete report retained a MANUAL final result"
    fi
    assert_file_contains "$complete_markdown" 'scan_mode: complete' "complete report mode"
    assert_file_contains "$complete_markdown" '| 수동 확인 | 0 |' "complete Markdown manual count"

    for rhel_version in 8.10 9.8 10.2; do
        rhel_root="$TEST_TEMP/full-rhel-${rhel_version}"
        rhel_output_dir="$TEST_TEMP/full-rhel-${rhel_version}-output"
        cp -a -- "$root" "$rhel_root"
        write_os_release "$rhel_root" rhel "$rhel_version" "Red Hat Enterprise Linux $rhel_version" fedora
        {
            awk '{print}' "$rhel_root/etc/pam.d/common-auth"
            awk '{print}' "$rhel_root/etc/pam.d/common-account"
            awk '{print}' "$rhel_root/etc/pam.d/common-password"
        } > "$rhel_root/etc/pam.d/system-auth"
        cp -- "$rhel_root/etc/pam.d/system-auth" "$rhel_root/etc/pam.d/password-auth"
        if [ "$rhel_version" != "10.2" ]; then
            sed -i 's/ENCRYPT_METHOD YESCRYPT/ENCRYPT_METHOD SHA512/' "$rhel_root/etc/login.defs"
        fi

        command_status=0
        command_output="$("$PROJECT_DIR/bin/kisa-cce-scan" \
            --root "$rhel_root" --output-dir "$rhel_output_dir" --no-runtime 2>&1)" || command_status=$?
        case "$command_status" in
            0|1) ;;
            *) fail "RHEL $rhel_version full catalog scan exited unexpectedly: $command_status" ;;
        esac
        text_report="$(scanner_console_value markdown_report "$command_output")"
        jsonl_report="$(scanner_console_value jsonl_report "$command_output")"
        [ -f "$text_report" ] || fail "RHEL $rhel_version Markdown report was not created: $command_output"
        [ -f "$jsonl_report" ] || fail "RHEL $rhel_version JSONL report was not created"
        assert_full_catalog_contract "$text_report" "$jsonl_report" "RHEL $rhel_version full catalog"
        assert_file_contains "$text_report" "platform_family: rhel" "RHEL $rhel_version platform family"
        if grep -Fq -- 'fixture-secret-that-must-not-leak' "$text_report" "$jsonl_report"; then
            fail "RHEL $rhel_version report retained a fixture password hash"
        fi
    done
)

test_conservative_account_regressions() (
    local root="$TEST_TEMP/account-regression-root"
    local scratch="$TEST_TEMP/account-regression-scratch"
    local metrics=""
    local status=0

    mkdir -p -- \
        "$root/etc/systemd/system" "$root/etc/pam.d" "$root/etc/security/pwquality.conf.d" \
        "$root/etc/firewalld/policies" "$root/usr/sbin" "$scratch"
    printf '%s\n' 'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin' > "$root/etc/passwd"
    printf '%s\n' 'daemon:x:1:' > "$root/etc/group"
    ln -s /dev/null "$root/etc/systemd/system/masked.service"

    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_account_file.sh
    . "$PROJECT_DIR/lib/checks_account_file.sh"
    SCRATCH_DIR="$scratch"
    set_test_platform ubuntu 26.04 "Ubuntu 26.04 LTS"

    printf '%s\n' '/etc/pam.d/common-password	password optional pam_pwquality.so minlen=8' > "$scratch/pam-lines"
    metrics="$(scanner_pam_module_control_metrics "$scratch/pam-lines" pam_pwquality.so)"
    assert_equal "0 1 0" "$metrics" "optional PAM module control classification"

    {
        printf '%s\n' 'PASS_MAX_DAYS 90'
        printf '%s\n' 'PASS_MIN_DAYS 1'
    } > "$root/etc/login.defs"
    {
        printf '%s\n' 'minlen = 8'
        printf '%s\n' 'dcredit = -1'
        printf '%s\n' 'ucredit = -1'
        printf '%s\n' 'lcredit = -1'
        printf '%s\n' 'ocredit = -1'
        printf '%s\n' 'enforce_for_root'
    } > "$root/etc/security/pwquality.conf"
    {
        printf '%s\n' 'minlen = 1'
        printf '%s\n' 'dcredit = 0'
        printf '%s\n' 'ucredit = 0'
        printf '%s\n' 'lcredit = 0'
        printf '%s\n' 'ocredit = 0'
    } > "$root/etc/security/site-pwquality.conf"
    {
        printf '%s\n' 'remember = 4'
        printf '%s\n' 'enforce_for_root'
    } > "$root/etc/security/pwhistory.conf"
    {
        printf '%s\n' 'password requisite pam_pwquality.so conf=/etc/security/site-pwquality.conf'
        printf '%s\n' 'password required pam_pwhistory.so use_authtok'
        printf '%s\n' 'password required pam_unix.so use_authtok'
    } > "$root/etc/pam.d/common-password"
    check_u_02
    assert_equal VULNERABLE "$RESULT_STATUS" "pam_pwquality custom conf precedence"

    mkdir -p -- "$root/etc/security/site-pwquality.conf.d"
    {
        printf '%s\n' 'minlen = 1'
        printf '%s\n' 'dcredit = 0'
        printf '%s\n' 'ucredit = 0'
        printf '%s\n' 'lcredit = 0'
        printf '%s\n' 'ocredit = 0'
    } > "$root/etc/security/site-pwquality.conf.d/90-role.conf"
    printf '%s\n' 'enforce_for_root' > "$root/etc/security/site-pwquality.conf"
    check_u_02
    assert_equal VULNERABLE "$RESULT_STATUS" "pam_pwquality custom drop-in precedence"

    {
        printf '%s\n' 'minlen = 8'
        printf '%s\n' 'dcredit = -1'
        printf '%s\n' 'ucredit = -1'
        printf '%s\n' 'lcredit = -1'
        printf '%s\n' 'ocredit = -1'
        printf '%s\n' 'enforce_for_root'
    } > "$root/etc/security/site-pwquality.conf"
    {
        printf '%s\n' 'password [success=1 default=ignore] pam_permit.so'
        printf '%s\n' 'password requisite pam_pwquality.so minlen=8 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 enforce_for_root'
        printf '%s\n' 'password required pam_pwhistory.so use_authtok remember=4 enforce_for_root'
        printf '%s\n' 'password required pam_unix.so use_authtok'
    } > "$root/etc/pam.d/common-password"
    check_u_02
    assert_equal MANUAL "$RESULT_STATUS" "PAM bracket jump control"

    printf '%s\n' '<policy target="DROP"><ingress-zone name="ANY"/><egress-zone name="HOST"/></policy>' > "$root/etc/firewalld/policies/restrict.xml"
    runtime_enabled() { return 1; }
    check_u_28
    assert_equal VULNERABLE "$RESULT_STATUS" "offline disabled firewalld policy object"
    assert_contains "$RESULT_EVIDENCE" "provider=firewalld" "firewalld policy evidence"

    {
        printf '%s\n' '#!/bin/sh'
        printf '%s\n' "case \"\$1\" in"
        printf "  check) exit \"\$(/bin/cat %s)\" ;;\n" "$scratch/authselect-check-status"
        printf '%s\n' '  current)'
        printf '    /bin/cat %s\n' "$scratch/authselect-current-profile"
        printf "    exit \"\$(/bin/cat %s)\"\n" "$scratch/authselect-current-status"
        printf '%s\n' '    ;;'
        printf '%s\n' 'esac'
        printf '%s\n' 'exit 1'
    } > "$scratch/authselect"
    chmod 0755 -- "$scratch/authselect"
    set_test_platform rhel 10.2 "Red Hat Enterprise Linux 10.2"
    runtime_enabled() { return 0; }
    trusted_command() { [ "$1" = authselect ] && printf '%s\n' "$scratch/authselect"; }

    printf '0\n' > "$scratch/authselect-check-status"
    printf '0\n' > "$scratch/authselect-current-status"
    : > "$scratch/authselect-current-profile"
    scanner_authselect_configuration_valid || fail "valid authselect configuration was rejected"
    assert_equal 0 "$SCANNER_AUTHSELECT_UNMANAGED" "valid authselect managed state"

    printf '2\n' > "$scratch/authselect-check-status"
    printf '2\n' > "$scratch/authselect-current-status"
    printf '%s\n' 'No existing configuration detected.' > "$scratch/authselect-current-profile"
    scanner_authselect_configuration_valid || fail "authselect opt-out was treated as invalid"
    assert_equal 1 "$SCANNER_AUTHSELECT_UNMANAGED" "authselect opt-out state"

    printf '6\n' > "$scratch/authselect-check-status"
    printf '6\n' > "$scratch/authselect-current-status"
    : > "$scratch/authselect-current-profile"
    scanner_authselect_configuration_valid || fail "RHEL 10 authselect opt-out was treated as invalid"
    assert_equal 1 "$SCANNER_AUTHSELECT_UNMANAGED" "RHEL 10 authselect opt-out state"

    printf '2\n' > "$scratch/authselect-check-status"
    printf '0\n' > "$scratch/authselect-current-status"
    printf '%s\n' 'sssd with-faillock' > "$scratch/authselect-current-profile"
    if scanner_authselect_configuration_valid; then
        fail "selected but invalid authselect profile was accepted"
    fi
    : > "$scratch/authselect-current-profile"
    printf '2\n' > "$scratch/authselect-check-status"
    printf '0\n' > "$scratch/authselect-current-status"
    if scanner_authselect_configuration_valid; then
        fail "blank successful authselect current output was accepted"
    fi
    for status in 1 3 5; do
        printf '%s\n' "$status" > "$scratch/authselect-check-status"
        if scanner_authselect_configuration_valid; then
            fail "authselect failure $status was accepted as opt-out"
        fi
    done

    set_test_platform ubuntu 26.04 "Ubuntu 26.04 LTS"
    runtime_enabled() { return 1; }

    check_u_31
    assert_equal VULNERABLE "$RESULT_STATUS" "U-31 includes non-login service account homes"
    check_u_17
    assert_equal GOOD "$RESULT_STATUS" "systemd /dev/null mask handling"
)

test_conservative_service_regressions() (
    local root="$TEST_TEMP/service-regression-root"
    local scratch="$TEST_TEMP/service-regression-scratch"
    local state=0
    local tab=""

    mkdir -p -- \
        "$root/etc/snmp" "$root/etc/sudoers.d" "$root/usr/lib/cargo/bin" \
        "$root/usr/sbin" "$scratch"
    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_service.sh
    . "$PROJECT_DIR/lib/checks_service.sh"
    SCRATCH_DIR="$scratch"
    set_test_platform ubuntu 26.04 "Ubuntu 26.04 LTS"

    runtime_enabled() { return 0; }
    trusted_command() { printf '%s\n' /usr/bin/false; }
    service_activation_state example.service >/dev/null 2>&1
    state=$?
    assert_equal 2 "$state" "systemctl failure preservation"

    runtime_enabled() { return 1; }
    service_detect_mail() { SERVICE_MAIL_PROVIDERS="postfix"; SERVICE_MAIL_UNCERTAIN=0; }
    check_u_46
    assert_equal MANUAL "$RESULT_STATUS" "Postfix internal privilege model"
    : > "$root/usr/sbin/postsuper"
    chmod 0700 -- "$root/usr/sbin/postsuper"
    check_u_46
    assert_equal VULNERABLE "$RESULT_STATUS" "non-root-owned mail administration command"

    {
        printf '%s\n' 'rouser secureUser authPriv'
        printf '%s\n' 'include site.conf'
    } > "$root/etc/snmp/snmpd.conf"
    service_detect_snmp() { return 0; }
    service_snmp_files() { printf '%s\n' "$root/etc/snmp/snmpd.conf"; }
    check_u_59
    assert_equal MANUAL "$RESULT_STATUS" "SNMP include prevents false GOOD"

    {
        printf '%s\n' 'acl xfer { any; };'
        printf '%s\n' 'options { allow-transfer { xfer; }; };'
        printf '%s\n' 'zone "example.test" { type primary; file "db"; };'
    } > "$scratch/named.conf"
    tab="$(printf '\t')"
    service_detect_dns() { return 0; }
    service_bind_effective_file() { printf 'validated%s%s\n' "$tab" "$scratch/named.conf"; }
    check_u_50
    assert_equal MANUAL "$RESULT_STATUS" "BIND ACL reference prevents false GOOD"

    {
        printf '%s\n' '#!/bin/sh'
        printf '%s\n' 'case "$1" in'
        printf '%s\n' '  --version) printf "sudo-rs 0.2.8\\n" ;;'
        printf '%s\n' '  *) exit 1 ;;'
        printf '%s\n' 'esac'
    } > "$root/usr/lib/cargo/bin/sudo"
    printf '%s\n' '#!/bin/sh' 'exit 0' > "$root/usr/lib/cargo/bin/visudo"
    chmod 0755 -- "$root/usr/lib/cargo/bin/sudo" "$root/usr/lib/cargo/bin/visudo"
    printf '%s\n' 'root ALL=(ALL:ALL) ALL' '@includedir /etc/sudoers.d' > "$root/etc/sudoers"
    printf '%s\n' 'operator ALL=(root) /usr/bin/id' > "$root/etc/sudoers.d/operator"
    chmod 0640 -- "$root/etc/sudoers"
    chmod 0440 -- "$root/etc/sudoers.d/operator"
    runtime_enabled() { return 0; }
    trusted_command() {
        case "$1" in
            sudo) printf '%s\n' "$root/usr/lib/cargo/bin/sudo" ;;
            visudo) printf '%s\n' "$root/usr/lib/cargo/bin/visudo" ;;
            *) return 1 ;;
        esac
    }
    stat_owner() { printf '%s\n' root; }
    stat_uid() { printf '%s\n' 0; }
    check_u_63
    assert_equal GOOD "$RESULT_STATUS" "active sudo-rs with /etc/sudoers"
    assert_contains "$RESULT_EVIDENCE" "sudo_provider=sudo-rs" "sudo-rs evidence"
    assert_contains "$RESULT_EVIDENCE" "policy_path=/etc/sudoers" "sudo-rs standard policy path"
    chmod 0644 -- "$root/etc/sudoers"
    check_u_63
    assert_equal VULNERABLE "$RESULT_STATUS" "sudo-rs world-readable sudoers policy"
)

test_chrony_peer_and_empty_log_handling() (
    local root="$TEST_TEMP/system-regression-root"
    local scratch="$TEST_TEMP/system-regression-scratch"
    local chronyc_fixture="$scratch/chronyc"
    local output=""
    local status=0

    mkdir -p -- \
        "$root/var/log" "$root/etc/chrony/conf.d" "$root/etc/chrony/a" \
        "$root/etc/chrony/b" "$root/run/chrony-dhcp" "$scratch"
    {
        printf '%s\n' '#!/bin/sh'
        printf '%s\n' 'case "$*" in'
        printf '%s\n' '  *tracking*) printf "Leap status     : Normal\\n" ;;'
        printf '%s\n' '  *sources*) printf "=* 192.0.2.10 2 6 377 10 +1us[+2us] +/- 1ms\\n" ;;'
        printf '%s\n' 'esac'
    } > "$chronyc_fixture"
    chmod 0755 -- "$chronyc_fixture"

    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_system.sh
    . "$PROJECT_DIR/lib/checks_system.sh"
    SCRATCH_DIR="$scratch"
    set_test_platform ubuntu 26.04 "Ubuntu 26.04 LTS"

    printf '%s\n' 'confdir /etc/chrony/conf.d' > "$root/etc/chrony/chrony.conf"
    printf '%s\n' 'server 192.0.2.10 iburst' > "$root/etc/chrony/conf.d/site.conf"
    output="$(chrony_config_evidence)" || fail "Chrony confdir source was not resolved"
    assert_contains "$output" "configured_sources=1" "Chrony confdir expansion"
    printf '%s\n' 'sourcedir /run/chrony-dhcp' > "$root/etc/chrony/chrony.conf"
    output="$(chrony_config_evidence)" || status=$?
    assert_equal 3 "$status" "empty Chrony sourcedir status"
    printf '%s\n' 'server 192.0.2.30 iburst' > "$root/run/chrony-dhcp/dynamic.sources"
    status=0
    output="$(chrony_config_evidence)" || status=$?
    assert_equal 3 "$status" "dynamic-only Chrony sourcedir status"
    assert_contains "$output" "dynamic_sources=1" "Chrony dynamic source evidence"
    printf '%s\n' 'server 192.0.2.30 noselect' > "$root/etc/chrony/chrony.conf"
    status=0
    chrony_config_evidence >/dev/null 2>&1 || status=$?
    assert_equal 3 "$status" "Chrony noselect-only source"

    printf '%s\n' 'confdir /etc/chrony/a /etc/chrony/b' > "$root/etc/chrony/chrony.conf"
    printf '%s\n' 'server 192.0.2.41' > "$root/etc/chrony/a/10-shared.conf"
    printf '%s\n' 'server 192.0.2.42' > "$root/etc/chrony/b/10-shared.conf"
    printf '%s\n' 'pool 192.0.2.43' > "$root/etc/chrony/b/20-unique.conf"
    output="$(chrony_config_evidence)" || fail "Chrony multi-confdir configuration was not resolved"
    assert_contains "$output" "configured_sources=2" "Chrony first-directory basename precedence"

    printf '%s\n' 'pool 192.0.2.50' 'sourcedir /run/chrony-missing' > "$root/etc/chrony/chrony.conf"
    status=0
    output="$(chrony_config_evidence)" || status=$?
    assert_equal 0 "$status" "Chrony static pool with absent sourcedir"
    assert_contains "$output" "configured_sources=1" "Chrony static pool source count"

    runtime_enabled() { return 0; }
    trusted_command() { [ "$1" = chronyc ] && printf '%s\n' "$chronyc_fixture"; }
    output="$(chrony_runtime_evidence)" || fail "selected Chrony peer was rejected"
    assert_contains "$output" "selected_sources=1" "Chrony peer selection"

    runtime_enabled() { return 1; }
    check_u_67
    assert_equal MANUAL "$RESULT_STATUS" "empty log directory result"
)

test_u02_rhel_dual_password_stacks() (
    local root="$TEST_TEMP/u02-rhel-dual-stack-root"
    local scratch="$TEST_TEMP/u02-rhel-dual-stack-scratch"

    mkdir -p -- "$root/etc/pam.d" "$root/etc/security" "$scratch"
    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_account_file.sh
    . "$PROJECT_DIR/lib/checks_account_file.sh"
    SCRATCH_DIR="$scratch"
    set_test_platform rhel 10.2 "Red Hat Enterprise Linux 10.2"

    {
        printf '%s\n' 'PASS_MAX_DAYS 90'
        printf '%s\n' 'PASS_MIN_DAYS 1'
    } > "$root/etc/login.defs"
    {
        printf '%s\n' 'minlen = 8'
        printf '%s\n' 'dcredit = -1'
        printf '%s\n' 'ucredit = -1'
        printf '%s\n' 'lcredit = -1'
        printf '%s\n' 'ocredit = -1'
        printf '%s\n' 'enforce_for_root'
    } > "$root/etc/security/pwquality.conf"
    {
        printf '%s\n' 'remember = 4'
        printf '%s\n' 'file = /etc/security/opasswd'
        printf '%s\n' 'enforce_for_root'
    } > "$root/etc/security/pwhistory.conf"
    : > "$root/etc/security/opasswd"

    write_u02_strong_stack() {
        local pam_service="$1"

        {
            printf '%s\n' 'password requisite pam_pwquality.so'
            printf '%s\n' 'password required pam_pwhistory.so use_authtok'
            printf '%s\n' 'password required pam_unix.so use_authtok sha512'
        } > "$root/etc/pam.d/$pam_service"
    }

    write_u02_strong_stack system-auth
    write_u02_strong_stack password-auth
    check_u_02
    assert_equal GOOD "$RESULT_STATUS" "U-02 both RHEL password stacks strong"
    assert_contains "$RESULT_EVIDENCE" "system-auth.status=GOOD" "U-02 system-auth strong evidence"
    assert_contains "$RESULT_EVIDENCE" "password-auth.status=GOOD" "U-02 password-auth strong evidence"

    {
        printf '%s\n' 'password requisite pam_pwquality.so'
        printf '%s\n' 'password required pam_unix.so use_authtok sha512'
    } > "$root/etc/pam.d/password-auth"
    check_u_02
    assert_equal VULNERABLE "$RESULT_STATUS" "U-02 RHEL password-auth missing history module"
    assert_contains "$RESULT_EVIDENCE" "password-auth.password_history_module_present=0" "U-02 missing history evidence"

    write_u02_strong_stack password-auth
    sed -i 's/pam_pwquality.so/pam_pwquality.so minlen=7/' "$root/etc/pam.d/password-auth"
    check_u_02
    assert_equal VULNERABLE "$RESULT_STATUS" "U-02 RHEL password-auth weak quality override"
    assert_contains "$RESULT_EVIDENCE" "password-auth.minlen=7" "U-02 weak stack override evidence"
    assert_contains "$RESULT_EVIDENCE" "system-auth.minlen=8" "U-02 shared fallback evidence"

    write_u02_strong_stack password-auth
    sed -i 's/pam_pwquality.so/pam_pwquality.so minlen=7/' "$root/etc/pam.d/system-auth"
    check_u_02
    assert_equal VULNERABLE "$RESULT_STATUS" "U-02 RHEL system-auth weak quality override"
    assert_contains "$RESULT_EVIDENCE" "system-auth.minlen=7" "U-02 reverse weak stack override evidence"
    assert_contains "$RESULT_EVIDENCE" "password-auth.minlen=8" "U-02 reverse shared fallback evidence"

    write_u02_strong_stack system-auth
    {
        printf '%s\n' 'password requisite pam_pwquality.so'
        printf '%s\n' 'password required pam_unix.so use_authtok sha512'
        printf '%s\n' 'password required pam_pwhistory.so use_authtok'
    } > "$root/etc/pam.d/password-auth"
    check_u_02
    assert_equal VULNERABLE "$RESULT_STATUS" "U-02 RHEL password-auth history order"

    {
        printf '%s\n' 'minlen = 8'
        printf '%s\n' 'dcredit = -1'
        printf '%s\n' 'ucredit = -1'
        printf '%s\n' 'lcredit = -1'
        printf '%s\n' 'ocredit = -1'
    } > "$root/etc/security/password-auth-pwquality.conf"
    {
        printf '%s\n' 'remember = 4'
        printf '%s\n' 'file = /etc/security/opasswd'
    } > "$root/etc/security/password-auth-pwhistory.conf"
    {
        printf '%s\n' 'password requisite pam_pwquality.so conf=/etc/security/password-auth-pwquality.conf'
        printf '%s\n' 'password required pam_pwhistory.so use_authtok conf=/etc/security/password-auth-pwhistory.conf'
        printf '%s\n' 'password required pam_unix.so use_authtok sha512'
    } > "$root/etc/pam.d/password-auth"
    check_u_02
    assert_equal VULNERABLE "$RESULT_STATUS" "U-02 RHEL password-auth custom config missing root enforcement"
    assert_contains "$RESULT_EVIDENCE" "password-auth.pwquality_enforce_for_root=absent" "U-02 missing quality root enforcement evidence"
    assert_contains "$RESULT_EVIDENCE" "password-auth.pwhistory_enforce_for_root=absent" "U-02 missing history root enforcement evidence"

    {
        printf '%s\n' 'password required pam_exec.so pam_pwquality.so minlen=8 enforce_for_root'
        printf '%s\n' 'password required pam_exec.so pam_pwhistory.so remember=4 file=/etc/security/opasswd enforce_for_root'
        printf '%s\n' 'password required pam_unix.so use_authtok sha512'
    } > "$root/etc/pam.d/password-auth"
    check_u_02
    assert_equal VULNERABLE "$RESULT_STATUS" "U-02 ignores PAM module-name decoy arguments"
    assert_contains "$RESULT_EVIDENCE" "password-auth.pam_pwquality_present=0" "U-02 pwquality decoy evidence"
    assert_contains "$RESULT_EVIDENCE" "password-auth.password_history_module_present=0" "U-02 pwhistory decoy evidence"
)

test_kisa_account_platform_goldens() (
    local root="$TEST_TEMP/kisa-account-golden-root"
    local scratch="$TEST_TEMP/kisa-account-golden-scratch"
    local pam_service=""
    local large_deny="999999999999999999999999999999"

    mkdir -p -- \
        "$root/etc/pam.d" "$root/etc/security" "$root/etc/ssh/sshd_config.d" \
        "$root/lib/security" "$root/lib64/security" "$root/usr/lib/security" \
        "$root/usr/lib64/security" "$scratch"
    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_account_file.sh
    . "$PROJECT_DIR/lib/checks_account_file.sh"
    SCRATCH_DIR="$scratch"

    set_test_platform ubuntu 26.04 "Ubuntu 26.04 LTS"
    printf '%s\n' 'PermitRootLogin no' > "$root/etc/ssh/sshd_config"
    printf '%s\n' 'auth required /lib/security/pam_securetty.so' > "$root/etc/pam.d/login"
    printf '%s\n' 'console' > "$root/etc/securetty"
    : > "$root/lib/security/pam_securetty.so"
    runtime_enabled() { return 0; }
    scanner_inetd_service_enabled() { return 1; }
    sshd_manager_has_custom_invocation() { return 1; }
    trusted_command() { return 1; }
    TELNET_FIXTURE_ACTIVE=1
    service_state() {
        case "$1" in
            telnet.socket) [ "$TELNET_FIXTURE_ACTIVE" -eq 1 ] && return 0 || return 3 ;;
            *) return 3 ;;
        esac
    }

    check_u_01
    assert_equal GOOD "$RESULT_STATUS" "U-01 active Telnet with enforcing securetty policy"
    printf '%s\n' 'console' 'pts/0' > "$root/etc/securetty"
    check_u_01
    assert_equal VULNERABLE "$RESULT_STATUS" "U-01 active Telnet pts root terminal"
    printf '%s\n' 'console' > "$root/etc/securetty"
    rm -f -- "$root/lib/security/pam_securetty.so"
    check_u_01
    assert_equal VULNERABLE "$RESULT_STATUS" "U-01 missing pam_securetty module"

    runtime_enabled() { return 1; }
    set_test_platform rhel 10.2 "Red Hat Enterprise Linux 10.2"
    {
        printf '%s\n' 'PASS_MAX_DAYS 90'
        printf '%s\n' 'PASS_MIN_DAYS 1'
        printf '%s\n' 'ENCRYPT_METHOD SHA512'
    } > "$root/etc/login.defs"
    {
        printf '%s\n' 'minlen = 8'
        printf '%s\n' 'dcredit = -1'
        printf '%s\n' 'ucredit = -1'
        printf '%s\n' 'lcredit = -1'
        printf '%s\n' 'ocredit = -1'
        printf '%s\n' 'enforce_for_root'
    } > "$root/etc/security/pwquality.conf"
    {
        printf '%s\n' 'enforce_for_root'
        printf '%s\n' 'file = /etc/security/opasswd'
    } > "$root/etc/security/pwhistory.conf"
    : > "$root/etc/security/opasswd"
    {
        printf '%s\n' 'password requisite pam_pwquality.so'
        printf '%s\n' 'password required pam_pwhistory.so use_authtok'
        printf '%s\n' 'password required pam_unix.so use_authtok sha512'
    } > "$root/etc/pam.d/system-auth"
    cp -- "$root/etc/pam.d/system-auth" "$root/etc/pam.d/password-auth"

    check_u_02
    assert_equal GOOD "$RESULT_STATUS" "U-02 pam_pwhistory default remember value"
    assert_contains "$RESULT_EVIDENCE" "remember=10" "U-02 default remember evidence"

    sed -i 's/dcredit = -1/dcredit = -2/' "$root/etc/security/pwquality.conf"
    check_u_02
    assert_equal VULNERABLE "$RESULT_STATUS" "U-02 credit values must equal minus one"
    sed -i 's/dcredit = -2/dcredit = -1/' "$root/etc/security/pwquality.conf"

    printf '%s\n' 'enforce_for_root' > "$root/etc/security/pwhistory.conf"
    check_u_02
    assert_equal VULNERABLE "$RESULT_STATUS" "U-02 RHEL opasswd path is required"
    printf '%s\n' 'enforce_for_root' 'file = /etc/security/opasswd' > "$root/etc/security/pwhistory.conf"

    sed -i 's/PASS_MIN_DAYS 1/PASS_MIN_DAYS 0/' "$root/etc/login.defs"
    check_u_02
    assert_equal MANUAL "$RESULT_STATUS" "U-02 conflicting RHEL minimum-age guide value"
    sed -i 's/PASS_MIN_DAYS 0/PASS_MIN_DAYS 1/' "$root/etc/login.defs"

    set_test_platform debian 13 "Debian GNU/Linux 13"
    cp -- "$root/etc/pam.d/system-auth" "$root/etc/pam.d/common-password"
    printf '%s\n' 'enforce_for_root' > "$root/etc/security/pwhistory.conf"
    check_u_02
    assert_equal GOOD "$RESULT_STATUS" "U-02 Debian common-password policy"
    assert_contains "$RESULT_EVIDENCE" "remember=10" "U-02 Debian default history evidence"

    set_test_platform rhel 10.2 "Red Hat Enterprise Linux 10.2"
    : > "$root/etc/security/faillock.conf"
    : > "$root/lib64/security/pam_faillock.so"
    for pam_service in system-auth password-auth; do
        {
            printf '%s\n' 'auth [success=1 default=bad] pam_unix.so'
            printf '%s\n' 'auth [default=die] pam_faillock.so authfail'
            printf '%s\n' 'auth sufficient pam_faillock.so authsucc'
            printf '%s\n' 'auth required pam_deny.so'
        } > "$root/etc/pam.d/$pam_service"
    done
    check_u_03
    assert_equal GOOD "$RESULT_STATUS" "U-03 default faillock deny and authsucc flow"
    assert_contains "$RESULT_EVIDENCE" "deny=3" "U-03 default deny evidence"

    printf '%s\n' \
        'auth [success=1 default=bad] pam_unix.so' \
        'auth sufficient pam_faillock.so authsucc' \
        'auth required pam_deny.so' > "$root/etc/pam.d/password-auth"
    check_u_03
    assert_equal VULNERABLE "$RESULT_STATUS" "U-03 RHEL PAM stacks are independently required"

    set_test_platform debian 13 "Debian GNU/Linux 13"
    {
        printf '%s\n' 'auth [success=2 default=ignore] pam_faillock.so preauth audit'
        printf '%s\n' 'auth [success=2 default=ignore] pam_unix.so nullok'
        printf '%s\n' 'auth [success=1 default=ignore] pam_sss.so use_first_pass'
        printf '%s\n' 'auth requisite pam_faillock.so authfail audit'
        printf '%s\n' 'auth [default=die] pam_faillock.so authsucc audit'
        printf '%s\n' 'auth requisite pam_deny.so'
    } > "$root/etc/pam.d/common-auth"
    printf '%s\n' 'account required pam_faillock.so' > "$root/etc/pam.d/common-account"
    check_u_03
    assert_equal GOOD "$RESULT_STATUS" "U-03 Debian guide bracket flow"

    set_test_platform rhel 8.10 "Red Hat Enterprise Linux 8.10"
    rm -f -- "$root/lib/security/pam_tally2.so" "$root/lib64/security/pam_faillock.so"
    for pam_service in system-auth password-auth; do
        {
            printf '%s\n' 'auth required /lib/security/pam_tally2.so deny=10 unlock_time=120 no_magic_root'
            printf '%s\n' 'auth required pam_unix.so'
            printf '%s\n' 'account required /lib/security/pam_tally2.so no_magic_root reset'
        } > "$root/etc/pam.d/$pam_service"
    done
    check_u_03
    assert_equal VULNERABLE "$RESULT_STATUS" "U-03 unavailable legacy tally module"
    : > "$root/lib/security/pam_tally2.so"
    check_u_03
    assert_equal GOOD "$RESULT_STATUS" "U-03 available legacy tally module"

    for pam_service in system-auth password-auth; do
        sed -i "s/deny=10/deny=$large_deny/" "$root/etc/pam.d/$pam_service"
    done
    check_u_03
    assert_equal VULNERABLE "$RESULT_STATUS" "U-03 oversized deny value"

    set_test_platform rhel 10.2 "Red Hat Enterprise Linux 10.2"
    printf '%s\n' 'ENCRYPT_METHOD SHA512' > "$root/etc/login.defs"
    printf '%s\n' 'password required pam_unix.so use_authtok sha512' > "$root/etc/pam.d/system-auth"
    cp -- "$root/etc/pam.d/system-auth" "$root/etc/pam.d/password-auth"
    printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' > "$root/etc/passwd"
    printf '%s\n' 'root:$6$salt$ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./ABCDEFGHIJKLMNOPQRSTUV:20000:0:99999:7:::' > "$root/etc/shadow"
    check_u_13
    assert_equal GOOD "$RESULT_STATUS" "U-13 RHEL SHA-512 policy"

    printf '%s\n' 'ENCRYPT_METHOD YESCRYPT' > "$root/etc/login.defs"
    printf '%s\n' 'password required pam_unix.so use_authtok yescrypt' > "$root/etc/pam.d/system-auth"
    printf '%s\n' 'root:$y$j9T$salt$ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq:20000:0:99999:7:::' > "$root/etc/shadow"
    check_u_13
    assert_equal MANUAL "$RESULT_STATUS" "U-13 RHEL unlisted yescrypt algorithm"

    set_test_platform debian 13 "Debian GNU/Linux 13"
    cp -- "$root/etc/pam.d/system-auth" "$root/etc/pam.d/common-password"
    check_u_13
    assert_equal GOOD "$RESULT_STATUS" "U-13 Debian yescrypt policy"

    printf '%s\n' 'ENCRYPT_METHOD SHA512' > "$root/etc/login.defs"
    printf '%s\n' 'password required pam_unix.so use_authtok sha512' > "$root/etc/pam.d/common-password"
    printf '%s\n' 'root:$2b$12$abcdefghijklmnopqrstuu4vWgG/1Lmru.YAq4m8pC4R8a5r8qabc:20000:0:99999:7:::' > "$root/etc/shadow"
    check_u_13
    assert_equal MANUAL "$RESULT_STATUS" "U-13 unlisted Blowfish algorithm"

    printf '%s\n' 'root:$6$junk' > "$root/etc/shadow"
    check_u_13
    assert_equal ERROR "$RESULT_STATUS" "U-13 malformed shadow record"
    printf '%s\n' 'root:$9$salt$hash:20000:0:99999:7:::' > "$root/etc/shadow"
    check_u_13
    assert_equal MANUAL "$RESULT_STATUS" "U-13 unknown modular hash"

    printf '%s\n' 'ENCRYPT_METHOD GOST_YESCRYPT' > "$root/etc/login.defs"
    printf '%s\n' 'password required pam_unix.so use_authtok gost_yescrypt' > "$root/etc/pam.d/common-password"
    printf '%s\n' 'root:$gy$j9T$salt$ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq:20000:0:99999:7:::' > "$root/etc/shadow"
    check_u_13
    assert_equal MANUAL "$RESULT_STATUS" "U-13 Debian GOST yescrypt remains unlisted"

    printf '%s\n' 'ENCRYPT_METHOD SHA512' > "$root/etc/login.defs"
    printf '%s\n' 'password required pam_unix.so use_authtok sha512' > "$root/etc/pam.d/common-password"
    rm -f -- "$root/etc/shadow"
    printf '%s\n' 'root:$6$salt$ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./ABCDEFGHIJKLMNOPQRSTUV:0:0:root:/root:/bin/bash' \
        > "$root/etc/passwd"
    check_u_04
    assert_equal GOOD "$RESULT_STATUS" "U-04 encrypted passwd fallback without shadow"
    assert_contains "$RESULT_EVIDENCE" "password_storage=encrypted_passwd_fallback" "U-04 passwd fallback evidence"
    check_u_13
    assert_equal GOOD "$RESULT_STATUS" "U-13 encrypted passwd fallback without shadow"
    assert_contains "$RESULT_EVIDENCE" "credential_file=per-account" "U-13 passwd fallback evidence"

    mkdir -- "$root/etc/shadow"
    check_u_04
    assert_equal ERROR "$RESULT_STATUS" "U-04 non-regular shadow path"
    check_u_13
    assert_equal ERROR "$RESULT_STATUS" "U-13 non-regular shadow path"
)

test_kisa_service_platform_goldens() (
    local root="$TEST_TEMP/kisa-service-golden-root"
    local scratch="$TEST_TEMP/kisa-service-golden-scratch"
    local service_golden_active=""
    local service_probe_arguments=""

    mkdir -p -- "$root/etc/snmp" "$scratch"
    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_service.sh
    . "$PROJECT_DIR/lib/checks_service.sh"
    SCRATCH_DIR="$scratch"

    runtime_enabled() { return 1; }
    trusted_command() { return 1; }
    service_activation_state() {
        service_probe_arguments="${service_probe_arguments}${service_probe_arguments:+ }$*"
        SERVICE_ACTIVATION_EVIDENCE="fixture_units=$*\n"
        case "$service_golden_active:$*" in
            ypupdated:*ypupdated*) return 0 ;;
            atftpd:*atftpd*) return 0 ;;
            *) return 1 ;;
        esac
    }
    service_legacy_enabled() { return 1; }
    service_listener_state() { return 1; }

    set_test_platform rhel 8.10 "Red Hat Enterprise Linux 8.10"
    service_golden_active="ypupdated"
    check_u_43
    assert_equal VULNERABLE "$RESULT_STATUS" "U-43 active rpc.ypupdated service"
    assert_contains "$service_probe_arguments" "rpc.ypupdated.service" "U-43 ypupdated unit coverage"
    service_golden_active=""
    check_u_43
    assert_equal GOOD "$RESULT_STATUS" "U-43 inactive RHEL 8 NIS services"
    assert_contains "$RESULT_EVIDENCE" "guide_distribution_note=yp_rpms_removed_since_rhel_8" "U-43 RHEL 8 guide note"

    set_test_platform rhel 8.10 "Red Hat Enterprise Linux 8.10"
    check_u_44
    assert_equal GOOD "$RESULT_STATUS" "U-44 inactive supported RHEL legacy services"
    assert_contains "$RESULT_EVIDENCE" "guide_distribution_note=talk_removed_since_rhel_7" "U-44 RHEL 7 guide note"
    assert_contains "$service_probe_arguments" "atftpd.service" "U-44 atftpd unit coverage"
    service_golden_active="atftpd"
    check_u_44
    assert_equal VULNERABLE "$RESULT_STATUS" "U-44 active atftpd service"

    service_detect_snmp() {
        SERVICE_SNMP_CONFIG_UNCERTAIN=0
        return 0
    }
    service_snmp_files() { printf '%s\n' "$root/etc/snmp/snmpd.conf"; }

    set_test_platform rhel 10.2 "Red Hat Enterprise Linux 10.2"
    printf '%s\n' 'com2sec notConfigUser 192.0.2.0/24 Strong123!' > "$root/etc/snmp/snmpd.conf"
    check_u_60
    assert_equal GOOD "$RESULT_STATUS" "U-60 RHEL com2sec dialect"
    check_u_61
    assert_equal GOOD "$RESULT_STATUS" "U-61 RHEL com2sec source restriction"

    printf '%s\n' 'rocommunity Strong123! 192.0.2.0/24' > "$root/etc/snmp/snmpd.conf"
    check_u_60
    assert_equal MANUAL "$RESULT_STATUS" "U-60 RHEL rejects unlisted Debian dialect"
    check_u_61
    assert_equal MANUAL "$RESULT_STATUS" "U-61 RHEL rejects unlisted Debian dialect"

    printf '%s\n' 'rocommunity public default' > "$root/etc/snmp/snmpd.conf"
    check_u_60
    assert_equal VULNERABLE "$RESULT_STATUS" "U-60 wrong-dialect weak community remains vulnerable"
    check_u_61
    assert_equal VULNERABLE "$RESULT_STATUS" "U-61 wrong-dialect unrestricted source remains vulnerable"

    set_test_platform debian 13 "Debian GNU/Linux 13"
    printf '%s\n' 'rocommunity Strong123! 192.0.2.0/24' > "$root/etc/snmp/snmpd.conf"
    check_u_60
    assert_equal GOOD "$RESULT_STATUS" "U-60 Debian rocommunity dialect"
    check_u_61
    assert_equal GOOD "$RESULT_STATUS" "U-61 Debian rocommunity source restriction"

    printf '%s\n' 'com2sec notConfigUser 192.0.2.0/24 Strong123!' > "$root/etc/snmp/snmpd.conf"
    check_u_60
    assert_equal MANUAL "$RESULT_STATUS" "U-60 Debian rejects unlisted RHEL dialect"
    check_u_61
    assert_equal MANUAL "$RESULT_STATUS" "U-61 Debian rejects unlisted RHEL dialect"

    {
        printf '%s\n' 'rocommunity Strong123! 192.0.2.0/24'
        printf '%s\n' 'rouser secureUser authPriv'
    } > "$root/etc/snmp/snmpd.conf"
    check_u_60
    assert_equal MANUAL "$RESULT_STATUS" "U-60 mixed v2c and v3 credentials"
    check_u_61
    assert_equal MANUAL "$RESULT_STATUS" "U-61 mixed v2c and v3 access control"

    printf '%s\n' 'rocommunity Strong123! 0.0.0.0/0.0.0.0' > "$root/etc/snmp/snmpd.conf"
    check_u_61
    assert_equal VULNERABLE "$RESULT_STATUS" "U-61 unrestricted address and mask notation"
)

test_enterprise_service_variant_goldens() (
    local root="$TEST_TEMP/enterprise-service-variant-root"
    local scratch="$TEST_TEMP/enterprise-service-variant-scratch"
    local wants_directory="$root/etc/systemd/system/multi-user.target.wants"
    local unit=""
    local status=0

    mkdir -p -- \
        "$wants_directory" "$root/usr/lib/systemd/system" "$root/etc/snmp" "$scratch"
    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_service.sh
    . "$PROJECT_DIR/lib/checks_service.sh"
    SCRATCH_DIR="$scratch"
    set_test_platform rhel 8.10 "Red Hat Enterprise Linux 8.10"
    printf '%s\n' 'options { listen-on port 53 { 127.0.0.1; }; };' > "$root/etc/named.conf"

    for unit in named-pkcs11.service named-sdb.service named-sdb-chroot.service; do
        find "$wants_directory" -mindepth 1 -maxdepth 1 -type l -delete
        printf '%s\n' '[Unit]' "Description=$unit" '[Service]' 'ExecStart=/usr/sbin/named -f' \
            > "$root/usr/lib/systemd/system/$unit"
        ln -s "../../../../usr/lib/systemd/system/$unit" "$wants_directory/$unit"
        service_activation_state "$unit" || fail "$unit offline enablement was not detected"
        service_detect_dns >/dev/null 2>&1
        status=$?
        [ "$status" -ne 1 ] || fail "$unit was omitted from DNS activation detection"
        check_u_49
        assert_equal MANUAL "$RESULT_STATUS" "U-49 active offline $unit"
    done

    find "$wants_directory" -mindepth 1 -maxdepth 1 -type l -delete
    printf '%s\n' '[Unit]' 'Description=SNMP trap daemon' '[Service]' 'ExecStart=/usr/sbin/snmptrapd -f' \
        > "$root/usr/lib/systemd/system/snmptrapd.service"
    printf '%s\n' '[Unit]' 'Description=SNMP trap socket' '[Socket]' 'ListenDatagram=162' \
        > "$root/usr/lib/systemd/system/snmptrapd.socket"
    ln -s ../../../../usr/lib/systemd/system/snmptrapd.service "$wants_directory/snmptrapd.service"
    ln -s ../../../../usr/lib/systemd/system/snmptrapd.socket "$wants_directory/snmptrapd.socket"
    printf '%s\n' 'authCommunity log public' > "$root/etc/snmp/snmptrapd.conf"
    check_u_59
    assert_equal MANUAL "$RESULT_STATUS" "U-59 unsupported active snmptrapd semantics"
    check_u_60
    assert_equal MANUAL "$RESULT_STATUS" "U-60 unsupported active snmptrapd semantics"
    check_u_61
    assert_equal MANUAL "$RESULT_STATUS" "U-61 unsupported active snmptrapd semantics"
)

test_bind_stock_environment_goldens() (
    local root="$TEST_TEMP/bind-stock-environment-root"
    local scratch="$TEST_TEMP/bind-stock-environment-scratch"
    local systemctl_fixture="$scratch/systemctl"
    local properties="$scratch/systemctl-properties"
    local platform_version=""
    local status=0

    mkdir -p -- "$root/etc/bind" "$root/etc/default" "$root/etc/sysconfig" "$scratch"
    SCAN_ROOT="$root"
    RUNTIME_MODE="on"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_service.sh
    . "$PROJECT_DIR/lib/checks_service.sh"
    SCRATCH_DIR="$scratch"

    {
        printf '%s\n' '#!/bin/sh'
        printf '%s\n' 'if [ "$2" = named.service ]; then'
        printf '  exec /bin/cat %s\n' "$properties"
        printf '%s\n' 'fi'
        printf '%s\n' 'printf "LoadState=not-found\\n"'
    } > "$systemctl_fixture"
    chmod 0755 -- "$systemctl_fixture"
    runtime_enabled() { return 0; }
    trusted_command() { [ "$1" = systemctl ] && printf '%s\n' "$systemctl_fixture"; }

    set_test_platform ubuntu 26.04 "Ubuntu 26.04 LTS"
    printf '%s\n' 'options {};' > "$root/etc/bind/named.conf"
    printf '%s\n' 'OPTIONS="-u bind"' > "$root/etc/default/named"
    {
        printf '%s\n' 'LoadState=loaded'
        printf '%s\n' 'ActiveState=inactive'
        printf '%s\n' 'UnitFileState=enabled'
        printf '%s\n' 'MainPID=0'
        printf '%s\n' 'ExecStart={ path=/usr/sbin/named ; argv[]=/usr/sbin/named -f $OPTIONS ; ignore_errors=no ; }'
        printf '%s\n' 'Environment='
        printf '%s\n' 'EnvironmentFiles=-/etc/default/named'
    } > "$properties"
    service_bind_custom_invocation_state >/dev/null 2>&1
    status=$?
    assert_equal 1 "$status" "Debian stock named OPTIONS expansion"

    printf '%s\n' 'options {};' > "$root/etc/named.conf"
    for platform_version in 9.8 10.2; do
        set_test_platform rhel "$platform_version" "Red Hat Enterprise Linux $platform_version"
        printf '%s\n' 'NAMEDCONF=/etc/named.conf' 'OPTIONS="-u named"' > "$root/etc/sysconfig/named"
        {
            printf '%s\n' 'LoadState=loaded'
            printf '%s\n' 'ActiveState=inactive'
            printf '%s\n' 'UnitFileState=enabled'
            printf '%s\n' 'MainPID=0'
            printf '%s\n' 'ExecStart={ path=/usr/sbin/named ; argv[]=/usr/sbin/named -f -c ${NAMEDCONF} $OPTIONS ; ignore_errors=no ; }'
            printf '%s\n' 'Environment='
            printf '%s\n' 'EnvironmentFiles=-/etc/sysconfig/named'
        } > "$properties"
        service_bind_custom_invocation_state >/dev/null 2>&1
        status=$?
        assert_equal 1 "$status" "RHEL $platform_version stock NAMEDCONF and OPTIONS expansion"
    done

    printf '%s\n' 'NAMEDCONF=/etc/custom-named.conf' 'OPTIONS="-u named"' > "$root/etc/sysconfig/named"
    service_bind_custom_invocation_state >/dev/null 2>&1
    status=$?
    assert_equal 0 "$status" "nonstandard RHEL NAMEDCONF override"
)

test_debian_tftp_activation_goldens() (
    local root="$TEST_TEMP/debian-tftp-activation-root"
    local scratch="$TEST_TEMP/debian-tftp-activation-scratch"
    local service_wants="$root/etc/systemd/system/multi-user.target.wants"
    local socket_wants="$root/etc/systemd/system/sockets.target.wants"

    mkdir -p -- \
        "$service_wants" "$socket_wants" "$root/usr/lib/systemd/system" \
        "$root/etc/init.d" "$root/etc/rc2.d" "$scratch"
    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_service.sh
    . "$PROJECT_DIR/lib/checks_service.sh"
    SCRATCH_DIR="$scratch"
    set_test_platform debian 13 "Debian GNU/Linux 13"

    printf '%s\n' '[Unit]' 'Description=atftpd' '[Service]' 'ExecStart=/usr/sbin/atftpd --daemon' \
        > "$root/usr/lib/systemd/system/atftpd.service"
    printf '%s\n' '[Unit]' 'Description=atftpd socket' '[Socket]' 'ListenDatagram=69' \
        > "$root/usr/lib/systemd/system/atftpd.socket"
    ln -s ../../../../usr/lib/systemd/system/atftpd.service "$service_wants/atftpd.service"
    check_u_44
    assert_equal VULNERABLE "$RESULT_STATUS" "U-44 enabled Debian atftpd service"
    rm -f -- "$service_wants/atftpd.service"

    ln -s ../../../../usr/lib/systemd/system/atftpd.socket "$socket_wants/atftpd.socket"
    check_u_44
    assert_equal VULNERABLE "$RESULT_STATUS" "U-44 enabled Debian atftpd socket"
    rm -f -- "$socket_wants/atftpd.socket"

    printf '%s\n' '#!/bin/sh' 'exit 0' > "$root/etc/init.d/tftpd-hpa"
    chmod 0755 -- "$root/etc/init.d/tftpd-hpa"
    ln -s ../init.d/tftpd-hpa "$root/etc/rc2.d/S01tftpd-hpa"
    check_u_44
    assert_equal VULNERABLE "$RESULT_STATUS" "U-44 enabled Debian tftpd-hpa SysV service"
    rm -f -- "$root/etc/rc2.d/S01tftpd-hpa"

    printf '%s\n' '#!/bin/sh' 'exit 0' > "$root/etc/init.d/pure-ftpd"
    chmod 0755 -- "$root/etc/init.d/pure-ftpd"
    ln -s ../init.d/pure-ftpd "$root/etc/rc2.d/S01pure-ftpd"
    service_detect_ftp
    assert_contains "$SERVICE_FTP_PROVIDERS" "pure-ftpd" "Debian pure-ftpd SysV provider detection"
    check_u_35
    assert_equal MANUAL "$RESULT_STATUS" "U-35 active offline pure-ftpd"
    check_u_54
    assert_equal MANUAL "$RESULT_STATUS" "U-54 active offline pure-ftpd"
    check_u_56
    assert_equal MANUAL "$RESULT_STATUS" "U-56 active offline pure-ftpd"
    check_u_57
    assert_equal MANUAL "$RESULT_STATUS" "U-57 active offline pure-ftpd"
)

test_service_false_positive_goldens() (
    local root="$TEST_TEMP/service-false-positive-root"
    local scratch="$TEST_TEMP/service-false-positive-scratch"
    local service_wants="$root/etc/systemd/system/multi-user.target.wants"
    local unit=""
    local status=0

    mkdir -p -- \
        "$service_wants" "$root/usr/lib/systemd/system" "$root/etc/xinetd.d" "$scratch"
    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_service.sh
    . "$PROJECT_DIR/lib/checks_service.sh"
    SCRATCH_DIR="$scratch"
    set_test_platform debian 13 "Debian GNU/Linux 13"

    for unit in nfs-idmapd.service nfs-blkmap.service; do
        printf '%s\n' '[Unit]' "Description=$unit" '[Service]' 'ExecStart=/usr/bin/true' \
            > "$root/usr/lib/systemd/system/$unit"
        ln -s "../../../../usr/lib/systemd/system/$unit" "$service_wants/$unit"
    done
    service_listener_state() {
        case " $* " in
            *' 53 '*) return 0 ;;
            *) return 1 ;;
        esac
    }
    service_nfs_state
    status=$?
    assert_equal 1 "$status" "client-only NFS helper units"
    check_u_39
    assert_equal GOOD "$RESULT_STATUS" "U-39 client-only NFS helper units"

    for unit in systemd-timesyncd.service systemd-resolved.service; do
        printf '%s\n' '[Unit]' "Description=$unit" '[Service]' 'ExecStart=/usr/bin/true' \
            > "$root/usr/lib/systemd/system/$unit"
        ln -s "../../../../usr/lib/systemd/system/$unit" "$service_wants/$unit"
    done
    check_u_38
    assert_equal MANUAL "$RESULT_STATUS" "U-38 normal timesyncd and unresolved port 53 listener"

    {
        printf '%s\n' 'defaults'
        printf '%s\n' '{'
        printf '%s\n' '    disabled = tftp talk'
        printf '%s\n' '    enabled = echo'
        printf '%s\n' '}'
        printf '%s\n' 'includedir /etc/xinetd.d'
    } > "$root/etc/xinetd.conf"
    for unit in tftp talk echo; do
        printf '%s\n' "service $unit" '{' '    socket_type = stream' '}' > "$root/etc/xinetd.d/$unit"
    done
    if service_xinetd_enabled '^tftp$'; then
        fail "xinetd defaults disabled list did not disable tftp"
    fi
    if service_xinetd_enabled '^talk$'; then
        fail "xinetd defaults disabled list did not disable talk"
    fi
    service_xinetd_enabled '^echo$' || fail "xinetd defaults enabled list did not enable echo"
)

test_ufw_sysctl_and_firewall_goldens() (
    local root="$TEST_TEMP/ufw-firewall-golden-root"
    local scratch="$TEST_TEMP/ufw-firewall-golden-scratch"
    local output=""
    local status=0

    mkdir -p -- \
        "$root/etc/default" "$root/etc/ufw" "$root/etc/sysctl.d" \
        "$root/etc/systemd/system/multi-user.target.wants" \
        "$root/usr/lib/systemd/system" "$scratch"
    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_account_file.sh
    . "$PROJECT_DIR/lib/checks_account_file.sh"
    SCRATCH_DIR="$scratch"
    set_test_platform ubuntu 26.04 "Ubuntu 26.04 LTS"

    printf '%s\n' 'net.ipv4.ip_forward = 0' > "$root/etc/sysctl.d/90-base.conf"
    printf '%s\n' 'ENABLED=yes' 'DEFAULT_INPUT_POLICY=DROP' > "$root/etc/default/ufw"
    printf '%s\n' 'net.ipv4.ip_forward = 1' > "$root/etc/ufw/sysctl.conf"
    ufw_effective_state
    status=$?
    assert_equal 0 "$status" "enabled UFW state"
    output="$(ufw_sysctl_value net.ipv4.ip_forward)" || fail "enabled UFW sysctl override was not resolved"
    assert_contains "$output" $'1\t/etc/ufw/sysctl.conf:1' "default UFW sysctl override"
    output="$(sysctl_explain net.ipv4.ip_forward)" || fail "UFW sysctl explanation failed"
    assert_contains "$output" "persistent=1" "active UFW final persistent value"

    printf '%s\n' 'ENABLED=no' 'DEFAULT_INPUT_POLICY=DROP' > "$root/etc/default/ufw"
    ufw_effective_state
    status=$?
    assert_equal 1 "$status" "disabled UFW state"
    if ufw_sysctl_value net.ipv4.ip_forward >/dev/null 2>&1; then
        fail "disabled UFW supplied a sysctl override"
    fi
    output="$(sysctl_explain net.ipv4.ip_forward)" || fail "disabled UFW sysctl explanation failed"
    assert_contains "$output" "persistent=0" "disabled UFW leaves systemd sysctl value"

    printf '%s\n' 'ENABLED=yes' 'DEFAULT_INPUT_POLICY=DROP' 'IPT_SYSCTL=/etc/ufw/custom-sysctl.conf' > "$root/etc/default/ufw"
    printf '%s\n' 'net.ipv4.ip_forward = 1' > "$root/etc/ufw/custom-sysctl.conf"
    output="$(ufw_sysctl_value net.ipv4.ip_forward)" || fail "custom UFW IPT_SYSCTL path was not resolved"
    assert_contains "$output" $'1\t/etc/ufw/custom-sysctl.conf:1' "custom UFW sysctl override"

    {
        printf '%s\n' '*filter'
        printf '%s\n' ':ufw-user-input - [0:0]'
        printf '%s\n' '-A ufw-user-input -s 192.0.2.0/24 -p tcp --dport 22 -j ACCEPT'
        printf '%s\n' 'COMMIT'
    } > "$root/etc/ufw/user.rules"
    printf '%s\n' 'ENABLED=no' 'DEFAULT_INPUT_POLICY=DROP' > "$root/etc/default/ufw"
    check_u_28
    assert_equal VULNERABLE "$RESULT_STATUS" "U-28 disabled UFW ignores persistent rules"

    printf '%s\n' '[Service]' 'ExecStart=/usr/lib/ufw/ufw-init start quiet' > "$root/usr/lib/systemd/system/ufw.service"
    ln -s ../../../../usr/lib/systemd/system/ufw.service \
        "$root/etc/systemd/system/multi-user.target.wants/ufw.service"
    printf '%s\n' 'ENABLED=yes' 'DEFAULT_INPUT_POLICY=DROP' > "$root/etc/default/ufw"
    check_u_28
    assert_equal MANUAL "$RESULT_STATUS" "U-28 enabled UFW with restrictive rule"

    rm -f -- "$root/etc/ufw/user.rules"
    printf '%s\n' 'ENABLED=no' 'DEFAULT_INPUT_POLICY=DROP' > "$root/etc/default/ufw"
    {
        printf '%s\n' 'flush ruleset'
        printf '%s\n' 'table inet filter {'
        printf '%s\n' '  chain input { type filter hook input priority filter; policy accept; }'
        printf '%s\n' '  chain forward { type filter hook forward priority filter; policy accept; }'
        printf '%s\n' '  chain output { type filter hook output priority filter; policy accept; }'
        printf '%s\n' '}'
    } > "$root/etc/nftables.conf"
    printf '%s\n' '[Unit]' 'Description=nftables' '[Service]' 'ExecStart=/usr/sbin/nft -f /etc/nftables.conf' \
        > "$root/usr/lib/systemd/system/nftables.service"
    check_u_28
    assert_equal VULNERABLE "$RESULT_STATUS" "U-28 disabled stock empty nftables chains"
)

test_u28_backend_goldens() (
    local wrapper_root="$TEST_TEMP/u28-wrapper-root"
    local ufw_root="$TEST_TEMP/u28-ufw-root"
    local nft_root="$TEST_TEMP/u28-nft-root"
    local iptables_root="$TEST_TEMP/u28-iptables-root"
    local ip6tables_root="$TEST_TEMP/u28-ip6tables-root"
    local firewalld_root="$TEST_TEMP/u28-firewalld-root"
    local scratch="$TEST_TEMP/u28-backend-scratch"
    local status=0
    local fake_firewall_command="$scratch/firewall-cmd"

    mkdir -p -- "$scratch"
    SCAN_ROOT="$wrapper_root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_account_file.sh
    . "$PROJECT_DIR/lib/checks_account_file.sh"
    SCRATCH_DIR="$scratch"

    enable_u28_unit() {
        local root="$1"
        local unit_name="$2"
        local command_line="$3"

        mkdir -p -- "$root/usr/lib/systemd/system" "$root/etc/systemd/system/multi-user.target.wants"
        printf '%s\n' '[Service]' "ExecStart=$command_line" > "$root/usr/lib/systemd/system/$unit_name"
        ln -s "../../../../usr/lib/systemd/system/$unit_name" \
            "$root/etc/systemd/system/multi-user.target.wants/$unit_name"
    }

    mkdir -p -- "$wrapper_root/etc"
    set_test_platform debian 13 "Debian GNU/Linux 13"
    printf '%s\n' 'ALL: ALL' > "$wrapper_root/etc/hosts.deny"
    printf '%s\n' 'in.rlogind: 192.0.2.0/24' > "$wrapper_root/etc/hosts.allow"
    printf '%s\n' 'login stream tcp nowait root /usr/sbin/tcpd /usr/sbin/in.rlogind' > "$wrapper_root/etc/inetd.conf"
    check_u_28
    assert_equal MANUAL "$RESULT_STATUS" "U-28 applicable TCP Wrapper allowlist"
    assert_contains "$RESULT_EVIDENCE" "wrapper_policy=restricted,applicable_daemon=in.rlogind" "U-28 TCP Wrapper applicability"

    printf '%s\n' 'in.rlogind: 192.0.2.0/24' 'in.rlogind: ALL' > "$wrapper_root/etc/hosts.allow"
    check_u_28
    assert_equal VULNERABLE "$RESULT_STATUS" "U-28 daemon-specific TCP Wrapper allow-all"

    printf '%s\n' 'ALL: ALL' > "$wrapper_root/etc/hosts.allow"
    check_u_28
    assert_equal VULNERABLE "$RESULT_STATUS" "U-28 TCP Wrapper allow-all is not restrictive"
    printf '%s\n' 'not a wrapper rule' > "$wrapper_root/etc/hosts.allow"
    check_u_28
    assert_equal MANUAL "$RESULT_STATUS" "U-28 malformed TCP Wrapper policy"
    rm -f -- "$wrapper_root/etc/hosts.allow"
    ln -s /outside-wrapper-policy "$wrapper_root/etc/hosts.allow"
    check_u_28
    assert_equal ERROR "$RESULT_STATUS" "U-28 unsafe TCP Wrapper path"
    rm -f -- "$wrapper_root/etc/hosts.allow"
    printf '%s\n' 'in.rlogind: 192.0.2.0/24' > "$wrapper_root/etc/hosts.allow"
    set_test_platform rhel 9.8 "Red Hat Enterprise Linux 9.8"
    check_u_28
    assert_equal VULNERABLE "$RESULT_STATUS" "U-28 RHEL ignores inapplicable TCP Wrapper files"

    mkdir -p -- "$ufw_root/etc/ufw" "$ufw_root/etc/default"
    enable_u28_unit "$ufw_root" ufw.service '/usr/lib/ufw/ufw-init start quiet'
    SCAN_ROOT="$ufw_root"
    set_test_platform ubuntu 24.04 "Ubuntu 24.04 LTS"
    printf '%s\n' 'ENABLED=yes' > "$ufw_root/etc/ufw/ufw.conf"
    printf '%s\n' 'IPV6=no' 'DEFAULT_INPUT_POLICY=DROP' > "$ufw_root/etc/default/ufw"
    printf '%s\n' '*filter' ':ufw-before-input - [0:0]' 'COMMIT' > "$ufw_root/etc/ufw/before.rules"
    printf '%s\n' '*filter' ':ufw-user-input - [0:0]' \
        '-A ufw-user-input -s 192.0.2.0/24 -p tcp --dport 22 -j ACCEPT' 'COMMIT' \
        > "$ufw_root/etc/ufw/user.rules"
    printf '%s\n' '*filter' ':ufw-after-input - [0:0]' 'COMMIT' > "$ufw_root/etc/ufw/after.rules"
    check_u_28
    assert_equal MANUAL "$RESULT_STATUS" "U-28 enabled UFW source and port restriction"
    printf '%s\n' '*filter' ':ufw-user-input - [0:0]' \
        '-A ufw-user-input -s 0.0.0.0/0 -p tcp --dport 22 -j ACCEPT' 'COMMIT' \
        > "$ufw_root/etc/ufw/user.rules"
    check_u_28
    assert_equal VULNERABLE "$RESULT_STATUS" "U-28 UFW allow-anywhere is not restrictive"
    : > "$ufw_root/etc/ufw/user.rules"
    printf '%s\n' '*filter' ':ufw-before-input - [0:0]' \
        '-A ufw-before-input -s 198.51.100.0/24 -p tcp --dport 443 -j ACCEPT' 'COMMIT' \
        > "$ufw_root/etc/ufw/before.rules"
    check_u_28
    assert_equal MANUAL "$RESULT_STATUS" "U-28 UFW before-rules graph"
    printf '%s\n' 'DEFAULT_INPUT_POLICY=ACCEPT' > "$ufw_root/etc/default/ufw"
    check_u_28
    assert_equal VULNERABLE "$RESULT_STATUS" "U-28 UFW default-allow input"
    printf '%s\n' 'IPV6=yes' 'DEFAULT_INPUT_POLICY=DROP' > "$ufw_root/etc/default/ufw"
    printf '%s\n' '*filter' ':ufw-before-input - [0:0]' 'COMMIT' > "$ufw_root/etc/ufw/before.rules"
    printf '%s\n' '*filter' ':ufw-user-input - [0:0]' \
        '-A ufw-user-input -s 192.0.2.0/24 -p tcp --dport 22 -j ACCEPT' 'COMMIT' \
        > "$ufw_root/etc/ufw/user.rules"
    printf '%s\n' '*filter' ':ufw-after-input - [0:0]' 'COMMIT' > "$ufw_root/etc/ufw/after.rules"
    printf '%s\n' '*filter' ':ufw6-before-input - [0:0]' 'COMMIT' > "$ufw_root/etc/ufw/before6.rules"
    printf '%s\n' '*filter' ':ufw6-user-input - [0:0]' \
        '-A ufw6-user-input -s ::/0 -p tcp --dport 22 -j ACCEPT' 'COMMIT' \
        > "$ufw_root/etc/ufw/user6.rules"
    printf '%s\n' '*filter' ':ufw6-after-input - [0:0]' 'COMMIT' > "$ufw_root/etc/ufw/after6.rules"
    check_u_28
    assert_equal VULNERABLE "$RESULT_STATUS" "U-28 UFW IPv6 broad input blocks IPv4 candidate"

    rm -f -- "$ufw_root/etc/ufw/after6.rules"
    status=0
    scanner_u28_ufw_probe || status=$?
    assert_equal 3 "$status" "U-28 UFW missing enabled-family rules file"
    printf '%s\n' '*filter' ':ufw6-after-input - [0:0]' 'COMMIT' > "$ufw_root/etc/ufw/after6.rules"
    printf '%s\n' '*filter' ':not-ufw6-before-input - [0:0]' 'COMMIT' > "$ufw_root/etc/ufw/before6.rules"
    status=0
    scanner_u28_ufw_probe || status=$?
    assert_equal 3 "$status" "U-28 UFW missing enabled-family input hook"

    ln -s /dev/null "$ufw_root/etc/systemd/system/ufw.service"
    check_u_28
    assert_equal VULNERABLE "$RESULT_STATUS" "U-28 masked UFW unit"

    (
        local ufw_runtime_case="open"
        local ufw_status=0

        runtime_enabled() { return 0; }
        scanner_u28_capture_command() {
            local output_file="$1"
            local command_name="$2"

            shift 2
            [ "$command_name" = ufw ] || return 1
            case "$*" in
                "status verbose")
                    printf '%s\n' 'Status: active' \
                        "Default: $([ "$ufw_runtime_case" = open ] && printf allow || printf deny) (incoming), allow (outgoing), disabled (routed)" \
                        > "$output_file"
                    ;;
                "show raw")
                    {
                        printf '%s\n' 'IPV4 (raw):'
                        printf 'Chain INPUT (policy %s 0 packets, 0 bytes)\n' \
                            "$([ "$ufw_runtime_case" = open ] && printf ACCEPT || printf DROP)"
                        printf '%s\n' '    pkts      bytes target     prot opt in     out     source               destination'
                        if [ "$ufw_runtime_case" = restricted ]; then
                            printf '%s\n' '       0        0 ACCEPT     tcp  --  *      *       192.0.2.0/24       0.0.0.0/0            tcp dpt:22'
                        fi
                        printf '%s\n' 'Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)' \
                            '    pkts      bytes target     prot opt in     out     source               destination' \
                            'Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)' \
                            '    pkts      bytes target     prot opt in     out     source               destination' \
                            'IPV6:'
                        printf 'Chain INPUT (policy %s 0 packets, 0 bytes)\n' \
                            "$([ "$ufw_runtime_case" = open ] && printf ACCEPT || printf DROP)"
                        printf '%s\n' '    pkts      bytes target     prot opt in     out     source               destination'
                        printf '%s\n' 'Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)' \
                            '    pkts      bytes target     prot opt in     out     source               destination' \
                            'Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)' \
                            '    pkts      bytes target     prot opt in     out     source               destination'
                    } > "$output_file"
                    ;;
                *) return 2 ;;
            esac
        }
        scanner_u28_tcp_wrapper_probe() { SCANNER_U28_PROBE_EVIDENCE="wrapper_policy=absent"; return 1; }
        scanner_u28_nftables_probe() { SCANNER_U28_PROBE_EVIDENCE="nftables_state=inactive"; return 1; }
        scanner_u28_xtables_probe() { SCANNER_U28_PROBE_EVIDENCE="${1}_state=inactive"; return 1; }
        scanner_u28_firewalld_probe() { SCANNER_U28_PROBE_EVIDENCE="firewalld_state=inactive"; return 1; }

        scanner_u28_ufw_probe || ufw_status=$?
        assert_equal 1 "$ufw_status" "U-28 live UFW native default-accept output"
        check_u_28
        assert_equal VULNERABLE "$RESULT_STATUS" "U-28 live UFW default-accept result"

        ufw_runtime_case="restricted"
        ufw_status=0
        scanner_u28_ufw_probe || ufw_status=$?
        assert_equal 0 "$ufw_status" "U-28 live UFW native restricted output"
        check_u_28
        assert_equal MANUAL "$RESULT_STATUS" "U-28 live UFW restricted candidate"
    )

    mkdir -p -- "$nft_root/etc/nftables"
    enable_u28_unit "$nft_root" nftables.service '/usr/sbin/nft -f /etc/nftables.conf'
    SCAN_ROOT="$nft_root"
    set_test_platform debian 13 "Debian GNU/Linux 13"
    printf '%s\n' 'include "/etc/nftables/input.nft"' > "$nft_root/etc/nftables.conf"
    printf '%s\n' 'table inet filter {' ' chain input {' \
        '  type filter hook input priority 0; policy drop;' \
        '  ip saddr 192.0.2.0/24 tcp dport 22 accept' ' }' '}' \
        > "$nft_root/etc/nftables/input.nft"
    check_u_28
    assert_equal MANUAL "$RESULT_STATUS" "U-28 nftables active entrypoint include"
    printf '%s\n' 'table inet filter {' ' chain output {' \
        '  type filter hook output priority 0; policy drop;' \
        '  ip daddr 192.0.2.0/24 tcp dport 22 accept' ' }' '}' \
        > "$nft_root/etc/nftables/input.nft"
    printf '%s\n' 'table inet filter {' ' chain input {' \
        '  type filter hook input priority 0; policy drop;' \
        '  ip saddr 203.0.113.0/24 tcp dport 22 accept' ' }' '}' \
        > "$nft_root/etc/nftables/orphan.nft"
    status=0
    scanner_u28_nftables_file_state "$nft_root/etc/nftables/input.nft" || status=$?
    assert_equal 1 "$status" "U-28 ignores nftables OUTPUT-only policy"
    check_u_28
    assert_equal MANUAL "$RESULT_STATUS" "U-28 include graph does not claim an orphan nftables candidate"
    printf '%s\n' 'include "/outside-nftables.conf"' > "$nft_root/etc/nftables.conf"
    check_u_28
    assert_equal ERROR "$RESULT_STATUS" "U-28 unsafe nftables include"
    status=0
    scanner_u28_nftables_file_state "$nft_root/etc/nftables/orphan.nft" || status=$?
    assert_equal 0 "$status" "U-28 nftables INPUT parser"

    printf '%s\n' 'table inet filter {' ' flags dormant;' ' chain input {' \
        '  type filter hook input priority 0; policy drop;' \
        '  ip saddr 192.0.2.0/24 tcp dport 22 accept' ' }' '}' \
        > "$scratch/nft-dormant"
    status=0
    scanner_u28_nftables_file_state "$scratch/nft-dormant" || status=$?
    assert_equal 3 "$status" "U-28 dormant nftables table requires conservative review"

    printf '%s\n' 'table ip6 filter {' ' chain input {' \
        '  type filter hook input priority 0; policy drop;' \
        '  ip saddr 192.0.2.0/24 tcp dport 22 accept' ' }' '}' \
        > "$scratch/nft-family-mismatch"
    status=0
    scanner_u28_nftables_file_state "$scratch/nft-family-mismatch" || status=$?
    assert_equal 3 "$status" "U-28 nftables address-family mismatch"

    printf '%s\n' 'table inet filter {' ' chain input {' \
        '  type filter hook input priority 0; policy drop;' \
        '  ct state new,established accept' \
        '  ip saddr 192.0.2.0/24 tcp dport 22 accept' ' }' '}' \
        > "$scratch/nft-new-state"
    status=0
    scanner_u28_nftables_file_state "$scratch/nft-new-state" || status=$?
    assert_equal 1 "$status" "U-28 nftables NEW state is not infrastructure traffic"

    printf '%s\n' 'table inet filter {' ' chain input {' \
        '  type filter hook input priority 0; policy drop;' \
        '  ip saddr != 192.0.2.0/24 tcp dport 22 accept' ' }' '}' \
        > "$scratch/nft-negated-source"
    status=0
    scanner_u28_nftables_file_state "$scratch/nft-negated-source" || status=$?
    assert_equal 1 "$status" "U-28 nftables negated source is broad"

    mkdir -p -- "$nft_root/etc/nftables.d" "$nft_root/etc/nftables.fragments"
    printf '%s\n' 'include "/etc/nftables.d/*.nft"' > "$nft_root/etc/nftables.conf"
    printf '%s\n' 'table inet filter {' ' chain input {' \
        '  type filter hook input priority 0; policy drop;' \
        '  ip saddr 192.0.2.0/24 tcp dport 22 accept' ' }' '}' \
        > "$nft_root/etc/nftables.fragments/input.nft"
    ln -s /etc/nftables.fragments/input.nft "$nft_root/etc/nftables.d/input.nft"
    status=0
    scanner_u28_nftables_probe || status=$?
    assert_equal 3 "$status" "U-28 nftables glob validates an in-root symlink before conservative review"
    check_u_28
    assert_equal MANUAL "$RESULT_STATUS" "U-28 nftables glob symlink review"

    rm -f -- "$nft_root/etc/nftables.d/input.nft"
    printf '%s\n' 'table inet ignored {}' > "$TEST_TEMP/u28-outside-nftables.conf"
    ln -s ../../../u28-outside-nftables.conf "$nft_root/etc/nftables.d/input.nft"
    status=0
    scanner_u28_nftables_probe || status=$?
    assert_equal 2 "$status" "U-28 nftables glob rejects an escaping symlink"

    mkdir -p -- "$iptables_root/etc/iptables"
    enable_u28_unit "$iptables_root" netfilter-persistent.service '/usr/sbin/netfilter-persistent start'
    SCAN_ROOT="$iptables_root"
    set_test_platform debian 13 "Debian GNU/Linux 13"
    printf '%s\n' '*filter' ':INPUT DROP [0:0]' ':FORWARD ACCEPT [0:0]' ':OUTPUT ACCEPT [0:0]' \
        '-A INPUT -s 192.0.2.0/24 -p tcp -m multiport --dports 22,443 -j ACCEPT' 'COMMIT' \
        > "$iptables_root/etc/iptables/rules.v4"
    check_u_28
    assert_equal MANUAL "$RESULT_STATUS" "U-28 Debian persistent INPUT policy and multiport"
    printf '%s\n' '*filter' ':INPUT ACCEPT [0:0]' ':FORWARD DROP [0:0]' ':OUTPUT DROP [0:0]' \
        '-A OUTPUT -d 192.0.2.1 -p tcp --dport 22 -j ACCEPT' 'COMMIT' \
        > "$iptables_root/etc/iptables/rules.v4"
    check_u_28
    assert_equal VULNERABLE "$RESULT_STATUS" "U-28 ignores FORWARD and OUTPUT-only xtables rules"
    printf '%s\n' '*filter' ':INPUT DROP [0:0]' \
        '-A INPUT -s 0.0.0.0/0 -p tcp --dport 22 -j ACCEPT' 'COMMIT' \
        > "$iptables_root/etc/iptables/rules.v4"
    check_u_28
    assert_equal VULNERABLE "$RESULT_STATUS" "U-28 rejects universal xtables ACCEPT"

    printf '%s\n' '*filter' ':INPUT DROP [0:0]' \
        '-A INPUT -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT' \
        '-A INPUT -s 192.0.2.0/24 -p tcp --dport 22 -j ACCEPT' 'COMMIT' \
        > "$scratch/iptables-new-state"
    status=0
    scanner_u28_iptables_file_state "$scratch/iptables-new-state" || status=$?
    assert_equal 1 "$status" "U-28 iptables NEW state is not infrastructure traffic"

    printf '%s\n' '*filter' ':INPUT DROP [0:0]' \
        '-A INPUT ! -i lo -j ACCEPT' \
        '-A INPUT -s 192.0.2.0/24 -p tcp --dport 22 -j ACCEPT' 'COMMIT' \
        > "$scratch/iptables-negated-loopback"
    status=0
    scanner_u28_iptables_file_state "$scratch/iptables-negated-loopback" || status=$?
    assert_equal 1 "$status" "U-28 iptables negated loopback is broad"

    mkdir -p -- "$ip6tables_root/etc/sysconfig"
    enable_u28_unit "$ip6tables_root" ip6tables.service '/usr/libexec/iptables/iptables.init start'
    SCAN_ROOT="$ip6tables_root"
    set_test_platform rhel 9.8 "Red Hat Enterprise Linux 9.8"
    printf '%s\n' '*filter' ':INPUT DROP [0:0]' \
        '-A INPUT -s 2001:db8::/32 -p tcp --dport 22 -j ACCEPT' 'COMMIT' \
        > "$ip6tables_root/etc/sysconfig/ip6tables"
    check_u_28
    assert_equal MANUAL "$RESULT_STATUS" "U-28 RHEL persistent ip6tables path"

    mkdir -p -- "$firewalld_root/etc/firewalld/zones" "$firewalld_root/etc/firewalld/policies"
    enable_u28_unit "$firewalld_root" firewalld.service '/usr/sbin/firewalld --nofork'
    SCAN_ROOT="$firewalld_root"
    set_test_platform rhel 9.8 "Red Hat Enterprise Linux 9.8"
    printf '%s\n' 'DefaultZone=public' > "$firewalld_root/etc/firewalld/firewalld.conf"
    printf '%s\n' '<zone><service name="ssh"/></zone>' > "$firewalld_root/etc/firewalld/zones/public.xml"
    printf '%s\n' '<zone target="DROP"><service name="ssh"/></zone>' > "$firewalld_root/etc/firewalld/zones/inactive.xml"
    printf '%s\n' '<policy target="CONTINUE"><ingress-zone name="ANY"/><egress-zone name="HOST"/></policy>' \
        > "$firewalld_root/etc/firewalld/policies/allow-host-ipv6.xml"
    check_u_28
    assert_equal VULNERABLE "$RESULT_STATUS" "U-28 ignores inactive firewalld zone and CONTINUE policy"
    printf '%s\n' 'DefaultZone=secure' > "$firewalld_root/etc/firewalld/firewalld.conf"
    printf '%s\n' '<zone target="DROP"><source address="192.0.2.0/24"/><service name="ssh"/></zone>' \
        > "$firewalld_root/etc/firewalld/zones/secure.xml"
    status=0
    scanner_u28_firewalld_zone_xml_state "$firewalld_root/etc/firewalld/zones/secure.xml" || status=$?
    assert_equal 1 "$status" "U-28 firewalld top-level source and service are not a paired rule"
    check_u_28
    assert_equal VULNERABLE "$RESULT_STATUS" "U-28 firewalld default-zone source binding does not scope services"
    printf '%s\n' '<zone target="ACCEPT"><source address="192.0.2.0/24"/><service name="ssh"/></zone>' \
        > "$firewalld_root/etc/firewalld/zones/secure.xml"
    check_u_28
    assert_equal VULNERABLE "$RESULT_STATUS" "U-28 rejects permissive firewalld target"

    printf '%s\n' 'DefaultZone=public' > "$firewalld_root/etc/firewalld/firewalld.conf"
    printf '%s\n' '<zone target="DROP"><rule><source address="192.0.2.0/24"/><service name="ssh"/><accept/></rule></zone>' \
        > "$firewalld_root/etc/firewalld/zones/secure.xml"
    status=0
    scanner_u28_firewalld_offline_probe || status=$?
    assert_equal 1 "$status" "U-28 inactive firewalld rich-rule provider state"
    check_u_28
    assert_equal VULNERABLE "$RESULT_STATUS" "U-28 inactive firewalld rich-rule zone"

    printf '%s\n' 'target: default' 'sources:' 'ports:' 'rich rules:' > "$scratch/empty-zone"
    status=0
    scanner_u28_firewalld_zone_text_state "$scratch/empty-zone" || status=$?
    assert_equal 4 "$status" "U-28 empty firewalld rich-rules section"

    printf '%s\n' '<zone target="DROP"><!-- <source address="192.0.2.0/24"/><service name="ssh"/> --></zone>' \
        > "$scratch/firewalld-commented-zone.xml"
    status=0
    scanner_u28_firewalld_zone_xml_state "$scratch/firewalld-commented-zone.xml" || status=$?
    assert_equal 4 "$status" "U-28 firewalld ignores commented XML elements"

    printf '%s\n' '<zone target="DROP"><rule><source invert="True" address="192.0.2.0/24"/><service name="ssh"/><accept/></rule></zone>' \
        > "$scratch/firewalld-inverted-zone.xml"
    status=0
    scanner_u28_firewalld_zone_xml_state "$scratch/firewalld-inverted-zone.xml" || status=$?
    assert_equal 1 "$status" "U-28 firewalld inverted source is broad"

    (
        SCAN_ROOT="/"
        RUNTIME_MODE="on"
        runtime_enabled() { return 0; }
        service_state() { [ "$1" = firewalld.service ] && return 0; return 3; }
        {
            printf '%s\n' '#!/bin/sh' 'case "$*" in'
            printf '%s\n' \
                '  "--get-active-zones") printf "public\n  interfaces: eth0\nsecure\n  sources: 192.0.2.0/24\n" ;;' \
                '  "--get-default-zone") printf "public\n" ;;' \
                '  "--zone public --list-all"|"--permanent --zone public --list-all") printf "target: ACCEPT\ninterfaces: eth0\nsources:\nservices: ssh\nrich rules:\n" ;;' \
                '  "--zone secure --list-all"|"--permanent --zone secure --list-all") printf "target: DROP\ninterfaces:\nsources: 192.0.2.0/24\nservices:\nports:\nrich rules:\nrule source address=\"192.0.2.0/24\" service name=\"ssh\" accept\n" ;;' \
                '  "--get-active-policies") : ;;' \
                '  *) exit 2 ;;'
            printf '%s\n' 'esac'
        } > "$fake_firewall_command"
        chmod 0755 -- "$fake_firewall_command"
        trusted_command() {
            [ "$1" = firewall-cmd ] && printf '%s\n' "$fake_firewall_command" && return 0
            return 1
        }
        status=0
        scanner_u28_firewalld_probe || status=$?
        assert_equal 1 "$status" "U-28 open active firewalld zone blocks restricted candidate"

        {
            printf '%s\n' '#!/bin/sh' 'case "$*" in'
            printf '%s\n' \
                '  "--get-active-zones") printf "secure\\n  sources: 192.0.2.0/24\\n" ;;' \
                '  "--get-default-zone") printf "secure\\n" ;;' \
                '  "--zone secure --list-all") printf "target: DROP\\nsources: 192.0.2.0/24\\nservices:\\nports:\\nrich rules:\\nrule source address=\"192.0.2.0/24\" service name=\"ssh\" accept\\n" ;;' \
                '  "--permanent --zone secure --list-all") printf "target: DROP\\nsources: 192.0.2.0/24\\nservices:\\nports:\\nrich rules:\\n" ;;' \
                '  "--get-active-policies") printf "allow-host-ipv6\\n" ;;' \
                '  "--policy allow-host-ipv6 --list-all"|"--permanent --policy allow-host-ipv6 --list-all") printf "target: CONTINUE\\ningress-zones: ANY\\negress-zones: HOST\\nrich rules:\\n" ;;' \
                '  *) exit 2 ;;'
            printf '%s\n' 'esac'
        } > "$fake_firewall_command"
        chmod 0755 -- "$fake_firewall_command"
        trusted_command() {
            [ "$1" = firewall-cmd ] && printf '%s\n' "$fake_firewall_command" && return 0
            return 1
        }
        status=0
        scanner_u28_firewalld_probe || status=$?
        assert_equal 3 "$status" "U-28 firewalld runtime and permanent drift"

        printf '%s\n' '#!/bin/sh' 'exit 2' > "$fake_firewall_command"
        trusted_command() {
            case "$1" in
                firewall-cmd|ufw|nft|iptables) printf '%s\n' "$fake_firewall_command" ;;
                *) return 1 ;;
            esac
        }
        status=0
        scanner_u28_firewalld_probe || status=$?
        assert_equal 2 "$status" "U-28 active firewalld collection failure"
        status=0
        scanner_u28_ufw_probe || status=$?
        assert_equal 2 "$status" "U-28 active UFW collection failure"
        status=0
        scanner_u28_nftables_probe || status=$?
        assert_equal 2 "$status" "U-28 nftables collection failure"
        status=0
        scanner_u28_xtables_probe iptables ipv4 || status=$?
        assert_equal 2 "$status" "U-28 iptables collection failure"
    )
)

test_kisa_time_provider_goldens() (
    local root="$TEST_TEMP/kisa-time-golden-root"
    local scratch="$TEST_TEMP/kisa-time-golden-scratch"
    local time_fixture_provider="chrony"
    local time_fixture_runtime_status=0
    local time_fixture_config_status=0
    local time_fixture_persistence_status=0

    mkdir -p -- "$root/etc/chrony" "$root/etc/ntpsec" "$scratch"
    SCAN_ROOT="$root"
    RUNTIME_MODE="on"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_system.sh
    . "$PROJECT_DIR/lib/checks_system.sh"
    SCRATCH_DIR="$scratch"

    runtime_enabled() { return 0; }
    service_state() {
        case "$time_fixture_provider:$1" in
            chrony:chronyd.service) return 0 ;;
            ntpsec:ntpsec.service) return 0 ;;
            systemd-timesyncd:systemd-timesyncd.service) return 0 ;;
            *) return 3 ;;
        esac
    }
    chrony_runtime_evidence() {
        printf '%s\n' 'provider=chrony' 'leap_status=Normal' 'selected_sources=1'
        return "$time_fixture_runtime_status"
    }
    ntpsec_runtime_evidence() {
        printf '%s\n' 'provider=ntpsec' 'selected_sources=1'
        return "$time_fixture_runtime_status"
    }
    timesyncd_runtime_evidence() {
        printf '%s\n' 'provider=systemd-timesyncd' 'synchronized=yes'
        return "$time_fixture_runtime_status"
    }
    chrony_config_evidence() {
        printf '%s\n' 'persistent_config=/etc/chrony.conf' 'configured_sources=1'
        return "$time_fixture_config_status"
    }
    ntpsec_config_evidence() {
        printf '%s\n' 'persistent_config=/etc/ntp.conf' 'configured_sources=1'
        return "$time_fixture_config_status"
    }
    time_service_persistence_state() { return "$time_fixture_persistence_status"; }

    set_test_platform rhel 8.10 "Red Hat Enterprise Linux 8.10"
    time_fixture_provider="chrony"
    check_u_65
    assert_equal MANUAL "$RESULT_STATUS" "U-65 RHEL 8 Chrony requires approved source evidence"
    assert_contains "$RESULT_EVIDENCE" "expected_provider=chrony" "U-65 RHEL expected provider evidence"
    assert_contains "$RESULT_EVIDENCE" "active_provider=chrony" "U-65 active Chrony evidence"
    assert_contains "$RESULT_EVIDENCE" "provider_scope=validated" "U-65 validated provider scope"
    assert_contains "$RESULT_EVIDENCE" "approved_source_evidence=unavailable" "U-65 RHEL source approval evidence"

    time_fixture_provider="ntpsec"
    check_u_65
    assert_equal MANUAL "$RESULT_STATUS" "U-65 RHEL NTPsec operational extension"
    assert_contains "$RESULT_EVIDENCE" "provider_scope=operational-extension" "U-65 NTPsec extension evidence"

    time_fixture_provider="systemd-timesyncd"
    check_u_65
    assert_equal MANUAL "$RESULT_STATUS" "U-65 RHEL timesyncd operational extension"
    assert_contains "$RESULT_EVIDENCE" "active_provider=systemd-timesyncd" "U-65 timesyncd provider evidence"

    time_fixture_provider="chrony"
    time_fixture_runtime_status=1
    check_u_65
    assert_equal VULNERABLE "$RESULT_STATUS" "U-65 unsynchronized RHEL Chrony"
    time_fixture_runtime_status=2
    check_u_65
    assert_equal ERROR "$RESULT_STATUS" "U-65 Chrony probe failure"

    time_fixture_runtime_status=0
    set_test_platform debian 13 "Debian GNU/Linux 13"
    time_fixture_provider="ntpsec"
    check_u_65
    assert_equal MANUAL "$RESULT_STATUS" "U-65 Debian NTP requires approved source evidence"
    assert_contains "$RESULT_EVIDENCE" "expected_provider=ntpd" "U-65 Debian expected provider evidence"
    assert_contains "$RESULT_EVIDENCE" "provider_scope=validated-extension" "U-65 Debian NTPsec validation scope"
    assert_contains "$RESULT_EVIDENCE" "approved_source_evidence=unavailable" "U-65 Debian source approval evidence"

    time_fixture_provider="systemd-timesyncd"
    check_u_65
    assert_equal MANUAL "$RESULT_STATUS" "U-65 Debian timesyncd operational extension"
    assert_contains "$RESULT_EVIDENCE" "provider_scope=operational-extension" "U-65 Debian timesyncd extension scope"
)

test_timesyncd_runtime_goldens() (
    local root="$TEST_TEMP/timesyncd-runtime-root"
    local scratch="$TEST_TEMP/timesyncd-runtime-scratch"
    local timedatectl_fixture="$scratch/timedatectl"
    local properties="$scratch/timesync-properties"
    local output=""
    local status=0

    mkdir -p -- "$root/etc/systemd" "$scratch"
    SCAN_ROOT="$root"
    RUNTIME_MODE="on"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_system.sh
    . "$PROJECT_DIR/lib/checks_system.sh"
    SCRATCH_DIR="$scratch"
    set_test_platform debian 13 "Debian GNU/Linux 13"

    {
        printf '%s\n' '#!/bin/sh'
        printf '%s\n' 'case "$1" in'
        printf '%s\n' '  show) printf "yes\\n" ;;'
        printf '  show-timesync) exec /bin/cat %s ;;\n' "$properties"
        printf '%s\n' '  *) exit 1 ;;'
        printf '%s\n' 'esac'
    } > "$timedatectl_fixture"
    chmod 0755 -- "$timedatectl_fixture"
    runtime_enabled() { return 0; }
    trusted_command() { [ "$1" = timedatectl ] && printf '%s\n' "$timedatectl_fixture"; }

    {
        printf '%s\n' 'ServerName=ntp.example'
        printf '%s\n' 'ServerAddress=192.0.2.10'
        printf '%s\n' 'SystemNTPServers=ntp.example'
        printf '%s\n' 'RuntimeNTPServers='
        printf '%s\n' 'FallbackNTPServers='
        printf '%s\n' 'NTPMessage={ Leap=0, Version=4, Mode=4, Stratum=2, PacketCount=4 }'
    } > "$properties"
    output="$(timesyncd_runtime_evidence)" || fail "timesyncd system source was rejected"
    assert_contains "$output" "selected_source_origin=system" "timesyncd system source origin"
    assert_contains "$output" "packet_count=4" "timesyncd packet count"
    assert_contains "$output" "leap_indicator=0" "timesyncd leap indicator"

    sed -i 's/SystemNTPServers=ntp.example/SystemNTPServers=/' "$properties"
    sed -i 's/RuntimeNTPServers=/RuntimeNTPServers=ntp.example/' "$properties"
    output="$(timesyncd_runtime_evidence)" || fail "timesyncd runtime source evidence failed"
    assert_contains "$output" "selected_source_origin=runtime" "timesyncd dynamic source origin"

    sed -i 's/PacketCount=4/PacketCount=0/' "$properties"
    status=0
    timesyncd_runtime_evidence >/dev/null 2>&1 || status=$?
    assert_equal 1 "$status" "timesyncd zero-packet source"
    sed -i 's/PacketCount=0/PacketCount=4/' "$properties"
    sed -i 's/Leap=0/Leap=1/' "$properties"
    status=0
    timesyncd_runtime_evidence >/dev/null 2>&1 || status=$?
    assert_equal 1 "$status" "timesyncd unsynchronized leap state"
)

test_u30_effective_umask_platform_goldens() (
    local root="$TEST_TEMP/u30-effective-root"
    local scratch="$TEST_TEMP/u30-effective-scratch"
    local u30_ftp_providers=""
    local u30_ftp_uncertain=0
    local platform_version=""

    mkdir -p -- "$root" "$scratch"
    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_account_file.sh
    . "$PROJECT_DIR/lib/checks_account_file.sh"
    # shellcheck source=../lib/checks_service.sh
    . "$PROJECT_DIR/lib/checks_service.sh"
    SCRATCH_DIR="$scratch"

    service_detect_ftp() {
        SERVICE_FTP_PROVIDERS="$u30_ftp_providers"
        SERVICE_FTP_UNCERTAIN="$u30_ftp_uncertain"
    }
    reset_u30_fixture() {
        rm -rf -- "$root"
        mkdir -p -- \
            "$root/etc/default" "$root/etc/pam.d" "$root/etc/profile.d" \
            "$root/etc/proftpd" "$root/etc/vsftpd" "$root/home/operator"
        printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' > "$root/etc/passwd"
        printf '%s\n' 'root:x:0:' > "$root/etc/group"
        printf '%s\n' 'umask 027' > "$root/etc/profile"
        printf '%s\n' 'UMASK 027' > "$root/etc/login.defs"
        u30_ftp_providers=""
        u30_ftp_uncertain=0
    }

    reset_u30_fixture
    set_test_platform debian 12 "Debian GNU/Linux 12"
    check_u_30
    assert_equal GOOD "$RESULT_STATUS" "U-30 Debian 12 login.defs without pam_umask"

    printf '%s\n' 'umask 002' 'umask 027' > "$root/etc/profile"
    check_u_30
    assert_equal GOOD "$RESULT_STATUS" "U-30 shell last safe value"
    printf '%s\n' 'umask 027' 'umask 002' > "$root/etc/profile"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 shell last weak value"

    reset_u30_fixture
    set_test_platform debian 12 "Debian GNU/Linux 12"
    printf '%s\n' 'umask 027' > "$root/etc/profile"
    printf '%s\n' 'umask 002' > "$root/etc/bash.bashrc"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 distinct weak Bash invocation path"
    rm -f -- "$root/etc/bash.bashrc"
    printf '%s\n' 'PATH=/usr/bin' > "$root/etc/profile"
    printf '%s\n' 'umask 002' > "$root/etc/profile.d/10-mask.sh"
    check_u_30
    assert_equal GOOD "$RESULT_STATUS" "U-30 unreferenced profile drop-in ignored"
    printf '%s\n' '. /etc/profile.d/10-mask.sh' > "$root/etc/profile"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 sourced profile drop-in"
    printf '%s\n' '. /etc/profile.d/10-mask.sh' 'umask 027' > "$root/etc/profile"
    check_u_30
    assert_equal GOOD "$RESULT_STATUS" "U-30 source graph preserves later override"
    printf '%s\n' 'helper() { :; }' 'umask 002 >/dev/null' > "$root/etc/profile"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 shell function closure and redirection"
    printf '%s\n' 'function helper {' '  umask 002' '}' 'umask 027' > "$root/etc/profile"
    check_u_30
    assert_equal GOOD "$RESULT_STATUS" "U-30 inactive function body ignored"

    reset_u30_fixture
    set_test_platform debian 12 "Debian GNU/Linux 12"
    printf '%s\n' \
        'root:x:0:0:root:/root:/bin/bash' \
        'operator:x:1000:1000:Operator:/home/operator:/bin/ksh93' > "$root/etc/passwd"
    printf '%s\n' 'operator:x:1000:' >> "$root/etc/group"
    printf '%s\n' 'umask 002' > "$root/home/operator/.kshrc"
    check_u_30
    assert_equal GOOD "$RESULT_STATUS" "U-30 inactive conventional kshrc ignored"
    printf '%s\n' 'ENV="$HOME/.kshrc"' > "$root/home/operator/.profile"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 ENV-selected kshrc"

    reset_u30_fixture
    set_test_platform debian 12 "Debian GNU/Linux 12"
    printf '%s\n' 'session optional pam_umask.so umask=002' > "$root/etc/pam.d/common-session"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 Debian 12 configured common-session pam_umask"

    reset_u30_fixture
    set_test_platform debian 13 "Debian GNU/Linux 13"
    printf '%s\n' 'session optional pam_umask.so umask=027 nousergroups' > "$root/etc/pam.d/common-session"
    printf '%s\n' 'session optional pam_umask.so umask=027 nousergroups' > "$root/etc/pam.d/common-session-noninteractive"
    check_u_30
    assert_equal GOOD "$RESULT_STATUS" "U-30 Debian 13 safe interactive and noninteractive PAM"
    printf '%s\n' 'session required pam_permit.so' > "$root/etc/pam.d/common-session-noninteractive"
    check_u_30
    assert_equal MANUAL "$RESULT_STATUS" "U-30 existing PAM stack without pam_umask"
    printf '%s\n' 'session optional pam_umask.so umask=002 nousergroups' > "$root/etc/pam.d/common-session-noninteractive"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 Debian 13 weak noninteractive PAM"

    for platform_version in 22.04 24.04 26.04; do
        reset_u30_fixture
        set_test_platform ubuntu "$platform_version" "Ubuntu $platform_version LTS"
        printf '%s\n' 'session optional pam_umask.so umask=027 nousergroups' > "$root/etc/pam.d/common-session"
        printf '%s\n' 'session optional pam_umask.so umask=002 nousergroups' > "$root/etc/pam.d/common-session-noninteractive"
        check_u_30
        assert_equal VULNERABLE "$RESULT_STATUS" "U-30 Ubuntu $platform_version PAM stack coverage"
    done

    for platform_version in 8.10 9.8 10.2; do
        reset_u30_fixture
        set_test_platform rhel "$platform_version" "Red Hat Enterprise Linux $platform_version"
        printf '%s\n' 'session optional pam_umask.so umask=002' > "$root/etc/pam.d/postlogin"
        check_u_30
        assert_equal VULNERABLE "$RESULT_STATUS" "U-30 RHEL $platform_version postlogin PAM"
    done

    reset_u30_fixture
    set_test_platform debian 12 "Debian GNU/Linux 12"
    printf '%s\n' 'operator:x:1000:1000:Operator,,,,umask=027:/home/operator:/bin/bash' > "$root/etc/passwd"
    printf '%s\n' 'operator:x:1000:' > "$root/etc/group"
    printf '%s\n' 'session optional pam_umask.so umask=002' > "$root/etc/pam.d/common-session"
    check_u_30
    assert_equal GOOD "$RESULT_STATUS" "U-30 GECOS safe override"
    printf '%s\n' 'operator:x:1000:1000:Operator,,,,umask=002:/home/operator:/bin/bash' > "$root/etc/passwd"
    printf '%s\n' 'session optional pam_umask.so umask=027' > "$root/etc/pam.d/common-session"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 GECOS weak override"

    printf '%s\n' 'operator:x:1000:1000:Operator:/home/operator:/bin/bash' > "$root/etc/passwd"
    printf '%s\n' 'session optional pam_umask.so umask=022 usergroups' > "$root/etc/pam.d/common-session"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 explicit PAM usergroups transformation"
    printf '%s\n' 'session optional pam_umask.so umask=022 nousergroups' > "$root/etc/pam.d/common-session"
    check_u_30
    assert_equal GOOD "$RESULT_STATUS" "U-30 explicit PAM nousergroups"

    set_test_platform ubuntu 22.04 "Ubuntu 22.04 LTS"
    printf '%s\n' 'session optional pam_umask.so umask=022' > "$root/etc/pam.d/common-session"
    check_u_30
    assert_equal GOOD "$RESULT_STATUS" "U-30 Ubuntu 22.04 usergroups build default"
    set_test_platform ubuntu 24.04 "Ubuntu 24.04 LTS"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 Ubuntu 24.04 usergroups build default"
    set_test_platform ubuntu 26.04 "Ubuntu 26.04 LTS"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 Ubuntu 26.04 usergroups build default"

    reset_u30_fixture
    set_test_platform ubuntu 24.04 "Ubuntu 24.04 LTS"
    printf '%s\n' 'operator:x:1000:1000:Operator:/home/operator:/bin/bash' > "$root/etc/passwd"
    printf '%s\n' 'operator:x:1000:' > "$root/etc/group"
    printf '%s\n' 'session optional pam_umask.so' > "$root/etc/pam.d/common-session"
    printf '%s\n' 'UMASK 022' 'USERGROUPS_ENAB no' > "$root/etc/login.defs"
    check_u_30
    assert_equal GOOD "$RESULT_STATUS" "U-30 Ubuntu USERGROUPS_ENAB disabled"
    printf '%s\n' 'UMASK 022' 'USERGROUPS_ENAB yes' > "$root/etc/login.defs"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 Ubuntu USERGROUPS_ENAB enabled"

    reset_u30_fixture
    set_test_platform debian 12 "Debian GNU/Linux 12"
    rm -f -- "$root/etc/login.defs"
    printf '%s\n' 'UMASK=002' > "$root/etc/default/login"
    printf '%s\n' 'session optional pam_umask.so' > "$root/etc/pam.d/common-session"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 default login fallback"
    printf '%s\n' 'UMASK 027' > "$root/etc/login.defs"
    check_u_30
    assert_equal GOOD "$RESULT_STATUS" "U-30 login.defs precedes default login"

    reset_u30_fixture
    set_test_platform debian 12 "Debian GNU/Linux 12"
    printf '%s\n' \
        'root:x:0:0:root:/root:/bin/bash' \
        'operator:x:1000:1000:Operator:/home/operator:/bin/sh' > "$root/etc/passwd"
    printf '%s\n' 'operator:x:1000:' >> "$root/etc/group"
    printf '%s\n' 'umask 002' > "$root/home/operator/.profile"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 weak user profile override"

    reset_u30_fixture
    set_test_platform debian 12 "Debian GNU/Linux 12"
    printf '%s\n' 'root:x:0:0:root:/root:/sbin/nologin' > "$root/etc/passwd"
    printf '%s' 'operator:x:1000:1000:Operator:/home/operator:/bin/sh' >> "$root/etc/passwd"
    printf '%s\n' 'operator:x:1000:' >> "$root/etc/group"
    printf '%s\n' 'umask 002' > "$root/home/operator/.profile"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 final passwd record without newline"

    reset_u30_fixture
    set_test_platform debian 13 "Debian GNU/Linux 13"
    mkdir -p -- "$root/etc/zsh"
    printf '%s\n' \
        'root:x:0:0:root:/root:/bin/bash' \
        'operator:x:1000:1000:Operator:/home/operator:/usr/bin/zsh' > "$root/etc/passwd"
    printf '%s\n' 'operator:x:1000:' >> "$root/etc/group"
    printf '%s\n' 'umask 002' > "$root/etc/zsh/zshenv"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 Debian zsh global startup"

    reset_u30_fixture
    set_test_platform debian 13 "Debian GNU/Linux 13"
    printf '%s\n' \
        'root:x:0:0:root:/root:/bin/bash' \
        'operator:x:1000:1000:Operator:/home/operator:/usr/bin/tcsh' > "$root/etc/passwd"
    printf '%s\n' 'operator:x:1000:' >> "$root/etc/group"
    printf '%s\n' 'umask 002' > "$root/etc/csh.cshrc"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 tcsh global startup"

    reset_u30_fixture
    set_test_platform debian 13 "Debian GNU/Linux 13"
    mkdir -p -- "$root/etc/fish" "$root/home/operator/.config/fish/conf.d"
    printf '%s\n' \
        'root:x:0:0:root:/root:/bin/bash' \
        'operator:x:1000:1000:Operator:/home/operator:/usr/bin/fish' > "$root/etc/passwd"
    printf '%s\n' 'operator:x:1000:' >> "$root/etc/group"
    printf '%s\n' 'umask 002' > "$root/etc/fish/config.fish"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 fish global startup"
    printf '%s\n' 'umask 027' > "$root/etc/fish/config.fish"
    printf '%s\n' 'umask 002' > "$root/home/operator/.config/fish/conf.d/10-mask.fish"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 fish user conf.d startup"

    reset_u30_fixture
    set_test_platform debian 12 "Debian GNU/Linux 12"
    printf '%s\n' \
        'root:x:0:0:root:/root:/bin/bash' \
        'operator:x:1000:1000:Operator:/home/operator:/bin/sh' > "$root/etc/passwd"
    printf '%s\n' 'operator:x:1000:' >> "$root/etc/group"
    printf '%s\n' 'umask 002' > "$root/home/operator/.profile"
    printf '%s\n' 'local_umask=002' > "$root/etc/vsftpd.conf"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 inactive FTP config ignored with existing weak user profile"
    rm -f -- "$root/home/operator/.profile"
    check_u_30
    assert_equal GOOD "$RESULT_STATUS" "U-30 inactive weak FTP config ignored"
    u30_ftp_providers=vsftpd
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 active Debian vsftpd mask"
    printf '%s\n' 'local_umask=18' > "$root/etc/vsftpd.conf"
    check_u_30
    assert_equal GOOD "$RESULT_STATUS" "U-30 vsftpd decimal mask"
    rm -f -- "$root/etc/vsftpd.conf"
    check_u_30
    assert_equal GOOD "$RESULT_STATUS" "U-30 vsftpd built-in mask"

    u30_ftp_providers=proftpd
    printf '%s\n' 'Umask 002' > "$root/etc/proftpd/proftpd.conf"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 active Debian ProFTPD mask"
    printf '%s\n' 'Umask 022 002' > "$root/etc/proftpd/proftpd.conf"
    check_u_30
    assert_equal VULNERABLE "$RESULT_STATUS" "U-30 ProFTPD directory mask"
    printf '%s\n' 'Umask 027' 'Include /etc/proftpd/conf.d/*.conf' > "$root/etc/proftpd/proftpd.conf"
    check_u_30
    assert_equal MANUAL "$RESULT_STATUS" "U-30 ProFTPD unresolved include"

    reset_u30_fixture
    set_test_platform rhel 10.2 "Red Hat Enterprise Linux 10.2"
    u30_ftp_providers="vsftpd proftpd"
    printf '%s\n' 'local_umask=027' > "$root/etc/vsftpd/vsftpd.conf"
    printf '%s\n' 'Umask 027' > "$root/etc/proftpd.conf"
    check_u_30
    assert_equal GOOD "$RESULT_STATUS" "U-30 RHEL native FTP paths"
    u30_ftp_uncertain=1
    check_u_30
    assert_equal MANUAL "$RESULT_STATUS" "U-30 offline active FTP custom path uncertainty"
    (
        u30_ftp_providers=""
        u30_ftp_uncertain=1
        runtime_enabled() { return 0; }
        check_u_30
        assert_equal MANUAL "$RESULT_STATUS" "U-30 live unidentified FTP activation uncertainty"
    )

    reset_u30_fixture
    set_test_platform rhel 9.8 "Red Hat Enterprise Linux 9.8"
    mkdir -p -- "$root/usr/share/login.defs.d" "$root/etc/login.defs.d" "$root/run/login.defs.d"
    printf '%s\n' 'UMASK 000' > "$root/usr/share/login.defs.d/99-vendor.defs"
    printf '%s\n' 'UMASK 027' > "$root/etc/login.defs.d/10-local.defs"
    printf '%s\n' 'UMASK 000' > "$root/run/login.defs"
    printf '%s\n' 'UMASK 000' > "$root/run/login.defs.d/zz-run.defs"
    printf '%s\n' 'session optional pam_umask.so' > "$root/etc/pam.d/postlogin"
    check_u_30
    assert_equal GOOD "$RESULT_STATUS" "U-30 RHEL 9 econf system layer and ignored run layer"

    reset_u30_fixture
    set_test_platform rhel 9.8 "Red Hat Enterprise Linux 9.8"
    rm -f -- "$root/etc/login.defs"
    mkdir -p -- "$root/usr/share/login.defs.d" "$root/etc/login.defs.d"
    printf '%s\n' 'UMASK 027' > "$root/usr/share/login.defs"
    printf '%s\n' 'UMASK 002' > "$root/usr/share/login.defs.d/50-policy.defs"
    printf '%s\n' 'PASS_MAX_DAYS 90' > "$root/etc/login.defs.d/50-policy.defs"
    printf '%s\n' 'session optional pam_umask.so nousergroups' > "$root/etc/pam.d/postlogin"
    check_u_30
    assert_equal GOOD "$RESULT_STATUS" "U-30 RHEL 9 same-basename econf mask"

    reset_u30_fixture
    set_test_platform rhel 10.2 "Red Hat Enterprise Linux 10.2"
    mkdir -p -- "$root/usr/share/login.defs.d" "$root/run/login.defs.d" "$root/etc/login.defs.d"
    printf '%s\n' 'UMASK 000' > "$root/usr/share/login.defs"
    printf '%s\n' 'UMASK 000' > "$root/run/login.defs"
    printf '%s\n' 'UMASK 027' > "$root/etc/login.defs.d/90-local.defs"
    printf '%s\n' 'session optional pam_umask.so' > "$root/etc/pam.d/postlogin"
    check_u_30
    assert_equal GOOD "$RESULT_STATUS" "U-30 RHEL 10 etc-only econf layer"
)

test_account_u04_u19_false_conclusive_paths() (
    local root="$TEST_TEMP/account-u04-u19-root"
    local scratch="$TEST_TEMP/account-u04-u19-scratch"
    local metadata_root="$TEST_TEMP/account-metadata-root"
    local startup_root="$TEST_TEMP/account-startup-root"
    local sha512_hash='$6$salt$ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./ABCDEFGHIJKLMNOPQRSTUV'
    local md5_hash='$1$12345678$abcdefghijklmnopqrstuv'
    local helper_status=0

    mkdir -p -- \
        "$root/etc/pam.d" "$root/etc/profile.d" "$root/etc/security" "$root/usr/bin" \
        "$root/customroot" "$root/lib/security" "$scratch"
    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_account_file.sh
    . "$PROJECT_DIR/lib/checks_account_file.sh"
    SCRATCH_DIR="$scratch"
    set_test_platform debian 13 "Debian GNU/Linux 13"

    printf '%s\n' 'UID_MIN 1000' 'ENCRYPT_METHOD SHA512' > "$root/etc/login.defs"
    printf '%s\n' 'password required pam_unix.so use_authtok sha512' > "$root/etc/pam.d/common-password"
    printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' "legacy:$sha512_hash:1000:1000::/home/legacy:/bin/bash" > "$root/etc/passwd"
    printf '%s\n' "root:$sha512_hash:20000:0:99999:7:::" > "$root/etc/shadow"

    check_u_04
    assert_equal GOOD "$RESULT_STATUS" "U-04 mixed shadow and encrypted passwd storage"
    printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' 'legacy:$9$salt$unknown:1000:1000::/home/legacy:/bin/bash' > "$root/etc/passwd"
    check_u_04
    assert_equal MANUAL "$RESULT_STATUS" "U-04 unknown modular passwd storage"
    printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' 'missing:x:1000:1000::/home/missing:/bin/bash' > "$root/etc/passwd"
    check_u_04
    assert_equal MANUAL "$RESULT_STATUS" "U-04 missing per-account shadow record"

    printf '%s\n' 'root:x:1:0:root:/root:/bin/bash' 'alias:x:1:1000::/home/alias:/bin/bash' > "$root/etc/passwd"
    check_u_05
    assert_equal VULNERABLE "$RESULT_STATUS" "U-05 noncanonical duplicated root UID"
    printf '%s\n' 'operator:x:1000:1000::/home/operator:/bin/bash' > "$root/etc/passwd"
    check_u_05
    assert_equal ERROR "$RESULT_STATUS" "U-05 missing root record"

    printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' 'operator:x:1000:1000::/home/operator:/bin/bash' > "$root/etc/passwd"
    printf '%s\n' 'root:x:0:' 'sudo:x:27:operator' > "$root/etc/group"
    : > "$root/usr/bin/su"
    : > "$root/lib/security/pam_wheel.so"
    chmod 0755 -- "$root/usr/bin/su"
    stat_uid() {
        case "$1" in
            "$root/usr/bin/su") printf '0\n' ;;
            *) /usr/bin/stat -Lc '%u' -- "$1" 2>/dev/null ;;
        esac
    }
    printf '%s\n' 'auth optional pam_wheel.so' 'auth sufficient pam_permit.so' 'auth required pam_wheel.so group=sudo' > "$root/etc/pam.d/su"
    check_u_06
    assert_equal MANUAL "$RESULT_STATUS" "U-06 early sufficient PAM bypass"
    assert_contains "$RESULT_EVIDENCE" "pam_early_bypass=1" "U-06 early bypass evidence"
    printf '%s\n' 'auth required pam_wheel.so group=sudo root_only' > "$root/etc/pam.d/su"
    check_u_06
    assert_equal MANUAL "$RESULT_STATUS" "U-06 root-only PAM scope"
    assert_contains "$RESULT_EVIDENCE" "pam_root_only=1" "U-06 root-only evidence"
    rm -f -- "$root/usr/bin/su"
    check_u_06
    assert_equal NOT_APPLICABLE "$RESULT_STATUS" "U-06 missing executable applicability"

    check_u_07
    assert_equal MANUAL "$RESULT_STATUS" "U-07 organizational account review"
    assert_contains "$RESULT_EVIDENCE" "recent_login_records=offline" "U-07 offline login evidence"

    printf '%s\n' 'root:x:0' > "$root/etc/group"
    check_u_08
    assert_equal ERROR "$RESULT_STATUS" "U-08 malformed group database"
    printf '%s\n' 'developers:x:2000:alice,bob' 'developers:x:2000:carol,dave' > "$root/etc/group"
    helper_status=0
    scanner_validate_group_database "$root/etc/group" || helper_status=$?
    assert_equal 0 "$helper_status" "valid split group database"
    printf '%s\n' 'developers:x:2000:alice,bob' 'developers:x:2001:carol,dave' > "$root/etc/group"
    helper_status=0
    scanner_validate_group_database "$root/etc/group" || helper_status=$?
    assert_equal 1 "$helper_status" "conflicting split group GID"
    printf '%s\n' 'root:x:0:' 'operator:x:1000:' > "$root/etc/group"
    printf '%s\n' 'root:!::' 'operator:!::operator' > "$root/etc/gshadow"
    check_u_09
    assert_equal MANUAL "$RESULT_STATUS" "U-09 gshadow and ownership review"
    assert_contains "$RESULT_EVIDENCE" "gshadow=present" "U-09 gshadow evidence"
    assert_contains "$RESULT_EVIDENCE" "filesystem_group_ownership=manual-review" "U-09 file ownership evidence"

    printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' 'first:x:1:1000::/home/first:/bin/bash' 'second:x:0001:1000::/home/second:/bin/bash' > "$root/etc/passwd"
    check_u_10
    assert_equal VULNERABLE "$RESULT_STATUS" "U-10 numerically duplicate UID"
    printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' 'daemon:x:1:1::/usr/sbin:/tmp/nologin' > "$root/etc/passwd"
    check_u_11
    assert_equal VULNERABLE "$RESULT_STATUS" "U-11 arbitrary nologin basename"

    printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' 'operator:x:1000:1000::/home/operator:/bin/bash' > "$root/etc/passwd"
    printf '%s\n' 'TMOUT=600' 'export TMOUT' > "$root/etc/profile"
    printf '%s\n' 'TMOUT=900' > "$root/etc/bashrc"
    check_u_12
    assert_equal MANUAL "$RESULT_STATUS" "U-12 literal policy remains conservative"
    assert_contains "$RESULT_EVIDENCE" "literal_noncompliant=0" "U-12 ignores RHEL-only bashrc on Debian"
    printf '%s\n' 'echo TMOUT=600' > "$root/etc/profile"
    check_u_12
    assert_equal MANUAL "$RESULT_STATUS" "U-12 command text is not an assignment"
    printf '%s\n' 'root:x:0:0:root:/root:/bin/tcsh' > "$root/etc/passwd"
    rm -f -- "$root/etc/profile"
    printf '%s\n' 'set autologout=10' > "$root/etc/csh.cshrc"
    check_u_12
    assert_equal MANUAL "$RESULT_STATUS" "U-12 csh-only compliant policy"
    assert_contains "$RESULT_EVIDENCE" "csh_accounts=1" "U-12 csh account evidence"

    printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' "legacy:$md5_hash:1000:1000::/home/legacy:/bin/bash" > "$root/etc/passwd"
    printf '%s\n' "root:$sha512_hash:20000:0:99999:7:::" > "$root/etc/shadow"
    check_u_13
    assert_equal VULNERABLE "$RESULT_STATUS" "U-13 mixed weak passwd hash"
    assert_contains "$RESULT_EVIDENCE" "credential_source_counts=shadow=1,direct=1,missing=0" "U-13 mixed storage evidence"

    set_test_platform rhel 10.2 "Red Hat Enterprise Linux 10.2"
    printf '%s\n' 'password required pam_unix.so use_authtok sha512' > "$root/etc/pam.d/system-auth"
    printf '%s\n' 'password required pam_unix.so use_authtok md5' > "$root/etc/pam.d/password-auth"
    printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' > "$root/etc/passwd"
    check_u_13
    assert_equal VULNERABLE "$RESULT_STATUS" "U-13 weak EL password-auth stack"

    set_test_platform debian 13 "Debian GNU/Linux 13"
    printf '%s\n' 'root:x:0:0:root:/customroot:/bin/bash' > "$root/etc/passwd"
    rm -f -- "$root/etc/shadow" "$root/etc/profile" "$root/etc/bash.bashrc"
    printf '%s\n' 'PATH=.:/usr/bin' > "$root/etc/bashrc"
    check_u_14
    assert_equal MANUAL "$RESULT_STATUS" "U-14 inactive cross-family bashrc"
    assert_contains "$RESULT_EVIDENCE" "candidate_unsafe_assignments=0" "U-14 ignores inactive RHEL bashrc"
    printf '%s\n' 'PATH=.:/usr/bin' > "$root/customroot/.bash_login"
    check_u_14
    assert_equal MANUAL "$RESULT_STATUS" "U-14 custom root home startup file"
    assert_contains "$RESULT_EVIDENCE" "candidate_unsafe_assignments=1" "U-14 custom root path evidence"
    assert_contains "$RESULT_EVIDENCE" "root_home=/customroot" "U-14 root home evidence"

    printf '%s\n' 'placeholder:x:4294967295:4294967295::/nonexistent:/bin/false' > "$root/etc/passwd"
    printf '%s\n' 'placeholder:x:4294967295:' > "$root/etc/group"
    printf '%s\n' 'passwd: files sss' 'group: files sss' > "$root/etc/nsswitch.conf"
    : > "$root/orphan"
    check_u_15
    assert_equal MANUAL "$RESULT_STATUS" "U-15 external NSS orphan uncertainty"
    printf '%s\n' 'passwd: files' 'group: files' > "$root/etc/nsswitch.conf"
    scanner_reset_full_filesystem_cache
    check_u_15
    assert_equal VULNERABLE "$RESULT_STATUS" "U-15 files-only orphan"
    SCAN_ROOT="/"
    trusted_command() { return 1; }
    helper_status=0
    scanner_local_filesystem_roots >/dev/null 2>&1 || helper_status=$?
    assert_equal 2 "$helper_status" "U-15 incomplete live mount inventory"

    mkdir -p -- "$metadata_root/etc/passwd" "$metadata_root/etc/shadow" "$metadata_root/etc/hosts"
    SCAN_ROOT="$metadata_root"
    check_u_16
    assert_equal ERROR "$RESULT_STATUS" "U-16 non-regular passwd path"
    check_u_18
    assert_equal ERROR "$RESULT_STATUS" "U-18 non-regular shadow path"
    check_u_19
    assert_equal ERROR "$RESULT_STATUS" "U-19 non-regular hosts path"

    mkdir -p -- "$startup_root/usr/lib/systemd/system" "$startup_root/etc/systemd/system"
    : > "$startup_root/usr/lib/systemd/system/vendor-only.service"
    SCAN_ROOT="$startup_root"
    set_test_platform rhel 10.2 "Red Hat Enterprise Linux 10.2"
    stat_uid() { printf '0\n'; }
    stat_mode() { printf '644\n'; }
    check_u_17
    assert_equal GOOD "$RESULT_STATUS" "U-17 vendor-only systemd path"
    ln -s -- /outside.service "$startup_root/etc/systemd/system/escape.service"
    check_u_17
    assert_equal ERROR "$RESULT_STATUS" "U-17 offline absolute symlink confinement"
)

test_account_u20_u33_false_conclusive_paths() (
    local base="$TEST_TEMP/account-u20-u33"
    local current_uid=""
    local current_gid=""

    current_uid="$(id -u)"
    current_gid="$(id -g)"

    load_account_stack() {
        local scan_root="$1"
        local scratch="$2"

        mkdir -p -- "$scan_root" "$scratch"
        SCAN_ROOT="$scan_root"
        RUNTIME_MODE="off"
        # shellcheck source=../lib/core.sh
        . "$PROJECT_DIR/lib/core.sh"
        # shellcheck source=../lib/resolvers.sh
        . "$PROJECT_DIR/lib/resolvers.sh"
        # shellcheck source=../lib/checks_account_file.sh
        . "$PROJECT_DIR/lib/checks_account_file.sh"
        # shellcheck source=../lib/checks_service.sh
        . "$PROJECT_DIR/lib/checks_service.sh"
        SCRATCH_DIR="$scratch"
        set_test_platform debian 13 "Debian GNU/Linux 13"
    }

    (
        local root="$base/u20"
        local scratch="$base/u20-scratch"

        mkdir -p -- "$root/etc/systemd/system/multi-user.target.wants" "$root/usr/lib/systemd/system" "$scratch"
        load_account_stack "$root" "$scratch"
        printf '%s\n' '[Manager]' > "$root/etc/systemd/system.conf"
        chmod 0600 -- "$root/etc/systemd/system.conf"
        printf '%s\n' '[Service]' > "$root/usr/lib/systemd/system/vendor.service"
        chmod 0644 -- "$root/usr/lib/systemd/system/vendor.service"
        ln -s -- /usr/lib/systemd/system/vendor.service "$root/etc/systemd/system/multi-user.target.wants/vendor.service"
        stat_uid() { printf '0\n'; }
        check_u_20
        assert_equal GOOD "$RESULT_STATUS" "U-20 ignores enabled vendor-unit symlinks"

        rm -f -- "$root/etc/systemd/system.conf"
        ln -s -- /dev/null "$root/etc/systemd/system.conf"
        check_u_20
        assert_equal NOT_APPLICABLE "$RESULT_STATUS" "U-20 mask-only configuration"

        mkdir -p -- "$root/etc/rsyslog.d"
        ln -s -- /dev/null "$root/etc/rsyslog.conf"
        check_u_21
        assert_equal NOT_APPLICABLE "$RESULT_STATUS" "U-21 mask-only configuration"
    ) || exit 1

    (
        local root="$base/config-paths"
        local scratch="$base/config-paths-scratch"

        mkdir -p -- "$root/etc" "$scratch"
        load_account_stack "$root" "$scratch"
        ln -s -- /missing-systemd "$root/etc/systemd"
        check_u_20
        assert_equal ERROR "$RESULT_STATUS" "U-20 unsafe systemd directory"
        rm -f -- "$root/etc/systemd"
        mkdir -p -- "$root/etc"
        printf '%s\n' '$IncludeConfig /etc/rsyslog.d/*.conf' > "$root/etc/rsyslog.conf"
        ln -s -- /missing-rsyslog-directory "$root/etc/rsyslog.d"
        check_u_21
        assert_equal ERROR "$RESULT_STATUS" "U-21 unsafe rsyslog include directory"
    ) || exit 1

    (
        local root="$base/enumerator"
        local scratch="$base/enumerator-scratch"

        mkdir -p -- "$root/dev" "$scratch"
        load_account_stack "$root" "$scratch"
        scanner_local_filesystem_roots() { return 2; }
        check_u_23
        assert_equal ERROR "$RESULT_STATUS" "U-23 mount inventory failure"
        check_u_25
        assert_equal ERROR "$RESULT_STATUS" "U-25 mount inventory failure"
        check_u_33
        assert_equal ERROR "$RESULT_STATUS" "U-33 mount inventory failure"
    ) || exit 1

    (
        local root="$base/u24"
        local scratch="$base/u24-scratch"

        mkdir -p -- "$root/etc" "$root/home/operator/.config/fish/conf.d" "$scratch"
        load_account_stack "$root" "$scratch"
        : > "$root/etc/passwd"
        check_u_24
        assert_equal ERROR "$RESULT_STATUS" "U-24 empty passwd database"

        printf 'operator:x:%s:%s::relative-home:/bin/bash\n' "$current_uid" "$current_gid" > "$root/etc/passwd"
        check_u_24
        assert_equal ERROR "$RESULT_STATUS" "U-24 nonabsolute home path"

        printf 'operator:x:%s:%s::/home/operator:/bin/bash\n' "$current_uid" "$current_gid" > "$root/etc/passwd"
        printf '%s\n' 'export PATH=/usr/bin' > "$root/home/operator/.xsessionrc"
        chmod 0666 -- "$root/home/operator/.xsessionrc"
        check_u_24
        assert_equal VULNERABLE "$RESULT_STATUS" "U-24 Debian X session environment file"

        rm -f -- "$root/home/operator/.xsessionrc"
        ln -s -- /missing-fish-environment "$root/home/operator/.config/fish/conf.d/90-site.fish"
        check_u_24
        assert_equal ERROR "$RESULT_STATUS" "U-24 unsafe fish environment symlink"
    ) || exit 1

    (
        local root="$base/u26"
        local scratch="$base/u26-scratch"

        mkdir -p -- "$root/dev/shm" "$root/dev/mqueue" "$scratch"
        load_account_stack "$root" "$scratch"
        : > "$root/dev/shm/runtime-file"
        : > "$root/dev/mqueue/runtime-file"
        check_u_26
        assert_equal GOOD "$RESULT_STATUS" "U-26 guide exceptions in offline root"
    ) || exit 1

    (
        local root="$base/u27"
        local scratch="$base/u27-scratch"

        mkdir -p -- "$root/etc" "$root/home/operator" "$scratch"
        load_account_stack "$root" "$scratch"
        printf 'operator:x:%s:%s::/home/operator:/bin/bash\n' "$current_uid" "$current_gid" > "$root/etc/passwd"
        printf '%s\n' 'login stream tcp nowait root /usr/sbin/in.rlogind in.rlogind' > "$root/etc/inetd.conf"
        printf '%s\n' '+ +' > "$root/home/operator/.rhosts"
        chmod 0666 -- "$root/home/operator/.rhosts"
        check_u_27
        assert_equal VULNERABLE "$RESULT_STATUS" "U-27 inetd login alias and unsafe trust file"

        rm -f -- "$root/home/operator/.rhosts"
        mkdir -p -- "$root/home/operator/.rhosts"
        check_u_27
        assert_equal ERROR "$RESULT_STATUS" "U-27 non-regular trust path"

        rm -rf -- "$root/home/operator/.rhosts"
        : > "$root/etc/passwd"
        check_u_27
        assert_equal ERROR "$RESULT_STATUS" "U-27 empty passwd database"
    ) || exit 1

    (
        local root="$base/u27-listener"
        local scratch="$base/u27-listener-scratch"

        mkdir -p -- "$root/etc" "$scratch"
        load_account_stack "$root" "$scratch"
        runtime_enabled() { return 0; }
        service_activation_state() { return 1; }
        service_legacy_enabled() { SERVICE_LEGACY_UNCERTAIN=0; return 1; }
        trusted_command() { [ "$1" = ss ] && printf '/usr/bin/ss\n'; }
        capture_command() {
            assert_equal "ss -H -lntp" "$*" "U-27 listener command"
            printf '%s\n' 'LISTEN 0 128 0.0.0.0:512 0.0.0.0:* users:(("in.rshd",pid=1,fd=3))'
        }
        listener_output="$(port_listener_facts 512 tcp)"
        assert_contains "$listener_output" "0.0.0.0:512" "U-27 native TCP listener row"
        check_u_27
        assert_equal MANUAL "$RESULT_STATUS" "U-27 detects native TCP r-command listener row"

        capture_command() { return 0; }
        check_u_27
        assert_equal GOOD "$RESULT_STATUS" "U-27 no TCP r-command listener"

        capture_command() { return 2; }
        check_u_27
        assert_equal MANUAL "$RESULT_STATUS" "U-27 listener collection failure"
    ) || exit 1

    (
        local root="$base/u29"
        local scratch="$base/u29-scratch"

        mkdir -p -- "$root/etc" "$scratch"
        load_account_stack "$root" "$scratch"
        ln -s -- /missing-hosts-lpd "$root/etc/hosts.lpd"
        check_u_29
        assert_equal ERROR "$RESULT_STATUS" "U-29 dangling hosts.lpd link"
    ) || exit 1

    (
        local root="$base/u31-u32"
        local scratch="$base/u31-u32-scratch"

        mkdir -p -- "$root/etc" "$root/home/operator" "$scratch"
        load_account_stack "$root" "$scratch"
        printf 'operator:x:%s:%s::/home/operator:\n' "$current_uid" "$current_gid" > "$root/etc/passwd"
        chmod 0777 -- "$root/home/operator"
        check_u_31
        assert_equal VULNERABLE "$RESULT_STATUS" "U-31 empty shell defaults to login shell"

        rmdir -- "$root/home/operator"
        check_u_32
        assert_equal VULNERABLE "$RESULT_STATUS" "U-32 missing home for empty shell"

        printf 'service:x:%s:%s::/home/service:/usr/sbin/nologin\n' "$current_uid" "$current_gid" > "$root/etc/passwd"
        check_u_32
        assert_equal VULNERABLE "$RESULT_STATUS" "U-32 missing home for non-login account"

        : > "$root/etc/passwd"
        check_u_31
        assert_equal ERROR "$RESULT_STATUS" "U-31 empty passwd database"
        check_u_32
        assert_equal ERROR "$RESULT_STATUS" "U-32 empty passwd database"

        printf 'operator:x:%s:%s::relative-home:/bin/bash\n' "$current_uid" "$current_gid" > "$root/etc/passwd"
        check_u_31
        assert_equal ERROR "$RESULT_STATUS" "U-31 nonabsolute home path"

        printf 'operator:x:%s:%s::/escape-home:/bin/bash\n' "$current_uid" "$current_gid" > "$root/etc/passwd"
        ln -s -- /missing-home "$root/escape-home"
        check_u_32
        assert_equal ERROR "$RESULT_STATUS" "U-32 unsafe home path"
    ) || exit 1
)

test_shared_full_filesystem_collector() (
    local root="$TEST_TEMP/shared-full-filesystem-root"
    local scratch="$TEST_TEMP/shared-full-filesystem-scratch"
    local second_root="$TEST_TEMP/shared-full-filesystem-second-root"
    local second_scratch="$TEST_TEMP/shared-full-filesystem-second-scratch"
    local world_path=""
    local hidden_path=""
    local valid_link=""
    local second_valid_link=""
    local dangling_link=""
    local current_uid=""
    local current_gid=""
    local padded_uid=""
    local padded_gid=""
    local parser_file=""
    local parser_status=0
    local find_calls=0

    mkdir -p -- "$root/etc" "$root/data" "$scratch"
    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    SELECTED_CHECKS=""
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_account_file.sh
    . "$PROJECT_DIR/lib/checks_account_file.sh"
    SCRATCH_DIR="$scratch"
    set_test_platform debian 13 "Debian GNU/Linux 13"

    parser_file="$(new_scratch_file full-filesystem-parser-test)" || fail "collector parser scratch creation failed"
    : > "$parser_file"
    scanner_full_filesystem_parse_selected_stream "$parser_file" "$root" || fail "collector parser rejected an empty stream"
    printf 'X\0' > "$parser_file"
    parser_status=0
    scanner_full_filesystem_parse_selected_stream "$parser_file" "$root" || parser_status=$?
    assert_equal 2 "$parser_status" "collector parser rejects an unknown tag"
    printf 'S\0/path\0' > "$parser_file"
    parser_status=0
    scanner_full_filesystem_parse_selected_stream "$parser_file" "$root" || parser_status=$?
    assert_equal 2 "$parser_status" "collector parser rejects a missing mode"
    printf 'S\0/path\0invalid\0' > "$parser_file"
    parser_status=0
    scanner_full_filesystem_parse_selected_stream "$parser_file" "$root" || parser_status=$?
    assert_equal 2 "$parser_status" "collector parser rejects an invalid mode"
    printf 'H\0/complete\0partial' > "$parser_file"
    parser_status=0
    scanner_full_filesystem_parse_selected_stream "$parser_file" "$root" || parser_status=$?
    assert_equal 2 "$parser_status" "collector parser rejects trailing partial bytes"
    scanner_reset_full_filesystem_cache

    current_uid="$(id -u)"
    current_gid="$(id -g)"
    printf -v padded_uid '%010d' "$current_uid"
    printf -v padded_gid '%010d' "$current_gid"
    printf 'owner:x:%s:%s::/nonexistent:/bin/false' "$padded_uid" "$padded_gid" > "$root/etc/passwd"
    printf 'owner:x:%s:' "$padded_gid" > "$root/etc/group"
    printf '%s\n' 'passwd: files' 'group: files' > "$root/etc/nsswitch.conf"

    world_path="$root/data/-world"$'\n'"line"$'\t'"tab%"
    hidden_path="$root/data/.hidden"$'\n'"entry"$'\t'"%"
    valid_link="$root/data/.link"$'\n'"valid"
    : > "$world_path"
    : > "$hidden_path"
    chmod 0666 -- "$world_path"
    chmod 0644 -- "$hidden_path"
    ln -s -- "${world_path##*/}" "$valid_link"

    find() {
        find_calls=$((find_calls + 1))
        /usr/bin/find "$@"
    }

    check_u_15
    assert_equal MANUAL "$RESULT_STATUS" "shared collector offline owner correlation"
    assert_contains "$RESULT_EVIDENCE" "orphaned_paths=0" "shared collector leading-zero owner IDs"
    check_u_23
    assert_equal MANUAL "$RESULT_STATUS" "shared collector special-permission result"
    assert_contains "$RESULT_EVIDENCE" "special_permission_files=0" "shared collector special-permission count"
    check_u_25
    assert_equal MANUAL "$RESULT_STATUS" "shared collector world-writable result"
    assert_contains "$RESULT_EVIDENCE" "world_writable_files=1" "shared collector world-writable count"
    assert_contains "$RESULT_EVIDENCE" "/data/-world?line?tab%" "shared collector arbitrary world-writable filename"
    check_u_33
    assert_equal MANUAL "$RESULT_STATUS" "shared collector hidden-path result"
    assert_contains "$RESULT_EVIDENCE" "hidden_paths=2" "shared collector hidden-path count"
    assert_contains "$RESULT_EVIDENCE" "/data/.hidden?entry?%" "shared collector arbitrary hidden filename"
    assert_equal 1 "$find_calls" "shared collector one traversal for four criteria"

    chmod 0644 -- "$world_path"
    check_u_25
    assert_contains "$RESULT_EVIDENCE" "world_writable_files=1" "shared collector snapshot remains stable"
    assert_equal 1 "$find_calls" "shared collector cache reuse"
    scanner_reset_full_filesystem_cache
    check_u_25
    assert_contains "$RESULT_EVIDENCE" "world_writable_files=0" "shared collector reset observes mutation"
    assert_equal 2 "$find_calls" "shared collector reset traversal"

    dangling_link="$root/data/dangling"$'\n'"link"$'\t'"%"
    ln -s -- /missing-target "$dangling_link"
    second_valid_link="$root/data/z-valid"$'\n'"link"
    ln -s -- "${world_path##*/}" "$second_valid_link"
    scanner_reset_full_filesystem_cache
    check_u_15
    assert_equal MANUAL "$RESULT_STATUS" "shared collector absolute offline symlink"
    assert_contains "$RESULT_EVIDENCE" "orphaned_paths=0" "shared collector absolute symlink lstat ownership"
    check_u_25
    assert_equal MANUAL "$RESULT_STATUS" "U-15 link error does not poison U-25 facts"
    check_u_33
    assert_equal MANUAL "$RESULT_STATUS" "U-15 link error does not poison U-33 facts"
    assert_equal 3 "$find_calls" "shared collector dangling-link traversal"

    rm -f -- "$dangling_link" "$second_valid_link"
    printf 'placeholder:x:4294967295:4294967295::/nonexistent:/bin/false' > "$root/etc/passwd"
    printf 'placeholder:x:4294967295:' > "$root/etc/group"
    scanner_reset_full_filesystem_cache
    check_u_15
    assert_equal VULNERABLE "$RESULT_STATUS" "shared collector offline unknown UID and GID"
    assert_contains "$RESULT_EVIDENCE" "external_nss_sources=0" "shared collector files-only NSS evidence"
    assert_equal 4 "$find_calls" "shared collector owner-correlation traversal"

    rm -f -- "$root/etc/passwd" "$root/etc/group" "$root/etc/nsswitch.conf"
    mkdir -p -- "$root/etc/passwd" "$root/etc/group"
    chmod 0666 -- "$world_path"
    SELECTED_CHECKS="U-25"
    scanner_reset_full_filesystem_cache
    check_u_25
    assert_equal MANUAL "$RESULT_STATUS" "selected U-25 ignores U-15 databases"
    assert_contains "$RESULT_EVIDENCE" "world_writable_files=1" "selected U-25 still collects its fact"
    assert_equal "" "$SCANNER_FULL_FILESYSTEM_U15_SETUP_ERROR" "selected U-25 skips U-15 setup"
    assert_equal 5 "$find_calls" "selected U-25 one traversal"

    scanner_local_filesystem_roots() { return 0; }
    scanner_reset_full_filesystem_cache
    check_u_25
    assert_equal MANUAL "$RESULT_STATUS" "selected U-25 empty offline root inventory"
    assert_contains "$RESULT_EVIDENCE" "world_writable_files=0" "empty offline root inventory yields no U-25 facts"
    assert_equal 5 "$find_calls" "empty offline root inventory avoids traversal"
    SELECTED_CHECKS=""
    scanner_reset_full_filesystem_cache
    check_u_15
    assert_equal ERROR "$RESULT_STATUS" "U-15 setup error precedes empty offline root inventory"
    check_u_25
    assert_equal MANUAL "$RESULT_STATUS" "empty offline inventory remains isolated after U-15 setup error"
    assert_contains "$RESULT_EVIDENCE" "world_writable_files=0" "combined setup error does not populate U-25 facts"
    assert_equal 5 "$find_calls" "combined setup and empty-root errors avoid traversal"
    SELECTED_CHECKS="U-25"
    scanner_local_filesystem_roots() { printf '%s\n' "${SCAN_ROOT%/}"; }
    scanner_reset_full_filesystem_cache
    check_u_25
    assert_contains "$RESULT_EVIDENCE" "world_writable_files=1" "restored offline root inventory"
    assert_equal 6 "$find_calls" "restored offline root traversal"

    RUNTIME_MODE="auto"
    check_u_25
    assert_equal 7 "$find_calls" "runtime-mode cache-key invalidation"
    mkdir -p -- "$second_scratch"
    SCRATCH_DIR="$second_scratch"
    check_u_25
    assert_equal 8 "$find_calls" "scratch-workspace cache-key invalidation"
    SELECTED_CHECKS="U-33"
    check_u_33
    assert_equal 9 "$find_calls" "selection cache-key invalidation"
    mkdir -p -- "$second_root/.cache-key"
    SCAN_ROOT="$second_root"
    check_u_33
    assert_contains "$RESULT_EVIDENCE" "hidden_paths=1" "scan-root cache-key result"
    assert_equal 10 "$find_calls" "scan-root cache-key invalidation"

    SCAN_ROOT="$root"
    SCRATCH_DIR="$scratch"
    RUNTIME_MODE="off"
    rm -rf -- "$root/etc/passwd" "$root/etc/group"
    printf 'owner:x:%s:%s::/nonexistent:/bin/false' "$padded_uid" "$padded_gid" > "$root/etc/passwd"
    printf 'owner:x:%s:' "$padded_gid" > "$root/etc/group"
    printf '%s\n' 'passwd: files' 'group: files' > "$root/etc/nsswitch.conf"
    SELECTED_CHECKS=""
    scanner_reset_full_filesystem_cache
    find() {
        find_calls=$((find_calls + 1))
        return 2
    }
    check_u_15
    assert_equal ERROR "$RESULT_STATUS" "shared collector U-15 traversal failure"
    check_u_23
    assert_equal ERROR "$RESULT_STATUS" "shared collector U-23 traversal failure"
    check_u_25
    assert_equal ERROR "$RESULT_STATUS" "shared collector U-25 traversal failure"
    check_u_33
    assert_equal ERROR "$RESULT_STATUS" "shared collector U-33 traversal failure"
    assert_equal 11 "$find_calls" "shared collector failure is cached"
)

test_shared_collector_excludes_workspace() (
    local root="$TEST_TEMP/shared-workspace-root"
    local scratch="$root/.run-self"
    local actual_hidden="$root/.actual-hidden"

    mkdir -p -- "$root/data" "$scratch"
    SCAN_ROOT="/"
    RUNTIME_MODE="auto"
    SELECTED_CHECKS="U-33"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_account_file.sh
    . "$PROJECT_DIR/lib/checks_account_file.sh"
    SCRATCH_DIR="$scratch"
    REPORT_TEXT="$root/.current-report.txt"
    REPORT_JSONL="$root/.current-report.jsonl"
    : > "$REPORT_TEXT"
    : > "$REPORT_JSONL"
    scanner_local_filesystem_roots() { printf '%s\n' "$root"; }

    check_u_33
    assert_equal GOOD "$RESULT_STATUS" "live shared collector excludes its workspace"
    assert_contains "$RESULT_EVIDENCE" "hidden_paths=0" "live shared workspace exclusion evidence"

    : > "$actual_hidden"
    scanner_reset_full_filesystem_cache
    check_u_33
    assert_equal MANUAL "$RESULT_STATUS" "live shared collector retains unrelated hidden paths"
    if ! printf '%s\n' "$RESULT_EVIDENCE" | grep -Fxq -- "$actual_hidden"; then
        fail "filesystem evidence path gained or lost a pathname byte"
    fi

    rm -f -- "$actual_hidden"
    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    scanner_reset_full_filesystem_cache
    check_u_33
    assert_equal MANUAL "$RESULT_STATUS" "offline shared collector excludes its workspace"
    assert_contains "$RESULT_EVIDENCE" "hidden_paths=0" "offline shared workspace exclusion evidence"
)

test_remaining_criterion_goldens() (
    local base="$TEST_TEMP/remaining-criterion-goldens"

    load_check_stack() {
        SCAN_ROOT="$1"
        RUNTIME_MODE="off"
        SELECTED_CHECKS=""
        # shellcheck source=../lib/core.sh
        . "$PROJECT_DIR/lib/core.sh"
        # shellcheck source=../lib/resolvers.sh
        . "$PROJECT_DIR/lib/resolvers.sh"
        # shellcheck source=../lib/checks_account_file.sh
        . "$PROJECT_DIR/lib/checks_account_file.sh"
        # shellcheck source=../lib/checks_service.sh
        . "$PROJECT_DIR/lib/checks_service.sh"
        # shellcheck source=../lib/checks_system.sh
        . "$PROJECT_DIR/lib/checks_system.sh"
        SCRATCH_DIR="$2"
        set_test_platform debian 13 "Debian GNU/Linux 13"
    }

    (
        local root="$base/metadata-root"
        local scratch="$base/metadata-scratch"

        mkdir -p -- "$root/etc" "$scratch"
        printf '%s\n' 'ssh 22/tcp' > "$root/etc/services"
        printf '%s\n' 'SHELL=/bin/sh' > "$root/etc/crontab"
        chmod 0644 -- "$root/etc/services"
        chmod 0640 -- "$root/etc/crontab"
        load_check_stack "$root" "$scratch"
        stat_uid() { printf '0\n'; }
        stat_owner() { printf 'root\n'; }

        check_u_22
        assert_equal GOOD "$RESULT_STATUS" "U-22 conforming services file"
        assert_contains "$RESULT_EVIDENCE" "owner_uid=0,mode=644" "U-22 metadata evidence"
        rm -f -- "$root/etc/services"
        mkdir -- "$root/etc/services"
        check_u_22
        assert_equal ERROR "$RESULT_STATUS" "U-22 rejects a directory"

        check_u_37
        assert_equal GOOD "$RESULT_STATUS" "U-37 conforming crontab file"
        rm -f -- "$root/etc/crontab"
        ln -s -- /missing-crontab "$root/etc/crontab"
        check_u_37
        assert_equal ERROR "$RESULT_STATUS" "U-37 rejects a dangling crontab path"
    ) || exit 1

    (
        local root="$base/activation-root"
        local scratch="$base/activation-scratch"
        local legacy_expression='^((rpc\.)?(cmsd|ttdbserverd?|sadmind|walld|sprayd|rstatd|rusersd|rexd|pcnfsd|statd|ypupdated|rquotad)|kcms_server|cachefsd)$'
        local listener_arguments=""
        local listener_arguments_file="$scratch/u52-listener-arguments"

        mkdir -p -- \
            "$root/etc/systemd/system/multi-user.target.wants" \
            "$root/usr/lib/systemd/system" "$scratch"
        printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' > "$root/etc/passwd"
        printf '%s\n' \
            'finger stream tcp nowait root /usr/sbin/in.fingerd in.fingerd' \
            'shell stream tcp nowait root /usr/sbin/in.rshd in.rshd' \
            'sadmind stream tcp nowait root /usr/sbin/sadmind sadmind' \
            'telnet stream tcp nowait root /usr/sbin/in.telnetd in.telnetd' > "$root/etc/inetd.conf"
        printf '%s\n' '[Service]' 'ExecStart=/usr/sbin/automount' > "$root/usr/lib/systemd/system/autofs.service"
        ln -s -- ../../../../usr/lib/systemd/system/autofs.service \
            "$root/etc/systemd/system/multi-user.target.wants/autofs.service"
        load_check_stack "$root" "$scratch"

        check_u_34
        assert_equal VULNERABLE "$RESULT_STATUS" "U-34 active inetd Finger"
        assert_contains "$RESULT_EVIDENCE" "legacy_activation=1" "U-34 legacy evidence"
        check_u_36
        assert_equal VULNERABLE "$RESULT_STATUS" "U-36 active inetd r-service"
        assert_contains "$RESULT_EVIDENCE" "legacy_activation=1" "U-36 legacy evidence"
        check_u_41
        assert_equal VULNERABLE "$RESULT_STATUS" "U-41 statically enabled autofs"
        assert_contains "$RESULT_EVIDENCE" "unit=autofs.service,offline_enabled=true" "U-41 unit evidence"
        check_u_42
        assert_equal VULNERABLE "$RESULT_STATUS" "U-42 unprefixed inetd sadmind"
        assert_contains "$RESULT_EVIDENCE" "legacy_dangerous_rpc=1" "U-42 legacy evidence"
        check_u_52
        assert_equal VULNERABLE "$RESULT_STATUS" "U-52 active inetd Telnet"

        printf '%s\n' 'rpcXcmsd stream tcp nowait root /usr/sbin/rpcXcmsd rpcXcmsd' > "$root/etc/inetd.conf"
        if service_inetd_enabled "$legacy_expression"; then
            fail "U-42 RPC expression matched a lookalike service"
        fi

        service_activation_state() { SERVICE_ACTIVATION_EVIDENCE="activation=inactive\n"; return 1; }
        runtime_enabled() { return 0; }
        trusted_command() {
            [ "$1" = pgrep ] && printf '/bin/true\n'
        }
        check_u_41
        assert_equal VULNERABLE "$RESULT_STATUS" "U-41 process-only activation"
        assert_contains "$RESULT_EVIDENCE" "process=automount,runtime_active=true" "U-41 process evidence"

        service_legacy_enabled() { SERVICE_LEGACY_UNCERTAIN=0; return 1; }
        capture_command() {
            shift
            printf '%s\n' "$*" > "$listener_arguments_file"
            return 0
        }
        LISTENER_SNAPSHOT_CACHE_ENABLED=0
        check_u_52
        assert_equal GOOD "$RESULT_STATUS" "U-52 ignores a nonexistent TCP listener"
        listener_arguments="$(< "$listener_arguments_file")"
        assert_equal "-H -lntp" "$listener_arguments" "U-52 requests only TCP listeners"

        service_detect_snmp() { SERVICE_SNMP_ENDPOINT_ACTIVE=0; SERVICE_SNMP_CONFIG_UNCERTAIN=0; return 1; }
        check_u_58
        assert_equal GOOD "$RESULT_STATUS" "U-58 inactive SNMP"
    ) || exit 1

    (
        local root="$base/nfs-root"
        local scratch="$base/nfs-scratch"

        mkdir -p -- "$root/etc" "$scratch"
        printf '%s\n' '/srv/share *(rw,sync,no_subtree_check)' > "$root/etc/exports"
        chmod 0644 -- "$root/etc/exports"
        load_check_stack "$root" "$scratch"
        runtime_enabled() { return 1; }
        service_nfs_state() { return 0; }
        stat_owner() { printf 'root\n'; }

        check_u_40
        assert_equal VULNERABLE "$RESULT_STATUS" "U-40 unrestricted active export"
        assert_contains "$RESULT_EVIDENCE" "unrestricted_exports=1" "U-40 unrestricted export evidence"
        rm -f -- "$root/etc/exports"
        ln -s -- /missing-exports "$root/etc/exports"
        check_u_40
        assert_equal ERROR "$RESULT_STATUS" "U-40 rejects an unsafe exports path"
    ) || exit 1

    (
        local root="$base/mail-root"
        local scratch="$base/mail-scratch"

        mkdir -p -- "$root/etc/postfix" "$scratch"
        printf '%s\n' \
            'mynetworks = 0.0.0.0/0' \
            'disable_vrfy_command = no' > "$root/etc/postfix/main.cf"
        load_check_stack "$root" "$scratch"
        runtime_enabled() { return 1; }
        service_detect_mail() { SERVICE_MAIL_PROVIDERS="postfix"; SERVICE_MAIL_UNCERTAIN=0; }

        check_u_45
        assert_equal MANUAL "$RESULT_STATUS" "U-45 active mail version review"
        check_u_47
        assert_equal VULNERABLE "$RESULT_STATUS" "U-47 unrestricted Postfix relay network"
        check_u_48
        assert_equal VULNERABLE "$RESULT_STATUS" "U-48 enabled Postfix VRFY"
    ) || exit 1

    (
        local root="$base/dns-root"
        local scratch="$base/dns-scratch"
        local tab_character=""

        mkdir -p -- "$root/etc/bind" "$scratch"
        load_check_stack "$root" "$scratch"
        tab_character="$(printf '\t')"
        service_detect_dns() { return 0; }
        service_bind_effective_file() { printf 'validated%s%s\n' "$tab_character" "$root/etc/bind/named.conf"; }

        printf '%s\n' 'zone "example.test" { type primary; allow-update { any; }; };' > "$root/etc/bind/named.conf"
        check_u_51
        assert_equal VULNERABLE "$RESULT_STATUS" "U-51 unrestricted dynamic update"
        printf '%s\n' 'zone "example.test" { type primary; allow-update { key "ddns-key"; }; };' > "$root/etc/bind/named.conf"
        check_u_51
        assert_equal GOOD "$RESULT_STATUS" "U-51 key-restricted dynamic update"
        assert_contains "$RESULT_EVIDENCE" "restricted_clauses=1" "U-51 restricted update evidence"
        printf '%s\n' 'zone "example.test" { type primary; update-policy { grant ddns-key zonesub ANY; }; };' > "$root/etc/bind/named.conf"
        check_u_51
        assert_equal MANUAL "$RESULT_STATUS" "U-51 update-policy ANY remains a structured policy"
        assert_contains "$RESULT_EVIDENCE" "unsafe_clauses=0" "U-51 update-policy is not an unrestricted allow-update clause"
    ) || exit 1

    (
        local root="$base/banner-root"
        local scratch="$base/banner-scratch"

        mkdir -p -- "$root/etc" "$root/var/log" "$scratch"
        printf '%s\n' \
            'root:x:0:0:root:/root:/bin/bash' \
            'ftp:x:14:50:FTP:/srv/ftp:/usr/sbin/nologin' > "$root/etc/passwd"
        printf '%s\n' 'ftpd_banner=WARNING: Authorized FTP access only' > "$root/etc/vsftpd.conf"
        printf '%s\n' 'Unauthorized access is prohibited.' > "$root/etc/issue"
        printf '%s\n' 'Authorized users only.' > "$root/etc/motd"
        load_check_stack "$root" "$scratch"
        service_detect_ftp() { SERVICE_FTP_PROVIDERS="vsftpd"; SERVICE_FTP_UNCERTAIN=0; }

        check_u_53
        assert_equal GOOD "$RESULT_STATUS" "U-53 generic FTP warning without product disclosure"
        printf '%s\n' 'ftpd_banner=WARNING: Policy 1.2 applies' > "$root/etc/vsftpd.conf"
        check_u_53
        assert_equal GOOD "$RESULT_STATUS" "U-53 policy number is not a product version"
        printf '%s\n' 'ftpd_banner=WARNING: vsftpd 3.0.5' > "$root/etc/vsftpd.conf"
        check_u_53
        assert_equal VULNERABLE "$RESULT_STATUS" "U-53 vsftpd product version disclosure"
        check_u_55
        assert_equal GOOD "$RESULT_STATUS" "U-55 non-login FTP account shell"

        service_activation_state() { SERVICE_ACTIVATION_EVIDENCE="activation=inactive\n"; return 1; }
        service_legacy_enabled() { SERVICE_LEGACY_UNCERTAIN=0; return 1; }
        service_listener_state() { return 1; }
        service_detect_ftp() { SERVICE_FTP_PROVIDERS=""; SERVICE_FTP_UNCERTAIN=0; }
        service_detect_mail() { SERVICE_MAIL_PROVIDERS=""; SERVICE_MAIL_UNCERTAIN=0; }
        service_detect_dns() { return 1; }
        check_u_62
        assert_equal GOOD "$RESULT_STATUS" "U-62 configured local warning surfaces"

        check_u_66
        assert_equal MANUAL "$RESULT_STATUS" "U-66 offline logging policy review"
    ) || exit 1

    (
        local root="$base/remote-account-root"
        local scratch="$base/remote-account-scratch"

        mkdir -p -- \
            "$root/etc/pam.d" "$root/etc/ssh" "$root/lib/security" \
            "$root/etc/systemd/system/sockets.target.wants" "$root/usr/lib/systemd/system" "$scratch"
        printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' > "$root/etc/passwd"
        printf '%s\n' 'PermitRootLogin no' > "$root/etc/ssh/sshd_config"
        printf '%s\n' 'auth required /lib/security/pam_securetty.so' > "$root/etc/pam.d/login"
        printf '%s\n' 'console' > "$root/etc/securetty"
        : > "$root/lib/security/pam_securetty.so"
        printf '%s\n' '[Socket]' 'ListenStream=23' > "$root/usr/lib/systemd/system/telnet.socket"
        ln -s -- ../../../../usr/lib/systemd/system/telnet.socket \
            "$root/etc/systemd/system/sockets.target.wants/telnet.socket"
        load_check_stack "$root" "$scratch"

        check_u_01
        assert_equal GOOD "$RESULT_STATUS" "U-01 offline enabled Telnet socket"
        assert_contains "$RESULT_EVIDENCE" "telnet_static_state_code=0" "U-01 offline Telnet activation evidence"
        rm -f -- "$root/lib/security/pam_securetty.so"
        check_u_01
        assert_equal VULNERABLE "$RESULT_STATUS" "U-01 offline Telnet requires an available securetty module"
    ) || exit 1

    (
        local root="$base/remote-account-path-root"
        local scratch="$base/remote-account-path-scratch"
        local outside_telnet="$base/remote-account-outside-telnet"

        mkdir -p -- "$root/etc/ssh" "$root/etc/xinetd.d" "$scratch"
        printf '%s\n' 'PermitRootLogin no' > "$root/etc/ssh/sshd_config"
        printf '%s\n' 'service telnet {' ' disable = no' '}' > "$outside_telnet"
        load_check_stack "$root" "$scratch"

        ln -s -- ../../../remote-account-outside-telnet "$root/etc/xinetd.d/telnet"
        check_u_01
        assert_equal ERROR "$RESULT_STATUS" "U-01 rejects an escaping xinetd Telnet path"

        rm -f -- "$root/etc/xinetd.d/telnet"
        mkdir -- "$root/etc/xinetd.d/telnet"
        check_u_01
        assert_equal ERROR "$RESULT_STATUS" "U-01 rejects a non-regular xinetd Telnet path"

        rmdir -- "$root/etc/xinetd.d/telnet"
        printf '%s\n' 'service telnet {' ' disable = no' '}' > "$root/etc/xinetd.d/telnet"
        chmod 000 -- "$root/etc/xinetd.d/telnet"
        check_u_01
        assert_equal ERROR "$RESULT_STATUS" "U-01 rejects an unreadable xinetd Telnet path"
        chmod 0600 -- "$root/etc/xinetd.d/telnet"
        rm -f -- "$root/etc/xinetd.d/telnet"

        check_u_01
        assert_equal GOOD "$RESULT_STATUS" "U-01 preserves the absent Telnet path result"
    ) || exit 1

    (
        local root="$base/remote-account-custom-xinetd-root"
        local scratch="$base/remote-account-custom-xinetd-scratch"

        mkdir -p -- "$root/etc/ssh" "$root/etc/xinetd.d" "$scratch"
        printf '%s\n' 'PermitRootLogin no' > "$root/etc/ssh/sshd_config"
        printf '%s\n' 'includedir /etc/xinetd.d' > "$root/etc/xinetd.conf"
        printf '%s\n' 'service telnet' '{' '    disable = no' '}' > "$root/etc/xinetd.d/custom-services"
        load_check_stack "$root" "$scratch"

        check_u_01
        assert_equal VULNERABLE "$RESULT_STATUS" "U-01 detects Telnet in a custom xinetd filename"
        assert_contains "$RESULT_EVIDENCE" "telnet_legacy_state_code=0" "U-01 custom xinetd activation evidence"
    ) || exit 1

    (
        local root="$base/remote-account-port22-root"
        local scratch="$base/remote-account-port22-scratch"
        local listener_process="dropbear"

        mkdir -p -- "$root/etc/ssh" "$scratch"
        printf '%s\n' 'PermitRootLogin no' > "$root/etc/ssh/sshd_config"
        load_check_stack "$root" "$scratch"
        runtime_enabled() { return 0; }
        service_state() { return 1; }
        sshd_manager_has_custom_invocation() { return 1; }
        trusted_command() { [ "$1" = ss ] && printf '%s\n' /usr/bin/ss; }
        port_listener_facts() {
            if [ "$1" = 22 ] && [ "$2" = tcp ]; then
                printf 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("%s",pid=10,fd=3))\n' "$listener_process"
            fi
        }

        check_u_01
        assert_equal MANUAL "$RESULT_STATUS" "U-01 does not apply OpenSSH policy to Dropbear"
        assert_contains "$RESULT_EVIDENCE" "unknown_port_22_listener=1" "U-01 unknown port 22 evidence"

        listener_process="sshd"
        sshd_effective_value() { printf '%s\n' no; }
        check_u_01
        assert_equal GOOD "$RESULT_STATUS" "U-01 binds an sshd listener to OpenSSH policy"
        assert_contains "$RESULT_EVIDENCE" "openssh_endpoint_active=1" "U-01 sshd listener evidence"
    ) || exit 1

    (
        local root="$base/remote-account-sshd-fifo-root"
        local scratch="$base/remote-account-sshd-fifo-scratch"

        mkdir -p -- "$root/etc/ssh/sshd_config.d" "$scratch"
        mkfifo -- "$root/etc/ssh/sshd_config"
        printf '%s\n' 'PermitRootLogin no' > "$root/etc/ssh/sshd_config.d/10-root.conf"
        load_check_stack "$root" "$scratch"

        check_u_01
        assert_equal ERROR "$RESULT_STATUS" "U-01 rejects a non-regular sshd main configuration"
    ) || exit 1

    (
        local root="$base/metadata-passwd-fifo-root"
        local scratch="$base/metadata-passwd-fifo-scratch"

        mkdir -p -- "$root/etc" "$scratch"
        printf '%s\n' 'ssh 22/tcp' > "$root/etc/services"
        chmod 0644 -- "$root/etc/services"
        mkfifo -- "$root/etc/passwd"
        load_check_stack "$root" "$scratch"

        check_u_22
        assert_equal ERROR "$RESULT_STATUS" "U-22 rejects a passwd FIFO during owner lookup"
        rm -f -- "$root/etc/passwd"
        printf '%s\n' 'bin:x:1000:1000:bin:/bin:/usr/sbin/nologin' > "$root/etc/passwd"
        check_u_22
        assert_equal GOOD "$RESULT_STATUS" "U-22 resolves an allowed non-root owner from passwd"
    ) || exit 1

    (
        local root="$base/su-policy-root"
        local scratch="$base/su-policy-scratch"

        mkdir -p -- "$root/etc/pam.d" "$root/lib/security" "$root/usr/bin" "$scratch"
        printf '%s\n' \
            'root:x:0:0:root:/root:/bin/bash' \
            'operator:x:1000:1000::/home/operator:/bin/bash' > "$root/etc/passwd"
        printf '%s\n' 'root:x:0:' 'sudo:x:27:operator' 'allusers:x:1000:operator' > "$root/etc/group"
        printf '%s\n' 'UID_MIN 1000' > "$root/etc/login.defs"
        : > "$root/usr/bin/su"
        : > "$root/lib/security/pam_wheel.so"
        chmod 0755 -- "$root/usr/bin/su"
        printf '%s\n' \
            'auth optional pam_wheel.so group=missing' \
            'auth required pam_wheel.so group=sudo use_uid' > "$root/etc/pam.d/su"
        load_check_stack "$root" "$scratch"
        stat_uid() {
            case "$1" in
                "$root/usr/bin/su") printf '0\n' ;;
                *) /usr/bin/stat -Lc '%u' -- "$1" 2>/dev/null ;;
            esac
        }

        check_u_06
        assert_equal GOOD "$RESULT_STATUS" "U-06 enforcing pam_wheel row binds its own group"
        assert_contains "$RESULT_EVIDENCE" "pam_wheel_group=sudo" "U-06 enforcing group evidence"
        rm -f -- "$root/lib/security/pam_wheel.so"
        check_u_06
        assert_equal VULNERABLE "$RESULT_STATUS" "U-06 missing pam_wheel module"
        mkdir -p -- "$root/usr/lib/not-a-loader-path/security"
        : > "$root/usr/lib/not-a-loader-path/security/pam_wheel.so"
        check_u_06
        assert_equal VULNERABLE "$RESULT_STATUS" "U-06 ignores a recursive PAM module decoy"
        assert_contains "$RESULT_EVIDENCE" "pam_wheel_module_available=0" "U-06 recursive module decoy evidence"
        rm -rf -- "$root/usr/lib/not-a-loader-path"

        mkdir -p -- "$root/usr/lib/arm-linux-gnueabihf/security"
        : > "$root/usr/lib/arm-linux-gnueabihf/security/pam_wheel.so"
        check_u_06
        assert_equal GOOD "$RESULT_STATUS" "U-06 accepts a direct multiarch PAM module path"
        rm -rf -- "$root/usr/lib/arm-linux-gnueabihf"
        : > "$root/lib/security/pam_wheel.so"
        printf '%s\n' 'auth required pam_wheel.so group=missing use_uid' > "$root/etc/pam.d/su"
        check_u_06
        assert_equal VULNERABLE "$RESULT_STATUS" "U-06 missing restriction group"

        printf '%s\n' \
            'auth [success=1 default=ignore] /lib/security/pam_wheel.so group=sudo use_uid' > "$root/etc/pam.d/su"
        check_u_06
        assert_equal MANUAL "$RESULT_STATUS" "U-06 structurally parses a bracket-controlled pam_wheel module"
        assert_contains "$RESULT_EVIDENCE" "pam_wheel_restriction=1" "U-06 bracketed module evidence"
        assert_contains "$RESULT_EVIDENCE" "pam_wheel_group=sudo" "U-06 bracketed group option evidence"

        printf '%s\n' \
            'auth required pam_exec.so pam_wheel.so group=sudo root_only' > "$root/etc/pam.d/su"
        check_u_06
        assert_equal VULNERABLE "$RESULT_STATUS" "U-06 ignores a pam_wheel decoy argument"
        assert_contains "$RESULT_EVIDENCE" "pam_wheel_restriction=0" "U-06 decoy restriction evidence"
        assert_contains "$RESULT_EVIDENCE" "pam_root_only=0" "U-06 decoy root-only evidence"

        printf '%s\n' \
            'auth required pam_wheel.so deny' \
            'auth sufficient pam_permit.so' \
            'auth required pam_wheel.so group=sudo use_uid' > "$root/etc/pam.d/su"
        check_u_06
        assert_equal MANUAL "$RESULT_STATUS" "U-06 does not stop bypass analysis at a deny row"
        assert_contains "$RESULT_EVIDENCE" "pam_early_bypass=1" "U-06 deny-row bypass evidence"

        printf '%s\n' 'auth required pam_wheel.so group=sudo group=allusers use_uid' > "$root/etc/pam.d/su"
        check_u_06
        assert_equal MANUAL "$RESULT_STATUS" "U-06 uses the last broad group option"
        assert_contains "$RESULT_EVIDENCE" "pam_wheel_group=allusers" "U-06 last broad group evidence"

        printf '%s\n' 'auth required pam_wheel.so group=allusers group=sudo use_uid' > "$root/etc/pam.d/su"
        check_u_06
        assert_equal GOOD "$RESULT_STATUS" "U-06 uses the last approved group option"
        assert_contains "$RESULT_EVIDENCE" "pam_wheel_group=sudo" "U-06 last approved group evidence"

        printf '%s\n' 'auth required pam_wheel.so group=allusers GROUP=sudo use_uid' > "$root/etc/pam.d/su"
        check_u_06
        assert_equal MANUAL "$RESULT_STATUS" "U-06 treats option names as case-sensitive"
        assert_contains "$RESULT_EVIDENCE" "pam_wheel_group=allusers" "U-06 case-sensitive group option evidence"
    ) || exit 1

    (
        local root="$base/timeout-path-root"
        local scratch="$base/timeout-path-scratch"

        mkdir -p -- "$root/etc" "$root/root" "$scratch"
        printf '%s\n' \
            'root:x:0:0:root:/root:/bin/bash' \
            'operator:x:1000:1000::/home/operator:/bin/tcsh' > "$root/etc/passwd"
        printf '%s\n' 'UID_MIN 1000' > "$root/etc/login.defs"
        printf '%s\n' 'TMOUT=600' 'export TMOUT' > "$root/etc/profile"
        load_check_stack "$root" "$scratch"

        check_u_12
        assert_equal VULNERABLE "$RESULT_STATUS" "U-12 missing csh timeout is not hidden by sh"
        printf '%s\n' 'set autologout=10' > "$root/etc/csh.cshrc"
        check_u_12
        assert_equal MANUAL "$RESULT_STATUS" "U-12 separate sh and csh timeout surfaces"
        rm -f -- "$root/etc/profile"
        check_u_12
        assert_equal VULNERABLE "$RESULT_STATUS" "U-12 missing sh timeout is not hidden by csh"
        printf '%s\n' 'TMOUT=900' > "$root/etc/profile"
        check_u_12
        assert_equal MANUAL "$RESULT_STATUS" "U-12 weak sh timeout remains conditional"
        assert_contains "$RESULT_EVIDENCE" "sh_noncompliant=1" "U-12 sh-specific evidence"

        printf '%s\n' 'root:x:0:0:root:/root:/bin/tcsh' > "$root/etc/passwd"
        rm -f -- "$root/etc/profile" "$root/etc/csh.cshrc"
        printf '%s\n' 'set path = ( /usr/bin "." /bin )' > "$root/root/.tcshrc"
        check_u_14
        assert_contains "$RESULT_EVIDENCE" "candidate_unsafe_assignments=1" "U-14 tcsh startup coverage"
        rm -f -- "$root/root/.tcshrc"
        printf '%s\n' 'PATH="/usr/bin:.:/bin"' > "$root/etc/profile"
        check_u_14
        assert_contains "$RESULT_EVIDENCE" "candidate_unsafe_assignments=1" "U-14 quoted middle PATH element"
    ) || exit 1

    (
        local root="$base/profile-directory-root"
        local scratch="$base/profile-directory-scratch"
        local outside_profile="$base/profile-directory-outside.sh"

        mkdir -p -- "$root/etc/profile.d" "$root/usr/share/kisa-profile" "$scratch"
        printf '%s\n' \
            'root:x:0:0:root:/root:/bin/bash' \
            'operator:x:1000:1000::/home/operator:/bin/bash' > "$root/etc/passwd"
        printf '%s\n' 'UID_MIN 1000' > "$root/etc/login.defs"
        printf '%s\n' 'TMOUT=600' 'export TMOUT' > "$root/usr/share/kisa-profile/session.sh"
        ln -s -- /usr/share/kisa-profile/session.sh "$root/etc/profile.d/session.sh"
        load_check_stack "$root" "$scratch"

        check_u_12
        assert_equal MANUAL "$RESULT_STATUS" "U-12 reads an in-root profile.d symlink"
        assert_contains "$RESULT_EVIDENCE" "sh_compliant=1" "U-12 profile.d symlink timeout evidence"

        printf '%s\n' 'PATH=/usr/bin:.:/bin' > "$root/usr/share/kisa-profile/session.sh"
        check_u_14
        assert_contains "$RESULT_EVIDENCE" "candidate_unsafe_assignments=1" "U-14 profile.d symlink PATH evidence"

        printf '%s\n' 'TMOUT=600' 'export TMOUT' > "$outside_profile"
        rm -f -- "$root/etc/profile.d/session.sh"
        ln -s -- ../../../profile-directory-outside.sh "$root/etc/profile.d/session.sh"
        check_u_12
        assert_equal MANUAL "$RESULT_STATUS" "U-12 keeps an escaping profile.d symlink inconclusive"
        assert_contains "$RESULT_EVIDENCE" "sh_unresolved=1" "U-12 escaping profile.d symlink evidence"
        check_u_14
        assert_contains "$RESULT_EVIDENCE" "unresolved_profile_paths=1" "U-14 escaping profile.d symlink evidence"
    ) || exit 1

    (
        local root="$base/xinetd-id-root"
        local scratch="$base/xinetd-id-scratch"

        mkdir -p -- "$root/etc/xinetd.d" "$root/etc/xinetd-real" "$scratch"
        {
            printf '%s\n' 'defaults' '{' '    enabled = telnet-custom' '}'
            printf '%s\n' 'includedir /etc/xinetd.d'
        } > "$root/etc/xinetd.conf"
        printf '%s\n' \
            'service telnet' '{' '    id = telnet-custom' '    disable = no' '}' \
            > "$root/etc/xinetd-real/telnet-service"
        ln -s -- ../xinetd-real/telnet-service "$root/etc/xinetd.d/telnet-service"
        load_check_stack "$root" "$scratch"

        SERVICE_LEGACY_UNCERTAIN=0
        service_xinetd_enabled '^telnet$' || fail "xinetd enabled list did not use the effective service ID"

        {
            printf '%s\n' 'defaults' '{' '    disabled = telnet-custom' '}'
            printf '%s\n' 'includedir /etc/xinetd.d'
        } > "$root/etc/xinetd.conf"
        SERVICE_LEGACY_UNCERTAIN=0
        if service_xinetd_enabled '^telnet$'; then
            fail "xinetd disabled list did not use the effective service ID"
        fi
        assert_equal 0 "$SERVICE_LEGACY_UNCERTAIN" "xinetd effective ID disable state"

        rm -f -- "$root/etc/xinetd.d/telnet-service"
        printf '%s\n' 'service telnet' '{' '    disable = no' '}' > "$root/etc/xinetd.d/telnet.conf"
        printf '%s\n' 'includedir /etc/xinetd.d' > "$root/etc/xinetd.conf"
        SERVICE_LEGACY_UNCERTAIN=0
        if service_xinetd_enabled '^telnet$'; then
            fail "xinetd loaded a dotted backup-style file"
        fi
        assert_equal 0 "$SERVICE_LEGACY_UNCERTAIN" "xinetd dotted file exclusion"
    ) || exit 1

    (
        local root="$base/service-symlink-root"
        local scratch="$base/service-symlink-scratch"

        mkdir -p -- \
            "$root/etc/cron.daily" "$root/etc/cron-targets" \
            "$root/etc/exports.d" "$root/etc/nfs-targets" "$scratch"
        printf '%s\n' '#!/bin/sh' 'exit 0' > "$root/etc/cron-targets/daily-job"
        chmod 0777 -- "$root/etc/cron-targets/daily-job"
        ln -s -- ../cron-targets/daily-job "$root/etc/cron.daily/daily-job"
        printf '%s\n' '/srv/share *(rw,sync)' > "$root/etc/nfs-targets/site.exports"
        chmod 0644 -- "$root/etc/nfs-targets/site.exports"
        ln -s -- ../nfs-targets/site.exports "$root/etc/exports.d/site.exports"
        load_check_stack "$root" "$scratch"
        stat_owner() { printf 'root\n'; }
        runtime_enabled() { return 1; }
        service_nfs_state() { return 0; }

        check_u_37
        assert_equal VULNERABLE "$RESULT_STATUS" "U-37 follows a confined cron symlink"
        assert_contains "$RESULT_EVIDENCE" "violations=1" "U-37 symlink target mode evidence"
        check_u_40
        assert_equal VULNERABLE "$RESULT_STATUS" "U-40 follows a confined exports.d symlink"
        assert_contains "$RESULT_EVIDENCE" "unrestricted_exports=1" "U-40 symlink export evidence"
    ) || exit 1

    (
        local root="$base/sysv-service-root"
        local scratch="$base/sysv-service-scratch"

        mkdir -p -- "$root/etc/init.d" "$root/etc/rc2.d" "$scratch"
        printf '%s\n' '#!/bin/sh' 'exit 0' > "$root/etc/init.d/autofs"
        printf '%s\n' '#!/bin/sh' 'exit 0' > "$root/etc/init.d/rpc.pcnfsd"
        chmod 0755 -- "$root/etc/init.d/autofs" "$root/etc/init.d/rpc.pcnfsd"
        ln -s -- ../init.d/autofs "$root/etc/rc2.d/S01autofs"
        ln -s -- ../init.d/rpc.pcnfsd "$root/etc/rc2.d/S02rpc.pcnfsd"
        load_check_stack "$root" "$scratch"
        runtime_enabled() { return 0; }
        trusted_command() { return 1; }

        check_u_41
        assert_equal VULNERABLE "$RESULT_STATUS" "U-41 keeps SysV activation when systemctl is unavailable"
        assert_contains "$RESULT_EVIDENCE" "runtime_sysv_enabled=true" "U-41 live SysV evidence"
        check_u_42
        assert_equal VULNERABLE "$RESULT_STATUS" "U-42 recognizes a dotted RPC SysV service"
        assert_contains "$RESULT_EVIDENCE" "runtime_sysv_enabled=true" "U-42 dotted RPC SysV evidence"
    ) || exit 1

    (
        local root="$base/mount-inventory-root"
        local scratch="$base/mount-inventory-scratch"
        local findmnt_fixture="$scratch/findmnt"
        local helper_status=0

        mkdir -p -- "$root" "$scratch"
        load_check_stack "$root" "$scratch"
        {
            printf '%s\n' '#!/bin/sh'
            printf '%s\n' "printf '%s\\n' '/mnt/encoded\\040target ext4'"
        } > "$findmnt_fixture"
        chmod 0755 -- "$findmnt_fixture"
        SCAN_ROOT="/"
        trusted_command() {
            [ "$1" = findmnt ] && printf '%s\n' "$findmnt_fixture"
        }
        scanner_local_filesystem_roots >/dev/null 2>&1 || helper_status=$?
        assert_equal 2 "$helper_status" "encoded findmnt target collection failure"
    ) || exit 1
)

test_u67_single_pass_inventory() (
    local root="$TEST_TEMP/u67-single-pass-root"
    local scratch="$TEST_TEMP/u67-single-pass-scratch"
    local log_file=""
    local findmnt_fixture="$scratch/findmnt"
    local find_behavior="normal"
    local find_calls=0

    mkdir -p -- "$root/var/log/archive" "$scratch"
    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    SELECTED_CHECKS=""
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_system.sh
    . "$PROJECT_DIR/lib/checks_system.sh"
    SCRATCH_DIR="$scratch"
    set_test_platform debian 13 "Debian GNU/Linux 13"

    log_file="$root/var/log/application"$'\n'"record"$'\t'"%"
    : > "$log_file"
    chmod 0666 -- "$log_file"
    ln -s -- "${log_file##*/}" "$root/var/log/current"
    ln -s -- archive "$root/var/log/archive-link"
    ln -s -- missing "$root/var/log/dangling"

    find() {
        find_calls=$((find_calls + 1))
        /usr/bin/find "$@"
        [ "$find_behavior" != "trailing" ] || printf 'trailing-bytes'
    }

    check_u_67
    assert_equal VULNERABLE "$RESULT_STATUS" "U-67 deterministic writable-log fixture"
    assert_contains "$RESULT_EVIDENCE" "scanned_files=2" "U-67 one-pass regular and link-target count"
    assert_contains "$RESULT_EVIDENCE" "scanned_directories=2" "U-67 one-pass directory count"
    assert_contains "$RESULT_EVIDENCE" "symlinks=3" "U-67 one-pass symlink count"
    assert_contains "$RESULT_EVIDENCE" "symlink_targets_scanned=1" "U-67 one-pass file target count"
    assert_contains "$RESULT_EVIDENCE" "symlink_directories_unscanned=1" "U-67 one-pass directory target count"
    assert_contains "$RESULT_EVIDENCE" "unresolved_symlinks=1" "U-67 one-pass unresolved target count"
    assert_contains "$RESULT_EVIDENCE" "stat_errors=0" "U-67 one-pass metadata completeness"
    assert_equal 1 "$find_calls" "U-67 uses one filesystem traversal"

    find_behavior="trailing"
    check_u_67
    assert_equal ERROR "$RESULT_STATUS" "U-67 rejects trailing non-NUL inventory bytes"

    find_behavior="normal"
    {
        printf '%s\n' '#!/bin/sh'
        printf '%s\n' "printf '%s\\n' '/var/log/encoded\\040mount ext4'"
    } > "$findmnt_fixture"
    chmod 0755 -- "$findmnt_fixture"
    runtime_enabled() { return 0; }
    trusted_command() {
        [ "$1" = findmnt ] && printf '%s\n' "$findmnt_fixture"
    }
    check_u_67
    assert_equal ERROR "$RESULT_STATUS" "U-67 rejects encoded findmnt targets"
)

run_test() {
    local name="$1"
    shift

    printf 'TEST %s\n' "$name"
    if "$@"; then
        PASSED=$((PASSED + 1))
        printf '  PASS\n'
    else
        FAILED=$((FAILED + 1))
        printf '  FAIL\n'
    fi
}

run_test "shell syntax" test_shell_syntax
run_test "manual page contract" test_manpage_contract
run_test "policy and evidence contracts" test_policy_and_evidence_contracts
run_test "supported platform matrix" test_platform_support_matrix
run_test "PAM facility and platform capabilities" test_pam_facility_scoping_and_platform_capabilities
run_test "time and sysctl platform adapters" test_time_and_sysctl_platform_adapters
run_test "core report counts and permissions" test_core_report_counts_and_permissions
run_test "result normalization differential" test_result_normalization_differential
run_test "report write failures" test_report_write_failures
run_test "path, scratch, and listener cache semantics" test_path_scratch_and_listener_cache_semantics
run_test "existing output directory remains unchanged" test_existing_output_directory_is_not_mutated
run_test "sysctl layering, masks, and drift" test_sysctl_layering_masks_and_drift
run_test "offline absolute symlink confinement" test_offline_absolute_symlinks_stay_inside_scan_root
run_test "layered consumer errors and symlink escape" test_layered_consumer_errors_and_symlink_escape
run_test "layered directory symlink escape" test_layered_directory_symlink_escape
run_test "CLI platform, selection, and reports" test_cli_platform_selection_and_reports
run_test "installed libexec and private-lib layouts" test_installed_layouts
run_test "full catalog cardinality and secret safety" test_full_catalog_produces_one_result_per_criterion
run_test "conservative account regressions" test_conservative_account_regressions
run_test "conservative service regressions" test_conservative_service_regressions
run_test "Chrony peer and empty log handling" test_chrony_peer_and_empty_log_handling
run_test "U-02 RHEL dual password stacks" test_u02_rhel_dual_password_stacks
run_test "KISA account platform goldens" test_kisa_account_platform_goldens
run_test "U-30 effective UMASK platform goldens" test_u30_effective_umask_platform_goldens
run_test "U-04 through U-19 false-conclusive paths" test_account_u04_u19_false_conclusive_paths
run_test "U-20 through U-33 false-conclusive paths" test_account_u20_u33_false_conclusive_paths
run_test "shared full-filesystem collector" test_shared_full_filesystem_collector
run_test "shared collector workspace exclusions" test_shared_collector_excludes_workspace
run_test "remaining criterion goldens" test_remaining_criterion_goldens
run_test "U-67 single-pass inventory" test_u67_single_pass_inventory
run_test "KISA service platform goldens" test_kisa_service_platform_goldens
run_test "enterprise service variant goldens" test_enterprise_service_variant_goldens
run_test "BIND stock environment goldens" test_bind_stock_environment_goldens
run_test "Debian TFTP and FTP activation goldens" test_debian_tftp_activation_goldens
run_test "service false-positive goldens" test_service_false_positive_goldens
run_test "UFW sysctl and firewall goldens" test_ufw_sysctl_and_firewall_goldens
run_test "U-28 backend goldens" test_u28_backend_goldens
run_test "KISA time-provider goldens" test_kisa_time_provider_goldens
run_test "timesyncd runtime goldens" test_timesyncd_runtime_goldens

printf 'RESULT passed=%d failed=%d\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
