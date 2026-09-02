#!/bin/bash

# shellcheck disable=SC1091,SC2034,SC2329

# Dependency-free regression tests for the scanner runtime and sysctl resolver.

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
LC_ALL=C
export LC_ALL
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

assert_file_contains() {
    local file="$1"
    local expected_part="$2"
    local context="$3"

    grep -Fq -- "$expected_part" "$file" || fail "$context: missing=[$expected_part] file=[$file]"
}

mode_of() {
    stat -c '%a' -- "$1" 2>/dev/null || stat -f '%Lp' -- "$1" 2>/dev/null
}

write_os_release() {
    local root="$1"
    local platform_id="$2"
    local platform_version="$3"
    local platform_name="$4"

    mkdir -p -- "$root/etc"
    {
        printf 'ID=%s\n' "$platform_id"
        printf 'VERSION_ID="%s"\n' "$platform_version"
        printf 'PRETTY_NAME="%s"\n' "$platform_name"
    } > "$root/etc/os-release"
}

test_shell_syntax() (
    local file=""

    /bin/sh -n "$PROJECT_DIR/bin/kisa-cce-scan" || fail "CLI wrapper syntax check failed"
    for file in "$PROJECT_DIR"/lib/*.sh "$PROJECT_DIR"/tests/*.sh; do
        /bin/bash -n "$file" || fail "syntax check failed: $file"
    done
)

test_manpage_contract() (
    local manpage="$PROJECT_DIR/man/kisa-cce-scan.8"
    local option=""

    [ -r "$manpage" ] || fail "manual page is missing"
    for option in \
        '\-\-root' \
        '\-\-output-dir' \
        '\-\-checks' \
        '\-\-no-runtime' \
        '\-\-explain-sysctl' \
        '\-\-allow-unsupported' \
        '\-\-help' \
        '\-\-version'; do
        grep -Fq -- "$option" "$manpage" || fail "manual page is missing option: $option"
    done

    if command -v mandoc >/dev/null 2>&1; then
        mandoc -T lint "$manpage" >/dev/null || fail "manual page lint failed"
    fi
)

test_core_report_counts_and_permissions() (
    local root="$TEST_TEMP/core-root"
    local output="$TEST_TEMP/core-reports"
    local json_lines=""

    write_os_release "$root" ubuntu 26.04 "Ubuntu 26.04 LTS"
    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    OUTPUT_PARENT="$output"
    SELECTED_CHECKS=""
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"

    detect_platform || fail "supported platform was not detected"
    initialize_workspace
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
    assert_equal 600 "$(mode_of "$REPORT_TEXT")" "text report mode"
    assert_equal 600 "$(mode_of "$REPORT_JSONL")" "JSONL report mode"
    case "$REPORT_TEXT$REPORT_JSONL" in *XXXXXXXX*) fail "report filename was not randomized" ;; esac
    assert_file_contains "$REPORT_TEXT" "total: 5" "text summary"
    assert_file_contains "$REPORT_TEXT" "password=[REDACTED]" "evidence redaction"
    assert_file_contains "$REPORT_TEXT" "owner=root" "evidence line normalization"
    if grep -Fq -- "do-not-write-this" "$REPORT_TEXT"; then
        fail "text report retained a secret"
    fi
    json_lines="$(wc -l < "$REPORT_JSONL" | tr -d '[:space:]')"
    assert_equal 6 "$json_lines" "JSONL result and summary line count"
    assert_file_contains "$REPORT_JSONL" '"type":"summary","total":5' "JSONL summary"
    validate_reports || fail "completed reports failed integrity validation"
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
    sysctl_runtime_value() { printf '%s\n' 1; }
    explanation="$(sysctl_explain net.ipv4.ip_forward)"
    assert_contains "$explanation" "runtime=1" "runtime sysctl explanation"
    assert_contains "$explanation" "drift=present" "runtime drift explanation"
    assert_contains "$explanation" "inactive_nonstandard_directory=/etc/sysctl.conf.d" "inactive sysctl directory warning"

    sysctl_runtime_value() { printf '%s\n' 2; }
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

    mkdir -p -- "$root/etc/pam.d" "$root/etc/authselect" "$root/etc/sysctl.d" "$scratch"
    printf '%s\n' 'auth required pam_faillock.so preauth' > "$root/etc/authselect/system-auth"
    ln -s /etc/authselect/system-auth "$root/etc/pam.d/system-auth"
    ln -s ../../../../etc/passwd "$root/etc/pam.d/escape"
    printf '%s\n' 'kernel.kptr_restrict = 2' > "$root/etc/sysctl.conf"
    ln -s /etc/sysctl.conf "$root/etc/sysctl.d/99-sysctl.conf"

    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    SCRATCH_DIR="$scratch"

    expanded="$(pam_expand_service system-auth)" || fail "rooted PAM absolute symlink was not resolved"
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

    PLATFORM_ID="rhel"
    resolved="$(login_defs_value PASS_MAX_DAYS)" || fail "RHEL login.defs.d value was not resolved"
    assert_contains "$resolved" $'45\t/etc/login.defs.d/90-final.defs:1' "RHEL login.defs.d lexical override"
    PLATFORM_ID="ubuntu"
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

    mkdir -p -- "$scanner_copy/bin" "$scanner_copy/lib" "$scanner_copy/data"
    cp -- "$PROJECT_DIR/bin/kisa-cce-scan" "$scanner_copy/bin/kisa-cce-scan"
    cp -- "$PROJECT_DIR/lib/core.sh" "$scanner_copy/lib/core.sh"
    cp -- "$PROJECT_DIR/lib/kisa-cce-scan-main.sh" "$scanner_copy/lib/kisa-cce-scan-main.sh"
    cp -- "$PROJECT_DIR/lib/resolvers.sh" "$scanner_copy/lib/resolvers.sh"
    cp -- "$PROJECT_DIR/data/criteria.tsv" "$scanner_copy/data/criteria.tsv"
    cp -- "$PROJECT_DIR/data/VERSION" "$scanner_copy/data/VERSION"
    {
        printf '%s\n' '#!/bin/bash'
        printf '%s\n' 'check_u_01() { set_result GOOD "fixture result" "fixture=true"; }'
    } > "$scanner_copy/lib/checks_fixture.sh"
    chmod 0755 -- "$scanner_copy/bin/kisa-cce-scan"

    write_os_release "$supported_root" ubuntu 26.04 "Ubuntu 26.04 LTS"
    write_os_release "$unsupported_root" debian 13 "Debian GNU/Linux 13"
    mkdir -p -- "$supported_root/etc/sysctl.d"
    printf '%s\n' 'net.ipv4.ip_forward = 0' > "$supported_root/etc/sysctl.d/90-local.conf"

    command_output="$("$scanner_copy/bin/kisa-cce-scan" \
        --root "$supported_root" \
        --output-dir "$output_dir" \
        --checks u-01,U-01 \
        --no-runtime 2>&1)"
    command_status="$?"
    assert_equal 0 "$command_status" "supported CLI scan exit status"
    text_report="$(printf '%s\n' "$command_output" | sed -n 's/^text_report=//p')"
    jsonl_report="$(printf '%s\n' "$command_output" | sed -n 's/^jsonl_report=//p')"
    [ -f "$text_report" ] || fail "CLI text report was not created"
    [ -f "$jsonl_report" ] || fail "CLI JSONL report was not created"
    assert_file_contains "$text_report" "total: 1" "selected CLI result count"
    assert_file_contains "$text_report" "runtime_collection: off" "offline runtime state"
    assert_equal 600 "$(mode_of "$text_report")" "CLI text report mode"
    assert_equal 600 "$(mode_of "$jsonl_report")" "CLI JSONL report mode"

    command_output="$("$scanner_copy/bin/kisa-cce-scan" --root "$unsupported_root" --checks U-01 2>&1)"
    command_status="$?"
    assert_equal 2 "$command_status" "unsupported platform rejection"
    assert_contains "$command_output" "지원되지 않은 플랫폼" "unsupported platform message"

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
        --explain-sysctl net.ipv4.ip_forward 2>&1)"
    command_status="$?"
    assert_equal 0 "$command_status" "sysctl explanation exit status"
    assert_contains "$command_output" "persistent=0" "sysctl persistent explanation"
    assert_contains "$command_output" "runtime=unavailable" "offline sysctl runtime explanation"

    command_output="$("$scanner_copy/bin/kisa-cce-scan" --root "$supported_root" --checks U-99 2>&1)"
    command_status="$?"
    assert_equal 2 "$command_status" "unknown check rejection"
    assert_contains "$command_output" "판정 기준에 없는 점검 코드" "unknown check message"
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
            printf '%s\n' 'check_u_01() { set_result GOOD "installed fixture" "layout=true"; }'
        } > "$private_library_path/checks_fixture.sh"

        assert_equal 755 "$(mode_of "$installed_prefix/bin/kisa-cce-scan")" \
            "$layout_name installed command mode"
        assert_equal 644 "$(mode_of "$private_library_path/kisa-cce-scan-main.sh")" \
            "$layout_name private main mode"
        assert_equal 644 "$(mode_of "$installed_prefix/share/kisa-cce-linux-scanner/criteria.tsv")" \
            "$layout_name criterion data mode"
        assert_equal 644 "$(mode_of "$installed_prefix/share/man/man8/kisa-cce-scan.8")" \
            "$layout_name installed manual page mode"
        [ ! -e "$installed_prefix/share/doc/kisa-cce-linux-scanner" ] ||
            fail "$layout_name install unexpectedly copied repository documentation"
        command_output="$(CDPATH='' cd -P -- "$TEST_TEMP" &&
            "$installed_prefix/bin/kisa-cce-scan" --version 2>&1)" ||
            fail "$layout_name installed version command failed"
        assert_equal "kisa-cce-scan $(sed -n '1p' "$PROJECT_DIR/data/VERSION")" \
            "$command_output" "$layout_name installed version"

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
        command_output="$("$installed_prefix/bin/kisa-cce-scan" \
            --root "$supported_root" \
            --output-dir "$output_dir" \
            --checks U-01 \
            --no-runtime 2>&1)" || command_status=$?
        assert_equal 0 "$command_status" "$layout_name installed scan exit status"
        text_report="$(printf '%s\n' "$command_output" | sed -n 's/^text_report=//p')"
        [ -f "$text_report" ] || fail "$layout_name installed scan did not create a text report"
        assert_file_contains "$text_report" "installed fixture" "$layout_name installed library lookup"
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
        0|1|2) ;;
        *) fail "full catalog scan exited unexpectedly: $command_status" ;;
    esac
    text_report="$(printf '%s\n' "$command_output" | sed -n 's/^text_report=//p')"
    jsonl_report="$(printf '%s\n' "$command_output" | sed -n 's/^jsonl_report=//p')"
    [ -f "$text_report" ] || fail "full scan text report was not created: $command_output"
    [ -f "$jsonl_report" ] || fail "full scan JSONL report was not created"
    result_count="$(grep -Ec '^\[U-[0-9]{2}\]RRRRR : ' "$text_report")"
    assert_equal 67 "$result_count" "full text result count"
    json_lines="$(wc -l < "$jsonl_report" | tr -d '[:space:]')"
    assert_equal 68 "$json_lines" "full JSONL line count"
    assert_file_contains "$jsonl_report" '"type":"summary","total":67' "full JSONL summary"
    if command -v jq >/dev/null 2>&1; then
        jq -e -c . "$jsonl_report" >/dev/null || fail "full JSONL report is not valid JSON"
    fi
    awk -F '"' '
        /"code":"U-[0-9][0-9]"/ {seen[$4]++}
        END {
            if (length(seen) != 67) exit 1
            for (code in seen) if (seen[code] != 1) exit 1
        }
    ' "$jsonl_report" || fail "criterion codes were missing or duplicated"
    if grep -Fq -- 'fixture-secret-that-must-not-leak' "$text_report" "$jsonl_report"; then
        fail "a fixture password hash escaped into a report"
    fi
)

test_conservative_account_regressions() (
    local root="$TEST_TEMP/account-regression-root"
    local scratch="$TEST_TEMP/account-regression-scratch"
    local metrics=""

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
    PLATFORM_ID="ubuntu"

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
    assert_equal MANUAL "$RESULT_STATUS" "offline firewalld policy object discovery"
    assert_contains "$RESULT_EVIDENCE" "persistent_firewall_lines=" "firewalld policy evidence"

    {
        printf '%s\n' '#!/bin/sh'
        printf '%s\n' 'exit 1'
    } > "$scratch/authselect"
    chmod 0755 -- "$scratch/authselect"
    PLATFORM_ID="rhel"
    runtime_enabled() { return 0; }
    trusted_command() { [ "$1" = authselect ] && printf '%s\n' "$scratch/authselect"; }
    scanner_authselect_configuration_valid || fail "authselect opt-out was treated as invalid"
    assert_equal 1 "$SCANNER_AUTHSELECT_UNMANAGED" "authselect opt-out state"
    PLATFORM_ID="ubuntu"
    runtime_enabled() { return 1; }

    check_u_31
    assert_equal GOOD "$RESULT_STATUS" "non-login service account home exclusion"
    check_u_17
    assert_equal GOOD "$RESULT_STATUS" "systemd /dev/null mask handling"
)

test_conservative_service_regressions() (
    local root="$TEST_TEMP/service-regression-root"
    local scratch="$TEST_TEMP/service-regression-scratch"
    local state=0
    local tab=""

    mkdir -p -- "$root/etc/snmp" "$scratch"
    SCAN_ROOT="$root"
    RUNTIME_MODE="off"
    PLATFORM_ID="ubuntu"
    # shellcheck source=../lib/core.sh
    . "$PROJECT_DIR/lib/core.sh"
    # shellcheck source=../lib/resolvers.sh
    . "$PROJECT_DIR/lib/resolvers.sh"
    # shellcheck source=../lib/checks_service.sh
    . "$PROJECT_DIR/lib/checks_service.sh"
    SCRATCH_DIR="$scratch"

    runtime_enabled() { return 0; }
    trusted_command() { printf '%s\n' /usr/bin/false; }
    service_activation_state example.service >/dev/null 2>&1
    state=$?
    assert_equal 2 "$state" "systemctl failure preservation"

    runtime_enabled() { return 1; }
    service_detect_mail() { SERVICE_MAIL_PROVIDERS="postfix"; SERVICE_MAIL_UNCERTAIN=0; }
    check_u_46
    assert_equal MANUAL "$RESULT_STATUS" "Postfix internal privilege model"

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

    printf '%s\n' 'root ALL=(ALL:ALL) ALL' > "$root/etc/sudoers-rs"
    service_sudo_provider() { printf '%s\n' sudo-rs; }
    stat_owner() { printf '%s\n' root; }
    stat_uid() { printf '%s\n' 0; }
    stat_mode() { printf '%s\n' 440; }
    check_u_63
    assert_equal GOOD "$RESULT_STATUS" "sudo-rs active policy path"
    assert_contains "$RESULT_EVIDENCE" "sudo_provider=sudo-rs" "sudo-rs evidence"
)

test_chrony_peer_and_empty_log_handling() (
    local root="$TEST_TEMP/system-regression-root"
    local scratch="$TEST_TEMP/system-regression-scratch"
    local chronyc_fixture="$scratch/chronyc"
    local output=""
    local status=0

    mkdir -p -- "$root/var/log" "$root/etc/chrony/conf.d" "$root/run/chrony-dhcp" "$scratch"
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
    PLATFORM_ID="ubuntu"

    printf '%s\n' 'confdir /etc/chrony/conf.d' > "$root/etc/chrony/chrony.conf"
    printf '%s\n' 'server 192.0.2.10 iburst' > "$root/etc/chrony/conf.d/site.conf"
    output="$(chrony_config_evidence)" || fail "Chrony confdir source was not resolved"
    assert_contains "$output" "configured_sources=1" "Chrony confdir expansion"
    printf '%s\n' 'sourcedir /run/chrony-dhcp' > "$root/etc/chrony/chrony.conf"
    output="$(chrony_config_evidence)" || status=$?
    assert_equal 3 "$status" "empty Chrony sourcedir status"

    runtime_enabled() { return 0; }
    trusted_command() { [ "$1" = chronyc ] && printf '%s\n' "$chronyc_fixture"; }
    output="$(chrony_runtime_evidence)" || fail "selected Chrony peer was rejected"
    assert_contains "$output" "selected_sources=1" "Chrony peer selection"

    runtime_enabled() { return 1; }
    check_u_67
    assert_equal MANUAL "$RESULT_STATUS" "empty log directory result"
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
run_test "core report counts and permissions" test_core_report_counts_and_permissions
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

printf 'RESULT passed=%d failed=%d\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
