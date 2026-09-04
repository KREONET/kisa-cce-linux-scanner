# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash

# shellcheck disable=SC2034

# Runs KISA CCE checks against a supported live system or an offline root.

KISA_CCE_CALLER_PATH="${PATH:-}"
KISA_CCE_CALLER_UMASK="$(umask)"

for imported_command_name in \
    awk cat chmod cp cut date find grep head hostname iconv id mkdir mktemp mv paste \
    readlink rm sed sort stat tail tr wc xargs; do
    unset -f "$imported_command_name" 2>/dev/null || true
done
unset imported_command_name

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
umask 077

case "${BASH_SOURCE[0]}" in
    */*) source_parent="${BASH_SOURCE[0]%/*}" ;;
    *) source_parent="." ;;
esac
SCANNER_CLI_DIRECTORY="$(CDPATH='' cd -P -- "$source_parent" && pwd)" || exit 2
unset source_parent
case "$SCANNER_CLI_DIRECTORY" in
    */kisa-cce-cli) SCANNER_LIBRARY_DIR="${SCANNER_CLI_DIRECTORY%/kisa-cce-cli}" ;;
    *) SCANNER_LIBRARY_DIR="" ;;
esac

bootstrap_console_uptime_into() {
    local __kisa_bootstrap_destination="$1"
    local uptime_value=""
    local uptime_seconds=""
    local uptime_fraction=""

    if [ -r /proc/uptime ]; then
        IFS=' ' read -r uptime_value _ < /proc/uptime || uptime_value=""
    fi
    case "$uptime_value" in
        *.*)
            uptime_seconds="${uptime_value%%.*}"
            uptime_fraction="${uptime_value#*.}"
            case "$uptime_seconds:$uptime_fraction" in
                :*|*:|*[!0-9:]*) uptime_seconds="" ;;
            esac
            ;;
        *) uptime_seconds="" ;;
    esac
    if [ -z "$uptime_seconds" ]; then
        uptime_seconds="${SECONDS:-0}"
        case "$uptime_seconds" in
            ''|*[!0-9]*) uptime_seconds=0 ;;
        esac
        uptime_fraction=""
    fi
    uptime_fraction="${uptime_fraction}000000"
    uptime_fraction="${uptime_fraction:0:6}"
    printf -v "$__kisa_bootstrap_destination" '%6s.%s' "$uptime_seconds" "$uptime_fraction"
}

bootstrap_console_emit() {
    local payload="${1-}"
    local line=""
    local sanitized_line=""
    local uptime=""

    while IFS= read -r line || [ -n "$line" ]; do
        bootstrap_console_sanitize_line_into "$line" sanitized_line
        bootstrap_console_uptime_into uptime
        printf '[%s] kisa-cce-scan: %s\n' "$uptime" "$sanitized_line"
    done <<< "$payload"
}

bootstrap_console_sanitize_line_into() {
    local input_line="$1"
    local destination_name="$2"
    local character=""
    local escaped_character=""
    local sanitized=""
    local index_value=0
    local byte_value=0

    for ((index_value = 0; index_value < ${#input_line}; index_value++)); do
        character="${input_line:index_value:1}"
        case "$character" in
            $'\t') sanitized+='\\t' ;;
            $'\r') sanitized+='\\r' ;;
            [[:cntrl:]])
                printf -v byte_value '%d' "'$character"
                printf -v escaped_character '\\x%02x' "$byte_value"
                sanitized+="$escaped_character"
                ;;
            *) sanitized+="$character" ;;
        esac
    done
    printf -v "$destination_name" '%s' "$sanitized"
}

bootstrap_die() {
    bootstrap_console_emit "ERROR: $*" >&2
    exit 2
}

select_runtime_layout() {
    local candidate_root=""
    local candidate_data_dir=""

    DEFAULT_POLICY_DIRECTORY="/etc/kisa-cce-scanner/policy.d"

    case "$SCANNER_LIBRARY_DIR" in
        */lib/kisa-cce-linux-scanner)
            candidate_root="${SCANNER_LIBRARY_DIR%/lib/kisa-cce-linux-scanner}"
            candidate_data_dir="$candidate_root/share/kisa-cce-linux-scanner"
            ;;
        */libexec/kisa-cce-linux-scanner)
            candidate_root="${SCANNER_LIBRARY_DIR%/libexec/kisa-cce-linux-scanner}"
            candidate_data_dir="$candidate_root/share/kisa-cce-linux-scanner"
            ;;
        */lib)
            candidate_root="${SCANNER_LIBRARY_DIR%/lib}"
            candidate_data_dir="$candidate_root/data"
            ;;
        *)
            bootstrap_die "cannot determine the scanner library path: $SCANNER_LIBRARY_DIR"
            ;;
    esac

    if [ -r "$SCANNER_LIBRARY_DIR/kisa-cce-core/_core.sh" ] &&
        [ -r "$SCANNER_LIBRARY_DIR/kisa-cce-core/_i18n.sh" ] &&
        [ -r "$SCANNER_LIBRARY_DIR/kisa-cce-policy/_policy.sh" ] &&
        [ -r "$SCANNER_LIBRARY_DIR/kisa-cce-runtime/_runtime-fallback.sh" ] &&
        [ -r "$SCANNER_LIBRARY_DIR/kisa-cce-core/_scan-epoch.sh" ] &&
        [ -r "$SCANNER_LIBRARY_DIR/kisa-cce-runtime/_evidence.sh" ] &&
        [ -r "$SCANNER_LIBRARY_DIR/kisa-cce-resolvers/_resolvers.sh" ] &&
        [ -r "$candidate_data_dir/criteria.tsv" ] &&
        [ -r "$candidate_data_dir/VERSION" ]; then
        DATA_DIR="$candidate_data_dir"
        VERSION_FILE="$candidate_data_dir/VERSION"
        return 0
    fi

    bootstrap_die "scanner libraries or assessment data not found: $candidate_root"
}

select_runtime_layout
CRITERIA_FILE="$DATA_DIR/criteria.tsv"
[ -r "$VERSION_FILE" ] || bootstrap_die "cannot read the version file: $VERSION_FILE"
IFS= read -r KISA_CCE_VERSION < "$VERSION_FILE" ||
    bootstrap_die "cannot read the version file: $VERSION_FILE"
case "$KISA_CCE_VERSION" in
    ''|*[!0-9A-Za-z.+~-]*) bootstrap_die "invalid version file format: $VERSION_FILE" ;;
esac

# shellcheck source=/dev/null
. "$SCANNER_LIBRARY_DIR/kisa-cce-core/_i18n.sh"
i18n_load_catalog || bootstrap_die "cannot read the localization catalog: $I18N_LOCALE_DIRECTORY/$KISA_CCE_LANGUAGE"
i18n_load_console_catalog || bootstrap_die "cannot read the English console catalog: $I18N_LOCALE_DIRECTORY/en"
# shellcheck source=/dev/null
. "$SCANNER_LIBRARY_DIR/kisa-cce-core/_core.sh"
initialize_report_labels || bootstrap_die "cannot initialize localized report labels"
# shellcheck source=/dev/null
. "$SCANNER_LIBRARY_DIR/kisa-cce-core/_scan-epoch.sh"
# shellcheck source=/dev/null
. "$SCANNER_LIBRARY_DIR/kisa-cce-runtime/_runtime-fallback.sh"
# shellcheck source=/dev/null
. "$SCANNER_LIBRARY_DIR/kisa-cce-policy/_policy.sh"
# shellcheck source=/dev/null
. "$SCANNER_LIBRARY_DIR/kisa-cce-runtime/_evidence.sh"
# shellcheck source=/dev/null
. "$SCANNER_LIBRARY_DIR/kisa-cce-resolvers/_resolvers.sh"

check_files=("$SCANNER_LIBRARY_DIR/kisa-cce-checks"/_*.sh)
if [ ! -e "${check_files[0]}" ]; then
    die "check group files not found: $SCANNER_LIBRARY_DIR/kisa-cce-checks/_*.sh"
fi
for check_file in "${check_files[@]}"; do
    # shellcheck source=/dev/null
    . "$check_file"
done
unset check_file check_files

SCAN_ROOT="/"
RUNTIME_MODE="auto"
OUTPUT_PARENT=""
SELECTED_CHECKS=""
ALLOW_UNSUPPORTED=0
VERBOSE=0
DEBUG=0
EXPLAIN_SYSCTL_KEY=""
SCAN_MODE="audit"
POLICY_DIRECTORY=""
EVIDENCE_BUNDLE_PATH=""
EVIDENCE_BUNDLE_ACTIVE=0
EVIDENCE_MAX_AGE_SECONDS=3600
EVIDENCE_AGE_SECONDS=""
NO_RUNTIME_REQUESTED=0

usage() {
    local line=""

    while IFS= read -r line; do
        console_emit "$line"
    done <<'EOF'
Usage: kisa-cce-scan [OPTIONS]

KISA CCE 2026 checks for supported Debian, Ubuntu, Enterprise Linux, and named derivative releases.
Base releases: Debian 12/13, Ubuntu 22.04/24.04/26.04, and RHEL 8.10/9.8/10.2.
Named derivatives are listed in the operator documentation and command manual.

Options:
  --root PATH              Inspect PATH as a root; --root / keeps live collection.
  --output-dir PATH        Store scan reports; validated but unused with --explain-sysctl.
  --checks U-01,U-02       Run only the comma-separated check codes.
  --mode MODE              Select audit, complete, or all-or-nothing automation mode.
  --policy-dir PATH        Override the installed default policy directory.
  --evidence-bundle PATH   Use a validated live-runtime bundle with an offline root.
  --evidence-max-age SEC   Reject evidence older than SEC; default: 3600.
  --no-runtime             Skip live security state; live-root scans retain mount topology.
  --explain-sysctl KEY     Explain the effective persistent and runtime value.
  --allow-unsupported      Continue when the detected platform is unsupported.
  -v, --verbose            Print platform, per-check status, and summary progress.
  --debug                  Print structured internal diagnostics; implies --verbose.
  -h, --help               Show this help text.
  --version                Show the scanner version.

Exit status:
  0  No scanner errors or vulnerable results were recorded.
  1  At least one vulnerable result was recorded.
  2  Invocation, scanner, report, or blocked automation error; errors take precedence.
EOF
}

require_option_value() {
    local option_name="$1"
    local remaining_count="$2"
    local option_value="${3:-}"

    [ "$remaining_count" -ge 2 ] || die "$option_name requires a value"
    [ -n "$option_value" ] || die "$option_name requires a value"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --root)
            require_option_value "$1" "$#" "${2:-}"
            SCAN_ROOT="$2"
            shift 2
            ;;
        --root=*)
            require_option_value --root 2 "${1#*=}"
            SCAN_ROOT="${1#*=}"
            shift
            ;;
        --output-dir)
            require_option_value "$1" "$#" "${2:-}"
            OUTPUT_PARENT="$2"
            shift 2
            ;;
        --output-dir=*)
            require_option_value --output-dir 2 "${1#*=}"
            OUTPUT_PARENT="${1#*=}"
            shift
            ;;
        --checks)
            require_option_value "$1" "$#" "${2:-}"
            SELECTED_CHECKS="$2"
            shift 2
            ;;
        --checks=*)
            require_option_value --checks 2 "${1#*=}"
            SELECTED_CHECKS="${1#*=}"
            shift
            ;;
        --mode)
            require_option_value "$1" "$#" "${2:-}"
            SCAN_MODE="$2"
            shift 2
            ;;
        --mode=*)
            require_option_value --mode 2 "${1#*=}"
            SCAN_MODE="${1#*=}"
            shift
            ;;
        --policy-dir)
            require_option_value "$1" "$#" "${2:-}"
            POLICY_DIRECTORY="$2"
            shift 2
            ;;
        --policy-dir=*)
            require_option_value --policy-dir 2 "${1#*=}"
            POLICY_DIRECTORY="${1#*=}"
            shift
            ;;
        --evidence-bundle)
            require_option_value "$1" "$#" "${2:-}"
            EVIDENCE_BUNDLE_PATH="$2"
            shift 2
            ;;
        --evidence-bundle=*)
            require_option_value --evidence-bundle 2 "${1#*=}"
            EVIDENCE_BUNDLE_PATH="${1#*=}"
            shift
            ;;
        --evidence-max-age)
            require_option_value "$1" "$#" "${2:-}"
            EVIDENCE_MAX_AGE_SECONDS="$2"
            shift 2
            ;;
        --evidence-max-age=*)
            require_option_value --evidence-max-age 2 "${1#*=}"
            EVIDENCE_MAX_AGE_SECONDS="${1#*=}"
            shift
            ;;
        --no-runtime)
            RUNTIME_MODE="off"
            NO_RUNTIME_REQUESTED=1
            shift
            ;;
        --explain-sysctl)
            require_option_value "$1" "$#" "${2:-}"
            EXPLAIN_SYSCTL_KEY="$2"
            shift 2
            ;;
        --explain-sysctl=*)
            require_option_value --explain-sysctl 2 "${1#*=}"
            EXPLAIN_SYSCTL_KEY="${1#*=}"
            shift
            ;;
        --allow-unsupported)
            ALLOW_UNSUPPORTED=1
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        --debug)
            DEBUG=1
            VERBOSE=1
            debug_initialize
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --version)
            console_emit "kisa-cce-scan $KISA_CCE_VERSION"
            exit 0
            ;;
        --)
            shift
            [ "$#" -eq 0 ] || die "positional arguments are not supported: $1"
            ;;
        -*)
            die "unknown option: $1"
            ;;
        *)
            die "positional arguments are not supported: $1"
            ;;
    esac
done

debug_initialize
trap 'debug_emit_signal_exit INT 130; exit 130' INT
trap 'debug_emit_signal_exit TERM 143; exit 143' TERM

case "$SCAN_MODE" in
    audit|complete|automation) ;;
    *) die "--mode must be audit, complete, or automation: $SCAN_MODE" ;;
esac
case "$SCAN_MODE" in
    complete|automation)
        if [ -z "$POLICY_DIRECTORY" ] && [ -d "$DEFAULT_POLICY_DIRECTORY" ]; then
            POLICY_DIRECTORY="$DEFAULT_POLICY_DIRECTORY"
        fi
        ;;
esac
case "$EVIDENCE_MAX_AGE_SECONDS" in
    ''|*[!0-9]*) die "--evidence-max-age must be a positive integer in seconds" ;;
esac
[ "$EVIDENCE_MAX_AGE_SECONDS" -ge 1 ] && [ "$EVIDENCE_MAX_AGE_SECONDS" -le 604800 ] ||
    die "--evidence-max-age must be between 1 and 604800 seconds"

case "$SCAN_ROOT" in
    /*) ;;
    *) die "--root must be an absolute path: $SCAN_ROOT" ;;
esac
case "$SCAN_ROOT" in
    *$'\n'*|*$'\r'*|*$'\t'*) die "--root contains a disallowed control character" ;;
esac
[ -d "$SCAN_ROOT" ] || die "scan root is not a directory: $SCAN_ROOT"
canonical_root="$(CDPATH='' cd -P -- "$SCAN_ROOT" && pwd)" || die "cannot resolve the scan root: $SCAN_ROOT"
SCAN_ROOT="$canonical_root"
unset canonical_root

if [ -n "$OUTPUT_PARENT" ]; then
    case "$OUTPUT_PARENT" in
        /*) ;;
        *) die "--output-dir must be an absolute path: $OUTPUT_PARENT" ;;
    esac
fi
if [ -n "$POLICY_DIRECTORY" ]; then
    case "$POLICY_DIRECTORY" in /*) ;; *) die "--policy-dir must be an absolute path: $POLICY_DIRECTORY" ;; esac
fi
if [ -n "$EVIDENCE_BUNDLE_PATH" ]; then
    case "$EVIDENCE_BUNDLE_PATH" in /*) ;; *) die "--evidence-bundle must be an absolute path: $EVIDENCE_BUNDLE_PATH" ;; esac
fi

if [ "$SCAN_ROOT" != "/" ]; then
    RUNTIME_MODE="off"
elif [ "$(id -u)" -ne 0 ]; then
    die "a full live scan requires root privileges; use --root for offline analysis"
fi

if [ "$SCAN_MODE" = "complete" ] || [ "$SCAN_MODE" = "automation" ]; then
    [ -z "$SELECTED_CHECKS" ] || die "$SCAN_MODE mode requires all checks from U-01 through U-67"
    [ "$ALLOW_UNSUPPORTED" -eq 0 ] || die "--allow-unsupported cannot be used in $SCAN_MODE mode"
    [ -z "$EXPLAIN_SYSCTL_KEY" ] || die "--explain-sysctl cannot be used in $SCAN_MODE mode"
    [ -n "$POLICY_DIRECTORY" ] || die "$SCAN_MODE mode requires --policy-dir"
    if [ "$SCAN_ROOT" = "/" ]; then
        [ "$NO_RUNTIME_REQUESTED" -eq 0 ] || die "--no-runtime cannot be used for a live $SCAN_MODE scan"
        [ -z "$EVIDENCE_BUNDLE_PATH" ] || die "a live $SCAN_MODE scan uses current host state and does not accept an evidence bundle"
    else
        [ -n "$EVIDENCE_BUNDLE_PATH" ] || die "an offline $SCAN_MODE scan requires --evidence-bundle"
    fi
fi
if [ -n "$EVIDENCE_BUNDLE_PATH" ] && [ "$NO_RUNTIME_REQUESTED" -eq 1 ]; then
    die "--evidence-bundle and --no-runtime cannot be used together"
fi
if [ -n "$EVIDENCE_BUNDLE_PATH" ] && [ "$SCAN_ROOT" = "/" ]; then
    die "--evidence-bundle must be used with an offline --root"
fi

if [ -n "$POLICY_DIRECTORY" ]; then
    policy_load_dir "$POLICY_DIRECTORY" || die "cannot read the policy directory safely: $POLICY_DIRECTORY"
fi
if [ -n "$EVIDENCE_BUNDLE_PATH" ]; then
    validate_evidence_bundle "$EVIDENCE_BUNDLE_PATH" "$SCAN_ROOT" ||
        die "invalid runtime evidence bundle: ${EVIDENCE_VALIDATION_ERROR:-unknown error}"
    EVIDENCE_AGE_SECONDS="$(evidence_capture_age_seconds)" ||
        die "cannot validate the runtime evidence bundle capture time"
    [ "$EVIDENCE_AGE_SECONDS" -le "$EVIDENCE_MAX_AGE_SECONDS" ] ||
        die "runtime evidence bundle exceeds the maximum age: ${EVIDENCE_AGE_SECONDS}s"
    EVIDENCE_BUNDLE_ACTIVE=1
    RUNTIME_MODE="bundle"
fi

validate_criteria() {
    [ -r "$CRITERIA_FILE" ] || die "cannot read the criteria file: $CRITERIA_FILE"
    awk -F '\t' '
        NR == 1 {
            if ($0 != "code\tcategory\tseverity\ttitle") exit 2
            next
        }
        NF != 4 || $1 !~ /^U-[0-9][0-9]$/ ||
            $2 !~ /^[a-z][a-z0-9_-]*$/ ||
            $3 !~ /^[a-z][a-z0-9_-]*$/ || $4 == "" { exit 3 }
        seen[$1]++ { exit 4 }
        {
            count++
            if ($1 != sprintf("U-%02d", count)) exit 5
        }
        END { if (count != 67) exit 5 }
    ' "$CRITERIA_FILE" || die "invalid criteria file format"
}

normalize_selected_checks() {
    local raw_checks="$1"
    local normalized_checks=""
    local code=""
    local old_ifs="$IFS"

    [ -n "$raw_checks" ] || return 0
    raw_checks="$(printf '%s' "$raw_checks" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
    case "$raw_checks" in
        ''|,*|*,|*,,*) die "--checks must be a non-empty comma-separated list of codes" ;;
    esac

    set -f
    IFS=,
    for code in $raw_checks; do
        case "$code" in
            U-[0-9][0-9]) ;;
            *) die "invalid check code: $code" ;;
        esac
        awk -F '\t' -v target="$code" 'NR > 1 && $1 == target { found=1 } END { exit(found ? 0 : 1) }' "$CRITERIA_FILE" ||
            die "check code not found in the criteria file: $code"
        case ",$normalized_checks," in
            *",$code,"*) ;;
            *)
                if [ -n "$normalized_checks" ]; then
                    normalized_checks="$normalized_checks,$code"
                else
                    normalized_checks="$code"
                fi
                ;;
        esac
    done
    set +f
    IFS="$old_ifs"
    SELECTED_CHECKS="$normalized_checks"
}

validate_criteria
normalize_selected_checks "$SELECTED_CHECKS"

if [ -n "$EXPLAIN_SYSCTL_KEY" ]; then
    [ -z "$SELECTED_CHECKS" ] || die "--explain-sysctl and --checks cannot be used together"
    case "$EXPLAIN_SYSCTL_KEY" in
        ''|-*|*[!A-Za-z0-9_./-]*) die "invalid sysctl key: $EXPLAIN_SYSCTL_KEY" ;;
    esac
fi

if ! detect_platform; then
    if [ "$ALLOW_UNSUPPORTED" -eq 1 ]; then
        warn "continuing on an unsupported platform: ${PLATFORM_ID:-unknown} ${PLATFORM_VERSION:-unknown}"
    else
        die "unsupported platform: ${PLATFORM_ID:-unknown} ${PLATFORM_VERSION:-unknown}; see --help and the operator documentation for the support matrix"
    fi
fi

debug_selected_count=67
if [ -n "$SELECTED_CHECKS" ]; then
    debug_selected_count=1
    debug_selected_remaining="$SELECTED_CHECKS"
    while [[ "$debug_selected_remaining" == *,* ]]; do
        debug_selected_remaining="${debug_selected_remaining#*,}"
        debug_selected_count=$((debug_selected_count + 1))
    done
fi
if [ -n "$POLICY_DIRECTORY" ]; then
    debug_policy_state=active
else
    debug_policy_state=inactive
fi
if [ "$EVIDENCE_BUNDLE_ACTIVE" -eq 1 ]; then
    debug_evidence_state=active
else
    debug_evidence_state=inactive
fi
debug_emit scan_start \
    platform_id "${PLATFORM_ID:-unknown}" \
    platform_version "${PLATFORM_VERSION:-unknown}" \
    platform_family "${PLATFORM_FAMILY:-unknown}" \
    runtime "$RUNTIME_MODE" \
    mode "$SCAN_MODE" \
    selected_count "$debug_selected_count" \
    policy "$debug_policy_state" \
    evidence "$debug_evidence_state"
DEBUG_SCAN_STARTED=1
unset debug_selected_count debug_selected_remaining debug_policy_state debug_evidence_state

verbose "platform=${PLATFORM_ID:-unknown} version=${PLATFORM_VERSION:-unknown} family=${PLATFORM_FAMILY:-unknown} root=${SCAN_ROOT} runtime=${RUNTIME_MODE} mode=${SCAN_MODE}"

trap cleanup_workspace EXIT

if [ -n "$EXPLAIN_SYSCTL_KEY" ]; then
    SCRATCH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-explain.XXXXXXXX")" || die "cannot create a secure temporary directory"
    chmod 0700 "$SCRATCH_DIR" || die "cannot set temporary directory permissions"
    debug_emit workspace_ready scope explain
    scan_epoch_begin || die "cannot initialize the scan epoch"
    sysctl_explanation="$(sysctl_explain "$EXPLAIN_SYSCTL_KEY")" ||
        die "cannot determine the sysctl configuration or runtime value reliably"
    console_emit_lines "$sysctl_explanation"
    scan_epoch_end
    debug_emit_scan_end 0
    exit 0
fi

initialize_workspace
debug_emit workspace_ready scope assessment
scan_epoch_begin || die "cannot initialize the scan epoch"
write_report_header || die "cannot write the report header"

while IFS=$'\t' read -r code category severity title || [ -n "$code" ]; do
    [ "$code" = "code" ] && continue
    run_one_check "$code" "$category" "$severity" "$title" || true
done < "$CRITERIA_FILE"

if [ "$SCAN_MODE" = "automation" ] &&
    { [ "$COUNT_TOTAL" -ne 67 ] || [ "$COUNT_MANUAL" -gt 0 ] || [ "$COUNT_ERROR" -gt 0 ] || [ "$REPORT_WRITE_ERROR" -gt 0 ]; }; then
    verbose "summary total=${COUNT_TOTAL} good=${COUNT_GOOD} vulnerable=${COUNT_VULNERABLE} manual=${COUNT_MANUAL} not_applicable=${COUNT_NOT_APPLICABLE} error=${COUNT_ERROR}"
    debug_emit report_publication status blocked mode automation total "$COUNT_TOTAL" \
        manual "$COUNT_MANUAL" error "$COUNT_ERROR"
    scan_epoch_end
    die "automation mode did not publish reports because one or more criteria remain unresolved or erroneous"
fi
write_report_summary || die "cannot write the report summary"
verbose "summary total=${COUNT_TOTAL} good=${COUNT_GOOD} vulnerable=${COUNT_VULNERABLE} manual=${COUNT_MANUAL} not_applicable=${COUNT_NOT_APPLICABLE} error=${COUNT_ERROR}"
if ! validate_reports; then
    debug_emit report_validation status failed component content total "$COUNT_TOTAL"
    die "completed report integrity validation failed"
fi
if ! report_output_paths_are_current; then
    REPORT_WRITE_ERROR=1
    debug_emit report_validation status failed component path_binding total "$COUNT_TOTAL"
    die "output directory path changed during the scan: $OUTPUT_PARENT"
fi
if [ "$SCAN_MODE" = "automation" ]; then
    publish_automation_reports || {
        REPORT_WRITE_ERROR=1
        debug_emit report_publication status failed mode automation total "$COUNT_TOTAL"
        die "cannot publish the completed automation reports safely"
    }
    report_output_paths_are_current || {
        REPORT_WRITE_ERROR=1
        die "output directory path changed while publishing automation reports: $OUTPUT_PARENT"
    }
    AUTOMATION_REPORTS_COMMITTED=1
    debug_emit report_publication status published mode automation total "$COUNT_TOTAL"
fi
debug_emit report_validation status passed total "$COUNT_TOTAL"
console_emit "markdown_report=$REPORT_MARKDOWN_OUTPUT_PATH"
console_emit "jsonl_report=$REPORT_JSONL_OUTPUT_PATH"

scan_epoch_end
scanner_exit_code
scanner_status=$?
debug_emit_scan_end "$scanner_status"
exit "$scanner_status"
