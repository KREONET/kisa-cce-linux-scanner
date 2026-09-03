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
SCANNER_LIBRARY_DIR="$(CDPATH='' cd -P -- "$source_parent" && pwd)" || exit 2
unset source_parent

bootstrap_die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 2
}

select_runtime_layout() {
    local candidate_root=""
    local candidate_data_dir=""

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
            bootstrap_die "스캐너 라이브러리 경로를 판별할 수 없습니다: $SCANNER_LIBRARY_DIR"
            ;;
    esac

    if [ -r "$SCANNER_LIBRARY_DIR/core.sh" ] &&
        [ -r "$SCANNER_LIBRARY_DIR/resolvers.sh" ] &&
        [ -r "$candidate_data_dir/criteria.tsv" ] &&
        [ -r "$candidate_data_dir/VERSION" ]; then
        DATA_DIR="$candidate_data_dir"
        VERSION_FILE="$candidate_data_dir/VERSION"
        return 0
    fi

    bootstrap_die "스캐너 라이브러리 또는 판정 데이터를 찾을 수 없습니다: $candidate_root"
}

select_runtime_layout
CRITERIA_FILE="$DATA_DIR/criteria.tsv"
[ -r "$VERSION_FILE" ] || bootstrap_die "버전 파일을 읽을 수 없습니다: $VERSION_FILE"
IFS= read -r KISA_CCE_VERSION < "$VERSION_FILE" ||
    bootstrap_die "버전 파일을 읽을 수 없습니다: $VERSION_FILE"
case "$KISA_CCE_VERSION" in
    ''|*[!0-9A-Za-z.+~-]*) bootstrap_die "버전 파일 형식이 유효하지 않습니다: $VERSION_FILE" ;;
esac

# shellcheck disable=SC1091
. "$SCANNER_LIBRARY_DIR/core.sh"
# shellcheck disable=SC1091
. "$SCANNER_LIBRARY_DIR/resolvers.sh"

check_files=("$SCANNER_LIBRARY_DIR"/checks_*.sh)
if [ ! -e "${check_files[0]}" ]; then
    die "검사 그룹 파일을 찾을 수 없습니다: $SCANNER_LIBRARY_DIR/checks_*.sh"
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
EXPLAIN_SYSCTL_KEY=""

usage() {
    cat <<'EOF'
Usage: kisa-cce-scan [OPTIONS]

KISA CCE 2026 checks for supported Debian, Ubuntu, Enterprise Linux, and named derivative releases.
Base releases: Debian 12/13, Ubuntu 22.04/24.04/26.04, and RHEL 8.10/9.8/10.2.
Named derivatives are listed in the operator documentation and command manual.

Options:
  --root PATH              Inspect PATH as a root; --root / keeps live collection.
  --output-dir PATH        Store scan reports; validated but unused with --explain-sysctl.
  --checks U-01,U-02       Run only the comma-separated check codes.
  --no-runtime             Do not query live services, listeners, or sysctls.
  --explain-sysctl KEY     Explain the effective persistent and runtime value.
  --allow-unsupported      Continue when the detected platform is unsupported.
  -v, --verbose            Print platform, per-check status, and summary progress.
  -h, --help               Show this help text.
  --version                Show the scanner version.

Exit status:
  0  No scanner errors or vulnerable results were recorded.
  1  At least one vulnerable result was recorded.
  2  Invocation, platform, scanner, or report error; errors take precedence.
EOF
}

require_option_value() {
    local option_name="$1"
    local remaining_count="$2"
    local option_value="${3:-}"

    [ "$remaining_count" -ge 2 ] || die "$option_name 옵션에 값이 필요합니다."
    [ -n "$option_value" ] || die "$option_name 옵션에 값이 필요합니다."
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
        --no-runtime)
            RUNTIME_MODE="off"
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
        -h|--help)
            usage
            exit 0
            ;;
        --version)
            printf 'kisa-cce-scan %s\n' "$KISA_CCE_VERSION"
            exit 0
            ;;
        --)
            shift
            [ "$#" -eq 0 ] || die "위치 인수는 지원하지 않습니다: $1"
            ;;
        -*)
            die "알 수 없는 옵션입니다: $1"
            ;;
        *)
            die "위치 인수는 지원하지 않습니다: $1"
            ;;
    esac
done

case "$SCAN_ROOT" in
    /*) ;;
    *) die "--root는 절대 경로여야 합니다: $SCAN_ROOT" ;;
esac
case "$SCAN_ROOT" in
    *$'\n'*|*$'\r'*|*$'\t'*) die "--root 경로에 허용되지 않는 제어 문자가 포함되어 있습니다." ;;
esac
[ -d "$SCAN_ROOT" ] || die "검사 루트가 디렉터리가 아닙니다: $SCAN_ROOT"
canonical_root="$(CDPATH='' cd -P -- "$SCAN_ROOT" && pwd)" || die "검사 루트를 확인할 수 없습니다: $SCAN_ROOT"
SCAN_ROOT="$canonical_root"
unset canonical_root

if [ -n "$OUTPUT_PARENT" ]; then
    case "$OUTPUT_PARENT" in
        /*) ;;
        *) die "--output-dir는 절대 경로여야 합니다: $OUTPUT_PARENT" ;;
    esac
fi

if [ "$SCAN_ROOT" != "/" ]; then
    RUNTIME_MODE="off"
elif [ "$(id -u)" -ne 0 ]; then
    die "실시간 전체 검사는 root 권한이 필요합니다. 오프라인 분석은 --root를 사용하세요."
fi

validate_criteria() {
    [ -r "$CRITERIA_FILE" ] || die "판정 기준 파일을 읽을 수 없습니다: $CRITERIA_FILE"
    awk -F '\t' '
        NR == 1 {
            if ($0 != "code\tcategory\tseverity\ttitle") exit 2
            next
        }
        NF != 4 || $1 !~ /^U-[0-9][0-9]$/ || $2 == "" || $3 == "" || $4 == "" { exit 3 }
        seen[$1]++ { exit 4 }
        {
            count++
            if ($1 != sprintf("U-%02d", count)) exit 5
        }
        END { if (count != 67) exit 5 }
    ' "$CRITERIA_FILE" || die "판정 기준 파일 형식이 유효하지 않습니다."
}

normalize_selected_checks() {
    local raw_checks="$1"
    local normalized_checks=""
    local code=""
    local old_ifs="$IFS"

    [ -n "$raw_checks" ] || return 0
    raw_checks="$(printf '%s' "$raw_checks" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
    case "$raw_checks" in
        ''|,*|*,|*,,*) die "--checks 값은 비어 있지 않은 쉼표 구분 코드여야 합니다." ;;
    esac

    set -f
    IFS=,
    for code in $raw_checks; do
        case "$code" in
            U-[0-9][0-9]) ;;
            *) die "유효하지 않은 점검 코드입니다: $code" ;;
        esac
        awk -F '\t' -v target="$code" 'NR > 1 && $1 == target { found=1 } END { exit(found ? 0 : 1) }' "$CRITERIA_FILE" ||
            die "판정 기준에 없는 점검 코드입니다: $code"
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
    [ -z "$SELECTED_CHECKS" ] || die "--explain-sysctl과 --checks는 함께 사용할 수 없습니다."
    case "$EXPLAIN_SYSCTL_KEY" in
        ''|-*|*[!A-Za-z0-9_./-]*) die "유효하지 않은 sysctl 키입니다: $EXPLAIN_SYSCTL_KEY" ;;
    esac
fi

if ! detect_platform; then
    if [ "$ALLOW_UNSUPPORTED" -eq 1 ]; then
        warn "지원되지 않은 플랫폼에서 계속합니다: ${PLATFORM_ID:-unknown} ${PLATFORM_VERSION:-unknown}"
    else
        die "지원되지 않은 플랫폼입니다: ${PLATFORM_ID:-unknown} ${PLATFORM_VERSION:-unknown}. 지원 행렬은 --help와 운영 문서를 확인하세요."
    fi
fi

verbose "platform=${PLATFORM_ID:-unknown} version=${PLATFORM_VERSION:-unknown} family=${PLATFORM_FAMILY:-unknown} root=${SCAN_ROOT} runtime=${RUNTIME_MODE}"

trap cleanup_workspace EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -n "$EXPLAIN_SYSCTL_KEY" ]; then
    SCRATCH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-explain.XXXXXXXX")" || die "안전한 임시 디렉터리를 만들 수 없습니다."
    chmod 0700 "$SCRATCH_DIR" || die "임시 디렉터리 권한을 설정할 수 없습니다."
    sysctl_explain "$EXPLAIN_SYSCTL_KEY" || die "sysctl 설정 또는 런타임 값을 신뢰성 있게 확인하지 못했습니다."
    exit 0
fi

initialize_workspace
write_report_header || die "보고서 헤더를 기록하지 못했습니다."

while IFS=$'\t' read -r code category severity title || [ -n "$code" ]; do
    [ "$code" = "code" ] && continue
    run_one_check "$code" "$category" "$severity" "$title" || true
done < "$CRITERIA_FILE"

write_report_summary || die "보고서 요약을 기록하지 못했습니다."
verbose "summary total=${COUNT_TOTAL} good=${COUNT_GOOD} vulnerable=${COUNT_VULNERABLE} manual=${COUNT_MANUAL} not_applicable=${COUNT_NOT_APPLICABLE} error=${COUNT_ERROR}"
validate_reports || die "완성된 보고서의 무결성 검증에 실패했습니다."
if ! report_output_paths_are_current; then
    REPORT_WRITE_ERROR=1
    die "출력 디렉터리 경로가 검사 중 변경되었습니다: $OUTPUT_PARENT"
fi
printf 'text_report=%s\njsonl_report=%s\n' "$REPORT_TEXT_OUTPUT_PATH" "$REPORT_JSONL_OUTPUT_PATH"

scanner_exit_code
exit "$?"
