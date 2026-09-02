# shellcheck shell=bash

# Core runtime and reporting helpers for the KISA CCE Linux scanner.

KISA_CCE_VERSION="${KISA_CCE_VERSION:?KISA_CCE_VERSION must be loaded from data/VERSION}"
KISA_CCE_GUIDE_BASE="https://kreonet.github.io/kisa-cce-guide-web"
SCAN_ROOT="${SCAN_ROOT:-/}"
RUNTIME_MODE="${RUNTIME_MODE:-auto}"
OUTPUT_PARENT="${OUTPUT_PARENT:-}"
SELECTED_CHECKS="${SELECTED_CHECKS:-}"
# shellcheck disable=SC2034
ORIGINAL_PATH="${KISA_CCE_CALLER_PATH:-${PATH:-}}"
# shellcheck disable=SC2034
ORIGINAL_UMASK="${KISA_CCE_CALLER_UMASK:-$(umask)}"

PLATFORM_ID=""
PLATFORM_VERSION=""
PLATFORM_NAME=""
SCRATCH_DIR=""
REPORT_TEXT=""
REPORT_JSONL=""
RESULT_STATUS=""
RESULT_SUMMARY=""
RESULT_EVIDENCE=""
RESULT_APPLICABLE="true"

COUNT_GOOD=0
COUNT_VULNERABLE=0
COUNT_MANUAL=0
COUNT_NOT_APPLICABLE=0
COUNT_ERROR=0
COUNT_TOTAL=0
REPORT_WRITE_ERROR=0

export LC_ALL=C
export LANG=C
PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
umask 077

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 2
}

warn() {
    printf 'WARNING: %s\n' "$*" >&2
}

trim() {
    awk '{$1=$1; print}'
}

fs_path() {
    local logical_path="$1"
    local physical_path=""
    local probe_parent=""
    local canonical_parent=""
    local canonical_root=""
    local resolved_path=""

    case "$logical_path" in
        /*) ;;
        *) return 2 ;;
    esac
    case "$logical_path" in
        *$'\n'*|*$'\r'*|*$'\t'*|*/../*|*/..|*/./*|*/.) return 2 ;;
    esac

    if [ "$SCAN_ROOT" = "/" ]; then
        printf '%s\n' "$logical_path"
    else
        physical_path="${SCAN_ROOT%/}${logical_path}"
        canonical_root="$(CDPATH='' cd -P -- "$SCAN_ROOT" 2>/dev/null && pwd)" || return 2
        probe_parent="${physical_path%/*}"
        while [ ! -d "$probe_parent" ] && [ "$probe_parent" != "${probe_parent%/*}" ]; do
            probe_parent="${probe_parent%/*}"
        done
        canonical_parent="$(CDPATH='' cd -P -- "$probe_parent" 2>/dev/null && pwd)" || return 2
        case "$canonical_parent" in
            "$canonical_root"|"$canonical_root"/*) ;;
            *) return 2 ;;
        esac

        if [ -L "$physical_path" ] && declare -F resolve_rooted_path >/dev/null 2>&1; then
            resolved_path="$(resolve_rooted_path "$physical_path" file 2>/dev/null || true)"
            [ -n "$resolved_path" ] || resolved_path="$(resolve_rooted_path "$physical_path" directory 2>/dev/null || true)"
            [ -n "$resolved_path" ] || return 2
            printf '%s\n' "$resolved_path"
        else
            printf '%s\n' "$physical_path"
        fi
    fi
}

display_path() {
    local physical_path="$1"
    local canonical_root=""

    if [ "$SCAN_ROOT" != "/" ]; then
        canonical_root="$(CDPATH='' cd -P -- "$SCAN_ROOT" 2>/dev/null && pwd)"
        case "$physical_path" in
            "${SCAN_ROOT%/}"/*) printf '/%s\n' "${physical_path#"${SCAN_ROOT%/}"/}" ;;
            "$canonical_root"/*) printf '/%s\n' "${physical_path#"$canonical_root"/}" ;;
            *) printf '%s\n' "$physical_path" ;;
        esac
    else
        printf '%s\n' "$physical_path"
    fi
}

runtime_enabled() {
    [ "$SCAN_ROOT" = "/" ] || return 1
    [ "$RUNTIME_MODE" != "off" ] || return 1
    return 0
}

trusted_command() {
    local command_name="$1"
    local candidate=""
    local candidate_owner=""
    local candidate_mode=""
    local resolved_candidate=""

    runtime_enabled || return 1

    for candidate in \
        "/usr/sbin/$command_name" \
        "/usr/bin/$command_name" \
        "/sbin/$command_name" \
        "/bin/$command_name"; do
        [ -x "$candidate" ] || continue
        resolved_candidate="$candidate"
        if [ -x /usr/bin/readlink ]; then
            resolved_candidate="$(/usr/bin/readlink -f -- "$candidate" 2>/dev/null || printf '%s' "$candidate")"
        fi
        candidate_owner="$(stat_owner "$resolved_candidate" 2>/dev/null || true)"
        candidate_mode="$(stat_mode "$resolved_candidate" 2>/dev/null || true)"
        [ "$candidate_owner" = "root" ] || continue
        mode_has_untrusted_write "$candidate_mode" && continue
        trusted_parent_chain "$resolved_candidate" || continue
        printf '%s\n' "$resolved_candidate"
        return 0
    done

    return 1
}

trusted_parent_chain() {
    local path="$1"
    local parent="${path%/*}"
    local owner=""
    local mode=""

    while [ -n "$parent" ]; do
        owner="$(stat_owner "$parent" 2>/dev/null || true)"
        mode="$(stat_mode "$parent" 2>/dev/null || true)"
        [ "$owner" = "root" ] || return 1
        mode_has_untrusted_write "$mode" && return 1
        [ "$parent" = "/" ] && return 0
        parent="${parent%/*}"
        [ -n "$parent" ] || parent="/"
    done
    return 1
}

capture_command() {
    local command_name="$1"
    shift
    local command_path=""

    command_path="$(trusted_command "$command_name")" || return 127
    "$command_path" "$@"
}

stat_owner() {
    local path="$1"
    local stat_path=""

    if command -v stat >/dev/null 2>&1; then
        stat_path="$(command -v stat)"
    else
        return 127
    fi

    "$stat_path" -Lc '%U' -- "$path" 2>/dev/null || "$stat_path" -f '%Su' -- "$path" 2>/dev/null
}

stat_uid() {
    local path="$1"
    local stat_path=""

    stat_path="$(command -v stat 2>/dev/null || true)"
    [ -n "$stat_path" ] || return 127
    "$stat_path" -Lc '%u' -- "$path" 2>/dev/null || "$stat_path" -f '%u' -- "$path" 2>/dev/null
}

stat_mode() {
    local path="$1"
    local stat_path=""

    stat_path="$(command -v stat 2>/dev/null || true)"
    [ -n "$stat_path" ] || return 127
    "$stat_path" -Lc '%a' -- "$path" 2>/dev/null || "$stat_path" -f '%Lp' -- "$path" 2>/dev/null
}

mode_to_decimal() {
    local mode="$1"

    case "$mode" in
        ''|*[!0-7]*) return 2 ;;
    esac
    printf '%d\n' "$((8#$mode))"
}

mode_has_untrusted_write() {
    local mode="$1"
    local decimal_mode=""

    decimal_mode="$(mode_to_decimal "$mode")" || return 0
    [ $((decimal_mode & 0022)) -ne 0 ]
}

mode_is_at_most() {
    local mode="$1"
    local allowed="$2"
    local decimal_mode=""
    local decimal_allowed=""

    decimal_mode="$(mode_to_decimal "$mode")" || return 1
    decimal_allowed="$(mode_to_decimal "$allowed")" || return 1
    [ $((decimal_mode & ~decimal_allowed & 07777)) -eq 0 ]
}

mode_other_writable() {
    local mode="$1"
    local decimal_mode=""

    decimal_mode="$(mode_to_decimal "$mode")" || return 1
    [ $((decimal_mode & 0002)) -ne 0 ]
}

mode_group_or_other_writable() {
    local mode="$1"
    local decimal_mode=""

    decimal_mode="$(mode_to_decimal "$mode")" || return 1
    [ $((decimal_mode & 0022)) -ne 0 ]
}

mode_has_group_or_other_permissions() {
    local mode="$1"
    local decimal_mode=""

    decimal_mode="$(mode_to_decimal "$mode")" || return 0
    [ $((decimal_mode & 0077)) -ne 0 ]
}

read_os_release_value() {
    local key="$1"
    local os_release=""

    os_release="$(fs_path /etc/os-release)"
    [ -r "$os_release" ] || return 1

    awk -F= -v target="$key" '
        $1 == target {
            value = substr($0, index($0, "=") + 1)
            if (value ~ /^".*"$/ || value ~ /^\047.*\047$/) {
                value = substr(value, 2, length(value) - 2)
            }
            print value
            exit
        }
    ' "$os_release"
}

detect_platform() {
    PLATFORM_ID="$(read_os_release_value ID 2>/dev/null || true)"
    PLATFORM_VERSION="$(read_os_release_value VERSION_ID 2>/dev/null || true)"
    PLATFORM_NAME="$(read_os_release_value PRETTY_NAME 2>/dev/null || true)"

    case "$PLATFORM_ID:$PLATFORM_VERSION" in
        ubuntu:26.04)
            return 0
            ;;
        rhel:10|rhel:10.*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

set_result() {
    local status="$1"
    local summary="$2"
    local evidence="${3:-}"
    local applicable="${4:-true}"

    case "$status" in
        GOOD|VULNERABLE|MANUAL|NOT_APPLICABLE|ERROR) ;;
        *)
            status="ERROR"
            summary="검사 함수가 유효하지 않은 상태를 반환했습니다."
            evidence="invalid_status=$1"
            applicable="true"
            ;;
    esac

    case "$applicable" in
        true|false) ;;
        *)
            status="ERROR"
            summary="검사 함수가 유효하지 않은 적용 여부를 반환했습니다."
            evidence="invalid_applicable=$applicable"
            applicable="true"
            ;;
    esac

    RESULT_STATUS="$status"
    RESULT_SUMMARY="$summary"
    RESULT_EVIDENCE="$(printf '%s' "$evidence" | normalize_evidence_separators | sanitize_text | normalize_utf8 | redact_evidence | limit_evidence)"
    RESULT_APPLICABLE="$applicable"
}

normalize_evidence_separators() {
    awk '{gsub(/\\n/, "\n"); print}'
}

sanitize_text() {
    LC_ALL=C tr -d '\000-\010\013\014\016-\037\177'
}

normalize_utf8() {
    if [ -x /usr/bin/iconv ]; then
        /usr/bin/iconv -f UTF-8 -t UTF-8 -c
    else
        cat
    fi
}

redact_evidence() {
    sed -E \
        -e 's/(\$[A-Za-z0-9./]+\$)[A-Za-z0-9./$]+/\1[REDACTED_HASH]/g' \
        -e 's/^([[:space:]]*(rocommunity|rwcommunity|com2sec)[[:space:]]+)[^[:space:]]+/\1[REDACTED]/I' \
        -e 's/^([[:space:]]*createUser[[:space:]]+[^[:space:]]+).*/\1 [REDACTED]/I' \
        -e 's/((password|passwd|secret|token|passphrase)[[:space:]]*[:=][[:space:]]*)[^[:space:]]+/\1[REDACTED]/Ig'
}

limit_evidence() {
    awk 'BEGIN { remaining = 8192 }
        {
            if (remaining <= 0) next
            line = $0
            if (length(line) > remaining) line = substr(line, 1, remaining)
            print line
            remaining -= length(line) + 1
        }'
}

json_escape() {
    sanitize_text | normalize_utf8 | awk 'BEGIN { ORS=""; first=1 }
        {
            gsub(/\\/, "\\\\")
            gsub(/\"/, "\\\"")
            gsub(/\t/, "\\t")
            gsub(/\r/, "\\r")
            if (!first) printf "\\n"
            printf "%s", $0
            first=0
        }'
}

increment_status() {
    case "$1" in
        GOOD) COUNT_GOOD=$((COUNT_GOOD + 1)) ;;
        VULNERABLE) COUNT_VULNERABLE=$((COUNT_VULNERABLE + 1)) ;;
        MANUAL) COUNT_MANUAL=$((COUNT_MANUAL + 1)) ;;
        NOT_APPLICABLE) COUNT_NOT_APPLICABLE=$((COUNT_NOT_APPLICABLE + 1)) ;;
        ERROR) COUNT_ERROR=$((COUNT_ERROR + 1)) ;;
    esac
    COUNT_TOTAL=$((COUNT_TOTAL + 1))
}

record_result() {
    local code="$1"
    local category="$2"
    local severity="$3"
    local title="$4"
    local criterion_slug=""
    local criterion_url=""
    local escaped_title=""
    local escaped_summary=""
    local escaped_evidence=""

    criterion_slug="$(printf '%s' "$code" | tr '[:upper:]' '[:lower:]')"
    criterion_url="${KISA_CCE_GUIDE_BASE}/unix/${criterion_slug}/"
    if ! {
        printf '[%s]SSSSS\n' "$code"
        printf '제목: %s\n' "$title"
        printf '분류: %s\n' "$category"
        printf '중요도: %s\n' "$severity"
        printf '판정: %s\n' "$RESULT_STATUS"
        printf '적용 여부: %s\n' "$RESULT_APPLICABLE"
        printf '요약: %s\n' "$RESULT_SUMMARY"
        if [ -n "$RESULT_EVIDENCE" ]; then
            printf '[근거]\n%s\n' "$RESULT_EVIDENCE"
        fi
        printf '기준: %s\n' "$criterion_url"
        printf '[%s]EEEEE\n' "$code"
        printf '[%s]RRRRR : %s\n\n' "$code" "$RESULT_STATUS"
    } >> "$REPORT_TEXT"; then
        REPORT_WRITE_ERROR=1
        return 1
    fi

    escaped_title="$(printf '%s' "$title" | json_escape)"
    escaped_summary="$(printf '%s' "$RESULT_SUMMARY" | json_escape)"
    escaped_evidence="$(printf '%s' "$RESULT_EVIDENCE" | json_escape)"
    if ! printf '{"code":"%s","category":"%s","severity":"%s","title":"%s","status":"%s","applicable":%s,"summary":"%s","evidence":"%s","criterion_url":"%s"}\n' \
        "$code" "$category" "$severity" "$escaped_title" "$RESULT_STATUS" "$RESULT_APPLICABLE" \
        "$escaped_summary" "$escaped_evidence" "$criterion_url" >> "$REPORT_JSONL"; then
        REPORT_WRITE_ERROR=1
        return 1
    fi

    increment_status "$RESULT_STATUS"
    return 0
}

check_selected() {
    local code="$1"

    [ -z "$SELECTED_CHECKS" ] && return 0
    case ",${SELECTED_CHECKS}," in
        *",${code},"*) return 0 ;;
        *) return 1 ;;
    esac
}

run_one_check() {
    local code="$1"
    local category="$2"
    local severity="$3"
    local title="$4"
    local function_name=""

    check_selected "$code" || return 0

    function_name="check_$(printf '%s' "$code" | tr '[:upper:]-' '[:lower:]_')"
    RESULT_STATUS=""
    RESULT_SUMMARY=""
    RESULT_EVIDENCE=""
    RESULT_APPLICABLE="true"

    if declare -F "$function_name" >/dev/null 2>&1; then
        "$function_name"
    else
        set_result ERROR "검사 함수가 구현되지 않았습니다." "function=$function_name"
    fi

    if [ -z "$RESULT_STATUS" ]; then
        set_result ERROR "검사 함수가 결과를 반환하지 않았습니다." "function=$function_name"
    fi

    if ! record_result "$code" "$category" "$severity" "$title"; then
        warn "보고서 기록에 실패했습니다: $code"
        return 1
    fi
    return 0
}

initialize_workspace() {
    local default_parent=""
    local output_uid=""
    local current_uid=""
    local parent_mode=""
    local timestamp=""
    local hostname_value=""

    if [ -z "$OUTPUT_PARENT" ]; then
        if [ "$(id -u)" -eq 0 ]; then
            default_parent="/var/log/kisa-cce-scanner"
        else
            default_parent="/tmp/kisa-cce-scanner-$(id -u)"
        fi
        OUTPUT_PARENT="$default_parent"
    fi

    [ ! -L "$OUTPUT_PARENT" ] || die "출력 디렉터리가 심볼릭 링크입니다: $OUTPUT_PARENT"
    if [ -e "$OUTPUT_PARENT" ]; then
        [ -d "$OUTPUT_PARENT" ] || die "출력 경로가 디렉터리가 아닙니다: $OUTPUT_PARENT"
    else
        mkdir -p -- "$OUTPUT_PARENT" || die "출력 디렉터리를 만들 수 없습니다: $OUTPUT_PARENT"
        chmod 0700 "$OUTPUT_PARENT" || die "새 출력 디렉터리 권한을 설정할 수 없습니다: $OUTPUT_PARENT"
    fi

    current_uid="$(id -u)"
    output_uid="$(stat_uid "$OUTPUT_PARENT" 2>/dev/null || true)"
    parent_mode="$(stat_mode "$OUTPUT_PARENT" 2>/dev/null || true)"
    [ "$output_uid" = "$current_uid" ] || die "출력 디렉터리 소유자가 현재 사용자와 다릅니다."
    mode_has_group_or_other_permissions "$parent_mode" && die "출력 디렉터리는 소유자만 접근 가능한 0700 이하 권한이어야 합니다."

    SCRATCH_DIR="$(mktemp -d "$OUTPUT_PARENT/.run.XXXXXXXX")" || die "안전한 임시 디렉터리를 만들 수 없습니다."
    chmod 0700 "$SCRATCH_DIR" || die "임시 디렉터리 권한을 설정할 수 없습니다."

    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    hostname_value="$(hostname 2>/dev/null | tr -cd 'A-Za-z0-9._-' | cut -c1-63)"
    [ -n "$hostname_value" ] || hostname_value="host"

    REPORT_TEXT="$(mktemp "$OUTPUT_PARENT/kisa-cce-${hostname_value}-${timestamp}.txt.XXXXXXXX")" || die "텍스트 보고서를 만들 수 없습니다."
    REPORT_JSONL="$(mktemp "$OUTPUT_PARENT/kisa-cce-${hostname_value}-${timestamp}.jsonl.XXXXXXXX")" || die "JSONL 보고서를 만들 수 없습니다."
    chmod 0600 "$REPORT_TEXT" "$REPORT_JSONL" || die "보고서 권한을 설정할 수 없습니다."
}

cleanup_workspace() {
    if [ -n "$SCRATCH_DIR" ] && [ -d "$SCRATCH_DIR" ]; then
        rm -rf -- "$SCRATCH_DIR"
    fi
}

write_report_header() {
    if ! {
        printf 'KISA CCE 2026 Linux Security Scanner\n'
        printf 'scanner_version: %s\n' "$KISA_CCE_VERSION"
        printf 'platform: %s\n' "$PLATFORM_NAME"
        printf 'platform_id: %s\n' "$PLATFORM_ID"
        printf 'platform_version: %s\n' "$PLATFORM_VERSION"
        printf 'scan_root: %s\n' "$SCAN_ROOT"
        printf 'runtime_collection: %s\n' "$RUNTIME_MODE"
        printf 'started_at: %s\n\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } >> "$REPORT_TEXT"; then
        REPORT_WRITE_ERROR=1
        return 1
    fi
    return 0
}

write_report_summary() {
    if ! {
        printf 'SUMMARY\n'
        printf 'total: %d\n' "$COUNT_TOTAL"
        printf 'good: %d\n' "$COUNT_GOOD"
        printf 'vulnerable: %d\n' "$COUNT_VULNERABLE"
        printf 'manual: %d\n' "$COUNT_MANUAL"
        printf 'not_applicable: %d\n' "$COUNT_NOT_APPLICABLE"
        printf 'error: %d\n' "$COUNT_ERROR"
        printf 'completed_at: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } >> "$REPORT_TEXT"; then
        REPORT_WRITE_ERROR=1
        return 1
    fi

    if ! printf '{"type":"summary","total":%d,"good":%d,"vulnerable":%d,"manual":%d,"not_applicable":%d,"error":%d}\n' \
        "$COUNT_TOTAL" "$COUNT_GOOD" "$COUNT_VULNERABLE" "$COUNT_MANUAL" "$COUNT_NOT_APPLICABLE" "$COUNT_ERROR" >> "$REPORT_JSONL"
    then
        REPORT_WRITE_ERROR=1
        return 1
    fi
    return 0
}

validate_reports() {
    local expected_json_lines=$((COUNT_TOTAL + 1))
    local actual_json_lines=""
    local text_result_count=""

    [ "$REPORT_WRITE_ERROR" -eq 0 ] || return 1
    [ -s "$REPORT_TEXT" ] && [ -s "$REPORT_JSONL" ] || return 1
    [ "$(stat_uid "$REPORT_TEXT" 2>/dev/null || true)" = "$(id -u)" ] || return 1
    [ "$(stat_uid "$REPORT_JSONL" 2>/dev/null || true)" = "$(id -u)" ] || return 1
    [ "$(stat_mode "$REPORT_TEXT" 2>/dev/null || true)" = "600" ] || return 1
    [ "$(stat_mode "$REPORT_JSONL" 2>/dev/null || true)" = "600" ] || return 1
    actual_json_lines="$(wc -l < "$REPORT_JSONL" | tr -d '[:space:]')"
    [ "$actual_json_lines" = "$expected_json_lines" ] || return 1
    text_result_count="$(grep -Ec '^\[U-[0-9]{2}\]RRRRR : ' "$REPORT_TEXT")"
    [ "$text_result_count" = "$COUNT_TOTAL" ] || return 1
    return 0
}

scanner_exit_code() {
    if [ "$REPORT_WRITE_ERROR" -gt 0 ]; then
        return 2
    fi
    if [ "$COUNT_ERROR" -gt 0 ]; then
        return 2
    fi
    if [ "$COUNT_VULNERABLE" -gt 0 ]; then
        return 1
    fi
    return 0
}
