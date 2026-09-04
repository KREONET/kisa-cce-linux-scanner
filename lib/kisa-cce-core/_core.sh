# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash
# shellcheck disable=SC2034

# Core runtime and reporting helpers for the KISA CCE Linux scanner.

KISA_CCE_VERSION="${KISA_CCE_VERSION:?KISA_CCE_VERSION must be loaded from data/VERSION}"
KISA_CCE_GUIDE_BASE="https://kreonet.github.io/kisa-cce-guide-web"
SCAN_ROOT="${SCAN_ROOT:-/}"
RUNTIME_MODE="${RUNTIME_MODE:-auto}"
OUTPUT_PARENT="${OUTPUT_PARENT:-}"
SELECTED_CHECKS="${SELECTED_CHECKS:-}"
VERBOSE="${VERBOSE:-0}"
DEBUG="${DEBUG:-0}"
SCAN_MODE="${SCAN_MODE:-audit}"
POLICY_DIRECTORY="${POLICY_DIRECTORY:-}"
EVIDENCE_BUNDLE_PATH="${EVIDENCE_BUNDLE_PATH:-}"
EVIDENCE_BUNDLE_ACTIVE="${EVIDENCE_BUNDLE_ACTIVE:-0}"
EVIDENCE_MAX_AGE_SECONDS="${EVIDENCE_MAX_AGE_SECONDS:-3600}"
EVIDENCE_AGE_SECONDS="${EVIDENCE_AGE_SECONDS:-}"
# shellcheck disable=SC2034
ORIGINAL_PATH="${KISA_CCE_CALLER_PATH:-${PATH:-}}"
# shellcheck disable=SC2034
ORIGINAL_UMASK="${KISA_CCE_CALLER_UMASK:-$(umask)}"

PLATFORM_ID=""
PLATFORM_ID_LIKE=""
PLATFORM_VERSION=""
PLATFORM_NAME=""
PLATFORM_FAMILY=""
PLATFORM_BASE_ID=""
PLATFORM_BASE_VERSION=""
PLATFORM_UBUNTU_CODENAME=""
SCRATCH_DIR=""
# REPORT_TEXT is the descriptor-anchored path of the human-readable Markdown report.
REPORT_TEXT=""
REPORT_JSONL=""
REPORT_MARKDOWN_OUTPUT_PATH=""
REPORT_JSONL_OUTPUT_PATH=""
REPORT_MARKDOWN_BODY=""
REPORT_PRIORITY_ERROR=""
REPORT_PRIORITY_VULNERABLE=""
REPORT_PRIORITY_MANUAL=""
AUTOMATION_REPORTS_COMMITTED=0
AUTOMATION_MARKDOWN_MOVED=0
AUTOMATION_JSONL_MOVED=0
AUTOMATION_MARKDOWN_PUBLISHED_PATH=""
AUTOMATION_JSONL_PUBLISHED_PATH=""
OUTPUT_DIRECTORY_FD=""
OUTPUT_DIRECTORY_FD_PATH=""
OUTPUT_DIRECTORY_DEVICE_INODE=""
RESULT_STATUS=""
RESULT_TECHNICAL_STATUS=""
RESULT_DECISION_BASIS=""
RESULT_REVIEW_ID=""
RESULT_ATTESTATION_TICKET=""
RESULT_ATTESTATION_APPROVER=""
RESULT_ATTESTATION_EXPIRES=""
RESULT_SUMMARY=""
RESULT_EVIDENCE=""
RESULT_APPLICABLE="true"

COUNT_GOOD=0
COUNT_VULNERABLE=0
COUNT_MANUAL=0
COUNT_NOT_APPLICABLE=0
COUNT_ERROR=0
COUNT_TOTAL=0
COUNT_POLICY_RESOLVED=0
REPORT_WRITE_ERROR=0

REPORT_LABEL_REPORT_TITLE="KISA CCE 2026 Linux 보안 점검 보고서"
REPORT_LABEL_SCAN_INFORMATION="점검 정보"
REPORT_LABEL_FIELD="항목"
REPORT_LABEL_VALUE="값"
REPORT_LABEL_CATEGORY="분류"
REPORT_LABEL_SEVERITY="중요도"
REPORT_LABEL_TECHNICAL_STATUS="기술 판정"
REPORT_LABEL_FINAL_STATUS="최종 판정"
REPORT_LABEL_DECISION_BASIS="판정 근거"
REPORT_LABEL_APPLICABLE="적용 여부"
REPORT_LABEL_REVIEW_ID="검토 ID"
REPORT_LABEL_ATTESTATION_TICKET="승인 티켓"
REPORT_LABEL_ATTESTATION_APPROVER="승인자"
REPORT_LABEL_ATTESTATION_EXPIRES="승인 만료일"
REPORT_LABEL_SUMMARY="요약"
REPORT_LABEL_EVIDENCE="근거"
REPORT_LABEL_REFERENCE="기준"
REPORT_LABEL_RESULT_SUMMARY="판정 요약"
REPORT_LABEL_STATUS="판정"
REPORT_LABEL_COUNT="개수"
REPORT_LABEL_TOTAL="전체"
REPORT_LABEL_GOOD="양호"
REPORT_LABEL_VULNERABLE="취약"
REPORT_LABEL_MANUAL="수동 확인"
REPORT_LABEL_NOT_APPLICABLE="해당 없음"
REPORT_LABEL_ERROR="오류"
REPORT_LABEL_POLICY_RESOLVED="정책 승인으로 확정"
REPORT_LABEL_COMPLETED_AT="완료 시각"

declare -A TRUSTED_COMMAND_CACHE=()
TRUSTED_COMMAND_CACHE_FILE=""
CANONICAL_SCAN_ROOT_SOURCE=""
CANONICAL_SCAN_ROOT_VALUE=""
CANONICAL_SCAN_ROOT_READY=0
LISTENER_SNAPSHOT_CACHE_ENABLED=0
LISTENER_SNAPSHOT_GENERATION=0
SCANNER_PROCESS_SECURITY_CONTEXT_READY=0
SCANNER_PROCESS_SECURITY_CONTEXT_WARNING_EMITTED=0
SCANNER_PROCESS_STATUS_FILE="/proc/self/status"
SCANNER_PROCESS_EUID_OVERRIDE=""
SCANNER_PROCESS_EUID=""
SCANNER_PROCESS_CAP_EFF=""
SCANNER_PROCESS_CAP_BND=""
SCANNER_PROCESS_NO_NEW_PRIVS=""
SCANNER_PROCESS_CAP_DAC_OVERRIDE="unknown"
SCANNER_PROCESS_CAP_DAC_READ_SEARCH="unknown"
SCANNER_PROCESS_ACCESS_CONTEXT="unknown"
DEBUG_OUTPUT_FD=""
DEBUG_OUTPUT_FD_OWNED=0
DEBUG_SCAN_STARTED=0
DEBUG_SCAN_ENDED=0

export LC_ALL=C
export LANG=C
PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
umask 077

console_uptime_into() {
    local __kisa_console_destination="$1"
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
    printf -v "$__kisa_console_destination" '%6s.%s' "$uptime_seconds" "$uptime_fraction"
}

console_emit() {
    local payload="${1-}"
    local line=""
    local sanitized_line=""
    local uptime=""

    while IFS= read -r line || [ -n "$line" ]; do
        console_sanitize_line_into "$line" sanitized_line
        console_uptime_into uptime
        printf '[%s] kisa-cce-scan: %s\n' "$uptime" "$sanitized_line"
    done <<< "$payload"
}

console_sanitize_line_into() {
    local input_line="$1"
    local destination_name="$2"
    local character=""
    local escaped_character=""
    local sanitized=""
    local index_value=0
    local byte_value=0

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|input_line|destination_name|character|escaped_character|sanitized|index_value|byte_value)
            return 2
            ;;
    esac
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

console_emit_lines() {
    local content="${1-}"
    local line=""

    while IFS= read -r line || [ -n "$line" ]; do
        console_emit "$line"
    done <<< "$content"
}

die() {
    console_emit "ERROR: $*" >&2
    debug_emit fatal criterion "${SCAN_ACTIVE_CRITERION:-none}" status error
    debug_emit_scan_end 2
    exit 2
}

warn() {
    console_emit "WARNING: $*" >&2
}

verbose() {
    [ "$VERBOSE" -eq 1 ] || return 0
    console_emit "$*" >&2
}

debug_initialize() {
    local __kisa_debug_probe_fd=""

    [ "$DEBUG" = "1" ] || return 0
    [ -z "$DEBUG_OUTPUT_FD" ] || return 0

    # The duplicate preserves the original diagnostic stream across locally suppressed stderr.
    if ! (exec {__kisa_debug_probe_fd}>&2) 2>/dev/null; then
        debug_activate_stderr_fallback
    elif ! exec {DEBUG_OUTPUT_FD}>&2; then
        debug_activate_stderr_fallback
    else
        DEBUG_OUTPUT_FD_OWNED=1
        DEBUG_SCAN_STARTED=1
    fi
    return 0
}

debug_activate_stderr_fallback() {
    DEBUG_OUTPUT_FD=2
    DEBUG_OUTPUT_FD_OWNED=0
    DEBUG_SCAN_STARTED=1
    warn "debug diagnostics could not preserve the original standard error; locally suppressed events may be unavailable"
}

debug_percent_encode_into() {
    local __kisa_debug_input="$1"
    local __kisa_debug_maximum_length="$2"
    local __kisa_debug_destination="$3"
    local __kisa_debug_truncated_destination="$4"
    local __kisa_debug_character=""
    local __kisa_debug_piece=""
    local __kisa_debug_encoded=""
    local __kisa_debug_byte_value=0
    local __kisa_debug_index=0
    local __kisa_debug_was_truncated=0

    case "$__kisa_debug_destination:$__kisa_debug_truncated_destination" in
        *[!A-Za-z0-9_:]*|:*|*:|__kisa_debug_*|*:__kisa_debug_*) return 0 ;;
    esac
    case "$__kisa_debug_maximum_length" in
        ''|*[!0-9]*) return 0 ;;
    esac

    # LC_ALL=C makes each substring operation consume exactly one input byte.
    for ((__kisa_debug_index = 0; __kisa_debug_index < ${#__kisa_debug_input}; __kisa_debug_index++)); do
        __kisa_debug_character="${__kisa_debug_input:__kisa_debug_index:1}"
        case "$__kisa_debug_character" in
            [A-Za-z0-9._~:/@+-])
                __kisa_debug_piece="$__kisa_debug_character"
                ;;
            *)
                printf -v __kisa_debug_byte_value '%d' "'$__kisa_debug_character"
                printf -v __kisa_debug_piece '%%%02X' "$__kisa_debug_byte_value"
                ;;
        esac
        if [ $((${#__kisa_debug_encoded} + ${#__kisa_debug_piece})) -gt "$__kisa_debug_maximum_length" ]; then
            __kisa_debug_was_truncated=1
            break
        fi
        __kisa_debug_encoded+="$__kisa_debug_piece"
    done

    printf -v "$__kisa_debug_destination" '%s' "$__kisa_debug_encoded"
    printf -v "$__kisa_debug_truncated_destination" '%d' "$__kisa_debug_was_truncated"
}

debug_emit() {
    local event_name="${1:-}"
    local payload=""
    local field_key=""
    local field_value=""
    local encoded_value=""
    local field_value_limit=0
    local field_truncated=0
    local event_truncated=0
    local event_content_limit=2036

    [ "$DEBUG" = "1" ] || return 0
    [ -n "$DEBUG_OUTPUT_FD" ] || return 0
    local -A seen_field_keys=([schema]=1 [event]=1 [truncated]=1)
    case "$event_name" in
        ''|[!a-z]*|*[!a-z0-9_]*) return 0 ;;
    esac
    shift
    [ $(( $# % 2 )) -eq 0 ] || return 0

    payload="DEBUG: schema=1 event=$event_name"
    [ "${#payload}" -le "$event_content_limit" ] || return 0
    while [ "$#" -gt 0 ]; do
        field_key="$1"
        field_value="$2"
        shift 2
        case "$field_key" in
            ''|[!a-z]*|*[!a-z0-9_]*) return 0 ;;
        esac
        [ -z "${seen_field_keys[$field_key]+present}" ] || return 0
        seen_field_keys["$field_key"]=1
        field_value_limit=$((255 - ${#field_key}))
        [ "$field_value_limit" -ge 0 ] || return 0
        encoded_value=""
        field_truncated=0
        debug_percent_encode_into "$field_value" "$field_value_limit" encoded_value field_truncated
        if [ $((${#payload} + ${#field_key} + ${#encoded_value} + 2)) -gt "$event_content_limit" ]; then
            event_truncated=1
            break
        fi
        payload+=" $field_key=$encoded_value"
        if [ "$field_truncated" -eq 1 ]; then
            event_truncated=1
        fi
    done
    if [ "$event_truncated" -eq 1 ]; then
        payload+=" truncated=1"
    fi

    console_emit "$payload" 1>&"$DEBUG_OUTPUT_FD" 2>/dev/null || true
    return 0
}

debug_emit_scan_end() {
    local exit_status="${1:-2}"

    [ "$DEBUG_SCAN_STARTED" -eq 1 ] || return 0
    [ "$DEBUG_SCAN_ENDED" -eq 0 ] || return 0
    DEBUG_SCAN_ENDED=1
    debug_emit scan_end \
        exit_status "$exit_status" \
        total "$COUNT_TOTAL" \
        good "$COUNT_GOOD" \
        vulnerable "$COUNT_VULNERABLE" \
        manual "$COUNT_MANUAL" \
        not_applicable "$COUNT_NOT_APPLICABLE" \
        error "$COUNT_ERROR"
}

debug_emit_signal_exit() {
    local signal_name="${1:-unknown}"
    local exit_status="${2:-2}"

    debug_emit termination_signal signal "$signal_name" exit_status "$exit_status"
    debug_emit_scan_end "$exit_status"
}

scanner_reset_process_security_context() {
    SCANNER_PROCESS_SECURITY_CONTEXT_READY=0
    SCANNER_PROCESS_SECURITY_CONTEXT_WARNING_EMITTED=0
    SCANNER_PROCESS_EUID=""
    SCANNER_PROCESS_CAP_EFF=""
    SCANNER_PROCESS_CAP_BND=""
    SCANNER_PROCESS_NO_NEW_PRIVS=""
    SCANNER_PROCESS_CAP_DAC_OVERRIDE="unknown"
    SCANNER_PROCESS_CAP_DAC_READ_SEARCH="unknown"
    SCANNER_PROCESS_ACCESS_CONTEXT="unknown"
}

scanner_collect_process_security_context() {
    local status_file="$SCANNER_PROCESS_STATUS_FILE"
    local effective_uid="${SCANNER_PROCESS_EUID_OVERRIDE:-${EUID:-}}"
    local field_name=""
    local field_value=""
    local low_nibble=""
    local low_bits=0

    [ "$SCANNER_PROCESS_SECURITY_CONTEXT_READY" -eq 0 ] || return 0
    SCANNER_PROCESS_SECURITY_CONTEXT_READY=1
    SCANNER_PROCESS_EUID="$effective_uid"

    if [ -r "$status_file" ]; then
        while IFS=: read -r field_name field_value; do
            case "$field_name" in
                CapEff)
                    read -r SCANNER_PROCESS_CAP_EFF _ <<< "$field_value"
                    ;;
                CapBnd)
                    read -r SCANNER_PROCESS_CAP_BND _ <<< "$field_value"
                    ;;
                NoNewPrivs)
                    read -r SCANNER_PROCESS_NO_NEW_PRIVS _ <<< "$field_value"
                    ;;
            esac
        done < "$status_file"
    fi

    if [ -n "$SCANNER_PROCESS_CAP_EFF" ] &&
        [[ "$SCANNER_PROCESS_CAP_EFF" != *[!0-9A-Fa-f]* ]]; then
        low_nibble="${SCANNER_PROCESS_CAP_EFF: -1}"
        low_bits=$((16#$low_nibble))
        if [ $((low_bits & 2)) -ne 0 ]; then
            SCANNER_PROCESS_CAP_DAC_OVERRIDE="present"
        else
            SCANNER_PROCESS_CAP_DAC_OVERRIDE="absent"
        fi
        if [ $((low_bits & 4)) -ne 0 ]; then
            SCANNER_PROCESS_CAP_DAC_READ_SEARCH="present"
        else
            SCANNER_PROCESS_CAP_DAC_READ_SEARCH="absent"
        fi
    fi

    case "$SCANNER_PROCESS_EUID" in
        0)
            if [ "$SCANNER_PROCESS_CAP_DAC_OVERRIDE" = "absent" ] &&
                [ "$SCANNER_PROCESS_CAP_DAC_READ_SEARCH" = "absent" ]; then
                SCANNER_PROCESS_ACCESS_CONTEXT="uid0_without_dac_read_capabilities"
            elif [ "$SCANNER_PROCESS_CAP_DAC_OVERRIDE" = "present" ] ||
                [ "$SCANNER_PROCESS_CAP_DAC_READ_SEARCH" = "present" ]; then
                SCANNER_PROCESS_ACCESS_CONTEXT="uid0_with_dac_read_capability"
            fi
            ;;
        ''|*[!0-9]*) ;;
        *) SCANNER_PROCESS_ACCESS_CONTEXT="non_root" ;;
    esac
}

scanner_process_security_context_evidence_into() {
    local destination_name="$1"
    local evidence_value=""

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|destination_name|evidence_value) return 2 ;;
    esac
    scanner_collect_process_security_context
    evidence_value="executor_euid=${SCANNER_PROCESS_EUID:-unavailable}
executor_access_context=${SCANNER_PROCESS_ACCESS_CONTEXT}
executor_cap_eff=${SCANNER_PROCESS_CAP_EFF:-unavailable}
executor_cap_bnd=${SCANNER_PROCESS_CAP_BND:-unavailable}
executor_cap_dac_override=${SCANNER_PROCESS_CAP_DAC_OVERRIDE}
executor_cap_dac_read_search=${SCANNER_PROCESS_CAP_DAC_READ_SEARCH}
executor_no_new_privs=${SCANNER_PROCESS_NO_NEW_PRIVS:-unavailable}"
    printf -v "$destination_name" '%s' "$evidence_value"
}

scanner_note_offline_access_context() {
    [ "$SCAN_ROOT" != "/" ] || return 0
    scanner_collect_process_security_context
    [ "$SCANNER_PROCESS_ACCESS_CONTEXT" = "uid0_without_dac_read_capabilities" ] || return 0
    [ "$SCANNER_PROCESS_SECURITY_CONTEXT_WARNING_EMITTED" -eq 0 ] || return 0
    SCANNER_PROCESS_SECURITY_CONTEXT_WARNING_EMITTED=1
    verbose "access_context=uid0_without_dac_read_capabilities cap_eff=${SCANNER_PROCESS_CAP_EFF:-unavailable} no_new_privs=${SCANNER_PROCESS_NO_NEW_PRIVS:-unavailable} warning=restricted paths may make offline results incomplete"
}

initialize_report_labels() {
    declare -F i18n_ui_label_into >/dev/null 2>&1 || return 2
    i18n_ui_label_into report_title REPORT_LABEL_REPORT_TITLE || return 2
    i18n_ui_label_into scan_information REPORT_LABEL_SCAN_INFORMATION || return 2
    i18n_ui_label_into field REPORT_LABEL_FIELD || return 2
    i18n_ui_label_into value REPORT_LABEL_VALUE || return 2
    i18n_ui_label_into category REPORT_LABEL_CATEGORY || return 2
    i18n_ui_label_into severity REPORT_LABEL_SEVERITY || return 2
    i18n_ui_label_into technical_status REPORT_LABEL_TECHNICAL_STATUS || return 2
    i18n_ui_label_into final_status REPORT_LABEL_FINAL_STATUS || return 2
    i18n_ui_label_into decision_basis REPORT_LABEL_DECISION_BASIS || return 2
    i18n_ui_label_into applicable REPORT_LABEL_APPLICABLE || return 2
    i18n_ui_label_into review_id REPORT_LABEL_REVIEW_ID || return 2
    i18n_ui_label_into attestation_ticket REPORT_LABEL_ATTESTATION_TICKET || return 2
    i18n_ui_label_into attestation_approver REPORT_LABEL_ATTESTATION_APPROVER || return 2
    i18n_ui_label_into attestation_expires REPORT_LABEL_ATTESTATION_EXPIRES || return 2
    i18n_ui_label_into summary REPORT_LABEL_SUMMARY || return 2
    i18n_ui_label_into evidence REPORT_LABEL_EVIDENCE || return 2
    i18n_ui_label_into reference REPORT_LABEL_REFERENCE || return 2
    i18n_ui_label_into result_summary REPORT_LABEL_RESULT_SUMMARY || return 2
    i18n_ui_label_into status REPORT_LABEL_STATUS || return 2
    i18n_ui_label_into count REPORT_LABEL_COUNT || return 2
    i18n_ui_label_into total REPORT_LABEL_TOTAL || return 2
    i18n_ui_label_into good REPORT_LABEL_GOOD || return 2
    i18n_ui_label_into vulnerable REPORT_LABEL_VULNERABLE || return 2
    i18n_ui_label_into manual REPORT_LABEL_MANUAL || return 2
    i18n_ui_label_into not_applicable REPORT_LABEL_NOT_APPLICABLE || return 2
    i18n_ui_label_into error REPORT_LABEL_ERROR || return 2
    i18n_ui_label_into policy_resolved REPORT_LABEL_POLICY_RESOLVED || return 2
    i18n_ui_label_into completed_at REPORT_LABEL_COMPLETED_AT || return 2
}

trim() {
    local input_line=""
    local field=""
    local field_separator=""
    local -a fields=()

    while IFS= read -r input_line || [ -n "$input_line" ]; do
        fields=()
        IFS=$' \t\n' read -r -a fields <<< "$input_line"
        field_separator=""
        for field in "${fields[@]}"; do
            printf '%s%s' "$field_separator" "$field"
            field_separator=" "
        done
        printf '\n'
    done
}

canonical_directory_into() {
    local __kisa_cd_directory="$1"
    local __kisa_cd_destination="$2"
    local __kisa_cd_saved_pwd="$PWD"
    local __kisa_cd_saved_oldpwd="${OLDPWD:-}"
    local __kisa_cd_oldpwd_was_set=0
    local __kisa_cd_result=""
    local __kisa_cd_restore_fd=""
    local __kisa_cd_restore_fd_open=0

    case "$__kisa_cd_destination" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|__kisa_cd_*) return 2 ;;
    esac
    printf -v "$__kisa_cd_destination" '%s' ""
    [ "${OLDPWD+x}" = "x" ] && __kisa_cd_oldpwd_was_set=1
    # The directory descriptor restores the caller's actual location when its logical PWD cannot be reopened.
    if { exec {__kisa_cd_restore_fd}<.; } 2>/dev/null; then
        __kisa_cd_restore_fd_open=1
    fi

    if ! CDPATH='' builtin cd -P -- "$__kisa_cd_directory" 2>/dev/null; then
        if [ "$__kisa_cd_restore_fd_open" -eq 1 ]; then
            exec {__kisa_cd_restore_fd}<&-
        fi
        return 1
    fi
    __kisa_cd_result="$PWD"
    if ! CDPATH='' builtin cd -L -- "$__kisa_cd_saved_pwd" 2>/dev/null; then
        if [ "$__kisa_cd_restore_fd_open" -ne 1 ] ||
            { ! CDPATH='' builtin cd -P -- "/proc/self/fd/$__kisa_cd_restore_fd" 2>/dev/null &&
              ! CDPATH='' builtin cd -P -- "/dev/fd/$__kisa_cd_restore_fd" 2>/dev/null; }; then
            if [ "$__kisa_cd_restore_fd_open" -eq 1 ]; then
                exec {__kisa_cd_restore_fd}<&-
            fi
            return 1
        fi
        PWD="$__kisa_cd_saved_pwd"
    fi
    if [ "$__kisa_cd_restore_fd_open" -eq 1 ]; then
        exec {__kisa_cd_restore_fd}<&-
    fi
    if [ "$__kisa_cd_oldpwd_was_set" -eq 1 ]; then
        OLDPWD="$__kisa_cd_saved_oldpwd"
    else
        unset OLDPWD
    fi

    printf -v "$__kisa_cd_destination" '%s' "$__kisa_cd_result"
}

canonical_scan_root_into() {
    local __kisa_root_destination="$1"
    local __kisa_root_result=""

    case "$__kisa_root_destination" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|__kisa_root_*) return 2 ;;
    esac
    printf -v "$__kisa_root_destination" '%s' ""

    if [ "$CANONICAL_SCAN_ROOT_READY" -eq 1 ] &&
        [ "$CANONICAL_SCAN_ROOT_SOURCE" = "$SCAN_ROOT" ]; then
        printf -v "$__kisa_root_destination" '%s' "$CANONICAL_SCAN_ROOT_VALUE"
        return 0
    fi

    if ! canonical_directory_into "$SCAN_ROOT" __kisa_root_result; then
        CANONICAL_SCAN_ROOT_SOURCE=""
        CANONICAL_SCAN_ROOT_VALUE=""
        CANONICAL_SCAN_ROOT_READY=0
        return 1
    fi
    CANONICAL_SCAN_ROOT_SOURCE="$SCAN_ROOT"
    CANONICAL_SCAN_ROOT_VALUE="$__kisa_root_result"
    CANONICAL_SCAN_ROOT_READY=1
    printf -v "$__kisa_root_destination" '%s' "$__kisa_root_result"
}

fs_path_into() {
    local __kisa_fs_logical_path="$1"
    local __kisa_fs_destination="$2"
    local __kisa_fs_physical_path=""
    local __kisa_fs_probe_parent=""
    local __kisa_fs_canonical_parent=""
    local __kisa_fs_canonical_root=""
    local __kisa_fs_resolved_path=""

    case "$__kisa_fs_destination" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|__kisa_fs_*) return 2 ;;
    esac
    printf -v "$__kisa_fs_destination" '%s' ""
    case "$__kisa_fs_logical_path" in
        /*) ;;
        *) return 2 ;;
    esac
    case "$__kisa_fs_logical_path" in
        *$'\n'*|*$'\r'*|*$'\t'*|*/../*|*/..|*/./*|*/.) return 2 ;;
    esac

    if [ "$SCAN_ROOT" = "/" ]; then
        printf -v "$__kisa_fs_destination" '%s' "$__kisa_fs_logical_path"
    else
        __kisa_fs_physical_path="${SCAN_ROOT%/}${__kisa_fs_logical_path}"
        canonical_scan_root_into __kisa_fs_canonical_root || return 2
        __kisa_fs_probe_parent="${__kisa_fs_physical_path%/*}"
        while [ ! -d "$__kisa_fs_probe_parent" ] &&
            [ "$__kisa_fs_probe_parent" != "${__kisa_fs_probe_parent%/*}" ]; do
            __kisa_fs_probe_parent="${__kisa_fs_probe_parent%/*}"
        done
        canonical_directory_into "$__kisa_fs_probe_parent" __kisa_fs_canonical_parent || return 2
        case "$__kisa_fs_canonical_parent" in
            "$__kisa_fs_canonical_root"|"$__kisa_fs_canonical_root"/*) ;;
            *) return 2 ;;
        esac

        if [ -L "$__kisa_fs_physical_path" ] && declare -F resolve_rooted_path_into >/dev/null 2>&1; then
            if ! resolve_rooted_path_into "$__kisa_fs_physical_path" file_or_directory __kisa_fs_resolved_path 2>/dev/null; then
                return 2
            fi
            printf -v "$__kisa_fs_destination" '%s' "$__kisa_fs_resolved_path"
        else
            printf -v "$__kisa_fs_destination" '%s' "$__kisa_fs_physical_path"
        fi
    fi
}

fs_path() {
    local resolved_fs_path=""

    fs_path_into "$1" resolved_fs_path || return $?
    printf '%s\n' "$resolved_fs_path"
}

display_path_into() {
    local __kisa_display_physical_path="$1"
    local __kisa_display_destination="$2"
    local __kisa_display_canonical_root=""
    local __kisa_display_logical_path=""

    case "$__kisa_display_destination" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|__kisa_display_*) return 2 ;;
    esac
    printf -v "$__kisa_display_destination" '%s' ""

    if [ "$SCAN_ROOT" != "/" ]; then
        canonical_scan_root_into __kisa_display_canonical_root 2>/dev/null || __kisa_display_canonical_root=""
        case "$__kisa_display_physical_path" in
            "${SCAN_ROOT%/}"/*) __kisa_display_logical_path="/${__kisa_display_physical_path#"${SCAN_ROOT%/}"/}" ;;
            "$__kisa_display_canonical_root"/*)
                if [ -n "$__kisa_display_canonical_root" ]; then
                    __kisa_display_logical_path="/${__kisa_display_physical_path#"$__kisa_display_canonical_root"/}"
                else
                    __kisa_display_logical_path="$__kisa_display_physical_path"
                fi
                ;;
            *) __kisa_display_logical_path="$__kisa_display_physical_path" ;;
        esac
    else
        __kisa_display_logical_path="$__kisa_display_physical_path"
    fi
    printf -v "$__kisa_display_destination" '%s' "$__kisa_display_logical_path"
}

display_path() {
    local displayed_path=""

    display_path_into "$1" displayed_path || return $?
    printf '%s\n' "$displayed_path"
}

runtime_enabled() {
    [ "$SCAN_ROOT" = "/" ] || return 1
    [ "$RUNTIME_MODE" != "off" ] || return 1
    return 0
}

runtime_snapshot_available() {
    runtime_enabled && return 0
    [ "${EVIDENCE_BUNDLE_ACTIVE:-0}" -eq 1 ] && [ -n "${EVIDENCE_BUNDLE_DIRECTORY:-}" ]
}

resolve_trusted_command_path() {
    local command_name="$1"
    local candidate=""
    local candidate_owner=""
    local candidate_mode=""
    local resolved_candidate=""
    local cached_name=""
    local cached_candidate=""
    local cacheable=0

    case "$command_name" in
        ''|*[!A-Za-z0-9._+-]*) ;;
        *) cacheable=1 ;;
    esac
    if [ "$cacheable" -eq 1 ] &&
        [ "${TRUSTED_COMMAND_CACHE[$command_name]+present}" = "present" ]; then
        cached_candidate="${TRUSTED_COMMAND_CACHE[$command_name]}"
        if [ -x "$cached_candidate" ]; then
            debug_emit trusted_command command "$command_name" operation lookup cache memory status ready
            printf '%s\n' "$cached_candidate"
            return 0
        fi
        unset 'TRUSTED_COMMAND_CACHE[$command_name]'
    fi
    if [ "$cacheable" -eq 1 ] &&
        [ -n "$TRUSTED_COMMAND_CACHE_FILE" ] &&
        [ -f "$TRUSTED_COMMAND_CACHE_FILE" ] &&
        [ ! -L "$TRUSTED_COMMAND_CACHE_FILE" ]; then
        while IFS=$'\t' read -r cached_name cached_candidate; do
            [ "$cached_name" = "$command_name" ] || continue
            [ -n "$cached_candidate" ] || continue
            [ -x "$cached_candidate" ] || continue
            TRUSTED_COMMAND_CACHE["$command_name"]="$cached_candidate"
            debug_emit trusted_command command "$command_name" operation lookup cache scratch status ready
            printf '%s\n' "$cached_candidate"
            return 0
        done < "$TRUSTED_COMMAND_CACHE_FILE"
    fi

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
        if [ "$cacheable" -eq 1 ]; then
            TRUSTED_COMMAND_CACHE["$command_name"]="$resolved_candidate"
            if [ -n "$TRUSTED_COMMAND_CACHE_FILE" ] &&
                [ -f "$TRUSTED_COMMAND_CACHE_FILE" ] &&
                [ ! -L "$TRUSTED_COMMAND_CACHE_FILE" ]; then
                printf '%s\t%s\n' "$command_name" "$resolved_candidate" >> "$TRUSTED_COMMAND_CACHE_FILE" 2>/dev/null || true
            fi
        fi
        debug_emit trusted_command command "$command_name" operation lookup cache fixed_path status ready
        printf '%s\n' "$resolved_candidate"
        return 0
    done

    debug_emit trusted_command command "$command_name" operation lookup cache none status unavailable
    return 1
}

trusted_command() {
    if ! runtime_enabled; then
        debug_emit trusted_command command "$1" operation lookup cache none status disabled
        return 1
    fi
    resolve_trusted_command_path "$1"
}

trusted_findmnt_command() {
    [ "$SCAN_ROOT" = "/" ] || return 1
    resolve_trusted_command_path findmnt
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
    local command_status=0

    command_path="$(trusted_command "$command_name")" || {
        debug_emit trusted_command command "$command_name" operation execute status unavailable
        return 127
    }
    "$command_path" "$@" || command_status=$?
    debug_emit trusted_command command "$command_name" operation execute status "$command_status"
    return "$command_status"
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

stat_device_inode() {
    local path="$1"
    local stat_path=""

    stat_path="$(command -v stat 2>/dev/null || true)"
    [ -n "$stat_path" ] || return 127
    "$stat_path" -Lc '%d:%i' -- "$path" 2>/dev/null
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

    fs_path_into /etc/os-release os_release || return 1
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

platform_is_debian_family() {
    [ "$PLATFORM_FAMILY" = "debian" ]
}

platform_is_rhel_family() {
    [ "$PLATFORM_FAMILY" = "rhel" ]
}

platform_id_like_contains() {
    local expected_id="$1"

    case " $PLATFORM_ID_LIKE " in
        *" $expected_id "*) return 0 ;;
        *) return 1 ;;
    esac
}

platform_is_ubuntu_derivative() {
    platform_id_like_contains ubuntu && platform_id_like_contains debian
}

platform_base_major() {
    local base_major="${PLATFORM_BASE_VERSION%%.*}"

    case "$base_major" in
        ''|*[!0-9]*) return 1 ;;
    esac
    printf '%s\n' "$base_major"
}

platform_uses_login_defs_dropins() {
    local base_major=""

    platform_is_rhel_family || return 1
    base_major="$(platform_base_major 2>/dev/null || true)"
    [ -n "$base_major" ] && [ "$base_major" -ge 10 ]
}

platform_supports_pwhistory_configuration() {
    if platform_is_rhel_family; then
        return 0
    fi

    case "$PLATFORM_BASE_ID:$PLATFORM_BASE_VERSION" in
        debian:13|ubuntu:24.04|ubuntu:26.04) return 0 ;;
        *) return 1 ;;
    esac
}

platform_supports_yescrypt() {
    local base_major=""

    if platform_is_rhel_family; then
        base_major="$(platform_base_major 2>/dev/null || true)"
        [ -n "$base_major" ] && [ "$base_major" -ge 10 ]
        return $?
    fi
    platform_is_debian_family
}

platform_ubuntu_version_from_codename() {
    case "$1" in
        jammy) printf '22.04\n' ;;
        noble) printf '24.04\n' ;;
        resolute) printf '26.04\n' ;;
        *) return 1 ;;
    esac
}

platform_infer_ubuntu_derivative_base() {
    [ -n "$PLATFORM_UBUNTU_CODENAME" ] || return 1
    platform_ubuntu_version_from_codename "$PLATFORM_UBUNTU_CODENAME"
}

classify_platform() {
    PLATFORM_FAMILY=""
    PLATFORM_BASE_ID=""
    PLATFORM_BASE_VERSION=""

    case "$PLATFORM_ID" in
        debian)
            PLATFORM_FAMILY="debian"
            PLATFORM_BASE_ID="debian"
            PLATFORM_BASE_VERSION="$PLATFORM_VERSION"
            ;;
        ubuntu)
            PLATFORM_FAMILY="debian"
            PLATFORM_BASE_ID="ubuntu"
            PLATFORM_BASE_VERSION="$PLATFORM_VERSION"
            ;;
        linuxmint|pop|zorin|elementary|neon)
            PLATFORM_FAMILY="debian"
            PLATFORM_BASE_ID="ubuntu"
            PLATFORM_BASE_VERSION="$(platform_infer_ubuntu_derivative_base 2>/dev/null || true)"
            ;;
        rhel|almalinux|rocky|ol|centos)
            PLATFORM_FAMILY="rhel"
            PLATFORM_BASE_ID="rhel"
            PLATFORM_BASE_VERSION="$PLATFORM_VERSION"
            ;;
    esac
}

platform_release_is_supported() {
    case "$PLATFORM_ID:$PLATFORM_VERSION" in
        debian:12|debian:13)
            return 0
            ;;
        ubuntu:22.04|ubuntu:24.04|ubuntu:26.04)
            return 0
            ;;
        rhel:8.10|rhel:9.8|rhel:10.2)
            return 0
            ;;
        almalinux:8.10|almalinux:9.8|almalinux:10.2)
            return 0
            ;;
        rocky:8.10|rocky:9.8|rocky:10.2)
            return 0
            ;;
        ol:8.10|ol:9.8|ol:10.2)
            return 0
            ;;
        centos:9|centos:10)
            case "$PLATFORM_NAME" in
                *"CentOS Stream"*) return 0 ;;
                *) return 1 ;;
            esac
            ;;
        linuxmint:21|linuxmint:21.1|linuxmint:21.2|linuxmint:21.3)
            platform_is_ubuntu_derivative && [ "$PLATFORM_BASE_VERSION" = "22.04" ]
            ;;
        linuxmint:22|linuxmint:22.1|linuxmint:22.2|linuxmint:22.3)
            platform_is_ubuntu_derivative && [ "$PLATFORM_BASE_VERSION" = "24.04" ]
            ;;
        pop:22.04|pop:24.04)
            platform_is_ubuntu_derivative && [ "$PLATFORM_BASE_VERSION" = "$PLATFORM_VERSION" ]
            ;;
        zorin:17)
            platform_is_ubuntu_derivative && [ "$PLATFORM_BASE_VERSION" = "22.04" ]
            ;;
        zorin:18)
            platform_is_ubuntu_derivative && [ "$PLATFORM_BASE_VERSION" = "24.04" ]
            ;;
        elementary:7|elementary:7.1)
            platform_is_ubuntu_derivative && [ "$PLATFORM_BASE_VERSION" = "22.04" ]
            ;;
        elementary:8)
            platform_is_ubuntu_derivative && [ "$PLATFORM_BASE_VERSION" = "24.04" ]
            ;;
        neon:24.04)
            platform_is_ubuntu_derivative &&
                [ "$PLATFORM_BASE_VERSION" = "24.04" ] &&
                [ "$PLATFORM_NAME" = "KDE neon User Edition" ]
            ;;
        *)
            return 1
            ;;
    esac
}

detect_platform() {
    local canonical_root=""

    canonical_scan_root_into canonical_root || return 1
    PLATFORM_ID="$(read_os_release_value ID 2>/dev/null || true)"
    PLATFORM_ID_LIKE="$(read_os_release_value ID_LIKE 2>/dev/null || true)"
    PLATFORM_VERSION="$(read_os_release_value VERSION_ID 2>/dev/null || true)"
    PLATFORM_NAME="$(read_os_release_value PRETTY_NAME 2>/dev/null || true)"
    [ -n "$PLATFORM_NAME" ] || PLATFORM_NAME="$(read_os_release_value NAME 2>/dev/null || true)"
    PLATFORM_UBUNTU_CODENAME="$(read_os_release_value UBUNTU_CODENAME 2>/dev/null || true)"

    classify_platform
    platform_release_is_supported
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
    RESULT_TECHNICAL_STATUS="$status"
    RESULT_DECISION_BASIS="technical"
    RESULT_REVIEW_ID=""
    RESULT_ATTESTATION_TICKET=""
    RESULT_ATTESTATION_APPROVER=""
    RESULT_ATTESTATION_EXPIRES=""
    RESULT_SUMMARY="$summary"
    RESULT_EVIDENCE="$evidence"
    RESULT_APPLICABLE="$applicable"
}

evidence_requires_redaction() {
    local input_value="$1"
    local sensitive_key_pattern='(^|[[:space:],;({])([[:alnum:].-]*[_-]?(password|passwd|secret|token|passphrase)([_.-](hash|value|plaintext|credential|auth|key))?)[[:space:]]*[:=]'
    local sensitive_directive_pattern='(^|[[:space:]])(rocommunity6?|rwcommunity6?|com2sec6?|authcommunity|createUser)([[:space:]]|$)'
    local nocasematch_was_set=0
    local match_status=1

    shopt -q nocasematch && nocasematch_was_set=1
    shopt -s nocasematch
    if [[ "$input_value" == *'$'* ]] || [[ "$input_value" =~ $sensitive_key_pattern ]] ||
        [[ "$input_value" =~ $sensitive_directive_pattern ]]; then
        match_status=0
    fi
    if [ "$nocasematch_was_set" -eq 0 ]; then
        shopt -u nocasematch
    fi
    return "$match_status"
}

redact_evidence_into() {
    local __kisa_evidence_input="$1"
    local __kisa_evidence_destination="$2"

    case "$__kisa_evidence_destination" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|__kisa_evidence_*) return 2 ;;
    esac
    printf -v "$__kisa_evidence_destination" '%s' ""

    if evidence_requires_redaction "$__kisa_evidence_input"; then
        __kisa_evidence_input="$(sed -E \
            -e 's/(\$[A-Za-z0-9./]+\$)[A-Za-z0-9./$]+/\1[REDACTED_HASH]/g' \
            -e 's/^([[:space:]]*(rocommunity6?|rwcommunity6?)[[:space:]]+)[^[:space:]]+/\1[REDACTED]/I' \
            -e 's/^([[:space:]]*com2sec6?[[:space:]]+-Cn[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+)[^[:space:]]+/\1[REDACTED]/I' \
            -e '/^[[:space:]]*com2sec6?[[:space:]]+-Cn[[:space:]]/I! s/^([[:space:]]*com2sec6?[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+)[^[:space:]]+/\1[REDACTED]/I' \
            -e 's/^([[:space:]]*authcommunity[[:space:]]+[^[:space:]]+[[:space:]]+)[^[:space:]]+/\1[REDACTED]/I' \
            -e 's/^([[:space:]]*createUser[[:space:]]+[^[:space:]]+).*/\1 [REDACTED]/I' \
            -e 's/(^|[[:space:],;({])(([[:alnum:].-]*[_-]?(password|passwd|secret|token|passphrase)([_.-](hash|value|plaintext|credential|auth|key))?)[[:space:]]*[:=][[:space:]]*)".*"/\1\2[REDACTED]/Ig' \
            -e 's/(^|[[:space:],;({])(([[:alnum:].-]*[_-]?(password|passwd|secret|token|passphrase)([_.-](hash|value|plaintext|credential|auth|key))?)[[:space:]]*[:=][[:space:]]*)".*/\1\2[REDACTED]/Ig' \
            -e "s/(^|[[:space:],;({])(([[:alnum:].-]*[_-]?(password|passwd|secret|token|passphrase)([_.-](hash|value|plaintext|credential|auth|key))?)[[:space:]]*[:=][[:space:]]*)'.*'/\\1\\2[REDACTED]/Ig" \
            -e "s/(^|[[:space:],;({])(([[:alnum:].-]*[_-]?(password|passwd|secret|token|passphrase)([_.-](hash|value|plaintext|credential|auth|key))?)[[:space:]]*[:=][[:space:]]*)'.*/\\1\\2[REDACTED]/Ig" \
            -e 's/(^|[[:space:],;({])(([[:alnum:].-]*[_-]?(password|passwd|secret|token|passphrase)([_.-](hash|value|plaintext|credential|auth|key))?)[[:space:]]*[:=][[:space:]]*)[^[:space:]]+/\1\2[REDACTED]/Ig' \
            <<< "$__kisa_evidence_input")"
    fi
    while [[ "$__kisa_evidence_input" == *$'\n' ]]; do
        __kisa_evidence_input="${__kisa_evidence_input%$'\n'}"
    done
    printf -v "$__kisa_evidence_destination" '%s' "$__kisa_evidence_input"
}

limit_evidence_into() {
    local input_value="$1"
    local destination_name="$2"

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|input_value|destination_name) return 2 ;;
    esac
    if [ "${#input_value}" -gt 8192 ]; then
        input_value="${input_value:0:8192}"
    fi
    while [[ "$input_value" == *$'\n' ]]; do
        input_value="${input_value%$'\n'}"
    done
    printf -v "$destination_name" '%s' "$input_value"
}

indent_markdown_evidence_into() {
    local __kisa_text_evidence_remaining="$1"
    local __kisa_text_evidence_destination="$2"
    local __kisa_text_evidence_output=""
    local __kisa_text_evidence_line=""
    local __kisa_text_evidence_separator=""
    local __kisa_text_evidence_has_more=0
    local __kisa_text_evidence_c1=$'\302[\200-\237]'

    case "$__kisa_text_evidence_destination" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|__kisa_text_evidence_*) return 2 ;;
    esac
    printf -v "$__kisa_text_evidence_destination" '%s' ""

    while :; do
        case "$__kisa_text_evidence_remaining" in
            *$'\n'*)
                __kisa_text_evidence_line="${__kisa_text_evidence_remaining%%$'\n'*}"
                __kisa_text_evidence_remaining="${__kisa_text_evidence_remaining#*$'\n'}"
                __kisa_text_evidence_has_more=1
                ;;
            *)
                __kisa_text_evidence_line="$__kisa_text_evidence_remaining"
                __kisa_text_evidence_remaining=""
                __kisa_text_evidence_has_more=0
                ;;
        esac
        __kisa_text_evidence_line="${__kisa_text_evidence_line//$'\t'/\\t}"
        __kisa_text_evidence_line="${__kisa_text_evidence_line//$'\r'/\\r}"
        __kisa_text_evidence_line="${__kisa_text_evidence_line//$__kisa_text_evidence_c1/?}"
        __kisa_text_evidence_output+="${__kisa_text_evidence_separator}    ${__kisa_text_evidence_line}"
        __kisa_text_evidence_separator=$'\n'
        [ "$__kisa_text_evidence_has_more" -eq 1 ] || break
    done
    printf -v "$__kisa_text_evidence_destination" '%s' "$__kisa_text_evidence_output"
}

escape_markdown_scalar_into() {
    local input_value="$1"
    local destination_name="$2"

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|input_value|destination_name) return 2 ;;
    esac
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

escape_html_text_into() {
    local input_value="$1"
    local destination_name="$2"

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|input_value|destination_name) return 2 ;;
    esac
    input_value="${input_value//&/\&amp;}"
    input_value="${input_value//</\&lt;}"
    input_value="${input_value//>/\&gt;}"
    input_value="${input_value//#/\&#35;}"
    printf -v "$destination_name" '%s' "$input_value"
}

remove_incomplete_utf8_suffix_into() {
    local __kisa_utf8_input="$1"
    local __kisa_utf8_destination="$2"
    local __kisa_utf8_length="${#__kisa_utf8_input}"
    local __kisa_utf8_index=$((__kisa_utf8_length - 1))
    local __kisa_utf8_continuation_count=0
    local __kisa_utf8_byte_value=0
    local __kisa_utf8_expected_length=1

    case "$__kisa_utf8_destination" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|__kisa_utf8_*) return 2 ;;
    esac
    printf -v "$__kisa_utf8_destination" '%s' ""

    while [ "$__kisa_utf8_index" -ge 0 ]; do
        printf -v __kisa_utf8_byte_value '%d' "'${__kisa_utf8_input:__kisa_utf8_index:1}"
        if [ "$__kisa_utf8_byte_value" -ge 128 ] && [ "$__kisa_utf8_byte_value" -le 191 ]; then
            __kisa_utf8_continuation_count=$((__kisa_utf8_continuation_count + 1))
            __kisa_utf8_index=$((__kisa_utf8_index - 1))
        else
            break
        fi
    done
    if [ "$__kisa_utf8_index" -lt 0 ]; then
        __kisa_utf8_input=""
    else
        printf -v __kisa_utf8_byte_value '%d' "'${__kisa_utf8_input:__kisa_utf8_index:1}"
        if [ "$__kisa_utf8_byte_value" -ge 194 ] && [ "$__kisa_utf8_byte_value" -le 223 ]; then
            __kisa_utf8_expected_length=2
        elif [ "$__kisa_utf8_byte_value" -ge 224 ] && [ "$__kisa_utf8_byte_value" -le 239 ]; then
            __kisa_utf8_expected_length=3
        elif [ "$__kisa_utf8_byte_value" -ge 240 ] && [ "$__kisa_utf8_byte_value" -le 244 ]; then
            __kisa_utf8_expected_length=4
        fi
        # Byte truncation can only damage the final sequence after iconv has validated the complete value.
        if [ "$__kisa_utf8_expected_length" -gt $((__kisa_utf8_continuation_count + 1)) ]; then
            __kisa_utf8_input="${__kisa_utf8_input:0:__kisa_utf8_index}"
        fi
    fi
    printf -v "$__kisa_utf8_destination" '%s' "$__kisa_utf8_input"
}

json_remove_control_bytes_into() {
    local input_value="$1"
    local destination_name="$2"
    local removable_control_bytes=$'[\001-\010\013\014\016-\037\177]'

    input_value="${input_value//$removable_control_bytes/}"
    printf -v "$destination_name" '%s' "$input_value"
}

json_escape_into() {
    local input_value="$1"
    local destination_name="$2"
    local escaped_value=""

    json_remove_control_bytes_into "$input_value" escaped_value
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

sanitize_header_field_into() {
    local input_value="$1"
    local destination_name="$2"
    local sanitized_value=""
    local control_bytes=$'[\001-\037\177]'
    local c1_control_sequence=$'\302[\200-\237]'

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|input_value|destination_name|sanitized_value|control_bytes|c1_control_sequence) return 2 ;;
    esac
    printf -v "$destination_name" '%s' ""
    if [ -x /usr/bin/iconv ]; then
        sanitized_value="$(printf '%s' "$input_value" | /usr/bin/iconv -f UTF-8 -t UTF-8 -c 2>/dev/null || true)"
    else
        sanitized_value="$input_value"
    fi
    sanitized_value="${sanitized_value//$control_bytes/}"
    sanitized_value="${sanitized_value//$c1_control_sequence/}"
    printf -v "$destination_name" '%s' "$sanitized_value"
}

trusted_sha256sum_command() {
    local candidate=""
    local candidate_owner=""
    local candidate_mode=""

    for candidate in /usr/bin/sha256sum /bin/sha256sum; do
        [ -x "$candidate" ] || continue
        candidate_owner="$(stat_owner "$candidate" 2>/dev/null || true)"
        candidate_mode="$(stat_mode "$candidate" 2>/dev/null || true)"
        [ "$candidate_owner" = "root" ] || continue
        mode_has_untrusted_write "$candidate_mode" && continue
        trusted_parent_chain "$candidate" || continue
        printf '%s\n' "$candidate"
        return 0
    done
    return 1
}

result_review_id_into() {
    local code="$1"
    local category="$2"
    local severity="$3"
    local title="$4"
    local applicable="$5"
    local summary="$6"
    local evidence="$7"
    local destination_name="$8"
    local sha256sum_path=""
    local review_file=""
    local review_directory=""
    local hash_output=""
    local digest=""

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|code|category|severity|title|applicable|summary|evidence|destination_name) return 2 ;;
    esac
    printf -v "$destination_name" '%s' ""
    sha256sum_path="$(trusted_sha256sum_command 2>/dev/null || true)"
    [ -n "$sha256sum_path" ] || return 2
    review_directory="${SCRATCH_DIR:-${TMPDIR:-/tmp}}"
    [ -d "$review_directory" ] && [ ! -L "$review_directory" ] || return 2
    review_file="$(mktemp "$review_directory/kisa-cce-review.XXXXXXXX")" || return 2
    if ! printf 'review_schema:1\nscanner_version:%s\nplatform:%s:%s\nplatform_base:%s:%s\nevidence_capture:%s:%s:%s:%s\ncode:%d:%s\ncategory:%d:%s\nseverity:%d:%s\ntitle:%d:%s\napplicable:%s\nsummary:%d:%s\nevidence:%d:%s\n' \
        "$KISA_CCE_VERSION" "${PLATFORM_ID:-unknown}" "${PLATFORM_VERSION:-unknown}" \
        "${PLATFORM_BASE_ID:-unknown}" "${PLATFORM_BASE_VERSION:-unknown}" \
        "${EVIDENCE_MACHINE_ID:-none}" "${EVIDENCE_BOOT_ID:-none}" "${EVIDENCE_CAPTURED_AT:-none}" "${EVIDENCE_BUNDLE_DIGEST:-none}" \
        "${#code}" "$code" "${#category}" "$category" "${#severity}" "$severity" \
        "${#title}" "$title" "$applicable" "${#summary}" "$summary" \
        "${#evidence}" "$evidence" > "$review_file"; then
        rm -f -- "$review_file"
        return 2
    fi
    hash_output="$("$sha256sum_path" "$review_file" 2>/dev/null)" || {
        rm -f -- "$review_file"
        return 2
    }
    rm -f -- "$review_file"
    digest="${hash_output%% *}"
    [ "${#digest}" -eq 64 ] || return 2
    case "$digest" in *[!0-9a-f]*) return 2 ;; esac
    printf -v "$destination_name" 'sha256:%s' "$digest"
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
    local normalized_title="$title"
    local normalized_summary="$RESULT_SUMMARY"
    local normalized_evidence="$RESULT_EVIDENCE"
    local full_redacted_evidence=""
    local normalized_json_evidence=""
    local normalized_bundle=""
    local remaining_bundle=""
    local json_field_separator=$'\036'
    local iconv_normalized=0
    local escaped_title=""
    local escaped_category=""
    local escaped_severity=""
    local escaped_summary=""
    local escaped_evidence=""
    local escaped_technical_status=""
    local escaped_decision_basis=""
    local escaped_review_id=""
    local escaped_attestation_ticket=""
    local escaped_attestation_approver=""
    local escaped_attestation_expires=""
    local markdown_title=""
    local markdown_summary=""
    local markdown_evidence=""
    local html_evidence=""
    local markdown_attestation_ticket=""
    local markdown_attestation_approver=""
    local markdown_output_path=""
    local priority_output_path=""
    local manual_summary=""
    local manual_review_id=""
    local policy_status=1
    local console_title=""

    criterion_slug="u-${code#U-}"
    criterion_url="${KISA_CCE_GUIDE_BASE}/unix/${criterion_slug}/"

    normalized_evidence="${normalized_evidence//\\n/$'\n'}"
    json_remove_control_bytes_into "$normalized_title" normalized_title
    json_remove_control_bytes_into "$normalized_summary" normalized_summary
    json_remove_control_bytes_into "$normalized_evidence" normalized_evidence
    if [ -x /usr/bin/iconv ]; then
        iconv_normalized=1
        # The separator is removed from every field first, so one normalization pass can preserve field boundaries.
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
    redact_evidence_into "$normalized_evidence" full_redacted_evidence
    if [ "$RESULT_STATUS" = "MANUAL" ]; then
        manual_summary="$normalized_summary"
        result_review_id_into "$code" "$category" "$severity" "$normalized_title" "$RESULT_APPLICABLE" \
            "$normalized_summary" "$full_redacted_evidence" manual_review_id || manual_review_id=""
        RESULT_REVIEW_ID="$manual_review_id"
        if [ "$SCAN_MODE" = "complete" ] || [ "$SCAN_MODE" = "automation" ]; then
            if [ -z "$manual_review_id" ]; then
                RESULT_STATUS="ERROR"
                RESULT_DECISION_BASIS="missing_review_id"
                normalized_summary="완전 검사에 필요한 검토 ID를 생성하지 못했습니다."
                printf -v normalized_evidence 'decision_basis=missing_review_id\nmanual_summary=%s\n%s' \
                    "$manual_summary" "$full_redacted_evidence"
            elif ! declare -F policy_lookup >/dev/null 2>&1; then
                RESULT_STATUS="ERROR"
                RESULT_DECISION_BASIS="policy_module_unavailable"
                normalized_summary="완전 검사 정책 모듈을 사용할 수 없습니다."
                printf -v normalized_evidence 'decision_basis=policy_module_unavailable\nmanual_review_id=%s\nmanual_summary=%s\n%s' \
                    "$manual_review_id" "$manual_summary" "$full_redacted_evidence"
            else
                policy_lookup "$code" "$manual_review_id" >/dev/null 2>&1
                policy_status=$?
                if [ "$policy_status" -eq 0 ]; then
                    RESULT_STATUS="$POLICY_MATCH_DECISION"
                    RESULT_DECISION_BASIS="policy_attestation"
                    RESULT_ATTESTATION_TICKET="$POLICY_MATCH_TICKET"
                    RESULT_ATTESTATION_APPROVER="$POLICY_MATCH_APPROVER"
                    RESULT_ATTESTATION_EXPIRES="$POLICY_MATCH_EXPIRES"
                    COUNT_POLICY_RESOLVED=$((COUNT_POLICY_RESOLVED + 1))
                    normalized_summary="정책 attestation과 현재 검토 ID가 일치하여 ${RESULT_STATUS}으로 확정했습니다."
                    printf -v normalized_evidence 'decision_basis=policy_attestation\nmanual_review_id=%s\npolicy_ticket=%s\npolicy_approver=%s\npolicy_expires=%s\nmanual_summary=%s\n%s' \
                        "$manual_review_id" "$POLICY_MATCH_TICKET" "$POLICY_MATCH_APPROVER" \
                        "$POLICY_MATCH_EXPIRES" "$manual_summary" "$full_redacted_evidence"
                elif [ "$policy_status" -eq 1 ]; then
                    RESULT_STATUS="ERROR"
                    RESULT_DECISION_BASIS="missing_policy_attestation"
                    normalized_summary="완전 검사에 필요한 정책 attestation이 없습니다."
                    printf -v normalized_evidence 'decision_basis=missing_policy_attestation\nmanual_review_id=%s\nmanual_summary=%s\n%s' \
                        "$manual_review_id" "$manual_summary" "$full_redacted_evidence"
                else
                    RESULT_STATUS="ERROR"
                    RESULT_DECISION_BASIS="invalid_policy_attestation"
                    normalized_summary="정책 attestation이 현재 증적과 일치하지 않거나 만료됐습니다."
                    printf -v normalized_evidence 'decision_basis=invalid_policy_attestation\nmanual_review_id=%s\nmanual_summary=%s\n%s' \
                        "$manual_review_id" "$manual_summary" "$full_redacted_evidence"
                fi
            fi
        else
            RESULT_DECISION_BASIS="manual_review"
            normalized_evidence="$full_redacted_evidence"
        fi
        redact_evidence_into "$normalized_evidence" full_redacted_evidence
        RESULT_SUMMARY="$normalized_summary"
    fi
    if [ "$SCAN_MODE" = "automation" ]; then
        case "$RESULT_STATUS" in
            GOOD|VULNERABLE|NOT_APPLICABLE) RESULT_TECHNICAL_STATUS="$RESULT_STATUS" ;;
        esac
    fi
    if declare -F i18n_criterion_title_into >/dev/null 2>&1; then
        i18n_criterion_title_into "$code" "$normalized_title" normalized_title || {
            REPORT_WRITE_ERROR=1
            return 1
        }
        i18n_summary_into "$normalized_summary" normalized_summary || {
            REPORT_WRITE_ERROR=1
            return 1
        }
        RESULT_SUMMARY="$normalized_summary"
    fi
    limit_evidence_into "$full_redacted_evidence" normalized_evidence
    RESULT_EVIDENCE="$normalized_evidence"
    normalized_json_evidence="$normalized_evidence"
    if [ "$iconv_normalized" -eq 1 ]; then
        remove_incomplete_utf8_suffix_into "$normalized_json_evidence" normalized_json_evidence
    fi
    if [ -n "$RESULT_EVIDENCE" ]; then
        if ! indent_markdown_evidence_into "$RESULT_EVIDENCE" markdown_evidence; then
            REPORT_WRITE_ERROR=1
            return 1
        fi
        html_evidence="${markdown_evidence#    }"
        html_evidence="${html_evidence//$'\n    '/$'\n'}"
        if ! escape_html_text_into "$html_evidence" html_evidence; then
            REPORT_WRITE_ERROR=1
            return 1
        fi
    fi
    escape_markdown_scalar_into "$normalized_title" markdown_title || {
        REPORT_WRITE_ERROR=1
        return 1
    }
    escape_markdown_scalar_into "$normalized_summary" markdown_summary || {
        REPORT_WRITE_ERROR=1
        return 1
    }
    escape_markdown_scalar_into "$RESULT_ATTESTATION_TICKET" markdown_attestation_ticket || {
        REPORT_WRITE_ERROR=1
        return 1
    }
    escape_markdown_scalar_into "$RESULT_ATTESTATION_APPROVER" markdown_attestation_approver || {
        REPORT_WRITE_ERROR=1
        return 1
    }

    if [ -n "$REPORT_MARKDOWN_BODY" ]; then
        markdown_output_path="$REPORT_MARKDOWN_BODY"
        if {
            printf '<a id="%s"></a>\n\n' "${code,,}"
            printf '## %s: %s\n\n' "$code" "$markdown_title"
            printf '> **%s:** `%s`  \n' "$REPORT_LABEL_FINAL_STATUS" "$RESULT_STATUS"
            printf '> %s\n\n' "$markdown_summary"
            printf '| %s | %s | %s | %s | %s |\n' \
                "$REPORT_LABEL_CATEGORY" "$REPORT_LABEL_SEVERITY" "$REPORT_LABEL_TECHNICAL_STATUS" \
                "$REPORT_LABEL_DECISION_BASIS" "$REPORT_LABEL_APPLICABLE"
            printf '|---|---|---|---|---|\n'
            printf '| `%s` | `%s` | `%s` | `%s` | `%s` |\n\n' \
                "$category" "$severity" "$RESULT_TECHNICAL_STATUS" "$RESULT_DECISION_BASIS" "$RESULT_APPLICABLE"
            if [ -n "$RESULT_REVIEW_ID" ]; then
                printf '**%s:** `%s`\n\n' "$REPORT_LABEL_REVIEW_ID" "$RESULT_REVIEW_ID"
            fi
            if [ "$RESULT_DECISION_BASIS" = "policy_attestation" ]; then
                printf '| %s | %s | %s |\n' \
                    "$REPORT_LABEL_ATTESTATION_TICKET" "$REPORT_LABEL_ATTESTATION_APPROVER" "$REPORT_LABEL_ATTESTATION_EXPIRES"
                printf '|---|---|---|\n'
                printf '| %s | %s | `%s` |\n\n' \
                    "$markdown_attestation_ticket" "$markdown_attestation_approver" "$RESULT_ATTESTATION_EXPIRES"
            fi
            printf '[%s: KISA CCE %s](%s)\n\n' "$REPORT_LABEL_REFERENCE" "$code" "$criterion_url"
            if [ -n "$RESULT_EVIDENCE" ]; then
                printf '<details>\n<summary>%s</summary>\n\n' "$REPORT_LABEL_EVIDENCE"
                printf '<pre><code>%s</code></pre>\n' "$html_evidence"
                printf '</details>\n\n'
            fi
            printf '%s\n\n' '---'
        } >> "$markdown_output_path"; then
            :
        else
            REPORT_WRITE_ERROR=1
            return 1
        fi
        case "$RESULT_STATUS" in
            ERROR) priority_output_path="$REPORT_PRIORITY_ERROR" ;;
            VULNERABLE) priority_output_path="$REPORT_PRIORITY_VULNERABLE" ;;
            MANUAL) priority_output_path="$REPORT_PRIORITY_MANUAL" ;;
        esac
        if [ -n "$priority_output_path" ] &&
            ! printf -- '- [%s: %s](#%s) - `%s`\n' \
                "$code" "$markdown_title" "${code,,}" "$severity" >> "$priority_output_path"; then
            REPORT_WRITE_ERROR=1
            return 1
        fi
    elif {
        printf '## %s: %s\n\n' "$code" "$markdown_title"
        printf '| %s | %s |\n' "$REPORT_LABEL_FIELD" "$REPORT_LABEL_VALUE"
        printf '|---|---|\n'
        printf "| %s | \`%s\` |\n" "$REPORT_LABEL_CATEGORY" "$category"
        printf "| %s | \`%s\` |\n" "$REPORT_LABEL_SEVERITY" "$severity"
        printf "| %s | \`%s\` |\n" "$REPORT_LABEL_TECHNICAL_STATUS" "$RESULT_TECHNICAL_STATUS"
        printf "| %s | \`%s\` |\n" "$REPORT_LABEL_FINAL_STATUS" "$RESULT_STATUS"
        printf "| %s | \`%s\` |\n" "$REPORT_LABEL_DECISION_BASIS" "$RESULT_DECISION_BASIS"
        printf "| %s | \`%s\` |\n" "$REPORT_LABEL_APPLICABLE" "$RESULT_APPLICABLE"
        if [ -n "$RESULT_REVIEW_ID" ]; then
            printf "| %s | \`%s\` |\n" "$REPORT_LABEL_REVIEW_ID" "$RESULT_REVIEW_ID"
        fi
        if [ "$RESULT_DECISION_BASIS" = "policy_attestation" ]; then
            printf '| %s | %s |\n' "$REPORT_LABEL_ATTESTATION_TICKET" "$markdown_attestation_ticket"
            printf '| %s | %s |\n' "$REPORT_LABEL_ATTESTATION_APPROVER" "$markdown_attestation_approver"
            printf "| %s | \`%s\` |\n" "$REPORT_LABEL_ATTESTATION_EXPIRES" "$RESULT_ATTESTATION_EXPIRES"
        fi
        printf '\n'
        printf '### %s\n\n%s\n\n' "$REPORT_LABEL_SUMMARY" "$markdown_summary"
        if [ -n "$RESULT_EVIDENCE" ]; then
            printf '### %s\n\n%s\n\n' "$REPORT_LABEL_EVIDENCE" "$markdown_evidence"
        fi
        printf '### %s\n\n' "$REPORT_LABEL_REFERENCE"
        printf '[KISA CCE %s](%s)\n\n' "$code" "$criterion_url"
        printf '%s\n\n' '---'
    } >> "$REPORT_TEXT"; then
        :
    else
        REPORT_WRITE_ERROR=1
        return 1
    fi

    json_escape_into "$normalized_title" escaped_title
    json_escape_into "$category" escaped_category
    json_escape_into "$severity" escaped_severity
    json_escape_into "$normalized_summary" escaped_summary
    json_escape_into "$normalized_json_evidence" escaped_evidence
    json_escape_into "$RESULT_TECHNICAL_STATUS" escaped_technical_status
    json_escape_into "$RESULT_DECISION_BASIS" escaped_decision_basis
    json_escape_into "$RESULT_REVIEW_ID" escaped_review_id
    json_escape_into "$RESULT_ATTESTATION_TICKET" escaped_attestation_ticket
    json_escape_into "$RESULT_ATTESTATION_APPROVER" escaped_attestation_approver
    json_escape_into "$RESULT_ATTESTATION_EXPIRES" escaped_attestation_expires
    if ! printf '{"code":"%s","category":"%s","severity":"%s","title":"%s","status":"%s","technical_status":"%s","decision_basis":"%s","review_id":"%s","attestation_ticket":"%s","attestation_approver":"%s","attestation_expires":"%s","applicable":%s,"summary":"%s","evidence":"%s","criterion_url":"%s"}\n' \
        "$code" "$escaped_category" "$escaped_severity" "$escaped_title" "$RESULT_STATUS" \
        "$escaped_technical_status" "$escaped_decision_basis" "$escaped_review_id" \
        "$escaped_attestation_ticket" "$escaped_attestation_approver" "$escaped_attestation_expires" \
        "$RESULT_APPLICABLE" "$escaped_summary" "$escaped_evidence" "$criterion_url" >> "$REPORT_JSONL"; then
        REPORT_WRITE_ERROR=1
        return 1
    fi

    increment_status "$RESULT_STATUS"
    if [ "$VERBOSE" -eq 1 ]; then
        i18n_console_translate_into "$title" console_title || console_title="unavailable"
        verbose "check=${code} status=${RESULT_STATUS} title=${console_title}"
    fi
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

    SCAN_ACTIVE_CRITERION="$code"
    debug_emit criterion_start code "$code"
    function_name="check_u_${code#U-}"
    RESULT_STATUS=""
    RESULT_TECHNICAL_STATUS=""
    RESULT_DECISION_BASIS=""
    RESULT_REVIEW_ID=""
    RESULT_ATTESTATION_TICKET=""
    RESULT_ATTESTATION_APPROVER=""
    RESULT_ATTESTATION_EXPIRES=""
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
    debug_emit criterion_technical code "$code" status "$RESULT_TECHNICAL_STATUS" applicable "$RESULT_APPLICABLE"

    if ! record_result "$code" "$category" "$severity" "$title"; then
        debug_emit criterion_end code "$code" status ERROR decision_basis report_write_error
        warn "failed to write report data for $code"
        SCAN_ACTIVE_CRITERION=""
        return 1
    fi
    debug_emit criterion_end code "$code" status "$RESULT_STATUS" decision_basis "$RESULT_DECISION_BASIS"
    SCAN_ACTIVE_CRITERION=""
    return 0
}

normalize_output_parent_into() {
    local input_path="$1"
    local destination_name="$2"
    local normalized_path="/"
    local component=""
    local old_ifs="$IFS"
    local -a components=()

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|normalized_path|component|components|old_ifs) return 2 ;;
    esac
    printf -v "$destination_name" '%s' ""
    case "$input_path" in
        /*) ;;
        *) return 2 ;;
    esac
    case "$input_path" in *$'\n'*|*$'\r'*|*$'\t'*) return 2 ;; esac

    IFS=/ read -r -a components <<< "${input_path#/}"
    IFS="$old_ifs"
    for component in "${components[@]}"; do
        case "$component" in
            '') continue ;;
            .|..) return 2 ;;
        esac
        normalized_path="${normalized_path%/}/$component"
    done
    printf -v "$destination_name" '%s' "$normalized_path"
}

output_path_has_no_symlink_components() {
    local output_path="$1"
    local current_path="/"
    local component=""
    local component_uid=""
    local old_ifs="$IFS"
    local -a components=()

    IFS=/ read -r -a components <<< "${output_path#/}"
    IFS="$old_ifs"
    for component in "${components[@]}"; do
        [ -n "$component" ] || continue
        current_path="${current_path%/}/$component"
        [ ! -L "$current_path" ] || return 1
    done
    return 0
}

output_path_components_are_trusted() {
    local output_path="$1"
    local current_path="/"
    local component=""
    local component_mode=""
    local decimal_mode=""
    local old_ifs="$IFS"
    local -a components=()

    IFS=/ read -r -a components <<< "${output_path#/}"
    IFS="$old_ifs"
    for component in "${components[@]}"; do
        [ -n "$component" ] || continue
        current_path="${current_path%/}/$component"
        if [ ! -e "$current_path" ] && [ ! -L "$current_path" ]; then
            break
        fi
        [ ! -L "$current_path" ] && [ -d "$current_path" ] || return 1
        component_mode="$(stat_mode "$current_path" 2>/dev/null || true)"
        [ -n "$component_mode" ] || return 1
        decimal_mode="$(mode_to_decimal "$component_mode" 2>/dev/null || true)"
        [ -n "$decimal_mode" ] || return 1
        if [ $((decimal_mode & 0022)) -ne 0 ] && [ $((decimal_mode & 01000)) -eq 0 ]; then
            return 1
        fi
        if [ $((decimal_mode & 0022)) -ne 0 ]; then
            component_uid="$(stat_uid "$current_path" 2>/dev/null || true)"
            [ -n "$component_uid" ] || return 1
            case "$current_path:$component_uid" in
                /tmp:*|/var/tmp:*|*:0|*:"$EUID") ;;
                *) return 1 ;;
            esac
        fi
    done
    return 0
}

output_directory_binding_is_current() {
    local descriptor_device_inode=""
    local lexical_device_inode=""

    [ -n "$OUTPUT_DIRECTORY_FD" ] || return 1
    [ -n "$OUTPUT_DIRECTORY_FD_PATH" ] || return 1
    [ -n "$OUTPUT_DIRECTORY_DEVICE_INODE" ] || return 1
    [ -d "$OUTPUT_DIRECTORY_FD_PATH" ] || return 1
    output_path_has_no_symlink_components "$OUTPUT_PARENT" || return 1
    output_path_components_are_trusted "$OUTPUT_PARENT" || return 1
    [ -d "$OUTPUT_PARENT" ] || return 1

    descriptor_device_inode="$(stat_device_inode "$OUTPUT_DIRECTORY_FD_PATH")" || return 1
    [ "$descriptor_device_inode" = "$OUTPUT_DIRECTORY_DEVICE_INODE" ] || return 1
    lexical_device_inode="$(stat_device_inode "$OUTPUT_PARENT")" || return 1
    [ "$lexical_device_inode" = "$OUTPUT_DIRECTORY_DEVICE_INODE" ] || return 1
    output_path_has_no_symlink_components "$OUTPUT_PARENT"
}

report_output_paths_are_current() {
    [ -n "$REPORT_MARKDOWN_OUTPUT_PATH" ] || return 1
    [ -n "$REPORT_JSONL_OUTPUT_PATH" ] || return 1
    output_directory_binding_is_current
}

initialize_workspace() {
    local default_parent=""
    local output_uid=""
    local current_uid=""
    local parent_mode=""
    local parent_decimal_mode=""
    local timestamp=""
    local hostname_value=""
    local markdown_report_temp=""
    local normalized_output_parent=""
    local report_fragment=""
    local report_staging_directory=""
    # shellcheck disable=SC2034
    local canonical_root=""

    AUTOMATION_REPORTS_COMMITTED=0
    AUTOMATION_MARKDOWN_MOVED=0
    AUTOMATION_JSONL_MOVED=0
    AUTOMATION_MARKDOWN_PUBLISHED_PATH=""
    AUTOMATION_JSONL_PUBLISHED_PATH=""

    if [ -z "$OUTPUT_PARENT" ]; then
        if [ "$(id -u)" -eq 0 ]; then
            default_parent="/var/log/kisa-cce-scanner"
        else
            default_parent="/tmp/kisa-cce-scanner-$(id -u)"
        fi
        OUTPUT_PARENT="$default_parent"
    fi

    normalize_output_parent_into "$OUTPUT_PARENT" normalized_output_parent ||
        die "output directory path is not a safe absolute path: $OUTPUT_PARENT"
    OUTPUT_PARENT="$normalized_output_parent"
    output_path_has_no_symlink_components "$OUTPUT_PARENT" ||
        die "output directory path contains a symbolic link: $OUTPUT_PARENT"
    output_path_components_are_trusted "$OUTPUT_PARENT" ||
        die "output directory parent path is not trusted: $OUTPUT_PARENT"
    if [ -e "$OUTPUT_PARENT" ]; then
        [ -d "$OUTPUT_PARENT" ] || die "output path is not a directory: $OUTPUT_PARENT"
    else
        mkdir -p -- "$OUTPUT_PARENT" || die "cannot create the output directory: $OUTPUT_PARENT"
    fi
    output_path_has_no_symlink_components "$OUTPUT_PARENT" ||
        die "output directory path contains a symbolic link: $OUTPUT_PARENT"
    output_path_components_are_trusted "$OUTPUT_PARENT" ||
        die "output directory parent path is not trusted: $OUTPUT_PARENT"

    if ! exec {OUTPUT_DIRECTORY_FD}<"$OUTPUT_PARENT"; then
        die "cannot open the output directory: $OUTPUT_PARENT"
    fi
    OUTPUT_DIRECTORY_FD_PATH="/proc/self/fd/$OUTPUT_DIRECTORY_FD"
    [ -d "$OUTPUT_DIRECTORY_FD_PATH" ] || die "cannot verify the output directory descriptor: $OUTPUT_PARENT"

    current_uid="$(id -u)"
    output_uid="$(stat_uid "$OUTPUT_DIRECTORY_FD_PATH" 2>/dev/null || true)"
    [ "$output_uid" = "$current_uid" ] || die "output directory owner differs from the current user"
    parent_mode="$(stat_mode "$OUTPUT_DIRECTORY_FD_PATH" 2>/dev/null || true)"
    mode_has_group_or_other_permissions "$parent_mode" && die "output directory permissions must be 0700 or more restrictive"
    parent_decimal_mode="$(mode_to_decimal "$parent_mode" 2>/dev/null || true)"
    [ -n "$parent_decimal_mode" ] && [ $((parent_decimal_mode & 8#700)) -eq $((8#700)) ] ||
        die "output directory requires owner read, write, and search permissions"
    OUTPUT_DIRECTORY_DEVICE_INODE="$(stat_device_inode "$OUTPUT_DIRECTORY_FD_PATH")" ||
        die "cannot verify the output directory descriptor: $OUTPUT_PARENT"
    output_directory_binding_is_current ||
        die "output directory path changed during the scan: $OUTPUT_PARENT"

    SCRATCH_DIR="$(mktemp -d "$OUTPUT_DIRECTORY_FD_PATH/.run.XXXXXXXX")" || die "cannot create a secure temporary directory"
    chmod 0700 "$SCRATCH_DIR" || die "cannot set temporary directory permissions"
    REPORT_MARKDOWN_BODY="$SCRATCH_DIR/report-body.md"
    REPORT_PRIORITY_ERROR="$SCRATCH_DIR/report-priority-error.md"
    REPORT_PRIORITY_VULNERABLE="$SCRATCH_DIR/report-priority-vulnerable.md"
    REPORT_PRIORITY_MANUAL="$SCRATCH_DIR/report-priority-manual.md"
    for report_fragment in \
        "$REPORT_MARKDOWN_BODY" \
        "$REPORT_PRIORITY_ERROR" \
        "$REPORT_PRIORITY_VULNERABLE" \
        "$REPORT_PRIORITY_MANUAL"; do
        : > "$report_fragment" || die "cannot create a secure report fragment"
        chmod 0600 "$report_fragment" || die "cannot set report fragment permissions"
    done
    canonical_scan_root_into canonical_root || die "cannot resolve the scan root: $SCAN_ROOT"
    TRUSTED_COMMAND_CACHE=()
    TRUSTED_COMMAND_CACHE_FILE="$SCRATCH_DIR/trusted-command-cache"
    : > "$TRUSTED_COMMAND_CACHE_FILE" || die "cannot create the command path cache"
    # This flag is consumed by the listener resolver after all libraries load.
    # shellcheck disable=SC2034
    LISTENER_SNAPSHOT_CACHE_ENABLED=1
    LISTENER_SNAPSHOT_GENERATION=0

    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    hostname_value="$(hostname 2>/dev/null | tr -cd 'A-Za-z0-9._-' | cut -c1-63)"
    [ -n "$hostname_value" ] || hostname_value="host"

    if [ "$SCAN_MODE" = "automation" ]; then
        report_staging_directory="$SCRATCH_DIR"
    else
        report_staging_directory="$OUTPUT_DIRECTORY_FD_PATH"
    fi
    markdown_report_temp="$(mktemp "$report_staging_directory/kisa-cce-${hostname_value}-${timestamp}.XXXXXXXX")" ||
        die "cannot create the Markdown report"
    REPORT_TEXT="${markdown_report_temp}.md"
    mv -- "$markdown_report_temp" "$REPORT_TEXT" || die "cannot finalize the Markdown report name"
    REPORT_MARKDOWN_OUTPUT_PATH="$OUTPUT_PARENT/${REPORT_TEXT##*/}"
    REPORT_JSONL="$(mktemp "$report_staging_directory/kisa-cce-${hostname_value}-${timestamp}.jsonl.XXXXXXXX")" || die "cannot create the JSONL report"
    REPORT_JSONL_OUTPUT_PATH="$OUTPUT_PARENT/${REPORT_JSONL##*/}"
    chmod 0600 "$REPORT_TEXT" "$REPORT_JSONL" || die "cannot set report permissions"
}

cleanup_workspace() {
    local output_directory_fd="${OUTPUT_DIRECTORY_FD:-}"
    local debug_output_fd="${DEBUG_OUTPUT_FD:-}"
    local debug_output_fd_owned="${DEBUG_OUTPUT_FD_OWNED:-0}"

    if [ "$SCAN_MODE" = "automation" ] && [ "$AUTOMATION_REPORTS_COMMITTED" -eq 0 ]; then
        [ "$AUTOMATION_MARKDOWN_MOVED" -eq 0 ] || rm -f -- "$AUTOMATION_MARKDOWN_PUBLISHED_PATH"
        [ "$AUTOMATION_JSONL_MOVED" -eq 0 ] || rm -f -- "$AUTOMATION_JSONL_PUBLISHED_PATH"
    fi
    if [ -n "$SCRATCH_DIR" ] && [ -d "$SCRATCH_DIR" ]; then
        rm -rf -- "$SCRATCH_DIR"
    fi
    SCRATCH_DIR=""
    REPORT_MARKDOWN_BODY=""
    REPORT_PRIORITY_ERROR=""
    REPORT_PRIORITY_VULNERABLE=""
    REPORT_PRIORITY_MANUAL=""
    if [ -n "$output_directory_fd" ]; then
        exec {output_directory_fd}<&- 2>/dev/null || true
    fi
    OUTPUT_DIRECTORY_FD=""
    OUTPUT_DIRECTORY_FD_PATH=""
    OUTPUT_DIRECTORY_DEVICE_INODE=""
    if [ -n "$debug_output_fd" ] && [ "$debug_output_fd_owned" -eq 1 ]; then
        exec {debug_output_fd}>&- || true
    fi
    DEBUG_OUTPUT_FD=""
    DEBUG_OUTPUT_FD_OWNED=0
}

publish_automation_reports() {
    local markdown_destination=""
    local jsonl_destination=""

    [ "$SCAN_MODE" = "automation" ] || return 0
    [ "$COUNT_TOTAL" -eq 67 ] && [ "$COUNT_MANUAL" -eq 0 ] && [ "$COUNT_ERROR" -eq 0 ] || return 2
    [ "$REPORT_WRITE_ERROR" -eq 0 ] || return 2
    output_directory_binding_is_current || return 2
    [ -f "$REPORT_TEXT" ] && [ ! -L "$REPORT_TEXT" ] || return 2
    [ -f "$REPORT_JSONL" ] && [ ! -L "$REPORT_JSONL" ] || return 2

    markdown_destination="$OUTPUT_DIRECTORY_FD_PATH/${REPORT_MARKDOWN_OUTPUT_PATH##*/}"
    jsonl_destination="$OUTPUT_DIRECTORY_FD_PATH/${REPORT_JSONL_OUTPUT_PATH##*/}"
    [ ! -e "$markdown_destination" ] && [ ! -L "$markdown_destination" ] || return 2
    [ ! -e "$jsonl_destination" ] && [ ! -L "$jsonl_destination" ] || return 2

    AUTOMATION_MARKDOWN_PUBLISHED_PATH="$markdown_destination"
    AUTOMATION_JSONL_PUBLISHED_PATH="$jsonl_destination"
    mv -n -- "$REPORT_TEXT" "$markdown_destination" || return 2
    [ ! -e "$REPORT_TEXT" ] || return 2
    AUTOMATION_MARKDOWN_MOVED=1
    mv -n -- "$REPORT_JSONL" "$jsonl_destination" || return 2
    [ ! -e "$REPORT_JSONL" ] || return 2
    AUTOMATION_JSONL_MOVED=1

    REPORT_TEXT="$markdown_destination"
    REPORT_JSONL="$jsonl_destination"
    [ "$(stat_uid "$REPORT_TEXT" 2>/dev/null || true)" = "$(id -u)" ] || return 2
    [ "$(stat_uid "$REPORT_JSONL" 2>/dev/null || true)" = "$(id -u)" ] || return 2
    [ "$(stat_mode "$REPORT_TEXT" 2>/dev/null || true)" = "600" ] || return 2
    [ "$(stat_mode "$REPORT_JSONL" 2>/dev/null || true)" = "600" ] || return 2
}

write_report_header() {
    local header_platform_base_id=""
    local header_platform_base_version=""
    local header_platform_family=""
    local header_platform_id=""
    local header_platform_id_like=""
    local header_platform_name=""
    local header_platform_version=""
    local header_runtime_mode=""
    local header_scan_mode=""
    local header_policy_directory=""
    local header_evidence_bundle=""
    local header_evidence_captured_at=""
    local header_evidence_machine_id=""
    local header_evidence_boot_id=""
    local header_evidence_kernel_release=""
    local header_evidence_digest=""
    local header_evidence_age=""
    local header_scan_root=""
    local header_started_at=""
    local header_version=""
    local header_variable=""
    local header_value=""

    sanitize_header_field_into "$KISA_CCE_VERSION" header_version || {
        REPORT_WRITE_ERROR=1
        return 1
    }
    sanitize_header_field_into "$PLATFORM_NAME" header_platform_name || {
        REPORT_WRITE_ERROR=1
        return 1
    }
    sanitize_header_field_into "$PLATFORM_ID" header_platform_id || {
        REPORT_WRITE_ERROR=1
        return 1
    }
    sanitize_header_field_into "${PLATFORM_ID_LIKE:-none}" header_platform_id_like || {
        REPORT_WRITE_ERROR=1
        return 1
    }
    sanitize_header_field_into "$PLATFORM_VERSION" header_platform_version || {
        REPORT_WRITE_ERROR=1
        return 1
    }
    sanitize_header_field_into "${PLATFORM_FAMILY:-unknown}" header_platform_family || {
        REPORT_WRITE_ERROR=1
        return 1
    }
    sanitize_header_field_into "${PLATFORM_BASE_ID:-unknown}" header_platform_base_id || {
        REPORT_WRITE_ERROR=1
        return 1
    }
    sanitize_header_field_into "${PLATFORM_BASE_VERSION:-unknown}" header_platform_base_version || {
        REPORT_WRITE_ERROR=1
        return 1
    }
    sanitize_header_field_into "$SCAN_ROOT" header_scan_root || {
        REPORT_WRITE_ERROR=1
        return 1
    }
    sanitize_header_field_into "$RUNTIME_MODE" header_runtime_mode || {
        REPORT_WRITE_ERROR=1
        return 1
    }
    sanitize_header_field_into "$SCAN_MODE" header_scan_mode || {
        REPORT_WRITE_ERROR=1
        return 1
    }
    sanitize_header_field_into "${POLICY_DIRECTORY:-none}" header_policy_directory || {
        REPORT_WRITE_ERROR=1
        return 1
    }
    sanitize_header_field_into "${EVIDENCE_BUNDLE_PATH:-none}" header_evidence_bundle || {
        REPORT_WRITE_ERROR=1
        return 1
    }
    sanitize_header_field_into "${EVIDENCE_CAPTURED_AT:-none}" header_evidence_captured_at || { REPORT_WRITE_ERROR=1; return 1; }
    sanitize_header_field_into "${EVIDENCE_MACHINE_ID:-none}" header_evidence_machine_id || { REPORT_WRITE_ERROR=1; return 1; }
    sanitize_header_field_into "${EVIDENCE_BOOT_ID:-none}" header_evidence_boot_id || { REPORT_WRITE_ERROR=1; return 1; }
    sanitize_header_field_into "${EVIDENCE_KERNEL_RELEASE:-none}" header_evidence_kernel_release || { REPORT_WRITE_ERROR=1; return 1; }
    sanitize_header_field_into "${EVIDENCE_BUNDLE_DIGEST:-none}" header_evidence_digest || { REPORT_WRITE_ERROR=1; return 1; }
    sanitize_header_field_into "${EVIDENCE_AGE_SECONDS:-none}" header_evidence_age || { REPORT_WRITE_ERROR=1; return 1; }
    sanitize_header_field_into "$(date -u +%Y-%m-%dT%H:%M:%SZ)" header_started_at || {
        REPORT_WRITE_ERROR=1
        return 1
    }
    for header_variable in \
        header_version \
        header_platform_name \
        header_platform_id \
        header_platform_id_like \
        header_platform_version \
        header_platform_family \
        header_platform_base_id \
        header_platform_base_version \
        header_scan_root \
        header_runtime_mode \
        header_scan_mode \
        header_policy_directory \
        header_evidence_bundle \
        header_evidence_captured_at \
        header_evidence_machine_id \
        header_evidence_boot_id \
        header_evidence_kernel_release \
        header_evidence_digest \
        header_evidence_age \
        header_started_at; do
        header_value="${!header_variable}"
        escape_markdown_scalar_into "$header_value" "$header_variable" || {
            REPORT_WRITE_ERROR=1
            return 1
        }
    done

    if {
        printf '# %s\n\n' "$REPORT_LABEL_REPORT_TITLE"
        printf '## %s\n\n' "$REPORT_LABEL_SCAN_INFORMATION"
        printf '| %s | %s |\n' "$REPORT_LABEL_FIELD" "$REPORT_LABEL_VALUE"
        printf '|---|---|\n'
        printf '| `scanner_version` | %s |\n' "$header_version"
        printf '| `platform` | %s |\n' "$header_platform_name"
        printf '| `platform_id` | %s |\n' "$header_platform_id"
        printf '| `platform_id_like` | %s |\n' "$header_platform_id_like"
        printf '| `platform_version` | %s |\n' "$header_platform_version"
        printf '| `platform_family` | %s |\n' "$header_platform_family"
        printf '| `platform_base` | %s %s |\n' "$header_platform_base_id" "$header_platform_base_version"
        printf '| `scan_root` | %s |\n' "$header_scan_root"
        printf '| `runtime_collection` | %s |\n' "$header_runtime_mode"
        printf '| `scan_mode` | %s |\n' "$header_scan_mode"
        printf '| `policy_directory` | %s |\n' "$header_policy_directory"
        printf '| `evidence_bundle` | %s |\n' "$header_evidence_bundle"
        printf '| `evidence_captured_at` | %s |\n' "$header_evidence_captured_at"
        printf '| `evidence_machine_id` | %s |\n' "$header_evidence_machine_id"
        printf '| `evidence_boot_id` | %s |\n' "$header_evidence_boot_id"
        printf '| `evidence_kernel_release` | %s |\n' "$header_evidence_kernel_release"
        printf '| `evidence_digest` | %s |\n' "$header_evidence_digest"
        printf '| `evidence_age_seconds` | %s |\n' "$header_evidence_age"
        printf '| `started_at` | %s |\n\n' "$header_started_at"
    } >> "$REPORT_TEXT"; then
        :
    else
        REPORT_WRITE_ERROR=1
        return 1
    fi
    return 0
}

write_report_summary() {
    local assembly_error=0

    if [ -n "$REPORT_MARKDOWN_BODY" ]; then
        [ -f "$REPORT_MARKDOWN_BODY" ] && [ ! -L "$REPORT_MARKDOWN_BODY" ] &&
            [ -f "$REPORT_PRIORITY_ERROR" ] && [ ! -L "$REPORT_PRIORITY_ERROR" ] &&
            [ -f "$REPORT_PRIORITY_VULNERABLE" ] && [ ! -L "$REPORT_PRIORITY_VULNERABLE" ] &&
            [ -f "$REPORT_PRIORITY_MANUAL" ] && [ ! -L "$REPORT_PRIORITY_MANUAL" ] || {
                REPORT_WRITE_ERROR=1
                return 1
            }
    fi

    if {
        printf '## %s\n\n' "$REPORT_LABEL_RESULT_SUMMARY"
        printf '| %s | %s |\n' "$REPORT_LABEL_STATUS" "$REPORT_LABEL_COUNT"
        printf '|---|---:|\n'
        printf '| %s | %d |\n' "$REPORT_LABEL_TOTAL" "$COUNT_TOTAL"
        printf '| %s | %d |\n' "$REPORT_LABEL_ERROR" "$COUNT_ERROR"
        printf '| %s | %d |\n' "$REPORT_LABEL_VULNERABLE" "$COUNT_VULNERABLE"
        printf '| %s | %d |\n' "$REPORT_LABEL_MANUAL" "$COUNT_MANUAL"
        printf '| %s | %d |\n' "$REPORT_LABEL_GOOD" "$COUNT_GOOD"
        printf '| %s | %d |\n' "$REPORT_LABEL_NOT_APPLICABLE" "$COUNT_NOT_APPLICABLE"
        printf '| %s | %d |\n\n' "$REPORT_LABEL_POLICY_RESOLVED" "$COUNT_POLICY_RESOLVED"
        printf "%s: \`%s\`\n\n" "$REPORT_LABEL_COMPLETED_AT" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        if [ -n "$REPORT_MARKDOWN_BODY" ]; then
            if [ "$COUNT_ERROR" -gt 0 ]; then
                printf '### `ERROR` (%d)\n\n' "$COUNT_ERROR"
                cat -- "$REPORT_PRIORITY_ERROR" || assembly_error=1
                printf '\n'
            fi
            if [ "$COUNT_VULNERABLE" -gt 0 ]; then
                printf '### `VULNERABLE` (%d)\n\n' "$COUNT_VULNERABLE"
                cat -- "$REPORT_PRIORITY_VULNERABLE" || assembly_error=1
                printf '\n'
            fi
            if [ "$COUNT_MANUAL" -gt 0 ]; then
                printf '### `MANUAL` (%d)\n\n' "$COUNT_MANUAL"
                cat -- "$REPORT_PRIORITY_MANUAL" || assembly_error=1
                printf '\n'
            fi
            printf '%s\n\n' '---'
            cat -- "$REPORT_MARKDOWN_BODY" || assembly_error=1
        fi
        [ "$assembly_error" -eq 0 ]
    } >> "$REPORT_TEXT"; then
        :
    else
        REPORT_WRITE_ERROR=1
        return 1
    fi

    if ! printf '{"type":"summary","total":%d,"good":%d,"vulnerable":%d,"manual":%d,"not_applicable":%d,"error":%d,"policy_resolved":%d}\n' \
        "$COUNT_TOTAL" "$COUNT_GOOD" "$COUNT_VULNERABLE" "$COUNT_MANUAL" "$COUNT_NOT_APPLICABLE" "$COUNT_ERROR" "$COUNT_POLICY_RESOLVED" >> "$REPORT_JSONL"
    then
        REPORT_WRITE_ERROR=1
        return 1
    fi
    return 0
}

validate_reports() {
    local expected_json_lines=$((COUNT_TOTAL + 1))
    local expected_priority_count=$((COUNT_ERROR + COUNT_VULNERABLE + COUNT_MANUAL))
    local actual_json_lines=""
    local markdown_anchor_count=""
    local markdown_codes=""
    local markdown_priority_count=""
    local markdown_result_count=""
    local jsonl_codes=""

    [ "$REPORT_WRITE_ERROR" -eq 0 ] || return 1
    [ -s "$REPORT_TEXT" ] && [ -s "$REPORT_JSONL" ] || return 1
    [ "$(stat_uid "$REPORT_TEXT" 2>/dev/null || true)" = "$(id -u)" ] || return 1
    [ "$(stat_uid "$REPORT_JSONL" 2>/dev/null || true)" = "$(id -u)" ] || return 1
    [ "$(stat_mode "$REPORT_TEXT" 2>/dev/null || true)" = "600" ] || return 1
    [ "$(stat_mode "$REPORT_JSONL" 2>/dev/null || true)" = "600" ] || return 1
    actual_json_lines="$(wc -l < "$REPORT_JSONL" | tr -d '[:space:]')"
    [ "$actual_json_lines" = "$expected_json_lines" ] || return 1
    markdown_result_count="$(grep -Ec '^## U-[0-9]{2}: ' "$REPORT_TEXT")"
    [ "$markdown_result_count" = "$COUNT_TOTAL" ] || return 1
    markdown_codes="$(sed -n 's/^## \(U-[0-9][0-9]\): .*/\1/p' "$REPORT_TEXT")"
    jsonl_codes="$(sed -n 's/^{"code":"\(U-[0-9][0-9]\)".*/\1/p' "$REPORT_JSONL")"
    [ "$markdown_codes" = "$jsonl_codes" ] || return 1
    [ "$(grep -Fxc -- "# $REPORT_LABEL_REPORT_TITLE" "$REPORT_TEXT")" = 1 ] || return 1
    [ "$(grep -Fxc -- "## $REPORT_LABEL_RESULT_SUMMARY" "$REPORT_TEXT")" = 1 ] || return 1
    [ "$(grep -Fxc -- "| $REPORT_LABEL_TOTAL | $COUNT_TOTAL |" "$REPORT_TEXT")" = 1 ] || return 1
    [ "$(grep -Fxc -- "| $REPORT_LABEL_GOOD | $COUNT_GOOD |" "$REPORT_TEXT")" = 1 ] || return 1
    [ "$(grep -Fxc -- "| $REPORT_LABEL_VULNERABLE | $COUNT_VULNERABLE |" "$REPORT_TEXT")" = 1 ] || return 1
    [ "$(grep -Fxc -- "| $REPORT_LABEL_MANUAL | $COUNT_MANUAL |" "$REPORT_TEXT")" = 1 ] || return 1
    [ "$(grep -Fxc -- "| $REPORT_LABEL_NOT_APPLICABLE | $COUNT_NOT_APPLICABLE |" "$REPORT_TEXT")" = 1 ] || return 1
    [ "$(grep -Fxc -- "| $REPORT_LABEL_ERROR | $COUNT_ERROR |" "$REPORT_TEXT")" = 1 ] || return 1
    [ "$(grep -Fxc -- "| $REPORT_LABEL_POLICY_RESOLVED | $COUNT_POLICY_RESOLVED |" "$REPORT_TEXT")" = 1 ] || return 1
    if [ -n "$REPORT_MARKDOWN_BODY" ]; then
        markdown_anchor_count="$(grep -Ec '^<a id="u-[0-9][0-9]"></a>$' "$REPORT_TEXT")"
        [ "$markdown_anchor_count" = "$COUNT_TOTAL" ] || return 1
        markdown_priority_count="$(grep -Ec '^- \[U-[0-9][0-9]: .*\]\(#u-[0-9][0-9]\) - `[^`]+`$' "$REPORT_TEXT")"
        [ "$markdown_priority_count" = "$expected_priority_count" ] || return 1
        awk -v expected="$expected_priority_count" '
            /^- \[U-[0-9][0-9]: / {
                code=substr($0, 4, 4)
                if (!match($0, /\]\(#u-[0-9][0-9]\) - `[^`]+`$/)) exit 1
                target=substr($0, RSTART + 3, 4)
                if (tolower(code) != target) exit 1
                count++
            }
            END {exit(count == expected ? 0 : 1)}
        ' "$REPORT_TEXT" || return 1
    fi
    if [ "$SCAN_MODE" = "complete" ] || [ "$SCAN_MODE" = "automation" ]; then
        [ "$COUNT_TOTAL" -eq 67 ] || return 1
        [ "$COUNT_MANUAL" -eq 0 ] || return 1
    fi
    if [ "$SCAN_MODE" = "automation" ]; then
        [ "$COUNT_ERROR" -eq 0 ] || return 1
        awk '
            /^\{"code":"U-[0-9][0-9]"/ {
                count++
                if ($0 !~ /"status":"(GOOD|VULNERABLE|NOT_APPLICABLE)"/) exit 1
                if ($0 !~ /"technical_status":"(GOOD|VULNERABLE|NOT_APPLICABLE)"/) exit 1
            }
            END {exit(count == 67 ? 0 : 1)}
        ' "$REPORT_JSONL" || return 1
    fi
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
