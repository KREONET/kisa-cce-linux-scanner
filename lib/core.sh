# shellcheck shell=bash

# Core runtime and reporting helpers for the KISA CCE Linux scanner.

KISA_CCE_VERSION="${KISA_CCE_VERSION:?KISA_CCE_VERSION must be loaded from data/VERSION}"
KISA_CCE_GUIDE_BASE="https://kreonet.github.io/kisa-cce-guide-web"
SCAN_ROOT="${SCAN_ROOT:-/}"
RUNTIME_MODE="${RUNTIME_MODE:-auto}"
OUTPUT_PARENT="${OUTPUT_PARENT:-}"
SELECTED_CHECKS="${SELECTED_CHECKS:-}"
VERBOSE="${VERBOSE:-0}"
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
OUTPUT_DIRECTORY_FD=""
OUTPUT_DIRECTORY_FD_PATH=""
OUTPUT_DIRECTORY_DEVICE_INODE=""
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

declare -A TRUSTED_COMMAND_CACHE=()
TRUSTED_COMMAND_CACHE_FILE=""
CANONICAL_SCAN_ROOT_SOURCE=""
CANONICAL_SCAN_ROOT_VALUE=""
CANONICAL_SCAN_ROOT_READY=0
LISTENER_SNAPSHOT_CACHE_ENABLED=0
LISTENER_SNAPSHOT_GENERATION=0

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

verbose() {
    [ "$VERBOSE" -eq 1 ] || return 0
    printf 'VERBOSE: %s\n' "$*" >&2
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

trusted_command() {
    local command_name="$1"
    local candidate=""
    local candidate_owner=""
    local candidate_mode=""
    local resolved_candidate=""
    local cached_name=""
    local cached_candidate=""
    local cacheable=0

    runtime_enabled || return 1

    case "$command_name" in
        ''|*[!A-Za-z0-9._+-]*) ;;
        *) cacheable=1 ;;
    esac
    if [ "$cacheable" -eq 1 ] &&
        [ "${TRUSTED_COMMAND_CACHE[$command_name]+present}" = "present" ]; then
        cached_candidate="${TRUSTED_COMMAND_CACHE[$command_name]}"
        if [ -x "$cached_candidate" ]; then
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
    RESULT_SUMMARY="$summary"
    RESULT_EVIDENCE="$evidence"
    RESULT_APPLICABLE="$applicable"
}

evidence_requires_redaction() {
    local input_value="$1"
    local sensitive_keyword_pattern='password|passwd|secret|token|passphrase|rocommunity|rwcommunity|com2sec|authcommunity|createUser'
    local nocasematch_was_set=0
    local match_status=1

    shopt -q nocasematch && nocasematch_was_set=1
    shopt -s nocasematch
    if [[ "$input_value" == *'$'* ]] || [[ "$input_value" =~ $sensitive_keyword_pattern ]]; then
        match_status=0
    fi
    if [ "$nocasematch_was_set" -eq 0 ]; then
        shopt -u nocasematch
    fi
    return "$match_status"
}

redact_and_limit_evidence_into() {
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
            -e 's/((password|passwd|secret|token|passphrase)[[:space:]]*[:=][[:space:]]*)".*"/\1[REDACTED]/Ig' \
            -e 's/((password|passwd|secret|token|passphrase)[[:space:]]*[:=][[:space:]]*)".*/\1[REDACTED]/Ig' \
            -e "s/((password|passwd|secret|token|passphrase)[[:space:]]*[:=][[:space:]]*)'.*'/\\1[REDACTED]/Ig" \
            -e "s/((password|passwd|secret|token|passphrase)[[:space:]]*[:=][[:space:]]*)'.*/\\1[REDACTED]/Ig" \
            -e 's/((password|passwd|secret|token|passphrase)[[:space:]]*[:=][[:space:]]*)[^[:space:]]+/\1[REDACTED]/Ig' \
            <<< "$__kisa_evidence_input")"
    fi
    if [ "${#__kisa_evidence_input}" -gt 8192 ]; then
        __kisa_evidence_input="${__kisa_evidence_input:0:8192}"
    fi
    while [[ "$__kisa_evidence_input" == *$'\n' ]]; do
        __kisa_evidence_input="${__kisa_evidence_input%$'\n'}"
    done
    printf -v "$__kisa_evidence_destination" '%s' "$__kisa_evidence_input"
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
    local markdown_title=""
    local markdown_summary=""
    local markdown_evidence=""

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
    redact_and_limit_evidence_into "$normalized_evidence" normalized_evidence
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
    fi
    escape_markdown_scalar_into "$normalized_title" markdown_title || {
        REPORT_WRITE_ERROR=1
        return 1
    }
    escape_markdown_scalar_into "$normalized_summary" markdown_summary || {
        REPORT_WRITE_ERROR=1
        return 1
    }

    if {
        printf '## %s: %s\n\n' "$code" "$markdown_title"
        printf '| 항목 | 값 |\n'
        printf '|---|---|\n'
        printf "| 분류 | \`%s\` |\n" "$category"
        printf "| 중요도 | \`%s\` |\n" "$severity"
        printf "| 판정 | \`%s\` |\n" "$RESULT_STATUS"
        printf "| 적용 여부 | \`%s\` |\n\n" "$RESULT_APPLICABLE"
        printf '### 요약\n\n%s\n\n' "$markdown_summary"
        if [ -n "$RESULT_EVIDENCE" ]; then
            printf '### 근거\n\n%s\n\n' "$markdown_evidence"
        fi
        printf '### 기준\n\n'
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
    if ! printf '{"code":"%s","category":"%s","severity":"%s","title":"%s","status":"%s","applicable":%s,"summary":"%s","evidence":"%s","criterion_url":"%s"}\n' \
        "$code" "$escaped_category" "$escaped_severity" "$escaped_title" "$RESULT_STATUS" "$RESULT_APPLICABLE" \
        "$escaped_summary" "$escaped_evidence" "$criterion_url" >> "$REPORT_JSONL"; then
        REPORT_WRITE_ERROR=1
        return 1
    fi

    increment_status "$RESULT_STATUS"
    verbose "check=${code} status=${RESULT_STATUS} title=${title}"
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

    if [ "$LISTENER_SNAPSHOT_CACHE_ENABLED" -eq 1 ]; then
        LISTENER_SNAPSHOT_GENERATION=$((LISTENER_SNAPSHOT_GENERATION + 1))
    fi
    function_name="check_u_${code#U-}"
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
    # shellcheck disable=SC2034
    local canonical_root=""

    if [ -z "$OUTPUT_PARENT" ]; then
        if [ "$(id -u)" -eq 0 ]; then
            default_parent="/var/log/kisa-cce-scanner"
        else
            default_parent="/tmp/kisa-cce-scanner-$(id -u)"
        fi
        OUTPUT_PARENT="$default_parent"
    fi

    normalize_output_parent_into "$OUTPUT_PARENT" normalized_output_parent ||
        die "출력 디렉터리 경로가 안전한 절대 경로가 아닙니다: $OUTPUT_PARENT"
    OUTPUT_PARENT="$normalized_output_parent"
    output_path_has_no_symlink_components "$OUTPUT_PARENT" ||
        die "출력 디렉터리 경로에 심볼릭 링크가 포함되어 있습니다: $OUTPUT_PARENT"
    output_path_components_are_trusted "$OUTPUT_PARENT" ||
        die "출력 디렉터리의 상위 경로가 신뢰할 수 없습니다: $OUTPUT_PARENT"
    if [ -e "$OUTPUT_PARENT" ]; then
        [ -d "$OUTPUT_PARENT" ] || die "출력 경로가 디렉터리가 아닙니다: $OUTPUT_PARENT"
    else
        mkdir -p -- "$OUTPUT_PARENT" || die "출력 디렉터리를 만들 수 없습니다: $OUTPUT_PARENT"
    fi
    output_path_has_no_symlink_components "$OUTPUT_PARENT" ||
        die "출력 디렉터리 경로에 심볼릭 링크가 포함되어 있습니다: $OUTPUT_PARENT"
    output_path_components_are_trusted "$OUTPUT_PARENT" ||
        die "출력 디렉터리의 상위 경로가 신뢰할 수 없습니다: $OUTPUT_PARENT"

    if ! exec {OUTPUT_DIRECTORY_FD}<"$OUTPUT_PARENT"; then
        die "출력 디렉터리를 열 수 없습니다: $OUTPUT_PARENT"
    fi
    OUTPUT_DIRECTORY_FD_PATH="/proc/self/fd/$OUTPUT_DIRECTORY_FD"
    [ -d "$OUTPUT_DIRECTORY_FD_PATH" ] || die "출력 디렉터리 설명자를 확인할 수 없습니다: $OUTPUT_PARENT"

    current_uid="$(id -u)"
    output_uid="$(stat_uid "$OUTPUT_DIRECTORY_FD_PATH" 2>/dev/null || true)"
    [ "$output_uid" = "$current_uid" ] || die "출력 디렉터리 소유자가 현재 사용자와 다릅니다."
    parent_mode="$(stat_mode "$OUTPUT_DIRECTORY_FD_PATH" 2>/dev/null || true)"
    mode_has_group_or_other_permissions "$parent_mode" && die "출력 디렉터리는 소유자만 접근 가능한 0700 이하 권한이어야 합니다."
    parent_decimal_mode="$(mode_to_decimal "$parent_mode" 2>/dev/null || true)"
    [ -n "$parent_decimal_mode" ] && [ $((parent_decimal_mode & 8#700)) -eq $((8#700)) ] ||
        die "출력 디렉터리는 소유자 읽기, 쓰기 및 검색 권한이 필요합니다."
    OUTPUT_DIRECTORY_DEVICE_INODE="$(stat_device_inode "$OUTPUT_DIRECTORY_FD_PATH")" ||
        die "출력 디렉터리 설명자를 확인할 수 없습니다: $OUTPUT_PARENT"
    output_directory_binding_is_current ||
        die "출력 디렉터리 경로가 검사 중 변경되었습니다: $OUTPUT_PARENT"

    SCRATCH_DIR="$(mktemp -d "$OUTPUT_DIRECTORY_FD_PATH/.run.XXXXXXXX")" || die "안전한 임시 디렉터리를 만들 수 없습니다."
    chmod 0700 "$SCRATCH_DIR" || die "임시 디렉터리 권한을 설정할 수 없습니다."
    canonical_scan_root_into canonical_root || die "검사 루트를 확인할 수 없습니다: $SCAN_ROOT"
    TRUSTED_COMMAND_CACHE=()
    TRUSTED_COMMAND_CACHE_FILE="$SCRATCH_DIR/trusted-command-cache"
    : > "$TRUSTED_COMMAND_CACHE_FILE" || die "명령 경로 캐시를 만들 수 없습니다."
    # This flag is consumed by the listener resolver after all libraries load.
    # shellcheck disable=SC2034
    LISTENER_SNAPSHOT_CACHE_ENABLED=1
    LISTENER_SNAPSHOT_GENERATION=0

    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    hostname_value="$(hostname 2>/dev/null | tr -cd 'A-Za-z0-9._-' | cut -c1-63)"
    [ -n "$hostname_value" ] || hostname_value="host"

    markdown_report_temp="$(mktemp "$OUTPUT_DIRECTORY_FD_PATH/kisa-cce-${hostname_value}-${timestamp}.XXXXXXXX")" ||
        die "Markdown 보고서를 만들 수 없습니다."
    REPORT_TEXT="${markdown_report_temp}.md"
    mv -- "$markdown_report_temp" "$REPORT_TEXT" || die "Markdown 보고서 이름을 확정할 수 없습니다."
    REPORT_MARKDOWN_OUTPUT_PATH="$OUTPUT_PARENT/${REPORT_TEXT##*/}"
    REPORT_JSONL="$(mktemp "$OUTPUT_DIRECTORY_FD_PATH/kisa-cce-${hostname_value}-${timestamp}.jsonl.XXXXXXXX")" || die "JSONL 보고서를 만들 수 없습니다."
    REPORT_JSONL_OUTPUT_PATH="$OUTPUT_PARENT/${REPORT_JSONL##*/}"
    chmod 0600 "$REPORT_TEXT" "$REPORT_JSONL" || die "보고서 권한을 설정할 수 없습니다."
}

cleanup_workspace() {
    local output_directory_fd="${OUTPUT_DIRECTORY_FD:-}"

    if [ -n "$SCRATCH_DIR" ] && [ -d "$SCRATCH_DIR" ]; then
        rm -rf -- "$SCRATCH_DIR"
    fi
    SCRATCH_DIR=""
    if [ -n "$output_directory_fd" ]; then
        exec {output_directory_fd}<&- 2>/dev/null || true
    fi
    OUTPUT_DIRECTORY_FD=""
    OUTPUT_DIRECTORY_FD_PATH=""
    OUTPUT_DIRECTORY_DEVICE_INODE=""
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
    local header_scan_root=""
    local header_started_at=""
    local header_version=""

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
    sanitize_header_field_into "$(date -u +%Y-%m-%dT%H:%M:%SZ)" header_started_at || {
        REPORT_WRITE_ERROR=1
        return 1
    }

    if {
        printf '# KISA CCE 2026 Linux 보안 점검 보고서\n\n'
        printf '## 점검 정보\n\n'
        printf '    scanner_version: %s\n' "$header_version"
        printf '    platform: %s\n' "$header_platform_name"
        printf '    platform_id: %s\n' "$header_platform_id"
        printf '    platform_id_like: %s\n' "$header_platform_id_like"
        printf '    platform_version: %s\n' "$header_platform_version"
        printf '    platform_family: %s\n' "$header_platform_family"
        printf '    platform_base: %s %s\n' "$header_platform_base_id" "$header_platform_base_version"
        printf '    scan_root: %s\n' "$header_scan_root"
        printf '    runtime_collection: %s\n' "$header_runtime_mode"
        printf '    started_at: %s\n\n' "$header_started_at"
        printf '%s\n\n' '---'
    } >> "$REPORT_TEXT"; then
        :
    else
        REPORT_WRITE_ERROR=1
        return 1
    fi
    return 0
}

write_report_summary() {
    if {
        printf '## 판정 요약\n\n'
        printf '| 판정 | 개수 |\n'
        printf '|---|---:|\n'
        printf '| 전체 | %d |\n' "$COUNT_TOTAL"
        printf '| 양호 | %d |\n' "$COUNT_GOOD"
        printf '| 취약 | %d |\n' "$COUNT_VULNERABLE"
        printf '| 수동 확인 | %d |\n' "$COUNT_MANUAL"
        printf '| 해당 없음 | %d |\n' "$COUNT_NOT_APPLICABLE"
        printf '| 오류 | %d |\n\n' "$COUNT_ERROR"
        printf "완료 시각: \`%s\`\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } >> "$REPORT_TEXT"; then
        :
    else
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
    local markdown_codes=""
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
    [ "$(grep -Fxc -- '# KISA CCE 2026 Linux 보안 점검 보고서' "$REPORT_TEXT")" = 1 ] || return 1
    [ "$(grep -Fxc -- '## 판정 요약' "$REPORT_TEXT")" = 1 ] || return 1
    [ "$(grep -Fxc -- "| 전체 | $COUNT_TOTAL |" "$REPORT_TEXT")" = 1 ] || return 1
    [ "$(grep -Fxc -- "| 양호 | $COUNT_GOOD |" "$REPORT_TEXT")" = 1 ] || return 1
    [ "$(grep -Fxc -- "| 취약 | $COUNT_VULNERABLE |" "$REPORT_TEXT")" = 1 ] || return 1
    [ "$(grep -Fxc -- "| 수동 확인 | $COUNT_MANUAL |" "$REPORT_TEXT")" = 1 ] || return 1
    [ "$(grep -Fxc -- "| 해당 없음 | $COUNT_NOT_APPLICABLE |" "$REPORT_TEXT")" = 1 ] || return 1
    [ "$(grep -Fxc -- "| 오류 | $COUNT_ERROR |" "$REPORT_TEXT")" = 1 ] || return 1
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
