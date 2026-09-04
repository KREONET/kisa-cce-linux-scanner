# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash
# shellcheck disable=SC2034

# Transactional metadata-only remediation engine for the KISA CCE Linux patcher.

PATCH_ENGINE_TSV_HEADER=$'schema\tcriterion\tstate\taction\tpath\troot_device\troot_inode\tdevice\tinode\tbefore_uid\tbefore_gid\tbefore_mode\tafter_uid\tafter_gid\tafter_mode\tsize\tmtime\tctime\tcontent_sha256'

PATCH_ENGINE_ROOT=""
PATCH_ENGINE_ROOT_DEVICE=""
PATCH_ENGINE_ROOT_INODE=""
PATCH_ENGINE_PLAN_VALID=0
PATCH_ENGINE_TRANSACTION_WRITTEN=0
PATCH_ENGINE_TRANSACTION_LOADED=0
PATCH_ENGINE_APPLY_STARTED=0
PATCH_ENGINE_CHANGE_COUNT=0
PATCH_ENGINE_COMPLIANT_COUNT=0
PATCH_ENGINE_NOT_APPLICABLE_COUNT=0
PATCH_ENGINE_ERROR_DETAIL=""

PATCH_ENGINE_CRITERIA=()
PATCH_ENGINE_SELECTED_CRITERIA=()
PATCH_ENGINE_STATES=()
PATCH_ENGINE_ACTIONS=()
PATCH_ENGINE_LOGICAL_PATHS=()
PATCH_ENGINE_PHYSICAL_PATHS=()
PATCH_ENGINE_DEVICES=()
PATCH_ENGINE_INODES=()
PATCH_ENGINE_BEFORE_UIDS=()
PATCH_ENGINE_BEFORE_GIDS=()
PATCH_ENGINE_BEFORE_MODES=()
PATCH_ENGINE_AFTER_UIDS=()
PATCH_ENGINE_AFTER_GIDS=()
PATCH_ENGINE_AFTER_MODES=()
PATCH_ENGINE_SIZES=()
PATCH_ENGINE_MTIMES=()
PATCH_ENGINE_CTIMES=()
PATCH_ENGINE_CONTENT_SHA256S=()
PATCH_ENGINE_TARGET_TYPES=()
PATCH_ENGINE_APPLIED_INDEXES=()

PATCH_ENGINE_CAPTURE_DEVICE=""
PATCH_ENGINE_CAPTURE_INODE=""
PATCH_ENGINE_CAPTURE_UID=""
PATCH_ENGINE_CAPTURE_GID=""
PATCH_ENGINE_CAPTURE_MODE=""
PATCH_ENGINE_CAPTURE_LINKS=""
PATCH_ENGINE_CAPTURE_SIZE=""
PATCH_ENGINE_CAPTURE_MTIME=""
PATCH_ENGINE_CAPTURE_CTIME=""
PATCH_ENGINE_CAPTURE_CONTENT_SHA256=""
PATCH_ENGINE_CAPTURE_TARGET_TYPE=""

_patch_engine_valid_destination() {
    case "$1" in
        ''|[0-9]*|*[!A-Za-z0-9_]*) return 1 ;;
        *) return 0 ;;
    esac
}

_patch_engine_set_error() {
    PATCH_ENGINE_ERROR_DETAIL="$1"
    PATCH_ENGINE_PLAN_VALID=0
    return 2
}

_patch_engine_command_into() {
    local command_name="$1"
    local destination_name="$2"
    local candidate=""

    _patch_engine_valid_destination "$destination_name" || return 2
    case "$command_name" in
        chmod) candidate=/bin/chmod ;;
        chown)
            if [ -x /usr/bin/chown ]; then
                candidate=/usr/bin/chown
            else
                candidate=/usr/sbin/chown
            fi
            ;;
        find) candidate=/usr/bin/find ;;
        mktemp) candidate=/usr/bin/mktemp ;;
        rm) candidate=/bin/rm ;;
        sha256sum)
            if [ -x /usr/bin/sha256sum ]; then
                candidate=/usr/bin/sha256sum
            elif [ -x /bin/sha256sum ]; then
                candidate=/bin/sha256sum
            else
                candidate=/usr/bin/shasum
            fi
            ;;
        stat) candidate=/usr/bin/stat ;;
        *) return 2 ;;
    esac
    [ -x "$candidate" ] || return 127
    printf -v "$destination_name" '%s' "$candidate"
}

_patch_engine_stat_into() {
    local path="$1"
    local device_destination="$2"
    local inode_destination="$3"
    local uid_destination="$4"
    local gid_destination="$5"
    local mode_destination="$6"
    local links_destination="$7"
    local size_destination="${8:-}"
    local mtime_destination="${9:-}"
    local ctime_destination="${10:-}"
    local __kisa_patch_stat_command=""
    local __kisa_patch_stat_output=""
    local __kisa_patch_stat_device=""
    local __kisa_patch_stat_inode=""
    local __kisa_patch_stat_owner_uid=""
    local __kisa_patch_stat_owner_gid=""
    local __kisa_patch_stat_mode=""
    local __kisa_patch_stat_links=""
    local __kisa_patch_stat_size=""
    local __kisa_patch_stat_mtime=""
    local __kisa_patch_stat_ctime=""
    local __kisa_patch_stat_remainder=""

    _patch_engine_valid_destination "$device_destination" || return 2
    _patch_engine_valid_destination "$inode_destination" || return 2
    _patch_engine_valid_destination "$uid_destination" || return 2
    _patch_engine_valid_destination "$gid_destination" || return 2
    _patch_engine_valid_destination "$mode_destination" || return 2
    _patch_engine_valid_destination "$links_destination" || return 2
    [ -z "$size_destination" ] || _patch_engine_valid_destination "$size_destination" || return 2
    [ -z "$mtime_destination" ] || _patch_engine_valid_destination "$mtime_destination" || return 2
    [ -z "$ctime_destination" ] || _patch_engine_valid_destination "$ctime_destination" || return 2
    _patch_engine_command_into stat __kisa_patch_stat_command || return $?

    if __kisa_patch_stat_output="$($__kisa_patch_stat_command -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' -- "$path" 2>/dev/null)"; then
        :
    elif __kisa_patch_stat_output="$($__kisa_patch_stat_command -f '%d:%i:%u:%g:%Lp:%l:%z:%m:%c' "$path" 2>/dev/null)"; then
        :
    else
        return 2
    fi
    IFS=: read -r __kisa_patch_stat_device __kisa_patch_stat_inode __kisa_patch_stat_owner_uid \
        __kisa_patch_stat_owner_gid __kisa_patch_stat_mode __kisa_patch_stat_links \
        __kisa_patch_stat_size __kisa_patch_stat_mtime __kisa_patch_stat_ctime \
        __kisa_patch_stat_remainder <<< "$__kisa_patch_stat_output"
    [ -z "$__kisa_patch_stat_remainder" ] || return 2
    case "$__kisa_patch_stat_device:$__kisa_patch_stat_inode:$__kisa_patch_stat_owner_uid:$__kisa_patch_stat_owner_gid:$__kisa_patch_stat_links" in
        *[!0-9:]*) return 2 ;;
    esac
    case "$__kisa_patch_stat_mode" in
        ''|*[!0-7]*) return 2 ;;
    esac
    case "$__kisa_patch_stat_size:$__kisa_patch_stat_mtime:$__kisa_patch_stat_ctime" in
        *[!0-9:]*) return 2 ;;
    esac
    [ -n "$__kisa_patch_stat_size" ] && [ -n "$__kisa_patch_stat_mtime" ] &&
        [ -n "$__kisa_patch_stat_ctime" ] || return 2

    printf -v "$device_destination" '%s' "$__kisa_patch_stat_device"
    printf -v "$inode_destination" '%s' "$__kisa_patch_stat_inode"
    printf -v "$uid_destination" '%s' "$__kisa_patch_stat_owner_uid"
    printf -v "$gid_destination" '%s' "$__kisa_patch_stat_owner_gid"
    printf -v "$mode_destination" '%s' "$__kisa_patch_stat_mode"
    printf -v "$links_destination" '%s' "$__kisa_patch_stat_links"
    [ -z "$size_destination" ] || printf -v "$size_destination" '%s' "$__kisa_patch_stat_size"
    [ -z "$mtime_destination" ] || printf -v "$mtime_destination" '%s' "$__kisa_patch_stat_mtime"
    [ -z "$ctime_destination" ] || printf -v "$ctime_destination" '%s' "$__kisa_patch_stat_ctime"
}

_patch_engine_sha256_into() {
    local path="$1"
    local destination_name="$2"
    local hash_command=""
    local hash_output=""
    local digest=""

    _patch_engine_valid_destination "$destination_name" || return 2
    _patch_engine_command_into sha256sum hash_command || return $?
    case "$hash_command" in
        */shasum) hash_output="$("$hash_command" -a 256 -- "$path" 2>/dev/null)" || return 2 ;;
        *) hash_output="$("$hash_command" -- "$path" 2>/dev/null)" || return 2 ;;
    esac
    digest="${hash_output%% *}"
    [ "${#digest}" -eq 64 ] || return 2
    case "$digest" in
        *[!0-9a-f]*) return 2 ;;
    esac
    printf -v "$destination_name" '%s' "$digest"
}

_patch_engine_capture_fingerprint() {
    local path="$1"
    local target_type=""
    local device_before=""
    local inode_before=""
    local uid_before=""
    local gid_before=""
    local mode_before=""
    local links_before=""
    local size_before=""
    local mtime_before=""
    local ctime_before=""
    local normalized_mode_before=""
    local content_sha256=""
    local device_after=""
    local inode_after=""
    local uid_after=""
    local gid_after=""
    local mode_after=""
    local links_after=""
    local size_after=""
    local mtime_after=""
    local ctime_after=""
    local normalized_mode_after=""

    [ ! -L "$path" ] || return 2
    if [ -f "$path" ]; then
        target_type='file'
    elif [ -d "$path" ]; then
        target_type=directory
    else
        return 2
    fi
    _patch_engine_stat_into "$path" device_before inode_before uid_before gid_before mode_before \
        links_before size_before mtime_before ctime_before || return 2
    if [ "$target_type" = file ]; then
        [ "$links_before" = 1 ] || return 2
    fi
    _patch_engine_normalize_mode_into "$mode_before" normalized_mode_before || return 2
    if [ "$target_type" = file ]; then
        _patch_engine_sha256_into "$path" content_sha256 || return 2
    else
        content_sha256=0000000000000000000000000000000000000000000000000000000000000000
    fi
    _patch_engine_stat_into "$path" device_after inode_after uid_after gid_after mode_after \
        links_after size_after mtime_after ctime_after || return 2
    if [ "$target_type" = file ]; then
        [ "$links_after" = 1 ] || return 2
    fi
    _patch_engine_normalize_mode_into "$mode_after" normalized_mode_after || return 2
    [ "$device_before" = "$device_after" ] && [ "$inode_before" = "$inode_after" ] &&
        [ "$uid_before" = "$uid_after" ] && [ "$gid_before" = "$gid_after" ] &&
        [ "$normalized_mode_before" = "$normalized_mode_after" ] &&
        [ "$size_before" = "$size_after" ] && [ "$mtime_before" = "$mtime_after" ] &&
        [ "$ctime_before" = "$ctime_after" ] || return 2

    PATCH_ENGINE_CAPTURE_DEVICE="$device_after"
    PATCH_ENGINE_CAPTURE_INODE="$inode_after"
    PATCH_ENGINE_CAPTURE_UID="$uid_after"
    PATCH_ENGINE_CAPTURE_GID="$gid_after"
    PATCH_ENGINE_CAPTURE_MODE="$normalized_mode_after"
    PATCH_ENGINE_CAPTURE_LINKS="$links_after"
    PATCH_ENGINE_CAPTURE_SIZE="$size_after"
    PATCH_ENGINE_CAPTURE_MTIME="$mtime_after"
    PATCH_ENGINE_CAPTURE_CTIME="$ctime_after"
    PATCH_ENGINE_CAPTURE_CONTENT_SHA256="$content_sha256"
    PATCH_ENGINE_CAPTURE_TARGET_TYPE="$target_type"
}

_patch_engine_normalize_mode_into() {
    local input_mode="$1"
    local destination_name="$2"
    local __kisa_patch_mode_decimal=0
    local __kisa_patch_mode_normalized=""

    _patch_engine_valid_destination "$destination_name" || return 2
    case "$input_mode" in
        ''|*[!0-7]*) return 2 ;;
    esac
    __kisa_patch_mode_decimal=$((8#$input_mode))
    [ "$__kisa_patch_mode_decimal" -ge 0 ] && [ "$__kisa_patch_mode_decimal" -le 4095 ] || return 2
    printf -v __kisa_patch_mode_normalized '%04o' "$__kisa_patch_mode_decimal"
    printf -v "$destination_name" '%s' "$__kisa_patch_mode_normalized"
}

_patch_engine_tightened_mode_into() {
    local current_mode="$1"
    local maximum_mode="$2"
    local destination_name="$3"
    local current_decimal=0
    local maximum_decimal=0
    local __kisa_patch_desired_decimal=0
    local __kisa_patch_desired_mode=""

    _patch_engine_valid_destination "$destination_name" || return 2
    case "$current_mode:$maximum_mode" in
        *[!0-7:]*) return 2 ;;
    esac
    current_decimal=$((8#$current_mode))
    maximum_decimal=$((8#$maximum_mode))
    __kisa_patch_desired_decimal=$((current_decimal & maximum_decimal))
    printf -v __kisa_patch_desired_mode '%04o' "$__kisa_patch_desired_decimal"
    printf -v "$destination_name" '%s' "$__kisa_patch_desired_mode"
}

_patch_engine_remove_untrusted_write_into() {
    local current_mode="$1"
    local destination_name="$2"
    local current_decimal=0
    local desired_decimal=0
    local desired_mode=""

    _patch_engine_valid_destination "$destination_name" || return 2
    case "$current_mode" in ''|*[!0-7]*) return 2 ;; esac
    current_decimal=$((8#$current_mode))
    desired_decimal=$((current_decimal & ~0022 & 07777))
    printf -v desired_mode '%04o' "$desired_decimal"
    printf -v "$destination_name" '%s' "$desired_mode"
}

_patch_engine_index_into() {
    local criterion="$1"
    local destination_name="$2"
    local __kisa_patch_index=0

    _patch_engine_valid_destination "$destination_name" || return 2
    while [ "$__kisa_patch_index" -lt "${#PATCH_ENGINE_CRITERIA[@]}" ]; do
        if [ "${PATCH_ENGINE_CRITERIA[$__kisa_patch_index]}" = "$criterion" ]; then
            printf -v "$destination_name" '%s' "$__kisa_patch_index"
            return 0
        fi
        __kisa_patch_index=$((__kisa_patch_index + 1))
    done
    return 1
}

_patch_engine_criterion_is_selected() {
    local criterion="$1"
    local selected=""

    for selected in "${PATCH_ENGINE_SELECTED_CRITERIA[@]}"; do
        [ "$selected" != "$criterion" ] || return 0
    done
    return 1
}

_patch_engine_record_path_exists() {
    local criterion="$1"
    local logical_path="$2"
    local index=0

    while [ "$index" -lt "${#PATCH_ENGINE_CRITERIA[@]}" ]; do
        if [ "${PATCH_ENGINE_CRITERIA[$index]}" = "$criterion" ] &&
            [ "${PATCH_ENGINE_LOGICAL_PATHS[$index]}" = "$logical_path" ]; then
            return 0
        fi
        index=$((index + 1))
    done
    return 1
}

_patch_engine_logical_path_into() {
    local physical_path="$1"
    local destination_name="$2"
    local __kisa_logical_result=""

    _patch_engine_valid_destination "$destination_name" || return 2
    if [ "$PATCH_ENGINE_ROOT" = / ]; then
        case "$physical_path" in /*) __kisa_logical_result="$physical_path" ;; *) return 2 ;; esac
    else
        case "$physical_path" in
            "$PATCH_ENGINE_ROOT") __kisa_logical_result=/ ;;
            "$PATCH_ENGINE_ROOT"/*) __kisa_logical_result="/${physical_path#"$PATCH_ENGINE_ROOT"/}" ;;
            *) return 2 ;;
        esac
    fi
    case "$__kisa_logical_result" in
        *$'\n'*|*$'\r'*|*$'\t'*|*/../*|*/..|*/./*|*/.) return 2 ;;
    esac
    printf -v "$destination_name" '%s' "$__kisa_logical_result"
}

_patch_engine_dynamic_rule_into() {
    local __kisa_dynamic_criterion="$1"
    local __kisa_dynamic_logical_path="$2"
    local __kisa_dynamic_target_type="$3"
    local __kisa_dynamic_owner_destination="$4"
    local __kisa_dynamic_mode_kind_destination="$5"
    local __kisa_dynamic_maximum_mode_destination="$6"
    local __kisa_dynamic_owner_uid=0
    local __kisa_dynamic_mode_kind=maximum
    local __kisa_dynamic_maximum_mode=""

    _patch_engine_valid_destination "$__kisa_dynamic_owner_destination" || return 2
    _patch_engine_valid_destination "$__kisa_dynamic_mode_kind_destination" || return 2
    _patch_engine_valid_destination "$__kisa_dynamic_maximum_mode_destination" || return 2
    case "$__kisa_dynamic_criterion:$__kisa_dynamic_target_type" in
        U-37:file)
            case "$__kisa_dynamic_logical_path" in
                /usr/bin/crontab|/usr/bin/at) __kisa_dynamic_maximum_mode=0750 ;;
                /etc/crontab|/etc/anacrontab|/etc/cron.allow|/etc/cron.deny|/etc/at.allow|/etc/at.deny|\
                /etc/cron.d/*|/etc/cron.hourly/*|/etc/cron.daily/*|/etc/cron.weekly/*|/etc/cron.monthly/*|\
                /var/spool/cron/*|\
                /var/spool/at/*|/var/spool/anacron/*)
                    __kisa_dynamic_maximum_mode=0640
                    ;;
                *) return 1 ;;
            esac
            ;;
        U-67:file)
            case "$__kisa_dynamic_logical_path" in /var/log/*) __kisa_dynamic_maximum_mode=0644 ;; *) return 1 ;; esac
            ;;
        U-67:directory)
            case "$__kisa_dynamic_logical_path" in /var/log|/var/log/*) ;; *) return 1 ;; esac
            __kisa_dynamic_mode_kind=remove_untrusted_write
            __kisa_dynamic_maximum_mode=-
            ;;
        *) return 1 ;;
    esac
    printf -v "$__kisa_dynamic_owner_destination" '%s' "$__kisa_dynamic_owner_uid"
    printf -v "$__kisa_dynamic_mode_kind_destination" '%s' "$__kisa_dynamic_mode_kind"
    printf -v "$__kisa_dynamic_maximum_mode_destination" '%s' "$__kisa_dynamic_maximum_mode"
}

_patch_engine_root_component_is_trusted() {
    local directory_path="$1"
    local device=""
    local inode=""
    local owner_uid=""
    local owner_gid=""
    local mode=""
    local links=""
    local normalized_mode=""
    local mode_decimal=0
    local effective_uid="${EUID:-}"

    [ -d "$directory_path" ] && [ ! -L "$directory_path" ] || return 2
    _patch_engine_stat_into "$directory_path" device inode owner_uid owner_gid mode links || return 2
    _patch_engine_normalize_mode_into "$mode" normalized_mode || return 2
    mode_decimal=$((8#$normalized_mode))
    [ -n "$effective_uid" ] || effective_uid="$owner_uid"
    [ "$owner_uid" = 0 ] || [ "$owner_uid" = "$effective_uid" ] || return 2
    if [ $((mode_decimal & 0022)) -ne 0 ]; then
        [ $((mode_decimal & 01000)) -ne 0 ] || return 2
        [ "$owner_uid" = 0 ] || return 2
        case "$directory_path" in
            /tmp|/var/tmp|/private/tmp|/private/var/tmp) ;;
            *) return 2 ;;
        esac
    fi
}

_patch_engine_canonical_root_chain_is_trusted() {
    local canonical_root="$1"
    local relative_path="${canonical_root#/}"
    local current_path=/
    local component=""
    local index=0
    local -a components=()

    case "$canonical_root" in
        /*) ;;
        *) return 2 ;;
    esac
    _patch_engine_root_component_is_trusted / || return 2
    [ -n "$relative_path" ] || return 0
    IFS=/ read -r -a components <<< "$relative_path"
    while [ "$index" -lt "${#components[@]}" ]; do
        component="${components[$index]}"
        case "$component" in
            ''|.|..) return 2 ;;
        esac
        current_path="${current_path%/}/$component"
        _patch_engine_root_component_is_trusted "$current_path" || return 2
        index=$((index + 1))
    done
}

patch_engine_root_is_trusted() {
    local requested_root="$1"
    local canonical_root=""

    [ -d "$requested_root" ] || return 2
    canonical_root="$(CDPATH='' builtin cd -P -- "$requested_root" 2>/dev/null && pwd -P)" || return 2
    _patch_engine_canonical_root_chain_is_trusted "$canonical_root"
}

_patch_engine_initialize_root() {
    local requested_root="$1"
    local canonical_root=""
    local root_device=""
    local root_inode=""
    local root_uid=""
    local root_gid=""
    local root_mode=""
    local root_links=""

    [ -d "$requested_root" ] || return 2
    canonical_root="$(CDPATH='' builtin cd -P -- "$requested_root" 2>/dev/null && pwd -P)" || return 2
    _patch_engine_canonical_root_chain_is_trusted "$canonical_root" || return 2
    _patch_engine_stat_into "$canonical_root" root_device root_inode root_uid root_gid root_mode root_links || return 2

    if [ -n "$PATCH_ENGINE_ROOT" ] && [ "$PATCH_ENGINE_ROOT" != "$canonical_root" ]; then
        return 2
    fi
    PATCH_ENGINE_ROOT="$canonical_root"
    PATCH_ENGINE_ROOT_DEVICE="$root_device"
    PATCH_ENGINE_ROOT_INODE="$root_inode"
}

_patch_engine_verify_root_identity() {
    local root_device=""
    local root_inode=""
    local root_uid=""
    local root_gid=""
    local root_mode=""
    local root_links=""

    [ -n "$PATCH_ENGINE_ROOT" ] || return 2
    [ -d "$PATCH_ENGINE_ROOT" ] && [ ! -L "$PATCH_ENGINE_ROOT" ] || return 2
    _patch_engine_canonical_root_chain_is_trusted "$PATCH_ENGINE_ROOT" || return 2
    _patch_engine_stat_into "$PATCH_ENGINE_ROOT" root_device root_inode root_uid root_gid root_mode root_links || return 2
    [ "$root_device" = "$PATCH_ENGINE_ROOT_DEVICE" ] &&
        [ "$root_inode" = "$PATCH_ENGINE_ROOT_INODE" ]
}

_patch_engine_directory_is_stable() {
    local directory_path="$1"
    local device=""
    local inode=""
    local owner_uid=""
    local owner_gid=""
    local mode=""
    local links=""
    local normalized_mode=""
    local mode_decimal=0
    local expected_uid="${EUID:-}"

    [ -d "$directory_path" ] && [ ! -L "$directory_path" ] || return 2
    _patch_engine_stat_into "$directory_path" device inode owner_uid owner_gid mode links || return 2
    _patch_engine_normalize_mode_into "$mode" normalized_mode || return 2
    mode_decimal=$((8#$normalized_mode))
    [ -n "$expected_uid" ] || expected_uid="$owner_uid"
    [ "$owner_uid" = "$expected_uid" ] && [ $((mode_decimal & 0022)) -eq 0 ]
}

_patch_engine_resolve_target_into() {
    local logical_path="$1"
    local expected_type="$2"
    local destination_name="$3"
    local relative_path=""
    local current_path=""
    local candidate_path=""
    local component=""
    local index=0
    local -a components=()

    _patch_engine_valid_destination "$destination_name" || return 2
    printf -v "$destination_name" '%s' ""
    [ -n "$PATCH_ENGINE_ROOT" ] || return 2
    case "$expected_type" in
        file|directory|file_or_directory) ;;
        *) return 2 ;;
    esac
    case "$logical_path" in
        /*) ;;
        *) return 2 ;;
    esac
    case "$logical_path" in
        /|*//*|*/./*|*/.|*/../*|*/..|*$'\n'*|*$'\r'*|*$'\t'*) return 2 ;;
    esac

    relative_path="${logical_path#/}"
    IFS=/ read -r -a components <<< "$relative_path"
    [ "${#components[@]}" -gt 0 ] || return 2
    current_path="$PATCH_ENGINE_ROOT"
    _patch_engine_directory_is_stable "$current_path" || return 2
    while [ "$index" -lt "${#components[@]}" ]; do
        component="${components[$index]}"
        case "$component" in
            ''|.|..) return 2 ;;
        esac
        candidate_path="${current_path%/}/$component"
        [ ! -L "$candidate_path" ] || return 2
        if [ "$index" -eq $(( ${#components[@]} - 1 )) ]; then
            if [ ! -e "$candidate_path" ]; then
                [ -r "$current_path" ] && [ -x "$current_path" ] || return 2
                return 1
            fi
            case "$expected_type" in
                file) [ -f "$candidate_path" ] || return 2 ;;
                directory) [ -d "$candidate_path" ] || return 2 ;;
                file_or_directory) [ -f "$candidate_path" ] || [ -d "$candidate_path" ] || return 2 ;;
            esac
        else
            if [ ! -e "$candidate_path" ]; then
                [ -r "$current_path" ] && [ -x "$current_path" ] || return 2
                return 1
            fi
            [ -d "$candidate_path" ] || return 2
            _patch_engine_directory_is_stable "$candidate_path" || return 2
        fi
        current_path="$candidate_path"
        index=$((index + 1))
    done
    [ ! -L "$current_path" ] || return 2
    printf -v "$destination_name" '%s' "$current_path"
}

_patch_engine_resolve_regular_into() {
    _patch_engine_resolve_target_into "$1" file "$2"
}

_patch_engine_append_record() {
    local physical_path="$5"
    local target_type=none

    if [ "$physical_path" != - ]; then
        if [ -d "$physical_path" ] && [ ! -L "$physical_path" ]; then
            target_type=directory
        else
            target_type='file'
        fi
    fi
    PATCH_ENGINE_CRITERIA+=("$1")
    PATCH_ENGINE_STATES+=("$2")
    PATCH_ENGINE_ACTIONS+=("$3")
    PATCH_ENGINE_LOGICAL_PATHS+=("$4")
    PATCH_ENGINE_PHYSICAL_PATHS+=("$5")
    PATCH_ENGINE_DEVICES+=("$6")
    PATCH_ENGINE_INODES+=("$7")
    PATCH_ENGINE_BEFORE_UIDS+=("$8")
    PATCH_ENGINE_BEFORE_GIDS+=("$9")
    shift 9
    PATCH_ENGINE_BEFORE_MODES+=("$1")
    PATCH_ENGINE_AFTER_UIDS+=("$2")
    PATCH_ENGINE_AFTER_GIDS+=("$3")
    PATCH_ENGINE_AFTER_MODES+=("$4")
    PATCH_ENGINE_SIZES+=("$5")
    PATCH_ENGINE_MTIMES+=("$6")
    PATCH_ENGINE_CTIMES+=("$7")
    PATCH_ENGINE_CONTENT_SHA256S+=("$8")
    PATCH_ENGINE_TARGET_TYPES+=("$target_type")
}

_patch_engine_valid_unsigned_identifier() {
    local identifier="$1"
    local decimal_identifier=0

    case "$identifier" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "${#identifier}" -le 10 ] || return 1
    decimal_identifier=$((10#$identifier))
    [ "$decimal_identifier" -le 4294967295 ]
}

_patch_engine_count_character() {
    local value="$1"
    local expected_character="$2"
    local expected_count="$3"
    local index=0
    local count=0

    while [ "$index" -lt "${#value}" ]; do
        [ "${value:$index:1}" != "$expected_character" ] || count=$((count + 1))
        index=$((index + 1))
    done
    [ "$count" -eq "$expected_count" ]
}

_patch_engine_owner_uid_allowed() {
    local criterion="$1"
    local owner_uid="$2"
    local allowed_owners=""
    local passwd_path=""
    local owner_name=""
    local password_field=""
    local account_uid=""
    local account_gid=""
    local gecos_field=""
    local home_path=""
    local shell_path=""
    local seen_names=$'\n'
    local records=0
    local matched=0
    local line=""

    patch_metadata_rule_allowed_owners_into "$criterion" allowed_owners || return 2
    [ "$owner_uid" != 0 ] || return 0
    case " $allowed_owners " in
        *' bin '*|*' sys '*) ;;
        *) return 1 ;;
    esac
    _patch_engine_resolve_regular_into /etc/passwd passwd_path || return 2

    while IFS= read -r line || [ -n "$line" ]; do
        _patch_engine_count_character "$line" : 6 || return 2
        IFS=: read -r owner_name password_field account_uid account_gid gecos_field home_path shell_path <<< "$line"
        [ -n "$owner_name" ] || return 2
        _patch_engine_valid_unsigned_identifier "$account_uid" || return 2
        _patch_engine_valid_unsigned_identifier "$account_gid" || return 2
        case "$seen_names" in
            *$'\n'"$owner_name"$'\n'*) return 2 ;;
        esac
        seen_names+="$owner_name"$'\n'
        records=$((records + 1))
        case " $allowed_owners " in
            *" $owner_name "*)
                [ "$account_uid" != "$owner_uid" ] || matched=1
                ;;
        esac
    done < "$passwd_path"
    [ "$records" -gt 0 ] || return 2
    [ "$matched" -eq 1 ]
}

_patch_engine_new_inventory_into() {
    local label="$1"
    local destination_name="$2"
    local base_directory="${SCRATCH_DIRECTORY:-${TMPDIR:-/tmp}}"
    local canonical_base=""
    local mktemp_command=""
    local chmod_command=""
    local __kisa_inventory_result=""

    _patch_engine_valid_destination "$destination_name" || return 2
    case "$label" in ''|*[!A-Za-z0-9_-]*) return 2 ;; esac
    canonical_base="$(CDPATH='' builtin cd -P -- "$base_directory" 2>/dev/null && pwd -P)" || return 2
    _patch_engine_canonical_root_chain_is_trusted "$canonical_base" || return 2
    _patch_engine_command_into mktemp mktemp_command || return 2
    _patch_engine_command_into chmod chmod_command || return 2
    __kisa_inventory_result="$(umask 077; "$mktemp_command" "$canonical_base/kisa-cce-$label.XXXXXXXX")" || return 2
    "$chmod_command" 0600 "$__kisa_inventory_result" || return 2
    printf -v "$destination_name" '%s' "$__kisa_inventory_result"
}

_patch_engine_remove_inventory() {
    local inventory_path="$1"
    local rm_command=""

    [ -n "$inventory_path" ] || return 0
    _patch_engine_command_into rm rm_command || return 2
    "$rm_command" -f -- "$inventory_path"
}

_patch_engine_plan_dynamic_target() {
    local criterion="$1"
    local logical_path="$2"
    local expected_type="$3"
    local physical_path=""
    local target_type=""
    local required_uid=""
    local mode_kind=""
    local maximum_mode=""
    local after_mode=""
    local after_uid=""

    _patch_engine_record_path_exists "$criterion" "$logical_path" && return 0
    _patch_engine_resolve_target_into "$logical_path" "$expected_type" physical_path || return 2
    if [ -d "$physical_path" ] && [ ! -L "$physical_path" ]; then
        target_type=directory
    else
        target_type='file'
    fi
    _patch_engine_dynamic_rule_into "$criterion" "$logical_path" "$target_type" \
        required_uid mode_kind maximum_mode || return 2
    _patch_engine_capture_fingerprint "$physical_path" || return 2
    [ "$PATCH_ENGINE_CAPTURE_TARGET_TYPE" = "$target_type" ] || return 2
    case "$mode_kind" in
        maximum)
            _patch_engine_tightened_mode_into "$PATCH_ENGINE_CAPTURE_MODE" "$maximum_mode" after_mode || return 2
            ;;
        remove_untrusted_write)
            _patch_engine_remove_untrusted_write_into "$PATCH_ENGINE_CAPTURE_MODE" after_mode || return 2
            ;;
        *) return 2 ;;
    esac
    after_uid="$required_uid"
    if [ "$PATCH_ENGINE_CAPTURE_UID" = "$after_uid" ] &&
        [ "$PATCH_ENGINE_CAPTURE_MODE" = "$after_mode" ]; then
        _patch_engine_append_record "$criterion" compliant none "$logical_path" "$physical_path" \
            "$PATCH_ENGINE_CAPTURE_DEVICE" "$PATCH_ENGINE_CAPTURE_INODE" \
            "$PATCH_ENGINE_CAPTURE_UID" "$PATCH_ENGINE_CAPTURE_GID" "$PATCH_ENGINE_CAPTURE_MODE" \
            "$after_uid" "$PATCH_ENGINE_CAPTURE_GID" "$after_mode" \
            "$PATCH_ENGINE_CAPTURE_SIZE" "$PATCH_ENGINE_CAPTURE_MTIME" "$PATCH_ENGINE_CAPTURE_CTIME" \
            "$PATCH_ENGINE_CAPTURE_CONTENT_SHA256"
        PATCH_ENGINE_COMPLIANT_COUNT=$((PATCH_ENGINE_COMPLIANT_COUNT + 1))
    else
        _patch_engine_append_record "$criterion" ready set_metadata "$logical_path" "$physical_path" \
            "$PATCH_ENGINE_CAPTURE_DEVICE" "$PATCH_ENGINE_CAPTURE_INODE" \
            "$PATCH_ENGINE_CAPTURE_UID" "$PATCH_ENGINE_CAPTURE_GID" "$PATCH_ENGINE_CAPTURE_MODE" \
            "$after_uid" "$PATCH_ENGINE_CAPTURE_GID" "$after_mode" \
            "$PATCH_ENGINE_CAPTURE_SIZE" "$PATCH_ENGINE_CAPTURE_MTIME" "$PATCH_ENGINE_CAPTURE_CTIME" \
            "$PATCH_ENGINE_CAPTURE_CONTENT_SHA256"
        PATCH_ENGINE_CHANGE_COUNT=$((PATCH_ENGINE_CHANGE_COUNT + 1))
    fi
}

_patch_engine_plan_u37() {
    local criterion=U-37
    local logical_path=""
    local directory_path=""
    local physical_path=""
    local path_status=0
    local inventory_path=""
    local find_command=""
    local candidate=""
    local collection_status=0
    local target_count=0
    local directory_device=""
    local candidate_device=""
    local unused_inode=""
    local unused_uid=""
    local unused_gid=""
    local unused_mode=""
    local unused_links=""
    local -a direct_files=(
        /etc/crontab /etc/anacrontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny
    )
    local -a directories=(
        /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
        /var/spool/cron /var/spool/cron/crontabs /var/spool/cron/atjobs /var/spool/at /var/spool/anacron
    )

    for logical_path in /usr/bin/crontab /usr/bin/at; do
        path_status=0
        _patch_engine_resolve_target_into "$logical_path" file physical_path || path_status=$?
        case "$path_status" in
            0) _patch_engine_plan_dynamic_target "$criterion" "$logical_path" file || return 2; target_count=$((target_count + 1)) ;;
            1) ;;
            *) return 2 ;;
        esac
    done
    for logical_path in "${direct_files[@]}"; do
        path_status=0
        _patch_engine_resolve_target_into "$logical_path" file physical_path || path_status=$?
        case "$path_status" in
            0) _patch_engine_plan_dynamic_target "$criterion" "$logical_path" file || return 2; target_count=$((target_count + 1)) ;;
            1) ;;
            *) return 2 ;;
        esac
    done

    _patch_engine_command_into find find_command || return 2
    _patch_engine_new_inventory_into u37 inventory_path || return 2
    for logical_path in "${directories[@]}"; do
        path_status=0
        _patch_engine_resolve_target_into "$logical_path" directory directory_path || path_status=$?
        case "$path_status" in
            0) ;;
            1) continue ;;
            *) collection_status=2; break ;;
        esac
        _patch_engine_directory_is_stable "$directory_path" || { collection_status=2; break; }
        _patch_engine_stat_into "$directory_path" directory_device unused_inode unused_uid unused_gid unused_mode unused_links || {
            collection_status=2
            break
        }
        : > "$inventory_path" || { collection_status=2; break; }
        "$find_command" -P "$directory_path" -xdev \( -type f -o -type d -o -type l \) -print0 \
            > "$inventory_path" 2>/dev/null || { collection_status=2; break; }
        while IFS= read -r -d '' candidate; do
            [ ! -L "$candidate" ] || { collection_status=2; break; }
            _patch_engine_stat_into "$candidate" candidate_device unused_inode unused_uid unused_gid unused_mode unused_links || {
                collection_status=2
                break
            }
            [ "$candidate_device" = "$directory_device" ] || { collection_status=2; break; }
            [ ! -d "$candidate" ] || continue
            _patch_engine_logical_path_into "$candidate" logical_path || { collection_status=2; break; }
            if ! _patch_engine_record_path_exists "$criterion" "$logical_path"; then
                _patch_engine_plan_dynamic_target "$criterion" "$logical_path" file || { collection_status=2; break; }
                target_count=$((target_count + 1))
            fi
        done < "$inventory_path"
        [ "$collection_status" -eq 0 ] || break
    done
    _patch_engine_remove_inventory "$inventory_path" || collection_status=2
    [ "$collection_status" -eq 0 ] || return 2
    if [ "$target_count" -eq 0 ]; then
        _patch_engine_append_record "$criterion" not_applicable none / - - - - - - - - - - - - -
        PATCH_ENGINE_NOT_APPLICABLE_COUNT=$((PATCH_ENGINE_NOT_APPLICABLE_COUNT + 1))
    fi
}

_patch_engine_plan_u67() {
    local criterion=U-67
    local log_directory=""
    local inventory_path=""
    local find_command=""
    local candidate=""
    local logical_path=""
    local target_type=""
    local collection_status=0
    local log_device=""
    local candidate_device=""
    local unused_inode=""
    local unused_uid=""
    local unused_gid=""
    local unused_mode=""
    local unused_links=""

    _patch_engine_resolve_target_into /var/log directory log_directory || return 2
    _patch_engine_directory_is_stable "$log_directory" || return 2
    _patch_engine_stat_into "$log_directory" log_device unused_inode unused_uid unused_gid unused_mode unused_links || return 2
    _patch_engine_command_into find find_command || return 2
    _patch_engine_new_inventory_into u67 inventory_path || return 2
    "$find_command" -P "$log_directory" -xdev \( -type f -o -type d -o -type l \) -print0 \
        > "$inventory_path" 2>/dev/null || collection_status=2
    if [ "$collection_status" -eq 0 ]; then
        while IFS= read -r -d '' candidate; do
            [ ! -L "$candidate" ] || { collection_status=2; break; }
            _patch_engine_stat_into "$candidate" candidate_device unused_inode unused_uid unused_gid unused_mode unused_links || {
                collection_status=2
                break
            }
            [ "$candidate_device" = "$log_device" ] || { collection_status=2; break; }
            _patch_engine_logical_path_into "$candidate" logical_path || { collection_status=2; break; }
            if [ -d "$candidate" ]; then target_type='directory'; else target_type='file'; fi
            _patch_engine_plan_dynamic_target "$criterion" "$logical_path" "$target_type" || {
                collection_status=2
                break
            }
        done < "$inventory_path"
    fi
    _patch_engine_remove_inventory "$inventory_path" || collection_status=2
    [ "$collection_status" -eq 0 ] || return 2
}

patch_engine_reset() {
    PATCH_ENGINE_ROOT=""
    PATCH_ENGINE_ROOT_DEVICE=""
    PATCH_ENGINE_ROOT_INODE=""
    PATCH_ENGINE_PLAN_VALID=0
    PATCH_ENGINE_TRANSACTION_WRITTEN=0
    PATCH_ENGINE_TRANSACTION_LOADED=0
    PATCH_ENGINE_APPLY_STARTED=0
    PATCH_ENGINE_CHANGE_COUNT=0
    PATCH_ENGINE_COMPLIANT_COUNT=0
    PATCH_ENGINE_NOT_APPLICABLE_COUNT=0
    PATCH_ENGINE_ERROR_DETAIL=""
    PATCH_ENGINE_CRITERIA=()
    PATCH_ENGINE_SELECTED_CRITERIA=()
    PATCH_ENGINE_STATES=()
    PATCH_ENGINE_ACTIONS=()
    PATCH_ENGINE_LOGICAL_PATHS=()
    PATCH_ENGINE_PHYSICAL_PATHS=()
    PATCH_ENGINE_DEVICES=()
    PATCH_ENGINE_INODES=()
    PATCH_ENGINE_BEFORE_UIDS=()
    PATCH_ENGINE_BEFORE_GIDS=()
    PATCH_ENGINE_BEFORE_MODES=()
    PATCH_ENGINE_AFTER_UIDS=()
    PATCH_ENGINE_AFTER_GIDS=()
    PATCH_ENGINE_AFTER_MODES=()
    PATCH_ENGINE_SIZES=()
    PATCH_ENGINE_MTIMES=()
    PATCH_ENGINE_CTIMES=()
    PATCH_ENGINE_CONTENT_SHA256S=()
    PATCH_ENGINE_TARGET_TYPES=()
    PATCH_ENGINE_APPLIED_INDEXES=()
    PATCH_ENGINE_CAPTURE_DEVICE=""
    PATCH_ENGINE_CAPTURE_INODE=""
    PATCH_ENGINE_CAPTURE_UID=""
    PATCH_ENGINE_CAPTURE_GID=""
    PATCH_ENGINE_CAPTURE_MODE=""
    PATCH_ENGINE_CAPTURE_LINKS=""
    PATCH_ENGINE_CAPTURE_SIZE=""
    PATCH_ENGINE_CAPTURE_MTIME=""
    PATCH_ENGINE_CAPTURE_CTIME=""
    PATCH_ENGINE_CAPTURE_CONTENT_SHA256=""
    PATCH_ENGINE_CAPTURE_TARGET_TYPE=""
}

_patch_engine_plan_one() {
    local criterion="$1"
    local rule_kind=""
    local required=""
    local logical_path=""
    local required_uid=""
    local group_policy=""
    local maximum_mode=""
    local physical_path=""
    local path_status=0
    local device=""
    local inode=""
    local before_uid=""
    local before_gid=""
    local before_mode=""
    local before_links=""
    local normalized_before_mode=""
    local after_mode=""
    local after_uid=""
    local owner_status=0
    local absent_state=""
    local existing_index=""
    local size=""
    local mtime=""
    local ctime=""
    local content_sha256=""

    if _patch_engine_criterion_is_selected "$criterion"; then
        return 0
    fi
    patch_metadata_rule_kind_into "$criterion" rule_kind || return 1
    PATCH_ENGINE_SELECTED_CRITERIA+=("$criterion")
    case "$rule_kind" in
        cron_set)
            _patch_engine_plan_u37 || {
                _patch_engine_set_error "U-37: cron and at target enumeration is unsafe or incomplete"
                return 2
            }
            return 0
            ;;
        log_set)
            _patch_engine_plan_u67 || {
                _patch_engine_set_error "U-67: log target enumeration is unsafe or incomplete"
                return 2
            }
            return 0
            ;;
        fixed) ;;
        *) return 2 ;;
    esac
    patch_metadata_rule_lookup_into "$criterion" required logical_path required_uid group_policy maximum_mode || return 1
    [ "$group_policy" = preserve ] || return 2

    _patch_engine_resolve_regular_into "$logical_path" physical_path || path_status=$?
    if [ "$path_status" -eq 1 ]; then
        if [ "$required" = optional ]; then
            patch_metadata_rule_absent_state_into "$criterion" absent_state || return 2
            _patch_engine_append_record "$criterion" "$absent_state" none "$logical_path" \
                - - - - - - - - - - - - -
            if [ "$absent_state" = compliant ]; then
                PATCH_ENGINE_COMPLIANT_COUNT=$((PATCH_ENGINE_COMPLIANT_COUNT + 1))
            else
                PATCH_ENGINE_NOT_APPLICABLE_COUNT=$((PATCH_ENGINE_NOT_APPLICABLE_COUNT + 1))
            fi
            return 0
        fi
        _patch_engine_append_record "$criterion" error none "$logical_path" \
            - - - - - - - - - - - - -
        _patch_engine_set_error "$criterion: required regular file is absent: $logical_path"
        return 2
    elif [ "$path_status" -ne 0 ]; then
        _patch_engine_append_record "$criterion" error none "$logical_path" \
            - - - - - - - - - - - - -
        _patch_engine_set_error "$criterion: path is unsafe or is not a regular file: $logical_path"
        return 2
    fi

    _patch_engine_stat_into "$physical_path" device inode before_uid before_gid before_mode before_links || {
        _patch_engine_append_record "$criterion" error none "$logical_path" "$physical_path" \
            - - - - - - - - - - - -
        _patch_engine_set_error "$criterion: cannot snapshot metadata: $logical_path"
        return 2
    }
    [ "$before_links" = 1 ] || {
        _patch_engine_set_error "$criterion: hard-linked targets are not safe to patch: $logical_path"
        return 2
    }
    [ ! -L "$physical_path" ] && [ -f "$physical_path" ] || {
        _patch_engine_set_error "$criterion: path changed during metadata snapshot: $logical_path"
        return 2
    }
    _patch_engine_capture_fingerprint "$physical_path" || {
        _patch_engine_set_error "$criterion: cannot capture a stable content fingerprint: $logical_path"
        return 2
    }
    device="$PATCH_ENGINE_CAPTURE_DEVICE"
    inode="$PATCH_ENGINE_CAPTURE_INODE"
    before_uid="$PATCH_ENGINE_CAPTURE_UID"
    before_gid="$PATCH_ENGINE_CAPTURE_GID"
    normalized_before_mode="$PATCH_ENGINE_CAPTURE_MODE"
    size="$PATCH_ENGINE_CAPTURE_SIZE"
    mtime="$PATCH_ENGINE_CAPTURE_MTIME"
    ctime="$PATCH_ENGINE_CAPTURE_CTIME"
    content_sha256="$PATCH_ENGINE_CAPTURE_CONTENT_SHA256"
    _patch_engine_tightened_mode_into "$normalized_before_mode" "$maximum_mode" after_mode || return 2
    _patch_engine_owner_uid_allowed "$criterion" "$before_uid" || owner_status=$?
    if [ "$owner_status" -eq 2 ]; then
        _patch_engine_set_error "$criterion: allowed owner identities cannot be resolved"
        return 2
    elif [ "$owner_status" -eq 0 ]; then
        after_uid="$before_uid"
    else
        after_uid="$required_uid"
    fi

    if [ "$before_uid" = "$after_uid" ] && [ "$normalized_before_mode" = "$after_mode" ]; then
        _patch_engine_append_record "$criterion" compliant none "$logical_path" "$physical_path" \
            "$device" "$inode" "$before_uid" "$before_gid" "$normalized_before_mode" \
            "$after_uid" "$before_gid" "$after_mode" "$size" "$mtime" "$ctime" "$content_sha256"
        PATCH_ENGINE_COMPLIANT_COUNT=$((PATCH_ENGINE_COMPLIANT_COUNT + 1))
    else
        _patch_engine_append_record "$criterion" ready set_metadata "$logical_path" "$physical_path" \
            "$device" "$inode" "$before_uid" "$before_gid" "$normalized_before_mode" \
            "$after_uid" "$before_gid" "$after_mode" "$size" "$mtime" "$ctime" "$content_sha256"
        PATCH_ENGINE_CHANGE_COUNT=$((PATCH_ENGINE_CHANGE_COUNT + 1))
    fi
}

patch_engine_plan() {
    local root="$1"
    local criterion=""
    local status=0

    shift
    [ "$#" -gt 0 ] || {
        _patch_engine_set_error "at least one criterion is required"
        return 2
    }
    _patch_engine_initialize_root "$root" || {
        _patch_engine_set_error "scan root is unavailable or changed: $root"
        return 2
    }

    for criterion in "$@"; do
        status=0
        _patch_engine_plan_one "$criterion" || status=$?
        if [ "$status" -eq 1 ]; then
            PATCH_ENGINE_ERROR_DETAIL="unsupported patch criterion: $criterion"
            PATCH_ENGINE_PLAN_VALID=0
            return 1
        elif [ "$status" -ne 0 ]; then
            PATCH_ENGINE_PLAN_VALID=0
            return 2
        fi
    done
    PATCH_ENGINE_PLAN_VALID=1
}

patch_engine_state_into() {
    local criterion="$1"
    local destination_name="$2"
    local index=0
    local found=0
    local selected_state=""
    local selected_rank=0
    local record_state=""
    local rank=0

    _patch_engine_valid_destination "$destination_name" || return 2
    while [ "$index" -lt "${#PATCH_ENGINE_CRITERIA[@]}" ]; do
        if [ "${PATCH_ENGINE_CRITERIA[$index]}" = "$criterion" ]; then
            found=1
            record_state="${PATCH_ENGINE_STATES[$index]}"
            case "$record_state" in
                error) rank=90 ;;
                applying) rank=80 ;;
                ready) rank=70 ;;
                applied) rank=60 ;;
                verified) rank=50 ;;
                rolled_back) rank=40 ;;
                compliant) rank=30 ;;
                not_applicable) rank=20 ;;
                *) return 2 ;;
            esac
            if [ "$rank" -gt "$selected_rank" ]; then
                selected_rank="$rank"
                selected_state="$record_state"
            fi
        fi
        index=$((index + 1))
    done
    [ "$found" -eq 1 ] || return 1
    printf -v "$destination_name" '%s' "$selected_state"
}

_patch_engine_record_index_into() {
    local index="$1"
    local destination_name="$2"
    local __kisa_patch_record_row=""

    _patch_engine_valid_destination "$destination_name" || return 2
    [ "$index" -ge 0 ] && [ "$index" -lt "${#PATCH_ENGINE_CRITERIA[@]}" ] || return 1
    printf -v __kisa_patch_record_row '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' \
        2 "${PATCH_ENGINE_CRITERIA[$index]}" "${PATCH_ENGINE_STATES[$index]}" \
        "${PATCH_ENGINE_ACTIONS[$index]}" "${PATCH_ENGINE_LOGICAL_PATHS[$index]}" \
        "$PATCH_ENGINE_ROOT_DEVICE" "$PATCH_ENGINE_ROOT_INODE" \
        "${PATCH_ENGINE_DEVICES[$index]}" "${PATCH_ENGINE_INODES[$index]}" \
        "${PATCH_ENGINE_BEFORE_UIDS[$index]}" "${PATCH_ENGINE_BEFORE_GIDS[$index]}" \
        "${PATCH_ENGINE_BEFORE_MODES[$index]}" "${PATCH_ENGINE_AFTER_UIDS[$index]}" \
        "${PATCH_ENGINE_AFTER_GIDS[$index]}" "${PATCH_ENGINE_AFTER_MODES[$index]}" \
        "${PATCH_ENGINE_SIZES[$index]}" "${PATCH_ENGINE_MTIMES[$index]}" \
        "${PATCH_ENGINE_CTIMES[$index]}" "${PATCH_ENGINE_CONTENT_SHA256S[$index]}"
    printf -v "$destination_name" '%s' "$__kisa_patch_record_row"
}

patch_engine_record_into() {
    local criterion="$1"
    local destination_name="$2"
    local index=""

    _patch_engine_valid_destination "$destination_name" || return 2
    _patch_engine_index_into "$criterion" index || return 1
    _patch_engine_record_index_into "$index" "$destination_name"
}

_patch_engine_render_plan() {
    local index=0
    local row=""

    printf '%s\n' "$PATCH_ENGINE_TSV_HEADER"
    while [ "$index" -lt "${#PATCH_ENGINE_CRITERIA[@]}" ]; do
        _patch_engine_record_index_into "$index" row || return 2
        printf '%s\n' "$row"
        index=$((index + 1))
    done
}

_patch_engine_render_transaction() {
    local index=0
    local row=""

    printf '%s\n' "$PATCH_ENGINE_TSV_HEADER"
    while [ "$index" -lt "${#PATCH_ENGINE_CRITERIA[@]}" ]; do
        if [ "${PATCH_ENGINE_ACTIONS[$index]}" = set_metadata ]; then
            _patch_engine_record_index_into "$index" row || return 2
            printf '%s\n' "$row"
        fi
        index=$((index + 1))
    done
}

_patch_engine_write_protected() {
    local output_path="$1"
    local renderer="$2"
    local output_device=""
    local output_inode=""
    local output_uid=""
    local output_gid=""
    local output_mode=""
    local output_links=""
    local normalized_mode=""
    local chmod_command=""
    local expected_uid="${EUID:-}"

    case "$output_path" in
        /*) ;;
        *) return 2 ;;
    esac
    [ ! -e "$output_path" ] && [ ! -L "$output_path" ] || return 2
    [ -d "${output_path%/*}" ] && [ ! -L "${output_path%/*}" ] || return 2
    _patch_engine_command_into chmod chmod_command || return 2

    if ! (
        umask 077
        set -o noclobber
        "$renderer" > "$output_path" && "$chmod_command" 0600 "$output_path"
    ); then
        return 2
    fi
    [ ! -L "$output_path" ] && [ -f "$output_path" ] || return 2
    _patch_engine_stat_into "$output_path" output_device output_inode output_uid output_gid output_mode output_links || return 2
    _patch_engine_normalize_mode_into "$output_mode" normalized_mode || return 2
    if [ -z "$expected_uid" ]; then
        expected_uid="$output_uid"
    fi
    [ "$output_uid" = "$expected_uid" ] && [ "$normalized_mode" = 0600 ] && [ "$output_links" = 1 ]
}

patch_engine_write_plan_tsv() {
    local output_path="$1"

    [ "$PATCH_ENGINE_PLAN_VALID" -eq 1 ] || return 2
    _patch_engine_write_protected "$output_path" _patch_engine_render_plan || {
        _patch_engine_set_error "cannot create protected plan: $output_path"
        return 2
    }
}

patch_engine_write_transaction_tsv() {
    local output_path="$1"

    [ "$PATCH_ENGINE_PLAN_VALID" -eq 1 ] || return 2
    [ "$PATCH_ENGINE_APPLY_STARTED" -eq 0 ] || return 2
    _patch_engine_write_protected "$output_path" _patch_engine_render_transaction || {
        _patch_engine_set_error "cannot create protected transaction snapshot: $output_path"
        return 2
    }
    PATCH_ENGINE_TRANSACTION_WRITTEN=1
}

_patch_engine_capture_matches_index() {
    local index="$1"
    local ctime_policy="${2:-ignore}"

    _patch_engine_capture_fingerprint "${PATCH_ENGINE_PHYSICAL_PATHS[$index]}" || return 2
    [ "$PATCH_ENGINE_CAPTURE_DEVICE" = "${PATCH_ENGINE_DEVICES[$index]}" ] &&
        [ "$PATCH_ENGINE_CAPTURE_INODE" = "${PATCH_ENGINE_INODES[$index]}" ] &&
        [ "$PATCH_ENGINE_CAPTURE_TARGET_TYPE" = "${PATCH_ENGINE_TARGET_TYPES[$index]}" ] &&
        [ "$PATCH_ENGINE_CAPTURE_SIZE" = "${PATCH_ENGINE_SIZES[$index]}" ] &&
        [ "$PATCH_ENGINE_CAPTURE_MTIME" = "${PATCH_ENGINE_MTIMES[$index]}" ] &&
        [ "$PATCH_ENGINE_CAPTURE_CONTENT_SHA256" = "${PATCH_ENGINE_CONTENT_SHA256S[$index]}" ] || return 2
    if [ "${PATCH_ENGINE_TARGET_TYPES[$index]}" = file ]; then
        [ "$PATCH_ENGINE_CAPTURE_LINKS" = 1 ] || return 2
    fi
    case "$ctime_policy" in
        exact) [ "$PATCH_ENGINE_CAPTURE_CTIME" = "${PATCH_ENGINE_CTIMES[$index]}" ] ;;
        ignore) return 0 ;;
        *) return 2 ;;
    esac
}

_patch_engine_metadata_matches_index() {
    local index="$1"
    local expected_side="$2"
    local ctime_policy="${3:-ignore}"
    local expected_uid=""
    local expected_gid=""
    local expected_mode=""

    _patch_engine_capture_matches_index "$index" "$ctime_policy" || return 2
    case "$expected_side" in
        before)
            expected_uid="${PATCH_ENGINE_BEFORE_UIDS[$index]}"
            expected_gid="${PATCH_ENGINE_BEFORE_GIDS[$index]}"
            expected_mode="${PATCH_ENGINE_BEFORE_MODES[$index]}"
            ;;
        after)
            expected_uid="${PATCH_ENGINE_AFTER_UIDS[$index]}"
            expected_gid="${PATCH_ENGINE_AFTER_GIDS[$index]}"
            expected_mode="${PATCH_ENGINE_AFTER_MODES[$index]}"
            ;;
        *) return 2 ;;
    esac
    [ "$PATCH_ENGINE_CAPTURE_UID" = "$expected_uid" ] &&
        [ "$PATCH_ENGINE_CAPTURE_GID" = "$expected_gid" ] &&
        [ "$PATCH_ENGINE_CAPTURE_MODE" = "$expected_mode" ]
}

_patch_engine_transition_metadata_matches_index() {
    local index="$1"

    _patch_engine_capture_matches_index "$index" ignore || return 2
    { [ "$PATCH_ENGINE_CAPTURE_UID" = "${PATCH_ENGINE_BEFORE_UIDS[$index]}" ] ||
      [ "$PATCH_ENGINE_CAPTURE_UID" = "${PATCH_ENGINE_AFTER_UIDS[$index]}" ]; } &&
        { [ "$PATCH_ENGINE_CAPTURE_GID" = "${PATCH_ENGINE_BEFORE_GIDS[$index]}" ] ||
          [ "$PATCH_ENGINE_CAPTURE_GID" = "${PATCH_ENGINE_AFTER_GIDS[$index]}" ]; } &&
        { [ "$PATCH_ENGINE_CAPTURE_MODE" = "${PATCH_ENGINE_BEFORE_MODES[$index]}" ] ||
          [ "$PATCH_ENGINE_CAPTURE_MODE" = "${PATCH_ENGINE_AFTER_MODES[$index]}" ]; }
}

_patch_engine_revalidate_index() {
    local index="$1"
    local resolved_path=""

    _patch_engine_verify_root_identity || return 2
    _patch_engine_resolve_target_into "${PATCH_ENGINE_LOGICAL_PATHS[$index]}" \
        "${PATCH_ENGINE_TARGET_TYPES[$index]}" resolved_path || return 2
    [ "$resolved_path" = "${PATCH_ENGINE_PHYSICAL_PATHS[$index]}" ] || return 2
    _patch_engine_metadata_matches_index "$index" before exact
}

_patch_engine_apply_index() {
    local index="$1"
    local chmod_command=""
    local chown_command=""
    local path="${PATCH_ENGINE_PHYSICAL_PATHS[$index]}"

    _patch_engine_revalidate_index "$index" || return 2
    _patch_engine_command_into chmod chmod_command || return 2
    _patch_engine_command_into chown chown_command || return 2
    PATCH_ENGINE_APPLIED_INDEXES+=("$index")
    PATCH_ENGINE_STATES[$index]=applying

    if [ "${PATCH_ENGINE_BEFORE_MODES[$index]}" != "${PATCH_ENGINE_AFTER_MODES[$index]}" ]; then
        "$chmod_command" "${PATCH_ENGINE_AFTER_MODES[$index]}" "$path" || return 2
    fi
    if [ "${PATCH_ENGINE_BEFORE_UIDS[$index]}" != "${PATCH_ENGINE_AFTER_UIDS[$index]}" ] ||
        [ "${PATCH_ENGINE_BEFORE_GIDS[$index]}" != "${PATCH_ENGINE_AFTER_GIDS[$index]}" ]; then
        "$chown_command" "${PATCH_ENGINE_AFTER_UIDS[$index]}:${PATCH_ENGINE_AFTER_GIDS[$index]}" "$path" || return 2
    fi
    _patch_engine_metadata_matches_index "$index" after || return 2
    PATCH_ENGINE_STATES[$index]=applied
}

_patch_engine_restore_index() {
    local index="$1"
    local restore_policy="$2"
    local resolved_path=""
    local chmod_command=""
    local chown_command=""
    local path="${PATCH_ENGINE_PHYSICAL_PATHS[$index]}"

    _patch_engine_verify_root_identity || return 2
    _patch_engine_resolve_target_into "${PATCH_ENGINE_LOGICAL_PATHS[$index]}" \
        "${PATCH_ENGINE_TARGET_TYPES[$index]}" resolved_path || return 2
    [ "$resolved_path" = "$path" ] || return 2
    _patch_engine_metadata_matches_index "$index" before && {
        PATCH_ENGINE_STATES[$index]=rolled_back
        return 0
    }
    case "$restore_policy" in
        strict)
            _patch_engine_metadata_matches_index "$index" after || return 2
            ;;
        transition)
            _patch_engine_transition_metadata_matches_index "$index" || return 2
            ;;
        partial) _patch_engine_transition_metadata_matches_index "$index" || return 2 ;;
        *) return 2 ;;
    esac

    _patch_engine_command_into chmod chmod_command || return 2
    _patch_engine_command_into chown chown_command || return 2
    "$chown_command" "${PATCH_ENGINE_BEFORE_UIDS[$index]}:${PATCH_ENGINE_BEFORE_GIDS[$index]}" "$path" || return 2
    "$chmod_command" "${PATCH_ENGINE_BEFORE_MODES[$index]}" "$path" || return 2
    _patch_engine_metadata_matches_index "$index" before || return 2
    PATCH_ENGINE_STATES[$index]=rolled_back
}

_patch_engine_rollback_indexes() {
    local restore_policy="$1"
    shift
    local -a indexes=("$@")
    local position=$(( ${#indexes[@]} - 1 ))
    local index=0
    local failures=0

    while [ "$position" -ge 0 ]; do
        index="${indexes[$position]}"
        if ! _patch_engine_restore_index "$index" "$restore_policy"; then
            failures=$((failures + 1))
            PATCH_ENGINE_STATES[$index]=error
            [ -n "$PATCH_ENGINE_ERROR_DETAIL" ] ||
                PATCH_ENGINE_ERROR_DETAIL="rollback refused changed path: ${PATCH_ENGINE_LOGICAL_PATHS[$index]}"
        fi
        position=$((position - 1))
    done
    [ "$failures" -eq 0 ]
}

_patch_engine_rollback_index_is_ready() {
    local index="$1"
    local restore_policy="$2"
    local resolved_path=""

    _patch_engine_resolve_target_into "${PATCH_ENGINE_LOGICAL_PATHS[$index]}" \
        "${PATCH_ENGINE_TARGET_TYPES[$index]}" resolved_path || return 2
    [ "$resolved_path" = "${PATCH_ENGINE_PHYSICAL_PATHS[$index]}" ] || return 2
    if _patch_engine_metadata_matches_index "$index" before; then
        return 0
    fi
    case "$restore_policy" in
        strict) _patch_engine_metadata_matches_index "$index" after ;;
        transition) _patch_engine_transition_metadata_matches_index "$index" ;;
        *) return 2 ;;
    esac
}

patch_engine_verify() {
    local index=0

    _patch_engine_verify_root_identity || {
        _patch_engine_set_error "scan root identity changed before verification"
        return 2
    }
    while [ "$index" -lt "${#PATCH_ENGINE_CRITERIA[@]}" ]; do
        case "${PATCH_ENGINE_ACTIONS[$index]}" in
            set_metadata)
                _patch_engine_metadata_matches_index "$index" after || {
                    _patch_engine_set_error "post-apply metadata verification failed: ${PATCH_ENGINE_LOGICAL_PATHS[$index]}"
                    return 2
                }
                PATCH_ENGINE_STATES[$index]=verified
                ;;
        esac
        index=$((index + 1))
    done
}

patch_engine_apply() {
    local index=0

    [ "$PATCH_ENGINE_PLAN_VALID" -eq 1 ] || return 2
    if [ "$PATCH_ENGINE_CHANGE_COUNT" -gt 0 ] && [ "$PATCH_ENGINE_TRANSACTION_WRITTEN" -ne 1 ]; then
        _patch_engine_set_error "a protected transaction snapshot is required before apply"
        return 2
    fi
    while [ "$index" -lt "${#PATCH_ENGINE_CRITERIA[@]}" ]; do
        if [ "${PATCH_ENGINE_ACTIONS[$index]}" = set_metadata ] &&
            ! _patch_engine_revalidate_index "$index"; then
            _patch_engine_set_error "apply preflight detected source drift: ${PATCH_ENGINE_LOGICAL_PATHS[$index]}"
            return 2
        fi
        index=$((index + 1))
    done
    PATCH_ENGINE_APPLY_STARTED=1
    PATCH_ENGINE_APPLIED_INDEXES=()
    index=0
    while [ "$index" -lt "${#PATCH_ENGINE_CRITERIA[@]}" ]; do
        if [ "${PATCH_ENGINE_ACTIONS[$index]}" = set_metadata ]; then
            if ! _patch_engine_apply_index "$index"; then
                PATCH_ENGINE_ERROR_DETAIL="apply failed or source metadata changed: ${PATCH_ENGINE_LOGICAL_PATHS[$index]}"
                _patch_engine_rollback_indexes partial "${PATCH_ENGINE_APPLIED_INDEXES[@]}" ||
                    PATCH_ENGINE_ERROR_DETAIL+="; automatic rollback was incomplete"
                PATCH_ENGINE_PLAN_VALID=0
                return 2
            fi
        fi
        index=$((index + 1))
    done
    if ! patch_engine_verify; then
        _patch_engine_rollback_indexes partial "${PATCH_ENGINE_APPLIED_INDEXES[@]}" ||
            PATCH_ENGINE_ERROR_DETAIL+="; automatic rollback was incomplete"
        return 2
    fi
}

patch_engine_rollback() {
    local restore_policy="${1:-strict}"
    local indexes=()
    local index=0

    case "$restore_policy" in strict|transition) ;; *) return 2 ;; esac
    if [ "$PATCH_ENGINE_TRANSACTION_LOADED" -ne 1 ] && [ "$PATCH_ENGINE_APPLY_STARTED" -ne 1 ]; then
        _patch_engine_set_error "no applied or loaded transaction is available for rollback"
        return 2
    fi
    while [ "$index" -lt "${#PATCH_ENGINE_CRITERIA[@]}" ]; do
        if [ "${PATCH_ENGINE_ACTIONS[$index]}" = set_metadata ]; then
            indexes+=("$index")
        fi
        index=$((index + 1))
    done
    _patch_engine_verify_root_identity || {
        _patch_engine_set_error "rollback root identity changed"
        return 2
    }
    for index in "${indexes[@]}"; do
        _patch_engine_rollback_index_is_ready "$index" "$restore_policy" || {
            _patch_engine_set_error "rollback preflight detected target drift: ${PATCH_ENGINE_LOGICAL_PATHS[$index]}"
            return 2
        }
    done
    _patch_engine_rollback_indexes "$restore_policy" "${indexes[@]}" || return 2
}

_patch_engine_validate_transaction_file() {
    local transaction_path="$1"
    local device=""
    local inode=""
    local owner_uid=""
    local owner_gid=""
    local mode=""
    local links=""
    local normalized_mode=""
    local expected_uid="${EUID:-}"

    case "$transaction_path" in
        /*) ;;
        *) return 2 ;;
    esac
    [ -f "$transaction_path" ] && [ ! -L "$transaction_path" ] || return 2
    _patch_engine_stat_into "$transaction_path" device inode owner_uid owner_gid mode links || return 2
    _patch_engine_normalize_mode_into "$mode" normalized_mode || return 2
    [ -n "$expected_uid" ] || expected_uid="$owner_uid"
    [ "$owner_uid" = "$expected_uid" ] && [ "$links" = 1 ] && [ "$normalized_mode" = 0600 ]
}

_patch_engine_valid_transaction_number() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

patch_engine_load_transaction() {
    local root="$1"
    local transaction_path="$2"
    local header=""
    local line=""
    local schema=""
    local criterion=""
    local state=""
    local action=""
    local logical_path=""
    local root_device=""
    local root_inode=""
    local device=""
    local inode=""
    local before_uid=""
    local before_gid=""
    local before_mode=""
    local after_uid=""
    local after_gid=""
    local after_mode=""
    local size=""
    local mtime=""
    local ctime=""
    local content_sha256=""
    local extra=""
    local required=""
    local expected_path=""
    local expected_uid=""
    local group_policy=""
    local maximum_mode=""
    local expected_after_mode=""
    local normalized_before_mode=""
    local normalized_after_mode=""
    local expected_after_uid=""
    local owner_status=0
    local resolved_path=""
    local existing_index=""
    local rule_kind=""
    local target_type=file
    local mode_kind=maximum
    local line_number=0
    local transaction_device_before=""
    local transaction_inode_before=""
    local transaction_uid_before=""
    local transaction_gid_before=""
    local transaction_mode_before=""
    local transaction_links_before=""
    local transaction_device_after=""
    local transaction_inode_after=""
    local transaction_uid_after=""
    local transaction_gid_after=""
    local transaction_mode_after=""
    local transaction_links_after=""

    patch_engine_reset
    _patch_engine_validate_transaction_file "$transaction_path" || {
        _patch_engine_set_error "transaction file is not a protected regular file: $transaction_path"
        return 2
    }
    _patch_engine_stat_into "$transaction_path" transaction_device_before transaction_inode_before \
        transaction_uid_before transaction_gid_before transaction_mode_before transaction_links_before || return 2
    _patch_engine_initialize_root "$root" || {
        _patch_engine_set_error "rollback root is unavailable: $root"
        return 2
    }
    IFS= read -r header < "$transaction_path" || {
        _patch_engine_set_error "transaction file is empty"
        return 2
    }
    [ "$header" = "$PATCH_ENGINE_TSV_HEADER" ] || {
        _patch_engine_set_error "transaction header is invalid"
        return 2
    }

    while IFS= read -r line || [ -n "$line" ]; do
        line_number=$((line_number + 1))
        if [ "$line_number" -eq 1 ]; then
            continue
        fi
        [ -n "$line" ] || {
            _patch_engine_set_error "transaction contains an empty record"
            return 2
        }
        IFS=$'\t' read -r schema criterion state action logical_path root_device root_inode \
            device inode before_uid before_gid before_mode after_uid after_gid after_mode \
            size mtime ctime content_sha256 extra <<< "$line"
        [ -z "$extra" ] && [ -n "$content_sha256" ] || {
            _patch_engine_set_error "transaction record has an invalid field count"
            return 2
        }
        [ "$schema" = 2 ] && [ "$state" = ready ] && [ "$action" = set_metadata ] || {
            _patch_engine_set_error "transaction record state is invalid: $criterion"
            return 2
        }
        patch_metadata_rule_kind_into "$criterion" rule_kind || {
            _patch_engine_set_error "transaction criterion is unsupported: $criterion"
            return 2
        }
        case "$rule_kind" in
            fixed)
                patch_metadata_rule_lookup_into "$criterion" required expected_path expected_uid group_policy maximum_mode || return 2
                [ "$logical_path" = "$expected_path" ] && [ "$group_policy" = preserve ] || {
                    _patch_engine_set_error "transaction rule does not match the registry: $criterion"
                    return 2
                }
                _patch_engine_resolve_target_into "$logical_path" file resolved_path || {
                    _patch_engine_set_error "transaction target is unavailable or unsafe: $criterion"
                    return 2
                }
                target_type='file'
                mode_kind=maximum
                ;;
            cron_set|log_set)
                _patch_engine_resolve_target_into "$logical_path" file_or_directory resolved_path || {
                    _patch_engine_set_error "transaction target is unavailable or unsafe: $criterion"
                    return 2
                }
                if [ -d "$resolved_path" ]; then target_type='directory'; else target_type='file'; fi
                _patch_engine_dynamic_rule_into "$criterion" "$logical_path" "$target_type" \
                    expected_uid mode_kind maximum_mode || {
                        _patch_engine_set_error "transaction target does not match the registry: $criterion:$logical_path"
                        return 2
                    }
                group_policy=preserve
                ;;
            *)
                _patch_engine_set_error "transaction rule kind is unsupported: $criterion"
                return 2
                ;;
        esac
        if _patch_engine_record_path_exists "$criterion" "$logical_path"; then
            _patch_engine_set_error "transaction contains a duplicate target: $criterion:$logical_path"
            return 2
        fi
        _patch_engine_valid_transaction_number "$root_device" &&
            _patch_engine_valid_transaction_number "$root_inode" &&
            _patch_engine_valid_transaction_number "$device" &&
            _patch_engine_valid_transaction_number "$inode" &&
            _patch_engine_valid_transaction_number "$before_uid" &&
            _patch_engine_valid_transaction_number "$before_gid" &&
            _patch_engine_valid_transaction_number "$after_uid" &&
            _patch_engine_valid_transaction_number "$after_gid" &&
            _patch_engine_valid_transaction_number "$size" &&
            _patch_engine_valid_transaction_number "$mtime" &&
            _patch_engine_valid_transaction_number "$ctime" || {
                _patch_engine_set_error "transaction contains invalid numeric metadata: $criterion"
                return 2
            }
        [ "${#content_sha256}" -eq 64 ] || {
            _patch_engine_set_error "transaction contains an invalid content digest: $criterion"
            return 2
        }
        case "$content_sha256" in
            *[!0-9a-f]*)
                _patch_engine_set_error "transaction contains an invalid content digest: $criterion"
                return 2
                ;;
        esac
        _patch_engine_normalize_mode_into "$before_mode" normalized_before_mode || {
            _patch_engine_set_error "transaction contains an invalid original mode: $criterion"
            return 2
        }
        _patch_engine_normalize_mode_into "$after_mode" normalized_after_mode || {
            _patch_engine_set_error "transaction contains an invalid target mode: $criterion"
            return 2
        }
        case "$mode_kind" in
            maximum) _patch_engine_tightened_mode_into "$normalized_before_mode" "$maximum_mode" expected_after_mode || return 2 ;;
            remove_untrusted_write) _patch_engine_remove_untrusted_write_into "$normalized_before_mode" expected_after_mode || return 2 ;;
            *) return 2 ;;
        esac
        if [ "$rule_kind" = fixed ]; then
            owner_status=0
            _patch_engine_owner_uid_allowed "$criterion" "$before_uid" || owner_status=$?
            if [ "$owner_status" -eq 2 ]; then
                _patch_engine_set_error "transaction owner identities cannot be resolved: $criterion"
                return 2
            elif [ "$owner_status" -eq 0 ]; then
                expected_after_uid="$before_uid"
            else
                expected_after_uid="$expected_uid"
            fi
        else
            expected_after_uid="$expected_uid"
        fi
        [ "$root_device" = "$PATCH_ENGINE_ROOT_DEVICE" ] &&
            [ "$root_inode" = "$PATCH_ENGINE_ROOT_INODE" ] &&
            [ "$after_uid" = "$expected_after_uid" ] && [ "$after_gid" = "$before_gid" ] &&
            [ "$normalized_after_mode" = "$expected_after_mode" ] || {
                _patch_engine_set_error "transaction metadata does not match the current rule: $criterion"
                return 2
            }
        if [ "$target_type" = directory ] &&
            [ "$content_sha256" != 0000000000000000000000000000000000000000000000000000000000000000 ]; then
            _patch_engine_set_error "transaction directory fingerprint is invalid: $criterion:$logical_path"
            return 2
        fi
        _patch_engine_append_record "$criterion" ready set_metadata "$logical_path" "$resolved_path" \
            "$device" "$inode" "$before_uid" "$before_gid" "$normalized_before_mode" \
            "$after_uid" "$after_gid" "$normalized_after_mode" "$size" "$mtime" "$ctime" "$content_sha256"
        PATCH_ENGINE_CHANGE_COUNT=$((PATCH_ENGINE_CHANGE_COUNT + 1))
        if ! _patch_engine_criterion_is_selected "$criterion"; then
            PATCH_ENGINE_SELECTED_CRITERIA+=("$criterion")
        fi
    done < "$transaction_path"

    _patch_engine_validate_transaction_file "$transaction_path" || {
        _patch_engine_set_error "transaction file changed while it was read: $transaction_path"
        return 2
    }
    _patch_engine_stat_into "$transaction_path" transaction_device_after transaction_inode_after \
        transaction_uid_after transaction_gid_after transaction_mode_after transaction_links_after || return 2
    [ "$transaction_device_before" = "$transaction_device_after" ] &&
        [ "$transaction_inode_before" = "$transaction_inode_after" ] || {
            _patch_engine_set_error "transaction file identity changed while it was read: $transaction_path"
            return 2
        }

    PATCH_ENGINE_PLAN_VALID=1
    PATCH_ENGINE_TRANSACTION_WRITTEN=1
    PATCH_ENGINE_TRANSACTION_LOADED=1
}

patch_engine_rollback_transaction() {
    local root="$1"
    local transaction_path="$2"
    local restore_policy="${3:-strict}"

    patch_engine_load_transaction "$root" "$transaction_path" || return 2
    patch_engine_rollback "$restore_policy"
}
