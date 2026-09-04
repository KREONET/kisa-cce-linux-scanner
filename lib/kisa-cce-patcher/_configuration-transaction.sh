# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash

# Transactional content remediation for deterministic KISA CCE configuration files.

PATCH_CONFIGURATION_MANIFEST_HEADER=$'schema\tcriterion\tpath\troot_device\troot_inode\tparent_device\tparent_inode\tbefore_state\tbefore_device\tbefore_inode\tbefore_uid\tbefore_gid\tbefore_mode\tbefore_size\tbefore_mtime\tbefore_ctime\tbefore_sha256\tdesired_uid\tdesired_gid\tdesired_mode\tdesired_sha256\tbackup\tpayload'
PATCH_CONFIGURATION_JOURNAL_HEADER=$'schema\tindex\tpath\tdevice\tinode\tuid\tgid\tmode\tsize\tmtime\tctime\tsha256'
PATCH_CONFIGURATION_PLAN_HEADER=$'criterion\taction\tpath\tbefore_uid\tbefore_gid\tbefore_mode\tbefore_sha256\tdesired_uid\tdesired_gid\tdesired_mode\tdesired_sha256'

PATCH_CONFIGURATION_ROOT=""
PATCH_CONFIGURATION_ROOT_DEVICE=""
PATCH_CONFIGURATION_ROOT_INODE=""
PATCH_CONFIGURATION_TRANSACTION_DIRECTORY=""
PATCH_CONFIGURATION_DATA_DIRECTORY=""
PATCH_CONFIGURATION_MANIFEST_DEVICE=""
PATCH_CONFIGURATION_MANIFEST_INODE=""
PATCH_CONFIGURATION_MANIFEST_SHA256=""
PATCH_CONFIGURATION_PLAN_VALID=0
PATCH_CONFIGURATION_VERIFIED=0
PATCH_CONFIGURATION_CHANGE_COUNT=0
PATCH_CONFIGURATION_COMPLIANT_COUNT=0
PATCH_CONFIGURATION_ERROR_DETAIL=""

PATCH_CONFIGURATION_CRITERIA=()
PATCH_CONFIGURATION_LOGICAL_PATHS=()
PATCH_CONFIGURATION_PHYSICAL_PATHS=()
PATCH_CONFIGURATION_PARENT_PATHS=()
PATCH_CONFIGURATION_PARENT_DEVICES=()
PATCH_CONFIGURATION_PARENT_INODES=()
PATCH_CONFIGURATION_BEFORE_STATES=()
PATCH_CONFIGURATION_BEFORE_DEVICES=()
PATCH_CONFIGURATION_BEFORE_INODES=()
PATCH_CONFIGURATION_BEFORE_UIDS=()
PATCH_CONFIGURATION_BEFORE_GIDS=()
PATCH_CONFIGURATION_BEFORE_MODES=()
PATCH_CONFIGURATION_BEFORE_SIZES=()
PATCH_CONFIGURATION_BEFORE_MTIMES=()
PATCH_CONFIGURATION_BEFORE_CTIMES=()
PATCH_CONFIGURATION_BEFORE_SHA256S=()
PATCH_CONFIGURATION_DESIRED_UIDS=()
PATCH_CONFIGURATION_DESIRED_GIDS=()
PATCH_CONFIGURATION_DESIRED_MODES=()
PATCH_CONFIGURATION_DESIRED_SHA256S=()
PATCH_CONFIGURATION_BACKUP_NAMES=()
PATCH_CONFIGURATION_PAYLOAD_NAMES=()
PATCH_CONFIGURATION_TARGET_STATES=()
PATCH_CONFIGURATION_STAGE_PATHS=()
PATCH_CONFIGURATION_AFTER_DEVICES=()
PATCH_CONFIGURATION_AFTER_INODES=()
PATCH_CONFIGURATION_AFTER_UIDS=()
PATCH_CONFIGURATION_AFTER_GIDS=()
PATCH_CONFIGURATION_AFTER_MODES=()
PATCH_CONFIGURATION_AFTER_SIZES=()
PATCH_CONFIGURATION_AFTER_MTIMES=()
PATCH_CONFIGURATION_AFTER_CTIMES=()
PATCH_CONFIGURATION_AFTER_SHA256S=()
PATCH_CONFIGURATION_CURRENT_STATES=()

PATCH_CONFIGURATION_CAPTURE_DEVICE=""
PATCH_CONFIGURATION_CAPTURE_INODE=""
PATCH_CONFIGURATION_CAPTURE_UID=""
PATCH_CONFIGURATION_CAPTURE_GID=""
PATCH_CONFIGURATION_CAPTURE_MODE=""
PATCH_CONFIGURATION_CAPTURE_SIZE=""
PATCH_CONFIGURATION_CAPTURE_MTIME=""
PATCH_CONFIGURATION_CAPTURE_CTIME=""
PATCH_CONFIGURATION_CAPTURE_SHA256=""

_patch_configuration_valid_destination() {
    case "$1" in
        ''|[0-9]*|*[!A-Za-z0-9_]*) return 1 ;;
        *) return 0 ;;
    esac
}

_patch_configuration_set_error() {
    PATCH_CONFIGURATION_ERROR_DETAIL="$1"
    return 2
}

_patch_configuration_command_into() {
    local command_name="$1"
    local destination_name="$2"
    local candidate=""

    _patch_configuration_valid_destination "$destination_name" || return 2
    case "$command_name" in
        chmod) candidate=/bin/chmod ;;
        chown)
            if [ -x /usr/bin/chown ]; then candidate=/usr/bin/chown; else candidate=/bin/chown; fi
            ;;
        cp)
            if [ -x /usr/bin/cp ]; then candidate=/usr/bin/cp; else candidate=/bin/cp; fi
            ;;
        mktemp)
            if [ -x /usr/bin/mktemp ]; then candidate=/usr/bin/mktemp; else candidate=/bin/mktemp; fi
            ;;
        mv)
            if [ -x /usr/bin/mv ]; then candidate=/usr/bin/mv; else candidate=/bin/mv; fi
            ;;
        rm)
            if [ -x /usr/bin/rm ]; then candidate=/usr/bin/rm; else candidate=/bin/rm; fi
            ;;
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

_patch_configuration_stat_into() {
    local path="$1"
    local device_destination="$2"
    local inode_destination="$3"
    local uid_destination="$4"
    local gid_destination="$5"
    local mode_destination="$6"
    local links_destination="$7"
    local size_destination="$8"
    local mtime_destination="$9"
    local ctime_destination="${10}"
    local stat_command=""
    local output=""
    local destination_name=""
    local stat_device=""
    local stat_inode=""
    local stat_uid=""
    local stat_gid=""
    local stat_mode=""
    local stat_links=""
    local stat_size=""
    local stat_mtime=""
    local stat_ctime=""
    local stat_remainder=""

    for destination_name in "$device_destination" "$inode_destination" "$uid_destination" \
        "$gid_destination" "$mode_destination" "$links_destination" "$size_destination" \
        "$mtime_destination" "$ctime_destination"; do
        _patch_configuration_valid_destination "$destination_name" || return 2
    done
    _patch_configuration_command_into stat stat_command || return $?
    if output="$($stat_command -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' -- "$path" 2>/dev/null)"; then
        :
    elif output="$($stat_command -f '%d:%i:%u:%g:%p:%l:%z:%m:%c' "$path" 2>/dev/null)"; then
        :
    else
        return 2
    fi
    IFS=: read -r stat_device stat_inode stat_uid stat_gid stat_mode stat_links stat_size \
        stat_mtime stat_ctime stat_remainder <<< "$output"
    [ -z "$stat_remainder" ] || return 2
    case "$stat_device:$stat_inode:$stat_uid:$stat_gid:$stat_links:$stat_size:$stat_mtime:$stat_ctime" in
        *[!0-9:]*) return 2 ;;
    esac
    case "$stat_mode" in ''|*[!0-7]*) return 2 ;; esac
    printf -v "$device_destination" '%s' "$stat_device"
    printf -v "$inode_destination" '%s' "$stat_inode"
    printf -v "$uid_destination" '%s' "$stat_uid"
    printf -v "$gid_destination" '%s' "$stat_gid"
    printf -v "$mode_destination" '%04o' "$((8#$stat_mode & 07777))"
    printf -v "$links_destination" '%s' "$stat_links"
    printf -v "$size_destination" '%s' "$stat_size"
    printf -v "$mtime_destination" '%s' "$stat_mtime"
    printf -v "$ctime_destination" '%s' "$stat_ctime"
}

_patch_configuration_sha256_into() {
    local path="$1"
    local destination_name="$2"
    local hash_command=""
    local output=""
    local hash_digest=""

    _patch_configuration_valid_destination "$destination_name" || return 2
    _patch_configuration_command_into sha256sum hash_command || return $?
    case "$hash_command" in
        */shasum) output="$("$hash_command" -a 256 -- "$path" 2>/dev/null)" || return 2 ;;
        *) output="$("$hash_command" -- "$path" 2>/dev/null)" || return 2 ;;
    esac
    hash_digest="${output%% *}"
    [ "${#hash_digest}" -eq 64 ] || return 2
    case "$hash_digest" in *[!0-9a-f]*) return 2 ;; esac
    printf -v "$destination_name" '%s' "$hash_digest"
}

_patch_configuration_capture_file() {
    local path="$1"
    local device_before=""
    local inode_before=""
    local uid_before=""
    local gid_before=""
    local mode_before=""
    local links_before=""
    local size_before=""
    local mtime_before=""
    local ctime_before=""
    local sha256=""
    local device_after=""
    local inode_after=""
    local uid_after=""
    local gid_after=""
    local mode_after=""
    local links_after=""
    local size_after=""
    local mtime_after=""
    local ctime_after=""

    [ -f "$path" ] && [ ! -L "$path" ] || return 2
    _patch_configuration_stat_into "$path" device_before inode_before uid_before gid_before \
        mode_before links_before size_before mtime_before ctime_before || return 2
    [ "$links_before" = 1 ] || return 2
    _patch_configuration_sha256_into "$path" sha256 || return 2
    _patch_configuration_stat_into "$path" device_after inode_after uid_after gid_after \
        mode_after links_after size_after mtime_after ctime_after || return 2
    [ "$links_after" = 1 ] || return 2
    [ "$device_before" = "$device_after" ] && [ "$inode_before" = "$inode_after" ] &&
        [ "$uid_before" = "$uid_after" ] && [ "$gid_before" = "$gid_after" ] &&
        [ "$mode_before" = "$mode_after" ] && [ "$links_before" = "$links_after" ] &&
        [ "$size_before" = "$size_after" ] && [ "$mtime_before" = "$mtime_after" ] &&
        [ "$ctime_before" = "$ctime_after" ] || return 2
    PATCH_CONFIGURATION_CAPTURE_DEVICE="$device_after"
    PATCH_CONFIGURATION_CAPTURE_INODE="$inode_after"
    PATCH_CONFIGURATION_CAPTURE_UID="$uid_after"
    PATCH_CONFIGURATION_CAPTURE_GID="$gid_after"
    PATCH_CONFIGURATION_CAPTURE_MODE="$mode_after"
    PATCH_CONFIGURATION_CAPTURE_SIZE="$size_after"
    PATCH_CONFIGURATION_CAPTURE_MTIME="$mtime_after"
    PATCH_CONFIGURATION_CAPTURE_CTIME="$ctime_after"
    PATCH_CONFIGURATION_CAPTURE_SHA256="$sha256"
}

_patch_configuration_directory_identity_into() {
    local path="$1"
    local device_destination="$2"
    local inode_destination="$3"
    local identity_device=""
    local identity_inode=""
    local identity_uid=""
    local identity_gid=""
    local identity_mode=""
    local identity_links=""
    local identity_size=""
    local identity_mtime=""
    local identity_ctime=""
    local mode_decimal=0
    local effective_uid="${EUID:-}"

    _patch_configuration_valid_destination "$device_destination" || return 2
    _patch_configuration_valid_destination "$inode_destination" || return 2
    [ -d "$path" ] && [ ! -L "$path" ] || return 2
    _patch_configuration_stat_into "$path" identity_device identity_inode identity_uid \
        identity_gid identity_mode identity_links identity_size identity_mtime identity_ctime || return 2
    : "$identity_gid:$identity_links:$identity_size:$identity_mtime:$identity_ctime"
    [ -n "$effective_uid" ] || effective_uid="$identity_uid"
    [ "$identity_uid" = 0 ] || [ "$identity_uid" = "$effective_uid" ] || return 2
    mode_decimal=$((8#$identity_mode))
    if [ $((mode_decimal & 0022)) -ne 0 ]; then
        [ $((mode_decimal & 01000)) -ne 0 ] && [ "$identity_uid" = 0 ] || return 2
        case "$path" in /tmp|/var/tmp|/private/tmp|/private/var/tmp) ;; *) return 2 ;; esac
    fi
    printf -v "$device_destination" '%s' "$identity_device"
    printf -v "$inode_destination" '%s' "$identity_inode"
}

_patch_configuration_root_chain_is_trusted() {
    local root="$1"
    local relative_path="${root#/}"
    local current_path=/
    local component=""
    local device=""
    local inode=""
    local index=0
    local -a components=()

    case "$root" in /*) ;; *) return 2 ;; esac
    _patch_configuration_directory_identity_into / device inode || return 2
    [ -n "$relative_path" ] || return 0
    IFS=/ read -r -a components <<< "$relative_path"
    while [ "$index" -lt "${#components[@]}" ]; do
        component="${components[$index]}"
        case "$component" in ''|.|..) return 2 ;; esac
        current_path="${current_path%/}/$component"
        _patch_configuration_directory_identity_into "$current_path" device inode || return 2
        index=$((index + 1))
    done
}

_patch_configuration_initialize_root() {
    local requested_root="$1"
    local canonical_root=""
    local device=""
    local inode=""

    [ -d "$requested_root" ] && [ ! -L "$requested_root" ] || return 2
    canonical_root="$(CDPATH='' builtin cd -P -- "$requested_root" 2>/dev/null && pwd -P)" || return 2
    _patch_configuration_root_chain_is_trusted "$canonical_root" || return 2
    _patch_configuration_directory_identity_into "$canonical_root" device inode || return 2
    PATCH_CONFIGURATION_ROOT="$canonical_root"
    PATCH_CONFIGURATION_ROOT_DEVICE="$device"
    PATCH_CONFIGURATION_ROOT_INODE="$inode"
}

_patch_configuration_verify_root() {
    local device=""
    local inode=""

    [ -n "$PATCH_CONFIGURATION_ROOT" ] || return 2
    _patch_configuration_root_chain_is_trusted "$PATCH_CONFIGURATION_ROOT" || return 2
    _patch_configuration_directory_identity_into "$PATCH_CONFIGURATION_ROOT" device inode || return 2
    [ "$device" = "$PATCH_CONFIGURATION_ROOT_DEVICE" ] &&
        [ "$inode" = "$PATCH_CONFIGURATION_ROOT_INODE" ]
}

_patch_configuration_resolve_parent_into() {
    local logical_path="$1"
    local parent_destination="$2"
    local physical_destination="$3"
    local relative_path=""
    local current_path=""
    local candidate_path=""
    local component=""
    local device=""
    local inode=""
    local index=0
    local -a components=()

    _patch_configuration_valid_destination "$parent_destination" || return 2
    _patch_configuration_valid_destination "$physical_destination" || return 2
    case "$logical_path" in
        /*) ;;
        *) return 2 ;;
    esac
    case "$logical_path" in /|*//*|*/./*|*/.|*/../*|*/..|*$'\n'*|*$'\r'*|*$'\t'*) return 2 ;; esac
    relative_path="${logical_path#/}"
    IFS=/ read -r -a components <<< "$relative_path"
    [ "${#components[@]}" -gt 1 ] || return 2
    current_path="$PATCH_CONFIGURATION_ROOT"
    _patch_configuration_directory_identity_into "$current_path" device inode || return 2
    while [ "$index" -lt $(( ${#components[@]} - 1 )) ]; do
        component="${components[$index]}"
        case "$component" in ''|.|..) return 2 ;; esac
        candidate_path="${current_path%/}/$component"
        [ -d "$candidate_path" ] && [ ! -L "$candidate_path" ] || return 2
        _patch_configuration_directory_identity_into "$candidate_path" device inode || return 2
        current_path="$candidate_path"
        index=$((index + 1))
    done
    candidate_path="${current_path%/}/${components[$index]}"
    [ ! -L "$candidate_path" ] || return 2
    printf -v "$parent_destination" '%s' "$current_path"
    printf -v "$physical_destination" '%s' "$candidate_path"
}

patch_configuration_supported_criteria() {
    printf '%s\n' U-12 U-62
}

_patch_configuration_rule_content_into() {
    local criterion="$1"
    local logical_path="$2"
    local destination_name="$3"
    local rule_content=""

    _patch_configuration_valid_destination "$destination_name" || return 2
    case "$criterion:$logical_path" in
        U-12:/etc/profile.d/99-kisa-cce-session-timeout.sh)
            rule_content=$'TMOUT=600\nreadonly TMOUT\nexport TMOUT\n'
            ;;
        U-62:/etc/issue|U-62:/etc/issue.net|U-62:/etc/motd)
            rule_content=$'WARNING: This system is for authorized use only. Unauthorized access is prohibited and may be monitored and recorded.\n'
            ;;
        *) return 1 ;;
    esac
    printf -v "$destination_name" '%s' "$rule_content"
}

_patch_configuration_rule_sha256_into() {
    local criterion="$1"
    local logical_path="$2"
    local destination_name="$3"
    local configured_sha256=""

    _patch_configuration_valid_destination "$destination_name" || return 2
    case "$criterion:$logical_path" in
        U-12:/etc/profile.d/99-kisa-cce-session-timeout.sh)
            configured_sha256=c561ac238efc84084c5b244f72f47dbbc78c3eb41a39914ecf33b48c627030a7
            ;;
        U-62:/etc/issue|U-62:/etc/issue.net|U-62:/etc/motd)
            configured_sha256=105d7776b60e9da78e18d0b69a633416f774997ce8d287e4c836537c888a4b9d
            ;;
        *) return 1 ;;
    esac
    printf -v "$destination_name" '%s' "$configured_sha256"
}

_patch_configuration_rule_paths() {
    case "$1" in
        U-12) printf '%s\n' /etc/profile.d/99-kisa-cce-session-timeout.sh ;;
        U-62) printf '%s\n' /etc/issue /etc/issue.net /etc/motd ;;
        *) return 1 ;;
    esac
}

_patch_configuration_desired_mode_into() {
    local before_state="$1"
    local before_mode="$2"
    local destination_name="$3"
    local calculated_mode=0644

    _patch_configuration_valid_destination "$destination_name" || return 2
    case "$before_state" in
        absent) ;;
        present)
            case "$before_mode" in ''|*[!0-7]*) return 2 ;; esac
            printf -v calculated_mode '%04o' "$((8#$before_mode & 8#0644))"
            ;;
        *) return 2 ;;
    esac
    printf -v "$destination_name" '%s' "$calculated_mode"
}

patch_configuration_reset() {
    PATCH_CONFIGURATION_ROOT=""
    PATCH_CONFIGURATION_ROOT_DEVICE=""
    PATCH_CONFIGURATION_ROOT_INODE=""
    PATCH_CONFIGURATION_TRANSACTION_DIRECTORY=""
    PATCH_CONFIGURATION_DATA_DIRECTORY=""
    PATCH_CONFIGURATION_MANIFEST_DEVICE=""
    PATCH_CONFIGURATION_MANIFEST_INODE=""
    PATCH_CONFIGURATION_MANIFEST_SHA256=""
    PATCH_CONFIGURATION_PLAN_VALID=0
    PATCH_CONFIGURATION_VERIFIED=0
    PATCH_CONFIGURATION_CHANGE_COUNT=0
    PATCH_CONFIGURATION_COMPLIANT_COUNT=0
    PATCH_CONFIGURATION_ERROR_DETAIL=""
    PATCH_CONFIGURATION_CRITERIA=()
    PATCH_CONFIGURATION_LOGICAL_PATHS=()
    PATCH_CONFIGURATION_PHYSICAL_PATHS=()
    PATCH_CONFIGURATION_PARENT_PATHS=()
    PATCH_CONFIGURATION_PARENT_DEVICES=()
    PATCH_CONFIGURATION_PARENT_INODES=()
    PATCH_CONFIGURATION_BEFORE_STATES=()
    PATCH_CONFIGURATION_BEFORE_DEVICES=()
    PATCH_CONFIGURATION_BEFORE_INODES=()
    PATCH_CONFIGURATION_BEFORE_UIDS=()
    PATCH_CONFIGURATION_BEFORE_GIDS=()
    PATCH_CONFIGURATION_BEFORE_MODES=()
    PATCH_CONFIGURATION_BEFORE_SIZES=()
    PATCH_CONFIGURATION_BEFORE_MTIMES=()
    PATCH_CONFIGURATION_BEFORE_CTIMES=()
    PATCH_CONFIGURATION_BEFORE_SHA256S=()
    PATCH_CONFIGURATION_DESIRED_UIDS=()
    PATCH_CONFIGURATION_DESIRED_GIDS=()
    PATCH_CONFIGURATION_DESIRED_MODES=()
    PATCH_CONFIGURATION_DESIRED_SHA256S=()
    PATCH_CONFIGURATION_BACKUP_NAMES=()
    PATCH_CONFIGURATION_PAYLOAD_NAMES=()
    PATCH_CONFIGURATION_TARGET_STATES=()
    PATCH_CONFIGURATION_STAGE_PATHS=()
    PATCH_CONFIGURATION_AFTER_DEVICES=()
    PATCH_CONFIGURATION_AFTER_INODES=()
    PATCH_CONFIGURATION_AFTER_UIDS=()
    PATCH_CONFIGURATION_AFTER_GIDS=()
    PATCH_CONFIGURATION_AFTER_MODES=()
    PATCH_CONFIGURATION_AFTER_SIZES=()
    PATCH_CONFIGURATION_AFTER_MTIMES=()
    PATCH_CONFIGURATION_AFTER_CTIMES=()
    PATCH_CONFIGURATION_AFTER_SHA256S=()
    PATCH_CONFIGURATION_CURRENT_STATES=()
}

patch_configuration_state_into() {
    local criterion="$1"
    local destination_name="$2"
    local computed_state=compliant
    local found=0
    local index=0

    _patch_configuration_valid_destination "$destination_name" || return 2
    case "$criterion" in U-12|U-62) ;; *) return 1 ;; esac
    while [ "$index" -lt "${#PATCH_CONFIGURATION_CRITERIA[@]}" ]; do
        if [ "${PATCH_CONFIGURATION_CRITERIA[$index]}" = "$criterion" ]; then
            found=1
            if [ "$PATCH_CONFIGURATION_VERIFIED" -eq 1 ]; then
                computed_state=verified
            elif [ "${PATCH_CONFIGURATION_TARGET_STATES[$index]}" = ready ]; then
                computed_state=ready
            fi
        fi
        index=$((index + 1))
    done
    [ "$found" -eq 1 ] || return 1
    printf -v "$destination_name" '%s' "$computed_state"
}

_patch_configuration_transaction_directory_is_safe() {
    local transaction_directory="$1"
    local canonical_transaction=""
    local device=""
    local inode=""
    local uid=""
    local gid=""
    local mode=""
    local links=""
    local size=""
    local mtime=""
    local ctime=""
    local effective_uid="${EUID:-}"

    [ -d "$transaction_directory" ] && [ ! -L "$transaction_directory" ] || return 2
    canonical_transaction="$(CDPATH='' builtin cd -P -- "$transaction_directory" 2>/dev/null && pwd -P)" || return 2
    _patch_configuration_root_chain_is_trusted "$canonical_transaction" || return 2
    _patch_configuration_stat_into "$canonical_transaction" device inode uid gid mode links size mtime ctime || return 2
    : "$gid:$links:$size:$mtime:$ctime"
    [ -n "$effective_uid" ] || effective_uid="$uid"
    [ "$uid" = "$effective_uid" ] && [ $((8#$mode & 0077)) -eq 0 ]
}

_patch_configuration_private_directory_is_safe() {
    local directory_path="$1"
    local device=""
    local inode=""
    local uid=""
    local gid=""
    local mode=""
    local links=""
    local size=""
    local mtime=""
    local ctime=""

    [ -d "$directory_path" ] && [ ! -L "$directory_path" ] || return 2
    _patch_configuration_stat_into "$directory_path" device inode uid gid mode links size mtime ctime || return 2
    [ "$uid" = "${EUID:-0}" ] && [ $((8#$mode & 0077)) -eq 0 ]
}

_patch_configuration_create_private_file() {
    local path="$1"

    [ ! -e "$path" ] && [ ! -L "$path" ] || return 2
    (umask 077; set -C; : > "$path") 2>/dev/null || return 2
    [ -f "$path" ] && [ ! -L "$path" ] || return 2
}

_patch_configuration_write_payload() {
    local path="$1"
    local content="$2"

    _patch_configuration_create_private_file "$path" || return 2
    printf '%s' "$content" > "$path" || return 2
    /bin/chmod 0600 "$path" || return 2
}

_patch_configuration_copy_backup() {
    local source_path="$1"
    local backup_path="$2"
    local cp_command=""
    local chmod_command=""

    [ ! -e "$backup_path" ] && [ ! -L "$backup_path" ] || return 2
    _patch_configuration_command_into cp cp_command || return $?
    _patch_configuration_command_into chmod chmod_command || return $?
    (umask 077; "$cp_command" "$source_path" "$backup_path") || return 2
    "$chmod_command" 0600 "$backup_path" || return 2
    [ -f "$backup_path" ] && [ ! -L "$backup_path" ] || return 2
}

_patch_configuration_append_record() {
    local target_state=ready
    local record_index="${#PATCH_CONFIGURATION_CRITERIA[@]}"

    PATCH_CONFIGURATION_CRITERIA+=("$1")
    PATCH_CONFIGURATION_LOGICAL_PATHS+=("$2")
    PATCH_CONFIGURATION_PHYSICAL_PATHS+=("$3")
    PATCH_CONFIGURATION_PARENT_PATHS+=("$4")
    PATCH_CONFIGURATION_PARENT_DEVICES+=("$5")
    PATCH_CONFIGURATION_PARENT_INODES+=("$6")
    PATCH_CONFIGURATION_BEFORE_STATES+=("$7")
    PATCH_CONFIGURATION_BEFORE_DEVICES+=("$8")
    PATCH_CONFIGURATION_BEFORE_INODES+=("$9")
    shift 9
    PATCH_CONFIGURATION_BEFORE_UIDS+=("$1")
    PATCH_CONFIGURATION_BEFORE_GIDS+=("$2")
    PATCH_CONFIGURATION_BEFORE_MODES+=("$3")
    PATCH_CONFIGURATION_BEFORE_SIZES+=("$4")
    PATCH_CONFIGURATION_BEFORE_MTIMES+=("$5")
    PATCH_CONFIGURATION_BEFORE_CTIMES+=("$6")
    PATCH_CONFIGURATION_BEFORE_SHA256S+=("$7")
    PATCH_CONFIGURATION_DESIRED_UIDS+=("$8")
    PATCH_CONFIGURATION_DESIRED_GIDS+=("$9")
    shift 9
    PATCH_CONFIGURATION_DESIRED_MODES+=("$1")
    PATCH_CONFIGURATION_DESIRED_SHA256S+=("$2")
    PATCH_CONFIGURATION_BACKUP_NAMES+=("$3")
    PATCH_CONFIGURATION_PAYLOAD_NAMES+=("$4")
    if [ "${PATCH_CONFIGURATION_BEFORE_STATES[$record_index]}" = present ] &&
        [ "${PATCH_CONFIGURATION_BEFORE_UIDS[$record_index]}" = "${PATCH_CONFIGURATION_DESIRED_UIDS[$record_index]}" ] &&
        [ "${PATCH_CONFIGURATION_BEFORE_GIDS[$record_index]}" = "${PATCH_CONFIGURATION_DESIRED_GIDS[$record_index]}" ] &&
        [ "${PATCH_CONFIGURATION_BEFORE_MODES[$record_index]}" = "$1" ] &&
        [ "${PATCH_CONFIGURATION_BEFORE_SHA256S[$record_index]}" = "$2" ]; then
        target_state=compliant
        PATCH_CONFIGURATION_COMPLIANT_COUNT=$((PATCH_CONFIGURATION_COMPLIANT_COUNT + 1))
    else
        PATCH_CONFIGURATION_CHANGE_COUNT=$((PATCH_CONFIGURATION_CHANGE_COUNT + 1))
    fi
    PATCH_CONFIGURATION_TARGET_STATES+=("$target_state")
    PATCH_CONFIGURATION_STAGE_PATHS+=("")
    PATCH_CONFIGURATION_AFTER_DEVICES+=("")
    PATCH_CONFIGURATION_AFTER_INODES+=("")
    PATCH_CONFIGURATION_AFTER_UIDS+=("")
    PATCH_CONFIGURATION_AFTER_GIDS+=("")
    PATCH_CONFIGURATION_AFTER_MODES+=("")
    PATCH_CONFIGURATION_AFTER_SIZES+=("")
    PATCH_CONFIGURATION_AFTER_MTIMES+=("")
    PATCH_CONFIGURATION_AFTER_CTIMES+=("")
    PATCH_CONFIGURATION_AFTER_SHA256S+=("")
    PATCH_CONFIGURATION_CURRENT_STATES+=("")
}

_patch_configuration_plan_path() {
    local criterion="$1"
    local logical_path="$2"
    local index="${#PATCH_CONFIGURATION_CRITERIA[@]}"
    local record_number=0
    local record_name=""
    local parent_path=""
    local physical_path=""
    local parent_device=""
    local parent_inode=""
    local before_state=absent
    local before_device=-
    local before_inode=-
    local before_uid=-
    local before_gid=-
    local before_mode=-
    local before_size=-
    local before_mtime=-
    local before_ctime=-
    local before_sha256=-
    local backup_name=-
    local payload_name=""
    local content=""
    local backup_sha256=""
    local payload_sha256=""
    local rule_sha256=""
    local desired_mode=""

    _patch_configuration_rule_content_into "$criterion" "$logical_path" content || return 2
    _patch_configuration_rule_sha256_into "$criterion" "$logical_path" rule_sha256 || return 2
    _patch_configuration_resolve_parent_into "$logical_path" parent_path physical_path || return 2
    _patch_configuration_directory_identity_into "$parent_path" parent_device parent_inode || return 2
    printf -v record_number '%06d' "$((index + 1))"
    payload_name="payloads/$record_number"
    _patch_configuration_write_payload "$PATCH_CONFIGURATION_DATA_DIRECTORY/$payload_name" "$content" || return 2
    _patch_configuration_capture_file "$PATCH_CONFIGURATION_DATA_DIRECTORY/$payload_name" || return 2
    payload_sha256="$PATCH_CONFIGURATION_CAPTURE_SHA256"
    [ "$payload_sha256" = "$rule_sha256" ] || return 2

    if [ -e "$physical_path" ] || [ -L "$physical_path" ]; then
        _patch_configuration_capture_file "$physical_path" || return 2
        before_state=present
        before_device="$PATCH_CONFIGURATION_CAPTURE_DEVICE"
        before_inode="$PATCH_CONFIGURATION_CAPTURE_INODE"
        before_uid="$PATCH_CONFIGURATION_CAPTURE_UID"
        before_gid="$PATCH_CONFIGURATION_CAPTURE_GID"
        before_mode="$PATCH_CONFIGURATION_CAPTURE_MODE"
        before_size="$PATCH_CONFIGURATION_CAPTURE_SIZE"
        before_mtime="$PATCH_CONFIGURATION_CAPTURE_MTIME"
        before_ctime="$PATCH_CONFIGURATION_CAPTURE_CTIME"
        before_sha256="$PATCH_CONFIGURATION_CAPTURE_SHA256"
        backup_name="backups/$record_number"
        _patch_configuration_copy_backup "$physical_path" \
            "$PATCH_CONFIGURATION_DATA_DIRECTORY/$backup_name" || return 2
        _patch_configuration_sha256_into "$PATCH_CONFIGURATION_DATA_DIRECTORY/$backup_name" backup_sha256 || return 2
        [ "$backup_sha256" = "$before_sha256" ] || return 2
        _patch_configuration_capture_file "$physical_path" || return 2
        [ "$PATCH_CONFIGURATION_CAPTURE_DEVICE" = "$before_device" ] &&
            [ "$PATCH_CONFIGURATION_CAPTURE_INODE" = "$before_inode" ] &&
            [ "$PATCH_CONFIGURATION_CAPTURE_UID" = "$before_uid" ] &&
            [ "$PATCH_CONFIGURATION_CAPTURE_GID" = "$before_gid" ] &&
            [ "$PATCH_CONFIGURATION_CAPTURE_MODE" = "$before_mode" ] &&
            [ "$PATCH_CONFIGURATION_CAPTURE_SIZE" = "$before_size" ] &&
            [ "$PATCH_CONFIGURATION_CAPTURE_MTIME" = "$before_mtime" ] &&
            [ "$PATCH_CONFIGURATION_CAPTURE_CTIME" = "$before_ctime" ] &&
            [ "$PATCH_CONFIGURATION_CAPTURE_SHA256" = "$before_sha256" ] || return 2
    fi
    _patch_configuration_desired_mode_into "$before_state" "$before_mode" desired_mode || return 2
    record_name="$criterion:$logical_path"
    case " ${PATCH_CONFIGURATION_LOGICAL_PATHS[*]} " in *" $logical_path "*) return 2 ;; esac
    [ -n "$record_name" ] || return 2
    _patch_configuration_append_record "$criterion" "$logical_path" "$physical_path" "$parent_path" \
        "$parent_device" "$parent_inode" "$before_state" "$before_device" "$before_inode" \
        "$before_uid" "$before_gid" "$before_mode" "$before_size" "$before_mtime" \
        "$before_ctime" "$before_sha256" 0 0 "$desired_mode" "$payload_sha256" "$backup_name" "$payload_name"
}

_patch_configuration_write_manifest() {
    local manifest_path="$PATCH_CONFIGURATION_DATA_DIRECTORY/manifest.tsv"
    local index=0

    _patch_configuration_create_private_file "$manifest_path" || return 2
    {
        printf '%s\n' "$PATCH_CONFIGURATION_MANIFEST_HEADER"
        while [ "$index" -lt "${#PATCH_CONFIGURATION_CRITERIA[@]}" ]; do
            printf '1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "${PATCH_CONFIGURATION_CRITERIA[$index]}" \
                "${PATCH_CONFIGURATION_LOGICAL_PATHS[$index]}" \
                "$PATCH_CONFIGURATION_ROOT_DEVICE" "$PATCH_CONFIGURATION_ROOT_INODE" \
                "${PATCH_CONFIGURATION_PARENT_DEVICES[$index]}" \
                "${PATCH_CONFIGURATION_PARENT_INODES[$index]}" \
                "${PATCH_CONFIGURATION_BEFORE_STATES[$index]}" \
                "${PATCH_CONFIGURATION_BEFORE_DEVICES[$index]}" \
                "${PATCH_CONFIGURATION_BEFORE_INODES[$index]}" \
                "${PATCH_CONFIGURATION_BEFORE_UIDS[$index]}" \
                "${PATCH_CONFIGURATION_BEFORE_GIDS[$index]}" \
                "${PATCH_CONFIGURATION_BEFORE_MODES[$index]}" \
                "${PATCH_CONFIGURATION_BEFORE_SIZES[$index]}" \
                "${PATCH_CONFIGURATION_BEFORE_MTIMES[$index]}" \
                "${PATCH_CONFIGURATION_BEFORE_CTIMES[$index]}" \
                "${PATCH_CONFIGURATION_BEFORE_SHA256S[$index]}" \
                "${PATCH_CONFIGURATION_DESIRED_UIDS[$index]}" \
                "${PATCH_CONFIGURATION_DESIRED_GIDS[$index]}" \
                "${PATCH_CONFIGURATION_DESIRED_MODES[$index]}" \
                "${PATCH_CONFIGURATION_DESIRED_SHA256S[$index]}" \
                "${PATCH_CONFIGURATION_BACKUP_NAMES[$index]}" \
                "${PATCH_CONFIGURATION_PAYLOAD_NAMES[$index]}"
            index=$((index + 1))
        done
    } > "$manifest_path" || return 2
    /bin/chmod 0600 "$manifest_path" || return 2
    _patch_configuration_capture_file "$manifest_path" || return 2
    [ "$PATCH_CONFIGURATION_CAPTURE_UID" = "${EUID:-0}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_MODE" = 0600 ] || return 2
    PATCH_CONFIGURATION_MANIFEST_DEVICE="$PATCH_CONFIGURATION_CAPTURE_DEVICE"
    PATCH_CONFIGURATION_MANIFEST_INODE="$PATCH_CONFIGURATION_CAPTURE_INODE"
    PATCH_CONFIGURATION_MANIFEST_SHA256="$PATCH_CONFIGURATION_CAPTURE_SHA256"
}

_patch_configuration_render_plan() {
    local index=0
    local action=""

    printf '%s\n' "$PATCH_CONFIGURATION_PLAN_HEADER"
    while [ "$index" -lt "${#PATCH_CONFIGURATION_CRITERIA[@]}" ]; do
        if [ "${PATCH_CONFIGURATION_BEFORE_STATES[$index]}" = absent ]; then
            action=create
        else
            action=replace
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${PATCH_CONFIGURATION_CRITERIA[$index]}" "$action" \
            "${PATCH_CONFIGURATION_LOGICAL_PATHS[$index]}" \
            "${PATCH_CONFIGURATION_BEFORE_UIDS[$index]}" \
            "${PATCH_CONFIGURATION_BEFORE_GIDS[$index]}" \
            "${PATCH_CONFIGURATION_BEFORE_MODES[$index]}" \
            "${PATCH_CONFIGURATION_BEFORE_SHA256S[$index]}" \
            "${PATCH_CONFIGURATION_DESIRED_UIDS[$index]}" \
            "${PATCH_CONFIGURATION_DESIRED_GIDS[$index]}" \
            "${PATCH_CONFIGURATION_DESIRED_MODES[$index]}" \
            "${PATCH_CONFIGURATION_DESIRED_SHA256S[$index]}"
        index=$((index + 1))
    done
}

patch_configuration_write_plan_tsv() {
    local output_path="$1"
    local output_parent="${output_path%/*}"
    local output_leaf="${output_path##*/}"
    local canonical_parent=""
    local rm_command=""

    [ "$PATCH_CONFIGURATION_PLAN_VALID" -eq 1 ] || return 2
    case "$output_path" in
        /*) ;;
        *) return 2 ;;
    esac
    case "$output_path" in *$'\n'*|*$'\r'*|*$'\t'*) return 2 ;; esac
    [ "$output_parent" != "$output_path" ] || return 2
    case "$output_leaf" in ''|.|..|*/*) return 2 ;; esac
    _patch_configuration_transaction_directory_is_safe "$output_parent" || return 2
    canonical_parent="$(CDPATH='' builtin cd -P -- "$output_parent" && pwd -P)" || return 2
    output_path="$canonical_parent/$output_leaf"
    [ ! -e "$output_path" ] && [ ! -L "$output_path" ] || return 2
    _patch_configuration_create_private_file "$output_path" || return 2
    if ! _patch_configuration_render_plan > "$output_path" ||
        ! /bin/chmod 0600 "$output_path" ||
        ! _patch_configuration_capture_file "$output_path" ||
        [ "$PATCH_CONFIGURATION_CAPTURE_UID" != "${EUID:-0}" ] ||
        [ "$PATCH_CONFIGURATION_CAPTURE_MODE" != 0600 ]; then
        _patch_configuration_command_into rm rm_command || return 2
        "$rm_command" -f "$output_path" >/dev/null 2>&1 || :
        return 2
    fi
}

_patch_configuration_discard_data_directory() {
    local rm_command=""

    [ -n "$PATCH_CONFIGURATION_DATA_DIRECTORY" ] || return 0
    case "$PATCH_CONFIGURATION_DATA_DIRECTORY" in
        "$PATCH_CONFIGURATION_TRANSACTION_DIRECTORY/configuration") ;;
        *) return 2 ;;
    esac
    _patch_configuration_command_into rm rm_command || return $?
    "$rm_command" -rf "$PATCH_CONFIGURATION_DATA_DIRECTORY"
}

patch_configuration_plan() {
    local requested_root="$1"
    local transaction_directory="$2"
    local criterion=""
    local selected=$'\n'
    local logical_path=""
    local status=0

    shift 2
    patch_configuration_reset
    [ "$#" -gt 0 ] || {
        _patch_configuration_set_error "no configuration patch criteria were selected"
        return 2
    }
    for criterion in "$@"; do
        case "$selected" in *$'\n'"$criterion"$'\n'*)
            _patch_configuration_set_error "duplicate configuration patch criterion: $criterion"
            return 2
            ;;
        esac
        _patch_configuration_rule_paths "$criterion" >/dev/null 2>&1 || {
            PATCH_CONFIGURATION_ERROR_DETAIL="unsupported configuration patch criterion: $criterion"
            return 1
        }
        selected+="$criterion"$'\n'
    done
    _patch_configuration_initialize_root "$requested_root" || {
        _patch_configuration_set_error "configuration patch root is unsafe: $requested_root"
        return 2
    }
    _patch_configuration_transaction_directory_is_safe "$transaction_directory" || {
        _patch_configuration_set_error "configuration transaction directory is unsafe: $transaction_directory"
        return 2
    }
    PATCH_CONFIGURATION_TRANSACTION_DIRECTORY="$(CDPATH='' builtin cd -P -- "$transaction_directory" && pwd -P)" || return 2
    PATCH_CONFIGURATION_DATA_DIRECTORY="$PATCH_CONFIGURATION_TRANSACTION_DIRECTORY/configuration"
    [ ! -e "$PATCH_CONFIGURATION_DATA_DIRECTORY" ] && [ ! -L "$PATCH_CONFIGURATION_DATA_DIRECTORY" ] || {
        _patch_configuration_set_error "configuration transaction data already exists"
        return 2
    }
    (umask 077; /bin/mkdir -- "$PATCH_CONFIGURATION_DATA_DIRECTORY" \
        "$PATCH_CONFIGURATION_DATA_DIRECTORY/backups" \
        "$PATCH_CONFIGURATION_DATA_DIRECTORY/payloads" \
        "$PATCH_CONFIGURATION_DATA_DIRECTORY/journal") || {
        _patch_configuration_set_error "cannot create configuration transaction data"
        return 2
    }
    for logical_path in "$PATCH_CONFIGURATION_DATA_DIRECTORY" \
        "$PATCH_CONFIGURATION_DATA_DIRECTORY/backups" \
        "$PATCH_CONFIGURATION_DATA_DIRECTORY/payloads" \
        "$PATCH_CONFIGURATION_DATA_DIRECTORY/journal"; do
        _patch_configuration_private_directory_is_safe "$logical_path" || {
            _patch_configuration_discard_data_directory >/dev/null 2>&1 || :
            _patch_configuration_set_error "configuration transaction data permissions are unsafe"
            return 2
        }
    done
    for criterion in "$@"; do
        while IFS= read -r logical_path; do
            [ -n "$logical_path" ] || continue
            _patch_configuration_plan_path "$criterion" "$logical_path" || status=$?
            if [ "$status" -ne 0 ]; then
                _patch_configuration_discard_data_directory >/dev/null 2>&1 || :
                _patch_configuration_set_error "$criterion: cannot safely back up and plan $logical_path"
                return 2
            fi
        done < <(_patch_configuration_rule_paths "$criterion")
    done
    _patch_configuration_write_manifest || {
        _patch_configuration_discard_data_directory >/dev/null 2>&1 || :
        _patch_configuration_set_error "cannot write configuration transaction manifest"
        return 2
    }
    PATCH_CONFIGURATION_PLAN_VALID=1
}

_patch_configuration_manifest_is_unchanged() {
    local manifest_path="$PATCH_CONFIGURATION_DATA_DIRECTORY/manifest.tsv"

    _patch_configuration_capture_file "$manifest_path" || return 2
    [ "$PATCH_CONFIGURATION_CAPTURE_DEVICE" = "$PATCH_CONFIGURATION_MANIFEST_DEVICE" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_INODE" = "$PATCH_CONFIGURATION_MANIFEST_INODE" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_SHA256" = "$PATCH_CONFIGURATION_MANIFEST_SHA256" ]
}

_patch_configuration_parent_is_unchanged() {
    local index="$1"
    local device=""
    local inode=""

    _patch_configuration_directory_identity_into "${PATCH_CONFIGURATION_PARENT_PATHS[$index]}" \
        device inode || return 2
    [ "$device" = "${PATCH_CONFIGURATION_PARENT_DEVICES[$index]}" ] &&
        [ "$inode" = "${PATCH_CONFIGURATION_PARENT_INODES[$index]}" ]
}

_patch_configuration_current_matches_before() {
    local index="$1"
    local path="${PATCH_CONFIGURATION_PHYSICAL_PATHS[$index]}"

    _patch_configuration_parent_is_unchanged "$index" || return 2
    if [ "${PATCH_CONFIGURATION_BEFORE_STATES[$index]}" = absent ]; then
        [ ! -e "$path" ] && [ ! -L "$path" ]
        return
    fi
    _patch_configuration_capture_file "$path" || return 2
    [ "$PATCH_CONFIGURATION_CAPTURE_DEVICE" = "${PATCH_CONFIGURATION_BEFORE_DEVICES[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_INODE" = "${PATCH_CONFIGURATION_BEFORE_INODES[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_UID" = "${PATCH_CONFIGURATION_BEFORE_UIDS[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_GID" = "${PATCH_CONFIGURATION_BEFORE_GIDS[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_MODE" = "${PATCH_CONFIGURATION_BEFORE_MODES[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_SIZE" = "${PATCH_CONFIGURATION_BEFORE_SIZES[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_MTIME" = "${PATCH_CONFIGURATION_BEFORE_MTIMES[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_CTIME" = "${PATCH_CONFIGURATION_BEFORE_CTIMES[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_SHA256" = "${PATCH_CONFIGURATION_BEFORE_SHA256S[$index]}" ]
}

_patch_configuration_current_matches_after() {
    local index="$1"
    local path="${PATCH_CONFIGURATION_PHYSICAL_PATHS[$index]}"

    _patch_configuration_parent_is_unchanged "$index" || return 2
    [ -n "${PATCH_CONFIGURATION_AFTER_INODES[$index]}" ] || return 2
    _patch_configuration_capture_file "$path" || return 2
    [ "$PATCH_CONFIGURATION_CAPTURE_DEVICE" = "${PATCH_CONFIGURATION_AFTER_DEVICES[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_INODE" = "${PATCH_CONFIGURATION_AFTER_INODES[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_UID" = "${PATCH_CONFIGURATION_AFTER_UIDS[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_GID" = "${PATCH_CONFIGURATION_AFTER_GIDS[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_MODE" = "${PATCH_CONFIGURATION_AFTER_MODES[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_SIZE" = "${PATCH_CONFIGURATION_AFTER_SIZES[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_MTIME" = "${PATCH_CONFIGURATION_AFTER_MTIMES[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_CTIME" = "${PATCH_CONFIGURATION_AFTER_CTIMES[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_SHA256" = "${PATCH_CONFIGURATION_AFTER_SHA256S[$index]}" ]
}

_patch_configuration_set_after_from_before() {
    local index="$1"

    [ "${PATCH_CONFIGURATION_BEFORE_STATES[$index]}" = present ] || return 2
    PATCH_CONFIGURATION_AFTER_DEVICES[$index]="${PATCH_CONFIGURATION_BEFORE_DEVICES[$index]}"
    PATCH_CONFIGURATION_AFTER_INODES[$index]="${PATCH_CONFIGURATION_BEFORE_INODES[$index]}"
    PATCH_CONFIGURATION_AFTER_UIDS[$index]="${PATCH_CONFIGURATION_BEFORE_UIDS[$index]}"
    PATCH_CONFIGURATION_AFTER_GIDS[$index]="${PATCH_CONFIGURATION_BEFORE_GIDS[$index]}"
    PATCH_CONFIGURATION_AFTER_MODES[$index]="${PATCH_CONFIGURATION_BEFORE_MODES[$index]}"
    PATCH_CONFIGURATION_AFTER_SIZES[$index]="${PATCH_CONFIGURATION_BEFORE_SIZES[$index]}"
    PATCH_CONFIGURATION_AFTER_MTIMES[$index]="${PATCH_CONFIGURATION_BEFORE_MTIMES[$index]}"
    PATCH_CONFIGURATION_AFTER_CTIMES[$index]="${PATCH_CONFIGURATION_BEFORE_CTIMES[$index]}"
    PATCH_CONFIGURATION_AFTER_SHA256S[$index]="${PATCH_CONFIGURATION_BEFORE_SHA256S[$index]}"
}

_patch_configuration_artifacts_are_valid() {
    local index=0
    local digest=""
    local path=""

    _patch_configuration_manifest_is_unchanged || return 2
    while [ "$index" -lt "${#PATCH_CONFIGURATION_CRITERIA[@]}" ]; do
        path="$PATCH_CONFIGURATION_DATA_DIRECTORY/${PATCH_CONFIGURATION_PAYLOAD_NAMES[$index]}"
        _patch_configuration_capture_file "$path" || return 2
        [ "$PATCH_CONFIGURATION_CAPTURE_UID" = "${EUID:-0}" ] &&
            [ "$PATCH_CONFIGURATION_CAPTURE_MODE" = 0600 ] &&
            [ "$PATCH_CONFIGURATION_CAPTURE_SHA256" = "${PATCH_CONFIGURATION_DESIRED_SHA256S[$index]}" ] || return 2
        if [ "${PATCH_CONFIGURATION_BEFORE_STATES[$index]}" = present ]; then
            path="$PATCH_CONFIGURATION_DATA_DIRECTORY/${PATCH_CONFIGURATION_BACKUP_NAMES[$index]}"
            _patch_configuration_capture_file "$path" || return 2
            digest="$PATCH_CONFIGURATION_CAPTURE_SHA256"
            [ "$PATCH_CONFIGURATION_CAPTURE_UID" = "${EUID:-0}" ] &&
                [ "$PATCH_CONFIGURATION_CAPTURE_MODE" = 0600 ] &&
                [ "$digest" = "${PATCH_CONFIGURATION_BEFORE_SHA256S[$index]}" ] || return 2
        fi
        index=$((index + 1))
    done
}

_patch_configuration_write_journal() {
    local index="$1"
    local record_number=0
    local journal_path=""

    printf -v record_number '%06d' "$((index + 1))"
    journal_path="$PATCH_CONFIGURATION_DATA_DIRECTORY/journal/$record_number.tsv"
    _patch_configuration_create_private_file "$journal_path" || return 2
    {
        printf '%s\n' "$PATCH_CONFIGURATION_JOURNAL_HEADER"
        printf '1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$index" "${PATCH_CONFIGURATION_LOGICAL_PATHS[$index]}" \
            "${PATCH_CONFIGURATION_AFTER_DEVICES[$index]}" \
            "${PATCH_CONFIGURATION_AFTER_INODES[$index]}" \
            "${PATCH_CONFIGURATION_AFTER_UIDS[$index]}" \
            "${PATCH_CONFIGURATION_AFTER_GIDS[$index]}" \
            "${PATCH_CONFIGURATION_AFTER_MODES[$index]}" \
            "${PATCH_CONFIGURATION_AFTER_SIZES[$index]}" \
            "${PATCH_CONFIGURATION_AFTER_MTIMES[$index]}" \
            "${PATCH_CONFIGURATION_AFTER_CTIMES[$index]}" \
            "${PATCH_CONFIGURATION_AFTER_SHA256S[$index]}"
    } > "$journal_path" || return 2
    /bin/chmod 0600 "$journal_path" || return 2
}

_patch_configuration_stage_payload() {
    local index="$1"
    local parent_path="${PATCH_CONFIGURATION_PARENT_PATHS[$index]}"
    local payload_path="$PATCH_CONFIGURATION_DATA_DIRECTORY/${PATCH_CONFIGURATION_PAYLOAD_NAMES[$index]}"
    local mktemp_command=""
    local cp_command=""
    local chown_command=""
    local chmod_command=""
    local stage_path=""

    _patch_configuration_command_into mktemp mktemp_command || return $?
    _patch_configuration_command_into cp cp_command || return $?
    _patch_configuration_command_into chown chown_command || return $?
    _patch_configuration_command_into chmod chmod_command || return $?
    stage_path="$(umask 077; "$mktemp_command" "$parent_path/.kisa-cce-patch.XXXXXXXX")" || return 2
    PATCH_CONFIGURATION_STAGE_PATHS[$index]="$stage_path"
    "$cp_command" "$payload_path" "$stage_path" || return 2
    "$chown_command" "${PATCH_CONFIGURATION_DESIRED_UIDS[$index]}:${PATCH_CONFIGURATION_DESIRED_GIDS[$index]}" \
        "$stage_path" || return 2
    "$chmod_command" "${PATCH_CONFIGURATION_DESIRED_MODES[$index]}" "$stage_path" || return 2
    _patch_configuration_capture_file "$stage_path" || return 2
    [ "$PATCH_CONFIGURATION_CAPTURE_UID" = "${PATCH_CONFIGURATION_DESIRED_UIDS[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_GID" = "${PATCH_CONFIGURATION_DESIRED_GIDS[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_MODE" = "${PATCH_CONFIGURATION_DESIRED_MODES[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_SHA256" = "${PATCH_CONFIGURATION_DESIRED_SHA256S[$index]}" ] || return 2
    PATCH_CONFIGURATION_AFTER_DEVICES[$index]="$PATCH_CONFIGURATION_CAPTURE_DEVICE"
    PATCH_CONFIGURATION_AFTER_INODES[$index]="$PATCH_CONFIGURATION_CAPTURE_INODE"
    PATCH_CONFIGURATION_AFTER_UIDS[$index]="$PATCH_CONFIGURATION_CAPTURE_UID"
    PATCH_CONFIGURATION_AFTER_GIDS[$index]="$PATCH_CONFIGURATION_CAPTURE_GID"
    PATCH_CONFIGURATION_AFTER_MODES[$index]="$PATCH_CONFIGURATION_CAPTURE_MODE"
    PATCH_CONFIGURATION_AFTER_SIZES[$index]="$PATCH_CONFIGURATION_CAPTURE_SIZE"
    PATCH_CONFIGURATION_AFTER_MTIMES[$index]="$PATCH_CONFIGURATION_CAPTURE_MTIME"
    PATCH_CONFIGURATION_AFTER_CTIMES[$index]="$PATCH_CONFIGURATION_CAPTURE_CTIME"
    PATCH_CONFIGURATION_AFTER_SHA256S[$index]="$PATCH_CONFIGURATION_CAPTURE_SHA256"
    _patch_configuration_write_journal "$index"
}

_patch_configuration_cleanup_stages() {
    local rm_command=""
    local stage_path=""
    local index=0

    _patch_configuration_command_into rm rm_command || return 2
    while [ "$index" -lt "${#PATCH_CONFIGURATION_STAGE_PATHS[@]}" ]; do
        stage_path="${PATCH_CONFIGURATION_STAGE_PATHS[$index]}"
        if [ -n "$stage_path" ] && [ -f "$stage_path" ] && [ ! -L "$stage_path" ]; then
            "$rm_command" -f "$stage_path" || return 2
        fi
        PATCH_CONFIGURATION_STAGE_PATHS[$index]=""
        index=$((index + 1))
    done
}

_patch_configuration_move_into_place() {
    local source_path="$1"
    local destination_path="$2"
    local mv_command=""

    _patch_configuration_command_into mv mv_command || return $?
    "$mv_command" -f "$source_path" "$destination_path"
}

_patch_configuration_refresh_after_move() {
    local index="$1"
    local expected_device="${PATCH_CONFIGURATION_AFTER_DEVICES[$index]}"
    local expected_inode="${PATCH_CONFIGURATION_AFTER_INODES[$index]}"
    local journal_name=""

    _patch_configuration_capture_file "${PATCH_CONFIGURATION_PHYSICAL_PATHS[$index]}" || return 2
    [ "$PATCH_CONFIGURATION_CAPTURE_DEVICE" = "$expected_device" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_INODE" = "$expected_inode" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_UID" = "${PATCH_CONFIGURATION_DESIRED_UIDS[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_GID" = "${PATCH_CONFIGURATION_DESIRED_GIDS[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_MODE" = "${PATCH_CONFIGURATION_DESIRED_MODES[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_SHA256" = "${PATCH_CONFIGURATION_DESIRED_SHA256S[$index]}" ] || return 2
    PATCH_CONFIGURATION_AFTER_DEVICES[$index]="$PATCH_CONFIGURATION_CAPTURE_DEVICE"
    PATCH_CONFIGURATION_AFTER_INODES[$index]="$PATCH_CONFIGURATION_CAPTURE_INODE"
    PATCH_CONFIGURATION_AFTER_UIDS[$index]="$PATCH_CONFIGURATION_CAPTURE_UID"
    PATCH_CONFIGURATION_AFTER_GIDS[$index]="$PATCH_CONFIGURATION_CAPTURE_GID"
    PATCH_CONFIGURATION_AFTER_MODES[$index]="$PATCH_CONFIGURATION_CAPTURE_MODE"
    PATCH_CONFIGURATION_AFTER_SIZES[$index]="$PATCH_CONFIGURATION_CAPTURE_SIZE"
    PATCH_CONFIGURATION_AFTER_MTIMES[$index]="$PATCH_CONFIGURATION_CAPTURE_MTIME"
    PATCH_CONFIGURATION_AFTER_CTIMES[$index]="$PATCH_CONFIGURATION_CAPTURE_CTIME"
    PATCH_CONFIGURATION_AFTER_SHA256S[$index]="$PATCH_CONFIGURATION_CAPTURE_SHA256"
    printf -v journal_name '%06d.tsv' "$((index + 1))"
    /bin/rm -f -- "$PATCH_CONFIGURATION_DATA_DIRECTORY/journal/$journal_name" || return 2
    _patch_configuration_write_journal "$index"
}

patch_configuration_verify() {
    local index=0

    _patch_configuration_verify_root || {
        _patch_configuration_set_error "configuration patch root identity changed during verification"
        return 2
    }
    while [ "$index" -lt "${#PATCH_CONFIGURATION_CRITERIA[@]}" ]; do
        _patch_configuration_current_matches_after "$index" || {
            _patch_configuration_set_error "configuration patch verification failed: ${PATCH_CONFIGURATION_LOGICAL_PATHS[$index]}"
            return 2
        }
        index=$((index + 1))
    done
}

_patch_configuration_apply_failure() {
    local detail="$1"
    local rollback_status=0

    patch_configuration_rollback transition >/dev/null 2>&1 || rollback_status=$?
    _patch_configuration_cleanup_stages >/dev/null 2>&1 || :
    if [ "$rollback_status" -eq 0 ]; then
        PATCH_CONFIGURATION_ERROR_DETAIL="$detail; automatic rollback completed"
    else
        PATCH_CONFIGURATION_ERROR_DETAIL="$detail; automatic rollback failed"
    fi
    return 2
}

patch_configuration_apply() {
    local index=0

    [ "${EUID:-$(id -u)}" -eq 0 ] || {
        _patch_configuration_set_error "configuration patches require effective UID 0"
        return 2
    }
    [ "$PATCH_CONFIGURATION_PLAN_VALID" -eq 1 ] || {
        _patch_configuration_set_error "configuration patch plan is not valid"
        return 2
    }
    _patch_configuration_verify_root && _patch_configuration_artifacts_are_valid || {
        _patch_configuration_set_error "configuration patch transaction changed before apply"
        return 2
    }
    while [ "$index" -lt "${#PATCH_CONFIGURATION_CRITERIA[@]}" ]; do
        _patch_configuration_current_matches_before "$index" || {
            _patch_configuration_set_error "configuration patch apply preflight failed: ${PATCH_CONFIGURATION_LOGICAL_PATHS[$index]}"
            return 2
        }
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_CONFIGURATION_CRITERIA[@]}" ]; do
        if [ "${PATCH_CONFIGURATION_TARGET_STATES[$index]}" = compliant ]; then
            _patch_configuration_set_after_from_before "$index" || return 2
        else
            _patch_configuration_stage_payload "$index" || {
                _patch_configuration_cleanup_stages >/dev/null 2>&1 || :
                _patch_configuration_set_error "cannot stage configuration patch: ${PATCH_CONFIGURATION_LOGICAL_PATHS[$index]}"
                return 2
            }
        fi
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_CONFIGURATION_CRITERIA[@]}" ]; do
        _patch_configuration_current_matches_before "$index" || {
            _patch_configuration_cleanup_stages >/dev/null 2>&1 || :
            _patch_configuration_set_error "configuration changed during apply preflight: ${PATCH_CONFIGURATION_LOGICAL_PATHS[$index]}"
            return 2
        }
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_CONFIGURATION_CRITERIA[@]}" ]; do
        if [ "${PATCH_CONFIGURATION_TARGET_STATES[$index]}" = compliant ]; then
            index=$((index + 1))
            continue
        fi
        _patch_configuration_move_into_place "${PATCH_CONFIGURATION_STAGE_PATHS[$index]}" \
            "${PATCH_CONFIGURATION_PHYSICAL_PATHS[$index]}" || {
            _patch_configuration_apply_failure \
                "cannot install configuration patch: ${PATCH_CONFIGURATION_LOGICAL_PATHS[$index]}"
            return 2
        }
        PATCH_CONFIGURATION_STAGE_PATHS[$index]=""
        _patch_configuration_refresh_after_move "$index" || {
            _patch_configuration_apply_failure \
                "installed configuration patch failed verification: ${PATCH_CONFIGURATION_LOGICAL_PATHS[$index]}"
            return 2
        }
        index=$((index + 1))
    done
    patch_configuration_verify || {
        _patch_configuration_apply_failure "$PATCH_CONFIGURATION_ERROR_DETAIL"
        return 2
    }
    PATCH_CONFIGURATION_VERIFIED=1
}

_patch_configuration_stage_backup() {
    local index="$1"
    local parent_path="${PATCH_CONFIGURATION_PARENT_PATHS[$index]}"
    local backup_path="$PATCH_CONFIGURATION_DATA_DIRECTORY/${PATCH_CONFIGURATION_BACKUP_NAMES[$index]}"
    local mktemp_command=""
    local cp_command=""
    local chown_command=""
    local chmod_command=""
    local stage_path=""

    _patch_configuration_command_into mktemp mktemp_command || return $?
    _patch_configuration_command_into cp cp_command || return $?
    _patch_configuration_command_into chown chown_command || return $?
    _patch_configuration_command_into chmod chmod_command || return $?
    stage_path="$(umask 077; "$mktemp_command" "$parent_path/.kisa-cce-rollback.XXXXXXXX")" || return 2
    PATCH_CONFIGURATION_STAGE_PATHS[$index]="$stage_path"
    "$cp_command" "$backup_path" "$stage_path" || return 2
    "$chown_command" "${PATCH_CONFIGURATION_BEFORE_UIDS[$index]}:${PATCH_CONFIGURATION_BEFORE_GIDS[$index]}" \
        "$stage_path" || return 2
    "$chmod_command" "${PATCH_CONFIGURATION_BEFORE_MODES[$index]}" "$stage_path" || return 2
    _patch_configuration_capture_file "$stage_path" || return 2
    [ "$PATCH_CONFIGURATION_CAPTURE_UID" = "${PATCH_CONFIGURATION_BEFORE_UIDS[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_GID" = "${PATCH_CONFIGURATION_BEFORE_GIDS[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_MODE" = "${PATCH_CONFIGURATION_BEFORE_MODES[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_SHA256" = "${PATCH_CONFIGURATION_BEFORE_SHA256S[$index]}" ]
}

_patch_configuration_current_state_into() {
    local index="$1"
    local policy="$2"
    local destination_name="$3"

    _patch_configuration_valid_destination "$destination_name" || return 2
    if _patch_configuration_current_matches_after "$index"; then
        printf -v "$destination_name" '%s' after
        return 0
    fi
    if [ "$policy" = transition ] && _patch_configuration_current_matches_before "$index"; then
        printf -v "$destination_name" '%s' before
        return 0
    fi
    return 2
}

_patch_configuration_restored_matches_before() {
    local index="$1"
    local path="${PATCH_CONFIGURATION_PHYSICAL_PATHS[$index]}"

    _patch_configuration_parent_is_unchanged "$index" || return 2
    if [ "${PATCH_CONFIGURATION_BEFORE_STATES[$index]}" = absent ]; then
        [ ! -e "$path" ] && [ ! -L "$path" ]
        return
    fi
    _patch_configuration_capture_file "$path" || return 2
    [ "$PATCH_CONFIGURATION_CAPTURE_UID" = "${PATCH_CONFIGURATION_BEFORE_UIDS[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_GID" = "${PATCH_CONFIGURATION_BEFORE_GIDS[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_MODE" = "${PATCH_CONFIGURATION_BEFORE_MODES[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_SIZE" = "${PATCH_CONFIGURATION_BEFORE_SIZES[$index]}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_SHA256" = "${PATCH_CONFIGURATION_BEFORE_SHA256S[$index]}" ]
}

patch_configuration_rollback() {
    local policy="${1:-strict}"
    local index=0
    local current_state=""
    local rm_command=""

    case "$policy" in strict|transition) ;; *) return 2 ;; esac
    [ "${EUID:-$(id -u)}" -eq 0 ] || {
        _patch_configuration_set_error "configuration rollback requires effective UID 0"
        return 2
    }
    [ "$PATCH_CONFIGURATION_PLAN_VALID" -eq 1 ] || {
        _patch_configuration_set_error "configuration rollback transaction is not loaded"
        return 2
    }
    _patch_configuration_verify_root && _patch_configuration_artifacts_are_valid || {
        _patch_configuration_set_error "configuration rollback transaction changed"
        return 2
    }
    while [ "$index" -lt "${#PATCH_CONFIGURATION_CRITERIA[@]}" ]; do
        _patch_configuration_current_state_into "$index" "$policy" current_state || {
            _patch_configuration_set_error "configuration rollback preflight failed: ${PATCH_CONFIGURATION_LOGICAL_PATHS[$index]}"
            return 2
        }
        PATCH_CONFIGURATION_CURRENT_STATES[$index]="$current_state"
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_CONFIGURATION_CRITERIA[@]}" ]; do
        if [ "${PATCH_CONFIGURATION_TARGET_STATES[$index]}" = ready ] &&
            [ "${PATCH_CONFIGURATION_CURRENT_STATES[$index]}" = after ] &&
            [ "${PATCH_CONFIGURATION_BEFORE_STATES[$index]}" = present ]; then
            _patch_configuration_stage_backup "$index" || {
                _patch_configuration_cleanup_stages >/dev/null 2>&1 || :
                _patch_configuration_set_error "cannot stage configuration rollback: ${PATCH_CONFIGURATION_LOGICAL_PATHS[$index]}"
                return 2
            }
        fi
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_CONFIGURATION_CRITERIA[@]}" ]; do
        _patch_configuration_current_state_into "$index" "$policy" current_state || {
            _patch_configuration_cleanup_stages >/dev/null 2>&1 || :
            _patch_configuration_set_error "configuration changed during rollback preflight: ${PATCH_CONFIGURATION_LOGICAL_PATHS[$index]}"
            return 2
        }
        [ "$current_state" = "${PATCH_CONFIGURATION_CURRENT_STATES[$index]}" ] || {
            _patch_configuration_cleanup_stages >/dev/null 2>&1 || :
            _patch_configuration_set_error "configuration state changed during rollback preflight: ${PATCH_CONFIGURATION_LOGICAL_PATHS[$index]}"
            return 2
        }
        index=$((index + 1))
    done
    _patch_configuration_command_into rm rm_command || return 2
    index=$(( ${#PATCH_CONFIGURATION_CRITERIA[@]} - 1 ))
    while [ "$index" -ge 0 ]; do
        if [ "${PATCH_CONFIGURATION_TARGET_STATES[$index]}" = ready ] &&
            [ "${PATCH_CONFIGURATION_CURRENT_STATES[$index]}" = after ]; then
            if [ "${PATCH_CONFIGURATION_BEFORE_STATES[$index]}" = present ]; then
                _patch_configuration_move_into_place "${PATCH_CONFIGURATION_STAGE_PATHS[$index]}" \
                    "${PATCH_CONFIGURATION_PHYSICAL_PATHS[$index]}" || {
                    _patch_configuration_cleanup_stages >/dev/null 2>&1 || :
                    _patch_configuration_set_error "cannot restore configuration backup: ${PATCH_CONFIGURATION_LOGICAL_PATHS[$index]}"
                    return 2
                }
                PATCH_CONFIGURATION_STAGE_PATHS[$index]=""
            else
                _patch_configuration_current_matches_after "$index" || {
                    _patch_configuration_cleanup_stages >/dev/null 2>&1 || :
                    _patch_configuration_set_error "new configuration file changed before removal: ${PATCH_CONFIGURATION_LOGICAL_PATHS[$index]}"
                    return 2
                }
                "$rm_command" -f "${PATCH_CONFIGURATION_PHYSICAL_PATHS[$index]}" || {
                    _patch_configuration_cleanup_stages >/dev/null 2>&1 || :
                    _patch_configuration_set_error "cannot remove new configuration file: ${PATCH_CONFIGURATION_LOGICAL_PATHS[$index]}"
                    return 2
                }
            fi
            _patch_configuration_restored_matches_before "$index" || {
                _patch_configuration_cleanup_stages >/dev/null 2>&1 || :
                _patch_configuration_set_error "configuration rollback verification failed: ${PATCH_CONFIGURATION_LOGICAL_PATHS[$index]}"
                return 2
            }
        fi
        index=$((index - 1))
    done
    _patch_configuration_cleanup_stages >/dev/null 2>&1 || :
    PATCH_CONFIGURATION_VERIFIED=0
}

_patch_configuration_load_journal() {
    local index="$1"
    local record_number=0
    local journal_path=""
    local header=""
    local schema=""
    local record_index=""
    local logical_path=""
    local device=""
    local inode=""
    local uid=""
    local gid=""
    local mode=""
    local size=""
    local mtime=""
    local ctime=""
    local sha256=""
    local extra=""
    local extra_line=""
    local journal_device=""
    local journal_inode=""
    local journal_sha256=""

    if [ "${PATCH_CONFIGURATION_TARGET_STATES[$index]}" = compliant ]; then
        _patch_configuration_set_after_from_before "$index"
        return
    fi
    printf -v record_number '%06d' "$((index + 1))"
    journal_path="$PATCH_CONFIGURATION_DATA_DIRECTORY/journal/$record_number.tsv"
    [ -e "$journal_path" ] || [ -L "$journal_path" ] || return 1
    _patch_configuration_capture_file "$journal_path" || return 2
    [ "$PATCH_CONFIGURATION_CAPTURE_UID" = "${EUID:-0}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_MODE" = 0600 ] || return 2
    journal_device="$PATCH_CONFIGURATION_CAPTURE_DEVICE"
    journal_inode="$PATCH_CONFIGURATION_CAPTURE_INODE"
    journal_sha256="$PATCH_CONFIGURATION_CAPTURE_SHA256"
    {
        IFS= read -r header || return 2
        IFS=$'\t' read -r schema record_index logical_path device inode uid gid mode size mtime ctime \
            sha256 extra || return 2
        if IFS= read -r extra_line; then
            [ -z "$extra_line" ] || :
            return 2
        fi
    } < "$journal_path"
    [ "$header" = "$PATCH_CONFIGURATION_JOURNAL_HEADER" ] || return 2
    [ -z "$extra" ] && [ "$schema" = 1 ] && [ "$record_index" = "$index" ] &&
        [ "$logical_path" = "${PATCH_CONFIGURATION_LOGICAL_PATHS[$index]}" ] || return 2
    case "$device:$inode:$uid:$gid:$size:$mtime:$ctime" in *[!0-9:]*) return 2 ;; esac
    case "$mode" in ''|*[!0-7]*) return 2 ;; esac
    printf -v mode '%04o' "$((8#$mode))"
    [ "${#sha256}" -eq 64 ] || return 2
    case "$sha256" in *[!0-9a-f]*) return 2 ;; esac
    [ "$device" = "${PATCH_CONFIGURATION_PARENT_DEVICES[$index]}" ] &&
        [ "$uid" = "${PATCH_CONFIGURATION_DESIRED_UIDS[$index]}" ] &&
        [ "$gid" = "${PATCH_CONFIGURATION_DESIRED_GIDS[$index]}" ] &&
        [ "$mode" = "${PATCH_CONFIGURATION_DESIRED_MODES[$index]}" ] &&
        [ "$sha256" = "${PATCH_CONFIGURATION_DESIRED_SHA256S[$index]}" ] || return 2
    _patch_configuration_capture_file "$journal_path" || return 2
    [ "$PATCH_CONFIGURATION_CAPTURE_DEVICE" = "$journal_device" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_INODE" = "$journal_inode" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_SHA256" = "$journal_sha256" ] || return 2
    PATCH_CONFIGURATION_AFTER_DEVICES[$index]="$device"
    PATCH_CONFIGURATION_AFTER_INODES[$index]="$inode"
    PATCH_CONFIGURATION_AFTER_UIDS[$index]="$uid"
    PATCH_CONFIGURATION_AFTER_GIDS[$index]="$gid"
    PATCH_CONFIGURATION_AFTER_MODES[$index]="$mode"
    PATCH_CONFIGURATION_AFTER_SIZES[$index]="$size"
    PATCH_CONFIGURATION_AFTER_MTIMES[$index]="$mtime"
    PATCH_CONFIGURATION_AFTER_CTIMES[$index]="$ctime"
    PATCH_CONFIGURATION_AFTER_SHA256S[$index]="$sha256"
}

patch_configuration_load_transaction() {
    local requested_root="$1"
    local transaction_directory="$2"
    local load_mode="${3:-applied}"
    local manifest_path=""
    local header=""
    local schema=""
    local criterion=""
    local logical_path=""
    local root_device=""
    local root_inode=""
    local parent_device=""
    local parent_inode=""
    local before_state=""
    local before_device=""
    local before_inode=""
    local before_uid=""
    local before_gid=""
    local before_mode=""
    local before_size=""
    local before_mtime=""
    local before_ctime=""
    local before_sha256=""
    local desired_uid=""
    local desired_gid=""
    local desired_mode=""
    local desired_sha256=""
    local manifest_backup_name=""
    local manifest_payload_name=""
    local expected_backup_name=""
    local expected_payload_name=""
    local extra=""
    local parent_path=""
    local physical_path=""
    local expected_sha256=""
    local rule_sha256=""
    local expected_desired_mode=""
    local actual_parent_device=""
    local actual_parent_inode=""
    local seen_paths=$'\n'
    local u12_count=0
    local u62_count=0
    local index=0
    local journal_status=0

    case "$load_mode" in planned|applied) ;; *) return 2 ;; esac
    patch_configuration_reset
    _patch_configuration_initialize_root "$requested_root" || {
        _patch_configuration_set_error "configuration rollback root is unsafe: $requested_root"
        return 2
    }
    _patch_configuration_transaction_directory_is_safe "$transaction_directory" || {
        _patch_configuration_set_error "configuration transaction directory is unsafe: $transaction_directory"
        return 2
    }
    PATCH_CONFIGURATION_TRANSACTION_DIRECTORY="$(CDPATH='' builtin cd -P -- "$transaction_directory" && pwd -P)" || return 2
    PATCH_CONFIGURATION_DATA_DIRECTORY="$PATCH_CONFIGURATION_TRANSACTION_DIRECTORY/configuration"
    for physical_path in "$PATCH_CONFIGURATION_DATA_DIRECTORY" \
        "$PATCH_CONFIGURATION_DATA_DIRECTORY/backups" \
        "$PATCH_CONFIGURATION_DATA_DIRECTORY/payloads" \
        "$PATCH_CONFIGURATION_DATA_DIRECTORY/journal"; do
        _patch_configuration_private_directory_is_safe "$physical_path" || {
            _patch_configuration_set_error "configuration transaction data permissions are unsafe"
            return 2
        }
    done
    manifest_path="$PATCH_CONFIGURATION_DATA_DIRECTORY/manifest.tsv"
    _patch_configuration_capture_file "$manifest_path" || {
        _patch_configuration_set_error "configuration transaction manifest is unsafe"
        return 2
    }
    PATCH_CONFIGURATION_MANIFEST_DEVICE="$PATCH_CONFIGURATION_CAPTURE_DEVICE"
    PATCH_CONFIGURATION_MANIFEST_INODE="$PATCH_CONFIGURATION_CAPTURE_INODE"
    PATCH_CONFIGURATION_MANIFEST_SHA256="$PATCH_CONFIGURATION_CAPTURE_SHA256"
    [ "$PATCH_CONFIGURATION_CAPTURE_UID" = "${EUID:-0}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_MODE" = 0600 ] || return 2
    IFS= read -r header < "$manifest_path" || return 2
    [ "$header" = "$PATCH_CONFIGURATION_MANIFEST_HEADER" ] || {
        _patch_configuration_set_error "configuration transaction manifest header is invalid"
        return 2
    }
    while IFS=$'\t' read -r schema criterion logical_path root_device root_inode \
        parent_device parent_inode before_state before_device before_inode before_uid before_gid \
        before_mode before_size before_mtime before_ctime before_sha256 desired_uid desired_gid \
        desired_mode desired_sha256 manifest_backup_name manifest_payload_name extra; do
        [ -n "$schema" ] || continue
        [ -z "$extra" ] && [ "$schema" = 1 ] || return 2
        [ "$root_device" = "$PATCH_CONFIGURATION_ROOT_DEVICE" ] &&
            [ "$root_inode" = "$PATCH_CONFIGURATION_ROOT_INODE" ] || return 2
        _patch_configuration_rule_sha256_into "$criterion" "$logical_path" rule_sha256 || return 2
        [ "$desired_sha256" = "$rule_sha256" ] || return 2
        case "$seen_paths" in *$'\n'"$logical_path"$'\n'*) return 2 ;; esac
        seen_paths+="$logical_path"$'\n'
        case "$criterion" in
            U-12) u12_count=$((u12_count + 1)) ;;
            U-62) u62_count=$((u62_count + 1)) ;;
            *) return 2 ;;
        esac
        _patch_configuration_resolve_parent_into "$logical_path" parent_path physical_path || return 2
        [ "$index" -lt 4 ] || return 2
        _patch_configuration_directory_identity_into "$parent_path" actual_parent_device \
            actual_parent_inode || return 2
        [ "$parent_device" = "$actual_parent_device" ] &&
            [ "$parent_inode" = "$actual_parent_inode" ] || return 2
        printf -v expected_payload_name 'payloads/%06d' "$((index + 1))"
        [ "$manifest_payload_name" = "$expected_payload_name" ] || return 2
        if [ "$before_state" = present ]; then
            printf -v expected_backup_name 'backups/%06d' "$((index + 1))"
            [ "$manifest_backup_name" = "$expected_backup_name" ] || return 2
        elif [ "$before_state" = absent ]; then
            expected_backup_name=-
            [ "$manifest_backup_name" = - ] || return 2
        else
            return 2
        fi
        case "$parent_device:$parent_inode:$desired_uid:$desired_gid" in *[!0-9:]*) return 2 ;; esac
        case "$desired_mode" in ''|*[!0-7]*) return 2 ;; esac
        [ "$desired_uid" = 0 ] && [ "$desired_gid" = 0 ] || return 2
        if [ "$before_state" = present ]; then
            case "$before_device:$before_inode:$before_uid:$before_gid:$before_size:$before_mtime:$before_ctime" in
                *[!0-9:]*) return 2 ;;
            esac
            case "$before_mode" in ''|*[!0-7]*) return 2 ;; esac
            printf -v before_mode '%04o' "$((8#$before_mode))"
            [ "${#before_sha256}" -eq 64 ] || return 2
        else
            [ "$before_device:$before_inode:$before_uid:$before_gid:$before_mode:$before_size:$before_mtime:$before_ctime:$before_sha256" = '-:-:-:-:-:-:-:-:-' ] || return 2
        fi
        _patch_configuration_desired_mode_into "$before_state" "$before_mode" \
            expected_desired_mode || return 2
        [ "$desired_mode" = "$expected_desired_mode" ] || return 2
        [ "${#desired_sha256}" -eq 64 ] || return 2
        case "$before_sha256:$desired_sha256" in *[!0-9a-f:-]*) return 2 ;; esac
        _patch_configuration_append_record "$criterion" "$logical_path" "$physical_path" "$parent_path" \
            "$parent_device" "$parent_inode" "$before_state" "$before_device" "$before_inode" \
            "$before_uid" "$before_gid" "$before_mode" "$before_size" "$before_mtime" "$before_ctime" \
            "$before_sha256" "$desired_uid" "$desired_gid" "$desired_mode" "$desired_sha256" \
            "$expected_backup_name" "$expected_payload_name"
        _patch_configuration_sha256_into "$PATCH_CONFIGURATION_DATA_DIRECTORY/$expected_payload_name" \
            expected_sha256 || return 2
        [ "$expected_sha256" = "$desired_sha256" ] || return 2
        index=$((index + 1))
    done < <(sed -n '2,$p' "$manifest_path")
    [ "$index" -gt 0 ] || return 2
    [ "$u12_count" -eq 0 ] || [ "$u12_count" -eq 1 ] || return 2
    [ "$u62_count" -eq 0 ] || [ "$u62_count" -eq 3 ] || return 2
    _patch_configuration_manifest_is_unchanged || return 2
    _patch_configuration_artifacts_are_valid || return 2
    index=0
    while [ "$index" -lt "${#PATCH_CONFIGURATION_CRITERIA[@]}" ]; do
        journal_status=0
        _patch_configuration_load_journal "$index" || journal_status=$?
        [ "$journal_status" -eq 0 ] || [ "$load_mode:$journal_status" = planned:1 ] || {
            _patch_configuration_set_error "configuration transaction journal is incomplete"
            return 2
        }
        index=$((index + 1))
    done
    PATCH_CONFIGURATION_PLAN_VALID=1
}

patch_configuration_rollback_transaction() {
    local root="$1"
    local transaction_directory="$2"
    local policy="${3:-strict}"

    patch_configuration_load_transaction "$root" "$transaction_directory" || {
        [ -n "$PATCH_CONFIGURATION_ERROR_DETAIL" ] ||
            PATCH_CONFIGURATION_ERROR_DETAIL="invalid configuration rollback transaction"
        return 2
    }
    patch_configuration_rollback "$policy"
}
