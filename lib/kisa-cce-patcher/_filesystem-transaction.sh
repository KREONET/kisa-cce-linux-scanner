# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash
# shellcheck disable=SC2034

# Applies inventory-bound filesystem remediations without deleting filesystem objects.

if ! declare -F _patch_configuration_capture_file >/dev/null 2>&1; then
    case "${BASH_SOURCE[0]}" in
        */*) __kisa_filesystem_source_directory="${BASH_SOURCE[0]%/*}" ;;
        *) __kisa_filesystem_source_directory=. ;;
    esac
    # shellcheck source=_configuration-transaction.sh
    . "$__kisa_filesystem_source_directory/_configuration-transaction.sh"
    unset __kisa_filesystem_source_directory
fi

PATCH_FILESYSTEM_INVENTORY_HEADER=$'criterion\tobject_type\tpath\taccount\texpected_uid\tapproval_id'
PATCH_FILESYSTEM_PLAN_HEADER=$'criterion\taction\tpath\tbefore_uid\tbefore_gid\tbefore_mode\tbefore_sha256\tdesired_uid\tdesired_gid\tdesired_mode\tdesired_sha256'
PATCH_FILESYSTEM_MANIFEST_HEADER=$'schema\tcriteria\tapprovals\tobject_type\tpath\troot_device\troot_inode\tinventory_sha256\tdevice\tinode\tuid\tgid\tmode\tlinks\tsize\tmtime\tctime\tsha256\tdesired_uid\tdesired_gid\tdesired_mode\tdesired_sha256\tcontent_action\tbackup\tpayload'
PATCH_FILESYSTEM_JOURNAL_HEADER=$'schema\tindex\tpath\tdevice\tinode\tuid\tgid\tmode\tlinks\tsize\tmtime\tctime\tsha256'

PATCH_FILESYSTEM_ERROR_DETAIL=""
PATCH_FILESYSTEM_PREREQUISITE="unresolved"
PATCH_FILESYSTEM_ROOT=""
PATCH_FILESYSTEM_ROOT_DEVICE=""
PATCH_FILESYSTEM_ROOT_INODE=""
PATCH_FILESYSTEM_TRANSACTION_DIRECTORY=""
PATCH_FILESYSTEM_DATA_DIRECTORY=""
PATCH_FILESYSTEM_PLAN_VALID=0
PATCH_FILESYSTEM_VERIFIED=0
PATCH_FILESYSTEM_CHANGE_COUNT=0
PATCH_FILESYSTEM_COMPLIANT_COUNT=0
PATCH_FILESYSTEM_MANIFEST_DEVICE=""
PATCH_FILESYSTEM_MANIFEST_INODE=""
PATCH_FILESYSTEM_MANIFEST_SHA256=""
PATCH_FILESYSTEM_INVENTORY_SHA256=""

declare -A PATCH_FILESYSTEM_CALLBACKS=()
declare -A PATCH_FILESYSTEM_SELECTED_CRITERIA=()
declare -A PATCH_FILESYSTEM_INVENTORY_KEYS=()
declare -A PATCH_FILESYSTEM_EXPECTED_KEYS=()
declare -A PATCH_FILESYSTEM_PATH_INDEX=()
declare -A PATCH_FILESYSTEM_ACCOUNT_UIDS=()
declare -A PATCH_FILESYSTEM_ACCOUNT_HOMES=()
declare -A PATCH_FILESYSTEM_ACCOUNT_SHELLS=()
declare -A PATCH_FILESYSTEM_CRITERION_STATES=()

PATCH_FILESYSTEM_INVENTORY_CRITERIA=()
PATCH_FILESYSTEM_INVENTORY_TYPES=()
PATCH_FILESYSTEM_INVENTORY_PATHS=()
PATCH_FILESYSTEM_INVENTORY_ACCOUNTS=()
PATCH_FILESYSTEM_INVENTORY_EXPECTED_UIDS=()
PATCH_FILESYSTEM_INVENTORY_APPROVALS=()

PATCH_FILESYSTEM_TARGET_CRITERIA=()
PATCH_FILESYSTEM_TARGET_APPROVALS=()
PATCH_FILESYSTEM_TARGET_TYPES=()
PATCH_FILESYSTEM_TARGET_PATHS=()
PATCH_FILESYSTEM_TARGET_PHYSICAL_PATHS=()
PATCH_FILESYSTEM_TARGET_PARENT_PATHS=()
PATCH_FILESYSTEM_TARGET_PARENT_DEVICES=()
PATCH_FILESYSTEM_TARGET_PARENT_INODES=()
PATCH_FILESYSTEM_BEFORE_DEVICES=()
PATCH_FILESYSTEM_BEFORE_INODES=()
PATCH_FILESYSTEM_BEFORE_UIDS=()
PATCH_FILESYSTEM_BEFORE_GIDS=()
PATCH_FILESYSTEM_BEFORE_MODES=()
PATCH_FILESYSTEM_BEFORE_LINKS=()
PATCH_FILESYSTEM_BEFORE_SIZES=()
PATCH_FILESYSTEM_BEFORE_MTIMES=()
PATCH_FILESYSTEM_BEFORE_CTIMES=()
PATCH_FILESYSTEM_BEFORE_SHA256S=()
PATCH_FILESYSTEM_DESIRED_UIDS=()
PATCH_FILESYSTEM_DESIRED_GIDS=()
PATCH_FILESYSTEM_DESIRED_MODES=()
PATCH_FILESYSTEM_DESIRED_SHA256S=()
PATCH_FILESYSTEM_CONTENT_ACTIONS=()
PATCH_FILESYSTEM_BACKUP_NAMES=()
PATCH_FILESYSTEM_PAYLOAD_NAMES=()
PATCH_FILESYSTEM_TARGET_STATES=()
PATCH_FILESYSTEM_AFTER_DEVICES=()
PATCH_FILESYSTEM_AFTER_INODES=()
PATCH_FILESYSTEM_AFTER_UIDS=()
PATCH_FILESYSTEM_AFTER_GIDS=()
PATCH_FILESYSTEM_AFTER_MODES=()
PATCH_FILESYSTEM_AFTER_LINKS=()
PATCH_FILESYSTEM_AFTER_SIZES=()
PATCH_FILESYSTEM_AFTER_MTIMES=()
PATCH_FILESYSTEM_AFTER_CTIMES=()
PATCH_FILESYSTEM_AFTER_SHA256S=()
PATCH_FILESYSTEM_APPLIED=()

PATCH_FILESYSTEM_CAPTURE_TYPE=""
PATCH_FILESYSTEM_CAPTURE_DEVICE=""
PATCH_FILESYSTEM_CAPTURE_INODE=""
PATCH_FILESYSTEM_CAPTURE_UID=""
PATCH_FILESYSTEM_CAPTURE_GID=""
PATCH_FILESYSTEM_CAPTURE_MODE=""
PATCH_FILESYSTEM_CAPTURE_LINKS=""
PATCH_FILESYSTEM_CAPTURE_SIZE=""
PATCH_FILESYSTEM_CAPTURE_MTIME=""
PATCH_FILESYSTEM_CAPTURE_CTIME=""
PATCH_FILESYSTEM_CAPTURE_SHA256=""

_patch_filesystem_set_error() {
    PATCH_FILESYSTEM_ERROR_DETAIL="$1"
    PATCH_FILESYSTEM_PLAN_VALID=0
    return 2
}

_patch_filesystem_set_prerequisite() {
    PATCH_FILESYSTEM_PREREQUISITE="$1"
    PATCH_FILESYSTEM_ERROR_DETAIL="prerequisite not satisfied: $1"
    PATCH_FILESYSTEM_PLAN_VALID=0
    return 3
}

_patch_filesystem_valid_criterion() {
    case "$1" in U-17|U-20|U-21|U-24|U-25|U-27|U-31|U-63) ;; *) return 1 ;; esac
}

patch_filesystem_supported_criteria() {
    printf '%s\n' U-17 U-20 U-21 U-24 U-25 U-27 U-31 U-63
}

_patch_filesystem_safe_token() {
    [ -n "$1" ] && [ "${#1}" -le 512 ] || return 1
    case "$1" in *[!A-Za-z0-9._:@,+%=-]*) return 1 ;; *) return 0 ;; esac
}

_patch_filesystem_host_parent_chain_is_safe() {
    local path="$1"
    local parent="${path%/*}"
    local current=/
    local component=""
    local device=""
    local inode=""
    local uid=""
    local gid=""
    local mode=""
    local links=""
    local size=""
    local mtime=""
    local ctime=""
    local mode_decimal=0
    local effective_uid="${EUID:-}"
    local index=0
    local -a components=()

    case "$path" in /*) ;; *) return 2 ;; esac
    [ -n "$effective_uid" ] || effective_uid=0
    IFS=/ read -r -a components <<< "${parent#/}"
    while [ "$index" -lt "${#components[@]}" ]; do
        component="${components[$index]}"
        case "$component" in ''|.|..) return 2 ;; esac
        current="${current%/}/$component"
        [ -d "$current" ] && [ ! -L "$current" ] || return 2
        _patch_configuration_stat_into "$current" device inode uid gid mode links size mtime ctime || return 2
        { [ "$uid" = 0 ] || [ "$uid" = "$effective_uid" ]; } || return 2
        mode_decimal=$((8#$mode))
        if [ $((mode_decimal & 0022)) -ne 0 ]; then
            [ "$uid" = 0 ] && [ $((mode_decimal & 01000)) -ne 0 ] || return 2
            case "$current" in /tmp|/var/tmp|/private/tmp|/private/var/tmp) ;; *) return 2 ;; esac
        fi
        index=$((index + 1))
    done
}

_patch_filesystem_callback_is_trusted() {
    local path="$1"
    local mode_decimal=0

    [ -x "$path" ] && [ -f "$path" ] && [ ! -L "$path" ] || return 2
    _patch_filesystem_host_parent_chain_is_safe "$path" || return 2
    _patch_configuration_capture_file "$path" || return 2
    mode_decimal=$((8#$PATCH_CONFIGURATION_CAPTURE_MODE))
    { [ "$PATCH_CONFIGURATION_CAPTURE_UID" = 0 ] ||
      [ "$PATCH_CONFIGURATION_CAPTURE_UID" = "${EUID:-0}" ]; } &&
        [ $((mode_decimal & 0022)) -eq 0 ]
}

patch_filesystem_register_callback() {
    local name="$1"
    local path="$2"
    local parent="${path%/*}"
    local canonical_parent=""
    local canonical_path=""

    case "$name" in r_service_state|visudo) ;; *) return 1 ;; esac
    [ -z "${PATCH_FILESYSTEM_CALLBACKS[$name]+present}" ] || return 2
    [ -n "$parent" ] || parent=/
    canonical_parent="$(CDPATH='' builtin cd -P -- "$parent" 2>/dev/null && pwd -P)" || return 2
    canonical_path="${canonical_parent%/}/${path##*/}"
    _patch_filesystem_callback_is_trusted "$canonical_path" || return 2
    PATCH_FILESYSTEM_CALLBACKS["$name"]="$canonical_path"
}

patch_filesystem_reset() {
    patch_configuration_reset
    PATCH_FILESYSTEM_ERROR_DETAIL=""
    PATCH_FILESYSTEM_PREREQUISITE=unresolved
    PATCH_FILESYSTEM_ROOT=""
    PATCH_FILESYSTEM_ROOT_DEVICE=""
    PATCH_FILESYSTEM_ROOT_INODE=""
    PATCH_FILESYSTEM_TRANSACTION_DIRECTORY=""
    PATCH_FILESYSTEM_DATA_DIRECTORY=""
    PATCH_FILESYSTEM_PLAN_VALID=0
    PATCH_FILESYSTEM_VERIFIED=0
    PATCH_FILESYSTEM_CHANGE_COUNT=0
    PATCH_FILESYSTEM_COMPLIANT_COUNT=0
    PATCH_FILESYSTEM_MANIFEST_DEVICE=""
    PATCH_FILESYSTEM_MANIFEST_INODE=""
    PATCH_FILESYSTEM_MANIFEST_SHA256=""
    PATCH_FILESYSTEM_INVENTORY_SHA256=""
    PATCH_FILESYSTEM_SELECTED_CRITERIA=()
    PATCH_FILESYSTEM_INVENTORY_KEYS=()
    PATCH_FILESYSTEM_EXPECTED_KEYS=()
    PATCH_FILESYSTEM_PATH_INDEX=()
    PATCH_FILESYSTEM_ACCOUNT_UIDS=()
    PATCH_FILESYSTEM_ACCOUNT_HOMES=()
    PATCH_FILESYSTEM_ACCOUNT_SHELLS=()
    PATCH_FILESYSTEM_CRITERION_STATES=()
    PATCH_FILESYSTEM_INVENTORY_CRITERIA=()
    PATCH_FILESYSTEM_INVENTORY_TYPES=()
    PATCH_FILESYSTEM_INVENTORY_PATHS=()
    PATCH_FILESYSTEM_INVENTORY_ACCOUNTS=()
    PATCH_FILESYSTEM_INVENTORY_EXPECTED_UIDS=()
    PATCH_FILESYSTEM_INVENTORY_APPROVALS=()
    PATCH_FILESYSTEM_TARGET_CRITERIA=()
    PATCH_FILESYSTEM_TARGET_APPROVALS=()
    PATCH_FILESYSTEM_TARGET_TYPES=()
    PATCH_FILESYSTEM_TARGET_PATHS=()
    PATCH_FILESYSTEM_TARGET_PHYSICAL_PATHS=()
    PATCH_FILESYSTEM_TARGET_PARENT_PATHS=()
    PATCH_FILESYSTEM_TARGET_PARENT_DEVICES=()
    PATCH_FILESYSTEM_TARGET_PARENT_INODES=()
    PATCH_FILESYSTEM_BEFORE_DEVICES=()
    PATCH_FILESYSTEM_BEFORE_INODES=()
    PATCH_FILESYSTEM_BEFORE_UIDS=()
    PATCH_FILESYSTEM_BEFORE_GIDS=()
    PATCH_FILESYSTEM_BEFORE_MODES=()
    PATCH_FILESYSTEM_BEFORE_LINKS=()
    PATCH_FILESYSTEM_BEFORE_SIZES=()
    PATCH_FILESYSTEM_BEFORE_MTIMES=()
    PATCH_FILESYSTEM_BEFORE_CTIMES=()
    PATCH_FILESYSTEM_BEFORE_SHA256S=()
    PATCH_FILESYSTEM_DESIRED_UIDS=()
    PATCH_FILESYSTEM_DESIRED_GIDS=()
    PATCH_FILESYSTEM_DESIRED_MODES=()
    PATCH_FILESYSTEM_DESIRED_SHA256S=()
    PATCH_FILESYSTEM_CONTENT_ACTIONS=()
    PATCH_FILESYSTEM_BACKUP_NAMES=()
    PATCH_FILESYSTEM_PAYLOAD_NAMES=()
    PATCH_FILESYSTEM_TARGET_STATES=()
    PATCH_FILESYSTEM_AFTER_DEVICES=()
    PATCH_FILESYSTEM_AFTER_INODES=()
    PATCH_FILESYSTEM_AFTER_UIDS=()
    PATCH_FILESYSTEM_AFTER_GIDS=()
    PATCH_FILESYSTEM_AFTER_MODES=()
    PATCH_FILESYSTEM_AFTER_LINKS=()
    PATCH_FILESYSTEM_AFTER_SIZES=()
    PATCH_FILESYSTEM_AFTER_MTIMES=()
    PATCH_FILESYSTEM_AFTER_CTIMES=()
    PATCH_FILESYSTEM_AFTER_SHA256S=()
    PATCH_FILESYSTEM_APPLIED=()
}

_patch_filesystem_load_accounts() {
    local passwd_path="$PATCH_FILESYSTEM_ROOT/etc/passwd"
    local name=""
    local password=""
    local uid=""
    local gid=""
    local gecos=""
    local home=""
    local shell=""
    local records=0

    [ -f "$passwd_path" ] && [ ! -L "$passwd_path" ] && [ -r "$passwd_path" ] || return 2
    while IFS=: read -r name password uid gid gecos home shell; do
        [ -n "$name" ] && [ -n "$uid" ] && [ -n "$gid" ] && [ -n "$home" ] || return 2
        case "$name" in *[!A-Za-z0-9_.-]*) return 2 ;; esac
        case "$uid:$gid" in *[!0-9:]*) return 2 ;; esac
        case "$home" in /*) ;; *) return 2 ;; esac
        [ -z "${PATCH_FILESYSTEM_ACCOUNT_UIDS[$name]+present}" ] || return 2
        PATCH_FILESYSTEM_ACCOUNT_UIDS["$name"]="$uid"
        PATCH_FILESYSTEM_ACCOUNT_HOMES["$name"]="$home"
        PATCH_FILESYSTEM_ACCOUNT_SHELLS["$name"]="$shell"
        records=$((records + 1))
    done < "$passwd_path"
    [ "$records" -gt 0 ]
}

_patch_filesystem_inventory_path_is_valid() {
    case "$1" in
        /*) ;;
        *) return 1 ;;
    esac
    case "$1" in /|*//*|*/./*|*/.|*/../*|*/..|*$'\n'*|*$'\r'*|*$'\t'*) return 1 ;; esac
}

_patch_filesystem_inventory_row_is_typed() {
    local criterion="$1"
    local object_type="$2"
    local logical_path="$3"
    local account="$4"
    local expected_uid="$5"
    local approval_id="$6"
    local account_uid=""
    local account_home=""
    local relative=""

    _patch_filesystem_valid_criterion "$criterion" || return 1
    _patch_filesystem_inventory_path_is_valid "$logical_path" || return 2
    case "$criterion:$object_type" in U-31:directory) ;; U-*:file) ;; *) return 2 ;; esac
    case "$criterion" in
        U-17)
            case "$logical_path" in
                /etc/systemd/system/*|/run/systemd/system/*|/run/systemd/generator.early/*|/run/systemd/generator/*|/run/systemd/generator.late/*|/usr/local/lib/systemd/system/*|/usr/lib/systemd/system/*|/lib/systemd/system/*|/etc/init.d/*|/etc/rc.local|/etc/rc[0-6S].d/*|/etc/rc.d/init.d/*|/etc/rc.d/rc[0-6].d/*) ;;
                *) return 2 ;;
            esac
            [ "$account:$expected_uid:$approval_id" = '-:0:-' ] || return 2
            ;;
        U-20)
            case "$logical_path" in
                /etc/inetd.conf|/etc/xinetd.conf|/etc/systemd/system.conf|/etc/xinetd.d/*|/etc/systemd/*) ;;
                *) return 2 ;;
            esac
            [ "$account:$expected_uid:$approval_id" = '-:0:-' ] || return 2
            ;;
        U-21)
            case "$logical_path" in /etc/syslog.conf|/etc/rsyslog.conf|/etc/rsyslog.d/*.conf) ;; *) return 2 ;; esac
            [ "$account:$approval_id" = '-:-' ] || return 2
            case "$expected_uid" in 0) ;; *)
                [ "${PATCH_FILESYSTEM_ACCOUNT_UIDS[bin]:-}" = "$expected_uid" ] ||
                    [ "${PATCH_FILESYSTEM_ACCOUNT_UIDS[sys]:-}" = "$expected_uid" ] || return 2
                ;;
            esac
            ;;
        U-24)
            [ "$account" != - ] && [ -n "${PATCH_FILESYSTEM_ACCOUNT_UIDS[$account]+present}" ] || return 2
            account_uid="${PATCH_FILESYSTEM_ACCOUNT_UIDS[$account]}"
            account_home="${PATCH_FILESYSTEM_ACCOUNT_HOMES[$account]}"
            case "$logical_path" in "$account_home"/*) ;; *) return 2 ;; esac
            relative="${logical_path#"$account_home"/}"
            case "$relative" in
                .profile|.bash_profile|.bash_login|.bashrc|.kshrc|.cshrc|.tcshrc|.login|.exrc|.netrc|.zprofile|.zshenv|.zshrc|.zlogin|.pam_environment|.xprofile|.xsessionrc|.config/fish/config.fish|.config/environment.d/*.conf|.config/fish/conf.d/*.fish) ;;
                *) return 2 ;;
            esac
            { [ "$expected_uid" = 0 ] || [ "$expected_uid" = "$account_uid" ]; } &&
                [ "$approval_id" = - ] || return 2
            ;;
        U-25)
            [ "$account:$expected_uid" = '-:preserve' ] || return 2
            [ "$approval_id" != - ] && _patch_filesystem_safe_token "$approval_id" || return 2
            ;;
        U-27)
            [ "$approval_id" != - ] && _patch_filesystem_safe_token "$approval_id" || return 2
            if [ "$logical_path" = /etc/hosts.equiv ]; then
                [ "$account:$expected_uid" = '-:0' ] || return 2
            else
                [ "$account" != - ] && [ -n "${PATCH_FILESYSTEM_ACCOUNT_UIDS[$account]+present}" ] || return 2
                account_uid="${PATCH_FILESYSTEM_ACCOUNT_UIDS[$account]}"
                [ "$logical_path" = "${PATCH_FILESYSTEM_ACCOUNT_HOMES[$account]%/}/.rhosts" ] || return 2
                { [ "$expected_uid" = 0 ] || [ "$expected_uid" = "$account_uid" ]; } || return 2
            fi
            ;;
        U-31)
            [ "$account" != - ] && [ -n "${PATCH_FILESYSTEM_ACCOUNT_UIDS[$account]+present}" ] || return 2
            [ "$logical_path" = "${PATCH_FILESYSTEM_ACCOUNT_HOMES[$account]}" ] || return 2
            [ "$expected_uid" = "${PATCH_FILESYSTEM_ACCOUNT_UIDS[$account]}" ] &&
                [ "$approval_id" = - ] || return 2
            ;;
        U-63)
            [ "$account:$expected_uid:$approval_id" = '-:0:-' ] || return 2
            ;;
    esac
}

_patch_filesystem_load_inventory() {
    local inventory_path="$1"
    local header=""
    local criterion=""
    local object_type=""
    local logical_path=""
    local account=""
    local expected_uid=""
    local approval_id=""
    local extra=""
    local key=""
    local rows=0

    _patch_configuration_capture_file "$inventory_path" || return 2
    [ $((8#$PATCH_CONFIGURATION_CAPTURE_MODE & 0022)) -eq 0 ] || return 2
    IFS= read -r header < "$inventory_path" || return 2
    [ "$header" = "$PATCH_FILESYSTEM_INVENTORY_HEADER" ] || return 2
    while IFS=$'\t' read -r criterion object_type logical_path account expected_uid approval_id extra; do
        [ -n "$criterion" ] || continue
        [ -z "$extra" ] || return 2
        _patch_filesystem_inventory_row_is_typed "$criterion" "$object_type" "$logical_path" \
            "$account" "$expected_uid" "$approval_id" || return $?
        key="$criterion|$object_type|$logical_path|$account"
        [ -z "${PATCH_FILESYSTEM_INVENTORY_KEYS[$key]+present}" ] || return 2
        PATCH_FILESYSTEM_INVENTORY_KEYS["$key"]="$rows"
        PATCH_FILESYSTEM_SELECTED_CRITERIA["$criterion"]=1
        PATCH_FILESYSTEM_INVENTORY_CRITERIA+=("$criterion")
        PATCH_FILESYSTEM_INVENTORY_TYPES+=("$object_type")
        PATCH_FILESYSTEM_INVENTORY_PATHS+=("$logical_path")
        PATCH_FILESYSTEM_INVENTORY_ACCOUNTS+=("$account")
        PATCH_FILESYSTEM_INVENTORY_EXPECTED_UIDS+=("$expected_uid")
        PATCH_FILESYSTEM_INVENTORY_APPROVALS+=("$approval_id")
        rows=$((rows + 1))
    done < <(sed -n '2,$p' "$inventory_path")
    [ "$rows" -gt 0 ]
}

_patch_filesystem_normalize_logical_into() {
    local input_path="$1"
    local destination_name="$2"
    local component=""
    local result=""
    local index=0
    local -a input_components=()
    local -a output_components=()

    _patch_configuration_valid_destination "$destination_name" || return 2
    case "$input_path" in /*) ;; *) return 2 ;; esac
    IFS=/ read -r -a input_components <<< "${input_path#/}"
    while [ "$index" -lt "${#input_components[@]}" ]; do
        component="${input_components[$index]}"
        case "$component" in
            ''|.) ;;
            ..)
                [ "${#output_components[@]}" -gt 0 ] || return 2
                unset 'output_components[${#output_components[@]}-1]'
                ;;
            *$'\n'*|*$'\r'*|*$'\t'*) return 2 ;;
            *) output_components+=("$component") ;;
        esac
        index=$((index + 1))
    done
    result=/
    for component in "${output_components[@]}"; do result="${result%/}/$component"; done
    printf -v "$destination_name" '%s' "$result"
}

_patch_filesystem_resolve_logical_into() {
    local input_path="$1"
    local expected_type="$2"
    local logical_destination="$3"
    local physical_destination="$4"
    local current_logical=""
    local current_physical=""
    local candidate=""
    local target=""
    local base=""
    local remainder=""
    local component=""
    local index=0
    local depth=0
    local restarted=0
    local -a components=()

    _patch_configuration_valid_destination "$logical_destination" || return 2
    _patch_configuration_valid_destination "$physical_destination" || return 2
    case "$expected_type" in file|directory) ;; *) return 2 ;; esac
    _patch_filesystem_normalize_logical_into "$input_path" current_logical || return 2
    while [ "$depth" -lt 40 ]; do
        depth=$((depth + 1))
        components=()
        IFS=/ read -r -a components <<< "${current_logical#/}"
        current_physical="$PATCH_FILESYSTEM_ROOT"
        base=/
        restarted=0
        index=0
        while [ "$index" -lt "${#components[@]}" ]; do
            component="${components[$index]}"
            candidate="${current_physical%/}/$component"
            if [ -L "$candidate" ]; then
                target="$(/usr/bin/readlink "$candidate" 2>/dev/null)" || return 2
                remainder=""
                if [ "$index" -lt $(( ${#components[@]} - 1 )) ]; then
                    remainder="/${components[*]:$((index + 1))}"
                    remainder="${remainder// //}"
                fi
                case "$target" in
                    /*) current_logical="$target$remainder" ;;
                    *) current_logical="${base%/}/$target$remainder" ;;
                esac
                _patch_filesystem_normalize_logical_into "$current_logical" current_logical || return 2
                restarted=1
                break
            fi
            current_physical="$candidate"
            base="${base%/}/$component"
            index=$((index + 1))
        done
        [ "$restarted" -eq 1 ] && continue
        case "$expected_type" in
            file) [ -f "$current_physical" ] && [ ! -L "$current_physical" ] || return 1 ;;
            directory) [ -d "$current_physical" ] && [ ! -L "$current_physical" ] || return 1 ;;
        esac
        printf -v "$logical_destination" '%s' "$current_logical"
        printf -v "$physical_destination" '%s' "$current_physical"
        return 0
    done
    return 2
}

_patch_filesystem_logical_from_physical_into() {
    local physical_path="$1"
    local destination_name="$2"
    local converted_path=""

    _patch_configuration_valid_destination "$destination_name" || return 2
    if [ "$PATCH_FILESYSTEM_ROOT" = / ]; then
        converted_path="$physical_path"
    else
        case "$physical_path" in
            "$PATCH_FILESYSTEM_ROOT"/*) converted_path="/${physical_path#"$PATCH_FILESYSTEM_ROOT"/}" ;;
            *) return 2 ;;
        esac
    fi
    _patch_filesystem_normalize_logical_into "$converted_path" converted_path || return 2
    printf -v "$destination_name" '%s' "$converted_path"
}

_patch_filesystem_capture_target() {
    local path="$1"
    local expected_type="$2"
    local device_before=""
    local inode_before=""
    local uid_before=""
    local gid_before=""
    local mode_before=""
    local links_before=""
    local size_before=""
    local mtime_before=""
    local ctime_before=""
    local device_after=""
    local inode_after=""
    local uid_after=""
    local gid_after=""
    local mode_after=""
    local links_after=""
    local size_after=""
    local mtime_after=""
    local ctime_after=""
    local sha256=0000000000000000000000000000000000000000000000000000000000000000

    [ ! -L "$path" ] || return 2
    case "$expected_type" in
        file)
            _patch_configuration_capture_file "$path" || return 2
            PATCH_FILESYSTEM_CAPTURE_TYPE="file"
            PATCH_FILESYSTEM_CAPTURE_DEVICE="$PATCH_CONFIGURATION_CAPTURE_DEVICE"
            PATCH_FILESYSTEM_CAPTURE_INODE="$PATCH_CONFIGURATION_CAPTURE_INODE"
            PATCH_FILESYSTEM_CAPTURE_UID="$PATCH_CONFIGURATION_CAPTURE_UID"
            PATCH_FILESYSTEM_CAPTURE_GID="$PATCH_CONFIGURATION_CAPTURE_GID"
            PATCH_FILESYSTEM_CAPTURE_MODE="$PATCH_CONFIGURATION_CAPTURE_MODE"
            PATCH_FILESYSTEM_CAPTURE_LINKS=1
            PATCH_FILESYSTEM_CAPTURE_SIZE="$PATCH_CONFIGURATION_CAPTURE_SIZE"
            PATCH_FILESYSTEM_CAPTURE_MTIME="$PATCH_CONFIGURATION_CAPTURE_MTIME"
            PATCH_FILESYSTEM_CAPTURE_CTIME="$PATCH_CONFIGURATION_CAPTURE_CTIME"
            PATCH_FILESYSTEM_CAPTURE_SHA256="$PATCH_CONFIGURATION_CAPTURE_SHA256"
            return 0
            ;;
        directory) [ -d "$path" ] || return 2 ;;
        *) return 2 ;;
    esac
    _patch_configuration_stat_into "$path" device_before inode_before uid_before gid_before \
        mode_before links_before size_before mtime_before ctime_before || return 2
    _patch_configuration_stat_into "$path" device_after inode_after uid_after gid_after \
        mode_after links_after size_after mtime_after ctime_after || return 2
    [ "$device_before:$inode_before:$uid_before:$gid_before:$mode_before:$links_before:$size_before:$mtime_before:$ctime_before" = \
        "$device_after:$inode_after:$uid_after:$gid_after:$mode_after:$links_after:$size_after:$mtime_after:$ctime_after" ] || return 2
    PATCH_FILESYSTEM_CAPTURE_TYPE="directory"
    PATCH_FILESYSTEM_CAPTURE_DEVICE="$device_after"
    PATCH_FILESYSTEM_CAPTURE_INODE="$inode_after"
    PATCH_FILESYSTEM_CAPTURE_UID="$uid_after"
    PATCH_FILESYSTEM_CAPTURE_GID="$gid_after"
    PATCH_FILESYSTEM_CAPTURE_MODE="$mode_after"
    PATCH_FILESYSTEM_CAPTURE_LINKS="$links_after"
    PATCH_FILESYSTEM_CAPTURE_SIZE="$size_after"
    PATCH_FILESYSTEM_CAPTURE_MTIME="$mtime_after"
    PATCH_FILESYSTEM_CAPTURE_CTIME="$ctime_after"
    PATCH_FILESYSTEM_CAPTURE_SHA256="$sha256"
}

_patch_filesystem_parent_chain_is_safe() {
    local logical_path="$1"
    local parent="${logical_path%/*}"
    local current="$PATCH_FILESYSTEM_ROOT"
    local component=""
    local physical=""
    local device=""
    local inode=""
    local uid=""
    local gid=""
    local mode=""
    local links=""
    local size=""
    local mtime=""
    local ctime=""
    local mode_decimal=0
    local trusted_uid="${EUID:-}"
    local index=0
    local -a components=()

    [ -n "$trusted_uid" ] || trusted_uid=0
    _patch_configuration_stat_into "$current" device inode uid gid mode links size mtime ctime || return 2
    [ "$device" = "$PATCH_FILESYSTEM_ROOT_DEVICE" ] || return 2
    { [ "$uid" = 0 ] || [ "$uid" = "$trusted_uid" ]; } || return 2
    mode_decimal=$((8#$mode))
    [ $((mode_decimal & 0022)) -eq 0 ] || return 2

    IFS=/ read -r -a components <<< "${parent#/}"
    while [ "$index" -lt "${#components[@]}" ]; do
        component="${components[$index]}"
        physical="${current%/}/$component"
        [ -d "$physical" ] && [ ! -L "$physical" ] || return 2
        _patch_configuration_stat_into "$physical" device inode uid gid mode links size mtime ctime || return 2
        { [ "$uid" = 0 ] || [ "$uid" = "$trusted_uid" ]; } || return 2
        mode_decimal=$((8#$mode))
        # Trusted ownership does not make a directory safe when another account can replace its entries.
        [ $((mode_decimal & 0022)) -eq 0 ] || return 2
        current="$physical"
        index=$((index + 1))
    done
}

_patch_filesystem_expected_add() {
    local criterion="$1"
    local object_type="$2"
    local logical_path="$3"
    local account="$4"
    local key="$criterion|$object_type|$logical_path|$account"

    PATCH_FILESYSTEM_EXPECTED_KEYS["$key"]=1
}

_patch_filesystem_add_existing_expected() {
    local criterion="$1"
    local object_type="$2"
    local logical_path="$3"
    local account="$4"
    local resolved_logical=""
    local resolved_physical=""
    local status=0

    _patch_filesystem_resolve_logical_into "$logical_path" "$object_type" \
        resolved_logical resolved_physical || status=$?
    [ "$status" -ne 1 ] || return 1
    [ "$status" -eq 0 ] || return 2
    _patch_filesystem_capture_target "$resolved_physical" "$object_type" || return 2
    [ "$PATCH_FILESYSTEM_CAPTURE_DEVICE" = "$PATCH_FILESYSTEM_ROOT_DEVICE" ] || return 2
    _patch_filesystem_expected_add "$criterion" "$object_type" "$resolved_logical" "$account"
}

_patch_filesystem_add_directory_files() {
    local criterion="$1"
    local logical_directory="$2"
    local recursive="$3"
    local name_pattern="$4"
    local account="$5"
    local link_policy="${6:-reject}"
    local resolved_logical=""
    local resolved_physical=""
    local candidate=""
    local candidate_logical=""
    local list_file=""
    local -a find_arguments=()

    _patch_filesystem_resolve_logical_into "$logical_directory" directory \
        resolved_logical resolved_physical || return 1
    _patch_filesystem_capture_target "$resolved_physical" directory || return 2
    [ "$PATCH_FILESYSTEM_CAPTURE_DEVICE" = "$PATCH_FILESYSTEM_ROOT_DEVICE" ] || return 2
    find_arguments=("$resolved_physical" -xdev)
    [ "$recursive" = recursive ] || find_arguments+=(-maxdepth 1)
    case "$link_policy" in
        ignore) find_arguments+=(-type f) ;;
        reject) find_arguments+=(\( -type f -o -type l \)) ;;
        *) return 2 ;;
    esac
    [ "$name_pattern" = - ] || find_arguments+=(-name "$name_pattern")
    find_arguments+=(-print0)
    list_file="$(umask 077; /usr/bin/mktemp "${TMPDIR:-/tmp}/kisa-cce-filesystem-list.XXXXXXXX")" || return 2
    if ! /usr/bin/find -P "${find_arguments[@]}" > "$list_file" 2>/dev/null; then
        /bin/rm -f "$list_file"
        return 2
    fi
    while IFS= read -r -d '' candidate; do
        if [ -L "$candidate" ]; then
            if [ "$(/usr/bin/readlink "$candidate" 2>/dev/null)" = /dev/null ]; then
                continue
            fi
            /bin/rm -f "$list_file"
            return 2
        fi
        _patch_filesystem_logical_from_physical_into "$candidate" candidate_logical || {
            /bin/rm -f "$list_file"
            return 2
        }
        _patch_filesystem_expected_add "$criterion" file "$candidate_logical" "$account"
    done < "$list_file"
    /bin/rm -f "$list_file"
}

_patch_filesystem_optional_expected() {
    local status=0

    _patch_filesystem_add_existing_expected "$@" || status=$?
    case "$status" in 0|1) return 0 ;; *) return 2 ;; esac
}

_patch_filesystem_optional_directory_files() {
    local status=0

    _patch_filesystem_add_directory_files "$@" || status=$?
    case "$status" in 0|1) return 0 ;; *) return 2 ;; esac
}

_patch_filesystem_enumerate_u17() {
    local directory=""

    for directory in \
        /etc/systemd/system /run/systemd/system /run/systemd/generator.early \
        /run/systemd/generator /run/systemd/generator.late /usr/local/lib/systemd/system \
        /usr/lib/systemd/system /lib/systemd/system /etc/init.d \
        /etc/rc0.d /etc/rc1.d /etc/rc2.d /etc/rc3.d /etc/rc4.d /etc/rc5.d /etc/rc6.d \
        /etc/rcS.d /etc/rc.d/init.d /etc/rc.d/rc0.d /etc/rc.d/rc1.d /etc/rc.d/rc2.d \
        /etc/rc.d/rc3.d /etc/rc.d/rc4.d /etc/rc.d/rc5.d /etc/rc.d/rc6.d; do
        _patch_filesystem_optional_directory_files U-17 "$directory" recursive - - || return 2
    done
    _patch_filesystem_optional_expected U-17 file /etc/rc.local -
}

_patch_filesystem_enumerate_u20() {
    local path=""

    for path in /etc/inetd.conf /etc/xinetd.conf /etc/systemd/system.conf; do
        _patch_filesystem_optional_expected U-20 file "$path" - || return 2
    done
    _patch_filesystem_optional_directory_files U-20 /etc/xinetd.d recursive - - ignore || return 2
    _patch_filesystem_optional_directory_files U-20 /etc/systemd recursive - - ignore
}

_patch_filesystem_rsyslog_has_standard_include() {
    local path="$PATCH_FILESYSTEM_ROOT/etc/rsyslog.conf"

    [ -f "$path" ] && [ ! -L "$path" ] && [ -r "$path" ] || return 1
    /usr/bin/awk '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line ~ /^\$IncludeConfig[[:space:]]+\/etc\/rsyslog\.d\/\*\.conf([[:space:]]|$)/) found=1
            if (line ~ /^include[[:space:]]*\([^)]*file[[:space:]]*=[[:space:]]*"\/etc\/rsyslog\.d\/\*\.conf"/) found=1
        }
        END {exit(found ? 0 : 1)}
    ' "$path"
}

_patch_filesystem_rsyslog_has_complex_include() {
    local path="$PATCH_FILESYSTEM_ROOT/etc/rsyslog.conf"

    [ -f "$path" ] && [ ! -L "$path" ] && [ -r "$path" ] || return 1
    /usr/bin/awk '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line ~ /^\$IncludeConfig[[:space:]]+/ && line !~ /^\$IncludeConfig[[:space:]]+\/etc\/rsyslog\.d\/\*\.conf([[:space:]]|$)/) complex=1
            if (line ~ /^include[[:space:]]*\(/ && line !~ /file[[:space:]]*=[[:space:]]*"\/etc\/rsyslog\.d\/\*\.conf"/) complex=1
        }
        END {exit(complex ? 0 : 1)}
    ' "$path"
}

_patch_filesystem_enumerate_u21() {
    _patch_filesystem_optional_expected U-21 file /etc/syslog.conf - || return 2
    _patch_filesystem_optional_expected U-21 file /etc/rsyslog.conf - || return 2
    _patch_filesystem_rsyslog_has_complex_include && return 2
    if _patch_filesystem_rsyslog_has_standard_include; then
        _patch_filesystem_optional_directory_files U-21 /etc/rsyslog.d shallow '*.conf' - || return 2
    fi
}

_patch_filesystem_home_file_names() {
    printf '%s\n' \
        .profile .bash_profile .bash_login .bashrc .kshrc .cshrc .tcshrc .login .exrc .netrc \
        .zprofile .zshenv .zshrc .zlogin .pam_environment .xprofile .xsessionrc \
        .config/fish/config.fish
}

_patch_filesystem_enumerate_u24() {
    local account=""
    local home=""
    local relative=""

    for account in "${!PATCH_FILESYSTEM_ACCOUNT_UIDS[@]}"; do
        home="${PATCH_FILESYSTEM_ACCOUNT_HOMES[$account]}"
        [ -d "${PATCH_FILESYSTEM_ROOT%/}$home" ] || continue
        while IFS= read -r relative; do
            _patch_filesystem_optional_expected U-24 file "${home%/}/$relative" "$account" || return 2
        done < <(_patch_filesystem_home_file_names)
        _patch_filesystem_optional_directory_files U-24 "${home%/}/.config/environment.d" shallow '*.conf' "$account" || return 2
        _patch_filesystem_optional_directory_files U-24 "${home%/}/.config/fish/conf.d" shallow '*.fish' "$account" || return 2
    done
}

_patch_filesystem_enumerate_u25() {
    local list_file=""
    local physical_path=""
    local logical_path=""

    list_file="$(umask 077; /usr/bin/mktemp "${TMPDIR:-/tmp}/kisa-cce-u25-list.XXXXXXXX")" || return 2
    if ! /usr/bin/find -P "$PATCH_FILESYSTEM_ROOT" -xdev -type f -perm -0002 -print0 \
        > "$list_file" 2>/dev/null; then
        /bin/rm -f "$list_file"
        return 2
    fi
    while IFS= read -r -d '' physical_path; do
        _patch_filesystem_capture_target "$physical_path" file || {
            /bin/rm -f "$list_file"
            return 2
        }
        _patch_filesystem_logical_from_physical_into "$physical_path" logical_path || {
            /bin/rm -f "$list_file"
            return 2
        }
        _patch_filesystem_expected_add U-25 file "$logical_path" -
    done < "$list_file"
    /bin/rm -f "$list_file"
}

_patch_filesystem_r_service_is_active() {
    local callback="${PATCH_FILESYSTEM_CALLBACKS[r_service_state]:-}"
    local output=""

    [ -n "$callback" ] && _patch_filesystem_callback_is_trusted "$callback" || return 2
    output="$("$callback" "$PATCH_FILESYSTEM_ROOT" 2>/dev/null)" || return 2
    [ "$output" = active ]
}

_patch_filesystem_enumerate_u27() {
    local account=""
    local home=""

    _patch_filesystem_r_service_is_active || {
        _patch_filesystem_set_prerequisite r_services_not_proven_active
        return 3
    }
    _patch_filesystem_optional_expected U-27 file /etc/hosts.equiv - || return 2
    for account in "${!PATCH_FILESYSTEM_ACCOUNT_UIDS[@]}"; do
        home="${PATCH_FILESYSTEM_ACCOUNT_HOMES[$account]}"
        _patch_filesystem_optional_expected U-27 file "${home%/}/.rhosts" "$account" || return 2
    done
}

_patch_filesystem_uid_minimum_into() {
    local destination_name="$1"
    local value=1000
    local file=""
    local parsed=""

    _patch_configuration_valid_destination "$destination_name" || return 2
    for file in "$PATCH_FILESYSTEM_ROOT/etc/login.defs" "$PATCH_FILESYSTEM_ROOT"/etc/login.defs.d/*.defs; do
        [ -f "$file" ] && [ ! -L "$file" ] && [ -r "$file" ] || continue
        parsed="$(/usr/bin/awk '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                split(line, fields, /[[:space:]]+/)
                if (fields[1] == "UID_MIN" && fields[2] ~ /^[0-9]+$/) value=fields[2]
            }
            END {if (value != "") print value}
        ' "$file")"
        [ -z "$parsed" ] || value="$parsed"
    done
    printf -v "$destination_name" '%s' "$value"
}

_patch_filesystem_enumerate_u31() {
    local uid_minimum=1000
    local account=""
    local uid=""
    local home=""
    local shell=""

    _patch_filesystem_uid_minimum_into uid_minimum || return 2
    for account in "${!PATCH_FILESYSTEM_ACCOUNT_UIDS[@]}"; do
        uid="${PATCH_FILESYSTEM_ACCOUNT_UIDS[$account]}"
        home="${PATCH_FILESYSTEM_ACCOUNT_HOMES[$account]}"
        shell="${PATCH_FILESYSTEM_ACCOUNT_SHELLS[$account]}"
        if [ "$account" != root ] && {
            [ "$uid" -lt "$uid_minimum" ] || [ "$uid" -ge 65534 ] ||
            case "$shell" in
                /bin/false|/usr/bin/false|/sbin/nologin|/usr/sbin/nologin|/bin/nologin) true ;;
                *) false ;;
            esac
        }; then
            continue
        fi
        _patch_filesystem_optional_expected U-31 directory "$home" "$account" || return 2
    done
}

_patch_filesystem_sudo_directives() {
    local path="$1"

    /usr/bin/awk '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line ~ /^(@include|#include)[[:space:]]+/) type="include"
            else if (line ~ /^(@includedir|#includedir)[[:space:]]+/) type="includedir"
            else next
            sub(/^(@include|#include|@includedir|#includedir)[[:space:]]+/, "", line)
            sub(/[[:space:]]+#.*/, "", line)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            if (line ~ /^".*"$/ || line ~ /^\047.*\047$/) line=substr(line,2,length(line)-2)
            print type "\t" line
        }
    ' "$path"
}

_patch_filesystem_enumerate_sudo_graph() {
    local logical_path="$1"
    local depth="$2"
    local account=-
    local physical_path=""
    local resolved_logical=""
    local directive_type=""
    local include_path=""
    local included_file=""
    local included_logical=""
    local included_directory=""
    local list_file=""
    local basename=""
    local key=""

    [ "$depth" -lt 32 ] || return 2
    _patch_filesystem_resolve_logical_into "$logical_path" file resolved_logical physical_path || return 2
    key="U-63|file|$resolved_logical|$account"
    [ -z "${PATCH_FILESYSTEM_EXPECTED_KEYS[$key]+present}" ] || return 0
    _patch_filesystem_expected_add U-63 file "$resolved_logical" "$account"
    while IFS=$'\t' read -r directive_type include_path; do
        [ -n "$include_path" ] || return 2
        case "$include_path" in *'%'*|*'*'*|*'?'*|*'['*|*\\*) return 2 ;; esac
        if [ "$directive_type" = include ]; then
            case "$include_path" in
                /*) included_logical="$include_path" ;;
                *) included_logical="${resolved_logical%/*}/$include_path" ;;
            esac
            _patch_filesystem_normalize_logical_into "$included_logical" included_logical || return 2
            _patch_filesystem_enumerate_sudo_graph "$included_logical" $((depth + 1)) || return 2
            continue
        fi
        case "$include_path" in
            /*) included_logical="$include_path" ;;
            *) included_logical="${resolved_logical%/*}/$include_path" ;;
        esac
        _patch_filesystem_normalize_logical_into "$included_logical" included_logical || return 2
        _patch_filesystem_resolve_logical_into "$included_logical" directory included_logical included_directory || return 2
        list_file="$(umask 077; /usr/bin/mktemp "${TMPDIR:-/tmp}/kisa-cce-sudo-list.XXXXXXXX")" || return 2
        if ! /usr/bin/find -P "$included_directory" -maxdepth 1 \( -type f -o -type l \) -print0 \
            > "$list_file" 2>/dev/null; then
            /bin/rm -f "$list_file"
            return 2
        fi
        while IFS= read -r -d '' included_file; do
            basename="${included_file##*/}"
            case "$basename" in *.*|*~*) continue ;; esac
            [ ! -L "$included_file" ] || {
                /bin/rm -f "$list_file"
                return 2
            }
            _patch_filesystem_logical_from_physical_into "$included_file" included_logical || return 2
            _patch_filesystem_enumerate_sudo_graph "$included_logical" $((depth + 1)) || {
                /bin/rm -f "$list_file"
                return 2
            }
        done < "$list_file"
        /bin/rm -f "$list_file"
    done < <(_patch_filesystem_sudo_directives "$physical_path")
}

_patch_filesystem_enumerate_u63() {
    local main=/etc/sudoers
    local callback="${PATCH_FILESYSTEM_CALLBACKS[visudo]:-}"
    local main_physical=""
    local main_logical=""

    [ -e "$PATCH_FILESYSTEM_ROOT/etc/sudoers" ] || main=/etc/sudoers-rs
    _patch_filesystem_resolve_logical_into "$main" file main_logical main_physical || return 2
    [ -n "$callback" ] && _patch_filesystem_callback_is_trusted "$callback" || {
        _patch_filesystem_set_prerequisite visudo_callback_missing
        return 3
    }
    "$callback" "$PATCH_FILESYSTEM_ROOT" "$main_physical" || return 2
    _patch_filesystem_enumerate_sudo_graph "$main_logical" 0
}

_patch_filesystem_enumerate_selected() {
    local criterion=""
    local status=0

    PATCH_FILESYSTEM_EXPECTED_KEYS=()
    for criterion in "${!PATCH_FILESYSTEM_SELECTED_CRITERIA[@]}"; do
        status=0
        case "$criterion" in
            U-17) _patch_filesystem_enumerate_u17 || status=$? ;;
            U-20) _patch_filesystem_enumerate_u20 || status=$? ;;
            U-21) _patch_filesystem_enumerate_u21 || status=$? ;;
            U-24) _patch_filesystem_enumerate_u24 || status=$? ;;
            U-25) _patch_filesystem_enumerate_u25 || status=$? ;;
            U-27) _patch_filesystem_enumerate_u27 || status=$? ;;
            U-31) _patch_filesystem_enumerate_u31 || status=$? ;;
            U-63) _patch_filesystem_enumerate_u63 || status=$? ;;
            *) return 2 ;;
        esac
        [ "$status" -eq 0 ] || return "$status"
    done
}

_patch_filesystem_inventory_is_exact() {
    local key=""

    for key in "${!PATCH_FILESYSTEM_EXPECTED_KEYS[@]}"; do
        [ -n "${PATCH_FILESYSTEM_INVENTORY_KEYS[$key]+present}" ] || {
            PATCH_FILESYSTEM_ERROR_DETAIL="typed inventory is missing scanner target: $key"
            return 2
        }
    done
    for key in "${!PATCH_FILESYSTEM_INVENTORY_KEYS[@]}"; do
        [ -n "${PATCH_FILESYSTEM_EXPECTED_KEYS[$key]+present}" ] || {
            PATCH_FILESYSTEM_ERROR_DETAIL="typed inventory contains a target outside scanner scope: $key"
            return 2
        }
    done
}

_patch_filesystem_prepare_transaction() {
    local transaction_directory="$1"
    local inventory_path="$2"
    local copied_inventory=""

    _patch_configuration_transaction_directory_is_safe "$transaction_directory" || return 2
    PATCH_FILESYSTEM_TRANSACTION_DIRECTORY="$(CDPATH='' builtin cd -P -- "$transaction_directory" && pwd -P)" || return 2
    PATCH_FILESYSTEM_DATA_DIRECTORY="$PATCH_FILESYSTEM_TRANSACTION_DIRECTORY/filesystem"
    [ ! -e "$PATCH_FILESYSTEM_DATA_DIRECTORY" ] && [ ! -L "$PATCH_FILESYSTEM_DATA_DIRECTORY" ] || return 2
    (umask 077; /bin/mkdir "$PATCH_FILESYSTEM_DATA_DIRECTORY" \
        "$PATCH_FILESYSTEM_DATA_DIRECTORY/backups" "$PATCH_FILESYSTEM_DATA_DIRECTORY/payloads" \
        "$PATCH_FILESYSTEM_DATA_DIRECTORY/journal") || return 2
    for copied_inventory in "$PATCH_FILESYSTEM_DATA_DIRECTORY" \
        "$PATCH_FILESYSTEM_DATA_DIRECTORY/backups" "$PATCH_FILESYSTEM_DATA_DIRECTORY/payloads" \
        "$PATCH_FILESYSTEM_DATA_DIRECTORY/journal"; do
        _patch_configuration_private_directory_is_safe "$copied_inventory" || return 2
    done
    copied_inventory="$PATCH_FILESYSTEM_DATA_DIRECTORY/inventory.tsv"
    (umask 077; /bin/cp "$inventory_path" "$copied_inventory") || return 2
    /bin/chmod 0600 "$copied_inventory" || return 2
    _patch_configuration_capture_file "$copied_inventory" || return 2
    PATCH_FILESYSTEM_INVENTORY_SHA256="$PATCH_CONFIGURATION_CAPTURE_SHA256"
}

_patch_filesystem_mode_into() {
    local criterion="$1"
    local before_mode="$2"
    local destination_name="$3"
    local before_decimal=0
    local desired_decimal=0
    local calculated_mode=""

    _patch_configuration_valid_destination "$destination_name" || return 2
    case "$before_mode" in ''|*[!0-7]*) return 2 ;; esac
    before_decimal=$((8#$before_mode))
    case "$criterion" in
        U-17|U-24) desired_decimal=$((before_decimal & ~0022 & 07777)) ;;
        U-20) desired_decimal=$((before_decimal & 0600)) ;;
        U-21|U-63) desired_decimal=$((before_decimal & 0640)) ;;
        U-25|U-31) desired_decimal=$((before_decimal & ~0002 & 07777)) ;;
        U-27) desired_decimal=$((before_decimal & 0600)) ;;
        *) return 2 ;;
    esac
    printf -v calculated_mode '%04o' "$desired_decimal"
    printf -v "$destination_name" '%s' "$calculated_mode"
}

_patch_filesystem_strip_plus_rules() {
    local input_path="$1"
    local output_path="$2"

    /usr/bin/awk '
        {
            line=$0
            trimmed=line
            sub(/^[[:space:]]+/, "", trimmed)
            if (trimmed == "" || trimmed ~ /^#/) {
                print line
                next
            }
            count=split(trimmed, fields, /[[:space:]]+/)
            remove=0
            for (index_value=1; index_value<=count; index_value++) {
                if (fields[index_value] ~ /^\+/) remove=1
            }
            if (!remove) print line
        }
    ' "$input_path" > "$output_path"
}

_patch_filesystem_backup_file() {
    local physical_path="$1"
    local relative_name="$2"
    local backup_path="$PATCH_FILESYSTEM_DATA_DIRECTORY/$relative_name"
    local digest=""

    [ ! -e "$backup_path" ] && [ ! -L "$backup_path" ] || return 2
    (umask 077; /bin/cp "$physical_path" "$backup_path") || return 2
    /bin/chmod 0600 "$backup_path" || return 2
    _patch_configuration_capture_file "$backup_path" || return 2
    digest="$PATCH_CONFIGURATION_CAPTURE_SHA256"
    [ "$digest" = "$PATCH_FILESYSTEM_CAPTURE_SHA256" ]
}

_patch_filesystem_create_u27_payload() {
    local index="$1"
    local record_number=""
    local payload_name=""
    local payload_path=""

    printf -v record_number '%06d' "$((index + 1))"
    payload_name="payloads/$record_number"
    payload_path="$PATCH_FILESYSTEM_DATA_DIRECTORY/$payload_name"
    [ ! -e "$payload_path" ] && [ ! -L "$payload_path" ] || return 2
    (umask 077; set -C; : > "$payload_path") 2>/dev/null || return 2
    _patch_filesystem_strip_plus_rules "${PATCH_FILESYSTEM_TARGET_PHYSICAL_PATHS[$index]}" \
        "$payload_path" || return 2
    /bin/chmod 0600 "$payload_path" || return 2
    _patch_configuration_capture_file "$payload_path" || return 2
    PATCH_FILESYSTEM_PAYLOAD_NAMES[$index]="$payload_name"
    PATCH_FILESYSTEM_DESIRED_SHA256S[$index]="$PATCH_CONFIGURATION_CAPTURE_SHA256"
    PATCH_FILESYSTEM_CONTENT_ACTIONS[$index]=strip_plus_rules
}

_patch_filesystem_append_criterion_into() {
    local current="$1"
    local criterion="$2"
    local destination_name="$3"

    _patch_configuration_valid_destination "$destination_name" || return 2
    case ",$current," in *",$criterion,"*) ;; *) current="${current:+$current,}$criterion" ;; esac
    printf -v "$destination_name" '%s' "$current"
}

_patch_filesystem_add_target() {
    local inventory_index="$1"
    local criterion="${PATCH_FILESYSTEM_INVENTORY_CRITERIA[$inventory_index]}"
    local object_type="${PATCH_FILESYSTEM_INVENTORY_TYPES[$inventory_index]}"
    local logical_path="${PATCH_FILESYSTEM_INVENTORY_PATHS[$inventory_index]}"
    local account="${PATCH_FILESYSTEM_INVENTORY_ACCOUNTS[$inventory_index]}"
    local expected_uid="${PATCH_FILESYSTEM_INVENTORY_EXPECTED_UIDS[$inventory_index]}"
    local approval="${PATCH_FILESYSTEM_INVENTORY_APPROVALS[$inventory_index]}"
    local account_uid=-
    local resolved_logical=""
    local physical_path=""
    local parent_path=""
    local parent_device=""
    local parent_inode=""
    local target_index=""
    local desired_uid=""
    local desired_mode=""
    local merged_criteria=""
    local merged_approvals=""
    local merged_mode_decimal=0
    local record_number=""
    local backup_name=-
    local _unused_uid=""
    local _unused_gid=""
    local _unused_mode=""
    local _unused_links=""
    local _unused_size=""
    local _unused_mtime=""
    local _unused_ctime=""

    [ "$account" = - ] || account_uid="${PATCH_FILESYSTEM_ACCOUNT_UIDS[$account]}"
    _patch_filesystem_resolve_logical_into "$logical_path" "$object_type" \
        resolved_logical physical_path || return 2
    [ "$resolved_logical" = "$logical_path" ] || return 2
    _patch_filesystem_parent_chain_is_safe "$logical_path" "$account_uid" || return 2
    _patch_filesystem_capture_target "$physical_path" "$object_type" || return 2
    [ "$PATCH_FILESYSTEM_CAPTURE_DEVICE" = "$PATCH_FILESYSTEM_ROOT_DEVICE" ] || return 2
    parent_path="${physical_path%/*}"
    _patch_configuration_stat_into "$parent_path" parent_device parent_inode _unused_uid \
        _unused_gid _unused_mode _unused_links _unused_size _unused_mtime _unused_ctime || return 2
    if [ "$expected_uid" = preserve ]; then desired_uid="$PATCH_FILESYSTEM_CAPTURE_UID"; else desired_uid="$expected_uid"; fi
    _patch_filesystem_mode_into "$criterion" "$PATCH_FILESYSTEM_CAPTURE_MODE" desired_mode || return 2

    if [ -n "${PATCH_FILESYSTEM_PATH_INDEX[$logical_path]+present}" ]; then
        target_index="${PATCH_FILESYSTEM_PATH_INDEX[$logical_path]}"
        [ "${PATCH_FILESYSTEM_TARGET_TYPES[$target_index]}" = "$object_type" ] || return 2
        [ "${PATCH_FILESYSTEM_BEFORE_DEVICES[$target_index]}:${PATCH_FILESYSTEM_BEFORE_INODES[$target_index]}" = \
            "$PATCH_FILESYSTEM_CAPTURE_DEVICE:$PATCH_FILESYSTEM_CAPTURE_INODE" ] || return 2
        if [ "${PATCH_FILESYSTEM_DESIRED_UIDS[$target_index]}" != "$desired_uid" ]; then
            if [ "$expected_uid" != preserve ] &&
                [ "${PATCH_FILESYSTEM_DESIRED_UIDS[$target_index]}" != "${PATCH_FILESYSTEM_BEFORE_UIDS[$target_index]}" ]; then
                return 2
            fi
            [ "$expected_uid" = preserve ] || PATCH_FILESYSTEM_DESIRED_UIDS[$target_index]="$desired_uid"
        fi
        merged_mode_decimal=$((8#${PATCH_FILESYSTEM_DESIRED_MODES[$target_index]} & 8#$desired_mode))
        printf -v desired_mode '%04o' "$merged_mode_decimal"
        PATCH_FILESYSTEM_DESIRED_MODES[$target_index]="$desired_mode"
        _patch_filesystem_append_criterion_into "${PATCH_FILESYSTEM_TARGET_CRITERIA[$target_index]}" \
            "$criterion" merged_criteria || return 2
        PATCH_FILESYSTEM_TARGET_CRITERIA[$target_index]="$merged_criteria"
        if [ "$approval" != - ]; then
            merged_approvals="${PATCH_FILESYSTEM_TARGET_APPROVALS[$target_index]}"
            [ "$merged_approvals" != - ] || merged_approvals=""
            merged_approvals="${merged_approvals:+$merged_approvals,}$criterion:$approval"
            PATCH_FILESYSTEM_TARGET_APPROVALS[$target_index]="$merged_approvals"
        fi
        if [ "$criterion" = U-27 ] && [ "${PATCH_FILESYSTEM_CONTENT_ACTIONS[$target_index]}" = none ]; then
            _patch_filesystem_create_u27_payload "$target_index" || return 2
        fi
        return 0
    fi

    target_index="${#PATCH_FILESYSTEM_TARGET_PATHS[@]}"
    PATCH_FILESYSTEM_PATH_INDEX["$logical_path"]="$target_index"
    PATCH_FILESYSTEM_TARGET_CRITERIA+=("$criterion")
    if [ "$approval" = - ]; then PATCH_FILESYSTEM_TARGET_APPROVALS+=(-); else PATCH_FILESYSTEM_TARGET_APPROVALS+=("$criterion:$approval"); fi
    PATCH_FILESYSTEM_TARGET_TYPES+=("$object_type")
    PATCH_FILESYSTEM_TARGET_PATHS+=("$logical_path")
    PATCH_FILESYSTEM_TARGET_PHYSICAL_PATHS+=("$physical_path")
    PATCH_FILESYSTEM_TARGET_PARENT_PATHS+=("$parent_path")
    PATCH_FILESYSTEM_TARGET_PARENT_DEVICES+=("$parent_device")
    PATCH_FILESYSTEM_TARGET_PARENT_INODES+=("$parent_inode")
    PATCH_FILESYSTEM_BEFORE_DEVICES+=("$PATCH_FILESYSTEM_CAPTURE_DEVICE")
    PATCH_FILESYSTEM_BEFORE_INODES+=("$PATCH_FILESYSTEM_CAPTURE_INODE")
    PATCH_FILESYSTEM_BEFORE_UIDS+=("$PATCH_FILESYSTEM_CAPTURE_UID")
    PATCH_FILESYSTEM_BEFORE_GIDS+=("$PATCH_FILESYSTEM_CAPTURE_GID")
    PATCH_FILESYSTEM_BEFORE_MODES+=("$PATCH_FILESYSTEM_CAPTURE_MODE")
    PATCH_FILESYSTEM_BEFORE_LINKS+=("$PATCH_FILESYSTEM_CAPTURE_LINKS")
    PATCH_FILESYSTEM_BEFORE_SIZES+=("$PATCH_FILESYSTEM_CAPTURE_SIZE")
    PATCH_FILESYSTEM_BEFORE_MTIMES+=("$PATCH_FILESYSTEM_CAPTURE_MTIME")
    PATCH_FILESYSTEM_BEFORE_CTIMES+=("$PATCH_FILESYSTEM_CAPTURE_CTIME")
    PATCH_FILESYSTEM_BEFORE_SHA256S+=("$PATCH_FILESYSTEM_CAPTURE_SHA256")
    PATCH_FILESYSTEM_DESIRED_UIDS+=("$desired_uid")
    PATCH_FILESYSTEM_DESIRED_GIDS+=("$PATCH_FILESYSTEM_CAPTURE_GID")
    PATCH_FILESYSTEM_DESIRED_MODES+=("$desired_mode")
    PATCH_FILESYSTEM_DESIRED_SHA256S+=("$PATCH_FILESYSTEM_CAPTURE_SHA256")
    PATCH_FILESYSTEM_CONTENT_ACTIONS+=(none)
    printf -v record_number '%06d' "$((target_index + 1))"
    if [ "$object_type" = file ]; then
        backup_name="backups/$record_number"
        _patch_filesystem_backup_file "$physical_path" "$backup_name" || return 2
    fi
    PATCH_FILESYSTEM_BACKUP_NAMES+=("$backup_name")
    PATCH_FILESYSTEM_PAYLOAD_NAMES+=(-)
    PATCH_FILESYSTEM_TARGET_STATES+=(compliant)
    PATCH_FILESYSTEM_AFTER_DEVICES+=("")
    PATCH_FILESYSTEM_AFTER_INODES+=("")
    PATCH_FILESYSTEM_AFTER_UIDS+=("")
    PATCH_FILESYSTEM_AFTER_GIDS+=("")
    PATCH_FILESYSTEM_AFTER_MODES+=("")
    PATCH_FILESYSTEM_AFTER_LINKS+=("")
    PATCH_FILESYSTEM_AFTER_SIZES+=("")
    PATCH_FILESYSTEM_AFTER_MTIMES+=("")
    PATCH_FILESYSTEM_AFTER_CTIMES+=("")
    PATCH_FILESYSTEM_AFTER_SHA256S+=("")
    PATCH_FILESYSTEM_APPLIED+=(0)
    if [ "$criterion" = U-27 ]; then _patch_filesystem_create_u27_payload "$target_index" || return 2; fi
}

_patch_filesystem_finalize_states() {
    local index=0
    local criterion=""
    local state=""
    local -a _criteria=()

    PATCH_FILESYSTEM_CHANGE_COUNT=0
    PATCH_FILESYSTEM_COMPLIANT_COUNT=0
    for criterion in "${!PATCH_FILESYSTEM_SELECTED_CRITERIA[@]}"; do
        PATCH_FILESYSTEM_CRITERION_STATES["$criterion"]=compliant
    done
    while [ "$index" -lt "${#PATCH_FILESYSTEM_TARGET_PATHS[@]}" ]; do
        state=compliant
        if [ "${PATCH_FILESYSTEM_BEFORE_UIDS[$index]}" != "${PATCH_FILESYSTEM_DESIRED_UIDS[$index]}" ] ||
            [ "${PATCH_FILESYSTEM_BEFORE_GIDS[$index]}" != "${PATCH_FILESYSTEM_DESIRED_GIDS[$index]}" ] ||
            [ "${PATCH_FILESYSTEM_BEFORE_MODES[$index]}" != "${PATCH_FILESYSTEM_DESIRED_MODES[$index]}" ] ||
            [ "${PATCH_FILESYSTEM_BEFORE_SHA256S[$index]}" != "${PATCH_FILESYSTEM_DESIRED_SHA256S[$index]}" ]; then
            state=ready
            PATCH_FILESYSTEM_CHANGE_COUNT=$((PATCH_FILESYSTEM_CHANGE_COUNT + 1))
            IFS=, read -r -a _criteria <<< "${PATCH_FILESYSTEM_TARGET_CRITERIA[$index]}"
            for criterion in "${_criteria[@]}"; do PATCH_FILESYSTEM_CRITERION_STATES["$criterion"]=ready; done
        else
            PATCH_FILESYSTEM_COMPLIANT_COUNT=$((PATCH_FILESYSTEM_COMPLIANT_COUNT + 1))
        fi
        PATCH_FILESYSTEM_TARGET_STATES[$index]="$state"
        index=$((index + 1))
    done
}

_patch_filesystem_write_manifest() {
    local path="$PATCH_FILESYSTEM_DATA_DIRECTORY/manifest.tsv"
    local index=0

    [ ! -e "$path" ] && [ ! -L "$path" ] || return 2
    (umask 077; set -C; : > "$path") 2>/dev/null || return 2
    {
        printf '%s\n' "$PATCH_FILESYSTEM_MANIFEST_HEADER"
        while [ "$index" -lt "${#PATCH_FILESYSTEM_TARGET_PATHS[@]}" ]; do
            printf '1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "${PATCH_FILESYSTEM_TARGET_CRITERIA[$index]}" \
                "${PATCH_FILESYSTEM_TARGET_APPROVALS[$index]}" \
                "${PATCH_FILESYSTEM_TARGET_TYPES[$index]}" \
                "${PATCH_FILESYSTEM_TARGET_PATHS[$index]}" \
                "$PATCH_FILESYSTEM_ROOT_DEVICE" "$PATCH_FILESYSTEM_ROOT_INODE" \
                "$PATCH_FILESYSTEM_INVENTORY_SHA256" \
                "${PATCH_FILESYSTEM_BEFORE_DEVICES[$index]}" \
                "${PATCH_FILESYSTEM_BEFORE_INODES[$index]}" \
                "${PATCH_FILESYSTEM_BEFORE_UIDS[$index]}" \
                "${PATCH_FILESYSTEM_BEFORE_GIDS[$index]}" \
                "${PATCH_FILESYSTEM_BEFORE_MODES[$index]}" \
                "${PATCH_FILESYSTEM_BEFORE_LINKS[$index]}" \
                "${PATCH_FILESYSTEM_BEFORE_SIZES[$index]}" \
                "${PATCH_FILESYSTEM_BEFORE_MTIMES[$index]}" \
                "${PATCH_FILESYSTEM_BEFORE_CTIMES[$index]}" \
                "${PATCH_FILESYSTEM_BEFORE_SHA256S[$index]}" \
                "${PATCH_FILESYSTEM_DESIRED_UIDS[$index]}" \
                "${PATCH_FILESYSTEM_DESIRED_GIDS[$index]}" \
                "${PATCH_FILESYSTEM_DESIRED_MODES[$index]}" \
                "${PATCH_FILESYSTEM_DESIRED_SHA256S[$index]}" \
                "${PATCH_FILESYSTEM_CONTENT_ACTIONS[$index]}" \
                "${PATCH_FILESYSTEM_BACKUP_NAMES[$index]}" \
                "${PATCH_FILESYSTEM_PAYLOAD_NAMES[$index]}"
            index=$((index + 1))
        done
    } > "$path" || return 2
    /bin/chmod 0600 "$path" || return 2
    _patch_configuration_capture_file "$path" || return 2
    PATCH_FILESYSTEM_MANIFEST_DEVICE="$PATCH_CONFIGURATION_CAPTURE_DEVICE"
    PATCH_FILESYSTEM_MANIFEST_INODE="$PATCH_CONFIGURATION_CAPTURE_INODE"
    PATCH_FILESYSTEM_MANIFEST_SHA256="$PATCH_CONFIGURATION_CAPTURE_SHA256"
}

_patch_filesystem_manifest_is_current() {
    local path="$PATCH_FILESYSTEM_DATA_DIRECTORY/manifest.tsv"

    _patch_configuration_capture_file "$path" || return 2
    [ "$PATCH_CONFIGURATION_CAPTURE_DEVICE" = "$PATCH_FILESYSTEM_MANIFEST_DEVICE" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_INODE" = "$PATCH_FILESYSTEM_MANIFEST_INODE" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_SHA256" = "$PATCH_FILESYSTEM_MANIFEST_SHA256" ]
}

_patch_filesystem_render_plan() {
    local index=0
    local action=""

    printf '%s\n' "$PATCH_FILESYSTEM_PLAN_HEADER"
    while [ "$index" -lt "${#PATCH_FILESYSTEM_TARGET_PATHS[@]}" ]; do
        if [ "${PATCH_FILESYSTEM_CONTENT_ACTIONS[$index]}" = strip_plus_rules ]; then
            action=strip_plus_rules
        else
            action=set_metadata
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${PATCH_FILESYSTEM_TARGET_CRITERIA[$index]}" "$action" \
            "${PATCH_FILESYSTEM_TARGET_PATHS[$index]}" \
            "${PATCH_FILESYSTEM_BEFORE_UIDS[$index]}" \
            "${PATCH_FILESYSTEM_BEFORE_GIDS[$index]}" \
            "${PATCH_FILESYSTEM_BEFORE_MODES[$index]}" \
            "${PATCH_FILESYSTEM_BEFORE_SHA256S[$index]}" \
            "${PATCH_FILESYSTEM_DESIRED_UIDS[$index]}" \
            "${PATCH_FILESYSTEM_DESIRED_GIDS[$index]}" \
            "${PATCH_FILESYSTEM_DESIRED_MODES[$index]}" \
            "${PATCH_FILESYSTEM_DESIRED_SHA256S[$index]}"
        index=$((index + 1))
    done
}

patch_filesystem_write_plan_tsv() {
    local output_path="$1"
    local output_parent="${output_path%/*}"
    local canonical_parent=""
    local leaf="${output_path##*/}"

    [ "$PATCH_FILESYSTEM_PLAN_VALID" -eq 1 ] || return 2
    case "$output_path" in /*) ;; *) return 2 ;; esac
    _patch_configuration_transaction_directory_is_safe "$output_parent" || return 2
    canonical_parent="$(CDPATH='' builtin cd -P -- "$output_parent" && pwd -P)" || return 2
    output_path="$canonical_parent/$leaf"
    [ ! -e "$output_path" ] && [ ! -L "$output_path" ] || return 2
    (umask 077; set -C; : > "$output_path") 2>/dev/null || return 2
    _patch_filesystem_render_plan > "$output_path" || return 2
    /bin/chmod 0600 "$output_path" || return 2
    _patch_configuration_capture_file "$output_path" >/dev/null
}

patch_filesystem_state_into() {
    local criterion="$1"
    local destination_name="$2"
    local computed_state=""

    _patch_configuration_valid_destination "$destination_name" || return 2
    _patch_filesystem_valid_criterion "$criterion" || return 1
    [ -n "${PATCH_FILESYSTEM_CRITERION_STATES[$criterion]+present}" ] || return 1
    if [ "$PATCH_FILESYSTEM_VERIFIED" -eq 1 ]; then
        computed_state=verified
    else
        computed_state="${PATCH_FILESYSTEM_CRITERION_STATES[$criterion]}"
    fi
    printf -v "$destination_name" '%s' "$computed_state"
}

patch_filesystem_plan() {
    local requested_root="$1"
    local transaction_directory="$2"
    local inventory_path="$3"
    local index=0
    local status=0

    patch_filesystem_reset
    _patch_configuration_initialize_root "$requested_root" || {
        _patch_filesystem_set_error "filesystem transaction root is unsafe"
        return 2
    }
    PATCH_FILESYSTEM_ROOT="$PATCH_CONFIGURATION_ROOT"
    PATCH_FILESYSTEM_ROOT_DEVICE="$PATCH_CONFIGURATION_ROOT_DEVICE"
    PATCH_FILESYSTEM_ROOT_INODE="$PATCH_CONFIGURATION_ROOT_INODE"
    _patch_filesystem_load_accounts || {
        _patch_filesystem_set_error "target account database is unsafe"
        return 2
    }
    _patch_filesystem_load_inventory "$inventory_path" || {
        _patch_filesystem_set_error "typed filesystem inventory is invalid"
        return 2
    }
    _patch_filesystem_enumerate_selected || status=$?
    if [ "$status" -eq 3 ]; then return 3; fi
    [ "$status" -eq 0 ] || {
        _patch_filesystem_set_error "filesystem scope enumeration failed"
        return 2
    }
    _patch_filesystem_inventory_is_exact || {
        [ -n "$PATCH_FILESYSTEM_ERROR_DETAIL" ] ||
            PATCH_FILESYSTEM_ERROR_DETAIL="typed inventory does not exactly match the confined scanner scope"
        PATCH_FILESYSTEM_PLAN_VALID=0
        return 2
    }
    _patch_filesystem_prepare_transaction "$transaction_directory" "$inventory_path" || {
        _patch_filesystem_set_error "filesystem transaction directory is unsafe"
        return 2
    }
    while [ "$index" -lt "${#PATCH_FILESYSTEM_INVENTORY_PATHS[@]}" ]; do
        _patch_filesystem_add_target "$index" || {
            _patch_filesystem_set_error "cannot snapshot filesystem target: ${PATCH_FILESYSTEM_INVENTORY_PATHS[$index]}"
            return 2
        }
        index=$((index + 1))
    done
    _patch_filesystem_finalize_states
    _patch_filesystem_write_manifest || {
        _patch_filesystem_set_error "cannot write filesystem transaction manifest"
        return 2
    }
    PATCH_FILESYSTEM_PLAN_VALID=1
    PATCH_FILESYSTEM_PREREQUISITE=satisfied
}

_patch_filesystem_root_is_current() {
    local device=""
    local inode=""
    local uid=""
    local gid=""
    local mode=""
    local links=""
    local size=""
    local mtime=""
    local ctime=""

    _patch_configuration_verify_root || return 2
    _patch_configuration_stat_into "$PATCH_FILESYSTEM_ROOT" device inode uid gid mode links size mtime ctime || return 2
    [ "$device" = "$PATCH_FILESYSTEM_ROOT_DEVICE" ] && [ "$inode" = "$PATCH_FILESYSTEM_ROOT_INODE" ]
}

_patch_filesystem_parent_is_current() {
    local index="$1"
    local device=""
    local inode=""
    local uid=""
    local gid=""
    local mode=""
    local links=""
    local size=""
    local mtime=""
    local ctime=""

    _patch_configuration_stat_into "${PATCH_FILESYSTEM_TARGET_PARENT_PATHS[$index]}" \
        device inode uid gid mode links size mtime ctime || return 2
    [ "$device" = "${PATCH_FILESYSTEM_TARGET_PARENT_DEVICES[$index]}" ] &&
        [ "$inode" = "${PATCH_FILESYSTEM_TARGET_PARENT_INODES[$index]}" ]
}

_patch_filesystem_artifacts_are_current() {
    local index=0
    local path=""
    local digest=""

    _patch_filesystem_manifest_is_current || return 2
    path="$PATCH_FILESYSTEM_DATA_DIRECTORY/inventory.tsv"
    _patch_configuration_capture_file "$path" || return 2
    [ "$PATCH_CONFIGURATION_CAPTURE_SHA256" = "$PATCH_FILESYSTEM_INVENTORY_SHA256" ] || return 2
    while [ "$index" -lt "${#PATCH_FILESYSTEM_TARGET_PATHS[@]}" ]; do
        if [ "${PATCH_FILESYSTEM_TARGET_TYPES[$index]}" = file ]; then
            path="$PATCH_FILESYSTEM_DATA_DIRECTORY/${PATCH_FILESYSTEM_BACKUP_NAMES[$index]}"
            _patch_configuration_capture_file "$path" || return 2
            digest="$PATCH_CONFIGURATION_CAPTURE_SHA256"
            [ "$digest" = "${PATCH_FILESYSTEM_BEFORE_SHA256S[$index]}" ] || return 2
        fi
        if [ "${PATCH_FILESYSTEM_CONTENT_ACTIONS[$index]}" = strip_plus_rules ]; then
            path="$PATCH_FILESYSTEM_DATA_DIRECTORY/${PATCH_FILESYSTEM_PAYLOAD_NAMES[$index]}"
            _patch_configuration_capture_file "$path" || return 2
            [ "$PATCH_CONFIGURATION_CAPTURE_SHA256" = "${PATCH_FILESYSTEM_DESIRED_SHA256S[$index]}" ] || return 2
        fi
        index=$((index + 1))
    done
}

_patch_filesystem_capture_matches_side() {
    local index="$1"
    local side="$2"
    local safety_mode="${3:-require_safe}"
    local expected_device=""
    local expected_inode=""
    local expected_uid=""
    local expected_gid=""
    local expected_mode=""
    local expected_links=""
    local expected_size=""
    local expected_mtime=""
    local expected_ctime=""
    local expected_sha256=""

    case "$safety_mode" in
        require_safe)
            _patch_filesystem_parent_chain_is_safe "${PATCH_FILESYSTEM_TARGET_PATHS[$index]}" - || return 2
            ;;
        read_only) ;;
        *) return 2 ;;
    esac
    _patch_filesystem_parent_is_current "$index" || return 2
    _patch_filesystem_capture_target "${PATCH_FILESYSTEM_TARGET_PHYSICAL_PATHS[$index]}" \
        "${PATCH_FILESYSTEM_TARGET_TYPES[$index]}" || return 2
    case "$side" in
        before)
            expected_device="${PATCH_FILESYSTEM_BEFORE_DEVICES[$index]}"
            expected_inode="${PATCH_FILESYSTEM_BEFORE_INODES[$index]}"
            expected_uid="${PATCH_FILESYSTEM_BEFORE_UIDS[$index]}"
            expected_gid="${PATCH_FILESYSTEM_BEFORE_GIDS[$index]}"
            expected_mode="${PATCH_FILESYSTEM_BEFORE_MODES[$index]}"
            expected_links="${PATCH_FILESYSTEM_BEFORE_LINKS[$index]}"
            expected_size="${PATCH_FILESYSTEM_BEFORE_SIZES[$index]}"
            expected_mtime="${PATCH_FILESYSTEM_BEFORE_MTIMES[$index]}"
            expected_ctime="${PATCH_FILESYSTEM_BEFORE_CTIMES[$index]}"
            expected_sha256="${PATCH_FILESYSTEM_BEFORE_SHA256S[$index]}"
            ;;
        after)
            [ -n "${PATCH_FILESYSTEM_AFTER_INODES[$index]}" ] || return 2
            expected_device="${PATCH_FILESYSTEM_AFTER_DEVICES[$index]}"
            expected_inode="${PATCH_FILESYSTEM_AFTER_INODES[$index]}"
            expected_uid="${PATCH_FILESYSTEM_AFTER_UIDS[$index]}"
            expected_gid="${PATCH_FILESYSTEM_AFTER_GIDS[$index]}"
            expected_mode="${PATCH_FILESYSTEM_AFTER_MODES[$index]}"
            expected_links="${PATCH_FILESYSTEM_AFTER_LINKS[$index]}"
            expected_size="${PATCH_FILESYSTEM_AFTER_SIZES[$index]}"
            expected_mtime="${PATCH_FILESYSTEM_AFTER_MTIMES[$index]}"
            expected_ctime="${PATCH_FILESYSTEM_AFTER_CTIMES[$index]}"
            expected_sha256="${PATCH_FILESYSTEM_AFTER_SHA256S[$index]}"
            ;;
        *) return 2 ;;
    esac
    [ "$PATCH_FILESYSTEM_CAPTURE_DEVICE:$PATCH_FILESYSTEM_CAPTURE_INODE:$PATCH_FILESYSTEM_CAPTURE_UID:$PATCH_FILESYSTEM_CAPTURE_GID:$PATCH_FILESYSTEM_CAPTURE_MODE:$PATCH_FILESYSTEM_CAPTURE_LINKS:$PATCH_FILESYSTEM_CAPTURE_SIZE:$PATCH_FILESYSTEM_CAPTURE_MTIME:$PATCH_FILESYSTEM_CAPTURE_CTIME:$PATCH_FILESYSTEM_CAPTURE_SHA256" = \
        "$expected_device:$expected_inode:$expected_uid:$expected_gid:$expected_mode:$expected_links:$expected_size:$expected_mtime:$expected_ctime:$expected_sha256" ]
}

_patch_filesystem_transition_matches() {
    local index="$1"

    _patch_filesystem_capture_matches_side "$index" before read_only && return 0
    _patch_filesystem_capture_matches_side "$index" after read_only && return 0
    [ "${PATCH_FILESYSTEM_CONTENT_ACTIONS[$index]}" = none ] || return 2
    _patch_filesystem_parent_is_current "$index" || return 2
    _patch_filesystem_capture_target "${PATCH_FILESYSTEM_TARGET_PHYSICAL_PATHS[$index]}" \
        "${PATCH_FILESYSTEM_TARGET_TYPES[$index]}" || return 2
    [ "$PATCH_FILESYSTEM_CAPTURE_DEVICE" = "${PATCH_FILESYSTEM_BEFORE_DEVICES[$index]}" ] &&
        [ "$PATCH_FILESYSTEM_CAPTURE_INODE" = "${PATCH_FILESYSTEM_BEFORE_INODES[$index]}" ] &&
        [ "$PATCH_FILESYSTEM_CAPTURE_GID" = "${PATCH_FILESYSTEM_BEFORE_GIDS[$index]}" ] &&
        [ "$PATCH_FILESYSTEM_CAPTURE_SHA256" = "${PATCH_FILESYSTEM_BEFORE_SHA256S[$index]}" ] &&
        { [ "$PATCH_FILESYSTEM_CAPTURE_UID" = "${PATCH_FILESYSTEM_BEFORE_UIDS[$index]}" ] ||
          [ "$PATCH_FILESYSTEM_CAPTURE_UID" = "${PATCH_FILESYSTEM_DESIRED_UIDS[$index]}" ]; } &&
        { [ "$PATCH_FILESYSTEM_CAPTURE_MODE" = "${PATCH_FILESYSTEM_BEFORE_MODES[$index]}" ] ||
          [ "$PATCH_FILESYSTEM_CAPTURE_MODE" = "${PATCH_FILESYSTEM_DESIRED_MODES[$index]}" ]; }
}

_patch_filesystem_set_after_from_capture() {
    local index="$1"

    PATCH_FILESYSTEM_AFTER_DEVICES[$index]="$PATCH_FILESYSTEM_CAPTURE_DEVICE"
    PATCH_FILESYSTEM_AFTER_INODES[$index]="$PATCH_FILESYSTEM_CAPTURE_INODE"
    PATCH_FILESYSTEM_AFTER_UIDS[$index]="$PATCH_FILESYSTEM_CAPTURE_UID"
    PATCH_FILESYSTEM_AFTER_GIDS[$index]="$PATCH_FILESYSTEM_CAPTURE_GID"
    PATCH_FILESYSTEM_AFTER_MODES[$index]="$PATCH_FILESYSTEM_CAPTURE_MODE"
    PATCH_FILESYSTEM_AFTER_LINKS[$index]="$PATCH_FILESYSTEM_CAPTURE_LINKS"
    PATCH_FILESYSTEM_AFTER_SIZES[$index]="$PATCH_FILESYSTEM_CAPTURE_SIZE"
    PATCH_FILESYSTEM_AFTER_MTIMES[$index]="$PATCH_FILESYSTEM_CAPTURE_MTIME"
    PATCH_FILESYSTEM_AFTER_CTIMES[$index]="$PATCH_FILESYSTEM_CAPTURE_CTIME"
    PATCH_FILESYSTEM_AFTER_SHA256S[$index]="$PATCH_FILESYSTEM_CAPTURE_SHA256"
}

_patch_filesystem_set_after_from_before() {
    local index="$1"

    PATCH_FILESYSTEM_AFTER_DEVICES[$index]="${PATCH_FILESYSTEM_BEFORE_DEVICES[$index]}"
    PATCH_FILESYSTEM_AFTER_INODES[$index]="${PATCH_FILESYSTEM_BEFORE_INODES[$index]}"
    PATCH_FILESYSTEM_AFTER_UIDS[$index]="${PATCH_FILESYSTEM_BEFORE_UIDS[$index]}"
    PATCH_FILESYSTEM_AFTER_GIDS[$index]="${PATCH_FILESYSTEM_BEFORE_GIDS[$index]}"
    PATCH_FILESYSTEM_AFTER_MODES[$index]="${PATCH_FILESYSTEM_BEFORE_MODES[$index]}"
    PATCH_FILESYSTEM_AFTER_LINKS[$index]="${PATCH_FILESYSTEM_BEFORE_LINKS[$index]}"
    PATCH_FILESYSTEM_AFTER_SIZES[$index]="${PATCH_FILESYSTEM_BEFORE_SIZES[$index]}"
    PATCH_FILESYSTEM_AFTER_MTIMES[$index]="${PATCH_FILESYSTEM_BEFORE_MTIMES[$index]}"
    PATCH_FILESYSTEM_AFTER_CTIMES[$index]="${PATCH_FILESYSTEM_BEFORE_CTIMES[$index]}"
    PATCH_FILESYSTEM_AFTER_SHA256S[$index]="${PATCH_FILESYSTEM_BEFORE_SHA256S[$index]}"
}

_patch_filesystem_write_journal() {
    local index="$1"
    local record_number=""
    local path=""

    printf -v record_number '%06d' "$((index + 1))"
    path="$PATCH_FILESYSTEM_DATA_DIRECTORY/journal/$record_number.tsv"
    [ ! -e "$path" ] && [ ! -L "$path" ] || return 2
    (umask 077; set -C; : > "$path") 2>/dev/null || return 2
    {
        printf '%s\n' "$PATCH_FILESYSTEM_JOURNAL_HEADER"
        printf '1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$index" "${PATCH_FILESYSTEM_TARGET_PATHS[$index]}" \
            "${PATCH_FILESYSTEM_AFTER_DEVICES[$index]}" "${PATCH_FILESYSTEM_AFTER_INODES[$index]}" \
            "${PATCH_FILESYSTEM_AFTER_UIDS[$index]}" "${PATCH_FILESYSTEM_AFTER_GIDS[$index]}" \
            "${PATCH_FILESYSTEM_AFTER_MODES[$index]}" "${PATCH_FILESYSTEM_AFTER_LINKS[$index]}" \
            "${PATCH_FILESYSTEM_AFTER_SIZES[$index]}" "${PATCH_FILESYSTEM_AFTER_MTIMES[$index]}" \
            "${PATCH_FILESYSTEM_AFTER_CTIMES[$index]}" "${PATCH_FILESYSTEM_AFTER_SHA256S[$index]}"
    } > "$path" || return 2
    /bin/chmod 0600 "$path"
}

_patch_filesystem_apply_metadata() {
    local index="$1"
    local path="${PATCH_FILESYSTEM_TARGET_PHYSICAL_PATHS[$index]}"

    _patch_filesystem_parent_chain_is_safe "${PATCH_FILESYSTEM_TARGET_PATHS[$index]}" - || return 2
    PATCH_FILESYSTEM_APPLIED[$index]=1
    if [ "${PATCH_FILESYSTEM_BEFORE_UIDS[$index]}" != "${PATCH_FILESYSTEM_DESIRED_UIDS[$index]}" ]; then
        /usr/bin/chown "${PATCH_FILESYSTEM_DESIRED_UIDS[$index]}:${PATCH_FILESYSTEM_DESIRED_GIDS[$index]}" \
            "$path" || return 2
    fi
    if [ "${PATCH_FILESYSTEM_BEFORE_MODES[$index]}" != "${PATCH_FILESYSTEM_DESIRED_MODES[$index]}" ]; then
        /bin/chmod "${PATCH_FILESYSTEM_DESIRED_MODES[$index]}" "$path" || return 2
    fi
    _patch_filesystem_capture_target "$path" "${PATCH_FILESYSTEM_TARGET_TYPES[$index]}" || return 2
    [ "$PATCH_FILESYSTEM_CAPTURE_DEVICE" = "${PATCH_FILESYSTEM_BEFORE_DEVICES[$index]}" ] &&
        [ "$PATCH_FILESYSTEM_CAPTURE_INODE" = "${PATCH_FILESYSTEM_BEFORE_INODES[$index]}" ] &&
        [ "$PATCH_FILESYSTEM_CAPTURE_UID" = "${PATCH_FILESYSTEM_DESIRED_UIDS[$index]}" ] &&
        [ "$PATCH_FILESYSTEM_CAPTURE_GID" = "${PATCH_FILESYSTEM_DESIRED_GIDS[$index]}" ] &&
        [ "$PATCH_FILESYSTEM_CAPTURE_MODE" = "${PATCH_FILESYSTEM_DESIRED_MODES[$index]}" ] &&
        [ "$PATCH_FILESYSTEM_CAPTURE_SHA256" = "${PATCH_FILESYSTEM_DESIRED_SHA256S[$index]}" ] || return 2
    _patch_filesystem_set_after_from_capture "$index"
    _patch_filesystem_write_journal "$index"
}

_patch_filesystem_apply_content() {
    local index="$1"
    local path="${PATCH_FILESYSTEM_TARGET_PHYSICAL_PATHS[$index]}"
    local parent="${PATCH_FILESYSTEM_TARGET_PARENT_PATHS[$index]}"
    local payload="$PATCH_FILESYSTEM_DATA_DIRECTORY/${PATCH_FILESYSTEM_PAYLOAD_NAMES[$index]}"
    local stage=""

    _patch_filesystem_parent_chain_is_safe "${PATCH_FILESYSTEM_TARGET_PATHS[$index]}" - || return 2
    stage="$(umask 077; /usr/bin/mktemp "$parent/.kisa-cce-filesystem.XXXXXXXX")" || return 2
    /bin/cp "$payload" "$stage" || { /bin/rm -f "$stage"; return 2; }
    /usr/bin/chown "${PATCH_FILESYSTEM_DESIRED_UIDS[$index]}:${PATCH_FILESYSTEM_DESIRED_GIDS[$index]}" \
        "$stage" || { /bin/rm -f "$stage"; return 2; }
    /bin/chmod "${PATCH_FILESYSTEM_DESIRED_MODES[$index]}" "$stage" || { /bin/rm -f "$stage"; return 2; }
    _patch_filesystem_capture_target "$stage" file || { /bin/rm -f "$stage"; return 2; }
    [ "$PATCH_FILESYSTEM_CAPTURE_SHA256" = "${PATCH_FILESYSTEM_DESIRED_SHA256S[$index]}" ] || {
        /bin/rm -f "$stage"
        return 2
    }
    _patch_filesystem_set_after_from_capture "$index"
    _patch_filesystem_write_journal "$index" || { /bin/rm -f "$stage"; return 2; }
    PATCH_FILESYSTEM_APPLIED[$index]=1
    /usr/bin/mv -f "$stage" "$path" || return 2
    _patch_filesystem_capture_matches_side "$index" after
}

_patch_filesystem_visudo_validate() {
    local callback="${PATCH_FILESYSTEM_CALLBACKS[visudo]:-}"
    local main="$PATCH_FILESYSTEM_ROOT/etc/sudoers"

    [ -n "${PATCH_FILESYSTEM_SELECTED_CRITERIA[U-63]+present}" ] || return 0
    [ -e "$main" ] || main="$PATCH_FILESYSTEM_ROOT/etc/sudoers-rs"
    [ -n "$callback" ] && _patch_filesystem_callback_is_trusted "$callback" || return 2
    "$callback" "$PATCH_FILESYSTEM_ROOT" "$main"
}

patch_filesystem_verify() {
    local index=0
    local criterion=""

    _patch_filesystem_root_is_current && _patch_filesystem_artifacts_are_current || return 2
    while [ "$index" -lt "${#PATCH_FILESYSTEM_TARGET_PATHS[@]}" ]; do
        _patch_filesystem_capture_matches_side "$index" after read_only || return 2
        index=$((index + 1))
    done
    _patch_filesystem_visudo_validate || return 2
    for criterion in "${!PATCH_FILESYSTEM_SELECTED_CRITERIA[@]}"; do
        PATCH_FILESYSTEM_CRITERION_STATES["$criterion"]=verified
    done
    PATCH_FILESYSTEM_VERIFIED=1
}

_patch_filesystem_apply_failure() {
    local detail="$1"
    local status=0

    patch_filesystem_rollback transition >/dev/null 2>&1 || status=$?
    if [ "$status" -eq 0 ]; then
        PATCH_FILESYSTEM_ERROR_DETAIL="$detail; automatic rollback completed"
    else
        PATCH_FILESYSTEM_ERROR_DETAIL="$detail; automatic rollback failed"
    fi
    return 2
}

patch_filesystem_apply() {
    local index=0

    [ "${EUID:-$(id -u)}" -eq 0 ] || {
        _patch_filesystem_set_error "filesystem apply requires effective UID 0"
        return 2
    }
    [ "$PATCH_FILESYSTEM_PLAN_VALID" -eq 1 ] || return 2
    _patch_filesystem_root_is_current && _patch_filesystem_artifacts_are_current || return 2
    while [ "$index" -lt "${#PATCH_FILESYSTEM_TARGET_PATHS[@]}" ]; do
        _patch_filesystem_capture_matches_side "$index" before || return 2
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_FILESYSTEM_TARGET_PATHS[@]}" ]; do
        if [ "${PATCH_FILESYSTEM_TARGET_STATES[$index]}" = compliant ]; then
            _patch_filesystem_set_after_from_before "$index"
        elif [ "${PATCH_FILESYSTEM_CONTENT_ACTIONS[$index]}" = strip_plus_rules ]; then
            _patch_filesystem_apply_content "$index" || {
                _patch_filesystem_apply_failure "filesystem content apply failed: ${PATCH_FILESYSTEM_TARGET_PATHS[$index]}"
                return 2
            }
        else
            _patch_filesystem_apply_metadata "$index" || {
                _patch_filesystem_apply_failure "filesystem metadata apply failed: ${PATCH_FILESYSTEM_TARGET_PATHS[$index]}"
                return 2
            }
        fi
        index=$((index + 1))
    done
    patch_filesystem_verify || {
        _patch_filesystem_apply_failure "filesystem postcondition verification failed"
        return 2
    }
}

_patch_filesystem_restore_matches() {
    local index="$1"

    _patch_filesystem_capture_target "${PATCH_FILESYSTEM_TARGET_PHYSICAL_PATHS[$index]}" \
        "${PATCH_FILESYSTEM_TARGET_TYPES[$index]}" || return 2
    [ "$PATCH_FILESYSTEM_CAPTURE_UID" = "${PATCH_FILESYSTEM_BEFORE_UIDS[$index]}" ] &&
        [ "$PATCH_FILESYSTEM_CAPTURE_GID" = "${PATCH_FILESYSTEM_BEFORE_GIDS[$index]}" ] &&
        [ "$PATCH_FILESYSTEM_CAPTURE_MODE" = "${PATCH_FILESYSTEM_BEFORE_MODES[$index]}" ] &&
        [ "$PATCH_FILESYSTEM_CAPTURE_SHA256" = "${PATCH_FILESYSTEM_BEFORE_SHA256S[$index]}" ]
}

_patch_filesystem_restore_content() {
    local index="$1"
    local path="${PATCH_FILESYSTEM_TARGET_PHYSICAL_PATHS[$index]}"
    local parent="${PATCH_FILESYSTEM_TARGET_PARENT_PATHS[$index]}"
    local backup="$PATCH_FILESYSTEM_DATA_DIRECTORY/${PATCH_FILESYSTEM_BACKUP_NAMES[$index]}"
    local stage=""

    _patch_filesystem_parent_chain_is_safe "${PATCH_FILESYSTEM_TARGET_PATHS[$index]}" - || return 2
    stage="$(umask 077; /usr/bin/mktemp "$parent/.kisa-cce-filesystem-rollback.XXXXXXXX")" || return 2
    /bin/cp "$backup" "$stage" || { /bin/rm -f "$stage"; return 2; }
    /usr/bin/chown "${PATCH_FILESYSTEM_BEFORE_UIDS[$index]}:${PATCH_FILESYSTEM_BEFORE_GIDS[$index]}" \
        "$stage" || { /bin/rm -f "$stage"; return 2; }
    /bin/chmod "${PATCH_FILESYSTEM_BEFORE_MODES[$index]}" "$stage" || { /bin/rm -f "$stage"; return 2; }
    _patch_filesystem_capture_target "$stage" file || { /bin/rm -f "$stage"; return 2; }
    [ "$PATCH_FILESYSTEM_CAPTURE_SHA256" = "${PATCH_FILESYSTEM_BEFORE_SHA256S[$index]}" ] || {
        /bin/rm -f "$stage"
        return 2
    }
    /usr/bin/mv -f "$stage" "$path" || return 2
    _patch_filesystem_restore_matches "$index"
}

_patch_filesystem_restore_metadata() {
    local index="$1"
    local path="${PATCH_FILESYSTEM_TARGET_PHYSICAL_PATHS[$index]}"

    _patch_filesystem_parent_chain_is_safe "${PATCH_FILESYSTEM_TARGET_PATHS[$index]}" - || return 2
    /usr/bin/chown "${PATCH_FILESYSTEM_BEFORE_UIDS[$index]}:${PATCH_FILESYSTEM_BEFORE_GIDS[$index]}" \
        "$path" || return 2
    /bin/chmod "${PATCH_FILESYSTEM_BEFORE_MODES[$index]}" "$path" || return 2
    _patch_filesystem_restore_matches "$index"
}

patch_filesystem_rollback() {
    local policy="${1:-strict}"
    local index=0
    local current_state=""
    local -a states=()

    case "$policy" in strict|transition) ;; *) return 2 ;; esac
    [ "${EUID:-$(id -u)}" -eq 0 ] || return 2
    [ "$PATCH_FILESYSTEM_PLAN_VALID" -eq 1 ] || return 2
    _patch_filesystem_root_is_current && _patch_filesystem_artifacts_are_current || return 2
    while [ "$index" -lt "${#PATCH_FILESYSTEM_TARGET_PATHS[@]}" ]; do
        if [ "${PATCH_FILESYSTEM_TARGET_STATES[$index]}" = compliant ]; then
            _patch_filesystem_capture_matches_side "$index" before read_only || return 2
            states+=(before)
        elif _patch_filesystem_capture_matches_side "$index" after read_only; then
            states+=(after)
        elif [ "$policy" = transition ] && _patch_filesystem_transition_matches "$index"; then
            states+=(transition)
        else
            _patch_filesystem_set_error "filesystem rollback preflight failed: ${PATCH_FILESYSTEM_TARGET_PATHS[$index]}"
            return 2
        fi
        index=$((index + 1))
    done
    index=$(( ${#PATCH_FILESYSTEM_TARGET_PATHS[@]} - 1 ))
    while [ "$index" -ge 0 ]; do
        current_state="${states[$index]}"
        if [ "$current_state" != before ]; then
            if [ "${PATCH_FILESYSTEM_CONTENT_ACTIONS[$index]}" = strip_plus_rules ]; then
                _patch_filesystem_restore_content "$index" || return 2
            else
                _patch_filesystem_restore_metadata "$index" || return 2
            fi
        fi
        index=$((index - 1))
    done
    _patch_filesystem_visudo_validate || return 2
    for current_state in "${!PATCH_FILESYSTEM_SELECTED_CRITERIA[@]}"; do
        PATCH_FILESYSTEM_CRITERION_STATES["$current_state"]=rolled_back
    done
    PATCH_FILESYSTEM_VERIFIED=0
}

_patch_filesystem_load_journal() {
    local index="$1"
    local record_number=""
    local path=""
    local header=""
    local schema=""
    local record_index=""
    local logical_path=""
    local device=""
    local inode=""
    local uid=""
    local gid=""
    local mode=""
    local links=""
    local size=""
    local mtime=""
    local ctime=""
    local sha256=""
    local extra=""

    if [ "${PATCH_FILESYSTEM_TARGET_STATES[$index]}" = compliant ]; then
        _patch_filesystem_set_after_from_before "$index"
        return
    fi
    printf -v record_number '%06d' "$((index + 1))"
    path="$PATCH_FILESYSTEM_DATA_DIRECTORY/journal/$record_number.tsv"
    _patch_configuration_capture_file "$path" || return 2
    IFS= read -r header < "$path" || return 2
    [ "$header" = "$PATCH_FILESYSTEM_JOURNAL_HEADER" ] || return 2
    IFS=$'\t' read -r schema record_index logical_path device inode uid gid mode links size \
        mtime ctime sha256 extra < <(sed -n '2p' "$path")
    [ -z "$extra" ] && [ "$schema" = 1 ] && [ "$record_index" = "$index" ] &&
        [ "$logical_path" = "${PATCH_FILESYSTEM_TARGET_PATHS[$index]}" ] || return 2
    case "$device:$inode:$uid:$gid:$links:$size:$mtime:$ctime" in *[!0-9:]*) return 2 ;; esac
    case "$mode" in ''|*[!0-7]*) return 2 ;; esac
    [ "${#sha256}" -eq 64 ] || return 2
    [ "$uid:$gid:$mode:$sha256" = \
        "${PATCH_FILESYSTEM_DESIRED_UIDS[$index]}:${PATCH_FILESYSTEM_DESIRED_GIDS[$index]}:${PATCH_FILESYSTEM_DESIRED_MODES[$index]}:${PATCH_FILESYSTEM_DESIRED_SHA256S[$index]}" ] || return 2
    PATCH_FILESYSTEM_AFTER_DEVICES[$index]="$device"
    PATCH_FILESYSTEM_AFTER_INODES[$index]="$inode"
    PATCH_FILESYSTEM_AFTER_UIDS[$index]="$uid"
    PATCH_FILESYSTEM_AFTER_GIDS[$index]="$gid"
    PATCH_FILESYSTEM_AFTER_MODES[$index]="$mode"
    PATCH_FILESYSTEM_AFTER_LINKS[$index]="$links"
    PATCH_FILESYSTEM_AFTER_SIZES[$index]="$size"
    PATCH_FILESYSTEM_AFTER_MTIMES[$index]="$mtime"
    PATCH_FILESYSTEM_AFTER_CTIMES[$index]="$ctime"
    PATCH_FILESYSTEM_AFTER_SHA256S[$index]="$sha256"
    PATCH_FILESYSTEM_APPLIED[$index]=1
}

patch_filesystem_load_transaction() {
    local requested_root="$1"
    local transaction_directory="$2"
    local load_mode="${3:-applied}"
    local manifest=""
    local header=""
    local schema=""
    local criteria=""
    local approvals=""
    local object_type=""
    local logical_path=""
    local root_device=""
    local root_inode=""
    local inventory_sha256=""
    local device=""
    local inode=""
    local uid=""
    local gid=""
    local mode=""
    local links=""
    local size=""
    local mtime=""
    local ctime=""
    local sha256=""
    local desired_uid=""
    local desired_gid=""
    local desired_mode=""
    local desired_sha256=""
    local content_action=""
    local backup=""
    local payload=""
    local extra=""
    local physical_path=""
    local resolved_logical=""
    local parent=""
    local parent_device=""
    local parent_inode=""
    local _unused_uid=""
    local _unused_gid=""
    local _unused_mode=""
    local _unused_links=""
    local _unused_size=""
    local _unused_mtime=""
    local _unused_ctime=""
    local index=0
    local criterion=""
    local record_number=""
    local digest=""
    local -a criterion_list=()

    case "$load_mode" in planned|applied) ;; *) return 2 ;; esac
    patch_filesystem_reset
    _patch_configuration_initialize_root "$requested_root" || return 2
    PATCH_FILESYSTEM_ROOT="$PATCH_CONFIGURATION_ROOT"
    PATCH_FILESYSTEM_ROOT_DEVICE="$PATCH_CONFIGURATION_ROOT_DEVICE"
    PATCH_FILESYSTEM_ROOT_INODE="$PATCH_CONFIGURATION_ROOT_INODE"
    _patch_filesystem_load_accounts || return 2
    _patch_configuration_transaction_directory_is_safe "$transaction_directory" || return 2
    PATCH_FILESYSTEM_TRANSACTION_DIRECTORY="$(CDPATH='' builtin cd -P -- "$transaction_directory" && pwd -P)" || return 2
    PATCH_FILESYSTEM_DATA_DIRECTORY="$PATCH_FILESYSTEM_TRANSACTION_DIRECTORY/filesystem"
    for physical_path in "$PATCH_FILESYSTEM_DATA_DIRECTORY" \
        "$PATCH_FILESYSTEM_DATA_DIRECTORY/backups" "$PATCH_FILESYSTEM_DATA_DIRECTORY/payloads" \
        "$PATCH_FILESYSTEM_DATA_DIRECTORY/journal"; do
        _patch_configuration_private_directory_is_safe "$physical_path" || return 2
    done
    physical_path="$PATCH_FILESYSTEM_DATA_DIRECTORY/inventory.tsv"
    _patch_configuration_capture_file "$physical_path" || return 2
    PATCH_FILESYSTEM_INVENTORY_SHA256="$PATCH_CONFIGURATION_CAPTURE_SHA256"
    _patch_filesystem_load_inventory "$physical_path" || return 2
    manifest="$PATCH_FILESYSTEM_DATA_DIRECTORY/manifest.tsv"
    _patch_configuration_capture_file "$manifest" || return 2
    PATCH_FILESYSTEM_MANIFEST_DEVICE="$PATCH_CONFIGURATION_CAPTURE_DEVICE"
    PATCH_FILESYSTEM_MANIFEST_INODE="$PATCH_CONFIGURATION_CAPTURE_INODE"
    PATCH_FILESYSTEM_MANIFEST_SHA256="$PATCH_CONFIGURATION_CAPTURE_SHA256"
    IFS= read -r header < "$manifest" || return 2
    [ "$header" = "$PATCH_FILESYSTEM_MANIFEST_HEADER" ] || return 2
    while IFS=$'\t' read -r schema criteria approvals object_type logical_path root_device root_inode \
        inventory_sha256 device inode uid gid mode links size mtime ctime sha256 desired_uid \
        desired_gid desired_mode desired_sha256 content_action backup payload extra; do
        [ -n "$schema" ] || continue
        [ -z "$extra" ] && [ "$schema" = 1 ] || return 2
        [ "$root_device:$root_inode:$inventory_sha256" = \
            "$PATCH_FILESYSTEM_ROOT_DEVICE:$PATCH_FILESYSTEM_ROOT_INODE:$PATCH_FILESYSTEM_INVENTORY_SHA256" ] || return 2
        case "$object_type" in file|directory) ;; *) return 2 ;; esac
        _patch_filesystem_resolve_logical_into "$logical_path" "$object_type" \
            resolved_logical physical_path || return 2
        [ "$resolved_logical" = "$logical_path" ] || return 2
        case "$device:$inode:$uid:$gid:$links:$size:$mtime:$ctime:$desired_uid:$desired_gid" in
            *[!0-9:]*) return 2 ;;
        esac
        case "$mode:$desired_mode" in *[!0-7:]*) return 2 ;; esac
        [ "${#sha256}" -eq 64 ] && [ "${#desired_sha256}" -eq 64 ] || return 2
        case "$content_action" in none|strip_plus_rules) ;; *) return 2 ;; esac
        printf -v record_number '%06d' "$((index + 1))"
        if [ "$object_type" = file ]; then
            [ "$backup" = "backups/$record_number" ] || return 2
            _patch_configuration_sha256_into "$PATCH_FILESYSTEM_DATA_DIRECTORY/$backup" digest || return 2
            [ "$digest" = "$sha256" ] || return 2
        else
            [ "$backup" = - ] || return 2
        fi
        if [ "$content_action" = strip_plus_rules ]; then
            [ "$payload" = "payloads/$record_number" ] || return 2
            _patch_configuration_sha256_into "$PATCH_FILESYSTEM_DATA_DIRECTORY/$payload" digest || return 2
            [ "$digest" = "$desired_sha256" ] || return 2
        else
            [ "$payload" = - ] && [ "$desired_sha256" = "$sha256" ] || return 2
        fi
        criterion_list=()
        IFS=, read -r -a criterion_list <<< "$criteria"
        [ "${#criterion_list[@]}" -gt 0 ] || return 2
        for criterion in "${criterion_list[@]}"; do
            _patch_filesystem_valid_criterion "$criterion" || return 2
            [ -n "${PATCH_FILESYSTEM_SELECTED_CRITERIA[$criterion]+present}" ] || return 2
            [ -n "${PATCH_FILESYSTEM_CRITERION_STATES[$criterion]+present}" ] ||
                PATCH_FILESYSTEM_CRITERION_STATES["$criterion"]=compliant
        done
        parent="${physical_path%/*}"
        _patch_configuration_stat_into "$parent" parent_device parent_inode _unused_uid _unused_gid \
            _unused_mode _unused_links _unused_size _unused_mtime _unused_ctime || return 2
        PATCH_FILESYSTEM_TARGET_CRITERIA+=("$criteria")
        PATCH_FILESYSTEM_TARGET_APPROVALS+=("$approvals")
        PATCH_FILESYSTEM_TARGET_TYPES+=("$object_type")
        PATCH_FILESYSTEM_TARGET_PATHS+=("$logical_path")
        PATCH_FILESYSTEM_TARGET_PHYSICAL_PATHS+=("$physical_path")
        PATCH_FILESYSTEM_TARGET_PARENT_PATHS+=("$parent")
        PATCH_FILESYSTEM_TARGET_PARENT_DEVICES+=("$parent_device")
        PATCH_FILESYSTEM_TARGET_PARENT_INODES+=("$parent_inode")
        PATCH_FILESYSTEM_BEFORE_DEVICES+=("$device")
        PATCH_FILESYSTEM_BEFORE_INODES+=("$inode")
        PATCH_FILESYSTEM_BEFORE_UIDS+=("$uid")
        PATCH_FILESYSTEM_BEFORE_GIDS+=("$gid")
        PATCH_FILESYSTEM_BEFORE_MODES+=("$mode")
        PATCH_FILESYSTEM_BEFORE_LINKS+=("$links")
        PATCH_FILESYSTEM_BEFORE_SIZES+=("$size")
        PATCH_FILESYSTEM_BEFORE_MTIMES+=("$mtime")
        PATCH_FILESYSTEM_BEFORE_CTIMES+=("$ctime")
        PATCH_FILESYSTEM_BEFORE_SHA256S+=("$sha256")
        PATCH_FILESYSTEM_DESIRED_UIDS+=("$desired_uid")
        PATCH_FILESYSTEM_DESIRED_GIDS+=("$desired_gid")
        PATCH_FILESYSTEM_DESIRED_MODES+=("$desired_mode")
        PATCH_FILESYSTEM_DESIRED_SHA256S+=("$desired_sha256")
        PATCH_FILESYSTEM_CONTENT_ACTIONS+=("$content_action")
        PATCH_FILESYSTEM_BACKUP_NAMES+=("$backup")
        PATCH_FILESYSTEM_PAYLOAD_NAMES+=("$payload")
        if [ "$uid:$gid:$mode:$sha256" = "$desired_uid:$desired_gid:$desired_mode:$desired_sha256" ]; then
            PATCH_FILESYSTEM_TARGET_STATES+=(compliant)
            PATCH_FILESYSTEM_COMPLIANT_COUNT=$((PATCH_FILESYSTEM_COMPLIANT_COUNT + 1))
        else
            PATCH_FILESYSTEM_TARGET_STATES+=(ready)
            PATCH_FILESYSTEM_CHANGE_COUNT=$((PATCH_FILESYSTEM_CHANGE_COUNT + 1))
            for criterion in "${criterion_list[@]}"; do PATCH_FILESYSTEM_CRITERION_STATES["$criterion"]=ready; done
        fi
        PATCH_FILESYSTEM_AFTER_DEVICES+=("")
        PATCH_FILESYSTEM_AFTER_INODES+=("")
        PATCH_FILESYSTEM_AFTER_UIDS+=("")
        PATCH_FILESYSTEM_AFTER_GIDS+=("")
        PATCH_FILESYSTEM_AFTER_MODES+=("")
        PATCH_FILESYSTEM_AFTER_LINKS+=("")
        PATCH_FILESYSTEM_AFTER_SIZES+=("")
        PATCH_FILESYSTEM_AFTER_MTIMES+=("")
        PATCH_FILESYSTEM_AFTER_CTIMES+=("")
        PATCH_FILESYSTEM_AFTER_SHA256S+=("")
        PATCH_FILESYSTEM_APPLIED+=(0)
        index=$((index + 1))
    done < <(sed -n '2,$p' "$manifest")
    [ "$index" -gt 0 ] || return 2
    _patch_filesystem_manifest_is_current || return 2
    index=0
    while [ "$index" -lt "${#PATCH_FILESYSTEM_TARGET_PATHS[@]}" ]; do
        if [ "$load_mode" = planned ] && [ "${PATCH_FILESYSTEM_TARGET_STATES[$index]}" = ready ]; then
            printf -v record_number '%06d' "$((index + 1))"
            [ ! -e "$PATCH_FILESYSTEM_DATA_DIRECTORY/journal/$record_number.tsv" ] || return 2
            index=$((index + 1))
            continue
        fi
        _patch_filesystem_load_journal "$index" || return 2
        index=$((index + 1))
    done
    _patch_filesystem_artifacts_are_current || return 2
    PATCH_FILESYSTEM_PLAN_VALID=1
    PATCH_FILESYSTEM_PREREQUISITE=satisfied
}

patch_filesystem_rollback_transaction() {
    local root="$1"
    local transaction_directory="$2"
    local policy="${3:-strict}"

    patch_filesystem_load_transaction "$root" "$transaction_directory" || {
        [ -n "$PATCH_FILESYSTEM_ERROR_DETAIL" ] || PATCH_FILESYSTEM_ERROR_DETAIL="invalid filesystem transaction"
        return 2
    }
    patch_filesystem_rollback "$policy"
}
