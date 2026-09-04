# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash
# shellcheck disable=SC2034

# This adapter keeps system policy, runtime control, and package execution in separate trust domains.

PATCH_SYSTEM_PLAN_HEADER=$'schema\tcriterion\tstate\taction\tprovider\tbackend\tconfig_path\tunit\tbefore_unit_enabled\tbefore_unit_active\tapproval\tsource\taddress\tbefore_sha256\tdesired_sha256'
PATCH_SYSTEM_MANIFEST_HEADER=$'schema\tcriterion\troot\troot_device\troot_inode\tprovider\tbackend\tsource\taddress\troute_selector\troute_destination\tconfig_path\tbefore_state\tbefore_device\tbefore_inode\tbefore_uid\tbefore_gid\tbefore_mode\tbefore_size\tbefore_mtime\tbefore_ctime\tbefore_sha256\tdesired_uid\tdesired_gid\tdesired_mode\tdesired_sha256\tconfig_changed\tunit\tbefore_unit_enabled\tbefore_unit_active\tbackup_name\tpayload_name'
PATCH_SYSTEM_APPLIED_HEADER=$'schema\tcriterion\tdevice\tinode\tuid\tgid\tmode\tlinks\tsize\tmtime\tctime\tsha256\tunit_enabled\tunit_active'
PATCH_SYSTEM_CHECKSUM_HEADER=$'schema\tpath\tsha256'
PATCH_SYSTEM_ERROR_DETAIL=""
PATCH_SYSTEM_ROOT=""
PATCH_SYSTEM_ROOT_DEVICE=""
PATCH_SYSTEM_ROOT_INODE=""
PATCH_SYSTEM_TRANSACTION_DIRECTORY=""
PATCH_SYSTEM_DATA_DIRECTORY=""
PATCH_SYSTEM_CRITERION=""
PATCH_SYSTEM_STATE=""
PATCH_SYSTEM_PLAN_VALID=0
PATCH_SYSTEM_APPLY_STARTED=0
PATCH_SYSTEM_PROVIDER=""
PATCH_SYSTEM_BACKEND=""
PATCH_SYSTEM_SOURCE=""
PATCH_SYSTEM_ADDRESS=""
PATCH_SYSTEM_APPROVAL=""
PATCH_SYSTEM_CONFIG_LOGICAL_PATH=""
PATCH_SYSTEM_CONFIG_PHYSICAL_PATH=""
PATCH_SYSTEM_CONFIG_PARENT_PATH=""
PATCH_SYSTEM_CONFIG_BEFORE_STATE=""
PATCH_SYSTEM_CONFIG_BEFORE_DEVICE=""
PATCH_SYSTEM_CONFIG_BEFORE_INODE=""
PATCH_SYSTEM_CONFIG_BEFORE_UID=""
PATCH_SYSTEM_CONFIG_BEFORE_GID=""
PATCH_SYSTEM_CONFIG_BEFORE_MODE=""
PATCH_SYSTEM_CONFIG_BEFORE_SIZE=""
PATCH_SYSTEM_CONFIG_BEFORE_MTIME=""
PATCH_SYSTEM_CONFIG_BEFORE_CTIME=""
PATCH_SYSTEM_CONFIG_BEFORE_SHA256=""
PATCH_SYSTEM_CONFIG_DESIRED_SHA256=""
PATCH_SYSTEM_CONFIG_DESIRED_UID=""
PATCH_SYSTEM_CONFIG_DESIRED_GID=""
PATCH_SYSTEM_CONFIG_DESIRED_MODE=""
PATCH_SYSTEM_CONFIG_BACKUP_PATH=""
PATCH_SYSTEM_CONFIG_PAYLOAD_PATH=""
PATCH_SYSTEM_CONFIG_CHANGED=0
PATCH_SYSTEM_APPLIED_DEVICE=""
PATCH_SYSTEM_APPLIED_INODE=""
PATCH_SYSTEM_APPLIED_UID=""
PATCH_SYSTEM_APPLIED_GID=""
PATCH_SYSTEM_APPLIED_MODE=""
PATCH_SYSTEM_APPLIED_LINKS=""
PATCH_SYSTEM_APPLIED_SIZE=""
PATCH_SYSTEM_APPLIED_MTIME=""
PATCH_SYSTEM_APPLIED_CTIME=""
PATCH_SYSTEM_APPLIED_SHA256=""
PATCH_SYSTEM_UNIT_APPLIED_ENABLED=""
PATCH_SYSTEM_UNIT_APPLIED_ACTIVE=""
PATCH_SYSTEM_UNIT=""
PATCH_SYSTEM_UNIT_BEFORE_ENABLED=""
PATCH_SYSTEM_UNIT_BEFORE_ACTIVE=""
PATCH_SYSTEM_ROUTE_SELECTOR=""
PATCH_SYSTEM_ROUTE_DESTINATION=""
PATCH_SYSTEM_PACKAGE_MANAGER=""
PATCH_SYSTEM_REPOSITORY_EVIDENCE=""
PATCH_SYSTEM_ADVISORY_EVIDENCE=""
PATCH_SYSTEM_REPOSITORY_DIGEST=""
PATCH_SYSTEM_ADVISORY_DIGEST=""
PATCH_SYSTEM_SIMULATION_PATH=""
PATCH_SYSTEM_SIMULATION_DIGEST=""
PATCH_SYSTEM_SNAPSHOT_TOKEN_DIGEST=""
PATCH_SYSTEM_ROLLBACK_TOKEN_DIGEST=""

PATCH_SYSTEM_CAPTURE_DEVICE=""
PATCH_SYSTEM_CAPTURE_INODE=""
PATCH_SYSTEM_CAPTURE_UID=""
PATCH_SYSTEM_CAPTURE_GID=""
PATCH_SYSTEM_CAPTURE_MODE=""
PATCH_SYSTEM_CAPTURE_LINKS=""
PATCH_SYSTEM_CAPTURE_SIZE=""
PATCH_SYSTEM_CAPTURE_MTIME=""
PATCH_SYSTEM_CAPTURE_CTIME=""
PATCH_SYSTEM_CAPTURE_SHA256=""

declare -A PATCH_SYSTEM_CALLBACKS=()

_patch_system_set_error() {
    PATCH_SYSTEM_ERROR_DETAIL="$1"
    return 2
}

_patch_system_valid_destination() {
    case "$1" in ''|[0-9]*|*[!A-Za-z0-9_]*) return 1 ;; *) return 0 ;; esac
}

_patch_system_safe_token() {
    [ -n "$1" ] && [ "${#1}" -le 512 ] || return 1
    case "$1" in *[!A-Za-z0-9._:@,+/%=-]*) return 1 ;; *) return 0 ;; esac
}

_patch_system_command_path_into() {
    local command_name="$1"
    local destination_name="$2"
    local candidate=""

    _patch_system_valid_destination "$destination_name" || return 2
    case "$command_name" in
        awk) candidate=/usr/bin/awk ;;
        chmod) candidate=/bin/chmod ;;
        chown) candidate=/usr/bin/chown; [ -x "$candidate" ] || candidate=/bin/chown ;;
        cp) candidate=/usr/bin/cp; [ -x "$candidate" ] || candidate=/bin/cp ;;
        mkdir) candidate=/bin/mkdir ;;
        mktemp) candidate=/usr/bin/mktemp; [ -x "$candidate" ] || candidate=/bin/mktemp ;;
        mv) candidate=/usr/bin/mv; [ -x "$candidate" ] || candidate=/bin/mv ;;
        rm) candidate=/usr/bin/rm; [ -x "$candidate" ] || candidate=/bin/rm ;;
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
        systemctl) candidate=/usr/bin/systemctl; [ -x "$candidate" ] || candidate=/bin/systemctl ;;
        *) return 2 ;;
    esac
    [ -x "$candidate" ] || return 127
    printf -v "$destination_name" '%s' "$candidate"
}

_patch_system_stat_into() {
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
    local stat_device=""
    local stat_inode=""
    local stat_uid=""
    local stat_gid=""
    local stat_mode=""
    local stat_links=""
    local stat_size=""
    local stat_mtime=""
    local stat_ctime=""
    local stat_extra=""
    local destination_name=""

    for destination_name in "$device_destination" "$inode_destination" "$uid_destination" \
        "$gid_destination" "$mode_destination" "$links_destination" "$size_destination" \
        "$mtime_destination" "$ctime_destination"; do
        _patch_system_valid_destination "$destination_name" || return 2
    done
    _patch_system_command_path_into stat stat_command || return $?
    if output="$($stat_command -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' -- "$path" 2>/dev/null)"; then
        :
    elif output="$($stat_command -f '%d:%i:%u:%g:%Lp:%l:%z:%m:%c' "$path" 2>/dev/null)"; then
        :
    else
        return 2
    fi
    IFS=: read -r stat_device stat_inode stat_uid stat_gid stat_mode stat_links \
        stat_size stat_mtime stat_ctime stat_extra <<< "$output"
    [ -z "$stat_extra" ] || return 2
    case "$stat_device:$stat_inode:$stat_uid:$stat_gid:$stat_links:$stat_size:$stat_mtime:$stat_ctime" in *[!0-9:]*) return 2 ;; esac
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

_patch_system_sha256_into() {
    local path="$1"
    local destination_name="$2"
    local hash_command=""
    local output=""
    local digest=""

    _patch_system_valid_destination "$destination_name" || return 2
    _patch_system_command_path_into sha256sum hash_command || return $?
    case "$hash_command" in
        */shasum) output="$("$hash_command" -a 256 -- "$path" 2>/dev/null)" || return 2 ;;
        *) output="$("$hash_command" -- "$path" 2>/dev/null)" || return 2 ;;
    esac
    digest="${output%% *}"
    [ "${#digest}" -eq 64 ] || return 2
    case "$digest" in *[!0-9a-f]*) return 2 ;; esac
    printf -v "$destination_name" '%s' "$digest"
}

_patch_system_string_sha256_into() {
    local value="$1"
    local destination_name="$2"
    local hash_command=""
    local output=""
    local digest=""

    _patch_system_valid_destination "$destination_name" || return 2
    _patch_system_command_path_into sha256sum hash_command || return $?
    case "$hash_command" in
        */shasum) output="$(printf '%s' "$value" | "$hash_command" -a 256 2>/dev/null)" || return 2 ;;
        *) output="$(printf '%s' "$value" | "$hash_command" 2>/dev/null)" || return 2 ;;
    esac
    digest="${output%% *}"
    [ "${#digest}" -eq 64 ] || return 2
    case "$digest" in *[!0-9a-f]*) return 2 ;; esac
    printf -v "$destination_name" '%s' "$digest"
}

_patch_system_capture_file() {
    local path="$1"
    local device_before="" inode_before="" uid_before="" gid_before="" mode_before=""
    local links_before="" size_before="" mtime_before="" ctime_before=""
    local device_after="" inode_after="" uid_after="" gid_after="" mode_after=""
    local links_after="" size_after="" mtime_after="" ctime_after="" sha256=""

    [ -f "$path" ] && [ ! -L "$path" ] || return 2
    _patch_system_stat_into "$path" device_before inode_before uid_before gid_before mode_before \
        links_before size_before mtime_before ctime_before || return 2
    [ "$links_before" = 1 ] || return 2
    _patch_system_sha256_into "$path" sha256 || return 2
    _patch_system_stat_into "$path" device_after inode_after uid_after gid_after mode_after \
        links_after size_after mtime_after ctime_after || return 2
    [ "$device_before:$inode_before:$uid_before:$gid_before:$mode_before:$links_before:$size_before:$mtime_before:$ctime_before" = \
      "$device_after:$inode_after:$uid_after:$gid_after:$mode_after:$links_after:$size_after:$mtime_after:$ctime_after" ] || return 2
    [ "$links_after" = 1 ] || return 2
    PATCH_SYSTEM_CAPTURE_DEVICE="$device_after"
    PATCH_SYSTEM_CAPTURE_INODE="$inode_after"
    PATCH_SYSTEM_CAPTURE_UID="$uid_after"
    PATCH_SYSTEM_CAPTURE_GID="$gid_after"
    PATCH_SYSTEM_CAPTURE_MODE="$mode_after"
    PATCH_SYSTEM_CAPTURE_LINKS="$links_after"
    PATCH_SYSTEM_CAPTURE_SIZE="$size_after"
    PATCH_SYSTEM_CAPTURE_MTIME="$mtime_after"
    PATCH_SYSTEM_CAPTURE_CTIME="$ctime_after"
    PATCH_SYSTEM_CAPTURE_SHA256="$sha256"
}

_patch_system_file_fingerprint_into() {
    local path="$1"
    local destination_name="$2"
    local fingerprint=""

    _patch_system_valid_destination "$destination_name" || return 2
    _patch_system_capture_file "$path" || return 2
    printf -v fingerprint '%s:%s:%s:%s:%s:%s:%s:%s:%s' \
        "$PATCH_SYSTEM_CAPTURE_DEVICE" "$PATCH_SYSTEM_CAPTURE_INODE" \
        "$PATCH_SYSTEM_CAPTURE_UID" "$PATCH_SYSTEM_CAPTURE_GID" \
        "$PATCH_SYSTEM_CAPTURE_MODE" "$PATCH_SYSTEM_CAPTURE_SIZE" \
        "$PATCH_SYSTEM_CAPTURE_MTIME" "$PATCH_SYSTEM_CAPTURE_CTIME" \
        "$PATCH_SYSTEM_CAPTURE_SHA256"
    printf -v "$destination_name" '%s' "$fingerprint"
}

_patch_system_directory_metadata_into() {
    local path="$1"
    local uid_destination="$2"
    local mode_destination="$3"
    local captured_device="" captured_inode="" captured_uid="" captured_gid=""
    local captured_mode="" captured_links="" captured_size="" captured_mtime="" captured_ctime=""

    [ -d "$path" ] && [ ! -L "$path" ] || return 2
    _patch_system_stat_into "$path" captured_device captured_inode captured_uid captured_gid \
        captured_mode captured_links captured_size captured_mtime captured_ctime || return 2
    printf -v "$uid_destination" '%s' "$captured_uid"
    printf -v "$mode_destination" '%s' "$captured_mode"
}

_patch_system_root_chain_trusted() {
    local path="$1"
    local strict="${2:-no}"
    local current=/
    local relative="${path#/}"
    local component=""
    local owner_uid=""
    local mode=""
    local mode_decimal=0
    local -a components=()

    case "$path" in /*) ;; *) return 2 ;; esac
    IFS=/ read -r -a components <<< "$relative"
    for component in "${components[@]}"; do
        [ -n "$component" ] || continue
        case "$component" in .|..) return 2 ;; esac
        current="${current%/}/$component"
        _patch_system_directory_metadata_into "$current" owner_uid mode || return 2
        [ "$owner_uid" = 0 ] || { [ "$strict" = no ] && [ "$owner_uid" = "${EUID:-}" ]; } || return 2
        mode_decimal=$((8#$mode))
        if [ $((mode_decimal & 0022)) -ne 0 ]; then
            [ "$strict" = no ] && [ "$owner_uid" = 0 ] && [ $((mode_decimal & 01000)) -ne 0 ] && \
                { [ "$current" = /tmp ] || [ "$current" = /var/tmp ] || [ "$current" = /private/tmp ] || [ "$current" = /private/var/tmp ]; } || return 2
        fi
    done
}

_patch_system_callback_trusted() {
    local callback_path="$1"
    local parent="${callback_path%/*}"
    local device="" inode="" owner_uid="" owner_gid="" mode="" links="" size="" mtime="" ctime=""

    case "$callback_path" in /*) ;; *) return 2 ;; esac
    case "$callback_path" in *$'\n'*|*$'\r'*|*$'\t'*) return 2 ;; esac
    [ -f "$callback_path" ] && [ ! -L "$callback_path" ] && [ -x "$callback_path" ] || return 2
    _patch_system_root_chain_trusted "$parent" yes || return 2
    _patch_system_stat_into "$callback_path" device inode owner_uid owner_gid mode links size mtime ctime || return 2
    [ "$owner_uid" = 0 ] && [ "$links" = 1 ] && [ $((8#$mode & 0022)) -eq 0 ]
}

patch_system_register_callback() {
    local role="$1"
    local callback_path="$2"

    case "$role" in policy_verifier|unit_query|unit_action|native_validator|runtime_probe|signature_verifier|snapshot_verifier|package_simulator) ;; *) return 1 ;; esac
    _patch_system_callback_trusted "$callback_path" || return 2
    PATCH_SYSTEM_CALLBACKS["$role"]="$callback_path"
}

patch_system_clear_callbacks() {
    PATCH_SYSTEM_CALLBACKS=()
}

patch_system_reset() {
    PATCH_SYSTEM_ERROR_DETAIL=""
    PATCH_SYSTEM_ROOT=""
    PATCH_SYSTEM_ROOT_DEVICE=""
    PATCH_SYSTEM_ROOT_INODE=""
    PATCH_SYSTEM_TRANSACTION_DIRECTORY=""
    PATCH_SYSTEM_DATA_DIRECTORY=""
    PATCH_SYSTEM_CRITERION=""
    PATCH_SYSTEM_STATE=""
    PATCH_SYSTEM_PLAN_VALID=0
    PATCH_SYSTEM_APPLY_STARTED=0
    PATCH_SYSTEM_PROVIDER=""
    PATCH_SYSTEM_BACKEND=""
    PATCH_SYSTEM_SOURCE=""
    PATCH_SYSTEM_ADDRESS=""
    PATCH_SYSTEM_APPROVAL=""
    PATCH_SYSTEM_CONFIG_LOGICAL_PATH=""
    PATCH_SYSTEM_CONFIG_PHYSICAL_PATH=""
    PATCH_SYSTEM_CONFIG_PARENT_PATH=""
    PATCH_SYSTEM_CONFIG_BEFORE_STATE=""
    PATCH_SYSTEM_CONFIG_BEFORE_DEVICE=""
    PATCH_SYSTEM_CONFIG_BEFORE_INODE=""
    PATCH_SYSTEM_CONFIG_BEFORE_UID=""
    PATCH_SYSTEM_CONFIG_BEFORE_GID=""
    PATCH_SYSTEM_CONFIG_BEFORE_MODE=""
    PATCH_SYSTEM_CONFIG_BEFORE_SIZE=""
    PATCH_SYSTEM_CONFIG_BEFORE_MTIME=""
    PATCH_SYSTEM_CONFIG_BEFORE_CTIME=""
    PATCH_SYSTEM_CONFIG_BEFORE_SHA256=""
    PATCH_SYSTEM_CONFIG_DESIRED_SHA256=""
    PATCH_SYSTEM_CONFIG_DESIRED_UID=""
    PATCH_SYSTEM_CONFIG_DESIRED_GID=""
    PATCH_SYSTEM_CONFIG_DESIRED_MODE=""
    PATCH_SYSTEM_CONFIG_BACKUP_PATH=""
    PATCH_SYSTEM_CONFIG_PAYLOAD_PATH=""
    PATCH_SYSTEM_CONFIG_CHANGED=0
    PATCH_SYSTEM_APPLIED_DEVICE=""
    PATCH_SYSTEM_APPLIED_INODE=""
    PATCH_SYSTEM_APPLIED_UID=""
    PATCH_SYSTEM_APPLIED_GID=""
    PATCH_SYSTEM_APPLIED_MODE=""
    PATCH_SYSTEM_APPLIED_LINKS=""
    PATCH_SYSTEM_APPLIED_SIZE=""
    PATCH_SYSTEM_APPLIED_MTIME=""
    PATCH_SYSTEM_APPLIED_CTIME=""
    PATCH_SYSTEM_APPLIED_SHA256=""
    PATCH_SYSTEM_UNIT_APPLIED_ENABLED=""
    PATCH_SYSTEM_UNIT_APPLIED_ACTIVE=""
    PATCH_SYSTEM_UNIT=""
    PATCH_SYSTEM_UNIT_BEFORE_ENABLED=""
    PATCH_SYSTEM_UNIT_BEFORE_ACTIVE=""
    PATCH_SYSTEM_ROUTE_SELECTOR=""
    PATCH_SYSTEM_ROUTE_DESTINATION=""
    PATCH_SYSTEM_PACKAGE_MANAGER=""
    PATCH_SYSTEM_REPOSITORY_EVIDENCE=""
    PATCH_SYSTEM_ADVISORY_EVIDENCE=""
    PATCH_SYSTEM_REPOSITORY_DIGEST=""
    PATCH_SYSTEM_ADVISORY_DIGEST=""
    PATCH_SYSTEM_SIMULATION_PATH=""
    PATCH_SYSTEM_SIMULATION_DIGEST=""
    PATCH_SYSTEM_SNAPSHOT_TOKEN_DIGEST=""
    PATCH_SYSTEM_ROLLBACK_TOKEN_DIGEST=""
}

patch_system_supported_criteria() {
    printf '%s\n' U-64 U-65 U-66 U-67
}

patch_system_state_into() {
    local destination_name="$1"

    _patch_system_valid_destination "$destination_name" || return 2
    [ -n "$PATCH_SYSTEM_STATE" ] || return 1
    printf -v "$destination_name" '%s' "$PATCH_SYSTEM_STATE"
}

_patch_system_initialize_root() {
    local requested_root="$1"
    local canonical_root=""
    local root_device="" root_inode="" root_uid="" root_gid="" root_mode=""
    local root_links="" root_size="" root_mtime="" root_ctime=""

    case "$requested_root" in *$'\n'*|*$'\r'*|*$'\t'*) return 2 ;; esac
    [ -d "$requested_root" ] && [ ! -L "$requested_root" ] || return 2
    canonical_root="$(CDPATH='' builtin cd -P -- "$requested_root" 2>/dev/null && pwd -P)" || return 2
    _patch_system_root_chain_trusted "$canonical_root" no || return 2
    _patch_system_stat_into "$canonical_root" root_device root_inode root_uid root_gid \
        root_mode root_links root_size root_mtime root_ctime || return 2
    PATCH_SYSTEM_ROOT="$canonical_root"
    PATCH_SYSTEM_ROOT_DEVICE="$root_device"
    PATCH_SYSTEM_ROOT_INODE="$root_inode"
}

_patch_system_transaction_safe() {
    local directory="$1"
    local owner_uid=""
    local mode=""

    [ -d "$directory" ] && [ ! -L "$directory" ] || return 2
    _patch_system_root_chain_trusted "$(CDPATH='' builtin cd -P -- "$directory" && pwd -P)" no || return 2
    _patch_system_directory_metadata_into "$directory" owner_uid mode || return 2
    [ "$owner_uid" = "${EUID:-}" ] && [ "$mode" = 0700 ]
}

_patch_system_prepare_transaction() {
    local transaction_directory="$1"
    local mkdir_command=""

    _patch_system_transaction_safe "$transaction_directory" || return 2
    PATCH_SYSTEM_TRANSACTION_DIRECTORY="$(CDPATH='' builtin cd -P -- "$transaction_directory" && pwd -P)" || return 2
    PATCH_SYSTEM_DATA_DIRECTORY="$PATCH_SYSTEM_TRANSACTION_DIRECTORY/system"
    [ ! -e "$PATCH_SYSTEM_DATA_DIRECTORY" ] && [ ! -L "$PATCH_SYSTEM_DATA_DIRECTORY" ] || return 2
    _patch_system_command_path_into mkdir mkdir_command || return $?
    (umask 077; "$mkdir_command" "$PATCH_SYSTEM_DATA_DIRECTORY" "$PATCH_SYSTEM_DATA_DIRECTORY/backups" "$PATCH_SYSTEM_DATA_DIRECTORY/payloads") || return 2
    _patch_system_transaction_safe "$PATCH_SYSTEM_DATA_DIRECTORY" && \
        _patch_system_transaction_safe "$PATCH_SYSTEM_DATA_DIRECTORY/backups" && \
        _patch_system_transaction_safe "$PATCH_SYSTEM_DATA_DIRECTORY/payloads"
}

_patch_system_resolve_config_into() {
    local logical_path="$1"
    local parent_destination="$2"
    local physical_destination="$3"
    local relative="${logical_path#/}"
    local current="$PATCH_SYSTEM_ROOT"
    local candidate=""
    local component=""
    local index=0
    local -a components=()

    case "$logical_path" in /*) ;; *) return 2 ;; esac
    case "$logical_path" in /|*//*|*/./*|*/.|*/../*|*/..|*$'\n'*|*$'\r'*|*$'\t'*) return 2 ;; esac
    IFS=/ read -r -a components <<< "$relative"
    [ "${#components[@]}" -gt 1 ] || return 2
    while [ "$index" -lt $(( ${#components[@]} - 1 )) ]; do
        component="${components[$index]}"
        candidate="${current%/}/$component"
        [ -d "$candidate" ] && [ ! -L "$candidate" ] || return 2
        current="$candidate"
        index=$((index + 1))
    done
    candidate="${current%/}/${components[$index]}"
    [ ! -L "$candidate" ] || return 2
    printf -v "$parent_destination" '%s' "$current"
    printf -v "$physical_destination" '%s' "$candidate"
}

_patch_system_content_may_contain_secret() {
    LC_ALL=C grep -Eiq '(^|[^A-Za-z0-9])(password|passphrase|secret|token|private[_-]?key|credential|cookie)[[:space:]]*[:=]' "$1" 2>/dev/null
}

_patch_system_write_private() {
    local path="$1"
    local content="$2"

    [ ! -e "$path" ] && [ ! -L "$path" ] || return 2
    (umask 077; printf '%s' "$content" > "$path") || return 2
    /bin/chmod 0600 "$path" || return 2
    _patch_system_capture_file "$path" || return 2
    [ "$PATCH_SYSTEM_CAPTURE_UID" = "${EUID:-}" ] && [ "$PATCH_SYSTEM_CAPTURE_MODE" = 0600 ]
}

_patch_system_copy_private() {
    local source_path="$1"
    local destination_path="$2"
    local cp_command=""

    _patch_system_command_path_into cp cp_command || return $?
    [ ! -e "$destination_path" ] && [ ! -L "$destination_path" ] || return 2
    (umask 077; "$cp_command" "$source_path" "$destination_path") || return 2
    /bin/chmod 0600 "$destination_path" || return 2
    _patch_system_capture_file "$destination_path"
}

_patch_system_select_chrony_unit_into() {
    local destination_name="$1"
    local candidate=""

    for candidate in \
        /usr/lib/systemd/system/chrony.service /lib/systemd/system/chrony.service \
        /usr/lib/systemd/system/chronyd.service /lib/systemd/system/chronyd.service; do
        if [ -f "${PATCH_SYSTEM_ROOT%/}$candidate" ]; then
            case "$candidate" in *chronyd.service) printf -v "$destination_name" '%s' chronyd.service ;; *) printf -v "$destination_name" '%s' chrony.service ;; esac
            return 0
        fi
    done
    return 1
}

_patch_system_u65_payload_into() {
    local provider="$1"
    local source_value="$2"
    local path_destination="$3"
    local unit_destination="$4"
    local payload_destination="$5"
    local selected_logical_path=""
    local selected_unit=""
    local generated_payload=""

    case "$provider" in
        chrony)
            if [ -d "${PATCH_SYSTEM_ROOT%/}/etc/chrony/sources.d" ]; then
                selected_logical_path=/etc/chrony/sources.d/99-kisa-cce.sources
            elif [ -d "${PATCH_SYSTEM_ROOT%/}/etc/chrony.d" ]; then
                selected_logical_path=/etc/chrony.d/99-kisa-cce.conf
            else
                return 2
            fi
            _patch_system_select_chrony_unit_into selected_unit || return 2
            printf -v generated_payload '# Managed by kisa-cce-patch.\nserver %s iburst\n' "$source_value"
            ;;
        ntpsec)
            selected_logical_path=/etc/ntpsec/ntp.d/99-kisa-cce.conf
            selected_unit=ntpsec.service
            printf -v generated_payload '# Managed by kisa-cce-patch.\nserver %s iburst\n' "$source_value"
            ;;
        systemd-timesyncd)
            selected_logical_path=/etc/systemd/timesyncd.conf.d/99-kisa-cce.conf
            selected_unit=systemd-timesyncd.service
            printf -v generated_payload '# Managed by kisa-cce-patch.\n[Time]\nNTP=%s\n' "$source_value"
            ;;
        ntpd-rs)
            selected_logical_path=/etc/ntpd-rs/ntp.toml
            selected_unit=ntpd-rs.service
            printf -v generated_payload '# Managed by kisa-cce-patch.\n[observability]\nobservation-path = "/run/ntpd-rs/observe"\n\n[[source]]\nmode = "pool"\naddress = "%s"\ncount = 4\n' "$source_value"
            ;;
        *) return 1 ;;
    esac
    printf -v "$path_destination" '%s' "$selected_logical_path"
    printf -v "$unit_destination" '%s' "$selected_unit"
    printf -v "$payload_destination" '%s' "$generated_payload"
}

_patch_system_unit_query_default() {
    local unit="$1"
    local systemctl_command=""
    local output=""
    local load_state="" active_state="" unit_file_state="" line=""

    [ "$PATCH_SYSTEM_ROOT" = / ] || return 2
    _patch_system_command_path_into systemctl systemctl_command || return $?
    output="$("$systemctl_command" show "$unit" --property=LoadState --property=ActiveState --property=UnitFileState 2>/dev/null)" || return 2
    while IFS= read -r line; do
        case "$line" in LoadState=*) load_state="${line#*=}" ;; ActiveState=*) active_state="${line#*=}" ;; UnitFileState=*) unit_file_state="${line#*=}" ;; esac
    done <<< "$output"
    [ "$load_state" != not-found ] && [ -n "$active_state" ] && [ -n "$unit_file_state" ] || return 2
    printf '%s\t%s\n' "$unit_file_state" "$active_state"
}

_patch_system_unit_query_into() {
    local unit="$1"
    local enabled_destination="$2"
    local active_destination="$3"
    local output=""
    local enabled="" active="" extra=""
    local callback_path="${PATCH_SYSTEM_CALLBACKS[unit_query]:-}"

    if [ -n "$callback_path" ]; then
        _patch_system_callback_trusted "$callback_path" || return 2
        output="$("$callback_path" query "$unit" 2>/dev/null)" || return 2
    else
        output="$(_patch_system_unit_query_default "$unit")" || return 2
    fi
    IFS=$'\t' read -r enabled active extra <<< "$output"
    [ -z "$extra" ] || return 2
    case "$enabled" in enabled|enabled-runtime|disabled|masked|static|indirect|generated) ;; *) return 2 ;; esac
    case "$active" in active|inactive|failed|activating|deactivating|reloading) ;; *) return 2 ;; esac
    printf -v "$enabled_destination" '%s' "$enabled"
    printf -v "$active_destination" '%s' "$active"
}

_patch_system_unit_action_default() {
    local action="$1"
    local unit="$2"
    local before_enabled="${3:-}"
    local before_active="${4:-}"
    local systemctl_command=""

    [ "$PATCH_SYSTEM_ROOT" = / ] || return 2
    _patch_system_command_path_into systemctl systemctl_command || return $?
    case "$action" in
        enable_start)
            [ "$before_enabled" != masked ] || \
                "$systemctl_command" unmask "$unit" >/dev/null 2>&1 || return 2
            case "$before_enabled" in
                static|indirect|generated) ;;
                *) "$systemctl_command" enable "$unit" >/dev/null 2>&1 || return 2 ;;
            esac
            "$systemctl_command" start "$unit" >/dev/null 2>&1 || return 2
            ;;
        restore)
            case "$before_enabled" in
                enabled) "$systemctl_command" enable "$unit" >/dev/null 2>&1 || return 2 ;;
                enabled-runtime)
                    "$systemctl_command" disable "$unit" >/dev/null 2>&1 || return 2
                    "$systemctl_command" enable --runtime "$unit" >/dev/null 2>&1 || return 2
                    ;;
                disabled) "$systemctl_command" disable "$unit" >/dev/null 2>&1 || return 2 ;;
                masked)
                    "$systemctl_command" disable "$unit" >/dev/null 2>&1 || return 2
                    "$systemctl_command" mask "$unit" >/dev/null 2>&1 || return 2
                    ;;
                static|indirect|generated) "$systemctl_command" disable "$unit" >/dev/null 2>&1 || return 2 ;;
                *) return 2 ;;
            esac
            case "$before_active" in
                active|activating|reloading) "$systemctl_command" start "$unit" >/dev/null 2>&1 || return 2 ;;
                inactive|failed|deactivating) "$systemctl_command" stop "$unit" >/dev/null 2>&1 || return 2 ;;
                *) return 2 ;;
            esac
            ;;
        *) return 2 ;;
    esac
}

_patch_system_unit_action() {
    local action="$1"
    shift
    local callback_path="${PATCH_SYSTEM_CALLBACKS[unit_action]:-}"

    if [ -n "$callback_path" ]; then
        _patch_system_callback_trusted "$callback_path" || return 2
        "$callback_path" "$action" "$@"
    else
        _patch_system_unit_action_default "$action" "$@"
    fi
}

_patch_system_native_validate() {
    local phase="$1"
    local callback_path="${PATCH_SYSTEM_CALLBACKS[native_validator]:-}"
    local validation_path="$PATCH_SYSTEM_CONFIG_PHYSICAL_PATH"

    [ -n "$callback_path" ] || return 127
    _patch_system_callback_trusted "$callback_path" || return 2
    [ "$phase" != pre ] || validation_path="$PATCH_SYSTEM_CONFIG_PAYLOAD_PATH"
    "$callback_path" "$PATCH_SYSTEM_CRITERION" "$phase" "${PATCH_SYSTEM_PROVIDER:-$PATCH_SYSTEM_BACKEND}" \
        "$PATCH_SYSTEM_ROOT" "$PATCH_SYSTEM_CONFIG_LOGICAL_PATH" "$validation_path"
}

_patch_system_runtime_probe() {
    local callback_path="${PATCH_SYSTEM_CALLBACKS[runtime_probe]:-}"

    [ -n "$callback_path" ] || return 127
    _patch_system_callback_trusted "$callback_path" || return 2
    "$callback_path" "$PATCH_SYSTEM_CRITERION" "${PATCH_SYSTEM_PROVIDER:-$PATCH_SYSTEM_BACKEND}" \
        "$PATCH_SYSTEM_SOURCE" "$PATCH_SYSTEM_ADDRESS" "$PATCH_SYSTEM_UNIT" \
        "$PATCH_SYSTEM_ROUTE_SELECTOR" "$PATCH_SYSTEM_ROUTE_DESTINATION"
}

_patch_system_plan_config() {
    local payload="$1"
    local parent_path=""
    local physical_path=""
    local desired_uid=0
    local desired_gid=0
    local desired_mode=0644

    _patch_system_resolve_config_into "$PATCH_SYSTEM_CONFIG_LOGICAL_PATH" parent_path physical_path || return 2
    PATCH_SYSTEM_CONFIG_PARENT_PATH="$parent_path"
    PATCH_SYSTEM_CONFIG_PHYSICAL_PATH="$physical_path"
    PATCH_SYSTEM_CONFIG_PAYLOAD_PATH="$PATCH_SYSTEM_DATA_DIRECTORY/payloads/config"
    _patch_system_write_private "$PATCH_SYSTEM_CONFIG_PAYLOAD_PATH" "$payload" || return 2
    PATCH_SYSTEM_CONFIG_DESIRED_SHA256="$PATCH_SYSTEM_CAPTURE_SHA256"
    if [ -e "$physical_path" ] || [ -L "$physical_path" ]; then
        _patch_system_capture_file "$physical_path" || return 2
        _patch_system_content_may_contain_secret "$physical_path" && return 2
        PATCH_SYSTEM_CONFIG_BEFORE_STATE=present
        PATCH_SYSTEM_CONFIG_BEFORE_DEVICE="$PATCH_SYSTEM_CAPTURE_DEVICE"
        PATCH_SYSTEM_CONFIG_BEFORE_INODE="$PATCH_SYSTEM_CAPTURE_INODE"
        PATCH_SYSTEM_CONFIG_BEFORE_UID="$PATCH_SYSTEM_CAPTURE_UID"
        PATCH_SYSTEM_CONFIG_BEFORE_GID="$PATCH_SYSTEM_CAPTURE_GID"
        PATCH_SYSTEM_CONFIG_BEFORE_MODE="$PATCH_SYSTEM_CAPTURE_MODE"
        PATCH_SYSTEM_CONFIG_BEFORE_SIZE="$PATCH_SYSTEM_CAPTURE_SIZE"
        PATCH_SYSTEM_CONFIG_BEFORE_MTIME="$PATCH_SYSTEM_CAPTURE_MTIME"
        PATCH_SYSTEM_CONFIG_BEFORE_CTIME="$PATCH_SYSTEM_CAPTURE_CTIME"
        PATCH_SYSTEM_CONFIG_BEFORE_SHA256="$PATCH_SYSTEM_CAPTURE_SHA256"
        desired_uid="$PATCH_SYSTEM_CONFIG_BEFORE_UID"
        desired_gid="$PATCH_SYSTEM_CONFIG_BEFORE_GID"
        desired_mode="$PATCH_SYSTEM_CONFIG_BEFORE_MODE"
        PATCH_SYSTEM_CONFIG_BACKUP_PATH="$PATCH_SYSTEM_DATA_DIRECTORY/backups/config"
        _patch_system_copy_private "$physical_path" "$PATCH_SYSTEM_CONFIG_BACKUP_PATH" || return 2
        [ "$PATCH_SYSTEM_CAPTURE_SHA256" = "$PATCH_SYSTEM_CONFIG_BEFORE_SHA256" ] || return 2
    else
        PATCH_SYSTEM_CONFIG_BEFORE_STATE=absent
        PATCH_SYSTEM_CONFIG_BEFORE_SHA256=-
        PATCH_SYSTEM_CONFIG_BACKUP_PATH=-
    fi
    PATCH_SYSTEM_CONFIG_DESIRED_UID="$desired_uid"
    PATCH_SYSTEM_CONFIG_DESIRED_GID="$desired_gid"
    PATCH_SYSTEM_CONFIG_DESIRED_MODE="$desired_mode"
    if [ "$PATCH_SYSTEM_CONFIG_BEFORE_STATE" = present ] && \
        [ "$PATCH_SYSTEM_CONFIG_BEFORE_SHA256" = "$PATCH_SYSTEM_CONFIG_DESIRED_SHA256" ]; then
        PATCH_SYSTEM_CONFIG_CHANGED=0
    else
        PATCH_SYSTEM_CONFIG_CHANGED=1
    fi
}

_patch_system_write_plan() {
    local plan_path="$PATCH_SYSTEM_DATA_DIRECTORY/plan.tsv"
    local action=replace
    local content=""

    [ "$PATCH_SYSTEM_CONFIG_BEFORE_STATE" != absent ] || action=create
    if [ "$PATCH_SYSTEM_CONFIG_CHANGED" -eq 0 ]; then action=none; fi
    case "$action" in none) action=enable_start ;; *) action="${action}_enable_start" ;; esac
    printf -v content '%s\n1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$PATCH_SYSTEM_PLAN_HEADER" "$PATCH_SYSTEM_CRITERION" "$PATCH_SYSTEM_STATE" "$action" \
        "${PATCH_SYSTEM_PROVIDER:--}" "${PATCH_SYSTEM_BACKEND:--}" \
        "${PATCH_SYSTEM_CONFIG_LOGICAL_PATH:--}" "${PATCH_SYSTEM_UNIT:--}" \
        "${PATCH_SYSTEM_UNIT_BEFORE_ENABLED:--}" "${PATCH_SYSTEM_UNIT_BEFORE_ACTIVE:--}" \
        "${PATCH_SYSTEM_APPROVAL:--}" "${PATCH_SYSTEM_SOURCE:--}" \
        "${PATCH_SYSTEM_ADDRESS:--}" "${PATCH_SYSTEM_CONFIG_BEFORE_SHA256:--}" \
        "${PATCH_SYSTEM_CONFIG_DESIRED_SHA256:--}"
    _patch_system_write_private "$plan_path" "$content" || return 2
}

_patch_system_private_file_safe() {
    local path="$1"

    _patch_system_capture_file "$path" || return 2
    [ "$PATCH_SYSTEM_CAPTURE_UID" = "${EUID:-}" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_MODE" = 0600 ]
}

_patch_system_write_state() {
    local state="$1"
    local state_path="$PATCH_SYSTEM_DATA_DIRECTORY/state"
    local mktemp_command="" mv_command=""
    local stage_path=""

    case "$state" in planned|applying|applied|verified|rollback_in_progress|rolled_back|rollback_failed) ;; *) return 2 ;; esac
    if [ -e "$state_path" ] || [ -L "$state_path" ]; then
        [ ! -L "$state_path" ] && _patch_system_private_file_safe "$state_path" || return 2
    fi
    _patch_system_command_path_into mktemp mktemp_command || return $?
    _patch_system_command_path_into mv mv_command || return $?
    stage_path="$(umask 077; "$mktemp_command" "$PATCH_SYSTEM_DATA_DIRECTORY/.state.XXXXXXXX")" || return 2
    if ! printf '%s\n' "$state" > "$stage_path" || \
        ! /bin/chmod 0600 "$stage_path" || \
        ! "$mv_command" -f "$stage_path" "$state_path"; then
        /bin/rm -f "$stage_path" 2>/dev/null || true
        return 2
    fi
    _patch_system_private_file_safe "$state_path" || return 2
    PATCH_SYSTEM_STATE="$state"
}

_patch_system_write_manifest() {
    local backup_name=-
    local content=""

    [ "$PATCH_SYSTEM_CONFIG_BEFORE_STATE" != present ] || backup_name=backups/config
    printf -v content '%s\n1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$PATCH_SYSTEM_MANIFEST_HEADER" "$PATCH_SYSTEM_CRITERION" "$PATCH_SYSTEM_ROOT" \
        "$PATCH_SYSTEM_ROOT_DEVICE" "$PATCH_SYSTEM_ROOT_INODE" \
        "${PATCH_SYSTEM_PROVIDER:--}" "${PATCH_SYSTEM_BACKEND:--}" \
        "${PATCH_SYSTEM_SOURCE:--}" "${PATCH_SYSTEM_ADDRESS:--}" \
        "${PATCH_SYSTEM_ROUTE_SELECTOR:--}" "${PATCH_SYSTEM_ROUTE_DESTINATION:--}" \
        "$PATCH_SYSTEM_CONFIG_LOGICAL_PATH" "$PATCH_SYSTEM_CONFIG_BEFORE_STATE" \
        "${PATCH_SYSTEM_CONFIG_BEFORE_DEVICE:--}" "${PATCH_SYSTEM_CONFIG_BEFORE_INODE:--}" \
        "${PATCH_SYSTEM_CONFIG_BEFORE_UID:--}" "${PATCH_SYSTEM_CONFIG_BEFORE_GID:--}" \
        "${PATCH_SYSTEM_CONFIG_BEFORE_MODE:--}" "${PATCH_SYSTEM_CONFIG_BEFORE_SIZE:--}" \
        "${PATCH_SYSTEM_CONFIG_BEFORE_MTIME:--}" "${PATCH_SYSTEM_CONFIG_BEFORE_CTIME:--}" \
        "$PATCH_SYSTEM_CONFIG_BEFORE_SHA256" "$PATCH_SYSTEM_CONFIG_DESIRED_UID" \
        "$PATCH_SYSTEM_CONFIG_DESIRED_GID" "$PATCH_SYSTEM_CONFIG_DESIRED_MODE" \
        "$PATCH_SYSTEM_CONFIG_DESIRED_SHA256" "$PATCH_SYSTEM_CONFIG_CHANGED" \
        "$PATCH_SYSTEM_UNIT" "$PATCH_SYSTEM_UNIT_BEFORE_ENABLED" \
        "$PATCH_SYSTEM_UNIT_BEFORE_ACTIVE" "$backup_name" payloads/config
    _patch_system_write_private "$PATCH_SYSTEM_DATA_DIRECTORY/manifest.tsv" "$content"
}

_patch_system_write_checksums() {
    local relative_path="" file_digest=""
    local content="$PATCH_SYSTEM_CHECKSUM_HEADER"$'\n'
    local -a relative_paths=(manifest.tsv plan.tsv payloads/config)

    [ "$PATCH_SYSTEM_CONFIG_BEFORE_STATE" != present ] || relative_paths+=(backups/config)
    for relative_path in "${relative_paths[@]}"; do
        _patch_system_private_file_safe "$PATCH_SYSTEM_DATA_DIRECTORY/$relative_path" || return 2
        _patch_system_sha256_into "$PATCH_SYSTEM_DATA_DIRECTORY/$relative_path" file_digest || return 2
        printf -v content '%s1\t%s\t%s\n' "$content" "$relative_path" "$file_digest"
    done
    _patch_system_write_private "$PATCH_SYSTEM_DATA_DIRECTORY/checksums.tsv" "$content"
}

_patch_system_finalize_recoverable_plan() {
    _patch_system_write_manifest || return 2
    _patch_system_write_checksums || return 2
    _patch_system_write_state planned
}

patch_system_write_plan_tsv() {
    local output_path="$1"
    local cp_command=""

    [ "$PATCH_SYSTEM_PLAN_VALID" -eq 1 ] || return 2
    [ -f "$PATCH_SYSTEM_DATA_DIRECTORY/plan.tsv" ] || return 2
    [ ! -e "$output_path" ] && [ ! -L "$output_path" ] || return 2
    _patch_system_command_path_into cp cp_command || return $?
    (umask 077; "$cp_command" "$PATCH_SYSTEM_DATA_DIRECTORY/plan.tsv" "$output_path") || return 2
    /bin/chmod 0600 "$output_path" || return 2
    _patch_system_capture_file "$output_path"
}

patch_system_u65_plan() {
    local requested_root="$1"
    local transaction_directory="$2"
    local provider="$3"
    local host="$4"
    local address="$5"
    local approval="$6"
    local source_value=""
    local logical_path=""
    local unit=""
    local payload=""
    local policy_verifier="${PATCH_SYSTEM_CALLBACKS[policy_verifier]:-}"

    patch_system_reset
    case "$provider" in chrony|ntpd-rs|ntpsec|systemd-timesyncd) ;; *) _patch_system_set_error "unsupported U-65 provider"; return 1 ;; esac
    _patch_system_safe_token "$approval" || { _patch_system_set_error "U-65 approval identifier is invalid"; return 2; }
    case "$host" in -|'') ;; *) _patch_system_safe_token "$host" || { _patch_system_set_error "U-65 host is invalid"; return 2; } ;; esac
    case "$address" in -|'') ;; *) _patch_system_safe_token "$address" || { _patch_system_set_error "U-65 address is invalid"; return 2; } ;; esac
    if [ "$provider" = ntpd-rs ] && { [ "$host" = - ] || [ -z "$host" ]; }; then
        _patch_system_set_error "U-65 ntpd-rs requires an approved pool host"
        return 2
    fi
    if [ "$host" != - ] && [ -n "$host" ]; then source_value="$host"; elif [ "$address" != - ] && [ -n "$address" ]; then source_value="$address"; else _patch_system_set_error "U-65 approved source is absent"; return 2; fi
    [ -n "$policy_verifier" ] && _patch_system_callback_trusted "$policy_verifier" || { _patch_system_set_error "U-65 typed policy verifier is required"; return 2; }
    "$policy_verifier" U-65 "$provider" "${host:--}" "${address:--}" "$approval" || { _patch_system_set_error "U-65 source is not approved by typed policy"; return 2; }
    _patch_system_initialize_root "$requested_root" || { _patch_system_set_error "U-65 root is unsafe"; return 2; }
    _patch_system_prepare_transaction "$transaction_directory" || { _patch_system_set_error "U-65 transaction directory is unsafe"; return 2; }
    _patch_system_u65_payload_into "$provider" "$source_value" logical_path unit payload || { _patch_system_set_error "U-65 provider configuration is unavailable"; return 2; }
    PATCH_SYSTEM_CRITERION=U-65
    PATCH_SYSTEM_PROVIDER="$provider"
    PATCH_SYSTEM_SOURCE="${host:--}"
    PATCH_SYSTEM_ADDRESS="${address:--}"
    PATCH_SYSTEM_APPROVAL="$approval"
    PATCH_SYSTEM_CONFIG_LOGICAL_PATH="$logical_path"
    PATCH_SYSTEM_UNIT="$unit"
    _patch_system_unit_query_into "$unit" PATCH_SYSTEM_UNIT_BEFORE_ENABLED PATCH_SYSTEM_UNIT_BEFORE_ACTIVE || { _patch_system_set_error "U-65 installed provider unit is unavailable"; return 2; }
    _patch_system_plan_config "$payload" || { _patch_system_set_error "U-65 configuration cannot be safely planned"; return 2; }
    PATCH_SYSTEM_STATE=planned
    PATCH_SYSTEM_PLAN_VALID=1
    _patch_system_write_plan || { _patch_system_set_error "U-65 plan cannot be written"; return 2; }
    _patch_system_finalize_recoverable_plan || { _patch_system_set_error "U-65 recovery manifest cannot be written"; return 2; }
}

patch_system_u66_plan() {
    local requested_root="$1"
    local transaction_directory="$2"
    local backend="$3"
    local selector="$4"
    local destination="$5"
    local approval="$6"
    local payload=""
    local policy_verifier="${PATCH_SYSTEM_CALLBACKS[policy_verifier]:-}"

    patch_system_reset
    _patch_system_safe_token "$approval" || { _patch_system_set_error "U-66 approval identifier is invalid"; return 2; }
    case "$backend" in
        journald)
            [ "$selector" = persistent ] && [ "$destination" = - ] || { _patch_system_set_error "U-66 journald input is invalid"; return 2; }
            PATCH_SYSTEM_CONFIG_LOGICAL_PATH=/etc/systemd/journald.conf.d/99-kisa-cce.conf
            PATCH_SYSTEM_UNIT=systemd-journald.service
            payload=$'# Managed by kisa-cce-patch.\n[Journal]\nStorage=persistent\n'
            ;;
        rsyslog)
            if [[ ! "$selector" =~ ^[A-Za-z0-9*.,\;\!_=-]+$ ]]; then
                _patch_system_set_error "U-66 rsyslog selector is invalid"
                return 2
            fi
            case "$destination" in /*) ;; *) _patch_system_set_error "U-66 rsyslog destination is invalid"; return 2 ;; esac
            case "$destination" in *$'\n'*|*$'\r'*|*$'\t'*|*'..'*) _patch_system_set_error "U-66 rsyslog destination is unsafe"; return 2 ;; esac
            PATCH_SYSTEM_CONFIG_LOGICAL_PATH=/etc/rsyslog.d/99-kisa-cce.conf
            PATCH_SYSTEM_UNIT=rsyslog.service
            printf -v payload '# Managed by kisa-cce-patch.\n%s    %s\n' "$selector" "$destination"
            ;;
        *) _patch_system_set_error "unsupported U-66 backend"; return 1 ;;
    esac
    [ -n "$policy_verifier" ] && _patch_system_callback_trusted "$policy_verifier" || { _patch_system_set_error "U-66 typed policy verifier is required"; return 2; }
    "$policy_verifier" U-66 "$backend" "$selector" "$destination" "$approval" || { _patch_system_set_error "U-66 route is not approved by typed policy"; return 2; }
    _patch_system_initialize_root "$requested_root" || { _patch_system_set_error "U-66 root is unsafe"; return 2; }
    _patch_system_prepare_transaction "$transaction_directory" || { _patch_system_set_error "U-66 transaction directory is unsafe"; return 2; }
    PATCH_SYSTEM_CRITERION=U-66
    PATCH_SYSTEM_BACKEND="$backend"
    PATCH_SYSTEM_ROUTE_SELECTOR="$selector"
    PATCH_SYSTEM_ROUTE_DESTINATION="$destination"
    PATCH_SYSTEM_APPROVAL="$approval"
    _patch_system_unit_query_into "$PATCH_SYSTEM_UNIT" PATCH_SYSTEM_UNIT_BEFORE_ENABLED PATCH_SYSTEM_UNIT_BEFORE_ACTIVE || { _patch_system_set_error "U-66 provider unit is unavailable"; return 2; }
    _patch_system_plan_config "$payload" || { _patch_system_set_error "U-66 configuration cannot be safely planned"; return 2; }
    PATCH_SYSTEM_STATE=planned
    PATCH_SYSTEM_PLAN_VALID=1
    _patch_system_write_plan || { _patch_system_set_error "U-66 plan cannot be written"; return 2; }
    _patch_system_finalize_recoverable_plan || { _patch_system_set_error "U-66 recovery manifest cannot be written"; return 2; }
}

_patch_system_config_matches_before() {
    if [ "$PATCH_SYSTEM_CONFIG_BEFORE_STATE" = absent ]; then
        [ ! -e "$PATCH_SYSTEM_CONFIG_PHYSICAL_PATH" ] && [ ! -L "$PATCH_SYSTEM_CONFIG_PHYSICAL_PATH" ]
        return
    fi
    _patch_system_capture_file "$PATCH_SYSTEM_CONFIG_PHYSICAL_PATH" || return 2
    [ "$PATCH_SYSTEM_CAPTURE_DEVICE" = "$PATCH_SYSTEM_CONFIG_BEFORE_DEVICE" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_INODE" = "$PATCH_SYSTEM_CONFIG_BEFORE_INODE" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_UID" = "$PATCH_SYSTEM_CONFIG_BEFORE_UID" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_GID" = "$PATCH_SYSTEM_CONFIG_BEFORE_GID" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_MODE" = "$PATCH_SYSTEM_CONFIG_BEFORE_MODE" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_SIZE" = "$PATCH_SYSTEM_CONFIG_BEFORE_SIZE" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_MTIME" = "$PATCH_SYSTEM_CONFIG_BEFORE_MTIME" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_CTIME" = "$PATCH_SYSTEM_CONFIG_BEFORE_CTIME" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_SHA256" = "$PATCH_SYSTEM_CONFIG_BEFORE_SHA256" ]
}

_patch_system_config_matches_desired() {
    _patch_system_capture_file "$PATCH_SYSTEM_CONFIG_PHYSICAL_PATH" || return 2
    [ "$PATCH_SYSTEM_CAPTURE_UID" = "$PATCH_SYSTEM_CONFIG_DESIRED_UID" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_GID" = "$PATCH_SYSTEM_CONFIG_DESIRED_GID" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_MODE" = "$PATCH_SYSTEM_CONFIG_DESIRED_MODE" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_SHA256" = "$PATCH_SYSTEM_CONFIG_DESIRED_SHA256" ]
}

_patch_system_config_matches_restored() {
    if [ "$PATCH_SYSTEM_CONFIG_BEFORE_STATE" = absent ]; then
        [ ! -e "$PATCH_SYSTEM_CONFIG_PHYSICAL_PATH" ] && [ ! -L "$PATCH_SYSTEM_CONFIG_PHYSICAL_PATH" ]
        return
    fi
    _patch_system_capture_file "$PATCH_SYSTEM_CONFIG_PHYSICAL_PATH" || return 2
    [ "$PATCH_SYSTEM_CAPTURE_UID" = "$PATCH_SYSTEM_CONFIG_BEFORE_UID" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_GID" = "$PATCH_SYSTEM_CONFIG_BEFORE_GID" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_MODE" = "$PATCH_SYSTEM_CONFIG_BEFORE_MODE" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_SHA256" = "$PATCH_SYSTEM_CONFIG_BEFORE_SHA256" ]
}

_patch_system_config_matches_applied_record() {
    [ -n "$PATCH_SYSTEM_APPLIED_INODE" ] || return 1
    _patch_system_capture_file "$PATCH_SYSTEM_CONFIG_PHYSICAL_PATH" || return 2
    [ "$PATCH_SYSTEM_CAPTURE_DEVICE" = "$PATCH_SYSTEM_APPLIED_DEVICE" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_INODE" = "$PATCH_SYSTEM_APPLIED_INODE" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_UID" = "$PATCH_SYSTEM_APPLIED_UID" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_GID" = "$PATCH_SYSTEM_APPLIED_GID" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_MODE" = "$PATCH_SYSTEM_APPLIED_MODE" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_LINKS" = "$PATCH_SYSTEM_APPLIED_LINKS" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_SIZE" = "$PATCH_SYSTEM_APPLIED_SIZE" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_MTIME" = "$PATCH_SYSTEM_APPLIED_MTIME" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_CTIME" = "$PATCH_SYSTEM_APPLIED_CTIME" ] && \
        [ "$PATCH_SYSTEM_CAPTURE_SHA256" = "$PATCH_SYSTEM_APPLIED_SHA256" ]
}

_patch_system_write_applied_record() {
    local current_enabled="" current_active=""
    local content="" applied_digest=""

    _patch_system_config_matches_desired || return 2
    PATCH_SYSTEM_APPLIED_DEVICE="$PATCH_SYSTEM_CAPTURE_DEVICE"
    PATCH_SYSTEM_APPLIED_INODE="$PATCH_SYSTEM_CAPTURE_INODE"
    PATCH_SYSTEM_APPLIED_UID="$PATCH_SYSTEM_CAPTURE_UID"
    PATCH_SYSTEM_APPLIED_GID="$PATCH_SYSTEM_CAPTURE_GID"
    PATCH_SYSTEM_APPLIED_MODE="$PATCH_SYSTEM_CAPTURE_MODE"
    PATCH_SYSTEM_APPLIED_LINKS="$PATCH_SYSTEM_CAPTURE_LINKS"
    PATCH_SYSTEM_APPLIED_SIZE="$PATCH_SYSTEM_CAPTURE_SIZE"
    PATCH_SYSTEM_APPLIED_MTIME="$PATCH_SYSTEM_CAPTURE_MTIME"
    PATCH_SYSTEM_APPLIED_CTIME="$PATCH_SYSTEM_CAPTURE_CTIME"
    PATCH_SYSTEM_APPLIED_SHA256="$PATCH_SYSTEM_CAPTURE_SHA256"
    _patch_system_unit_query_into "$PATCH_SYSTEM_UNIT" current_enabled current_active || return 2
    PATCH_SYSTEM_UNIT_APPLIED_ENABLED="$current_enabled"
    PATCH_SYSTEM_UNIT_APPLIED_ACTIVE="$current_active"
    printf -v content '%s\n1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$PATCH_SYSTEM_APPLIED_HEADER" "$PATCH_SYSTEM_CRITERION" \
        "$PATCH_SYSTEM_APPLIED_DEVICE" "$PATCH_SYSTEM_APPLIED_INODE" \
        "$PATCH_SYSTEM_APPLIED_UID" "$PATCH_SYSTEM_APPLIED_GID" \
        "$PATCH_SYSTEM_APPLIED_MODE" "$PATCH_SYSTEM_APPLIED_LINKS" \
        "$PATCH_SYSTEM_APPLIED_SIZE" "$PATCH_SYSTEM_APPLIED_MTIME" \
        "$PATCH_SYSTEM_APPLIED_CTIME" "$PATCH_SYSTEM_APPLIED_SHA256" \
        "$PATCH_SYSTEM_UNIT_APPLIED_ENABLED" "$PATCH_SYSTEM_UNIT_APPLIED_ACTIVE"
    _patch_system_write_private "$PATCH_SYSTEM_DATA_DIRECTORY/applied.tsv" "$content" || return 2
    _patch_system_sha256_into "$PATCH_SYSTEM_DATA_DIRECTORY/applied.tsv" applied_digest || return 2
    printf -v content '%s\n1\tapplied.tsv\t%s\n' "$PATCH_SYSTEM_CHECKSUM_HEADER" "$applied_digest"
    _patch_system_write_private "$PATCH_SYSTEM_DATA_DIRECTORY/applied-checksum.tsv" "$content"
}

_patch_system_unit_active_matches_before() {
    [ "$1" != "$PATCH_SYSTEM_UNIT_BEFORE_ACTIVE" ] || return 0
    case "$PATCH_SYSTEM_UNIT_BEFORE_ACTIVE:$1" in
        active:active|activating:active|reloading:active|inactive:inactive|failed:inactive|deactivating:inactive) return 0 ;;
        *) return 1 ;;
    esac
}

_patch_system_unit_matches_before() {
    [ "$1" = "$PATCH_SYSTEM_UNIT_BEFORE_ENABLED" ] && \
        _patch_system_unit_active_matches_before "$2"
}

_patch_system_unit_matches_applied() {
    [ -n "$PATCH_SYSTEM_UNIT_APPLIED_ENABLED" ] && \
        [ "$1" = "$PATCH_SYSTEM_UNIT_APPLIED_ENABLED" ] && \
        [ "$2" = "$PATCH_SYSTEM_UNIT_APPLIED_ACTIVE" ]
}

_patch_system_unit_transition_allowed() {
    local current_enabled="$1"
    local current_active="$2"
    local enabled_allowed=1 active_allowed=1

    if [ "$current_enabled" = "$PATCH_SYSTEM_UNIT_BEFORE_ENABLED" ]; then
        enabled_allowed=0
    elif [ -n "$PATCH_SYSTEM_UNIT_APPLIED_ENABLED" ]; then
        [ "$current_enabled" = "$PATCH_SYSTEM_UNIT_APPLIED_ENABLED" ] && enabled_allowed=0
    else
        case "$current_enabled" in enabled|enabled-runtime|static) enabled_allowed=0 ;; esac
    fi
    if _patch_system_unit_active_matches_before "$current_active"; then
        active_allowed=0
    elif [ -n "$PATCH_SYSTEM_UNIT_APPLIED_ACTIVE" ]; then
        [ "$current_active" = "$PATCH_SYSTEM_UNIT_APPLIED_ACTIVE" ] && active_allowed=0
    elif [ "$current_active" = active ]; then
        active_allowed=0
    fi
    [ "$enabled_allowed" -eq 0 ] && [ "$active_allowed" -eq 0 ]
}

_patch_system_load_checksums() {
    local checksum_path="$PATCH_SYSTEM_DATA_DIRECTORY/checksums.tsv"
    local line="" schema="" relative_path="" recorded_digest="" extra=""
    local actual_digest=""
    local first=1 count=0
    local -A seen=()

    _patch_system_private_file_safe "$checksum_path" || return 2
    while IFS= read -r line || [ -n "$line" ]; do
        if [ "$first" -eq 1 ]; then
            [ "$line" = "$PATCH_SYSTEM_CHECKSUM_HEADER" ] || return 2
            first=0
            continue
        fi
        IFS=$'\t' read -r schema relative_path recorded_digest extra <<< "$line"
        [ -z "$extra" ] && [ "$schema" = 1 ] || return 2
        case "$relative_path" in manifest.tsv|plan.tsv|payloads/config|backups/config) ;; *) return 2 ;; esac
        [ -z "${seen[$relative_path]:-}" ] || return 2
        [ "${#recorded_digest}" -eq 64 ] || return 2
        case "$recorded_digest" in *[!0-9a-f]*) return 2 ;; esac
        _patch_system_private_file_safe "$PATCH_SYSTEM_DATA_DIRECTORY/$relative_path" || return 2
        _patch_system_sha256_into "$PATCH_SYSTEM_DATA_DIRECTORY/$relative_path" actual_digest || return 2
        [ "$actual_digest" = "$recorded_digest" ] || return 2
        seen["$relative_path"]=1
        count=$((count + 1))
    done < "$checksum_path"
    [ "$first" -eq 0 ] && [ "$count" -ge 3 ] && [ "$count" -le 4 ] || return 2
    [ "${seen[manifest.tsv]:-}" = 1 ] && [ "${seen[plan.tsv]:-}" = 1 ] && \
        [ "${seen[payloads/config]:-}" = 1 ]
}

_patch_system_load_state() {
    local state_path="$PATCH_SYSTEM_DATA_DIRECTORY/state"
    local -a state_lines=()

    _patch_system_private_file_safe "$state_path" || return 2
    mapfile -t state_lines < "$state_path" || return 2
    [ "${#state_lines[@]}" -eq 1 ] || return 2
    case "${state_lines[0]}" in planned|applying|applied|verified|rollback_in_progress|rolled_back|rollback_failed) ;; *) return 2 ;; esac
    PATCH_SYSTEM_STATE="${state_lines[0]}"
}

_patch_system_load_applied_record() {
    local record_path="$PATCH_SYSTEM_DATA_DIRECTORY/applied.tsv"
    local checksum_path="$PATCH_SYSTEM_DATA_DIRECTORY/applied-checksum.tsv"
    local -a lines=() checksum_lines=()
    local schema="" criterion="" device="" inode="" owner_uid="" owner_gid=""
    local mode="" links="" size="" mtime="" ctime="" sha256=""
    local unit_enabled="" unit_active="" extra=""
    local checksum_schema="" checksum_name="" recorded_digest="" checksum_extra=""
    local actual_digest=""

    if [ ! -e "$record_path" ] && [ ! -L "$record_path" ] && \
        [ ! -e "$checksum_path" ] && [ ! -L "$checksum_path" ]; then
        return 0
    fi
    _patch_system_private_file_safe "$record_path" && \
        _patch_system_private_file_safe "$checksum_path" || return 2
    mapfile -t checksum_lines < "$checksum_path" || return 2
    [ "${#checksum_lines[@]}" -eq 2 ] && \
        [ "${checksum_lines[0]}" = "$PATCH_SYSTEM_CHECKSUM_HEADER" ] || return 2
    IFS=$'\t' read -r checksum_schema checksum_name recorded_digest checksum_extra <<< "${checksum_lines[1]}"
    [ -z "$checksum_extra" ] && [ "$checksum_schema" = 1 ] && \
        [ "$checksum_name" = applied.tsv ] || return 2
    _patch_system_sha256_into "$record_path" actual_digest || return 2
    [ "$recorded_digest" = "$actual_digest" ] || return 2

    mapfile -t lines < "$record_path" || return 2
    [ "${#lines[@]}" -eq 2 ] && [ "${lines[0]}" = "$PATCH_SYSTEM_APPLIED_HEADER" ] || return 2
    IFS=$'\t' read -r schema criterion device inode owner_uid owner_gid mode links size \
        mtime ctime sha256 unit_enabled unit_active extra <<< "${lines[1]}"
    [ -z "$extra" ] && [ "$schema" = 1 ] && [ "$criterion" = "$PATCH_SYSTEM_CRITERION" ] || return 2
    case "$device:$inode:$owner_uid:$owner_gid:$links:$size:$mtime:$ctime" in *[!0-9:]*) return 2 ;; esac
    case "$mode" in ''|*[!0-7]*) return 2 ;; esac
    [ "$links" = 1 ] && [ "${#sha256}" -eq 64 ] || return 2
    case "$sha256" in *[!0-9a-f]*) return 2 ;; esac
    [ "$owner_uid" = "$PATCH_SYSTEM_CONFIG_DESIRED_UID" ] && \
        [ "$owner_gid" = "$PATCH_SYSTEM_CONFIG_DESIRED_GID" ] && \
        [ "$mode" = "$PATCH_SYSTEM_CONFIG_DESIRED_MODE" ] && \
        [ "$sha256" = "$PATCH_SYSTEM_CONFIG_DESIRED_SHA256" ] || return 2
    case "$unit_enabled" in enabled|enabled-runtime|static) ;; *) return 2 ;; esac
    [ "$unit_active" = active ] || return 2
    PATCH_SYSTEM_APPLIED_DEVICE="$device"
    PATCH_SYSTEM_APPLIED_INODE="$inode"
    PATCH_SYSTEM_APPLIED_UID="$owner_uid"
    PATCH_SYSTEM_APPLIED_GID="$owner_gid"
    PATCH_SYSTEM_APPLIED_MODE="$mode"
    PATCH_SYSTEM_APPLIED_LINKS="$links"
    PATCH_SYSTEM_APPLIED_SIZE="$size"
    PATCH_SYSTEM_APPLIED_MTIME="$mtime"
    PATCH_SYSTEM_APPLIED_CTIME="$ctime"
    PATCH_SYSTEM_APPLIED_SHA256="$sha256"
    PATCH_SYSTEM_UNIT_APPLIED_ENABLED="$unit_enabled"
    PATCH_SYSTEM_UNIT_APPLIED_ACTIVE="$unit_active"
}

patch_system_load_transaction() {
    local requested_root="$1"
    local transaction_directory="$2"
    local supplied_root="" supplied_root_device="" supplied_root_inode=""
    local -a manifest_lines=()
    local schema="" criterion="" recorded_root="" root_device="" root_inode=""
    local provider="" backend="" source="" address="" route_selector="" route_destination=""
    local config_path="" before_state="" before_device="" before_inode=""
    local before_uid="" before_gid="" before_mode="" before_size="" before_mtime=""
    local before_ctime="" before_sha256="" desired_uid="" desired_gid=""
    local desired_mode="" desired_sha256="" config_changed="" unit=""
    local before_unit_enabled="" before_unit_active="" backup_name="" payload_name="" extra=""
    local expected_path="" expected_unit="" expected_payload="" expected_digest=""
    local expected_source="" parent_path="" physical_path="" payload_digest="" backup_digest=""

    patch_system_reset
    _patch_system_initialize_root "$requested_root" || { _patch_system_set_error "system rollback root is unsafe"; return 2; }
    supplied_root="$PATCH_SYSTEM_ROOT"
    supplied_root_device="$PATCH_SYSTEM_ROOT_DEVICE"
    supplied_root_inode="$PATCH_SYSTEM_ROOT_INODE"
    _patch_system_transaction_safe "$transaction_directory" || { _patch_system_set_error "system transaction directory is unsafe"; return 2; }
    PATCH_SYSTEM_TRANSACTION_DIRECTORY="$(CDPATH='' builtin cd -P -- "$transaction_directory" && pwd -P)" || return 2
    PATCH_SYSTEM_DATA_DIRECTORY="$PATCH_SYSTEM_TRANSACTION_DIRECTORY/system"
    _patch_system_transaction_safe "$PATCH_SYSTEM_DATA_DIRECTORY" && \
        _patch_system_transaction_safe "$PATCH_SYSTEM_DATA_DIRECTORY/backups" && \
        _patch_system_transaction_safe "$PATCH_SYSTEM_DATA_DIRECTORY/payloads" || { _patch_system_set_error "system transaction payload directories are unsafe"; return 2; }
    _patch_system_load_checksums || { _patch_system_set_error "system transaction checksum validation failed"; return 2; }
    mapfile -t manifest_lines < "$PATCH_SYSTEM_DATA_DIRECTORY/manifest.tsv" || return 2
    [ "${#manifest_lines[@]}" -eq 2 ] && \
        [ "${manifest_lines[0]}" = "$PATCH_SYSTEM_MANIFEST_HEADER" ] || { _patch_system_set_error "system transaction manifest schema is invalid"; return 2; }
    IFS=$'\t' read -r schema criterion recorded_root root_device root_inode provider backend \
        source address route_selector route_destination config_path before_state before_device \
        before_inode before_uid before_gid before_mode before_size before_mtime before_ctime \
        before_sha256 desired_uid desired_gid desired_mode desired_sha256 config_changed unit \
        before_unit_enabled before_unit_active backup_name payload_name extra <<< "${manifest_lines[1]}"
    [ -z "$extra" ] && [ "$schema" = 1 ] || return 2
    [ "$recorded_root" = "$supplied_root" ] && [ "$root_device" = "$supplied_root_device" ] && \
        [ "$root_inode" = "$supplied_root_inode" ] || { _patch_system_set_error "system transaction root identity does not match"; return 2; }
    case "$root_device:$root_inode:$desired_uid:$desired_gid" in *[!0-9:]*) return 2 ;; esac
    case "$desired_mode" in ''|*[!0-7]*) return 2 ;; esac
    [ "${#desired_sha256}" -eq 64 ] || return 2
    case "$desired_sha256" in *[!0-9a-f]*) return 2 ;; esac
    case "$config_changed" in 0|1) ;; *) return 2 ;; esac
    case "$before_unit_enabled" in enabled|enabled-runtime|disabled|masked|static|indirect|generated) ;; *) return 2 ;; esac
    case "$before_unit_active" in active|inactive|failed|activating|deactivating|reloading) ;; *) return 2 ;; esac
    case "$before_state" in
        present)
            case "$before_device:$before_inode:$before_uid:$before_gid:$before_size:$before_mtime:$before_ctime" in *[!0-9:]*) return 2 ;; esac
            case "$before_mode" in ''|*[!0-7]*) return 2 ;; esac
            [ "${#before_sha256}" -eq 64 ] && [ "$backup_name" = backups/config ] || return 2
            case "$before_sha256" in *[!0-9a-f]*) return 2 ;; esac
            [ "$desired_uid:$desired_gid:$desired_mode" = "$before_uid:$before_gid:$before_mode" ] || return 2
            if [ "$before_sha256" = "$desired_sha256" ]; then
                [ "$config_changed" = 0 ] || return 2
            else
                [ "$config_changed" = 1 ] || return 2
            fi
            ;;
        absent)
            [ "$before_device:$before_inode:$before_uid:$before_gid:$before_mode:$before_size:$before_mtime:$before_ctime:$before_sha256:$backup_name" = '-:-:-:-:-:-:-:-:-:-' ] || return 2
            [ "$desired_uid:$desired_gid:$desired_mode:$config_changed" = '0:0:0644:1' ] || return 2
            ;;
        *) return 2 ;;
    esac
    [ "$payload_name" = payloads/config ] || return 2

    case "$criterion" in
        U-65)
            case "$provider" in chrony|ntpd-rs|ntpsec|systemd-timesyncd) ;; *) return 2 ;; esac
            [ "$backend:$route_selector:$route_destination" = '-:-:-' ] || return 2
            case "$source" in -|'') ;; *) _patch_system_safe_token "$source" || return 2 ;; esac
            case "$address" in -|'') ;; *) _patch_system_safe_token "$address" || return 2 ;; esac
            if [ "$source" != - ] && [ -n "$source" ]; then
                expected_source="$source"
            elif [ "$address" != - ] && [ -n "$address" ]; then
                expected_source="$address"
            else
                return 2
            fi
            _patch_system_u65_payload_into "$provider" "$expected_source" expected_path expected_unit expected_payload || return 2
            ;;
        U-66)
            [ "$provider:$source:$address" = '-:-:-' ] || return 2
            case "$backend" in
                journald)
                    [ "$route_selector:$route_destination" = 'persistent:-' ] || return 2
                    expected_path=/etc/systemd/journald.conf.d/99-kisa-cce.conf
                    expected_unit=systemd-journald.service
                    expected_payload=$'# Managed by kisa-cce-patch.\n[Journal]\nStorage=persistent\n'
                    ;;
                rsyslog)
                    [[ "$route_selector" =~ ^[A-Za-z0-9*.,\;\!_=-]+$ ]] || return 2
                    case "$route_destination" in /*) ;; *) return 2 ;; esac
                    case "$route_destination" in *$'\n'*|*$'\r'*|*$'\t'*|*'..'*) return 2 ;; esac
                    expected_path=/etc/rsyslog.d/99-kisa-cce.conf
                    expected_unit=rsyslog.service
                    printf -v expected_payload '# Managed by kisa-cce-patch.\n%s    %s\n' "$route_selector" "$route_destination"
                    ;;
                *) return 2 ;;
            esac
            ;;
        *) _patch_system_set_error "system transaction is not rollback-capable"; return 2 ;;
    esac
    [ "$config_path:$unit" = "$expected_path:$expected_unit" ] || return 2
    _patch_system_string_sha256_into "$expected_payload" expected_digest || return 2
    [ "$expected_digest" = "$desired_sha256" ] || return 2
    _patch_system_sha256_into "$PATCH_SYSTEM_DATA_DIRECTORY/payloads/config" payload_digest || return 2
    [ "$payload_digest" = "$desired_sha256" ] || return 2
    if [ "$before_state" = present ]; then
        _patch_system_sha256_into "$PATCH_SYSTEM_DATA_DIRECTORY/backups/config" backup_digest || return 2
        [ "$backup_digest" = "$before_sha256" ] || return 2
    else
        [ ! -e "$PATCH_SYSTEM_DATA_DIRECTORY/backups/config" ] && \
            [ ! -L "$PATCH_SYSTEM_DATA_DIRECTORY/backups/config" ] || return 2
    fi

    PATCH_SYSTEM_ROOT="$supplied_root"
    PATCH_SYSTEM_ROOT_DEVICE="$supplied_root_device"
    PATCH_SYSTEM_ROOT_INODE="$supplied_root_inode"
    PATCH_SYSTEM_CRITERION="$criterion"
    PATCH_SYSTEM_PROVIDER="${provider#-}"
    PATCH_SYSTEM_BACKEND="${backend#-}"
    PATCH_SYSTEM_SOURCE="$source"
    PATCH_SYSTEM_ADDRESS="$address"
    PATCH_SYSTEM_ROUTE_SELECTOR="${route_selector#-}"
    PATCH_SYSTEM_ROUTE_DESTINATION="$route_destination"
    PATCH_SYSTEM_CONFIG_LOGICAL_PATH="$config_path"
    _patch_system_resolve_config_into "$config_path" parent_path physical_path || return 2
    PATCH_SYSTEM_CONFIG_PARENT_PATH="$parent_path"
    PATCH_SYSTEM_CONFIG_PHYSICAL_PATH="$physical_path"
    PATCH_SYSTEM_CONFIG_BEFORE_STATE="$before_state"
    PATCH_SYSTEM_CONFIG_BEFORE_DEVICE="${before_device#-}"
    PATCH_SYSTEM_CONFIG_BEFORE_INODE="${before_inode#-}"
    PATCH_SYSTEM_CONFIG_BEFORE_UID="${before_uid#-}"
    PATCH_SYSTEM_CONFIG_BEFORE_GID="${before_gid#-}"
    PATCH_SYSTEM_CONFIG_BEFORE_MODE="${before_mode#-}"
    PATCH_SYSTEM_CONFIG_BEFORE_SIZE="${before_size#-}"
    PATCH_SYSTEM_CONFIG_BEFORE_MTIME="${before_mtime#-}"
    PATCH_SYSTEM_CONFIG_BEFORE_CTIME="${before_ctime#-}"
    PATCH_SYSTEM_CONFIG_BEFORE_SHA256="$before_sha256"
    PATCH_SYSTEM_CONFIG_DESIRED_UID="$desired_uid"
    PATCH_SYSTEM_CONFIG_DESIRED_GID="$desired_gid"
    PATCH_SYSTEM_CONFIG_DESIRED_MODE="$desired_mode"
    PATCH_SYSTEM_CONFIG_DESIRED_SHA256="$desired_sha256"
    PATCH_SYSTEM_CONFIG_CHANGED="$config_changed"
    PATCH_SYSTEM_CONFIG_BACKUP_PATH=-
    [ "$before_state" != present ] || PATCH_SYSTEM_CONFIG_BACKUP_PATH="$PATCH_SYSTEM_DATA_DIRECTORY/backups/config"
    PATCH_SYSTEM_CONFIG_PAYLOAD_PATH="$PATCH_SYSTEM_DATA_DIRECTORY/payloads/config"
    PATCH_SYSTEM_UNIT="$unit"
    PATCH_SYSTEM_UNIT_BEFORE_ENABLED="$before_unit_enabled"
    PATCH_SYSTEM_UNIT_BEFORE_ACTIVE="$before_unit_active"
    _patch_system_load_state || { _patch_system_set_error "system transaction state is invalid"; return 2; }
    _patch_system_load_applied_record || { _patch_system_set_error "system applied record is invalid"; return 2; }
    PATCH_SYSTEM_PLAN_VALID=1
    case "$PATCH_SYSTEM_STATE" in planned|rolled_back) PATCH_SYSTEM_APPLY_STARTED=0 ;; *) PATCH_SYSTEM_APPLY_STARTED=1 ;; esac
}

_patch_system_install_file() {
    local source_path="$1"
    local destination_path="$2"
    local parent_path="${destination_path%/*}"
    local mktemp_command="" cp_command="" chown_command="" chmod_command="" mv_command=""
    local stage_path=""

    _patch_system_command_path_into mktemp mktemp_command || return $?
    _patch_system_command_path_into cp cp_command || return $?
    _patch_system_command_path_into chown chown_command || return $?
    _patch_system_command_path_into chmod chmod_command || return $?
    _patch_system_command_path_into mv mv_command || return $?
    stage_path="$(umask 077; "$mktemp_command" "$parent_path/.kisa-cce-system.XXXXXXXX")" || return 2
    if ! "$cp_command" "$source_path" "$stage_path" || \
        ! "$chown_command" "$PATCH_SYSTEM_CONFIG_DESIRED_UID:$PATCH_SYSTEM_CONFIG_DESIRED_GID" "$stage_path" || \
        ! "$chmod_command" "$PATCH_SYSTEM_CONFIG_DESIRED_MODE" "$stage_path" || \
        ! "$mv_command" -f "$stage_path" "$destination_path"; then
        /bin/rm -f "$stage_path" 2>/dev/null || true
        return 2
    fi
}

_patch_system_restore_config() {
    local rm_command=""
    local saved_uid="$PATCH_SYSTEM_CONFIG_DESIRED_UID"
    local saved_gid="$PATCH_SYSTEM_CONFIG_DESIRED_GID"
    local saved_mode="$PATCH_SYSTEM_CONFIG_DESIRED_MODE"
    local restore_status=0

    if [ "$PATCH_SYSTEM_CONFIG_BEFORE_STATE" = absent ]; then
        _patch_system_command_path_into rm rm_command || return $?
        "$rm_command" -f "$PATCH_SYSTEM_CONFIG_PHYSICAL_PATH" || return 2
        [ ! -e "$PATCH_SYSTEM_CONFIG_PHYSICAL_PATH" ] && [ ! -L "$PATCH_SYSTEM_CONFIG_PHYSICAL_PATH" ]
        return
    fi
    PATCH_SYSTEM_CONFIG_DESIRED_UID="$PATCH_SYSTEM_CONFIG_BEFORE_UID"
    PATCH_SYSTEM_CONFIG_DESIRED_GID="$PATCH_SYSTEM_CONFIG_BEFORE_GID"
    PATCH_SYSTEM_CONFIG_DESIRED_MODE="$PATCH_SYSTEM_CONFIG_BEFORE_MODE"
    _patch_system_install_file "$PATCH_SYSTEM_CONFIG_BACKUP_PATH" "$PATCH_SYSTEM_CONFIG_PHYSICAL_PATH" || restore_status=$?
    PATCH_SYSTEM_CONFIG_DESIRED_UID="$saved_uid"
    PATCH_SYSTEM_CONFIG_DESIRED_GID="$saved_gid"
    PATCH_SYSTEM_CONFIG_DESIRED_MODE="$saved_mode"
    [ "$restore_status" -eq 0 ] || return 2
    _patch_system_config_matches_restored
}

patch_system_verify() {
    local current_enabled="" current_active=""

    [ "$PATCH_SYSTEM_PLAN_VALID" -eq 1 ] || return 2
    case "$PATCH_SYSTEM_CRITERION" in U-65|U-66) ;; *) return 1 ;; esac
    _patch_system_config_matches_desired || { _patch_system_set_error "$PATCH_SYSTEM_CRITERION persistent configuration verification failed"; return 2; }
    _patch_system_unit_query_into "$PATCH_SYSTEM_UNIT" current_enabled current_active || { _patch_system_set_error "$PATCH_SYSTEM_CRITERION unit query failed"; return 2; }
    case "$current_enabled" in enabled|enabled-runtime|static) ;; *) _patch_system_set_error "$PATCH_SYSTEM_CRITERION unit is not enabled"; return 2 ;; esac
    [ "$current_active" = active ] || { _patch_system_set_error "$PATCH_SYSTEM_CRITERION unit is not active"; return 2; }
    _patch_system_native_validate post || { _patch_system_set_error "$PATCH_SYSTEM_CRITERION native validation failed"; return 2; }
    if [ "$PATCH_SYSTEM_CRITERION" = U-65 ] || [ -n "${PATCH_SYSTEM_CALLBACKS[runtime_probe]:-}" ]; then
        _patch_system_runtime_probe || { _patch_system_set_error "$PATCH_SYSTEM_CRITERION fresh runtime verification failed"; return 2; }
    fi
    _patch_system_write_applied_record || { _patch_system_set_error "$PATCH_SYSTEM_CRITERION applied record cannot be written"; return 2; }
    _patch_system_write_state verified || { _patch_system_set_error "$PATCH_SYSTEM_CRITERION verified state cannot be written"; return 2; }
}

_patch_system_rollback_loaded() {
    local mode="$1"
    local current_enabled="" current_active=""
    local config_is_restored=1 unit_is_restored=1

    [ "${EUID:-$(id -u)}" -eq 0 ] || { _patch_system_set_error "system rollback requires effective UID 0"; return 2; }
    [ "$PATCH_SYSTEM_PLAN_VALID" -eq 1 ] && [ "$PATCH_SYSTEM_APPLY_STARTED" -eq 1 ] || return 2
    case "$PATCH_SYSTEM_STATE" in applying|applied|verified|rollback_in_progress|rollback_failed) ;; *) return 2 ;; esac
    case "$mode" in strict|transition) ;; *) return 2 ;; esac
    _patch_system_unit_query_into "$PATCH_SYSTEM_UNIT" current_enabled current_active || { _patch_system_set_error "system rollback unit query failed"; return 2; }
    if _patch_system_config_matches_restored; then config_is_restored=0; fi
    if _patch_system_unit_matches_before "$current_enabled" "$current_active"; then unit_is_restored=0; fi
    if [ "$mode" = strict ]; then
        _patch_system_config_matches_applied_record && \
            _patch_system_unit_matches_applied "$current_enabled" "$current_active" || { _patch_system_set_error "strict system rollback preflight detected drift"; return 2; }
    else
        if [ -n "$PATCH_SYSTEM_APPLIED_INODE" ]; then
            [ "$config_is_restored" -eq 0 ] || _patch_system_config_matches_applied_record || { _patch_system_set_error "system rollback transition preflight detected configuration drift"; return 2; }
        else
            [ "$config_is_restored" -eq 0 ] || _patch_system_config_matches_desired || { _patch_system_set_error "system rollback transition preflight detected configuration drift"; return 2; }
        fi
        _patch_system_unit_transition_allowed "$current_enabled" "$current_active" || { _patch_system_set_error "system rollback transition preflight detected drift"; return 2; }
    fi
    _patch_system_write_state rollback_in_progress || { _patch_system_set_error "system rollback state cannot be written"; return 2; }
    if [ "$config_is_restored" -ne 0 ]; then
        if ! _patch_system_restore_config; then
            _patch_system_write_state rollback_failed >/dev/null 2>&1 || true
            _patch_system_set_error "system configuration rollback failed"
            return 2
        fi
    fi
    if [ "$unit_is_restored" -ne 0 ]; then
        if ! _patch_system_unit_action restore "$PATCH_SYSTEM_UNIT" "$PATCH_SYSTEM_UNIT_BEFORE_ENABLED" "$PATCH_SYSTEM_UNIT_BEFORE_ACTIVE"; then
            _patch_system_write_state rollback_failed >/dev/null 2>&1 || true
            _patch_system_set_error "system unit rollback failed"
            return 2
        fi
    fi
    _patch_system_unit_query_into "$PATCH_SYSTEM_UNIT" current_enabled current_active && \
        _patch_system_config_matches_restored && \
        _patch_system_unit_matches_before "$current_enabled" "$current_active" || {
            _patch_system_write_state rollback_failed >/dev/null 2>&1 || true
            _patch_system_set_error "system rollback verification failed"
            return 2
        }
    _patch_system_write_state rolled_back || { _patch_system_set_error "system rolled-back state cannot be written"; return 2; }
}

patch_system_rollback() {
    _patch_system_rollback_loaded transition
}

patch_system_rollback_transaction() {
    local requested_root="$1"
    local transaction_directory="$2"
    local mode="${3:-strict}"

    case "$mode" in strict|transition) ;; *) _patch_system_set_error "system rollback mode is invalid"; return 2 ;; esac
    patch_system_load_transaction "$requested_root" "$transaction_directory" || return 2
    _patch_system_rollback_loaded "$mode"
}

patch_system_apply() {
    local rollback_status=0

    [ "${EUID:-$(id -u)}" -eq 0 ] || { _patch_system_set_error "system apply requires effective UID 0"; return 2; }
    [ "$PATCH_SYSTEM_PLAN_VALID" -eq 1 ] && [ "$PATCH_SYSTEM_STATE" = planned ] || return 2
    case "$PATCH_SYSTEM_CRITERION" in U-65|U-66) ;; U-64) return 3 ;; *) return 1 ;; esac
    _patch_system_config_matches_before || { _patch_system_set_error "system apply preflight detected configuration drift"; return 2; }
    _patch_system_native_validate pre || { _patch_system_set_error "$PATCH_SYSTEM_CRITERION native preflight failed"; return 2; }
    PATCH_SYSTEM_APPLY_STARTED=1
    _patch_system_write_state applying || { _patch_system_set_error "$PATCH_SYSTEM_CRITERION applying state cannot be written"; return 2; }
    if [ "$PATCH_SYSTEM_CONFIG_CHANGED" -eq 1 ]; then
        _patch_system_install_file "$PATCH_SYSTEM_CONFIG_PAYLOAD_PATH" "$PATCH_SYSTEM_CONFIG_PHYSICAL_PATH" || {
            patch_system_rollback >/dev/null 2>&1 || rollback_status=$?
            _patch_system_set_error "$PATCH_SYSTEM_CRITERION configuration installation failed"
            return 2
        }
    fi
    if ! _patch_system_unit_action enable_start "$PATCH_SYSTEM_UNIT" \
        "$PATCH_SYSTEM_UNIT_BEFORE_ENABLED" "$PATCH_SYSTEM_UNIT_BEFORE_ACTIVE"; then
        patch_system_rollback >/dev/null 2>&1 || rollback_status=$?
        _patch_system_set_error "$PATCH_SYSTEM_CRITERION unit activation failed; rollback_status=$rollback_status"
        return 2
    fi
    if ! _patch_system_write_state applied; then
        patch_system_rollback >/dev/null 2>&1 || rollback_status=$?
        _patch_system_set_error "$PATCH_SYSTEM_CRITERION applied state cannot be written; rollback_status=$rollback_status"
        return 2
    fi
    if ! patch_system_verify; then
        local verification_error="$PATCH_SYSTEM_ERROR_DETAIL"
        patch_system_rollback >/dev/null 2>&1 || rollback_status=$?
        _patch_system_set_error "$verification_error; rollback_status=$rollback_status"
        return 2
    fi
}

validate_u65_time_synchronization_v2() {
    [ "$PATCH_SYSTEM_CRITERION" = U-65 ] && [ "$PATCH_SYSTEM_STATE" = verified ] && \
        [ "$PATCH_SYSTEM_PLAN_VALID" -eq 1 ]
}

validate_u66_logging_policy_v2() {
    [ "$PATCH_SYSTEM_CRITERION" = U-66 ] && [ "$PATCH_SYSTEM_STATE" = verified ] && \
        [ "$PATCH_SYSTEM_PLAN_VALID" -eq 1 ]
}

_patch_system_evidence_file_trusted() {
    local path="$1"
    local parent="${path%/*}"
    local device="" inode="" owner_uid="" owner_gid="" mode="" links="" size="" mtime="" ctime=""

    case "$path" in /*) ;; *) return 2 ;; esac
    [ -f "$path" ] && [ ! -L "$path" ] && [ -r "$path" ] || return 2
    _patch_system_root_chain_trusted "$parent" yes || return 2
    _patch_system_stat_into "$path" device inode owner_uid owner_gid mode links size mtime ctime || return 2
    [ "$owner_uid" = 0 ] && [ "$links" = 1 ] && [ $((8#$mode & 0022)) -eq 0 ]
}

patch_system_u64_plan() {
    local requested_root="$1"
    local transaction_directory="$2"
    local manager="$3"
    local repository_evidence="$4"
    local repository_signature="$5"
    local advisory_evidence="$6"
    local advisory_signature="$7"
    local snapshot_token="$8"
    local rollback_token="$9"
    local verifier="${PATCH_SYSTEM_CALLBACKS[signature_verifier]:-}"
    local snapshot_verifier="${PATCH_SYSTEM_CALLBACKS[snapshot_verifier]:-}"
    local simulator="${PATCH_SYSTEM_CALLBACKS[package_simulator]:-}"
    local simulation_content=""
    local repository_fingerprint_before="" repository_fingerprint_after=""
    local repository_signature_fingerprint_before="" repository_signature_fingerprint_after=""
    local advisory_fingerprint_before="" advisory_fingerprint_after=""
    local advisory_signature_fingerprint_before="" advisory_signature_fingerprint_after=""
    local root_device_before="" root_inode_before="" root_uid_before="" root_gid_before=""
    local root_mode_before="" root_links_before="" root_size_before="" root_mtime_before="" root_ctime_before=""
    local root_device_after="" root_inode_after="" root_uid_after="" root_gid_after=""
    local root_mode_after="" root_links_after="" root_size_after="" root_mtime_after="" root_ctime_after=""

    patch_system_reset
    case "$manager" in apt|dnf|dnf5) ;; *) _patch_system_set_error "unsupported U-64 package manager"; return 1 ;; esac
    _patch_system_safe_token "$snapshot_token" && _patch_system_safe_token "$rollback_token" || { _patch_system_set_error "U-64 immutable snapshot or rollback token is invalid"; return 2; }
    [ -n "$verifier" ] && [ -n "$snapshot_verifier" ] && [ -n "$simulator" ] || { _patch_system_set_error "U-64 trusted verifier, snapshot, and simulator callbacks are required"; return 2; }
    _patch_system_callback_trusted "$verifier" && _patch_system_callback_trusted "$snapshot_verifier" && \
        _patch_system_callback_trusted "$simulator" || { _patch_system_set_error "U-64 callback trust validation failed"; return 2; }
    _patch_system_evidence_file_trusted "$repository_evidence" && _patch_system_evidence_file_trusted "$repository_signature" && \
        _patch_system_evidence_file_trusted "$advisory_evidence" && _patch_system_evidence_file_trusted "$advisory_signature" || { _patch_system_set_error "U-64 signed evidence paths are untrusted"; return 2; }
    _patch_system_file_fingerprint_into "$repository_evidence" repository_fingerprint_before || return 2
    PATCH_SYSTEM_REPOSITORY_DIGEST="$PATCH_SYSTEM_CAPTURE_SHA256"
    _patch_system_file_fingerprint_into "$repository_signature" repository_signature_fingerprint_before || return 2
    _patch_system_file_fingerprint_into "$advisory_evidence" advisory_fingerprint_before || return 2
    PATCH_SYSTEM_ADVISORY_DIGEST="$PATCH_SYSTEM_CAPTURE_SHA256"
    _patch_system_file_fingerprint_into "$advisory_signature" advisory_signature_fingerprint_before || return 2
    "$verifier" repository "$repository_evidence" "$repository_signature" || { _patch_system_set_error "U-64 repository signature verification failed"; return 2; }
    "$verifier" advisory "$advisory_evidence" "$advisory_signature" || { _patch_system_set_error "U-64 advisory signature verification failed"; return 2; }
    _patch_system_initialize_root "$requested_root" || { _patch_system_set_error "U-64 root is unsafe"; return 2; }
    _patch_system_stat_into "$PATCH_SYSTEM_ROOT" root_device_before root_inode_before root_uid_before \
        root_gid_before root_mode_before root_links_before root_size_before root_mtime_before root_ctime_before || return 2
    printf '%s\0%s\0' "$snapshot_token" "$rollback_token" | \
        "$snapshot_verifier" "$PATCH_SYSTEM_ROOT" || { _patch_system_set_error "U-64 snapshot or rollback token verification failed"; return 2; }
    _patch_system_prepare_transaction "$transaction_directory" || { _patch_system_set_error "U-64 transaction directory is unsafe"; return 2; }
    PATCH_SYSTEM_CRITERION=U-64
    PATCH_SYSTEM_PACKAGE_MANAGER="$manager"
    PATCH_SYSTEM_REPOSITORY_EVIDENCE="$repository_evidence"
    PATCH_SYSTEM_ADVISORY_EVIDENCE="$advisory_evidence"
    _patch_system_string_sha256_into "$snapshot_token" PATCH_SYSTEM_SNAPSHOT_TOKEN_DIGEST || return 2
    _patch_system_string_sha256_into "$rollback_token" PATCH_SYSTEM_ROLLBACK_TOKEN_DIGEST || return 2
    PATCH_SYSTEM_SIMULATION_PATH="$PATCH_SYSTEM_DATA_DIRECTORY/simulation.txt"
    [ ! -e "$PATCH_SYSTEM_SIMULATION_PATH" ] || return 2
    (umask 077; "$simulator" "$manager" "$PATCH_SYSTEM_ROOT" "$repository_evidence" \
        "$advisory_evidence" > "$PATCH_SYSTEM_SIMULATION_PATH") || { _patch_system_set_error "U-64 package simulation failed"; return 2; }
    /bin/chmod 0600 "$PATCH_SYSTEM_SIMULATION_PATH" || return 2
    [ -s "$PATCH_SYSTEM_SIMULATION_PATH" ] || { _patch_system_set_error "U-64 package simulation is empty"; return 2; }
    [ "$(wc -c < "$PATCH_SYSTEM_SIMULATION_PATH")" -le 1048576 ] || { _patch_system_set_error "U-64 package simulation exceeds limit"; return 2; }
    _patch_system_content_may_contain_secret "$PATCH_SYSTEM_SIMULATION_PATH" && { _patch_system_set_error "U-64 package simulation contains secret-like fields"; return 2; }
    _patch_system_capture_file "$PATCH_SYSTEM_SIMULATION_PATH" || return 2
    PATCH_SYSTEM_SIMULATION_DIGEST="$PATCH_SYSTEM_CAPTURE_SHA256"
    _patch_system_file_fingerprint_into "$repository_evidence" repository_fingerprint_after || return 2
    _patch_system_file_fingerprint_into "$repository_signature" repository_signature_fingerprint_after || return 2
    _patch_system_file_fingerprint_into "$advisory_evidence" advisory_fingerprint_after || return 2
    _patch_system_file_fingerprint_into "$advisory_signature" advisory_signature_fingerprint_after || return 2
    [ "$repository_fingerprint_before" = "$repository_fingerprint_after" ] && \
        [ "$repository_signature_fingerprint_before" = "$repository_signature_fingerprint_after" ] && \
        [ "$advisory_fingerprint_before" = "$advisory_fingerprint_after" ] && \
        [ "$advisory_signature_fingerprint_before" = "$advisory_signature_fingerprint_after" ] || { _patch_system_set_error "U-64 signed evidence changed during simulation"; return 2; }
    _patch_system_stat_into "$PATCH_SYSTEM_ROOT" root_device_after root_inode_after root_uid_after \
        root_gid_after root_mode_after root_links_after root_size_after root_mtime_after root_ctime_after || return 2
    [ "$root_device_before:$root_inode_before" = "$root_device_after:$root_inode_after" ] || { _patch_system_set_error "U-64 root identity changed during simulation"; return 2; }
    PATCH_SYSTEM_STATE=external_action_required
    PATCH_SYSTEM_PLAN_VALID=1
    printf -v simulation_content '%s\n1\tU-64\texternal_action_required\tpackage_simulation\t-\t%s\t-\t-\t-\t-\t-\t-\t-\t%s\t%s\n' \
        "$PATCH_SYSTEM_PLAN_HEADER" "$manager" "$PATCH_SYSTEM_REPOSITORY_DIGEST" \
        "$PATCH_SYSTEM_SIMULATION_DIGEST"
    _patch_system_write_private "$PATCH_SYSTEM_DATA_DIRECTORY/plan.tsv" "$simulation_content" || return 2
}

patch_system_u64_external_request_into() {
    local destination_name="$1"
    local rendered_request=""

    _patch_system_valid_destination "$destination_name" || return 2
    [ "$PATCH_SYSTEM_CRITERION" = U-64 ] && [ "$PATCH_SYSTEM_STATE" = external_action_required ] && \
        [ "$PATCH_SYSTEM_PLAN_VALID" -eq 1 ] || return 2
    printf -v rendered_request 'state=external_action_required\nmanager=%s\nsimulation_path=%s\nsimulation_sha256=%s\nrepository_evidence_sha256=%s\nadvisory_evidence_sha256=%s\nsnapshot_token_sha256=%s\nrollback_token_sha256=%s' \
        "$PATCH_SYSTEM_PACKAGE_MANAGER" "$PATCH_SYSTEM_SIMULATION_PATH" "$PATCH_SYSTEM_SIMULATION_DIGEST" \
        "$PATCH_SYSTEM_REPOSITORY_DIGEST" "$PATCH_SYSTEM_ADVISORY_DIGEST" \
        "$PATCH_SYSTEM_SNAPSHOT_TOKEN_DIGEST" "$PATCH_SYSTEM_ROLLBACK_TOKEN_DIGEST"
    printf -v "$destination_name" '%s' "$rendered_request"
}

patch_system_u64_apply() {
    [ "$PATCH_SYSTEM_CRITERION" = U-64 ] && [ "$PATCH_SYSTEM_STATE" = external_action_required ] || return 2
    return 3
}

validate_u64_patch_management_v2() {
    [ "$PATCH_SYSTEM_CRITERION" = U-64 ] && [ "$PATCH_SYSTEM_STATE" = external_action_required ] && \
        [ "$PATCH_SYSTEM_PLAN_VALID" -eq 1 ]
}

patch_system_u67_delegate_into() {
    local destination_name="$1"

    _patch_system_valid_destination "$destination_name" || return 2
    printf -v "$destination_name" '%s' metadata.u67.v1
}

validate_u67_log_metadata_v2() {
    local delegate=""

    patch_system_u67_delegate_into delegate || return 2
    [ "$delegate" = metadata.u67.v1 ]
}
