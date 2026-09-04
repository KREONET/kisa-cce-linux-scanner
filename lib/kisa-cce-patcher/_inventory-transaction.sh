# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash
# shellcheck disable=SC2034

# Applies high-impact inventory decisions only when complete evidence is bound to the plan.

if ! declare -F _patch_filesystem_capture_target >/dev/null 2>&1; then
    case "${BASH_SOURCE[0]}" in
        */*) __kisa_inventory_source_directory="${BASH_SOURCE[0]%/*}" ;;
        *) __kisa_inventory_source_directory=. ;;
    esac
    # shellcheck source=_filesystem-transaction.sh
    . "$__kisa_inventory_source_directory/_filesystem-transaction.sh"
    unset __kisa_inventory_source_directory
fi

PATCH_INVENTORY_HEADER=$'criterion\tobject_type\tpath\tdecision\tvalue\tprovenance\tapproval_id'
PATCH_INVENTORY_EVIDENCE_HEADER=$'schema\tsnapshot_id\troot_device\troot_inode\tfilesystem\tmounts\tnss\tinventory_sha256'
PATCH_INVENTORY_MANIFEST_HEADER=$'schema\tcriterion\tobject_type\tpath\tdecision\tvalue\tprovenance\tapproval_id\troot_device\troot_inode\tinventory_sha256\tbefore_state\tdevice\tinode\tuid\tgid\tmode\tlinks\tsize\tmtime\tctime\tsha256\tdesired_uid\tdesired_gid\tdesired_mode\tdesired_sha256\tdestination\tbackup\tpayload\txattr_state'
PATCH_INVENTORY_JOURNAL_HEADER=$'schema\tindex\tpath\tcurrent_path\tdevice\tinode\tuid\tgid\tmode\tlinks\tsize\tmtime\tctime\tsha256'

PATCH_INVENTORY_ERROR_DETAIL=""
PATCH_INVENTORY_PREREQUISITE=unresolved
PATCH_INVENTORY_ROOT=""
PATCH_INVENTORY_ROOT_DEVICE=""
PATCH_INVENTORY_ROOT_INODE=""
PATCH_INVENTORY_TRANSACTION_DIRECTORY=""
PATCH_INVENTORY_DATA_DIRECTORY=""
PATCH_INVENTORY_INVENTORY_SHA256=""
PATCH_INVENTORY_EVIDENCE_SHA256=""
PATCH_INVENTORY_SNAPSHOT_ID=""
PATCH_INVENTORY_PLAN_VALID=0
PATCH_INVENTORY_VERIFIED=0
PATCH_INVENTORY_CHANGE_COUNT=0
PATCH_INVENTORY_COMPLIANT_COUNT=0
PATCH_INVENTORY_MANIFEST_DEVICE=""
PATCH_INVENTORY_MANIFEST_INODE=""
PATCH_INVENTORY_MANIFEST_SHA256=""

declare -A PATCH_INVENTORY_CALLBACKS=()
declare -A PATCH_INVENTORY_SELECTED_CRITERIA=()
declare -A PATCH_INVENTORY_EXPECTED_KEYS=()
declare -A PATCH_INVENTORY_ACTUAL_KEYS=()
declare -A PATCH_INVENTORY_UIDS=()
declare -A PATCH_INVENTORY_GIDS=()

PATCH_INVENTORY_CRITERIA=()
PATCH_INVENTORY_TYPES=()
PATCH_INVENTORY_PATHS=()
PATCH_INVENTORY_DECISIONS=()
PATCH_INVENTORY_VALUES=()
PATCH_INVENTORY_PROVENANCE=()
PATCH_INVENTORY_APPROVALS=()
PATCH_INVENTORY_PHYSICAL_PATHS=()
PATCH_INVENTORY_CURRENT_PATHS=()
PATCH_INVENTORY_DESTINATIONS=()
PATCH_INVENTORY_BEFORE_STATES=()
PATCH_INVENTORY_BEFORE_DEVICES=()
PATCH_INVENTORY_BEFORE_INODES=()
PATCH_INVENTORY_BEFORE_UIDS=()
PATCH_INVENTORY_BEFORE_GIDS=()
PATCH_INVENTORY_BEFORE_MODES=()
PATCH_INVENTORY_BEFORE_LINKS=()
PATCH_INVENTORY_BEFORE_SIZES=()
PATCH_INVENTORY_BEFORE_MTIMES=()
PATCH_INVENTORY_BEFORE_CTIMES=()
PATCH_INVENTORY_BEFORE_SHA256S=()
PATCH_INVENTORY_DESIRED_UIDS=()
PATCH_INVENTORY_DESIRED_GIDS=()
PATCH_INVENTORY_DESIRED_MODES=()
PATCH_INVENTORY_DESIRED_SHA256S=()
PATCH_INVENTORY_BACKUPS=()
PATCH_INVENTORY_PAYLOADS=()
PATCH_INVENTORY_XATTR_STATES=()
PATCH_INVENTORY_STATES=()
PATCH_INVENTORY_AFTER_PATHS=()
PATCH_INVENTORY_AFTER_DEVICES=()
PATCH_INVENTORY_AFTER_INODES=()
PATCH_INVENTORY_AFTER_UIDS=()
PATCH_INVENTORY_AFTER_GIDS=()
PATCH_INVENTORY_AFTER_MODES=()
PATCH_INVENTORY_AFTER_LINKS=()
PATCH_INVENTORY_AFTER_SIZES=()
PATCH_INVENTORY_AFTER_MTIMES=()
PATCH_INVENTORY_AFTER_CTIMES=()
PATCH_INVENTORY_AFTER_SHA256S=()
PATCH_INVENTORY_APPLIED=()

_patch_inventory_error() { PATCH_INVENTORY_ERROR_DETAIL="$1"; PATCH_INVENTORY_PLAN_VALID=0; return 2; }
_patch_inventory_prerequisite() { PATCH_INVENTORY_PREREQUISITE="$1"; PATCH_INVENTORY_ERROR_DETAIL="prerequisite not satisfied: $1"; return 3; }
_patch_inventory_valid_criterion() { case "$1" in U-14|U-15|U-23|U-26|U-30|U-33) ;; *) return 1 ;; esac; }

patch_inventory_supported_criteria() { printf '%s\n' U-14 U-15 U-23 U-26 U-30 U-33; }

_patch_inventory_safe_token() {
    [ -n "$1" ] && [ "${#1}" -le 512 ] || return 1
    case "$1" in *[!A-Za-z0-9._:@,+/%=-]*) return 1 ;; *) return 0 ;; esac
}

patch_inventory_register_callback() {
    local name="$1"
    local path="$2"

    case "$name" in root_path_runtime|umask_native) ;; *) return 1 ;; esac
    [ -z "${PATCH_INVENTORY_CALLBACKS[$name]+present}" ] || return 2
    _patch_filesystem_callback_is_trusted "$path" || return 2
    PATCH_INVENTORY_CALLBACKS["$name"]="$path"
}

patch_inventory_reset() {
    patch_filesystem_reset
    PATCH_INVENTORY_ERROR_DETAIL=""
    PATCH_INVENTORY_PREREQUISITE=unresolved
    PATCH_INVENTORY_ROOT=""
    PATCH_INVENTORY_ROOT_DEVICE=""
    PATCH_INVENTORY_ROOT_INODE=""
    PATCH_INVENTORY_TRANSACTION_DIRECTORY=""
    PATCH_INVENTORY_DATA_DIRECTORY=""
    PATCH_INVENTORY_INVENTORY_SHA256=""
    PATCH_INVENTORY_EVIDENCE_SHA256=""
    PATCH_INVENTORY_SNAPSHOT_ID=""
    PATCH_INVENTORY_PLAN_VALID=0
    PATCH_INVENTORY_VERIFIED=0
    PATCH_INVENTORY_CHANGE_COUNT=0
    PATCH_INVENTORY_COMPLIANT_COUNT=0
    PATCH_INVENTORY_MANIFEST_DEVICE=""
    PATCH_INVENTORY_MANIFEST_INODE=""
    PATCH_INVENTORY_MANIFEST_SHA256=""
    PATCH_INVENTORY_SELECTED_CRITERIA=()
    PATCH_INVENTORY_EXPECTED_KEYS=()
    PATCH_INVENTORY_ACTUAL_KEYS=()
    PATCH_INVENTORY_UIDS=()
    PATCH_INVENTORY_GIDS=()
    PATCH_INVENTORY_CRITERIA=()
    PATCH_INVENTORY_TYPES=()
    PATCH_INVENTORY_PATHS=()
    PATCH_INVENTORY_DECISIONS=()
    PATCH_INVENTORY_VALUES=()
    PATCH_INVENTORY_PROVENANCE=()
    PATCH_INVENTORY_APPROVALS=()
    PATCH_INVENTORY_PHYSICAL_PATHS=()
    PATCH_INVENTORY_CURRENT_PATHS=()
    PATCH_INVENTORY_DESTINATIONS=()
    PATCH_INVENTORY_BEFORE_STATES=()
    PATCH_INVENTORY_BEFORE_DEVICES=()
    PATCH_INVENTORY_BEFORE_INODES=()
    PATCH_INVENTORY_BEFORE_UIDS=()
    PATCH_INVENTORY_BEFORE_GIDS=()
    PATCH_INVENTORY_BEFORE_MODES=()
    PATCH_INVENTORY_BEFORE_LINKS=()
    PATCH_INVENTORY_BEFORE_SIZES=()
    PATCH_INVENTORY_BEFORE_MTIMES=()
    PATCH_INVENTORY_BEFORE_CTIMES=()
    PATCH_INVENTORY_BEFORE_SHA256S=()
    PATCH_INVENTORY_DESIRED_UIDS=()
    PATCH_INVENTORY_DESIRED_GIDS=()
    PATCH_INVENTORY_DESIRED_MODES=()
    PATCH_INVENTORY_DESIRED_SHA256S=()
    PATCH_INVENTORY_BACKUPS=()
    PATCH_INVENTORY_PAYLOADS=()
    PATCH_INVENTORY_XATTR_STATES=()
    PATCH_INVENTORY_STATES=()
    PATCH_INVENTORY_AFTER_PATHS=()
    PATCH_INVENTORY_AFTER_DEVICES=()
    PATCH_INVENTORY_AFTER_INODES=()
    PATCH_INVENTORY_AFTER_UIDS=()
    PATCH_INVENTORY_AFTER_GIDS=()
    PATCH_INVENTORY_AFTER_MODES=()
    PATCH_INVENTORY_AFTER_LINKS=()
    PATCH_INVENTORY_AFTER_SIZES=()
    PATCH_INVENTORY_AFTER_MTIMES=()
    PATCH_INVENTORY_AFTER_CTIMES=()
    PATCH_INVENTORY_AFTER_SHA256S=()
    PATCH_INVENTORY_APPLIED=()
}

_patch_inventory_load_identities() {
    local file=""
    local name=""
    local unused=""
    local identifier=""
    local records=0

    file="$PATCH_INVENTORY_ROOT/etc/passwd"
    [ -f "$file" ] && [ ! -L "$file" ] || return 2
    while IFS=: read -r name unused identifier _; do
        [ -n "$name" ] && [ -n "$identifier" ] || return 2
        case "$identifier" in *[!0-9]*) return 2 ;; esac
        PATCH_INVENTORY_UIDS["$identifier"]=1
        records=$((records + 1))
    done < "$file"
    [ "$records" -gt 0 ] || return 2
    records=0
    file="$PATCH_INVENTORY_ROOT/etc/group"
    [ -f "$file" ] && [ ! -L "$file" ] || return 2
    while IFS=: read -r name unused identifier _; do
        [ -n "$name" ] && [ -n "$identifier" ] || return 2
        case "$identifier" in *[!0-9]*) return 2 ;; esac
        PATCH_INVENTORY_GIDS["$identifier"]=1
        records=$((records + 1))
    done < "$file"
    [ "$records" -gt 0 ]
}

_patch_inventory_file_sha256_into() {
    _patch_configuration_sha256_into "$1" "$2"
}

_patch_inventory_validate_evidence() {
    local evidence_path="$1"
    local inventory_path="$2"
    local header=""
    local schema=""
    local snapshot_id=""
    local root_device=""
    local root_inode=""
    local filesystem=""
    local mounts=""
    local nss=""
    local inventory_sha256=""
    local extra=""
    local actual_sha256=""

    _patch_configuration_capture_file "$inventory_path" || return 2
    PATCH_INVENTORY_INVENTORY_SHA256="$PATCH_CONFIGURATION_CAPTURE_SHA256"
    _patch_configuration_capture_file "$evidence_path" || return 2
    PATCH_INVENTORY_EVIDENCE_SHA256="$PATCH_CONFIGURATION_CAPTURE_SHA256"
    {
        IFS= read -r header || return 2
        IFS=$'\t' read -r schema snapshot_id root_device root_inode filesystem mounts nss \
            inventory_sha256 extra || return 2
    } < "$evidence_path"
    [ "$header" = "$PATCH_INVENTORY_EVIDENCE_HEADER" ] && [ "$schema" = 1 ] && [ -z "$extra" ] || return 2
    _patch_inventory_safe_token "$snapshot_id" || return 2
    [ "$filesystem:$mounts:$nss" = complete:complete:complete ] || return 3
    [ "$root_device:$root_inode" = "$PATCH_INVENTORY_ROOT_DEVICE:$PATCH_INVENTORY_ROOT_INODE" ] || return 2
    [ "$inventory_sha256" = "$PATCH_INVENTORY_INVENTORY_SHA256" ] || return 2
    _patch_inventory_file_sha256_into "$inventory_path" actual_sha256 || return 2
    [ "$actual_sha256" = "$inventory_sha256" ] || return 2
    PATCH_INVENTORY_SNAPSHOT_ID="$snapshot_id"
}

_patch_inventory_umask_valid() {
    local value="$1"
    local decimal=0

    case "$value" in ''|*[!0-7]*) return 1 ;; esac
    [ "${#value}" -le 4 ] || return 1
    decimal=$((8#$value))
    [ $((decimal & 0022)) -eq $((8#022)) ]
}

_patch_inventory_row_is_typed() {
    local criterion="$1" object_type="$2" logical_path="$3" decision="$4"
    local value="$5" provenance="$6" approval="$7"
    local destination=""

    _patch_inventory_valid_criterion "$criterion" || return 1
    _patch_filesystem_inventory_path_is_valid "$logical_path" || return 2
    _patch_inventory_safe_token "$provenance" || return 2
    case "$criterion:$object_type:$decision" in
        U-14:profile:set_root_path|U-14:file:set_root_path)
            [ "$logical_path" = /etc/profile.d/99-kisa-cce-root-path.sh ] || return 2
            case "$value" in /*:*|/*) ;; *) return 2 ;; esac
            ;;
        U-14:directory:trust_path_component) [ "$value" = - ] || return 2 ;;
        U-15:file:set_owner|U-15:directory:set_owner)
            case "$value" in *:*:*) return 2 ;; [0-9]*:[0-9]*) ;; *) return 2 ;; esac
            [ -n "${PATCH_INVENTORY_UIDS[${value%%:*}]+present}" ] &&
                [ -n "${PATCH_INVENTORY_GIDS[${value#*:}]+present}" ] || return 2
            ;;
        U-23:file:keep_privileged)
            [ "$value" = preserve ] || return 2
            case "$provenance" in package:*|content:sha256:*) ;; *) return 2 ;; esac
            ;;
        U-23:file:remove_privileged_bits)
            [ "$value" = 06000 ] || return 2
            case "$provenance" in package:*|content:sha256:*) ;; *) return 2 ;; esac
            ;;
        U-26:file:quarantine|U-33:file:quarantine|U-33:directory:quarantine)
            _patch_filesystem_inventory_path_is_valid "$value" || return 2
            destination="$value"
            case "$criterion:$destination" in
                U-26:/dev/kisa-cce-quarantine/*|U-26:/var/lib/kisa-cce-quarantine/*|\
                U-33:/var/lib/kisa-cce-quarantine/*|U-33:*/kisa-cce-quarantine/*) ;;
                *) return 2 ;;
            esac
            case "$provenance" in package:*|content:sha256:*) ;; *) return 2 ;; esac
            ;;
        U-30:file:set_umask)
            _patch_inventory_umask_valid "$value" || return 2
            case "$provenance" in subsystem:shell|subsystem:login_defs|subsystem:pam|subsystem:ftp-vsftpd|subsystem:ftp-proftpd) ;;
                *) return 2 ;;
            esac
            case "$provenance:$logical_path" in
                subsystem:shell:/etc/profile.d/99-kisa-cce-umask.sh|\
                subsystem:login_defs:/etc/login.defs.d/99-kisa-cce-umask.defs|\
                subsystem:pam:/etc/pam.d/99-kisa-cce-umask|\
                subsystem:ftp-vsftpd:/etc/vsftpd.conf.d/99-kisa-cce-umask.conf|\
                subsystem:ftp-proftpd:/etc/proftpd/conf.d/99-kisa-cce-umask.conf) ;;
                *) return 2 ;;
            esac
            ;;
        U-33:file:keep|U-33:directory:keep)
            [ "$value" = preserve ] || return 2
            case "$provenance" in package:*|content:sha256:*) ;; *) return 2 ;; esac
            ;;
        *) return 2 ;;
    esac
    case "$decision" in
        trust_path_component|keep_privileged|keep) [ "$approval" != - ] || return 2 ;;
        *) [ "$approval" != - ] || return 2 ;;
    esac
    _patch_inventory_safe_token "$approval"
}

_patch_inventory_load() {
    local path="$1"
    local header=""
    local criterion="" object_type="" logical_path="" decision="" value="" provenance="" approval="" extra=""
    local key=""

    IFS= read -r header < "$path" || return 2
    [ "$header" = "$PATCH_INVENTORY_HEADER" ] || return 2
    while IFS=$'\t' read -r criterion object_type logical_path decision value provenance approval extra; do
        [ -n "$criterion" ] || continue
        [ -z "$extra" ] || return 2
        _patch_inventory_row_is_typed "$criterion" "$object_type" "$logical_path" "$decision" \
            "$value" "$provenance" "$approval" || return $?
        key="$criterion|$object_type|$logical_path"
        [ -z "${PATCH_INVENTORY_ACTUAL_KEYS[$key]+present}" ] || return 2
        PATCH_INVENTORY_ACTUAL_KEYS["$key"]="${#PATCH_INVENTORY_PATHS[@]}"
        PATCH_INVENTORY_SELECTED_CRITERIA["$criterion"]=1
        PATCH_INVENTORY_CRITERIA+=("$criterion")
        PATCH_INVENTORY_TYPES+=("$object_type")
        PATCH_INVENTORY_PATHS+=("$logical_path")
        PATCH_INVENTORY_DECISIONS+=("$decision")
        PATCH_INVENTORY_VALUES+=("$value")
        PATCH_INVENTORY_PROVENANCE+=("$provenance")
        PATCH_INVENTORY_APPROVALS+=("$approval")
    done < <(sed -n '2,$p' "$path")
    [ "${#PATCH_INVENTORY_PATHS[@]}" -gt 0 ]
}

_patch_inventory_expected_add() {
    PATCH_INVENTORY_EXPECTED_KEYS["$1|$2|$3"]=1
}

_patch_inventory_enumerate_full() {
    local list=""
    local physical=""
    local logical=""
    local object_type=""
    local uid=""
    local gid=""
    local mode=""
    local basename=""
    local decimal=0

    list="$(umask 077; /usr/bin/mktemp "${TMPDIR:-/tmp}/kisa-cce-inventory-scan.XXXXXXXX")" || return 2
    if ! /usr/bin/find -P "$PATCH_INVENTORY_ROOT" -xdev -printf '%p\0%y\0%U\0%G\0%m\0' \
        > "$list" 2>/dev/null; then
        /bin/rm -f "$list"
        return 2
    fi
    while IFS= read -r -d '' physical; do
        IFS= read -r -d '' object_type || return 2
        IFS= read -r -d '' uid || return 2
        IFS= read -r -d '' gid || return 2
        IFS= read -r -d '' mode || return 2
        [ "$physical" != "$PATCH_INVENTORY_ROOT" ] || continue
        _patch_filesystem_logical_from_physical_into "$physical" logical || return 2
        decimal=$((8#$mode))
        if [ -n "${PATCH_INVENTORY_SELECTED_CRITERIA[U-15]+present}" ] &&
            { [ -z "${PATCH_INVENTORY_UIDS[$uid]+present}" ] ||
              [ -z "${PATCH_INVENTORY_GIDS[$gid]+present}" ]; }; then
            case "$object_type" in f) object_type="file" ;; d) object_type="directory" ;; *) continue ;; esac
            _patch_inventory_expected_add U-15 "$object_type" "$logical"
        fi
        if [ -n "${PATCH_INVENTORY_SELECTED_CRITERIA[U-23]+present}" ] &&
            [ "$object_type" = f ] && [ "$uid" = 0 ] && [ $((decimal & 06000)) -ne 0 ]; then
            _patch_inventory_expected_add U-23 file "$logical"
        fi
        if [ -n "${PATCH_INVENTORY_SELECTED_CRITERIA[U-33]+present}" ]; then
            basename="${logical##*/}"
            case "$basename" in
                .|..) ;;
                .*)
                    case "$object_type" in
                        f) _patch_inventory_expected_add U-33 file "$logical" ;;
                        d) _patch_inventory_expected_add U-33 directory "$logical" ;;
                    esac
                    ;;
            esac
        fi
    done < "$list"
    /bin/rm -f "$list"
}

_patch_inventory_enumerate_u26() {
    local device="$PATCH_INVENTORY_ROOT/dev"
    local list=""
    local physical=""
    local logical=""

    [ -d "$device" ] && [ ! -L "$device" ] || return 2
    list="$(umask 077; /usr/bin/mktemp "${TMPDIR:-/tmp}/kisa-cce-u26-scan.XXXXXXXX")" || return 2
    if ! /usr/bin/find -P "$device" -xdev \
        \( -path "$device/shm" -o -path "$device/mqueue" \) -prune -o -type f -print0 \
        > "$list" 2>/dev/null; then
        /bin/rm -f "$list"
        return 2
    fi
    while IFS= read -r -d '' physical; do
        _patch_filesystem_logical_from_physical_into "$physical" logical || return 2
        _patch_inventory_expected_add U-26 file "$logical"
    done < "$list"
    /bin/rm -f "$list"
}

_patch_inventory_admit_evidenced_mount_targets() {
    local index=0 criterion="" object_type="" logical="" resolved="" physical="" decimal=0 basename=""

    while [ "$index" -lt "${#PATCH_INVENTORY_PATHS[@]}" ]; do
        criterion="${PATCH_INVENTORY_CRITERIA[$index]}"
        case "$criterion" in U-15|U-23|U-33) ;; *) index=$((index + 1)); continue ;; esac
        object_type="${PATCH_INVENTORY_TYPES[$index]}"
        logical="${PATCH_INVENTORY_PATHS[$index]}"
        _patch_filesystem_resolve_logical_into "$logical" "$object_type" resolved physical || return 2
        _patch_filesystem_capture_target "$physical" "$object_type" || return 2
        if [ "$PATCH_FILESYSTEM_CAPTURE_DEVICE" != "$PATCH_INVENTORY_ROOT_DEVICE" ]; then
            case "$criterion" in
                U-15)
                    [ -z "${PATCH_INVENTORY_UIDS[$PATCH_FILESYSTEM_CAPTURE_UID]+present}" ] ||
                        [ -z "${PATCH_INVENTORY_GIDS[$PATCH_FILESYSTEM_CAPTURE_GID]+present}" ] || return 2
                    ;;
                U-23)
                    [ "$object_type" = file ] && [ "$PATCH_FILESYSTEM_CAPTURE_UID" = 0 ] || return 2
                    decimal=$((8#$PATCH_FILESYSTEM_CAPTURE_MODE))
                    [ $((decimal & 06000)) -ne 0 ] || return 2
                    ;;
                U-33)
                    basename="${logical##*/}"
                    case "$basename" in .?*) ;; *) return 2 ;; esac
                    ;;
            esac
            _patch_inventory_expected_add "$criterion" "$object_type" "$logical"
        fi
        index=$((index + 1))
    done
}

_patch_inventory_enumerate_u14() {
    local profile_key='U-14|profile|/etc/profile.d/99-kisa-cce-root-path.sh'
    local index=0
    local value=""
    local component=""
    local physical=""
    local resolved=""
    local -a _path_components=()

    [ -n "${PATCH_INVENTORY_ACTUAL_KEYS[$profile_key]+present}" ] || return 2
    index="${PATCH_INVENTORY_ACTUAL_KEYS[$profile_key]}"
    value="${PATCH_INVENTORY_VALUES[$index]}"
    _patch_inventory_expected_add U-14 profile /etc/profile.d/99-kisa-cce-root-path.sh
    IFS=: read -r -a _path_components <<< "$value"
    [ "${#_path_components[@]}" -gt 0 ] || return 2
    for component in "${_path_components[@]}"; do
        case "$component" in /*) ;; *) return 2 ;; esac
        case "$component" in *[!A-Za-z0-9_./+-]*) return 2 ;; esac
        _patch_filesystem_resolve_logical_into "$component" directory resolved physical || return 2
        [ "$resolved" = "$component" ] || return 2
        _patch_filesystem_capture_target "$physical" directory || return 2
        [ "$PATCH_FILESYSTEM_CAPTURE_UID" = 0 ] &&
            [ $((8#$PATCH_FILESYSTEM_CAPTURE_MODE & 0022)) -eq 0 ] || return 2
        _patch_inventory_expected_add U-14 directory "$component"
    done
}

_patch_inventory_enumerate_u30() {
    local index=0
    local subsystem=""
    local seen_shell=0 seen_login_defs=0 seen_pam=0 seen_ftp=0

    while [ "$index" -lt "${#PATCH_INVENTORY_PATHS[@]}" ]; do
        if [ "${PATCH_INVENTORY_CRITERIA[$index]}" = U-30 ]; then
            subsystem="${PATCH_INVENTORY_PROVENANCE[$index]}"
            case "$subsystem" in
                subsystem:shell) seen_shell=1 ;;
                subsystem:login_defs) seen_login_defs=1 ;;
                subsystem:pam) seen_pam=1 ;;
                subsystem:ftp-*) seen_ftp=1 ;;
            esac
            _patch_inventory_expected_add U-30 file "${PATCH_INVENTORY_PATHS[$index]}"
        fi
        index=$((index + 1))
    done
    [ "$seen_shell:$seen_login_defs:$seen_pam:$seen_ftp" = 1:1:1:1 ]
}

_patch_inventory_enumerate_expected() {
    PATCH_INVENTORY_EXPECTED_KEYS=()
    if [ -n "${PATCH_INVENTORY_SELECTED_CRITERIA[U-14]+present}" ]; then
        _patch_inventory_enumerate_u14 || return 2
    fi
    if [ -n "${PATCH_INVENTORY_SELECTED_CRITERIA[U-15]+present}" ] ||
        [ -n "${PATCH_INVENTORY_SELECTED_CRITERIA[U-23]+present}" ] ||
        [ -n "${PATCH_INVENTORY_SELECTED_CRITERIA[U-33]+present}" ]; then
        _patch_inventory_enumerate_full || return 2
        _patch_inventory_admit_evidenced_mount_targets || return 2
    fi
    if [ -n "${PATCH_INVENTORY_SELECTED_CRITERIA[U-26]+present}" ]; then
        _patch_inventory_enumerate_u26 || return 2
    fi
    if [ -n "${PATCH_INVENTORY_SELECTED_CRITERIA[U-30]+present}" ]; then
        _patch_inventory_enumerate_u30 || return 2
    fi
}

_patch_inventory_exact() {
    local key=""

    for key in "${!PATCH_INVENTORY_EXPECTED_KEYS[@]}"; do
        [ -n "${PATCH_INVENTORY_ACTUAL_KEYS[$key]+present}" ] || {
            PATCH_INVENTORY_ERROR_DETAIL="inventory is missing complete-scan target: $key"
            return 2
        }
    done
    for key in "${!PATCH_INVENTORY_ACTUAL_KEYS[@]}"; do
        [ -n "${PATCH_INVENTORY_EXPECTED_KEYS[$key]+present}" ] || {
            PATCH_INVENTORY_ERROR_DETAIL="inventory contains target outside complete-scan scope: $key"
            return 2
        }
    done
}

_patch_inventory_prepare_transaction() {
    local transaction="$1"
    local inventory="$2"
    local evidence="$3"
    local directory=""

    _patch_configuration_transaction_directory_is_safe "$transaction" || return 2
    PATCH_INVENTORY_TRANSACTION_DIRECTORY="$(CDPATH='' builtin cd -P -- "$transaction" && pwd -P)" || return 2
    PATCH_INVENTORY_DATA_DIRECTORY="$PATCH_INVENTORY_TRANSACTION_DIRECTORY/inventory"
    [ ! -e "$PATCH_INVENTORY_DATA_DIRECTORY" ] && [ ! -L "$PATCH_INVENTORY_DATA_DIRECTORY" ] || return 2
    (umask 077; /bin/mkdir "$PATCH_INVENTORY_DATA_DIRECTORY" \
        "$PATCH_INVENTORY_DATA_DIRECTORY/backups" "$PATCH_INVENTORY_DATA_DIRECTORY/payloads" \
        "$PATCH_INVENTORY_DATA_DIRECTORY/journal" "$PATCH_INVENTORY_DATA_DIRECTORY/xattrs") || return 2
    for directory in "$PATCH_INVENTORY_DATA_DIRECTORY" "$PATCH_INVENTORY_DATA_DIRECTORY/backups" \
        "$PATCH_INVENTORY_DATA_DIRECTORY/payloads" "$PATCH_INVENTORY_DATA_DIRECTORY/journal" \
        "$PATCH_INVENTORY_DATA_DIRECTORY/xattrs"; do
        _patch_configuration_private_directory_is_safe "$directory" || return 2
    done
    (umask 077; /bin/cp "$inventory" "$PATCH_INVENTORY_DATA_DIRECTORY/inventory.tsv") || return 2
    (umask 077; /bin/cp "$evidence" "$PATCH_INVENTORY_DATA_DIRECTORY/evidence.tsv") || return 2
    /bin/chmod 0600 "$PATCH_INVENTORY_DATA_DIRECTORY/inventory.tsv" \
        "$PATCH_INVENTORY_DATA_DIRECTORY/evidence.tsv" || return 2
}

_patch_inventory_desired_content() {
    local index="$1"
    local output="$2"
    local value="${PATCH_INVENTORY_VALUES[$index]}"
    local provenance="${PATCH_INVENTORY_PROVENANCE[$index]}"

    case "${PATCH_INVENTORY_DECISIONS[$index]}:$provenance" in
        set_root_path:*)
            printf '# Managed by kisa-cce-linux-scanner.\nPATH=%s\nreadonly PATH\nexport PATH\n' "$value" > "$output"
            ;;
        set_umask:subsystem:shell) printf '# Managed by kisa-cce-linux-scanner.\numask %s\n' "$value" > "$output" ;;
        set_umask:subsystem:login_defs) printf '# Managed by kisa-cce-linux-scanner.\nUMASK %s\n' "$value" > "$output" ;;
        set_umask:subsystem:pam) printf '# Managed by kisa-cce-linux-scanner.\nsession required pam_umask.so umask=%s\n' "$value" > "$output" ;;
        set_umask:subsystem:ftp-vsftpd) printf '# Managed by kisa-cce-linux-scanner.\nlocal_umask=%s\n' "$value" > "$output" ;;
        set_umask:subsystem:ftp-proftpd) printf '# Managed by kisa-cce-linux-scanner.\nUmask %s %s\n' "$value" "$value" > "$output" ;;
        *) return 2 ;;
    esac
}

_patch_inventory_capture_xattrs() {
    local index="$1"
    local path="$2"
    local output=""

    if [ -x /usr/bin/getfattr ] && [ -x /usr/bin/setfattr ]; then
        printf -v output '%s/xattrs/%06d.attrs' "$PATCH_INVENTORY_DATA_DIRECTORY" "$((index + 1))"
        /usr/bin/getfattr --absolute-names -d -m- "$path" > "$output" 2>/dev/null || return 2
        /bin/chmod 0600 "$output" || return 2
        PATCH_INVENTORY_XATTR_STATES[$index]=captured
    elif [ -x /usr/bin/getfattr ] || [ -x /usr/bin/setfattr ]; then
        return 2
    else
        PATCH_INVENTORY_XATTR_STATES[$index]=unavailable
    fi
}

_patch_inventory_restore_xattrs() {
    local index="$1"

    [ "${PATCH_INVENTORY_XATTR_STATES[$index]}" = captured ] || return 0
    /usr/bin/setfattr --restore="$PATCH_INVENTORY_DATA_DIRECTORY/xattrs/$(printf '%06d' "$((index + 1))").attrs"
}

_patch_inventory_resolve_parent() {
    local logical="$1"
    local parent_output_name="$2"
    local physical_output_name="$3"
    local parent_logical="${logical%/*}"
    local parent_physical=""
    local resolved_parent=""

    [ -n "$parent_logical" ] || parent_logical=/
    _patch_filesystem_resolve_logical_into "$parent_logical" directory resolved_parent parent_physical || return 2
    [ "$resolved_parent" = "$parent_logical" ] || return 2
    _patch_configuration_valid_destination "$parent_output_name" || return 2
    _patch_configuration_valid_destination "$physical_output_name" || return 2
    printf -v "$parent_output_name" '%s' "$parent_physical"
    printf -v "$physical_output_name" '%s' "${parent_physical%/}/${logical##*/}"
}

_patch_inventory_parent_chains_are_safe() {
    local index="$1"
    local logical="${PATCH_INVENTORY_PATHS[$index]}"

    _patch_filesystem_parent_chain_is_safe "$logical" - || return 2
    if [ "${PATCH_INVENTORY_DECISIONS[$index]}" = quarantine ]; then
        _patch_filesystem_parent_chain_is_safe "${PATCH_INVENTORY_DESTINATIONS[$index]}" - || return 2
    fi
}

_patch_inventory_snapshot_row() {
    local index="$1"
    local criterion="${PATCH_INVENTORY_CRITERIA[$index]}"
    local object_type="${PATCH_INVENTORY_TYPES[$index]}"
    local logical="${PATCH_INVENTORY_PATHS[$index]}"
    local decision="${PATCH_INVENTORY_DECISIONS[$index]}"
    local value="${PATCH_INVENTORY_VALUES[$index]}"
    local physical=""
    local resolved=""
    local parent=""
    local destination="-"
    local before_state=present
    local desired_uid=""
    local desired_gid=""
    local desired_mode=""
    local desired_sha=""
    local backup=-
    local payload=-
    local number=""
    local decimal=0
    local uid=""
    local gid=""
    local parent_destination=""
    local physical_destination=""
    local destination_device=""
    local _di="" _du="" _dg="" _dm="" _dl="" _ds="" _dt="" _dc=""

    printf -v number '%06d' "$((index + 1))"
    case "$object_type" in profile) object_type="file"; PATCH_INVENTORY_TYPES[$index]="file" ;; esac
    _patch_filesystem_parent_chain_is_safe "$logical" - || return 2
    if _patch_filesystem_resolve_logical_into "$logical" "$object_type" resolved physical; then
        [ "$resolved" = "$logical" ] || return 2
        _patch_filesystem_capture_target "$physical" "$object_type" || return 2
    else
        case "$decision" in set_root_path|set_umask) ;; *) return 2 ;; esac
        before_state=absent
        _patch_inventory_resolve_parent "$logical" parent physical || return 2
        PATCH_FILESYSTEM_CAPTURE_DEVICE=-
        PATCH_FILESYSTEM_CAPTURE_INODE=-
        PATCH_FILESYSTEM_CAPTURE_UID=-
        PATCH_FILESYSTEM_CAPTURE_GID=-
        PATCH_FILESYSTEM_CAPTURE_MODE=-
        PATCH_FILESYSTEM_CAPTURE_LINKS=-
        PATCH_FILESYSTEM_CAPTURE_SIZE=-
        PATCH_FILESYSTEM_CAPTURE_MTIME=-
        PATCH_FILESYSTEM_CAPTURE_CTIME=-
        PATCH_FILESYSTEM_CAPTURE_SHA256=-
    fi
    [ -n "$parent" ] || parent="${physical%/*}"
    PATCH_INVENTORY_PHYSICAL_PATHS[$index]="$physical"
    PATCH_INVENTORY_CURRENT_PATHS[$index]="$physical"
    PATCH_INVENTORY_BEFORE_STATES[$index]="$before_state"
    PATCH_INVENTORY_BEFORE_DEVICES[$index]="$PATCH_FILESYSTEM_CAPTURE_DEVICE"
    PATCH_INVENTORY_BEFORE_INODES[$index]="$PATCH_FILESYSTEM_CAPTURE_INODE"
    PATCH_INVENTORY_BEFORE_UIDS[$index]="$PATCH_FILESYSTEM_CAPTURE_UID"
    PATCH_INVENTORY_BEFORE_GIDS[$index]="$PATCH_FILESYSTEM_CAPTURE_GID"
    PATCH_INVENTORY_BEFORE_MODES[$index]="$PATCH_FILESYSTEM_CAPTURE_MODE"
    PATCH_INVENTORY_BEFORE_LINKS[$index]="$PATCH_FILESYSTEM_CAPTURE_LINKS"
    PATCH_INVENTORY_BEFORE_SIZES[$index]="$PATCH_FILESYSTEM_CAPTURE_SIZE"
    PATCH_INVENTORY_BEFORE_MTIMES[$index]="$PATCH_FILESYSTEM_CAPTURE_MTIME"
    PATCH_INVENTORY_BEFORE_CTIMES[$index]="$PATCH_FILESYSTEM_CAPTURE_CTIME"
    PATCH_INVENTORY_BEFORE_SHA256S[$index]="$PATCH_FILESYSTEM_CAPTURE_SHA256"
    if [ "$before_state" = present ]; then
        _patch_inventory_capture_xattrs "$index" "$physical" || return 2
        if [ "$object_type" = file ]; then
            backup="backups/$number"
            (umask 077; /bin/cp "$physical" "$PATCH_INVENTORY_DATA_DIRECTORY/$backup") || return 2
            /bin/chmod 0600 "$PATCH_INVENTORY_DATA_DIRECTORY/$backup" || return 2
        fi
    else
        PATCH_INVENTORY_XATTR_STATES[$index]=none
    fi

    desired_uid="$PATCH_FILESYSTEM_CAPTURE_UID"
    desired_gid="$PATCH_FILESYSTEM_CAPTURE_GID"
    desired_mode="$PATCH_FILESYSTEM_CAPTURE_MODE"
    desired_sha="$PATCH_FILESYSTEM_CAPTURE_SHA256"
    case "$decision" in
        trust_path_component|keep_privileged|keep) ;;
        set_owner)
            uid="${value%%:*}"
            gid="${value#*:}"
            desired_uid="$uid"
            desired_gid="$gid"
            ;;
        remove_privileged_bits)
            decimal=$((8#$desired_mode & ~06000 & 07777))
            printf -v desired_mode '%04o' "$decimal"
            ;;
        quarantine)
            destination="$value"
            _patch_filesystem_parent_chain_is_safe "$destination" - || return 2
            _patch_inventory_resolve_parent "$destination" parent_destination physical_destination || return 2
            [ ! -e "$physical_destination" ] && [ ! -L "$physical_destination" ] || return 2
            _patch_configuration_stat_into "$parent_destination" destination_device _di _du _dg _dm _dl _ds _dt _dc || return 2
            [ "$destination_device" = "$PATCH_FILESYSTEM_CAPTURE_DEVICE" ] || return 2
            ;;
        set_root_path|set_umask)
            desired_uid=0
            desired_gid=0
            if [ "$before_state" = present ]; then
                printf -v desired_mode '%04o' "$((8#$desired_mode & 0644))"
            else
                desired_mode=0644
            fi
            payload="payloads/$number"
            (umask 077; set -C; : > "$PATCH_INVENTORY_DATA_DIRECTORY/$payload") 2>/dev/null || return 2
            _patch_inventory_desired_content "$index" "$PATCH_INVENTORY_DATA_DIRECTORY/$payload" || return 2
            /bin/chmod 0600 "$PATCH_INVENTORY_DATA_DIRECTORY/$payload" || return 2
            _patch_inventory_file_sha256_into "$PATCH_INVENTORY_DATA_DIRECTORY/$payload" desired_sha || return 2
            ;;
        *) return 2 ;;
    esac
    PATCH_INVENTORY_DESTINATIONS[$index]="$destination"
    PATCH_INVENTORY_DESIRED_UIDS[$index]="$desired_uid"
    PATCH_INVENTORY_DESIRED_GIDS[$index]="$desired_gid"
    PATCH_INVENTORY_DESIRED_MODES[$index]="$desired_mode"
    PATCH_INVENTORY_DESIRED_SHA256S[$index]="$desired_sha"
    PATCH_INVENTORY_BACKUPS[$index]="$backup"
    PATCH_INVENTORY_PAYLOADS[$index]="$payload"
    if [ "$decision" = quarantine ] || [ "$before_state:$PATCH_FILESYSTEM_CAPTURE_UID:$PATCH_FILESYSTEM_CAPTURE_GID:$PATCH_FILESYSTEM_CAPTURE_MODE:$PATCH_FILESYSTEM_CAPTURE_SHA256" != \
        "present:$desired_uid:$desired_gid:$desired_mode:$desired_sha" ]; then
        PATCH_INVENTORY_STATES[$index]=ready
        PATCH_INVENTORY_CHANGE_COUNT=$((PATCH_INVENTORY_CHANGE_COUNT + 1))
    else
        PATCH_INVENTORY_STATES[$index]=compliant
        PATCH_INVENTORY_COMPLIANT_COUNT=$((PATCH_INVENTORY_COMPLIANT_COUNT + 1))
    fi
    PATCH_INVENTORY_AFTER_PATHS[$index]=""
    PATCH_INVENTORY_AFTER_DEVICES[$index]=""
    PATCH_INVENTORY_AFTER_INODES[$index]=""
    PATCH_INVENTORY_AFTER_UIDS[$index]=""
    PATCH_INVENTORY_AFTER_GIDS[$index]=""
    PATCH_INVENTORY_AFTER_MODES[$index]=""
    PATCH_INVENTORY_AFTER_LINKS[$index]=""
    PATCH_INVENTORY_AFTER_SIZES[$index]=""
    PATCH_INVENTORY_AFTER_MTIMES[$index]=""
    PATCH_INVENTORY_AFTER_CTIMES[$index]=""
    PATCH_INVENTORY_AFTER_SHA256S[$index]=""
    PATCH_INVENTORY_APPLIED[$index]=0
}

_patch_inventory_write_manifest() {
    local path="$PATCH_INVENTORY_DATA_DIRECTORY/manifest.tsv"
    local index=0

    [ ! -e "$path" ] && [ ! -L "$path" ] || return 2
    (umask 077; set -C; : > "$path") 2>/dev/null || return 2
    {
        printf '%s\n' "$PATCH_INVENTORY_MANIFEST_HEADER"
        while [ "$index" -lt "${#PATCH_INVENTORY_PATHS[@]}" ]; do
            printf '1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "${PATCH_INVENTORY_CRITERIA[$index]}" "${PATCH_INVENTORY_TYPES[$index]}" \
                "${PATCH_INVENTORY_PATHS[$index]}" "${PATCH_INVENTORY_DECISIONS[$index]}" \
                "${PATCH_INVENTORY_VALUES[$index]}" "${PATCH_INVENTORY_PROVENANCE[$index]}" \
                "${PATCH_INVENTORY_APPROVALS[$index]}" "$PATCH_INVENTORY_ROOT_DEVICE" \
                "$PATCH_INVENTORY_ROOT_INODE" "$PATCH_INVENTORY_INVENTORY_SHA256" \
                "${PATCH_INVENTORY_BEFORE_STATES[$index]}" "${PATCH_INVENTORY_BEFORE_DEVICES[$index]}" \
                "${PATCH_INVENTORY_BEFORE_INODES[$index]}" "${PATCH_INVENTORY_BEFORE_UIDS[$index]}" \
                "${PATCH_INVENTORY_BEFORE_GIDS[$index]}" "${PATCH_INVENTORY_BEFORE_MODES[$index]}" \
                "${PATCH_INVENTORY_BEFORE_LINKS[$index]}" "${PATCH_INVENTORY_BEFORE_SIZES[$index]}" \
                "${PATCH_INVENTORY_BEFORE_MTIMES[$index]}" "${PATCH_INVENTORY_BEFORE_CTIMES[$index]}" \
                "${PATCH_INVENTORY_BEFORE_SHA256S[$index]}" "${PATCH_INVENTORY_DESIRED_UIDS[$index]}" \
                "${PATCH_INVENTORY_DESIRED_GIDS[$index]}" "${PATCH_INVENTORY_DESIRED_MODES[$index]}" \
                "${PATCH_INVENTORY_DESIRED_SHA256S[$index]}" "${PATCH_INVENTORY_DESTINATIONS[$index]}" \
                "${PATCH_INVENTORY_BACKUPS[$index]}" "${PATCH_INVENTORY_PAYLOADS[$index]}" \
                "${PATCH_INVENTORY_XATTR_STATES[$index]}"
            index=$((index + 1))
        done
    } > "$path" || return 2
    /bin/chmod 0600 "$path" || return 2
    _patch_configuration_capture_file "$path" || return 2
    PATCH_INVENTORY_MANIFEST_DEVICE="$PATCH_CONFIGURATION_CAPTURE_DEVICE"
    PATCH_INVENTORY_MANIFEST_INODE="$PATCH_CONFIGURATION_CAPTURE_INODE"
    PATCH_INVENTORY_MANIFEST_SHA256="$PATCH_CONFIGURATION_CAPTURE_SHA256"
}

_patch_inventory_manifest_current() {
    _patch_configuration_capture_file "$PATCH_INVENTORY_DATA_DIRECTORY/manifest.tsv" || return 2
    [ "$PATCH_CONFIGURATION_CAPTURE_DEVICE:$PATCH_CONFIGURATION_CAPTURE_INODE:$PATCH_CONFIGURATION_CAPTURE_SHA256" = \
        "$PATCH_INVENTORY_MANIFEST_DEVICE:$PATCH_INVENTORY_MANIFEST_INODE:$PATCH_INVENTORY_MANIFEST_SHA256" ]
}

_patch_inventory_root_is_current() {
    local device=""
    local inode=""
    local uid=""
    local gid=""
    local mode=""
    local links=""
    local size=""
    local mtime=""
    local ctime=""

    _patch_configuration_root_chain_is_trusted "$PATCH_INVENTORY_ROOT" || return 2
    _patch_configuration_stat_into "$PATCH_INVENTORY_ROOT" device inode uid gid mode links size mtime ctime || return 2
    [ "$device:$inode" = "$PATCH_INVENTORY_ROOT_DEVICE:$PATCH_INVENTORY_ROOT_INODE" ]
}

patch_inventory_state_into() {
    local criterion="$1"
    local destination_name="$2"
    local result=compliant
    local index=0
    local found=0

    _patch_configuration_valid_destination "$destination_name" || return 2
    while [ "$index" -lt "${#PATCH_INVENTORY_CRITERIA[@]}" ]; do
        if [ "${PATCH_INVENTORY_CRITERIA[$index]}" = "$criterion" ]; then
            found=1
            if [ "$PATCH_INVENTORY_VERIFIED" -eq 1 ]; then result=verified
            elif [ "${PATCH_INVENTORY_STATES[$index]}" = ready ]; then result=ready
            fi
        fi
        index=$((index + 1))
    done
    [ "$found" -eq 1 ] || return 1
    printf -v "$destination_name" '%s' "$result"
}

patch_inventory_plan() {
    local requested_root="$1"
    local transaction="$2"
    local inventory="$3"
    local evidence="$4"
    local status=0
    local index=0

    patch_inventory_reset
    _patch_configuration_initialize_root "$requested_root" || { _patch_inventory_error "inventory root is unsafe"; return 2; }
    PATCH_INVENTORY_ROOT="$PATCH_CONFIGURATION_ROOT"
    PATCH_INVENTORY_ROOT_DEVICE="$PATCH_CONFIGURATION_ROOT_DEVICE"
    PATCH_INVENTORY_ROOT_INODE="$PATCH_CONFIGURATION_ROOT_INODE"
    PATCH_FILESYSTEM_ROOT="$PATCH_INVENTORY_ROOT"
    PATCH_FILESYSTEM_ROOT_DEVICE="$PATCH_INVENTORY_ROOT_DEVICE"
    PATCH_FILESYSTEM_ROOT_INODE="$PATCH_INVENTORY_ROOT_INODE"
    _patch_inventory_load_identities || { _patch_inventory_error "local identity databases are unsafe"; return 2; }
    _patch_inventory_load "$inventory" || { _patch_inventory_error "decision inventory is invalid"; return 2; }
    _patch_inventory_validate_evidence "$evidence" "$inventory" || status=$?
    if [ "$status" -eq 3 ]; then _patch_inventory_prerequisite complete_filesystem_mount_nss_evidence; return 3; fi
    [ "$status" -eq 0 ] || { _patch_inventory_error "complete evidence token is invalid"; return 2; }
    _patch_inventory_enumerate_expected || { _patch_inventory_error "complete inventory enumeration failed"; return 2; }
    _patch_inventory_exact || { PATCH_INVENTORY_PLAN_VALID=0; return 2; }
    if [ -n "${PATCH_INVENTORY_SELECTED_CRITERIA[U-14]+present}" ]; then
        [ -n "${PATCH_INVENTORY_CALLBACKS[root_path_runtime]:-}" ] || { _patch_inventory_prerequisite root_path_runtime_callback; return 3; }
    fi
    if [ -n "${PATCH_INVENTORY_SELECTED_CRITERIA[U-30]+present}" ]; then
        [ -n "${PATCH_INVENTORY_CALLBACKS[umask_native]:-}" ] || { _patch_inventory_prerequisite umask_native_callback; return 3; }
    fi
    _patch_inventory_prepare_transaction "$transaction" "$inventory" "$evidence" || { _patch_inventory_error "transaction directory is unsafe"; return 2; }
    while [ "$index" -lt "${#PATCH_INVENTORY_PATHS[@]}" ]; do
        _patch_inventory_snapshot_row "$index" || { _patch_inventory_error "target snapshot failed: ${PATCH_INVENTORY_PATHS[$index]}"; return 2; }
        index=$((index + 1))
    done
    _patch_inventory_write_manifest || { _patch_inventory_error "manifest write failed"; return 2; }
    PATCH_INVENTORY_PLAN_VALID=1
    PATCH_INVENTORY_PREREQUISITE=satisfied
}

_patch_inventory_artifacts_current() {
    local index=0
    local digest=""

    _patch_inventory_root_is_current || return 2
    _patch_inventory_manifest_current || return 2
    _patch_inventory_file_sha256_into "$PATCH_INVENTORY_DATA_DIRECTORY/inventory.tsv" digest || return 2
    [ "$digest" = "$PATCH_INVENTORY_INVENTORY_SHA256" ] || return 2
    _patch_inventory_file_sha256_into "$PATCH_INVENTORY_DATA_DIRECTORY/evidence.tsv" digest || return 2
    [ "$digest" = "$PATCH_INVENTORY_EVIDENCE_SHA256" ] || return 2
    while [ "$index" -lt "${#PATCH_INVENTORY_PATHS[@]}" ]; do
        _patch_inventory_parent_chains_are_safe "$index" || return 2
        if [ "${PATCH_INVENTORY_BACKUPS[$index]}" != - ]; then
            _patch_inventory_file_sha256_into "$PATCH_INVENTORY_DATA_DIRECTORY/${PATCH_INVENTORY_BACKUPS[$index]}" digest || return 2
            [ "$digest" = "${PATCH_INVENTORY_BEFORE_SHA256S[$index]}" ] || return 2
        fi
        if [ "${PATCH_INVENTORY_PAYLOADS[$index]}" != - ]; then
            _patch_inventory_file_sha256_into "$PATCH_INVENTORY_DATA_DIRECTORY/${PATCH_INVENTORY_PAYLOADS[$index]}" digest || return 2
            [ "$digest" = "${PATCH_INVENTORY_DESIRED_SHA256S[$index]}" ] || return 2
        fi
        index=$((index + 1))
    done
}

_patch_inventory_capture_path() {
    local index="$1"
    local side="$2"
    local path=""

    case "$side" in
        before) path="${PATCH_INVENTORY_PHYSICAL_PATHS[$index]}" ;;
        after) path="${PATCH_INVENTORY_AFTER_PATHS[$index]}" ;;
        *) return 2 ;;
    esac
    [ -n "$path" ] || return 2
    _patch_filesystem_capture_target "$path" "${PATCH_INVENTORY_TYPES[$index]}"
}

_patch_inventory_matches() {
    local index="$1"
    local side="$2"
    local expected=""

    _patch_inventory_parent_chains_are_safe "$index" || return 2
    if [ "$side" = before ] && [ "${PATCH_INVENTORY_BEFORE_STATES[$index]}" = absent ]; then
        [ ! -e "${PATCH_INVENTORY_PHYSICAL_PATHS[$index]}" ] && [ ! -L "${PATCH_INVENTORY_PHYSICAL_PATHS[$index]}" ]
        return
    fi
    _patch_inventory_capture_path "$index" "$side" || return 2
    if [ "$side" = before ]; then
        expected="${PATCH_INVENTORY_BEFORE_DEVICES[$index]}:${PATCH_INVENTORY_BEFORE_INODES[$index]}:${PATCH_INVENTORY_BEFORE_UIDS[$index]}:${PATCH_INVENTORY_BEFORE_GIDS[$index]}:${PATCH_INVENTORY_BEFORE_MODES[$index]}:${PATCH_INVENTORY_BEFORE_LINKS[$index]}:${PATCH_INVENTORY_BEFORE_SIZES[$index]}:${PATCH_INVENTORY_BEFORE_MTIMES[$index]}:${PATCH_INVENTORY_BEFORE_CTIMES[$index]}:${PATCH_INVENTORY_BEFORE_SHA256S[$index]}"
    else
        expected="${PATCH_INVENTORY_AFTER_DEVICES[$index]}:${PATCH_INVENTORY_AFTER_INODES[$index]}:${PATCH_INVENTORY_AFTER_UIDS[$index]}:${PATCH_INVENTORY_AFTER_GIDS[$index]}:${PATCH_INVENTORY_AFTER_MODES[$index]}:${PATCH_INVENTORY_AFTER_LINKS[$index]}:${PATCH_INVENTORY_AFTER_SIZES[$index]}:${PATCH_INVENTORY_AFTER_MTIMES[$index]}:${PATCH_INVENTORY_AFTER_CTIMES[$index]}:${PATCH_INVENTORY_AFTER_SHA256S[$index]}"
    fi
    [ "$PATCH_FILESYSTEM_CAPTURE_DEVICE:$PATCH_FILESYSTEM_CAPTURE_INODE:$PATCH_FILESYSTEM_CAPTURE_UID:$PATCH_FILESYSTEM_CAPTURE_GID:$PATCH_FILESYSTEM_CAPTURE_MODE:$PATCH_FILESYSTEM_CAPTURE_LINKS:$PATCH_FILESYSTEM_CAPTURE_SIZE:$PATCH_FILESYSTEM_CAPTURE_MTIME:$PATCH_FILESYSTEM_CAPTURE_CTIME:$PATCH_FILESYSTEM_CAPTURE_SHA256" = "$expected" ]
}

_patch_inventory_after_from_capture() {
    local index="$1" path="$2"

    PATCH_INVENTORY_AFTER_PATHS[$index]="$path"
    PATCH_INVENTORY_AFTER_DEVICES[$index]="$PATCH_FILESYSTEM_CAPTURE_DEVICE"
    PATCH_INVENTORY_AFTER_INODES[$index]="$PATCH_FILESYSTEM_CAPTURE_INODE"
    PATCH_INVENTORY_AFTER_UIDS[$index]="$PATCH_FILESYSTEM_CAPTURE_UID"
    PATCH_INVENTORY_AFTER_GIDS[$index]="$PATCH_FILESYSTEM_CAPTURE_GID"
    PATCH_INVENTORY_AFTER_MODES[$index]="$PATCH_FILESYSTEM_CAPTURE_MODE"
    PATCH_INVENTORY_AFTER_LINKS[$index]="$PATCH_FILESYSTEM_CAPTURE_LINKS"
    PATCH_INVENTORY_AFTER_SIZES[$index]="$PATCH_FILESYSTEM_CAPTURE_SIZE"
    PATCH_INVENTORY_AFTER_MTIMES[$index]="$PATCH_FILESYSTEM_CAPTURE_MTIME"
    PATCH_INVENTORY_AFTER_CTIMES[$index]="$PATCH_FILESYSTEM_CAPTURE_CTIME"
    PATCH_INVENTORY_AFTER_SHA256S[$index]="$PATCH_FILESYSTEM_CAPTURE_SHA256"
}

_patch_inventory_write_journal() {
    local index="$1" number="" path=""
    printf -v number '%06d' "$((index + 1))"
    path="$PATCH_INVENTORY_DATA_DIRECTORY/journal/$number.tsv"
    [ ! -e "$path" ] && [ ! -L "$path" ] || return 2
    {
        printf '%s\n' "$PATCH_INVENTORY_JOURNAL_HEADER"
        printf '1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$index" "${PATCH_INVENTORY_PATHS[$index]}" "${PATCH_INVENTORY_AFTER_PATHS[$index]}" \
            "${PATCH_INVENTORY_AFTER_DEVICES[$index]}" "${PATCH_INVENTORY_AFTER_INODES[$index]}" \
            "${PATCH_INVENTORY_AFTER_UIDS[$index]}" "${PATCH_INVENTORY_AFTER_GIDS[$index]}" \
            "${PATCH_INVENTORY_AFTER_MODES[$index]}" "${PATCH_INVENTORY_AFTER_LINKS[$index]}" \
            "${PATCH_INVENTORY_AFTER_SIZES[$index]}" "${PATCH_INVENTORY_AFTER_MTIMES[$index]}" \
            "${PATCH_INVENTORY_AFTER_CTIMES[$index]}" "${PATCH_INVENTORY_AFTER_SHA256S[$index]}"
    } > "$path" || return 2
    /bin/chmod 0600 "$path"
}

_patch_inventory_apply_replace() {
    local index="$1"
    local path="${PATCH_INVENTORY_PHYSICAL_PATHS[$index]}"
    local parent="${path%/*}"
    local payload="$PATCH_INVENTORY_DATA_DIRECTORY/${PATCH_INVENTORY_PAYLOADS[$index]}" stage=""

    _patch_inventory_parent_chains_are_safe "$index" || return 2
    stage="$(umask 077; /usr/bin/mktemp "$parent/.kisa-cce-inventory.XXXXXXXX")" || return 2
    /bin/cp "$payload" "$stage" || return 2
    /usr/bin/chown "${PATCH_INVENTORY_DESIRED_UIDS[$index]}:${PATCH_INVENTORY_DESIRED_GIDS[$index]}" "$stage" || return 2
    /bin/chmod "${PATCH_INVENTORY_DESIRED_MODES[$index]}" "$stage" || return 2
    PATCH_INVENTORY_APPLIED[$index]=1
    /usr/bin/mv -f "$stage" "$path" || return 2
    _patch_inventory_restore_xattrs "$index" || return 2
    _patch_filesystem_capture_target "$path" file || return 2
    [ "$PATCH_FILESYSTEM_CAPTURE_UID:$PATCH_FILESYSTEM_CAPTURE_GID:$PATCH_FILESYSTEM_CAPTURE_MODE:$PATCH_FILESYSTEM_CAPTURE_SHA256" = \
        "${PATCH_INVENTORY_DESIRED_UIDS[$index]}:${PATCH_INVENTORY_DESIRED_GIDS[$index]}:${PATCH_INVENTORY_DESIRED_MODES[$index]}:${PATCH_INVENTORY_DESIRED_SHA256S[$index]}" ] || return 2
    _patch_inventory_after_from_capture "$index" "$path"
    _patch_inventory_write_journal "$index"
}

_patch_inventory_apply_metadata() {
    local index="$1"
    local path="${PATCH_INVENTORY_PHYSICAL_PATHS[$index]}"

    _patch_inventory_parent_chains_are_safe "$index" || return 2
    PATCH_INVENTORY_APPLIED[$index]=1
    /usr/bin/chown "${PATCH_INVENTORY_DESIRED_UIDS[$index]}:${PATCH_INVENTORY_DESIRED_GIDS[$index]}" "$path" || return 2
    /bin/chmod "${PATCH_INVENTORY_DESIRED_MODES[$index]}" "$path" || return 2
    _patch_inventory_restore_xattrs "$index" || return 2
    _patch_filesystem_capture_target "$path" "${PATCH_INVENTORY_TYPES[$index]}" || return 2
    [ "$PATCH_FILESYSTEM_CAPTURE_UID:$PATCH_FILESYSTEM_CAPTURE_GID:$PATCH_FILESYSTEM_CAPTURE_MODE:$PATCH_FILESYSTEM_CAPTURE_SHA256" = \
        "${PATCH_INVENTORY_DESIRED_UIDS[$index]}:${PATCH_INVENTORY_DESIRED_GIDS[$index]}:${PATCH_INVENTORY_DESIRED_MODES[$index]}:${PATCH_INVENTORY_DESIRED_SHA256S[$index]}" ] || return 2
    _patch_inventory_after_from_capture "$index" "$path"
    _patch_inventory_write_journal "$index"
}

_patch_inventory_apply_quarantine() {
    local index="$1"
    local source="${PATCH_INVENTORY_PHYSICAL_PATHS[$index]}"
    local destination=""
    local destination_parent="" destination_physical=""

    _patch_inventory_parent_chains_are_safe "$index" || return 2
    _patch_inventory_resolve_parent "${PATCH_INVENTORY_DESTINATIONS[$index]}" destination_parent destination_physical || return 2
    [ ! -e "$destination_physical" ] && [ ! -L "$destination_physical" ] || return 2
    PATCH_INVENTORY_APPLIED[$index]=1
    /usr/bin/mv "$source" "$destination_physical" || return 2
    _patch_filesystem_capture_target "$destination_physical" "${PATCH_INVENTORY_TYPES[$index]}" || return 2
    [ "$PATCH_FILESYSTEM_CAPTURE_DEVICE:$PATCH_FILESYSTEM_CAPTURE_INODE:$PATCH_FILESYSTEM_CAPTURE_SHA256" = \
        "${PATCH_INVENTORY_BEFORE_DEVICES[$index]}:${PATCH_INVENTORY_BEFORE_INODES[$index]}:${PATCH_INVENTORY_BEFORE_SHA256S[$index]}" ] || return 2
    _patch_inventory_after_from_capture "$index" "$destination_physical"
    _patch_inventory_write_journal "$index"
}

_patch_inventory_native_verify() {
    local index=0 callback="" value="" provenance=""

    if [ -n "${PATCH_INVENTORY_SELECTED_CRITERIA[U-14]+present}" ]; then
        callback="${PATCH_INVENTORY_CALLBACKS[root_path_runtime]:-}"
        [ -n "$callback" ] && _patch_filesystem_callback_is_trusted "$callback" || return 2
        while [ "$index" -lt "${#PATCH_INVENTORY_PATHS[@]}" ]; do
            if [ "${PATCH_INVENTORY_DECISIONS[$index]}" = set_root_path ]; then
                "$callback" "$PATCH_INVENTORY_ROOT" "${PATCH_INVENTORY_VALUES[$index]}" || return 2
            fi
            index=$((index + 1))
        done
    fi
    index=0
    if [ -n "${PATCH_INVENTORY_SELECTED_CRITERIA[U-30]+present}" ]; then
        callback="${PATCH_INVENTORY_CALLBACKS[umask_native]:-}"
        [ -n "$callback" ] && _patch_filesystem_callback_is_trusted "$callback" || return 2
        while [ "$index" -lt "${#PATCH_INVENTORY_PATHS[@]}" ]; do
            if [ "${PATCH_INVENTORY_DECISIONS[$index]}" = set_umask ]; then
                value="${PATCH_INVENTORY_VALUES[$index]}"
                provenance="${PATCH_INVENTORY_PROVENANCE[$index]#subsystem:}"
                "$callback" "$PATCH_INVENTORY_ROOT" "${PATCH_INVENTORY_PHYSICAL_PATHS[$index]}" \
                    "$provenance" "$value" || return 2
            fi
            index=$((index + 1))
        done
    fi
}

patch_inventory_verify() {
    local index=0
    _patch_inventory_artifacts_current || return 2
    while [ "$index" -lt "${#PATCH_INVENTORY_PATHS[@]}" ]; do
        _patch_inventory_matches "$index" after || return 2
        index=$((index + 1))
    done
    _patch_inventory_native_verify || return 2
    PATCH_INVENTORY_VERIFIED=1
}

patch_inventory_apply() {
    local index=0 status=0

    [ "${EUID:-$(id -u)}" -eq 0 ] && [ "$PATCH_INVENTORY_PLAN_VALID" -eq 1 ] || return 2
    _patch_inventory_artifacts_current || return 2
    while [ "$index" -lt "${#PATCH_INVENTORY_PATHS[@]}" ]; do
        _patch_inventory_matches "$index" before || return 2
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_INVENTORY_PATHS[@]}" ]; do
        if [ "${PATCH_INVENTORY_STATES[$index]}" = compliant ]; then
            PATCH_INVENTORY_AFTER_PATHS[$index]="${PATCH_INVENTORY_PHYSICAL_PATHS[$index]}"
            PATCH_INVENTORY_AFTER_DEVICES[$index]="${PATCH_INVENTORY_BEFORE_DEVICES[$index]}"
            PATCH_INVENTORY_AFTER_INODES[$index]="${PATCH_INVENTORY_BEFORE_INODES[$index]}"
            PATCH_INVENTORY_AFTER_UIDS[$index]="${PATCH_INVENTORY_BEFORE_UIDS[$index]}"
            PATCH_INVENTORY_AFTER_GIDS[$index]="${PATCH_INVENTORY_BEFORE_GIDS[$index]}"
            PATCH_INVENTORY_AFTER_MODES[$index]="${PATCH_INVENTORY_BEFORE_MODES[$index]}"
            PATCH_INVENTORY_AFTER_LINKS[$index]="${PATCH_INVENTORY_BEFORE_LINKS[$index]}"
            PATCH_INVENTORY_AFTER_SIZES[$index]="${PATCH_INVENTORY_BEFORE_SIZES[$index]}"
            PATCH_INVENTORY_AFTER_MTIMES[$index]="${PATCH_INVENTORY_BEFORE_MTIMES[$index]}"
            PATCH_INVENTORY_AFTER_CTIMES[$index]="${PATCH_INVENTORY_BEFORE_CTIMES[$index]}"
            PATCH_INVENTORY_AFTER_SHA256S[$index]="${PATCH_INVENTORY_BEFORE_SHA256S[$index]}"
        else
            case "${PATCH_INVENTORY_DECISIONS[$index]}" in
                set_root_path|set_umask) _patch_inventory_apply_replace "$index" || status=2 ;;
                set_owner|remove_privileged_bits) _patch_inventory_apply_metadata "$index" || status=2 ;;
                quarantine) _patch_inventory_apply_quarantine "$index" || status=2 ;;
                *) status=2 ;;
            esac
            [ "$status" -eq 0 ] || break
        fi
        index=$((index + 1))
    done
    [ "$status" -eq 0 ] && patch_inventory_verify || status=2
    if [ "$status" -ne 0 ]; then
        PATCH_INVENTORY_ERROR_DETAIL="apply or verification failed"
        patch_inventory_rollback transition >/dev/null 2>&1 || PATCH_INVENTORY_ERROR_DETAIL+="; automatic rollback incomplete"
        return 2
    fi
}

_patch_inventory_restore_row() {
    local index="$1"
    local decision="${PATCH_INVENTORY_DECISIONS[$index]}"
    local original="${PATCH_INVENTORY_PHYSICAL_PATHS[$index]}" current="${PATCH_INVENTORY_AFTER_PATHS[$index]}"
    local parent="${original%/*}" stage="" backup=""

    _patch_inventory_parent_chains_are_safe "$index" || return 2
    case "$decision" in
        quarantine)
            [ ! -e "$original" ] && [ ! -L "$original" ] || return 2
            /usr/bin/mv "$current" "$original" || return 2
            ;;
        set_root_path|set_umask)
            if [ "${PATCH_INVENTORY_BEFORE_STATES[$index]}" = absent ]; then
                _patch_inventory_matches "$index" after || return 2
                /bin/rm -f "$current" || return 2
                return 0
            fi
            backup="$PATCH_INVENTORY_DATA_DIRECTORY/${PATCH_INVENTORY_BACKUPS[$index]}"
            stage="$(umask 077; /usr/bin/mktemp "$parent/.kisa-cce-inventory-rollback.XXXXXXXX")" || return 2
            /bin/cp "$backup" "$stage" || return 2
            /usr/bin/chown "${PATCH_INVENTORY_BEFORE_UIDS[$index]}:${PATCH_INVENTORY_BEFORE_GIDS[$index]}" "$stage" || return 2
            /bin/chmod "${PATCH_INVENTORY_BEFORE_MODES[$index]}" "$stage" || return 2
            /usr/bin/mv -f "$stage" "$original" || return 2
            ;;
        set_owner|remove_privileged_bits)
            /usr/bin/chown "${PATCH_INVENTORY_BEFORE_UIDS[$index]}:${PATCH_INVENTORY_BEFORE_GIDS[$index]}" "$original" || return 2
            /bin/chmod "${PATCH_INVENTORY_BEFORE_MODES[$index]}" "$original" || return 2
            ;;
        *) return 2 ;;
    esac
    _patch_inventory_restore_xattrs "$index" || return 2
    _patch_filesystem_capture_target "$original" "${PATCH_INVENTORY_TYPES[$index]}" || return 2
    [ "$PATCH_FILESYSTEM_CAPTURE_UID:$PATCH_FILESYSTEM_CAPTURE_GID:$PATCH_FILESYSTEM_CAPTURE_MODE:$PATCH_FILESYSTEM_CAPTURE_SHA256" = \
        "${PATCH_INVENTORY_BEFORE_UIDS[$index]}:${PATCH_INVENTORY_BEFORE_GIDS[$index]}:${PATCH_INVENTORY_BEFORE_MODES[$index]}:${PATCH_INVENTORY_BEFORE_SHA256S[$index]}" ]
}

patch_inventory_rollback() {
    local policy="${1:-strict}" index=0

    case "$policy" in strict|transition) ;; *) return 2 ;; esac
    [ "${EUID:-$(id -u)}" -eq 0 ] && [ "$PATCH_INVENTORY_PLAN_VALID" -eq 1 ] || return 2
    _patch_inventory_artifacts_current || return 2
    while [ "$index" -lt "${#PATCH_INVENTORY_PATHS[@]}" ]; do
        if [ "${PATCH_INVENTORY_STATES[$index]}" = compliant ]; then
            _patch_inventory_matches "$index" before || return 2
        elif ! _patch_inventory_matches "$index" after; then
            [ "$policy" = transition ] && _patch_inventory_matches "$index" before || return 2
        fi
        index=$((index + 1))
    done
    index=$(( ${#PATCH_INVENTORY_PATHS[@]} - 1 ))
    while [ "$index" -ge 0 ]; do
        if [ "${PATCH_INVENTORY_STATES[$index]}" = ready ] &&
            _patch_inventory_matches "$index" after; then
            _patch_inventory_restore_row "$index" || return 2
        fi
        index=$((index - 1))
    done
    PATCH_INVENTORY_VERIFIED=0
}

_patch_inventory_load_journal() {
    local index="$1" number="" path="" header="" schema="" record_index="" logical="" current=""
    local device="" inode="" uid="" gid="" mode="" links="" size="" mtime="" ctime="" sha="" extra=""

    if [ "${PATCH_INVENTORY_STATES[$index]}" = compliant ]; then
        PATCH_INVENTORY_AFTER_PATHS[$index]="${PATCH_INVENTORY_PHYSICAL_PATHS[$index]}"
        PATCH_INVENTORY_AFTER_DEVICES[$index]="${PATCH_INVENTORY_BEFORE_DEVICES[$index]}"
        PATCH_INVENTORY_AFTER_INODES[$index]="${PATCH_INVENTORY_BEFORE_INODES[$index]}"
        PATCH_INVENTORY_AFTER_UIDS[$index]="${PATCH_INVENTORY_BEFORE_UIDS[$index]}"
        PATCH_INVENTORY_AFTER_GIDS[$index]="${PATCH_INVENTORY_BEFORE_GIDS[$index]}"
        PATCH_INVENTORY_AFTER_MODES[$index]="${PATCH_INVENTORY_BEFORE_MODES[$index]}"
        PATCH_INVENTORY_AFTER_LINKS[$index]="${PATCH_INVENTORY_BEFORE_LINKS[$index]}"
        PATCH_INVENTORY_AFTER_SIZES[$index]="${PATCH_INVENTORY_BEFORE_SIZES[$index]}"
        PATCH_INVENTORY_AFTER_MTIMES[$index]="${PATCH_INVENTORY_BEFORE_MTIMES[$index]}"
        PATCH_INVENTORY_AFTER_CTIMES[$index]="${PATCH_INVENTORY_BEFORE_CTIMES[$index]}"
        PATCH_INVENTORY_AFTER_SHA256S[$index]="${PATCH_INVENTORY_BEFORE_SHA256S[$index]}"
        return 0
    fi
    printf -v number '%06d' "$((index + 1))"
    path="$PATCH_INVENTORY_DATA_DIRECTORY/journal/$number.tsv"
    _patch_configuration_capture_file "$path" || return 2
    IFS= read -r header < "$path" || return 2
    [ "$header" = "$PATCH_INVENTORY_JOURNAL_HEADER" ] || return 2
    IFS=$'\t' read -r schema record_index logical current device inode uid gid mode links size mtime ctime sha extra \
        < <(sed -n '2p' "$path")
    [ "$schema" = 1 ] && [ "$record_index" = "$index" ] &&
        [ "$logical" = "${PATCH_INVENTORY_PATHS[$index]}" ] && [ -z "$extra" ] || return 2
    PATCH_INVENTORY_AFTER_PATHS[$index]="$current"
    PATCH_INVENTORY_AFTER_DEVICES[$index]="$device"
    PATCH_INVENTORY_AFTER_INODES[$index]="$inode"
    PATCH_INVENTORY_AFTER_UIDS[$index]="$uid"
    PATCH_INVENTORY_AFTER_GIDS[$index]="$gid"
    PATCH_INVENTORY_AFTER_MODES[$index]="$mode"
    PATCH_INVENTORY_AFTER_LINKS[$index]="$links"
    PATCH_INVENTORY_AFTER_SIZES[$index]="$size"
    PATCH_INVENTORY_AFTER_MTIMES[$index]="$mtime"
    PATCH_INVENTORY_AFTER_CTIMES[$index]="$ctime"
    PATCH_INVENTORY_AFTER_SHA256S[$index]="$sha"
}

patch_inventory_load_transaction() {
    local requested_root="$1" transaction="$2" inventory="" evidence="" manifest=""
    local load_mode="${3:-applied}"
    local header="" schema="" criterion="" object_type="" logical="" decision="" value="" provenance="" approval=""
    local root_device="" root_inode="" inventory_sha="" before_state="" device="" inode="" uid="" gid="" mode=""
    local links="" size="" mtime="" ctime="" sha="" desired_uid="" desired_gid="" desired_mode="" desired_sha=""
    local destination="" backup="" payload="" xattr_state="" extra="" physical="" parent="" resolved="" index=0
    local digest="" journal_number=""

    case "$load_mode" in planned|applied) ;; *) return 2 ;; esac
    patch_inventory_reset
    _patch_configuration_initialize_root "$requested_root" || return 2
    PATCH_INVENTORY_ROOT="$PATCH_CONFIGURATION_ROOT"
    PATCH_INVENTORY_ROOT_DEVICE="$PATCH_CONFIGURATION_ROOT_DEVICE"
    PATCH_INVENTORY_ROOT_INODE="$PATCH_CONFIGURATION_ROOT_INODE"
    PATCH_FILESYSTEM_ROOT="$PATCH_INVENTORY_ROOT"
    PATCH_FILESYSTEM_ROOT_DEVICE="$PATCH_INVENTORY_ROOT_DEVICE"
    PATCH_FILESYSTEM_ROOT_INODE="$PATCH_INVENTORY_ROOT_INODE"
    _patch_inventory_load_identities || return 2
    _patch_configuration_transaction_directory_is_safe "$transaction" || return 2
    PATCH_INVENTORY_TRANSACTION_DIRECTORY="$(CDPATH='' builtin cd -P -- "$transaction" && pwd -P)" || return 2
    PATCH_INVENTORY_DATA_DIRECTORY="$PATCH_INVENTORY_TRANSACTION_DIRECTORY/inventory"
    inventory="$PATCH_INVENTORY_DATA_DIRECTORY/inventory.tsv"
    evidence="$PATCH_INVENTORY_DATA_DIRECTORY/evidence.tsv"
    _patch_inventory_load "$inventory" || return 2
    _patch_inventory_validate_evidence "$evidence" "$inventory" || return 2
    manifest="$PATCH_INVENTORY_DATA_DIRECTORY/manifest.tsv"
    _patch_configuration_capture_file "$manifest" || return 2
    PATCH_INVENTORY_MANIFEST_DEVICE="$PATCH_CONFIGURATION_CAPTURE_DEVICE"
    PATCH_INVENTORY_MANIFEST_INODE="$PATCH_CONFIGURATION_CAPTURE_INODE"
    PATCH_INVENTORY_MANIFEST_SHA256="$PATCH_CONFIGURATION_CAPTURE_SHA256"
    IFS= read -r header < "$manifest" || return 2
    [ "$header" = "$PATCH_INVENTORY_MANIFEST_HEADER" ] || return 2
    while IFS=$'\t' read -r schema criterion object_type logical decision value provenance approval \
        root_device root_inode inventory_sha before_state device inode uid gid mode links size mtime ctime sha \
        desired_uid desired_gid desired_mode desired_sha destination backup payload xattr_state extra; do
        [ -n "$schema" ] || continue
        [ "$schema" = 1 ] && [ -z "$extra" ] || return 2
        [ "$root_device:$root_inode:$inventory_sha" = \
            "$PATCH_INVENTORY_ROOT_DEVICE:$PATCH_INVENTORY_ROOT_INODE:$PATCH_INVENTORY_INVENTORY_SHA256" ] || return 2
        _patch_inventory_row_is_typed "$criterion" "$object_type" "$logical" "$decision" "$value" "$provenance" "$approval" || return 2
        if [ "$before_state" = present ]; then
            _patch_filesystem_resolve_logical_into "$logical" "$object_type" resolved physical || {
                _patch_inventory_resolve_parent "$logical" parent physical || return 2
            }
        else
            _patch_inventory_resolve_parent "$logical" parent physical || return 2
        fi
        if [ "$backup" != - ]; then
            _patch_inventory_file_sha256_into "$PATCH_INVENTORY_DATA_DIRECTORY/$backup" digest || return 2
            [ "$digest" = "$sha" ] || return 2
        fi
        if [ "$payload" != - ]; then
            _patch_inventory_file_sha256_into "$PATCH_INVENTORY_DATA_DIRECTORY/$payload" digest || return 2
            [ "$digest" = "$desired_sha" ] || return 2
        fi
        PATCH_INVENTORY_PHYSICAL_PATHS[$index]="$physical"
        PATCH_INVENTORY_TYPES[$index]="$object_type"
        PATCH_INVENTORY_CURRENT_PATHS[$index]="$physical"
        PATCH_INVENTORY_DESTINATIONS[$index]="$destination"
        PATCH_INVENTORY_BEFORE_STATES[$index]="$before_state"
        PATCH_INVENTORY_BEFORE_DEVICES[$index]="$device"
        PATCH_INVENTORY_BEFORE_INODES[$index]="$inode"
        PATCH_INVENTORY_BEFORE_UIDS[$index]="$uid"
        PATCH_INVENTORY_BEFORE_GIDS[$index]="$gid"
        PATCH_INVENTORY_BEFORE_MODES[$index]="$mode"
        PATCH_INVENTORY_BEFORE_LINKS[$index]="$links"
        PATCH_INVENTORY_BEFORE_SIZES[$index]="$size"
        PATCH_INVENTORY_BEFORE_MTIMES[$index]="$mtime"
        PATCH_INVENTORY_BEFORE_CTIMES[$index]="$ctime"
        PATCH_INVENTORY_BEFORE_SHA256S[$index]="$sha"
        PATCH_INVENTORY_DESIRED_UIDS[$index]="$desired_uid"
        PATCH_INVENTORY_DESIRED_GIDS[$index]="$desired_gid"
        PATCH_INVENTORY_DESIRED_MODES[$index]="$desired_mode"
        PATCH_INVENTORY_DESIRED_SHA256S[$index]="$desired_sha"
        PATCH_INVENTORY_BACKUPS[$index]="$backup"
        PATCH_INVENTORY_PAYLOADS[$index]="$payload"
        PATCH_INVENTORY_XATTR_STATES[$index]="$xattr_state"
        if [ "$decision" = quarantine ] || [ "$before_state:$uid:$gid:$mode:$sha" != \
            "present:$desired_uid:$desired_gid:$desired_mode:$desired_sha" ]; then
            PATCH_INVENTORY_STATES[$index]=ready
        else
            PATCH_INVENTORY_STATES[$index]=compliant
        fi
        PATCH_INVENTORY_AFTER_PATHS[$index]=""
        PATCH_INVENTORY_AFTER_DEVICES[$index]=""
        PATCH_INVENTORY_AFTER_INODES[$index]=""
        PATCH_INVENTORY_AFTER_UIDS[$index]=""
        PATCH_INVENTORY_AFTER_GIDS[$index]=""
        PATCH_INVENTORY_AFTER_MODES[$index]=""
        PATCH_INVENTORY_AFTER_LINKS[$index]=""
        PATCH_INVENTORY_AFTER_SIZES[$index]=""
        PATCH_INVENTORY_AFTER_MTIMES[$index]=""
        PATCH_INVENTORY_AFTER_CTIMES[$index]=""
        PATCH_INVENTORY_AFTER_SHA256S[$index]=""
        PATCH_INVENTORY_APPLIED[$index]=0
        if [ "$load_mode" = planned ] && [ "${PATCH_INVENTORY_STATES[$index]}" = ready ]; then
            printf -v journal_number '%06d' "$((index + 1))"
            [ ! -e "$PATCH_INVENTORY_DATA_DIRECTORY/journal/$journal_number.tsv" ] || return 2
        else
            _patch_inventory_load_journal "$index" || return 2
        fi
        index=$((index + 1))
    done < <(sed -n '2,$p' "$manifest")
    [ "$index" -gt 0 ] || return 2
    _patch_inventory_artifacts_current || return 2
    PATCH_INVENTORY_PLAN_VALID=1
    PATCH_INVENTORY_PREREQUISITE=satisfied
}

patch_inventory_rollback_transaction() {
    local root="$1" transaction="$2"
    patch_inventory_load_transaction "$root" "$transaction" || return 2
    patch_inventory_rollback strict
}
