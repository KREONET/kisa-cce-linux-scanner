# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash
# shellcheck disable=SC2034

# Edge-service adapters delegate privileged subsystem mutation to narrow, trusted executors.

PATCH_EDGE_PLAN_HEADER=$'schema\tcriterion\tstate\tdomain\tprovider\tbackend\tpayload_sha256\tapproval\tsnapshot_sha256'
PATCH_EDGE_MANIFEST_HEADER=$'schema\tcriterion\tdomain\troot\troot_device\troot_inode\tprovider\tbackend\tpayload_sha256\tapproval\tsnapshot_sha256\tsecret_reference_sha256'
PATCH_EDGE_CHECKSUM_HEADER=$'schema\tpath\tsha256'
PATCH_EDGE_APPLIED_HEADER=$'schema\tcriterion\tapplied_sha256'

PATCH_EDGE_ERROR_DETAIL=""
PATCH_EDGE_ROOT=""
PATCH_EDGE_ROOT_DEVICE=""
PATCH_EDGE_ROOT_INODE=""
PATCH_EDGE_TRANSACTION_DIRECTORY=""
PATCH_EDGE_DATA_DIRECTORY=""
PATCH_EDGE_CRITERION=""
PATCH_EDGE_DOMAIN=""
PATCH_EDGE_PROVIDER=""
PATCH_EDGE_BACKEND=""
PATCH_EDGE_APPROVAL=""
PATCH_EDGE_PAYLOAD_PATH=""
PATCH_EDGE_PAYLOAD_SHA256=""
PATCH_EDGE_SNAPSHOT_SHA256=""
PATCH_EDGE_APPLIED_SHA256=""
PATCH_EDGE_SECRET_REFERENCE="-"
PATCH_EDGE_SECRET_REFERENCE_SHA256="-"
PATCH_EDGE_STATE=""
PATCH_EDGE_PLAN_VALID=0
PATCH_EDGE_APPLY_STARTED=0

PATCH_EDGE_CAPTURE_DEVICE=""
PATCH_EDGE_CAPTURE_INODE=""
PATCH_EDGE_CAPTURE_UID=""
PATCH_EDGE_CAPTURE_MODE=""
PATCH_EDGE_CAPTURE_LINKS=""
PATCH_EDGE_CAPTURE_SHA256=""

declare -A PATCH_EDGE_CALLBACKS=()

_patch_edge_set_error() {
    PATCH_EDGE_ERROR_DETAIL="$1"
    return 2
}

_patch_edge_valid_destination() {
    case "$1" in ''|[0-9]*|*[!A-Za-z0-9_]*) return 1 ;; *) return 0 ;; esac
}

_patch_edge_command_into() {
    local command_name="$1"
    local destination_name="$2"
    local command_path=""

    _patch_edge_valid_destination "$destination_name" || return 2
    case "$command_name" in
        chmod) command_path=/bin/chmod ;;
        mkdir) command_path=/bin/mkdir ;;
        mktemp) command_path=/usr/bin/mktemp; [ -x "$command_path" ] || command_path=/bin/mktemp ;;
        mv) command_path=/usr/bin/mv; [ -x "$command_path" ] || command_path=/bin/mv ;;
        sha256sum)
            if [ -x /usr/bin/sha256sum ]; then
                command_path=/usr/bin/sha256sum
            elif [ -x /bin/sha256sum ]; then
                command_path=/bin/sha256sum
            else
                command_path=/usr/bin/shasum
            fi
            ;;
        stat) command_path=/usr/bin/stat ;;
        *) return 2 ;;
    esac
    [ -x "$command_path" ] || return 127
    printf -v "$destination_name" '%s' "$command_path"
}

_patch_edge_stat_into() {
    local path="$1"
    local device_destination="$2"
    local inode_destination="$3"
    local uid_destination="$4"
    local mode_destination="$5"
    local links_destination="$6"
    local stat_command="" output=""
    local stat_device="" stat_inode="" stat_uid="" stat_mode="" stat_links="" stat_extra=""

    _patch_edge_command_into stat stat_command || return $?
    if output="$("$stat_command" -c '%d:%i:%u:%a:%h' -- "$path" 2>/dev/null)"; then
        :
    elif output="$("$stat_command" -f '%d:%i:%u:%Lp:%l' "$path" 2>/dev/null)"; then
        :
    else
        return 2
    fi
    IFS=: read -r stat_device stat_inode stat_uid stat_mode stat_links stat_extra <<< "$output"
    [ -z "$stat_extra" ] || return 2
    case "$stat_device:$stat_inode:$stat_uid:$stat_links" in *[!0-9:]*) return 2 ;; esac
    case "$stat_mode" in ''|*[!0-7]*) return 2 ;; esac
    printf -v "$device_destination" '%s' "$stat_device"
    printf -v "$inode_destination" '%s' "$stat_inode"
    printf -v "$uid_destination" '%s' "$stat_uid"
    printf -v "$mode_destination" '%04o' "$((8#$stat_mode & 07777))"
    printf -v "$links_destination" '%s' "$stat_links"
}

_patch_edge_sha256_into() {
    local path="$1"
    local destination_name="$2"
    local hash_command="" output="" file_digest=""

    _patch_edge_valid_destination "$destination_name" || return 2
    _patch_edge_command_into sha256sum hash_command || return $?
    case "$hash_command" in
        */shasum) output="$("$hash_command" -a 256 -- "$path" 2>/dev/null)" || return 2 ;;
        *) output="$("$hash_command" -- "$path" 2>/dev/null)" || return 2 ;;
    esac
    file_digest="${output%% *}"
    [ "${#file_digest}" -eq 64 ] || return 2
    case "$file_digest" in *[!0-9a-f]*) return 2 ;; esac
    printf -v "$destination_name" '%s' "$file_digest"
}

_patch_edge_string_sha256_into() {
    local value="$1"
    local destination_name="$2"
    local hash_command="" output="" string_digest=""

    _patch_edge_valid_destination "$destination_name" || return 2
    _patch_edge_command_into sha256sum hash_command || return $?
    case "$hash_command" in
        */shasum) output="$(printf '%s' "$value" | "$hash_command" -a 256 2>/dev/null)" || return 2 ;;
        *) output="$(printf '%s' "$value" | "$hash_command" 2>/dev/null)" || return 2 ;;
    esac
    string_digest="${output%% *}"
    [ "${#string_digest}" -eq 64 ] || return 2
    case "$string_digest" in *[!0-9a-f]*) return 2 ;; esac
    printf -v "$destination_name" '%s' "$string_digest"
}

_patch_edge_capture_file() {
    local path="$1"
    local device_before="" inode_before="" uid_before="" mode_before="" links_before=""
    local device_after="" inode_after="" uid_after="" mode_after="" links_after=""
    local captured_digest=""

    [ -f "$path" ] && [ ! -L "$path" ] || return 2
    _patch_edge_stat_into "$path" device_before inode_before uid_before mode_before links_before || return 2
    [ "$links_before" = 1 ] || return 2
    _patch_edge_sha256_into "$path" captured_digest || return 2
    _patch_edge_stat_into "$path" device_after inode_after uid_after mode_after links_after || return 2
    [ "$device_before:$inode_before:$uid_before:$mode_before:$links_before" = \
      "$device_after:$inode_after:$uid_after:$mode_after:$links_after" ] || return 2
    PATCH_EDGE_CAPTURE_DEVICE="$device_after"
    PATCH_EDGE_CAPTURE_INODE="$inode_after"
    PATCH_EDGE_CAPTURE_UID="$uid_after"
    PATCH_EDGE_CAPTURE_MODE="$mode_after"
    PATCH_EDGE_CAPTURE_LINKS="$links_after"
    PATCH_EDGE_CAPTURE_SHA256="$captured_digest"
}

_patch_edge_directory_safe() {
    local path="$1"
    local strict="${2:-no}"
    local canonical="" current=/ relative="" component=""
    local device="" inode="" owner_uid="" mode="" links=""
    local -a components=()

    [ -d "$path" ] && [ ! -L "$path" ] || return 2
    canonical="$(CDPATH='' builtin cd -P -- "$path" 2>/dev/null && pwd -P)" || return 2
    case "$canonical" in *$'\n'*|*$'\r'*|*$'\t'*) return 2 ;; esac
    relative="${canonical#/}"
    IFS=/ read -r -a components <<< "$relative"
    for component in "${components[@]}"; do
        [ -n "$component" ] || continue
        case "$component" in .|..) return 2 ;; esac
        current="${current%/}/$component"
        [ -d "$current" ] && [ ! -L "$current" ] || return 2
        _patch_edge_stat_into "$current" device inode owner_uid mode links || return 2
        [ "$owner_uid" = 0 ] || { [ "$strict" = no ] && [ "$owner_uid" = "${EUID:-}" ]; } || return 2
        if [ $((8#$mode & 0022)) -ne 0 ]; then
            [ "$strict" = no ] && [ "$owner_uid" = 0 ] && [ $((8#$mode & 01000)) -ne 0 ] && \
                { [ "$current" = /tmp ] || [ "$current" = /var/tmp ] || [ "$current" = /private/tmp ] || [ "$current" = /private/var/tmp ]; } || return 2
        fi
    done
}

_patch_edge_callback_trusted() {
    local callback_path="$1"
    local parent="${callback_path%/*}"
    local device="" inode="" owner_uid="" mode="" links=""

    case "$callback_path" in /*) ;; *) return 2 ;; esac
    case "$callback_path" in *$'\n'*|*$'\r'*|*$'\t'*) return 2 ;; esac
    [ -f "$callback_path" ] && [ ! -L "$callback_path" ] && [ -x "$callback_path" ] || return 2
    _patch_edge_directory_safe "$parent" yes || return 2
    _patch_edge_stat_into "$callback_path" device inode owner_uid mode links || return 2
    [ "$owner_uid" = 0 ] && [ "$links" = 1 ] && [ $((8#$mode & 0022)) -eq 0 ]
}

patch_edge_register_callback() {
    local role="$1"
    local callback_path="$2"

    case "$role" in policy_verifier|provider_probe|native_validator|runtime_probe|protocol_probe|snapshot|apply|rollback) ;; *) return 1 ;; esac
    _patch_edge_callback_trusted "$callback_path" || return 2
    PATCH_EDGE_CALLBACKS["$role"]="$callback_path"
}

patch_edge_clear_callbacks() {
    PATCH_EDGE_CALLBACKS=()
}

patch_edge_reset() {
    PATCH_EDGE_ERROR_DETAIL=""
    PATCH_EDGE_ROOT=""
    PATCH_EDGE_ROOT_DEVICE=""
    PATCH_EDGE_ROOT_INODE=""
    PATCH_EDGE_TRANSACTION_DIRECTORY=""
    PATCH_EDGE_DATA_DIRECTORY=""
    PATCH_EDGE_CRITERION=""
    PATCH_EDGE_DOMAIN=""
    PATCH_EDGE_PROVIDER=""
    PATCH_EDGE_BACKEND=""
    PATCH_EDGE_APPROVAL=""
    PATCH_EDGE_PAYLOAD_PATH=""
    PATCH_EDGE_PAYLOAD_SHA256=""
    PATCH_EDGE_SNAPSHOT_SHA256=""
    PATCH_EDGE_APPLIED_SHA256=""
    PATCH_EDGE_SECRET_REFERENCE="-"
    PATCH_EDGE_SECRET_REFERENCE_SHA256="-"
    PATCH_EDGE_STATE=""
    PATCH_EDGE_PLAN_VALID=0
    PATCH_EDGE_APPLY_STARTED=0
}

patch_edge_supported_criteria() {
    printf '%s\n' U-01 U-28 U-53 U-56 U-57 U-59 U-60 U-61
}

patch_edge_state_into() {
    local destination_name="$1"

    _patch_edge_valid_destination "$destination_name" || return 2
    [ -n "$PATCH_EDGE_STATE" ] || return 1
    printf -v "$destination_name" '%s' "$PATCH_EDGE_STATE"
}

_patch_edge_initialize_root() {
    local requested_root="$1"
    local canonical_root="" root_uid="" root_mode="" root_links=""

    case "$requested_root" in *$'\n'*|*$'\r'*|*$'\t'*) return 2 ;; esac
    _patch_edge_directory_safe "$requested_root" no || return 2
    canonical_root="$(CDPATH='' builtin cd -P -- "$requested_root" 2>/dev/null && pwd -P)" || return 2
    _patch_edge_stat_into "$canonical_root" PATCH_EDGE_ROOT_DEVICE PATCH_EDGE_ROOT_INODE \
        root_uid root_mode root_links || return 2
    PATCH_EDGE_ROOT="$canonical_root"
}

_patch_edge_private_file_safe() {
    _patch_edge_capture_file "$1" || return 2
    [ "$PATCH_EDGE_CAPTURE_UID" = "${EUID:-}" ] && [ "$PATCH_EDGE_CAPTURE_MODE" = 0600 ]
}

_patch_edge_write_private() {
    local path="$1"
    local content="$2"

    [ ! -e "$path" ] && [ ! -L "$path" ] || return 2
    (umask 077; printf '%s' "$content" > "$path") || return 2
    /bin/chmod 0600 "$path" || return 2
    _patch_edge_private_file_safe "$path"
}

_patch_edge_prepare_transaction() {
    local transaction_directory="$1"
    local mkdir_command="" owner_uid="" mode="" device="" inode="" links=""

    _patch_edge_directory_safe "$transaction_directory" no || return 2
    _patch_edge_stat_into "$transaction_directory" device inode owner_uid mode links || return 2
    [ "$owner_uid" = "${EUID:-}" ] && [ "$mode" = 0700 ] || return 2
    PATCH_EDGE_TRANSACTION_DIRECTORY="$(CDPATH='' builtin cd -P -- "$transaction_directory" && pwd -P)" || return 2
    PATCH_EDGE_DATA_DIRECTORY="$PATCH_EDGE_TRANSACTION_DIRECTORY/edge"
    [ ! -e "$PATCH_EDGE_DATA_DIRECTORY" ] && [ ! -L "$PATCH_EDGE_DATA_DIRECTORY" ] || return 2
    _patch_edge_command_into mkdir mkdir_command || return $?
    (umask 077; "$mkdir_command" "$PATCH_EDGE_DATA_DIRECTORY") || return 2
    _patch_edge_directory_safe "$PATCH_EDGE_DATA_DIRECTORY" no || return 2
    _patch_edge_stat_into "$PATCH_EDGE_DATA_DIRECTORY" device inode owner_uid mode links || return 2
    [ "$owner_uid" = "${EUID:-}" ] && [ "$mode" = 0700 ]
}

_patch_edge_write_state() {
    local state="$1"
    local state_path="$PATCH_EDGE_DATA_DIRECTORY/state"
    local mktemp_command="" mv_command="" stage_path=""

    case "$state" in planned|not_applicable|applying|applied|verified|rollback_in_progress|rolled_back|rollback_failed) ;; *) return 2 ;; esac
    if [ -e "$state_path" ] || [ -L "$state_path" ]; then
        [ ! -L "$state_path" ] && _patch_edge_private_file_safe "$state_path" || return 2
    fi
    _patch_edge_command_into mktemp mktemp_command || return $?
    _patch_edge_command_into mv mv_command || return $?
    stage_path="$(umask 077; "$mktemp_command" "$PATCH_EDGE_DATA_DIRECTORY/.state.XXXXXXXX")" || return 2
    if ! printf '%s\n' "$state" > "$stage_path" || ! /bin/chmod 0600 "$stage_path" || \
        ! "$mv_command" -f "$stage_path" "$state_path"; then
        /bin/rm -f "$stage_path" 2>/dev/null || true
        return 2
    fi
    _patch_edge_private_file_safe "$state_path" || return 2
    PATCH_EDGE_STATE="$state"
}

_patch_edge_safe_token() {
    [ -n "$1" ] && [ "${#1}" -le 512 ] || return 1
    case "$1" in *[!A-Za-z0-9._:@,+/%=-]*) return 1 ;; *) return 0 ;; esac
}

_patch_edge_safe_name() {
    [ -n "$1" ] && [ "${#1}" -le 64 ] || return 1
    case "$1" in [A-Za-z_]* ) case "$1" in *[!A-Za-z0-9_.-]*) return 1 ;; esac ;; *) return 1 ;; esac
}

_patch_edge_validate_port() {
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

_patch_edge_validate_cidr() {
    local value="$1"
    local address="${value%/*}"
    local prefix="${value##*/}"
    local octet=""
    local -a octets=()

    [ "$address" != "$value" ] || return 1
    case "$prefix" in ''|*[!0-9]*) return 1 ;; esac
    if [[ "$address" == *:* ]]; then
        [[ "$address" =~ ^[0-9A-Fa-f:]+$ ]] || return 1
        [[ "$address" != *:::* ]] || return 1
        [ "$prefix" -le 128 ]
        return
    fi
    IFS=. read -r -a octets <<< "$address"
    [ "${#octets[@]}" -eq 4 ] && [ "$prefix" -le 32 ] || return 1
    for octet in "${octets[@]}"; do
        case "$octet" in ''|*[!0-9]*) return 1 ;; esac
        [ "$octet" -le 255 ] || return 1
    done
}

_patch_edge_validate_cidr_list() {
    local value="$1"
    local cidr=""
    local -a cidrs=()

    [ -n "$value" ] || return 1
    case "$value" in *[[:space:]]*|,*|*,|*,,*) return 1 ;; esac
    IFS=, read -r -a cidrs <<< "$value"
    [ "${#cidrs[@]}" -gt 0 ] || return 1
    for cidr in "${cidrs[@]}"; do
        _patch_edge_validate_cidr "$cidr" || return 1
    done
}

_patch_edge_validate_denied_accounts() {
    local value="$1"
    local account="" root_found=0
    local -a accounts=()

    case "$value" in ''|,*|*,|*,,*|*[[:space:]]*) return 1 ;; esac
    IFS=, read -r -a accounts <<< "$value"
    for account in "${accounts[@]}"; do
        _patch_edge_safe_name "$account" || return 1
        [ "$account" != root ] || root_found=1
    done
    [ "$root_found" -eq 1 ]
}

_patch_edge_validate_secret_reference() {
    case "$1" in secret://*) _patch_edge_safe_token "$1" ;; *) return 1 ;; esac
}

_patch_edge_callback_required() {
    local role="$1"
    local callback_path="${PATCH_EDGE_CALLBACKS[$role]:-}"

    [ -n "$callback_path" ] && _patch_edge_callback_trusted "$callback_path"
}

_patch_edge_probe_provider() {
    local criterion="$1"
    local provider="$2"
    local callback_path="${PATCH_EDGE_CALLBACKS[provider_probe]:-}"
    local output=""

    _patch_edge_callback_required provider_probe || return 2
    output="$("$callback_path" "$criterion" "$provider" "$PATCH_EDGE_ROOT" 2>/dev/null)" || return 2
    case "$output" in present|absent|complex) printf '%s\n' "$output" ;; *) return 2 ;; esac
}

_patch_edge_policy_approved() {
    local callback_path="${PATCH_EDGE_CALLBACKS[policy_verifier]:-}"

    _patch_edge_callback_required policy_verifier || return 2
    "$callback_path" "$@"
}

_patch_edge_native_validate() {
    local phase="$1"
    local callback_path="${PATCH_EDGE_CALLBACKS[native_validator]:-}"

    _patch_edge_callback_required native_validator || return 2
    "$callback_path" "$PATCH_EDGE_CRITERION" "$phase" "$PATCH_EDGE_PROVIDER" \
        "$PATCH_EDGE_BACKEND" "$PATCH_EDGE_ROOT" "$PATCH_EDGE_PAYLOAD_PATH"
}

_patch_edge_verify_live() {
    local role="" callback_path=""

    for role in runtime_probe protocol_probe; do
        callback_path="${PATCH_EDGE_CALLBACKS[$role]:-}"
        _patch_edge_callback_required "$role" || return 2
        "$callback_path" "$PATCH_EDGE_CRITERION" "$PATCH_EDGE_PROVIDER" \
            "$PATCH_EDGE_BACKEND" "$PATCH_EDGE_ROOT" "$PATCH_EDGE_TRANSACTION_DIRECTORY" || return 2
    done
}

_patch_edge_payload_has_secret() {
    LC_ALL=C grep -Eiq '(^|[^A-Za-z0-9])(password|passphrase|authpass|privpass|secret|token|private[_-]?key|credential)[[:space:]]*[:=]' "$1" 2>/dev/null
}

_patch_edge_snapshot() {
    local callback_path="${PATCH_EDGE_CALLBACKS[snapshot]:-}"
    local output=""

    _patch_edge_callback_required snapshot || return 2
    output="$("$callback_path" capture "$PATCH_EDGE_CRITERION" "$PATCH_EDGE_DOMAIN" \
        "$PATCH_EDGE_PROVIDER" "$PATCH_EDGE_BACKEND" "$PATCH_EDGE_ROOT" \
        "$PATCH_EDGE_TRANSACTION_DIRECTORY" 2>/dev/null)" || return 2
    [ "${#output}" -eq 64 ] || return 2
    case "$output" in *[!0-9a-f]*) return 2 ;; esac
    PATCH_EDGE_SNAPSHOT_SHA256="$output"
}

_patch_edge_write_manifest_and_checksums() {
    local manifest_content="" plan_content="" checksum_content=""
    local manifest_digest="" plan_digest="" payload_digest=""

    printf -v manifest_content '%s\n1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$PATCH_EDGE_MANIFEST_HEADER" "$PATCH_EDGE_CRITERION" "$PATCH_EDGE_DOMAIN" \
        "$PATCH_EDGE_ROOT" "$PATCH_EDGE_ROOT_DEVICE" "$PATCH_EDGE_ROOT_INODE" \
        "${PATCH_EDGE_PROVIDER:--}" "${PATCH_EDGE_BACKEND:--}" \
        "$PATCH_EDGE_PAYLOAD_SHA256" "$PATCH_EDGE_APPROVAL" \
        "$PATCH_EDGE_SNAPSHOT_SHA256" "$PATCH_EDGE_SECRET_REFERENCE_SHA256"
    printf -v plan_content '%s\n1\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$PATCH_EDGE_PLAN_HEADER" "$PATCH_EDGE_CRITERION" "$PATCH_EDGE_STATE" \
        "$PATCH_EDGE_DOMAIN" "${PATCH_EDGE_PROVIDER:--}" "${PATCH_EDGE_BACKEND:--}" \
        "$PATCH_EDGE_PAYLOAD_SHA256" "$PATCH_EDGE_APPROVAL" "$PATCH_EDGE_SNAPSHOT_SHA256"
    _patch_edge_write_private "$PATCH_EDGE_DATA_DIRECTORY/manifest.tsv" "$manifest_content" || return 2
    _patch_edge_write_private "$PATCH_EDGE_DATA_DIRECTORY/plan.tsv" "$plan_content" || return 2
    _patch_edge_sha256_into "$PATCH_EDGE_DATA_DIRECTORY/manifest.tsv" manifest_digest || return 2
    _patch_edge_sha256_into "$PATCH_EDGE_DATA_DIRECTORY/plan.tsv" plan_digest || return 2
    checksum_content="$PATCH_EDGE_CHECKSUM_HEADER"$'\n'
    printf -v checksum_content '%s1\tmanifest.tsv\t%s\n1\tplan.tsv\t%s\n' \
        "$checksum_content" "$manifest_digest" "$plan_digest"
    if [ "$PATCH_EDGE_PAYLOAD_SHA256" != - ]; then
        _patch_edge_sha256_into "$PATCH_EDGE_PAYLOAD_PATH" payload_digest || return 2
        [ "$payload_digest" = "$PATCH_EDGE_PAYLOAD_SHA256" ] || return 2
        printf -v checksum_content '%s1\tpayload.rules\t%s\n' "$checksum_content" "$payload_digest"
    fi
    _patch_edge_write_private "$PATCH_EDGE_DATA_DIRECTORY/checksums.tsv" "$checksum_content"
}

_patch_edge_plan_not_applicable() {
    local transaction_directory="$1"

    _patch_edge_prepare_transaction "$transaction_directory" || return 2
    PATCH_EDGE_PAYLOAD_PATH="-"
    PATCH_EDGE_PAYLOAD_SHA256="-"
    PATCH_EDGE_SNAPSHOT_SHA256="-"
    PATCH_EDGE_SECRET_REFERENCE_SHA256="-"
    PATCH_EDGE_STATE=not_applicable
    PATCH_EDGE_PLAN_VALID=1
    _patch_edge_write_manifest_and_checksums || return 2
    _patch_edge_write_state not_applicable
}

_patch_edge_plan_present() {
    local transaction_directory="$1"
    local payload="$2"
    local role=""

    for role in native_validator runtime_probe protocol_probe snapshot apply rollback; do
        _patch_edge_callback_required "$role" || { _patch_edge_set_error "required edge callback is unavailable: $role"; return 2; }
    done
    _patch_edge_prepare_transaction "$transaction_directory" || return 2
    PATCH_EDGE_PAYLOAD_PATH="$PATCH_EDGE_DATA_DIRECTORY/payload.rules"
    _patch_edge_write_private "$PATCH_EDGE_PAYLOAD_PATH" "$payload" || return 2
    _patch_edge_payload_has_secret "$PATCH_EDGE_PAYLOAD_PATH" && { _patch_edge_set_error "edge payload contains secret-like material"; return 2; }
    PATCH_EDGE_PAYLOAD_SHA256="$PATCH_EDGE_CAPTURE_SHA256"
    _patch_edge_native_validate pre || { _patch_edge_set_error "native edge syntax validation failed"; return 2; }
    _patch_edge_snapshot || { _patch_edge_set_error "edge configuration and runtime snapshot failed"; return 2; }
    PATCH_EDGE_STATE=planned
    PATCH_EDGE_PLAN_VALID=1
    _patch_edge_write_manifest_and_checksums || return 2
    _patch_edge_write_state planned
}

_patch_edge_probe_or_finish() {
    local criterion="$1"
    local provider="$2"
    local transaction_directory="$3"
    local probe_state=""

    probe_state="$(_patch_edge_probe_provider "$criterion" "$provider")" || return 2
    case "$probe_state" in
        present) return 1 ;;
        absent) _patch_edge_plan_not_applicable "$transaction_directory"; return 0 ;;
        complex) _patch_edge_set_error "$criterion uses a complex provider invocation or include graph"; return 2 ;;
    esac
}

_patch_edge_probe_state_into() {
    local criterion="$1"
    local provider="$2"
    local destination_name="$3"
    local probe_result=""

    _patch_edge_valid_destination "$destination_name" || return 2
    probe_result="$(_patch_edge_probe_provider "$criterion" "$provider")" || return 2
    printf -v "$destination_name" '%s' "$probe_result"
}

_patch_edge_begin() {
    local criterion="$1"
    local requested_root="$2"
    local domain="$3"
    local provider="$4"
    local backend="$5"
    local approval="$6"

    patch_edge_reset
    _patch_edge_safe_token "$approval" || { _patch_edge_set_error "$criterion approval identifier is invalid"; return 2; }
    _patch_edge_initialize_root "$requested_root" || { _patch_edge_set_error "$criterion root is unsafe"; return 2; }
    PATCH_EDGE_CRITERION="$criterion"
    PATCH_EDGE_DOMAIN="$domain"
    PATCH_EDGE_PROVIDER="$provider"
    PATCH_EDGE_BACKEND="$backend"
    PATCH_EDGE_APPROVAL="$approval"
}

_patch_edge_finish_absent_if_needed() {
    local provider="$1"
    local transaction_directory="$2"
    local probe_state=""

    _patch_edge_probe_state_into "$PATCH_EDGE_CRITERION" "$provider" probe_state || {
        _patch_edge_set_error "$PATCH_EDGE_CRITERION provider probe failed"
        return 2
    }
    case "$probe_state" in
        present) return 1 ;;
        absent) _patch_edge_plan_not_applicable "$transaction_directory"; return 0 ;;
        complex)
            _patch_edge_set_error "$PATCH_EDGE_CRITERION complex custom invocation or include graph is not actionable"
            return 2
            ;;
    esac
}

_patch_edge_render_firewall_payload_into() {
    local criterion="$1"
    local backend="$2"
    local cidr_list="$3"
    local port="$4"
    local protocol="$5"
    local destination_name="$6"
    local cidr="" family="" rendered=""
    local -a cidrs=()

    _patch_edge_valid_destination "$destination_name" || return 2
    _patch_edge_validate_cidr_list "$cidr_list" && _patch_edge_validate_port "$port" || return 2
    case "$protocol" in tcp|udp) ;; *) return 2 ;; esac
    IFS=, read -r -a cidrs <<< "$cidr_list"
    case "$backend" in
        nftables)
            printf -v rendered '# kisa-cce %s managed rules\ntable inet kisa_cce_%s {\n chain input { type filter hook input priority 0; policy drop;\n' "$criterion" "${criterion#U-}"
            for cidr in "${cidrs[@]}"; do
                if [[ "$cidr" == *:* ]]; then family=ip6; else family=ip; fi
                printf -v rendered '%s  %s saddr %s meta l4proto %s %s dport %s accept\n' \
                    "$rendered" "$family" "$cidr" "$protocol" "$protocol" "$port"
            done
            rendered+=' }'$'\n''}'$'\n'
            ;;
        ufw)
            printf -v rendered '# kisa-cce %s managed rules\ndefault deny incoming\n' "$criterion"
            for cidr in "${cidrs[@]}"; do
                printf -v rendered '%sallow proto %s from %s to any port %s\n' \
                    "$rendered" "$protocol" "$cidr" "$port"
            done
            ;;
        firewalld)
            printf -v rendered '# kisa-cce %s managed rules\ntarget=DROP\n' "$criterion"
            for cidr in "${cidrs[@]}"; do
                if [[ "$cidr" == *:* ]]; then family=ipv6; else family=ipv4; fi
                printf -v rendered '%srule family=%s source address=%s port port=%s protocol=%s accept\n' \
                    "$rendered" "$family" "$cidr" "$port" "$protocol"
            done
            ;;
        *) return 1 ;;
    esac
    printf -v "$destination_name" '%s' "$rendered"
}

_patch_edge_plan_firewall_common() {
    local criterion="$1"
    local requested_root="$2"
    local transaction_directory="$3"
    local provider="$4"
    local backend="$5"
    local cidr_list="$6"
    local port="$7"
    local protocol="$8"
    local approval="$9"
    local probe_status=0 payload=""

    case "$backend" in nftables|ufw|firewalld) ;; *) _patch_edge_set_error "unsupported firewall backend"; return 1 ;; esac
    _patch_edge_begin "$criterion" "$requested_root" firewall "$provider" "$backend" "$approval" || return 2
    _patch_edge_validate_cidr_list "$cidr_list" && _patch_edge_validate_port "$port" || { _patch_edge_set_error "$criterion firewall tuple is invalid"; return 2; }
    case "$protocol" in tcp|udp) ;; *) _patch_edge_set_error "$criterion protocol is invalid"; return 2 ;; esac
    _patch_edge_finish_absent_if_needed "$provider" "$transaction_directory" || probe_status=$?
    case "$probe_status" in 0) return 0 ;; 1) ;; *) return 2 ;; esac
    _patch_edge_policy_approved "$criterion" "$approval" "$provider" "$backend" \
        "$cidr_list" "$port" "$protocol" || { _patch_edge_set_error "$criterion firewall policy is not approved"; return 2; }
    _patch_edge_render_firewall_payload_into "$criterion" "$backend" "$cidr_list" \
        "$port" "$protocol" payload || return 2
    _patch_edge_plan_present "$transaction_directory" "$payload"
}

patch_edge_u01_plan() {
    local requested_root="$1"
    local transaction_directory="$2"
    local transport="$3"
    local approval="$4"
    local probe_status=0 payload=""

    case "$transport" in openssh|telnet) ;; *) _patch_edge_set_error "unsupported U-01 transport"; return 1 ;; esac
    _patch_edge_begin U-01 "$requested_root" service "$transport" - "$approval" || return 2
    _patch_edge_finish_absent_if_needed "$transport" "$transaction_directory" || probe_status=$?
    case "$probe_status" in 0) return 0 ;; 1) ;; *) return 2 ;; esac
    _patch_edge_policy_approved U-01 "$approval" "$transport" || { _patch_edge_set_error "U-01 remote-root policy is not approved"; return 2; }
    if [ "$transport" = openssh ]; then
        payload=$'# Managed by kisa-cce-patch.\n# target=/etc/ssh/sshd_config.d/99-kisa-cce-root-login.conf\nPermitRootLogin no\n'
    else
        payload=$'# Explicit Telnet disable delegate.\naction=disable\nservice=telnet\n'
    fi
    _patch_edge_plan_present "$transaction_directory" "$payload"
}

patch_edge_u28_plan() {
    _patch_edge_plan_firewall_common U-28 "$1" "$2" "$3" "$3" "$4" "$5" "$6" "$7"
}

patch_edge_u53_plan() {
    local requested_root="$1"
    local transaction_directory="$2"
    local provider="$3"
    local banner="$4"
    local approval="$5"
    local probe_status=0 payload=""

    case "$provider" in vsftpd|proftpd) ;; *) _patch_edge_set_error "unsupported U-53 FTP provider"; return 1 ;; esac
    [ -n "$banner" ] && [ "${#banner}" -le 256 ] || { _patch_edge_set_error "U-53 banner is invalid"; return 2; }
    case "$banner" in *$'\n'*|*$'\r'*|*$'\t'*) _patch_edge_set_error "U-53 banner contains a control byte"; return 2 ;; esac
    _patch_edge_begin U-53 "$requested_root" configuration "$provider" - "$approval" || return 2
    _patch_edge_finish_absent_if_needed "$provider" "$transaction_directory" || probe_status=$?
    case "$probe_status" in 0) return 0 ;; 1) ;; *) return 2 ;; esac
    _patch_edge_policy_approved U-53 "$approval" "$provider" "$banner" || { _patch_edge_set_error "U-53 banner policy is not approved"; return 2; }
    case "$provider" in
        vsftpd) printf -v payload '# Managed provider directive.\n# config=/etc/vsftpd.conf\nftpd_banner=%s\n' "$banner" ;;
        proftpd) printf -v payload '# Managed provider directives.\n# config=/etc/proftpd/conf.d/99-kisa-cce.conf\n# banner=/etc/proftpd/kisa-cce-banner.txt\nServerIdent off\nDisplayConnect /etc/proftpd/kisa-cce-banner.txt\nbanner_text=%s\n' "$banner" ;;
    esac
    _patch_edge_plan_present "$transaction_directory" "$payload"
}

patch_edge_u56_plan() {
    local requested_root="$1"
    local transaction_directory="$2"
    local ftp_provider="$3"
    local backend="$4"
    local cidr_list="$5"
    local port="$6"
    local protocol="$7"
    local approval="$8"
    local probe_state="" payload=""

    case "$backend" in nftables|ufw|firewalld) ;; *) _patch_edge_set_error "unsupported U-56 firewall backend"; return 1 ;; esac
    _patch_edge_validate_cidr_list "$cidr_list" && _patch_edge_validate_port "$port" || { _patch_edge_set_error "U-56 firewall tuple is invalid"; return 2; }
    case "$protocol" in tcp|udp) ;; *) _patch_edge_set_error "U-56 protocol is invalid"; return 2 ;; esac
    case "$ftp_provider" in vsftpd|proftpd) ;; *) _patch_edge_set_error "unsupported U-56 FTP provider"; return 1 ;; esac
    _patch_edge_begin U-56 "$requested_root" firewall "$ftp_provider" "$backend" "$approval" || return 2
    _patch_edge_probe_state_into U-56 "$ftp_provider" probe_state || return 2
    case "$probe_state" in
        absent) _patch_edge_plan_not_applicable "$transaction_directory"; return ;;
        complex) _patch_edge_set_error "U-56 complex FTP invocation is not actionable"; return 2 ;;
    esac
    _patch_edge_probe_state_into U-56 "$backend" probe_state || return 2
    case "$probe_state" in
        absent) _patch_edge_plan_not_applicable "$transaction_directory"; return ;;
        complex) _patch_edge_set_error "U-56 complex firewall invocation is not actionable"; return 2 ;;
    esac
    _patch_edge_policy_approved U-56 "$approval" "$ftp_provider" "$backend" \
        "$cidr_list" "$port" "$protocol" || { _patch_edge_set_error "U-56 FTP client policy is not approved"; return 2; }
    _patch_edge_render_firewall_payload_into U-56 "$backend" "$cidr_list" "$port" "$protocol" payload || return 2
    _patch_edge_plan_present "$transaction_directory" "$payload"
}

patch_edge_u57_plan() {
    local requested_root="$1"
    local transaction_directory="$2"
    local provider="$3"
    local denied_accounts="$4"
    local approval="$5"
    local probe_status=0 payload=""

    case "$provider" in vsftpd|proftpd) ;; *) _patch_edge_set_error "unsupported U-57 FTP provider"; return 1 ;; esac
    _patch_edge_validate_denied_accounts "$denied_accounts" || { _patch_edge_set_error "U-57 denied-account set must contain root"; return 2; }
    _patch_edge_begin U-57 "$requested_root" configuration "$provider" - "$approval" || return 2
    _patch_edge_finish_absent_if_needed "$provider" "$transaction_directory" || probe_status=$?
    case "$probe_status" in 0) return 0 ;; 1) ;; *) return 2 ;; esac
    _patch_edge_policy_approved U-57 "$approval" "$provider" "$denied_accounts" || { _patch_edge_set_error "U-57 denied-account policy is not approved"; return 2; }
    case "$provider" in
        vsftpd) printf -v payload '# Managed provider directives.\n# config=/etc/vsftpd.conf\n# deny_file=/etc/ftpusers\nuserlist_enable=YES\nuserlist_deny=YES\nuserlist_file=/etc/ftpusers\ndeny_users=%s\n' "$denied_accounts" ;;
        proftpd) printf -v payload '# Managed provider directives.\n# config=/etc/proftpd/conf.d/99-kisa-cce.conf\n# deny_file=/etc/ftpusers\nRootLogin off\nUseFtpUsers on\ndeny_users=%s\n' "$denied_accounts" ;;
    esac
    _patch_edge_plan_present "$transaction_directory" "$payload"
}

_patch_edge_plan_snmp_common() {
    local criterion="$1"
    local requested_root="$2"
    local transaction_directory="$3"
    local security_name="$4"
    local secret_reference="$5"
    local view_name="$6"
    local approval="$7"
    local probe_status=0 payload=""

    _patch_edge_safe_name "$security_name" && _patch_edge_safe_name "$view_name" || { _patch_edge_set_error "$criterion SNMP identity is invalid"; return 2; }
    _patch_edge_validate_secret_reference "$secret_reference" || { _patch_edge_set_error "$criterion requires a typed secret reference"; return 2; }
    _patch_edge_begin "$criterion" "$requested_root" configuration net-snmp - "$approval" || return 2
    _patch_edge_finish_absent_if_needed net-snmp "$transaction_directory" || probe_status=$?
    case "$probe_status" in 0) return 0 ;; 1) ;; *) return 2 ;; esac
    _patch_edge_policy_approved "$criterion" "$approval" net-snmp "$security_name" \
        "$secret_reference" "$view_name" authPriv || { _patch_edge_set_error "$criterion SNMPv3 policy is not approved"; return 2; }
    PATCH_EDGE_SECRET_REFERENCE="$secret_reference"
    _patch_edge_string_sha256_into "$secret_reference" PATCH_EDGE_SECRET_REFERENCE_SHA256 || return 2
    printf -v payload '# Managed Net-SNMP VACM directives.\n# config=/etc/snmp/snmpd.conf\nview %s included .1\nrouser %s authPriv -V %s\n' \
        "$view_name" "$security_name" "$view_name"
    _patch_edge_plan_present "$transaction_directory" "$payload"
}

patch_edge_u59_plan() {
    _patch_edge_plan_snmp_common U-59 "$@"
}

patch_edge_u60_plan() {
    _patch_edge_plan_snmp_common U-60 "$@"
}

patch_edge_u61_plan() {
    local requested_root="$1"
    local transaction_directory="$2"
    local backend="$3"
    local cidr_list="$4"
    local port="$5"
    local protocol="$6"
    local security_name="$7"
    local secret_reference="$8"
    local view_name="$9"
    local approval="${10}"
    local probe_state="" firewall_payload="" payload=""

    case "$backend" in nftables|ufw|firewalld) ;; *) _patch_edge_set_error "unsupported U-61 firewall backend"; return 1 ;; esac
    _patch_edge_validate_cidr_list "$cidr_list" && _patch_edge_validate_port "$port" || { _patch_edge_set_error "U-61 firewall tuple is invalid"; return 2; }
    case "$protocol" in tcp|udp) ;; *) _patch_edge_set_error "U-61 protocol is invalid"; return 2 ;; esac
    _patch_edge_safe_name "$security_name" && _patch_edge_safe_name "$view_name" || { _patch_edge_set_error "U-61 SNMP identity is invalid"; return 2; }
    _patch_edge_validate_secret_reference "$secret_reference" || { _patch_edge_set_error "U-61 requires a typed secret reference"; return 2; }
    _patch_edge_begin U-61 "$requested_root" firewall_snmp net-snmp "$backend" "$approval" || return 2
    _patch_edge_probe_state_into U-61 net-snmp probe_state || return 2
    case "$probe_state" in
        absent) _patch_edge_plan_not_applicable "$transaction_directory"; return ;;
        complex) _patch_edge_set_error "U-61 complex SNMP invocation or include graph is not actionable"; return 2 ;;
    esac
    _patch_edge_probe_state_into U-61 "$backend" probe_state || return 2
    case "$probe_state" in
        absent) _patch_edge_plan_not_applicable "$transaction_directory"; return ;;
        complex) _patch_edge_set_error "U-61 complex firewall invocation is not actionable"; return 2 ;;
    esac
    _patch_edge_policy_approved U-61 "$approval" net-snmp "$backend" "$cidr_list" \
        "$port" "$protocol" "$security_name" "$secret_reference" "$view_name" authPriv || { _patch_edge_set_error "U-61 SNMP manager policy is not approved"; return 2; }
    PATCH_EDGE_SECRET_REFERENCE="$secret_reference"
    _patch_edge_string_sha256_into "$secret_reference" PATCH_EDGE_SECRET_REFERENCE_SHA256 || return 2
    _patch_edge_render_firewall_payload_into U-61 "$backend" "$cidr_list" "$port" "$protocol" firewall_payload || return 2
    printf -v payload '# Managed Net-SNMP VACM directives.\n# config=/etc/snmp/snmpd.conf\nview %s included .1\nrouser %s authPriv -V %s\n%s' \
        "$view_name" "$security_name" "$view_name" "$firewall_payload"
    _patch_edge_plan_present "$transaction_directory" "$payload"
}

validate_u01_remote_root_access_v2() {
    [ "$PATCH_EDGE_PLAN_VALID" -eq 1 ] && [ "$PATCH_EDGE_CRITERION" = U-01 ] && { [ "$PATCH_EDGE_STATE" = verified ] || [ "$PATCH_EDGE_STATE" = not_applicable ]; }
}

validate_u28_network_access_v2() {
    [ "$PATCH_EDGE_PLAN_VALID" -eq 1 ] && [ "$PATCH_EDGE_CRITERION" = U-28 ] && { [ "$PATCH_EDGE_STATE" = verified ] || [ "$PATCH_EDGE_STATE" = not_applicable ]; }
}

validate_u53_ftp_banner_v2() {
    [ "$PATCH_EDGE_PLAN_VALID" -eq 1 ] && [ "$PATCH_EDGE_CRITERION" = U-53 ] && { [ "$PATCH_EDGE_STATE" = verified ] || [ "$PATCH_EDGE_STATE" = not_applicable ]; }
}

validate_u56_ftp_access_v2() {
    [ "$PATCH_EDGE_PLAN_VALID" -eq 1 ] && [ "$PATCH_EDGE_CRITERION" = U-56 ] && { [ "$PATCH_EDGE_STATE" = verified ] || [ "$PATCH_EDGE_STATE" = not_applicable ]; }
}

validate_u57_ftp_denied_users_v2() {
    [ "$PATCH_EDGE_PLAN_VALID" -eq 1 ] && [ "$PATCH_EDGE_CRITERION" = U-57 ] && { [ "$PATCH_EDGE_STATE" = verified ] || [ "$PATCH_EDGE_STATE" = not_applicable ]; }
}

validate_u59_snmp_version_v2() {
    [ "$PATCH_EDGE_PLAN_VALID" -eq 1 ] && [ "$PATCH_EDGE_CRITERION" = U-59 ] && { [ "$PATCH_EDGE_STATE" = verified ] || [ "$PATCH_EDGE_STATE" = not_applicable ]; }
}

validate_u60_snmp_community_v2() {
    [ "$PATCH_EDGE_PLAN_VALID" -eq 1 ] && [ "$PATCH_EDGE_CRITERION" = U-60 ] && { [ "$PATCH_EDGE_STATE" = verified ] || [ "$PATCH_EDGE_STATE" = not_applicable ]; }
}

validate_u61_snmp_access_v2() {
    [ "$PATCH_EDGE_PLAN_VALID" -eq 1 ] && [ "$PATCH_EDGE_CRITERION" = U-61 ] && { [ "$PATCH_EDGE_STATE" = verified ] || [ "$PATCH_EDGE_STATE" = not_applicable ]; }
}

_patch_edge_write_applied_record() {
    local applied_digest="$1"
    local content="" record_digest="" checksum_content=""

    [ "${#applied_digest}" -eq 64 ] || return 2
    case "$applied_digest" in *[!0-9a-f]*) return 2 ;; esac
    printf -v content '%s\n1\t%s\t%s\n' "$PATCH_EDGE_APPLIED_HEADER" \
        "$PATCH_EDGE_CRITERION" "$applied_digest"
    _patch_edge_write_private "$PATCH_EDGE_DATA_DIRECTORY/applied.tsv" "$content" || return 2
    _patch_edge_sha256_into "$PATCH_EDGE_DATA_DIRECTORY/applied.tsv" record_digest || return 2
    printf -v checksum_content '%s\n1\tapplied.tsv\t%s\n' \
        "$PATCH_EDGE_CHECKSUM_HEADER" "$record_digest"
    _patch_edge_write_private "$PATCH_EDGE_DATA_DIRECTORY/applied-checksum.tsv" "$checksum_content" || return 2
    PATCH_EDGE_APPLIED_SHA256="$applied_digest"
}

_patch_edge_rollback_loaded() {
    local mode="$1"
    local callback_path="${PATCH_EDGE_CALLBACKS[rollback]:-}"
    local snapshot_callback="${PATCH_EDGE_CALLBACKS[snapshot]:-}"
    local output=""

    [ "${EUID:-$(id -u)}" -eq 0 ] || { _patch_edge_set_error "edge rollback requires effective UID 0"; return 2; }
    [ "$PATCH_EDGE_PLAN_VALID" -eq 1 ] && [ "$PATCH_EDGE_APPLY_STARTED" -eq 1 ] || return 2
    case "$PATCH_EDGE_STATE" in applying|applied|verified|rollback_in_progress|rollback_failed) ;; *) return 2 ;; esac
    case "$mode" in
        strict) [ -n "$PATCH_EDGE_APPLIED_SHA256" ] || { _patch_edge_set_error "strict edge rollback requires an applied record"; return 2; } ;;
        transition) ;;
        *) return 2 ;;
    esac
    _patch_edge_callback_required rollback && _patch_edge_callback_required snapshot || { _patch_edge_set_error "edge rollback callbacks are unavailable"; return 2; }
    _patch_edge_write_state rollback_in_progress || return 2
    output="$("$callback_path" "$PATCH_EDGE_CRITERION" "$PATCH_EDGE_DOMAIN" \
        "$PATCH_EDGE_PROVIDER" "$PATCH_EDGE_BACKEND" "$PATCH_EDGE_ROOT" \
        "$PATCH_EDGE_TRANSACTION_DIRECTORY" "$mode" "$PATCH_EDGE_SNAPSHOT_SHA256" \
        "${PATCH_EDGE_APPLIED_SHA256:--}" 2>/dev/null)" || {
            _patch_edge_write_state rollback_failed >/dev/null 2>&1 || true
            _patch_edge_set_error "edge rollback callback failed"
            return 2
        }
    [ "$output" = restored ] || {
        _patch_edge_write_state rollback_failed >/dev/null 2>&1 || true
        _patch_edge_set_error "edge rollback callback returned an invalid result"
        return 2
    }
    "$snapshot_callback" verify "$PATCH_EDGE_CRITERION" "$PATCH_EDGE_DOMAIN" \
        "$PATCH_EDGE_PROVIDER" "$PATCH_EDGE_BACKEND" "$PATCH_EDGE_ROOT" \
        "$PATCH_EDGE_TRANSACTION_DIRECTORY" "$PATCH_EDGE_SNAPSHOT_SHA256" || {
            _patch_edge_write_state rollback_failed >/dev/null 2>&1 || true
            _patch_edge_set_error "edge rollback verification failed"
            return 2
        }
    _patch_edge_write_state rolled_back
}

patch_edge_rollback() {
    _patch_edge_rollback_loaded transition
}

patch_edge_apply() {
    local callback_path="${PATCH_EDGE_CALLBACKS[apply]:-}"
    local output="" rollback_status=0 verification_error=""

    [ "${EUID:-$(id -u)}" -eq 0 ] || { _patch_edge_set_error "edge apply requires effective UID 0"; return 2; }
    [ "$PATCH_EDGE_PLAN_VALID" -eq 1 ] || return 2
    if [ "$PATCH_EDGE_STATE" = not_applicable ]; then
        return 0
    fi
    [ "$PATCH_EDGE_STATE" = planned ] || return 2
    _patch_edge_callback_required apply || { _patch_edge_set_error "edge apply callback is unavailable"; return 2; }
    _patch_edge_native_validate pre || return 2
    PATCH_EDGE_APPLY_STARTED=1
    _patch_edge_write_state applying || return 2
    output="$(printf '%s\0' "$PATCH_EDGE_SECRET_REFERENCE" | \
        "$callback_path" "$PATCH_EDGE_CRITERION" "$PATCH_EDGE_DOMAIN" \
            "$PATCH_EDGE_PROVIDER" "$PATCH_EDGE_BACKEND" "$PATCH_EDGE_ROOT" \
            "$PATCH_EDGE_TRANSACTION_DIRECTORY" "$PATCH_EDGE_PAYLOAD_PATH" 2>/dev/null)" || {
                patch_edge_rollback >/dev/null 2>&1 || rollback_status=$?
                _patch_edge_set_error "edge apply callback failed; rollback_status=$rollback_status"
                return 2
            }
    _patch_edge_write_applied_record "$output" || {
        patch_edge_rollback >/dev/null 2>&1 || rollback_status=$?
        _patch_edge_set_error "edge applied record is invalid; rollback_status=$rollback_status"
        return 2
    }
    _patch_edge_write_state applied || {
        patch_edge_rollback >/dev/null 2>&1 || rollback_status=$?
        _patch_edge_set_error "edge applied state cannot be written; rollback_status=$rollback_status"
        return 2
    }
    if ! _patch_edge_native_validate post || ! _patch_edge_verify_live; then
        verification_error="edge native or live verification failed"
        patch_edge_rollback >/dev/null 2>&1 || rollback_status=$?
        _patch_edge_set_error "$verification_error; rollback_status=$rollback_status"
        return 2
    fi
    _patch_edge_write_state verified || {
        patch_edge_rollback >/dev/null 2>&1 || rollback_status=$?
        _patch_edge_set_error "edge verified state cannot be written; rollback_status=$rollback_status"
        return 2
    }
}

_patch_edge_load_checksum_inventory() {
    local checksum_path="$PATCH_EDGE_DATA_DIRECTORY/checksums.tsv"
    local line="" schema="" relative_path="" recorded_digest="" extra="" actual_digest=""
    local first=1 count=0
    local -A seen=()

    _patch_edge_private_file_safe "$checksum_path" || return 2
    while IFS= read -r line || [ -n "$line" ]; do
        if [ "$first" -eq 1 ]; then
            [ "$line" = "$PATCH_EDGE_CHECKSUM_HEADER" ] || return 2
            first=0
            continue
        fi
        IFS=$'\t' read -r schema relative_path recorded_digest extra <<< "$line"
        [ -z "$extra" ] && [ "$schema" = 1 ] || return 2
        case "$relative_path" in manifest.tsv|plan.tsv|payload.rules) ;; *) return 2 ;; esac
        [ -z "${seen[$relative_path]:-}" ] || return 2
        _patch_edge_private_file_safe "$PATCH_EDGE_DATA_DIRECTORY/$relative_path" || return 2
        _patch_edge_sha256_into "$PATCH_EDGE_DATA_DIRECTORY/$relative_path" actual_digest || return 2
        [ "$recorded_digest" = "$actual_digest" ] || return 2
        seen["$relative_path"]=1
        count=$((count + 1))
    done < "$checksum_path"
    [ "$first" -eq 0 ] && [ "${seen[manifest.tsv]:-}" = 1 ] && [ "${seen[plan.tsv]:-}" = 1 ] || return 2
    case "$count" in 2) [ -z "${seen[payload.rules]:-}" ] ;; 3) [ "${seen[payload.rules]:-}" = 1 ] ;; *) return 2 ;; esac
}

_patch_edge_load_state() {
    local -a lines=()

    _patch_edge_private_file_safe "$PATCH_EDGE_DATA_DIRECTORY/state" || return 2
    mapfile -t lines < "$PATCH_EDGE_DATA_DIRECTORY/state" || return 2
    [ "${#lines[@]}" -eq 1 ] || return 2
    case "${lines[0]}" in planned|not_applicable|applying|applied|verified|rollback_in_progress|rolled_back|rollback_failed) ;; *) return 2 ;; esac
    PATCH_EDGE_STATE="${lines[0]}"
}

_patch_edge_load_applied() {
    local record_path="$PATCH_EDGE_DATA_DIRECTORY/applied.tsv"
    local checksum_path="$PATCH_EDGE_DATA_DIRECTORY/applied-checksum.tsv"
    local -a record_lines=() checksum_lines=()
    local schema="" criterion="" applied_digest="" extra=""
    local checksum_schema="" checksum_name="" recorded_digest="" checksum_extra="" actual_digest=""

    if [ ! -e "$record_path" ] && [ ! -L "$record_path" ] && \
        [ ! -e "$checksum_path" ] && [ ! -L "$checksum_path" ]; then
        return 0
    fi
    _patch_edge_private_file_safe "$record_path" && _patch_edge_private_file_safe "$checksum_path" || return 2
    mapfile -t checksum_lines < "$checksum_path" || return 2
    [ "${#checksum_lines[@]}" -eq 2 ] && [ "${checksum_lines[0]}" = "$PATCH_EDGE_CHECKSUM_HEADER" ] || return 2
    IFS=$'\t' read -r checksum_schema checksum_name recorded_digest checksum_extra <<< "${checksum_lines[1]}"
    [ -z "$checksum_extra" ] && [ "$checksum_schema" = 1 ] && [ "$checksum_name" = applied.tsv ] || return 2
    _patch_edge_sha256_into "$record_path" actual_digest || return 2
    [ "$actual_digest" = "$recorded_digest" ] || return 2
    mapfile -t record_lines < "$record_path" || return 2
    [ "${#record_lines[@]}" -eq 2 ] && [ "${record_lines[0]}" = "$PATCH_EDGE_APPLIED_HEADER" ] || return 2
    IFS=$'\t' read -r schema criterion applied_digest extra <<< "${record_lines[1]}"
    [ -z "$extra" ] && [ "$schema" = 1 ] && [ "$criterion" = "$PATCH_EDGE_CRITERION" ] || return 2
    [ "${#applied_digest}" -eq 64 ] || return 2
    case "$applied_digest" in *[!0-9a-f]*) return 2 ;; esac
    PATCH_EDGE_APPLIED_SHA256="$applied_digest"
}

_patch_edge_manifest_rule_valid() {
    case "$PATCH_EDGE_CRITERION:$PATCH_EDGE_DOMAIN:$PATCH_EDGE_PROVIDER:$PATCH_EDGE_BACKEND" in
        U-01:service:openssh:-|U-01:service:telnet:-) ;;
        U-28:firewall:nftables:nftables|U-28:firewall:ufw:ufw|U-28:firewall:firewalld:firewalld) ;;
        U-53:configuration:vsftpd:-|U-53:configuration:proftpd:-) ;;
        U-56:firewall:vsftpd:nftables|U-56:firewall:vsftpd:ufw|U-56:firewall:vsftpd:firewalld|U-56:firewall:proftpd:nftables|U-56:firewall:proftpd:ufw|U-56:firewall:proftpd:firewalld) ;;
        U-57:configuration:vsftpd:-|U-57:configuration:proftpd:-) ;;
        U-59:configuration:net-snmp:-|U-60:configuration:net-snmp:-) ;;
        U-61:firewall_snmp:net-snmp:nftables|U-61:firewall_snmp:net-snmp:ufw|U-61:firewall_snmp:net-snmp:firewalld) ;;
        *) return 2 ;;
    esac
}

_patch_edge_payload_shape_valid() {
    local payload="$PATCH_EDGE_PAYLOAD_PATH"

    _patch_edge_payload_has_secret "$payload" && return 2
    case "$PATCH_EDGE_CRITERION:$PATCH_EDGE_PROVIDER" in
        U-01:openssh) grep -Fxq '# target=/etc/ssh/sshd_config.d/99-kisa-cce-root-login.conf' "$payload" && grep -Fxq 'PermitRootLogin no' "$payload" ;;
        U-01:telnet) grep -Fxq 'action=disable' "$payload" && grep -Fxq 'service=telnet' "$payload" ;;
        U-28:*|U-56:*) grep -Fq 'managed rules' "$payload" ;;
        U-53:vsftpd) grep -Fxq '# config=/etc/vsftpd.conf' "$payload" && grep -Eq '^ftpd_banner=.' "$payload" ;;
        U-53:proftpd) grep -Fxq '# config=/etc/proftpd/conf.d/99-kisa-cce.conf' "$payload" && grep -Fxq 'ServerIdent off' "$payload" && grep -Fxq 'DisplayConnect /etc/proftpd/kisa-cce-banner.txt' "$payload" ;;
        U-57:vsftpd) grep -Fxq '# deny_file=/etc/ftpusers' "$payload" && grep -Fxq 'userlist_deny=YES' "$payload" && grep -Eq '^deny_users=([^,]*,)*root(,|$)' "$payload" ;;
        U-57:proftpd) grep -Fxq '# deny_file=/etc/ftpusers' "$payload" && grep -Fxq 'RootLogin off' "$payload" && grep -Eq '^deny_users=([^,]*,)*root(,|$)' "$payload" ;;
        U-59:*|U-60:*|U-61:*) grep -Fxq '# config=/etc/snmp/snmpd.conf' "$payload" && grep -Eq '^rouser [A-Za-z_][A-Za-z0-9_.-]* authPriv -V [A-Za-z_][A-Za-z0-9_.-]*$' "$payload" ;;
        *) return 2 ;;
    esac
}

patch_edge_load_transaction() {
    local requested_root="$1"
    local transaction_directory="$2"
    local supplied_root="" supplied_device="" supplied_inode=""
    local -a manifest_lines=()
    local schema="" criterion="" domain="" recorded_root="" root_device="" root_inode=""
    local provider="" backend="" payload_digest="" approval="" snapshot_digest=""
    local secret_reference_digest="" extra="" owner_uid="" mode="" links="" device="" inode=""
    local actual_payload_digest=""

    patch_edge_reset
    _patch_edge_initialize_root "$requested_root" || { _patch_edge_set_error "edge rollback root is unsafe"; return 2; }
    supplied_root="$PATCH_EDGE_ROOT"
    supplied_device="$PATCH_EDGE_ROOT_DEVICE"
    supplied_inode="$PATCH_EDGE_ROOT_INODE"
    _patch_edge_directory_safe "$transaction_directory" no || return 2
    _patch_edge_stat_into "$transaction_directory" device inode owner_uid mode links || return 2
    [ "$owner_uid" = "${EUID:-}" ] && [ "$mode" = 0700 ] || return 2
    PATCH_EDGE_TRANSACTION_DIRECTORY="$(CDPATH='' builtin cd -P -- "$transaction_directory" && pwd -P)" || return 2
    PATCH_EDGE_DATA_DIRECTORY="$PATCH_EDGE_TRANSACTION_DIRECTORY/edge"
    _patch_edge_directory_safe "$PATCH_EDGE_DATA_DIRECTORY" no || return 2
    _patch_edge_stat_into "$PATCH_EDGE_DATA_DIRECTORY" device inode owner_uid mode links || return 2
    [ "$owner_uid" = "${EUID:-}" ] && [ "$mode" = 0700 ] || return 2
    _patch_edge_load_checksum_inventory || { _patch_edge_set_error "edge transaction checksum validation failed"; return 2; }
    mapfile -t manifest_lines < "$PATCH_EDGE_DATA_DIRECTORY/manifest.tsv" || return 2
    [ "${#manifest_lines[@]}" -eq 2 ] && [ "${manifest_lines[0]}" = "$PATCH_EDGE_MANIFEST_HEADER" ] || return 2
    IFS=$'\t' read -r schema criterion domain recorded_root root_device root_inode provider \
        backend payload_digest approval snapshot_digest secret_reference_digest extra <<< "${manifest_lines[1]}"
    [ -z "$extra" ] && [ "$schema" = 1 ] || return 2
    [ "$recorded_root:$root_device:$root_inode" = "$supplied_root:$supplied_device:$supplied_inode" ] || { _patch_edge_set_error "edge transaction root identity does not match"; return 2; }
    _patch_edge_safe_token "$approval" || return 2
    PATCH_EDGE_ROOT="$supplied_root"
    PATCH_EDGE_ROOT_DEVICE="$supplied_device"
    PATCH_EDGE_ROOT_INODE="$supplied_inode"
    PATCH_EDGE_CRITERION="$criterion"
    PATCH_EDGE_DOMAIN="$domain"
    PATCH_EDGE_PROVIDER="$provider"
    PATCH_EDGE_BACKEND="$backend"
    PATCH_EDGE_APPROVAL="$approval"
    PATCH_EDGE_PAYLOAD_SHA256="$payload_digest"
    PATCH_EDGE_SNAPSHOT_SHA256="$snapshot_digest"
    PATCH_EDGE_SECRET_REFERENCE_SHA256="$secret_reference_digest"
    _patch_edge_manifest_rule_valid || return 2
    if [ "$payload_digest" = - ]; then
        [ "$snapshot_digest:$secret_reference_digest" = '-:-' ] || return 2
        [ ! -e "$PATCH_EDGE_DATA_DIRECTORY/payload.rules" ] && \
            [ ! -L "$PATCH_EDGE_DATA_DIRECTORY/payload.rules" ] || return 2
        _patch_edge_load_state || return 2
        [ "$PATCH_EDGE_STATE" = not_applicable ] || return 2
        PATCH_EDGE_PLAN_VALID=1
        PATCH_EDGE_APPLY_STARTED=0
        return 0
    fi
    [ "${#snapshot_digest}" -eq 64 ] || return 2
    case "$snapshot_digest" in *[!0-9a-f]*) return 2 ;; esac
    [ "${#payload_digest}" -eq 64 ] || return 2
    case "$payload_digest" in *[!0-9a-f]*) return 2 ;; esac
    PATCH_EDGE_PAYLOAD_PATH="$PATCH_EDGE_DATA_DIRECTORY/payload.rules"
    _patch_edge_sha256_into "$PATCH_EDGE_PAYLOAD_PATH" actual_payload_digest || return 2
    [ "$actual_payload_digest" = "$payload_digest" ] || return 2
    _patch_edge_payload_shape_valid || { _patch_edge_set_error "edge transaction payload is invalid"; return 2; }
    case "$criterion" in
        U-59|U-60|U-61)
            [ "${#secret_reference_digest}" -eq 64 ] || return 2
            case "$secret_reference_digest" in *[!0-9a-f]*) return 2 ;; esac
            ;;
        *) [ "$secret_reference_digest" = - ] || return 2 ;;
    esac
    _patch_edge_load_state || return 2
    _patch_edge_load_applied || return 2
    PATCH_EDGE_PLAN_VALID=1
    case "$PATCH_EDGE_STATE" in planned|not_applicable|rolled_back) PATCH_EDGE_APPLY_STARTED=0 ;; *) PATCH_EDGE_APPLY_STARTED=1 ;; esac
}

patch_edge_rollback_transaction() {
    local requested_root="$1"
    local transaction_directory="$2"
    local mode="${3:-strict}"

    case "$mode" in strict|transition) ;; *) _patch_edge_set_error "edge rollback mode is invalid"; return 2 ;; esac
    patch_edge_load_transaction "$requested_root" "$transaction_directory" || return 2
    _patch_edge_rollback_loaded "$mode"
}
