# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash
# shellcheck disable=SC2034

# This adapter applies explicitly approved network-service configuration changes.

PATCH_NETWORK_SERVICE_SUPPORTED_CRITERIA=(U-35 U-39 U-40 U-42 U-45 U-46 U-47 U-48 U-49 U-50 U-51)
PATCH_NETWORK_SERVICE_ERROR_DETAIL=""
PATCH_NETWORK_SERVICE_ROOT=""
PATCH_NETWORK_SERVICE_ROOT_DEVICE=""
PATCH_NETWORK_SERVICE_ROOT_INODE=""
PATCH_NETWORK_SERVICE_TRANSACTION_DIRECTORY=""
PATCH_NETWORK_SERVICE_DATA_DIRECTORY=""
PATCH_NETWORK_SERVICE_CRITERION=""
PATCH_NETWORK_SERVICE_MODE=""
PATCH_NETWORK_SERVICE_PROVIDER=""
PATCH_NETWORK_SERVICE_STATE=""
PATCH_NETWORK_SERVICE_TARGET_KIND=none
PATCH_NETWORK_SERVICE_PLAN_VALID=0
PATCH_NETWORK_SERVICE_APPLY_STARTED=0
PATCH_NETWORK_SERVICE_TRANSACTION_LOADED=0
PATCH_NETWORK_SERVICE_CHANGE_COUNT=0
PATCH_NETWORK_SERVICE_EXTERNAL_ACTION_REQUIRED_COUNT=0

PATCH_NETWORK_SERVICE_CONFIG_LOGICAL_PATH=""
PATCH_NETWORK_SERVICE_CONFIG_PHYSICAL_PATH=""
PATCH_NETWORK_SERVICE_CONFIG_BEFORE_STATE=absent
PATCH_NETWORK_SERVICE_CONFIG_DEVICE="0"
PATCH_NETWORK_SERVICE_CONFIG_INODE="0"
PATCH_NETWORK_SERVICE_CONFIG_UID="0"
PATCH_NETWORK_SERVICE_CONFIG_GID="0"
PATCH_NETWORK_SERVICE_CONFIG_MODE="0000"
PATCH_NETWORK_SERVICE_CONFIG_SIZE="0"
PATCH_NETWORK_SERVICE_CONFIG_MTIME="0"
PATCH_NETWORK_SERVICE_CONFIG_CTIME="0"
PATCH_NETWORK_SERVICE_CONFIG_BEFORE_SHA256="-"
PATCH_NETWORK_SERVICE_CONFIG_DESIRED_UID="0"
PATCH_NETWORK_SERVICE_CONFIG_DESIRED_GID="0"
PATCH_NETWORK_SERVICE_CONFIG_DESIRED_MODE="0640"
PATCH_NETWORK_SERVICE_CONFIG_DESIRED_SHA256="-"
PATCH_NETWORK_SERVICE_CONFIG_BACKUP=""
PATCH_NETWORK_SERVICE_CONFIG_PAYLOAD=""

PATCH_NETWORK_SERVICE_ADVISORY_VERSION=""
PATCH_NETWORK_SERVICE_ADVISORY_STATUS=""
PATCH_NETWORK_SERVICE_ADVISORY_TOKEN=""
PATCH_NETWORK_SERVICE_ADVISORY_APPROVAL=""
PATCH_NETWORK_SERVICE_ADVISORY_CRITERION=""
PATCH_NETWORK_SERVICE_ADVISORY_PROVIDER=""

declare -A PATCH_NETWORK_SERVICE_CALLBACKS=()
declare -A PATCH_NETWORK_SERVICE_CALLBACK_FINGERPRINTS=()
declare -A PATCH_NETWORK_SERVICE_INTENTS=()
declare -A PATCH_NETWORK_SERVICE_INTENT_APPROVALS=()
declare -A PATCH_NETWORK_SERVICE_CRITERION_STATES=()
declare -A PATCH_NETWORK_SERVICE_NFS_EXPORT_SEEN=()
declare -A PATCH_NETWORK_SERVICE_RPC_ALLOW_SEEN=()
declare -A PATCH_NETWORK_SERVICE_MAIL_CLIENT_SEEN=()
declare -A PATCH_NETWORK_SERVICE_TSIG_SEEN=()
declare -A PATCH_NETWORK_SERVICE_TRANSFER_PEER_SEEN=()
declare -A PATCH_NETWORK_SERVICE_UPDATE_KEY_SEEN=()

PATCH_NETWORK_SERVICE_INTENT_CRITERIA=()
PATCH_NETWORK_SERVICE_INTENT_MODES=()
PATCH_NETWORK_SERVICE_INTENT_PROVIDERS=()
PATCH_NETWORK_SERVICE_INTENT_APPROVAL_LIST=()
PATCH_NETWORK_SERVICE_NFS_EXPORT_PATHS=()
PATCH_NETWORK_SERVICE_NFS_EXPORT_CLIENTS=()
PATCH_NETWORK_SERVICE_NFS_EXPORT_OPTIONS=()
PATCH_NETWORK_SERVICE_NFS_EXPORT_APPROVALS=()
PATCH_NETWORK_SERVICE_RPC_SERVICES=()
PATCH_NETWORK_SERVICE_RPC_CLIENTS=()
PATCH_NETWORK_SERVICE_RPC_APPROVALS=()
PATCH_NETWORK_SERVICE_MAIL_CLIENTS=()
PATCH_NETWORK_SERVICE_MAIL_CLIENT_APPROVALS=()
PATCH_NETWORK_SERVICE_TSIG_NAMES=()
PATCH_NETWORK_SERVICE_TSIG_REFERENCES=()
PATCH_NETWORK_SERVICE_TSIG_APPROVALS=()
PATCH_NETWORK_SERVICE_TRANSFER_PEER_KINDS=()
PATCH_NETWORK_SERVICE_TRANSFER_PEER_VALUES=()
PATCH_NETWORK_SERVICE_TRANSFER_PEER_APPROVALS=()
PATCH_NETWORK_SERVICE_UPDATE_KEY_NAMES=()
PATCH_NETWORK_SERVICE_UPDATE_KEY_APPROVALS=()
PATCH_NETWORK_SERVICE_CONFIG_INPUT_PROVIDER=""
PATCH_NETWORK_SERVICE_CONFIG_INPUT_PATH=""
PATCH_NETWORK_SERVICE_CONFIG_INPUT_APPROVAL=""
PATCH_NETWORK_SERVICE_COMMAND_INPUT_PROVIDER=""
PATCH_NETWORK_SERVICE_COMMAND_INPUT_PATH=""
PATCH_NETWORK_SERVICE_COMMAND_INPUT_APPROVAL=""

_patch_network_service_set_error() {
    PATCH_NETWORK_SERVICE_ERROR_DETAIL="$1"
    PATCH_NETWORK_SERVICE_PLAN_VALID=0
    return 2
}

_patch_network_service_valid_criterion() {
    case "$1" in U-35|U-39|U-40|U-42|U-45|U-46|U-47|U-48|U-49|U-50|U-51) return 0 ;; *) return 1 ;; esac
}

_patch_network_service_safe_token() {
    case "$1" in ''|*[!A-Za-z0-9._:+@/-]*) return 1 ;; *) return 0 ;; esac
}

_patch_network_service_safe_approval() {
    case "$1" in ''|*[!A-Za-z0-9._:+-]*) return 1 ;; *) return 0 ;; esac
}

_patch_network_service_valid_provider_for_criterion() {
    local criterion="$1"
    local provider="$2"

    case "$criterion:$provider" in
        U-35:ftp|U-35:nfs|U-35:samba|U-39:nfs|U-40:nfs|U-42:rpcbind|\
        U-45:postfix|U-45:sendmail|U-45:exim|U-46:postfix|U-46:sendmail|U-46:exim|\
        U-47:postfix|U-47:sendmail|U-47:exim|U-48:postfix|U-48:sendmail|U-48:exim|\
        U-49:bind|U-50:bind|U-51:bind) return 0 ;;
        *) return 1 ;;
    esac
}

patch_network_service_supported_criteria() {
    printf '%s\n' "${PATCH_NETWORK_SERVICE_SUPPORTED_CRITERIA[@]}"
}

patch_network_service_callback_reset() {
    PATCH_NETWORK_SERVICE_CALLBACKS=()
    PATCH_NETWORK_SERVICE_CALLBACK_FINGERPRINTS=()
}

patch_network_service_intent_reset() {
    PATCH_NETWORK_SERVICE_INTENTS=()
    PATCH_NETWORK_SERVICE_INTENT_APPROVALS=()
    PATCH_NETWORK_SERVICE_INTENT_CRITERIA=()
    PATCH_NETWORK_SERVICE_INTENT_MODES=()
    PATCH_NETWORK_SERVICE_INTENT_PROVIDERS=()
    PATCH_NETWORK_SERVICE_INTENT_APPROVAL_LIST=()
}

patch_network_service_input_reset() {
    PATCH_NETWORK_SERVICE_NFS_EXPORT_SEEN=()
    PATCH_NETWORK_SERVICE_RPC_ALLOW_SEEN=()
    PATCH_NETWORK_SERVICE_MAIL_CLIENT_SEEN=()
    PATCH_NETWORK_SERVICE_TSIG_SEEN=()
    PATCH_NETWORK_SERVICE_TRANSFER_PEER_SEEN=()
    PATCH_NETWORK_SERVICE_UPDATE_KEY_SEEN=()
    PATCH_NETWORK_SERVICE_NFS_EXPORT_PATHS=()
    PATCH_NETWORK_SERVICE_NFS_EXPORT_CLIENTS=()
    PATCH_NETWORK_SERVICE_NFS_EXPORT_OPTIONS=()
    PATCH_NETWORK_SERVICE_NFS_EXPORT_APPROVALS=()
    PATCH_NETWORK_SERVICE_RPC_SERVICES=()
    PATCH_NETWORK_SERVICE_RPC_CLIENTS=()
    PATCH_NETWORK_SERVICE_RPC_APPROVALS=()
    PATCH_NETWORK_SERVICE_MAIL_CLIENTS=()
    PATCH_NETWORK_SERVICE_MAIL_CLIENT_APPROVALS=()
    PATCH_NETWORK_SERVICE_TSIG_NAMES=()
    PATCH_NETWORK_SERVICE_TSIG_REFERENCES=()
    PATCH_NETWORK_SERVICE_TSIG_APPROVALS=()
    PATCH_NETWORK_SERVICE_TRANSFER_PEER_KINDS=()
    PATCH_NETWORK_SERVICE_TRANSFER_PEER_VALUES=()
    PATCH_NETWORK_SERVICE_TRANSFER_PEER_APPROVALS=()
    PATCH_NETWORK_SERVICE_UPDATE_KEY_NAMES=()
    PATCH_NETWORK_SERVICE_UPDATE_KEY_APPROVALS=()
    PATCH_NETWORK_SERVICE_CONFIG_INPUT_PROVIDER=""
    PATCH_NETWORK_SERVICE_CONFIG_INPUT_PATH=""
    PATCH_NETWORK_SERVICE_CONFIG_INPUT_APPROVAL=""
    PATCH_NETWORK_SERVICE_COMMAND_INPUT_PROVIDER=""
    PATCH_NETWORK_SERVICE_COMMAND_INPUT_PATH=""
    PATCH_NETWORK_SERVICE_COMMAND_INPUT_APPROVAL=""
    PATCH_NETWORK_SERVICE_ADVISORY_VERSION=""
    PATCH_NETWORK_SERVICE_ADVISORY_STATUS=""
    PATCH_NETWORK_SERVICE_ADVISORY_TOKEN=""
    PATCH_NETWORK_SERVICE_ADVISORY_APPROVAL=""
    PATCH_NETWORK_SERVICE_ADVISORY_CRITERION=""
    PATCH_NETWORK_SERVICE_ADVISORY_PROVIDER=""
}

patch_network_service_reset() {
    PATCH_NETWORK_SERVICE_ERROR_DETAIL=""
    PATCH_NETWORK_SERVICE_ROOT=""
    PATCH_NETWORK_SERVICE_ROOT_DEVICE=""
    PATCH_NETWORK_SERVICE_ROOT_INODE=""
    PATCH_NETWORK_SERVICE_TRANSACTION_DIRECTORY=""
    PATCH_NETWORK_SERVICE_DATA_DIRECTORY=""
    PATCH_NETWORK_SERVICE_CRITERION=""
    PATCH_NETWORK_SERVICE_MODE=""
    PATCH_NETWORK_SERVICE_PROVIDER=""
    PATCH_NETWORK_SERVICE_STATE=""
    PATCH_NETWORK_SERVICE_TARGET_KIND=none
    PATCH_NETWORK_SERVICE_PLAN_VALID=0
    PATCH_NETWORK_SERVICE_APPLY_STARTED=0
    PATCH_NETWORK_SERVICE_TRANSACTION_LOADED=0
    PATCH_NETWORK_SERVICE_CHANGE_COUNT=0
    PATCH_NETWORK_SERVICE_EXTERNAL_ACTION_REQUIRED_COUNT=0
    PATCH_NETWORK_SERVICE_CRITERION_STATES=()
    PATCH_NETWORK_SERVICE_CONFIG_LOGICAL_PATH=""
    PATCH_NETWORK_SERVICE_CONFIG_PHYSICAL_PATH=""
    PATCH_NETWORK_SERVICE_CONFIG_BEFORE_STATE=absent
    PATCH_NETWORK_SERVICE_CONFIG_DEVICE=0
    PATCH_NETWORK_SERVICE_CONFIG_INODE=0
    PATCH_NETWORK_SERVICE_CONFIG_UID=0
    PATCH_NETWORK_SERVICE_CONFIG_GID=0
    PATCH_NETWORK_SERVICE_CONFIG_MODE=0000
    PATCH_NETWORK_SERVICE_CONFIG_SIZE=0
    PATCH_NETWORK_SERVICE_CONFIG_MTIME=0
    PATCH_NETWORK_SERVICE_CONFIG_CTIME=0
    PATCH_NETWORK_SERVICE_CONFIG_BEFORE_SHA256=-
    PATCH_NETWORK_SERVICE_CONFIG_DESIRED_UID=0
    PATCH_NETWORK_SERVICE_CONFIG_DESIRED_GID=0
    PATCH_NETWORK_SERVICE_CONFIG_DESIRED_MODE=0640
    PATCH_NETWORK_SERVICE_CONFIG_DESIRED_SHA256=-
    PATCH_NETWORK_SERVICE_CONFIG_BACKUP=""
    PATCH_NETWORK_SERVICE_CONFIG_PAYLOAD=""
}

patch_network_service_intent_add() {
    local criterion="$1"
    local mode="$2"
    local provider="$3"
    local approval="$4"
    local key="$criterion:$provider"

    _patch_network_service_valid_criterion "$criterion" || return 1
    case "$mode" in disabled|required) ;; *) return 2 ;; esac
    _patch_network_service_valid_provider_for_criterion "$criterion" "$provider" || return 2
    _patch_network_service_safe_approval "$approval" || return 2
    [ "${PATCH_NETWORK_SERVICE_INTENTS[$key]+present}" != present ] || return 2
    PATCH_NETWORK_SERVICE_INTENTS["$key"]="$mode"
    PATCH_NETWORK_SERVICE_INTENT_APPROVALS["$key"]="$approval"
    PATCH_NETWORK_SERVICE_INTENT_CRITERIA+=("$criterion")
    PATCH_NETWORK_SERVICE_INTENT_MODES+=("$mode")
    PATCH_NETWORK_SERVICE_INTENT_PROVIDERS+=("$provider")
    PATCH_NETWORK_SERVICE_INTENT_APPROVAL_LIST+=("$approval")
}

patch_network_service_config_set() {
    local provider="$1"
    local logical_path="$2"
    local approval="$3"

    case "$provider:$logical_path" in
        nfs:/etc/exports|postfix:/etc/postfix/main.cf|sendmail:/etc/mail/sendmail.cf|\
        bind:/etc/bind/named.conf.options|bind:/etc/bind/named.conf|bind:/etc/named.conf) ;;
        *) return 2 ;;
    esac
    _patch_network_service_safe_approval "$approval" || return 2
    [ -z "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PROVIDER" ] || return 2
    PATCH_NETWORK_SERVICE_CONFIG_INPUT_PROVIDER="$provider"
    PATCH_NETWORK_SERVICE_CONFIG_INPUT_PATH="$logical_path"
    PATCH_NETWORK_SERVICE_CONFIG_INPUT_APPROVAL="$approval"
}

patch_network_service_mail_command_set() {
    local provider="$1"
    local logical_path="$2"
    local approval="$3"

    case "$provider:$logical_path" in
        postfix:/usr/sbin/postsuper|exim:/usr/sbin/exiqgrep|exim:/usr/sbin/exiqgrep4) ;;
        *) return 2 ;;
    esac
    _patch_network_service_safe_approval "$approval" || return 2
    [ -z "$PATCH_NETWORK_SERVICE_COMMAND_INPUT_PROVIDER" ] || return 2
    PATCH_NETWORK_SERVICE_COMMAND_INPUT_PROVIDER="$provider"
    PATCH_NETWORK_SERVICE_COMMAND_INPUT_PATH="$logical_path"
    PATCH_NETWORK_SERVICE_COMMAND_INPUT_APPROVAL="$approval"
}

patch_network_service_nfs_export_add() {
    local export_path="$1"
    local client="$2"
    local options="$3"
    local approval="$4"
    local key="$export_path:$client"

    case "$export_path" in /*) ;; *) return 2 ;; esac
    case "$export_path" in *$'\t'*|*$'\n'*|*$'\r'*|*' '*|*/../*|*/..|*/./*|*/.) return 2 ;; esac
    case "$client" in ''|'*'|*' '*|*$'\t'*|*$'\n'*|*$'\r'*|*[!A-Za-z0-9._:/@+-]*) return 2 ;; esac
    case "$options" in ''|*[!A-Za-z0-9_=.,:+-]*) return 2 ;; esac
    case ",$options," in *,no_root_squash,*|*,insecure,*|*,anonuid=0,*|*,anongid=0,*) return 2 ;; esac
    _patch_network_service_safe_approval "$approval" || return 2
    [ "${PATCH_NETWORK_SERVICE_NFS_EXPORT_SEEN[$key]+present}" != present ] || return 2
    PATCH_NETWORK_SERVICE_NFS_EXPORT_SEEN["$key"]=1
    PATCH_NETWORK_SERVICE_NFS_EXPORT_PATHS+=("$export_path")
    PATCH_NETWORK_SERVICE_NFS_EXPORT_CLIENTS+=("$client")
    PATCH_NETWORK_SERVICE_NFS_EXPORT_OPTIONS+=("$options")
    PATCH_NETWORK_SERVICE_NFS_EXPORT_APPROVALS+=("$approval")
}

patch_network_service_rpc_allow_add() {
    local service="$1"
    local client="$2"
    local approval="$3"
    local key="$service:$client"

    case "$service" in rpcbind|rpc-statd|rpc-mountd|nfs|nfs-lock|rquotad) ;; *) return 2 ;; esac
    case "$client" in ''|'*'|*' '*|*$'\t'*|*$'\n'*|*$'\r'*|*[!A-Za-z0-9._:/@+-]*) return 2 ;; esac
    _patch_network_service_safe_approval "$approval" || return 2
    [ "${PATCH_NETWORK_SERVICE_RPC_ALLOW_SEEN[$key]+present}" != present ] || return 2
    PATCH_NETWORK_SERVICE_RPC_ALLOW_SEEN["$key"]=1
    PATCH_NETWORK_SERVICE_RPC_SERVICES+=("$service")
    PATCH_NETWORK_SERVICE_RPC_CLIENTS+=("$client")
    PATCH_NETWORK_SERVICE_RPC_APPROVALS+=("$approval")
}

patch_network_service_mail_relay_client_add() {
    local client="$1"
    local approval="$2"

    case "$client" in ''|'*'|0.0.0.0/0|'::/0'|'[::]/0'|*' '*|*$'\t'*|*$'\n'*|*$'\r'*|*[!A-Za-z0-9._:/@+-]*) return 2 ;; esac
    _patch_network_service_safe_approval "$approval" || return 2
    [ "${PATCH_NETWORK_SERVICE_MAIL_CLIENT_SEEN[$client]+present}" != present ] || return 2
    PATCH_NETWORK_SERVICE_MAIL_CLIENT_SEEN["$client"]=1
    PATCH_NETWORK_SERVICE_MAIL_CLIENTS+=("$client")
    PATCH_NETWORK_SERVICE_MAIL_CLIENT_APPROVALS+=("$approval")
}

patch_network_service_bind_tsig_add() {
    local key_name="$1"
    local secret_reference="$2"
    local approval="$3"

    case "$key_name" in ''|*[!A-Za-z0-9._:-]*) return 2 ;; esac
    case "$secret_reference" in /etc/*) ;; *) return 2 ;; esac
    case "$secret_reference" in *$'\t'*|*$'\n'*|*$'\r'*|*' '*|*/../*|*/..|*/./*|*/.) return 2 ;; esac
    _patch_network_service_safe_approval "$approval" || return 2
    [ "${PATCH_NETWORK_SERVICE_TSIG_SEEN[$key_name]+present}" != present ] || return 2
    PATCH_NETWORK_SERVICE_TSIG_SEEN["$key_name"]="$secret_reference"
    PATCH_NETWORK_SERVICE_TSIG_NAMES+=("$key_name")
    PATCH_NETWORK_SERVICE_TSIG_REFERENCES+=("$secret_reference")
    PATCH_NETWORK_SERVICE_TSIG_APPROVALS+=("$approval")
}

patch_network_service_bind_transfer_peer_add() {
    local kind="$1"
    local value="$2"
    local approval="$3"
    local key="$kind:$value"

    case "$kind" in
        address)
            case "$value" in ''|'*'|any|0/0|0.0.0.0/0|'::/0'|*' '*|*$'\t'*|*$'\n'*|*$'\r'*|*[!A-Za-z0-9._:/@+-]*) return 2 ;; esac
            ;;
        key) case "$value" in ''|*[!A-Za-z0-9._:-]*) return 2 ;; esac ;;
        *) return 2 ;;
    esac
    _patch_network_service_safe_approval "$approval" || return 2
    [ "${PATCH_NETWORK_SERVICE_TRANSFER_PEER_SEEN[$key]+present}" != present ] || return 2
    PATCH_NETWORK_SERVICE_TRANSFER_PEER_SEEN["$key"]=1
    PATCH_NETWORK_SERVICE_TRANSFER_PEER_KINDS+=("$kind")
    PATCH_NETWORK_SERVICE_TRANSFER_PEER_VALUES+=("$value")
    PATCH_NETWORK_SERVICE_TRANSFER_PEER_APPROVALS+=("$approval")
}

patch_network_service_bind_update_key_add() {
    local key_name="$1"
    local approval="$2"

    case "$key_name" in ''|*[!A-Za-z0-9._:-]*) return 2 ;; esac
    _patch_network_service_safe_approval "$approval" || return 2
    [ "${PATCH_NETWORK_SERVICE_UPDATE_KEY_SEEN[$key_name]+present}" != present ] || return 2
    PATCH_NETWORK_SERVICE_UPDATE_KEY_SEEN["$key_name"]=1
    PATCH_NETWORK_SERVICE_UPDATE_KEY_NAMES+=("$key_name")
    PATCH_NETWORK_SERVICE_UPDATE_KEY_APPROVALS+=("$approval")
}

patch_network_service_advisory_set() {
    local criterion="$1"
    local provider="$2"
    local version="$3"
    local status="$4"
    local snapshot_token="$5"
    local approval="$6"

    case "$criterion" in U-45|U-49) ;; *) return 2 ;; esac
    _patch_network_service_valid_provider_for_criterion "$criterion" "$provider" || return 2
    case "$version" in ''|*[!A-Za-z0-9.+:~_-]*) return 2 ;; esac
    case "$status" in current|update-required) ;; *) return 2 ;; esac
    _patch_network_service_safe_token "$snapshot_token" || return 2
    _patch_network_service_safe_approval "$approval" || return 2
    [ -z "$PATCH_NETWORK_SERVICE_ADVISORY_VERSION" ] || return 2
    PATCH_NETWORK_SERVICE_ADVISORY_CRITERION="$criterion"
    PATCH_NETWORK_SERVICE_ADVISORY_PROVIDER="$provider"
    PATCH_NETWORK_SERVICE_ADVISORY_VERSION="$version"
    PATCH_NETWORK_SERVICE_ADVISORY_STATUS="$status"
    PATCH_NETWORK_SERVICE_ADVISORY_TOKEN="$snapshot_token"
    PATCH_NETWORK_SERVICE_ADVISORY_APPROVAL="$approval"
}

_patch_network_service_valid_destination() {
    case "$1" in ''|[0-9]*|*[!A-Za-z0-9_]*) return 1 ;; *) return 0 ;; esac
}

_patch_network_service_command_into() {
    local command_name="$1"
    local destination_name="$2"
    local candidate=""
    local metadata=""
    local owner_uid=""
    local mode=""

    _patch_network_service_valid_destination "$destination_name" || return 2
    case "$command_name" in
        awk) candidate=/usr/bin/awk ;;
        chmod) candidate=/bin/chmod ;;
        chown) candidate=/usr/bin/chown; [ -x "$candidate" ] || candidate=/bin/chown ;;
        cp) candidate=/usr/bin/cp; [ -x "$candidate" ] || candidate=/bin/cp ;;
        mkdir) candidate=/bin/mkdir; [ -x "$candidate" ] || candidate=/usr/bin/mkdir ;;
        mktemp) candidate=/usr/bin/mktemp; [ -x "$candidate" ] || candidate=/bin/mktemp ;;
        mv) candidate=/bin/mv; [ -x "$candidate" ] || candidate=/usr/bin/mv ;;
        rm) candidate=/bin/rm; [ -x "$candidate" ] || candidate=/usr/bin/rm ;;
        sha256sum)
            if [ -x /usr/bin/sha256sum ]; then candidate=/usr/bin/sha256sum
            elif [ -x /bin/sha256sum ]; then candidate=/bin/sha256sum
            else candidate=/usr/bin/shasum
            fi
            ;;
        stat) candidate=/usr/bin/stat ;;
        *) return 2 ;;
    esac
    [ -x "$candidate" ] || return 127
    if metadata="$(/usr/bin/stat -Lc '%u:%a' -- "$candidate" 2>/dev/null)"; then :
    elif metadata="$(/usr/bin/stat -L -f '%u:%Lp' "$candidate" 2>/dev/null)"; then :
    else return 2
    fi
    owner_uid="${metadata%%:*}"
    mode="${metadata#*:}"
    case "$owner_uid:$mode" in *[!0-9:]*) return 2 ;; esac
    [ "$owner_uid" = 0 ] && [ $((8#$mode & 0022)) -eq 0 ] || return 2
    printf -v "$destination_name" '%s' "$candidate"
}

_patch_network_service_stat_into() {
    local path="$1"
    local destination_name="$2"
    local stat_command=""
    local stat_output=""

    _patch_network_service_valid_destination "$destination_name" || return 2
    _patch_network_service_command_into stat stat_command || return $?
    if stat_output="$("$stat_command" -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' -- "$path" 2>/dev/null)"; then :
    elif stat_output="$("$stat_command" -f '%d:%i:%u:%g:%Lp:%l:%z:%m:%c' "$path" 2>/dev/null)"; then :
    else return 2
    fi
    case "$stat_output" in *[!0-9:]*) return 2 ;; esac
    printf -v "$destination_name" '%s' "$stat_output"
}

_patch_network_service_sha256_into() {
    local path="$1"
    local destination_name="$2"
    local hash_command=""
    local hash_output=""
    local hash_digest=""

    _patch_network_service_valid_destination "$destination_name" || return 2
    _patch_network_service_command_into sha256sum hash_command || return $?
    case "$hash_command" in
        */shasum) hash_output="$("$hash_command" -a 256 -- "$path" 2>/dev/null)" || return 2 ;;
        *) hash_output="$("$hash_command" -- "$path" 2>/dev/null)" || return 2 ;;
    esac
    hash_digest="${hash_output%% *}"
    [ "${#hash_digest}" -eq 64 ] || return 2
    case "$hash_digest" in *[!0-9a-f]*) return 2 ;; esac
    printf -v "$destination_name" '%s' "$hash_digest"
}

_patch_network_service_file_fingerprint_into() {
    local path="$1"
    local destination_name="$2"
    local file_metadata=""
    local file_sha256=""

    [ -f "$path" ] && [ ! -L "$path" ] && [ -r "$path" ] || return 2
    _patch_network_service_stat_into "$path" file_metadata || return 2
    case "$file_metadata" in *:*:*:*:*:1:*) ;; *) return 2 ;; esac
    _patch_network_service_sha256_into "$path" file_sha256 || return 2
    printf -v "$destination_name" '%s:%s' "$file_metadata" "$file_sha256"
}

_patch_network_service_root_chain_trusted() {
    local path="$1"
    local canonical_path=""
    local current=/
    local relative=""
    local component=""
    local metadata=""
    local device="" inode="" owner_uid="" group_id="" mode="" links="" size="" mtime="" ctime="" extra=""
    local -a components=()

    canonical_path="$(CDPATH='' builtin cd -P -- "$path" 2>/dev/null && pwd -P)" || return 2
    relative="${canonical_path#/}"
    IFS=/ read -r -a components <<< "$relative"
    for component in "${components[@]}"; do
        [ -n "$component" ] || continue
        current="${current%/}/$component"
        _patch_network_service_stat_into "$current" metadata || return 2
        IFS=: read -r device inode owner_uid group_id mode links size mtime ctime extra <<< "$metadata"
        [ -z "$extra" ] && [ "$owner_uid" = 0 ] || return 2
        if [ $((8#$mode & 0022)) -ne 0 ]; then
            [ $((8#$mode & 01000)) -ne 0 ] &&
                { [ "$current" = /tmp ] || [ "$current" = /var/tmp ] ||
                  [ "$current" = /private/tmp ] || [ "$current" = /private/var/tmp ]; } || return 2
        fi
    done
}

_patch_network_service_callback_trusted() {
    local path="$1"
    local fingerprint=""
    local device="" inode="" group_id="" links="" size="" mtime="" ctime="" digest="" extra=""
    local owner_uid=""
    local mode=""
    local parent="${path%/*}"

    case "$path" in /*) ;; *) return 2 ;; esac
    _patch_network_service_root_chain_trusted "$parent" || return 2
    [ -x "$path" ] && [ -f "$path" ] && [ ! -L "$path" ] || return 2
    _patch_network_service_file_fingerprint_into "$path" fingerprint || return 2
    IFS=: read -r device inode owner_uid group_id mode links size mtime ctime digest extra <<< "$fingerprint"
    [ -z "$extra" ] && [ -n "$device$inode$group_id$links$size$mtime$ctime$digest" ] || return 2
    [ "$owner_uid" = 0 ] && [ $((8#$mode & 0022)) -eq 0 ]
}

patch_network_service_register_callback() {
    local callback_kind="$1"
    local callback_path="$2"
    local fingerprint=""

    case "$callback_kind" in policy_verifier|native_validator|runtime_transition|service_graph) ;; *) return 2 ;; esac
    [ "${EUID:-$(id -u)}" -eq 0 ] || return 2
    [ "${PATCH_NETWORK_SERVICE_CALLBACKS[$callback_kind]+present}" != present ] || return 2
    _patch_network_service_callback_trusted "$callback_path" || return 2
    _patch_network_service_file_fingerprint_into "$callback_path" fingerprint || return 2
    PATCH_NETWORK_SERVICE_CALLBACKS["$callback_kind"]="$callback_path"
    PATCH_NETWORK_SERVICE_CALLBACK_FINGERPRINTS["$callback_kind"]="$fingerprint"
}

_patch_network_service_canonical_directory_into() {
    local path="$1"
    local destination_name="$2"
    local canonical_path=""

    _patch_network_service_valid_destination "$destination_name" || return 2
    [ -d "$path" ] && [ ! -L "$path" ] || return 2
    canonical_path="$(CDPATH='' builtin cd -P -- "$path" 2>/dev/null && pwd -P)" || return 2
    printf -v "$destination_name" '%s' "$canonical_path"
}

_patch_network_service_initialize_root() {
    local requested_root="$1"
    local canonical_root=""
    local root_metadata=""

    case "$requested_root" in *$'\t'*|*$'\n'*|*$'\r'*) return 2 ;; esac
    _patch_network_service_canonical_directory_into "$requested_root" canonical_root || return 2
    _patch_network_service_stat_into "$canonical_root" root_metadata || return 2
    PATCH_NETWORK_SERVICE_ROOT="$canonical_root"
    PATCH_NETWORK_SERVICE_ROOT_DEVICE="${root_metadata%%:*}"
    root_metadata="${root_metadata#*:}"
    PATCH_NETWORK_SERVICE_ROOT_INODE="${root_metadata%%:*}"
}

_patch_network_service_root_identity_current() {
    local root_metadata=""
    local current_device=""
    local current_inode=""

    _patch_network_service_stat_into "$PATCH_NETWORK_SERVICE_ROOT" root_metadata || return 2
    current_device="${root_metadata%%:*}"
    root_metadata="${root_metadata#*:}"
    current_inode="${root_metadata%%:*}"
    [ "$current_device" = "$PATCH_NETWORK_SERVICE_ROOT_DEVICE" ] &&
        [ "$current_inode" = "$PATCH_NETWORK_SERVICE_ROOT_INODE" ]
}

_patch_network_service_root_path_into() {
    local logical_path="$1"
    local destination_name="$2"

    _patch_network_service_valid_destination "$destination_name" || return 2
    case "$logical_path" in /*) ;; *) return 2 ;; esac
    case "$logical_path" in *$'\t'*|*$'\n'*|*$'\r'*|*/../*|*/..|*/./*|*/.) return 2 ;; esac
    if [ "$PATCH_NETWORK_SERVICE_ROOT" = / ]; then
        printf -v "$destination_name" '%s' "$logical_path"
    else
        printf -v "$destination_name" '%s' "${PATCH_NETWORK_SERVICE_ROOT%/}$logical_path"
    fi
}

_patch_network_service_safe_parent_into() {
    local logical_path="$1"
    local destination_name="$2"
    local physical_path=""
    local physical_parent=""
    local canonical_parent=""

    _patch_network_service_root_path_into "$logical_path" physical_path || return 2
    physical_parent="${physical_path%/*}"
    _patch_network_service_canonical_directory_into "$physical_parent" canonical_parent || return 2
    if [ "$PATCH_NETWORK_SERVICE_ROOT" != / ]; then
        case "$canonical_parent/" in "$PATCH_NETWORK_SERVICE_ROOT"/*) ;; *) return 2 ;; esac
    fi
    printf -v "$destination_name" '%s' "$canonical_parent"
}

_patch_network_service_prepare_transaction() {
    local requested_directory="$1"
    local canonical_directory=""
    local directory_metadata=""
    local remaining=""
    local owner_uid=""
    local mode=""
    local mkdir_command=""

    _patch_network_service_canonical_directory_into "$requested_directory" canonical_directory || return 2
    [ "$canonical_directory" = "$requested_directory" ] || return 2
    _patch_network_service_stat_into "$canonical_directory" directory_metadata || return 2
    remaining="${directory_metadata#*:*:}"
    owner_uid="${remaining%%:*}"
    remaining="${remaining#*:}"
    remaining="${remaining#*:}"
    mode="${remaining%%:*}"
    [ "$owner_uid" = "${EUID:-$owner_uid}" ] && [ "$mode" = 700 ] || return 2
    PATCH_NETWORK_SERVICE_TRANSACTION_DIRECTORY="$canonical_directory"
    PATCH_NETWORK_SERVICE_DATA_DIRECTORY="$canonical_directory/network-service"
    [ ! -e "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY" ] && [ ! -L "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY" ] || return 2
    _patch_network_service_command_into mkdir mkdir_command || return 2
    "$mkdir_command" -m 0700 -- "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY" || return 2
    "$mkdir_command" -m 0700 -- "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/backups" \
        "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/payloads" "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/delegates" || return 2
}

_patch_network_service_set_state() {
    local new_state="$1"
    local state_path="$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/state"
    local temporary_path=""
    local mktemp_command=""
    local mv_command=""

    case "$new_state" in planned|external_action_required|applying|verified|rollback_in_progress|rolled_back|rollback_failed) ;; *) return 2 ;; esac
    _patch_network_service_command_into mktemp mktemp_command || return 2
    _patch_network_service_command_into mv mv_command || return 2
    temporary_path="$("$mktemp_command" "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/.state.XXXXXXXX")" || return 2
    printf '%s\n' "$new_state" > "$temporary_path" || return 2
    chmod 0600 "$temporary_path" || return 2
    "$mv_command" -f -- "$temporary_path" "$state_path" || return 2
    PATCH_NETWORK_SERVICE_STATE="$new_state"
}

patch_network_service_state_into() {
    local criterion="$1"
    local destination_name="$2"

    _patch_network_service_valid_destination "$destination_name" || return 2
    [ "${PATCH_NETWORK_SERVICE_CRITERION_STATES[$criterion]+present}" = present ] || return 1
    printf -v "$destination_name" '%s' "${PATCH_NETWORK_SERVICE_CRITERION_STATES[$criterion]}"
}

_patch_network_service_callback_is_current() {
    local callback_kind="$1"
    local callback_path="${PATCH_NETWORK_SERVICE_CALLBACKS[$callback_kind]:-}"
    local current_fingerprint=""

    [ -n "$callback_path" ] || return 2
    _patch_network_service_callback_trusted "$callback_path" || return 2
    _patch_network_service_file_fingerprint_into "$callback_path" current_fingerprint || return 2
    [ "$current_fingerprint" = "${PATCH_NETWORK_SERVICE_CALLBACK_FINGERPRINTS[$callback_kind]:-}" ]
}

_patch_network_service_verify_policy_record() {
    local provider="$1"
    local record_kind="$2"
    local first_value="$3"
    local second_value="$4"
    local approval="$5"
    local verifier="${PATCH_NETWORK_SERVICE_CALLBACKS[policy_verifier]:-}"

    _patch_network_service_callback_is_current policy_verifier || return 2
    "$verifier" "$PATCH_NETWORK_SERVICE_CRITERION" "$provider" "$record_kind" \
        "$first_value" "$second_value" "$approval"
}

_patch_network_service_validate_intents() {
    local index=0
    local intent_count=0
    local required_count=0
    local selected_mode=""
    local provider_list=""
    local separator=""

    while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_INTENT_CRITERIA[@]}" ]; do
        [ "${PATCH_NETWORK_SERVICE_INTENT_CRITERIA[$index]}" = "$PATCH_NETWORK_SERVICE_CRITERION" ] || return 2
        if [ -n "$selected_mode" ] && [ "$selected_mode" != "${PATCH_NETWORK_SERVICE_INTENT_MODES[$index]}" ]; then
            return 2
        fi
        selected_mode="${PATCH_NETWORK_SERVICE_INTENT_MODES[$index]}"
        [ "$selected_mode" != required ] || required_count=$((required_count + 1))
        provider_list+="$separator${PATCH_NETWORK_SERVICE_INTENT_PROVIDERS[$index]}"
        separator=,
        _patch_network_service_verify_policy_record "${PATCH_NETWORK_SERVICE_INTENT_PROVIDERS[$index]}" \
            intent "$selected_mode" - "${PATCH_NETWORK_SERVICE_INTENT_APPROVAL_LIST[$index]}" || return 2
        intent_count=$((intent_count + 1))
        index=$((index + 1))
    done
    [ "$intent_count" -gt 0 ] || return 2
    if [ "$selected_mode" = required ]; then
        [ "$required_count" -eq 1 ] && [ "$intent_count" -eq 1 ] || return 2
        PATCH_NETWORK_SERVICE_PROVIDER="$provider_list"
    else
        PATCH_NETWORK_SERVICE_PROVIDER="$provider_list"
    fi
    PATCH_NETWORK_SERVICE_MODE="$selected_mode"
}

_patch_network_service_no_nfs_inputs() {
    [ "${#PATCH_NETWORK_SERVICE_NFS_EXPORT_PATHS[@]}" -eq 0 ]
}

_patch_network_service_no_rpc_inputs() {
    [ "${#PATCH_NETWORK_SERVICE_RPC_SERVICES[@]}" -eq 0 ]
}

_patch_network_service_no_mail_inputs() {
    [ "${#PATCH_NETWORK_SERVICE_MAIL_CLIENTS[@]}" -eq 0 ] &&
        [ -z "$PATCH_NETWORK_SERVICE_COMMAND_INPUT_PROVIDER" ]
}

_patch_network_service_no_bind_inputs() {
    [ "${#PATCH_NETWORK_SERVICE_TSIG_NAMES[@]}" -eq 0 ] &&
        [ "${#PATCH_NETWORK_SERVICE_TRANSFER_PEER_KINDS[@]}" -eq 0 ] &&
        [ "${#PATCH_NETWORK_SERVICE_UPDATE_KEY_NAMES[@]}" -eq 0 ]
}

_patch_network_service_no_advisory_input() {
    [ -z "$PATCH_NETWORK_SERVICE_ADVISORY_VERSION" ]
}

_patch_network_service_verify_nfs_inputs() {
    local index=0

    [ "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PROVIDER" = nfs ] &&
        [ "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PATH" = /etc/exports ] || return 2
    [ "${#PATCH_NETWORK_SERVICE_NFS_EXPORT_PATHS[@]}" -gt 0 ] || return 2
    while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_NFS_EXPORT_PATHS[@]}" ]; do
        if [ "$PATCH_NETWORK_SERVICE_CRITERION" = U-35 ]; then
            case ",${PATCH_NETWORK_SERVICE_NFS_EXPORT_OPTIONS[$index]}," in *,root_squash,*) ;; *) return 2 ;; esac
        fi
        _patch_network_service_verify_policy_record nfs nfs-export \
            "${PATCH_NETWORK_SERVICE_NFS_EXPORT_PATHS[$index]}" \
            "${PATCH_NETWORK_SERVICE_NFS_EXPORT_CLIENTS[$index]}(${PATCH_NETWORK_SERVICE_NFS_EXPORT_OPTIONS[$index]})" \
            "${PATCH_NETWORK_SERVICE_NFS_EXPORT_APPROVALS[$index]}" || return 2
        index=$((index + 1))
    done
    _patch_network_service_verify_policy_record nfs config "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PATH" - \
        "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_APPROVAL"
}

_patch_network_service_verify_rpc_inputs() {
    local index=0

    [ "${#PATCH_NETWORK_SERVICE_RPC_SERVICES[@]}" -gt 0 ] || return 2
    while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_RPC_SERVICES[@]}" ]; do
        _patch_network_service_verify_policy_record rpcbind rpc-allow \
            "${PATCH_NETWORK_SERVICE_RPC_SERVICES[$index]}" "${PATCH_NETWORK_SERVICE_RPC_CLIENTS[$index]}" \
            "${PATCH_NETWORK_SERVICE_RPC_APPROVALS[$index]}" || return 2
        index=$((index + 1))
    done
}

_patch_network_service_verify_mail_relay_inputs() {
    local index=0

    [ "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PROVIDER" = postfix ] &&
        [ "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PATH" = /etc/postfix/main.cf ] || return 2
    [ "${#PATCH_NETWORK_SERVICE_MAIL_CLIENTS[@]}" -gt 0 ] || return 2
    _patch_network_service_verify_policy_record postfix config "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PATH" - \
        "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_APPROVAL" || return 2
    while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_MAIL_CLIENTS[@]}" ]; do
        _patch_network_service_verify_policy_record postfix relay-client \
            "${PATCH_NETWORK_SERVICE_MAIL_CLIENTS[$index]}" - \
            "${PATCH_NETWORK_SERVICE_MAIL_CLIENT_APPROVALS[$index]}" || return 2
        index=$((index + 1))
    done
}

_patch_network_service_verify_mail_command_input() {
    [ "$PATCH_NETWORK_SERVICE_COMMAND_INPUT_PROVIDER" = "$PATCH_NETWORK_SERVICE_PROVIDER" ] || return 2
    _patch_network_service_verify_policy_record "$PATCH_NETWORK_SERVICE_PROVIDER" command \
        "$PATCH_NETWORK_SERVICE_COMMAND_INPUT_PATH" - "$PATCH_NETWORK_SERVICE_COMMAND_INPUT_APPROVAL"
}

_patch_network_service_verify_mail_config_input() {
    local expected_path=""

    case "$PATCH_NETWORK_SERVICE_PROVIDER" in
        postfix) expected_path=/etc/postfix/main.cf ;;
        sendmail) expected_path=/etc/mail/sendmail.cf ;;
        *) return 2 ;;
    esac
    [ "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PROVIDER" = "$PATCH_NETWORK_SERVICE_PROVIDER" ] &&
        [ "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PATH" = "$expected_path" ] || return 2
    _patch_network_service_verify_policy_record "$PATCH_NETWORK_SERVICE_PROVIDER" config \
        "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PATH" - "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_APPROVAL"
}

_patch_network_service_verify_advisory_input() {
    [ -n "$PATCH_NETWORK_SERVICE_ADVISORY_VERSION" ] &&
        [ "$PATCH_NETWORK_SERVICE_ADVISORY_CRITERION" = "$PATCH_NETWORK_SERVICE_CRITERION" ] &&
        [ "$PATCH_NETWORK_SERVICE_ADVISORY_PROVIDER" = "$PATCH_NETWORK_SERVICE_PROVIDER" ] || return 2
    _patch_network_service_verify_policy_record "$PATCH_NETWORK_SERVICE_PROVIDER" advisory \
        "$PATCH_NETWORK_SERVICE_ADVISORY_VERSION" \
        "$PATCH_NETWORK_SERVICE_ADVISORY_STATUS:$PATCH_NETWORK_SERVICE_ADVISORY_TOKEN" \
        "$PATCH_NETWORK_SERVICE_ADVISORY_APPROVAL"
}

_patch_network_service_verify_bind_inputs() {
    local index=0
    local peer_kind=""
    local peer_value=""
    local key_name=""
    local -A referenced_keys=()

    [ "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PROVIDER" = bind ] || return 2
    _patch_network_service_verify_policy_record bind config "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PATH" - \
        "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_APPROVAL" || return 2
    while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_TSIG_NAMES[@]}" ]; do
        _patch_network_service_verify_policy_record bind tsig-reference \
            "${PATCH_NETWORK_SERVICE_TSIG_NAMES[$index]}" "${PATCH_NETWORK_SERVICE_TSIG_REFERENCES[$index]}" \
            "${PATCH_NETWORK_SERVICE_TSIG_APPROVALS[$index]}" || return 2
        index=$((index + 1))
    done
    if [ "$PATCH_NETWORK_SERVICE_CRITERION" = U-50 ]; then
        [ "${#PATCH_NETWORK_SERVICE_TRANSFER_PEER_KINDS[@]}" -gt 0 ] || return 2
        [ "${#PATCH_NETWORK_SERVICE_UPDATE_KEY_NAMES[@]}" -eq 0 ] || return 2
        index=0
        while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_TRANSFER_PEER_KINDS[@]}" ]; do
            peer_kind="${PATCH_NETWORK_SERVICE_TRANSFER_PEER_KINDS[$index]}"
            peer_value="${PATCH_NETWORK_SERVICE_TRANSFER_PEER_VALUES[$index]}"
            if [ "$peer_kind" = key ]; then
                [ "${PATCH_NETWORK_SERVICE_TSIG_SEEN[$peer_value]+present}" = present ] || return 2
                referenced_keys["$peer_value"]=1
            fi
            _patch_network_service_verify_policy_record bind transfer-peer "$peer_kind" "$peer_value" \
                "${PATCH_NETWORK_SERVICE_TRANSFER_PEER_APPROVALS[$index]}" || return 2
            index=$((index + 1))
        done
    else
        [ "${#PATCH_NETWORK_SERVICE_UPDATE_KEY_NAMES[@]}" -gt 0 ] || return 2
        [ "${#PATCH_NETWORK_SERVICE_TRANSFER_PEER_KINDS[@]}" -eq 0 ] || return 2
        index=0
        while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_UPDATE_KEY_NAMES[@]}" ]; do
            key_name="${PATCH_NETWORK_SERVICE_UPDATE_KEY_NAMES[$index]}"
            [ "${PATCH_NETWORK_SERVICE_TSIG_SEEN[$key_name]+present}" = present ] || return 2
            referenced_keys["$key_name"]=1
            _patch_network_service_verify_policy_record bind update-key "$key_name" - \
                "${PATCH_NETWORK_SERVICE_UPDATE_KEY_APPROVALS[$index]}" || return 2
            index=$((index + 1))
        done
    fi
    for key_name in "${PATCH_NETWORK_SERVICE_TSIG_NAMES[@]}"; do
        [ "${referenced_keys[$key_name]+present}" = present ] || return 2
    done
}

_patch_network_service_validate_required_inputs() {
    _patch_network_service_callback_is_current native_validator || return 2
    case "$PATCH_NETWORK_SERVICE_CRITERION:$PATCH_NETWORK_SERVICE_PROVIDER" in
        U-35:nfs|U-40:nfs)
            _patch_network_service_verify_nfs_inputs && _patch_network_service_no_rpc_inputs &&
                _patch_network_service_no_mail_inputs && _patch_network_service_no_bind_inputs &&
                _patch_network_service_no_advisory_input || return 2
            PATCH_NETWORK_SERVICE_TARGET_KIND=config
            ;;
        U-35:*|U-40:*) return 1 ;;
        U-39:nfs)
            _patch_network_service_no_nfs_inputs && _patch_network_service_no_rpc_inputs &&
                _patch_network_service_no_mail_inputs && _patch_network_service_no_bind_inputs &&
                _patch_network_service_no_advisory_input && [ -z "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PROVIDER" ] || return 2
            PATCH_NETWORK_SERVICE_TARGET_KIND=none
            ;;
        U-42:rpcbind)
            _patch_network_service_verify_rpc_inputs && _patch_network_service_no_nfs_inputs &&
                _patch_network_service_no_mail_inputs && _patch_network_service_no_bind_inputs &&
                _patch_network_service_no_advisory_input && [ -z "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PROVIDER" ] || return 2
            PATCH_NETWORK_SERVICE_TARGET_KIND=none
            ;;
        U-45:postfix|U-45:sendmail|U-45:exim|U-49:bind)
            _patch_network_service_verify_advisory_input && _patch_network_service_no_nfs_inputs &&
                _patch_network_service_no_rpc_inputs && _patch_network_service_no_mail_inputs &&
                _patch_network_service_no_bind_inputs && [ -z "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PROVIDER" ] || return 2
            PATCH_NETWORK_SERVICE_TARGET_KIND=none
            ;;
        U-46:postfix|U-46:exim)
            _patch_network_service_verify_mail_command_input && _patch_network_service_no_nfs_inputs &&
                _patch_network_service_no_rpc_inputs && [ "${#PATCH_NETWORK_SERVICE_MAIL_CLIENTS[@]}" -eq 0 ] &&
                _patch_network_service_no_bind_inputs && _patch_network_service_no_advisory_input &&
                [ -z "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PROVIDER" ] || return 2
            PATCH_NETWORK_SERVICE_TARGET_KIND=metadata
            ;;
        U-46:sendmail)
            _patch_network_service_verify_mail_config_input && _patch_network_service_no_nfs_inputs &&
                _patch_network_service_no_rpc_inputs && _patch_network_service_no_mail_inputs &&
                _patch_network_service_no_bind_inputs && _patch_network_service_no_advisory_input || return 2
            PATCH_NETWORK_SERVICE_TARGET_KIND=config
            ;;
        U-47:postfix)
            _patch_network_service_verify_mail_relay_inputs && _patch_network_service_no_nfs_inputs &&
                _patch_network_service_no_rpc_inputs && _patch_network_service_no_bind_inputs &&
                _patch_network_service_no_advisory_input && [ -z "$PATCH_NETWORK_SERVICE_COMMAND_INPUT_PROVIDER" ] || return 2
            PATCH_NETWORK_SERVICE_TARGET_KIND=config
            ;;
        U-47:sendmail|U-47:exim) return 1 ;;
        U-48:postfix|U-48:sendmail)
            _patch_network_service_verify_mail_config_input && _patch_network_service_no_nfs_inputs &&
                _patch_network_service_no_rpc_inputs && _patch_network_service_no_mail_inputs &&
                _patch_network_service_no_bind_inputs && _patch_network_service_no_advisory_input || return 2
            PATCH_NETWORK_SERVICE_TARGET_KIND=config
            ;;
        U-48:exim) return 1 ;;
        U-50:bind|U-51:bind)
            _patch_network_service_verify_bind_inputs && _patch_network_service_no_nfs_inputs &&
                _patch_network_service_no_rpc_inputs && _patch_network_service_no_mail_inputs &&
                _patch_network_service_no_advisory_input || return 2
            PATCH_NETWORK_SERVICE_TARGET_KIND=config
            ;;
        *) return 1 ;;
    esac
    _patch_network_service_callback_is_current runtime_transition || return 2
}

_patch_network_service_capture_target() {
    local logical_path="$1"
    local target_kind="$2"
    local parent_path=""
    local physical_path=""
    local metadata_before=""
    local metadata_after=""
    local content_sha256=""
    local remaining=""
    local links=""
    local cp_command=""

    _patch_network_service_safe_parent_into "$logical_path" parent_path || return 2
    physical_path="$parent_path/${logical_path##*/}"
    [ -f "$physical_path" ] && [ ! -L "$physical_path" ] && [ -r "$physical_path" ] || return 2
    _patch_network_service_stat_into "$physical_path" metadata_before || return 2
    remaining="${metadata_before#*:*:*:*:*:}"
    links="${remaining%%:*}"
    [ "$links" = 1 ] || return 2
    _patch_network_service_sha256_into "$physical_path" content_sha256 || return 2
    _patch_network_service_stat_into "$physical_path" metadata_after || return 2
    [ "$metadata_before" = "$metadata_after" ] || return 2

    PATCH_NETWORK_SERVICE_CONFIG_LOGICAL_PATH="$logical_path"
    PATCH_NETWORK_SERVICE_CONFIG_PHYSICAL_PATH="$physical_path"
    PATCH_NETWORK_SERVICE_CONFIG_BEFORE_STATE=present
    PATCH_NETWORK_SERVICE_CONFIG_DEVICE="${metadata_before%%:*}"; remaining="${metadata_before#*:}"
    PATCH_NETWORK_SERVICE_CONFIG_INODE="${remaining%%:*}"; remaining="${remaining#*:}"
    PATCH_NETWORK_SERVICE_CONFIG_UID="${remaining%%:*}"; remaining="${remaining#*:}"
    PATCH_NETWORK_SERVICE_CONFIG_GID="${remaining%%:*}"; remaining="${remaining#*:}"
    PATCH_NETWORK_SERVICE_CONFIG_MODE="${remaining%%:*}"; remaining="${remaining#*:}"
    remaining="${remaining#*:}"
    PATCH_NETWORK_SERVICE_CONFIG_SIZE="${remaining%%:*}"; remaining="${remaining#*:}"
    PATCH_NETWORK_SERVICE_CONFIG_MTIME="${remaining%%:*}"; remaining="${remaining#*:}"
    PATCH_NETWORK_SERVICE_CONFIG_CTIME="${remaining%%:*}"
    printf -v PATCH_NETWORK_SERVICE_CONFIG_MODE '%04o' "$((8#$PATCH_NETWORK_SERVICE_CONFIG_MODE & 07777))"
    PATCH_NETWORK_SERVICE_CONFIG_BEFORE_SHA256="$content_sha256"
    PATCH_NETWORK_SERVICE_CONFIG_DESIRED_UID=0
    PATCH_NETWORK_SERVICE_CONFIG_DESIRED_GID="$PATCH_NETWORK_SERVICE_CONFIG_GID"
    if [ "$target_kind" = metadata ]; then
        printf -v PATCH_NETWORK_SERVICE_CONFIG_DESIRED_MODE '%04o' "$((8#$PATCH_NETWORK_SERVICE_CONFIG_MODE & 07776))"
    else
        PATCH_NETWORK_SERVICE_CONFIG_DESIRED_MODE=0640
    fi
    PATCH_NETWORK_SERVICE_CONFIG_BACKUP="$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/backups/target"
    PATCH_NETWORK_SERVICE_CONFIG_PAYLOAD="$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/payloads/target"
    _patch_network_service_command_into cp cp_command || return 2
    "$cp_command" -- "$physical_path" "$PATCH_NETWORK_SERVICE_CONFIG_BACKUP" || return 2
    "$cp_command" -- "$physical_path" "$PATCH_NETWORK_SERVICE_CONFIG_PAYLOAD" || return 2
    chmod 0600 "$PATCH_NETWORK_SERVICE_CONFIG_BACKUP" "$PATCH_NETWORK_SERVICE_CONFIG_PAYLOAD" || return 2
}

_patch_network_service_validate_nfs_source() {
    local path="$1"
    local awk_command=""

    _patch_network_service_command_into awk awk_command || return 2
    "$awk_command" '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            sub(/[[:space:]]+#.*/, "", line)
            sub(/[[:space:]]+$/, "", line)
            if (line == "" || line ~ /^#/) next
            if (line ~ /\\$/ || line ~ /[\047\042]/) exit 2
            count=split(line, fields, /[[:space:]]+/)
            if (count < 2 || fields[1] !~ /^\//) exit 2
            for (field_index=2; field_index<=count; field_index++) {
                if (fields[field_index] !~ /^[*A-Za-z0-9._:\/@+-]+\([A-Za-z0-9_=.,:+-]+\)$/) exit 2
            }
        }
    ' "$path"
}

_patch_network_service_validate_postfix_source() {
    local path="$1"
    local awk_command=""

    _patch_network_service_command_into awk awk_command || return 2
    "$awk_command" '
        {
            line=$0
            if (line ~ /^[[:space:]]/ && line !~ /^[[:space:]]*($|#)/) exit 2
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            if (line ~ /^(include|multi_wrapper|multi_instance_directories)[[:space:]]*=/) exit 2
            if (line !~ /^[A-Za-z0-9_]+[[:space:]]*=/) exit 2
        }
    ' "$path"
}

_patch_network_service_validate_sendmail_source() {
    local path="$1"
    local awk_command=""

    _patch_network_service_command_into awk awk_command || return 2
    "$awk_command" '
        /^[[:space:]]/ && $0 !~ /^[[:space:]]*($|#)/ {exit 2}
        /^[[:space:]]*O[[:space:]]*PrivacyOptions[[:space:]]*=/ {privacy++}
        END {if (privacy > 1) exit 2}
    ' "$path"
}

_patch_network_service_preflight_bind_source() {
    local parent_path=""
    local physical_path=""
    local allowed_includes=""
    local separator=""
    local reference=""
    local awk_command=""

    [ "$PATCH_NETWORK_SERVICE_MODE" = required ] && [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = config ] &&
        [ "$PATCH_NETWORK_SERVICE_PROVIDER" = bind ] || return 0
    _patch_network_service_safe_parent_into "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PATH" parent_path || return 2
    physical_path="$parent_path/${PATCH_NETWORK_SERVICE_CONFIG_INPUT_PATH##*/}"
    [ -f "$physical_path" ] && [ ! -L "$physical_path" ] && [ -r "$physical_path" ] || return 2
    for reference in "${PATCH_NETWORK_SERVICE_TSIG_REFERENCES[@]}"; do
        allowed_includes+="$separator$reference"
        separator='|'
    done
    _patch_network_service_command_into awk awk_command || return 2
    "$awk_command" -v allowed_includes="$allowed_includes" '
        function include_allowed(path, count,item_index,items) {
            count=split(allowed_includes, items, "|")
            for (item_index=1; item_index<=count; item_index++) if (items[item_index] == path) return 1
            return 0
        }
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^(#|\/\/)/) next
            lower=tolower(line)
            if (lower ~ /(^|[[:space:];{}])secret[[:space:]]+/) exit 2
            if (lower ~ /^(acl|view)[[:space:]]/) exit 2
            if (lower ~ /^include[[:space:]]+/) {
                path=line
                sub(/^include[[:space:]]+"/, "", path)
                sub(/"[[:space:]]*;[[:space:]]*($|\/\/.*$)/, "", path)
                if (!include_allowed(path)) exit 2
            }
        }
    ' "$physical_path"
}

_patch_network_service_render_nfs_payload() {
    local output_path="$1"
    local index=0

    {
        printf '# Managed by kisa-cce-patch.\n'
        while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_NFS_EXPORT_PATHS[@]}" ]; do
            printf '%s %s(%s)\n' "${PATCH_NETWORK_SERVICE_NFS_EXPORT_PATHS[$index]}" \
                "${PATCH_NETWORK_SERVICE_NFS_EXPORT_CLIENTS[$index]}" \
                "${PATCH_NETWORK_SERVICE_NFS_EXPORT_OPTIONS[$index]}"
            index=$((index + 1))
        done
    } > "$output_path"
}

_patch_network_service_render_postfix_payload() {
    local input_path="$1"
    local output_path="$2"
    local clients=""
    local separator=""
    local client=""
    local awk_command=""

    for client in "${PATCH_NETWORK_SERVICE_MAIL_CLIENTS[@]}"; do
        clients+="$separator$client"
        separator=,
    done
    _patch_network_service_command_into awk awk_command || return 2
    "$awk_command" -v criterion="$PATCH_NETWORK_SERVICE_CRITERION" -v clients="$clients" '
        {
            line=$0
            probe=tolower(line)
            sub(/^[[:space:]]+/, "", probe)
            if (criterion == "U-47" && probe ~ /^(mynetworks|smtpd_relay_restrictions|smtpd_recipient_restrictions)[[:space:]]*=/) next
            if (criterion == "U-48" && probe ~ /^disable_vrfy_command[[:space:]]*=/) next
            print line
        }
        END {
            print ""
            print "# Managed by kisa-cce-patch."
            if (criterion == "U-47") {
                print "mynetworks = " clients
                print "smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination"
            } else {
                print "disable_vrfy_command = yes"
            }
        }
    ' "$input_path" > "$output_path"
}

_patch_network_service_render_sendmail_payload() {
    local input_path="$1"
    local output_path="$2"
    local awk_command=""

    _patch_network_service_command_into awk awk_command || return 2
    "$awk_command" -v criterion="$PATCH_NETWORK_SERVICE_CRITERION" '
        function emit(value, count,item_index,items,seen,output,item) {
            count=split(value, items, /[[:space:],]+/)
            for (item_index=1; item_index<=count; item_index++) {
                item=tolower(items[item_index])
                if (item != "" && !seen[item]++) output=output (output=="" ? "" : ",") items[item_index]
            }
            if (criterion == "U-46" && !seen["restrictqrun"]++) output=output (output=="" ? "" : ",") "restrictqrun"
            if (criterion == "U-48") {
                if (!seen["noexpn"]++) output=output (output=="" ? "" : ",") "noexpn"
                if (!seen["novrfy"]++) output=output (output=="" ? "" : ",") "novrfy"
            }
            print "O PrivacyOptions=" output
        }
        /^[[:space:]]*O[[:space:]]*PrivacyOptions[[:space:]]*=/ {
            value=$0
            sub(/^[^=]*=/, "", value)
            emit(value)
            found=1
            next
        }
        {print}
        END {if (!found) emit("")}
    ' "$input_path" > "$output_path"
}

_patch_network_service_bind_directive_into() {
    local destination_name="$1"
    local output_value=""
    local separator=""
    local index=0

    if [ "$PATCH_NETWORK_SERVICE_CRITERION" = U-50 ]; then
        while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_TRANSFER_PEER_KINDS[@]}" ]; do
            if [ "${PATCH_NETWORK_SERVICE_TRANSFER_PEER_KINDS[$index]}" = key ]; then
                output_value+="$separator key \"${PATCH_NETWORK_SERVICE_TRANSFER_PEER_VALUES[$index]}\";"
            else
                output_value+="$separator ${PATCH_NETWORK_SERVICE_TRANSFER_PEER_VALUES[$index]};"
            fi
            separator=""
            index=$((index + 1))
        done
        printf -v "$destination_name" '    allow-transfer {%s };' "$output_value"
    else
        while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_UPDATE_KEY_NAMES[@]}" ]; do
            output_value+=" key \"${PATCH_NETWORK_SERVICE_UPDATE_KEY_NAMES[$index]}\";"
            index=$((index + 1))
        done
        printf -v "$destination_name" '    allow-update {%s };\n    allow-update-forwarding { none; };' "$output_value"
    fi
}

_patch_network_service_render_bind_payload() {
    local input_path="$1"
    local output_path="$2"
    local directive=""
    local allowed_includes=""
    local reference=""
    local separator=""
    local awk_command=""

    _patch_network_service_bind_directive_into directive || return 2
    for reference in "${PATCH_NETWORK_SERVICE_TSIG_REFERENCES[@]}"; do
        allowed_includes+="$separator$reference"
        separator='|'
    done
    _patch_network_service_command_into awk awk_command || return 2
    "$awk_command" -v criterion="$PATCH_NETWORK_SERVICE_CRITERION" -v directive="$directive" \
        -v allowed_includes="$allowed_includes" '
        function include_allowed(path, count,item_index,items) {
            count=split(allowed_includes, items, "|")
            for (item_index=1; item_index<=count; item_index++) if (items[item_index] == path) return 1
            return 0
        }
        {
            line=$0
            lower=tolower(line)
            if (lower ~ /(^|[[:space:];{}])secret[[:space:]]+/) exit 2
            if (lower ~ /^[[:space:]]*(acl|view)[[:space:]]/) exit 2
            if (lower ~ /^[[:space:]]*include[[:space:]]+/) {
                path=line
                sub(/^[[:space:]]*include[[:space:]]+"/, "", path)
                sub(/"[[:space:]]*;[[:space:]]*($|\/\/.*$)/, "", path)
                if (!include_allowed(path)) exit 2
                present_include[path]=1
            }
            opens=line; open_count=gsub(/\{/, "{", opens)
            closes=line; close_count=gsub(/\}/, "}", closes)
            if (lower ~ /^[[:space:]]*options[[:space:]]*\{/) {
                if (depth != 0 || open_count != 1 || close_count != 0 || options_found) exit 2
                options_found=1
                options_depth=depth+1
            }
            target=(criterion == "U-50" ? "allow-transfer" : "allow-update")
            if (criterion == "U-51" && index(lower, "update-policy")) exit 2
            if (criterion == "U-51" && index(lower, "allow-update-forwarding")) {
                if (depth != options_depth || lower !~ "^[[:space:]]*allow-update-forwarding[[:space:]]*\\{[^{}]*\\}[[:space:]]*;[[:space:]]*($|//)") exit 2
                next
            }
            if (index(lower, target)) {
                if (depth != options_depth || lower !~ "^[[:space:]]*" target "[[:space:]]*\\{[^{}]*\\}[[:space:]]*;[[:space:]]*($|//)") exit 2
                next
            }
            if (options_found && depth == options_depth && lower ~ /^[[:space:]]*\}/) print directive
            print line
            depth += open_count - close_count
            if (depth < 0) exit 2
        }
        END {
            if (depth != 0 || options_found != 1) exit 2
            count=split(allowed_includes, includes, "|")
            for (item_index=1; item_index<=count; item_index++) if (includes[item_index] != "" && !present_include[includes[item_index]]) {
                print "include \"" includes[item_index] "\";"
            }
        }
    ' "$input_path" > "$output_path"
}

_patch_network_service_finalize_payload() {
    local temporary_path=""
    local mktemp_command=""
    local mv_command=""
    local desired_sha256=""

    [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = config ] || {
        PATCH_NETWORK_SERVICE_CONFIG_DESIRED_SHA256="$PATCH_NETWORK_SERVICE_CONFIG_BEFORE_SHA256"
        [ "$PATCH_NETWORK_SERVICE_CONFIG_UID" = "$PATCH_NETWORK_SERVICE_CONFIG_DESIRED_UID" ] &&
            [ "$PATCH_NETWORK_SERVICE_CONFIG_MODE" = "$PATCH_NETWORK_SERVICE_CONFIG_DESIRED_MODE" ] ||
            PATCH_NETWORK_SERVICE_CHANGE_COUNT=1
        return 0
    }
    _patch_network_service_command_into mktemp mktemp_command || return 2
    _patch_network_service_command_into mv mv_command || return 2
    temporary_path="$("$mktemp_command" "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/payloads/.target.XXXXXXXX")" || return 2
    case "$PATCH_NETWORK_SERVICE_PROVIDER" in
        nfs)
            _patch_network_service_validate_nfs_source "$PATCH_NETWORK_SERVICE_CONFIG_PAYLOAD" || return 2
            _patch_network_service_render_nfs_payload "$temporary_path" || return 2
            ;;
        postfix)
            _patch_network_service_validate_postfix_source "$PATCH_NETWORK_SERVICE_CONFIG_PAYLOAD" || return 2
            _patch_network_service_render_postfix_payload "$PATCH_NETWORK_SERVICE_CONFIG_PAYLOAD" "$temporary_path" || return 2
            ;;
        sendmail)
            _patch_network_service_validate_sendmail_source "$PATCH_NETWORK_SERVICE_CONFIG_PAYLOAD" || return 2
            _patch_network_service_render_sendmail_payload "$PATCH_NETWORK_SERVICE_CONFIG_PAYLOAD" "$temporary_path" || return 2
            ;;
        bind)
            _patch_network_service_render_bind_payload "$PATCH_NETWORK_SERVICE_CONFIG_PAYLOAD" "$temporary_path" || return 2
            ;;
        *) return 2 ;;
    esac
    chmod 0600 "$temporary_path" || return 2
    "$mv_command" -f -- "$temporary_path" "$PATCH_NETWORK_SERVICE_CONFIG_PAYLOAD" || return 2
    _patch_network_service_sha256_into "$PATCH_NETWORK_SERVICE_CONFIG_PAYLOAD" desired_sha256 || return 2
    PATCH_NETWORK_SERVICE_CONFIG_DESIRED_SHA256="$desired_sha256"
    if [ "$desired_sha256" != "$PATCH_NETWORK_SERVICE_CONFIG_BEFORE_SHA256" ] ||
        [ "$PATCH_NETWORK_SERVICE_CONFIG_UID" != "$PATCH_NETWORK_SERVICE_CONFIG_DESIRED_UID" ] ||
        [ "$PATCH_NETWORK_SERVICE_CONFIG_MODE" != "$PATCH_NETWORK_SERVICE_CONFIG_DESIRED_MODE" ]; then
        PATCH_NETWORK_SERVICE_CHANGE_COUNT=1
    fi
}

_patch_network_service_render_policy() {
    local index=0

    printf 'schema\trecord_type\tcriterion\tprovider\tfield_1\tfield_2\tapproval\n'
    while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_INTENT_CRITERIA[@]}" ]; do
        printf '1\tintent\t%s\t%s\t%s\t-\t%s\n' \
            "${PATCH_NETWORK_SERVICE_INTENT_CRITERIA[$index]}" \
            "${PATCH_NETWORK_SERVICE_INTENT_PROVIDERS[$index]}" \
            "${PATCH_NETWORK_SERVICE_INTENT_MODES[$index]}" \
            "${PATCH_NETWORK_SERVICE_INTENT_APPROVAL_LIST[$index]}"
        index=$((index + 1))
    done
    if [ -n "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PROVIDER" ]; then
        printf '1\tconfig\t%s\t%s\t%s\t-\t%s\n' "$PATCH_NETWORK_SERVICE_CRITERION" \
            "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PROVIDER" "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PATH" \
            "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_APPROVAL"
    fi
    if [ -n "$PATCH_NETWORK_SERVICE_COMMAND_INPUT_PROVIDER" ]; then
        printf '1\tcommand\t%s\t%s\t%s\t-\t%s\n' "$PATCH_NETWORK_SERVICE_CRITERION" \
            "$PATCH_NETWORK_SERVICE_COMMAND_INPUT_PROVIDER" "$PATCH_NETWORK_SERVICE_COMMAND_INPUT_PATH" \
            "$PATCH_NETWORK_SERVICE_COMMAND_INPUT_APPROVAL"
    fi
    index=0
    while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_NFS_EXPORT_PATHS[@]}" ]; do
        printf '1\tnfs-export\t%s\tnfs\t%s\t%s(%s)\t%s\n' "$PATCH_NETWORK_SERVICE_CRITERION" \
            "${PATCH_NETWORK_SERVICE_NFS_EXPORT_PATHS[$index]}" \
            "${PATCH_NETWORK_SERVICE_NFS_EXPORT_CLIENTS[$index]}" \
            "${PATCH_NETWORK_SERVICE_NFS_EXPORT_OPTIONS[$index]}" \
            "${PATCH_NETWORK_SERVICE_NFS_EXPORT_APPROVALS[$index]}"
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_RPC_SERVICES[@]}" ]; do
        printf '1\trpc-allow\t%s\trpcbind\t%s\t%s\t%s\n' "$PATCH_NETWORK_SERVICE_CRITERION" \
            "${PATCH_NETWORK_SERVICE_RPC_SERVICES[$index]}" "${PATCH_NETWORK_SERVICE_RPC_CLIENTS[$index]}" \
            "${PATCH_NETWORK_SERVICE_RPC_APPROVALS[$index]}"
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_MAIL_CLIENTS[@]}" ]; do
        printf '1\trelay-client\t%s\tpostfix\t%s\t-\t%s\n' "$PATCH_NETWORK_SERVICE_CRITERION" \
            "${PATCH_NETWORK_SERVICE_MAIL_CLIENTS[$index]}" "${PATCH_NETWORK_SERVICE_MAIL_CLIENT_APPROVALS[$index]}"
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_TSIG_NAMES[@]}" ]; do
        printf '1\ttsig-reference\t%s\tbind\t%s\t%s\t%s\n' "$PATCH_NETWORK_SERVICE_CRITERION" \
            "${PATCH_NETWORK_SERVICE_TSIG_NAMES[$index]}" "${PATCH_NETWORK_SERVICE_TSIG_REFERENCES[$index]}" \
            "${PATCH_NETWORK_SERVICE_TSIG_APPROVALS[$index]}"
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_TRANSFER_PEER_KINDS[@]}" ]; do
        printf '1\ttransfer-peer\t%s\tbind\t%s\t%s\t%s\n' "$PATCH_NETWORK_SERVICE_CRITERION" \
            "${PATCH_NETWORK_SERVICE_TRANSFER_PEER_KINDS[$index]}" \
            "${PATCH_NETWORK_SERVICE_TRANSFER_PEER_VALUES[$index]}" \
            "${PATCH_NETWORK_SERVICE_TRANSFER_PEER_APPROVALS[$index]}"
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_UPDATE_KEY_NAMES[@]}" ]; do
        printf '1\tupdate-key\t%s\tbind\t%s\t-\t%s\n' "$PATCH_NETWORK_SERVICE_CRITERION" \
            "${PATCH_NETWORK_SERVICE_UPDATE_KEY_NAMES[$index]}" \
            "${PATCH_NETWORK_SERVICE_UPDATE_KEY_APPROVALS[$index]}"
        index=$((index + 1))
    done
    if [ -n "$PATCH_NETWORK_SERVICE_ADVISORY_VERSION" ]; then
        printf '1\tadvisory\t%s\t%s\t%s\t%s:%s\t%s\n' "$PATCH_NETWORK_SERVICE_ADVISORY_CRITERION" \
            "$PATCH_NETWORK_SERVICE_ADVISORY_PROVIDER" "$PATCH_NETWORK_SERVICE_ADVISORY_VERSION" \
            "$PATCH_NETWORK_SERVICE_ADVISORY_STATUS" "$PATCH_NETWORK_SERVICE_ADVISORY_TOKEN" \
            "$PATCH_NETWORK_SERVICE_ADVISORY_APPROVAL"
    fi
}

_patch_network_service_render_plan() {
    local index=0
    local action=""

    printf 'criterion\tprovider\tintent\taction\tpath\tstate\tapproval\n'
    while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_INTENT_CRITERIA[@]}" ]; do
        case "$PATCH_NETWORK_SERVICE_MODE:$PATCH_NETWORK_SERVICE_TARGET_KIND" in
            disabled:*) action=delegate-disable ;;
            required:config) action=replace-config ;;
            required:metadata) action=restrict-command ;;
            required:none)
                if [ "$PATCH_NETWORK_SERVICE_STATE" = external_action_required ]; then action=package-update
                else action=validate-required-service
                fi
                ;;
        esac
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$PATCH_NETWORK_SERVICE_CRITERION" \
            "${PATCH_NETWORK_SERVICE_INTENT_PROVIDERS[$index]}" "$PATCH_NETWORK_SERVICE_MODE" "$action" \
            "${PATCH_NETWORK_SERVICE_CONFIG_LOGICAL_PATH:--}" \
            "${PATCH_NETWORK_SERVICE_CRITERION_STATES[$PATCH_NETWORK_SERVICE_CRITERION]}" \
            "${PATCH_NETWORK_SERVICE_INTENT_APPROVAL_LIST[$index]}"
        index=$((index + 1))
    done
}

_patch_network_service_render_manifest() {
    local callback_kind=""
    local index=0

    printf 'schema\trecord_type\trecord_fields\n'
    printf '1\troot\t%s\t%s\t%s\n' "$PATCH_NETWORK_SERVICE_ROOT" \
        "$PATCH_NETWORK_SERVICE_ROOT_DEVICE" "$PATCH_NETWORK_SERVICE_ROOT_INODE"
    printf '1\tcriterion\t%s\t%s\t%s\t%s\n' "$PATCH_NETWORK_SERVICE_CRITERION" \
        "$PATCH_NETWORK_SERVICE_MODE" "$PATCH_NETWORK_SERVICE_PROVIDER" "$PATCH_NETWORK_SERVICE_TARGET_KIND"
    while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_INTENT_CRITERIA[@]}" ]; do
        printf '1\tintent\t%s\t%s\t%s\n' "${PATCH_NETWORK_SERVICE_INTENT_PROVIDERS[$index]}" \
            "${PATCH_NETWORK_SERVICE_INTENT_MODES[$index]}" "${PATCH_NETWORK_SERVICE_INTENT_APPROVAL_LIST[$index]}"
        index=$((index + 1))
    done
    for callback_kind in policy_verifier native_validator runtime_transition service_graph; do
        case "$callback_kind:$PATCH_NETWORK_SERVICE_MODE" in
            policy_verifier:*) ;;
            service_graph:disabled) ;;
            native_validator:required|runtime_transition:required) ;;
            *) continue ;;
        esac
        printf '1\tcallback\t%s\t%s\t%s\n' "$callback_kind" \
            "${PATCH_NETWORK_SERVICE_CALLBACKS[$callback_kind]}" \
            "${PATCH_NETWORK_SERVICE_CALLBACK_FINGERPRINTS[$callback_kind]}"
    done
    if [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = config ] || [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = metadata ]; then
        printf '1\ttarget\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$PATCH_NETWORK_SERVICE_CONFIG_LOGICAL_PATH" "$PATCH_NETWORK_SERVICE_CONFIG_BEFORE_STATE" \
            "$PATCH_NETWORK_SERVICE_CONFIG_DEVICE" "$PATCH_NETWORK_SERVICE_CONFIG_INODE" \
            "$PATCH_NETWORK_SERVICE_CONFIG_UID" "$PATCH_NETWORK_SERVICE_CONFIG_GID" \
            "$PATCH_NETWORK_SERVICE_CONFIG_MODE" "$PATCH_NETWORK_SERVICE_CONFIG_SIZE" \
            "$PATCH_NETWORK_SERVICE_CONFIG_MTIME" "$PATCH_NETWORK_SERVICE_CONFIG_CTIME" \
            "$PATCH_NETWORK_SERVICE_CONFIG_BEFORE_SHA256" "$PATCH_NETWORK_SERVICE_CONFIG_DESIRED_UID" \
            "$PATCH_NETWORK_SERVICE_CONFIG_DESIRED_GID" "$PATCH_NETWORK_SERVICE_CONFIG_DESIRED_MODE" \
            "$PATCH_NETWORK_SERVICE_CONFIG_DESIRED_SHA256" target
    fi
    if [ -n "$PATCH_NETWORK_SERVICE_ADVISORY_VERSION" ]; then
        printf '1\tadvisory\t%s\t%s\t%s\t%s\t%s\t%s\n' "$PATCH_NETWORK_SERVICE_ADVISORY_CRITERION" \
            "$PATCH_NETWORK_SERVICE_ADVISORY_PROVIDER" "$PATCH_NETWORK_SERVICE_ADVISORY_VERSION" \
            "$PATCH_NETWORK_SERVICE_ADVISORY_STATUS" "$PATCH_NETWORK_SERVICE_ADVISORY_TOKEN" \
            "$PATCH_NETWORK_SERVICE_ADVISORY_APPROVAL"
    fi
}

_patch_network_service_write_artifact() {
    local path="$1"
    local renderer="$2"

    [ ! -e "$path" ] && [ ! -L "$path" ] || return 2
    (umask 077; set -o noclobber; "$renderer" > "$path" && chmod 0600 "$path")
}

_patch_network_service_write_checksums() {
    local checksum_path="$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/checksums.sha256"
    local relative=""
    local checksum_value=""

    [ ! -e "$checksum_path" ] && [ ! -L "$checksum_path" ] || return 2
    {
        for relative in manifest.tsv plan.tsv policy.tsv; do
            _patch_network_service_sha256_into "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/$relative" checksum_value || exit 2
            printf '%s  %s\n' "$checksum_value" "$relative"
        done
        if [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = config ] || [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = metadata ]; then
            for relative in backups/target payloads/target; do
                _patch_network_service_sha256_into "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/$relative" checksum_value || exit 2
                printf '%s  %s\n' "$checksum_value" "$relative"
            done
        fi
    } > "$checksum_path" || return 2
    chmod 0600 "$checksum_path"
}

_patch_network_service_native_validate() {
    local phase="$1"
    local validator="${PATCH_NETWORK_SERVICE_CALLBACKS[native_validator]:-}"
    local candidate=-

    _patch_network_service_callback_is_current native_validator || return 2
    if [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = config ] || [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = metadata ]; then
        case "$phase" in plan|preapply) candidate="$PATCH_NETWORK_SERVICE_CONFIG_PAYLOAD" ;; *) candidate="$PATCH_NETWORK_SERVICE_CONFIG_PHYSICAL_PATH" ;; esac
    fi
    "$validator" "$phase" "$PATCH_NETWORK_SERVICE_CRITERION" "$PATCH_NETWORK_SERVICE_PROVIDER" \
        "$PATCH_NETWORK_SERVICE_ROOT" "${PATCH_NETWORK_SERVICE_CONFIG_LOGICAL_PATH:--}" "$candidate" \
        "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/policy.tsv"
}

_patch_network_service_runtime_transition() {
    local phase="$1"
    local runtime_callback="${PATCH_NETWORK_SERVICE_CALLBACKS[runtime_transition]:-}"

    _patch_network_service_callback_is_current runtime_transition || return 2
    "$runtime_callback" "$phase" "$PATCH_NETWORK_SERVICE_CRITERION" "$PATCH_NETWORK_SERVICE_PROVIDER" \
        "$PATCH_NETWORK_SERVICE_ROOT" "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/policy.tsv"
}

_patch_network_service_delegate_action() {
    local action="$1"
    local rollback_mode="${2:-strict}"
    local callback="${PATCH_NETWORK_SERVICE_CALLBACKS[service_graph]:-}"
    local index=0
    local provider=""
    local delegate_directory=""

    _patch_network_service_callback_is_current service_graph || return 2
    while [ "$index" -lt "${#PATCH_NETWORK_SERVICE_INTENT_PROVIDERS[@]}" ]; do
        provider="${PATCH_NETWORK_SERVICE_INTENT_PROVIDERS[$index]}"
        delegate_directory="$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/delegates/$provider"
        "$callback" "$action" "$PATCH_NETWORK_SERVICE_ROOT" "$delegate_directory" \
            "$PATCH_NETWORK_SERVICE_CRITERION" "$provider" \
            "${PATCH_NETWORK_SERVICE_INTENT_APPROVAL_LIST[$index]}" "$rollback_mode" || return 2
        if [ "$action" = plan ]; then
            [ -d "$delegate_directory" ] && [ ! -L "$delegate_directory" ] || return 2
        fi
        index=$((index + 1))
    done
}

patch_network_service_write_plan_tsv() {
    local output_path="$1"
    local cp_command=""

    [ "$PATCH_NETWORK_SERVICE_PLAN_VALID" -eq 1 ] || return 2
    [ ! -e "$output_path" ] && [ ! -L "$output_path" ] || return 2
    _patch_network_service_command_into cp cp_command || return 2
    "$cp_command" -- "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/plan.tsv" "$output_path" || return 2
    chmod 0600 "$output_path"
}

_patch_network_service_inputs_are_empty() {
    _patch_network_service_no_nfs_inputs && _patch_network_service_no_rpc_inputs &&
        _patch_network_service_no_mail_inputs && _patch_network_service_no_bind_inputs &&
        _patch_network_service_no_advisory_input && [ -z "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PROVIDER" ]
}

_patch_network_service_cleanup_plan() {
    local rm_command=""

    [ -n "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY" ] || return 0
    case "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY" in "$PATCH_NETWORK_SERVICE_TRANSACTION_DIRECTORY"/network-service) ;; *) return 2 ;; esac
    _patch_network_service_command_into rm rm_command || return 2
    "$rm_command" -rf -- "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY"
}

patch_network_service_plan() {
    local requested_root="$1"
    local transaction_directory="$2"
    local criterion="$3"
    local validation_status=0
    local plan_error=""

    patch_network_service_reset
    _patch_network_service_valid_criterion "$criterion" || return 1
    PATCH_NETWORK_SERVICE_CRITERION="$criterion"
    _patch_network_service_callback_is_current policy_verifier || {
        _patch_network_service_set_error "trusted typed-policy verifier is required"
        return 2
    }
    _patch_network_service_validate_intents || {
        _patch_network_service_set_error "$criterion requires exact typed service intent"
        return 2
    }
    if [ "$PATCH_NETWORK_SERVICE_MODE" = disabled ]; then
        _patch_network_service_inputs_are_empty || {
            _patch_network_service_set_error "$criterion disabled intent cannot include provider configuration inputs"
            return 2
        }
        _patch_network_service_callback_is_current service_graph || {
            _patch_network_service_set_error "$criterion disabled intent requires the service graph adapter"
            return 2
        }
        PATCH_NETWORK_SERVICE_TARGET_KIND=delegated
    else
        _patch_network_service_validate_required_inputs || validation_status=$?
        if [ "$validation_status" -eq 1 ]; then
            _patch_network_service_set_error "$criterion provider configuration is unsupported or structurally complex"
            return 1
        elif [ "$validation_status" -ne 0 ]; then
            _patch_network_service_set_error "$criterion required intent is missing exact typed configuration input"
            return 2
        fi
    fi
    _patch_network_service_initialize_root "$requested_root" || {
        _patch_network_service_set_error "scan root is unsafe"
        return 2
    }
    _patch_network_service_preflight_bind_source || {
        _patch_network_service_set_error "BIND source contains an unapproved include, inline secret, or complex context"
        return 2
    }
    _patch_network_service_prepare_transaction "$transaction_directory" || {
        _patch_network_service_set_error "transaction directory is unsafe"
        return 2
    }
    if ! _patch_network_service_write_artifact "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/policy.tsv" \
        _patch_network_service_render_policy; then
        plan_error="typed policy artifact could not be written"
    elif [ "$PATCH_NETWORK_SERVICE_MODE" = disabled ]; then
        _patch_network_service_delegate_action plan || plan_error="service graph adapter rejected the disabled plan"
    else
        case "$PATCH_NETWORK_SERVICE_TARGET_KIND" in
            config)
                _patch_network_service_capture_target "$PATCH_NETWORK_SERVICE_CONFIG_INPUT_PATH" config ||
                    plan_error="provider configuration path is unsafe or unavailable"
                ;;
            metadata)
                _patch_network_service_capture_target "$PATCH_NETWORK_SERVICE_COMMAND_INPUT_PATH" metadata ||
                    plan_error="mail administration command is unsafe or unavailable"
                ;;
        esac
        if [ -z "$plan_error" ] && { [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = config ] ||
            [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = metadata ]; }; then
            _patch_network_service_finalize_payload || plan_error="provider configuration IR could not be rendered safely"
        fi
        if [ -z "$plan_error" ]; then
            _patch_network_service_native_validate plan || plan_error="native provider validation rejected the plan"
        fi
    fi
    if [ -n "$plan_error" ]; then
        _patch_network_service_cleanup_plan >/dev/null 2>&1 || true
        _patch_network_service_set_error "$plan_error"
        return 2
    fi
    if [ "$PATCH_NETWORK_SERVICE_ADVISORY_STATUS" = update-required ]; then
        PATCH_NETWORK_SERVICE_EXTERNAL_ACTION_REQUIRED_COUNT=1
        PATCH_NETWORK_SERVICE_STATE=external_action_required
        PATCH_NETWORK_SERVICE_CRITERION_STATES["$criterion"]=external_action_required
    elif [ "$PATCH_NETWORK_SERVICE_MODE" = disabled ]; then
        PATCH_NETWORK_SERVICE_STATE=planned
        PATCH_NETWORK_SERVICE_CRITERION_STATES["$criterion"]=delegated
    else
        PATCH_NETWORK_SERVICE_STATE=planned
        PATCH_NETWORK_SERVICE_CRITERION_STATES["$criterion"]=ready
    fi
    if ! _patch_network_service_write_artifact "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/manifest.tsv" \
        _patch_network_service_render_manifest ||
        ! _patch_network_service_write_artifact "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/plan.tsv" \
        _patch_network_service_render_plan ||
        ! _patch_network_service_write_checksums ||
        ! _patch_network_service_set_state "$PATCH_NETWORK_SERVICE_STATE"; then
        _patch_network_service_cleanup_plan >/dev/null 2>&1 || true
        _patch_network_service_set_error "transaction artifacts could not be finalized"
        return 2
    fi
    PATCH_NETWORK_SERVICE_PLAN_VALID=1
}

_patch_network_service_target_current_into() {
    local destination_name="$1"
    local current_metadata=""
    local current_sha256=""
    local current_device="" current_inode="" current_uid="" current_gid="" current_mode=""
    local current_links="" current_size="" current_mtime="" current_ctime="" remainder=""

    _patch_network_service_stat_into "$PATCH_NETWORK_SERVICE_CONFIG_PHYSICAL_PATH" current_metadata || return 2
    IFS=: read -r current_device current_inode current_uid current_gid current_mode current_links \
        current_size current_mtime current_ctime remainder <<< "$current_metadata"
    [ -z "$remainder" ] && [ "$current_links" = 1 ] || return 2
    printf -v current_mode '%04o' "$((8#$current_mode & 07777))"
    _patch_network_service_sha256_into "$PATCH_NETWORK_SERVICE_CONFIG_PHYSICAL_PATH" current_sha256 || return 2
    if [ "$current_device" = "$PATCH_NETWORK_SERVICE_CONFIG_DEVICE" ] &&
        [ "$current_inode" = "$PATCH_NETWORK_SERVICE_CONFIG_INODE" ] &&
        [ "$current_uid" = "$PATCH_NETWORK_SERVICE_CONFIG_UID" ] &&
        [ "$current_gid" = "$PATCH_NETWORK_SERVICE_CONFIG_GID" ] &&
        [ "$current_mode" = "$PATCH_NETWORK_SERVICE_CONFIG_MODE" ] &&
        [ "$current_size" = "$PATCH_NETWORK_SERVICE_CONFIG_SIZE" ] &&
        [ "$current_mtime" = "$PATCH_NETWORK_SERVICE_CONFIG_MTIME" ] &&
        [ "$current_ctime" = "$PATCH_NETWORK_SERVICE_CONFIG_CTIME" ] &&
        [ "$current_sha256" = "$PATCH_NETWORK_SERVICE_CONFIG_BEFORE_SHA256" ]; then
        printf -v "$destination_name" '%s' before_original
    elif [ "$current_uid" = "$PATCH_NETWORK_SERVICE_CONFIG_UID" ] &&
        [ "$current_gid" = "$PATCH_NETWORK_SERVICE_CONFIG_GID" ] &&
        [ "$current_mode" = "$PATCH_NETWORK_SERVICE_CONFIG_MODE" ] &&
        [ "$current_sha256" = "$PATCH_NETWORK_SERVICE_CONFIG_BEFORE_SHA256" ]; then
        printf -v "$destination_name" '%s' before_restored
    elif [ "$current_uid" = "$PATCH_NETWORK_SERVICE_CONFIG_DESIRED_UID" ] &&
        [ "$current_gid" = "$PATCH_NETWORK_SERVICE_CONFIG_DESIRED_GID" ] &&
        [ "$current_mode" = "$PATCH_NETWORK_SERVICE_CONFIG_DESIRED_MODE" ] &&
        [ "$current_sha256" = "$PATCH_NETWORK_SERVICE_CONFIG_DESIRED_SHA256" ]; then
        printf -v "$destination_name" '%s' after
    else
        printf -v "$destination_name" '%s' drift
    fi
}

_patch_network_service_write_journal() {
    local journal_path="$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/journal.tsv"
    local current_metadata=""
    local current_sha256=""

    [ ! -e "$journal_path" ] && [ ! -L "$journal_path" ] || return 2
    _patch_network_service_stat_into "$PATCH_NETWORK_SERVICE_CONFIG_PHYSICAL_PATH" current_metadata || return 2
    _patch_network_service_sha256_into "$PATCH_NETWORK_SERVICE_CONFIG_PHYSICAL_PATH" current_sha256 || return 2
    {
        printf 'schema\tdevice\tinode\tuid\tgid\tmode\tlinks\tsize\tmtime\tctime\tsha256\n'
        printf '1\t%s\t%s\n' "${current_metadata//:/$'\t'}" "$current_sha256"
    } > "$journal_path" || return 2
    chmod 0600 "$journal_path"
}

_patch_network_service_journal_matches_current() {
    local journal_path="$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/journal.tsv"
    local header=""
    local record=""
    local current_metadata=""
    local current_sha256=""
    local schema="" device="" inode="" uid="" gid="" mode="" links="" size="" mtime="" ctime="" sha256="" extra=""

    [ -f "$journal_path" ] && [ ! -L "$journal_path" ] || return 2
    IFS= read -r header < "$journal_path" || return 2
    [ "$header" = $'schema\tdevice\tinode\tuid\tgid\tmode\tlinks\tsize\tmtime\tctime\tsha256' ] || return 2
    record="$(sed -n '2p' "$journal_path")" || return 2
    [ "$(wc -l < "$journal_path" | tr -d '[:space:]')" = 2 ] || return 2
    IFS=$'\t' read -r schema device inode uid gid mode links size mtime ctime sha256 extra <<< "$record"
    [ -z "$extra" ] && [ "$schema" = 1 ] || return 2
    case "$device:$inode:$uid:$gid:$mode:$links:$size:$mtime:$ctime" in *[!0-9:]*) return 2 ;; esac
    [ "${#sha256}" -eq 64 ] || return 2
    case "$sha256" in *[!0-9a-f]*) return 2 ;; esac
    _patch_network_service_stat_into "$PATCH_NETWORK_SERVICE_CONFIG_PHYSICAL_PATH" current_metadata || return 2
    _patch_network_service_sha256_into "$PATCH_NETWORK_SERVICE_CONFIG_PHYSICAL_PATH" current_sha256 || return 2
    [ "$current_metadata" = "$device:$inode:$uid:$gid:$mode:$links:$size:$mtime:$ctime" ] &&
        [ "$current_sha256" = "$sha256" ]
}

_patch_network_service_replace_target() {
    local source_path="$1"
    local uid="$2"
    local gid="$3"
    local mode="$4"
    local parent_path="${PATCH_NETWORK_SERVICE_CONFIG_PHYSICAL_PATH%/*}"
    local temporary_path=""
    local mktemp_command=""
    local cp_command=""
    local chown_command=""
    local mv_command=""

    _patch_network_service_command_into mktemp mktemp_command || return 2
    _patch_network_service_command_into cp cp_command || return 2
    _patch_network_service_command_into chown chown_command || return 2
    _patch_network_service_command_into mv mv_command || return 2
    temporary_path="$("$mktemp_command" "$parent_path/.kisa-cce-network-service.XXXXXXXX")" || return 2
    "$cp_command" -- "$source_path" "$temporary_path" || return 2
    "$chown_command" "$uid:$gid" "$temporary_path" || return 2
    chmod "$mode" "$temporary_path" || return 2
    "$mv_command" -f -- "$temporary_path" "$PATCH_NETWORK_SERVICE_CONFIG_PHYSICAL_PATH"
}

_patch_network_service_apply_target() {
    local chown_command=""

    case "$PATCH_NETWORK_SERVICE_TARGET_KIND" in
        config)
            _patch_network_service_replace_target "$PATCH_NETWORK_SERVICE_CONFIG_PAYLOAD" \
                "$PATCH_NETWORK_SERVICE_CONFIG_DESIRED_UID" "$PATCH_NETWORK_SERVICE_CONFIG_DESIRED_GID" \
                "$PATCH_NETWORK_SERVICE_CONFIG_DESIRED_MODE" || return 2
            ;;
        metadata)
            _patch_network_service_command_into chown chown_command || return 2
            "$chown_command" "$PATCH_NETWORK_SERVICE_CONFIG_DESIRED_UID:$PATCH_NETWORK_SERVICE_CONFIG_DESIRED_GID" \
                "$PATCH_NETWORK_SERVICE_CONFIG_PHYSICAL_PATH" || return 2
            chmod "$PATCH_NETWORK_SERVICE_CONFIG_DESIRED_MODE" "$PATCH_NETWORK_SERVICE_CONFIG_PHYSICAL_PATH" || return 2
            ;;
        none) return 0 ;;
        *) return 2 ;;
    esac
    _patch_network_service_write_journal
}

_patch_network_service_restore_target() {
    local rm_command=""

    case "$PATCH_NETWORK_SERVICE_TARGET_KIND" in
        config)
            _patch_network_service_replace_target "$PATCH_NETWORK_SERVICE_CONFIG_BACKUP" \
                "$PATCH_NETWORK_SERVICE_CONFIG_UID" "$PATCH_NETWORK_SERVICE_CONFIG_GID" \
                "$PATCH_NETWORK_SERVICE_CONFIG_MODE"
            ;;
        metadata)
            chown "$PATCH_NETWORK_SERVICE_CONFIG_UID:$PATCH_NETWORK_SERVICE_CONFIG_GID" \
                "$PATCH_NETWORK_SERVICE_CONFIG_PHYSICAL_PATH" &&
                chmod "$PATCH_NETWORK_SERVICE_CONFIG_MODE" "$PATCH_NETWORK_SERVICE_CONFIG_PHYSICAL_PATH"
            ;;
        none) return 0 ;;
        *)
            _patch_network_service_command_into rm rm_command || return 2
            return 2
            ;;
    esac
}

patch_network_service_verify() {
    local current_side=""

    [ "$PATCH_NETWORK_SERVICE_PLAN_VALID" -eq 1 ] || return 2
    if [ "$PATCH_NETWORK_SERVICE_MODE" = disabled ]; then
        _patch_network_service_delegate_action verify || return 2
    else
        if [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = config ] || [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = metadata ]; then
            _patch_network_service_target_current_into current_side || return 2
            [ "$current_side" = after ] && _patch_network_service_journal_matches_current || return 2
        fi
        _patch_network_service_native_validate verify || return 2
        _patch_network_service_runtime_transition verify || return 2
    fi
    PATCH_NETWORK_SERVICE_CRITERION_STATES["$PATCH_NETWORK_SERVICE_CRITERION"]=verified
    _patch_network_service_set_state verified
}

patch_network_service_rollback() {
    local rollback_status=0
    local current_side=""

    [ "$PATCH_NETWORK_SERVICE_APPLY_STARTED" -eq 1 ] || return 2
    _patch_network_service_set_state rollback_in_progress || return 2
    if [ "$PATCH_NETWORK_SERVICE_MODE" = disabled ]; then
        _patch_network_service_delegate_action rollback transition || rollback_status=2
    else
        if [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = config ] || [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = metadata ]; then
            _patch_network_service_target_current_into current_side || rollback_status=2
            if [ "$rollback_status" -eq 0 ]; then
                case "$current_side" in
                    before_original|before_restored) ;;
                    after) _patch_network_service_restore_target || rollback_status=2 ;;
                    *) rollback_status=2 ;;
                esac
            fi
        fi
        if [ "$rollback_status" -eq 0 ]; then
            _patch_network_service_native_validate rollback || rollback_status=2
        fi
        if [ "$rollback_status" -eq 0 ]; then
            _patch_network_service_runtime_transition rollback || rollback_status=2
        fi
    fi
    if [ "$rollback_status" -ne 0 ]; then
        _patch_network_service_set_state rollback_failed >/dev/null 2>&1 || true
        PATCH_NETWORK_SERVICE_ERROR_DETAIL="network service rollback was incomplete"
        return 2
    fi
    PATCH_NETWORK_SERVICE_CRITERION_STATES["$PATCH_NETWORK_SERVICE_CRITERION"]=rolled_back
    _patch_network_service_set_state rolled_back
}

patch_network_service_apply() {
    local apply_status=0
    local current_side=""

    [ "$PATCH_NETWORK_SERVICE_PLAN_VALID" -eq 1 ] || return 2
    [ "${EUID:-$(id -u)}" -eq 0 ] || return 2
    [ "$PATCH_NETWORK_SERVICE_STATE" = planned ] || {
        [ "$PATCH_NETWORK_SERVICE_STATE" = external_action_required ] && return 3
        return 2
    }
    [ -n "$PATCH_NETWORK_SERVICE_ADVISORY_TOKEN" ] || {
        case "$PATCH_NETWORK_SERVICE_CRITERION" in U-45|U-49) return 2 ;; esac
    }
    _patch_network_service_root_identity_current || return 2
    if [ "$PATCH_NETWORK_SERVICE_MODE" = disabled ]; then
        _patch_network_service_callback_is_current service_graph || return 2
    else
        _patch_network_service_callback_is_current native_validator &&
            _patch_network_service_callback_is_current runtime_transition || return 2
        if [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = config ] || [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = metadata ]; then
            _patch_network_service_target_current_into current_side || return 2
            [ "$current_side" = before_original ] || return 2
        fi
        _patch_network_service_native_validate preapply || return 2
    fi
    PATCH_NETWORK_SERVICE_APPLY_STARTED=1
    _patch_network_service_set_state applying || return 2
    if [ "$PATCH_NETWORK_SERVICE_MODE" = disabled ]; then
        _patch_network_service_delegate_action apply || apply_status=2
    else
        _patch_network_service_apply_target || apply_status=2
        [ "$apply_status" -ne 0 ] || _patch_network_service_runtime_transition apply || apply_status=2
    fi
    [ "$apply_status" -ne 0 ] || patch_network_service_verify || apply_status=2
    if [ "$apply_status" -ne 0 ]; then
        patch_network_service_rollback >/dev/null 2>&1 ||
            PATCH_NETWORK_SERVICE_ERROR_DETAIL="network service apply failed and rollback was incomplete"
        return 2
    fi
}

_patch_network_service_artifact_protected() {
    local path="$1"
    local expected_mode="$2"
    local metadata=""
    local device="" inode="" uid="" gid="" mode="" links="" size="" mtime="" ctime="" extra=""

    [ -f "$path" ] && [ ! -L "$path" ] || return 2
    _patch_network_service_stat_into "$path" metadata || return 2
    IFS=: read -r device inode uid gid mode links size mtime ctime extra <<< "$metadata"
    [ -z "$extra" ] && [ "$uid" = "${EUID:-$uid}" ] && [ "$mode" = "$expected_mode" ] && [ "$links" = 1 ]
}

_patch_network_service_directory_protected() {
    local path="$1"
    local metadata=""
    local device="" inode="" uid="" gid="" mode="" links="" size="" mtime="" ctime="" extra=""

    [ -d "$path" ] && [ ! -L "$path" ] || return 2
    _patch_network_service_stat_into "$path" metadata || return 2
    IFS=: read -r device inode uid gid mode links size mtime ctime extra <<< "$metadata"
    [ -z "$extra" ] && [ "$uid" = "${EUID:-$uid}" ] && [ "$mode" = 700 ]
}

_patch_network_service_bind_transaction() {
    local requested_directory="$1"
    local canonical_directory=""
    local directory=""

    _patch_network_service_canonical_directory_into "$requested_directory" canonical_directory || return 2
    [ "$canonical_directory" = "$requested_directory" ] || return 2
    PATCH_NETWORK_SERVICE_TRANSACTION_DIRECTORY="$canonical_directory"
    PATCH_NETWORK_SERVICE_DATA_DIRECTORY="$canonical_directory/network-service"
    for directory in "$canonical_directory" "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY" \
        "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/backups" "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/payloads" \
        "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/delegates"; do
        _patch_network_service_directory_protected "$directory" || return 2
    done
}

_patch_network_service_validate_checksums() {
    local checksum_path="$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/checksums.sha256"
    local line=""
    local expected=""
    local relative=""
    local actual=""
    local count=0
    local -A seen=()

    _patch_network_service_artifact_protected "$checksum_path" 600 || return 2
    while IFS= read -r line || [ -n "$line" ]; do
        expected="${line%%  *}"
        relative="${line#*  }"
        [ "$relative" != "$line" ] && [ "${#expected}" -eq 64 ] || return 2
        case "$expected" in *[!0-9a-f]*) return 2 ;; esac
        case "$relative" in manifest.tsv|plan.tsv|policy.tsv|backups/target|payloads/target) ;; *) return 2 ;; esac
        [ "${seen[$relative]+present}" != present ] || return 2
        seen["$relative"]=1
        _patch_network_service_artifact_protected "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/$relative" 600 || return 2
        _patch_network_service_sha256_into "$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/$relative" actual || return 2
        [ "$actual" = "$expected" ] || return 2
        count=$((count + 1))
    done < "$checksum_path"
    [ "${seen[manifest.tsv]+present}" = present ] && [ "${seen[plan.tsv]+present}" = present ] &&
        [ "${seen[policy.tsv]+present}" = present ] || return 2
    case "$count" in 3|5) ;; *) return 2 ;; esac
}

_patch_network_service_validate_policy_artifact() {
    local policy_path="$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/policy.tsv"
    local line=""
    local line_number=0
    local schema="" record_type="" criterion="" provider="" first_value="" second_value="" approval="" extra=""
    local intent_count=0

    _patch_network_service_artifact_protected "$policy_path" 600 || return 2
    while IFS= read -r line || [ -n "$line" ]; do
        line_number=$((line_number + 1))
        if [ "$line_number" -eq 1 ]; then
            [ "$line" = $'schema\trecord_type\tcriterion\tprovider\tfield_1\tfield_2\tapproval' ] || return 2
            continue
        fi
        IFS=$'\t' read -r schema record_type criterion provider first_value second_value approval extra <<< "$line"
        [ -z "$extra" ] && [ "$schema" = 1 ] && [ "$criterion" = "$PATCH_NETWORK_SERVICE_CRITERION" ] || return 2
        _patch_network_service_valid_provider_for_criterion "$criterion" "$provider" || return 2
        _patch_network_service_safe_approval "$approval" || return 2
        case "$record_type" in
            intent) intent_count=$((intent_count + 1)); case "$first_value" in disabled|required) ;; *) return 2 ;; esac ;;
            config|command|nfs-export|rpc-allow|relay-client|tsig-reference|transfer-peer|update-key|advisory) ;;
            *) return 2 ;;
        esac
    done < "$policy_path"
    [ "$line_number" -gt 1 ] && [ "$intent_count" -eq "${#PATCH_NETWORK_SERVICE_INTENT_PROVIDERS[@]}" ]
}

_patch_network_service_load_manifest() {
    local manifest_path="$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/manifest.tsv"
    local line=""
    local line_number=0
    local -a fields=()
    local root_seen=0
    local criterion_seen=0
    local target_seen=0
    local advisory_seen=0
    local callback_kind=""
    local callback_path=""
    local callback_fingerprint=""
    local expected_physical=""
    local parent_path=""
    local backup_sha256=""
    local payload_sha256=""

    _patch_network_service_artifact_protected "$manifest_path" 600 || return 2
    while IFS= read -r line || [ -n "$line" ]; do
        line_number=$((line_number + 1))
        if [ "$line_number" -eq 1 ]; then
            [ "$line" = $'schema\trecord_type\trecord_fields' ] || return 2
            continue
        fi
        IFS=$'\t' read -r -a fields <<< "$line"
        [ "${fields[0]:-}" = 1 ] || return 2
        case "${fields[1]:-}" in
            root)
                [ "${#fields[@]}" -eq 5 ] && [ "$root_seen" -eq 0 ] || return 2
                [ "${fields[2]}" = "$PATCH_NETWORK_SERVICE_ROOT" ] &&
                    [ "${fields[3]}" = "$PATCH_NETWORK_SERVICE_ROOT_DEVICE" ] &&
                    [ "${fields[4]}" = "$PATCH_NETWORK_SERVICE_ROOT_INODE" ] || return 2
                root_seen=1
                ;;
            criterion)
                [ "${#fields[@]}" -eq 6 ] && [ "$criterion_seen" -eq 0 ] || return 2
                _patch_network_service_valid_criterion "${fields[2]}" || return 2
                case "${fields[3]}" in disabled|required) ;; *) return 2 ;; esac
                case "${fields[5]}" in delegated|none|config|metadata) ;; *) return 2 ;; esac
                PATCH_NETWORK_SERVICE_CRITERION="${fields[2]}"
                PATCH_NETWORK_SERVICE_MODE="${fields[3]}"
                PATCH_NETWORK_SERVICE_PROVIDER="${fields[4]}"
                PATCH_NETWORK_SERVICE_TARGET_KIND="${fields[5]}"
                criterion_seen=1
                ;;
            intent)
                [ "${#fields[@]}" -eq 5 ] && [ "$criterion_seen" -eq 1 ] || return 2
                _patch_network_service_valid_provider_for_criterion "$PATCH_NETWORK_SERVICE_CRITERION" "${fields[2]}" || return 2
                [ "${fields[3]}" = "$PATCH_NETWORK_SERVICE_MODE" ] || return 2
                _patch_network_service_safe_approval "${fields[4]}" || return 2
                PATCH_NETWORK_SERVICE_INTENT_CRITERIA+=("$PATCH_NETWORK_SERVICE_CRITERION")
                PATCH_NETWORK_SERVICE_INTENT_PROVIDERS+=("${fields[2]}")
                PATCH_NETWORK_SERVICE_INTENT_MODES+=("${fields[3]}")
                PATCH_NETWORK_SERVICE_INTENT_APPROVAL_LIST+=("${fields[4]}")
                PATCH_NETWORK_SERVICE_INTENTS["$PATCH_NETWORK_SERVICE_CRITERION:${fields[2]}"]="${fields[3]}"
                PATCH_NETWORK_SERVICE_INTENT_APPROVALS["$PATCH_NETWORK_SERVICE_CRITERION:${fields[2]}"]="${fields[4]}"
                ;;
            callback)
                [ "${#fields[@]}" -eq 5 ] || return 2
                callback_kind="${fields[2]}"
                callback_path="${fields[3]}"
                callback_fingerprint="${fields[4]}"
                case "$callback_kind" in policy_verifier|native_validator|runtime_transition|service_graph) ;; *) return 2 ;; esac
                [ "${PATCH_NETWORK_SERVICE_CALLBACKS[$callback_kind]:-}" = "$callback_path" ] &&
                    [ "${PATCH_NETWORK_SERVICE_CALLBACK_FINGERPRINTS[$callback_kind]:-}" = "$callback_fingerprint" ] &&
                    _patch_network_service_callback_is_current "$callback_kind" || return 2
                ;;
            target)
                [ "${#fields[@]}" -eq 18 ] && [ "$target_seen" -eq 0 ] && [ "$criterion_seen" -eq 1 ] || return 2
                case "${fields[2]}" in /*) ;; *) return 2 ;; esac
                [ "${fields[3]}" = present ] && [ "${fields[17]}" = target ] || return 2
                case "${fields[4]}:${fields[5]}:${fields[6]}:${fields[7]}:${fields[8]}:${fields[9]}:${fields[10]}:${fields[11]}:${fields[13]}:${fields[14]}:${fields[15]}" in *[!0-9:]*) return 2 ;; esac
                [ "${#fields[12]}" -eq 64 ] && [ "${#fields[16]}" -eq 64 ] || return 2
                case "${fields[12]}${fields[16]}" in *[!0-9a-f]*) return 2 ;; esac
                PATCH_NETWORK_SERVICE_CONFIG_LOGICAL_PATH="${fields[2]}"
                _patch_network_service_safe_parent_into "${fields[2]}" parent_path || return 2
                expected_physical="$parent_path/${fields[2]##*/}"
                PATCH_NETWORK_SERVICE_CONFIG_PHYSICAL_PATH="$expected_physical"
                PATCH_NETWORK_SERVICE_CONFIG_BEFORE_STATE=present
                PATCH_NETWORK_SERVICE_CONFIG_DEVICE="${fields[4]}"
                PATCH_NETWORK_SERVICE_CONFIG_INODE="${fields[5]}"
                PATCH_NETWORK_SERVICE_CONFIG_UID="${fields[6]}"
                PATCH_NETWORK_SERVICE_CONFIG_GID="${fields[7]}"
                printf -v PATCH_NETWORK_SERVICE_CONFIG_MODE '%04o' "$((8#${fields[8]} & 07777))"
                PATCH_NETWORK_SERVICE_CONFIG_SIZE="${fields[9]}"
                PATCH_NETWORK_SERVICE_CONFIG_MTIME="${fields[10]}"
                PATCH_NETWORK_SERVICE_CONFIG_CTIME="${fields[11]}"
                PATCH_NETWORK_SERVICE_CONFIG_BEFORE_SHA256="${fields[12]}"
                PATCH_NETWORK_SERVICE_CONFIG_DESIRED_UID="${fields[13]}"
                PATCH_NETWORK_SERVICE_CONFIG_DESIRED_GID="${fields[14]}"
                printf -v PATCH_NETWORK_SERVICE_CONFIG_DESIRED_MODE '%04o' "$((8#${fields[15]} & 07777))"
                PATCH_NETWORK_SERVICE_CONFIG_DESIRED_SHA256="${fields[16]}"
                PATCH_NETWORK_SERVICE_CONFIG_BACKUP="$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/backups/target"
                PATCH_NETWORK_SERVICE_CONFIG_PAYLOAD="$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/payloads/target"
                _patch_network_service_sha256_into "$PATCH_NETWORK_SERVICE_CONFIG_BACKUP" backup_sha256 || return 2
                _patch_network_service_sha256_into "$PATCH_NETWORK_SERVICE_CONFIG_PAYLOAD" payload_sha256 || return 2
                [ "$backup_sha256" = "$PATCH_NETWORK_SERVICE_CONFIG_BEFORE_SHA256" ] &&
                    [ "$payload_sha256" = "$PATCH_NETWORK_SERVICE_CONFIG_DESIRED_SHA256" ] || return 2
                target_seen=1
                ;;
            advisory)
                [ "${#fields[@]}" -eq 8 ] && [ "$advisory_seen" -eq 0 ] || return 2
                [ "${fields[2]}" = "$PATCH_NETWORK_SERVICE_CRITERION" ] &&
                    [ "${fields[3]}" = "$PATCH_NETWORK_SERVICE_PROVIDER" ] || return 2
                case "${fields[4]}" in ''|*[!A-Za-z0-9.+:~_-]*) return 2 ;; esac
                case "${fields[5]}" in current|update-required) ;; *) return 2 ;; esac
                _patch_network_service_safe_token "${fields[6]}" && _patch_network_service_safe_approval "${fields[7]}" || return 2
                PATCH_NETWORK_SERVICE_ADVISORY_CRITERION="${fields[2]}"
                PATCH_NETWORK_SERVICE_ADVISORY_PROVIDER="${fields[3]}"
                PATCH_NETWORK_SERVICE_ADVISORY_VERSION="${fields[4]}"
                PATCH_NETWORK_SERVICE_ADVISORY_STATUS="${fields[5]}"
                PATCH_NETWORK_SERVICE_ADVISORY_TOKEN="${fields[6]}"
                PATCH_NETWORK_SERVICE_ADVISORY_APPROVAL="${fields[7]}"
                advisory_seen=1
                ;;
            *) return 2 ;;
        esac
    done < "$manifest_path"
    [ "$root_seen" -eq 1 ] && [ "$criterion_seen" -eq 1 ] &&
        [ "${#PATCH_NETWORK_SERVICE_INTENT_PROVIDERS[@]}" -gt 0 ] || return 2
    case "$PATCH_NETWORK_SERVICE_TARGET_KIND" in
        config|metadata) [ "$target_seen" -eq 1 ] || return 2 ;;
        *) [ "$target_seen" -eq 0 ] || return 2 ;;
    esac
    case "$PATCH_NETWORK_SERVICE_CRITERION" in
        U-45|U-49) [ "$advisory_seen" -eq 1 ] || return 2 ;;
        *) [ "$advisory_seen" -eq 0 ] || return 2 ;;
    esac
}

_patch_network_service_read_state() {
    local state_path="$PATCH_NETWORK_SERVICE_DATA_DIRECTORY/state"
    local loaded_state=""

    _patch_network_service_artifact_protected "$state_path" 600 || return 2
    [ "$(wc -l < "$state_path" | tr -d '[:space:]')" = 1 ] || return 2
    IFS= read -r loaded_state < "$state_path" || return 2
    case "$loaded_state" in planned|external_action_required|applying|verified|rollback_in_progress|rolled_back|rollback_failed) ;; *) return 2 ;; esac
    PATCH_NETWORK_SERVICE_STATE="$loaded_state"
    case "$loaded_state" in
        verified) PATCH_NETWORK_SERVICE_CRITERION_STATES["$PATCH_NETWORK_SERVICE_CRITERION"]=verified ;;
        rolled_back) PATCH_NETWORK_SERVICE_CRITERION_STATES["$PATCH_NETWORK_SERVICE_CRITERION"]=rolled_back ;;
        external_action_required) PATCH_NETWORK_SERVICE_CRITERION_STATES["$PATCH_NETWORK_SERVICE_CRITERION"]=external_action_required ;;
        *)
            if [ "$PATCH_NETWORK_SERVICE_MODE" = disabled ]; then
                PATCH_NETWORK_SERVICE_CRITERION_STATES["$PATCH_NETWORK_SERVICE_CRITERION"]=delegated
            else
                PATCH_NETWORK_SERVICE_CRITERION_STATES["$PATCH_NETWORK_SERVICE_CRITERION"]=ready
            fi
            ;;
    esac
}

patch_network_service_load_transaction() {
    local root="$1"
    local transaction_directory="$2"

    patch_network_service_reset
    patch_network_service_intent_reset
    patch_network_service_input_reset
    _patch_network_service_initialize_root "$root" || return 2
    _patch_network_service_bind_transaction "$transaction_directory" || return 2
    _patch_network_service_validate_checksums || return 2
    _patch_network_service_load_manifest || return 2
    _patch_network_service_validate_policy_artifact || return 2
    _patch_network_service_read_state || return 2
    PATCH_NETWORK_SERVICE_PLAN_VALID=1
    PATCH_NETWORK_SERVICE_TRANSACTION_LOADED=1
}

patch_network_service_rollback_transaction() {
    local root="$1"
    local transaction_directory="$2"
    local rollback_mode="${3:-strict}"
    local current_side=""

    case "$rollback_mode" in strict|transition) ;; *) return 2 ;; esac
    [ "${EUID:-$(id -u)}" -eq 0 ] || return 2
    patch_network_service_load_transaction "$root" "$transaction_directory" || return 2
    case "$PATCH_NETWORK_SERVICE_STATE" in
        planned|external_action_required) return 2 ;;
        verified) ;;
        applying|rollback_in_progress|rollback_failed) [ "$rollback_mode" = transition ] || return 2 ;;
        rolled_back)
            if [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = config ] || [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = metadata ]; then
                _patch_network_service_target_current_into current_side || return 2
                case "$current_side" in before_original|before_restored) ;; *) return 2 ;; esac
            elif [ "$PATCH_NETWORK_SERVICE_MODE" = disabled ]; then
                _patch_network_service_delegate_action rollback-verify || return 2
            fi
            return 0
            ;;
        *) return 2 ;;
    esac
    if [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = config ] || [ "$PATCH_NETWORK_SERVICE_TARGET_KIND" = metadata ]; then
        _patch_network_service_target_current_into current_side || return 2
        case "$PATCH_NETWORK_SERVICE_STATE:$rollback_mode:$current_side" in
            verified:strict:after) _patch_network_service_journal_matches_current || return 2 ;;
            *:transition:after) _patch_network_service_journal_matches_current || return 2 ;;
            *:transition:before_original|*:transition:before_restored) ;;
            *) return 2 ;;
        esac
    fi
    PATCH_NETWORK_SERVICE_APPLY_STARTED=1
    patch_network_service_rollback
}
