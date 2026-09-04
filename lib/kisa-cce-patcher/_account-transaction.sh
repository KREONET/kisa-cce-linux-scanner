# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash
# shellcheck disable=SC2034

# This adapter applies explicitly approved local-account database changes.

PATCH_ACCOUNT_SUPPORTED_CRITERIA=(U-04 U-05 U-07 U-08 U-09 U-10 U-11 U-13 U-32 U-55)
PATCH_ACCOUNT_ROOT=""
PATCH_ACCOUNT_ROOT_DEVICE=""
PATCH_ACCOUNT_ROOT_INODE=""
PATCH_ACCOUNT_TRANSACTION_DIRECTORY=""
PATCH_ACCOUNT_DATA_DIRECTORY=""
PATCH_ACCOUNT_ERROR_DETAIL=""
PATCH_ACCOUNT_PLAN_VALID=0
PATCH_ACCOUNT_APPLY_STARTED=0
PATCH_ACCOUNT_TRANSACTION_LOADED=0
PATCH_ACCOUNT_TRANSACTION_STATE=""
PATCH_ACCOUNT_CHANGE_COUNT=0
PATCH_ACCOUNT_EXTERNAL_ACTION_REQUIRED_COUNT=0
PATCH_ACCOUNT_PLATFORM_FAMILY="unknown"
PATCH_ACCOUNT_PLATFORM_MAJOR="0"
PATCH_ACCOUNT_UID_MINIMUM="1000"

declare -A PATCH_ACCOUNT_EVIDENCE_STATES=()
declare -A PATCH_ACCOUNT_EVIDENCE_IDS=()
declare -A PATCH_ACCOUNT_DECISION_ACTIONS=()
declare -A PATCH_ACCOUNT_DECISION_VALUES=()
declare -A PATCH_ACCOUNT_DECISION_APPROVALS=()
declare -A PATCH_ACCOUNT_CRITERION_STATES=()
declare -A PATCH_ACCOUNT_TARGETS=()

PATCH_ACCOUNT_SELECTED_CRITERIA=()
PATCH_ACCOUNT_DECISION_CRITERIA=()
PATCH_ACCOUNT_DECISION_SUBJECTS=()
PATCH_ACCOUNT_DECISION_ACTION_LIST=()
PATCH_ACCOUNT_DECISION_VALUE_LIST=()
PATCH_ACCOUNT_DECISION_APPROVAL_LIST=()
PATCH_ACCOUNT_FILE_NAMES=()
PATCH_ACCOUNT_FILE_PATHS=()
PATCH_ACCOUNT_FILE_DEVICES=()
PATCH_ACCOUNT_FILE_INODES=()
PATCH_ACCOUNT_FILE_UIDS=()
PATCH_ACCOUNT_FILE_GIDS=()
PATCH_ACCOUNT_FILE_MODES=()
PATCH_ACCOUNT_FILE_SIZES=()
PATCH_ACCOUNT_FILE_MTIMES=()
PATCH_ACCOUNT_FILE_CTIMES=()
PATCH_ACCOUNT_FILE_BEFORE_SHA256S=()
PATCH_ACCOUNT_FILE_DESIRED_SHA256S=()
PATCH_ACCOUNT_FILE_BACKUPS=()
PATCH_ACCOUNT_FILE_PAYLOADS=()
PATCH_ACCOUNT_FILE_APPLIED=()

PATCH_ACCOUNT_LOCK_FDS=()

_patch_account_set_error() {
    PATCH_ACCOUNT_ERROR_DETAIL="$1"
    PATCH_ACCOUNT_PLAN_VALID=0
    return 2
}

_patch_account_valid_criterion() {
    case "$1" in U-04|U-05|U-07|U-08|U-09|U-10|U-11|U-13|U-32|U-55) return 0 ;; *) return 1 ;; esac
}

patch_account_supported_criteria() {
    printf '%s\n' "${PATCH_ACCOUNT_SUPPORTED_CRITERIA[@]}"
}

patch_account_evidence_reset() {
    PATCH_ACCOUNT_EVIDENCE_STATES=()
    PATCH_ACCOUNT_EVIDENCE_IDS=()
}

patch_account_evidence_add() {
    local evidence_kind="$1"
    local state="$2"
    local evidence_id="$3"

    case "$evidence_kind" in nss|processes|filesystem-ownership) ;; *) return 2 ;; esac
    [ "$state" = complete ] || return 2
    case "$evidence_id" in ''|*[!A-Za-z0-9._:+-]*) return 2 ;; esac
    [ "${PATCH_ACCOUNT_EVIDENCE_STATES[$evidence_kind]+present}" != present ] || return 2
    PATCH_ACCOUNT_EVIDENCE_STATES["$evidence_kind"]="$state"
    PATCH_ACCOUNT_EVIDENCE_IDS["$evidence_kind"]="$evidence_id"
}

patch_account_decision_reset() {
    PATCH_ACCOUNT_DECISION_ACTIONS=()
    PATCH_ACCOUNT_DECISION_VALUES=()
    PATCH_ACCOUNT_DECISION_APPROVALS=()
    PATCH_ACCOUNT_DECISION_CRITERIA=()
    PATCH_ACCOUNT_DECISION_SUBJECTS=()
    PATCH_ACCOUNT_DECISION_ACTION_LIST=()
    PATCH_ACCOUNT_DECISION_VALUE_LIST=()
    PATCH_ACCOUNT_DECISION_APPROVAL_LIST=()
}

_patch_account_action_allowed() {
    local criterion="$1"
    local action="$2"

    case "$criterion:$action" in
        U-04:lock-account|U-04:credential-reset|U-05:set-uid|U-05:delete-account|\
        U-07:keep|U-07:disable-login|U-07:delete-account|\
        U-08:keep|U-08:remove-root-membership|U-08:set-primary-gid|\
        U-09:keep|U-09:delete-group|U-09:set-group-gid|\
        U-10:set-uid|U-10:delete-account|U-11:set-shell|\
        U-13:credential-reset|U-32:set-home|U-32:create-home|U-32:disable-login|\
        U-55:set-shell) return 0 ;;
        *) return 1 ;;
    esac
}

_patch_account_validate_action_value() {
    local action="$1"
    local value="$2"

    case "$action" in
        keep|lock-account|credential-reset|delete-account|remove-root-membership|delete-group)
            [ "$value" = - ]
            ;;
        set-uid|set-primary-gid|set-group-gid)
            case "$value" in ''|*[!0-9]*) return 1 ;; esac
            [ "$value" -ge 0 ] && [ "$value" -lt 4294967295 ]
            ;;
        set-shell|disable-login)
            case "$value" in /bin/false|/usr/bin/false|/sbin/nologin|/usr/sbin/nologin|/bin/nologin) return 0 ;; *) return 1 ;; esac
            ;;
        set-home|create-home)
            case "$value" in /*) ;; *) return 1 ;; esac
            case "$value" in *$'\t'*|*$'\n'*|*$'\r'*|*/../*|*/..|*/./*|*/.) return 1 ;; esac
            ;;
        *) return 1 ;;
    esac
}

patch_account_decision_add() {
    local criterion="$1"
    local subject="$2"
    local action="$3"
    local value="$4"
    local approval_id="$5"
    local key="$criterion:$subject"

    _patch_account_valid_criterion "$criterion" || return 1
    case "$subject" in ''|*[!A-Za-z0-9_.@+-]*) return 2 ;; esac
    _patch_account_action_allowed "$criterion" "$action" || return 2
    _patch_account_validate_action_value "$action" "$value" || return 2
    case "$approval_id" in ''|*[!A-Za-z0-9._:+-]*) return 2 ;; esac
    [ "${PATCH_ACCOUNT_DECISION_ACTIONS[$key]+present}" != present ] || return 2
    PATCH_ACCOUNT_DECISION_ACTIONS["$key"]="$action"
    PATCH_ACCOUNT_DECISION_VALUES["$key"]="$value"
    PATCH_ACCOUNT_DECISION_APPROVALS["$key"]="$approval_id"
    PATCH_ACCOUNT_DECISION_CRITERIA+=("$criterion")
    PATCH_ACCOUNT_DECISION_SUBJECTS+=("$subject")
    PATCH_ACCOUNT_DECISION_ACTION_LIST+=("$action")
    PATCH_ACCOUNT_DECISION_VALUE_LIST+=("$value")
    PATCH_ACCOUNT_DECISION_APPROVAL_LIST+=("$approval_id")
}

patch_account_reset() {
    PATCH_ACCOUNT_ROOT=""
    PATCH_ACCOUNT_ROOT_DEVICE=""
    PATCH_ACCOUNT_ROOT_INODE=""
    PATCH_ACCOUNT_TRANSACTION_DIRECTORY=""
    PATCH_ACCOUNT_DATA_DIRECTORY=""
    PATCH_ACCOUNT_ERROR_DETAIL=""
    PATCH_ACCOUNT_PLAN_VALID=0
    PATCH_ACCOUNT_APPLY_STARTED=0
    PATCH_ACCOUNT_TRANSACTION_LOADED=0
    PATCH_ACCOUNT_TRANSACTION_STATE=""
    PATCH_ACCOUNT_CHANGE_COUNT=0
    PATCH_ACCOUNT_EXTERNAL_ACTION_REQUIRED_COUNT=0
    PATCH_ACCOUNT_PLATFORM_FAMILY="unknown"
    PATCH_ACCOUNT_PLATFORM_MAJOR="0"
    PATCH_ACCOUNT_UID_MINIMUM="1000"
    PATCH_ACCOUNT_CRITERION_STATES=()
    PATCH_ACCOUNT_TARGETS=()
    PATCH_ACCOUNT_SELECTED_CRITERIA=()
    PATCH_ACCOUNT_FILE_NAMES=()
    PATCH_ACCOUNT_FILE_PATHS=()
    PATCH_ACCOUNT_FILE_DEVICES=()
    PATCH_ACCOUNT_FILE_INODES=()
    PATCH_ACCOUNT_FILE_UIDS=()
    PATCH_ACCOUNT_FILE_GIDS=()
    PATCH_ACCOUNT_FILE_MODES=()
    PATCH_ACCOUNT_FILE_SIZES=()
    PATCH_ACCOUNT_FILE_MTIMES=()
    PATCH_ACCOUNT_FILE_CTIMES=()
    PATCH_ACCOUNT_FILE_BEFORE_SHA256S=()
    PATCH_ACCOUNT_FILE_DESIRED_SHA256S=()
    PATCH_ACCOUNT_FILE_BACKUPS=()
    PATCH_ACCOUNT_FILE_PAYLOADS=()
    PATCH_ACCOUNT_FILE_APPLIED=()
    PATCH_ACCOUNT_LOCK_FDS=()
}

patch_account_state_into() {
    local criterion="$1"
    local destination_name="$2"

    [ "${PATCH_ACCOUNT_CRITERION_STATES[$criterion]+present}" = present ] || return 1
    printf -v "$destination_name" '%s' "${PATCH_ACCOUNT_CRITERION_STATES[$criterion]}"
}

_patch_account_command_into() {
    local command_name="$1"
    local destination_name="$2"
    local candidate=""
    local metadata=""
    local owner_uid=""
    local mode=""

    case "$command_name" in
        awk) candidate=/usr/bin/awk ;;
        chmod) candidate=/bin/chmod ;;
        chown) candidate=/usr/bin/chown; [ -x "$candidate" ] || candidate=/bin/chown ;;
        cp) candidate=/usr/bin/cp; [ -x "$candidate" ] || candidate=/bin/cp ;;
        flock) candidate=/usr/bin/flock; [ -x "$candidate" ] || candidate=/bin/flock ;;
        mkdir) candidate=/bin/mkdir; [ -x "$candidate" ] || candidate=/usr/bin/mkdir ;;
        mktemp) candidate=/usr/bin/mktemp; [ -x "$candidate" ] || candidate=/bin/mktemp ;;
        mv) candidate=/bin/mv; [ -x "$candidate" ] || candidate=/usr/bin/mv ;;
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

_patch_account_stat_into() {
    local path="$1"
    local destination_name="$2"
    local stat_command=""
    local output=""

    _patch_account_command_into stat stat_command || return $?
    if output="$($stat_command -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' -- "$path" 2>/dev/null)"; then :
    elif output="$($stat_command -f '%d:%i:%u:%g:%Lp:%l:%z:%m:%c' "$path" 2>/dev/null)"; then :
    else return 2
    fi
    case "$output" in *[!0-9:]*) return 2 ;; esac
    printf -v "$destination_name" '%s' "$output"
}

_patch_account_sha256_into() {
    local path="$1"
    local destination_name="$2"
    local command_path=""
    local output=""
    local hash_digest=""

    _patch_account_command_into sha256sum command_path || return $?
    case "$command_path" in
        */shasum) output="$($command_path -a 256 -- "$path" 2>/dev/null)" || return 2 ;;
        *) output="$($command_path -- "$path" 2>/dev/null)" || return 2 ;;
    esac
    hash_digest="${output%% *}"
    [ "${#hash_digest}" -eq 64 ] || return 2
    case "$hash_digest" in *[!0-9a-f]*) return 2 ;; esac
    printf -v "$destination_name" '%s' "$hash_digest"
}

_patch_account_canonical_directory_into() {
    local path="$1"
    local destination_name="$2"
    local resolved=""

    [ -d "$path" ] && [ ! -L "$path" ] || return 2
    resolved="$(CDPATH='' builtin cd -P -- "$path" 2>/dev/null && pwd -P)" || return 2
    printf -v "$destination_name" '%s' "$resolved"
}

_patch_account_initialize_root() {
    local requested_root="$1"
    local canonical=""
    local metadata=""

    case "$requested_root" in *$'\t'*|*$'\n'*|*$'\r'*) return 2 ;; esac
    _patch_account_canonical_directory_into "$requested_root" canonical || return 2
    _patch_account_stat_into "$canonical" metadata || return 2
    PATCH_ACCOUNT_ROOT="$canonical"
    PATCH_ACCOUNT_ROOT_DEVICE="${metadata%%:*}"
    metadata="${metadata#*:}"
    PATCH_ACCOUNT_ROOT_INODE="${metadata%%:*}"
}

_patch_account_root_path_into() {
    local logical_path="$1"
    local destination_name="$2"

    case "$logical_path" in /*) ;; *) return 2 ;; esac
    if [ "$PATCH_ACCOUNT_ROOT" = / ]; then
        printf -v "$destination_name" '%s' "$logical_path"
    else
        printf -v "$destination_name" '%s' "${PATCH_ACCOUNT_ROOT%/}$logical_path"
    fi
}

_patch_account_selected() {
    local requested_criterion="$1"
    local selected_criterion=""

    for selected_criterion in "${PATCH_ACCOUNT_SELECTED_CRITERIA[@]}"; do
        [ "$selected_criterion" = "$requested_criterion" ] && return 0
    done
    return 1
}

_patch_account_safe_input_file_into() {
    local logical_path="$1"
    local destination_name="$2"
    local physical_path=""
    local parent_path=""
    local canonical_parent=""
    local candidate_path=""
    local metadata=""
    local remaining=""
    local link_count=""

    _patch_account_root_path_into "$logical_path" physical_path || return 2
    [ -e "$physical_path" ] || [ -L "$physical_path" ] || return 1
    [ -f "$physical_path" ] && [ ! -L "$physical_path" ] && [ -r "$physical_path" ] || return 2
    parent_path="${physical_path%/*}"
    _patch_account_canonical_directory_into "$parent_path" canonical_parent || return 2
    if [ "$PATCH_ACCOUNT_ROOT" != / ]; then
        case "$canonical_parent/" in "$PATCH_ACCOUNT_ROOT"/*) ;; *) return 2 ;; esac
    fi
    candidate_path="$canonical_parent/${physical_path##*/}"
    [ -f "$candidate_path" ] && [ ! -L "$candidate_path" ] && [ -r "$candidate_path" ] || return 2
    _patch_account_stat_into "$candidate_path" metadata || return 2
    remaining="${metadata#*:*:*:*:*:}"
    link_count="${remaining%%:*}"
    [ "$link_count" = 1 ] || return 2
    printf -v "$destination_name" '%s' "$candidate_path"
}

_patch_account_os_release_file_into() {
    local destination_name="$1"
    local etc_path=""
    local vendor_path=""
    local resolved_path=""
    local status=0

    _patch_account_root_path_into /etc/os-release etc_path || return 2
    if [ -L "$etc_path" ]; then
        _patch_account_safe_input_file_into /usr/lib/os-release vendor_path || return 2
        [ "$etc_path" -ef "$vendor_path" ] || return 2
        printf -v "$destination_name" '%s' "$vendor_path"
        return 0
    fi
    _patch_account_safe_input_file_into /etc/os-release resolved_path || status=$?
    if [ "$status" -eq 0 ]; then
        printf -v "$destination_name" '%s' "$resolved_path"
        return 0
    elif [ "$status" -ne 1 ]; then
        return 2
    fi
    _patch_account_safe_input_file_into /usr/lib/os-release resolved_path || return 2
    printf -v "$destination_name" '%s' "$resolved_path"
}

_patch_account_os_release_value_into() {
    local path="$1"
    local key="$2"
    local destination_name="$3"
    local awk_command=""
    local parsed_value=""

    _patch_account_command_into awk awk_command || return 2
    parsed_value="$($awk_command -F= -v target="$key" '
        $1 == target {
            count++
            value=substr($0, index($0, "=") + 1)
            if (value ~ /^"[^"]*"$/ || value ~ /^\047[^\047]*\047$/) {
                value=substr(value, 2, length(value) - 2)
            }
            result=value
        }
        END {if (count == 1) print result; else exit 1}
    ' "$path")" || return 1
    case "$parsed_value" in *$'\t'*|*$'\n'*|*$'\r'*) return 2 ;; esac
    printf -v "$destination_name" '%s' "$parsed_value"
}

_patch_account_detect_platform() {
    local os_release_file=""
    local platform_id=""
    local id_like=""
    local version_id=""
    local version_major=""
    local id_like_status=0

    _patch_account_os_release_file_into os_release_file || return 2
    _patch_account_os_release_value_into "$os_release_file" ID platform_id || return 2
    _patch_account_os_release_value_into "$os_release_file" ID_LIKE id_like || id_like_status=$?
    [ "$id_like_status" -eq 1 ] && id_like=""
    [ "$id_like_status" -ne 2 ] || return 2
    _patch_account_os_release_value_into "$os_release_file" VERSION_ID version_id || return 2
    case "$platform_id" in ''|*[!A-Za-z0-9._-]*) return 2 ;; esac
    case "$id_like" in *[!A-Za-z0-9._[:space:]-]*) return 2 ;; esac
    case "$version_id" in ''|*[!0-9.]*) return 2 ;; esac
    version_major="${version_id%%.*}"
    case "$version_major" in ''|*[!0-9]*) return 2 ;; esac
    case "$platform_id" in
        debian|ubuntu) PATCH_ACCOUNT_PLATFORM_FAMILY=debian ;;
        rhel|almalinux|rocky|ol|centos) PATCH_ACCOUNT_PLATFORM_FAMILY=rhel ;;
        *)
            case " $id_like " in
                *" debian "*) PATCH_ACCOUNT_PLATFORM_FAMILY=debian ;;
                *" rhel "*) PATCH_ACCOUNT_PLATFORM_FAMILY=rhel ;;
                *) return 2 ;;
            esac
            ;;
    esac
    PATCH_ACCOUNT_PLATFORM_MAJOR="$version_major"
}

_patch_account_login_defs_file_value_into() {
    local path="$1"
    local duplicate_mode="$2"
    local comment_mode="$3"
    local destination_name="$4"
    local awk_command=""
    local extracted_value=""

    _patch_account_command_into awk awk_command || return 2
    extracted_value="$($awk_command -v duplicate_mode="$duplicate_mode" -v comment_mode="$comment_mode" '
        {
            raw=$0
            sub(/^[[:space:]]+/, "", raw)
            if (raw == "" || raw ~ /^#/) next
            if (comment_mode == "econf") sub(/[[:space:]]*#.*/, "", raw)
            name=raw
            sub(/[[:space:]].*$/, "", name)
            if (name != "UID_MIN") next
            value=substr(raw, length(name) + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (duplicate_mode == "first") {print value; found=1; exit}
            result=value
            found=1
        }
        END {if (duplicate_mode != "first" && found) print result; else if (!found) exit 1}
    ' "$path")" || return 1
    case "$extracted_value" in *$'\t'*|*$'\n'*|*$'\r'*) return 2 ;; esac
    printf -v "$destination_name" '%s' "$extracted_value"
}

_patch_account_resolve_uid_minimum_into() {
    local destination_name="$1"
    local main_file=""
    local main_status=0
    local parsed_value=""
    local parsed_status=0
    local selected_value=""
    local predecessor_present=0
    local dropin_directory=""
    local canonical_dropin_directory=""
    local dropin_path=""
    local resolved_dropin=""
    local LC_ALL=C

    _patch_account_safe_input_file_into /etc/login.defs main_file || main_status=$?
    [ "$main_status" -ne 2 ] || return 2
    if [ "$main_status" -eq 0 ]; then
        if [ "$PATCH_ACCOUNT_PLATFORM_FAMILY" = rhel ] && [ "$PATCH_ACCOUNT_PLATFORM_MAJOR" -ge 10 ]; then
            _patch_account_login_defs_file_value_into "$main_file" first econf parsed_value || parsed_status=$?
        else
            _patch_account_login_defs_file_value_into "$main_file" last legacy parsed_value || parsed_status=$?
        fi
        [ "$parsed_status" -ne 2 ] || return 2
        if [ "$parsed_status" -eq 0 ]; then
            selected_value="$parsed_value"
        fi
        predecessor_present=1
    fi
    if [ "$PATCH_ACCOUNT_PLATFORM_FAMILY" = rhel ] && [ "$PATCH_ACCOUNT_PLATFORM_MAJOR" -ge 10 ]; then
        _patch_account_root_path_into /etc/login.defs.d dropin_directory || return 2
        if [ -e "$dropin_directory" ] || [ -L "$dropin_directory" ]; then
            _patch_account_canonical_directory_into "$dropin_directory" canonical_dropin_directory || return 2
            if [ "$PATCH_ACCOUNT_ROOT" != / ]; then
                case "$canonical_dropin_directory/" in "$PATCH_ACCOUNT_ROOT"/*) ;; *) return 2 ;; esac
            fi
            for dropin_path in "$canonical_dropin_directory"/*.defs; do
                [ -e "$dropin_path" ] || [ -L "$dropin_path" ] || continue
                if [ -L "$dropin_path" ]; then
                    [ "$dropin_path" -ef /dev/null ] && continue
                    return 2
                fi
                _patch_account_safe_input_file_into "/etc/login.defs.d/${dropin_path##*/}" resolved_dropin || return 2
                parsed_status=0
                if [ "$predecessor_present" -eq 1 ]; then
                    _patch_account_login_defs_file_value_into "$resolved_dropin" last econf parsed_value || parsed_status=$?
                else
                    _patch_account_login_defs_file_value_into "$resolved_dropin" first econf parsed_value || parsed_status=$?
                fi
                [ "$parsed_status" -ne 2 ] || return 2
                if [ "$parsed_status" -eq 0 ]; then
                    selected_value="$parsed_value"
                fi
                predecessor_present=1
            done
        fi
    fi
    [ -n "$selected_value" ] || selected_value=1000
    case "$selected_value" in ''|*[!0-9]*) return 2 ;; esac
    [ "$selected_value" -lt 4294967295 ] || return 2
    printf -v "$destination_name" '%s' "$selected_value"
}

_patch_account_resolve_policy_context() {
    local resolved_uid_minimum="1000"

    PATCH_ACCOUNT_PLATFORM_FAMILY=unknown
    PATCH_ACCOUNT_PLATFORM_MAJOR=0
    PATCH_ACCOUNT_UID_MINIMUM=1000
    if _patch_account_selected U-07 || _patch_account_selected U-11 ||
        _patch_account_selected U-13 || _patch_account_selected U-32; then
        _patch_account_detect_platform || return 2
    fi
    if _patch_account_selected U-07 || _patch_account_selected U-11 || _patch_account_selected U-32; then
        _patch_account_resolve_uid_minimum_into resolved_uid_minimum || return 2
        PATCH_ACCOUNT_UID_MINIMUM="$resolved_uid_minimum"
    fi
}

_patch_account_revalidate_policy_context() {
    local expected_family="$PATCH_ACCOUNT_PLATFORM_FAMILY"
    local expected_major="$PATCH_ACCOUNT_PLATFORM_MAJOR"
    local expected_uid_minimum="$PATCH_ACCOUNT_UID_MINIMUM"

    _patch_account_resolve_policy_context || return 2
    [ "$PATCH_ACCOUNT_PLATFORM_FAMILY" = "$expected_family" ] &&
        [ "$PATCH_ACCOUNT_PLATFORM_MAJOR" = "$expected_major" ] &&
        [ "$PATCH_ACCOUNT_UID_MINIMUM" = "$expected_uid_minimum" ]
}

_patch_account_yescrypt_supported() {
    [ "$PATCH_ACCOUNT_PLATFORM_FAMILY" = debian ] ||
        { [ "$PATCH_ACCOUNT_PLATFORM_FAMILY" = rhel ] && [ "$PATCH_ACCOUNT_PLATFORM_MAJOR" -ge 10 ]; }
}

_patch_account_file_metadata_into() {
    local path="$1"
    local prefix="$2"
    local metadata=""
    local value=""

    _patch_account_stat_into "$path" metadata || return 2
    value="${metadata%%:*}"; printf -v "${prefix}_device" '%s' "$value"; metadata="${metadata#*:}"
    value="${metadata%%:*}"; printf -v "${prefix}_inode" '%s' "$value"; metadata="${metadata#*:}"
    value="${metadata%%:*}"; printf -v "${prefix}_uid" '%s' "$value"; metadata="${metadata#*:}"
    value="${metadata%%:*}"; printf -v "${prefix}_gid" '%s' "$value"; metadata="${metadata#*:}"
    value="${metadata%%:*}"; printf -v "${prefix}_mode" '%04o' "$((8#$value & 07777))"; metadata="${metadata#*:}"
    value="${metadata%%:*}"; [ "$value" = 1 ] || return 2; metadata="${metadata#*:}"
    value="${metadata%%:*}"; printf -v "${prefix}_size" '%s' "$value"; metadata="${metadata#*:}"
    value="${metadata%%:*}"; printf -v "${prefix}_mtime" '%s' "$value"; metadata="${metadata#*:}"
    printf -v "${prefix}_ctime" '%s' "${metadata%%:*}"
}

_patch_account_prepare_transaction() {
    local requested="$1"
    local canonical=""
    local metadata=""
    local owner_uid=""
    local mode=""
    local mkdir_command=""

    _patch_account_canonical_directory_into "$requested" canonical || return 2
    [ "$canonical" = "$requested" ] || return 2
    _patch_account_stat_into "$canonical" metadata || return 2
    metadata="${metadata#*:*:}"
    owner_uid="${metadata%%:*}"; metadata="${metadata#*:}"
    metadata="${metadata#*:}"
    mode="${metadata%%:*}"
    [ "$owner_uid" = "${EUID:-$owner_uid}" ] && [ "$mode" = 700 ] || return 2
    PATCH_ACCOUNT_TRANSACTION_DIRECTORY="$canonical"
    PATCH_ACCOUNT_DATA_DIRECTORY="$canonical/account"
    [ ! -e "$PATCH_ACCOUNT_DATA_DIRECTORY" ] && [ ! -L "$PATCH_ACCOUNT_DATA_DIRECTORY" ] || return 2
    _patch_account_command_into mkdir mkdir_command || return 2
    "$mkdir_command" -m 0700 -- "$PATCH_ACCOUNT_DATA_DIRECTORY" || return 2
    "$mkdir_command" -m 0700 -- "$PATCH_ACCOUNT_DATA_DIRECTORY/backups" "$PATCH_ACCOUNT_DATA_DIRECTORY/payloads" || return 2
}

_patch_account_snapshot_database_file() {
    local name="$1"
    local required="$2"
    local path=""
    local index="${#PATCH_ACCOUNT_FILE_NAMES[@]}"
    local before_device="" before_inode="" before_uid="" before_gid="" before_mode=""
    local before_size="" before_mtime="" before_ctime="" before_sha256=""
    local backup="$PATCH_ACCOUNT_DATA_DIRECTORY/backups/$name"
    local payload="$PATCH_ACCOUNT_DATA_DIRECTORY/payloads/$name"
    local cp_command=""
    local chmod_command=""

    _patch_account_root_path_into "/etc/$name" path || return 2
    if [ ! -e "$path" ]; then
        [ "$required" = optional ] && return 0
        return 2
    fi
    [ -f "$path" ] && [ ! -L "$path" ] || return 2
    _patch_account_file_metadata_into "$path" before || return 2
    _patch_account_sha256_into "$path" before_sha256 || return 2
    _patch_account_command_into cp cp_command || return 2
    _patch_account_command_into chmod chmod_command || return 2
    "$cp_command" -- "$path" "$backup" || return 2
    "$cp_command" -- "$path" "$payload" || return 2
    "$chmod_command" 0600 "$backup" "$payload" || return 2
    PATCH_ACCOUNT_FILE_NAMES+=("$name")
    PATCH_ACCOUNT_FILE_PATHS+=("$path")
    PATCH_ACCOUNT_FILE_DEVICES+=("$before_device")
    PATCH_ACCOUNT_FILE_INODES+=("$before_inode")
    PATCH_ACCOUNT_FILE_UIDS+=("$before_uid")
    PATCH_ACCOUNT_FILE_GIDS+=("$before_gid")
    PATCH_ACCOUNT_FILE_MODES+=("$before_mode")
    PATCH_ACCOUNT_FILE_SIZES+=("$before_size")
    PATCH_ACCOUNT_FILE_MTIMES+=("$before_mtime")
    PATCH_ACCOUNT_FILE_CTIMES+=("$before_ctime")
    PATCH_ACCOUNT_FILE_BEFORE_SHA256S+=("$before_sha256")
    PATCH_ACCOUNT_FILE_DESIRED_SHA256S+=("$before_sha256")
    PATCH_ACCOUNT_FILE_BACKUPS+=("$backup")
    PATCH_ACCOUNT_FILE_PAYLOADS+=("$payload")
    PATCH_ACCOUNT_FILE_APPLIED+=(0)
}

_patch_account_payload_path() {
    local name="$1"
    local index=0

    while [ "$index" -lt "${#PATCH_ACCOUNT_FILE_NAMES[@]}" ]; do
        [ "${PATCH_ACCOUNT_FILE_NAMES[$index]}" = "$name" ] && {
            printf '%s\n' "${PATCH_ACCOUNT_FILE_PAYLOADS[$index]}"
            return 0
        }
        index=$((index + 1))
    done
    return 1
}

_patch_account_validate_databases() {
    local passwd_file=""
    local shadow_file=""
    local group_file=""
    local gshadow_file=""

    passwd_file="$(_patch_account_payload_path passwd)" || return 2
    group_file="$(_patch_account_payload_path group)" || return 2
    shadow_file="$(_patch_account_payload_path shadow 2>/dev/null || true)"
    gshadow_file="$(_patch_account_payload_path gshadow 2>/dev/null || true)"
    awk -F: '
        NF != 7 || $1 !~ /^[A-Za-z_][A-Za-z0-9_.-]*[$]?$/ || $3 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/ {exit 1}
        seen[$1]++ {exit 1}
        $1 == "root" {root++; if ($3 != 0) exit 1}
        END {exit(root == 1 ? 0 : 1)}
    ' "$passwd_file" || return 2
    awk -F: '
        NF != 4 || $1 !~ /^[A-Za-z_][A-Za-z0-9_.-]*[$]?$/ || $3 !~ /^[0-9]+$/ {exit 1}
        seen[$1]++ {exit 1}
        END {exit(NR > 0 ? 0 : 1)}
    ' "$group_file" || return 2
    if [ -n "$shadow_file" ]; then
        awk -F: 'NF != 9 || $1 !~ /^[A-Za-z_][A-Za-z0-9_.-]*[$]?$/ || seen[$1]++ {exit 1}' "$shadow_file" || return 2
    fi
    if [ -n "$gshadow_file" ]; then
        awk -F: 'NF != 4 || $1 !~ /^[A-Za-z_][A-Za-z0-9_.-]*[$]?$/ || seen[$1]++ {exit 1}' "$gshadow_file" || return 2
    fi
}

_patch_account_validate_evidence() {
    local kind=""
    local nsswitch=""
    local line=""
    local database=""
    local sources=""
    local source=""

    for kind in nss processes filesystem-ownership; do
        [ "${PATCH_ACCOUNT_EVIDENCE_STATES[$kind]:-}" = complete ] || return 2
    done
    _patch_account_root_path_into /etc/nsswitch.conf nsswitch || return 2
    [ -r "$nsswitch" ] || return 2
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%%#*}"
        case "$line" in passwd:*|group:*) ;; *) continue ;; esac
        database="${line%%:*}"
        sources="${line#*:}"
        [ "$database" = passwd ] || [ "$database" = group ] || continue
        for source in $sources; do
            [ "$source" = files ] || return 2
        done
    done < "$nsswitch"
}

_patch_account_collect_targets() {
    local output_path="$PATCH_ACCOUNT_DATA_DIRECTORY/targets.tsv"
    local passwd_file=""
    local shadow_file=""
    local group_file=""
    local criterion=""
    local account_name=""
    local account_uid=""
    local account_home=""
    local account_shell=""
    local physical_home=""
    local uid_minimum="$PATCH_ACCOUNT_UID_MINIMUM"
    local yescrypt_supported=0

    _patch_account_yescrypt_supported && yescrypt_supported=1

    passwd_file="$(_patch_account_payload_path passwd)" || return 2
    group_file="$(_patch_account_payload_path group)" || return 2
    shadow_file="$(_patch_account_payload_path shadow 2>/dev/null || true)"
    : > "$output_path" || return 2
    for criterion in "${PATCH_ACCOUNT_SELECTED_CRITERIA[@]}"; do
        case "$criterion" in
            U-04)
                awk -F: '$2 != "x" && $2 !~ /^[!*]+$/ && $2 !~ /^\$(1|2|5|6|y|gy)\$/ {print "U-04\t" $1}' "$passwd_file" >> "$output_path"
                ;;
            U-05)
                awk -F: '$1 == "root" && $3 != 0 {print "U-05\troot"} $1 != "root" && $3 == 0 {print "U-05\t" $1}' "$passwd_file" >> "$output_path"
                ;;
            U-07)
                awk -F: -v uid_minimum="$uid_minimum" '
                    function nonlogin(shell) {return shell ~ /\/(false|nologin)$/}
                    $1 != "root" && (($3 == 0) || ($3 >= uid_minimum && $3 < 65534)) && !nonlogin($7) {print "U-07\t" $1}
                ' "$passwd_file" >> "$output_path"
                ;;
            U-08)
                awk -F: '
                    NR == FNR {if ($1 == "root") root_gid=$3; primary[$1]=$4; next}
                    $1 == "root" {count=split($4,members,","); for(i=1;i<=count;i++) if(members[i]!="" && members[i]!="root") seen[members[i]]=1}
                    END {for(name in primary) if(name!="root" && primary[name]==root_gid) seen[name]=1; for(name in seen) print "U-08\t" name}
                ' "$passwd_file" "$group_file" >> "$output_path"
                ;;
            U-09)
                awk -F: '
                    NR == FNR {used[$4]=1; account[$1]=1; next}
                    {in_use=used[$3]; count=split($4,members,","); for(i=1;i<=count;i++) if(members[i] in account) in_use=1; if(!in_use) print "U-09\t" $1}
                ' "$passwd_file" "$group_file" >> "$output_path"
                ;;
            U-10)
                awk -F: '{count[$3]++; names[$3]=names[$3] " " $1} END {for(uid in count) if(count[uid]>1) {n=split(names[uid],a," "); for(i=1;i<=n;i++) if(a[i]!="") print "U-10\t" a[i]}}' "$passwd_file" >> "$output_path"
                ;;
            U-11)
                awk -F: -v uid_minimum="$uid_minimum" '
                    function nonlogin(shell) {return shell ~ /\/(false|nologin)$/}
                    BEGIN {split("daemon bin sys adm listen nobody nobody4 noaccess diag operator games gopher",a," "); for(i in a) fixed[a[i]]=1}
                    (fixed[$1] || ($3>0 && $3<uid_minimum && $1 !~ /^(sync|shutdown|halt)$/)) && !nonlogin($7) {print "U-11\t" $1}
                ' "$passwd_file" >> "$output_path"
                ;;
            U-13)
                [ -n "$shadow_file" ] || return 2
                awk -F: -v yescrypt_supported="$yescrypt_supported" '
                    {
                        value=$2
                        while(substr(value,1,1)=="!") value=substr(value,2)
                        if(value=="" || value=="*" || value=="!!") next
                        if(value ~ /^\$(5|6)\$/) next
                        if(yescrypt_supported && value ~ /^\$y\$/) next
                        print "U-13\t" $1
                    }
                ' "$shadow_file" >> "$output_path"
                ;;
            U-32)
                while IFS=: read -r account_name _ account_uid _ _ account_home account_shell; do
                    if [ "$account_name" != root ] && { [ "$account_uid" -lt "$uid_minimum" ] || [ "$account_uid" -ge 65534 ]; }; then
                        continue
                    fi
                    case "$account_shell" in */false|*/nologin) continue ;; esac
                    case "$account_home" in /*) ;; *) return 2 ;; esac
                    case "$account_home" in *$'\t'*|*$'\n'*|*$'\r'*|*/../*|*/..|*/./*|*/.) return 2 ;; esac
                    _patch_account_root_path_into "$account_home" physical_home || return 2
                    [ -d "$physical_home" ] || printf 'U-32\t%s\n' "$account_name" >> "$output_path"
                done < "$passwd_file"
                ;;
            U-55)
                awk -F: '$1=="ftp" && $7 !~ /\/(false|nologin)$/ {print "U-55\tftp"}' "$passwd_file" >> "$output_path"
                ;;
        esac
    done
    LC_ALL=C sort -u "$output_path" -o "$output_path" || return 2
    while IFS=$'\t' read -r criterion subject; do
        [ -n "$criterion$subject" ] || continue
        PATCH_ACCOUNT_TARGETS["$criterion:$subject"]=1
    done < "$output_path"
    chmod 0600 "$output_path" || return 2
}

_patch_account_action_requires_external_work() {
    case "$1" in credential-reset|set-uid|set-primary-gid|set-group-gid|delete-account|delete-group|create-home) return 0 ;; *) return 1 ;; esac
}

_patch_account_subject_exists() {
    local criterion="$1"
    local subject="$2"
    local passwd_file=""
    local group_file=""

    passwd_file="$(_patch_account_payload_path passwd)" || return 2
    group_file="$(_patch_account_payload_path group)" || return 2
    case "$criterion" in
        U-09) awk -F: -v name="$subject" '$1==name {found=1} END {exit(found ? 0 : 1)}' "$group_file" ;;
        *) awk -F: -v name="$subject" '$1==name {found=1} END {exit(found ? 0 : 1)}' "$passwd_file" ;;
    esac
}

_patch_account_subject_has_live_process() {
    local subject="$1"
    local passwd_file=""
    local subject_uid=""
    local status_path=""
    local line=""

    [ "$PATCH_ACCOUNT_ROOT" = / ] || return 1
    passwd_file="$(_patch_account_payload_path passwd)" || return 2
    subject_uid="$(awk -F: -v name="$subject" '$1==name {print $3; exit}' "$passwd_file")"
    [ -n "$subject_uid" ] || return 1
    for status_path in /proc/[0-9]*/status; do
        [ -r "$status_path" ] || continue
        while IFS= read -r line; do
            case "$line" in
                Uid:*)
                    line="${line#Uid:}"
                    set -- $line
                    [ "${1:-}" = "$subject_uid" ] && return 0
                    break
                    ;;
            esac
        done < "$status_path"
    done
    return 1
}

_patch_account_validate_decisions() {
    local criterion=""
    local subject=""
    local key=""
    local action=""
    local value=""
    local index=0
    local target_count=0
    local -A selected=()
    local -A desired_shells=()
    local -A desired_homes=()

    for criterion in "${PATCH_ACCOUNT_SELECTED_CRITERIA[@]}"; do selected["$criterion"]=1; done
    for key in "${!PATCH_ACCOUNT_TARGETS[@]}"; do
        criterion="${key%%:*}"
        subject="${key#*:}"
        [ "${PATCH_ACCOUNT_DECISION_ACTIONS[$key]+present}" = present ] || {
            _patch_account_set_error "$criterion:$subject requires an exact typed decision"
            return 2
        }
        target_count=$((target_count + 1))
    done
    while [ "$index" -lt "${#PATCH_ACCOUNT_DECISION_CRITERIA[@]}" ]; do
        criterion="${PATCH_ACCOUNT_DECISION_CRITERIA[$index]}"
        subject="${PATCH_ACCOUNT_DECISION_SUBJECTS[$index]}"
        key="$criterion:$subject"
        action="${PATCH_ACCOUNT_DECISION_ACTION_LIST[$index]}"
        value="${PATCH_ACCOUNT_DECISION_VALUE_LIST[$index]}"
        [ "${selected[$criterion]+present}" = present ] || return 2
        [ "${PATCH_ACCOUNT_TARGETS[$key]+present}" = present ] || return 2
        _patch_account_subject_exists "$criterion" "$subject" || return 2
        if [ "$action" != keep ] && [ "$action" != credential-reset ] &&
            _patch_account_subject_has_live_process "$subject"; then
            _patch_account_set_error "$criterion:$subject has an active process"
            return 2
        fi
        case "$action" in
            set-shell|disable-login)
                if [ "${desired_shells[$subject]+present}" = present ] && [ "${desired_shells[$subject]}" != "$value" ]; then
                    return 2
                fi
                desired_shells["$subject"]="$value"
                ;;
            set-home)
                if [ "${desired_homes[$subject]+present}" = present ] && [ "${desired_homes[$subject]}" != "$value" ]; then
                    return 2
                fi
                desired_homes["$subject"]="$value"
                ;;
        esac
        if _patch_account_action_requires_external_work "$action"; then
            PATCH_ACCOUNT_EXTERNAL_ACTION_REQUIRED_COUNT=$((PATCH_ACCOUNT_EXTERNAL_ACTION_REQUIRED_COUNT + 1))
            PATCH_ACCOUNT_CRITERION_STATES["$criterion"]=external_action_required
        elif [ "$action" != keep ]; then
            PATCH_ACCOUNT_CRITERION_STATES["$criterion"]=ready
        fi
        index=$((index + 1))
    done
    [ "$target_count" -eq "${#PATCH_ACCOUNT_DECISION_CRITERIA[@]}" ]
}

_patch_account_write_operations() {
    local operations="$PATCH_ACCOUNT_DATA_DIRECTORY/operations.tsv"
    local index=0

    {
        printf 'criterion\tsubject\taction\tvalue\tapproval_id\n'
        while [ "$index" -lt "${#PATCH_ACCOUNT_DECISION_CRITERIA[@]}" ]; do
            printf '%s\t%s\t%s\t%s\t%s\n' "${PATCH_ACCOUNT_DECISION_CRITERIA[$index]}" \
                "${PATCH_ACCOUNT_DECISION_SUBJECTS[$index]}" "${PATCH_ACCOUNT_DECISION_ACTION_LIST[$index]}" \
                "${PATCH_ACCOUNT_DECISION_VALUE_LIST[$index]}" "${PATCH_ACCOUNT_DECISION_APPROVAL_LIST[$index]}"
            index=$((index + 1))
        done
    } > "$operations" || return 2
    chmod 0600 "$operations" || return 2
}

_patch_account_transform_payload() {
    local name="$1"
    local payload=""
    local operations="$PATCH_ACCOUNT_DATA_DIRECTORY/operations.tsv"
    local temporary=""
    local mktemp_command=""
    local mv_command=""

    payload="$(_patch_account_payload_path "$name" 2>/dev/null || true)"
    [ -n "$payload" ] || return 0
    _patch_account_command_into mktemp mktemp_command || return 2
    _patch_account_command_into mv mv_command || return 2
    temporary="$($mktemp_command "$PATCH_ACCOUNT_DATA_DIRECTORY/payloads/.${name}.XXXXXXXX")" || return 2
    case "$name" in
        passwd)
            awk -F: -v OFS=: -v operations="$operations" '
                BEGIN {while ((getline line < operations)>0) {if(line ~ /^criterion/) continue; split(line,f,"\t"); key=f[2]; if(f[3]=="set-shell" || f[3]=="disable-login") shell[key]=f[4]; if(f[3]=="set-home") home[key]=f[4]; if(f[3]=="lock-account") lock[key]=1}}
                {if($1 in shell) $7=shell[$1]; if($1 in home) $6=home[$1]; if(($1 in lock) && $2 !~ /^!/) $2="!" $2; print}
            ' "$payload" > "$temporary" || return 2
            ;;
        shadow)
            awk -F: -v OFS=: -v operations="$operations" '
                BEGIN {while ((getline line < operations)>0) {if(line ~ /^criterion/) continue; split(line,f,"\t"); if(f[3]=="lock-account" || f[3]=="disable-login") lock[f[2]]=1}}
                {if(($1 in lock) && $2 !~ /^!/) $2="!" $2; print}
            ' "$payload" > "$temporary" || return 2
            ;;
        group|gshadow)
            awk -F: -v OFS=: -v operations="$operations" -v database="$name" '
                BEGIN {while ((getline line < operations)>0) {if(line ~ /^criterion/) continue; split(line,f,"\t"); if(f[3]=="remove-root-membership") remove[f[2]]=1}}
                function filter(value, count,i,a,out) {count=split(value,a,","); for(i=1;i<=count;i++) if(a[i]!="" && !(a[i] in remove)) out=out (out?",":"") a[i]; return out}
                {if($1=="root") {$4=filter($4); if(database=="gshadow") $3=filter($3)}; print}
            ' "$payload" > "$temporary" || return 2
            ;;
        *) return 2 ;;
    esac
    chmod 0600 "$temporary" || return 2
    "$mv_command" -f -- "$temporary" "$payload" || return 2
}

_patch_account_finalize_payloads() {
    local name=""
    local index=0
    local digest=""

    _patch_account_write_operations || return 2
    for name in passwd shadow group gshadow; do
        _patch_account_transform_payload "$name" || return 2
    done
    _patch_account_validate_databases || return 2
    while [ "$index" -lt "${#PATCH_ACCOUNT_FILE_NAMES[@]}" ]; do
        _patch_account_sha256_into "${PATCH_ACCOUNT_FILE_PAYLOADS[$index]}" digest || return 2
        PATCH_ACCOUNT_FILE_DESIRED_SHA256S[$index]="$digest"
        [ "$digest" = "${PATCH_ACCOUNT_FILE_BEFORE_SHA256S[$index]}" ] ||
            PATCH_ACCOUNT_CHANGE_COUNT=$((PATCH_ACCOUNT_CHANGE_COUNT + 1))
        index=$((index + 1))
    done
}

_patch_account_render_manifest() {
    local kind=""
    local index=0

    printf 'schema\trecord_type\trecord_fields\n'
    printf '1\troot\t%s\t%s\t%s\n' "$PATCH_ACCOUNT_ROOT" "$PATCH_ACCOUNT_ROOT_DEVICE" "$PATCH_ACCOUNT_ROOT_INODE"
    for kind in nss processes filesystem-ownership; do
        printf '1\tevidence\t%s\t%s\t%s\n' "$kind" "${PATCH_ACCOUNT_EVIDENCE_STATES[$kind]}" \
            "${PATCH_ACCOUNT_EVIDENCE_IDS[$kind]}"
    done
    printf '1\tcontext\tplatform\t%s\t%s\n' "$PATCH_ACCOUNT_PLATFORM_FAMILY" "$PATCH_ACCOUNT_PLATFORM_MAJOR"
    printf '1\tcontext\tuid_minimum\t%s\n' "$PATCH_ACCOUNT_UID_MINIMUM"
    while [ "$index" -lt "${#PATCH_ACCOUNT_SELECTED_CRITERIA[@]}" ]; do
        printf '1\tselected\t%s\n' "${PATCH_ACCOUNT_SELECTED_CRITERIA[$index]}"
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_ACCOUNT_DECISION_CRITERIA[@]}" ]; do
        printf '1\tdecision\t%s\t%s\t%s\t%s\t%s\n' "${PATCH_ACCOUNT_DECISION_CRITERIA[$index]}" \
            "${PATCH_ACCOUNT_DECISION_SUBJECTS[$index]}" "${PATCH_ACCOUNT_DECISION_ACTION_LIST[$index]}" \
            "${PATCH_ACCOUNT_DECISION_VALUE_LIST[$index]}" "${PATCH_ACCOUNT_DECISION_APPROVAL_LIST[$index]}"
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_ACCOUNT_FILE_NAMES[@]}" ]; do
        printf '1\tfile\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${PATCH_ACCOUNT_FILE_NAMES[$index]}" "${PATCH_ACCOUNT_FILE_PATHS[$index]}" \
            "${PATCH_ACCOUNT_FILE_DEVICES[$index]}" "${PATCH_ACCOUNT_FILE_INODES[$index]}" \
            "${PATCH_ACCOUNT_FILE_UIDS[$index]}" "${PATCH_ACCOUNT_FILE_GIDS[$index]}" \
            "${PATCH_ACCOUNT_FILE_MODES[$index]}" "${PATCH_ACCOUNT_FILE_SIZES[$index]}" \
            "${PATCH_ACCOUNT_FILE_MTIMES[$index]}" "${PATCH_ACCOUNT_FILE_CTIMES[$index]}" \
            "${PATCH_ACCOUNT_FILE_BEFORE_SHA256S[$index]}" "${PATCH_ACCOUNT_FILE_DESIRED_SHA256S[$index]}" \
            "${PATCH_ACCOUNT_FILE_BACKUPS[$index]##*/}"
        index=$((index + 1))
    done
}

_patch_account_render_plan() {
    local criterion=""
    local index=0

    printf 'criterion\tsubject\taction\tvalue\tapproval_id\tstate\n'
    while [ "$index" -lt "${#PATCH_ACCOUNT_DECISION_CRITERIA[@]}" ]; do
        criterion="${PATCH_ACCOUNT_DECISION_CRITERIA[$index]}"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$criterion" "${PATCH_ACCOUNT_DECISION_SUBJECTS[$index]}" \
            "${PATCH_ACCOUNT_DECISION_ACTION_LIST[$index]}" "${PATCH_ACCOUNT_DECISION_VALUE_LIST[$index]}" \
            "${PATCH_ACCOUNT_DECISION_APPROVAL_LIST[$index]}" "${PATCH_ACCOUNT_CRITERION_STATES[$criterion]}"
        index=$((index + 1))
    done
}

_patch_account_write_artifact() {
    local path="$1"
    local renderer="$2"

    [ ! -e "$path" ] && [ ! -L "$path" ] || return 2
    if ! (umask 077; set -o noclobber; "$renderer" > "$path" && chmod 0600 "$path"); then
        return 2
    fi
}

_patch_account_set_state() {
    local state="$1"
    local state_path="$PATCH_ACCOUNT_DATA_DIRECTORY/state"
    local temporary=""
    local mktemp_command=""
    local mv_command=""

    case "$state" in planned|external_action_required|applying|verified|rollback_in_progress|rolled_back|rollback_failed) ;; *) return 2 ;; esac
    _patch_account_command_into mktemp mktemp_command || return 2
    _patch_account_command_into mv mv_command || return 2
    temporary="$($mktemp_command "$PATCH_ACCOUNT_DATA_DIRECTORY/.state.XXXXXXXX")" || return 2
    printf '%s\n' "$state" > "$temporary" || return 2
    chmod 0600 "$temporary" || return 2
    "$mv_command" -f -- "$temporary" "$state_path" || return 2
    PATCH_ACCOUNT_TRANSACTION_STATE="$state"
}

_patch_account_write_checksums() {
    local path="$PATCH_ACCOUNT_DATA_DIRECTORY/checksums.sha256"
    local relative=""
    local digest_value=""
    local index=0

    {
        for relative in manifest.tsv plan.tsv operations.tsv targets.tsv; do
            _patch_account_sha256_into "$PATCH_ACCOUNT_DATA_DIRECTORY/$relative" digest_value || exit 2
            printf '%s  %s\n' "$digest_value" "$relative"
        done
        while [ "$index" -lt "${#PATCH_ACCOUNT_FILE_NAMES[@]}" ]; do
            for relative in "backups/${PATCH_ACCOUNT_FILE_NAMES[$index]}" "payloads/${PATCH_ACCOUNT_FILE_NAMES[$index]}"; do
                _patch_account_sha256_into "$PATCH_ACCOUNT_DATA_DIRECTORY/$relative" digest_value || exit 2
                printf '%s  %s\n' "$digest_value" "$relative"
            done
            index=$((index + 1))
        done
    } > "$path" || return 2
    chmod 0600 "$path" || return 2
}

patch_account_write_plan_tsv() {
    local path="$1"

    [ "$PATCH_ACCOUNT_PLAN_VALID" -eq 1 ] || return 2
    _patch_account_write_artifact "$path" _patch_account_render_plan
}

patch_account_plan() {
    local root="$1"
    local transaction_directory="$2"
    local criterion=""
    local seen=","

    shift 2
    patch_account_reset
    [ "$#" -gt 0 ] || return 2
    for criterion in "$@"; do
        _patch_account_valid_criterion "$criterion" || return 1
        case "$seen" in *",$criterion,"*) return 2 ;; esac
        seen+="$criterion,"
        PATCH_ACCOUNT_SELECTED_CRITERIA+=("$criterion")
        PATCH_ACCOUNT_CRITERION_STATES["$criterion"]=compliant
    done
    _patch_account_initialize_root "$root" || return 2
    _patch_account_validate_evidence || {
        _patch_account_set_error "NSS, process, or filesystem ownership evidence is incomplete"
        return 2
    }
    _patch_account_resolve_policy_context || {
        _patch_account_set_error "platform or UID_MIN policy could not be resolved safely"
        return 2
    }
    _patch_account_prepare_transaction "$transaction_directory" || return 2
    _patch_account_snapshot_database_file passwd required || return 2
    _patch_account_snapshot_database_file shadow optional || return 2
    _patch_account_snapshot_database_file group required || return 2
    _patch_account_snapshot_database_file gshadow optional || return 2
    _patch_account_validate_databases || return 2
    _patch_account_collect_targets || return 2
    _patch_account_validate_decisions || return 2
    _patch_account_finalize_payloads || return 2
    _patch_account_write_artifact "$PATCH_ACCOUNT_DATA_DIRECTORY/manifest.tsv" _patch_account_render_manifest || return 2
    _patch_account_write_artifact "$PATCH_ACCOUNT_DATA_DIRECTORY/plan.tsv" _patch_account_render_plan || return 2
    _patch_account_write_checksums || return 2
    if [ "$PATCH_ACCOUNT_EXTERNAL_ACTION_REQUIRED_COUNT" -gt 0 ]; then
        _patch_account_set_state external_action_required || return 2
    else
        _patch_account_set_state planned || return 2
    fi
    PATCH_ACCOUNT_PLAN_VALID=1
}

_patch_account_file_is_current() {
    local index="$1"
    local current_device="" current_inode="" current_uid="" current_gid="" current_mode=""
    local current_size="" current_mtime="" current_ctime="" current_sha256=""

    _patch_account_file_metadata_into "${PATCH_ACCOUNT_FILE_PATHS[$index]}" current || return 2
    _patch_account_sha256_into "${PATCH_ACCOUNT_FILE_PATHS[$index]}" current_sha256 || return 2
    [ "$current_device" = "${PATCH_ACCOUNT_FILE_DEVICES[$index]}" ] &&
        [ "$current_inode" = "${PATCH_ACCOUNT_FILE_INODES[$index]}" ] &&
        [ "$current_uid" = "${PATCH_ACCOUNT_FILE_UIDS[$index]}" ] &&
        [ "$current_gid" = "${PATCH_ACCOUNT_FILE_GIDS[$index]}" ] &&
        [ "$current_mode" = "${PATCH_ACCOUNT_FILE_MODES[$index]}" ] &&
        [ "$current_size" = "${PATCH_ACCOUNT_FILE_SIZES[$index]}" ] &&
        [ "$current_mtime" = "${PATCH_ACCOUNT_FILE_MTIMES[$index]}" ] &&
        [ "$current_ctime" = "${PATCH_ACCOUNT_FILE_CTIMES[$index]}" ] &&
        [ "$current_sha256" = "${PATCH_ACCOUNT_FILE_BEFORE_SHA256S[$index]}" ]
}

_patch_account_acquire_locks() {
    local flock_command=""
    local path=""
    local descriptor=""

    _patch_account_command_into flock flock_command || return 2
    PATCH_ACCOUNT_LOCK_FDS=()
    for path in "${PATCH_ACCOUNT_FILE_PATHS[@]}"; do
        exec {descriptor}<>"$path" || return 2
        "$flock_command" -n -x "$descriptor" || {
            exec {descriptor}>&-
            return 2
        }
        PATCH_ACCOUNT_LOCK_FDS+=("$descriptor")
    done
}

_patch_account_release_locks() {
    local descriptor=""

    for descriptor in "${PATCH_ACCOUNT_LOCK_FDS[@]}"; do
        exec {descriptor}>&- || true
    done
    PATCH_ACCOUNT_LOCK_FDS=()
}

_patch_account_copy_over() {
    local source="$1"
    local target="$2"
    local uid="$3"
    local gid="$4"
    local mode="$5"
    local cp_command=""
    local chown_command=""
    local chmod_command=""

    _patch_account_command_into cp cp_command || return 2
    _patch_account_command_into chown chown_command || return 2
    _patch_account_command_into chmod chmod_command || return 2
    "$cp_command" -- "$source" "$target" || return 2
    "$chown_command" "$uid:$gid" "$target" || return 2
    "$chmod_command" "$mode" "$target" || return 2
}

_patch_account_verify_applied_decisions() {
    local passwd_file=""
    local shadow_file=""
    local group_file=""
    local gshadow_file=""
    local index=0
    local subject=""
    local action=""
    local value=""

    _patch_account_root_path_into /etc/passwd passwd_file || return 2
    _patch_account_root_path_into /etc/shadow shadow_file || return 2
    _patch_account_root_path_into /etc/group group_file || return 2
    _patch_account_root_path_into /etc/gshadow gshadow_file || return 2
    while [ "$index" -lt "${#PATCH_ACCOUNT_DECISION_ACTION_LIST[@]}" ]; do
        subject="${PATCH_ACCOUNT_DECISION_SUBJECTS[$index]}"
        action="${PATCH_ACCOUNT_DECISION_ACTION_LIST[$index]}"
        value="${PATCH_ACCOUNT_DECISION_VALUE_LIST[$index]}"
        case "$action" in
            keep) ;;
            set-shell|disable-login)
                awk -F: -v name="$subject" -v expected="$value" '$1==name {found=1; if($7==expected) good=1} END {exit(found && good ? 0 : 1)}' "$passwd_file" || return 2
                ;;
            set-home)
                awk -F: -v name="$subject" -v expected="$value" '$1==name {found=1; if($6==expected) good=1} END {exit(found && good ? 0 : 1)}' "$passwd_file" || return 2
                ;;
            lock-account)
                if awk -F: -v name="$subject" '$1==name {found=1; if($2 ~ /^!/) good=1} END {exit(found && good ? 0 : 1)}' "$passwd_file"; then :
                elif [ -r "$shadow_file" ] && awk -F: -v name="$subject" '$1==name {found=1; if($2 ~ /^!/) good=1} END {exit(found && good ? 0 : 1)}' "$shadow_file"; then :
                else return 2
                fi
                ;;
            remove-root-membership)
                awk -F: -v name="$subject" '$1=="root" {count=split($4,a,","); for(i=1;i<=count;i++) if(a[i]==name) exit 1; found=1} END {exit(found ? 0 : 1)}' "$group_file" || return 2
                if [ -r "$gshadow_file" ]; then
                    awk -F: -v name="$subject" '$1=="root" {count=split($3 "," $4,a,","); for(i=1;i<=count;i++) if(a[i]==name) exit 1; found=1} END {exit(found ? 0 : 1)}' "$gshadow_file" || return 2
                fi
                ;;
        esac
        index=$((index + 1))
    done
}

patch_account_verify() {
    local index=0
    local digest=""
    local criterion=""

    while [ "$index" -lt "${#PATCH_ACCOUNT_FILE_PATHS[@]}" ]; do
        _patch_account_sha256_into "${PATCH_ACCOUNT_FILE_PATHS[$index]}" digest || return 2
        [ "$digest" = "${PATCH_ACCOUNT_FILE_DESIRED_SHA256S[$index]}" ] || return 2
        index=$((index + 1))
    done
    _patch_account_verify_applied_decisions || return 2
    for criterion in "${PATCH_ACCOUNT_SELECTED_CRITERIA[@]}"; do
        [ "${PATCH_ACCOUNT_CRITERION_STATES[$criterion]}" = external_action_required ] ||
            PATCH_ACCOUNT_CRITERION_STATES["$criterion"]=verified
    done
    _patch_account_set_state verified || return 2
}

patch_account_rollback() {
    local index=$(( ${#PATCH_ACCOUNT_FILE_PATHS[@]} - 1 ))
    local failures=0
    local digest=""
    local criterion=""

    [ "$PATCH_ACCOUNT_APPLY_STARTED" -eq 1 ] || return 2
    _patch_account_set_state rollback_in_progress || return 2
    while [ "$index" -ge 0 ]; do
        if [ "${PATCH_ACCOUNT_FILE_APPLIED[$index]}" -eq 1 ]; then
            _patch_account_copy_over "${PATCH_ACCOUNT_FILE_BACKUPS[$index]}" \
                "${PATCH_ACCOUNT_FILE_PATHS[$index]}" "${PATCH_ACCOUNT_FILE_UIDS[$index]}" \
                "${PATCH_ACCOUNT_FILE_GIDS[$index]}" "${PATCH_ACCOUNT_FILE_MODES[$index]}" || failures=$((failures + 1))
            _patch_account_sha256_into "${PATCH_ACCOUNT_FILE_PATHS[$index]}" digest || failures=$((failures + 1))
            [ "$digest" = "${PATCH_ACCOUNT_FILE_BEFORE_SHA256S[$index]}" ] || failures=$((failures + 1))
        fi
        index=$((index - 1))
    done
    if [ "$failures" -gt 0 ]; then
        _patch_account_set_state rollback_failed >/dev/null 2>&1 || true
        PATCH_ACCOUNT_ERROR_DETAIL="account rollback was incomplete: failures=$failures"
        return 2
    fi
    for criterion in "${PATCH_ACCOUNT_SELECTED_CRITERIA[@]}"; do
        PATCH_ACCOUNT_CRITERION_STATES["$criterion"]=rolled_back
    done
    _patch_account_set_state rolled_back || return 2
}

patch_account_apply() {
    local index=0
    local digest=""
    local status=0

    [ "$PATCH_ACCOUNT_PLAN_VALID" -eq 1 ] || return 2
    [ "${EUID:-$(id -u)}" -eq 0 ] || return 2
    [ "$PATCH_ACCOUNT_EXTERNAL_ACTION_REQUIRED_COUNT" -eq 0 ] || {
        PATCH_ACCOUNT_ERROR_DETAIL="credential, UID/GID, deletion, or home creation requires an external action"
        return 2
    }
    _patch_account_revalidate_policy_context || {
        PATCH_ACCOUNT_ERROR_DETAIL="platform or UID_MIN policy changed after planning"
        return 2
    }
    _patch_account_acquire_locks || return 2
    while [ "$index" -lt "${#PATCH_ACCOUNT_FILE_PATHS[@]}" ]; do
        _patch_account_file_is_current "$index" || status=2
        index=$((index + 1))
    done
    if [ "$status" -ne 0 ]; then
        _patch_account_release_locks
        return 2
    fi
    PATCH_ACCOUNT_APPLY_STARTED=1
    _patch_account_set_state applying || status=2
    index=0
    while [ "$status" -eq 0 ] && [ "$index" -lt "${#PATCH_ACCOUNT_FILE_PATHS[@]}" ]; do
        if [ "${PATCH_ACCOUNT_FILE_BEFORE_SHA256S[$index]}" != "${PATCH_ACCOUNT_FILE_DESIRED_SHA256S[$index]}" ]; then
            PATCH_ACCOUNT_FILE_APPLIED[$index]=1
            _patch_account_copy_over "${PATCH_ACCOUNT_FILE_PAYLOADS[$index]}" \
                "${PATCH_ACCOUNT_FILE_PATHS[$index]}" "${PATCH_ACCOUNT_FILE_UIDS[$index]}" \
                "${PATCH_ACCOUNT_FILE_GIDS[$index]}" "${PATCH_ACCOUNT_FILE_MODES[$index]}" || status=2
        fi
        index=$((index + 1))
    done
    [ "$status" -ne 0 ] || patch_account_verify || status=2
    if [ "$status" -ne 0 ]; then
        patch_account_rollback || PATCH_ACCOUNT_ERROR_DETAIL="account apply failed and rollback was incomplete"
        _patch_account_release_locks
        return 2
    fi
    _patch_account_release_locks
}

_patch_account_artifact_is_protected() {
    local path="$1"
    local expected_mode="$2"
    local metadata=""
    local owner_uid=""
    local mode=""
    local links=""

    [ -f "$path" ] && [ ! -L "$path" ] || return 2
    _patch_account_stat_into "$path" metadata || return 2
    metadata="${metadata#*:*:}"
    owner_uid="${metadata%%:*}"; metadata="${metadata#*:}"
    metadata="${metadata#*:}"
    mode="${metadata%%:*}"; metadata="${metadata#*:}"
    links="${metadata%%:*}"
    [ "$owner_uid" = "${EUID:-$owner_uid}" ] && [ "$mode" = "$expected_mode" ] && [ "$links" = 1 ]
}

_patch_account_bind_existing_transaction() {
    local requested="$1"
    local canonical=""
    local metadata=""
    local owner_uid=""
    local mode=""
    local directory=""

    _patch_account_canonical_directory_into "$requested" canonical || return 2
    [ "$canonical" = "$requested" ] || return 2
    for directory in "$canonical" "$canonical/account" "$canonical/account/backups" "$canonical/account/payloads"; do
        [ -d "$directory" ] && [ ! -L "$directory" ] || return 2
        _patch_account_stat_into "$directory" metadata || return 2
        metadata="${metadata#*:*:}"
        owner_uid="${metadata%%:*}"; metadata="${metadata#*:}"
        metadata="${metadata#*:}"
        mode="${metadata%%:*}"
        [ "$owner_uid" = "${EUID:-$owner_uid}" ] && [ "$mode" = 700 ] || return 2
    done
    PATCH_ACCOUNT_TRANSACTION_DIRECTORY="$canonical"
    PATCH_ACCOUNT_DATA_DIRECTORY="$canonical/account"
}

_patch_account_validate_checksums() {
    local checksum_path="$PATCH_ACCOUNT_DATA_DIRECTORY/checksums.sha256"
    local line=""
    local digest=""
    local relative=""
    local actual=""
    local count=0
    local -A seen=()

    _patch_account_artifact_is_protected "$checksum_path" 600 || return 2
    while IFS= read -r line || [ -n "$line" ]; do
        digest="${line%%  *}"
        relative="${line#*  }"
        [ "$relative" != "$line" ] && [ "${#digest}" -eq 64 ] || return 2
        case "$digest" in *[!0-9a-f]*) return 2 ;; esac
        case "$relative" in
            manifest.tsv|plan.tsv|operations.tsv|targets.tsv|backups/passwd|backups/shadow|backups/group|backups/gshadow|payloads/passwd|payloads/shadow|payloads/group|payloads/gshadow) ;;
            *) return 2 ;;
        esac
        [ "${seen[$relative]+present}" != present ] || return 2
        seen["$relative"]=1
        _patch_account_artifact_is_protected "$PATCH_ACCOUNT_DATA_DIRECTORY/$relative" 600 || return 2
        _patch_account_sha256_into "$PATCH_ACCOUNT_DATA_DIRECTORY/$relative" actual || return 2
        [ "$actual" = "$digest" ] || return 2
        count=$((count + 1))
    done < "$checksum_path"
    [ "$count" -ge 8 ] || return 2
    for relative in manifest.tsv plan.tsv operations.tsv targets.tsv backups/passwd payloads/passwd backups/group payloads/group; do
        [ "${seen[$relative]+present}" = present ] || return 2
    done
}

_patch_account_load_manifest() {
    local path="$PATCH_ACCOUNT_DATA_DIRECTORY/manifest.tsv"
    local line=""
    local -a fields=()
    local line_number=0
    local criterion=""
    local action=""
    local root_seen=0
    local platform_context_seen=0
    local uid_context_seen=0
    local name=""
    local expected_path=""
    local index=0
    local digest=""
    local -A selected=()
    local -A files=()

    _patch_account_artifact_is_protected "$path" 600 || return 2
    patch_account_evidence_reset
    patch_account_decision_reset
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
                [ "${fields[2]}" = "$PATCH_ACCOUNT_ROOT" ] &&
                    [ "${fields[3]}" = "$PATCH_ACCOUNT_ROOT_DEVICE" ] &&
                    [ "${fields[4]}" = "$PATCH_ACCOUNT_ROOT_INODE" ] || return 2
                root_seen=1
                ;;
            evidence)
                [ "${#fields[@]}" -eq 5 ] || return 2
                patch_account_evidence_add "${fields[2]}" "${fields[3]}" "${fields[4]}" || return 2
                ;;
            context)
                case "${fields[2]:-}" in
                    platform)
                        [ "${#fields[@]}" -eq 5 ] && [ "$platform_context_seen" -eq 0 ] || return 2
                        case "${fields[3]}" in unknown|debian|rhel) ;; *) return 2 ;; esac
                        case "${fields[4]}" in ''|*[!0-9]*) return 2 ;; esac
                        PATCH_ACCOUNT_PLATFORM_FAMILY="${fields[3]}"
                        PATCH_ACCOUNT_PLATFORM_MAJOR="${fields[4]}"
                        platform_context_seen=1
                        ;;
                    uid_minimum)
                        [ "${#fields[@]}" -eq 4 ] && [ "$uid_context_seen" -eq 0 ] || return 2
                        case "${fields[3]}" in ''|*[!0-9]*) return 2 ;; esac
                        [ "${fields[3]}" -lt 4294967295 ] || return 2
                        PATCH_ACCOUNT_UID_MINIMUM="${fields[3]}"
                        uid_context_seen=1
                        ;;
                    *) return 2 ;;
                esac
                ;;
            selected)
                [ "${#fields[@]}" -eq 3 ] || return 2
                criterion="${fields[2]}"
                _patch_account_valid_criterion "$criterion" || return 2
                [ "${selected[$criterion]+present}" != present ] || return 2
                selected["$criterion"]=1
                PATCH_ACCOUNT_SELECTED_CRITERIA+=("$criterion")
                PATCH_ACCOUNT_CRITERION_STATES["$criterion"]=compliant
                ;;
            decision)
                [ "${#fields[@]}" -eq 7 ] || return 2
                criterion="${fields[2]}"
                [ "${selected[$criterion]+present}" = present ] || return 2
                patch_account_decision_add "$criterion" "${fields[3]}" "${fields[4]}" "${fields[5]}" "${fields[6]}" || return 2
                action="${fields[4]}"
                if _patch_account_action_requires_external_work "$action"; then
                    PATCH_ACCOUNT_EXTERNAL_ACTION_REQUIRED_COUNT=$((PATCH_ACCOUNT_EXTERNAL_ACTION_REQUIRED_COUNT + 1))
                    PATCH_ACCOUNT_CRITERION_STATES["$criterion"]=external_action_required
                elif [ "$action" != keep ]; then
                    PATCH_ACCOUNT_CRITERION_STATES["$criterion"]=ready
                fi
                ;;
            file)
                [ "${#fields[@]}" -eq 15 ] || return 2
                name="${fields[2]}"
                case "$name" in passwd|shadow|group|gshadow) ;; *) return 2 ;; esac
                [ "${files[$name]+present}" != present ] || return 2
                files["$name"]=1
                _patch_account_root_path_into "/etc/$name" expected_path || return 2
                [ "${fields[3]}" = "$expected_path" ] || return 2
                case "${fields[4]}:${fields[5]}:${fields[6]}:${fields[7]}:${fields[8]}:${fields[9]}:${fields[10]}:${fields[11]}" in *[!0-9:]*) return 2 ;; esac
                [ "${#fields[12]}" -eq 64 ] && [ "${#fields[13]}" -eq 64 ] || return 2
                case "${fields[12]}${fields[13]}" in *[!0-9a-f]*) return 2 ;; esac
                [ "${fields[14]}" = "$name" ] || return 2
                for digest in "$PATCH_ACCOUNT_DATA_DIRECTORY/backups/$name" "$PATCH_ACCOUNT_DATA_DIRECTORY/payloads/$name"; do
                    _patch_account_artifact_is_protected "$digest" 600 || return 2
                done
                PATCH_ACCOUNT_FILE_NAMES+=("$name")
                PATCH_ACCOUNT_FILE_PATHS+=("${fields[3]}")
                PATCH_ACCOUNT_FILE_DEVICES+=("${fields[4]}")
                PATCH_ACCOUNT_FILE_INODES+=("${fields[5]}")
                PATCH_ACCOUNT_FILE_UIDS+=("${fields[6]}")
                PATCH_ACCOUNT_FILE_GIDS+=("${fields[7]}")
                PATCH_ACCOUNT_FILE_MODES+=("${fields[8]}")
                PATCH_ACCOUNT_FILE_SIZES+=("${fields[9]}")
                PATCH_ACCOUNT_FILE_MTIMES+=("${fields[10]}")
                PATCH_ACCOUNT_FILE_CTIMES+=("${fields[11]}")
                PATCH_ACCOUNT_FILE_BEFORE_SHA256S+=("${fields[12]}")
                PATCH_ACCOUNT_FILE_DESIRED_SHA256S+=("${fields[13]}")
                PATCH_ACCOUNT_FILE_BACKUPS+=("$PATCH_ACCOUNT_DATA_DIRECTORY/backups/$name")
                PATCH_ACCOUNT_FILE_PAYLOADS+=("$PATCH_ACCOUNT_DATA_DIRECTORY/payloads/$name")
                PATCH_ACCOUNT_FILE_APPLIED+=(0)
                [ "${fields[12]}" = "${fields[13]}" ] || PATCH_ACCOUNT_CHANGE_COUNT=$((PATCH_ACCOUNT_CHANGE_COUNT + 1))
                ;;
            *) return 2 ;;
        esac
    done < "$path"
    [ "$root_seen" -eq 1 ] && [ "$platform_context_seen" -eq 1 ] && [ "$uid_context_seen" -eq 1 ] &&
        [ "${files[passwd]+present}" = present ] && [ "${files[group]+present}" = present ] || return 2
    [ "${#PATCH_ACCOUNT_SELECTED_CRITERIA[@]}" -gt 0 ] || return 2
    if _patch_account_selected U-07 || _patch_account_selected U-11 ||
        _patch_account_selected U-13 || _patch_account_selected U-32; then
        [ "$PATCH_ACCOUNT_PLATFORM_FAMILY" != unknown ] || return 2
    fi
    _patch_account_validate_evidence || return 2
    _patch_account_validate_databases || return 2
    [ "$(< "$PATCH_ACCOUNT_DATA_DIRECTORY/plan.tsv")" = "$(_patch_account_render_plan)" ] || return 2
    while [ "$index" -lt "${#PATCH_ACCOUNT_FILE_NAMES[@]}" ]; do
        _patch_account_sha256_into "${PATCH_ACCOUNT_FILE_BACKUPS[$index]}" digest || return 2
        [ "$digest" = "${PATCH_ACCOUNT_FILE_BEFORE_SHA256S[$index]}" ] || return 2
        _patch_account_sha256_into "${PATCH_ACCOUNT_FILE_PAYLOADS[$index]}" digest || return 2
        [ "$digest" = "${PATCH_ACCOUNT_FILE_DESIRED_SHA256S[$index]}" ] || return 2
        index=$((index + 1))
    done
}

_patch_account_read_state() {
    local path="$PATCH_ACCOUNT_DATA_DIRECTORY/state"
    local state=""

    _patch_account_artifact_is_protected "$path" 600 || return 2
    [ "$(wc -l < "$path" | tr -d '[:space:]')" = 1 ] || return 2
    IFS= read -r state < "$path" || return 2
    case "$state" in planned|external_action_required|applying|verified|rollback_in_progress|rolled_back|rollback_failed) ;; *) return 2 ;; esac
    PATCH_ACCOUNT_TRANSACTION_STATE="$state"
}

patch_account_load_transaction() {
    local root="$1"
    local transaction_directory="$2"

    patch_account_reset
    patch_account_decision_reset
    patch_account_evidence_reset
    _patch_account_initialize_root "$root" || return 2
    _patch_account_bind_existing_transaction "$transaction_directory" || return 2
    _patch_account_validate_checksums || return 2
    _patch_account_load_manifest || return 2
    _patch_account_read_state || return 2
    PATCH_ACCOUNT_PLAN_VALID=1
    PATCH_ACCOUNT_TRANSACTION_LOADED=1
}

_patch_account_current_file_side() {
    local index="$1"
    local destination_name="$2"
    local current_device="" current_inode="" current_uid="" current_gid="" current_mode=""
    local current_size="" current_mtime="" current_ctime="" current_sha256=""

    _patch_account_file_metadata_into "${PATCH_ACCOUNT_FILE_PATHS[$index]}" current || return 2
    _patch_account_sha256_into "${PATCH_ACCOUNT_FILE_PATHS[$index]}" current_sha256 || return 2
    [ "$current_device" = "${PATCH_ACCOUNT_FILE_DEVICES[$index]}" ] &&
        [ "$current_inode" = "${PATCH_ACCOUNT_FILE_INODES[$index]}" ] &&
        [ "$current_uid" = "${PATCH_ACCOUNT_FILE_UIDS[$index]}" ] &&
        [ "$current_gid" = "${PATCH_ACCOUNT_FILE_GIDS[$index]}" ] &&
        [ "$current_mode" = "${PATCH_ACCOUNT_FILE_MODES[$index]}" ] || return 2
    if [ "${PATCH_ACCOUNT_FILE_BEFORE_SHA256S[$index]}" = "${PATCH_ACCOUNT_FILE_DESIRED_SHA256S[$index]}" ] &&
        [ "$current_sha256" = "${PATCH_ACCOUNT_FILE_BEFORE_SHA256S[$index]}" ]; then
        printf -v "$destination_name" '%s' unchanged
    elif [ "$current_sha256" = "${PATCH_ACCOUNT_FILE_BEFORE_SHA256S[$index]}" ]; then
        printf -v "$destination_name" '%s' before
    elif [ "$current_sha256" = "${PATCH_ACCOUNT_FILE_DESIRED_SHA256S[$index]}" ]; then
        printf -v "$destination_name" '%s' after
    else
        printf -v "$destination_name" '%s' transition
    fi
}

patch_account_rollback_transaction() {
    local root="$1"
    local transaction_directory="$2"
    local mode="${3:-strict}"
    local index=0
    local side=""
    local status=0

    case "$mode" in strict|transition) ;; *) return 2 ;; esac
    [ "${EUID:-$(id -u)}" -eq 0 ] || return 2
    patch_account_load_transaction "$root" "$transaction_directory" || return 2
    case "$PATCH_ACCOUNT_TRANSACTION_STATE" in
        external_action_required|planned) return 2 ;;
        rolled_back)
            while [ "$index" -lt "${#PATCH_ACCOUNT_FILE_PATHS[@]}" ]; do
                _patch_account_current_file_side "$index" side || return 2
                [ "$side" = before ] || [ "$side" = unchanged ] || return 2
                index=$((index + 1))
            done
            return 0
            ;;
        verified) ;;
        applying|rollback_in_progress|rollback_failed) [ "$mode" = transition ] || return 2 ;;
        *) return 2 ;;
    esac
    _patch_account_acquire_locks || return 2
    index=0
    while [ "$index" -lt "${#PATCH_ACCOUNT_FILE_PATHS[@]}" ]; do
        _patch_account_current_file_side "$index" side || status=2
        if [ "$status" -eq 0 ]; then
            case "$PATCH_ACCOUNT_TRANSACTION_STATE:$mode:$side" in
                verified:strict:after) PATCH_ACCOUNT_FILE_APPLIED[$index]=1 ;;
                verified:strict:unchanged) PATCH_ACCOUNT_FILE_APPLIED[$index]=0 ;;
                verified:transition:before) PATCH_ACCOUNT_FILE_APPLIED[$index]=0 ;;
                verified:transition:after|applying:transition:after|rollback_in_progress:transition:after|rollback_failed:transition:after)
                    PATCH_ACCOUNT_FILE_APPLIED[$index]=1
                    ;;
                applying:transition:before|rollback_in_progress:transition:before|rollback_failed:transition:before)
                    PATCH_ACCOUNT_FILE_APPLIED[$index]=0
                    ;;
                *:transition:unchanged) PATCH_ACCOUNT_FILE_APPLIED[$index]=0 ;;
                *:transition:transition) PATCH_ACCOUNT_FILE_APPLIED[$index]=1 ;;
                *) status=2 ;;
            esac
        fi
        index=$((index + 1))
    done
    if [ "$status" -ne 0 ]; then
        _patch_account_release_locks
        return 2
    fi
    PATCH_ACCOUNT_APPLY_STARTED=1
    patch_account_rollback || status=$?
    _patch_account_release_locks
    return "$status"
}
