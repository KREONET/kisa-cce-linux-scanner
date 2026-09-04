# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash
# shellcheck disable=SC2034

# Distribution-aware PAM transactions for U-02, U-03, and U-06.

if ! declare -F patch_configuration_reset >/dev/null 2>&1; then
    case "${BASH_SOURCE[0]}" in
        */*) __kisa_pam_source_directory="${BASH_SOURCE[0]%/*}" ;;
        *) __kisa_pam_source_directory=. ;;
    esac
    # shellcheck source=_configuration-transaction.sh
    . "$__kisa_pam_source_directory/_configuration-transaction.sh"
    unset __kisa_pam_source_directory
fi

PAM_TRANSACTION_CONTEXT_HEADER=$'schema\tfamily\tapproved_group\tauthselect_profile\tauthselect_features\tcriteria'
PAM_TRANSACTION_ROOT=""
PAM_TRANSACTION_FAMILY=""
PAM_TRANSACTION_APPROVED_GROUP=""
PAM_TRANSACTION_AUTHSELECT_PROFILE="-"
PAM_TRANSACTION_AUTHSELECT_FEATURES="-"
PAM_TRANSACTION_CRITERIA=""
PAM_TRANSACTION_PREREQUISITE_RESULT="unresolved"
PAM_TRANSACTION_ERROR_DETAIL=""
PAM_TRANSACTION_VERIFIED=0

_pam_transaction_set_error() {
    PAM_TRANSACTION_ERROR_DETAIL="$1"
    return 2
}

_pam_transaction_set_prerequisite() {
    PAM_TRANSACTION_PREREQUISITE_RESULT="$1"
    PAM_TRANSACTION_ERROR_DETAIL="prerequisite not satisfied: $1"
    return 3
}

_pam_transaction_criterion_selected() {
    local criterion="$1"

    case ",$PAM_TRANSACTION_CRITERIA," in
        *",$criterion,"*) return 0 ;;
        *) return 1 ;;
    esac
}

_pam_transaction_set_criteria() {
    local criterion=""
    local requested=$'\n'
    local canonical=""

    if [ "$#" -eq 0 ]; then
        set -- U-02 U-03 U-06
    fi
    for criterion in "$@"; do
        case "$criterion" in U-02|U-03|U-06) ;; *) return 2 ;; esac
        case "$requested" in *$'\n'"$criterion"$'\n'*) return 2 ;; esac
        requested+="$criterion"$'\n'
    done
    for criterion in U-02 U-03 U-06; do
        case "$requested" in
            *$'\n'"$criterion"$'\n'*) canonical="${canonical:+$canonical,}$criterion" ;;
        esac
    done
    [ -n "$canonical" ] || return 2
    PAM_TRANSACTION_CRITERIA="$canonical"
}

_pam_transaction_physical_path_into() {
    local __kisa_pam_logical_input="$1"
    local __kisa_pam_physical_destination="$2"
    local __kisa_pam_physical_result=""

    _patch_configuration_valid_destination "$__kisa_pam_physical_destination" || return 2
    case "$__kisa_pam_logical_input" in /*) ;; *) return 2 ;; esac
    case "$__kisa_pam_logical_input" in *$'\n'*|*$'\r'*|*$'\t'*|*/../*|*/..|*/./*|*/.) return 2 ;; esac
    if [ "$PATCH_CONFIGURATION_ROOT" = / ]; then
        __kisa_pam_physical_result="$__kisa_pam_logical_input"
    else
        __kisa_pam_physical_result="${PATCH_CONFIGURATION_ROOT%/}$__kisa_pam_logical_input"
    fi
    printf -v "$__kisa_pam_physical_destination" '%s' "$__kisa_pam_physical_result"
}

_pam_transaction_detect_family_into() {
    local root="$1"
    local destination_name="$2"
    local release_file="${root%/}/etc/os-release"
    local line=""
    local platform_id=""
    local id_like=""
    local family=""
    local link_target=""

    _patch_configuration_valid_destination "$destination_name" || return 2
    if [ -L "$release_file" ]; then
        link_target="$(/usr/bin/readlink "$release_file" 2>/dev/null)" || return 2
        case "$link_target" in
            ../usr/lib/os-release|/usr/lib/os-release) release_file="${root%/}/usr/lib/os-release" ;;
            *) return 2 ;;
        esac
    fi
    [ -f "$release_file" ] && [ ! -L "$release_file" ] && [ -r "$release_file" ] || return 2
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ID=*)
                [ -z "$platform_id" ] || return 2
                platform_id="${line#ID=}"
                platform_id="${platform_id#\"}"
                platform_id="${platform_id%\"}"
                ;;
            ID_LIKE=*)
                [ -z "$id_like" ] || return 2
                id_like="${line#ID_LIKE=}"
                id_like="${id_like#\"}"
                id_like="${id_like%\"}"
                ;;
        esac
    done < "$release_file"
    case "$platform_id $id_like" in
        *ubuntu*|*debian*) family=debian ;;
        *rhel*|*fedora*|*centos*|*rocky*|*almalinux*) family=rhel ;;
        *) return 1 ;;
    esac
    printf -v "$destination_name" '%s' "$family"
}

_pam_transaction_module_available() {
    local module_name="$1"
    local candidate=""
    local directory=""
    local old_nullglob=0
    local -a directories=()

    case "$module_name" in pam_*.so) ;; *) return 2 ;; esac
    shopt -q nullglob && old_nullglob=1
    shopt -s nullglob
    directories=(
        "$PATCH_CONFIGURATION_ROOT"/usr/lib/security
        "$PATCH_CONFIGURATION_ROOT"/usr/lib64/security
        "$PATCH_CONFIGURATION_ROOT"/lib/security
        "$PATCH_CONFIGURATION_ROOT"/lib64/security
        "$PATCH_CONFIGURATION_ROOT"/usr/lib/*/security
        "$PATCH_CONFIGURATION_ROOT"/lib/*/security
    )
    [ "$old_nullglob" -eq 1 ] || shopt -u nullglob
    for directory in "${directories[@]}"; do
        candidate="$directory/$module_name"
        if [ -f "$candidate" ] && [ ! -L "$candidate" ] && [ -r "$candidate" ]; then
            _patch_configuration_capture_file "$candidate" || return 2
            if { [ "$PATCH_CONFIGURATION_CAPTURE_UID" = 0 ] ||
                 [ "$PATCH_CONFIGURATION_CAPTURE_UID" = "${EUID:-0}" ]; } &&
                [ $((8#$PATCH_CONFIGURATION_CAPTURE_MODE & 0022)) -eq 0 ]; then
                return 0
            fi
            return 2
        fi
    done
    return 1
}

_pam_transaction_group_exists() {
    local group_name="$1"
    local group_file=""
    local name=""
    local password=""
    local gid=""
    local members=""
    local found=0

    _pam_transaction_physical_path_into /etc/group group_file || return 2
    [ -f "$group_file" ] && [ ! -L "$group_file" ] && [ -r "$group_file" ] || return 2
    while IFS=: read -r name password gid members; do
        [ -n "$name" ] && [ -n "$gid" ] || return 2
        case "$gid" in *[!0-9]*) return 2 ;; esac
        [ "$name" != "$group_name" ] || found=$((found + 1))
    done < "$group_file"
    [ "$found" -eq 1 ]
}

_pam_transaction_required_file() {
    local logical_path="$1"
    local physical_path=""

    _pam_transaction_physical_path_into "$logical_path" physical_path || return 2
    [ -e "$physical_path" ] || [ -L "$physical_path" ] || return 1
    _patch_configuration_capture_file "$physical_path" || return 2
}

_pam_transaction_command_is_safe() {
    local path="$1"
    local mode_decimal=0
    local effective_uid="${EUID:-0}"

    [ -x "$path" ] || return 2
    _patch_configuration_capture_file "$path" || return 2
    mode_decimal=$((8#$PATCH_CONFIGURATION_CAPTURE_MODE))
    { [ "$PATCH_CONFIGURATION_CAPTURE_UID" = 0 ] ||
      [ "$PATCH_CONFIGURATION_CAPTURE_UID" = "$effective_uid" ]; } &&
        [ $((mode_decimal & 0022)) -eq 0 ]
}

_pam_transaction_run_authselect() {
    local destination_name="$1"
    local __kisa_pam_authselect_result=""

    shift
    _patch_configuration_valid_destination "$destination_name" || return 2
    [ "$PATCH_CONFIGURATION_ROOT" = / ] || return 125
    _pam_transaction_command_is_safe /usr/bin/authselect || return 127
    __kisa_pam_authselect_result="$(/usr/bin/authselect "$@" 2>/dev/null)" || return $?
    printf -v "$destination_name" '%s' "$__kisa_pam_authselect_result"
}

_pam_transaction_authselect_context() {
    local raw=""
    local token=""
    local profile=""
    local features=""
    local output=""
    local -a tokens=()

    _pam_transaction_run_authselect output check || return 2
    _pam_transaction_run_authselect raw current --raw || return 2
    read -r -a tokens <<< "$raw"
    [ "${#tokens[@]}" -gt 0 ] || return 2
    profile="${tokens[0]}"
    case "$profile" in ''|*[!A-Za-z0-9_./-]*) return 2 ;; esac
    for token in "${tokens[@]:1}"; do
        case "$token" in ''|*[!A-Za-z0-9_-]*) return 2 ;; esac
        case " $features " in *" $token "*) ;; *) features="${features:+$features }$token" ;; esac
    done
    if _pam_transaction_criterion_selected U-03; then
        case " $features " in *' with-faillock '*) ;; *) features="${features:+$features }with-faillock" ;; esac
    fi
    if _pam_transaction_criterion_selected U-02; then
        case " $features " in *' with-pwhistory '*) ;; *) features="${features:+$features }with-pwhistory" ;; esac
    fi
    PAM_TRANSACTION_AUTHSELECT_PROFILE="$profile"
    PAM_TRANSACTION_AUTHSELECT_FEATURES="$features"
}

_pam_transaction_strip_managed_block_into() {
    local input_path="$1"
    local marker="$2"
    local destination_name="$3"
    local begin_marker="# BEGIN KISA CCE MANAGED $marker"
    local end_marker="# END KISA CCE MANAGED $marker"
    local line=""
    local result=""
    local inside=0

    _patch_configuration_valid_destination "$destination_name" || return 2
    [ -f "$input_path" ] && [ ! -L "$input_path" ] && [ -r "$input_path" ] || return 2
    while IFS= read -r line || [ -n "$line" ]; do
        if [ "$line" = "$begin_marker" ]; then
            [ "$inside" -eq 0 ] || return 2
            inside=1
            continue
        fi
        if [ "$line" = "$end_marker" ]; then
            [ "$inside" -eq 1 ] || return 2
            inside=0
            continue
        fi
        [ "$inside" -eq 1 ] || result+="$line"$'\n'
    done < "$input_path"
    [ "$inside" -eq 0 ] || return 2
    printf -v "$destination_name" '%s' "$result"
}

_pam_transaction_strip_managed_block_content_into() {
    local input_content="$1"
    local marker="$2"
    local destination_name="$3"
    local begin_marker="# BEGIN KISA CCE MANAGED $marker"
    local end_marker="# END KISA CCE MANAGED $marker"
    local line=""
    local result=""
    local inside=0

    _patch_configuration_valid_destination "$destination_name" || return 2
    while IFS= read -r line || [ -n "$line" ]; do
        if [ "$line" = "$begin_marker" ]; then
            [ "$inside" -eq 0 ] || return 2
            inside=1
            continue
        fi
        if [ "$line" = "$end_marker" ]; then
            [ "$inside" -eq 1 ] || return 2
            inside=0
            continue
        fi
        [ "$inside" -eq 1 ] || result+="$line"$'\n'
    done <<< "$input_content"
    [ "$inside" -eq 0 ] || return 2
    printf -v "$destination_name" '%s' "$result"
}

_pam_transaction_append_block_into() {
    local input_path="$1"
    local marker="$2"
    local block="$3"
    local destination_name="$4"
    local base=""

    _pam_transaction_strip_managed_block_into "$input_path" "$marker" base || return 2
    while [ "${base%$'\n'}" != "$base" ]; do base="${base%$'\n'}"; done
    printf -v "$destination_name" '%s\n\n# BEGIN KISA CCE MANAGED %s\n%s\n# END KISA CCE MANAGED %s\n' \
        "$base" "$marker" "$block" "$marker"
}

_pam_transaction_login_defs_into() {
    local input_path="$1"
    local destination_name="$2"
    local base=""
    local line=""
    local active=""
    local result=""

    _pam_transaction_strip_managed_block_into "$input_path" U-02-AGING base || return 2
    while IFS= read -r line || [ -n "$line" ]; do
        active="${line#"${line%%[![:space:]]*}"}"
        case "$active" in
            PASS_MAX_DAYS[=[:space:]]*|PASS_MIN_DAYS[=[:space:]]*) continue ;;
        esac
        result+="$line"$'\n'
    done <<< "$base"
    while [ "${result%$'\n'}" != "$result" ]; do result="${result%$'\n'}"; done
    printf -v "$destination_name" '%s\n\n# BEGIN KISA CCE MANAGED U-02-AGING\nPASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\n# END KISA CCE MANAGED U-02-AGING\n' "$result"
}

_pam_transaction_insert_pam_block_into() {
    local input_path="$1"
    local marker="$2"
    local facility="$3"
    local anchor_module="$4"
    local placement="$5"
    local block="$6"
    local forbidden_modules="$7"
    local destination_name="$8"
    local base=""
    local line=""
    local result=""
    local anchor_count=0
    local active=""

    _pam_transaction_strip_managed_block_into "$input_path" "$marker" base || return 2
    while [ "${base%$'\n'}" != "$base" ]; do base="${base%$'\n'}"; done
    while IFS= read -r line || [ -n "$line" ]; do
        active="${line#"${line%%[![:space:]]*}"}"
        if [ -n "$active" ] && [ "${active#\#}" = "$active" ]; then
            case "$active" in
                "$facility"[[:space:]]*"$anchor_module"*|"$facility"[[:space:]]*/*/"$anchor_module"*)
                    anchor_count=$((anchor_count + 1))
                    if [ "$placement" = before ]; then
                        result+="# BEGIN KISA CCE MANAGED $marker"$'\n'"$block"$'\n'"# END KISA CCE MANAGED $marker"$'\n'
                    fi
                    result+="$line"$'\n'
                    if [ "$placement" = after ]; then
                        result+="# BEGIN KISA CCE MANAGED $marker"$'\n'"$block"$'\n'"# END KISA CCE MANAGED $marker"$'\n'
                    fi
                    continue
                    ;;
            esac
            if [ -n "$forbidden_modules" ]; then
                case "$active" in *pam_pwquality.so*|*pam_pwhistory.so*|*pam_faillock.so*|*pam_wheel.so*) return 2 ;; esac
            fi
        fi
        result+="$line"$'\n'
    done <<< "$base"
    [ "$anchor_count" -eq 1 ] || return 2
    printf -v "$destination_name" '%s' "$result"
}

_pam_transaction_insert_common_auth_into() {
    local input_path="$1"
    local destination_name="$2"
    local base=""
    local line=""
    local active=""
    local result=""
    local count=0

    _pam_transaction_strip_managed_block_into "$input_path" U-03-FAILLOCK-PRE base || return 2
    _pam_transaction_strip_managed_block_content_into "$base" U-03-FAILLOCK-POST base || return 2
    while [ "${base%$'\n'}" != "$base" ]; do base="${base%$'\n'}"; done
    while IFS= read -r line || [ -n "$line" ]; do
        active="${line#"${line%%[![:space:]]*}"}"
        if [ -n "$active" ] && [ "${active#\#}" = "$active" ]; then
            case "$active" in *pam_faillock.so*) return 2 ;; esac
            case "$active" in
                auth[[:space:]]*pam_unix.so*|auth[[:space:]]*/*/pam_unix.so*)
                    count=$((count + 1))
                    result+="# BEGIN KISA CCE MANAGED U-03-FAILLOCK-PRE"$'\n'
                    result+=$'auth required pam_faillock.so preauth silent\n'
                    result+="# END KISA CCE MANAGED U-03-FAILLOCK-PRE"$'\n'
                    result+="$line"$'\n'
                    result+="# BEGIN KISA CCE MANAGED U-03-FAILLOCK-POST"$'\n'
                    result+=$'auth [default=die] pam_faillock.so authfail\n'
                    result+=$'auth sufficient pam_faillock.so authsucc\n'
                    result+="# END KISA CCE MANAGED U-03-FAILLOCK-POST"$'\n'
                    continue
                    ;;
            esac
        fi
        result+="$line"$'\n'
    done <<< "$base"
    [ "$count" -eq 1 ] || return 2
    printf -v "$destination_name" '%s' "$result"
}

_pam_transaction_insert_common_password_into() {
    local input_path="$1"
    local destination_name="$2"
    local marker=U-02-PASSWORD
    local base=""
    local line=""
    local active=""
    local result=""
    local anchor_count=0

    _pam_transaction_strip_managed_block_into "$input_path" "$marker" base || return 2
    while [ "${base%$'\n'}" != "$base" ]; do base="${base%$'\n'}"; done
    while IFS= read -r line || [ -n "$line" ]; do
        active="${line#"${line%%[![:space:]]*}"}"
        if [ -n "$active" ] && [ "${active#\#}" = "$active" ]; then
            case "$active" in
                password[[:space:]]*pam_pwquality.so*|password[[:space:]]*/*/pam_pwquality.so*|\
                password[[:space:]]*pam_pwhistory.so*|password[[:space:]]*/*/pam_pwhistory.so*)
                    case "$active" in password[[:space:]]requisite[[:space:]]*|password[[:space:]]required[[:space:]]*) continue ;; *) return 2 ;; esac
                    ;;
                password[[:space:]]*pam_unix.so*|password[[:space:]]*/*/pam_unix.so*)
                    anchor_count=$((anchor_count + 1))
                    result+="# BEGIN KISA CCE MANAGED $marker"$'\n'
                    result+=$'password requisite pam_pwquality.so retry=3\n'
                    result+=$'password required pam_pwhistory.so use_authtok\n'
                    result+="# END KISA CCE MANAGED $marker"$'\n'
                    result+="$line"$'\n'
                    continue
                    ;;
            esac
        fi
        result+="$line"$'\n'
    done <<< "$base"
    [ "$anchor_count" -eq 1 ] || return 2
    printf -v "$destination_name" '%s' "$result"
}

_pam_transaction_authselect_test_into() {
    local selector="$1"
    local destination_name="$2"
    local output=""
    local header=""
    local result=""
    local -a arguments=(test "$PAM_TRANSACTION_AUTHSELECT_PROFILE")
    local feature=""

    _patch_configuration_valid_destination "$destination_name" || return 2
    for feature in $PAM_TRANSACTION_AUTHSELECT_FEATURES; do arguments+=("$feature"); done
    arguments+=("$selector")
    _pam_transaction_run_authselect output "${arguments[@]}" || return 2
    header="${output%%$'\n'*}"
    case "$header:$selector" in
        'File /etc/pam.d/system-auth:'*-s|'File /etc/pam.d/password-auth:'*-p) ;;
        *) return 2 ;;
    esac
    result="${output#*$'\n'}"
    while [ "${result%$'\n'}" != "$result" ]; do result="${result%$'\n'}"; done
    printf -v "$destination_name" '%s\n' "$result"
}

_pam_transaction_authselect_conf_into() {
    local destination_name="$1"
    local result="$PAM_TRANSACTION_AUTHSELECT_PROFILE"$'\n'
    local feature=""

    _patch_configuration_valid_destination "$destination_name" || return 2
    for feature in $PAM_TRANSACTION_AUTHSELECT_FEATURES; do result+="$feature"$'\n'; done
    printf -v "$destination_name" '%s' "$result"
}

_pam_transaction_desired_content_into() {
    local family="$1"
    local approved_group="$2"
    local logical_path="$3"
    local source_path="$4"
    local destination_name="$5"
    local content=""
    local block=""

    _patch_configuration_valid_destination "$destination_name" || return 2
    case "$family:$logical_path" in
        debian:/etc/pam.d/common-password)
            _pam_transaction_insert_common_password_into "$source_path" content || return 2
            ;;
        debian:/etc/pam.d/common-auth)
            _pam_transaction_insert_common_auth_into "$source_path" content || return 2
            ;;
        debian:/etc/pam.d/common-account)
            block='account required pam_faillock.so'
            _pam_transaction_insert_pam_block_into "$source_path" U-03-ACCOUNT account pam_unix.so before \
                "$block" yes content || return 2
            ;;
        debian:/etc/pam.d/su|rhel:/etc/pam.d/su)
            block="auth required pam_wheel.so use_uid group=$approved_group"
            _pam_transaction_insert_pam_block_into "$source_path" U-06-WHEEL auth pam_rootok.so after \
                "$block" yes content || return 2
            ;;
        debian:/etc/login.defs|rhel:/etc/login.defs)
            _pam_transaction_login_defs_into "$source_path" content || return 2
            ;;
        debian:/etc/security/pwquality.conf|rhel:/etc/security/pwquality.conf)
            block=$'minlen = 8\ndcredit = -1\nucredit = -1\nlcredit = -1\nocredit = -1\nenforce_for_root'
            _pam_transaction_append_block_into "$source_path" U-02-PWQUALITY "$block" content || return 2
            ;;
        debian:/etc/security/pwhistory.conf)
            block=$'remember = 4\nenforce_for_root'
            _pam_transaction_append_block_into "$source_path" U-02-PWHISTORY "$block" content || return 2
            ;;
        rhel:/etc/security/pwhistory.conf)
            block=$'remember = 4\nenforce_for_root\nfile = /etc/security/opasswd'
            _pam_transaction_append_block_into "$source_path" U-02-PWHISTORY "$block" content || return 2
            ;;
        debian:/etc/security/faillock.conf|rhel:/etc/security/faillock.conf)
            block='deny = 5'
            _pam_transaction_append_block_into "$source_path" U-03-FAILLOCK "$block" content || return 2
            ;;
        rhel:/etc/authselect/authselect.conf)
            _pam_transaction_authselect_conf_into content || return 2
            ;;
        rhel:/etc/authselect/system-auth)
            _pam_transaction_authselect_test_into -s content || return 2
            ;;
        rhel:/etc/authselect/password-auth)
            _pam_transaction_authselect_test_into -p content || return 2
            ;;
        *) return 1 ;;
    esac
    printf -v "$destination_name" '%s' "$content"
}

_pam_transaction_path_selected() {
    local family="$1"
    local logical_path="$2"

    case "$family:$logical_path" in
        debian:/etc/login.defs|debian:/etc/security/pwquality.conf|\
        debian:/etc/security/pwhistory.conf|debian:/etc/pam.d/common-password|\
        rhel:/etc/login.defs|rhel:/etc/security/pwquality.conf|\
        rhel:/etc/security/pwhistory.conf)
            _pam_transaction_criterion_selected U-02
            ;;
        debian:/etc/security/faillock.conf|debian:/etc/pam.d/common-auth|\
        debian:/etc/pam.d/common-account|rhel:/etc/security/faillock.conf)
            _pam_transaction_criterion_selected U-03
            ;;
        debian:/etc/pam.d/su|rhel:/etc/pam.d/su)
            _pam_transaction_criterion_selected U-06
            ;;
        rhel:/etc/authselect/authselect.conf|rhel:/etc/authselect/system-auth|\
        rhel:/etc/authselect/password-auth)
            _pam_transaction_criterion_selected U-02 ||
                _pam_transaction_criterion_selected U-03
            ;;
        *) return 1 ;;
    esac
}

_pam_transaction_rule_paths() {
    local family="$1"
    local logical_path=""
    local -a paths=()

    case "$family" in
        debian)
            paths=(
                /etc/login.defs
                /etc/security/pwquality.conf
                /etc/security/pwhistory.conf
                /etc/security/faillock.conf
                /etc/pam.d/common-password
                /etc/pam.d/common-auth
                /etc/pam.d/common-account
                /etc/pam.d/su
            )
            ;;
        rhel)
            paths=(
                /etc/login.defs
                /etc/security/pwquality.conf
                /etc/security/pwhistory.conf
                /etc/security/faillock.conf
                /etc/authselect/authselect.conf
                /etc/authselect/system-auth
                /etc/authselect/password-auth
                /etc/pam.d/su
            )
            ;;
        *) return 1 ;;
    esac
    for logical_path in "${paths[@]}"; do
        _pam_transaction_path_selected "$family" "$logical_path" || continue
        printf '%s\n' "$logical_path"
    done
}

_pam_transaction_criterion_for_path_into() {
    local logical_path="$1"
    local destination_name="$2"
    local __kisa_pam_criterion_result=""

    _patch_configuration_valid_destination "$destination_name" || return 2
    case "$PAM_TRANSACTION_FAMILY:$logical_path" in
        rhel:/etc/authselect/authselect.conf|rhel:/etc/authselect/system-auth)
            if _pam_transaction_criterion_selected U-03; then
                __kisa_pam_criterion_result=U-03
            else
                __kisa_pam_criterion_result=U-02
            fi
            ;;
        rhel:/etc/authselect/password-auth)
            if _pam_transaction_criterion_selected U-02; then
                __kisa_pam_criterion_result=U-02
            else
                __kisa_pam_criterion_result=U-03
            fi
            ;;
        *:/etc/pam.d/su) __kisa_pam_criterion_result=U-06 ;;
        *:/etc/security/faillock.conf|*:/etc/pam.d/common-auth|*:/etc/pam.d/common-account)
            __kisa_pam_criterion_result=U-03
            ;;
        *) __kisa_pam_criterion_result=U-02 ;;
    esac
    _pam_transaction_criterion_selected "$__kisa_pam_criterion_result" || return 2
    printf -v "$destination_name" '%s' "$__kisa_pam_criterion_result"
}

_pam_transaction_check_prerequisites() {
    local family="$1"
    local approved_group="$2"
    local module=""
    local logical_path=""
    local status=0

    if _pam_transaction_criterion_selected U-06; then
        case "$approved_group" in
            sudo|wheel) ;;
            *) _pam_transaction_set_prerequisite "unapproved_group:$approved_group"; return 3 ;;
        esac
        status=0
        _pam_transaction_group_exists "$approved_group" || status=$?
        case "$status" in
            0) ;;
            1) _pam_transaction_set_prerequisite "missing_group:$approved_group"; return 3 ;;
            *) _pam_transaction_set_error "group database is unsafe"; return 2 ;;
        esac
    fi
    for module in \
        U-02:pam_pwquality.so \
        U-02:pam_pwhistory.so \
        U-03:pam_faillock.so \
        U-06:pam_wheel.so; do
        _pam_transaction_criterion_selected "${module%%:*}" || continue
        module="${module#*:}"
        status=0
        _pam_transaction_module_available "$module" || status=$?
        case "$status" in
            0) ;;
            1) _pam_transaction_set_prerequisite "missing_module:$module"; return 3 ;;
            *) _pam_transaction_set_error "PAM module path is unsafe: $module"; return 2 ;;
        esac
    done
    while IFS= read -r logical_path; do
        [ -n "$logical_path" ] || continue
        status=0
        _pam_transaction_required_file "$logical_path" || status=$?
        case "$status" in
            0) ;;
            1) _pam_transaction_set_prerequisite "missing_file:$logical_path"; return 3 ;;
            *) _pam_transaction_set_error "required PAM path is unsafe: $logical_path"; return 2 ;;
        esac
    done < <(_pam_transaction_rule_paths "$family")
    if [ "$family" = debian ] && {
        _pam_transaction_criterion_selected U-02 ||
            _pam_transaction_criterion_selected U-03
    }; then
        _pam_transaction_physical_path_into /usr/sbin/pam-auth-update logical_path || return 2
        _pam_transaction_command_is_safe "$logical_path" || {
            _pam_transaction_set_prerequisite missing_command:pam-auth-update
            return 3
        }
    elif [ "$family" = rhel ] && {
        _pam_transaction_criterion_selected U-02 ||
            _pam_transaction_criterion_selected U-03
    }; then
        _pam_transaction_authselect_context || {
            _pam_transaction_set_prerequisite authselect_unmanaged_or_invalid
            return 3
        }
    fi
    PAM_TRANSACTION_PREREQUISITE_RESULT=ready
}

_pam_transaction_discard_data() {
    local rm_command=""

    [ -n "$PATCH_CONFIGURATION_DATA_DIRECTORY" ] || return 0
    case "$PATCH_CONFIGURATION_DATA_DIRECTORY" in "$PATCH_CONFIGURATION_TRANSACTION_DIRECTORY/pam") ;; *) return 2 ;; esac
    _patch_configuration_command_into rm rm_command || return 2
    "$rm_command" -rf "$PATCH_CONFIGURATION_DATA_DIRECTORY"
}

_pam_transaction_create_data() {
    local directory=""

    PATCH_CONFIGURATION_DATA_DIRECTORY="$PATCH_CONFIGURATION_TRANSACTION_DIRECTORY/pam"
    [ ! -e "$PATCH_CONFIGURATION_DATA_DIRECTORY" ] && [ ! -L "$PATCH_CONFIGURATION_DATA_DIRECTORY" ] || return 2
    (umask 077; /bin/mkdir -- "$PATCH_CONFIGURATION_DATA_DIRECTORY" \
        "$PATCH_CONFIGURATION_DATA_DIRECTORY/backups" \
        "$PATCH_CONFIGURATION_DATA_DIRECTORY/payloads" \
        "$PATCH_CONFIGURATION_DATA_DIRECTORY/journal") || return 2
    for directory in "$PATCH_CONFIGURATION_DATA_DIRECTORY" \
        "$PATCH_CONFIGURATION_DATA_DIRECTORY/backups" \
        "$PATCH_CONFIGURATION_DATA_DIRECTORY/payloads" \
        "$PATCH_CONFIGURATION_DATA_DIRECTORY/journal"; do
        _patch_configuration_private_directory_is_safe "$directory" || return 2
    done
}

_pam_transaction_write_context() {
    local context_path="$PATCH_CONFIGURATION_DATA_DIRECTORY/context.tsv"

    _patch_configuration_create_private_file "$context_path" || return 2
    {
        printf '%s\n' "$PAM_TRANSACTION_CONTEXT_HEADER"
        printf '2\t%s\t%s\t%s\t%s\t%s\n' "$PAM_TRANSACTION_FAMILY" \
            "$PAM_TRANSACTION_APPROVED_GROUP" "$PAM_TRANSACTION_AUTHSELECT_PROFILE" \
            "${PAM_TRANSACTION_AUTHSELECT_FEATURES// /,}" "$PAM_TRANSACTION_CRITERIA"
    } > "$context_path" || return 2
    /bin/chmod 0600 "$context_path" || return 2
    _patch_configuration_capture_file "$context_path" || return 2
    [ "$PATCH_CONFIGURATION_CAPTURE_UID" = "${EUID:-0}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_MODE" = 0600 ]
}

_pam_transaction_plan_path() {
    local criterion="$1"
    local logical_path="$2"
    local desired_content="$3"
    local index="${#PATCH_CONFIGURATION_CRITERIA[@]}"
    local record_number=0
    local parent_path=""
    local physical_path=""
    local parent_device=""
    local parent_inode=""
    local before_device=""
    local before_inode=""
    local before_uid=""
    local before_gid=""
    local before_mode=""
    local before_size=""
    local before_mtime=""
    local before_ctime=""
    local before_sha256=""
    local desired_mode=""
    local backup_name=""
    local payload_name=""
    local backup_sha256=""
    local payload_sha256=""

    case " ${PATCH_CONFIGURATION_LOGICAL_PATHS[*]} " in *" $logical_path "*) return 2 ;; esac
    _patch_configuration_resolve_parent_into "$logical_path" parent_path physical_path || return 2
    _patch_configuration_directory_identity_into "$parent_path" parent_device parent_inode || return 2
    _patch_configuration_capture_file "$physical_path" || return 2
    before_device="$PATCH_CONFIGURATION_CAPTURE_DEVICE"
    before_inode="$PATCH_CONFIGURATION_CAPTURE_INODE"
    before_uid="$PATCH_CONFIGURATION_CAPTURE_UID"
    before_gid="$PATCH_CONFIGURATION_CAPTURE_GID"
    before_mode="$PATCH_CONFIGURATION_CAPTURE_MODE"
    before_size="$PATCH_CONFIGURATION_CAPTURE_SIZE"
    before_mtime="$PATCH_CONFIGURATION_CAPTURE_MTIME"
    before_ctime="$PATCH_CONFIGURATION_CAPTURE_CTIME"
    before_sha256="$PATCH_CONFIGURATION_CAPTURE_SHA256"
    printf -v desired_mode '%04o' "$((8#$before_mode & 8#0644))"
    printf -v record_number '%06d' "$((index + 1))"
    backup_name="backups/$record_number"
    payload_name="payloads/$record_number"
    _patch_configuration_copy_backup "$physical_path" "$PATCH_CONFIGURATION_DATA_DIRECTORY/$backup_name" || return 2
    _patch_configuration_sha256_into "$PATCH_CONFIGURATION_DATA_DIRECTORY/$backup_name" backup_sha256 || return 2
    [ "$backup_sha256" = "$before_sha256" ] || return 2
    _patch_configuration_write_payload "$PATCH_CONFIGURATION_DATA_DIRECTORY/$payload_name" "$desired_content" || return 2
    _patch_configuration_sha256_into "$PATCH_CONFIGURATION_DATA_DIRECTORY/$payload_name" payload_sha256 || return 2
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
    _patch_configuration_append_record "$criterion" "$logical_path" "$physical_path" "$parent_path" \
        "$parent_device" "$parent_inode" present "$before_device" "$before_inode" \
        "$before_uid" "$before_gid" "$before_mode" "$before_size" "$before_mtime" \
        "$before_ctime" "$before_sha256" 0 0 "$desired_mode" "$payload_sha256" \
        "$backup_name" "$payload_name"
}

pam_transaction_reset() {
    patch_configuration_reset
    PAM_TRANSACTION_ROOT=""
    PAM_TRANSACTION_FAMILY=""
    PAM_TRANSACTION_APPROVED_GROUP=""
    PAM_TRANSACTION_AUTHSELECT_PROFILE=-
    PAM_TRANSACTION_AUTHSELECT_FEATURES=-
    PAM_TRANSACTION_CRITERIA=""
    PAM_TRANSACTION_PREREQUISITE_RESULT=unresolved
    PAM_TRANSACTION_ERROR_DETAIL=""
    PAM_TRANSACTION_VERIFIED=0
}

pam_transaction_plan() {
    local requested_root="$1"
    local transaction_directory="$2"
    local approved_group="$3"
    local logical_path=""
    local physical_path=""
    local desired_content=""
    local criterion=""
    local prerequisite_status=0

    shift 3
    pam_transaction_reset
    _pam_transaction_set_criteria "$@" || {
        _pam_transaction_set_error "invalid or duplicate PAM criterion"
        return 2
    }
    _patch_configuration_initialize_root "$requested_root" || {
        _pam_transaction_set_error "PAM transaction root is unsafe: $requested_root"
        return 2
    }
    PAM_TRANSACTION_ROOT="$PATCH_CONFIGURATION_ROOT"
    _pam_transaction_detect_family_into "$PATCH_CONFIGURATION_ROOT" PAM_TRANSACTION_FAMILY || {
        _pam_transaction_set_prerequisite unsupported_platform
        return 3
    }
    if _pam_transaction_criterion_selected U-06; then
        PAM_TRANSACTION_APPROVED_GROUP="$approved_group"
    else
        PAM_TRANSACTION_APPROVED_GROUP=-
    fi
    _patch_configuration_transaction_directory_is_safe "$transaction_directory" || {
        _pam_transaction_set_error "PAM transaction directory is unsafe: $transaction_directory"
        return 2
    }
    PATCH_CONFIGURATION_TRANSACTION_DIRECTORY="$(CDPATH='' builtin cd -P -- "$transaction_directory" && pwd -P)" || return 2
    _pam_transaction_check_prerequisites "$PAM_TRANSACTION_FAMILY" \
        "$PAM_TRANSACTION_APPROVED_GROUP" || prerequisite_status=$?
    [ "$prerequisite_status" -eq 0 ] || return "$prerequisite_status"
    _pam_transaction_create_data || {
        _pam_transaction_discard_data >/dev/null 2>&1 || :
        _pam_transaction_set_error "cannot create protected PAM transaction data"
        return 2
    }
    while IFS= read -r logical_path; do
        [ -n "$logical_path" ] || continue
        _pam_transaction_physical_path_into "$logical_path" physical_path || {
            _pam_transaction_discard_data >/dev/null 2>&1 || :
            return 2
        }
        _pam_transaction_criterion_for_path_into "$logical_path" criterion || return 2
        _pam_transaction_desired_content_into "$PAM_TRANSACTION_FAMILY" \
            "$PAM_TRANSACTION_APPROVED_GROUP" \
            "$logical_path" "$physical_path" desired_content || {
                _pam_transaction_discard_data >/dev/null 2>&1 || :
                _pam_transaction_set_error "cannot create a safe PAM payload for $logical_path"
                return 2
            }
        _pam_transaction_plan_path "$criterion" "$logical_path" "$desired_content" || {
            _pam_transaction_discard_data >/dev/null 2>&1 || :
            _pam_transaction_set_error "cannot safely back up and plan $logical_path"
            return 2
        }
    done < <(_pam_transaction_rule_paths "$PAM_TRANSACTION_FAMILY")
    _patch_configuration_write_manifest || {
        _pam_transaction_discard_data >/dev/null 2>&1 || :
        _pam_transaction_set_error "cannot write PAM transaction manifest"
        return 2
    }
    _pam_transaction_write_context || {
        _pam_transaction_discard_data >/dev/null 2>&1 || :
        _pam_transaction_set_error "cannot write PAM transaction context"
        return 2
    }
    PATCH_CONFIGURATION_PLAN_VALID=1
}

pam_transaction_state_into() {
    local criterion="$1"
    local destination_name="$2"
    local index=0
    local found=0
    local state=compliant

    _patch_configuration_valid_destination "$destination_name" || return 2
    case "$criterion" in U-02|U-03|U-06) ;; *) return 1 ;; esac
    while [ "$index" -lt "${#PATCH_CONFIGURATION_CRITERIA[@]}" ]; do
        if [ "${PATCH_CONFIGURATION_CRITERIA[$index]}" = "$criterion" ]; then
            found=1
            if [ "$PAM_TRANSACTION_VERIFIED" -eq 1 ]; then
                state=verified
            elif [ "${PATCH_CONFIGURATION_TARGET_STATES[$index]}" = ready ]; then
                state=ready
            fi
        fi
        index=$((index + 1))
    done
    [ "$found" -eq 1 ] || return 1
    printf -v "$destination_name" '%s' "$state"
}

pam_transaction_write_plan_tsv() {
    patch_configuration_write_plan_tsv "$1"
}

_pam_transaction_file_contains_line() {
    local logical_path="$1"
    local expected_line="$2"
    local physical_path=""
    local line=""
    local count=0

    _pam_transaction_physical_path_into "$logical_path" physical_path || return 2
    [ -f "$physical_path" ] && [ ! -L "$physical_path" ] && [ -r "$physical_path" ] || return 2
    while IFS= read -r line || [ -n "$line" ]; do
        [ "$line" != "$expected_line" ] || count=$((count + 1))
    done < "$physical_path"
    [ "$count" -eq 1 ]
}

_pam_transaction_validate_debian_desired() {
    local line=""

    if _pam_transaction_criterion_selected U-02; then
        for line in \
            'password requisite pam_pwquality.so retry=3' \
            'password required pam_pwhistory.so use_authtok'; do
            _pam_transaction_file_contains_line /etc/pam.d/common-password "$line" || return 2
        done
        _pam_transaction_file_contains_line /etc/login.defs 'PASS_MAX_DAYS 90' || return 2
        _pam_transaction_file_contains_line /etc/login.defs 'PASS_MIN_DAYS 1' || return 2
        _pam_transaction_file_contains_line /etc/security/pwquality.conf 'minlen = 8' || return 2
        _pam_transaction_file_contains_line /etc/security/pwquality.conf 'dcredit = -1' || return 2
        _pam_transaction_file_contains_line /etc/security/pwquality.conf 'ucredit = -1' || return 2
        _pam_transaction_file_contains_line /etc/security/pwquality.conf 'lcredit = -1' || return 2
        _pam_transaction_file_contains_line /etc/security/pwquality.conf 'ocredit = -1' || return 2
        _pam_transaction_file_contains_line /etc/security/pwquality.conf enforce_for_root || return 2
        _pam_transaction_file_contains_line /etc/security/pwhistory.conf 'remember = 4' || return 2
        _pam_transaction_file_contains_line /etc/security/pwhistory.conf enforce_for_root || return 2
    fi
    if _pam_transaction_criterion_selected U-03; then
        for line in \
            'auth required pam_faillock.so preauth silent' \
            'auth [default=die] pam_faillock.so authfail' \
            'auth sufficient pam_faillock.so authsucc'; do
            _pam_transaction_file_contains_line /etc/pam.d/common-auth "$line" || return 2
        done
        _pam_transaction_file_contains_line /etc/pam.d/common-account \
            'account required pam_faillock.so' || return 2
        _pam_transaction_file_contains_line /etc/security/faillock.conf 'deny = 5' || return 2
    fi
    if _pam_transaction_criterion_selected U-06; then
        _pam_transaction_file_contains_line /etc/pam.d/su \
            "auth required pam_wheel.so use_uid group=$PAM_TRANSACTION_APPROVED_GROUP" || return 2
    fi
}

_pam_transaction_validate_rhel_desired() {
    local output=""
    local raw=""
    local expected="$PAM_TRANSACTION_AUTHSELECT_PROFILE"
    local feature=""

    if _pam_transaction_criterion_selected U-02 ||
        _pam_transaction_criterion_selected U-03; then
        _pam_transaction_run_authselect output check || return 2
        _pam_transaction_run_authselect raw current --raw || return 2
        for feature in $PAM_TRANSACTION_AUTHSELECT_FEATURES; do expected+=" $feature"; done
        [ "$raw" = "$expected" ] || return 2
    fi
    if _pam_transaction_criterion_selected U-02; then
        _pam_transaction_file_contains_line /etc/login.defs 'PASS_MAX_DAYS 90' || return 2
        _pam_transaction_file_contains_line /etc/login.defs 'PASS_MIN_DAYS 1' || return 2
        _pam_transaction_file_contains_line /etc/security/pwquality.conf 'minlen = 8' || return 2
        _pam_transaction_file_contains_line /etc/security/pwhistory.conf 'remember = 4' || return 2
        _pam_transaction_file_contains_line /etc/security/pwhistory.conf \
            'file = /etc/security/opasswd' || return 2
    fi
    if _pam_transaction_criterion_selected U-03; then
        _pam_transaction_file_contains_line /etc/security/faillock.conf 'deny = 5' || return 2
    fi
    if _pam_transaction_criterion_selected U-06; then
        _pam_transaction_file_contains_line /etc/pam.d/su \
            "auth required pam_wheel.so use_uid group=$PAM_TRANSACTION_APPROVED_GROUP" || return 2
    fi
}

_pam_transaction_validate_original_native() {
    local output=""
    local logical_path=""
    local physical_path=""
    local facility=""
    local module=""
    local count=0
    local line=""

    if [ "$PAM_TRANSACTION_FAMILY" = rhel ] && {
        _pam_transaction_criterion_selected U-02 ||
            _pam_transaction_criterion_selected U-03
    }; then
        _pam_transaction_run_authselect output check || return 2
    fi
    for logical_path in /etc/pam.d/common-password /etc/pam.d/common-auth /etc/pam.d/common-account; do
        case "$logical_path" in
            */common-password)
                if [ "$PAM_TRANSACTION_FAMILY" != debian ] ||
                    ! _pam_transaction_criterion_selected U-02; then
                    continue
                fi
                facility=password
                ;;
            */common-auth)
                if [ "$PAM_TRANSACTION_FAMILY" != debian ] ||
                    ! _pam_transaction_criterion_selected U-03; then
                    continue
                fi
                facility=auth
                ;;
            *)
                if [ "$PAM_TRANSACTION_FAMILY" != debian ] ||
                    ! _pam_transaction_criterion_selected U-03; then
                    continue
                fi
                facility=account
                ;;
        esac
        module=pam_unix.so
        count=0
        _pam_transaction_physical_path_into "$logical_path" physical_path || return 2
        while IFS= read -r line || [ -n "$line" ]; do
            line="${line#"${line%%[![:space:]]*}"}"
            case "$line" in
                \#*|'') ;;
                "$facility"[[:space:]]*"$module"*) count=$((count + 1)) ;;
            esac
        done < "$physical_path"
        [ "$count" -eq 1 ] || return 2
    done
    if _pam_transaction_criterion_selected U-06; then
        logical_path=/etc/pam.d/su
        facility=auth
        module=pam_rootok.so
        count=0
        _pam_transaction_physical_path_into "$logical_path" physical_path || return 2
        while IFS= read -r line || [ -n "$line" ]; do
            line="${line#"${line%%[![:space:]]*}"}"
            case "$line" in
                \#*|'') ;;
                "$facility"[[:space:]]*"$module"*) count=$((count + 1)) ;;
            esac
        done < "$physical_path"
        [ "$count" -eq 1 ] || return 2
    fi
}

pam_transaction_verify() {
    patch_configuration_verify || {
        PAM_TRANSACTION_ERROR_DETAIL="$PATCH_CONFIGURATION_ERROR_DETAIL"
        return 2
    }
    case "$PAM_TRANSACTION_FAMILY" in
        debian) _pam_transaction_validate_debian_desired || return 2 ;;
        rhel) _pam_transaction_validate_rhel_desired || return 2 ;;
        *) return 2 ;;
    esac
    PAM_TRANSACTION_VERIFIED=1
}

_pam_transaction_refresh_after_move() {
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

pam_transaction_apply() {
    local index=0
    local rollback_status=0

    [ "${EUID:-$(id -u)}" -eq 0 ] && [ "$PATCH_CONFIGURATION_PLAN_VALID" -eq 1 ] || {
        _pam_transaction_set_error "PAM apply requires effective UID 0 and a valid plan"
        return 2
    }
    _patch_configuration_verify_root && _patch_configuration_artifacts_are_valid || return 2
    while [ "$index" -lt "${#PATCH_CONFIGURATION_CRITERIA[@]}" ]; do
        _patch_configuration_current_matches_before "$index" || return 2
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_CONFIGURATION_CRITERIA[@]}" ]; do
        if [ "${PATCH_CONFIGURATION_TARGET_STATES[$index]}" = compliant ]; then
            _patch_configuration_set_after_from_before "$index" || return 2
        else
            _patch_configuration_stage_payload "$index" || {
                _patch_configuration_cleanup_stages >/dev/null 2>&1 || :
                return 2
            }
        fi
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_CONFIGURATION_CRITERIA[@]}" ]; do
        _patch_configuration_current_matches_before "$index" || {
            _patch_configuration_cleanup_stages >/dev/null 2>&1 || :
            return 2
        }
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_CONFIGURATION_CRITERIA[@]}" ]; do
        if [ "${PATCH_CONFIGURATION_TARGET_STATES[$index]}" = ready ]; then
            _patch_configuration_move_into_place "${PATCH_CONFIGURATION_STAGE_PATHS[$index]}" \
                "${PATCH_CONFIGURATION_PHYSICAL_PATHS[$index]}" || {
                    _patch_configuration_apply_failure "cannot install PAM payload"
                    return 2
                }
            PATCH_CONFIGURATION_STAGE_PATHS[$index]=""
            _pam_transaction_refresh_after_move "$index" || {
                _patch_configuration_apply_failure "installed PAM payload failed verification"
                return 2
            }
        fi
        index=$((index + 1))
    done
    patch_configuration_verify || {
        _patch_configuration_apply_failure "$PATCH_CONFIGURATION_ERROR_DETAIL"
        return 2
    }
    PATCH_CONFIGURATION_VERIFIED=1
    pam_transaction_verify || {
        patch_configuration_rollback transition >/dev/null 2>&1 || rollback_status=$?
        if [ "$rollback_status" -eq 0 ]; then
            PAM_TRANSACTION_ERROR_DETAIL="PAM native validation failed; automatic rollback completed"
        else
            PAM_TRANSACTION_ERROR_DETAIL="PAM native validation failed; automatic rollback failed"
        fi
        return 2
    }
}

pam_transaction_rollback() {
    local policy="${1:-strict}"

    patch_configuration_rollback "$policy" || {
        PAM_TRANSACTION_ERROR_DETAIL="$PATCH_CONFIGURATION_ERROR_DETAIL"
        return 2
    }
    _pam_transaction_validate_original_native || {
        _pam_transaction_set_error "restored PAM configuration failed native validation"
        return 2
    }
    PAM_TRANSACTION_VERIFIED=0
}

_pam_transaction_path_is_allowed() {
    local family="$1"
    local requested_path="$2"
    local candidate=""

    while IFS= read -r candidate; do
        [ "$candidate" != "$requested_path" ] || return 0
    done < <(_pam_transaction_rule_paths "$family")
    return 1
}

_pam_transaction_load_context() {
    local context_path="$PATCH_CONFIGURATION_DATA_DIRECTORY/context.tsv"
    local header=""
    local schema=""
    local family=""
    local approved_group=""
    local profile=""
    local features=""
    local criteria=""
    local extra=""
    local extra_line=""
    local detected_family=""
    local feature=""
    local seen_features=$'\n'
    local -a criterion_tokens=()

    _patch_configuration_capture_file "$context_path" || return 2
    [ "$PATCH_CONFIGURATION_CAPTURE_UID" = "${EUID:-0}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_MODE" = 0600 ] || return 2
    {
        IFS= read -r header || return 2
        IFS=$'\t' read -r schema family approved_group profile features criteria extra || return 2
        if IFS= read -r extra_line; then return 2; fi
    } < "$context_path"
    [ "$header" = "$PAM_TRANSACTION_CONTEXT_HEADER" ] && [ "$schema" = 2 ] && [ -z "$extra" ] || return 2
    case "$family" in debian|rhel) ;; *) return 2 ;; esac
    IFS=, read -r -a criterion_tokens <<< "$criteria"
    _pam_transaction_set_criteria "${criterion_tokens[@]}" || return 2
    [ "$PAM_TRANSACTION_CRITERIA" = "$criteria" ] || return 2
    if _pam_transaction_criterion_selected U-06; then
        case "$approved_group" in sudo|wheel) ;; *) return 2 ;; esac
    else
        [ "$approved_group" = - ] || return 2
    fi
    _pam_transaction_detect_family_into "$PATCH_CONFIGURATION_ROOT" detected_family || return 2
    [ "$detected_family" = "$family" ] || return 2
    PAM_TRANSACTION_FAMILY="$family"
    PAM_TRANSACTION_APPROVED_GROUP="$approved_group"
    PAM_TRANSACTION_AUTHSELECT_PROFILE="$profile"
    if [ "$features" = - ]; then
        PAM_TRANSACTION_AUTHSELECT_FEATURES=-
    else
        case "$features" in ''|,*|*,|*,,*|*[!A-Za-z0-9_,-]*) return 2 ;; esac
        PAM_TRANSACTION_AUTHSELECT_FEATURES="${features//,/ }"
        for feature in $PAM_TRANSACTION_AUTHSELECT_FEATURES; do
            case "$seen_features" in *$'\n'"$feature"$'\n'*) return 2 ;; esac
            seen_features+="$feature"$'\n'
        done
    fi
    if [ "$family" = rhel ] && {
        _pam_transaction_criterion_selected U-02 ||
            _pam_transaction_criterion_selected U-03
    }; then
        case "$profile" in ''|-|*[!A-Za-z0-9_./-]*) return 2 ;; esac
        if _pam_transaction_criterion_selected U-03; then
            case " $PAM_TRANSACTION_AUTHSELECT_FEATURES " in
                *' with-faillock '*) ;;
                *) return 2 ;;
            esac
        fi
        if _pam_transaction_criterion_selected U-02; then
            case " $PAM_TRANSACTION_AUTHSELECT_FEATURES " in
                *' with-pwhistory '*) ;;
                *) return 2 ;;
            esac
        fi
    else
        [ "$profile:$features" = '-:-' ] || return 2
    fi
}

pam_transaction_load_transaction() {
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
    local backup_name=""
    local payload_name=""
    local extra=""
    local parent_path=""
    local physical_path=""
    local actual_parent_device=""
    local actual_parent_inode=""
    local expected_backup_name=""
    local expected_payload_name=""
    local expected_mode=""
    local expected_content=""
    local payload_content=""
    local backup_path=""
    local payload_path=""
    local expected_criterion=""
    local selected_criterion=""
    local selected_found=0
    local seen_paths=$'\n'
    local index=0
    local expected_record_count=0
    local journal_status=0

    case "$load_mode" in planned|applied) ;; *) return 2 ;; esac
    pam_transaction_reset
    _patch_configuration_initialize_root "$requested_root" || {
        _pam_transaction_set_error "PAM rollback root is unsafe: $requested_root"
        return 2
    }
    PAM_TRANSACTION_ROOT="$PATCH_CONFIGURATION_ROOT"
    _patch_configuration_transaction_directory_is_safe "$transaction_directory" || return 2
    PATCH_CONFIGURATION_TRANSACTION_DIRECTORY="$(CDPATH='' builtin cd -P -- "$transaction_directory" && pwd -P)" || return 2
    PATCH_CONFIGURATION_DATA_DIRECTORY="$PATCH_CONFIGURATION_TRANSACTION_DIRECTORY/pam"
    for physical_path in "$PATCH_CONFIGURATION_DATA_DIRECTORY" \
        "$PATCH_CONFIGURATION_DATA_DIRECTORY/backups" \
        "$PATCH_CONFIGURATION_DATA_DIRECTORY/payloads" \
        "$PATCH_CONFIGURATION_DATA_DIRECTORY/journal"; do
        _patch_configuration_private_directory_is_safe "$physical_path" || return 2
    done
    _pam_transaction_load_context || return 2
    manifest_path="$PATCH_CONFIGURATION_DATA_DIRECTORY/manifest.tsv"
    _patch_configuration_capture_file "$manifest_path" || return 2
    [ "$PATCH_CONFIGURATION_CAPTURE_UID" = "${EUID:-0}" ] &&
        [ "$PATCH_CONFIGURATION_CAPTURE_MODE" = 0600 ] || return 2
    PATCH_CONFIGURATION_MANIFEST_DEVICE="$PATCH_CONFIGURATION_CAPTURE_DEVICE"
    PATCH_CONFIGURATION_MANIFEST_INODE="$PATCH_CONFIGURATION_CAPTURE_INODE"
    PATCH_CONFIGURATION_MANIFEST_SHA256="$PATCH_CONFIGURATION_CAPTURE_SHA256"
    IFS= read -r header < "$manifest_path" || return 2
    [ "$header" = "$PATCH_CONFIGURATION_MANIFEST_HEADER" ] || return 2
    while IFS=$'\t' read -r schema criterion logical_path root_device root_inode \
        parent_device parent_inode before_state before_device before_inode before_uid before_gid \
        before_mode before_size before_mtime before_ctime before_sha256 desired_uid desired_gid \
        desired_mode desired_sha256 backup_name payload_name extra; do
        [ -n "$schema" ] || continue
        [ "$schema" = 1 ] && [ -z "$extra" ] && [ "$before_state" = present ] || return 2
        [ "$root_device" = "$PATCH_CONFIGURATION_ROOT_DEVICE" ] &&
            [ "$root_inode" = "$PATCH_CONFIGURATION_ROOT_INODE" ] || return 2
        _pam_transaction_path_is_allowed "$PAM_TRANSACTION_FAMILY" "$logical_path" || return 2
        _pam_transaction_criterion_for_path_into "$logical_path" expected_criterion || return 2
        [ "$criterion" = "$expected_criterion" ] || return 2
        case "$seen_paths" in *$'\n'"$logical_path"$'\n'*) return 2 ;; esac
        seen_paths+="$logical_path"$'\n'
        _patch_configuration_resolve_parent_into "$logical_path" parent_path physical_path || return 2
        _patch_configuration_directory_identity_into "$parent_path" actual_parent_device actual_parent_inode || return 2
        [ "$parent_device" = "$actual_parent_device" ] && [ "$parent_inode" = "$actual_parent_inode" ] || return 2
        printf -v expected_backup_name 'backups/%06d' "$((index + 1))"
        printf -v expected_payload_name 'payloads/%06d' "$((index + 1))"
        [ "$backup_name" = "$expected_backup_name" ] && [ "$payload_name" = "$expected_payload_name" ] || return 2
        case "$before_device:$before_inode:$before_uid:$before_gid:$before_size:$before_mtime:$before_ctime:$desired_uid:$desired_gid" in
            *[!0-9:]*) return 2 ;;
        esac
        case "$before_mode:$desired_mode" in *[!0-7:]*) return 2 ;; esac
        printf -v before_mode '%04o' "$((8#$before_mode))"
        printf -v desired_mode '%04o' "$((8#$desired_mode))"
        printf -v expected_mode '%04o' "$((8#$before_mode & 8#0644))"
        [ "$desired_uid:$desired_gid:$desired_mode" = "0:0:$expected_mode" ] || return 2
        [ "${#before_sha256}" -eq 64 ] && [ "${#desired_sha256}" -eq 64 ] || return 2
        case "$before_sha256:$desired_sha256" in *[!0-9a-f:]*) return 2 ;; esac
        backup_path="$PATCH_CONFIGURATION_DATA_DIRECTORY/$backup_name"
        payload_path="$PATCH_CONFIGURATION_DATA_DIRECTORY/$payload_name"
        _patch_configuration_sha256_into "$backup_path" expected_mode || return 2
        [ "$expected_mode" = "$before_sha256" ] || return 2
        _patch_configuration_sha256_into "$payload_path" expected_mode || return 2
        [ "$expected_mode" = "$desired_sha256" ] || return 2
        _pam_transaction_desired_content_into "$PAM_TRANSACTION_FAMILY" "$PAM_TRANSACTION_APPROVED_GROUP" \
            "$logical_path" "$backup_path" expected_content || return 2
        payload_content="$(< "$payload_path")"
        while [ "${expected_content%$'\n'}" != "$expected_content" ]; do expected_content="${expected_content%$'\n'}"; done
        [ "$payload_content" = "$expected_content" ] || return 2
        _patch_configuration_append_record "$criterion" "$logical_path" "$physical_path" "$parent_path" \
            "$parent_device" "$parent_inode" present "$before_device" "$before_inode" \
            "$before_uid" "$before_gid" "$before_mode" "$before_size" "$before_mtime" "$before_ctime" \
            "$before_sha256" "$desired_uid" "$desired_gid" "$desired_mode" "$desired_sha256" \
            "$backup_name" "$payload_name"
        index=$((index + 1))
    done < <(sed -n '2,$p' "$manifest_path")
    while IFS= read -r logical_path; do
        [ -n "$logical_path" ] || continue
        expected_record_count=$((expected_record_count + 1))
    done < <(_pam_transaction_rule_paths "$PAM_TRANSACTION_FAMILY")
    [ "$expected_record_count" -gt 0 ] && [ "$index" -eq "$expected_record_count" ] || return 2
    for selected_criterion in U-02 U-03 U-06; do
        _pam_transaction_criterion_selected "$selected_criterion" || continue
        selected_found=0
        for criterion in "${PATCH_CONFIGURATION_CRITERIA[@]}"; do
            [ "$criterion" != "$selected_criterion" ] || selected_found=1
        done
        [ "$selected_found" -eq 1 ] || return 2
    done
    _patch_configuration_manifest_is_unchanged || return 2
    _patch_configuration_artifacts_are_valid || return 2
    index=0
    while [ "$index" -lt "${#PATCH_CONFIGURATION_CRITERIA[@]}" ]; do
        journal_status=0
        _patch_configuration_load_journal "$index" || journal_status=$?
        [ "$journal_status" -eq 0 ] || [ "$load_mode:$journal_status" = planned:1 ] || return 2
        index=$((index + 1))
    done
    PATCH_CONFIGURATION_PLAN_VALID=1
    PAM_TRANSACTION_PREREQUISITE_RESULT=ready
    [ "$load_mode" = planned ] || PAM_TRANSACTION_VERIFIED=1
}

pam_transaction_rollback_transaction() {
    local root="$1"
    local transaction_directory="$2"
    local policy="${3:-strict}"

    pam_transaction_load_transaction "$root" "$transaction_directory" || {
        [ -n "$PAM_TRANSACTION_ERROR_DETAIL" ] || PAM_TRANSACTION_ERROR_DETAIL="invalid PAM rollback transaction"
        return 2
    }
    pam_transaction_rollback "$policy"
}
