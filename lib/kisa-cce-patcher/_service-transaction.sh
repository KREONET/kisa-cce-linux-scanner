# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash
# shellcheck disable=SC2034

# This adapter disables explicitly approved legacy network services as one transaction.

PATCH_SERVICE_SUPPORTED_CRITERIA=(U-34 U-36 U-38 U-41 U-43 U-44 U-52 U-54 U-58)
PATCH_SERVICE_ERROR_DETAIL=""
PATCH_SERVICE_ROOT=""
PATCH_SERVICE_ROOT_DEVICE=""
PATCH_SERVICE_ROOT_INODE=""
PATCH_SERVICE_TRANSACTION_DIRECTORY=""
PATCH_SERVICE_DATA_DIRECTORY=""
PATCH_SERVICE_PLAN_VALID=0
PATCH_SERVICE_APPLY_STARTED=0
PATCH_SERVICE_VERIFIED=0
PATCH_SERVICE_CHANGE_COUNT=0
PATCH_SERVICE_COMPLIANT_COUNT=0
PATCH_SERVICE_TRANSACTION_STATE=""
PATCH_SERVICE_TRANSACTION_LOADED=0
PATCH_SERVICE_LOAD_MODE=strict
PATCH_SERVICE_SNAPSHOT_PATH=""
PATCH_SERVICE_INTERNAL_PLAN_PATH=""
PATCH_SERVICE_CHECKSUM_PATH=""

declare -A PATCH_SERVICE_INTENT_DECISIONS=()
declare -A PATCH_SERVICE_INTENT_APPROVALS=()
declare -A PATCH_SERVICE_CRITERION_STATES=()
declare -A PATCH_SERVICE_CRITERION_CHANGES=()
declare -A PATCH_SERVICE_UNIT_SEEN=()
declare -A PATCH_SERVICE_CHECKSUM_RELATIVES=()

PATCH_SERVICE_SELECTED_CRITERIA=()
PATCH_SERVICE_UNIT_CRITERIA=()
PATCH_SERVICE_UNIT_NAMES=()
PATCH_SERVICE_UNIT_IDS=()
PATCH_SERVICE_UNIT_ALIASES=()
PATCH_SERVICE_UNIT_LOAD_STATES=()
PATCH_SERVICE_UNIT_ACTIVE_STATES=()
PATCH_SERVICE_UNIT_SUB_STATES=()
PATCH_SERVICE_UNIT_FILE_STATES=()
PATCH_SERVICE_UNIT_FRAGMENTS=()
PATCH_SERVICE_UNIT_DROPINS=()
PATCH_SERVICE_UNIT_TRIGGERS=()
PATCH_SERVICE_UNIT_TRIGGERED_BY=()
PATCH_SERVICE_UNIT_APPLIED=()

PATCH_SERVICE_SYSV_CRITERIA=()
PATCH_SERVICE_SYSV_NAMES=()
PATCH_SERVICE_SYSV_ACTIVE=()
PATCH_SERVICE_SYSV_LINK_RECORDS=()
PATCH_SERVICE_SYSV_APPLIED=()

PATCH_SERVICE_FILE_CRITERIA=()
PATCH_SERVICE_FILE_KINDS=()
PATCH_SERVICE_FILE_PATHS=()
PATCH_SERVICE_FILE_DEVICES=()
PATCH_SERVICE_FILE_INODES=()
PATCH_SERVICE_FILE_UIDS=()
PATCH_SERVICE_FILE_GIDS=()
PATCH_SERVICE_FILE_MODES=()
PATCH_SERVICE_FILE_SIZES=()
PATCH_SERVICE_FILE_MTIMES=()
PATCH_SERVICE_FILE_CTIMES=()
PATCH_SERVICE_FILE_SHA256S=()
PATCH_SERVICE_FILE_BACKUPS=()
PATCH_SERVICE_FILE_PAYLOADS=()
PATCH_SERVICE_FILE_DESIRED_SHA256S=()
PATCH_SERVICE_FILE_AFTER_DEVICES=()
PATCH_SERVICE_FILE_AFTER_INODES=()
PATCH_SERVICE_FILE_APPLIED=()
PATCH_SERVICE_FILE_WRITE_COMPLETED=()

PATCH_SERVICE_ENDPOINT_CRITERIA=()
PATCH_SERVICE_ENDPOINT_TRANSPORTS=()
PATCH_SERVICE_ENDPOINT_PORTS=()
PATCH_SERVICE_ENDPOINT_BEFORE=()
PATCH_SERVICE_PROCESS_CRITERIA=()
PATCH_SERVICE_PROCESS_NAMES=()
PATCH_SERVICE_PROCESS_BEFORE=()

_patch_service_set_error() {
    PATCH_SERVICE_ERROR_DETAIL="$1"
    PATCH_SERVICE_PLAN_VALID=0
    return 2
}

_patch_service_valid_criterion() {
    case "$1" in
        U-34|U-36|U-38|U-41|U-43|U-44|U-52|U-54|U-58) return 0 ;;
        *) return 1 ;;
    esac
}

patch_service_supported_criteria() {
    printf '%s\n' "${PATCH_SERVICE_SUPPORTED_CRITERIA[@]}"
}

patch_service_intent_reset() {
    PATCH_SERVICE_INTENT_DECISIONS=()
    PATCH_SERVICE_INTENT_APPROVALS=()
}

patch_service_intent_add() {
    local criterion="$1"
    local decision="$2"
    local approval_id="$3"

    _patch_service_valid_criterion "$criterion" || return 1
    [ "$decision" = allow-disable ] || return 2
    case "$approval_id" in
        ''|*[!A-Za-z0-9._:+-]*) return 2 ;;
    esac
    [ "${PATCH_SERVICE_INTENT_DECISIONS[$criterion]+present}" != present ] || return 2
    PATCH_SERVICE_INTENT_DECISIONS["$criterion"]="$decision"
    PATCH_SERVICE_INTENT_APPROVALS["$criterion"]="$approval_id"
}

patch_service_reset() {
    PATCH_SERVICE_ERROR_DETAIL=""
    PATCH_SERVICE_ROOT=""
    PATCH_SERVICE_ROOT_DEVICE=""
    PATCH_SERVICE_ROOT_INODE=""
    PATCH_SERVICE_TRANSACTION_DIRECTORY=""
    PATCH_SERVICE_DATA_DIRECTORY=""
    PATCH_SERVICE_PLAN_VALID=0
    PATCH_SERVICE_APPLY_STARTED=0
    PATCH_SERVICE_VERIFIED=0
    PATCH_SERVICE_CHANGE_COUNT=0
    PATCH_SERVICE_COMPLIANT_COUNT=0
    PATCH_SERVICE_TRANSACTION_STATE=""
    PATCH_SERVICE_TRANSACTION_LOADED=0
    PATCH_SERVICE_LOAD_MODE=strict
    PATCH_SERVICE_SNAPSHOT_PATH=""
    PATCH_SERVICE_INTERNAL_PLAN_PATH=""
    PATCH_SERVICE_CHECKSUM_PATH=""
    PATCH_SERVICE_CRITERION_STATES=()
    PATCH_SERVICE_CRITERION_CHANGES=()
    PATCH_SERVICE_UNIT_SEEN=()
    PATCH_SERVICE_CHECKSUM_RELATIVES=()
    PATCH_SERVICE_SELECTED_CRITERIA=()
    PATCH_SERVICE_UNIT_CRITERIA=()
    PATCH_SERVICE_UNIT_NAMES=()
    PATCH_SERVICE_UNIT_IDS=()
    PATCH_SERVICE_UNIT_ALIASES=()
    PATCH_SERVICE_UNIT_LOAD_STATES=()
    PATCH_SERVICE_UNIT_ACTIVE_STATES=()
    PATCH_SERVICE_UNIT_SUB_STATES=()
    PATCH_SERVICE_UNIT_FILE_STATES=()
    PATCH_SERVICE_UNIT_FRAGMENTS=()
    PATCH_SERVICE_UNIT_DROPINS=()
    PATCH_SERVICE_UNIT_TRIGGERS=()
    PATCH_SERVICE_UNIT_TRIGGERED_BY=()
    PATCH_SERVICE_UNIT_APPLIED=()
    PATCH_SERVICE_SYSV_CRITERIA=()
    PATCH_SERVICE_SYSV_NAMES=()
    PATCH_SERVICE_SYSV_ACTIVE=()
    PATCH_SERVICE_SYSV_LINK_RECORDS=()
    PATCH_SERVICE_SYSV_APPLIED=()
    PATCH_SERVICE_FILE_CRITERIA=()
    PATCH_SERVICE_FILE_KINDS=()
    PATCH_SERVICE_FILE_PATHS=()
    PATCH_SERVICE_FILE_DEVICES=()
    PATCH_SERVICE_FILE_INODES=()
    PATCH_SERVICE_FILE_UIDS=()
    PATCH_SERVICE_FILE_GIDS=()
    PATCH_SERVICE_FILE_MODES=()
    PATCH_SERVICE_FILE_SIZES=()
    PATCH_SERVICE_FILE_MTIMES=()
    PATCH_SERVICE_FILE_CTIMES=()
    PATCH_SERVICE_FILE_SHA256S=()
    PATCH_SERVICE_FILE_BACKUPS=()
    PATCH_SERVICE_FILE_PAYLOADS=()
    PATCH_SERVICE_FILE_DESIRED_SHA256S=()
    PATCH_SERVICE_FILE_AFTER_DEVICES=()
    PATCH_SERVICE_FILE_AFTER_INODES=()
    PATCH_SERVICE_FILE_APPLIED=()
    PATCH_SERVICE_FILE_WRITE_COMPLETED=()
    PATCH_SERVICE_ENDPOINT_CRITERIA=()
    PATCH_SERVICE_ENDPOINT_TRANSPORTS=()
    PATCH_SERVICE_ENDPOINT_PORTS=()
    PATCH_SERVICE_ENDPOINT_BEFORE=()
    PATCH_SERVICE_PROCESS_CRITERIA=()
    PATCH_SERVICE_PROCESS_NAMES=()
    PATCH_SERVICE_PROCESS_BEFORE=()
}

_patch_service_command_into() {
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
        ln) candidate=/bin/ln; [ -x "$candidate" ] || candidate=/usr/bin/ln ;;
        mkdir) candidate=/bin/mkdir; [ -x "$candidate" ] || candidate=/usr/bin/mkdir ;;
        mktemp) candidate=/usr/bin/mktemp; [ -x "$candidate" ] || candidate=/bin/mktemp ;;
        mv) candidate=/bin/mv; [ -x "$candidate" ] || candidate=/usr/bin/mv ;;
        readlink) candidate=/usr/bin/readlink; [ -x "$candidate" ] || candidate=/bin/readlink ;;
        rm) candidate=/bin/rm; [ -x "$candidate" ] || candidate=/usr/bin/rm ;;
        sha256sum)
            if [ -x /usr/bin/sha256sum ]; then candidate=/usr/bin/sha256sum
            elif [ -x /bin/sha256sum ]; then candidate=/bin/sha256sum
            else candidate=/usr/bin/shasum
            fi
            ;;
        stat) candidate=/usr/bin/stat ;;
        systemctl) candidate=/usr/bin/systemctl; [ -x "$candidate" ] || candidate=/bin/systemctl ;;
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

_patch_service_stat_into() {
    local path="$1"
    local destination_name="$2"
    local stat_command=""
    local output=""

    _patch_service_command_into stat stat_command || return $?
    if output="$($stat_command -c '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' -- "$path" 2>/dev/null)"; then :
    elif output="$($stat_command -f '%d:%i:%u:%g:%Lp:%l:%z:%m:%c' "$path" 2>/dev/null)"; then :
    else return 2
    fi
    case "$output" in *[!0-9:]*) return 2 ;; esac
    printf -v "$destination_name" '%s' "$output"
}

_patch_service_sha256_into() {
    local path="$1"
    local destination_name="$2"
    local command_path=""
    local output=""
    local digest=""

    _patch_service_command_into sha256sum command_path || return $?
    case "$command_path" in
        */shasum) output="$($command_path -a 256 -- "$path" 2>/dev/null)" || return 2 ;;
        *) output="$($command_path -- "$path" 2>/dev/null)" || return 2 ;;
    esac
    digest="${output%% *}"
    [ "${#digest}" -eq 64 ] || return 2
    case "$digest" in *[!0-9a-f]*) return 2 ;; esac
    printf -v "$destination_name" '%s' "$digest"
}

_patch_service_canonical_directory_into() {
    local path="$1"
    local destination_name="$2"
    local resolved_directory=""

    [ -d "$path" ] && [ ! -L "$path" ] || return 2
    resolved_directory="$(CDPATH='' builtin cd -P -- "$path" 2>/dev/null && pwd -P)" || return 2
    printf -v "$destination_name" '%s' "$resolved_directory"
}

_patch_service_root_path_into() {
    local logical_path="$1"
    local destination_name="$2"

    case "$logical_path" in /*) ;; *) return 2 ;; esac
    case "$logical_path" in *$'\n'*|*$'\r'*|*$'\t'*|*/../*|*/..|*/./*|*/.) return 2 ;; esac
    if [ "$PATCH_SERVICE_ROOT" = / ]; then
        printf -v "$destination_name" '%s' "$logical_path"
    else
        printf -v "$destination_name" '%s' "${PATCH_SERVICE_ROOT%/}$logical_path"
    fi
}

_patch_service_path_components_are_safe() {
    local physical_path="$1"
    local allow_final_symlink="${2:-false}"
    local relative_path=""
    local current_path="$PATCH_SERVICE_ROOT"
    local component=""
    local index=0
    local -a components=()

    if [ "$PATCH_SERVICE_ROOT" = / ]; then
        case "$physical_path" in /*) ;; *) return 2 ;; esac
        relative_path="${physical_path#/}"
    else
        case "$physical_path" in "$PATCH_SERVICE_ROOT"|"$PATCH_SERVICE_ROOT"/*) ;; *) return 2 ;; esac
        relative_path="${physical_path#"$PATCH_SERVICE_ROOT"/}"
    fi
    [ "$relative_path" != "$physical_path" ] || return 0
    IFS=/ read -r -a components <<< "$relative_path"
    while [ "$index" -lt "${#components[@]}" ]; do
        component="${components[$index]}"
        case "$component" in ''|.|..) return 2 ;; esac
        current_path="${current_path%/}/$component"
        if [ -L "$current_path" ]; then
            [ "$allow_final_symlink" = true ] && [ "$index" -eq $(( ${#components[@]} - 1 )) ] || return 2
        elif [ ! -e "$current_path" ]; then
            [ "$index" -eq $(( ${#components[@]} - 1 )) ] || return 2
        fi
        index=$((index + 1))
    done
}

_patch_service_initialize_root() {
    local requested_root="$1"
    local canonical_root=""
    local metadata=""

    case "$requested_root" in *$'\n'*|*$'\r'*|*$'\t'*) return 2 ;; esac
    _patch_service_canonical_directory_into "$requested_root" canonical_root || return 2
    _patch_service_stat_into "$canonical_root" metadata || return 2
    PATCH_SERVICE_ROOT="$canonical_root"
    PATCH_SERVICE_ROOT_DEVICE="${metadata%%:*}"
    metadata="${metadata#*:}"
    PATCH_SERVICE_ROOT_INODE="${metadata%%:*}"
}

_patch_service_root_identity_is_current() {
    local metadata=""

    _patch_service_stat_into "$PATCH_SERVICE_ROOT" metadata || return 2
    [ "${metadata%%:*}" = "$PATCH_SERVICE_ROOT_DEVICE" ] || return 2
    metadata="${metadata#*:}"
    [ "${metadata%%:*}" = "$PATCH_SERVICE_ROOT_INODE" ]
}

_patch_service_prepare_transaction() {
    local transaction_directory="$1"
    local canonical=""
    local metadata=""
    local owner_uid=""
    local mode=""
    local remainder=""
    local mkdir_command=""

    case "$transaction_directory" in *$'\n'*|*$'\r'*|*$'\t'*) return 2 ;; esac
    _patch_service_canonical_directory_into "$transaction_directory" canonical || return 2
    [ "$canonical" = "$transaction_directory" ] || return 2
    _patch_service_stat_into "$canonical" metadata || return 2
    metadata="${metadata#*:*:}"
    owner_uid="${metadata%%:*}"
    metadata="${metadata#*:}"
    metadata="${metadata#*:}"
    mode="${metadata%%:*}"
    remainder="${metadata#*:}"
    [ -n "$remainder" ] || return 2
    [ "$owner_uid" = "${EUID:-$owner_uid}" ] || return 2
    [ $((8#$mode & 0077)) -eq 0 ] || return 2
    PATCH_SERVICE_TRANSACTION_DIRECTORY="$canonical"
    PATCH_SERVICE_DATA_DIRECTORY="$canonical/service"
    [ ! -e "$PATCH_SERVICE_DATA_DIRECTORY" ] && [ ! -L "$PATCH_SERVICE_DATA_DIRECTORY" ] || return 2
    _patch_service_command_into mkdir mkdir_command || return 2
    "$mkdir_command" -m 0700 -- "$PATCH_SERVICE_DATA_DIRECTORY" || return 2
    "$mkdir_command" -m 0700 -- "$PATCH_SERVICE_DATA_DIRECTORY/backups" "$PATCH_SERVICE_DATA_DIRECTORY/payloads" || return 2
}

_patch_service_cleanup_transaction() {
    local rm_command=""

    [ -n "$PATCH_SERVICE_DATA_DIRECTORY" ] || return 0
    case "$PATCH_SERVICE_DATA_DIRECTORY" in "$PATCH_SERVICE_TRANSACTION_DIRECTORY"/service) ;; *) return 2 ;; esac
    _patch_service_command_into rm rm_command || return 2
    "$rm_command" -rf -- "$PATCH_SERVICE_DATA_DIRECTORY"
}

_patch_service_mark_change() {
    local criterion="$1"

    PATCH_SERVICE_CRITERION_CHANGES["$criterion"]=$(( ${PATCH_SERVICE_CRITERION_CHANGES[$criterion]:-0} + 1 ))
    PATCH_SERVICE_CRITERION_STATES["$criterion"]=ready
    PATCH_SERVICE_CHANGE_COUNT=$((PATCH_SERVICE_CHANGE_COUNT + 1))
}

patch_service_state_into() {
    local criterion="$1"
    local destination_name="$2"

    _patch_service_valid_criterion "$criterion" || return 1
    [ "${PATCH_SERVICE_CRITERION_STATES[$criterion]+present}" = present ] || return 1
    printf -v "$destination_name" '%s' "${PATCH_SERVICE_CRITERION_STATES[$criterion]}"
}

_patch_service_unit_patterns() {
    case "$1" in
        U-34) printf '%s\n' 'finger*.service' 'finger*.socket' ;;
        U-36) printf '%s\n' 'rlogin*.service' 'rlogin*.socket' 'rsh*.service' 'rsh*.socket' 'rexec*.service' 'rexec*.socket' ;;
        U-38) printf '%s\n' 'echo*.service' 'echo*.socket' 'discard*.service' 'discard*.socket' 'daytime*.service' 'daytime*.socket' 'chargen*.service' 'chargen*.socket' ;;
        U-41) printf '%s\n' 'autofs*.service' 'automount*.service' 'automountd*.service' ;;
        U-43) printf '%s\n' 'ypbind*.service' 'yppasswdd*.service' 'rpc-yppasswdd*.service' 'rpc.yppasswdd*.service' 'ypserv*.service' 'ypxfrd*.service' 'ypupdated*.service' 'rpc-ypupdated*.service' 'rpc.ypupdated*.service' 'nis.service' ;;
        U-44) printf '%s\n' 'tftp*.service' 'tftp*.socket' 'tftpd*.service' 'tftpd*.socket' 'atftpd*.service' 'atftpd*.socket' 'talk*.service' 'talk*.socket' 'ntalk*.service' 'ntalk*.socket' ;;
        U-52) printf '%s\n' 'telnet*.service' 'telnet*.socket' 'telnetd*.service' 'telnetd*.socket' ;;
        U-54) printf '%s\n' 'ftp*.service' 'ftp*.socket' 'vsftpd*.service' 'vsftpd*.socket' 'proftpd*.service' 'proftpd*.socket' 'pure-ftpd*.service' 'pure-ftpd*.socket' ;;
        U-58) printf '%s\n' 'snmpd*.service' 'snmpd*.socket' 'snmptrapd*.service' 'snmptrapd*.socket' ;;
    esac
}

_patch_service_unit_seeds() {
    case "$1" in
        U-34) printf '%s\n' finger.service finger.socket fingerd.service fingerd.socket finger@.service ;;
        U-36) printf '%s\n' rlogin.service rlogin.socket rlogin@.service rsh.service rsh.socket rsh@.service rexec.service rexec.socket rexec@.service ;;
        U-38) printf '%s\n' echo.service echo.socket echo-stream.socket echo-dgram.socket discard.service discard.socket discard-stream.socket discard-dgram.socket daytime.service daytime.socket daytime-stream.socket daytime-dgram.socket chargen.service chargen.socket chargen-stream.socket chargen-dgram.socket ;;
        U-41) printf '%s\n' autofs.service automount.service automountd.service ;;
        U-43) printf '%s\n' ypbind.service yppasswdd.service rpc-yppasswdd.service rpc.yppasswdd.service ypserv.service ypxfrd.service ypupdated.service rpc-ypupdated.service rpc.ypupdated.service nis.service ;;
        U-44) printf '%s\n' tftp.service tftp.socket tftp@.service tftpd.service tftpd.socket tftpd@.service tftpd-hpa.service atftpd.service atftpd.socket atftpd@.service talk.service talk.socket talk@.service ntalk.service ntalk.socket ntalk@.service ;;
        U-52) printf '%s\n' telnet.service telnet.socket telnet@.service telnetd.service telnetd.socket ;;
        U-54) printf '%s\n' ftp.service ftp.socket vsftpd.service vsftpd.socket proftpd.service proftpd.socket pure-ftpd.service pure-ftpd.socket ;;
        U-58) printf '%s\n' snmpd.service snmpd.socket snmptrapd.service snmptrapd.socket ;;
    esac
}

_patch_service_legacy_names() {
    case "$1" in
        U-34) printf '%s\n' finger ;;
        U-36) printf '%s\n' login rlogin shell rsh exec rexec ;;
        U-38) printf '%s\n' echo echo-stream echo-dgram discard discard-stream discard-dgram daytime daytime-stream daytime-dgram chargen chargen-stream chargen-dgram ;;
        U-41) printf '%s\n' autofs automount automountd ;;
        U-43) printf '%s\n' ypbind yppasswdd ypserv ypxfrd ypupdated nis ;;
        U-44) printf '%s\n' tftp tftpd atftpd talk ntalk ;;
        U-52) printf '%s\n' telnet telnetd ;;
        U-54) printf '%s\n' ftp ftpd vsftpd proftpd pure-ftpd ;;
        U-58) printf '%s\n' snmp snmpd snmptrapd ;;
    esac
}

_patch_service_endpoints() {
    case "$1" in
        U-34) printf 'tcp\t79\n' ;;
        U-36) printf 'tcp\t512\ntcp\t513\ntcp\t514\n' ;;
        U-38) printf 'tcp\t7\nudp\t7\ntcp\t9\nudp\t9\ntcp\t13\nudp\t13\ntcp\t19\nudp\t19\n' ;;
        U-44) printf 'udp\t69\nudp\t517\nudp\t518\n' ;;
        U-52) printf 'tcp\t23\n' ;;
        U-54) printf 'tcp\t21\n' ;;
        U-58) printf 'udp\t161\nudp\t162\n' ;;
    esac
}

_patch_service_process_names() {
    case "$1" in
        U-34) printf '%s\n' fingerd in.fingerd ;;
        U-36) printf '%s\n' rlogind in.rlogind rshd in.rshd rexecd in.rexecd ;;
        U-41) printf '%s\n' automount automountd ;;
        U-43) printf '%s\n' ypbind yppasswdd ypserv ypxfrd ypupdated ;;
        U-44) printf '%s\n' tftpd in.tftpd atftpd talkd in.talkd ntalkd in.ntalkd ;;
        U-52) printf '%s\n' telnetd in.telnetd ;;
        U-54) printf '%s\n' ftpd in.ftpd vsftpd proftpd pure-ftpd ;;
        U-58) printf '%s\n' snmpd snmptrapd ;;
    esac
}

_patch_service_systemctl_show() {
    local unit_name="$1"
    local systemctl_command=""

    [ "$PATCH_SERVICE_ROOT" = / ] || return 1
    _patch_service_command_into systemctl systemctl_command || return 1
    "$systemctl_command" show "$unit_name" --no-pager \
        --property=Id,Names,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,Triggers,TriggeredBy \
        2>/dev/null
}

_patch_service_systemctl_list() {
    local systemctl_command=""

    [ "$PATCH_SERVICE_ROOT" = / ] || return 1
    _patch_service_command_into systemctl systemctl_command || return 1
    "$systemctl_command" list-unit-files --no-legend --no-pager \
        --type=service --type=socket --type=timer --type=path 2>/dev/null | awk '{print $1}'
    "$systemctl_command" list-units --all --no-legend --no-pager \
        --type=service --type=socket --type=timer --type=path 2>/dev/null | awk '{print $1}'
}

_patch_service_systemctl_change() {
    local action="$1"
    local unit_name="${2:-}"
    local systemctl_command=""

    [ "$PATCH_SERVICE_ROOT" = / ] || return 2
    _patch_service_command_into systemctl systemctl_command || return 2
    case "$action" in
        stop) "$systemctl_command" stop -- "$unit_name" >/dev/null 2>&1 ;;
        disable) "$systemctl_command" disable -- "$unit_name" >/dev/null 2>&1 ;;
        mask) "$systemctl_command" mask -- "$unit_name" >/dev/null 2>&1 ;;
        unmask) "$systemctl_command" unmask -- "$unit_name" >/dev/null 2>&1 ;;
        enable) "$systemctl_command" enable -- "$unit_name" >/dev/null 2>&1 ;;
        enable-runtime) "$systemctl_command" enable --runtime -- "$unit_name" >/dev/null 2>&1 ;;
        start) "$systemctl_command" start -- "$unit_name" >/dev/null 2>&1 ;;
        daemon-reload) "$systemctl_command" daemon-reload >/dev/null 2>&1 ;;
        *) return 2 ;;
    esac
}

_patch_service_unit_matches_criterion() {
    local criterion="$1"
    local unit_name="$2"
    local pattern=""

    while IFS= read -r pattern; do
        [ -n "$pattern" ] || continue
        # The registry value is deliberately interpreted as a shell pattern.
        # shellcheck disable=SC2053
        [[ "$unit_name" == $pattern ]] && return 0
    done < <(_patch_service_unit_patterns "$criterion")
    return 1
}

_patch_service_parse_systemd_show() {
    local output="$1"
    local destination_prefix="$2"
    local line=""
    local key=""
    local value=""

    printf -v "${destination_prefix}_id" '%s' ""
    printf -v "${destination_prefix}_names" '%s' ""
    printf -v "${destination_prefix}_load" '%s' ""
    printf -v "${destination_prefix}_active" '%s' ""
    printf -v "${destination_prefix}_sub" '%s' ""
    printf -v "${destination_prefix}_file" '%s' ""
    printf -v "${destination_prefix}_fragment" '%s' ""
    printf -v "${destination_prefix}_dropins" '%s' ""
    printf -v "${destination_prefix}_triggers" '%s' ""
    printf -v "${destination_prefix}_triggered_by" '%s' ""
    while IFS= read -r line || [ -n "$line" ]; do
        key="${line%%=*}"
        value="${line#*=}"
        [ "$key" != "$line" ] || return 2
        case "$value" in *$'\t'*|*$'\r'*|*$'\n'*) return 2 ;; esac
        case "$key" in
            Id) printf -v "${destination_prefix}_id" '%s' "$value" ;;
            Names) printf -v "${destination_prefix}_names" '%s' "$value" ;;
            LoadState) printf -v "${destination_prefix}_load" '%s' "$value" ;;
            ActiveState) printf -v "${destination_prefix}_active" '%s' "$value" ;;
            SubState) printf -v "${destination_prefix}_sub" '%s' "$value" ;;
            UnitFileState) printf -v "${destination_prefix}_file" '%s' "$value" ;;
            FragmentPath) printf -v "${destination_prefix}_fragment" '%s' "$value" ;;
            DropInPaths) printf -v "${destination_prefix}_dropins" '%s' "$value" ;;
            Triggers) printf -v "${destination_prefix}_triggers" '%s' "$value" ;;
            TriggeredBy) printf -v "${destination_prefix}_triggered_by" '%s' "$value" ;;
        esac
    done <<< "$output"
}

_patch_service_snapshot_unit() {
    local criterion="$1"
    local requested_name="$2"
    local show_output=""
    local unit_id=""
    local unit_names=""
    local unit_load=""
    local unit_active=""
    local unit_sub=""
    local unit_file=""
    local unit_fragment=""
    local unit_dropins=""
    local unit_triggers=""
    local unit_triggered_by=""
    local key=""
    local change_required=0

    case "$requested_name" in
        ''|*[!A-Za-z0-9_.@:+-]*) return 2 ;;
    esac
    show_output="$(_patch_service_systemctl_show "$requested_name" 2>/dev/null)" || return 1
    _patch_service_parse_systemd_show "$show_output" unit || return 2
    [ -n "$unit_id" ] || unit_id="$requested_name"
    case "$unit_id" in *[!A-Za-z0-9_.@:+-]*) return 2 ;; esac
    [ "$unit_load" != not-found ] || return 1
    key="$criterion:$unit_id"
    [ "${PATCH_SERVICE_UNIT_SEEN[$key]+present}" != present ] || return 3
    case "$unit_active" in active|activating|reloading) change_required=1 ;; esac
    case "$unit_file" in enabled|enabled-runtime|linked|linked-runtime|alias) change_required=1 ;; esac
    [ "$change_required" -eq 1 ] || return 3
    case "$unit_file" in linked|linked-runtime) return 2 ;; esac
    PATCH_SERVICE_UNIT_SEEN["$key"]=1
    PATCH_SERVICE_UNIT_CRITERIA+=("$criterion")
    PATCH_SERVICE_UNIT_NAMES+=("$requested_name")
    PATCH_SERVICE_UNIT_IDS+=("$unit_id")
    PATCH_SERVICE_UNIT_ALIASES+=("$unit_names")
    PATCH_SERVICE_UNIT_LOAD_STATES+=("$unit_load")
    PATCH_SERVICE_UNIT_ACTIVE_STATES+=("$unit_active")
    PATCH_SERVICE_UNIT_SUB_STATES+=("$unit_sub")
    PATCH_SERVICE_UNIT_FILE_STATES+=("$unit_file")
    PATCH_SERVICE_UNIT_FRAGMENTS+=("$unit_fragment")
    PATCH_SERVICE_UNIT_DROPINS+=("$unit_dropins")
    PATCH_SERVICE_UNIT_TRIGGERS+=("$unit_triggers")
    PATCH_SERVICE_UNIT_TRIGGERED_BY+=("$unit_triggered_by")
    PATCH_SERVICE_UNIT_APPLIED+=(0)
    _patch_service_mark_change "$criterion"
}

_patch_service_unit_exists_on_disk() {
    local unit_name="$1"
    local template_name="$unit_name"
    local logical_directory=""
    local physical_directory=""

    case "$unit_name" in
        *@*.*)
            template_name="${unit_name%%@*}@.${unit_name##*.}"
            ;;
    esac
    for logical_directory in /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
        _patch_service_root_path_into "$logical_directory" physical_directory || return 2
        [ -e "$physical_directory/$unit_name" ] || [ -L "$physical_directory/$unit_name" ] ||
            [ -e "$physical_directory/$template_name" ] || [ -L "$physical_directory/$template_name" ] || continue
        return 0
    done
    return 1
}

_patch_service_snapshot_systemd() {
    local criterion="$1"
    local candidate=""
    local pattern=""
    local related=""
    local index=0
    local -a candidates=()
    local -A queued=()
    local -A listed=()
    local snapshot_status=0

    while IFS= read -r candidate; do
        [ -n "$candidate" ] || continue
        queued["$candidate"]=1
        candidates+=("$candidate")
    done < <(_patch_service_unit_seeds "$criterion")
    while IFS= read -r candidate; do
        [ -n "$candidate" ] || continue
        _patch_service_unit_matches_criterion "$criterion" "$candidate" || continue
        listed["$candidate"]=1
        if [ "${queued[$candidate]+present}" != present ]; then
            queued["$candidate"]=1
            candidates+=("$candidate")
        fi
    done < <(_patch_service_systemctl_list 2>/dev/null | LC_ALL=C sort -u)

    while [ "$index" -lt "${#candidates[@]}" ]; do
        candidate="${candidates[$index]}"
        snapshot_status=0
        _patch_service_snapshot_unit "$criterion" "$candidate" || snapshot_status=$?
        if [ "$snapshot_status" -eq 0 ]; then
            for related in ${PATCH_SERVICE_UNIT_TRIGGERS[-1]:-} ${PATCH_SERVICE_UNIT_TRIGGERED_BY[-1]:-}; do
                case "$related" in *.service|*.socket|*.timer|*.path) ;; *) continue ;; esac
                if [ "${queued[$related]+present}" != present ]; then
                    queued["$related"]=1
                    candidates+=("$related")
                fi
            done
        else
            case "$snapshot_status" in
                1)
                    if [ "${listed[$candidate]+present}" = present ] ||
                        _patch_service_unit_exists_on_disk "$candidate"; then
                        return 2
                    fi
                    ;;
                3) ;;
                *) return 2 ;;
            esac
        fi
        index=$((index + 1))
    done
}

_patch_service_unit_state_is_current() {
    local index="$1"
    local show_output=""
    local unit_id=""
    local unit_names=""
    local unit_load=""
    local unit_active=""
    local unit_sub=""
    local unit_file=""
    local unit_fragment=""
    local unit_dropins=""
    local unit_triggers=""
    local unit_triggered_by=""

    show_output="$(_patch_service_systemctl_show "${PATCH_SERVICE_UNIT_NAMES[$index]}" 2>/dev/null)" || return 2
    _patch_service_parse_systemd_show "$show_output" unit || return 2
    [ "${unit_id:-${PATCH_SERVICE_UNIT_NAMES[$index]}}" = "${PATCH_SERVICE_UNIT_IDS[$index]}" ] &&
        [ "$unit_load" = "${PATCH_SERVICE_UNIT_LOAD_STATES[$index]}" ] &&
        [ "$unit_active" = "${PATCH_SERVICE_UNIT_ACTIVE_STATES[$index]}" ] &&
        [ "$unit_sub" = "${PATCH_SERVICE_UNIT_SUB_STATES[$index]}" ] &&
        [ "$unit_file" = "${PATCH_SERVICE_UNIT_FILE_STATES[$index]}" ] &&
        [ "$unit_fragment" = "${PATCH_SERVICE_UNIT_FRAGMENTS[$index]}" ] &&
        [ "$unit_dropins" = "${PATCH_SERVICE_UNIT_DROPINS[$index]}" ] &&
        [ "$unit_names" = "${PATCH_SERVICE_UNIT_ALIASES[$index]}" ] &&
        [ "$unit_triggers" = "${PATCH_SERVICE_UNIT_TRIGGERS[$index]}" ] &&
        [ "$unit_triggered_by" = "${PATCH_SERVICE_UNIT_TRIGGERED_BY[$index]}" ]
}

_patch_service_unit_is_disabled() {
    local index="$1"
    local show_output=""
    local unit_id=""
    local unit_names=""
    local unit_load=""
    local unit_active=""
    local unit_sub=""
    local unit_file=""
    local unit_fragment=""
    local unit_dropins=""
    local unit_triggers=""
    local unit_triggered_by=""

    show_output="$(_patch_service_systemctl_show "${PATCH_SERVICE_UNIT_NAMES[$index]}" 2>/dev/null)" || return 2
    _patch_service_parse_systemd_show "$show_output" unit || return 2
    case "$unit_active" in inactive|failed) ;; *) return 1 ;; esac
    [ "$unit_file" = masked ]
}

_patch_service_sysv_is_active() {
    local service_name="$1"
    local script_path=""

    _patch_service_root_path_into "/etc/init.d/$service_name" script_path || return 2
    [ "$PATCH_SERVICE_ROOT" = / ] || return 1
    [ -x "$script_path" ] || return 1
    "$script_path" status >/dev/null 2>&1 && return 0
    return 1
}

_patch_service_sysv_change() {
    local action="$1"
    local service_name="$2"
    local script_path=""

    _patch_service_root_path_into "/etc/init.d/$service_name" script_path || return 2
    [ "$PATCH_SERVICE_ROOT" = / ] || return 2
    [ -x "$script_path" ] || return 2
    case "$action" in
        stop) "$script_path" stop >/dev/null 2>&1 ;;
        start) "$script_path" start >/dev/null 2>&1 ;;
        *) return 2 ;;
    esac
}

_patch_service_sysv_link_records() {
    local service_name="$1"
    local readlink_command=""
    local link_path=""
    local target=""
    local -a link_paths=()

    _patch_service_command_into readlink readlink_command || return 2
    shopt -s nullglob
    link_paths=("${PATCH_SERVICE_ROOT%/}/etc"/rc*.d/[SK][0-9][0-9]"$service_name")
    shopt -u nullglob
    for link_path in "${link_paths[@]}"; do
        [ -L "$link_path" ] || continue
        _patch_service_path_components_are_safe "$link_path" true || return 2
        target="$($readlink_command -- "$link_path" 2>/dev/null)" || return 2
        case "$link_path$target" in *$'\t'*|*$'\n'*|*$'\r'*) return 2 ;; esac
        printf '%s\t%s\n' "$link_path" "$target"
    done
}

_patch_service_snapshot_sysv() {
    local criterion="$1"
    local service_name=""
    local script_path=""
    local active=0
    local links=""

    while IFS= read -r service_name; do
        [ -n "$service_name" ] || continue
        _patch_service_root_path_into "/etc/init.d/$service_name" script_path || return 2
        [ -f "$script_path" ] && [ ! -L "$script_path" ] || continue
        _patch_service_path_components_are_safe "$script_path" || return 2
        _patch_service_sysv_is_active "$service_name" && active=1 || active=0
        links="$(_patch_service_sysv_link_records "$service_name")" || return 2
        [ "$active" -eq 1 ] || [ -n "$links" ] || continue
        PATCH_SERVICE_SYSV_CRITERIA+=("$criterion")
        PATCH_SERVICE_SYSV_NAMES+=("$service_name")
        PATCH_SERVICE_SYSV_ACTIVE+=("$active")
        PATCH_SERVICE_SYSV_LINK_RECORDS+=("$links")
        PATCH_SERVICE_SYSV_APPLIED+=(0)
        _patch_service_mark_change "$criterion"
    done < <(_patch_service_legacy_names "$criterion")
}

_patch_service_remove_sysv_links() {
    local index="$1"
    local link_path=""
    local target=""
    local rm_command=""

    _patch_service_command_into rm rm_command || return 2
    while IFS=$'\t' read -r link_path target; do
        [ -n "$link_path" ] || continue
        [ -L "$link_path" ] || return 2
        "$rm_command" -f -- "$link_path" || return 2
    done <<< "${PATCH_SERVICE_SYSV_LINK_RECORDS[$index]}"
}

_patch_service_restore_sysv_links() {
    local index="$1"
    local link_path=""
    local target=""
    local ln_command=""

    _patch_service_command_into ln ln_command || return 2
    while IFS=$'\t' read -r link_path target; do
        [ -n "$link_path" ] || continue
        [ ! -e "$link_path" ] && [ ! -L "$link_path" ] || return 2
        "$ln_command" -s -- "$target" "$link_path" || return 2
    done <<< "${PATCH_SERVICE_SYSV_LINK_RECORDS[$index]}"
}

_patch_service_sysv_is_disabled() {
    local index="$1"
    local current_links=""

    _patch_service_sysv_is_active "${PATCH_SERVICE_SYSV_NAMES[$index]}" && return 1
    current_links="$(_patch_service_sysv_link_records "${PATCH_SERVICE_SYSV_NAMES[$index]}")" || return 2
    [ -z "$current_links" ]
}

_patch_service_file_metadata_into() {
    local path="$1"
    local prefix="$2"
    local metadata=""
    local value=""

    _patch_service_stat_into "$path" metadata || return 2
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

_patch_service_file_index_into() {
    local path="$1"
    local destination_name="$2"
    local index=0

    while [ "$index" -lt "${#PATCH_SERVICE_FILE_PATHS[@]}" ]; do
        if [ "${PATCH_SERVICE_FILE_PATHS[$index]}" = "$path" ]; then
            printf -v "$destination_name" '%s' "$index"
            return 0
        fi
        index=$((index + 1))
    done
    return 1
}

_patch_service_legacy_file_matches() {
    local kind="$1"
    local path="$2"
    local names="$3"
    local awk_command=""

    _patch_service_command_into awk awk_command || return 2
    case "$kind" in
        inetd)
            "$awk_command" -v names="$names" '
                BEGIN {count=split(names, wanted, ","); for (i=1;i<=count;i++) selected[wanted[i]]=1}
                {line=$0; sub(/^[[:space:]]+/, "", line); if (line=="" || line ~ /^#/) next; split(line, fields, /[[:space:]]+/); if (selected[fields[1]]) found=1}
                END {exit(found ? 0 : 1)}
            ' "$path"
            ;;
        xinetd)
            "$awk_command" -v names="$names" -v basename="${path##*/}" '
                BEGIN {count=split(names, wanted, ","); for (i=1;i<=count;i++) selected[wanted[i]]=1; relevant=selected[basename]}
                {line=$0; sub(/^[[:space:]]+/, "", line); if (line ~ /^service[[:space:]]+/) {split(line, fields, /[[:space:]]+/); blocks++; if (selected[fields[2]]) relevant=1} if (line ~ /^disable[[:space:]]*=[[:space:]]*(yes|true|1)([[:space:]#]|$)/) disabled=1}
                END {if (blocks > 1) exit 2; exit(relevant && !disabled ? 0 : 1)}
            ' "$path"
            ;;
        *) return 2 ;;
    esac
}

_patch_service_render_legacy_payload() {
    local kind="$1"
    local source_path="$2"
    local names="$3"
    local destination_path="$4"
    local awk_command=""

    _patch_service_command_into awk awk_command || return 2
    case "$kind" in
        inetd)
            "$awk_command" -v names="$names" '
                BEGIN {count=split(names, wanted, ","); for (i=1;i<=count;i++) selected[wanted[i]]=1}
                {
                    line=$0; probe=line; sub(/^[[:space:]]+/, "", probe)
                    if (probe != "" && probe !~ /^#/) {split(probe, fields, /[[:space:]]+/); if (selected[fields[1]]) line="# kisa-cce-disabled " line}
                    print line
                }
            ' "$source_path" > "$destination_path"
            ;;
        xinetd)
            "$awk_command" -v names="$names" -v basename="${source_path##*/}" '
                BEGIN {count=split(names, wanted, ","); for (i=1;i<=count;i++) selected[wanted[i]]=1; relevant=selected[basename]}
                {
                    line=$0; probe=line; sub(/^[[:space:]]+/, "", probe)
                    if (probe ~ /^service[[:space:]]+/) {split(probe, fields, /[[:space:]]+/); if (selected[fields[2]]) relevant=1}
                    if (relevant && probe ~ /^disable[[:space:]]*=/) {match(line, /^[[:space:]]*/); prefix=substr(line,1,RLENGTH); line=prefix "disable = yes"; changed=1}
                    if (relevant && probe ~ /^}/ && !changed) {print "    disable = yes"; changed=1}
                    print line
                }
                END {if (!relevant || !changed) exit 2}
            ' "$source_path" > "$destination_path"
            ;;
        *) return 2 ;;
    esac
}

_patch_service_snapshot_legacy_file() {
    local criterion="$1"
    local kind="$2"
    local path="$3"
    local names="$4"
    local match_status=0
    local existing_index=""
    local index="${#PATCH_SERVICE_FILE_PATHS[@]}"
    local backup_name=""
    local backup_path=""
    local payload_path=""
    local cp_command=""
    local chmod_command=""
    local mktemp_command=""
    local mv_command=""
    local merge_path=""
    local before_device="" before_inode="" before_uid="" before_gid="" before_mode=""
    local before_size="" before_mtime="" before_ctime="" before_sha256="" desired_sha256=""

    printf -v backup_name '%06d' "$((index + 1))"
    backup_path="$PATCH_SERVICE_DATA_DIRECTORY/backups/$backup_name"
    payload_path="$PATCH_SERVICE_DATA_DIRECTORY/payloads/$backup_name"

    [ -f "$path" ] && [ ! -L "$path" ] || return 0
    _patch_service_path_components_are_safe "$path" || return 2
    _patch_service_legacy_file_matches "$kind" "$path" "$names" || match_status=$?
    case "$match_status" in 0) ;; 1) return 0 ;; *) return 2 ;; esac
    if _patch_service_file_index_into "$path" existing_index; then
        [ "$kind" = inetd ] && [ "${PATCH_SERVICE_FILE_KINDS[$existing_index]}" = inetd ] || return 2
        _patch_service_command_into mktemp mktemp_command || return 2
        _patch_service_command_into mv mv_command || return 2
        _patch_service_command_into chmod chmod_command || return 2
        merge_path="$($mktemp_command "$PATCH_SERVICE_DATA_DIRECTORY/payloads/.merge.XXXXXXXX")" || return 2
        if ! _patch_service_render_legacy_payload inetd "${PATCH_SERVICE_FILE_PAYLOADS[$existing_index]}" \
            "$names" "$merge_path" || ! "$chmod_command" 0600 "$merge_path" ||
            ! "$mv_command" -f -- "$merge_path" "${PATCH_SERVICE_FILE_PAYLOADS[$existing_index]}"; then
            return 2
        fi
        _patch_service_sha256_into "${PATCH_SERVICE_FILE_PAYLOADS[$existing_index]}" desired_sha256 || return 2
        PATCH_SERVICE_FILE_DESIRED_SHA256S[$existing_index]="$desired_sha256"
        PATCH_SERVICE_FILE_CRITERIA[$existing_index]+=",$criterion"
        _patch_service_mark_change "$criterion"
        return 0
    fi
    _patch_service_file_metadata_into "$path" before || return 2
    _patch_service_sha256_into "$path" before_sha256 || return 2
    _patch_service_command_into cp cp_command || return 2
    _patch_service_command_into chmod chmod_command || return 2
    "$cp_command" -- "$path" "$backup_path" || return 2
    "$chmod_command" 0600 "$backup_path" || return 2
    _patch_service_render_legacy_payload "$kind" "$path" "$names" "$payload_path" || return 2
    "$chmod_command" 0600 "$payload_path" || return 2
    _patch_service_sha256_into "$payload_path" desired_sha256 || return 2
    [ "$before_sha256" != "$desired_sha256" ] || return 0
    PATCH_SERVICE_FILE_CRITERIA+=("$criterion")
    PATCH_SERVICE_FILE_KINDS+=("$kind")
    PATCH_SERVICE_FILE_PATHS+=("$path")
    PATCH_SERVICE_FILE_DEVICES+=("$before_device")
    PATCH_SERVICE_FILE_INODES+=("$before_inode")
    PATCH_SERVICE_FILE_UIDS+=("$before_uid")
    PATCH_SERVICE_FILE_GIDS+=("$before_gid")
    PATCH_SERVICE_FILE_MODES+=("$before_mode")
    PATCH_SERVICE_FILE_SIZES+=("$before_size")
    PATCH_SERVICE_FILE_MTIMES+=("$before_mtime")
    PATCH_SERVICE_FILE_CTIMES+=("$before_ctime")
    PATCH_SERVICE_FILE_SHA256S+=("$before_sha256")
    PATCH_SERVICE_FILE_BACKUPS+=("$backup_path")
    PATCH_SERVICE_FILE_PAYLOADS+=("$payload_path")
    PATCH_SERVICE_FILE_DESIRED_SHA256S+=("$desired_sha256")
    PATCH_SERVICE_FILE_AFTER_DEVICES+=("")
    PATCH_SERVICE_FILE_AFTER_INODES+=("")
    PATCH_SERVICE_FILE_APPLIED+=(0)
    PATCH_SERVICE_FILE_WRITE_COMPLETED+=(0)
    _patch_service_mark_change "$criterion"
}

_patch_service_snapshot_legacy_files() {
    local criterion="$1"
    local names=""
    local names_csv=""
    local path=""
    local xinetd_directory=""
    local candidate=""
    local -a candidates=()

    while IFS= read -r names; do
        [ -n "$names" ] || continue
        names_csv="${names_csv:+$names_csv,}$names"
    done < <(_patch_service_legacy_names "$criterion")
    _patch_service_root_path_into /etc/inetd.conf path || return 2
    _patch_service_snapshot_legacy_file "$criterion" inetd "$path" "$names_csv" || return 2
    _patch_service_root_path_into /etc/xinetd.d xinetd_directory || return 2
    [ -d "$xinetd_directory" ] && [ ! -L "$xinetd_directory" ] || return 0
    _patch_service_path_components_are_safe "$xinetd_directory" || return 2
    shopt -s nullglob
    candidates=("$xinetd_directory"/*)
    shopt -u nullglob
    for candidate in "${candidates[@]}"; do
        [ -f "$candidate" ] && [ ! -L "$candidate" ] || continue
        _patch_service_snapshot_legacy_file "$criterion" xinetd "$candidate" "$names_csv" || return 2
    done
}

_patch_service_file_fingerprint_is_current() {
    local index="$1"
    local current_device="" current_inode="" current_uid="" current_gid="" current_mode=""
    local current_size="" current_mtime="" current_ctime="" current_sha256=""

    _patch_service_file_metadata_into "${PATCH_SERVICE_FILE_PATHS[$index]}" current || return 2
    _patch_service_sha256_into "${PATCH_SERVICE_FILE_PATHS[$index]}" current_sha256 || return 2
    [ "$current_device" = "${PATCH_SERVICE_FILE_DEVICES[$index]}" ] &&
        [ "$current_inode" = "${PATCH_SERVICE_FILE_INODES[$index]}" ] &&
        [ "$current_uid" = "${PATCH_SERVICE_FILE_UIDS[$index]}" ] &&
        [ "$current_gid" = "${PATCH_SERVICE_FILE_GIDS[$index]}" ] &&
        [ "$current_mode" = "${PATCH_SERVICE_FILE_MODES[$index]}" ] &&
        [ "$current_size" = "${PATCH_SERVICE_FILE_SIZES[$index]}" ] &&
        [ "$current_mtime" = "${PATCH_SERVICE_FILE_MTIMES[$index]}" ] &&
        [ "$current_ctime" = "${PATCH_SERVICE_FILE_CTIMES[$index]}" ] &&
        [ "$current_sha256" = "${PATCH_SERVICE_FILE_SHA256S[$index]}" ]
}

_patch_service_replace_file() {
    local source_path="$1"
    local target_path="$2"
    local uid="$3"
    local gid="$4"
    local mode="$5"
    local cp_command="" chmod_command="" chown_command=""

    _patch_service_command_into cp cp_command || return 2
    _patch_service_command_into chmod chmod_command || return 2
    _patch_service_command_into chown chown_command || return 2
    # Updating the existing inode preserves ACLs and security labels on legacy supervisor files.
    "$cp_command" -- "$source_path" "$target_path" || return 2
    "$chown_command" "$uid:$gid" "$target_path" || return 2
    "$chmod_command" "$mode" "$target_path" || return 2
}

_patch_service_listener_active() {
    local transport="$1"
    local port="$2"
    local port_hex=""
    local table=""
    local local_address=""
    local state=""

    case "$transport" in tcp|udp) ;; *) return 2 ;; esac
    case "$port" in ''|*[!0-9]*) return 2 ;; esac
    printf -v port_hex '%04X' "$port"
    for table in "/proc/net/$transport" "/proc/net/${transport}6"; do
        [ -r "$table" ] || continue
        while read -r _ local_address _ state _; do
            [ "${local_address##*:}" = "$port_hex" ] || continue
            if [ "$transport" = tcp ]; then
                [ "$state" = 0A ] || continue
            fi
            return 0
        done < "$table"
    done
    return 1
}

_patch_service_process_active() {
    local process_name="$1"
    local comm_path=""
    local observed_name=""

    case "$process_name" in ''|*[!A-Za-z0-9_.+-]*) return 2 ;; esac
    for comm_path in /proc/[0-9]*/comm; do
        [ -r "$comm_path" ] || continue
        IFS= read -r observed_name < "$comm_path" || return 2
        [ "$observed_name" = "$process_name" ] && return 0
    done
    return 1
}

_patch_service_snapshot_endpoints() {
    local criterion="$1"
    local transport=""
    local port=""
    local state=0

    while IFS=$'\t' read -r transport port; do
        [ -n "$transport" ] || continue
        state=0
        _patch_service_listener_active "$transport" "$port" || state=$?
        case "$state" in 0|1) ;; *) return 2 ;; esac
        PATCH_SERVICE_ENDPOINT_CRITERIA+=("$criterion")
        PATCH_SERVICE_ENDPOINT_TRANSPORTS+=("$transport")
        PATCH_SERVICE_ENDPOINT_PORTS+=("$port")
        PATCH_SERVICE_ENDPOINT_BEFORE+=("$([ "$state" -eq 0 ] && printf active || printf inactive)")
    done < <(_patch_service_endpoints "$criterion")
}

_patch_service_snapshot_processes() {
    local criterion="$1"
    local process_name=""
    local state=0

    while IFS= read -r process_name; do
        [ -n "$process_name" ] || continue
        state=0
        _patch_service_process_active "$process_name" || state=$?
        case "$state" in 0|1) ;; *) return 2 ;; esac
        PATCH_SERVICE_PROCESS_CRITERIA+=("$criterion")
        PATCH_SERVICE_PROCESS_NAMES+=("$process_name")
        PATCH_SERVICE_PROCESS_BEFORE+=("$([ "$state" -eq 0 ] && printf active || printf inactive)")
    done < <(_patch_service_process_names "$criterion")
}

_patch_service_criterion_has_manageable_change() {
    [ "${PATCH_SERVICE_CRITERION_CHANGES[$1]:-0}" -gt 0 ]
}

_patch_service_validate_endpoint_manageability() {
    local index=0
    local criterion=""

    while [ "$index" -lt "${#PATCH_SERVICE_ENDPOINT_CRITERIA[@]}" ]; do
        criterion="${PATCH_SERVICE_ENDPOINT_CRITERIA[$index]}"
        if [ "${PATCH_SERVICE_ENDPOINT_BEFORE[$index]}" = active ] &&
            ! _patch_service_criterion_has_manageable_change "$criterion"; then
            _patch_service_set_error "$criterion: listener is active without a managed activation path"
            return 2
        fi
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_SERVICE_PROCESS_CRITERIA[@]}" ]; do
        criterion="${PATCH_SERVICE_PROCESS_CRITERIA[$index]}"
        if [ "${PATCH_SERVICE_PROCESS_BEFORE[$index]}" = active ] &&
            ! _patch_service_criterion_has_manageable_change "$criterion"; then
            _patch_service_set_error "$criterion: process is active without a managed activation path"
            return 2
        fi
        index=$((index + 1))
    done
}

_patch_service_artifact_is_protected() {
    local path="$1"
    local expected_mode="$2"
    local metadata=""
    local owner_uid=""
    local mode=""
    local links=""

    [ -f "$path" ] && [ ! -L "$path" ] || return 2
    _patch_service_stat_into "$path" metadata || return 2
    metadata="${metadata#*:*:}"
    owner_uid="${metadata%%:*}"; metadata="${metadata#*:}"
    metadata="${metadata#*:}"
    mode="${metadata%%:*}"; metadata="${metadata#*:}"
    links="${metadata%%:*}"
    [ "$owner_uid" = "${EUID:-$owner_uid}" ] && [ "$mode" = "$expected_mode" ] && [ "$links" = 1 ]
}

_patch_service_directory_is_protected() {
    local path="$1"
    local metadata=""
    local owner_uid=""
    local mode=""

    [ -d "$path" ] && [ ! -L "$path" ] || return 2
    _patch_service_stat_into "$path" metadata || return 2
    metadata="${metadata#*:*:}"
    owner_uid="${metadata%%:*}"; metadata="${metadata#*:}"
    metadata="${metadata#*:}"
    mode="${metadata%%:*}"
    [ "$owner_uid" = "${EUID:-$owner_uid}" ] && [ "$mode" = 700 ]
}

_patch_service_value_is_tsv_safe() {
    case "$1" in *$'\t'*|*$'\n'*|*$'\r'*) return 1 ;; *) return 0 ;; esac
}

_patch_service_render_snapshot() {
    local index=0
    local criterion=""
    local link_path=""
    local link_target=""

    printf 'schema\trecord_type\trecord_fields\n'
    printf '2\troot\t-\t%s\t%s\t%s\n' "$PATCH_SERVICE_ROOT" "$PATCH_SERVICE_ROOT_DEVICE" "$PATCH_SERVICE_ROOT_INODE"
    for criterion in "${PATCH_SERVICE_SELECTED_CRITERIA[@]}"; do
        printf '2\tintent\t%s\tallow-disable\t%s\n' "$criterion" "${PATCH_SERVICE_INTENT_APPROVALS[$criterion]}"
    done
    while [ "$index" -lt "${#PATCH_SERVICE_UNIT_NAMES[@]}" ]; do
        printf '2\tunit\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${PATCH_SERVICE_UNIT_CRITERIA[$index]}" "${PATCH_SERVICE_UNIT_NAMES[$index]}" \
            "${PATCH_SERVICE_UNIT_IDS[$index]}" "${PATCH_SERVICE_UNIT_ALIASES[$index]:--}" \
            "${PATCH_SERVICE_UNIT_LOAD_STATES[$index]:--}" "${PATCH_SERVICE_UNIT_ACTIVE_STATES[$index]:--}" \
            "${PATCH_SERVICE_UNIT_SUB_STATES[$index]:--}" "${PATCH_SERVICE_UNIT_FILE_STATES[$index]:--}" \
            "${PATCH_SERVICE_UNIT_FRAGMENTS[$index]:--}" "${PATCH_SERVICE_UNIT_DROPINS[$index]:--}" \
            "${PATCH_SERVICE_UNIT_TRIGGERS[$index]:--}" "${PATCH_SERVICE_UNIT_TRIGGERED_BY[$index]:--}"
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_SERVICE_SYSV_NAMES[@]}" ]; do
        printf '2\tsysv\t%s\t%s\t%s\n' "${PATCH_SERVICE_SYSV_CRITERIA[$index]}" \
            "${PATCH_SERVICE_SYSV_NAMES[$index]}" "${PATCH_SERVICE_SYSV_ACTIVE[$index]}"
        while IFS=$'\t' read -r link_path link_target; do
            [ -n "$link_path" ] || continue
            printf '2\tsysv_link\t%s\t%s\t%s\t%s\n' "${PATCH_SERVICE_SYSV_CRITERIA[$index]}" \
                "${PATCH_SERVICE_SYSV_NAMES[$index]}" "$link_path" "$link_target"
        done <<< "${PATCH_SERVICE_SYSV_LINK_RECORDS[$index]}"
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_SERVICE_FILE_PATHS[@]}" ]; do
        printf '2\tfile\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${PATCH_SERVICE_FILE_CRITERIA[$index]}" "${PATCH_SERVICE_FILE_KINDS[$index]}" \
            "${PATCH_SERVICE_FILE_PATHS[$index]}" "${PATCH_SERVICE_FILE_DEVICES[$index]}" \
            "${PATCH_SERVICE_FILE_INODES[$index]}" "${PATCH_SERVICE_FILE_UIDS[$index]}" \
            "${PATCH_SERVICE_FILE_GIDS[$index]}" "${PATCH_SERVICE_FILE_MODES[$index]}" \
            "${PATCH_SERVICE_FILE_SIZES[$index]}" "${PATCH_SERVICE_FILE_MTIMES[$index]}" \
            "${PATCH_SERVICE_FILE_CTIMES[$index]}" "${PATCH_SERVICE_FILE_SHA256S[$index]}" \
            "${PATCH_SERVICE_FILE_DESIRED_SHA256S[$index]}" "${PATCH_SERVICE_FILE_BACKUPS[$index]##*/}" \
            "${PATCH_SERVICE_FILE_PAYLOADS[$index]##*/}"
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_SERVICE_ENDPOINT_CRITERIA[@]}" ]; do
        printf '2\tendpoint\t%s\t%s\t%s\t%s\n' "${PATCH_SERVICE_ENDPOINT_CRITERIA[$index]}" \
            "${PATCH_SERVICE_ENDPOINT_TRANSPORTS[$index]}" "${PATCH_SERVICE_ENDPOINT_PORTS[$index]}" \
            "${PATCH_SERVICE_ENDPOINT_BEFORE[$index]}"
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_SERVICE_PROCESS_CRITERIA[@]}" ]; do
        printf '2\tprocess\t%s\t%s\t%s\n' "${PATCH_SERVICE_PROCESS_CRITERIA[$index]}" \
            "${PATCH_SERVICE_PROCESS_NAMES[$index]}" "${PATCH_SERVICE_PROCESS_BEFORE[$index]}"
        index=$((index + 1))
    done
}

_patch_service_render_plan() {
    local criterion=""

    printf 'criterion\taction\tstate\tapproval_id\tchange_count\n'
    for criterion in "${PATCH_SERVICE_SELECTED_CRITERIA[@]}"; do
        printf '%s\tdisable-service\t%s\t%s\t%s\n' "$criterion" \
            "${PATCH_SERVICE_CRITERION_STATES[$criterion]}" "${PATCH_SERVICE_INTENT_APPROVALS[$criterion]}" \
            "${PATCH_SERVICE_CRITERION_CHANGES[$criterion]:-0}"
    done
}

_patch_service_write_rendered_artifact() {
    local output_path="$1"
    local renderer="$2"

    [ ! -e "$output_path" ] && [ ! -L "$output_path" ] || return 2
    if ! (
        umask 077
        set -o noclobber
        "$renderer" > "$output_path" && chmod 0600 "$output_path"
    ); then
        return 2
    fi
    _patch_service_artifact_is_protected "$output_path" 600
}

_patch_service_set_state() {
    local state="$1"
    local state_path="$PATCH_SERVICE_DATA_DIRECTORY/state"
    local temporary_path=""
    local mktemp_command=""
    local mv_command=""

    case "$state" in planned|applying|verified|rollback_in_progress|rolled_back|rollback_failed) ;; *) return 2 ;; esac
    _patch_service_command_into mktemp mktemp_command || return 2
    _patch_service_command_into mv mv_command || return 2
    temporary_path="$($mktemp_command "$PATCH_SERVICE_DATA_DIRECTORY/.state.XXXXXXXX")" || return 2
    printf '%s\n' "$state" > "$temporary_path" || return 2
    chmod 0600 "$temporary_path" || return 2
    "$mv_command" -f -- "$temporary_path" "$state_path" || return 2
    _patch_service_artifact_is_protected "$state_path" 600 || return 2
    PATCH_SERVICE_TRANSACTION_STATE="$state"
}

_patch_service_write_checksums() {
    local checksum_path="$PATCH_SERVICE_DATA_DIRECTORY/checksums.sha256"
    local relative_path=""
    local artifact_digest=""
    local index=0

    [ ! -e "$checksum_path" ] && [ ! -L "$checksum_path" ] || return 2
    {
        for relative_path in manifest.tsv snapshot.tsv plan.tsv; do
            _patch_service_sha256_into "$PATCH_SERVICE_DATA_DIRECTORY/$relative_path" artifact_digest || exit 2
            printf '%s  %s\n' "$artifact_digest" "$relative_path"
        done
        while [ "$index" -lt "${#PATCH_SERVICE_FILE_PATHS[@]}" ]; do
            for relative_path in "backups/${PATCH_SERVICE_FILE_BACKUPS[$index]##*/}" \
                "payloads/${PATCH_SERVICE_FILE_PAYLOADS[$index]##*/}"; do
                _patch_service_sha256_into "$PATCH_SERVICE_DATA_DIRECTORY/$relative_path" artifact_digest || exit 2
                printf '%s  %s\n' "$artifact_digest" "$relative_path"
            done
            index=$((index + 1))
        done
    } > "$checksum_path" || return 2
    chmod 0600 "$checksum_path" || return 2
    _patch_service_artifact_is_protected "$checksum_path" 600 || return 2
    PATCH_SERVICE_CHECKSUM_PATH="$checksum_path"
}

_patch_service_bind_existing_transaction() {
    local transaction_directory="$1"
    local canonical=""

    case "$transaction_directory" in *$'\n'*|*$'\r'*|*$'\t'*) return 2 ;; esac
    _patch_service_canonical_directory_into "$transaction_directory" canonical || return 2
    [ "$canonical" = "$transaction_directory" ] || return 2
    PATCH_SERVICE_TRANSACTION_DIRECTORY="$canonical"
    PATCH_SERVICE_DATA_DIRECTORY="$canonical/service"
    _patch_service_directory_is_protected "$canonical" || return 2
    _patch_service_directory_is_protected "$PATCH_SERVICE_DATA_DIRECTORY" || return 2
    _patch_service_directory_is_protected "$PATCH_SERVICE_DATA_DIRECTORY/backups" || return 2
    _patch_service_directory_is_protected "$PATCH_SERVICE_DATA_DIRECTORY/payloads" || return 2
    PATCH_SERVICE_SNAPSHOT_PATH="$PATCH_SERVICE_DATA_DIRECTORY/snapshot.tsv"
    PATCH_SERVICE_INTERNAL_PLAN_PATH="$PATCH_SERVICE_DATA_DIRECTORY/plan.tsv"
    PATCH_SERVICE_CHECKSUM_PATH="$PATCH_SERVICE_DATA_DIRECTORY/checksums.sha256"
}

_patch_service_read_state() {
    local state_path="$PATCH_SERVICE_DATA_DIRECTORY/state"
    local state=""
    local line_count=""

    _patch_service_artifact_is_protected "$state_path" 600 || return 2
    line_count="$(wc -l < "$state_path" | tr -d '[:space:]')" || return 2
    [ "$line_count" = 1 ] || return 2
    IFS= read -r state < "$state_path" || return 2
    case "$state" in planned|applying|verified|rollback_in_progress|rolled_back|rollback_failed) ;; *) return 2 ;; esac
    PATCH_SERVICE_TRANSACTION_STATE="$state"
}

_patch_service_validate_checksums() {
    local line=""
    local digest=""
    local relative_path=""
    local actual_digest=""
    local count=0
    local entry=""
    local relative_entry=""
    local -a entries=()

    PATCH_SERVICE_CHECKSUM_RELATIVES=()
    _patch_service_artifact_is_protected "$PATCH_SERVICE_CHECKSUM_PATH" 600 || return 2
    while IFS= read -r line || [ -n "$line" ]; do
        digest="${line%%  *}"
        relative_path="${line#*  }"
        [ "$relative_path" != "$line" ] && [ "${#digest}" -eq 64 ] || return 2
        case "$digest" in *[!0-9a-f]*) return 2 ;; esac
        case "$relative_path" in
            manifest.tsv|snapshot.tsv|plan.tsv|backups/[0-9][0-9][0-9][0-9][0-9][0-9]|payloads/[0-9][0-9][0-9][0-9][0-9][0-9]) ;;
            *) return 2 ;;
        esac
        [ "${PATCH_SERVICE_CHECKSUM_RELATIVES[$relative_path]+present}" != present ] || return 2
        PATCH_SERVICE_CHECKSUM_RELATIVES["$relative_path"]="$digest"
        _patch_service_artifact_is_protected "$PATCH_SERVICE_DATA_DIRECTORY/$relative_path" 600 || return 2
        _patch_service_sha256_into "$PATCH_SERVICE_DATA_DIRECTORY/$relative_path" actual_digest || return 2
        [ "$actual_digest" = "$digest" ] || return 2
        count=$((count + 1))
    done < "$PATCH_SERVICE_CHECKSUM_PATH"
    [ "$count" -ge 3 ] &&
        [ "${PATCH_SERVICE_CHECKSUM_RELATIVES[manifest.tsv]+present}" = present ] &&
        [ "${PATCH_SERVICE_CHECKSUM_RELATIVES[snapshot.tsv]+present}" = present ] &&
        [ "${PATCH_SERVICE_CHECKSUM_RELATIVES[plan.tsv]+present}" = present ] || return 2
    shopt -s nullglob dotglob
    entries=("$PATCH_SERVICE_DATA_DIRECTORY"/*)
    shopt -u nullglob dotglob
    for entry in "${entries[@]}"; do
        case "${entry##*/}" in
            manifest.tsv|snapshot.tsv|plan.tsv|checksums.sha256|state|backups|payloads) ;;
            *) return 2 ;;
        esac
    done
    for relative_entry in backups payloads; do
        shopt -s nullglob dotglob
        entries=("$PATCH_SERVICE_DATA_DIRECTORY/$relative_entry"/*)
        shopt -u nullglob dotglob
        for entry in "${entries[@]}"; do
            [ -f "$entry" ] && [ ! -L "$entry" ] || return 2
            [ "${PATCH_SERVICE_CHECKSUM_RELATIVES[$relative_entry/${entry##*/}]+present}" = present ] || return 2
        done
    done
}

_patch_service_registry_contains_name() {
    local criterion="$1"
    local expected_name="$2"
    local observed_name=""

    while IFS= read -r observed_name; do
        [ "$observed_name" = "$expected_name" ] && return 0
    done < <(_patch_service_legacy_names "$criterion")
    return 1
}

_patch_service_registry_contains_endpoint() {
    local criterion="$1"
    local transport="$2"
    local port="$3"
    local observed_transport=""
    local observed_port=""

    while IFS=$'\t' read -r observed_transport observed_port; do
        [ "$observed_transport:$observed_port" = "$transport:$port" ] && return 0
    done < <(_patch_service_endpoints "$criterion")
    return 1
}

_patch_service_registry_contains_process() {
    local criterion="$1"
    local process_name="$2"
    local observed_name=""

    while IFS= read -r observed_name; do
        [ "$observed_name" = "$process_name" ] && return 0
    done < <(_patch_service_process_names "$criterion")
    return 1
}

_patch_service_related_unit_allowed() {
    local criterion="$1"
    local unit_name="$2"
    local index=0

    _patch_service_unit_matches_criterion "$criterion" "$unit_name" && return 0
    case "$unit_name" in *.timer|*.path|*.socket|*.service) ;; *) return 1 ;; esac
    while [ "$index" -lt "${#PATCH_SERVICE_UNIT_NAMES[@]}" ]; do
        if [ "${PATCH_SERVICE_UNIT_CRITERIA[$index]}" = "$criterion" ]; then
            case " ${PATCH_SERVICE_UNIT_TRIGGERS[$index]} ${PATCH_SERVICE_UNIT_TRIGGERED_BY[$index]} " in
                *" $unit_name "*) return 0 ;;
            esac
        fi
        index=$((index + 1))
    done
    return 1
}

_patch_service_sysv_index_into() {
    local criterion="$1"
    local service_name="$2"
    local destination_name="$3"
    local index=0

    while [ "$index" -lt "${#PATCH_SERVICE_SYSV_NAMES[@]}" ]; do
        if [ "${PATCH_SERVICE_SYSV_CRITERIA[$index]}:${PATCH_SERVICE_SYSV_NAMES[$index]}" = "$criterion:$service_name" ]; then
            printf -v "$destination_name" '%s' "$index"
            return 0
        fi
        index=$((index + 1))
    done
    return 1
}

_patch_service_decode_snapshot_value() {
    [ "$1" = - ] && printf '%s' "" || printf '%s' "$1"
}

_patch_service_load_snapshot() {
    local line=""
    local -a fields=()
    local line_number=0
    local root_seen=0
    local criterion=""
    local approval=""
    local service_index=""
    local criteria_value=""
    local criterion_part=""
    local old_ifs="$IFS"
    local backup_relative=""
    local payload_relative=""
    local expected_checksum_count=3
    local inetd_path=""
    local xinetd_directory=""
    local selected_count=0
    local -a criteria_parts=()
    local -A selected=()
    local -A unit_records=()
    local -A sysv_records=()
    local -A file_records=()

    patch_service_intent_reset
    while IFS= read -r line || [ -n "$line" ]; do
        line_number=$((line_number + 1))
        if [ "$line_number" -eq 1 ]; then
            [ "$line" = $'schema\trecord_type\trecord_fields' ] || return 2
            continue
        fi
        IFS=$'\t' read -r -a fields <<< "$line"
        IFS="$old_ifs"
        [ "${fields[0]:-}" = 2 ] || return 2
        case "${fields[1]:-}" in
            root)
                [ "${#fields[@]}" -eq 6 ] && [ "$root_seen" -eq 0 ] && [ "$line_number" -eq 2 ] || return 2
                [ "${fields[3]}" = "$PATCH_SERVICE_ROOT" ] &&
                    [ "${fields[4]}" = "$PATCH_SERVICE_ROOT_DEVICE" ] &&
                    [ "${fields[5]}" = "$PATCH_SERVICE_ROOT_INODE" ] || return 2
                root_seen=1
                ;;
            intent)
                [ "${#fields[@]}" -eq 5 ] && [ "$root_seen" -eq 1 ] || return 2
                criterion="${fields[2]}"
                approval="${fields[4]}"
                _patch_service_valid_criterion "$criterion" || return 2
                [ "${fields[3]}" = allow-disable ] || return 2
                case "$approval" in ''|*[!A-Za-z0-9._:+-]*) return 2 ;; esac
                [ "${selected[$criterion]+present}" != present ] || return 2
                selected["$criterion"]=1
                PATCH_SERVICE_INTENT_DECISIONS["$criterion"]=allow-disable
                PATCH_SERVICE_INTENT_APPROVALS["$criterion"]="$approval"
                PATCH_SERVICE_SELECTED_CRITERIA+=("$criterion")
                PATCH_SERVICE_CRITERION_STATES["$criterion"]=compliant
                PATCH_SERVICE_CRITERION_CHANGES["$criterion"]=0
                selected_count=$((selected_count + 1))
                ;;
            unit)
                [ "${#fields[@]}" -eq 14 ] || return 2
                criterion="${fields[2]}"
                [ "${selected[$criterion]+present}" = present ] || return 2
                _patch_service_related_unit_allowed "$criterion" "${fields[3]}" || return 2
                case "${fields[3]}:${fields[4]}" in *[!A-Za-z0-9_.@:+-]*) return 2 ;; esac
                [ "${unit_records[$criterion:${fields[4]}]+present}" != present ] || return 2
                unit_records["$criterion:${fields[4]}"]=1
                PATCH_SERVICE_UNIT_CRITERIA+=("$criterion")
                PATCH_SERVICE_UNIT_NAMES+=("${fields[3]}")
                PATCH_SERVICE_UNIT_IDS+=("${fields[4]}")
                PATCH_SERVICE_UNIT_ALIASES+=("$(_patch_service_decode_snapshot_value "${fields[5]}")")
                PATCH_SERVICE_UNIT_LOAD_STATES+=("$(_patch_service_decode_snapshot_value "${fields[6]}")")
                PATCH_SERVICE_UNIT_ACTIVE_STATES+=("$(_patch_service_decode_snapshot_value "${fields[7]}")")
                PATCH_SERVICE_UNIT_SUB_STATES+=("$(_patch_service_decode_snapshot_value "${fields[8]}")")
                PATCH_SERVICE_UNIT_FILE_STATES+=("$(_patch_service_decode_snapshot_value "${fields[9]}")")
                PATCH_SERVICE_UNIT_FRAGMENTS+=("$(_patch_service_decode_snapshot_value "${fields[10]}")")
                PATCH_SERVICE_UNIT_DROPINS+=("$(_patch_service_decode_snapshot_value "${fields[11]}")")
                PATCH_SERVICE_UNIT_TRIGGERS+=("$(_patch_service_decode_snapshot_value "${fields[12]}")")
                PATCH_SERVICE_UNIT_TRIGGERED_BY+=("$(_patch_service_decode_snapshot_value "${fields[13]}")")
                PATCH_SERVICE_UNIT_APPLIED+=(0)
                _patch_service_mark_change "$criterion"
                ;;
            sysv)
                [ "${#fields[@]}" -eq 5 ] || return 2
                criterion="${fields[2]}"
                [ "${selected[$criterion]+present}" = present ] || return 2
                _patch_service_registry_contains_name "$criterion" "${fields[3]}" || return 2
                case "${fields[4]}" in 0|1) ;; *) return 2 ;; esac
                [ "${sysv_records[$criterion:${fields[3]}]+present}" != present ] || return 2
                sysv_records["$criterion:${fields[3]}"]=1
                PATCH_SERVICE_SYSV_CRITERIA+=("$criterion")
                PATCH_SERVICE_SYSV_NAMES+=("${fields[3]}")
                PATCH_SERVICE_SYSV_ACTIVE+=("${fields[4]}")
                PATCH_SERVICE_SYSV_LINK_RECORDS+=("")
                PATCH_SERVICE_SYSV_APPLIED+=(0)
                _patch_service_mark_change "$criterion"
                ;;
            sysv_link)
                [ "${#fields[@]}" -eq 6 ] || return 2
                criterion="${fields[2]}"
                _patch_service_sysv_index_into "$criterion" "${fields[3]}" service_index || return 2
                _patch_service_value_is_tsv_safe "${fields[4]}${fields[5]}" || return 2
                _patch_service_path_components_are_safe "${fields[4]}" true || return 2
                PATCH_SERVICE_SYSV_LINK_RECORDS[$service_index]+="${PATCH_SERVICE_SYSV_LINK_RECORDS[$service_index]:+$'\n'}${fields[4]}"$'\t'"${fields[5]}"
                ;;
            file)
                [ "${#fields[@]}" -eq 17 ] || return 2
                criteria_value="${fields[2]}"
                case "${fields[3]}" in inetd|xinetd) ;; *) return 2 ;; esac
                [ "${file_records[${fields[4]}]+present}" != present ] || return 2
                file_records["${fields[4]}"]=1
                IFS=, read -r -a criteria_parts <<< "$criteria_value"
                IFS="$old_ifs"
                [ "${#criteria_parts[@]}" -gt 0 ] || return 2
                for criterion_part in "${criteria_parts[@]}"; do
                    [ "${selected[$criterion_part]+present}" = present ] || return 2
                    _patch_service_mark_change "$criterion_part"
                done
                _patch_service_root_path_into /etc/inetd.conf inetd_path || return 2
                _patch_service_root_path_into /etc/xinetd.d xinetd_directory || return 2
                case "${fields[3]}:${fields[4]}" in
                    inetd:"$inetd_path") ;;
                    xinetd:"$xinetd_directory"/*) case "${fields[4]#"$xinetd_directory"/}" in ''|*/*) return 2 ;; esac ;;
                    *) return 2 ;;
                esac
                case "${fields[5]}:${fields[6]}:${fields[7]}:${fields[8]}:${fields[9]}:${fields[10]}:${fields[11]}:${fields[12]}" in *[!0-9:]*) return 2 ;; esac
                case "${fields[13]}:${fields[14]}" in *[!0-9a-f:]*) return 2 ;; esac
                [ "${#fields[13]}" -eq 64 ] && [ "${#fields[14]}" -eq 64 ] || return 2
                case "${fields[15]}:${fields[16]}" in *[!0-9:]*) return 2 ;; esac
                [ "${#fields[15]}" -eq 6 ] && [ "${#fields[16]}" -eq 6 ] || return 2
                backup_relative="backups/${fields[15]}"
                payload_relative="payloads/${fields[16]}"
                [ "${PATCH_SERVICE_CHECKSUM_RELATIVES[$backup_relative]+present}" = present ] &&
                    [ "${PATCH_SERVICE_CHECKSUM_RELATIVES[$payload_relative]+present}" = present ] || return 2
                [ "${PATCH_SERVICE_CHECKSUM_RELATIVES[$backup_relative]}" = "${fields[13]}" ] &&
                    [ "${PATCH_SERVICE_CHECKSUM_RELATIVES[$payload_relative]}" = "${fields[14]}" ] || return 2
                PATCH_SERVICE_FILE_CRITERIA+=("$criteria_value")
                PATCH_SERVICE_FILE_KINDS+=("${fields[3]}")
                PATCH_SERVICE_FILE_PATHS+=("${fields[4]}")
                PATCH_SERVICE_FILE_DEVICES+=("${fields[5]}")
                PATCH_SERVICE_FILE_INODES+=("${fields[6]}")
                PATCH_SERVICE_FILE_UIDS+=("${fields[7]}")
                PATCH_SERVICE_FILE_GIDS+=("${fields[8]}")
                PATCH_SERVICE_FILE_MODES+=("${fields[9]}")
                PATCH_SERVICE_FILE_SIZES+=("${fields[10]}")
                PATCH_SERVICE_FILE_MTIMES+=("${fields[11]}")
                PATCH_SERVICE_FILE_CTIMES+=("${fields[12]}")
                PATCH_SERVICE_FILE_SHA256S+=("${fields[13]}")
                PATCH_SERVICE_FILE_DESIRED_SHA256S+=("${fields[14]}")
                PATCH_SERVICE_FILE_BACKUPS+=("$PATCH_SERVICE_DATA_DIRECTORY/$backup_relative")
                PATCH_SERVICE_FILE_PAYLOADS+=("$PATCH_SERVICE_DATA_DIRECTORY/$payload_relative")
                PATCH_SERVICE_FILE_AFTER_DEVICES+=("")
                PATCH_SERVICE_FILE_AFTER_INODES+=("")
                PATCH_SERVICE_FILE_APPLIED+=(0)
                PATCH_SERVICE_FILE_WRITE_COMPLETED+=(0)
                expected_checksum_count=$((expected_checksum_count + 2))
                ;;
            endpoint)
                [ "${#fields[@]}" -eq 6 ] || return 2
                criterion="${fields[2]}"
                [ "${selected[$criterion]+present}" = present ] || return 2
                _patch_service_registry_contains_endpoint "$criterion" "${fields[3]}" "${fields[4]}" || return 2
                case "${fields[5]}" in active|inactive) ;; *) return 2 ;; esac
                PATCH_SERVICE_ENDPOINT_CRITERIA+=("$criterion")
                PATCH_SERVICE_ENDPOINT_TRANSPORTS+=("${fields[3]}")
                PATCH_SERVICE_ENDPOINT_PORTS+=("${fields[4]}")
                PATCH_SERVICE_ENDPOINT_BEFORE+=("${fields[5]}")
                ;;
            process)
                [ "${#fields[@]}" -eq 5 ] || return 2
                criterion="${fields[2]}"
                [ "${selected[$criterion]+present}" = present ] || return 2
                _patch_service_registry_contains_process "$criterion" "${fields[3]}" || return 2
                case "${fields[4]}" in active|inactive) ;; *) return 2 ;; esac
                PATCH_SERVICE_PROCESS_CRITERIA+=("$criterion")
                PATCH_SERVICE_PROCESS_NAMES+=("${fields[3]}")
                PATCH_SERVICE_PROCESS_BEFORE+=("${fields[4]}")
                ;;
            *) return 2 ;;
        esac
    done < "$PATCH_SERVICE_SNAPSHOT_PATH"
    [ "$line_number" -ge 2 ] && [ "$root_seen" -eq 1 ] && [ "$selected_count" -gt 0 ] || return 2
    [ "${#PATCH_SERVICE_CHECKSUM_RELATIVES[@]}" -eq "$expected_checksum_count" ] || return 2
}

_patch_service_validate_manifest_and_plan() {
    local manifest_path="$PATCH_SERVICE_DATA_DIRECTORY/manifest.tsv"
    local line=""
    local line_number=0
    local schema=""
    local record_type=""
    local criterion=""
    local object=""
    local before_state=""
    local metadata=""
    local extra=""
    local intent_count=0
    local expected_plan=""
    local actual_plan=""

    _patch_service_artifact_is_protected "$manifest_path" 600 || return 2
    _patch_service_artifact_is_protected "$PATCH_SERVICE_INTERNAL_PLAN_PATH" 600 || return 2
    while IFS= read -r line || [ -n "$line" ]; do
        line_number=$((line_number + 1))
        if [ "$line_number" -eq 1 ]; then
            [ "$line" = $'schema\trecord_type\tcriterion\tobject\tbefore_state\tmetadata' ] || return 2
            continue
        fi
        IFS=$'\t' read -r schema record_type criterion object before_state metadata extra <<< "$line"
        [ "$schema" = 1 ] && [ -z "$extra" ] || return 2
        if [ "$record_type" = intent ]; then
            [ "${PATCH_SERVICE_INTENT_DECISIONS[$criterion]:-}" = allow-disable ] || return 2
            [ "$object" = allow-disable ] &&
                [ "$before_state" = "${PATCH_SERVICE_INTENT_APPROVALS[$criterion]}" ] &&
                [ "$metadata" = "root=$PATCH_SERVICE_ROOT_DEVICE:$PATCH_SERVICE_ROOT_INODE" ] || return 2
            intent_count=$((intent_count + 1))
        fi
    done < "$manifest_path"
    [ "$intent_count" -eq "${#PATCH_SERVICE_SELECTED_CRITERIA[@]}" ] || return 2
    expected_plan="$(_patch_service_render_plan)" || return 2
    actual_plan="$(< "$PATCH_SERVICE_INTERNAL_PLAN_PATH")" || return 2
    [ "$actual_plan" = "$expected_plan" ]
}

patch_service_load_transaction() {
    local root="$1"
    local transaction_directory="$2"
    local criterion=""

    patch_service_reset
    patch_service_intent_reset
    _patch_service_initialize_root "$root" || {
        _patch_service_set_error "rollback root is unavailable or unsafe"
        return 2
    }
    _patch_service_bind_existing_transaction "$transaction_directory" || {
        _patch_service_set_error "service transaction directory is unsafe"
        return 2
    }
    _patch_service_validate_checksums || {
        _patch_service_set_error "service transaction checksum or artifact validation failed"
        return 2
    }
    _patch_service_load_snapshot || {
        _patch_service_set_error "service transaction snapshot is invalid"
        return 2
    }
    _patch_service_validate_manifest_and_plan || {
        _patch_service_set_error "service transaction manifest or plan is invalid"
        return 2
    }
    _patch_service_read_state || {
        _patch_service_set_error "service transaction state is invalid"
        return 2
    }
    for criterion in "${PATCH_SERVICE_SELECTED_CRITERIA[@]}"; do
        if [ "${PATCH_SERVICE_CRITERION_CHANGES[$criterion]:-0}" -eq 0 ]; then
            PATCH_SERVICE_COMPLIANT_COUNT=$((PATCH_SERVICE_COMPLIANT_COUNT + 1))
        fi
    done
    PATCH_SERVICE_PLAN_VALID=1
    PATCH_SERVICE_TRANSACTION_LOADED=1
}

_patch_service_unit_matches_before_loaded() {
    local index="$1"
    local show_output=""
    local unit_id="" unit_names="" unit_load="" unit_active="" unit_sub="" unit_file=""
    local unit_fragment="" unit_dropins="" unit_triggers="" unit_triggered_by=""

    show_output="$(_patch_service_systemctl_show "${PATCH_SERVICE_UNIT_NAMES[$index]}" 2>/dev/null)" || return 2
    _patch_service_parse_systemd_show "$show_output" unit || return 2
    [ "${unit_id:-${PATCH_SERVICE_UNIT_NAMES[$index]}}" = "${PATCH_SERVICE_UNIT_IDS[$index]}" ] &&
        [ "$unit_names" = "${PATCH_SERVICE_UNIT_ALIASES[$index]}" ] &&
        [ "$unit_load" = "${PATCH_SERVICE_UNIT_LOAD_STATES[$index]}" ] &&
        [ "$unit_active" = "${PATCH_SERVICE_UNIT_ACTIVE_STATES[$index]}" ] &&
        [ "$unit_file" = "${PATCH_SERVICE_UNIT_FILE_STATES[$index]}" ] &&
        [ "$unit_fragment" = "${PATCH_SERVICE_UNIT_FRAGMENTS[$index]}" ] &&
        [ "$unit_dropins" = "${PATCH_SERVICE_UNIT_DROPINS[$index]}" ]
}

_patch_service_unit_identity_is_loaded() {
    local index="$1"
    local show_output=""
    local unit_id="" unit_names="" unit_load="" unit_active="" unit_sub="" unit_file=""
    local unit_fragment="" unit_dropins="" unit_triggers="" unit_triggered_by=""

    show_output="$(_patch_service_systemctl_show "${PATCH_SERVICE_UNIT_NAMES[$index]}" 2>/dev/null)" || return 2
    _patch_service_parse_systemd_show "$show_output" unit || return 2
    [ "${unit_id:-${PATCH_SERVICE_UNIT_NAMES[$index]}}" = "${PATCH_SERVICE_UNIT_IDS[$index]}" ] &&
        [ "$unit_names" = "${PATCH_SERVICE_UNIT_ALIASES[$index]}" ] &&
        [ "$unit_fragment" = "${PATCH_SERVICE_UNIT_FRAGMENTS[$index]}" ] &&
        [ "$unit_dropins" = "${PATCH_SERVICE_UNIT_DROPINS[$index]}" ]
}

_patch_service_file_matches_before_loaded() {
    local index="$1"
    local current_device="" current_inode="" current_uid="" current_gid="" current_mode=""
    local current_size="" current_mtime="" current_ctime="" current_sha256=""

    _patch_service_file_metadata_into "${PATCH_SERVICE_FILE_PATHS[$index]}" current || return 2
    _patch_service_sha256_into "${PATCH_SERVICE_FILE_PATHS[$index]}" current_sha256 || return 2
    [ "$current_device" = "${PATCH_SERVICE_FILE_DEVICES[$index]}" ] &&
        [ "$current_inode" = "${PATCH_SERVICE_FILE_INODES[$index]}" ] &&
        [ "$current_uid" = "${PATCH_SERVICE_FILE_UIDS[$index]}" ] &&
        [ "$current_gid" = "${PATCH_SERVICE_FILE_GIDS[$index]}" ] &&
        [ "$current_mode" = "${PATCH_SERVICE_FILE_MODES[$index]}" ] &&
        [ "$current_sha256" = "${PATCH_SERVICE_FILE_SHA256S[$index]}" ]
}

_patch_service_file_matches_after_loaded() {
    local index="$1"
    local current_device="" current_inode="" current_uid="" current_gid="" current_mode=""
    local current_size="" current_mtime="" current_ctime="" current_sha256=""

    _patch_service_file_metadata_into "${PATCH_SERVICE_FILE_PATHS[$index]}" current || return 2
    _patch_service_sha256_into "${PATCH_SERVICE_FILE_PATHS[$index]}" current_sha256 || return 2
    [ "$current_device" = "${PATCH_SERVICE_FILE_DEVICES[$index]}" ] &&
        [ "$current_inode" = "${PATCH_SERVICE_FILE_INODES[$index]}" ] &&
        [ "$current_uid" = "${PATCH_SERVICE_FILE_UIDS[$index]}" ] &&
        [ "$current_gid" = "${PATCH_SERVICE_FILE_GIDS[$index]}" ] &&
        [ "$current_mode" = "${PATCH_SERVICE_FILE_MODES[$index]}" ] &&
        [ "$current_sha256" = "${PATCH_SERVICE_FILE_DESIRED_SHA256S[$index]}" ]
}

_patch_service_file_identity_is_loaded() {
    local index="$1"
    local current_device="" current_inode="" current_uid="" current_gid="" current_mode=""
    local current_size="" current_mtime="" current_ctime=""

    _patch_service_file_metadata_into "${PATCH_SERVICE_FILE_PATHS[$index]}" current || return 2
    [ "$current_device" = "${PATCH_SERVICE_FILE_DEVICES[$index]}" ] &&
        [ "$current_inode" = "${PATCH_SERVICE_FILE_INODES[$index]}" ]
}

_patch_service_sysv_current_state_into() {
    local index="$1"
    local active_destination="$2"
    local links_destination="$3"
    local active=0
    local links=""

    if _patch_service_sysv_is_active "${PATCH_SERVICE_SYSV_NAMES[$index]}"; then
        active=1
    else
        [ "$?" -eq 1 ] || return 2
    fi
    links="$(_patch_service_sysv_link_records "${PATCH_SERVICE_SYSV_NAMES[$index]}")" || return 2
    printf -v "$active_destination" '%s' "$active"
    printf -v "$links_destination" '%s' "$links"
}

_patch_service_classify_loaded_state() {
    local mode="$1"
    local expected_side="$2"
    local index=0
    local current_active=0
    local current_links=""
    local state=0

    while [ "$index" -lt "${#PATCH_SERVICE_UNIT_NAMES[@]}" ]; do
        if _patch_service_unit_matches_before_loaded "$index"; then
            PATCH_SERVICE_UNIT_APPLIED[$index]=0
            [ "$expected_side" != after ] || [ "$mode" = transition ] || return 2
        elif _patch_service_unit_is_disabled "$index"; then
            PATCH_SERVICE_UNIT_APPLIED[$index]=1
            [ "$expected_side" != before ] || [ "$mode" = transition ] || return 2
        elif [ "$mode" = transition ] && _patch_service_unit_identity_is_loaded "$index"; then
            PATCH_SERVICE_UNIT_APPLIED[$index]=1
        else
            return 2
        fi
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_SERVICE_SYSV_NAMES[@]}" ]; do
        _patch_service_sysv_current_state_into "$index" current_active current_links || return 2
        if [ "$current_active" -eq "${PATCH_SERVICE_SYSV_ACTIVE[$index]}" ] &&
            [ "$current_links" = "${PATCH_SERVICE_SYSV_LINK_RECORDS[$index]}" ]; then
            PATCH_SERVICE_SYSV_APPLIED[$index]=0
            [ "$expected_side" != after ] || [ "$mode" = transition ] || return 2
        elif [ "$current_active" -eq 0 ] && [ -z "$current_links" ]; then
            PATCH_SERVICE_SYSV_APPLIED[$index]=1
            [ "$expected_side" != before ] || [ "$mode" = transition ] || return 2
        elif [ "$mode" = transition ] &&
            { [ -z "$current_links" ] || [ "$current_links" = "${PATCH_SERVICE_SYSV_LINK_RECORDS[$index]}" ]; }; then
            PATCH_SERVICE_SYSV_APPLIED[$index]=1
        else
            return 2
        fi
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_SERVICE_FILE_PATHS[@]}" ]; do
        if _patch_service_file_matches_before_loaded "$index"; then
            PATCH_SERVICE_FILE_APPLIED[$index]=0
            [ "$expected_side" != after ] || [ "$mode" = transition ] || return 2
        elif _patch_service_file_matches_after_loaded "$index"; then
            PATCH_SERVICE_FILE_APPLIED[$index]=1
            PATCH_SERVICE_FILE_WRITE_COMPLETED[$index]=1
            PATCH_SERVICE_FILE_AFTER_DEVICES[$index]="${PATCH_SERVICE_FILE_DEVICES[$index]}"
            PATCH_SERVICE_FILE_AFTER_INODES[$index]="${PATCH_SERVICE_FILE_INODES[$index]}"
            [ "$expected_side" != before ] || [ "$mode" = transition ] || return 2
        elif [ "$mode" = transition ] && _patch_service_file_identity_is_loaded "$index"; then
            PATCH_SERVICE_FILE_APPLIED[$index]=1
            PATCH_SERVICE_FILE_WRITE_COMPLETED[$index]=0
            PATCH_SERVICE_FILE_AFTER_DEVICES[$index]="${PATCH_SERVICE_FILE_DEVICES[$index]}"
            PATCH_SERVICE_FILE_AFTER_INODES[$index]="${PATCH_SERVICE_FILE_INODES[$index]}"
        else
            return 2
        fi
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_SERVICE_ENDPOINT_CRITERIA[@]}" ]; do
        state=0
        _patch_service_listener_active "${PATCH_SERVICE_ENDPOINT_TRANSPORTS[$index]}" \
            "${PATCH_SERVICE_ENDPOINT_PORTS[$index]}" || state=$?
        if [ "$expected_side" = before ]; then
            case "${PATCH_SERVICE_ENDPOINT_BEFORE[$index]}:$state" in active:0|inactive:1) ;; *) return 2 ;; esac
        elif [ "$expected_side" = after ]; then
            [ "$state" -eq 1 ] || return 2
        elif [ "$mode" != transition ]; then
            return 2
        fi
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_SERVICE_PROCESS_CRITERIA[@]}" ]; do
        state=0
        _patch_service_process_active "${PATCH_SERVICE_PROCESS_NAMES[$index]}" || state=$?
        if [ "$expected_side" = before ]; then
            case "${PATCH_SERVICE_PROCESS_BEFORE[$index]}:$state" in active:0|inactive:1) ;; *) return 2 ;; esac
        elif [ "$expected_side" = after ]; then
            [ "$state" -eq 1 ] || return 2
        elif [ "$mode" != transition ]; then
            return 2
        fi
        index=$((index + 1))
    done
}

patch_service_rollback_transaction() {
    local root="$1"
    local transaction_directory="$2"
    local mode="${3:-strict}"

    case "$mode" in strict|transition) ;; *) return 2 ;; esac
    [ "${EUID:-$(id -u)}" -eq 0 ] || {
        _patch_service_set_error "service rollback requires root privileges"
        return 2
    }
    patch_service_load_transaction "$root" "$transaction_directory" || return 2
    case "$PATCH_SERVICE_TRANSACTION_STATE" in
        rolled_back)
            _patch_service_classify_loaded_state strict before || {
                _patch_service_set_error "rolled-back service transaction has drifted"
                return 2
            }
            return 0
            ;;
        verified)
            _patch_service_classify_loaded_state "$mode" after || {
                _patch_service_set_error "verified service transaction does not match its applied snapshot"
                return 2
            }
            ;;
        applying|rollback_in_progress|rollback_failed)
            [ "$mode" = transition ] || {
                _patch_service_set_error "transitional service state requires transition rollback mode"
                return 2
            }
            _patch_service_classify_loaded_state transition transition || {
                _patch_service_set_error "transitional service transaction contains unrecognized drift"
                return 2
            }
            ;;
        planned)
            _patch_service_set_error "planned service transaction has not been applied"
            return 2
            ;;
        *) return 2 ;;
    esac
    PATCH_SERVICE_APPLY_STARTED=1
    PATCH_SERVICE_TRANSACTION_LOADED=1
    patch_service_rollback
}

_patch_service_write_manifest() {
    local manifest="$PATCH_SERVICE_DATA_DIRECTORY/manifest.tsv"
    local index=0
    local criterion=""
    local approval=""

    [ ! -e "$manifest" ] && [ ! -L "$manifest" ] || return 2
    {
        printf 'schema\trecord_type\tcriterion\tobject\tbefore_state\tmetadata\n'
        for criterion in "${PATCH_SERVICE_SELECTED_CRITERIA[@]}"; do
            approval="${PATCH_SERVICE_INTENT_APPROVALS[$criterion]}"
            printf '1\tintent\t%s\tallow-disable\t%s\troot=%s:%s\n' \
                "$criterion" "$approval" "$PATCH_SERVICE_ROOT_DEVICE" "$PATCH_SERVICE_ROOT_INODE"
        done
        while [ "$index" -lt "${#PATCH_SERVICE_UNIT_NAMES[@]}" ]; do
            printf '1\tsystemd\t%s\t%s\t%s/%s\tid=%s;unit_file=%s;aliases=%s;fragment=%s;dropins=%s;triggers=%s;triggered_by=%s\n' \
                "${PATCH_SERVICE_UNIT_CRITERIA[$index]}" "${PATCH_SERVICE_UNIT_NAMES[$index]}" \
                "${PATCH_SERVICE_UNIT_ACTIVE_STATES[$index]}" "${PATCH_SERVICE_UNIT_SUB_STATES[$index]}" \
                "${PATCH_SERVICE_UNIT_IDS[$index]}" "${PATCH_SERVICE_UNIT_FILE_STATES[$index]}" \
                "${PATCH_SERVICE_UNIT_ALIASES[$index]}" "${PATCH_SERVICE_UNIT_FRAGMENTS[$index]}" \
                "${PATCH_SERVICE_UNIT_DROPINS[$index]}" "${PATCH_SERVICE_UNIT_TRIGGERS[$index]}" \
                "${PATCH_SERVICE_UNIT_TRIGGERED_BY[$index]}"
            index=$((index + 1))
        done
        index=0
        while [ "$index" -lt "${#PATCH_SERVICE_SYSV_NAMES[@]}" ]; do
            printf '1\tsysv\t%s\t%s\t%s\tlinks=%s\n' \
                "${PATCH_SERVICE_SYSV_CRITERIA[$index]}" "${PATCH_SERVICE_SYSV_NAMES[$index]}" \
                "${PATCH_SERVICE_SYSV_ACTIVE[$index]}" \
                "$(printf '%s' "${PATCH_SERVICE_SYSV_LINK_RECORDS[$index]}" | tr '\n\t' ',|')"
            index=$((index + 1))
        done
        index=0
        while [ "$index" -lt "${#PATCH_SERVICE_FILE_PATHS[@]}" ]; do
            printf '1\t%s\t%s\t%s\tpresent\tdevice=%s;inode=%s;uid=%s;gid=%s;mode=%s;size=%s;mtime=%s;ctime=%s;sha256=%s;desired_sha256=%s\n' \
                "${PATCH_SERVICE_FILE_KINDS[$index]}" "${PATCH_SERVICE_FILE_CRITERIA[$index]}" \
                "${PATCH_SERVICE_FILE_PATHS[$index]}" "${PATCH_SERVICE_FILE_DEVICES[$index]}" \
                "${PATCH_SERVICE_FILE_INODES[$index]}" "${PATCH_SERVICE_FILE_UIDS[$index]}" \
                "${PATCH_SERVICE_FILE_GIDS[$index]}" "${PATCH_SERVICE_FILE_MODES[$index]}" \
                "${PATCH_SERVICE_FILE_SIZES[$index]}" "${PATCH_SERVICE_FILE_MTIMES[$index]}" \
                "${PATCH_SERVICE_FILE_CTIMES[$index]}" "${PATCH_SERVICE_FILE_SHA256S[$index]}" \
                "${PATCH_SERVICE_FILE_DESIRED_SHA256S[$index]}"
            index=$((index + 1))
        done
        index=0
        while [ "$index" -lt "${#PATCH_SERVICE_ENDPOINT_CRITERIA[@]}" ]; do
            printf '1\tlistener\t%s\t%s:%s\t%s\t-\n' \
                "${PATCH_SERVICE_ENDPOINT_CRITERIA[$index]}" "${PATCH_SERVICE_ENDPOINT_TRANSPORTS[$index]}" \
                "${PATCH_SERVICE_ENDPOINT_PORTS[$index]}" "${PATCH_SERVICE_ENDPOINT_BEFORE[$index]}"
            index=$((index + 1))
        done
        index=0
        while [ "$index" -lt "${#PATCH_SERVICE_PROCESS_CRITERIA[@]}" ]; do
            printf '1\tprocess\t%s\t%s\t%s\t-\n' \
                "${PATCH_SERVICE_PROCESS_CRITERIA[$index]}" "${PATCH_SERVICE_PROCESS_NAMES[$index]}" \
                "${PATCH_SERVICE_PROCESS_BEFORE[$index]}"
            index=$((index + 1))
        done
    } > "$manifest" || return 2
    chmod 0600 "$manifest" || return 2
    _patch_service_artifact_is_protected "$manifest" 600
}

patch_service_write_plan_tsv() {
    local output_path="$1"

    [ "$PATCH_SERVICE_PLAN_VALID" -eq 1 ] || return 2
    case "$output_path" in /*) ;; *) return 2 ;; esac
    _patch_service_write_rendered_artifact "$output_path" _patch_service_render_plan
}

patch_service_plan() {
    local root="$1"
    local transaction_directory="$2"
    local criterion=""
    local seen=","

    shift 2
    patch_service_reset
    [ "$#" -gt 0 ] || return 2
    for criterion in "$@"; do
        _patch_service_valid_criterion "$criterion" || return 1
        case "$seen" in *",$criterion,"*) return 2 ;; esac
        seen+="$criterion,"
        [ "${PATCH_SERVICE_INTENT_DECISIONS[$criterion]:-}" = allow-disable ] || {
            _patch_service_set_error "$criterion: explicit allow-disable intent is required"
            return 2
        }
        PATCH_SERVICE_SELECTED_CRITERIA+=("$criterion")
        PATCH_SERVICE_CRITERION_STATES["$criterion"]=compliant
        PATCH_SERVICE_CRITERION_CHANGES["$criterion"]=0
    done
    _patch_service_initialize_root "$root" || {
        _patch_service_set_error "scan root is unavailable or unsafe"
        return 2
    }
    _patch_service_prepare_transaction "$transaction_directory" || {
        _patch_service_set_error "service transaction directory is unsafe"
        return 2
    }
    for criterion in "${PATCH_SERVICE_SELECTED_CRITERIA[@]}"; do
        _patch_service_snapshot_systemd "$criterion" || {
            _patch_service_cleanup_transaction >/dev/null 2>&1 || true
            _patch_service_set_error "$criterion: systemd activation snapshot failed"
            return 2
        }
        _patch_service_snapshot_sysv "$criterion" || {
            _patch_service_cleanup_transaction >/dev/null 2>&1 || true
            _patch_service_set_error "$criterion: SysV activation snapshot failed"
            return 2
        }
        _patch_service_snapshot_legacy_files "$criterion" || {
            _patch_service_cleanup_transaction >/dev/null 2>&1 || true
            _patch_service_set_error "$criterion: inetd or xinetd snapshot failed"
            return 2
        }
        _patch_service_snapshot_endpoints "$criterion" || {
            _patch_service_cleanup_transaction >/dev/null 2>&1 || true
            _patch_service_set_error "$criterion: listener snapshot failed"
            return 2
        }
        _patch_service_snapshot_processes "$criterion" || {
            _patch_service_cleanup_transaction >/dev/null 2>&1 || true
            _patch_service_set_error "$criterion: process snapshot failed"
            return 2
        }
    done
    _patch_service_validate_endpoint_manageability || {
        _patch_service_cleanup_transaction >/dev/null 2>&1 || true
        return 2
    }
    for criterion in "${PATCH_SERVICE_SELECTED_CRITERIA[@]}"; do
        if [ "${PATCH_SERVICE_CRITERION_CHANGES[$criterion]}" -eq 0 ]; then
            PATCH_SERVICE_COMPLIANT_COUNT=$((PATCH_SERVICE_COMPLIANT_COUNT + 1))
        fi
    done
    _patch_service_write_manifest || {
        _patch_service_cleanup_transaction >/dev/null 2>&1 || true
        _patch_service_set_error "cannot write protected service transaction"
        return 2
    }
    PATCH_SERVICE_SNAPSHOT_PATH="$PATCH_SERVICE_DATA_DIRECTORY/snapshot.tsv"
    _patch_service_write_rendered_artifact "$PATCH_SERVICE_SNAPSHOT_PATH" _patch_service_render_snapshot || {
        _patch_service_cleanup_transaction >/dev/null 2>&1 || true
        _patch_service_set_error "cannot write protected service snapshot"
        return 2
    }
    PATCH_SERVICE_INTERNAL_PLAN_PATH="$PATCH_SERVICE_DATA_DIRECTORY/plan.tsv"
    _patch_service_write_rendered_artifact "$PATCH_SERVICE_INTERNAL_PLAN_PATH" _patch_service_render_plan || {
        _patch_service_cleanup_transaction >/dev/null 2>&1 || true
        _patch_service_set_error "cannot write protected service plan"
        return 2
    }
    _patch_service_write_checksums || {
        _patch_service_cleanup_transaction >/dev/null 2>&1 || true
        _patch_service_set_error "cannot write service transaction checksums"
        return 2
    }
    _patch_service_set_state planned || {
        _patch_service_cleanup_transaction >/dev/null 2>&1 || true
        _patch_service_set_error "cannot initialize service transaction state"
        return 2
    }
    PATCH_SERVICE_PLAN_VALID=1
}

_patch_service_apply_root_allowed() {
    [ "$PATCH_SERVICE_ROOT" = / ]
}

_patch_service_preflight() {
    local index=0
    local current_links=""
    local state=0

    [ "$PATCH_SERVICE_PLAN_VALID" -eq 1 ] || return 2
    [ "${EUID:-$(id -u)}" -eq 0 ] || return 2
    _patch_service_apply_root_allowed || return 2
    _patch_service_root_identity_is_current || return 2
    while [ "$index" -lt "${#PATCH_SERVICE_UNIT_NAMES[@]}" ]; do
        _patch_service_unit_state_is_current "$index" || return 2
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_SERVICE_SYSV_NAMES[@]}" ]; do
        if _patch_service_sysv_is_active "${PATCH_SERVICE_SYSV_NAMES[$index]}"; then
            state=1
        else
            state=$?
            [ "$state" -eq 1 ] || return 2
            state=0
        fi
        [ "$state" -eq "${PATCH_SERVICE_SYSV_ACTIVE[$index]}" ] || return 2
        current_links="$(_patch_service_sysv_link_records "${PATCH_SERVICE_SYSV_NAMES[$index]}")" || return 2
        [ "$current_links" = "${PATCH_SERVICE_SYSV_LINK_RECORDS[$index]}" ] || return 2
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_SERVICE_FILE_PATHS[@]}" ]; do
        _patch_service_file_fingerprint_is_current "$index" || return 2
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_SERVICE_ENDPOINT_CRITERIA[@]}" ]; do
        state=0
        _patch_service_listener_active "${PATCH_SERVICE_ENDPOINT_TRANSPORTS[$index]}" \
            "${PATCH_SERVICE_ENDPOINT_PORTS[$index]}" || state=$?
        case "${PATCH_SERVICE_ENDPOINT_BEFORE[$index]}:$state" in
            active:0|inactive:1) ;;
            *) return 2 ;;
        esac
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_SERVICE_PROCESS_CRITERIA[@]}" ]; do
        state=0
        _patch_service_process_active "${PATCH_SERVICE_PROCESS_NAMES[$index]}" || state=$?
        case "${PATCH_SERVICE_PROCESS_BEFORE[$index]}:$state" in
            active:0|inactive:1) ;;
            *) return 2 ;;
        esac
        index=$((index + 1))
    done
}

_patch_service_apply_unit() {
    local index="$1"
    local unit_name="${PATCH_SERVICE_UNIT_IDS[$index]}"

    PATCH_SERVICE_UNIT_APPLIED[$index]=1
    case "${PATCH_SERVICE_UNIT_ACTIVE_STATES[$index]}" in
        active|activating|reloading)
            _patch_service_systemctl_change stop "$unit_name" || return 2
            ;;
    esac
    case "${PATCH_SERVICE_UNIT_FILE_STATES[$index]}" in
        enabled|enabled-runtime|linked|linked-runtime|alias)
            _patch_service_systemctl_change disable "$unit_name" || return 2
            ;;
    esac
    _patch_service_systemctl_change mask "$unit_name" || return 2
}

_patch_service_apply_systemd_type() {
    local unit_type="$1"
    local index=0

    while [ "$index" -lt "${#PATCH_SERVICE_UNIT_NAMES[@]}" ]; do
        case "${PATCH_SERVICE_UNIT_IDS[$index]}" in
            *."$unit_type") _patch_service_apply_unit "$index" || return 2 ;;
        esac
        index=$((index + 1))
    done
}

_patch_service_apply_sysv() {
    local index=0

    while [ "$index" -lt "${#PATCH_SERVICE_SYSV_NAMES[@]}" ]; do
        PATCH_SERVICE_SYSV_APPLIED[$index]=1
        if [ "${PATCH_SERVICE_SYSV_ACTIVE[$index]}" -eq 1 ]; then
            _patch_service_sysv_change stop "${PATCH_SERVICE_SYSV_NAMES[$index]}" || return 2
        fi
        _patch_service_remove_sysv_links "$index" || return 2
        index=$((index + 1))
    done
}

_patch_service_apply_files() {
    local index=0
    local after_device="" after_inode="" after_uid="" after_gid="" after_mode=""
    local after_size="" after_mtime="" after_ctime="" after_sha256=""

    while [ "$index" -lt "${#PATCH_SERVICE_FILE_PATHS[@]}" ]; do
        PATCH_SERVICE_FILE_APPLIED[$index]=1
        PATCH_SERVICE_FILE_AFTER_DEVICES[$index]="${PATCH_SERVICE_FILE_DEVICES[$index]}"
        PATCH_SERVICE_FILE_AFTER_INODES[$index]="${PATCH_SERVICE_FILE_INODES[$index]}"
        _patch_service_replace_file "${PATCH_SERVICE_FILE_PAYLOADS[$index]}" \
            "${PATCH_SERVICE_FILE_PATHS[$index]}" "${PATCH_SERVICE_FILE_UIDS[$index]}" \
            "${PATCH_SERVICE_FILE_GIDS[$index]}" "${PATCH_SERVICE_FILE_MODES[$index]}" || return 2
        PATCH_SERVICE_FILE_WRITE_COMPLETED[$index]=1
        _patch_service_file_metadata_into "${PATCH_SERVICE_FILE_PATHS[$index]}" after || return 2
        PATCH_SERVICE_FILE_AFTER_DEVICES[$index]="$after_device"
        PATCH_SERVICE_FILE_AFTER_INODES[$index]="$after_inode"
        _patch_service_sha256_into "${PATCH_SERVICE_FILE_PATHS[$index]}" after_sha256 || return 2
        [ "$after_uid" = "${PATCH_SERVICE_FILE_UIDS[$index]}" ] &&
            [ "$after_gid" = "${PATCH_SERVICE_FILE_GIDS[$index]}" ] &&
            [ "$after_mode" = "${PATCH_SERVICE_FILE_MODES[$index]}" ] &&
            [ "$after_sha256" = "${PATCH_SERVICE_FILE_DESIRED_SHA256S[$index]}" ] || return 2
        index=$((index + 1))
    done
}

_patch_service_reload_legacy_supervisors() {
    local systemctl_command=""
    local script_path=""
    local supervisor=""

    if [ "$PATCH_SERVICE_ROOT" = / ] && _patch_service_command_into systemctl systemctl_command; then
        "$systemctl_command" try-reload-or-restart inetd.service xinetd.service >/dev/null 2>&1 || true
    fi
    for supervisor in inetd xinetd; do
        _patch_service_root_path_into "/etc/init.d/$supervisor" script_path || return 2
        if [ "$PATCH_SERVICE_ROOT" = / ] && [ -x "$script_path" ]; then
            "$script_path" reload >/dev/null 2>&1 || "$script_path" restart >/dev/null 2>&1 || return 2
        fi
    done
}

patch_service_verify() {
    local index=0
    local state=0
    local current_sha256=""

    _patch_service_root_identity_is_current || return 2
    while [ "$index" -lt "${#PATCH_SERVICE_UNIT_NAMES[@]}" ]; do
        _patch_service_unit_is_disabled "$index" || return 2
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_SERVICE_SYSV_NAMES[@]}" ]; do
        _patch_service_sysv_is_disabled "$index" || return 2
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_SERVICE_FILE_PATHS[@]}" ]; do
        _patch_service_sha256_into "${PATCH_SERVICE_FILE_PATHS[$index]}" current_sha256 || return 2
        [ "$current_sha256" = "${PATCH_SERVICE_FILE_DESIRED_SHA256S[$index]}" ] || return 2
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_SERVICE_ENDPOINT_CRITERIA[@]}" ]; do
        state=0
        _patch_service_listener_active "${PATCH_SERVICE_ENDPOINT_TRANSPORTS[$index]}" \
            "${PATCH_SERVICE_ENDPOINT_PORTS[$index]}" || state=$?
        [ "$state" -eq 1 ] || return 2
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_SERVICE_PROCESS_CRITERIA[@]}" ]; do
        state=0
        _patch_service_process_active "${PATCH_SERVICE_PROCESS_NAMES[$index]}" || state=$?
        [ "$state" -eq 1 ] || return 2
        index=$((index + 1))
    done
    for index in "${!PATCH_SERVICE_SELECTED_CRITERIA[@]}"; do
        PATCH_SERVICE_CRITERION_STATES["${PATCH_SERVICE_SELECTED_CRITERIA[$index]}"]=verified
    done
    _patch_service_set_state verified || return 2
    PATCH_SERVICE_VERIFIED=1
}

_patch_service_restore_file() {
    local index="$1"
    local current_device="" current_inode="" current_uid="" current_gid="" current_mode=""
    local current_size="" current_mtime="" current_ctime="" current_sha256=""

    _patch_service_file_metadata_into "${PATCH_SERVICE_FILE_PATHS[$index]}" current || return 2
    _patch_service_sha256_into "${PATCH_SERVICE_FILE_PATHS[$index]}" current_sha256 || return 2
    [ "$current_device" = "${PATCH_SERVICE_FILE_AFTER_DEVICES[$index]}" ] &&
        [ "$current_inode" = "${PATCH_SERVICE_FILE_AFTER_INODES[$index]}" ] || return 2
    if [ "${PATCH_SERVICE_FILE_WRITE_COMPLETED[$index]}" -eq 1 ]; then
        [ "$current_sha256" = "${PATCH_SERVICE_FILE_DESIRED_SHA256S[$index]}" ] || return 2
    fi
    _patch_service_replace_file "${PATCH_SERVICE_FILE_BACKUPS[$index]}" \
        "${PATCH_SERVICE_FILE_PATHS[$index]}" "${PATCH_SERVICE_FILE_UIDS[$index]}" \
        "${PATCH_SERVICE_FILE_GIDS[$index]}" "${PATCH_SERVICE_FILE_MODES[$index]}" || return 2
    _patch_service_sha256_into "${PATCH_SERVICE_FILE_PATHS[$index]}" current_sha256 || return 2
    [ "$current_sha256" = "${PATCH_SERVICE_FILE_SHA256S[$index]}" ]
}

_patch_service_restore_sysv() {
    local index="$1"

    _patch_service_restore_sysv_links "$index" || return 2
    if [ "${PATCH_SERVICE_SYSV_ACTIVE[$index]}" -eq 1 ]; then
        _patch_service_sysv_change start "${PATCH_SERVICE_SYSV_NAMES[$index]}" || return 2
    fi
}

_patch_service_restore_unit() {
    local index="$1"
    local unit_name="${PATCH_SERVICE_UNIT_IDS[$index]}"

    _patch_service_systemctl_change unmask "$unit_name" || return 2
    case "${PATCH_SERVICE_UNIT_FILE_STATES[$index]}" in
        masked) ;;
        enabled) _patch_service_systemctl_change enable "$unit_name" || return 2 ;;
        enabled-runtime) _patch_service_systemctl_change enable-runtime "$unit_name" || return 2 ;;
        disabled|static|indirect|generated|transient|alias|'') ;;
        linked|linked-runtime) return 2 ;;
        *) return 2 ;;
    esac
    case "${PATCH_SERVICE_UNIT_ACTIVE_STATES[$index]}" in
        active|activating|reloading) _patch_service_systemctl_change start "$unit_name" || return 2 ;;
    esac
    if [ "${PATCH_SERVICE_UNIT_FILE_STATES[$index]}" = masked ]; then
        _patch_service_systemctl_change mask "$unit_name" || return 2
    fi
}

patch_service_rollback() {
    local index=0
    local failures=0
    local endpoint_state=0
    local process_state=0

    [ "$PATCH_SERVICE_APPLY_STARTED" -eq 1 ] || return 2
    _patch_service_set_state rollback_in_progress || return 2
    index=$(( ${#PATCH_SERVICE_FILE_PATHS[@]} - 1 ))
    while [ "$index" -ge 0 ]; do
        if [ "${PATCH_SERVICE_FILE_APPLIED[$index]}" -eq 1 ]; then
            _patch_service_restore_file "$index" || failures=$((failures + 1))
        fi
        index=$((index - 1))
    done
    _patch_service_reload_legacy_supervisors || failures=$((failures + 1))
    index=$(( ${#PATCH_SERVICE_SYSV_NAMES[@]} - 1 ))
    while [ "$index" -ge 0 ]; do
        if [ "${PATCH_SERVICE_SYSV_APPLIED[$index]}" -eq 1 ]; then
            _patch_service_restore_sysv "$index" || failures=$((failures + 1))
        fi
        index=$((index - 1))
    done
    index=$(( ${#PATCH_SERVICE_UNIT_NAMES[@]} - 1 ))
    while [ "$index" -ge 0 ]; do
        if [ "${PATCH_SERVICE_UNIT_APPLIED[$index]}" -eq 1 ]; then
            _patch_service_restore_unit "$index" || failures=$((failures + 1))
        fi
        index=$((index - 1))
    done
    if [ "${#PATCH_SERVICE_UNIT_NAMES[@]}" -gt 0 ]; then
        _patch_service_systemctl_change daemon-reload || failures=$((failures + 1))
    fi
    index=0
    while [ "$index" -lt "${#PATCH_SERVICE_ENDPOINT_CRITERIA[@]}" ]; do
        endpoint_state=0
        _patch_service_listener_active "${PATCH_SERVICE_ENDPOINT_TRANSPORTS[$index]}" \
            "${PATCH_SERVICE_ENDPOINT_PORTS[$index]}" || endpoint_state=$?
        case "${PATCH_SERVICE_ENDPOINT_BEFORE[$index]}:$endpoint_state" in
            active:0|inactive:1) ;;
            *) failures=$((failures + 1)) ;;
        esac
        index=$((index + 1))
    done
    index=0
    while [ "$index" -lt "${#PATCH_SERVICE_PROCESS_CRITERIA[@]}" ]; do
        process_state=0
        _patch_service_process_active "${PATCH_SERVICE_PROCESS_NAMES[$index]}" || process_state=$?
        case "${PATCH_SERVICE_PROCESS_BEFORE[$index]}:$process_state" in
            active:0|inactive:1) ;;
            *) failures=$((failures + 1)) ;;
        esac
        index=$((index + 1))
    done
    [ "$failures" -eq 0 ] || {
        PATCH_SERVICE_ERROR_DETAIL="service rollback was incomplete: failures=$failures"
        _patch_service_set_state rollback_failed >/dev/null 2>&1 || true
        return 2
    }
    for index in "${!PATCH_SERVICE_SELECTED_CRITERIA[@]}"; do
        PATCH_SERVICE_CRITERION_STATES["${PATCH_SERVICE_SELECTED_CRITERIA[$index]}"]=rolled_back
    done
    _patch_service_set_state rolled_back || return 2
    PATCH_SERVICE_VERIFIED=0
}

patch_service_apply() {
    local status=0

    _patch_service_preflight || {
        _patch_service_set_error "service state changed before apply or apply is not authorized"
        return 2
    }
    PATCH_SERVICE_APPLY_STARTED=1
    _patch_service_set_state applying || return 2
    _patch_service_apply_systemd_type path || status=2
    [ "$status" -eq 0 ] && _patch_service_apply_systemd_type timer || status=2
    [ "$status" -eq 0 ] && _patch_service_apply_systemd_type socket || status=2
    [ "$status" -eq 0 ] && _patch_service_apply_systemd_type service || status=2
    if [ "$status" -eq 0 ] && [ "${#PATCH_SERVICE_UNIT_NAMES[@]}" -gt 0 ]; then
        _patch_service_systemctl_change daemon-reload || status=2
    fi
    [ "$status" -eq 0 ] && _patch_service_apply_sysv || status=2
    [ "$status" -eq 0 ] && _patch_service_apply_files || status=2
    [ "$status" -eq 0 ] && _patch_service_reload_legacy_supervisors || status=2
    [ "$status" -eq 0 ] && patch_service_verify || status=2
    if [ "$status" -ne 0 ]; then
        PATCH_SERVICE_ERROR_DETAIL="service apply or verification failed"
        patch_service_rollback || PATCH_SERVICE_ERROR_DETAIL+="; automatic rollback was incomplete"
        return 2
    fi
}
