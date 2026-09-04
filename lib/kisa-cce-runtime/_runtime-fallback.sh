# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash
# shellcheck disable=SC2034

# Provides conservative procfs runtime facts when native service tools are unavailable.

RUNTIME_FALLBACK_PROC_ROOT="${RUNTIME_FALLBACK_PROC_ROOT:-/proc}"
RUNTIME_FALLBACK_RUN_ROOT="${RUNTIME_FALLBACK_RUN_ROOT:-/run}"
RUNTIME_FALLBACK_FIND_COMMAND="${RUNTIME_FALLBACK_FIND_COMMAND:-/usr/bin/find}"
RUNTIME_FALLBACK_MAX_PROCESSES="${RUNTIME_FALLBACK_MAX_PROCESSES:-32768}"
RUNTIME_FALLBACK_MAX_FIELD_BYTES="${RUNTIME_FALLBACK_MAX_FIELD_BYTES:-1024}"

PROCFS_RUNTIME_CACHE_EPOCH=""
PROCFS_RUNTIME_CACHE_PROC_ROOT=""
PROCFS_RUNTIME_CACHE_RUN_ROOT=""
PROCFS_RUNTIME_PROCESS_READY=0
PROCFS_RUNTIME_PROCESS_STATUS=2
PROCFS_RUNTIME_PROCESS_ROWS=""
PROCFS_RUNTIME_PROCESS_READ_ERRORS=0
PROCFS_RUNTIME_PROCESS_TRUNCATED=0
PROCFS_RUNTIME_LISTENER_READY=0
PROCFS_RUNTIME_LISTENER_STATUS=2
PROCFS_RUNTIME_LISTENER_ROWS=""
PROCFS_RUNTIME_SOCKET_TABLES_READ=0
PROCFS_RUNTIME_SOCKET_TABLE_ERRORS=0
PROCFS_RUNTIME_SOCKET_MALFORMED_ROWS=0
PROCFS_RUNTIME_MANAGER_READY=0
PROCFS_RUNTIME_MANAGER_STATUS=2

declare -gA PROCFS_RUNTIME_PID_COMM=()
declare -gA PROCFS_RUNTIME_PID_RAW_COMM=()
declare -gA PROCFS_RUNTIME_PID_EXE=()
declare -gA PROCFS_RUNTIME_PROCESS_NAME=()
declare -gA PROCFS_RUNTIME_SOCKET_PID=()
declare -gA PROCFS_RUNTIME_SOCKET_COMM=()
declare -gA PROCFS_RUNTIME_LISTENER_ROWS_BY_KEY=()

procfs_runtime_destination_is_valid() {
    case "${1-}" in
        ''|[0-9]*|*[!A-Za-z0-9_]*) return 1 ;;
    esac
}

procfs_runtime_numeric_setting_is_valid() {
    local value="${1-}"

    case "$value" in ''|*[!0-9]*) return 1 ;; esac
    [ "$value" -gt 0 ]
}

procfs_runtime_safe_field_into() {
    local input_value="$1"
    local destination_name="$2"
    local maximum_bytes="${3:-$RUNTIME_FALLBACK_MAX_FIELD_BYTES}"
    local encoded_value=""
    local character=""
    local encoded_character=""
    local byte_value=0
    local index_value=0

    procfs_runtime_destination_is_valid "$destination_name" || return 2
    procfs_runtime_numeric_setting_is_valid "$maximum_bytes" || return 2
    while [ "$index_value" -lt "${#input_value}" ]; do
        character="${input_value:index_value:1}"
        case "$character" in
            [A-Za-z0-9._@:+/=-]) encoded_character="$character" ;;
            *)
                printf -v byte_value '%d' "'$character"
                printf -v encoded_character '%%%02X' "$byte_value"
                ;;
        esac
        if [ $((${#encoded_value} + ${#encoded_character})) -gt "$maximum_bytes" ]; then
            encoded_value+="~"
            break
        fi
        encoded_value+="$encoded_character"
        index_value=$((index_value + 1))
    done
    [ -n "$encoded_value" ] || encoded_value="-"
    printf -v "$destination_name" '%s' "$encoded_value"
}

runtime_fallback_reset_epoch_cache() {
    PROCFS_RUNTIME_CACHE_EPOCH=""
    PROCFS_RUNTIME_CACHE_PROC_ROOT=""
    PROCFS_RUNTIME_CACHE_RUN_ROOT=""
    PROCFS_RUNTIME_PROCESS_READY=0
    PROCFS_RUNTIME_PROCESS_STATUS=2
    PROCFS_RUNTIME_PROCESS_ROWS=""
    PROCFS_RUNTIME_PROCESS_READ_ERRORS=0
    PROCFS_RUNTIME_PROCESS_TRUNCATED=0
    PROCFS_RUNTIME_LISTENER_READY=0
    PROCFS_RUNTIME_LISTENER_STATUS=2
    PROCFS_RUNTIME_LISTENER_ROWS=""
    PROCFS_RUNTIME_SOCKET_TABLES_READ=0
    PROCFS_RUNTIME_SOCKET_TABLE_ERRORS=0
    PROCFS_RUNTIME_SOCKET_MALFORMED_ROWS=0
    PROCFS_RUNTIME_MANAGER_READY=0
    PROCFS_RUNTIME_MANAGER_STATUS=2
    PROCFS_RUNTIME_PID_COMM=()
    PROCFS_RUNTIME_PID_RAW_COMM=()
    PROCFS_RUNTIME_PID_EXE=()
    PROCFS_RUNTIME_PROCESS_NAME=()
    PROCFS_RUNTIME_SOCKET_PID=()
    PROCFS_RUNTIME_SOCKET_COMM=()
    PROCFS_RUNTIME_LISTENER_ROWS_BY_KEY=()
}

procfs_runtime_ensure_epoch() {
    local epoch_value="${SCAN_EPOCH_ID:-0}"

    case "$epoch_value" in ''|*[!0-9]*) return 2 ;; esac
    if [ "$PROCFS_RUNTIME_CACHE_EPOCH" != "$epoch_value" ] ||
        [ "$PROCFS_RUNTIME_CACHE_PROC_ROOT" != "$RUNTIME_FALLBACK_PROC_ROOT" ] ||
        [ "$PROCFS_RUNTIME_CACHE_RUN_ROOT" != "$RUNTIME_FALLBACK_RUN_ROOT" ]; then
        runtime_fallback_reset_epoch_cache
        PROCFS_RUNTIME_CACHE_EPOCH="$epoch_value"
        PROCFS_RUNTIME_CACHE_PROC_ROOT="$RUNTIME_FALLBACK_PROC_ROOT"
        PROCFS_RUNTIME_CACHE_RUN_ROOT="$RUNTIME_FALLBACK_RUN_ROOT"
    fi
}

procfs_runtime_collect_executable_links() {
    local -a executable_paths=("$@")
    local executable_path=""
    local executable_target=""
    local executable_fd=""
    local find_pid=""
    local pid_value=""
    local relative_path=""
    local encoded_target=""
    local find_status=0

    [ "${#executable_paths[@]}" -gt 0 ] || return 0
    [ -x "$RUNTIME_FALLBACK_FIND_COMMAND" ] || return 1
    exec {executable_fd}< <(
        "$RUNTIME_FALLBACK_FIND_COMMAND" "${executable_paths[@]}" \
            -maxdepth 0 -type l -printf '%p\0%l\0' 2>/dev/null
    ) || return 1
    find_pid=$!
    while IFS= read -r -d '' -u "$executable_fd" executable_path &&
        IFS= read -r -d '' -u "$executable_fd" executable_target; do
        relative_path="${executable_path#"$RUNTIME_FALLBACK_PROC_ROOT"/}"
        pid_value="${relative_path%%/*}"
        case "$pid_value" in ''|*[!0-9]*) continue ;; esac
        procfs_runtime_safe_field_into "$executable_target" encoded_target || {
            exec {executable_fd}<&-
            wait "$find_pid" 2>/dev/null || :
            return 1
        }
        PROCFS_RUNTIME_PID_EXE["$pid_value"]="$encoded_target"
        executable_target="${executable_target##*/}"
        procfs_runtime_safe_field_into "$executable_target" encoded_target || continue
        PROCFS_RUNTIME_PROCESS_NAME["$encoded_target"]=1
    done
    exec {executable_fd}<&-
    wait "$find_pid" || find_status=$?
    [ "$find_status" -eq 0 ]
}

procfs_runtime_collect_socket_owners() {
    local -a descriptor_directories=("$@")
    local descriptor_path=""
    local descriptor_target=""
    local descriptor_fd=""
    local find_pid=""
    local pid_value=""
    local relative_path=""
    local inode_value=""
    local find_status=0

    [ "${#descriptor_directories[@]}" -gt 0 ] || return 0
    [ -x "$RUNTIME_FALLBACK_FIND_COMMAND" ] || return 1
    exec {descriptor_fd}< <(
        "$RUNTIME_FALLBACK_FIND_COMMAND" "${descriptor_directories[@]}" \
            -mindepth 1 -maxdepth 1 -type l -printf '%p\0%l\0' 2>/dev/null
    ) || return 1
    find_pid=$!
    while IFS= read -r -d '' -u "$descriptor_fd" descriptor_path &&
        IFS= read -r -d '' -u "$descriptor_fd" descriptor_target; do
        [[ "$descriptor_target" =~ ^socket:\[([0-9]+)\]$ ]] || continue
        inode_value="${BASH_REMATCH[1]}"
        relative_path="${descriptor_path#"$RUNTIME_FALLBACK_PROC_ROOT"/}"
        pid_value="${relative_path%%/*}"
        case "$pid_value" in ''|*[!0-9]*) continue ;; esac
        if [ -z "${PROCFS_RUNTIME_SOCKET_PID[$inode_value]+present}" ]; then
            PROCFS_RUNTIME_SOCKET_PID["$inode_value"]="$pid_value"
            PROCFS_RUNTIME_SOCKET_COMM["$inode_value"]="${PROCFS_RUNTIME_PID_COMM[$pid_value]:--}"
        fi
    done
    exec {descriptor_fd}<&-
    wait "$find_pid" || find_status=$?
    [ "$find_status" -eq 0 ]
}

procfs_runtime_prepare_process_snapshot() {
    local -a process_directories=()
    local -a executable_paths=()
    local -a descriptor_directories=()
    local process_directory=""
    local process_name=""
    local pid_value=""
    local comm_value=""
    local encoded_comm=""
    local executable_value=""
    local process_count=0
    local partial=0
    local had_nullglob=0

    procfs_runtime_ensure_epoch || return 2
    [ "$PROCFS_RUNTIME_PROCESS_READY" -eq 0 ] || return "$PROCFS_RUNTIME_PROCESS_STATUS"
    PROCFS_RUNTIME_PROCESS_READY=1
    PROCFS_RUNTIME_PROCESS_STATUS=2
    PROCFS_RUNTIME_PROCESS_ROWS=""
    PROCFS_RUNTIME_PROCESS_READ_ERRORS=0
    PROCFS_RUNTIME_PROCESS_TRUNCATED=0

    [ -d "$RUNTIME_FALLBACK_PROC_ROOT" ] && [ -x "$RUNTIME_FALLBACK_PROC_ROOT" ] || return 2
    procfs_runtime_numeric_setting_is_valid "$RUNTIME_FALLBACK_MAX_PROCESSES" || return 2
    shopt -q nullglob && had_nullglob=1
    shopt -s nullglob
    process_directories=("$RUNTIME_FALLBACK_PROC_ROOT"/[0-9]*)
    [ "$had_nullglob" -eq 1 ] || shopt -u nullglob
    [ "${#process_directories[@]}" -gt 0 ] || return 2

    for process_directory in "${process_directories[@]}"; do
        [ -d "$process_directory" ] || continue
        pid_value="${process_directory##*/}"
        case "$pid_value" in ''|*[!0-9]*) continue ;; esac
        if [ "$process_count" -ge "$RUNTIME_FALLBACK_MAX_PROCESSES" ]; then
            PROCFS_RUNTIME_PROCESS_TRUNCATED=1
            partial=1
            break
        fi
        if ! IFS= read -r comm_value < "$process_directory/comm" 2>/dev/null; then
            [ ! -d "$process_directory" ] || {
                PROCFS_RUNTIME_PROCESS_READ_ERRORS=$((PROCFS_RUNTIME_PROCESS_READ_ERRORS + 1))
                partial=1
            }
            continue
        fi
        procfs_runtime_safe_field_into "$comm_value" encoded_comm 128 || return 2
        PROCFS_RUNTIME_PID_RAW_COMM["$pid_value"]="$comm_value"
        PROCFS_RUNTIME_PID_COMM["$pid_value"]="$encoded_comm"
        PROCFS_RUNTIME_PROCESS_NAME["$encoded_comm"]=1
        [ ! -L "$process_directory/exe" ] || executable_paths+=("$process_directory/exe")
        if [ -d "$process_directory/fd" ] && [ -x "$process_directory/fd" ]; then
            descriptor_directories+=("$process_directory/fd")
        fi
        process_count=$((process_count + 1))
    done

    # Executable links enrich names that exceed TASK_COMM_LEN, but comm remains
    # the authoritative complete process inventory when a link cannot be read.
    procfs_runtime_collect_executable_links "${executable_paths[@]}" || :
    # Socket ownership is optional, so an inaccessible descriptor directory does not
    # make endpoint presence incomplete.
    procfs_runtime_collect_socket_owners "${descriptor_directories[@]}" || :

    for process_directory in "${process_directories[@]}"; do
        pid_value="${process_directory##*/}"
        [ -n "${PROCFS_RUNTIME_PID_COMM[$pid_value]+present}" ] || continue
        executable_value="${PROCFS_RUNTIME_PID_EXE[$pid_value]:--}"
        printf -v process_name '%s\t%s\t%s' \
            "$pid_value" "${PROCFS_RUNTIME_PID_COMM[$pid_value]}" "$executable_value"
        [ -z "$PROCFS_RUNTIME_PROCESS_ROWS" ] || PROCFS_RUNTIME_PROCESS_ROWS+=$'\n'
        PROCFS_RUNTIME_PROCESS_ROWS+="$process_name"
    done
    if [ "$process_count" -eq 0 ]; then
        PROCFS_RUNTIME_PROCESS_STATUS=2
    elif [ "$partial" -eq 1 ]; then
        PROCFS_RUNTIME_PROCESS_STATUS=3
    else
        PROCFS_RUNTIME_PROCESS_STATUS=0
    fi
    return "$PROCFS_RUNTIME_PROCESS_STATUS"
}

runtime_process_snapshot_into() {
    local destination_name="$1"
    local snapshot_status=0

    procfs_runtime_destination_is_valid "$destination_name" || return 2
    if declare -F scan_dependency_register >/dev/null 2>&1; then
        scan_dependency_register runtime:processes procfs:process-snapshot || return 2
    fi
    procfs_runtime_prepare_process_snapshot || snapshot_status=$?
    printf -v "$destination_name" '%s' "$PROCFS_RUNTIME_PROCESS_ROWS"
    return "$snapshot_status"
}

runtime_process_state() {
    local requested_name=""
    local encoded_name=""
    local snapshot_status=0

    [ "$#" -gt 0 ] || return 2
    if declare -F scan_dependency_register >/dev/null 2>&1; then
        scan_dependency_register runtime:processes procfs:process-snapshot || return 2
    fi
    procfs_runtime_prepare_process_snapshot || snapshot_status=$?
    for requested_name in "$@"; do
        case "$requested_name" in ''|*[!A-Za-z0-9._@:+-]*) return 2 ;; esac
        procfs_runtime_safe_field_into "$requested_name" encoded_name 128 || return 2
        [ -z "${PROCFS_RUNTIME_PROCESS_NAME[$encoded_name]+present}" ] || return 0
    done
    [ "$snapshot_status" -eq 0 ] && return 1
    return 2
}

runtime_systemd_manager_state() {
    local manager_name=""
    local manager_file="$RUNTIME_FALLBACK_PROC_ROOT/1/comm"
    local marker_path="$RUNTIME_FALLBACK_RUN_ROOT/systemd/system"

    if declare -F scan_dependency_register >/dev/null 2>&1; then
        scan_dependency_register runtime:system-manager procfs:system-manager || return 2
    fi
    procfs_runtime_ensure_epoch || return 2
    if [ "$PROCFS_RUNTIME_MANAGER_READY" -eq 1 ]; then
        return "$PROCFS_RUNTIME_MANAGER_STATUS"
    fi
    PROCFS_RUNTIME_MANAGER_READY=1
    if [ ! -f "$manager_file" ] || [ ! -r "$manager_file" ] ||
        ! IFS= read -r manager_name < "$manager_file" || [ -z "$manager_name" ]; then
        PROCFS_RUNTIME_MANAGER_STATUS=2
    elif [ "$manager_name" != "systemd" ]; then
        PROCFS_RUNTIME_MANAGER_STATUS=1
    elif [ -d "$marker_path" ] && [ -x "$marker_path" ]; then
        PROCFS_RUNTIME_MANAGER_STATUS=0
    else
        PROCFS_RUNTIME_MANAGER_STATUS=2
    fi
    return "$PROCFS_RUNTIME_MANAGER_STATUS"
}

procfs_runtime_listener_index_append() {
    local transport="$1"
    local port="$2"
    local row_value="$3"
    local key=""

    for key in "$transport:$port" "any:$port"; do
        if [ -n "${PROCFS_RUNTIME_LISTENER_ROWS_BY_KEY[$key]+present}" ]; then
            PROCFS_RUNTIME_LISTENER_ROWS_BY_KEY["$key"]+=$'\n'"$row_value"
        else
            PROCFS_RUNTIME_LISTENER_ROWS_BY_KEY["$key"]="$row_value"
        fi
    done
}

procfs_runtime_ipv4_into() {
    local hexadecimal_value="$1"
    local destination_name="$2"
    local normalized_address=""
    local offset=0
    local byte_value=0

    procfs_runtime_destination_is_valid "$destination_name" || return 2
    case "$hexadecimal_value" in
        ????????) ;;
        *) return 1 ;;
    esac
    case "$hexadecimal_value" in *[!0-9A-Fa-f]*) return 1 ;; esac
    for offset in 6 4 2 0; do
        byte_value=$((16#${hexadecimal_value:offset:2}))
        [ -z "$normalized_address" ] || normalized_address+="."
        normalized_address+="$byte_value"
    done
    printf -v "$destination_name" '%s' "$normalized_address"
}

procfs_runtime_ipv6_into() {
    local hexadecimal_value="$1"
    local destination_name="$2"
    local normalized_hex=""
    local normalized_address=""
    local word_value=""
    local offset=0
    local group_offset=0

    procfs_runtime_destination_is_valid "$destination_name" || return 2
    [ "${#hexadecimal_value}" -eq 32 ] || return 1
    case "$hexadecimal_value" in *[!0-9A-Fa-f]*) return 1 ;; esac
    hexadecimal_value="${hexadecimal_value,,}"
    for offset in 0 8 16 24; do
        word_value="${hexadecimal_value:offset:8}"
        normalized_hex+="${word_value:6:2}${word_value:4:2}${word_value:2:2}${word_value:0:2}"
    done
    for group_offset in 0 4 8 12 16 20 24 28; do
        [ -z "$normalized_address" ] || normalized_address+=":"
        normalized_address+="${normalized_hex:group_offset:4}"
    done
    printf -v "$destination_name" '%s' "$normalized_address"
}

procfs_runtime_parse_socket_table() {
    local table_path="$1"
    local table_name="$2"
    local line_value=""
    local local_endpoint=""
    local remote_endpoint=""
    local address_hex=""
    local port_hex=""
    local address_value=""
    local port_value=0
    local state_hex=""
    local inode_value=""
    local process_value="-"
    local pid_value="-"
    local normalized_state=""
    local normalized_row=""
    local table_fd=""
    local malformed_rows=0
    local -a fields=()

    [ -f "$table_path" ] && [ -r "$table_path" ] || return 2
    if ! { exec {table_fd}<"$table_path"; } 2>/dev/null; then
        return 2
    fi
    while IFS= read -r -u "$table_fd" line_value || [ -n "$line_value" ]; do
        [[ "$line_value" == *local_address* ]] && continue
        [ -n "${line_value//[[:space:]]/}" ] || continue
        read -r -a fields <<< "$line_value"
        if [ "${#fields[@]}" -lt 10 ]; then
            malformed_rows=$((malformed_rows + 1))
            continue
        fi
        local_endpoint="${fields[1]}"
        remote_endpoint="${fields[2]}"
        address_hex="${local_endpoint%:*}"
        port_hex="${local_endpoint##*:}"
        state_hex="${fields[3]}"
        inode_value="${fields[9]}"
        if [ "$address_hex" = "$local_endpoint" ] || [ "${#port_hex}" -ne 4 ] ||
            [[ "$port_hex" == *[!0-9A-Fa-f]* ]] || [ "${#state_hex}" -ne 2 ] ||
            [[ "$state_hex" == *[!0-9A-Fa-f]* ]] || [[ "$inode_value" == *[!0-9]* ]] ||
            [ -z "$inode_value" ]; then
            malformed_rows=$((malformed_rows + 1))
            continue
        fi
        state_hex="${state_hex^^}"
        case "$table_name" in
            tcp|tcp6)
                [ "$state_hex" = "0A" ] || continue
                normalized_state="listen"
                ;;
            udp|udp6)
                [ "$state_hex" = "07" ] || continue
                case "$table_name:$remote_endpoint" in
                    udp:00000000:0000|udp6:00000000000000000000000000000000:0000) ;;
                    *) continue ;;
                esac
                normalized_state="bound"
                ;;
            *)
                exec {table_fd}<&-
                return 2
                ;;
        esac
        port_value=$((16#$port_hex))
        [ "$port_value" -gt 0 ] || continue
        case "$table_name" in
            tcp|udp) procfs_runtime_ipv4_into "$address_hex" address_value || {
                malformed_rows=$((malformed_rows + 1))
                continue
            } ;;
            tcp6|udp6) procfs_runtime_ipv6_into "$address_hex" address_value || {
                malformed_rows=$((malformed_rows + 1))
                continue
            } ;;
        esac
        process_value="${PROCFS_RUNTIME_SOCKET_COMM[$inode_value]:--}"
        pid_value="${PROCFS_RUNTIME_SOCKET_PID[$inode_value]:--}"
        printf -v normalized_row '%s\t%s\t%s\t%s\t%s\t%s\t%s' \
            "${table_name%6}" "$address_value" "$port_value" "$process_value" \
            "$pid_value" "$inode_value" "$normalized_state"
        [ -z "$PROCFS_RUNTIME_LISTENER_ROWS" ] || PROCFS_RUNTIME_LISTENER_ROWS+=$'\n'
        PROCFS_RUNTIME_LISTENER_ROWS+="$normalized_row"
        procfs_runtime_listener_index_append "${table_name%6}" "$port_value" "$normalized_row"
    done
    exec {table_fd}<&-
    PROCFS_RUNTIME_SOCKET_MALFORMED_ROWS=$((PROCFS_RUNTIME_SOCKET_MALFORMED_ROWS + malformed_rows))
    [ "$malformed_rows" -eq 0 ]
}

procfs_runtime_prepare_listener_snapshot() {
    local table_name=""
    local table_status=0
    local partial=0

    procfs_runtime_ensure_epoch || return 2
    [ "$PROCFS_RUNTIME_LISTENER_READY" -eq 0 ] || return "$PROCFS_RUNTIME_LISTENER_STATUS"
    PROCFS_RUNTIME_LISTENER_READY=1
    PROCFS_RUNTIME_LISTENER_STATUS=2
    PROCFS_RUNTIME_LISTENER_ROWS=""
    PROCFS_RUNTIME_SOCKET_TABLES_READ=0
    PROCFS_RUNTIME_SOCKET_TABLE_ERRORS=0
    PROCFS_RUNTIME_SOCKET_MALFORMED_ROWS=0
    PROCFS_RUNTIME_LISTENER_ROWS_BY_KEY=()

    # Process ownership enriches positive facts but is not required to prove that
    # a local endpoint exists or is absent from a complete socket table set.
    procfs_runtime_prepare_process_snapshot >/dev/null 2>&1 || :
    for table_name in tcp tcp6 udp udp6; do
        table_status=0
        procfs_runtime_parse_socket_table "$RUNTIME_FALLBACK_PROC_ROOT/net/$table_name" "$table_name" || table_status=$?
        case "$table_status" in
            0) PROCFS_RUNTIME_SOCKET_TABLES_READ=$((PROCFS_RUNTIME_SOCKET_TABLES_READ + 1)) ;;
            1)
                PROCFS_RUNTIME_SOCKET_TABLES_READ=$((PROCFS_RUNTIME_SOCKET_TABLES_READ + 1))
                partial=1
                ;;
            *)
                PROCFS_RUNTIME_SOCKET_TABLE_ERRORS=$((PROCFS_RUNTIME_SOCKET_TABLE_ERRORS + 1))
                partial=1
                ;;
        esac
    done
    if [ "$PROCFS_RUNTIME_SOCKET_TABLES_READ" -eq 0 ]; then
        PROCFS_RUNTIME_LISTENER_STATUS=2
    elif [ "$partial" -eq 1 ]; then
        PROCFS_RUNTIME_LISTENER_STATUS=3
    else
        PROCFS_RUNTIME_LISTENER_STATUS=0
    fi
    return "$PROCFS_RUNTIME_LISTENER_STATUS"
}

runtime_listener_snapshot_into() {
    local destination_name="$1"
    local snapshot_status=0

    procfs_runtime_destination_is_valid "$destination_name" || return 2
    if declare -F scan_dependency_register >/dev/null 2>&1; then
        scan_dependency_register runtime:listeners procfs:listener-snapshot || return 2
    fi
    procfs_runtime_prepare_listener_snapshot || snapshot_status=$?
    printf -v "$destination_name" '%s' "$PROCFS_RUNTIME_LISTENER_ROWS"
    return "$snapshot_status"
}

runtime_listener_facts_for_port_into() {
    local destination_name="$1"
    local requested_port="$2"
    local requested_transport="${3:-any}"
    local snapshot_status=0
    local matched_rows=""
    local lookup_key=""

    procfs_runtime_destination_is_valid "$destination_name" || return 2
    if declare -F scan_dependency_register >/dev/null 2>&1; then
        scan_dependency_register runtime:listeners procfs:listener-snapshot || return 2
    fi
    case "$requested_port" in ''|*[!0-9]*) return 2 ;; esac
    [ "$requested_port" -le 65535 ] || return 2
    case "$requested_transport" in any|tcp|udp) ;; *) return 2 ;; esac
    procfs_runtime_prepare_listener_snapshot || snapshot_status=$?
    lookup_key="$requested_transport:$requested_port"
    matched_rows="${PROCFS_RUNTIME_LISTENER_ROWS_BY_KEY[$lookup_key]-}"
    printf -v "$destination_name" '%s' "$matched_rows"
    [ -z "$matched_rows" ] || return 0
    [ "$snapshot_status" -eq 0 ] && return 1
    return 2
}
