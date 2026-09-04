# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash

# Account and file-system checks cover U-01 through U-33.

scanner_is_integer() {
    local value="${1:-}"
    local magnitude="${value#-}"

    [[ "$value" =~ ^-?[0-9]+$ ]] && [ "${#magnitude}" -le 10 ]
}

scanner_is_unsigned_integer() {
    local value="${1:-}"

    [[ "$value" =~ ^[0-9]+$ ]] && [ "${#value}" -le 10 ]
}

scanner_validate_passwd_database() {
    local file="$1"

    [ -f "$file" ] && [ -r "$file" ] || return 2
    awk -F: '
        function valid_identifier(value) {
            return value ~ /^[0-9]+$/ && length(value) <= 10 && (value + 0) <= 4294967295
        }
        NF != 7 || $1 == "" || !valid_identifier($3) || !valid_identifier($4) {invalid=1}
        seen[$1]++ {invalid=1}
        {records++}
        END {exit(invalid || records == 0 ? 1 : 0)}
    ' "$file"
}

scanner_validate_group_database() {
    local file="$1"

    [ -f "$file" ] && [ -r "$file" ] || return 2
    awk -F: '
        function valid_identifier(value) {
            return value ~ /^[0-9]+$/ && length(value) <= 10 && (value + 0) <= 4294967295
        }
        NF != 4 || $1 == "" || !valid_identifier($3) {invalid=1}
        ($1 in group_gid) && group_gid[$1] != ($3 + 0) {invalid=1}
        !($1 in group_gid) {group_gid[$1]=$3 + 0}
        {records++}
        END {exit(invalid || records == 0 ? 1 : 0)}
    ' "$file"
}

scanner_validate_shadow_database() {
    local file="$1"

    [ -f "$file" ] && [ -r "$file" ] || return 2
    awk -F: '
        NF != 9 || $1 == "" {invalid=1}
        {
            for (field_index=3; field_index<=9; field_index++) {
                if ($field_index != "" && $field_index !~ /^-?[0-9]+$/) invalid=1
            }
        }
        seen[$1]++ {invalid=1}
        {records++}
        END {exit(invalid || records == 0 ? 1 : 0)}
    ' "$file"
}

scanner_validate_gshadow_database() {
    local file="$1"

    [ -f "$file" ] && [ -r "$file" ] || return 2
    awk -F: '
        NF != 4 || $1 == "" {invalid=1}
        seen[$1]++ {invalid=1}
        {records++}
        END {exit(invalid || records == 0 ? 1 : 0)}
    ' "$file"
}

scanner_account_nss_source_state_into() {
    local __kisa_nss_destination="$1"
    local __kisa_nss_file=""
    local __kisa_nss_path_status=0
    local __kisa_nss_parse_status=0

    case "$__kisa_nss_destination" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|__kisa_nss_*) return 2 ;;
    esac
    printf -v "$__kisa_nss_destination" '%s' unresolved
    __kisa_nss_file="$(optional_rooted_read_path /etc/nsswitch.conf 2>/dev/null)" || __kisa_nss_path_status=$?
    case "$__kisa_nss_path_status" in
        0) ;;
        1)
            printf -v "$__kisa_nss_destination" '%s' absent
            return 1
            ;;
        *)
            printf -v "$__kisa_nss_destination" '%s' path_error
            return 2
            ;;
    esac
    LC_ALL=C awk '
        {
            line=$0
            sub(/#.*/, "", line)
            if (line !~ /^[[:space:]]*(passwd|group)[[:space:]]*:/) next
            key=line
            sub(/^[[:space:]]*/, "", key)
            sub(/[[:space:]]*:.*$/, "", key)
            value=line
            sub(/^[^:]*:[[:space:]]*/, "", value)
            sub(/[[:space:]]+$/, "", value)
            records[key]++
            if (value != "files") non_files=1
        }
        END {
            if (records["passwd"] == 1 && records["group"] == 1 && !non_files) exit 0
            exit 1
        }
    ' "$__kisa_nss_file" || __kisa_nss_parse_status=$?
    case "$__kisa_nss_parse_status" in
        0)
            printf -v "$__kisa_nss_destination" '%s' files_only
            return 0
            ;;
        1)
            printf -v "$__kisa_nss_destination" '%s' external_or_unresolved
            return 1
            ;;
        *)
            printf -v "$__kisa_nss_destination" '%s' parse_error
            return 2
            ;;
    esac
}

scanner_account_shadow_completeness_into() {
    local __kisa_shadow_passwd_file="$1"
    local __kisa_shadow_destination="$2"
    local __kisa_shadow_file=""
    local __kisa_shadow_path_status=0
    local __kisa_shadow_counts=""
    local __kisa_shadow_missing=0
    local __kisa_shadow_orphaned=0

    case "$__kisa_shadow_destination" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|__kisa_shadow_*) return 2 ;;
    esac
    printf -v "$__kisa_shadow_destination" '%s' 'shadow_status=unresolved'
    __kisa_shadow_file="$(optional_rooted_read_path /etc/shadow 2>/dev/null)" || __kisa_shadow_path_status=$?
    case "$__kisa_shadow_path_status" in
        0) ;;
        1)
            printf -v "$__kisa_shadow_destination" '%s' 'shadow_status=absent'
            return 1
            ;;
        *)
            printf -v "$__kisa_shadow_destination" '%s' 'shadow_status=path_error'
            return 2
            ;;
    esac
    if ! scanner_validate_shadow_database "$__kisa_shadow_file"; then
        printf -v "$__kisa_shadow_destination" '%s' 'shadow_status=invalid'
        return 2
    fi
    __kisa_shadow_counts="$(awk -F: '
        FNR == NR {passwd_account[$1]=1; next}
        {
            shadow_account[$1]=1
            if (!($1 in passwd_account)) orphaned++
        }
        END {
            for (account in passwd_account) if (!(account in shadow_account)) missing++
            print missing+0, orphaned+0
        }
    ' "$__kisa_shadow_passwd_file" "$__kisa_shadow_file")" || {
        printf -v "$__kisa_shadow_destination" '%s' 'shadow_status=parse_error'
        return 2
    }
    read -r __kisa_shadow_missing __kisa_shadow_orphaned <<< "$__kisa_shadow_counts"
    if [ "$__kisa_shadow_missing" -eq 0 ] && [ "$__kisa_shadow_orphaned" -eq 0 ]; then
        printf -v "$__kisa_shadow_destination" \
            'shadow_status=complete\nmissing_shadow_accounts=0\norphan_shadow_accounts=0'
        return 0
    fi
    printf -v "$__kisa_shadow_destination" \
        'shadow_status=incomplete\nmissing_shadow_accounts=%s\norphan_shadow_accounts=%s' \
        "$__kisa_shadow_missing" "$__kisa_shadow_orphaned"
    return 1
}

scanner_stat_gid() {
    local path="$1"
    local stat_path=""

    stat_path="$(command -v stat 2>/dev/null || true)"
    [ -n "$stat_path" ] || return 127
    "$stat_path" -Lc '%g' -- "$path" 2>/dev/null || "$stat_path" -f '%g' -- "$path" 2>/dev/null
}

scanner_stat_device() {
    local path="$1"
    local stat_path=""

    stat_path="$(command -v stat 2>/dev/null || true)"
    [ -n "$stat_path" ] || return 127
    "$stat_path" -Lc '%d' -- "$path" 2>/dev/null || "$stat_path" -f '%d' -- "$path" 2>/dev/null
}

scanner_local_filesystem_roots() {
    local candidates_file=""
    local mount_inventory_file=""
    local seen_devices=""
    local target=""
    local filesystem_type=""
    local device=""
    local findmnt_path=""

    if [ "$SCAN_ROOT" != "/" ]; then
        if [ "${EVIDENCE_BUNDLE_ACTIVE:-0}" -eq 1 ] && declare -F evidence_mount_roots >/dev/null 2>&1; then
            mount_inventory_file="$(new_scratch_file bundle-mount-roots)" || return 2
            evidence_mount_roots > "$mount_inventory_file" || return 2
            printf '%s\n' "${SCAN_ROOT%/}"
            while IFS=$'\t' read -r target filesystem_type; do
                case "$target" in /) continue ;; esac
                case "$target" in /proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/run|/run/*) continue ;; esac
                case "$filesystem_type" in
                    proc|sysfs|devtmpfs|devpts|tmpfs|cgroup*|securityfs|debugfs|tracefs|configfs|pstore|efivarfs|mqueue|hugetlbfs|rpc_pipefs|nfs|nfs4|cifs|smb3|fuse.*) continue ;;
                esac
                target="$(fs_path "$target" 2>/dev/null || true)"
                [ -n "$target" ] || return 2
                target="$(resolve_rooted_directory "$target" 2>/dev/null || true)"
                [ -n "$target" ] || return 2
                printf '%s\n' "$target"
            done < "$mount_inventory_file"
            return 0
        fi
        printf '%s\n' "${SCAN_ROOT%/}"
        return 0
    fi

    candidates_file="$(new_scratch_file mount-roots)" || return 1
    printf '/\n/usr\n/var\n/home\n/opt\n/srv\n/tmp\n' > "$candidates_file"
    findmnt_path="$(trusted_findmnt_command 2>/dev/null || true)"
    [ -n "$findmnt_path" ] || return 2
    mount_inventory_file="$(new_scratch_file mount-inventory)" || return 2
    "$findmnt_path" -rn -o TARGET,FSTYPE > "$mount_inventory_file" 2>/dev/null || return 2
    while read -r target filesystem_type; do
        case "$target" in *\\*) return 2 ;; esac
        case "$target" in /*) ;; *) continue ;; esac
        case "$target" in /proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/run|/run/*) continue ;; esac
        case "$filesystem_type" in
            proc|sysfs|devtmpfs|devpts|tmpfs|cgroup*|securityfs|debugfs|tracefs|configfs|pstore|efivarfs|mqueue|hugetlbfs|rpc_pipefs|nfs|nfs4|cifs|smb3|fuse.*) continue ;;
        esac
        printf '%s\n' "$target" >> "$candidates_file"
    done < "$mount_inventory_file"

    while IFS= read -r target; do
        [ -d "$target" ] || continue
        device="$(scanner_stat_device "$target" 2>/dev/null || true)"
        [ -n "$device" ] || return 2
        case " $seen_devices " in *" $device "*) continue ;; esac
        seen_devices="${seen_devices}${seen_devices:+ }${device}"
        printf '%s\n' "$target"
    done < <(LC_ALL=C sort -u "$candidates_file")
}

scanner_append_evidence() {
    local variable_name="$1"
    shift
    printf -v "$variable_name" '%s%s\n' "${!variable_name}" "$*"
}

scanner_evidence_path() {
    local path="$1"
    local displayed_path=""
    local sanitized_path=""
    local character=""
    local index_value=0
    local LC_ALL=C

    display_path_into "$path" displayed_path || return 2
    displayed_path="${displayed_path//$'\n'/?}"
    displayed_path="${displayed_path//$'\r'/?}"
    displayed_path="${displayed_path//$'\t'/?}"
    for ((index_value = 0; index_value < ${#displayed_path}; index_value++)); do
        character="${displayed_path:index_value:1}"
        case "$character" in [[:print:]]) sanitized_path+="$character" ;; esac
    done
    printf '%s' "$sanitized_path"
}

scanner_directory_searchable() {
    [ -x "$1" ]
}

scanner_capture_bounded_find_diagnostics() {
    local output_file="$1"
    local diagnostic_line=""
    local sanitized_diagnostic=""
    local diagnostic_count=0
    local permission_denied_count=0
    local other_count=0
    local truncated=0

    : > "$output_file" || return 2
    while IFS= read -r diagnostic_line || [ -n "$diagnostic_line" ]; do
        diagnostic_count=$((diagnostic_count + 1))
        case "$diagnostic_line" in
            *"Permission denied"*) permission_denied_count=$((permission_denied_count + 1)) ;;
            *) other_count=$((other_count + 1)) ;;
        esac
        if [ "$diagnostic_count" -le 20 ]; then
            if [ "$SCAN_ROOT" != "/" ]; then
                diagnostic_line="${diagnostic_line//"${SCAN_ROOT%/}"/}"
            fi
            if [ "${#diagnostic_line}" -gt 256 ]; then
                diagnostic_line="${diagnostic_line:0:256}"
                truncated=1
            fi
            console_sanitize_line_into "$diagnostic_line" sanitized_diagnostic
            printf 'D\t%s\n' "$sanitized_diagnostic" >> "$output_file" || return 2
        else
            truncated=1
        fi
    done
    printf 'M\t%s\t%s\t%s\t%s\n' \
        "$diagnostic_count" "$permission_denied_count" "$other_count" "$truncated" >> "$output_file" || return 2
}

scanner_run_find_with_diagnostics() {
    local stream_file="$1"
    local diagnostic_file="$2"
    local -a pipeline_status=()

    shift 2
    LC_ALL=C find "$@" 2>&1 > "$stream_file" |
        scanner_capture_bounded_find_diagnostics "$diagnostic_file"
    pipeline_status=("${PIPESTATUS[@]}")
    [ "${pipeline_status[1]:-2}" -eq 0 ] || return 125
    return "${pipeline_status[0]:-2}"
}

scanner_record_full_filesystem_scan_error() {
    local diagnostic_file="$1"
    local find_status="$2"
    local record_type=""
    local field_one=""
    local field_two=""
    local field_three=""
    local field_four=""
    local diagnostic_key=""
    local saw_metadata=0
    local current_diagnostic_lines=0

    SCANNER_FULL_FILESYSTEM_SCAN_ERRORS=$((SCANNER_FULL_FILESYSTEM_SCAN_ERRORS + 1))
    while IFS=$'\t' read -r record_type field_one field_two field_three field_four; do
        case "$record_type" in
            D)
                SCANNER_FULL_FILESYSTEM_DIAGNOSTIC_COUNT=$((SCANNER_FULL_FILESYSTEM_DIAGNOSTIC_COUNT + 1))
                if [ "$SCANNER_FULL_FILESYSTEM_DIAGNOSTIC_COUNT" -le 20 ]; then
                    printf -v diagnostic_key 'scan_diagnostic_%02d' "$SCANNER_FULL_FILESYSTEM_DIAGNOSTIC_COUNT"
                    scanner_append_evidence SCANNER_FULL_FILESYSTEM_ERROR_EVIDENCE "${diagnostic_key}=${field_one}"
                else
                    SCANNER_FULL_FILESYSTEM_DIAGNOSTICS_TRUNCATED=1
                fi
                ;;
            M)
                saw_metadata=1
                current_diagnostic_lines="$field_one"
                SCANNER_FULL_FILESYSTEM_DIAGNOSTIC_LINES=$((SCANNER_FULL_FILESYSTEM_DIAGNOSTIC_LINES + field_one))
                SCANNER_FULL_FILESYSTEM_PERMISSION_DENIED_DIAGNOSTICS=$((SCANNER_FULL_FILESYSTEM_PERMISSION_DENIED_DIAGNOSTICS + field_two))
                SCANNER_FULL_FILESYSTEM_OTHER_DIAGNOSTICS=$((SCANNER_FULL_FILESYSTEM_OTHER_DIAGNOSTICS + field_three))
                [ "$field_four" -eq 0 ] || SCANNER_FULL_FILESYSTEM_DIAGNOSTICS_TRUNCATED=1
                ;;
        esac
    done < "$diagnostic_file"
    if [ "$saw_metadata" -eq 0 ] || [ "$current_diagnostic_lines" -eq 0 ]; then
        SCANNER_FULL_FILESYSTEM_OTHER_DIAGNOSTICS=$((SCANNER_FULL_FILESYSTEM_OTHER_DIAGNOSTICS + 1))
        scanner_append_evidence SCANNER_FULL_FILESYSTEM_ERROR_EVIDENCE "scan_diagnostic_detail=unavailable,find_status=${find_status}"
    fi
}

scanner_record_full_filesystem_parse_error() {
    SCANNER_FULL_FILESYSTEM_SCAN_ERRORS=$((SCANNER_FULL_FILESYSTEM_SCAN_ERRORS + 1))
    SCANNER_FULL_FILESYSTEM_OTHER_DIAGNOSTICS=$((SCANNER_FULL_FILESYSTEM_OTHER_DIAGNOSTICS + 1))
    scanner_append_evidence SCANNER_FULL_FILESYSTEM_ERROR_EVIDENCE "scan_diagnostic_detail=invalid_traversal_record_stream"
}

scanner_full_filesystem_error_evidence_into() {
    local destination_name="$1"
    local process_evidence=""
    local evidence_value=""

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|destination_name|process_evidence|evidence_value) return 2 ;;
    esac
    scanner_process_security_context_evidence_into process_evidence || return 2
    evidence_value="scope=${SCAN_ROOT},xdev=true
filesystem_scan_errors=${SCANNER_FULL_FILESYSTEM_SCAN_ERRORS}
diagnostic_lines=${SCANNER_FULL_FILESYSTEM_DIAGNOSTIC_LINES}
permission_denied_diagnostics=${SCANNER_FULL_FILESYSTEM_PERMISSION_DENIED_DIAGNOSTICS}
other_diagnostics=${SCANNER_FULL_FILESYSTEM_OTHER_DIAGNOSTICS}
diagnostics_truncated=$([ "$SCANNER_FULL_FILESYSTEM_DIAGNOSTICS_TRUNCATED" -eq 1 ] && printf true || printf false)
${process_evidence}
${SCANNER_FULL_FILESYSTEM_ERROR_EVIDENCE}"
    printf -v "$destination_name" '%s' "$evidence_value"
}

scanner_collect_profile_directory_files() {
    local logical_directory="$1"
    local output_file="$2"
    local raw_directory=""
    local resolved_directory=""
    local candidates_file=""
    local sorted_candidates_file=""
    local candidate=""
    local resolved_candidate=""

    : > "$output_file" || return 2
    if [ "$SCAN_ROOT" = "/" ]; then
        raw_directory="$logical_directory"
    else
        raw_directory="${SCAN_ROOT%/}$logical_directory"
    fi
    [ -e "$raw_directory" ] || [ -L "$raw_directory" ] || return 1
    resolved_directory="$(fs_path "$logical_directory" 2>/dev/null)" || return 2
    resolved_directory="$(resolve_rooted_directory "$resolved_directory" 2>/dev/null)" || return 2
    candidates_file="$(new_scratch_file profile-directory-candidates)" || return 2
    sorted_candidates_file="$(new_scratch_file profile-directory-sorted)" || return 2
    if ! find -P "$resolved_directory" -maxdepth 1 \( -type f -o -type l \) \
        -name '*.sh' ! -name '.*' -print0 > "$candidates_file" 2>/dev/null; then
        return 2
    fi
    LC_ALL=C sort -z "$candidates_file" > "$sorted_candidates_file" || return 2
    while IFS= read -r -d '' candidate; do
        resolved_candidate="$(resolve_rooted_read_path "$candidate" 2>/dev/null)" || return 2
        printf '%s\0' "$resolved_candidate" >> "$output_file" || return 2
    done < "$sorted_candidates_file"
}

scanner_reset_full_filesystem_cache() {
    SCANNER_FULL_FILESYSTEM_CACHE_READY=0
    SCANNER_FULL_FILESYSTEM_CACHE_ROOT=""
    SCANNER_FULL_FILESYSTEM_CACHE_RUNTIME=""
    SCANNER_FULL_FILESYSTEM_CACHE_SCRATCH=""
    SCANNER_FULL_FILESYSTEM_CACHE_SELECTION=""
    SCANNER_FULL_FILESYSTEM_SCRATCH_ERROR=0
    SCANNER_FULL_FILESYSTEM_ROOT_STATUS=0
    SCANNER_FULL_FILESYSTEM_ROOT_COUNT=0
    SCANNER_FULL_FILESYSTEM_SCAN_ERRORS=0
    SCANNER_FULL_FILESYSTEM_DIAGNOSTIC_COUNT=0
    SCANNER_FULL_FILESYSTEM_DIAGNOSTIC_LINES=0
    SCANNER_FULL_FILESYSTEM_PERMISSION_DENIED_DIAGNOSTICS=0
    SCANNER_FULL_FILESYSTEM_OTHER_DIAGNOSTICS=0
    SCANNER_FULL_FILESYSTEM_DIAGNOSTICS_TRUNCATED=0
    SCANNER_FULL_FILESYSTEM_ERROR_EVIDENCE=""
    SCANNER_FULL_FILESYSTEM_U15_SETUP_ERROR=""
    SCANNER_FULL_FILESYSTEM_U15_EXTERNAL_NSS=1
    SCANNER_FULL_FILESYSTEM_U15_METADATA_ERRORS=0
    SCANNER_FULL_FILESYSTEM_U15_COUNT=0
    SCANNER_FULL_FILESYSTEM_U15_EVIDENCE=""
    SCANNER_FULL_FILESYSTEM_U23_COUNT=0
    SCANNER_FULL_FILESYSTEM_U23_EVIDENCE=""
    SCANNER_FULL_FILESYSTEM_U25_COUNT=0
    SCANNER_FULL_FILESYSTEM_U25_EVIDENCE=""
    SCANNER_FULL_FILESYSTEM_U33_COUNT=0
    SCANNER_FULL_FILESYSTEM_U33_EVIDENCE=""
}

scanner_full_filesystem_cache_status_into() {
    local destination_name="$1"
    local cache_status="ready"

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|destination_name|cache_status) return 2 ;;
    esac
    if [ "$SCANNER_FULL_FILESYSTEM_SCRATCH_ERROR" -gt 0 ] ||
        [ "$SCANNER_FULL_FILESYSTEM_ROOT_STATUS" -ne 0 ] ||
        [ "$SCANNER_FULL_FILESYSTEM_SCAN_ERRORS" -gt 0 ] ||
        [ -n "$SCANNER_FULL_FILESYSTEM_U15_SETUP_ERROR" ]; then
        cache_status="error"
    elif [ "$SCANNER_FULL_FILESYSTEM_ROOT_COUNT" -eq 0 ]; then
        cache_status="absent"
    fi
    printf -v "$destination_name" '%s' "$cache_status"
}

scanner_full_filesystem_record_u15() {
    local path="$1"

    SCANNER_FULL_FILESYSTEM_U15_COUNT=$((SCANNER_FULL_FILESYSTEM_U15_COUNT + 1))
    if [ "$SCANNER_FULL_FILESYSTEM_U15_COUNT" -le 20 ]; then
        scanner_append_evidence SCANNER_FULL_FILESYSTEM_U15_EVIDENCE "$(scanner_evidence_path "$path")"
    fi
}

scanner_full_filesystem_record_u23() {
    local path="$1"
    local mode="$2"

    SCANNER_FULL_FILESYSTEM_U23_COUNT=$((SCANNER_FULL_FILESYSTEM_U23_COUNT + 1))
    if [ "$SCANNER_FULL_FILESYSTEM_U23_COUNT" -le 20 ]; then
        scanner_append_evidence SCANNER_FULL_FILESYSTEM_U23_EVIDENCE "$(scanner_evidence_path "$path"):mode=${mode}"
    fi
}

scanner_full_filesystem_record_u25() {
    local path="$1"

    SCANNER_FULL_FILESYSTEM_U25_COUNT=$((SCANNER_FULL_FILESYSTEM_U25_COUNT + 1))
    if [ "$SCANNER_FULL_FILESYSTEM_U25_COUNT" -le 20 ]; then
        scanner_append_evidence SCANNER_FULL_FILESYSTEM_U25_EVIDENCE "$(scanner_evidence_path "$path")"
    fi
}

scanner_full_filesystem_record_u33() {
    local path="$1"

    SCANNER_FULL_FILESYSTEM_U33_COUNT=$((SCANNER_FULL_FILESYSTEM_U33_COUNT + 1))
    if [ "$SCANNER_FULL_FILESYSTEM_U33_COUNT" -le 20 ]; then
        scanner_append_evidence SCANNER_FULL_FILESYSTEM_U33_EVIDENCE "$(scanner_evidence_path "$path")"
    fi
}

scanner_full_filesystem_parse_selected_stream() {
    local stream_file="$1"
    local filesystem_root="$2"
    local record_type=""
    local path=""
    local mode=""
    local basename_value=""

    while IFS= read -r -d '' record_type; do
        case "$record_type" in
            O)
                IFS= read -r -d '' path || return 2
                scanner_full_filesystem_record_u15 "$path"
                ;;
            S)
                IFS= read -r -d '' path || return 2
                IFS= read -r -d '' mode || return 2
                case "$mode" in ''|*[!0-7]*) return 2 ;; esac
                [ "${#mode}" -le 4 ] || return 2
                scanner_full_filesystem_record_u23 "$path" "$mode"
                ;;
            W)
                IFS= read -r -d '' path || return 2
                scanner_full_filesystem_record_u25 "$path"
                ;;
            H)
                IFS= read -r -d '' path || return 2
                [ "$path" = "$filesystem_root" ] && continue
                basename_value="${path##*/}"
                case "$basename_value" in .|..) continue ;; esac
                scanner_full_filesystem_record_u33 "$path"
                ;;
            *)
                return 2
                ;;
        esac
    done < "$stream_file"
    [ -z "$record_type" ] || return 2
}

scanner_collect_full_filesystem_facts() {
    local roots_file=""
    local stream_file=""
    local diagnostic_file=""
    local find_status=0
    local stream_parse_error=0
    local cache_status="ready"
    local filesystem_root=""
    local nsswitch_file=""
    local passwd_file=""
    local group_file=""
    local passwd_status=0
    local group_status=0
    local nsswitch_status=0
    local collect_u15=0
    local collect_u23=0
    local collect_u25=0
    local collect_u33=0
    local collect_offline_other_facts=1
    local u23_find_gate="-false"
    local u25_find_gate="-false"
    local u33_find_gate="-false"
    local file_type=""
    local path=""
    local file_uid=""
    local file_gid=""
    local file_mode=""
    local decimal_mode=0
    local basename_value=""
    local generated_path=""
    local -a scan_prune_expression=("(" -false)
    local -a passwd_fields=()
    local -a group_fields=()
    local -A passwd_identifiers=()
    local -A group_identifiers=()

    if [ "$SCANNER_FULL_FILESYSTEM_CACHE_READY" -eq 1 ] &&
        [ "$SCANNER_FULL_FILESYSTEM_CACHE_ROOT" = "$SCAN_ROOT" ] &&
        [ "$SCANNER_FULL_FILESYSTEM_CACHE_RUNTIME" = "$RUNTIME_MODE" ] &&
        [ "$SCANNER_FULL_FILESYSTEM_CACHE_SCRATCH" = "$SCRATCH_DIR" ] &&
        [ "$SCANNER_FULL_FILESYSTEM_CACHE_SELECTION" = "$SELECTED_CHECKS" ]; then
        scanner_full_filesystem_cache_status_into cache_status
        debug_emit filesystem_snapshot phase reuse cache hit status "$cache_status" \
            roots "$SCANNER_FULL_FILESYSTEM_ROOT_COUNT" errors "$SCANNER_FULL_FILESYSTEM_SCAN_ERRORS"
        return 0
    fi

    scanner_reset_full_filesystem_cache
    debug_emit filesystem_snapshot phase begin cache miss status collecting
    SCANNER_FULL_FILESYSTEM_CACHE_ROOT="$SCAN_ROOT"
    SCANNER_FULL_FILESYSTEM_CACHE_RUNTIME="$RUNTIME_MODE"
    SCANNER_FULL_FILESYSTEM_CACHE_SCRATCH="$SCRATCH_DIR"
    SCANNER_FULL_FILESYSTEM_CACHE_SELECTION="$SELECTED_CHECKS"
    SCANNER_FULL_FILESYSTEM_CACHE_READY=1

    if check_selected U-15; then
        collect_u15=1
        nsswitch_file="$(optional_rooted_read_path /etc/nsswitch.conf 2>/dev/null)" || nsswitch_status=$?
        if [ "$nsswitch_status" -eq 0 ]; then
            if awk '
                /^[[:space:]]*(passwd|group):/ {
                    records++
                    for (index_value=2; index_value<=NF; index_value++) {
                        if ($index_value != "files") external=1
                    }
                }
                END {exit(external || records < 2 ? 0 : 1)}
            ' "$nsswitch_file"; then
                SCANNER_FULL_FILESYSTEM_U15_EXTERNAL_NSS=1
            else
                SCANNER_FULL_FILESYSTEM_U15_EXTERNAL_NSS=0
            fi
        elif [ "$nsswitch_status" -eq 2 ]; then
            SCANNER_FULL_FILESYSTEM_U15_SETUP_ERROR="nsswitch"
        fi

        if [ "$SCAN_ROOT" != "/" ] && [ -z "$SCANNER_FULL_FILESYSTEM_U15_SETUP_ERROR" ]; then
            passwd_file="$(optional_rooted_read_path /etc/passwd 2>/dev/null)" || passwd_status=$?
            group_file="$(optional_rooted_read_path /etc/group 2>/dev/null)" || group_status=$?
            if [ "$passwd_status" -ne 0 ] || [ "$group_status" -ne 0 ] ||
                ! scanner_validate_passwd_database "$passwd_file" ||
                ! scanner_validate_group_database "$group_file"; then
                SCANNER_FULL_FILESYSTEM_U15_SETUP_ERROR="database"
            else
                while IFS=: read -r -a passwd_fields || [ "${#passwd_fields[@]}" -gt 0 ]; do
                    file_uid="${passwd_fields[2]}"
                    while [ "${#file_uid}" -gt 1 ] && [ "${file_uid#0}" != "$file_uid" ]; do
                        file_uid="${file_uid#0}"
                    done
                    passwd_identifiers["$file_uid"]=1
                done < "$passwd_file"
                while IFS=: read -r -a group_fields || [ "${#group_fields[@]}" -gt 0 ]; do
                    file_gid="${group_fields[2]}"
                    while [ "${#file_gid}" -gt 1 ] && [ "${file_gid#0}" != "$file_gid" ]; do
                        file_gid="${file_gid#0}"
                    done
                    group_identifiers["$file_gid"]=1
                done < "$group_file"
            fi
        fi
    fi
    if check_selected U-23; then
        collect_u23=1
        u23_find_gate="-true"
    fi
    if check_selected U-25; then
        collect_u25=1
        u25_find_gate="-true"
    fi
    if check_selected U-33; then
        collect_u33=1
        u33_find_gate="-true"
    fi

    roots_file="$(new_scratch_file full-filesystem-roots)" || {
        SCANNER_FULL_FILESYSTEM_SCRATCH_ERROR=1
        debug_emit filesystem_snapshot phase result cache miss status error reason scratch
        return 0
    }
    stream_file="$(new_scratch_file full-filesystem-stream)" || {
        SCANNER_FULL_FILESYSTEM_SCRATCH_ERROR=1
        debug_emit filesystem_snapshot phase result cache miss status error reason scratch
        return 0
    }
    diagnostic_file="$(new_scratch_file full-filesystem-diagnostics)" || {
        SCANNER_FULL_FILESYSTEM_SCRATCH_ERROR=1
        debug_emit filesystem_snapshot phase result cache miss status error reason scratch
        return 0
    }
    for generated_path in "$SCRATCH_DIR" "$REPORT_TEXT" "$REPORT_JSONL"; do
        [ -n "$generated_path" ] || continue
        [ -e "$generated_path" ] || [ -L "$generated_path" ] || continue
        scan_prune_expression+=(-o -samefile "$generated_path")
    done
    scan_prune_expression+=(")" -prune -o)
    scanner_local_filesystem_roots > "$roots_file" || SCANNER_FULL_FILESYSTEM_ROOT_STATUS=$?
    if [ "$SCAN_ROOT" = "/" ]; then
        if [ "$SCANNER_FULL_FILESYSTEM_ROOT_STATUS" -ne 0 ]; then
            debug_emit filesystem_snapshot phase result cache miss status error reason mount_inventory
            return 0
        fi
    else
        if [ "$SCANNER_FULL_FILESYSTEM_ROOT_STATUS" -eq 0 ]; then
            while IFS= read -r filesystem_root; do
                [ -n "$filesystem_root" ] || continue
                SCANNER_FULL_FILESYSTEM_ROOT_COUNT=$((SCANNER_FULL_FILESYSTEM_ROOT_COUNT + 1))
            done < "$roots_file"
        fi
        if [ "$SCANNER_FULL_FILESYSTEM_ROOT_STATUS" -ne 0 ] ||
            [ "$SCANNER_FULL_FILESYSTEM_ROOT_COUNT" -eq 0 ]; then
            collect_offline_other_facts=0
            u23_find_gate="-false"
            u25_find_gate="-false"
            u33_find_gate="-false"
        fi
        if [ "$collect_u15" -eq 0 ] && [ "$collect_offline_other_facts" -eq 0 ]; then
            debug_emit filesystem_snapshot phase result cache miss status absent reason no_roots
            return 0
        fi
        if [ -n "$SCANNER_FULL_FILESYSTEM_U15_SETUP_ERROR" ] &&
            [ "$collect_offline_other_facts" -eq 0 ]; then
            debug_emit filesystem_snapshot phase result cache miss status error reason account_database
            return 0
        fi
        if [ "${EVIDENCE_BUNDLE_ACTIVE:-0}" -ne 1 ]; then
            # Without a mount snapshot, offline U-15 is limited to the supplied root.
            printf '%s\n' "${SCAN_ROOT%/}" > "$roots_file" || {
                SCANNER_FULL_FILESYSTEM_SCRATCH_ERROR=1
                debug_emit filesystem_snapshot phase result cache miss status error reason scratch
                return 0
            }
        fi
    fi

    while IFS= read -r filesystem_root; do
        [ -n "$filesystem_root" ] || continue
        if [ "$SCAN_ROOT" = "/" ]; then
            SCANNER_FULL_FILESYSTEM_ROOT_COUNT=$((SCANNER_FULL_FILESYSTEM_ROOT_COUNT + 1))
        fi
        : > "$stream_file" || {
            SCANNER_FULL_FILESYSTEM_SCRATCH_ERROR=1
            debug_emit filesystem_snapshot phase result cache miss status error reason scratch
            return 0
        }

        if [ "$SCAN_ROOT" = "/" ] && [ "$collect_u15" -eq 1 ]; then
            find_status=0
            scanner_run_find_with_diagnostics "$stream_file" "$diagnostic_file" \
                -P "$filesystem_root" -xdev "${scan_prune_expression[@]}" \
                \( \
                    \( \( -nouser -o -nogroup \) -printf 'O\0%p\0' \) , \
                    \( "$u23_find_gate" -type f -uid 0 \( -perm -04000 -o -perm -02000 \) -printf 'S\0%p\0%m\0' \) , \
                    \( "$u25_find_gate" -type f -perm -0002 -printf 'W\0%p\0' \) , \
                    \( "$u33_find_gate" -name '.*' -printf 'H\0%p\0' \) \
                \) || find_status=$?
            if [ "$find_status" -eq 125 ]; then
                SCANNER_FULL_FILESYSTEM_SCRATCH_ERROR=1
                debug_emit filesystem_snapshot phase result cache miss status error reason diagnostic_capture
                return 0
            elif [ "$find_status" -ne 0 ]; then
                scanner_record_full_filesystem_scan_error "$diagnostic_file" "$find_status"
                continue
            fi
            scanner_full_filesystem_parse_selected_stream "$stream_file" "$filesystem_root" ||
                scanner_record_full_filesystem_parse_error
            continue
        fi

        if [ "$SCAN_ROOT" = "/" ] || [ "$collect_u15" -eq 0 ] ||
            [ -n "$SCANNER_FULL_FILESYSTEM_U15_SETUP_ERROR" ]; then
            find_status=0
            scanner_run_find_with_diagnostics "$stream_file" "$diagnostic_file" \
                -P "$filesystem_root" -xdev "${scan_prune_expression[@]}" \
                \( \
                    \( "$u23_find_gate" -type f -uid 0 \( -perm -04000 -o -perm -02000 \) -printf 'S\0%p\0%m\0' \) , \
                    \( "$u25_find_gate" -type f -perm -0002 -printf 'W\0%p\0' \) , \
                    \( "$u33_find_gate" -name '.*' -printf 'H\0%p\0' \) \
                \) || find_status=$?
            if [ "$find_status" -eq 125 ]; then
                SCANNER_FULL_FILESYSTEM_SCRATCH_ERROR=1
                debug_emit filesystem_snapshot phase result cache miss status error reason diagnostic_capture
                return 0
            elif [ "$find_status" -ne 0 ]; then
                scanner_record_full_filesystem_scan_error "$diagnostic_file" "$find_status"
                continue
            fi
            scanner_full_filesystem_parse_selected_stream "$stream_file" "$filesystem_root" ||
                scanner_record_full_filesystem_parse_error
            continue
        fi

        find_status=0
        scanner_run_find_with_diagnostics "$stream_file" "$diagnostic_file" \
            -P "$filesystem_root" -xdev "${scan_prune_expression[@]}" \
            -printf 'M\0%p\0%y\0%U\0%G\0%m\0' || find_status=$?
        if [ "$find_status" -eq 125 ]; then
            SCANNER_FULL_FILESYSTEM_SCRATCH_ERROR=1
            debug_emit filesystem_snapshot phase result cache miss status error reason diagnostic_capture
            return 0
        elif [ "$find_status" -ne 0 ]; then
            scanner_record_full_filesystem_scan_error "$diagnostic_file" "$find_status"
            continue
        fi

        stream_parse_error=0
        while IFS= read -r -d '' file_type; do
            [ "$file_type" = "M" ] || {
                stream_parse_error=1
                break
            }
            IFS= read -r -d '' path || { stream_parse_error=1; break; }
            IFS= read -r -d '' file_type || { stream_parse_error=1; break; }
            IFS= read -r -d '' file_uid || { stream_parse_error=1; break; }
            IFS= read -r -d '' file_gid || { stream_parse_error=1; break; }
            IFS= read -r -d '' file_mode || { stream_parse_error=1; break; }
            case "$file_uid:$file_gid:$file_mode" in
                *[!0-9:]*|*::*|:*|*:)
                    stream_parse_error=1
                    break
                    ;;
            esac
            case "$file_mode" in *[!0-7]*) stream_parse_error=1; break ;; esac
            if [ "${#file_uid}" -gt 10 ] || [ "${#file_gid}" -gt 10 ] || [ "${#file_mode}" -gt 4 ]; then
                stream_parse_error=1
                break
            fi

            if [ -n "$file_uid" ] && [ -n "$file_gid" ] &&
                { [ -z "${passwd_identifiers[$file_uid]+present}" ] ||
                  [ -z "${group_identifiers[$file_gid]+present}" ]; }; then
                scanner_full_filesystem_record_u15 "$path"
            fi

            decimal_mode=$((8#$file_mode))
            if [ "$collect_offline_other_facts" -eq 1 ] && [ "$collect_u23" -eq 1 ] &&
                [ "$file_type" = "f" ] &&
                [ "$file_uid" = "0" ] && [ $((decimal_mode & 06000)) -ne 0 ]; then
                scanner_full_filesystem_record_u23 "$path" "$file_mode"
            fi
            if [ "$collect_offline_other_facts" -eq 1 ] && [ "$collect_u25" -eq 1 ] &&
                [ "$file_type" = "f" ] &&
                [ $((decimal_mode & 0002)) -ne 0 ]; then
                scanner_full_filesystem_record_u25 "$path"
            fi
            if [ "$collect_offline_other_facts" -eq 1 ] && [ "$collect_u33" -eq 1 ] &&
                [ "$path" != "$filesystem_root" ]; then
                basename_value="${path##*/}"
                case "$basename_value" in
                    .|..) ;;
                    .*) scanner_full_filesystem_record_u33 "$path" ;;
                esac
            fi
        done < "$stream_file"
        if [ "$stream_parse_error" -eq 1 ] || [ -n "$file_type" ]; then
            scanner_record_full_filesystem_parse_error
        fi
    done < "$roots_file"
    scanner_full_filesystem_cache_status_into cache_status
    debug_emit filesystem_snapshot phase result cache miss status "$cache_status" \
        roots "$SCANNER_FULL_FILESYSTEM_ROOT_COUNT" errors "$SCANNER_FULL_FILESYSTEM_SCAN_ERRORS"
}

scanner_reset_full_filesystem_cache

scanner_is_dev_null_mask() {
    local path="$1"
    local target=""

    [ -L "$path" ] || return 1
    target="$(readlink "$path" 2>/dev/null || true)"
    [ "$target" = "/dev/null" ] || [ "${path%/*}/$target" = "/dev/null" ]
}

scanner_value_only() {
    printf '%s\n' "${1%%"$(printf '\t')"*}"
}

scanner_source_only() {
    local value="$1"
    local tab_character=""

    tab_character="$(printf '\t')"
    case "$value" in
        *"$tab_character"*) printf '%s\n' "${value#*"$tab_character"}" ;;
        *) printf 'unresolved\n' ;;
    esac
}

scanner_capture_optional_value() {
    local variable_name="$1"
    local captured_value=""
    local captured_status=0

    shift
    captured_value="$("$@" 2>/dev/null)"
    captured_status=$?
    case "$captured_status" in
        0) ;;
        1) captured_value="" ;;
        *) return 2 ;;
    esac
    printf -v "$variable_name" '%s' "$captured_value"
}

scanner_nonlogin_shell() {
    case "$1" in
        /bin/false|/usr/bin/false|/sbin/nologin|/usr/sbin/nologin|/bin/nologin) return 0 ;;
        *) return 1 ;;
    esac
}

scanner_optional_metadata_path() {
    local logical_path="$1"
    local raw_path=""
    local physical_path=""

    if [ "$SCAN_ROOT" = "/" ]; then
        raw_path="$logical_path"
    else
        raw_path="${SCAN_ROOT%/}$logical_path"
    fi
    [ -e "$raw_path" ] || [ -L "$raw_path" ] || return 1
    if scanner_is_dev_null_mask "$raw_path"; then
        printf '%s\n' "$raw_path"
        return 0
    fi
    physical_path="$(fs_path "$logical_path" 2>/dev/null)" || return 2
    resolve_rooted_read_path "$physical_path" || return 2
}

scanner_file_uid_allowed() {
    local file_uid="$1"
    shift
    local owner_name=""
    local owner_uid=""
    local passwd_file=""
    local passwd_status=0
    local needs_passwd=0

    for owner_name in "$@"; do
        if [ "$owner_name" = "root" ] && [ "$file_uid" = "0" ]; then
            return 0
        fi
        [ "$owner_name" = "root" ] || needs_passwd=1
    done

    [ "$needs_passwd" -eq 1 ] || return 1
    passwd_file="$(optional_rooted_read_path /etc/passwd 2>/dev/null)" || passwd_status=$?
    [ "$passwd_status" -eq 0 ] || return 2
    scanner_validate_passwd_database "$passwd_file" || return 2
    for owner_name in "$@"; do
        [ "$owner_name" = "root" ] && continue
        owner_uid="$(awk -F: -v name="$owner_name" '$1 == name {print $3; exit}' "$passwd_file" 2>/dev/null || true)"
        [ -n "$owner_uid" ] && [ "$file_uid" = "$owner_uid" ] && return 0
    done

    return 1
}

# Returns 0 for compliant metadata, 1 for a policy violation, and 2 for an
# unreadable metadata record. The result contains no file contents.
scanner_file_metadata_status() {
    local path="$1"
    local allowed_mode="$2"
    shift 2
    local file_uid=""
    local file_mode=""

    file_uid="$(stat_uid "$path" 2>/dev/null || true)"
    file_mode="$(stat_mode "$path" 2>/dev/null || true)"
    [ -n "$file_uid" ] && [ -n "$file_mode" ] || return 2
    scanner_file_uid_allowed "$file_uid" "$@"
    case $? in
        0) ;;
        1) return 1 ;;
        *) return 2 ;;
    esac
    mode_is_at_most "$file_mode" "$allowed_mode" || return 1
    return 0
}

scanner_password_pam_lines() {
    local service=""

    if platform_is_debian_family; then
        service="common-password"
    elif platform_is_rhel_family; then
        service="system-auth"
    else
        return 2
    fi
    pam_expand_service "$service" password 2>/dev/null
}

SCANNER_AUTHSELECT_UNMANAGED=0

scanner_authselect_command_exists() {
    local candidate=""

    for candidate in /usr/sbin/authselect /usr/bin/authselect /sbin/authselect /bin/authselect; do
        [ ! -e "$candidate" ] && [ ! -L "$candidate" ] || return 0
    done
    return 1
}

scanner_authselect_configuration_valid() {
    local authselect_path=""
    local check_status=0
    local current_status=0

    SCANNER_AUTHSELECT_UNMANAGED=0
    platform_is_rhel_family || return 0
    runtime_enabled || return 0
    authselect_path="$(trusted_command authselect)" || {
        if scanner_authselect_command_exists; then
            return 2
        fi
        SCANNER_AUTHSELECT_UNMANAGED=1
        return 0
    }
    "$authselect_path" check >/dev/null 2>&1
    check_status=$?
    case "$check_status" in
        0)
            return 0
            ;;
        2|6)
            "$authselect_path" current --raw >/dev/null 2>&1
            current_status=$?
            case "$current_status" in
                2|6)
                    SCANNER_AUTHSELECT_UNMANAGED=1
                    return 0
                    ;;
                0)
                    return 2
                    ;;
                *)
                    return 2
                    ;;
            esac
            ;;
        *)
            return 2
            ;;
    esac
}

scanner_authentication_pam_lines() {
    local service=""
    local expansion_status=0

    if platform_is_debian_family; then
        pam_expand_service common-auth auth 2>/dev/null || expansion_status=1
        pam_expand_service common-account account 2>/dev/null || expansion_status=1
    elif platform_is_rhel_family; then
        for service in system-auth password-auth; do
            pam_expand_service "$service" auth 2>/dev/null || expansion_status=1
            pam_expand_service "$service" account 2>/dev/null || expansion_status=1
        done
    else
        return 2
    fi
    return "$expansion_status"
}

scanner_pam_has_module() {
    local lines_file="$1"
    local module_name="$2"
    local module_reference=""

    while IFS= read -r module_reference; do
        [ -n "$module_reference" ] && return 0
    done <<EOF
$(scanner_pam_module_references "$lines_file" "$module_name")
EOF
    return 1
}

scanner_pam_module_references() {
    local lines_file="$1"
    local module_name="$2"

    awk -v target="$module_name" '
        {
            line=$0
            sub(/^[^\t]*\t/, "", line)
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            count=split(line, fields, /[[:space:]]+/)
            module_index=3
            if (fields[2] ~ /^\[/) {
                module_index=2
                while (module_index <= count && fields[module_index] !~ /\]$/) module_index++
                module_index++
            }
            if (module_index > count) next
            module=fields[module_index]
            basename_value=module
            sub(/^.*\//, "", basename_value)
            if (basename_value == target) print module
        }
    ' "$lines_file" | LC_ALL=C sort -u
}

scanner_pam_module_reference_available() {
    local module_reference="$1"
    local module_name="$2"
    local candidate=""
    local logical_directory=""
    local physical_directory=""
    local resolved_candidate=""

    if [ "${module_reference#/}" != "$module_reference" ]; then
        candidate="$(fs_path "$module_reference" 2>/dev/null)" || return 1
        resolved_candidate="$(resolve_rooted_read_path "$candidate" 2>/dev/null || true)"
        [ -n "$resolved_candidate" ]
        return $?
    fi

    [ "$module_reference" = "$module_name" ] || return 1
    for logical_directory in /lib/security /lib64/security /usr/lib/security /usr/lib64/security; do
        candidate="$(fs_path "$logical_directory/$module_name" 2>/dev/null || true)"
        [ -n "$candidate" ] || continue
        resolved_candidate="$(resolve_rooted_read_path "$candidate" 2>/dev/null || true)"
        [ -n "$resolved_candidate" ] && return 0
    done
    for logical_directory in /lib /lib64 /usr/lib /usr/lib64; do
        physical_directory="$(fs_path "$logical_directory" 2>/dev/null || true)"
        [ -n "$physical_directory" ] && [ -d "$physical_directory" ] || continue
        for candidate in \
            "$physical_directory"/*-linux-gnu/security/"$module_name" \
            "$physical_directory"/*-linux-gnueabi/security/"$module_name" \
            "$physical_directory"/*-linux-gnueabihf/security/"$module_name" \
            "$physical_directory"/*-linux-gnuabi64/security/"$module_name" \
            "$physical_directory"/*-linux-gnuabin32/security/"$module_name" \
            "$physical_directory"/*-linux-gnux32/security/"$module_name"; do
            [ -e "$candidate" ] || [ -L "$candidate" ] || continue
            resolved_candidate="$(resolve_rooted_read_path "$candidate" 2>/dev/null || true)"
            [ -n "$resolved_candidate" ] && return 0
        done
    done
    return 1
}

scanner_pam_module_available() {
    local lines_file="$1"
    local module_name="$2"
    local module_reference=""
    local references=0

    while IFS= read -r module_reference; do
        [ -n "$module_reference" ] || continue
        references=$((references + 1))
        scanner_pam_module_reference_available "$module_reference" "$module_name" || return 1
    done <<EOF
$(scanner_pam_module_references "$lines_file" "$module_name")
EOF
    [ "$references" -gt 0 ]
}

scanner_pam_option_values() {
    local lines_file="$1"
    local module_expression="$2"
    local option_name="$3"
    local option_matching="${4:-insensitive}"

    awk -v module_expression="$module_expression" -v option="$option_name" -v option_matching="$option_matching" '
        {
            line=$0
            sub(/^[^\t]*\t/, "", line)
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            count=split(line, fields, /[[:space:]]+/)
            module_index=3
            if (fields[2] ~ /^\[/) {
                module_index=2
                while (module_index <= count && fields[module_index] !~ /\]$/) module_index++
                module_index++
            }
            if (module_index > count) next
            module_name=fields[module_index]
            sub(/^.*\//, "", module_name)
            if (module_name !~ ("^(" module_expression ")$")) next
            for (index_value=module_index + 1; index_value<=count; index_value++) {
                separator=index(fields[index_value], "=")
                if (separator <= 1) continue
                name=substr(fields[index_value], 1, separator - 1)
                if ((option_matching == "sensitive" && name == option) ||
                    (option_matching != "sensitive" && tolower(name) == tolower(option))) {
                    value=substr(fields[index_value], separator + 1)
                    print value
                }
            }
        }
    ' "$lines_file"
}

scanner_pam_unix_hash_option_counts() {
    local lines_file="$1"
    local yescrypt_supported=0

    platform_is_debian_family && yescrypt_supported=1

    awk -v yescrypt_supported="$yescrypt_supported" '
        {
            line=$0
            sub(/^[^\t]*\t/, "", line)
            if (line ~ /^[[:space:]]*#/) next
            sub(/^[[:space:]]+/, "", line)
            count=split(line, fields, /[[:space:]]+/)
            module_index=3
            if (fields[2] ~ /^\[/) {
                module_index=2
                while (module_index <= count && fields[module_index] !~ /\]$/) module_index++
                module_index++
            }
            if (module_index > count) next
            module_name=fields[module_index]
            sub(/^.*\//, "", module_name)
            if (module_name != "pam_unix.so") next
            modules++
            category=""
            for (index_value=module_index + 1; index_value<=count; index_value++) {
                option=tolower(fields[index_value])
                if (option ~ /^(sha256|sha512)$/) category="secure"
                else if (option == "blowfish") category="unsupported"
                else if (option ~ /^(yescrypt|gost_yescrypt)$/) {
                    if (option == "yescrypt" && yescrypt_supported) category="secure"
                    else category="unsupported"
                }
                else if (option ~ /^(md5|bigcrypt|des)$/) category="weak"
            }
            if (category == "secure") secure++
            else if (category == "weak") weak++
            else if (category == "unsupported") unsupported++
        }
        END {print modules+0, secure+0, weak+0, unsupported+0}
    ' "$lines_file"
}

scanner_pam_custom_configuration_file() {
    local lines_file="$1"
    local module_expression="$2"
    local paths=""
    local count=0
    local logical_path=""
    local physical_path=""
    local resolved_path=""

    paths="$(scanner_pam_option_values "$lines_file" "$module_expression" conf sensitive | LC_ALL=C sort -u)"
    count="$(printf '%s\n' "$paths" | awk 'NF {count++} END {print count+0}')"
    [ "$count" -le 1 ] || return 2
    [ "$count" -eq 1 ] || return 1
    logical_path="$(printf '%s\n' "$paths" | head -n 1)"
    case "$logical_path" in /*) ;; *) return 2 ;; esac
    case "$logical_path" in *'/../'*|*/..|*/./*|*/.) return 2 ;; esac
    if [ "$SCAN_ROOT" = "/" ]; then physical_path="$logical_path"; else physical_path="${SCAN_ROOT%/}$logical_path"; fi
    resolved_path="$(resolve_rooted_read_path "$physical_path" 2>/dev/null || true)"
    [ -n "$resolved_path" ] || return 2
    printf '%s\t%s\n' "$logical_path" "$resolved_path"
}

scanner_pam_module_precedes_unix() {
    local lines_file="$1"
    local module_name="$2"
    local pam_type="$3"

    awk -v module="$module_name" -v expected_type="$pam_type" '
        {
            line=$0
            sub(/^[^\t]*\t/, "", line)
            if (line ~ /^[[:space:]]*#/) next
            normalized=line
            sub(/^[[:space:]]+/, "", normalized)
            field_count=split(normalized, fields, /[[:space:]]+/)
            line_type=tolower(fields[1])
            sub(/^-/, "", line_type)
            if (line_type != expected_type) next
            module_index=3
            if (fields[2] ~ /^\[/) {
                module_index=2
                while (module_index <= field_count && fields[module_index] !~ /\]$/) module_index++
                module_index++
            }
            module_basename=fields[module_index]
            sub(/^.*\//, "", module_basename)
            if (!module_line && module_basename == module) module_line=NR
            if (!unix_line && module_basename == "pam_unix.so") unix_line=NR
        }
        END {exit(module_line && (!unix_line || module_line < unix_line) ? 0 : 1)}
    ' "$lines_file"
}

scanner_pam_module_control_metrics() {
    local lines_file="$1"
    local module_name="$2"

    awk -v module="$module_name" '
        {
            line=$0
            sub(/^[^\t]*\t/, "", line)
            if (line ~ /^[[:space:]]*#/) next
            normalized=line
            sub(/^[[:space:]]+/, "", normalized)
            field_count=split(normalized, fields, /[[:space:]]+/)
            line_type=tolower(fields[1])
            sub(/^-/, "", line_type)
            control=tolower(fields[2])
            module_index=3
            if (fields[2] ~ /^\[/) {
                module_index=2
                while (module_index <= field_count && fields[module_index] !~ /\]$/) module_index++
                module_index++
                control="bracket"
            }
            module_basename=fields[module_index]
            sub(/^.*\//, "", module_basename)
            if (module_basename != module) next
            if (line_type ~ /^(auth|account|password|session)$/ && control ~ /^(required|requisite)$/) mandatory++
            else if (line_type ~ /^(auth|account|password|session)$/ && control ~ /^(optional|sufficient)$/) bypassable++
            else ambiguous++
        }
        END {print mandatory+0, bypassable+0, ambiguous+0}
    ' "$lines_file"
}

scanner_pam_module_has_flag() {
    local lines_file="$1"
    local module_name="$2"
    local flag="$3"

    awk -v expected_module="$module_name" -v expected_flag="$flag" '
        {
            line=$0
            sub(/^[^\t]*\t/, "", line)
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            field_count=split(line, fields, /[[:space:]]+/)
            module_index=3
            if (fields[2] ~ /^\[/) {
                module_index=2
                while (module_index <= field_count && fields[module_index] !~ /\]$/) module_index++
                module_index++
            }
            if (module_index > field_count) next
            module_basename=fields[module_index]
            sub(/^.*\//, "", module_basename)
            if (module_basename != expected_module) next
            for (field_index=module_index + 1; field_index<=field_count; field_index++) {
                if (fields[field_index] == expected_flag) found=1
            }
        }
        END {exit(found ? 0 : 1)}
    ' "$lines_file"
}

scanner_pam_stack_has_bracket_control() {
    local lines_file="$1"
    local pam_types="$2"

    awk -v expected_types="$pam_types" '
        {
            line=$0
            sub(/^[^\t]*\t/, "", line)
            normalized=line
            sub(/^[[:space:]]+/, "", normalized)
            split(normalized, fields, /[[:space:]]+/)
            line_type=tolower(fields[1])
            sub(/^-/, "", line_type)
            if (line_type ~ ("^(" expected_types ")$") && fields[2] ~ /^\[/) found=1
        }
        END {exit(found ? 0 : 1)}
    ' "$lines_file"
}

scanner_configuration_has_flag() {
    local flag="$1"
    shift
    local file=""

    for file in "$@"; do
        [ -r "$file" ] || continue
        if awk -v target="$flag" '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                sub(/[[:space:]]+#.*$/, "", line)
                sub(/[[:space:]]+$/, "", line)
                if (line == target) found=1
            }
            END {exit(found ? 0 : 1)}
        ' "$file"; then
            return 0
        fi
    done
    return 1
}

scanner_pwquality_has_flag() {
    local flag="$1"
    local files=()
    local file=""

    while IFS= read -r file; do
        [ -n "$file" ] && files+=("$file")
    done <<EOF
$(pwquality_files)
EOF
    scanner_configuration_has_flag "$flag" "${files[@]}"
}

scanner_pwhistory_has_flag() {
    local flag="$1"
    local file=""

    platform_supports_pwhistory_configuration || return 1
    file="$(fs_path /etc/security/pwhistory.conf)"
    scanner_configuration_has_flag "$flag" "$file"
}

scanner_faillock_value() {
    local key="$1"
    local file=""
    local file_status=0

    file="$(optional_rooted_read_path /etc/security/faillock.conf 2>/dev/null)" || file_status=$?
    [ "$file_status" -eq 0 ] || return "$file_status"
    assignment_from_files_last_wins "$key" "$file"
}

scanner_pam_lock_flow_analysis() {
    local auth_lines_file="$1"
    local account_lines_file="$2"

    awk -v account_file="$account_lines_file" '
        function parse_line(raw, fields, count, index_value) {
            line=raw
            sub(/^[^\t]*\t/, "", line)
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) return 0
            count=split(line, fields, /[[:space:]]+/)
            line_type=tolower(fields[1])
            sub(/^-/, "", line_type)
            control=tolower(fields[2])
            module_index=3
            if (fields[2] ~ /^\[/) {
                module_index=2
                control=""
                while (module_index <= count) {
                    control=control " " tolower(fields[module_index])
                    if (fields[module_index] ~ /\]$/) break
                    module_index++
                }
                sub(/^ /, "", control)
                module_index++
            }
            if (module_index > count) return 0
            module_path=fields[module_index]
            module_name=module_path
            sub(/^.*\//, "", module_name)
            options=""
            for (index_value=module_index + 1; index_value<=count; index_value++) {
                options=options " " fields[index_value]
            }
            options=options " "
            return 1
        }
        function mandatory(value) {
            return value == "required" || value == "requisite" || value ~ /default=(bad|die)/
        }
        function credential_module(value) {
            return value ~ /^pam_(unix|sss|winbind|ldap|krb5|userdb|pkcs11|fprintd|u2f|google_authenticator)[.]so$/
        }
        {
            if (!parse_line($0, fields)) next
            is_account=(FILENAME == account_file)
            if (!is_account) {
                auth_position++
                if (credential_module(module_name)) {
                    credential_count++
                    if (!first_credential) first_credential=auth_position
                    last_credential=auth_position
                    if (control == "sufficient") sufficient_credentials++
                    if (control ~ /^\[/ && control ~ /success=[0-9]+/) bracket_credentials++
                }
                if (module_name == "pam_permit.so" && control == "sufficient") {
                    if (!first_bypass) first_bypass=auth_position
                }
                if (module_name == "pam_deny.so" && !first_deny) first_deny=auth_position
                if (module_name == "pam_faillock.so") {
                    if (options ~ / preauth /) {
                        preauth_count++
                        if (!preauth_position) preauth_position=auth_position
                        if (!mandatory(control) && control !~ /^\[/) invalid_controls++
                    }
                    if (options ~ / authfail /) {
                        authfail_count++
                        if (!authfail_position) authfail_position=auth_position
                        if (!mandatory(control)) invalid_controls++
                    }
                    if (options ~ / authsucc /) {
                        authsucc_count++
                        if (!authsucc_position) authsucc_position=auth_position
                        if (!(control == "sufficient" || mandatory(control))) invalid_controls++
                    }
                }
                if (module_name ~ /^pam_(tally|tally2)[.]so$/) {
                    tally_auth_count++
                    if (!tally_position) tally_position=auth_position
                    if (!mandatory(control)) invalid_controls++
                }
            } else {
                if (line_type != "account") next
                if (module_name == "pam_faillock.so") {
                    faillock_account_count++
                    if (!mandatory(control)) invalid_controls++
                }
                if (module_name ~ /^pam_(tally|tally2)[.]so$/ && options ~ / reset /) {
                    tally_account_count++
                    if (!mandatory(control)) invalid_controls++
                }
            }
        }
        END {
            ordered=(credential_count > 0 && authfail_count == 1 && authfail_position > last_credential)
            if (preauth_count > 0 && preauth_position >= first_credential) ordered=0
            if (first_bypass && (!preauth_position || first_bypass < preauth_position)) ordered=0
            if (first_deny && first_deny < authfail_position) ordered=0

            reset_with_authsucc=(authsucc_count == 1 && authsucc_position > authfail_position &&
                                 sufficient_credentials == 0 && bracket_credentials == credential_count)
            reset_with_account=(faillock_account_count > 0 && preauth_count == 1 &&
                                (sufficient_credentials > 0 || bracket_credentials == credential_count))
            faillock_valid=(ordered && invalid_controls == 0 && (reset_with_authsucc || reset_with_account))

            tally_valid=(tally_auth_count == 1 && tally_account_count > 0 && credential_count > 0 &&
                         tally_position < first_credential && invalid_controls == 0)
            printf "%d %d %d %d %d %d %d %d %d\n", faillock_valid, tally_valid,
                   preauth_count, authfail_count, authsucc_count, faillock_account_count,
                   tally_auth_count, tally_account_count, invalid_controls
        }
    ' "$auth_lines_file" "$account_lines_file"
}

scanner_sshd_static_value() {
    local key="$1"
    local file=""
    local main_file=""
    local match=""
    local files=()
    local selected_files=""
    local selected_status=0
    local resolved_file=""
    local main_status=0

    main_file="$(optional_rooted_read_path /etc/ssh/sshd_config 2>/dev/null)" || main_status=$?
    case "$main_status" in
        0) ;;
        1) return 1 ;;
        *) return 2 ;;
    esac
    selected_files="$(select_layered_files .conf /etc/ssh/sshd_config.d)" || selected_status=$?
    [ "$selected_status" -eq 0 ] || return "$selected_status"
    while IFS= read -r file; do
        [ -n "$file" ] && files+=("$file")
    done <<EOF
$selected_files
EOF
    files+=("$main_file")

    for file in "${files[@]}"; do
        resolved_file="$(resolve_rooted_read_path "$file" 2>/dev/null)" || return 2
        file="$resolved_file"
        match="$(awk -v target="$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')" '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                sub(/[[:space:]]+#.*$/, "", line)
                split(line, fields, /[[:space:]]+/)
                name=tolower(fields[1])
                if (name == "match") exit
                if (name == target) {
                    value=fields[2]
                    print tolower(value) "\t" FNR
                    exit
                }
            }
        ' "$file")"
        if [ -n "$match" ]; then
            printf '%s\t%s:%s\n' "${match%%"$(printf '\t')"*}" "$(display_path "$file")" "${match##*"$(printf '\t')"}"
            return 0
        fi
    done
    return 1
}

scanner_sshd_static_ambiguous() {
    local main_file=""
    local file=""
    local dropin_count=0
    local selected_files=""
    local selected_status=0
    local resolved_file=""
    local main_status=0

    main_file="$(optional_rooted_read_path /etc/ssh/sshd_config 2>/dev/null)" || main_status=$?
    case "$main_status" in
        0) ;;
        1) return 1 ;;
        *) return 2 ;;
    esac
    selected_files="$(select_layered_files .conf /etc/ssh/sshd_config.d)" || selected_status=$?
    [ "$selected_status" -eq 0 ] || return 2
    if [ -n "$selected_files" ]; then
        dropin_count="$(printf '%s\n' "$selected_files" | awk 'NF {count++} END {print count+0}')"
        while IFS= read -r file; do
            [ -n "$file" ] || continue
            resolved_file="$(resolve_rooted_read_path "$file" 2>/dev/null)" || return 2
            file="$resolved_file"
            if awk '
                {
                    line=$0
                    sub(/^[[:space:]]+/, "", line)
                    if (line == "" || line ~ /^#/) next
                    split(line, fields, /[[:space:]]+/)
                    name=tolower(fields[1])
                    if (name == "include" || name == "match") ambiguous=1
                }
                END {exit(ambiguous ? 0 : 1)}
            ' "$file"; then
                return 0
            fi
        done <<EOF
$selected_files
EOF
    fi

    if awk -v dropins="$dropin_count" '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            split(line, fields, /[[:space:]]+/)
            name=tolower(fields[1])
            if (name == "match") ambiguous=1
            if (name == "permitrootlogin") saw_setting=1
            if (name == "include") {
                if (fields[2] != "/etc/ssh/sshd_config.d/*.conf" || fields[3] != "" || saw_setting) ambiguous=1
                saw_standard_include=1
            }
        }
        END {
            if (dropins > 0 && !saw_standard_include) ambiguous=1
            exit(ambiguous ? 0 : 1)
        }
    ' "$main_file"; then
        return 0
    fi

    return 1
}

scanner_inetd_service_enabled() {
    local service_name="$1"
    local inetd_file=""
    local xinetd_file=""
    local path_status=0

    inetd_file="$(optional_rooted_read_path /etc/inetd.conf 2>/dev/null)" || path_status=$?
    case "$path_status" in
        0) ;;
        1) inetd_file="" ;;
        *) return 2 ;;
    esac
    if [ -n "$inetd_file" ] && awk -v service="$service_name" '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            split(line, fields, /[[:space:]]+/)
            if (fields[1] == service) found=1
        }
        END {exit(found ? 0 : 1)}
    ' "$inetd_file"; then
        return 0
    fi

    path_status=0
    xinetd_file="$(optional_rooted_read_path "/etc/xinetd.d/$service_name" 2>/dev/null)" || path_status=$?
    case "$path_status" in
        0) ;;
        1) return 1 ;;
        *) return 2 ;;
    esac
    if awk '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                if (line ~ /^disable[[:space:]]*=[[:space:]]*yes([[:space:]]|$)/) disabled=1
                if (line ~ /^disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)/) disabled=0
            }
            END {exit(disabled ? 0 : 1)}
        ' "$xinetd_file"; then
        return 1
    fi
    return 0
}

SCANNER_TELNET_PAM_SECURETTY=0
SCANNER_TELNET_PAM_MODULE_AVAILABLE=0
SCANNER_TELNET_SECURETTY_PRESENT=0
SCANNER_TELNET_SECURETTY_PTS=0

scanner_telnet_root_access_status() {
    local pam_lines_file=""
    local securetty_file=""
    local securetty_status=0

    SCANNER_TELNET_PAM_SECURETTY=0
    SCANNER_TELNET_PAM_MODULE_AVAILABLE=0
    SCANNER_TELNET_SECURETTY_PRESENT=0
    SCANNER_TELNET_SECURETTY_PTS=0
    pam_lines_file="$(new_scratch_file u01-telnet-pam)" || return 2
    pam_expand_service login auth > "$pam_lines_file" 2>/dev/null || return 1
    if awk '
        {
            line=$0
            sub(/^[^\t]*\t/, "", line)
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            count=split(line, fields, /[[:space:]]+/)
            position++
            control=tolower(fields[2])
            module_index=3
            if (fields[2] ~ /^\[/) {
                bracket=1
                module_index=2
                while (module_index <= count && fields[module_index] !~ /\]$/) module_index++
                module_index++
            } else {
                bracket=0
            }
            module=fields[module_index]
            sub(/^.*\//, "", module)
            if (!securetty_position && module == "pam_securetty.so" &&
                (control == "required" || control == "requisite")) securetty_position=position
            if (!securetty_position && (control == "sufficient" || bracket)) bypass_before=1
        }
        END {exit(securetty_position && !bypass_before ? 0 : 1)}
    ' "$pam_lines_file"; then
        SCANNER_TELNET_PAM_SECURETTY=1
    fi
    scanner_pam_module_available "$pam_lines_file" pam_securetty.so && SCANNER_TELNET_PAM_MODULE_AVAILABLE=1

    securetty_file="$(optional_rooted_read_path /etc/securetty 2>/dev/null)" || securetty_status=$?
    case "$securetty_status" in
        0) SCANNER_TELNET_SECURETTY_PRESENT=1 ;;
        1) return 1 ;;
        *) return 2 ;;
    esac
    SCANNER_TELNET_SECURETTY_PTS="$(awk '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            sub(/[[:space:]]+#.*$/, "", line)
            sub(/[[:space:]]+$/, "", line)
            if (line ~ /^(pts\/|\/dev\/pts\/)/) count++
        }
        END {print count+0}
    ' "$securetty_file")"

    [ "$SCANNER_TELNET_PAM_SECURETTY" -eq 1 ] &&
        [ "$SCANNER_TELNET_PAM_MODULE_AVAILABLE" -eq 1 ] &&
        [ "$SCANNER_TELNET_SECURETTY_PTS" -eq 0 ]
}

check_u_01() {
    local ssh_value_record=""
    local ssh_value=""
    local ssh_state=3
    local telnet_state=3
    local telnet_static_status=1
    local ssh_active=0
    local telnet_enabled=0
    local listener_checked=0
    local static_ambiguous=0
    local evidence=""
    local listener_output=""
    local listener_status=0
    local port_listener_status=0
    local custom_invocation_status=1
    local ssh_static_status=0
    local ambiguity_status=1
    local telnet_policy_status=1
    local telnet_compliant=0
    local telnet_legacy_status=1
    local openssh_active=0
    local ssh_listener_unknown=0

    ssh_value_record="$(scanner_sshd_static_value PermitRootLogin 2>/dev/null)" || ssh_static_status=$?
    if [ "$ssh_static_status" -gt 1 ]; then
        set_result ERROR "SSH drop-in 또는 기본 구성의 전체 그래프를 안전하게 읽지 못했습니다." "ssh_static_status=${ssh_static_status}"
        return
    fi
    ssh_value="$(scanner_value_only "$ssh_value_record")"
    if [ -n "$ssh_value_record" ]; then
        scanner_append_evidence evidence "ssh_persistent=${ssh_value},source=$(scanner_source_only "$ssh_value_record")"
    else
        scanner_append_evidence evidence "ssh_persistent=unresolved"
    fi
    scanner_sshd_static_ambiguous
    ambiguity_status=$?
    if [ "$ambiguity_status" -eq 0 ]; then
        static_ambiguous=1
    elif [ "$ambiguity_status" -gt 1 ]; then
        set_result ERROR "SSH Include 또는 Match 구성을 안전하게 분석하지 못했습니다." "ssh_ambiguity_status=${ambiguity_status}"
        return
    fi
    scanner_append_evidence evidence "ssh_static_ambiguous=${static_ambiguous}"

    scanner_inetd_service_enabled telnet
    telnet_legacy_status=$?
    case "$telnet_legacy_status" in
        0) telnet_enabled=1 ;;
        1) ;;
        *)
            set_result ERROR "Telnet inetd 또는 xinetd 경로를 안전한 일반 파일로 읽지 못했습니다." \
                "paths=/etc/inetd.conf,/etc/xinetd.d/telnet"
            return
            ;;
    esac
    if declare -F service_legacy_enabled >/dev/null 2>&1; then
        SERVICE_LEGACY_UNCERTAIN=0
        if service_legacy_enabled '^telnet$'; then
            telnet_enabled=1
            telnet_legacy_status=0
        elif [ "${SERVICE_LEGACY_UNCERTAIN:-0}" -eq 1 ]; then
            telnet_legacy_status=2
        fi
    fi
    scanner_append_evidence evidence "telnet_legacy_state_code=${telnet_legacy_status}"
    if ! runtime_enabled && declare -F service_activation_state >/dev/null 2>&1; then
        service_activation_state \
            telnet.service telnet.socket telnet@.service telnetd.service telnetd.socket
        telnet_static_status=$?
        [ "$telnet_static_status" -eq 0 ] && telnet_enabled=1
        scanner_append_evidence evidence "telnet_static_state_code=${telnet_static_status}"
        scanner_append_evidence evidence "${SERVICE_ACTIVATION_EVIDENCE:-telnet_static_evidence=none}"
    fi
    if runtime_enabled; then
        service_state ssh.service sshd.service ssh.socket sshd.socket >/dev/null 2>&1
        ssh_state=$?
        service_state telnet.socket telnet.service >/dev/null 2>&1
        telnet_state=$?
        if [ "$ssh_state" -eq 0 ]; then
            ssh_active=1
            openssh_active=1
        fi
        [ "$telnet_state" -eq 0 ] && telnet_enabled=1
        listener_status=0
        port_listener_status=0
        listener_output="$(port_listener_facts 22 tcp 2>/dev/null)" || port_listener_status=$?
        if [ "$port_listener_status" -eq 0 ]; then
            listener_checked=1
            if [ -n "$listener_output" ]; then
                ssh_active=1
                if printf '%s\n' "$listener_output" | grep -Eiq '(^|[^[:alnum:]_])sshd([^[:alnum:]_]|$)'; then
                    openssh_active=1
                fi
                if printf '%s\n' "$listener_output" | \
                    awk 'index($0, "users:") && $0 !~ /(^|[^[:alnum:]_])sshd([^[:alnum:]_]|$)/ {found=1} END {exit(found ? 0 : 1)}'; then
                    ssh_listener_unknown=1
                elif [ "$openssh_active" -eq 0 ]; then
                    ssh_listener_unknown=1
                fi
            fi
        else
            listener_status="$port_listener_status"
        fi
        port_listener_status=0
        listener_output="$(port_listener_facts 23 tcp 2>/dev/null)" || port_listener_status=$?
        if [ "$port_listener_status" -eq 0 ]; then
            listener_checked=1
            [ -n "$listener_output" ] && telnet_enabled=1
        elif [ "$listener_status" -eq 0 ]; then
            listener_status="$port_listener_status"
        fi
        if [ "$ssh_state" -eq 0 ] || [ "$openssh_active" -eq 1 ]; then
            sshd_manager_has_custom_invocation >/dev/null 2>&1
            custom_invocation_status=$?
            if [ "$custom_invocation_status" -eq 3 ]; then
                # A non-systemd OpenSSH process can use an unobserved custom invocation.
                custom_invocation_status=0
            fi
        else
            custom_invocation_status=1
        fi
        [ "$custom_invocation_status" -eq 0 ] && static_ambiguous=1
        scanner_append_evidence evidence "ssh_runtime_state_code=${ssh_state}"
        scanner_append_evidence evidence "telnet_runtime_state_code=${telnet_state}"
        scanner_append_evidence evidence "listener_table_checked=${listener_checked}"
        scanner_append_evidence evidence "ssh_endpoint_active=${ssh_active}"
        scanner_append_evidence evidence "openssh_endpoint_active=${openssh_active}"
        scanner_append_evidence evidence "unknown_port_22_listener=${ssh_listener_unknown}"
        scanner_append_evidence evidence "custom_sshd_invocation=$([ "$custom_invocation_status" -eq 0 ] && printf true || printf false_or_unavailable)"

        if [ "$ssh_state" -eq 2 ] || [ "$telnet_state" -eq 2 ] || [ "$custom_invocation_status" -eq 2 ] || [ "$listener_status" -ne 0 ]; then
            set_result ERROR "원격 터미널의 unit, 실행 인수 또는 리스너 상태를 완전히 수집하지 못했습니다." "$evidence"
            return
        fi

        if [ "$openssh_active" -eq 1 ]; then
            ssh_value="$(sshd_effective_value PermitRootLogin 2>/dev/null || true)"
            scanner_append_evidence evidence "ssh_effective=${ssh_value:-unresolved}"
            if [ -z "$ssh_value" ]; then
                if [ "$ssh_state" -eq 0 ]; then
                    set_result ERROR "활성 SSH 서비스의 유효 설정을 확인하지 못했습니다." "$evidence"
                else
                    set_result MANUAL "22번 포트 리스너를 확인했지만 SSH 서비스와 root 정책을 확정하지 못했습니다." "$evidence"
                fi
                return
            fi
        fi
    fi

    if [ "$telnet_enabled" -eq 1 ]; then
        scanner_telnet_root_access_status
        telnet_policy_status=$?
        scanner_append_evidence evidence "telnet_pam_securetty=${SCANNER_TELNET_PAM_SECURETTY}"
        scanner_append_evidence evidence "telnet_pam_module_available=${SCANNER_TELNET_PAM_MODULE_AVAILABLE}"
        scanner_append_evidence evidence "securetty_present=${SCANNER_TELNET_SECURETTY_PRESENT}"
        scanner_append_evidence evidence "securetty_pts_entries=${SCANNER_TELNET_SECURETTY_PTS}"
        if [ "$telnet_policy_status" -eq 0 ]; then
            telnet_compliant=1
        elif [ "$telnet_policy_status" -eq 2 ]; then
            set_result ERROR "활성 Telnet의 PAM 또는 securetty 경로를 안전하게 분석하지 못했습니다." "$evidence"
            return
        else
            set_result VULNERABLE "활성 Telnet에서 root 직접 접속을 차단하는 PAM 및 securetty 설정이 불완전합니다." "$evidence"
            return
        fi
    fi

    if [ "$ssh_listener_unknown" -eq 1 ]; then
        set_result MANUAL "22번 포트 리스너가 OpenSSH인지 확정할 수 없어 root 원격 접속 정책을 수동 확인해야 합니다." "$evidence"
        return
    fi

    if [ "$telnet_compliant" -eq 1 ] && [ "$ssh_value" = "no" ] && [ "$static_ambiguous" -eq 0 ]; then
        set_result GOOD "활성 Telnet과 SSH의 root 직접 접속이 차단되어 있습니다." "$evidence"
    elif [ "$telnet_compliant" -eq 1 ] && runtime_enabled && [ "$ssh_active" -eq 0 ] && [ "$listener_checked" -eq 1 ]; then
        set_result GOOD "활성 Telnet의 root 직접 접속이 차단되어 있고 활성 SSH는 확인되지 않았습니다." "$evidence"
    elif runtime_enabled && [ "$ssh_active" -eq 0 ] && [ "$listener_checked" -eq 1 ]; then
        set_result GOOD "활성 원격 터미널 서비스를 확인하지 못했습니다." "$evidence"
    elif runtime_enabled && [ "$ssh_active" -eq 0 ]; then
        set_result MANUAL "리스너 표를 확인하지 못해 원격 터미널 비활성 상태를 확정할 수 없습니다." "$evidence"
    elif ! runtime_enabled && [ "$telnet_static_status" -eq 2 ]; then
        set_result MANUAL "오프라인 Telnet unit의 정적 활성 상태를 확정할 수 없습니다." "$evidence"
    elif [ "$telnet_legacy_status" -eq 2 ]; then
        set_result MANUAL "Telnet inetd 또는 xinetd 유효 활성 상태를 확정할 수 없습니다." "$evidence"
    elif ! runtime_enabled && [ "$static_ambiguous" -eq 1 ]; then
        set_result MANUAL "오프라인 SSH Include 또는 Match 문맥의 유효값을 확정할 수 없습니다." "$evidence"
    elif runtime_enabled && [ "$ssh_active" -eq 1 ] && [ "$static_ambiguous" -eq 1 ]; then
        set_result MANUAL "SSH Match 조건 전체에서 root 직접 접속 차단을 확인해야 합니다." "$evidence"
    elif [ "$ssh_value" = "no" ]; then
        set_result GOOD "SSH의 root 직접 접속이 차단되어 있습니다." "$evidence"
    elif [ -n "$ssh_value" ]; then
        set_result VULNERABLE "SSH의 root 직접 접속이 완전히 차단되지 않았습니다." "$evidence"
    else
        set_result MANUAL "원격 터미널 사용 여부와 root 직접 접속의 유효 설정을 확정할 수 없습니다." "$evidence"
    fi
}

scanner_check_u_02_stack() {
    local pam_service="$1"
    local pam_lines_file=""
    local maximum_days_record="$2"
    local minimum_days_record="$3"
    local minimum_length_record="$4"
    local digit_credit_record="$5"
    local uppercase_credit_record="$6"
    local lowercase_credit_record="$7"
    local other_credit_record="$8"
    local history_record="$9"
    local history_file_record="${10}"
    local shared_quality_enforce_present="${11}"
    local shared_history_enforce_present="${12}"
    local history_file_value=""
    local value=""
    local failures=0
    local evidence=""
    local module_present=0
    local history_module_present=0
    local quality_control_metrics=""
    local history_control_metrics=""
    local bypassable_controls=0
    local ambiguous_controls=0
    local stack_bracket_controls=0
    local quality_custom_file=""
    local quality_custom_logical=""
    local quality_custom_record=""
    local history_custom_file=""
    local custom_status=0
    local quality_enforce_file=""
    local history_enforce_file=""
    local quality_enforce_present=0
    local history_enforce_present=0
    local quality_custom_files_list=""
    local quality_custom_files_array=()
    local quality_custom_entry=""
    local minimum_days_guide_conflict=0

    pam_lines_file="$(new_scratch_file u02-pam)" || {
        set_result ERROR "PAM 설정을 분석할 임시 파일을 만들지 못했습니다."
        return
    }
    if ! pam_expand_service "$pam_service" password > "$pam_lines_file" 2>/dev/null; then
        set_result ERROR "유효 PAM 비밀번호 스택의 include 그래프를 완전히 해석하지 못했습니다." "pam_service=${pam_service},pam_graph=incomplete"
        return
    fi

    quality_custom_record="$(scanner_pam_custom_configuration_file "$pam_lines_file" 'pam_pwquality[.]so' 2>/dev/null)" || custom_status=$?
    if [ "$custom_status" -eq 2 ]; then
        set_result ERROR "pam_pwquality의 conf= 경로를 안전하게 단일 해석하지 못했습니다." "pam_pwquality_conf=invalid_or_multiple"
        return
    elif [ "$custom_status" -eq 0 ]; then
        quality_custom_logical="${quality_custom_record%%"$(printf '\t')"*}"
        quality_custom_file="${quality_custom_record#*"$(printf '\t')"}"
        quality_custom_files_list="$(pwquality_custom_files "$quality_custom_logical" "$quality_custom_file" 2>/dev/null)" || {
            set_result ERROR "pam_pwquality custom 구성의 drop-in 그래프를 해석하지 못했습니다." "pam_pwquality_conf=unreadable_dropin"
            return
        }
        while IFS= read -r quality_custom_entry; do
            [ -n "$quality_custom_entry" ] && quality_custom_files_array+=("$quality_custom_entry")
        done <<EOF
$quality_custom_files_list
EOF
        minimum_length_record="$(assignment_from_files_last_wins minlen "${quality_custom_files_array[@]}" 2>/dev/null || true)"
        digit_credit_record="$(assignment_from_files_last_wins dcredit "${quality_custom_files_array[@]}" 2>/dev/null || true)"
        uppercase_credit_record="$(assignment_from_files_last_wins ucredit "${quality_custom_files_array[@]}" 2>/dev/null || true)"
        lowercase_credit_record="$(assignment_from_files_last_wins lcredit "${quality_custom_files_array[@]}" 2>/dev/null || true)"
        other_credit_record="$(assignment_from_files_last_wins ocredit "${quality_custom_files_array[@]}" 2>/dev/null || true)"
        quality_enforce_file="$quality_custom_files_list"
    fi
    if platform_supports_pwhistory_configuration; then
        custom_status=0
        history_custom_file="$(scanner_pam_custom_configuration_file "$pam_lines_file" 'pam_pwhistory[.]so' 2>/dev/null)" || custom_status=$?
        if [ "$custom_status" -eq 2 ]; then
            set_result ERROR "pam_pwhistory의 conf= 경로를 안전하게 단일 해석하지 못했습니다." "pam_pwhistory_conf=invalid_or_multiple"
            return
        elif [ "$custom_status" -eq 0 ]; then
            history_custom_file="${history_custom_file#*"$(printf '\t')"}"
            if ! scanner_capture_optional_value history_record pwhistory_file_value remember "$history_custom_file"; then
                set_result ERROR "pam_pwhistory custom 구성 값을 안전하게 해석하지 못했습니다." "pam_pwhistory_conf=unreadable"
                return
            fi
            if ! scanner_capture_optional_value history_file_record pwhistory_file_value file "$history_custom_file"; then
                set_result ERROR "pam_pwhistory custom 구성 값을 안전하게 해석하지 못했습니다." "pam_pwhistory_conf=unreadable"
                return
            fi
            history_enforce_file="$history_custom_file"
        fi
    fi

    value="$(scanner_pam_option_values "$pam_lines_file" 'pam_pwquality[.]so' minlen sensitive | tail -n 1)"
    [ -n "$value" ] && minimum_length_record="${value}"$'\t'"PAM"
    value="$(scanner_pam_option_values "$pam_lines_file" 'pam_pwquality[.]so' dcredit sensitive | tail -n 1)"
    [ -n "$value" ] && digit_credit_record="${value}"$'\t'"PAM"
    value="$(scanner_pam_option_values "$pam_lines_file" 'pam_pwquality[.]so' ucredit sensitive | tail -n 1)"
    [ -n "$value" ] && uppercase_credit_record="${value}"$'\t'"PAM"
    value="$(scanner_pam_option_values "$pam_lines_file" 'pam_pwquality[.]so' lcredit sensitive | tail -n 1)"
    [ -n "$value" ] && lowercase_credit_record="${value}"$'\t'"PAM"
    value="$(scanner_pam_option_values "$pam_lines_file" 'pam_pwquality[.]so' ocredit sensitive | tail -n 1)"
    [ -n "$value" ] && other_credit_record="${value}"$'\t'"PAM"
    value="$(scanner_pam_option_values "$pam_lines_file" 'pam_(pwhistory|unix)[.]so' remember | tail -n 1)"
    [ -n "$value" ] && history_record="${value}"$'\t'"PAM"
    value="$(scanner_pam_option_values "$pam_lines_file" 'pam_pwhistory[.]so' file | tail -n 1)"
    [ -n "$value" ] && history_file_record="${value}"$'\t'"PAM"

    scanner_pam_has_module "$pam_lines_file" pam_pwquality.so && module_present=1
    if scanner_pam_has_module "$pam_lines_file" pam_pwhistory.so; then
        history_module_present=1
    fi
    [ "$history_module_present" -eq 1 ] && [ -z "$history_record" ] && history_record="10"$'\t'"pam_pwhistory-default"
    history_file_value="$(scanner_value_only "$history_file_record")"
    quality_control_metrics="$(scanner_pam_module_control_metrics "$pam_lines_file" pam_pwquality.so)"
    history_control_metrics="$(scanner_pam_module_control_metrics "$pam_lines_file" pam_pwhistory.so)"
    bypassable_controls=$((
        $(printf '%s\n' "$quality_control_metrics" | awk '{print $2+0}') +
        $(printf '%s\n' "$history_control_metrics" | awk '{print $2+0}')
    ))
    ambiguous_controls=$((
        $(printf '%s\n' "$quality_control_metrics" | awk '{print $3+0}') +
        $(printf '%s\n' "$history_control_metrics" | awk '{print $3+0}')
    ))
    scanner_pam_stack_has_bracket_control "$pam_lines_file" password && stack_bracket_controls=1

    for value in \
        "PASS_MAX_DAYS:$(scanner_value_only "$maximum_days_record"):maximum" \
        "PASS_MIN_DAYS:$(scanner_value_only "$minimum_days_record"):minimum" \
        "minlen:$(scanner_value_only "$minimum_length_record"):length" \
        "dcredit:$(scanner_value_only "$digit_credit_record"):credit" \
        "ucredit:$(scanner_value_only "$uppercase_credit_record"):credit" \
        "lcredit:$(scanner_value_only "$lowercase_credit_record"):credit" \
        "ocredit:$(scanner_value_only "$other_credit_record"):credit" \
        "remember:$(scanner_value_only "$history_record"):history"; do
        local setting_name="${value%%:*}"
        local remainder="${value#*:}"
        local setting_value="${remainder%%:*}"
        local setting_kind="${remainder##*:}"
        local compliant=0

        if scanner_is_integer "$setting_value"; then
            case "$setting_kind" in
                maximum) [ "$setting_value" -gt 0 ] && [ "$setting_value" -le 90 ] && compliant=1 ;;
                minimum)
                    if [ "$setting_value" -ge 1 ]; then
                        compliant=1
                    elif platform_is_rhel_family && [ "$setting_value" -eq 0 ]; then
                        compliant=1
                        minimum_days_guide_conflict=1
                    fi
                    ;;
                length) [ "$setting_value" -ge 8 ] && compliant=1 ;;
                credit) [ "$setting_value" -eq -1 ] && compliant=1 ;;
                history) [ "$setting_value" -ge 4 ] && compliant=1 ;;
            esac
        fi
        [ "$compliant" -eq 1 ] || failures=$((failures + 1))
        scanner_append_evidence evidence "${setting_name}=${setting_value:-unresolved}"
    done

    [ "$module_present" -eq 1 ] || failures=$((failures + 1))
    [ "$history_module_present" -eq 1 ] || failures=$((failures + 1))
    if platform_is_rhel_family && ! scanner_pam_has_module "$pam_lines_file" pam_unix.so; then
        failures=$((failures + 1))
    fi
    if platform_is_rhel_family && [ "$history_file_value" != "/etc/security/opasswd" ]; then
        failures=$((failures + 1))
    fi
    scanner_pam_module_precedes_unix "$pam_lines_file" pam_pwquality.so password || failures=$((failures + 1))
    if scanner_pam_has_module "$pam_lines_file" pam_pwhistory.so; then
        scanner_pam_module_precedes_unix "$pam_lines_file" pam_pwhistory.so password || failures=$((failures + 1))
    fi

    if [ -n "$quality_enforce_file" ]; then
        scanner_configuration_has_flag enforce_for_root "${quality_custom_files_array[@]}" && quality_enforce_present=1
    elif [ "$shared_quality_enforce_present" -eq 1 ]; then
        quality_enforce_present=1
    fi
    scanner_pam_module_has_flag "$pam_lines_file" pam_pwquality.so enforce_for_root && quality_enforce_present=1
    if [ "$quality_enforce_present" -eq 0 ]; then
        failures=$((failures + 1))
        scanner_append_evidence evidence "pwquality_enforce_for_root=absent"
    else
        scanner_append_evidence evidence "pwquality_enforce_for_root=present"
    fi
    if [ -n "$history_enforce_file" ]; then
        scanner_configuration_has_flag enforce_for_root "$history_enforce_file" && history_enforce_present=1
    elif [ "$shared_history_enforce_present" -eq 1 ]; then
        history_enforce_present=1
    fi
    scanner_pam_module_has_flag "$pam_lines_file" pam_pwhistory.so enforce_for_root && history_enforce_present=1
    if [ "$history_enforce_present" -eq 0 ]; then
        failures=$((failures + 1))
        scanner_append_evidence evidence "pwhistory_enforce_for_root=absent"
    else
        scanner_append_evidence evidence "pwhistory_enforce_for_root=present"
    fi
    scanner_append_evidence evidence "pam_pwquality_present=${module_present}"
    scanner_append_evidence evidence "password_history_module_present=${history_module_present}"
    scanner_append_evidence evidence "pwhistory_file=${history_file_value:-unresolved}"
    scanner_append_evidence evidence "pass_min_days_guide_conflict=${minimum_days_guide_conflict}"
    scanner_append_evidence evidence "bypassable_pam_controls=${bypassable_controls}"
    scanner_append_evidence evidence "ambiguous_pam_controls=${ambiguous_controls}"
    scanner_append_evidence evidence "stack_bracket_controls=${stack_bracket_controls}"
    scanner_append_evidence evidence "authselect_unmanaged=${SCANNER_AUTHSELECT_UNMANAGED}"
    if [ "$bypassable_controls" -gt 0 ]; then
        set_result VULNERABLE "비밀번호 품질 또는 이력 모듈이 우회 가능한 PAM control로 구성되어 있습니다." "$evidence"
    elif [ "$failures" -eq 0 ] && [ "$minimum_days_guide_conflict" -eq 1 ]; then
        set_result MANUAL "Redhat 절차의 PASS_MIN_DAYS 0과 1 표기가 충돌하여 최소 사용 기간을 확인해야 합니다." "$evidence"
    elif [ "$failures" -eq 0 ] && [ "$SCANNER_AUTHSELECT_UNMANAGED" -eq 1 ]; then
        set_result MANUAL "PAM 정책은 충족하지만 RHEL authselect opt-out 구성이므로 변경 관리 상태를 확인해야 합니다." "$evidence"
    elif [ "$failures" -eq 0 ] && [ "$ambiguous_controls" -eq 0 ] && [ "$stack_bracket_controls" -eq 0 ]; then
        set_result GOOD "비밀번호 길이·복잡성·사용기간·이력 정책이 KISA 기준을 충족합니다." "$evidence"
    elif [ "$failures" -eq 0 ]; then
        set_result MANUAL "복잡한 PAM control 흐름에서 비밀번호 정책이 항상 적용되는지 확인해야 합니다." "$evidence"
    else
        set_result VULNERABLE "비밀번호 관리 정책에서 KISA 기준 미충족 또는 미설정 항목을 확인했습니다." "$evidence"
    fi
}

check_u_02() {
    local pam_service=""
    local maximum_days_record=""
    local minimum_days_record=""
    local minimum_length_record=""
    local digit_credit_record=""
    local uppercase_credit_record=""
    local lowercase_credit_record=""
    local other_credit_record=""
    local history_record=""
    local history_file_record=""
    local shared_quality_enforce_present=0
    local shared_history_enforce_present=0
    local stack_status=""
    local stack_evidence=""
    local evidence=""
    local evidence_line=""
    local vulnerable_stacks=0
    local manual_stacks=0
    local error_stacks=0

    if ! scanner_authselect_configuration_valid; then
        set_result ERROR "RHEL authselect 구성이 없거나 무결성 검증에 실패했습니다." "authselect_check=failed"
        return
    fi

    if ! platform_is_debian_family && ! platform_is_rhel_family; then
        set_result ERROR "지원 계열의 PAM 비밀번호 서비스를 선택하지 못했습니다." "pam_family=unsupported"
        return
    fi

    if ! scanner_capture_optional_value maximum_days_record login_defs_value PASS_MAX_DAYS ||
       ! scanner_capture_optional_value minimum_days_record login_defs_value PASS_MIN_DAYS ||
       ! scanner_capture_optional_value minimum_length_record pwquality_value minlen ||
       ! scanner_capture_optional_value digit_credit_record pwquality_value dcredit ||
       ! scanner_capture_optional_value uppercase_credit_record pwquality_value ucredit ||
       ! scanner_capture_optional_value lowercase_credit_record pwquality_value lcredit ||
       ! scanner_capture_optional_value other_credit_record pwquality_value ocredit ||
       ! scanner_capture_optional_value history_record pwhistory_value remember ||
       ! scanner_capture_optional_value history_file_record pwhistory_value file; then
        set_result ERROR "비밀번호 정책 파일의 우선순위 또는 경로를 안전하게 해석하지 못했습니다." "policy_resolver=failed"
        return
    fi
    scanner_pwquality_has_flag enforce_for_root && shared_quality_enforce_present=1
    scanner_pwhistory_has_flag enforce_for_root && shared_history_enforce_present=1

    if platform_is_debian_family; then
        scanner_check_u_02_stack common-password \
            "$maximum_days_record" "$minimum_days_record" \
            "$minimum_length_record" "$digit_credit_record" \
            "$uppercase_credit_record" "$lowercase_credit_record" \
            "$other_credit_record" "$history_record" "$history_file_record" \
            "$shared_quality_enforce_present" "$shared_history_enforce_present"
        return
    fi

    for pam_service in system-auth password-auth; do
        scanner_check_u_02_stack "$pam_service" \
            "$maximum_days_record" "$minimum_days_record" \
            "$minimum_length_record" "$digit_credit_record" \
            "$uppercase_credit_record" "$lowercase_credit_record" \
            "$other_credit_record" "$history_record" "$history_file_record" \
            "$shared_quality_enforce_present" "$shared_history_enforce_present"
        stack_status="$RESULT_STATUS"
        stack_evidence="$RESULT_EVIDENCE"
        scanner_append_evidence evidence "${pam_service}.status=${stack_status}"
        while IFS= read -r evidence_line; do
            [ -n "$evidence_line" ] || continue
            scanner_append_evidence evidence "${pam_service}.${evidence_line}"
        done <<< "$stack_evidence"
        case "$stack_status" in
            VULNERABLE) vulnerable_stacks=$((vulnerable_stacks + 1)) ;;
            MANUAL) manual_stacks=$((manual_stacks + 1)) ;;
            ERROR) error_stacks=$((error_stacks + 1)) ;;
        esac
    done

    scanner_append_evidence evidence "pam_stacks=system-auth,password-auth"
    if [ "$error_stacks" -gt 0 ]; then
        set_result ERROR "RHEL PAM 비밀번호 스택 중 안전하게 판정하지 못한 구성이 있습니다." "$evidence"
    elif [ "$vulnerable_stacks" -gt 0 ]; then
        set_result VULNERABLE "RHEL PAM 비밀번호 스택 중 KISA 기준을 충족하지 못한 구성이 있습니다." "$evidence"
    elif [ "$manual_stacks" -gt 0 ]; then
        set_result MANUAL "RHEL PAM 비밀번호 스택의 정책 적용을 추가로 확인해야 합니다." "$evidence"
    else
        set_result GOOD "system-auth와 password-auth의 비밀번호 정책이 KISA 기준을 충족합니다." "$evidence"
    fi
}

check_u_03() {
    local pam_lines_file=""
    local auth_lines_file=""
    local account_lines_file=""
    local deny_record=""
    local deny_value=""
    local pam_values=""
    local module_present=0
    local faillock_present=0
    local tally_present=0
    local module_available=1
    local mixed_lock_modules=0
    local required_service_count=0
    local valid_service_count=0
    local invalid_service_count=0
    local service=""
    local account_service=""
    local services=()
    local expansion_status=0
    local flow_analysis=""
    local faillock_flow_valid=0
    local tally_flow_valid=0
    local preauth_count=0
    local authfail_count=0
    local authsucc_count=0
    local account_count=0
    local tally_auth_count=0
    local tally_account_count=0
    local invalid_control_count=0
    local faillock_custom_file=""
    local custom_status=0
    local invalid_values=0
    local evidence=""
    local value=""
    local configuration_status=0

    pam_lines_file="$(new_scratch_file u03-pam)" || {
        set_result ERROR "PAM 설정을 분석할 임시 파일을 만들지 못했습니다."
        return
    }
    if ! scanner_authselect_configuration_valid; then
        set_result ERROR "RHEL authselect 구성이 없거나 무결성 검증에 실패했습니다." "authselect_check=failed"
        return
    fi
    : > "$pam_lines_file"
    if platform_is_debian_family; then
        services=(common-auth)
    elif platform_is_rhel_family; then
        services=(system-auth password-auth)
    else
        set_result ERROR "지원 계열의 PAM 인증 서비스를 선택하지 못했습니다." "pam_family=unsupported"
        return
    fi

    required_service_count="${#services[@]}"
    for service in "${services[@]}"; do
        auth_lines_file="$(new_scratch_file "u03-${service}-auth")" || {
            set_result ERROR "PAM 인증 스택을 분석할 임시 파일을 만들지 못했습니다."
            return
        }
        account_lines_file="$(new_scratch_file "u03-${service}-account")" || {
            set_result ERROR "PAM 계정 스택을 분석할 임시 파일을 만들지 못했습니다."
            return
        }
        account_service="$service"
        platform_is_debian_family && account_service="common-account"

        expansion_status=0
        pam_expand_service "$service" auth > "$auth_lines_file" 2>/dev/null || expansion_status=$?
        if [ "$expansion_status" -eq 2 ]; then
            set_result ERROR "유효 PAM 인증 스택의 include 그래프를 완전히 해석하지 못했습니다." "pam_service=${service},pam_type=auth"
            return
        fi
        expansion_status=0
        pam_expand_service "$account_service" account > "$account_lines_file" 2>/dev/null || expansion_status=$?
        if [ "$expansion_status" -eq 2 ]; then
            set_result ERROR "유효 PAM 계정 스택의 include 그래프를 완전히 해석하지 못했습니다." "pam_service=${account_service},pam_type=account"
            return
        fi
        cat "$auth_lines_file" "$account_lines_file" >> "$pam_lines_file"
        flow_analysis="$(scanner_pam_lock_flow_analysis "$auth_lines_file" "$account_lines_file")"
        read -r faillock_flow_valid tally_flow_valid preauth_count authfail_count authsucc_count account_count tally_auth_count tally_account_count invalid_control_count <<< "$flow_analysis"
        if [ "$faillock_flow_valid" -eq 1 ] || [ "$tally_flow_valid" -eq 1 ]; then
            valid_service_count=$((valid_service_count + 1))
        else
            invalid_service_count=$((invalid_service_count + 1))
        fi
        scanner_append_evidence evidence "${service}_faillock_flow=${faillock_flow_valid},preauth=${preauth_count},authfail=${authfail_count},authsucc=${authsucc_count},account=${account_count}"
        scanner_append_evidence evidence "${service}_tally_flow=${tally_flow_valid},auth=${tally_auth_count},account_reset=${tally_account_count},invalid_controls=${invalid_control_count}"
    done

    scanner_pam_has_module "$pam_lines_file" pam_faillock.so && faillock_present=1
    if scanner_pam_has_module "$pam_lines_file" pam_tally.so || \
       scanner_pam_has_module "$pam_lines_file" pam_tally2.so; then
        tally_present=1
    fi
    if [ "$faillock_present" -eq 1 ] || [ "$tally_present" -eq 1 ]; then
        module_present=1
    fi
    if [ "$faillock_present" -eq 1 ] && [ "$tally_present" -eq 1 ]; then
        mixed_lock_modules=1
    fi
    if [ "$faillock_present" -eq 1 ] && ! scanner_pam_module_available "$pam_lines_file" pam_faillock.so; then
        module_available=0
    fi
    if scanner_pam_has_module "$pam_lines_file" pam_tally.so && ! scanner_pam_module_available "$pam_lines_file" pam_tally.so; then
        module_available=0
    fi
    if scanner_pam_has_module "$pam_lines_file" pam_tally2.so && ! scanner_pam_module_available "$pam_lines_file" pam_tally2.so; then
        module_available=0
    fi

    if [ "$faillock_present" -eq 1 ]; then
        pam_values="$(scanner_pam_option_values "$pam_lines_file" 'pam_faillock[.]so' deny sensitive)"
        faillock_custom_file="$(scanner_pam_custom_configuration_file "$pam_lines_file" 'pam_faillock[.]so' 2>/dev/null)" || custom_status=$?
        if [ "$custom_status" -eq 2 ]; then
            set_result ERROR "pam_faillock의 conf= 경로를 안전하게 단일 해석하지 못했습니다." "pam_faillock_conf=invalid_or_multiple"
            return
        elif [ "$custom_status" -eq 0 ]; then
            faillock_custom_file="${faillock_custom_file#*"$(printf '\t')"}"
            deny_record="$(assignment_from_files_last_wins deny "$faillock_custom_file" 2>/dev/null || true)"
        else
            configuration_status=0
            deny_record="$(scanner_faillock_value deny 2>/dev/null)" || configuration_status=$?
            [ "$configuration_status" -ne 2 ] || {
                set_result ERROR "faillock.conf 경로 또는 내용을 안전하게 해석하지 못했습니다." "pam_faillock_conf=unreadable"
                return
            }
        fi
        deny_value="$(scanner_value_only "$deny_record")"
        [ -n "$deny_value" ] || deny_value=3
    else
        pam_values="$(scanner_pam_option_values "$pam_lines_file" 'pam_(tally|tally2)[.]so' deny sensitive)"
        deny_value="$(printf '%s\n' "$pam_values" | tail -n 1)"
    fi

    while IFS= read -r value; do
        [ -n "$value" ] || continue
        if ! scanner_is_unsigned_integer "$value" || [ "$value" -lt 1 ] || [ "$value" -gt 10 ]; then
            invalid_values=$((invalid_values + 1))
        fi
    done <<EOF
${deny_value}
${pam_values}
EOF

    scanner_append_evidence evidence "lock_module_present=${module_present}"
    scanner_append_evidence evidence "lock_module_available=${module_available}"
    scanner_append_evidence evidence "deny=${deny_value:-unresolved}"
    scanner_append_evidence evidence "valid_lock_services=${valid_service_count}/${required_service_count}"
    if [ "$valid_service_count" -eq "$required_service_count" ]; then
        scanner_append_evidence evidence "lock_flow_valid=1"
    else
        scanner_append_evidence evidence "lock_flow_valid=0"
    fi
    scanner_append_evidence evidence "mixed_lock_modules=${mixed_lock_modules}"
    scanner_append_evidence evidence "authselect_unmanaged=${SCANNER_AUTHSELECT_UNMANAGED}"
    if [ "$module_present" -eq 0 ] || [ "$module_available" -eq 0 ] || [ -z "$deny_value" ] || [ "$invalid_values" -gt 0 ]; then
        set_result VULNERABLE "계정 잠금 모듈이 없거나 잠금 임계값이 1~10회로 설정되지 않았습니다." "$evidence"
    elif [ "$invalid_service_count" -gt 0 ]; then
        set_result VULNERABLE "모든 유효 인증 서비스에서 실패 기록·잠금·성공 초기화 흐름을 확인하지 못했습니다." "$evidence"
    elif [ "$mixed_lock_modules" -eq 1 ] || [ "$SCANNER_AUTHSELECT_UNMANAGED" -eq 1 ]; then
        set_result MANUAL "잠금 임계값은 확인했지만 PAM의 실패 기록·잠금·성공 초기화 흐름을 완전하게 입증하지 못했습니다." "$evidence"
    else
        set_result GOOD "계정 잠금 임계값과 PAM 잠금 흐름이 확인됐습니다." "$evidence"
    fi
}

check_u_04() {
    local passwd_file=""
    local shadow_file=""
    local shadow_input="/dev/null"
    local counts=""
    local protected_count=0
    local vulnerable_count=0
    local unresolved_count=0
    local evidence=""
    local passwd_path_status=0
    local shadow_path_status=0
    local shadow_present=0

    passwd_file="$(optional_rooted_read_path /etc/passwd 2>/dev/null)" || passwd_path_status=$?
    [ "$passwd_path_status" -eq 0 ] || {
        set_result ERROR "/etc/passwd를 안전한 일반 파일로 읽을 수 없습니다." "path=/etc/passwd"
        return
    }
    scanner_validate_passwd_database "$passwd_file" || {
        set_result ERROR "/etc/passwd의 필드 구조, 계정 이름 또는 UID/GID가 유효하지 않습니다." "path=/etc/passwd"
        return
    }
    shadow_file="$(optional_rooted_read_path /etc/shadow 2>/dev/null)" || shadow_path_status=$?
    case "$shadow_path_status" in
        0)
            shadow_present=1
            shadow_input="$shadow_file"
            scanner_validate_shadow_database "$shadow_file" || {
                set_result ERROR "/etc/shadow의 필드 구조 또는 계정 이름이 유효하지 않습니다." "path=/etc/shadow"
                return
            }
            ;;
        1) shadow_present=0 ;;
        *)
            set_result ERROR "/etc/shadow 경로가 안전하지 않거나 일반 파일로 읽히지 않습니다." "path=/etc/shadow"
            return
            ;;
    esac

    counts="$(awk -F: -v shadow_file="$shadow_input" -v shadow_present="$shadow_present" '
        function crypt_characters(value) {
            return value != "" && value !~ /[^.\/0-9A-Za-z]/
        }
        function valid_sha_crypt(value, identifier, parts, count, salt, digest, expected_length) {
            count=split(value, parts, "\\$")
            if (count == 4) {
                salt=parts[3]
                digest=parts[4]
            } else if (count == 5 && parts[3] ~ /^rounds=[1-9][0-9]*$/) {
                salt=parts[4]
                digest=parts[5]
            } else return 0
            expected_length=(identifier == "5" ? 43 : 86)
            return length(salt) >= 1 && length(salt) <= 16 && crypt_characters(salt) &&
                   length(digest) == expected_length && crypt_characters(digest)
        }
        function valid_md5_crypt(value, parts, count) {
            count=split(value, parts, "\\$")
            return count == 4 && length(parts[3]) >= 1 && length(parts[3]) <= 8 &&
                   crypt_characters(parts[3]) && length(parts[4]) == 22 && crypt_characters(parts[4])
        }
        function valid_yescrypt(value, parts, count) {
            count=split(value, parts, "\\$")
            return count == 5 && length(parts[3]) >= 3 && length(parts[3]) <= 11 &&
                   crypt_characters(parts[3]) && length(parts[4]) >= 1 && length(parts[4]) <= 86 &&
                   crypt_characters(parts[4]) && length(parts[5]) == 43 && crypt_characters(parts[5])
        }
        function valid_bcrypt(value, parts, count, cost) {
            count=split(value, parts, "\\$")
            if (count != 4 || parts[2] !~ /^2[abxy]$/ || parts[3] !~ /^[0-9][0-9]$/) return 0
            cost=parts[3] + 0
            return cost >= 4 && cost <= 31 && length(parts[4]) == 53 && crypt_characters(parts[4])
        }
        function storage_category(value, stripped) {
            if (value ~ /^[!*]+$/) return 1
            stripped=value
            while (substr(stripped, 1, 1) == "!") stripped=substr(stripped, 2)
            if (stripped ~ /^\$[56]\$/ && valid_sha_crypt(stripped, substr(stripped, 2, 1))) return 1
            if (stripped ~ /^\$1\$/ && valid_md5_crypt(stripped)) return 1
            if (stripped ~ /^\$(y|gy)\$/ && valid_yescrypt(stripped)) return 1
            if (stripped ~ /^\$2/ && valid_bcrypt(stripped)) return 1
            if (length(stripped) == 13 && crypt_characters(stripped)) return 1
            if (stripped ~ /^\$/) return 2
            return 0
        }
        FILENAME == shadow_file {
            shadow_account[$1]=1
            next
        }
        {
            if ($2 == "x") {
                if (shadow_present && ($1 in shadow_account)) protected++
                else unresolved++
                next
            }
            category=storage_category($2)
            if (category == 1) protected++
            else if (category == 2) unresolved++
            else vulnerable++
        }
        END {print protected+0, vulnerable+0, unresolved+0}
    ' "$shadow_input" "$passwd_file")" || {
        set_result ERROR "비밀번호 저장 위치를 계정별로 분석하지 못했습니다." "paths=/etc/passwd,/etc/shadow"
        return
    }
    read -r protected_count vulnerable_count unresolved_count <<< "$counts"
    if [ "$shadow_present" -eq 1 ]; then
        scanner_append_evidence evidence "password_storage=per_account_shadow_or_encrypted"
    else
        scanner_append_evidence evidence "password_storage=encrypted_passwd_fallback"
    fi
    scanner_append_evidence evidence "shadow_file=$([ "$shadow_present" -eq 1 ] && printf present || printf absent)"
    scanner_append_evidence evidence "protected_password_fields=${protected_count}"
    scanner_append_evidence evidence "unencrypted_password_fields=${vulnerable_count}"
    scanner_append_evidence evidence "unresolved_password_fields=${unresolved_count}"
    if [ "$vulnerable_count" -gt 0 ]; then
        set_result VULNERABLE "쉐도우 저장 또는 암호화된 /etc/passwd 비밀번호 필드가 아닌 계정이 존재합니다." "$evidence"
    elif [ "$unresolved_count" -gt 0 ]; then
        set_result MANUAL "쉐도우 대응 레코드가 없거나 알 수 없는 비밀번호 저장 형식이 존재합니다." "$evidence"
    else
        set_result GOOD "모든 계정 비밀번호가 쉐도우 또는 암호화된 비밀번호 필드로 저장됩니다." "$evidence"
    fi
}

check_u_05() {
    local passwd_file=""
    local accounts=""
    local count=0
    local root_uid=""
    local passwd_status=0

    passwd_file="$(optional_rooted_read_path /etc/passwd 2>/dev/null)" || passwd_status=$?
    if [ "$passwd_status" -ne 0 ] || ! scanner_validate_passwd_database "$passwd_file"; then
        set_result ERROR "/etc/passwd를 안전한 일반 파일로 읽고 검증하지 못했습니다." "path=/etc/passwd"
        return
    fi
    root_uid="$(awk -F: '$1 == "root" {print $3; exit}' "$passwd_file")"
    [ -n "$root_uid" ] || {
        set_result ERROR "root 계정 레코드를 찾지 못했습니다." "path=/etc/passwd"
        return
    }
    accounts="$(awk -F: -v root_uid="$root_uid" '$1 != "root" && ($3 + 0) == (root_uid + 0) {print $1}' "$passwd_file")"
    count="$(printf '%s\n' "$accounts" | awk 'NF {count++} END {print count+0}')"
    if [ "$root_uid" -ne 0 ]; then
        set_result VULNERABLE "root 계정 UID가 Linux 관리자 UID 0이 아닙니다." "root_uid=${root_uid}"
    elif [ "$count" -gt 0 ]; then
        local evidence=""
        scanner_append_evidence evidence "count=${count}"
        scanner_append_evidence evidence "root_uid=${root_uid}"
        scanner_append_evidence evidence "accounts=$(printf '%s\n' "$accounts" | head -n 20 | paste -sd, -)"
        set_result VULNERABLE "root 외 UID 0 계정이 존재합니다." "$evidence"
    else
        set_result GOOD "root 외 UID 0 계정이 없습니다." "count=0"
    fi
}

scanner_u06_structured_pam_records() {
    local pam_lines_file="$1"

    awk '
        {
            line=$0
            sub(/^[^\t]*\t/, "", line)
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            field_count=split(line, fields, /[[:space:]]+/)
            line_type=tolower(fields[1])
            sub(/^-/, "", line_type)
            if (line_type != "auth") next

            control=tolower(fields[2])
            module_index=3
            if (fields[2] ~ /^\[/) {
                module_index=2
                while (module_index <= field_count && fields[module_index] !~ /\]$/) module_index++
                if (module_index > field_count) {
                    malformed=1
                    next
                }
                control="bracket"
                module_index++
            }
            if (module_index > field_count || fields[module_index] == "") {
                malformed=1
                next
            }

            module_reference=fields[module_index]
            module_name=module_reference
            sub(/^.*\//, "", module_name)
            options=""
            for (field_index=module_index + 1; field_index<=field_count; field_index++) {
                options=options (options == "" ? "" : " ") fields[field_index]
            }
            printf "%s\t%s\t%s\t%s\n", control, module_reference, module_name, options
        }
        END {if (malformed) exit 2}
    ' "$pam_lines_file"
}

check_u_06() {
    local pam_lines_file=""
    local pam_records_file=""
    local su_path=""
    local su_path_status=0
    local file_uid=""
    local file_gid=""
    local file_mode=""
    local decimal_mode=""
    local pam_restricted=0
    local pam_module_available=0
    local permission_restricted=0
    local evidence=""
    local pam_group=""
    local effective_pam_group=""
    local pam_group_exists=0
    local pam_wheel_record=""
    local pam_wheel_module_reference=""
    local stack_bracket_controls=0
    local pam_early_bypass=0
    local pam_root_only=0
    local su_integrity=0
    local passwd_file=""
    local passwd_status=0
    local group_file=""
    local group_status=0
    local uid_minimum_record=""
    local uid_minimum=1000
    local general_account_count=0
    local nss_source_state="unresolved"
    local nss_source_status=0

    su_path="$(optional_rooted_read_path /usr/bin/su 2>/dev/null)" || su_path_status=$?
    case "$su_path_status" in
        0) ;;
        1)
            set_result NOT_APPLICABLE "su 명령이 설치되어 있지 않습니다." "path=/usr/bin/su" false
            return
            ;;
        *)
            set_result ERROR "su 명령 경로를 안전한 일반 파일로 해석하지 못했습니다." "path=/usr/bin/su"
            return
            ;;
    esac
    if [ ! -x "$su_path" ]; then
        set_result NOT_APPLICABLE "su 파일에 실행 권한이 없어 명령을 사용할 수 없습니다." "path=/usr/bin/su" false
        return
    fi

    passwd_file="$(optional_rooted_read_path /etc/passwd 2>/dev/null)" || passwd_status=$?
    if [ "$passwd_status" -ne 0 ] || ! scanner_validate_passwd_database "$passwd_file"; then
        set_result ERROR "/etc/passwd를 안전한 일반 파일로 읽고 검증하지 못했습니다." "path=/etc/passwd"
        return
    fi
    if ! scanner_capture_optional_value uid_minimum_record login_defs_value UID_MIN; then
        set_result ERROR "UID_MIN 설정 경로를 안전하게 해석하지 못했습니다." "setting=UID_MIN"
        return
    fi
    if [ -n "$uid_minimum_record" ]; then
        scanner_is_unsigned_integer "$(scanner_value_only "$uid_minimum_record")" || {
            set_result ERROR "UID_MIN 값이 유효한 정수가 아닙니다." "setting=UID_MIN"
            return
        }
        uid_minimum="$(scanner_value_only "$uid_minimum_record")"
    fi
    general_account_count="$(awk -F: -v minimum="$uid_minimum" '
        function nonlogin(shell) {
            return shell == "/bin/false" || shell == "/usr/bin/false" || shell == "/sbin/nologin" ||
                   shell == "/usr/sbin/nologin" || shell == "/bin/nologin"
        }
        $1 != "root" && ($3 + 0) >= minimum && !nonlogin($7) {count++}
        END {print count+0}
    ' "$passwd_file")"
    if [ "$general_account_count" -eq 0 ]; then
        scanner_account_nss_source_state_into nss_source_state || nss_source_status=$?
        if [ "$nss_source_status" -eq 2 ]; then
            set_result ERROR "/etc/nsswitch.conf 경로를 안전한 일반 파일로 읽지 못했습니다." \
                "local_general_accounts=0\nnss_account_sources=${nss_source_state}"
        elif [ "$nss_source_status" -eq 0 ] && [ "$nss_source_state" = "files_only" ]; then
            set_result NOT_APPLICABLE \
                "로컬 일반 사용자와 외부 NSS 계정 소스가 없어 su 제한 점검 대상이 없습니다." \
                "local_general_accounts=0\nnss_account_sources=files_only" false
        else
            set_result MANUAL \
                "로컬 일반 사용자 계정은 없지만 외부 계정 소스까지 부재함을 입증하지 못했습니다." \
                "local_general_accounts=0\nnss_account_sources=${nss_source_state}"
        fi
        return
    fi

    pam_lines_file="$(new_scratch_file u06-pam)" || {
        set_result ERROR "PAM 설정을 분석할 임시 파일을 만들지 못했습니다."
        return
    }
    if ! scanner_authselect_configuration_valid; then
        set_result ERROR "RHEL authselect 구성이 없거나 무결성 검증에 실패했습니다." "authselect_check=failed"
        return
    fi
    if ! pam_expand_service su auth > "$pam_lines_file" 2>/dev/null; then
        set_result ERROR "su PAM include 그래프를 완전히 해석하지 못했습니다." "pam_service=su"
        return
    fi
    pam_records_file="$(new_scratch_file u06-pam-records)" || {
        set_result ERROR "su PAM 구조 분석용 임시 파일을 만들지 못했습니다."
        return
    }
    if ! scanner_u06_structured_pam_records "$pam_lines_file" > "$pam_records_file"; then
        set_result ERROR "su PAM 행의 control 및 module 구조를 해석하지 못했습니다." "pam_service=su"
        return
    fi
    pam_wheel_record="$(awk -F '\t' '
        function has_option(options, target, option_count, option_index, option_fields) {
            option_count=split(options, option_fields, /[[:space:]]+/)
            for (option_index=1; option_index<=option_count; option_index++) {
                if (tolower(option_fields[option_index]) == target) return 1
            }
            return 0
        }
        {
            if ($3 == "pam_wheel.so" && $1 ~ /^(required|requisite|bracket)$/ && !has_option($4, "deny")) {
                print
                exit
            }
        }
    ' "$pam_records_file")"
    if [ -n "$pam_wheel_record" ]; then
        pam_restricted=1
        pam_group="$(printf '%s\n' "$pam_wheel_record" | awk -F '\t' '
            {
                count=split($4, fields, /[[:space:]]+/)
                for (index_value=1; index_value<=count; index_value++) {
                    if (fields[index_value] ~ /^group=/) {
                        sub(/^[^=]*=/, "", fields[index_value])
                        selected_group=fields[index_value]
                    }
                }
            }
            END {if (selected_group != "") print selected_group}
        ')"
        effective_pam_group="${pam_group:-wheel}"
        pam_wheel_module_reference="${pam_wheel_record#*$'\t'}"
        pam_wheel_module_reference="${pam_wheel_module_reference%%$'\t'*}"
        scanner_pam_module_reference_available "$pam_wheel_module_reference" pam_wheel.so && pam_module_available=1

        group_file="$(optional_rooted_read_path /etc/group 2>/dev/null)" || group_status=$?
        if [ "$group_status" -ne 0 ] || ! scanner_validate_group_database "$group_file"; then
            set_result ERROR "/etc/group을 안전한 일반 파일로 읽고 검증하지 못했습니다." "path=/etc/group"
            return
        fi
        if awk -F: -v target="$effective_pam_group" '$1 == target {found=1} END {exit(found ? 0 : 1)}' "$group_file"; then
            pam_group_exists=1
        fi
    fi
    scanner_pam_stack_has_bracket_control "$pam_lines_file" auth && stack_bracket_controls=1

    if awk -F '\t' '
        function has_option(options, target, option_count, option_index, option_fields) {
            option_count=split(options, option_fields, /[[:space:]]+/)
            for (option_index=1; option_index<=option_count; option_index++) {
                if (tolower(option_fields[option_index]) == target) return 1
            }
            return 0
        }
        {
            if ($3 == "pam_wheel.so" && $1 ~ /^(required|requisite|bracket)$/ &&
                !has_option($4, "deny") && !has_option($4, "root_only")) exit
            if ($1 == "sufficient" && $3 != "pam_rootok.so") {found=1; exit}
        }
        END {exit(found ? 0 : 1)}
    ' "$pam_records_file"; then
        pam_early_bypass=1
    fi
    if awk -F '\t' '
        function has_option(options, target, option_count, option_index, option_fields) {
            option_count=split(options, option_fields, /[[:space:]]+/)
            for (option_index=1; option_index<=option_count; option_index++) {
                if (tolower(option_fields[option_index]) == target) return 1
            }
            return 0
        }
        {
            if ($3 == "pam_wheel.so" && has_option($4, "root_only")) {found=1; exit}
        }
        END {exit(found ? 0 : 1)}
    ' "$pam_records_file"; then
        pam_root_only=1
    fi

    file_uid="$(stat_uid "$su_path" 2>/dev/null || true)"
    file_gid="$(scanner_stat_gid "$su_path" 2>/dev/null || true)"
    file_mode="$(stat_mode "$su_path" 2>/dev/null || true)"
    decimal_mode="$(mode_to_decimal "$file_mode" 2>/dev/null || true)"
    if [ "$file_uid" = "0" ] && [ -n "$decimal_mode" ] && [ $((decimal_mode & 0022)) -eq 0 ]; then
        su_integrity=1
    fi
    if [ "$su_integrity" -eq 1 ] && [ $((decimal_mode & 0001)) -eq 0 ] && [ $((decimal_mode & 0010)) -ne 0 ]; then
        permission_restricted=1
    fi

    scanner_append_evidence evidence "pam_wheel_restriction=${pam_restricted}"
    scanner_append_evidence evidence "pam_wheel_module_available=${pam_module_available}"
    scanner_append_evidence evidence "pam_wheel_group=${effective_pam_group:-not_configured}"
    scanner_append_evidence evidence "pam_wheel_group_exists=${pam_group_exists}"
    scanner_append_evidence evidence "stack_bracket_controls=${stack_bracket_controls}"
    scanner_append_evidence evidence "pam_early_bypass=${pam_early_bypass}"
    scanner_append_evidence evidence "pam_root_only=${pam_root_only}"
    scanner_append_evidence evidence "local_general_accounts=${general_account_count}"
    scanner_append_evidence evidence "su_integrity=${su_integrity}"
    scanner_append_evidence evidence "su_owner_uid=${file_uid:-unresolved}"
    scanner_append_evidence evidence "su_group_gid=${file_gid:-unresolved}"
    scanner_append_evidence evidence "su_mode=${file_mode:-unresolved}"
    if [ "$pam_restricted" -eq 1 ] && { [ "$pam_module_available" -eq 0 ] || [ "$pam_group_exists" -eq 0 ]; }; then
        set_result VULNERABLE "su PAM 제한 모듈 또는 대상 그룹을 사용할 수 없습니다." "$evidence"
    elif [ "$pam_restricted" -eq 1 ] && [ "$SCANNER_AUTHSELECT_UNMANAGED" -eq 0 ] && [ "$stack_bracket_controls" -eq 0 ] && \
       [ "$pam_early_bypass" -eq 0 ] && [ "$pam_root_only" -eq 0 ] && [ "$su_integrity" -eq 1 ] && \
       { [ "$effective_pam_group" = "wheel" ] || [ "$effective_pam_group" = "sudo" ]; }; then
        set_result GOOD "su 실행이 필수 PAM 규칙으로 특정 그룹에 제한되어 있습니다." "$evidence"
    elif [ "$pam_restricted" -eq 1 ]; then
        set_result MANUAL "su 제한 그룹의 구성원 범위가 관리 목적에 적합한지 확인해야 합니다." "$evidence"
    elif [ "$permission_restricted" -eq 1 ]; then
        set_result MANUAL "su 파일 권한은 그룹 실행으로 제한되지만 해당 그룹의 업무상 적정성을 확인해야 합니다." "$evidence"
    else
        set_result VULNERABLE "일반 사용자의 su 실행을 제한하는 설정을 확인하지 못했습니다." "$evidence"
    fi
}

check_u_07() {
    local passwd_file=""
    local uid_minimum_record=""
    local uid_minimum="1000"
    local accounts=""
    local count=0
    local evidence=""
    local passwd_status=0
    local account_count=0
    local last_path=""
    local last_status=0
    local recent_login_records=0
    local shadow_evidence=""
    local shadow_status=0

    passwd_file="$(optional_rooted_read_path /etc/passwd 2>/dev/null)" || passwd_status=$?
    if [ "$passwd_status" -ne 0 ] || ! scanner_validate_passwd_database "$passwd_file"; then
        set_result ERROR "/etc/passwd를 안전한 일반 파일로 읽고 검증하지 못했습니다." "path=/etc/passwd"
        return
    fi
    if ! scanner_capture_optional_value uid_minimum_record login_defs_value UID_MIN; then
        set_result ERROR "UID_MIN 설정 경로를 안전하게 해석하지 못했습니다." "setting=UID_MIN"
        return
    fi
    if [ -n "$uid_minimum_record" ]; then
        scanner_is_unsigned_integer "$(scanner_value_only "$uid_minimum_record")" || {
            set_result ERROR "UID_MIN 값이 유효한 정수가 아닙니다." "setting=UID_MIN"
            return
        }
        uid_minimum="$(scanner_value_only "$uid_minimum_record")"
    fi
    accounts="$(awk -F: -v minimum="$uid_minimum" '
        function nonlogin(shell) {
            return shell == "/bin/false" || shell == "/usr/bin/false" || shell == "/sbin/nologin" ||
                   shell == "/usr/sbin/nologin" || shell == "/bin/nologin"
        }
        ($3 + 0) == 0 || (($3 + 0) >= minimum && ($3 + 0) < 65534) {
            if (!nonlogin($7)) print $1
        }
    ' "$passwd_file")"
    count="$(printf '%s\n' "$accounts" | awk 'NF {count++} END {print count+0}')"
    account_count="$(awk -F: 'END {print NR+0}' "$passwd_file")"
    scanner_append_evidence evidence "login_capable_accounts=${count}"
    scanner_append_evidence evidence "local_accounts=${account_count}"
    scanner_append_evidence evidence "accounts=$(printf '%s\n' "$accounts" | head -n 20 | paste -sd, -)"
    if [ "$count" -eq 1 ] && [ "$accounts" = "root" ]; then
        scanner_append_evidence evidence "root_only_login_capable=true"
        scanner_account_shadow_completeness_into "$passwd_file" shadow_evidence || shadow_status=$?
        scanner_append_evidence evidence "$shadow_evidence"
        if [ "$shadow_status" -eq 0 ]; then
            set_result GOOD \
                "완전한 로컬 계정 자료에서 로그인 가능한 계정은 필수 관리자 계정 root뿐입니다." \
                "$evidence"
            return
        elif [ "$shadow_status" -eq 2 ]; then
            set_result ERROR \
                "U-07 계정 검토에 필요한 /etc/shadow를 안전하게 읽고 검증하지 못했습니다." \
                "$evidence"
            return
        fi
    else
        scanner_append_evidence evidence "root_only_login_capable=false"
    fi
    if runtime_enabled; then
        last_path="$(trusted_command last 2>/dev/null || true)"
        if [ -n "$last_path" ]; then
            recent_login_records="$("$last_path" -w 2>/dev/null | awk '!/^wtmp begins/ && NF {count++} END {print count+0}')" || last_status=$?
            if [ "$last_status" -eq 0 ]; then
                scanner_append_evidence evidence "recent_login_records=${recent_login_records}"
            else
                scanner_append_evidence evidence "recent_login_records=unresolved"
            fi
        else
            scanner_append_evidence evidence "recent_login_records=unavailable"
        fi
    else
        scanner_append_evidence evidence "recent_login_records=offline"
    fi
    set_result MANUAL "계정의 업무 필요성과 최근 사용 여부는 조직의 계정 대장 및 인증 로그로 확인해야 합니다." "$evidence"
}

check_u_08() {
    local passwd_file=""
    local group_file=""
    local root_gid=""
    local accounts=""
    local count=0
    local evidence=""
    local passwd_status=0
    local group_status=0

    passwd_file="$(optional_rooted_read_path /etc/passwd 2>/dev/null)" || passwd_status=$?
    group_file="$(optional_rooted_read_path /etc/group 2>/dev/null)" || group_status=$?
    if [ "$passwd_status" -ne 0 ] || [ "$group_status" -ne 0 ] || \
       ! scanner_validate_passwd_database "$passwd_file" || ! scanner_validate_group_database "$group_file"; then
        set_result ERROR "관리자 그룹을 확인할 계정·그룹 파일을 안전하게 읽고 검증하지 못했습니다." "paths=/etc/passwd,/etc/group"
        return
    fi
    root_gid="$(awk -F: '$1 == "root" {print $3; exit}' "$group_file")"
    [ -n "$root_gid" ] || {
        set_result ERROR "root 그룹을 찾을 수 없습니다." "path=/etc/group"
        return
    }
    accounts="$(awk -F: -v gid="$root_gid" '
        NR == FNR {if ($4 == gid && $1 != "root") print $1; next}
        $1 == "root" {
            count=split($4, members, ",")
            for (index_value=1; index_value<=count; index_value++) if (members[index_value] != "" && members[index_value] != "root") print members[index_value]
        }
    ' "$passwd_file" "$group_file" | LC_ALL=C sort -u)"
    count="$(printf '%s\n' "$accounts" | awk 'NF {count++} END {print count+0}')"
    if [ "$count" -eq 0 ]; then
        set_result GOOD "root 그룹에 추가 계정이 없습니다." "additional_accounts=0"
    else
        scanner_append_evidence evidence "additional_accounts=${count}"
        scanner_append_evidence evidence "accounts=$(printf '%s\n' "$accounts" | head -n 20 | paste -sd, -)"
        set_result MANUAL "root 그룹의 추가 계정이 업무상 필요한지 확인해야 합니다." "$evidence"
    fi
}

check_u_09() {
    local passwd_file=""
    local group_file=""
    local gshadow_file=""
    local gshadow_input="/dev/null"
    local passwd_status=0
    local group_status=0
    local gshadow_status=0
    local candidates=""
    local count=0
    local evidence=""

    passwd_file="$(optional_rooted_read_path /etc/passwd 2>/dev/null)" || passwd_status=$?
    group_file="$(optional_rooted_read_path /etc/group 2>/dev/null)" || group_status=$?
    if [ "$passwd_status" -ne 0 ] || [ "$group_status" -ne 0 ] || \
       ! scanner_validate_passwd_database "$passwd_file" || ! scanner_validate_group_database "$group_file"; then
        set_result ERROR "계정 및 그룹 파일을 안전하게 읽고 검증하지 못했습니다." "paths=/etc/passwd,/etc/group"
        return
    fi
    gshadow_file="$(optional_rooted_read_path /etc/gshadow 2>/dev/null)" || gshadow_status=$?
    case "$gshadow_status" in
        0)
            scanner_validate_gshadow_database "$gshadow_file" || {
                set_result ERROR "/etc/gshadow의 필드 구조 또는 그룹 이름이 유효하지 않습니다." "path=/etc/gshadow"
                return
            }
            gshadow_input="$gshadow_file"
            ;;
        1) ;;
        *)
            set_result ERROR "/etc/gshadow 경로를 안전한 일반 파일로 읽지 못했습니다." "path=/etc/gshadow"
            return
            ;;
    esac
    candidates="$(awk -F: -v passwd_file="$passwd_file" -v gshadow_file="$gshadow_input" '
        FILENAME == passwd_file {used_gid[$4 + 0]=1; account[$1]=1; next}
        FILENAME == gshadow_file {
            admin_count=split($3, admins, ",")
            member_count=split($4, members, ",")
            for (index_value=1; index_value<=admin_count; index_value++) if (admins[index_value] in account) gshadow_used[$1]=1
            for (index_value=1; index_value<=member_count; index_value++) if (members[index_value] in account) gshadow_used[$1]=1
            next
        }
        {
            used=used_gid[$3 + 0] || gshadow_used[$1]
            count=split($4, members, ",")
            for (index_value=1; index_value<=count; index_value++) {
                if (members[index_value] != "" && account[members[index_value]]) used=1
            }
            if (!used) print $1 ":" $3
        }
    ' "$passwd_file" "$gshadow_input" "$group_file")"
    count="$(printf '%s\n' "$candidates" | awk 'NF {count++} END {print count+0}')"
    scanner_append_evidence evidence "gshadow=$([ "$gshadow_status" -eq 0 ] && printf present || printf absent)"
    scanner_append_evidence evidence "filesystem_group_ownership=manual-review"
    if [ "$count" -eq 0 ]; then
        scanner_append_evidence evidence "unused_group_candidates=0"
        set_result MANUAL "직접 연결되지 않은 그룹은 없지만 전체 그룹의 업무 필요성과 파일 소유 관계를 대조해야 합니다." "$evidence"
    else
        scanner_append_evidence evidence "unused_group_candidates=${count}"
        scanner_append_evidence evidence "groups=$(printf '%s\n' "$candidates" | head -n 20 | paste -sd, -)"
        set_result MANUAL "계정과 직접 연결되지 않은 그룹의 시스템·서비스상 필요성을 확인해야 합니다." "$evidence"
    fi
}

check_u_10() {
    local passwd_file=""
    local duplicates=""
    local count=0
    local evidence=""
    local passwd_status=0

    passwd_file="$(optional_rooted_read_path /etc/passwd 2>/dev/null)" || passwd_status=$?
    if [ "$passwd_status" -ne 0 ] || ! scanner_validate_passwd_database "$passwd_file"; then
        set_result ERROR "/etc/passwd를 안전한 일반 파일로 읽고 검증하지 못했습니다." "path=/etc/passwd"
        return
    fi
    duplicates="$(awk -F: '
        {
            uid=$3 + 0
            accounts[uid]=accounts[uid] (accounts[uid] ? "," : "") $1
            counts[uid]++
        }
        END {for (uid in counts) if (counts[uid] > 1) print uid ":" accounts[uid]}
    ' "$passwd_file" | LC_ALL=C sort -n)"
    count="$(printf '%s\n' "$duplicates" | awk 'NF {count++} END {print count+0}')"
    if [ "$count" -gt 0 ]; then
        scanner_append_evidence evidence "duplicate_uid_sets=${count}"
        scanner_append_evidence evidence "sets=$(printf '%s\n' "$duplicates" | head -n 20 | paste -sd';' -)"
        set_result VULNERABLE "동일한 UID를 공유하는 로컬 계정이 존재합니다." "$evidence"
    else
        set_result GOOD "동일한 UID를 공유하는 로컬 계정이 없습니다." "duplicate_uid_sets=0"
    fi
}

check_u_11() {
    local passwd_file=""
    local accounts=""
    local additional_accounts=""
    local count=0
    local additional_count=0
    local evidence=""
    local uid_minimum_record=""
    local uid_minimum=1000
    local passwd_status=0

    passwd_file="$(optional_rooted_read_path /etc/passwd 2>/dev/null)" || passwd_status=$?
    if [ "$passwd_status" -ne 0 ] || ! scanner_validate_passwd_database "$passwd_file"; then
        set_result ERROR "/etc/passwd를 안전한 일반 파일로 읽고 검증하지 못했습니다." "path=/etc/passwd"
        return
    fi
    accounts="$(awk -F: '
        function nonlogin(shell) {
            return shell == "/bin/false" || shell == "/usr/bin/false" || shell == "/sbin/nologin" ||
                   shell == "/usr/sbin/nologin" || shell == "/bin/nologin"
        }
        BEGIN {
            split("daemon bin sys adm listen nobody nobody4 noaccess diag operator games gopher", names, " ")
            for (index_value in names) checked[names[index_value]]=1
        }
        checked[$1] && !nonlogin($7) {print $1 ":" $7}
    ' "$passwd_file")"
    if ! scanner_capture_optional_value uid_minimum_record login_defs_value UID_MIN; then
        set_result ERROR "UID_MIN 설정 경로를 안전하게 해석하지 못했습니다." "setting=UID_MIN"
        return
    fi
    if [ -n "$uid_minimum_record" ]; then
        scanner_is_unsigned_integer "$(scanner_value_only "$uid_minimum_record")" || {
            set_result ERROR "UID_MIN 값이 유효한 정수가 아닙니다." "setting=UID_MIN"
            return
        }
        uid_minimum="$(scanner_value_only "$uid_minimum_record")"
    fi
    additional_accounts="$(awk -F: -v minimum="$uid_minimum" '
        function nonlogin(shell) {
            return shell == "/bin/false" || shell == "/usr/bin/false" || shell == "/sbin/nologin" ||
                   shell == "/usr/sbin/nologin" || shell == "/bin/nologin"
        }
        ($3 + 0) > 0 && ($3 + 0) < minimum && !nonlogin($7) && $1 !~ /^(sync|shutdown|halt)$/ {print $1 ":" $7}
    ' "$passwd_file")"
    count="$(printf '%s\n' "$accounts" | awk 'NF {count++} END {print count+0}')"
    additional_count="$(printf '%s\n' "$additional_accounts" | awk 'NF {count++} END {print count+0}')"
    if [ "$count" -gt 0 ]; then
        scanner_append_evidence evidence "affected_accounts=${count}"
        scanner_append_evidence evidence "accounts=$(printf '%s\n' "$accounts" | paste -sd, -)"
        set_result VULNERABLE "로그인이 불필요한 표준 시스템 계정에 로그인 셸이 부여되어 있습니다." "$evidence"
    elif [ "$additional_count" -gt 0 ]; then
        scanner_append_evidence evidence "additional_system_accounts=${additional_count}"
        scanner_append_evidence evidence "accounts=$(printf '%s\n' "$additional_accounts" | head -n 20 | paste -sd, -)"
        set_result MANUAL "로그인 셸을 가진 추가 시스템 계정의 업무 필요성을 확인해야 합니다." "$evidence"
    else
        set_result GOOD "점검 대상 시스템 계정에 비로그인 셸이 부여되어 있습니다." "affected_accounts=0"
    fi
}

check_u_12() {
    local files=()
    local file=""
    local profile_files_file=""
    local profile_status=0
    local record=""
    local record_type=""
    local value=""
    local compliant=0
    local noncompliant=0
    local unresolved=0
    local exported=0
    local sh_accounts=0
    local csh_accounts=0
    local unsupported_shell_accounts=0
    local sh_compliant=0
    local sh_noncompliant=0
    local sh_unresolved=0
    local csh_compliant=0
    local csh_noncompliant=0
    local csh_unresolved=0
    local missing_required=0
    local evidence=""
    local passwd_file=""
    local passwd_status=0
    local uid_minimum_record=""
    local uid_minimum=1000

    passwd_file="$(optional_rooted_read_path /etc/passwd 2>/dev/null)" || passwd_status=$?
    if [ "$passwd_status" -ne 0 ] || ! scanner_validate_passwd_database "$passwd_file"; then
        set_result ERROR "/etc/passwd를 안전한 일반 파일로 읽고 검증하지 못했습니다." "path=/etc/passwd"
        return
    fi
    if ! scanner_capture_optional_value uid_minimum_record login_defs_value UID_MIN; then
        set_result ERROR "UID_MIN 설정 경로를 안전하게 해석하지 못했습니다." "setting=UID_MIN"
        return
    fi
    if [ -n "$uid_minimum_record" ]; then
        scanner_is_unsigned_integer "$(scanner_value_only "$uid_minimum_record")" || {
            set_result ERROR "UID_MIN 값이 유효한 정수가 아닙니다." "setting=UID_MIN"
            return
        }
        uid_minimum="$(scanner_value_only "$uid_minimum_record")"
    fi
    read -r sh_accounts csh_accounts unsupported_shell_accounts < <(awk -F: -v minimum="$uid_minimum" '
        function nonlogin(shell) {
            return shell == "/bin/false" || shell == "/usr/bin/false" || shell == "/sbin/nologin" ||
                   shell == "/usr/sbin/nologin" || shell == "/bin/nologin"
        }
        (($3 + 0) == 0 || ($3 + 0) >= minimum) && !nonlogin($7) {
            if ($7 ~ /\/(sh|bash|dash|ksh|mksh)$/) sh_count++
            else if ($7 ~ /\/(csh|tcsh)$/) csh_count++
            else unsupported_count++
        }
        END {print sh_count+0, csh_count+0, unsupported_count+0}
    ' "$passwd_file")

    local logical_files=(/etc/profile)
    if platform_is_debian_family; then
        logical_files+=(/etc/bash.bashrc)
    elif platform_is_rhel_family; then
        logical_files+=(/etc/bashrc)
    fi
    for file in "${logical_files[@]}"; do
        local logical_file="$file"
        file="$(fs_path "$logical_file" 2>/dev/null)" || {
            unresolved=$((unresolved + 1))
            sh_unresolved=$((sh_unresolved + 1))
            continue
        }
        if [ -e "$file" ] || [ -L "$file" ]; then
            if [ -f "$file" ] && [ -r "$file" ]; then
                files+=("$file")
            else
                unresolved=$((unresolved + 1))
                sh_unresolved=$((sh_unresolved + 1))
            fi
        fi
    done
    profile_files_file="$(new_scratch_file u12-profile-files)" || {
        set_result ERROR "profile.d 파일 목록을 저장할 임시 파일을 만들지 못했습니다."
        return
    }
    scanner_collect_profile_directory_files /etc/profile.d "$profile_files_file" || profile_status=$?
    case "$profile_status" in
        0)
            while IFS= read -r -d '' file; do files+=("$file"); done < "$profile_files_file"
            ;;
        1) ;;
        *)
            unresolved=$((unresolved + 1))
            sh_unresolved=$((sh_unresolved + 1))
            ;;
    esac

    for file in "${files[@]}"; do
        while IFS= read -r record; do
            [ -n "$record" ] || continue
            record_type="${record%%:*}"
            record="${record#*:}"
            value="${record%%:*}"
            if [ "$record_type" = "literal" ] && scanner_is_unsigned_integer "$value"; then
                if [ "$value" -gt 0 ] && [ "$value" -le 600 ]; then
                    compliant=$((compliant + 1))
                    sh_compliant=$((sh_compliant + 1))
                else
                    noncompliant=$((noncompliant + 1))
                    sh_noncompliant=$((sh_noncompliant + 1))
                fi
                scanner_append_evidence evidence "TMOUT=${value},source=$(display_path "$file"):${record#*:}"
            elif [ "$record_type" = "export" ]; then
                exported=$((exported + 1))
            else
                unresolved=$((unresolved + 1))
                sh_unresolved=$((sh_unresolved + 1))
            fi
        done < <(awk '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                sub(/[[:space:]]+#.*$/, "", line)
                if (line ~ /^(export[[:space:]]+|readonly[[:space:]]+)?TMOUT[[:space:]]*=/) {
                    value=line
                    sub(/^(export[[:space:]]+|readonly[[:space:]]+)?TMOUT[[:space:]]*=[[:space:]]*/, "", value)
                    sub(/[[:space:]]*;.*$/, "", value)
                    sub(/[[:space:]]+$/, "", value)
                    if (value ~ /^[0-9]+$/) print "literal:" value ":" FNR
                    else print "dynamic:dynamic:" FNR
                } else if (line ~ /^export[[:space:]]+TMOUT([[:space:];]|$)/) {
                    print "export:present:" FNR
                } else if (line ~ /(^|[;[:space:]])(unset[[:space:]]+TMOUT|TMOUT[[:space:]]*=)/) {
                    print "dynamic:dynamic:" FNR
                }
            }
        ' "$file")
    done

    if [ "$csh_accounts" -gt 0 ]; then
        for file in /etc/csh.cshrc /etc/csh.login; do
            local logical_csh_file="$file"
            file="$(fs_path "$logical_csh_file" 2>/dev/null)" || {
                unresolved=$((unresolved + 1))
                csh_unresolved=$((csh_unresolved + 1))
                continue
            }
            [ -e "$file" ] || continue
            [ -f "$file" ] && [ -r "$file" ] || {
                unresolved=$((unresolved + 1))
                csh_unresolved=$((csh_unresolved + 1))
                continue
            }
            while IFS=: read -r record_type value; do
                [ -n "$record_type" ] || continue
                if [ "$record_type" = "literal" ] && scanner_is_unsigned_integer "$value"; then
                    if [ "$value" -gt 0 ] && [ "$value" -le 10 ]; then
                        compliant=$((compliant + 1))
                        csh_compliant=$((csh_compliant + 1))
                    else
                        noncompliant=$((noncompliant + 1))
                        csh_noncompliant=$((csh_noncompliant + 1))
                    fi
                    scanner_append_evidence evidence "csh_autologout=${value},source=$(display_path "$file")"
                else
                    unresolved=$((unresolved + 1))
                    csh_unresolved=$((csh_unresolved + 1))
                fi
            done < <(awk '
                /^[[:space:]]*set[[:space:]]+autologout[[:space:]]*=/ {
                    line=$0
                    sub(/^.*=[[:space:]]*/, "", line)
                    sub(/[[:space:]]+$/, "", line)
                    if (line ~ /^[0-9]+$/) print "literal:" line
                    else print "dynamic:dynamic"
                }
            ' "$file")
        done
    fi

    [ "$sh_accounts" -eq 0 ] || [ $((sh_compliant + sh_noncompliant + sh_unresolved)) -gt 0 ] || missing_required=1
    [ "$csh_accounts" -eq 0 ] || [ $((csh_compliant + csh_noncompliant + csh_unresolved)) -gt 0 ] || missing_required=1
    scanner_append_evidence evidence "sh_accounts=${sh_accounts}"
    scanner_append_evidence evidence "csh_accounts=${csh_accounts}"
    scanner_append_evidence evidence "unsupported_shell_accounts=${unsupported_shell_accounts}"
    scanner_append_evidence evidence "sh_compliant=${sh_compliant}"
    scanner_append_evidence evidence "sh_noncompliant=${sh_noncompliant}"
    scanner_append_evidence evidence "sh_unresolved=${sh_unresolved}"
    scanner_append_evidence evidence "csh_compliant=${csh_compliant}"
    scanner_append_evidence evidence "csh_noncompliant=${csh_noncompliant}"
    scanner_append_evidence evidence "csh_unresolved=${csh_unresolved}"
    scanner_append_evidence evidence "literal_compliant=${compliant}"
    scanner_append_evidence evidence "literal_noncompliant=${noncompliant}"
    scanner_append_evidence evidence "export_statements=${exported}"
    scanner_append_evidence evidence "unresolved_assignments=${unresolved}"
    if [ "$missing_required" -gt 0 ]; then
        set_result VULNERABLE "사용 중인 셸에 대한 전역 세션 시간 제한 설정을 확인하지 못했습니다." "$evidence"
    elif [ "$unsupported_shell_accounts" -gt 0 ] || [ "$unresolved" -gt 0 ] || [ "$noncompliant" -gt 0 ]; then
        set_result MANUAL "셸별 설정 순서와 동적 재정의를 반영한 최종 세션 시간 제한을 확인해야 합니다." "$evidence"
    elif [ "$compliant" -gt 0 ]; then
        set_result MANUAL "600초 이하의 설정은 확인했지만 사용자 시작 파일의 재정의 가능성을 확인해야 합니다." "$evidence"
    else
        set_result MANUAL "적용 가능한 대화형 셸과 세션 시간 제한 정책을 확인해야 합니다." "$evidence"
    fi
}

check_u_13() {
    local passwd_file=""
    local shadow_file=""
    local shadow_input="/dev/null"
    local credential_file=""
    local credential_logical_path="per-account"
    local record_format="normalized"
    local pam_lines_file=""
    local pam_service=""
    local pam_expansion_status=0
    local pam_stacks=""
    local pam_option_counts=""
    local pam_unix_modules=0
    local pam_secure_options=0
    local pam_weak_options=0
    local pam_unsupported_options=0
    local method_record=""
    local method=""
    local counts=""
    local secure_count=0
    local weak_count=0
    local unknown_count=0
    local empty_count=0
    local unsupported_hash_count=0
    local invalid_hash_count=0
    local malformed_record_count=0
    local shadow_source_count=0
    local passwd_source_count=0
    local missing_source_count=0
    local method_secure=0
    local method_unsupported=0
    local evidence=""
    local passwd_status=0
    local shadow_status=0
    local shadow_present=0
    local debian_hashes=0

    passwd_file="$(optional_rooted_read_path /etc/passwd 2>/dev/null)" || passwd_status=$?
    if [ "$passwd_status" -ne 0 ] || ! scanner_validate_passwd_database "$passwd_file"; then
        set_result ERROR "/etc/passwd를 안전한 일반 파일로 읽고 검증하지 못했습니다." "path=/etc/passwd"
        return
    fi
    shadow_file="$(optional_rooted_read_path /etc/shadow 2>/dev/null)" || shadow_status=$?
    case "$shadow_status" in
        0)
            scanner_validate_shadow_database "$shadow_file" || {
                set_result ERROR "/etc/shadow의 필드 구조 또는 계정 이름이 유효하지 않습니다." "path=/etc/shadow"
                return
            }
            shadow_input="$shadow_file"
            shadow_present=1
            ;;
        1)
            ;;
        *)
            set_result ERROR "/etc/shadow 경로가 안전하지 않거나 파일을 읽을 수 없습니다." "path=/etc/shadow"
            return
            ;;
    esac
    credential_file="$(new_scratch_file u13-credentials)" || {
        set_result ERROR "계정별 비밀번호 저장 위치를 분석할 임시 파일을 만들지 못했습니다."
        return
    }
    if ! awk -F: -v shadow_file="$shadow_input" -v shadow_present="$shadow_present" '
        FILENAME == shadow_file {
            shadow_password[$1]=$2
            next
        }
        {
            if ($2 == "x") {
                if (shadow_present && ($1 in shadow_password)) print $1 ":" shadow_password[$1] ":shadow"
                else print $1 ":@missing-shadow@:missing"
            } else {
                print $1 ":" $2 ":passwd"
            }
        }
    ' "$shadow_input" "$passwd_file" > "$credential_file"; then
        set_result ERROR "계정별 비밀번호 저장 위치를 분석하지 못했습니다." "paths=/etc/passwd,/etc/shadow"
        return
    fi
    pam_lines_file="$(new_scratch_file u13-pam)" || {
        set_result ERROR "PAM 비밀번호 스택을 분석할 임시 파일을 만들지 못했습니다."
        return
    }
    if ! scanner_authselect_configuration_valid; then
        set_result ERROR "RHEL authselect 구성이 없거나 무결성 검증에 실패했습니다." "authselect_check=failed"
        return
    fi
    if platform_is_rhel_family; then
        : > "$pam_lines_file"
        for pam_service in system-auth password-auth; do
            pam_expand_service "$pam_service" password >> "$pam_lines_file" 2>/dev/null || pam_expansion_status=1
        done
        pam_stacks="system-auth,password-auth"
    else
        scanner_password_pam_lines > "$pam_lines_file" || pam_expansion_status=1
        pam_stacks="common-password"
    fi
    if [ "$pam_expansion_status" -ne 0 ]; then
        set_result ERROR "유효 PAM 비밀번호 스택의 include 그래프를 완전히 해석하지 못했습니다." "pam_graph=incomplete"
        return
    fi
    pam_option_counts="$(scanner_pam_unix_hash_option_counts "$pam_lines_file")"
    read -r pam_unix_modules pam_secure_options pam_weak_options pam_unsupported_options <<< "$pam_option_counts"
    if ! scanner_capture_optional_value method_record pam_login_defs_value ENCRYPT_METHOD; then
        set_result ERROR "ENCRYPT_METHOD 설정 경로를 안전하게 해석하지 못했습니다." "setting=ENCRYPT_METHOD"
        return
    fi
    method="$(scanner_value_only "$method_record" | tr '[:lower:]' '[:upper:]')"
    case "$method" in
        SHA256|SHA512) method_secure=1 ;;
        YESCRYPT)
            if platform_is_debian_family; then
                method_secure=1
            else
                method_unsupported=1
            fi
            ;;
        GOST_YESCRYPT|BCRYPT|BLOWFISH) method_unsupported=1 ;;
    esac

    platform_is_debian_family && debian_hashes=1
    counts="$(awk -F: -v debian_hashes="$debian_hashes" -v record_format="$record_format" '
        function crypt_characters(value) {
            return value != "" && value !~ /[^.\/0-9A-Za-z]/
        }
        function valid_sha_crypt(value, identifier, parts, count, salt, digest, expected_length) {
            count=split(value, parts, "\\$")
            if (count == 4) {
                salt=parts[3]
                digest=parts[4]
            } else if (count == 5 && parts[3] ~ /^rounds=[1-9][0-9]*$/) {
                salt=parts[4]
                digest=parts[5]
            } else {
                return 0
            }
            expected_length=(identifier == "5" ? 43 : 86)
            return length(salt) >= 1 && length(salt) <= 16 && crypt_characters(salt) &&
                   length(digest) == expected_length && crypt_characters(digest)
        }
        function valid_yescrypt(value, parts, count) {
            count=split(value, parts, "\\$")
            return count == 5 && length(parts[3]) >= 3 && length(parts[3]) <= 11 &&
                   crypt_characters(parts[3]) && length(parts[4]) >= 1 && length(parts[4]) <= 86 &&
                   crypt_characters(parts[4]) && length(parts[5]) == 43 && crypt_characters(parts[5])
        }
        function valid_bcrypt(value, parts, count, cost) {
            count=split(value, parts, "\\$")
            if (count != 4 || parts[2] !~ /^2[abxy]$/ || parts[3] !~ /^[0-9][0-9]$/) return 0
            cost=parts[3] + 0
            return cost >= 4 && cost <= 31 && length(parts[4]) == 53 && crypt_characters(parts[4])
        }
        {
            if (record_format != "normalized" || NF != 3 || $1 == "" || $3 !~ /^(shadow|passwd|missing)$/) {
                malformed++
                next
            }
            if ($3 == "shadow") shadow_sources++
            else if ($3 == "passwd") passwd_sources++
            else {
                missing_sources++
                unknown++
                next
            }
            password=$2
            while (substr(password,1,1) == "!") password=substr(password,2)
            if (password == "" && $2 == "") empty++
            else if (password == "" || password == "*" || password == "!!") locked++
            else if (password ~ /^\$[56]\$/) {
                identifier=substr(password, 2, 1)
                if (valid_sha_crypt(password, identifier)) secure++
                else invalid++
            }
            else if (password ~ /^\$y\$/) {
                if (!valid_yescrypt(password)) invalid++
                else if (debian_hashes) secure++
                else unsupported++
            }
            else if (password ~ /^\$gy\$/) {
                if (!valid_yescrypt(password)) invalid++
                else unsupported++
            }
            else if (password ~ /^\$2/) {
                if (valid_bcrypt(password)) unsupported++
                else invalid++
            }
            else if (password == "x") unknown++
            else if (password ~ /^\$(1|3|4)\$/ || password !~ /^\$/) weak++
            else unknown++
        }
        END {
            print secure+0, weak+0, unsupported+0, unknown+0, empty+0, locked+0, invalid+0, malformed+0,
                  shadow_sources+0, passwd_sources+0, missing_sources+0
        }
    ' "$credential_file")"
    read -r secure_count weak_count unsupported_hash_count unknown_count empty_count _ invalid_hash_count malformed_record_count \
        shadow_source_count passwd_source_count missing_source_count <<< "$counts"
    scanner_append_evidence evidence "configured_method=${method:-unresolved}"
    scanner_append_evidence evidence "credential_file=${credential_logical_path}"
    scanner_append_evidence evidence "credential_source_counts=shadow=${shadow_source_count},direct=${passwd_source_count},missing=${missing_source_count}"
    scanner_append_evidence evidence "pam_stacks=${pam_stacks}"
    scanner_append_evidence evidence "configured_method_unsupported=${method_unsupported}"
    scanner_append_evidence evidence "pam_unix_password_modules=${pam_unix_modules}"
    scanner_append_evidence evidence "pam_secure_hash_options=${pam_secure_options}"
    scanner_append_evidence evidence "pam_weak_hash_options=${pam_weak_options}"
    scanner_append_evidence evidence "pam_unsupported_hash_options=${pam_unsupported_options}"
    scanner_append_evidence evidence "secure_hashes=${secure_count}"
    scanner_append_evidence evidence "weak_hashes=${weak_count}"
    scanner_append_evidence evidence "unsupported_hashes=${unsupported_hash_count}"
    scanner_append_evidence evidence "unknown_hashes=${unknown_count}"
    scanner_append_evidence evidence "invalid_hashes=${invalid_hash_count}"
    scanner_append_evidence evidence "malformed_shadow_records=${malformed_record_count}"
    scanner_append_evidence evidence "empty_password_fields=${empty_count}"

    if [ "$malformed_record_count" -gt 0 ]; then
        set_result ERROR "비밀번호 저장 파일의 필드 구조가 해당 파일 형식을 충족하지 않습니다." "$evidence"
    elif [ "$weak_count" -gt 0 ] || [ "$empty_count" -gt 0 ] || [ "$pam_weak_options" -gt 0 ] || { [ -n "$method" ] && [ "$method_secure" -eq 0 ] && [ "$method_unsupported" -eq 0 ]; }; then
        set_result VULNERABLE "취약한 비밀번호 해시 또는 향후 생성 비밀번호의 취약한 알고리즘 설정을 확인했습니다." "$evidence"
    elif [ "$invalid_hash_count" -gt 0 ] || [ "$unknown_count" -gt 0 ]; then
        set_result MANUAL "형식이 불완전하거나 알 수 없는 비밀번호 해시의 안전성을 확인해야 합니다." "$evidence"
    elif [ "$unsupported_hash_count" -gt 0 ] || [ "$pam_unsupported_options" -gt 0 ] || [ "$method_unsupported" -gt 0 ]; then
        set_result MANUAL "이 플랫폼에서 지원하지 않는 PAM 해시 옵션의 실제 적용 결과를 확인해야 합니다." "$evidence"
    elif [ "$pam_unix_modules" -gt $((pam_secure_options + pam_weak_options)) ] && [ -z "$method" ]; then
        set_result MANUAL "명시적 해시 방식이 없는 PAM 경로의 향후 비밀번호 알고리즘을 확인해야 합니다." "$evidence"
    elif [ "$secure_count" -gt 0 ] || [ "$method_secure" -eq 1 ] || [ "$pam_secure_options" -gt 0 ]; then
        set_result GOOD "SHA-2 이상 또는 yescrypt 계열의 비밀번호 알고리즘을 사용합니다." "$evidence"
    else
        set_result MANUAL "활성 비밀번호 해시와 명시적 생성 알고리즘이 없어 정책을 확정할 수 없습니다." "$evidence"
    fi
}

scanner_path_assignments_have_current_directory() {
    awk '
        function trim(value) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            return value
        }
        function unquote(value, first, last) {
            value=trim(value)
            first=substr(value, 1, 1)
            last=substr(value, length(value), 1)
            if (length(value) >= 2 && ((first == "\"" && last == "\"") ||
                (first == "\047" && last == "\047"))) {
                value=substr(value, 2, length(value) - 2)
            }
            return trim(value)
        }
        {
            line=$0
            sub(/^[0-9]+:/, "", line)
            if (line ~ /^(export[[:space:]]+)?PATH[[:space:]]*=/) {
                sub(/^(export[[:space:]]+)?PATH[[:space:]]*=[[:space:]]*/, "", line)
                sub(/[[:space:]]*;.*$/, "", line)
                line=unquote(line)
                entry_count=split(line, entries, ":")
                for (entry_index=1; entry_index<=entry_count; entry_index++) {
                    entry=unquote(entries[entry_index])
                    if (entry == "." || entry == "") found=1
                }
            } else if (line ~ /^set[[:space:]]+path[[:space:]]*=/) {
                sub(/^set[[:space:]]+path[[:space:]]*=[[:space:]]*/, "", line)
                line=trim(line)
                sub(/^\(/, "", line)
                sub(/\)$/, "", line)
                entry_count=split(line, entries, /[[:space:]]+/)
                for (entry_index=1; entry_index<=entry_count; entry_index++) {
                    if (unquote(entries[entry_index]) == ".") found=1
                }
            }
        }
        END {exit(found ? 0 : 1)}
    '
}

check_u_14() {
    local passwd_file=""
    local passwd_status=0
    local root_home=""
    local unsafe_count=0
    local unresolved=0
    local evidence=""
    local file=""
    local physical_file=""
    local assignments=""
    local profile_files_file=""
    local profile_status=0
    local logical_files=()

    passwd_file="$(optional_rooted_read_path /etc/passwd 2>/dev/null)" || passwd_status=$?
    if [ "$passwd_status" -ne 0 ] || ! scanner_validate_passwd_database "$passwd_file"; then
        set_result ERROR "/etc/passwd를 안전한 일반 파일로 읽고 검증하지 못했습니다." "path=/etc/passwd"
        return
    fi
    root_home="$(awk -F: '$1 == "root" {print $6; exit}' "$passwd_file")"
    case "$root_home" in
        /*) ;;
        *)
            set_result ERROR "root 홈 디렉터리가 절대 경로가 아닙니다." "root_home=${root_home:-empty}"
            return
            ;;
    esac
    case "$root_home" in *'/../'*|*/..|*/./*|*/.) set_result ERROR "root 홈 디렉터리 경로가 안전하지 않습니다." "root_home=$root_home"; return ;; esac

    logical_files=(
        "$root_home/.profile" "$root_home/.bash_profile" "$root_home/.bash_login" "$root_home/.bashrc"
        "$root_home/.kshrc" "$root_home/.cshrc" "$root_home/.tcshrc" "$root_home/.login"
        /etc/profile /etc/csh.cshrc /etc/csh.login
    )
    if platform_is_debian_family; then
        logical_files+=(/etc/bash.bashrc)
    elif platform_is_rhel_family; then
        logical_files+=(/etc/bashrc)
    fi
    for file in "${logical_files[@]}"; do
        physical_file="$(fs_path "$file" 2>/dev/null)" || {
            unresolved=$((unresolved + 1))
            continue
        }
        [ -e "$physical_file" ] || continue
        if [ ! -f "$physical_file" ] || [ ! -r "$physical_file" ]; then
            unresolved=$((unresolved + 1))
            continue
        fi
        assignments="$(awk '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                if (line ~ /^(export[[:space:]]+)?PATH[[:space:]]*=/ || line ~ /^set[[:space:]]+path[[:space:]]*=/) print FNR ":" line
            }
        ' "$physical_file")"
        if printf '%s\n' "$assignments" | scanner_path_assignments_have_current_directory; then
            unsafe_count=$((unsafe_count + 1))
            scanner_append_evidence evidence "unsafe_path_assignment=${file}"
        fi
    done
    profile_files_file="$(new_scratch_file u14-profile-files)" || {
        set_result ERROR "profile.d 파일 목록을 저장할 임시 파일을 만들지 못했습니다."
        return
    }
    scanner_collect_profile_directory_files /etc/profile.d "$profile_files_file" || profile_status=$?
    case "$profile_status" in
        0)
            while IFS= read -r -d '' physical_file; do
            assignments="$(awk '
                {
                    line=$0
                    sub(/^[[:space:]]+/, "", line)
                    if (line == "" || line ~ /^#/) next
                    if (line ~ /^(export[[:space:]]+)?PATH[[:space:]]*=/) print FNR ":" line
                }
            ' "$physical_file")"
            if printf '%s\n' "$assignments" | scanner_path_assignments_have_current_directory; then
                unsafe_count=$((unsafe_count + 1))
                scanner_append_evidence evidence "unsafe_path_assignment=$(display_path "$physical_file")"
            fi
            done < "$profile_files_file"
            ;;
        1) ;;
        *) unresolved=$((unresolved + 1)) ;;
    esac

    scanner_append_evidence evidence "candidate_unsafe_assignments=${unsafe_count}"
    scanner_append_evidence evidence "unresolved_profile_paths=${unresolved}"
    scanner_append_evidence evidence "root_home=${root_home}"
    if [ "$unsafe_count" -gt 0 ]; then
        set_result MANUAL "취약할 수 있는 PATH 할당은 발견했지만 셸 시작 순서상의 최종 유효값을 확인해야 합니다." "$evidence"
    elif [ "$unresolved" -gt 0 ]; then
        set_result MANUAL "일부 root 셸 시작 파일을 안전하게 해석하지 못해 최종 PATH 확인이 필요합니다." "$evidence"
    else
        set_result MANUAL "정적 환경 파일에는 명백한 취약 PATH가 없지만 root 로그인 시 유효값 확인이 필요합니다." "$evidence"
    fi
}

check_u_15() {
    local evidence=""

    scanner_collect_full_filesystem_facts
    if [ "$SCANNER_FULL_FILESYSTEM_SCRATCH_ERROR" -gt 0 ]; then
        set_result ERROR "전체 파일 목록을 저장할 임시 파일을 만들지 못했습니다."
        return
    fi
    case "$SCANNER_FULL_FILESYSTEM_U15_SETUP_ERROR" in
        nsswitch)
            set_result ERROR "/etc/nsswitch.conf 경로를 안전한 일반 파일로 읽지 못했습니다." "path=/etc/nsswitch.conf"
            return
            ;;
        database)
            set_result ERROR "오프라인 루트의 계정 및 그룹 파일을 안전하게 읽고 검증하지 못했습니다." "paths=/etc/passwd,/etc/group"
            return
            ;;
    esac
    if [ "$SCAN_ROOT" = "/" ] &&
        { [ "$SCANNER_FULL_FILESYSTEM_ROOT_STATUS" -ne 0 ] ||
          [ "$SCANNER_FULL_FILESYSTEM_ROOT_COUNT" -eq 0 ]; }; then
        set_result ERROR "로컬 파일시스템 마운트 목록을 완전하게 수집하지 못했습니다." "scope=/"
        return
    fi
    if [ "$SCANNER_FULL_FILESYSTEM_SCAN_ERRORS" -gt 0 ]; then
        scanner_full_filesystem_error_evidence_into evidence
        scanner_note_offline_access_context
        if [ "$SCAN_ROOT" = "/" ]; then
            set_result ERROR "루트 파일시스템의 소유자 없는 파일 검색을 완료하지 못했습니다." "$evidence"
        else
            set_result ERROR "오프라인 루트의 전체 파일 목록을 수집하지 못했습니다." "$evidence"
        fi
        return
    fi
    if [ "$SCANNER_FULL_FILESYSTEM_U15_METADATA_ERRORS" -gt 0 ]; then
        set_result ERROR "일부 파일의 소유자 메타데이터를 확인하지 못했습니다." "metadata_errors=${SCANNER_FULL_FILESYSTEM_U15_METADATA_ERRORS}"
        return
    fi

    evidence="orphaned_paths=${SCANNER_FULL_FILESYSTEM_U15_COUNT}
external_nss_sources=${SCANNER_FULL_FILESYSTEM_U15_EXTERNAL_NSS}
${SCANNER_FULL_FILESYSTEM_U15_EVIDENCE}"
    if [ "$SCANNER_FULL_FILESYSTEM_U15_COUNT" -gt 0 ]; then
        if [ "$SCANNER_FULL_FILESYSTEM_U15_EXTERNAL_NSS" -eq 1 ]; then
            set_result MANUAL "외부 NSS 조회 실패와 실제 소유자 부재를 구분할 수 없어 확인이 필요합니다." "$evidence"
        else
            set_result VULNERABLE "소유자 또는 그룹이 존재하지 않는 파일·디렉터리가 있습니다." "$evidence"
        fi
    elif [ "$SCAN_ROOT" != "/" ]; then
        set_result MANUAL "오프라인 루트의 하위 마운트 경계를 확인할 수 없어 소유자 검색 완료를 확정할 수 없습니다." "$evidence"
    else
        set_result GOOD "검사한 파일시스템에서 소유자 없는 파일·디렉터리가 없습니다." "$evidence"
    fi
}

check_u_16() {
    local path=""
    local uid=""
    local mode=""
    local result=2
    local path_status=0

    path="$(optional_rooted_read_path /etc/passwd 2>/dev/null)" || path_status=$?
    if [ "$path_status" -eq 1 ]; then
        set_result ERROR "/etc/passwd가 존재하지 않습니다." "path=/etc/passwd"
        return
    elif [ "$path_status" -ne 0 ]; then
        set_result ERROR "/etc/passwd 경로를 안전한 일반 파일로 읽지 못했습니다." "path=/etc/passwd"
        return
    fi
    uid="$(stat_uid "$path" 2>/dev/null || true)"
    mode="$(stat_mode "$path" 2>/dev/null || true)"
    scanner_file_metadata_status "$path" 644 root
    result=$?
    case "$result" in
        0) set_result GOOD "/etc/passwd가 root 소유이며 권한이 0644 이하입니다." "owner_uid=${uid},mode=${mode}" ;;
        1) set_result VULNERABLE "/etc/passwd의 소유자 또는 권한이 기준을 벗어납니다." "owner_uid=${uid},mode=${mode}" ;;
        *) set_result ERROR "/etc/passwd의 메타데이터를 확인하지 못했습니다." "path=/etc/passwd" ;;
    esac
}

check_u_17() {
    local list_file=""
    local logical_path=""
    local directory=""
    local resolved_directory=""
    local path_status=0
    local path=""
    local resolved_path=""
    local uid=""
    local mode=""
    local decimal_mode=""
    local scanned=0
    local violations=0
    local errors=0
    local dangling_links=0
    local evidence=""
    local masks=0
    local paths=(
        /etc/systemd/system /run/systemd/system /run/systemd/generator.early /run/systemd/generator
        /run/systemd/generator.late /usr/local/lib/systemd/system /usr/lib/systemd/system
        /etc/init.d /etc/rc.local
    )
    local -A scanned_directory_paths=()

    list_file="$(new_scratch_file u17-files)" || {
        set_result ERROR "시작 스크립트 목록을 저장할 임시 파일을 만들지 못했습니다."
        return
    }
    if platform_is_debian_family; then
        paths+=(/lib/systemd/system /etc/rc0.d /etc/rc1.d /etc/rc2.d /etc/rc3.d /etc/rc4.d /etc/rc5.d /etc/rc6.d /etc/rcS.d)
    elif platform_is_rhel_family; then
        paths+=(/etc/rc.d/init.d /etc/rc.d/rc0.d /etc/rc.d/rc1.d /etc/rc.d/rc2.d /etc/rc.d/rc3.d /etc/rc.d/rc4.d /etc/rc.d/rc5.d /etc/rc.d/rc6.d)
    fi
    for logical_path in "${paths[@]}"; do
        path_status=0
        directory="$(fs_path "$logical_path" 2>/dev/null)" || path_status=$?
        if [ "$path_status" -ne 0 ]; then
            errors=$((errors + 1))
            continue
        fi
        if [ -d "$directory" ]; then
            resolved_directory=""
            if ! resolve_rooted_directory_into "$directory" resolved_directory 2>/dev/null; then
                errors=$((errors + 1))
                continue
            fi
            if [ -n "${scanned_directory_paths[$resolved_directory]+present}" ]; then
                continue
            fi
            scanned_directory_paths["$resolved_directory"]=1
            if ! find -P "$resolved_directory" -xdev \( -type f -o -type l \) -print0 >> "$list_file" 2>/dev/null; then
                errors=$((errors + 1))
            fi
        elif [ -e "$directory" ] || [ -L "$directory" ]; then
            printf '%s\0' "$directory" >> "$list_file"
        fi
    done
    while IFS= read -r -d '' path; do
        scanned=$((scanned + 1))
        if scanner_is_dev_null_mask "$path"; then
            masks=$((masks + 1))
            continue
        fi
        resolved_path="$path"
        if [ -L "$path" ]; then
            resolved_path="$(resolve_rooted_read_path "$path" 2>/dev/null || true)"
            if [ -z "$resolved_path" ]; then
                if [ "$SCAN_ROOT" = "/" ] && [ ! -e "$path" ]; then
                    dangling_links=$((dangling_links + 1))
                    [ "$dangling_links" -le 20 ] &&
                        scanner_append_evidence evidence "dangling_startup_alias=$(scanner_evidence_path "$path")"
                else
                    errors=$((errors + 1))
                fi
                continue
            fi
        elif [ ! -f "$path" ]; then
            errors=$((errors + 1))
            continue
        fi
        uid="$(stat_uid "$resolved_path" 2>/dev/null || true)"
        mode="$(stat_mode "$resolved_path" 2>/dev/null || true)"
        decimal_mode="$(mode_to_decimal "$mode" 2>/dev/null || true)"
        if [ -z "$uid" ] || [ -z "$decimal_mode" ]; then
            errors=$((errors + 1))
        elif [ "$uid" != "0" ] || [ $((decimal_mode & 0022)) -ne 0 ]; then
            violations=$((violations + 1))
            [ "$violations" -le 20 ] && scanner_append_evidence evidence "$(scanner_evidence_path "$resolved_path"):owner_uid=${uid},mode=${mode}"
        fi
    done < "$list_file"
    evidence="scanned_paths=${scanned}
violations=${violations}
metadata_errors=${errors}
dangling_aliases=${dangling_links}
masks=${masks}
${evidence}"
    if [ "$errors" -gt 0 ]; then
        debug_emit filesystem_snapshot phase result name startup status error \
            paths "$scanned" errors "$errors" masks "$masks"
        set_result ERROR "일부 시스템 시작 스크립트의 메타데이터를 확인하지 못했습니다." "$evidence"
    elif [ "$violations" -gt 0 ]; then
        debug_emit filesystem_snapshot phase result name startup status vulnerable \
            paths "$scanned" violations "$violations" masks "$masks"
        set_result VULNERABLE "root 소유가 아니거나 일반 사용자 쓰기가 허용된 시작 스크립트가 있습니다." "$evidence"
    elif [ "$dangling_links" -gt 0 ]; then
        debug_emit filesystem_snapshot phase result name startup status ambiguous \
            paths "$scanned" dangling "$dangling_links" masks "$masks"
        set_result MANUAL "대상이 없는 시스템 시작 별칭의 필요성과 잔여 구성을 확인해야 합니다." "$evidence"
    elif [ "$scanned" -eq 0 ]; then
        debug_emit filesystem_snapshot phase result name startup status absent paths 0 masks "$masks"
        set_result NOT_APPLICABLE "로컬 시스템 시작 스크립트를 찾지 못했습니다." "$evidence" false
    else
        debug_emit filesystem_snapshot phase result name startup status ready paths "$scanned" masks "$masks"
        set_result GOOD "시스템 시작 스크립트가 root 소유이며 일반 사용자 쓰기가 차단되어 있습니다." "$evidence"
    fi
}

check_u_18() {
    local path=""
    local uid=""
    local mode=""
    local result=2
    local path_status=0

    path="$(optional_rooted_read_path /etc/shadow 2>/dev/null)" || path_status=$?
    if [ "$path_status" -ne 0 ]; then
        if [ "$path_status" -eq 1 ]; then
            set_result VULNERABLE "/etc/shadow가 존재하지 않습니다." "path=/etc/shadow"
            return
        fi
        set_result ERROR "/etc/shadow 경로가 검사 루트 밖을 가리키거나 안전하게 해석되지 않았습니다." "path=/etc/shadow"
        return
    fi
    uid="$(stat_uid "$path" 2>/dev/null || true)"
    mode="$(stat_mode "$path" 2>/dev/null || true)"
    scanner_file_metadata_status "$path" 400 root
    result=$?
    case "$result" in
        0) set_result GOOD "/etc/shadow가 root 소유이며 권한이 0400 이하입니다." "owner_uid=${uid},mode=${mode}" ;;
        1) set_result VULNERABLE "/etc/shadow의 소유자 또는 권한이 KISA 기준을 벗어납니다." "owner_uid=${uid},mode=${mode}" ;;
        *) set_result ERROR "/etc/shadow의 메타데이터를 확인하지 못했습니다." "path=/etc/shadow" ;;
    esac
}

check_u_19() {
    local path=""
    local uid=""
    local mode=""
    local result=2
    local path_status=0

    path="$(optional_rooted_read_path /etc/hosts 2>/dev/null)" || path_status=$?
    if [ "$path_status" -eq 1 ]; then
        set_result ERROR "/etc/hosts가 존재하지 않습니다." "path=/etc/hosts"
        return
    elif [ "$path_status" -ne 0 ]; then
        set_result ERROR "/etc/hosts 경로를 안전한 일반 파일로 읽지 못했습니다." "path=/etc/hosts"
        return
    fi
    uid="$(stat_uid "$path" 2>/dev/null || true)"
    mode="$(stat_mode "$path" 2>/dev/null || true)"
    scanner_file_metadata_status "$path" 644 root
    result=$?
    case "$result" in
        0) set_result GOOD "/etc/hosts가 root 소유이며 권한이 0644 이하입니다." "owner_uid=${uid},mode=${mode}" ;;
        1) set_result VULNERABLE "/etc/hosts의 소유자 또는 권한이 기준을 벗어납니다." "owner_uid=${uid},mode=${mode}" ;;
        *) set_result ERROR "/etc/hosts의 메타데이터를 확인하지 못했습니다." "path=/etc/hosts" ;;
    esac
}

scanner_check_configuration_metadata_set() {
    local allowed_mode="$1"
    local allowed_owners="$2"
    shift 2
    local list_file="$1"
    local allowed_owner_names=()
    local path=""
    local uid=""
    local mode=""
    local result=0

    SCANNER_METADATA_SCANNED=0
    SCANNER_METADATA_VIOLATIONS=0
    SCANNER_METADATA_ERRORS=0
    SCANNER_METADATA_MASKS=0
    SCANNER_METADATA_EVIDENCE=""
    read -r -a allowed_owner_names <<< "$allowed_owners"
    while IFS= read -r -d '' path; do
        if scanner_is_dev_null_mask "$path"; then
            SCANNER_METADATA_MASKS=$((SCANNER_METADATA_MASKS + 1))
            continue
        fi
        SCANNER_METADATA_SCANNED=$((SCANNER_METADATA_SCANNED + 1))
        uid="$(stat_uid "$path" 2>/dev/null || true)"
        mode="$(stat_mode "$path" 2>/dev/null || true)"
        scanner_file_metadata_status "$path" "$allowed_mode" "${allowed_owner_names[@]}"
        result=$?
        if [ "$result" -eq 1 ]; then
            SCANNER_METADATA_VIOLATIONS=$((SCANNER_METADATA_VIOLATIONS + 1))
            [ "$SCANNER_METADATA_VIOLATIONS" -le 20 ] && scanner_append_evidence SCANNER_METADATA_EVIDENCE "$(scanner_evidence_path "$path"):owner_uid=${uid},mode=${mode}"
        elif [ "$result" -eq 2 ]; then
            SCANNER_METADATA_ERRORS=$((SCANNER_METADATA_ERRORS + 1))
        fi
    done < "$list_file"
}

check_u_20() {
    local list_file=""
    local path=""
    local directory=""
    local path_status=0
    local evidence=""
    local scan_errors=0

    list_file="$(new_scratch_file u20-files)" || {
        set_result ERROR "구성 파일 목록을 저장할 임시 파일을 만들지 못했습니다."
        return
    }
    for path in /etc/inetd.conf /etc/xinetd.conf /etc/systemd/system.conf; do
        path_status=0
        path="$(scanner_optional_metadata_path "$path" 2>/dev/null)" || path_status=$?
        case "$path_status" in
            0) printf '%s\0' "$path" >> "$list_file" ;;
            1) ;;
            *) scan_errors=$((scan_errors + 1)) ;;
        esac
    done
    for directory in /etc/xinetd.d /etc/systemd; do
        path_status=0
        directory="$(fs_path "$directory" 2>/dev/null)" || path_status=$?
        if [ "$path_status" -ne 0 ]; then
            scan_errors=$((scan_errors + 1))
            continue
        fi
        [ -d "$directory" ] || continue
        find -P "$directory" -xdev -type f -print0 >> "$list_file" 2>/dev/null || scan_errors=$((scan_errors + 1))
    done
    scanner_check_configuration_metadata_set 600 "root" "$list_file"
    evidence="scanned_files=${SCANNER_METADATA_SCANNED}
violations=${SCANNER_METADATA_VIOLATIONS}
metadata_errors=${SCANNER_METADATA_ERRORS}
masks=${SCANNER_METADATA_MASKS}
scan_errors=${scan_errors}
${SCANNER_METADATA_EVIDENCE}"
    if [ "$SCANNER_METADATA_ERRORS" -gt 0 ] || [ "$scan_errors" -gt 0 ]; then
        set_result ERROR "inetd·xinetd·systemd 관리자 구성 일부를 확인하지 못했습니다." "$evidence"
    elif [ "$SCANNER_METADATA_VIOLATIONS" -gt 0 ]; then
        set_result VULNERABLE "관리자 서비스 구성 파일의 소유자 또는 권한이 기준을 벗어납니다." "$evidence"
    elif [ "$SCANNER_METADATA_SCANNED" -eq 0 ]; then
        set_result NOT_APPLICABLE "점검 대상 inetd·xinetd·systemd 관리자 구성 파일이 없습니다." "$evidence" false
    else
        set_result GOOD "관리자 서비스 구성 파일이 root 소유이며 권한이 0600 이하입니다." "$evidence"
    fi
}

check_u_21() {
    local list_file=""
    local path=""
    local directory=""
    local evidence=""
    local main_file=""
    local include_lines=""
    local standard_include=0
    local complex_include=0
    local scan_errors=0
    local path_status=0
    local candidate_file=""
    local candidate=""
    local resolved_candidate=""

    list_file="$(new_scratch_file u21-files)" || {
        set_result ERROR "로깅 구성 파일 목록을 저장할 임시 파일을 만들지 못했습니다."
        return
    }
    for path in /etc/syslog.conf /etc/rsyslog.conf; do
        path_status=0
        path="$(scanner_optional_metadata_path "$path" 2>/dev/null)" || path_status=$?
        case "$path_status" in
            0) printf '%s\0' "$path" >> "$list_file" ;;
            1) ;;
            *) scan_errors=$((scan_errors + 1)) ;;
        esac
    done
    path_status=0
    main_file="$(scanner_optional_metadata_path /etc/rsyslog.conf 2>/dev/null)" || path_status=$?
    [ "$path_status" -le 1 ] || scan_errors=$((scan_errors + 1))
    if [ -r "$main_file" ]; then
        include_lines="$(awk '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line ~ /^\$IncludeConfig[[:space:]]+/ || line ~ /^include[[:space:]]*\(/) print line
            }
        ' "$main_file")"
        if printf '%s\n' "$include_lines" | grep -Fq '/etc/rsyslog.d/*.conf'; then
            standard_include=1
        fi
        if [ -n "$include_lines" ] && printf '%s\n' "$include_lines" | grep -Fv '/etc/rsyslog.d/*.conf' | grep -q .; then
            complex_include=1
        fi
    fi
    path_status=0
    directory="$(fs_path /etc/rsyslog.d 2>/dev/null)" || path_status=$?
    [ "$path_status" -eq 0 ] || {
        [ "$path_status" -eq 2 ] && scan_errors=$((scan_errors + 1))
        directory=""
    }
    if [ "$standard_include" -eq 1 ] && [ -d "$directory" ]; then
        candidate_file="$(new_scratch_file u21-candidates)" || {
            set_result ERROR "rsyslog 분할 구성 목록을 저장할 임시 파일을 만들지 못했습니다."
            return
        }
        if ! find -P "$directory" -maxdepth 1 \( -type f -o -type l \) -name '*.conf' -print0 > "$candidate_file" 2>/dev/null; then
            scan_errors=$((scan_errors + 1))
        else
            while IFS= read -r -d '' candidate; do
                if scanner_is_dev_null_mask "$candidate"; then
                    printf '%s\0' "$candidate" >> "$list_file"
                    continue
                fi
                resolved_candidate="$(resolve_rooted_read_path "$candidate" 2>/dev/null)" || {
                    scan_errors=$((scan_errors + 1))
                    continue
                }
                printf '%s\0' "$resolved_candidate" >> "$list_file"
                if awk '
                    {
                        line=$0
                        sub(/^[[:space:]]+/, "", line)
                        if (line ~ /^\$IncludeConfig[[:space:]]+/ || line ~ /^include[[:space:]]*\(/) found=1
                    }
                    END {exit(found ? 0 : 1)}
                ' "$resolved_candidate"; then
                    complex_include=1
                fi
            done < "$candidate_file"
        fi
    fi
    scanner_check_configuration_metadata_set 640 "root bin sys" "$list_file"
    evidence="scanned_files=${SCANNER_METADATA_SCANNED}
violations=${SCANNER_METADATA_VIOLATIONS}
metadata_errors=${SCANNER_METADATA_ERRORS}
masks=${SCANNER_METADATA_MASKS}
standard_include=${standard_include}
complex_include=${complex_include}
scan_errors=${scan_errors}
${SCANNER_METADATA_EVIDENCE}"
    if [ "$SCANNER_METADATA_ERRORS" -gt 0 ] || [ "$scan_errors" -gt 0 ]; then
        set_result ERROR "(r)syslog 구성 일부의 메타데이터를 확인하지 못했습니다." "$evidence"
    elif [ "$SCANNER_METADATA_VIOLATIONS" -gt 0 ]; then
        set_result VULNERABLE "(r)syslog 구성의 소유자 또는 권한이 기준을 벗어납니다." "$evidence"
    elif [ "$complex_include" -gt 0 ]; then
        set_result MANUAL "rsyslog의 비표준 include 그래프에 포함된 모든 파일의 메타데이터를 확인해야 합니다." "$evidence"
    elif [ "$SCANNER_METADATA_SCANNED" -eq 0 ]; then
        set_result NOT_APPLICABLE "(r)syslog 구성 파일이 없으며 journald 점검은 U-66에서 수행합니다." "$evidence" false
    else
        set_result GOOD "(r)syslog 기본 파일과 분할 구성이 허용 소유자이며 0640 이하입니다." "$evidence"
    fi
}

check_u_22() {
    local path=""
    local uid=""
    local mode=""
    local result=2
    local path_status=0

    path="$(optional_rooted_read_path /etc/services 2>/dev/null)" || path_status=$?
    if [ "$path_status" -eq 1 ]; then
        set_result NOT_APPLICABLE "/etc/services가 존재하지 않습니다." "path=/etc/services" false
        return
    elif [ "$path_status" -ne 0 ]; then
        set_result ERROR "/etc/services 경로를 안전한 일반 파일로 읽지 못했습니다." "path=/etc/services"
        return
    fi
    uid="$(stat_uid "$path" 2>/dev/null || true)"
    mode="$(stat_mode "$path" 2>/dev/null || true)"
    scanner_file_metadata_status "$path" 644 root bin sys
    result=$?
    case "$result" in
        0) set_result GOOD "/etc/services가 허용 소유자이며 권한이 0644 이하입니다." "owner_uid=${uid},mode=${mode}" ;;
        1) set_result VULNERABLE "/etc/services의 소유자 또는 권한이 기준을 벗어납니다." "owner_uid=${uid},mode=${mode}" ;;
        *) set_result ERROR "/etc/services의 메타데이터를 확인하지 못했습니다." "path=/etc/services" ;;
    esac
}

check_u_23() {
    local evidence=""

    scanner_collect_full_filesystem_facts
    if [ "$SCANNER_FULL_FILESYSTEM_SCRATCH_ERROR" -gt 0 ]; then
        set_result ERROR "특수 권한 파일 목록을 저장할 임시 파일을 만들지 못했습니다."
        return
    fi
    if [ "$SCANNER_FULL_FILESYSTEM_ROOT_STATUS" -ne 0 ]; then
        set_result ERROR "로컬 파일시스템 목록을 완전하게 수집하지 못했습니다." "scope=/,xdev=true"
        return
    fi
    if [ "$SCANNER_FULL_FILESYSTEM_SCAN_ERRORS" -gt 0 ]; then
        scanner_full_filesystem_error_evidence_into evidence
        scanner_note_offline_access_context
        set_result ERROR "루트 파일시스템의 SUID·SGID 검색을 완료하지 못했습니다." "$evidence"
        return
    fi
    evidence="special_permission_files=${SCANNER_FULL_FILESYSTEM_U23_COUNT}
${SCANNER_FULL_FILESYSTEM_U23_EVIDENCE}"
    if [ "$SCANNER_FULL_FILESYSTEM_U23_COUNT" -eq 0 ]; then
        if [ "$SCAN_ROOT" != "/" ]; then
            set_result MANUAL "오프라인 루트의 하위 마운트 경계를 확인할 수 없어 SUID·SGID 검색 완료를 확정할 수 없습니다." "$evidence"
        else
            set_result GOOD "일반 파일에서 SUID·SGID 설정을 찾지 못했습니다." "$evidence"
        fi
    else
        set_result MANUAL "SUID·SGID 파일의 설치 출처와 업무 필요성을 승인 목록과 대조해야 합니다." "$evidence"
    fi
}

check_u_24() {
    local passwd_file=""
    local user_name=""
    local evidence_user_name=""
    local user_uid=""
    local home_path=""
    local home_physical_path=""
    local evidence_home_path=""
    local shell_path=""
    local logical_file=""
    local path=""
    local file_uid=""
    local mode=""
    local decimal_mode=""
    local scanned=0
    local violations=0
    local errors=0
    local path_errors=0
    local metadata_errors=0
    local enumeration_errors=0
    local access_errors=0
    local evidence=""
    local process_evidence=""
    local database_status=0
    local path_status=0
    local directory_spec=""
    local relative_directory=""
    local name_pattern=""
    local candidate_file=""
    local candidate=""
    local resolved_candidate=""

    passwd_file="$(fs_path /etc/passwd)"
    [ -r "$passwd_file" ] || {
        set_result ERROR "/etc/passwd를 읽을 수 없습니다." "path=/etc/passwd"
        return
    }
    scanner_validate_passwd_database "$passwd_file"
    database_status=$?
    if [ "$database_status" -ne 0 ]; then
        set_result ERROR "/etc/passwd 계정 데이터가 비어 있거나 올바르지 않습니다." "path=/etc/passwd,status=${database_status}"
        return
    fi
    while IFS=: read -r user_name _ user_uid _ _ home_path _; do
        console_sanitize_line_into "$user_name" evidence_user_name
        evidence_home_path="$(scanner_evidence_path "$home_path")"
        case "$home_path" in
            /*) ;;
            *)
                errors=$((errors + 1))
                path_errors=$((path_errors + 1))
                [ "$errors" -le 20 ] && scanner_append_evidence evidence "account=${evidence_user_name},home=${evidence_home_path:-unset},error=nonabsolute_home_path"
                continue
                ;;
        esac
        path_status=0
        home_physical_path="$(fs_path "$home_path" 2>/dev/null)" || path_status=$?
        if [ "$path_status" -ne 0 ]; then
            errors=$((errors + 1))
            path_errors=$((path_errors + 1))
            [ "$errors" -le 20 ] && scanner_append_evidence evidence "account=${evidence_user_name},home=${evidence_home_path},error=home_path_resolution_failed"
            continue
        fi
        if [ ! -e "$home_physical_path" ] && [ ! -L "$home_physical_path" ]; then
            continue
        fi
        if [ ! -d "$home_physical_path" ]; then
            if [ -L "$home_physical_path" ]; then
                errors=$((errors + 1))
                path_errors=$((path_errors + 1))
                [ "$errors" -le 20 ] && scanner_append_evidence evidence "account=${evidence_user_name},home=${evidence_home_path},error=dangling_or_unsafe_symlink"
            fi
            continue
        fi
        if ! scanner_directory_searchable "$home_physical_path"; then
            errors=$((errors + 1))
            path_errors=$((path_errors + 1))
            access_errors=$((access_errors + 1))
            [ "$errors" -le 20 ] && scanner_append_evidence evidence "account=${evidence_user_name},home=${evidence_home_path},error=directory_search_permission_denied"
            continue
        fi
        for logical_file in .profile .bash_profile .bash_login .bashrc .kshrc .cshrc .tcshrc .login .exrc .netrc .zprofile .zshenv .zshrc .zlogin .pam_environment .xprofile .xsessionrc .config/fish/config.fish; do
            path_status=0
            path="$(fs_path "${home_path%/}/$logical_file" 2>/dev/null)" || path_status=$?
            if [ "$path_status" -ne 0 ]; then
                errors=$((errors + 1))
                path_errors=$((path_errors + 1))
                [ "$errors" -le 20 ] && scanner_append_evidence evidence "account=${evidence_user_name},path=${evidence_home_path%/}/$logical_file,error=path_resolution_failed"
                continue
            fi
            if [ ! -e "$path" ]; then
                if [ -L "$path" ]; then
                    errors=$((errors + 1))
                    path_errors=$((path_errors + 1))
                    [ "$errors" -le 20 ] && scanner_append_evidence evidence "$(scanner_evidence_path "$path"):dangling_or_unsafe_symlink"
                fi
                continue
            fi
            scanned=$((scanned + 1))
            file_uid="$(stat_uid "$path" 2>/dev/null || true)"
            mode="$(stat_mode "$path" 2>/dev/null || true)"
            decimal_mode="$(mode_to_decimal "$mode" 2>/dev/null || true)"
            if [ -z "$file_uid" ] || [ -z "$decimal_mode" ]; then
                errors=$((errors + 1))
                metadata_errors=$((metadata_errors + 1))
                [ "$errors" -le 20 ] && scanner_append_evidence evidence "account=${evidence_user_name},path=$(scanner_evidence_path "$path"),error=metadata_read_failed"
            elif { [ "$file_uid" != "0" ] && [ "$file_uid" != "$user_uid" ]; } || [ $((decimal_mode & 0022)) -ne 0 ]; then
                violations=$((violations + 1))
                [ "$violations" -le 20 ] && scanner_append_evidence evidence "$(scanner_evidence_path "$path"):owner_uid=${file_uid},expected_uid=${user_uid},mode=${mode}"
            fi
        done
        for directory_spec in '.config/environment.d|*.conf' '.config/fish/conf.d|*.fish'; do
            IFS='|' read -r relative_directory name_pattern <<< "$directory_spec"
            path_status=0
            path="$(fs_path "${home_path%/}/$relative_directory" 2>/dev/null)" || path_status=$?
            if [ "$path_status" -ne 0 ]; then
                errors=$((errors + 1))
                path_errors=$((path_errors + 1))
                [ "$errors" -le 20 ] && scanner_append_evidence evidence "account=${evidence_user_name},path=${evidence_home_path%/}/$relative_directory,error=path_resolution_failed"
                continue
            fi
            [ -d "$path" ] || {
                if [ -L "$path" ]; then
                    errors=$((errors + 1))
                    path_errors=$((path_errors + 1))
                    [ "$errors" -le 20 ] && scanner_append_evidence evidence "account=${evidence_user_name},path=$(scanner_evidence_path "$path"),error=dangling_or_unsafe_symlink"
                fi
                continue
            }
            if [ ! -r "$path" ] || [ ! -x "$path" ]; then
                errors=$((errors + 1))
                enumeration_errors=$((enumeration_errors + 1))
                access_errors=$((access_errors + 1))
                [ "$errors" -le 20 ] && scanner_append_evidence evidence "account=${evidence_user_name},path=$(scanner_evidence_path "$path"),error=directory_enumeration_permission_denied"
                continue
            fi
            candidate_file="$(new_scratch_file u24-environment)" || {
                errors=$((errors + 1))
                enumeration_errors=$((enumeration_errors + 1))
                [ "$errors" -le 20 ] && scanner_append_evidence evidence "account=${evidence_user_name},path=$(scanner_evidence_path "$path"),error=scratch_file_unavailable"
                continue
            }
            if ! find -P "$path" -maxdepth 1 \( -type f -o -type l \) -name "$name_pattern" -print0 > "$candidate_file" 2>/dev/null; then
                errors=$((errors + 1))
                enumeration_errors=$((enumeration_errors + 1))
                [ "$errors" -le 20 ] && scanner_append_evidence evidence "account=${evidence_user_name},path=$(scanner_evidence_path "$path"),error=directory_enumeration_failed"
                continue
            fi
            while IFS= read -r -d '' candidate; do
                resolved_candidate="$candidate"
                if [ -L "$candidate" ]; then
                    resolved_candidate="$(resolve_rooted_read_path "$candidate" 2>/dev/null)" || {
                        errors=$((errors + 1))
                        path_errors=$((path_errors + 1))
                        [ "$errors" -le 20 ] && scanner_append_evidence evidence "$(scanner_evidence_path "$candidate"):dangling_or_unsafe_symlink"
                        continue
                    }
                fi
                scanned=$((scanned + 1))
                file_uid="$(stat_uid "$resolved_candidate" 2>/dev/null || true)"
                mode="$(stat_mode "$resolved_candidate" 2>/dev/null || true)"
                decimal_mode="$(mode_to_decimal "$mode" 2>/dev/null || true)"
                if [ -z "$file_uid" ] || [ -z "$decimal_mode" ]; then
                    errors=$((errors + 1))
                    metadata_errors=$((metadata_errors + 1))
                    [ "$errors" -le 20 ] && scanner_append_evidence evidence "account=${evidence_user_name},path=$(scanner_evidence_path "$candidate"),error=metadata_read_failed"
                elif { [ "$file_uid" != "0" ] && [ "$file_uid" != "$user_uid" ]; } || [ $((decimal_mode & 0022)) -ne 0 ]; then
                    violations=$((violations + 1))
                    [ "$violations" -le 20 ] && scanner_append_evidence evidence "$(scanner_evidence_path "$candidate"):owner_uid=${file_uid},expected_uid=${user_uid},mode=${mode}"
                fi
            done < "$candidate_file"
        done
    done < "$passwd_file"
    evidence="scanned_files=${scanned}
violations=${violations}
path_errors=${path_errors}
metadata_errors=${metadata_errors}
enumeration_errors=${enumeration_errors}
collection_errors=${errors}
${evidence}"
    if [ "$errors" -gt 0 ]; then
        if [ "$access_errors" -gt 0 ]; then
            scanner_process_security_context_evidence_into process_evidence
            evidence="${process_evidence}
${evidence}"
            scanner_note_offline_access_context
        fi
        set_result ERROR "일부 홈 환경 파일을 완전하게 검사하지 못했습니다." "$evidence"
    elif [ "$violations" -gt 0 ]; then
        set_result VULNERABLE "홈 환경 파일의 소유자 또는 쓰기 권한이 기준을 벗어납니다." "$evidence"
    else
        set_result GOOD "발견된 홈 환경 파일은 root 또는 해당 계정 소유이며 타 사용자 쓰기가 차단되어 있습니다." "$evidence"
    fi
}

check_u_25() {
    local evidence=""

    scanner_collect_full_filesystem_facts
    if [ "$SCANNER_FULL_FILESYSTEM_SCRATCH_ERROR" -gt 0 ]; then
        set_result ERROR "world writable 파일 목록을 저장할 임시 파일을 만들지 못했습니다."
        return
    fi
    if [ "$SCANNER_FULL_FILESYSTEM_ROOT_STATUS" -ne 0 ]; then
        set_result ERROR "로컬 파일시스템 목록을 완전하게 수집하지 못했습니다." "scope=/,xdev=true"
        return
    fi
    if [ "$SCANNER_FULL_FILESYSTEM_SCAN_ERRORS" -gt 0 ]; then
        scanner_full_filesystem_error_evidence_into evidence
        scanner_note_offline_access_context
        set_result ERROR "루트 파일시스템의 world writable 파일 검색을 완료하지 못했습니다." "$evidence"
        return
    fi
    evidence="world_writable_files=${SCANNER_FULL_FILESYSTEM_U25_COUNT}
${SCANNER_FULL_FILESYSTEM_U25_EVIDENCE}"
    if [ "$SCANNER_FULL_FILESYSTEM_U25_COUNT" -eq 0 ]; then
        if [ "$SCAN_ROOT" != "/" ]; then
            set_result MANUAL "오프라인 루트의 하위 마운트 경계를 확인할 수 없어 world writable 검색 완료를 확정할 수 없습니다." "$evidence"
        else
            set_result GOOD "world writable 일반 파일이 없습니다." "$evidence"
        fi
    else
        set_result MANUAL "world writable 파일의 설정 사유와 승인 여부를 확인해야 합니다." "$evidence"
    fi
}

check_u_26() {
    local device_directory=""
    local list_file=""
    local path=""
    local count=0
    local evidence=""

    device_directory="$(fs_path /dev 2>/dev/null)" || {
        set_result ERROR "/dev 경로를 안전하게 해석하지 못했습니다." "path=/dev"
        return
    }
    [ -d "$device_directory" ] || {
        set_result ERROR "/dev 디렉터리가 존재하지 않습니다." "path=/dev"
        return
    }
    list_file="$(new_scratch_file u26-files)" || {
        set_result ERROR "/dev 일반 파일 목록을 저장할 임시 파일을 만들지 못했습니다."
        return
    }
    if ! find -P "$device_directory" -xdev \
        \( -path "$device_directory/shm" -o -path "$device_directory/mqueue" \) -prune -o \
        -type f -print0 > "$list_file" 2>/dev/null; then
        set_result ERROR "/dev의 일반 파일 검색을 완료하지 못했습니다." "path=/dev"
        return
    fi
    while IFS= read -r -d '' path; do
        count=$((count + 1))
        [ "$count" -le 20 ] && scanner_append_evidence evidence "$(scanner_evidence_path "$path")"
    done < "$list_file"
    evidence="regular_files=${count}
${evidence}"
    if [ "$count" -gt 0 ]; then
        set_result VULNERABLE "/dev에 device node가 아닌 일반 파일이 존재합니다." "$evidence"
    else
        set_result GOOD "/dev에 일반 파일이 없습니다." "$evidence"
    fi
}

scanner_tcp_listener_state() {
    local port=""
    local output=""
    local status=0

    runtime_snapshot_available || return 2
    for port in "$@"; do
        output="$(port_listener_facts "$port" tcp 2>/dev/null)"
        status=$?
        [ "$status" -eq 0 ] || return 2
        [ -n "$output" ] && return 0
    done
    return 1
}

scanner_trust_file_violation() {
    local path="$1"
    local expected_uid="$2"
    local uid=""
    local mode=""
    local parse_status=0

    [ -f "$path" ] && [ -r "$path" ] || return 2
    uid="$(stat_uid "$path" 2>/dev/null || true)"
    mode="$(stat_mode "$path" 2>/dev/null || true)"
    [ -n "$uid" ] && [ -n "$mode" ] || return 2
    { [ "$uid" = "0" ] || [ "$uid" = "$expected_uid" ]; } || return 0
    mode_is_at_most "$mode" 600 || return 0
    awk '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            count=split(line, fields, /[[:space:]]+/)
            for (index_value=1; index_value<=count; index_value++) if (fields[index_value] ~ /^\+/) found=1
        }
        END {exit(found ? 0 : 1)}
    ' "$path"
    parse_status=$?
    case "$parse_status" in
        0) return 0 ;;
        1) return 1 ;;
        *) return 2 ;;
    esac
}

check_u_27() {
    local service_active=0
    local activation_status=1
    local listener_status=2
    local legacy_active=0
    local legacy_uncertain=0
    local path=""
    local path_status=0
    local passwd_file=""
    local database_status=0
    local user_name=""
    local user_uid=""
    local home_path=""
    local shell_path=""
    local checked=0
    local violations=0
    local errors=0
    local result=1
    local evidence=""

    service_activation_state \
        rlogin.service rlogin.socket rlogin@.service \
        rsh.service rsh.socket rsh@.service \
        rexec.service rexec.socket rexec@.service
    activation_status=$?
    [ "$activation_status" -eq 0 ] && service_active=1
    service_legacy_enabled '^(login|rlogin|shell|rsh|exec|rexec)$' && legacy_active=1
    legacy_uncertain="$SERVICE_LEGACY_UNCERTAIN"
    [ "$legacy_active" -eq 1 ] && service_active=1
    scanner_tcp_listener_state 512 513 514
    listener_status=$?

    if [ "$service_active" -eq 0 ]; then
        evidence="activation_state=${activation_status}
legacy_activation=${legacy_active}
legacy_uncertain=${legacy_uncertain}
tcp_listener_state=${listener_status}"
        if [ "$listener_status" -eq 0 ]; then
            set_result MANUAL "r-command 포트의 TCP 수신 프로세스가 실제 rlogin·rsh·rexec인지 확인해야 합니다." "$evidence"
        elif [ "$activation_status" -eq 2 ] || [ "$legacy_uncertain" -eq 1 ] || [ "$listener_status" -eq 2 ]; then
            set_result MANUAL "rlogin·rsh·rexec의 활성 상태를 완전하게 확정하지 못했습니다." "$evidence"
        else
            set_result GOOD "rlogin·rsh·rexec 서비스가 비활성 상태입니다." "$evidence"
        fi
        return
    fi

    path_status=0
    path="$(optional_rooted_read_path /etc/hosts.equiv 2>/dev/null)" || path_status=$?
    if [ "$path_status" -eq 0 ]; then
        checked=$((checked + 1))
        scanner_trust_file_violation "$path" 0
        result=$?
        [ "$result" -eq 0 ] && violations=$((violations + 1))
        [ "$result" -eq 2 ] && errors=$((errors + 1))
        [ "$result" -ne 1 ] && scanner_append_evidence evidence "$(scanner_evidence_path "$path"):metadata_or_plus_violation"
    elif [ "$path_status" -eq 2 ]; then
        errors=$((errors + 1))
        scanner_append_evidence evidence "/etc/hosts.equiv:path_error=true"
    fi
    passwd_file="$(fs_path /etc/passwd 2>/dev/null || true)"
    if [ -r "$passwd_file" ]; then
        scanner_validate_passwd_database "$passwd_file"
        database_status=$?
        if [ "$database_status" -ne 0 ]; then
            errors=$((errors + 1))
            scanner_append_evidence evidence "/etc/passwd:database_status=${database_status}"
        fi
    else
        errors=$((errors + 1))
    fi
    if [ "$database_status" -eq 0 ] && [ -r "$passwd_file" ]; then
        while IFS=: read -r user_name _ user_uid _ _ home_path shell_path; do
            case "$home_path" in
                /*) ;;
                *)
                    errors=$((errors + 1))
                    scanner_append_evidence evidence "account=${user_name},home_path_error=true"
                    continue
                    ;;
            esac
            path_status=0
            path="$(optional_rooted_read_path "${home_path%/}/.rhosts" 2>/dev/null)" || path_status=$?
            [ "$path_status" -ne 1 ] || continue
            if [ "$path_status" -eq 2 ]; then
                errors=$((errors + 1))
                scanner_append_evidence evidence "account=${user_name},rhosts_path_error=true"
                continue
            fi
            checked=$((checked + 1))
            scanner_trust_file_violation "$path" "$user_uid"
            result=$?
            [ "$result" -eq 0 ] && violations=$((violations + 1))
            [ "$result" -eq 2 ] && errors=$((errors + 1))
            [ "$result" -ne 1 ] && scanner_append_evidence evidence "$(scanner_evidence_path "$path"):metadata_or_plus_violation"
        done < "$passwd_file"
    fi
    evidence="activation_state=${activation_status}
legacy_activation=${legacy_active}
legacy_uncertain=${legacy_uncertain}
tcp_listener_state=${listener_status}
trust_files_checked=${checked}
violations=${violations}
errors=${errors}
${evidence}"
    if [ "$errors" -gt 0 ]; then
        set_result ERROR "활성 r 계열 서비스의 신뢰 파일 일부를 확인하지 못했습니다." "$evidence"
    elif [ "$violations" -gt 0 ]; then
        set_result VULNERABLE "활성 r 계열 서비스의 신뢰 파일 소유자·권한 또는 '+' 설정이 취약합니다." "$evidence"
    else
        set_result GOOD "r 계열 서비스 신뢰 파일이 없거나 소유자·권한·'+' 설정 기준을 충족합니다." "$evidence"
    fi
}

SCANNER_U28_RULE_COUNT=0
SCANNER_U28_PROBE_EVIDENCE=""
SCANNER_U28_DEFAULT_DENY=0
SCANNER_U28_QUALIFIED_COUNT=0
SCANNER_U28_BROAD_COUNT=0
SCANNER_U28_COMPLEX_COUNT=0
SCANNER_U28_MISSING_ROOT_COUNT=0

scanner_u28_command_exists_at_standard_path() {
    local command_name="$1"
    local candidate=""

    for candidate in "/usr/sbin/$command_name" "/usr/bin/$command_name" "/sbin/$command_name" "/bin/$command_name"; do
        [ -e "$candidate" ] || [ -L "$candidate" ] || continue
        return 0
    done
    return 1
}

# Returns 1 when the command is not installed and 2 when an installed command
# cannot be trusted or a command invocation fails.
scanner_u28_capture_command() {
    local output_file="$1"
    local command_name="$2"
    local command_path=""
    shift 2

    command_path="$(trusted_command "$command_name" 2>/dev/null || true)"
    if [ -z "$command_path" ]; then
        scanner_u28_command_exists_at_standard_path "$command_name" && return 2
        return 1
    fi
    "$command_path" "$@" > "$output_file" 2>/dev/null || return 2
}

# A firewall unit counts as persistent only when its enabling link resolves to
# a readable unit inside the inspected root. Masks and dangling links do not
# establish activation.
scanner_u28_unit_enabled() {
    local unit_name="$1"
    local unit_state=0
    local override_path=""
    local logical_directory=""
    local directory=""
    local candidates_file=""
    local candidate=""

    if runtime_enabled; then
        service_state "$unit_name" >/dev/null 2>&1
        unit_state=$?
        case "$unit_state" in
            0) return 0 ;;
            1|3) return 1 ;;
            *) return 2 ;;
        esac
    fi

    override_path="${SCAN_ROOT%/}/etc/systemd/system/$unit_name"
    if [ -L "$override_path" ]; then
        scanner_is_dev_null_mask "$override_path" && return 1
        resolve_rooted_read_path "$override_path" >/dev/null 2>&1 || return 2
    fi

    candidates_file="$(new_scratch_file u28-units)" || return 2
    : > "$candidates_file"
    for logical_directory in /etc/systemd/system /run/systemd/system; do
        directory="$(fs_path "$logical_directory" 2>/dev/null || true)"
        [ -n "$directory" ] || return 2
        [ -d "$directory" ] || continue
        find -P "$directory" -mindepth 2 -maxdepth 3 \
            \( -path '*.wants/*' -o -path '*.requires/*' \) \
            -name "$unit_name" -print0 >> "$candidates_file" 2>/dev/null || return 2
    done
    while IFS= read -r -d '' candidate; do
        scanner_is_dev_null_mask "$candidate" && continue
        resolve_rooted_read_path "$candidate" >/dev/null 2>&1 || return 2
        return 0
    done < "$candidates_file"
    return 1
}

scanner_u28_tcp_wrapper_probe() {
    local allow_file=""
    local deny_file=""
    local inetd_file=""
    local path_status=0
    local allowed_services_file=""
    local broad_services_file=""
    local wrapped_services_file=""
    local allow_status=0
    local deny_all=0
    local malformed=0
    local service_name=""

    SCANNER_U28_RULE_COUNT=0
    SCANNER_U28_PROBE_EVIDENCE="wrapper_policy=absent"
    platform_is_debian_family || return 1

    allow_file="$(optional_rooted_read_path /etc/hosts.allow 2>/dev/null)" || path_status=$?
    [ "$path_status" -ne 2 ] || return 2
    path_status=0
    deny_file="$(optional_rooted_read_path /etc/hosts.deny 2>/dev/null)" || path_status=$?
    [ "$path_status" -ne 2 ] || return 2
    [ -n "$allow_file$deny_file" ] || return 1

    allowed_services_file="$(new_scratch_file u28-wrapper-allow)" || return 2
    broad_services_file="$(new_scratch_file u28-wrapper-broad)" || return 2
    wrapped_services_file="$(new_scratch_file u28-wrapper-daemons)" || return 2
    : > "$allowed_services_file"
    : > "$broad_services_file"
    : > "$wrapped_services_file"

    if [ -n "$deny_file" ]; then
        deny_all="$(awk -F: '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                if (NF < 2) {malformed=1; next}
                daemon=$1; client=$2
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", daemon)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", client)
                if (toupper(daemon) == "ALL" && toupper(client) == "ALL") found=1
            }
            END {print (found ? 1 : 0) " " (malformed ? 1 : 0)}
        ' "$deny_file")" || return 2
        malformed="${deny_all##* }"
        deny_all="${deny_all%% *}"
    fi

    if [ -n "$allow_file" ]; then
        awk -F: -v broad_file="$broad_services_file" '
            function trim(value) {gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); return value}
            function specific_address(value) {
                value=tolower(trim(value))
                if (value == "" || value == "all" || value == "local" || value == "0.0.0.0/0" || value == "::/0") return 0
                return value ~ /^[0-9][0-9.]*([/][0-9][0-9.]*)?$/ || value ~ /^\[[0-9a-f:]+\]([/][0-9]+)?$/
            }
            function universal_client(value) {
                value=tolower(trim(value))
                return value == "all" || value == "0.0.0.0/0" || value == "::/0"
            }
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                if (NF < 2 || NF > 3) {malformed=1; next}
                daemons=trim($1); clients=trim($2)
                if (toupper(daemons) ~ /(^|[ ,])EXCEPT([ ,]|$)/ || toupper(clients) ~ /(^|[ ,])EXCEPT([ ,]|$)/) {malformed=1; next}
                if (toupper(daemons) == "ALL" && toupper(clients) == "ALL") {allow_all=1; next}
                count=split(daemons, daemon_values, /[ ,]+/)
                client_count=split(clients, client_values, /[ ,]+/)
                has_address=0
                has_universal=0
                for (client_index=1; client_index<=client_count; client_index++) {
                    if (specific_address(client_values[client_index])) has_address=1
                    if (universal_client(client_values[client_index])) has_universal=1
                }
                for (daemon_index=1; daemon_index<=count; daemon_index++) {
                    daemon=tolower(daemon_values[daemon_index])
                    if (daemon == "") continue
                    if (has_universal) print daemon > broad_file
                    if (has_address && daemon != "all") print daemon
                }
            }
            END {
                if (malformed) print "__MALFORMED__"
                if (allow_all) print "__ALLOW_ALL__"
            }
        ' "$allow_file" > "$allowed_services_file" || return 2
    fi
    grep -Fxq -- __MALFORMED__ "$allowed_services_file" && malformed=1
    allow_status=0
    grep -Fxq -- __ALLOW_ALL__ "$allowed_services_file" && allow_status=1
    sed -i '/^__/d' "$allowed_services_file"
    SCANNER_U28_RULE_COUNT="$(awk 'NF {count++} END {print count+0}' "$allowed_services_file")"

    [ "$malformed" -eq 0 ] || {
        SCANNER_U28_PROBE_EVIDENCE="wrapper_policy=malformed"
        return 3
    }
    if [ "$deny_all" -ne 1 ] || [ "$allow_status" -ne 0 ] || [ "$SCANNER_U28_RULE_COUNT" -eq 0 ]; then
        SCANNER_U28_PROBE_EVIDENCE="wrapper_policy=permissive_or_incomplete,allow_rules=${SCANNER_U28_RULE_COUNT}"
        return 1
    fi

    path_status=0
    inetd_file="$(optional_rooted_read_path /etc/inetd.conf 2>/dev/null)" || path_status=$?
    [ "$path_status" -ne 2 ] || return 2
    if [ -n "$inetd_file" ]; then
        awk '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                split(line, fields, /[[:space:]]+/)
                server=fields[6]
                sub(/^.*\//, "", server)
                if (server != "tcpd") next
                daemon=(fields[7] != "" ? fields[7] : fields[1])
                sub(/^.*\//, "", daemon)
                print tolower(daemon)
                print tolower(fields[1])
            }
        ' "$inetd_file" | LC_ALL=C sort -u > "$wrapped_services_file" || return 2
    fi
    while IFS= read -r service_name; do
        [ -n "$service_name" ] || continue
        if { [ "$service_name" = all ] && [ -s "$wrapped_services_file" ]; } || grep -Fxq -- "$service_name" "$wrapped_services_file"; then
            SCANNER_U28_PROBE_EVIDENCE="wrapper_policy=permissive,applicable_daemon=${service_name},allow_rules=${SCANNER_U28_RULE_COUNT}"
            return 1
        fi
    done < "$broad_services_file"
    while IFS= read -r service_name; do
        [ -n "$service_name" ] || continue
        grep -Fxq -- "$service_name" "$wrapped_services_file" || continue
        SCANNER_U28_PROBE_EVIDENCE="wrapper_policy=restricted,applicable_daemon=${service_name},allow_rules=${SCANNER_U28_RULE_COUNT}"
        return 0
    done < "$allowed_services_file"

    SCANNER_U28_PROBE_EVIDENCE="wrapper_policy=restricted,applicability=none,allow_rules=${SCANNER_U28_RULE_COUNT}"
    return 1
}

# The parser accepts only a default-deny INPUT path with a source-specific,
# port-specific allow. It follows named chains, ignores OUTPUT/FORWARD, and
# rejects broad ACCEPT rules on the reachable INPUT graph.
scanner_u28_iptables_file_state() {
    local file="$1"
    local root_chains="${2:-INPUT}"
    local metrics=""

    [ -f "$file" ] && [ -r "$file" ] || return 2
    metrics="$(awk -v root_chains="$root_chains" '
        function target_of(line, fields, count, index_value) {
            count=split(line, fields, /[[:space:]]+/)
            for (index_value=1; index_value<=count; index_value++) {
                if (fields[index_value] == "-j" || fields[index_value] == "--jump" || fields[index_value] == "-g" || fields[index_value] == "--goto") return fields[index_value+1]
            }
            return ""
        }
        function has_specific_source(line, fields, count, index_value, value) {
            count=split(line, fields, /[[:space:]]+/)
            for (index_value=1; index_value<=count; index_value++) {
                if (fields[index_value] != "-s" && fields[index_value] != "--source") continue
                if ((index_value > 1 && fields[index_value-1] == "!") || fields[index_value+1] == "!") return 0
                value=tolower(fields[index_value+1])
                if (value != "" && value != "0.0.0.0/0" && value != "0/0" && value != "::/0" && value != "anywhere") return 1
            }
            return 0
        }
        function has_specific_port(line, fields, count, index_value, value) {
            count=split(line, fields, /[[:space:]]+/)
            for (index_value=1; index_value<=count; index_value++) {
                if (fields[index_value] != "--dport" && fields[index_value] != "--dports" && fields[index_value] != "--destination-port") continue
                if ((index_value > 1 && fields[index_value-1] == "!") || fields[index_value+1] == "!") return 0
                value=fields[index_value+1]
                if (value ~ /^[0-9]+([,:][0-9]+)*$/ && value != "0:65535" && value != "1:65535") return 1
            }
            return 0
        }
        function safe_infrastructure_accept(line, fields, count, index_value, value, states, state_count, state_index) {
            count=split(line, fields, /[[:space:]]+/)
            for (index_value=1; index_value<=count; index_value++) {
                if (fields[index_value] == "-i" || fields[index_value] == "--in-interface") {
                    if (index_value > 1 && fields[index_value-1] == "!") continue
                    if (fields[index_value+1] == "lo") return 1
                }
                if (fields[index_value] == "-p" || fields[index_value] == "--protocol") {
                    if (index_value > 1 && fields[index_value-1] == "!") continue
                    value=tolower(fields[index_value+1])
                    if (value == "icmp" || value == "ipv6-icmp" || value == "icmpv6") return 1
                }
                if (fields[index_value] == "--ctstate" || fields[index_value] == "--state") {
                    if ((index_value > 1 && fields[index_value-1] == "!") || fields[index_value+1] == "!") continue
                    value=toupper(fields[index_value+1])
                    state_count=split(value, states, /,/)
                    if (state_count == 0) continue
                    for (state_index=1; state_index<=state_count; state_index++) {
                        if (states[state_index] != "ESTABLISHED" && states[state_index] != "RELATED") break
                    }
                    if (state_index > state_count) return 1
                }
            }
            return 0
        }
        function conditional_jump(line, fields, count, index_value, option, value) {
            count=split(line, fields, /[[:space:]]+/)
            for (index_value=1; index_value<=count; index_value++) {
                option=fields[index_value]
                if (index_value == 1 && option == "-A") {index_value++; continue}
                if (option == "-j" || option == "--jump" || option == "-g" || option == "--goto") {index_value++; continue}
                if (option == "-s" || option == "--source" || option == "-d" || option == "--destination") {
                    value=tolower(fields[++index_value])
                    if (value == "0.0.0.0/0" || value == "0/0" || value == "::/0" || value == "anywhere") continue
                    return 1
                }
                if (option == "-p" || option == "--protocol") {
                    if (tolower(fields[++index_value]) == "all") continue
                    return 1
                }
                if (option == "-i" || option == "--in-interface" || option == "-o" || option == "--out-interface") {
                    if (fields[++index_value] == "*") continue
                    return 1
                }
                return 1
            }
            return 0
        }
        function standard_target(value) {
            return value == "" || value == "ACCEPT" || value == "DROP" || value == "REJECT" || value == "RETURN" || value == "LOG" || value == "NFLOG" || value == "QUEUE" || value == "NOTRACK" || value == "MARK" || value == "CT"
        }
        BEGIN {
            root_count=split(root_chains, root_values, /[[:space:]]+/)
            for (root_index=1; root_index<=root_count; root_index++) if (root_values[root_index] != "") {
                reachable[root_values[root_index]]=1
                required_root[root_values[root_index]]=1
            }
            in_filter=1
        }
        {
            raw=$0
            sub(/^[[:space:]]+/, "", raw)
            sub(/[[:space:]]+$/, "", raw)
            if (raw == "" || raw ~ /^#/) next
            if (raw ~ /^\*/) {saw_table=1; in_filter=(raw == "*filter"); next}
            if (raw == "COMMIT") {in_filter=0; next}
            if (saw_table && !in_filter) next
            if (raw ~ /^:/) {
                split(raw, fields, /[[:space:]]+/)
                chain=substr(fields[1], 2)
                known_chain[chain]=1
                if (chain == "INPUT") {
                    if (fields[2] == "DROP") saw_default_drop=1
                    else saw_non_drop_policy=1
                }
                next
            }
            if (raw ~ /^-N[[:space:]]+/) {
                split(raw, fields, /[[:space:]]+/)
                known_chain[fields[2]]=1
                next
            }
            if (raw ~ /^-P[[:space:]]+/) {
                split(raw, fields, /[[:space:]]+/)
                known_chain[fields[2]]=1
                if (fields[2] == "INPUT") {
                    if (fields[3] == "DROP") saw_default_drop=1
                    else saw_non_drop_policy=1
                }
                next
            }
            if (raw !~ /^-A[[:space:]]+/) {complex=1; next}
            split(raw, fields, /[[:space:]]+/)
            rules[++rule_count]=raw
            rule_chain[rule_count]=fields[2]
            rule_target[rule_count]=target_of(raw)
            known_chain[fields[2]]=1
        }
        END {
            for (root_name in required_root) if (!known_chain[root_name]) {complex=1; missing_roots++}
            for (iteration=1; iteration<=rule_count+1; iteration++) {
                changed=0
                for (rule_index=1; rule_index<=rule_count; rule_index++) {
                    if (!reachable[rule_chain[rule_index]]) continue
                    target=rule_target[rule_index]
                    if (known_chain[target]) {
                        if (conditional_jump(rules[rule_index])) complex=1
                        if (!reachable[target]) {reachable[target]=1; changed=1}
                    }
                }
                if (!changed) break
            }
            for (rule_index=1; rule_index<=rule_count; rule_index++) {
                if (!reachable[rule_chain[rule_index]]) continue
                target=rule_target[rule_index]
                if (!standard_target(target) && !known_chain[target]) complex=1
                if (target != "ACCEPT") continue
                if (rules[rule_index] ~ /(^|[[:space:]])--match-set([[:space:]]|$)/ || rules[rule_index] ~ /(^|[[:space:]])-m[[:space:]]+set([[:space:]]|$)/) {complex=1; continue}
                if (safe_infrastructure_accept(rules[rule_index])) continue
                if (has_specific_source(rules[rule_index]) && has_specific_port(rules[rule_index]) && rules[rule_index] ~ /(^|[[:space:]])(-p|--protocol)[[:space:]]+(tcp|udp)([[:space:]]|$)/) qualified++
                else if (rule_chain[rule_index] ~ /^ufw6?-(before|after)-input$/) complex=1
                else broad++
            }
            default_deny=(saw_default_drop && !saw_non_drop_policy)
            print default_deny+0, qualified+0, broad+0, complex+0, missing_roots+0
        }
    ' "$file")" || return 2
    read -r SCANNER_U28_DEFAULT_DENY SCANNER_U28_QUALIFIED_COUNT SCANNER_U28_BROAD_COUNT SCANNER_U28_COMPLEX_COUNT SCANNER_U28_MISSING_ROOT_COUNT <<< "$metrics"
    [ "$SCANNER_U28_MISSING_ROOT_COUNT" -eq 0 ] || return 3
    [ "$SCANNER_U28_DEFAULT_DENY" -eq 1 ] && [ "$SCANNER_U28_BROAD_COUNT" -eq 0 ] || return 1
    [ "$SCANNER_U28_COMPLEX_COUNT" -eq 0 ] || return 3
    [ "$SCANNER_U28_QUALIFIED_COUNT" -gt 0 ] && return 0
    return 1
}

scanner_u28_assignment_value() {
    local logical_path="$1"
    local key="$2"
    local file=""
    local file_status=0

    file="$(optional_rooted_read_path "$logical_path" 2>/dev/null)" || file_status=$?
    [ "$file_status" -ne 2 ] || return 2
    [ "$file_status" -eq 0 ] || return 1
    awk -v target="$key" '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            sub(/^export[[:space:]]+/, "", line)
            if (line !~ "^" target "[[:space:]]*=") next
            sub("^" target "[[:space:]]*=[[:space:]]*", "", line)
            sub(/[[:space:]]+#.*$/, "", line)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            if (line ~ /^".*"$/ || line ~ /^\047.*\047$/) line=substr(line, 2, length(line)-2)
            value=line
        }
        END {if (value != "") print value; else exit 1}
    ' "$file"
}

scanner_u28_ufw_static_enabled() {
    local value=""
    local status=0

    value="$(scanner_u28_assignment_value /etc/ufw/ufw.conf ENABLED 2>/dev/null)" || status=$?
    if [ "$status" -eq 1 ]; then
        status=0
        value="$(scanner_u28_assignment_value /etc/default/ufw ENABLED 2>/dev/null)" || status=$?
    fi
    [ "$status" -ne 2 ] || return 2
    [ "$status" -eq 0 ] || return 1
    case "$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')" in
        yes) return 0 ;;
        no) return 1 ;;
        *) return 2 ;;
    esac
}

scanner_u28_ufw_raw_family() {
    local input_file="$1"
    local family="$2"
    local output_file="$3"

    [ -f "$input_file" ] && [ -r "$input_file" ] || return 2
    awk -v wanted_family="$family" '
        function emit_complex() {print "__U28_COMPLEX__"}
        /^IPV4 \(raw\):[[:space:]]*$/ {
            selected=(wanted_family == "ipv4")
            if (selected) section_seen=1
            next
        }
        /^IPV6:[[:space:]]*$/ {
            if (selected && wanted_family == "ipv4") selected=0
            selected=(wanted_family == "ipv6")
            if (selected) section_seen=1
            next
        }
        !selected {next}
        /^Chain[[:space:]]+/ {
            chain=$2
            if (chain == "PREROUTING" && saw_input) {in_filter=0; next}
            if (!saw_input && chain != "INPUT") {emit_complex(); next}
            if (!in_filter && saw_input) next
            in_filter=1
            if (chain == "INPUT") saw_input=1
            current_chain=chain
            if (match($0, /\(policy[[:space:]]+[A-Za-z]+/)) {
                policy=substr($0, RSTART, RLENGTH)
                sub(/^\(policy[[:space:]]+/, "", policy)
                print "-P " chain " " toupper(policy)
            } else {
                print "-N " chain
            }
            next
        }
        !in_filter || current_chain == "" {next}
        /^[[:space:]]*pkts[[:space:]]+bytes[[:space:]]+target[[:space:]]+/ {next}
        /^[[:space:]]*[0-9]+[[:space:]]+[0-9]+[[:space:]]+/ {
            if (NF < 9 || $3 == "") {emit_complex(); next}
            target=$3
            protocol=tolower($4)
            input_interface=$6
            output_interface=$7
            source=$8
            destination=$9
            rule="-A " current_chain
            if (protocol != "all") rule=rule " -p " protocol
            if (input_interface != "*") rule=rule " -i " input_interface
            if (output_interface != "*") rule=rule " -o " output_interface
            if (source != "0.0.0.0/0" && source != "::/0" && source != "anywhere") rule=rule " -s " source
            if (destination != "0.0.0.0/0" && destination != "::/0" && destination != "anywhere") rule=rule " -d " destination
            unknown=0
            for (index_value=10; index_value<=NF; index_value++) {
                value=$index_value
                if (value == "tcp" || value == "udp" || value == "multiport") continue
                if (value ~ /^dpt:/) {sub(/^dpt:/, "", value); rule=rule " --dport " value; continue}
                if (value ~ /^dpts:/) {sub(/^dpts:/, "", value); rule=rule " --dports " value; continue}
                if (value == "dports" && index_value < NF) {rule=rule " --dports " $(++index_value); continue}
                if (value == "state" && index_value < NF) {rule=rule " --state " $(++index_value); continue}
                if (value == "ctstate" && index_value < NF) {rule=rule " --ctstate " $(++index_value); continue}
                if (value ~ /^(spt|spts):/) continue
                unknown=1
            }
            print rule " -j " target
            if (unknown) emit_complex()
            next
        }
        /^[[:space:]]*$/ {next}
        {emit_complex()}
        END {if (!section_seen || !saw_input) exit 2}
    ' "$input_file" > "$output_file" || return 2
}

scanner_u28_ufw_static_family() {
    local family="$1"
    local output_file="$2"
    local suffix=""
    local roots="INPUT ufw-before-input ufw-user-input ufw-after-input"
    local logical_path=""
    local file=""
    local status=0

    SCANNER_U28_DEFAULT_DENY=0
    SCANNER_U28_QUALIFIED_COUNT=0
    SCANNER_U28_BROAD_COUNT=0
    SCANNER_U28_COMPLEX_COUNT=0
    SCANNER_U28_MISSING_ROOT_COUNT=0
    if [ "$family" = ipv6 ]; then
        suffix=6
        roots="INPUT ufw6-before-input ufw6-user-input ufw6-after-input"
    fi
    printf '%s\n' '-P INPUT DROP' > "$output_file" || return 2
    for logical_path in "/etc/ufw/before${suffix}.rules" "/etc/ufw/user${suffix}.rules" "/etc/ufw/after${suffix}.rules"; do
        status=0
        file="$(optional_rooted_read_path "$logical_path" 2>/dev/null)" || status=$?
        [ "$status" -ne 2 ] || return 2
        [ "$status" -eq 0 ] && [ -s "$file" ] || return 3
        cat "$file" >> "$output_file" || return 2
        printf '\n' >> "$output_file" || return 2
    done
    scanner_u28_iptables_file_state "$output_file" "$roots"
}

scanner_u28_ufw_probe() {
    local status=0
    local static_status=0
    local output_file=""
    local raw_file=""
    local ipv4_file=""
    local ipv6_file=""
    local logical_path=""
    local hook_file=""
    local hook_status=0
    local default_policy=""
    local ipv6_value=""
    local ipv4_default=0
    local ipv4_qualified=0
    local ipv4_broad=0
    local ipv4_complex=0
    local ipv6_default=1
    local ipv6_qualified=0
    local ipv6_broad=0
    local ipv6_complex=0
    local ufw_state="enabled"

    SCANNER_U28_RULE_COUNT=0
    SCANNER_U28_PROBE_EVIDENCE="ufw_state=inactive"
    output_file="$(new_scratch_file u28-ufw-output)" || return 2
    raw_file="$(new_scratch_file u28-ufw-raw)" || return 2
    ipv4_file="$(new_scratch_file u28-ufw-ipv4)" || return 2
    ipv6_file="$(new_scratch_file u28-ufw-ipv6)" || return 2

    if runtime_enabled; then
        ufw_state="active"
        scanner_u28_capture_command "$output_file" ufw status verbose
        status=$?
        if [ "$status" -eq 1 ]; then
            scanner_u28_ufw_static_enabled >/dev/null 2>&1
            static_status=$?
            case "$static_status" in
                0) return 3 ;;
                1) return 1 ;;
                *) return 2 ;;
            esac
        elif [ "$status" -ne 0 ]; then
            return 2
        fi
        if grep -q '^Status:[[:space:]]*inactive' "$output_file"; then
            return 1
        elif ! grep -q '^Status:[[:space:]]*active' "$output_file"; then
            return 2
        fi
        scanner_u28_capture_command "$raw_file" ufw show raw || return 2
        scanner_u28_ufw_raw_family "$raw_file" ipv4 "$ipv4_file" || return 2
        scanner_u28_ufw_raw_family "$raw_file" ipv6 "$ipv6_file" || return 2
        scanner_u28_iptables_file_state "$ipv4_file" INPUT || status=$?
        ipv4_default="$SCANNER_U28_DEFAULT_DENY"
        ipv4_qualified="$SCANNER_U28_QUALIFIED_COUNT"
        ipv4_broad="$SCANNER_U28_BROAD_COUNT"
        ipv4_complex="$SCANNER_U28_COMPLEX_COUNT"
        status=0
        scanner_u28_iptables_file_state "$ipv6_file" INPUT || status=$?
        ipv6_default="$SCANNER_U28_DEFAULT_DENY"
        ipv6_qualified="$SCANNER_U28_QUALIFIED_COUNT"
        ipv6_broad="$SCANNER_U28_BROAD_COUNT"
        ipv6_complex="$SCANNER_U28_COMPLEX_COUNT"
    else
        scanner_u28_ufw_static_enabled || status=$?
        [ "$status" -ne 2 ] || return 2
        [ "$status" -eq 0 ] || return 1
        status=0
        scanner_u28_unit_enabled ufw.service || status=$?
        case "$status" in
            0) ;;
            1) return 1 ;;
            2) return 2 ;;
            *) return 3 ;;
        esac
        default_policy="$(scanner_u28_assignment_value /etc/default/ufw DEFAULT_INPUT_POLICY 2>/dev/null)" || status=$?
        [ "$status" -ne 2 ] || return 2
        [ "$status" -eq 0 ] || return 3
        case "$(printf '%s' "$default_policy" | tr '[:lower:]' '[:upper:]')" in
            DROP|REJECT) ;;
            *)
                SCANNER_U28_PROBE_EVIDENCE="ufw_state=enabled,default_input=${default_policy:-unset}"
                return 1
                ;;
        esac
        for logical_path in /etc/ufw/before.init /etc/ufw/after.init; do
            hook_status=0
            hook_file="$(optional_rooted_read_path "$logical_path" 2>/dev/null)" || hook_status=$?
            [ "$hook_status" -ne 2 ] || return 2
            [ "$hook_status" -eq 0 ] || continue
            [ -x "$hook_file" ] && return 3
        done
        status=0
        scanner_u28_ufw_static_family ipv4 "$ipv4_file" || status=$?
        [ "$status" -ne 2 ] || return 2
        [ "$status" -ne 3 ] || return 3
        ipv4_default="$SCANNER_U28_DEFAULT_DENY"
        ipv4_qualified="$SCANNER_U28_QUALIFIED_COUNT"
        ipv4_broad="$SCANNER_U28_BROAD_COUNT"
        ipv4_complex="$SCANNER_U28_COMPLEX_COUNT"

        status=0
        ipv6_value="$(scanner_u28_assignment_value /etc/default/ufw IPV6 2>/dev/null)" || status=$?
        [ "$status" -ne 2 ] || return 2
        [ "$status" -eq 0 ] || return 3
        case "$(printf '%s' "$ipv6_value" | tr '[:upper:]' '[:lower:]')" in
            yes)
                status=0
                scanner_u28_ufw_static_family ipv6 "$ipv6_file" || status=$?
                [ "$status" -ne 2 ] || return 2
                [ "$status" -ne 3 ] || return 3
                ipv6_default="$SCANNER_U28_DEFAULT_DENY"
                ipv6_qualified="$SCANNER_U28_QUALIFIED_COUNT"
                ipv6_broad="$SCANNER_U28_BROAD_COUNT"
                ipv6_complex="$SCANNER_U28_COMPLEX_COUNT"
                ;;
            no) ;;
            *) return 3 ;;
        esac
    fi

    SCANNER_U28_RULE_COUNT=$((ipv4_qualified + ipv6_qualified))
    SCANNER_U28_PROBE_EVIDENCE="ufw_state=${ufw_state},ipv4_default_deny=${ipv4_default},ipv6_default_deny=${ipv6_default},qualified_rules=${SCANNER_U28_RULE_COUNT},broad_rules=$((ipv4_broad + ipv6_broad)),complex_graphs=$((ipv4_complex + ipv6_complex))"
    [ "$ipv4_default" -eq 1 ] && [ "$ipv6_default" -eq 1 ] && [ "$ipv4_broad" -eq 0 ] && [ "$ipv6_broad" -eq 0 ] || return 1
    [ "$ipv4_complex" -eq 0 ] && [ "$ipv6_complex" -eq 0 ] || return 3
    [ "$SCANNER_U28_RULE_COUNT" -gt 0 ] && return 0
    return 1
}

scanner_u28_nftables_file_state() {
    local file="$1"

    [ -f "$file" ] && [ -r "$file" ] || return 2
    awk '
        function brace_count(value, character, copy) {
            copy=value
            return gsub(character, "", copy)
        }
        function finish_chain() {
            if (chain_name == "") return
            if (chain_seen[chain_name]) complex=1
            chain_seen[chain_name]=1
            chain_body[chain_name]=current_body
            if (current_body ~ /(^|[;[:space:]])type[[:space:]]+filter[[:space:]]+hook[[:space:]]+input([;[:space:]]|$)/) {
                input_chain[chain_name]=1
                input_count++
                if (current_body ~ /(^|[;[:space:]])policy[[:space:]]+drop([;[:space:]]|$)/) input_drop[chain_name]=1
            }
            chain_name=""
            current_body=""
            depth=0
        }
        function target_of(statement, fields, count, index_value) {
            count=split(statement, fields, /[[:space:]]+/)
            for (index_value=1; index_value<=count; index_value++) {
                if (fields[index_value] == "jump" || fields[index_value] == "goto") return fields[index_value+1]
            }
            return ""
        }
        function specific_source(statement, fields, count, index_value, value) {
            count=split(statement, fields, /[[:space:]]+/)
            for (index_value=1; index_value<count; index_value++) {
                if ((fields[index_value] == "ip" || fields[index_value] == "ip6") && fields[index_value+1] == "saddr") {
                    value=tolower(fields[index_value+2])
                    if (value == "!=" || value == "==") {
                        if (value == "!=") return 0
                        value=tolower(fields[index_value+3])
                    }
                    if (value ~ /^[@${]/) return -1
                    if (value != "" && value != "0.0.0.0/0" && value != "::/0") return 1
                }
            }
            return 0
        }
        function specific_port(statement, fields, count, index_value, value) {
            count=split(statement, fields, /[[:space:]]+/)
            for (index_value=1; index_value<count; index_value++) {
                if ((fields[index_value] == "tcp" || fields[index_value] == "udp") && fields[index_value+1] == "dport") {
                    value=fields[index_value+2]
                    if (value == "!=" || value == "==") {
                        if (value == "!=") return 0
                        value=fields[index_value+3]
                    }
                    if (value ~ /^[@${]/) return -1
                    if (value ~ /^[0-9]+([-,:][0-9]+)*$/ && value != "0-65535" && value != "1-65535") return 1
                }
            }
            return 0
        }
        function safe_infrastructure_accept(statement, fields, count, index_value, value, states, state_count, state_index) {
            count=split(statement, fields, /[[:space:]]+/)
            for (index_value=1; index_value<=count; index_value++) {
                if (fields[index_value] == "ct" && fields[index_value+1] == "state") {
                    value=fields[index_value+2]
                    if (value == "!=" || value == "==") {
                        if (value == "!=") continue
                        value=fields[index_value+3]
                    }
                    state_count=split(value, states, /,/)
                    if (state_count == 0) continue
                    for (state_index=1; state_index<=state_count; state_index++) {
                        if (states[state_index] != "established" && states[state_index] != "related") break
                    }
                    if (state_index > state_count) return 1
                }
                if (fields[index_value] == "iif" || fields[index_value] == "iifname") {
                    value=fields[index_value+1]
                    if (value == "==") value=fields[index_value+2]
                    else if (value == "!=") continue
                    gsub(/^"|"$/, "", value)
                    if (value == "lo") return 1
                }
            }
            return statement ~ /(^|[[:space:]])(icmp|icmpv6)[[:space:]]+type([[:space:]]|$)/
        }
        function conditional_jump(statement, fields, count, index_value) {
            count=split(statement, fields, /[[:space:]]+/)
            for (index_value=1; index_value<=count; index_value++) {
                if (fields[index_value] == "jump" || fields[index_value] == "goto") return index_value != 1 || count != 2
            }
            return 0
        }
        {
            line=$0
            sub(/#.*/, "", line)
            lower_line=tolower(line)
            if (lower_line ~ /(^|[;[:space:]])flags[[:space:]]+dormant([;[:space:]]|$)/) complex=1
            if (lower_line ~ /^[[:space:]]*table[[:space:]]+(arp|bridge|netdev)[[:space:]]/) complex=1
            if (lower_line ~ /^[[:space:]]*table[[:space:]]+ip[[:space:]]/) saw_ip_table=1
            if (lower_line ~ /^[[:space:]]*table[[:space:]]+ip6[[:space:]]/) saw_ip6_table=1
            if (lower_line ~ /(^|[[:space:]])ip[[:space:]]+saddr([[:space:]]|$)/) saw_ip_source=1
            if (lower_line ~ /(^|[[:space:]])ip6[[:space:]]+saddr([[:space:]]|$)/) saw_ip6_source=1
            if (!in_chain) {
                trimmed=line
                sub(/^[[:space:]]+/, "", trimmed)
                if (trimmed !~ /^chain[[:space:]]+[A-Za-z0-9_.-]+[[:space:]]*\{/) next
                chain_name=trimmed
                sub(/^chain[[:space:]]+/, "", chain_name)
                sub(/[[:space:]]*\{.*/, "", chain_name)
                in_chain=1
                depth=brace_count(trimmed, "\\{") - brace_count(trimmed, "\\}")
                current_body=trimmed ";"
                if (depth <= 0) {in_chain=0; finish_chain()}
                next
            }
            current_body=current_body " " line ";"
            depth+=brace_count(line, "\\{") - brace_count(line, "\\}")
            if (depth <= 0) {in_chain=0; finish_chain()}
        }
        END {
            if (in_chain) complex=1
            if (input_count > 1) complex=1
            for (name in input_chain) reachable[name]=1
            for (iteration=1; iteration<=64; iteration++) {
                changed=0
                for (name in reachable) {
                    count=split(chain_body[name], statements, /;/)
                    for (statement_index=1; statement_index<=count; statement_index++) {
                        statement=tolower(statements[statement_index])
                        target=target_of(statement)
                        if (target == "") continue
                        if (conditional_jump(statement)) complex=1
                        if (!chain_seen[target]) {complex=1; continue}
                        if (!reachable[target]) {reachable[target]=1; changed=1}
                    }
                }
                if (!changed) break
            }
            for (name in reachable) {
                count=split(chain_body[name], statements, /;/)
                for (statement_index=1; statement_index<=count; statement_index++) {
                    statement=tolower(statements[statement_index])
                    if (statement ~ /(^|[[:space:]])(vmap|map)[[:space:]]/ || statement ~ /(^|[[:space:]])verdict[[:space:]]+map/) complex=1
                    if (statement !~ /(^|[[:space:]])accept([[:space:]]|$)/) continue
                    if (safe_infrastructure_accept(statement)) continue
                    source_state=specific_source(statement)
                    port_state=specific_port(statement)
                    if (source_state < 0 || port_state < 0) {complex=1; continue}
                    if (source_state == 1 && port_state == 1) qualified++
                    else broad++
                }
            }
            default_deny=0
            for (name in input_chain) if (input_drop[name]) default_deny=1
            if ((saw_ip_table && saw_ip6_source) || (saw_ip6_table && saw_ip_source)) complex=1
            if (input_count == 1 && default_deny && qualified > 0 && broad == 0 && !complex) exit 0
            if (complex) exit 3
            exit 1
        }
    ' "$file"
}

scanner_u28_unit_definition() {
    local unit_name="$1"
    local logical_path=""
    local file=""
    local status=0

    for logical_path in \
        "/etc/systemd/system/$unit_name" \
        "/run/systemd/system/$unit_name" \
        "/usr/local/lib/systemd/system/$unit_name" \
        "/usr/lib/systemd/system/$unit_name" \
        "/lib/systemd/system/$unit_name"; do
        status=0
        file="$(optional_rooted_read_path "$logical_path" 2>/dev/null)" || status=$?
        [ "$status" -ne 2 ] || return 2
        [ "$status" -eq 0 ] || continue
        printf '%s\n' "$file"
        return 0
    done
    return 1
}

scanner_u28_nftables_entrypoint() {
    local unit_file=""
    local status=0
    local logical_directory=""
    local directory=""
    local dropin_file=""
    local dropins_file=""
    local command_line=""
    local config_path=""

    unit_file="$(scanner_u28_unit_definition nftables.service 2>/dev/null)" || status=$?
    [ "$status" -eq 0 ] || return "$status"
    dropins_file="$(new_scratch_file u28-nft-dropins)" || return 2
    for logical_directory in \
        /etc/systemd/system/nftables.service.d \
        /run/systemd/system/nftables.service.d \
        /usr/local/lib/systemd/system/nftables.service.d \
        /usr/lib/systemd/system/nftables.service.d; do
        directory="$(fs_path "$logical_directory" 2>/dev/null || true)"
        [ -n "$directory" ] || return 2
        [ -d "$directory" ] || continue
        : > "$dropins_file"
        find -P "$directory" -maxdepth 1 \( -type f -o -type l \) -name '*.conf' -print0 > "$dropins_file" 2>/dev/null || return 2
        while IFS= read -r -d '' dropin_file; do
            scanner_is_dev_null_mask "$dropin_file" && continue
            resolve_rooted_read_path "$dropin_file" >/dev/null 2>&1 || return 2
            return 3
        done < "$dropins_file"
    done
    command_line="$(awk '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^[#;]/) next
            if (line ~ /^ExecStart[[:space:]]*=/) {
                sub(/^ExecStart[[:space:]]*=[[:space:]]*/, "", line)
                if (line == "") {value=""; next}
                if (value != "") duplicate=1
                value=line
            }
        }
        END {if (duplicate || value == "") exit 1; print value}
    ' "$unit_file")" || return 3
    case "$command_line" in
        *'$'*|*'`'*|*'%'*|*\\*) return 3 ;;
    esac
    config_path="$(printf '%s\n' "$command_line" | awk '
        {
            for (index_value=1; index_value<=NF; index_value++) {
                command=$index_value
                sub(/^.*\//, "", command)
                if (index_value == 1 && command != "nft") exit 2
                if ($index_value == "-f" || $index_value == "--file") {print $(index_value+1); found=1; exit}
                if ($index_value ~ /^--file=/) {value=$index_value; sub(/^--file=/, "", value); print value; found=1; exit}
            }
        }
        END {if (!found) exit 1}
    ')" || return 3
    case "$config_path" in
        /*) printf '%s\n' "$config_path" ;;
        *) return 3 ;;
    esac
}

SCANNER_U28_NFT_SEEN_FILE=""
SCANNER_U28_NFT_OUTPUT_FILE=""
SCANNER_U28_NFT_HAS_INCLUDE=0

scanner_u28_nftables_collect_file() {
    local logical_path="$1"
    local depth="$2"
    local file=""
    local status=0
    local includes_file=""
    local include_spec=""
    local logical_directory=""
    local pattern=""
    local physical_directory=""
    local matches_file=""
    local match=""
    local match_count=0

    [ "$depth" -le 16 ] || return 3
    case "$logical_path" in
        /*) ;;
        *) return 3 ;;
    esac
    case "$logical_path" in
        *$'\n'*|*$'\r'*|*$'\t'*|*/../*|*/..|*/./*|*/.) return 2 ;;
    esac
    grep -Fxq -- "$logical_path" "$SCANNER_U28_NFT_SEEN_FILE" && return 0
    printf '%s\n' "$logical_path" >> "$SCANNER_U28_NFT_SEEN_FILE" || return 2
    file="$(optional_rooted_read_path "$logical_path" 2>/dev/null)" || status=$?
    [ "$status" -eq 0 ] || return 2
    cat "$file" >> "$SCANNER_U28_NFT_OUTPUT_FILE" || return 2
    printf '\n' >> "$SCANNER_U28_NFT_OUTPUT_FILE" || return 2

    includes_file="$(new_scratch_file u28-nft-includes)" || return 2
    awk '
        {
            line=$0
            sub(/#.*/, "", line)
            sub(/^[[:space:]]+/, "", line)
            if (line !~ /^include[[:space:]]+/) next
            sub(/^include[[:space:]]+/, "", line)
            sub(/[[:space:]]*;[[:space:]]*$/, "", line)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            if (line ~ /^".*"$/) line=substr(line, 2, length(line)-2)
            print line
        }
    ' "$file" > "$includes_file" || return 2
    [ -s "$includes_file" ] && SCANNER_U28_NFT_HAS_INCLUDE=1
    while IFS= read -r include_spec; do
        [ -n "$include_spec" ] || return 3
        case "$include_spec" in
            /*) ;;
            *) return 3 ;;
        esac
        case "$include_spec" in
            *'$'*|*'`'*|*\\*|*[[:space:]]*) return 3 ;;
        esac
        case "$include_spec" in
            *'*'*|*'?'*|*'['*)
                logical_directory="${include_spec%/*}"
                pattern="${include_spec##*/}"
                case "$logical_directory" in *'*'*|*'?'*|*'['*) return 3 ;; esac
                physical_directory="$(fs_path "$logical_directory" 2>/dev/null || true)"
                [ -n "$physical_directory" ] || return 2
                physical_directory="$(resolve_rooted_directory "$physical_directory" 2>/dev/null || true)"
                [ -n "$physical_directory" ] || return 2
                matches_file="$(new_scratch_file u28-nft-matches)" || return 2
                find -P "$physical_directory" -maxdepth 1 \( -type f -o -type l \) -name "$pattern" -print0 > "$matches_file" 2>/dev/null || return 2
                sort -z "$matches_file" -o "$matches_file" || return 2
                match_count=0
                while IFS= read -r -d '' match; do
                    match_count=$((match_count + 1))
                    scanner_u28_nftables_collect_file "$(display_path "$match")" $((depth + 1)) || return $?
                done < "$matches_file"
                [ "$match_count" -gt 0 ] || return 3
                ;;
            *)
                scanner_u28_nftables_collect_file "$include_spec" $((depth + 1)) || return $?
                ;;
        esac
    done < "$includes_file"
}

scanner_u28_nftables_probe() {
    local status=0
    local output_file=""
    local entrypoint=""

    SCANNER_U28_RULE_COUNT=0
    SCANNER_U28_PROBE_EVIDENCE="nftables_state=inactive"
    output_file="$(new_scratch_file u28-nft-rules)" || return 2
    if runtime_enabled; then
        scanner_u28_capture_command "$output_file" nft list ruleset
        status=$?
        [ "$status" -ne 1 ] || return 1
        [ "$status" -eq 0 ] || return 2
    else
        scanner_u28_unit_enabled nftables.service || status=$?
        case "$status" in
            0) ;;
            1) return 1 ;;
            2) return 2 ;;
            *) return 3 ;;
        esac
        entrypoint="$(scanner_u28_nftables_entrypoint 2>/dev/null)" || status=$?
        [ "$status" -eq 0 ] || return "$status"
        SCANNER_U28_NFT_SEEN_FILE="$(new_scratch_file u28-nft-seen)" || return 2
        SCANNER_U28_NFT_OUTPUT_FILE="$output_file"
        SCANNER_U28_NFT_HAS_INCLUDE=0
        : > "$SCANNER_U28_NFT_SEEN_FILE"
        : > "$SCANNER_U28_NFT_OUTPUT_FILE"
        scanner_u28_nftables_collect_file "$entrypoint" 0 || return $?
        [ "$SCANNER_U28_NFT_HAS_INCLUDE" -eq 0 ] || return 3
    fi
    scanner_u28_nftables_file_state "$output_file"
    status=$?
    SCANNER_U28_PROBE_EVIDENCE="nftables_state=$([ "$status" -eq 0 ] && printf restricted || printf unresolved_or_open),rule_graph_state=${status}"
    [ "$status" -eq 0 ] && SCANNER_U28_RULE_COUNT=1
    return "$status"
}

scanner_u28_xtables_probe() {
    local command_name="$1"
    local family="$2"
    local logical_path=""
    local unit_name=""
    local file=""
    local status=0

    SCANNER_U28_RULE_COUNT=0
    SCANNER_U28_PROBE_EVIDENCE="${command_name}_state=inactive"
    file="$(new_scratch_file "u28-${command_name}")" || return 2
    if runtime_enabled; then
        scanner_u28_capture_command "$file" "$command_name" -S
        status=$?
        [ "$status" -ne 1 ] || return 1
        [ "$status" -eq 0 ] || return 2
    else
        if platform_is_debian_family; then
            if [ "$family" = ipv4 ]; then logical_path=/etc/iptables/rules.v4; else logical_path=/etc/iptables/rules.v6; fi
            unit_name=netfilter-persistent.service
        elif platform_is_rhel_family; then
            if [ "$family" = ipv4 ]; then
                logical_path=/etc/sysconfig/iptables
                unit_name=iptables.service
            else
                logical_path=/etc/sysconfig/ip6tables
                unit_name=ip6tables.service
            fi
        else
            return 1
        fi
        status=0
        file="$(optional_rooted_read_path "$logical_path" 2>/dev/null)" || status=$?
        [ "$status" -ne 2 ] || return 2
        [ "$status" -eq 0 ] || return 1
        scanner_u28_unit_enabled "$unit_name" || status=$?
        case "$status" in
            0) ;;
            1) return 1 ;;
            2) return 2 ;;
            *) return 3 ;;
        esac
    fi
    scanner_u28_iptables_file_state "$file"
    status=$?
    SCANNER_U28_PROBE_EVIDENCE="${command_name}_state=$([ "$status" -eq 0 ] && printf restricted || printf unresolved_or_open),rule_graph_state=${status}"
    [ "$status" -eq 0 ] && SCANNER_U28_RULE_COUNT=1
    return "$status"
}

scanner_u28_firewalld_zone_text_state() {
    local file="$1"
    local role="${2:-default}"

    [ -f "$file" ] && [ -r "$file" ] || return 2
    awk -v role="$role" '
        function specific_address(value) {
            value=tolower(value)
            return value != "" && value != "0.0.0.0/0" && value != "::/0" && value != "any" && value != "anywhere"
        }
        function universal_address(value) {
            value=tolower(value)
            return value == "0.0.0.0/0" || value == "::/0" || value == "any" || value == "anywhere"
        }
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            lower=tolower(line)
            if (lower ~ /^target:/) {
                target=lower
                sub(/^target:[[:space:]]*/, "", target)
            } else if (lower ~ /^interfaces:/) {
                value=lower
                sub(/^interfaces:[[:space:]]*/, "", value)
                if (value != "") interface_count++
            } else if (lower ~ /^sources:/) {
                value=lower
                sub(/^sources:[[:space:]]*/, "", value)
                count=split(value, fields, /[[:space:]]+/)
                for (index_value=1; index_value<=count; index_value++) {
                    if (fields[index_value] ~ /^ipset:/) {complex=1; ipset_sources++}
                    else if (universal_address(fields[index_value])) universal_sources++
                    else if (specific_address(fields[index_value])) source_count++
                }
            } else if (lower ~ /^(services|ports|protocols):/) {
                value=lower
                sub(/^[^:]+:[[:space:]]*/, "", value)
                if (value != "") endpoint_count++
            } else if (lower ~ /^rule[[:space:]]/) {
                if (lower !~ /(^|[[:space:]])accept([[:space:]]|$)/) next
                has_endpoint=(lower ~ /(port[[:space:]]+port=|service[[:space:]]+name=)/)
                has_source=(lower ~ /source[[:space:]]+(not[[:space:]]+)?address="[^"]+"/)
                if (lower ~ /source[[:space:]]+ipset=/) {complex=1; next}
                if (lower ~ /source[[:space:]]+not[[:space:]]+address=/ || lower ~ /source[[:space:]][^[:space:]]*invert=/) {rich_broad=1; next}
                if (!has_source || !has_endpoint || lower ~ /source[[:space:]]+address="(0\.0\.0\.0\/0|::\/0)"/) rich_broad=1
                else rich_pair++
            }
        }
        END {
            if (target == "") exit 3
            if (target != "default" && target != "accept" && target != "drop" && target != "reject") exit 3
            active=(role != "offline" || interface_count > 0 || source_count > 0 || universal_sources > 0 || ipset_sources > 0)
            if (!active) exit 4
            if (target == "accept" || rich_broad > 0) exit 1
            if (endpoint_count > 0) {
                if (role == "default" || interface_count > 0 || universal_sources > 0) exit 1
                if (source_count > 0) rich_pair++
                else complex=1
            }
            if (complex) exit 3
            if (rich_pair > 0) exit 0
            exit 4
        }
    ' "$file"
}

scanner_u28_firewalld_policy_text_state() {
    local file="$1"

    [ -f "$file" ] && [ -r "$file" ] || return 2
    awk '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            lower=tolower(line)
            if (lower ~ /^target:/) {target=lower; sub(/^target:[[:space:]]*/, "", target)}
            else if (lower ~ /^ingress-zones:/ && lower ~ /(^|[[:space:]])any([[:space:]]|$)/) ingress=1
            else if (lower ~ /^egress-zones:/ && lower ~ /(^|[[:space:]])host([[:space:]]|$)/) egress=1
            else if (lower ~ /^rule[[:space:]]/) {
                if (lower !~ /(^|[[:space:]])accept([[:space:]]|$)/) next
                has_endpoint=(lower ~ /(port[[:space:]]+port=|service[[:space:]]+name=)/)
                has_source=(lower ~ /source[[:space:]]+(not[[:space:]]+)?address="[^"]+"/)
                if (lower ~ /source[[:space:]]+ipset=/) {complex=1; next}
                if (lower ~ /source[[:space:]]+not[[:space:]]+address=/ || !has_source || !has_endpoint || lower ~ /source[[:space:]]+address="(0\.0\.0\.0\/0|::\/0)"/) rich_broad=1
                else rich_pair++
            }
        }
        END {
            if (!ingress || !egress) exit 4
            if (target == "accept" || rich_broad > 0) exit 1
            if (complex) exit 3
            if (target == "continue") exit 4
            if (target != "drop" && target != "reject") exit 3
            if (rich_pair > 0) exit 0
            exit 4
        }
    ' "$file"
}

scanner_u28_firewalld_zone_xml_state() {
    local file="$1"
    local role="${2:-default}"

    [ -f "$file" ] && [ -r "$file" ] || return 2
    awk -v role="$role" '
        function attribute(record, name, pattern, value) {
            pattern=name "=\"[^\"]+\""
            if (!match(record, pattern)) return ""
            value=substr(record, RSTART, RLENGTH)
            sub(/^[^=]+="/, "", value)
            sub(/"$/, "", value)
            return tolower(value)
        }
        function specific_source(record, value) {
            value=attribute(record, "address")
            return value != "" && value != "0.0.0.0/0" && value != "::/0"
        }
        function strip_comments(value, start_index, tail, close_index) {
            while ((start_index=index(value, "<!--")) > 0) {
                tail=substr(value, start_index+4)
                close_index=index(tail, "-->")
                if (close_index == 0) {comment_error=1; return substr(value, 1, start_index-1)}
                value=substr(value, 1, start_index-1) substr(tail, close_index+3)
            }
            return value
        }
        END {
            content=tolower(content)
            content=strip_comments(content)
            target="default"
            if (match(content, /<zone[^>]*target="[^"]+"/)) target=attribute(substr(content, RSTART, RLENGTH), "target")
            if (target != "default" && target != "accept" && target != "drop" && target != "reject") exit 3
            if (content ~ /<(zone|source|service|port|rule|accept)[^>]*=\047/) complex=1
            remaining=content
            while (match(remaining, /<rule[^>]*>/)) {
                start=RSTART
                tail=substr(remaining, start)
                close_index=index(tail, "</rule>")
                if (close_index == 0) exit 3
                rule=substr(tail, 1, close_index + 6)
                has_accept=(rule ~ /<accept([[:space:]\/>])/)
                has_endpoint=(rule ~ /<(port|service)[[:space:]][^>]*>/)
                has_source=(rule ~ /<source[^>]*>/)
                if (rule ~ /<source[^>]*ipset=/) complex=1
                if (has_accept) {
                    if (rule ~ /<source[^>]*invert="(true|yes|1)"/ || !has_source || !has_endpoint || !specific_source(rule)) rich_broad=1
                    else rich_pair++
                }
                remaining=substr(remaining, 1, start-1) substr(tail, close_index+7)
            }
            interface_count=(remaining ~ /<interface[[:space:]][^>]*name=/)
            scan=remaining
            while (match(scan, /<source[^>]*>/)) {
                record=substr(scan, RSTART, RLENGTH)
                if (record ~ /ipset=/) {complex=1; ipset_sources++}
                else if (record ~ /invert="(true|yes|1)"/ || !specific_source(record)) universal_sources++
                else if (specific_source(record)) source_count++
                scan=substr(scan, RSTART+RLENGTH)
            }
            if (remaining ~ /<(port|service|protocol)[[:space:]][^>]*>/) endpoint_count++
            active=(role != "offline" || interface_count > 0 || source_count > 0 || universal_sources > 0 || ipset_sources > 0)
            if (!active) exit 4
            if (target == "accept" || rich_broad > 0) exit 1
            if (endpoint_count > 0) {
                if (role == "default" || interface_count > 0 || universal_sources > 0) exit 1
                if (source_count > 0) rich_pair++
                else complex=1
            }
            if (comment_error) complex=1
            if (complex) exit 3
            if (rich_pair > 0) exit 0
            exit 4
        }
        {content=content " " $0}
    ' "$file"
}

scanner_u28_firewalld_policy_xml_state() {
    local file="$1"

    [ -f "$file" ] && [ -r "$file" ] || return 2
    awk '
        function attribute(record, name, pattern, value) {
            pattern=name "=\"[^\"]+\""
            if (!match(record, pattern)) return ""
            value=substr(record, RSTART, RLENGTH)
            sub(/^[^=]+="/, "", value)
            sub(/"$/, "", value)
            return tolower(value)
        }
        function specific_source(record, value) {
            value=attribute(record, "address")
            return value != "" && value != "0.0.0.0/0" && value != "::/0"
        }
        function strip_comments(value, start_index, tail, close_index) {
            while ((start_index=index(value, "<!--")) > 0) {
                tail=substr(value, start_index+4)
                close_index=index(tail, "-->")
                if (close_index == 0) {comment_error=1; return substr(value, 1, start_index-1)}
                value=substr(value, 1, start_index-1) substr(tail, close_index+3)
            }
            return value
        }
        END {
            content=tolower(content)
            content=strip_comments(content)
            target=""
            if (match(content, /<policy[^>]*target="[^"]+"/)) target=attribute(substr(content, RSTART, RLENGTH), "target")
            ingress=(content ~ /<ingress-zone[[:space:]][^>]*name="any"/)
            egress=(content ~ /<egress-zone[[:space:]][^>]*name="host"/)
            if (!ingress || !egress) exit 4
            if (target != "accept" && target != "continue" && target != "drop" && target != "reject") exit 3
            if (content ~ /<(policy|source|service|port|rule|accept)[^>]*=\047/) complex=1
            remaining=content
            while (match(remaining, /<rule[^>]*>/)) {
                start=RSTART
                tail=substr(remaining, start)
                close_index=index(tail, "</rule>")
                if (close_index == 0) exit 3
                rule=substr(tail, 1, close_index + 6)
                if (rule ~ /<source[^>]*ipset=/) complex=1
                has_accept=(rule ~ /<accept([[:space:]\/>])/)
                has_endpoint=(rule ~ /<(port|service)[[:space:]][^>]*>/)
                has_source=(rule ~ /<source[^>]*>/)
                if (has_accept) {
                    if (rule ~ /<source[^>]*invert="(true|yes|1)"/ || !has_source || !has_endpoint || !specific_source(rule)) rich_broad=1
                    else rich_pair++
                }
                remaining=substr(remaining, 1, start-1) substr(tail, close_index+7)
            }
            if (target == "accept" || rich_broad > 0) exit 1
            if (comment_error) complex=1
            if (complex) exit 3
            if (target == "continue") exit 4
            if (rich_pair > 0) exit 0
            exit 4
        }
        {content=content " " $0}
    ' "$file"
}

scanner_u28_firewalld_object_file() {
    local object_type="$1"
    local object_name="$2"
    local logical_path=""
    local file=""
    local status=0

    case "$object_type:$object_name" in
        *:*[!A-Za-z0-9_.-]*) return 2 ;;
    esac
    for logical_path in "/etc/firewalld/${object_type}s/${object_name}.xml" "/usr/lib/firewalld/${object_type}s/${object_name}.xml"; do
        status=0
        file="$(optional_rooted_read_path "$logical_path" 2>/dev/null)" || status=$?
        [ "$status" -ne 2 ] || return 2
        [ "$status" -eq 0 ] || continue
        printf '%s\n' "$file"
        return 0
    done
    return 1
}

scanner_u28_firewalld_runtime_probe() {
    local status=0
    local output_file=""
    local names_file=""
    local runtime_file=""
    local permanent_file=""
    local name=""
    local default_zone=""
    local zone_role="active"
    local runtime_state=0
    local permanent_state=0
    local confirmed=0
    local uncertain=0
    local open=0

    scanner_u28_unit_enabled firewalld.service || status=$?
    [ "$status" -ne 2 ] || return 2
    [ "$status" -eq 0 ] || return 1
    output_file="$(new_scratch_file u28-firewalld-output)" || return 2
    names_file="$(new_scratch_file u28-firewalld-names)" || return 2
    runtime_file="$(new_scratch_file u28-firewalld-runtime)" || return 2
    permanent_file="$(new_scratch_file u28-firewalld-permanent)" || return 2
    : > "$names_file"

    scanner_u28_capture_command "$output_file" firewall-cmd --get-active-zones || return 2
    awk '/^[^[:space:]]/ && $1 ~ /^[A-Za-z0-9_.-]+$/ {print $1}' "$output_file" >> "$names_file"
    scanner_u28_capture_command "$output_file" firewall-cmd --get-default-zone || return 2
    default_zone="$(awk 'NF {print $1; exit}' "$output_file")"
    case "$default_zone" in ''|*[!A-Za-z0-9_.-]*) return 2 ;; esac
    printf '%s\n' "$default_zone" >> "$names_file"
    LC_ALL=C sort -u "$names_file" -o "$names_file" || return 2
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        zone_role=active
        [ "$name" = "$default_zone" ] && zone_role=default
        scanner_u28_capture_command "$runtime_file" firewall-cmd --zone "$name" --list-all || return 2
        scanner_u28_capture_command "$permanent_file" firewall-cmd --permanent --zone "$name" --list-all || return 2
        scanner_u28_firewalld_zone_text_state "$runtime_file" "$zone_role"
        runtime_state=$?
        scanner_u28_firewalld_zone_text_state "$permanent_file" "$zone_role"
        permanent_state=$?
        [ "$runtime_state" -ne 2 ] && [ "$permanent_state" -ne 2 ] || return 2
        if [ "$runtime_state" -eq 1 ] || [ "$permanent_state" -eq 1 ]; then
            open=$((open + 1))
        elif [ "$runtime_state" -eq 0 ] && [ "$permanent_state" -eq 0 ]; then
            confirmed=$((confirmed + 1))
        elif [ "$runtime_state" -eq 3 ] || [ "$permanent_state" -eq 3 ] || [ "$runtime_state" -ne "$permanent_state" ]; then
            uncertain=$((uncertain + 1))
        fi
    done < "$names_file"

    if scanner_u28_capture_command "$output_file" firewall-cmd --get-active-policies; then
        awk 'NF && $1 ~ /^[A-Za-z0-9_.-]+$/ {print $1}' "$output_file" > "$names_file"
        while IFS= read -r name; do
            [ -n "$name" ] || continue
            scanner_u28_capture_command "$runtime_file" firewall-cmd --policy "$name" --list-all || return 2
            scanner_u28_capture_command "$permanent_file" firewall-cmd --permanent --policy "$name" --list-all || return 2
            scanner_u28_firewalld_policy_text_state "$runtime_file"
            runtime_state=$?
            scanner_u28_firewalld_policy_text_state "$permanent_file"
            permanent_state=$?
            [ "$runtime_state" -ne 2 ] && [ "$permanent_state" -ne 2 ] || return 2
            if [ "$runtime_state" -eq 1 ] || [ "$permanent_state" -eq 1 ]; then
                open=$((open + 1))
            elif [ "$runtime_state" -eq 0 ] && [ "$permanent_state" -eq 0 ]; then
                confirmed=$((confirmed + 1))
            elif [ "$runtime_state" -eq 3 ] || [ "$permanent_state" -eq 3 ] || [ "$runtime_state" -ne "$permanent_state" ]; then
                uncertain=$((uncertain + 1))
            fi
        done < "$names_file"
    else
        status=$?
        [ "$status" -eq 1 ] || uncertain=$((uncertain + 1))
    fi
    SCANNER_U28_RULE_COUNT="$confirmed"
    SCANNER_U28_PROBE_EVIDENCE="firewalld_state=active,restricted_objects=${confirmed},open_objects=${open},uncertain_objects=${uncertain}"
    [ "$open" -eq 0 ] || return 1
    [ "$uncertain" -eq 0 ] || return 3
    [ "$confirmed" -gt 0 ] && return 0
    return 1
}

scanner_u28_firewalld_offline_probe() {
    local status=0
    local default_zone="public"
    local object_file=""
    local logical_directory=""
    local directory=""
    local candidates_file=""
    local seen_file=""
    local candidate=""
    local basename_value=""
    local object_state=0
    local confirmed=0
    local uncertain=0
    local open=0

    scanner_u28_unit_enabled firewalld.service || status=$?
    [ "$status" -ne 2 ] || return 2
    [ "$status" -eq 0 ] || return 1
    status=0
    default_zone="$(scanner_u28_assignment_value /etc/firewalld/firewalld.conf DefaultZone 2>/dev/null)" || status=$?
    [ "$status" -ne 2 ] || return 2
    [ "$status" -eq 0 ] || default_zone=public
    case "$default_zone" in ''|*[!A-Za-z0-9_.-]*) return 3 ;; esac
    status=0
    object_file="$(scanner_u28_firewalld_object_file zone "$default_zone" 2>/dev/null)" || status=$?
    [ "$status" -ne 2 ] || return 2
    if [ "$status" -eq 0 ]; then
        scanner_u28_firewalld_zone_xml_state "$object_file" default
        object_state=$?
        [ "$object_state" -ne 2 ] || return 2
        [ "$object_state" -eq 0 ] && confirmed=$((confirmed + 1))
        [ "$object_state" -eq 1 ] && open=$((open + 1))
        [ "$object_state" -eq 3 ] && uncertain=$((uncertain + 1))
    else
        uncertain=$((uncertain + 1))
    fi

    candidates_file="$(new_scratch_file u28-firewalld-objects)" || return 2
    seen_file="$(new_scratch_file u28-firewalld-seen)" || return 2
    : > "$candidates_file"
    : > "$seen_file"
    printf '%s\n' "${default_zone}.xml" > "$seen_file" || return 2
    for logical_directory in /etc/firewalld/zones /usr/lib/firewalld/zones; do
        directory="$(fs_path "$logical_directory" 2>/dev/null || true)"
        [ -n "$directory" ] || return 2
        [ -d "$directory" ] || continue
        directory="$(resolve_rooted_directory "$directory" 2>/dev/null || true)"
        [ -n "$directory" ] || return 2
        find -P "$directory" -maxdepth 1 \( -type f -o -type l \) -name '*.xml' -print0 >> "$candidates_file" 2>/dev/null || return 2
    done
    while IFS= read -r -d '' candidate; do
        basename_value="${candidate##*/}"
        grep -Fxq -- "$basename_value" "$seen_file" && continue
        printf '%s\n' "$basename_value" >> "$seen_file" || return 2
        candidate="$(resolve_rooted_read_path "$candidate" 2>/dev/null || true)"
        [ -n "$candidate" ] || return 2
        scanner_u28_firewalld_zone_xml_state "$candidate" offline
        object_state=$?
        [ "$object_state" -ne 2 ] || return 2
        [ "$object_state" -eq 0 ] && confirmed=$((confirmed + 1))
        [ "$object_state" -eq 1 ] && open=$((open + 1))
        [ "$object_state" -eq 3 ] && uncertain=$((uncertain + 1))
    done < "$candidates_file"

    : > "$candidates_file"
    : > "$seen_file"
    for logical_directory in /etc/firewalld/policies /usr/lib/firewalld/policies; do
        directory="$(fs_path "$logical_directory" 2>/dev/null || true)"
        [ -n "$directory" ] || return 2
        [ -d "$directory" ] || continue
        directory="$(resolve_rooted_directory "$directory" 2>/dev/null || true)"
        [ -n "$directory" ] || return 2
        find -P "$directory" -maxdepth 1 \( -type f -o -type l \) -name '*.xml' -print0 >> "$candidates_file" 2>/dev/null || return 2
    done
    while IFS= read -r -d '' candidate; do
        basename_value="${candidate##*/}"
        grep -Fxq -- "$basename_value" "$seen_file" && continue
        printf '%s\n' "$basename_value" >> "$seen_file" || return 2
        candidate="$(resolve_rooted_read_path "$candidate" 2>/dev/null || true)"
        [ -n "$candidate" ] || return 2
        scanner_u28_firewalld_policy_xml_state "$candidate"
        object_state=$?
        [ "$object_state" -ne 2 ] || return 2
        [ "$object_state" -eq 0 ] && confirmed=$((confirmed + 1))
        [ "$object_state" -eq 1 ] && open=$((open + 1))
        [ "$object_state" -eq 3 ] && uncertain=$((uncertain + 1))
    done < "$candidates_file"
    SCANNER_U28_RULE_COUNT="$confirmed"
    SCANNER_U28_PROBE_EVIDENCE="firewalld_state=enabled,default_zone=${default_zone},restricted_objects=${confirmed},open_objects=${open},uncertain_objects=${uncertain}"
    [ "$open" -eq 0 ] || return 1
    [ "$uncertain" -eq 0 ] || return 3
    [ "$confirmed" -gt 0 ] && return 0
    return 1
}

scanner_u28_firewalld_probe() {
    local status=0

    SCANNER_U28_RULE_COUNT=0
    SCANNER_U28_PROBE_EVIDENCE="firewalld_state=probing"
    if runtime_enabled; then
        scanner_u28_firewalld_runtime_probe || status=$?
    else
        scanner_u28_firewalld_offline_probe || status=$?
    fi
    if [ "$SCANNER_U28_PROBE_EVIDENCE" = "firewalld_state=probing" ]; then
        case "$status" in
            1) SCANNER_U28_PROBE_EVIDENCE="firewalld_state=inactive" ;;
            2) SCANNER_U28_PROBE_EVIDENCE="firewalld_state=unavailable,collection_error=true" ;;
            3) SCANNER_U28_PROBE_EVIDENCE="firewalld_state=ambiguous" ;;
            *)
                SCANNER_U28_PROBE_EVIDENCE="firewalld_state=unavailable,collection_error=true"
                status=2
                ;;
        esac
    fi
    return "$status"
}

check_u_28() {
    local confirmed=0
    local uncertain=0
    local errors=0
    local status=0
    local evidence=""

    status=0
    scanner_u28_tcp_wrapper_probe || status=$?
    scanner_append_evidence evidence "provider=tcp_wrapper,state=${status},${SCANNER_U28_PROBE_EVIDENCE}"
    case "$status" in 0) confirmed=$((confirmed + 1)) ;; 2) errors=$((errors + 1)) ;; 3) uncertain=$((uncertain + 1)) ;; esac

    status=0
    scanner_u28_ufw_probe || status=$?
    scanner_append_evidence evidence "provider=ufw,state=${status},${SCANNER_U28_PROBE_EVIDENCE}"
    case "$status" in 0) confirmed=$((confirmed + 1)) ;; 2) errors=$((errors + 1)) ;; 3) uncertain=$((uncertain + 1)) ;; esac

    status=0
    scanner_u28_nftables_probe || status=$?
    scanner_append_evidence evidence "provider=nftables,state=${status},${SCANNER_U28_PROBE_EVIDENCE}"
    case "$status" in 0) confirmed=$((confirmed + 1)) ;; 2) errors=$((errors + 1)) ;; 3) uncertain=$((uncertain + 1)) ;; esac

    status=0
    scanner_u28_xtables_probe iptables ipv4 || status=$?
    scanner_append_evidence evidence "provider=iptables,state=${status},${SCANNER_U28_PROBE_EVIDENCE}"
    case "$status" in 0) confirmed=$((confirmed + 1)) ;; 2) errors=$((errors + 1)) ;; 3) uncertain=$((uncertain + 1)) ;; esac

    status=0
    scanner_u28_xtables_probe ip6tables ipv6 || status=$?
    scanner_append_evidence evidence "provider=ip6tables,state=${status},${SCANNER_U28_PROBE_EVIDENCE}"
    case "$status" in 0) confirmed=$((confirmed + 1)) ;; 2) errors=$((errors + 1)) ;; 3) uncertain=$((uncertain + 1)) ;; esac

    status=0
    scanner_u28_firewalld_probe || status=$?
    scanner_append_evidence evidence "provider=firewalld,state=${status},${SCANNER_U28_PROBE_EVIDENCE}"
    case "$status" in 0) confirmed=$((confirmed + 1)) ;; 2) errors=$((errors + 1)) ;; 3) uncertain=$((uncertain + 1)) ;; esac

    evidence="confirmed_providers=${confirmed}
uncertain_providers=${uncertain}
collection_errors=${errors}
${evidence}"
    if [ "$errors" -gt 0 ]; then
        set_result ERROR "접근 제한 공급자의 설정 또는 실행 상태를 안전하게 수집하지 못했습니다." "$evidence"
    elif [ "$confirmed" -gt 0 ]; then
        set_result MANUAL "입력 경로의 호스트·포트 제한 후보가 확인됐으며 업무 허용 목록과 대조해야 합니다." "$evidence"
    elif [ "$uncertain" -gt 0 ]; then
        set_result MANUAL "복잡하거나 적용 여부가 불명확한 접근 제한 구성을 검토해야 합니다." "$evidence"
    else
        set_result VULNERABLE "호스트·IP·포트 접근 제한을 입증할 활성 또는 영구 입력 규칙을 찾지 못했습니다." "$evidence"
    fi
}

check_u_29() {
    local path=""
    local path_status=0
    local uid=""
    local mode=""
    local result=2

    path="$(optional_rooted_read_path /etc/hosts.lpd 2>/dev/null)" || path_status=$?
    if [ "$path_status" -eq 1 ]; then
        set_result GOOD "/etc/hosts.lpd가 존재하지 않습니다." "path=/etc/hosts.lpd"
        return
    elif [ "$path_status" -ne 0 ]; then
        set_result ERROR "/etc/hosts.lpd 경로를 안전하게 읽지 못했습니다." "path=/etc/hosts.lpd"
        return
    fi
    uid="$(stat_uid "$path" 2>/dev/null || true)"
    mode="$(stat_mode "$path" 2>/dev/null || true)"
    scanner_file_metadata_status "$path" 600 root
    result=$?
    case "$result" in
        0) set_result GOOD "/etc/hosts.lpd가 root 소유이며 권한이 0600 이하입니다." "owner_uid=${uid},mode=${mode}" ;;
        1) set_result VULNERABLE "/etc/hosts.lpd의 소유자 또는 권한이 기준을 벗어납니다." "owner_uid=${uid},mode=${mode}" ;;
        *) set_result ERROR "/etc/hosts.lpd의 메타데이터를 확인하지 못했습니다." "path=/etc/hosts.lpd" ;;
    esac
}

scanner_u30_shell_source_token() {
    local line="$1"
    local token=""

    line="${line#"${line%%[![:space:]]*}"}"
    case "$line" in ''|\#*) return 1 ;; esac
    case "$line" in *[[:space:]]\#*) line="${line%%[[:space:]]\#*}" ;; esac
    case "$line" in
        builtin[[:space:]]*)
            line="${line#builtin}"
            line="${line#"${line%%[![:space:]]*}"}"
            ;;
    esac
    case "$line" in
        .[[:space:]]*) line="${line#.}" ;;
        source[[:space:]]*) line="${line#source}" ;;
        *[\;[:space:]].[[:space:]]*|*[\;[:space:]]source[[:space:]]*) return 3 ;;
        *) return 1 ;;
    esac
    line="${line#"${line%%[![:space:]]*}"}"
    token="${line%%[[:space:]]*}"
    token="${token%;}"
    [ -n "$token" ] || return 2
    printf '%s\n' "$token"
}

scanner_u30_normalize_shell_source_path() {
    local token="$1"
    local home_path="$2"

    case "$token" in
        \"*\") token="${token#\"}"; token="${token%\"}" ;;
        \'*\') token="${token#\'}"; token="${token%\'}" ;;
    esac
    case "$token" in
        \~/*) [ -n "$home_path" ] || return 1; token="$home_path/${token#\~/}" ;;
        \$HOME/*) [ -n "$home_path" ] || return 1; token="$home_path/${token#\$HOME/}" ;;
        \$\{HOME\}/*) [ -n "$home_path" ] || return 1; token="$home_path/${token#\$\{HOME\}/}" ;;
    esac
    case "$token" in
        /*) ;;
        *) return 1 ;;
    esac
    case "$token" in *$'\n'*|*$'\r'*|*$'\t'*|*/../*|*/..|*/./*|*/.) return 1 ;; esac
    printf '%s\n' "$token"
}

scanner_u30_shell_expand_directory() {
    local logical_directory="$1"
    local pattern="$2"
    local home_path="$3"
    local depth="$4"
    local active_stack="$5"
    local stream_file="$6"
    local raw_directory="${SCAN_ROOT%/}${logical_directory}"
    local directory=""
    local candidates_file=""
    local sorted_candidates_file=""
    local candidate=""
    local candidate_status=0
    local matches=0

    [ -e "$raw_directory" ] || [ -L "$raw_directory" ] || return 1
    directory="$(fs_path "$logical_directory" 2>/dev/null)" || return 2
    directory="$(resolve_rooted_directory "$directory" 2>/dev/null)" || return 2
    candidates_file="$(new_scratch_file u30-shell-sources)" || return 2
    sorted_candidates_file="$(new_scratch_file u30-shell-sources-sorted)" || return 2
    find -P "$directory" -maxdepth 1 \( -type f -o -type l \) -name "$pattern" -print0 > "$candidates_file" 2>/dev/null || return 2
    LC_ALL=C sort -z "$candidates_file" > "$sorted_candidates_file" || return 2
    while IFS= read -r -d '' candidate; do
        matches=$((matches + 1))
        candidate_status=0
        scanner_u30_shell_expand_file "$(display_path "$candidate")" "$home_path" "$depth" "$active_stack" "$stream_file" || candidate_status=$?
        [ "$candidate_status" -ne 2 ] || return 2
        [ "$candidate_status" -eq 0 ] || return 3
    done < "$sorted_candidates_file"
    [ "$matches" -gt 0 ] || return 1
}

scanner_u30_shell_expand_source() {
    local logical_path="$1"
    local home_path="$2"
    local depth="$3"
    local active_stack="$4"
    local stream_file="$5"
    local logical_directory=""
    local pattern=""

    case "${logical_path##*/}" in
        *'*'*|*'?'*|*'['*)
            logical_directory="${logical_path%/*}"
            pattern="${logical_path##*/}"
            [ -n "$logical_directory" ] || logical_directory=/
            scanner_u30_shell_expand_directory "$logical_directory" "$pattern" "$home_path" "$depth" "$active_stack" "$stream_file"
            ;;
        *) scanner_u30_shell_expand_file "$logical_path" "$home_path" "$depth" "$active_stack" "$stream_file" ;;
    esac
}

scanner_u30_shell_expand_file() {
    local logical_path="$1"
    local home_path="$2"
    local depth="$3"
    local active_stack="$4"
    local stream_file="$5"
    local file=""
    local file_status=0
    local source_name=""
    local line=""
    local parse_line=""
    local line_number=0
    local source_token=""
    local source_path=""
    local source_status=0
    local profile_iterator_seen=0

    [ "$depth" -lt 16 ] || return 3
    file="$(optional_rooted_read_path "$logical_path" 2>/dev/null)" || file_status=$?
    [ "$file_status" -ne 2 ] || return 2
    [ "$file_status" -eq 0 ] || return 1
    case "|$active_stack|" in *"|$file|"*) return 3 ;; esac
    active_stack="${active_stack:+$active_stack|}${file}"
    source_name="$(display_path "$file")"

    while IFS= read -r line || [ -n "$line" ]; do
        line_number=$((line_number + 1))
        printf '%s\t%s\t%s\n' "$source_name" "$line_number" "$line" >> "$stream_file" || return 2
        parse_line="${line#"${line%%[![:space:]]*}"}"
        case "$parse_line" in ''|\#*) continue ;; esac
        case "$parse_line" in *'/etc/profile.d/'*'.sh'*) profile_iterator_seen=1 ;; esac
        source_status=0
        source_token="$(scanner_u30_shell_source_token "$parse_line" 2>/dev/null)" || source_status=$?
        [ "$source_status" -ne 2 ] || return 2
        if [ "$source_status" -eq 3 ]; then
            printf '%s\t%s\t%s\n' "$source_name" "$line_number" '__SCANNER_U30_UNRESOLVED_SOURCE__' >> "$stream_file" || return 2
            continue
        fi
        [ "$source_status" -eq 0 ] || continue
        case "$source_token" in
            \$i|\"\$i\"|\$\{i\}|\"\$\{i\}\")
                if [ "$profile_iterator_seen" -eq 1 ]; then
                    source_status=0
                    scanner_u30_shell_expand_directory /etc/profile.d '*.sh' "$home_path" $((depth + 1)) "$active_stack" "$stream_file" || source_status=$?
                    [ "$source_status" -ne 2 ] || return 2
                    continue
                fi
                ;;
        esac
        source_status=0
        source_path="$(scanner_u30_normalize_shell_source_path "$source_token" "$home_path" 2>/dev/null)" || source_status=$?
        if [ "$source_status" -ne 0 ]; then
            printf '%s\t%s\t%s\n' "$source_name" "$line_number" '__SCANNER_U30_UNRESOLVED_SOURCE__' >> "$stream_file" || return 2
            continue
        fi
        source_status=0
        scanner_u30_shell_expand_source "$source_path" "$home_path" $((depth + 1)) "$active_stack" "$stream_file" || source_status=$?
        if [ "$source_status" -eq 2 ]; then
            return 2
        elif [ "$source_status" -ne 0 ]; then
            printf '%s\t%s\t%s\n' "$source_name" "$line_number" '__SCANNER_U30_UNRESOLVED_SOURCE__' >> "$stream_file" || return 2
        fi
    done < "$file"
}

scanner_u30_shell_file_records() {
    local logical_path="$1"
    local scope="$2"
    local home_path="${3:-}"
    local stream_file=""
    local expansion_status=0

    stream_file="$(new_scratch_file u30-shell-stream)" || return 2
    scanner_u30_shell_expand_file "$logical_path" "$home_path" 0 "" "$stream_file" || expansion_status=$?
    [ "$expansion_status" -ne 2 ] || return 2
    [ "$expansion_status" -eq 0 ] || return 0
    awk -F '\t' -v scope="$scope" '
        function trim(value) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            return value
        }
        function remember_conditional(value, origin, certainty) {
            conditional_count++
            conditional_value[conditional_count]=value
            conditional_source[conditional_count]=origin
            conditional_certainty[conditional_count]=certainty
        }
        {
            source=$1
            source_line=$2
            prefix=source FS source_line FS
            line=substr($0, length(prefix) + 1)
            origin=source ":" source_line
            sub(/\r$/, "", line)
            if (line == "__SCANNER_U30_UNRESOLVED_SOURCE__") {
                remember_conditional("unknown", origin, "conditional")
                next
            }
            sub(/[[:space:]]+#.*$/, "", line)
            line=trim(line)
            if (line == "" || line ~ /^#/) next

            if (line ~ /^(fi|done|esac)([;[:space:]]|$)/ && depth > 0) depth--
            if (line ~ /^}/ && function_depth > 0) function_depth--
            exact_line=line
            gsub(/[[:space:]]+[012]*>>?[^;[:space:]]+/, "", exact_line)
            exact=(exact_line ~ /^(builtin[[:space:]]+)?umask[[:space:]]+[^;[:space:]]+[[:space:]]*;?[[:space:]]*$/)
            if (exact || line ~ /(^|[^[:alnum:]_])umask[[:space:]]+[^;[:space:]]+/) {
                value=line
                sub(/^.*umask[[:space:]]+/, "", value)
                sub(/[;[:space:]].*$/, "", value)
                if (exact && depth == 0 && function_depth == 0) {
                    last_seen=1
                    last_value=value
                    last_source=origin
                    last_certainty=(value ~ /^[0-7]+$/ && length(value) <= 4 ? "resolved" : "unresolved")
                    conditional_count=0
                } else {
                    remember_conditional(value, origin, "conditional")
                }
            }

            opens=(line ~ /^(if|case|for|while|until|select)([[:space:]]|$)/ ||
                   line ~ /^\{([;[:space:]]|$)/)
            closes_inline=(line ~ /(^|[;[:space:]])(fi|done|esac)([;[:space:]]|$)/)
            if (opens && !closes_inline) depth++
            function_opens=(line ~ /^(function[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*[[:space:]]*(\(\))?[[:space:]]*\{/)
            if (function_opens && line !~ /}/) function_depth++
        }
        END {
            if (last_seen) print last_value "\t" last_source "\t" last_certainty "\t" scope "\toctal"
            for (index_value=1; index_value<=conditional_count; index_value++) {
                print conditional_value[index_value] "\t" conditional_source[index_value] \
                    "\t" conditional_certainty[index_value] "\t" scope "\toctal"
            }
        }
    ' "$stream_file"
}

scanner_u30_shell_directory_records() {
    local logical_directory="$1"
    local pattern="$2"
    local scope="$3"
    local home_path="${4:-}"
    local raw_directory="${SCAN_ROOT%/}${logical_directory}"
    local directory=""
    local candidates_file=""
    local sorted_candidates_file=""
    local file=""

    [ -e "$raw_directory" ] || [ -L "$raw_directory" ] || return 0
    directory="$(fs_path "$logical_directory" 2>/dev/null)" || return 2
    directory="$(resolve_rooted_directory "$directory" 2>/dev/null)" || return 2
    candidates_file="$(new_scratch_file u30-profile-files)" || return 2
    sorted_candidates_file="$(new_scratch_file u30-profile-files-sorted)" || return 2
    find -P "$directory" -maxdepth 1 \( -type f -o -type l \) -name "$pattern" -print0 > "$candidates_file" 2>/dev/null || return 2
    LC_ALL=C sort -z "$candidates_file" > "$sorted_candidates_file" || return 2
    while IFS= read -r -d '' file; do
        scanner_u30_shell_file_records "$(display_path "$file")" "$scope" "$home_path" || return 2
    done < "$sorted_candidates_file"
}

scanner_u30_first_user_startup_record() {
    local scope="$1"
    local home_path="$2"
    local logical_path=""
    local file=""
    local file_status=0
    shift 2

    for logical_path in "$@"; do
        file_status=0
        file="$(optional_rooted_read_path "$logical_path" 2>/dev/null)" || file_status=$?
        [ "$file_status" -ne 2 ] || return 2
        [ "$file_status" -eq 0 ] || continue
        scanner_u30_shell_file_records "$logical_path" "$scope" "$home_path" || return 2
        return 0
    done
    return 0
}

scanner_u30_ksh_env_value() {
    local logical_path="$1"
    local file=""
    local file_status=0

    file="$(optional_rooted_read_path "$logical_path" 2>/dev/null)" || file_status=$?
    [ "$file_status" -ne 2 ] || return 2
    [ "$file_status" -eq 0 ] || return 1
    awk -v source="$(display_path "$file")" '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            sub(/[[:space:]]+#.*$/, "", line)
            if (line ~ /^export[[:space:]]+ENV=/) sub(/^export[[:space:]]+/, "", line)
            else if (line ~ /^typeset[[:space:]]+-x[[:space:]]+ENV=/) sub(/^typeset[[:space:]]+-x[[:space:]]+/, "", line)
            if (line !~ /^ENV=/) next
            sub(/^ENV=/, "", line)
            sub(/[;[:space:]].*$/, "", line)
            if (line != "") last=line "\t" source ":" FNR
        }
        END {if (last != "") print last; else exit 1}
    ' "$file"
}

scanner_u30_ksh_env_records() {
    local user_name="$1"
    local home_path="$2"
    local logical_path=""
    local env_record=""
    local candidate_record=""
    local candidate_status=0
    local env_value=""
    local env_source=""
    local env_path=""

    for logical_path in /etc/profile "$home_path/.profile"; do
        candidate_status=0
        candidate_record="$(scanner_u30_ksh_env_value "$logical_path" 2>/dev/null)" || candidate_status=$?
        [ "$candidate_status" -ne 2 ] || return 2
        [ "$candidate_status" -ne 0 ] || env_record="$candidate_record"
    done
    [ -n "$env_record" ] || return 0
    env_value="$(scanner_value_only "$env_record")"
    env_source="$(scanner_source_only "$env_record")"
    env_path="$(scanner_u30_normalize_shell_source_path "$env_value" "$home_path" 2>/dev/null)" || {
        printf 'unknown\t%s\tconditional\tuser:%s:ksh-interactive\toctal\n' "$env_source" "$user_name"
        return 0
    }
    scanner_u30_shell_file_records "$env_path" "user:${user_name}:ksh-interactive" "$home_path"
}

scanner_u30_user_shell_records() {
    local passwd_file=""
    local passwd_status=0
    local user_name=""
    local home_path=""
    local shell_path=""

    passwd_file="$(optional_rooted_read_path /etc/passwd 2>/dev/null)" || passwd_status=$?
    [ "$passwd_status" -eq 0 ] || return 2
    scanner_validate_passwd_database "$passwd_file" || return 2
    while IFS=: read -r user_name _ _ _ _ home_path shell_path || [ -n "$user_name" ]; do
        case "$shell_path" in
            /bin/false|/usr/bin/false|/sbin/nologin|/usr/sbin/nologin|/bin/nologin) continue ;;
            '') shell_path=/bin/sh ;;
        esac
        case "$home_path" in /*) ;; *) return 2 ;; esac
        case "${shell_path##*/}" in
            bash)
                scanner_u30_first_user_startup_record "user:${user_name}:bash-login" "$home_path" \
                    "$home_path/.bash_profile" "$home_path/.bash_login" "$home_path/.profile" || return 2
                scanner_u30_shell_file_records "$home_path/.bashrc" "user:${user_name}:bash-interactive" "$home_path" || return 2
                ;;
            csh)
                scanner_u30_shell_file_records "$home_path/.cshrc" "user:${user_name}:csh-interactive" "$home_path" || return 2
                scanner_u30_shell_file_records "$home_path/.cshrc" "user:${user_name}:csh-login" "$home_path" || return 2
                scanner_u30_shell_file_records "$home_path/.login" "user:${user_name}:csh-login" "$home_path" || return 2
                ;;
            tcsh)
                scanner_u30_first_user_startup_record "user:${user_name}:tcsh-interactive" "$home_path" \
                    "$home_path/.tcshrc" "$home_path/.cshrc" || return 2
                scanner_u30_first_user_startup_record "user:${user_name}:tcsh-login" "$home_path" \
                    "$home_path/.tcshrc" "$home_path/.cshrc" || return 2
                scanner_u30_shell_file_records "$home_path/.login" "user:${user_name}:tcsh-login" "$home_path" || return 2
                ;;
            ksh|ksh93|mksh|pdksh)
                scanner_u30_shell_file_records "$home_path/.profile" "user:${user_name}:ksh-login" "$home_path" || return 2
                scanner_u30_ksh_env_records "$user_name" "$home_path" || return 2
                ;;
            zsh)
                scanner_u30_shell_file_records "$home_path/.zshenv" "user:${user_name}:zsh-all" "$home_path" || return 2
                scanner_u30_shell_file_records "$home_path/.zprofile" "user:${user_name}:zsh-login" "$home_path" || return 2
                scanner_u30_shell_file_records "$home_path/.zlogin" "user:${user_name}:zsh-login" "$home_path" || return 2
                scanner_u30_shell_file_records "$home_path/.zshrc" "user:${user_name}:zsh-interactive" "$home_path" || return 2
                ;;
            fish)
                scanner_u30_shell_directory_records "$home_path/.config/fish/conf.d" '*.fish' "user:${user_name}:fish" "$home_path" || return 2
                scanner_u30_shell_file_records "$home_path/.config/fish/config.fish" "user:${user_name}:fish" "$home_path" || return 2
                ;;
            *) scanner_u30_shell_file_records "$home_path/.profile" "user:${user_name}:profile" "$home_path" || return 2 ;;
        esac
    done < "$passwd_file"
}

scanner_u30_global_nonbash_records() {
    local zsh_directory=""

    scanner_u30_shell_file_records /etc/csh.cshrc global:csh-interactive || return 2
    scanner_u30_shell_file_records /etc/csh.cshrc global:csh-login || return 2
    scanner_u30_shell_file_records /etc/csh.login global:csh-login || return 2

    if platform_is_debian_family; then zsh_directory=/etc/zsh
    elif platform_is_rhel_family; then zsh_directory=/etc
    else return 2
    fi
    scanner_u30_shell_file_records "$zsh_directory/zshenv" global:zsh-all || return 2
    scanner_u30_shell_file_records "$zsh_directory/zprofile" global:zsh-login || return 2
    scanner_u30_shell_file_records "$zsh_directory/zlogin" global:zsh-login || return 2
    scanner_u30_shell_file_records "$zsh_directory/zshrc" global:zsh-interactive || return 2

    scanner_u30_shell_directory_records /usr/share/fish/vendor_conf.d '*.fish' global:fish || return 2
    scanner_u30_shell_directory_records /etc/fish/conf.d '*.fish' global:fish || return 2
    scanner_u30_shell_file_records /etc/fish/config.fish global:fish || return 2
}

scanner_umask_records() {
    scanner_u30_shell_file_records /etc/profile global:posix-login || return 2
    if platform_is_debian_family; then
        scanner_u30_shell_file_records /etc/bash.bashrc global:bash-interactive || return 2
    elif platform_is_rhel_family; then
        scanner_u30_shell_file_records /etc/bashrc global:bash-interactive || return 2
    else
        return 2
    fi
    scanner_u30_global_nonbash_records || return 2
    scanner_u30_user_shell_records || return 2
}

scanner_u30_pam_service_names() {
    if platform_is_debian_family; then
        printf '%s\n' login common-session common-session-noninteractive
    elif platform_is_rhel_family; then
        printf '%s\n' postlogin system-auth password-auth
    else
        return 2
    fi
}

scanner_u30_pam_umask_lines() {
    local service=""
    local service_file=""
    local service_status=0
    local expanded_file=""
    local expanded_status=0
    local records_file=""
    local service_records_file=""
    local found_modules=0

    records_file="$(new_scratch_file u30-pam-lines)" || return 2
    : > "$records_file"
    while IFS= read -r service; do
        service_status=0
        service_file="$(pam_service_file "$service" 2>/dev/null)" || service_status=$?
        [ "$service_status" -ne 2 ] || return 2
        [ "$service_status" -eq 0 ] || continue
        expanded_file="$(new_scratch_file u30-pam-expanded)" || return 2
        expanded_status=0
        pam_expand_service "$service" session > "$expanded_file" || expanded_status=$?
        [ "$expanded_status" -ne 2 ] || return 2
        service_records_file="$(new_scratch_file u30-pam-service-records)" || return 2
        : > "$service_records_file"
        if [ "$expanded_status" -ne 0 ]; then
            printf '%s\t%s\t%s\n' "$service" "$(display_path "$service_file")" '__SCANNER_U30_NO_PAM_UMASK__' >> "$records_file" || return 2
            continue
        fi
        awk -v service="$service" -F '\t' '
            {
                source=$1
                line=substr($0, length(source) + 2)
                count=split(line, fields, /[[:space:]]+/)
                for (index_value=1; index_value<=count; index_value++) {
                    module=tolower(fields[index_value])
                    sub(/^.*\//, "", module)
                    if (module == "pam_umask.so") {
                        print service "\t" source "\t" line
                        break
                    }
                }
            }
        ' "$expanded_file" > "$service_records_file" || return 2
        if [ -s "$service_records_file" ]; then
            cat "$service_records_file" >> "$records_file" || return 2
            found_modules=$((found_modules + 1))
        else
            printf '%s\t%s\t%s\n' "$service" "$(display_path "$service_file")" '__SCANNER_U30_NO_PAM_UMASK__' >> "$records_file" || return 2
        fi
    done < <(scanner_u30_pam_service_names)

    [ "$found_modules" -gt 0 ] || return 1
    awk '!seen[$0]++' "$records_file"
}

scanner_u30_pam_module_options() {
    local line="$1"

    awk -v line="$line" 'BEGIN {
        count=split(line, fields, /[[:space:]]+/)
        module_index=0
        for (index_value=1; index_value<=count; index_value++) {
            module=tolower(fields[index_value])
            sub(/^.*\//, "", module)
            if (module == "pam_umask.so") {module_index=index_value; break}
        }
        if (module_index == 0) exit 2
        has_mask=0
        mask=""
        usergroups="default"
        for (index_value=module_index + 1; index_value<=count; index_value++) {
            option=tolower(fields[index_value])
            if (option ~ /^umask=/) {
                has_mask=1
                mask=substr(fields[index_value], index(fields[index_value], "=") + 1)
            } else if (option == "usergroups") {
                usergroups="on"
            } else if (option == "nousergroups") {
                usergroups="off"
            }
        }
        print has_mask "\t" mask "\t" usergroups
    }'
}

scanner_u30_build_usergroups_default() {
    case "$PLATFORM_BASE_ID:$PLATFORM_BASE_VERSION" in
        debian:13|ubuntu:24.04|ubuntu:26.04) printf 'on\n' ;;
        *) printf 'off\n' ;;
    esac
}

scanner_u30_gecos_umask() {
    local gecos="$1"

    awk -v gecos="$gecos" 'BEGIN {
        count=split(gecos, fields, ",")
        found=0
        for (index_value=1; index_value<=count; index_value++) {
            if (tolower(substr(fields[index_value], 1, 6)) == "umask=") {
                value=substr(fields[index_value], 7)
                found=1
            }
        }
        if (!found) exit 1
        print value
    }'
}

scanner_u30_usergroup_mask() {
    local value="$1"
    local decimal_value=""

    decimal_value="$(mode_to_decimal "$value" 2>/dev/null)" || return 2
    [ "$decimal_value" -le $((0777)) ] || return 2
    printf '%03o\n' "$(((decimal_value & ~0070) | ((decimal_value >> 3) & 0070)))"
}

scanner_u30_pam_records() {
    local lines_file=""
    local lines_status=0
    local passwd_file=""
    local passwd_status=0
    local group_file=""
    local group_status=0
    local service=""
    local pam_source=""
    local pam_line=""
    local options=""
    local has_module_mask=""
    local module_mask=""
    local configured_usergroups=""
    local base_record=""
    local base_value=""
    local base_source=""
    local base_origin=""
    local usergroups=""
    local usergroups_record=""
    local user_name=""
    local user_uid=""
    local user_gid=""
    local gecos=""
    local shell_path=""
    local gecos_value=""
    local gecos_status=0
    local effective_value=""
    local effective_source=""
    local certainty=""
    local group_name=""
    local line_number=0
    local emitted=0

    lines_file="$(new_scratch_file u30-pam-records)" || return 2
    scanner_u30_pam_umask_lines > "$lines_file" || lines_status=$?
    [ "$lines_status" -ne 2 ] || return 2
    [ "$lines_status" -eq 0 ] || return 1
    passwd_file="$(optional_rooted_read_path /etc/passwd 2>/dev/null)" || passwd_status=$?
    [ "$passwd_status" -eq 0 ] || return 2
    scanner_validate_passwd_database "$passwd_file" || return 2

    while IFS=$'\t' read -r service pam_source pam_line; do
        if [ "$pam_line" = '__SCANNER_U30_NO_PAM_UMASK__' ]; then
            printf 'unknown\t%s\tconditional\tpam:%s:module\toctal\n' "$pam_source" "$service"
            emitted=$((emitted + 1))
            continue
        fi
        options="$(scanner_u30_pam_module_options "$pam_line")" || return 2
        IFS=$'\t' read -r has_module_mask module_mask configured_usergroups <<< "$options"
        if [ "$has_module_mask" -eq 1 ]; then
            base_value="$module_mask"
            base_source="$pam_source"
            base_origin=module
        else
            base_record=""
            if ! scanner_capture_optional_value base_record pam_login_defs_value UMASK; then return 2; fi
            if [ -z "$base_record" ]; then
                if ! scanner_capture_optional_value base_record pam_default_login_value UMASK; then return 2; fi
            fi
            if [ -n "$base_record" ]; then
                base_value="$(scanner_value_only "$base_record")"
                base_source="$(scanner_source_only "$base_record")"
                case "$base_source" in
                    */login.defs:*|*/login.defs.d/*) base_origin=login_defs ;;
                    *) base_origin=default_login ;;
                esac
            else
                base_value="missing"
                base_source="pam_umask:no-source"
                base_origin=missing
            fi
        fi

        usergroups="$(scanner_u30_build_usergroups_default)"
        [ "$configured_usergroups" = default ] || usergroups="$configured_usergroups"
        if [ "$PLATFORM_BASE_ID" = ubuntu ] && [ "$base_origin" = login_defs ]; then
            usergroups_record=""
            if ! scanner_capture_optional_value usergroups_record pam_login_defs_value USERGROUPS_ENAB; then return 2; fi
            if [ -n "$usergroups_record" ]; then
                case "$(scanner_value_only "$usergroups_record" | tr '[:upper:]' '[:lower:]')" in
                    yes) usergroups=on ;;
                    *) usergroups=off ;;
                esac
            fi
        fi

        group_file=""
        if [ "$usergroups" = on ]; then
            group_status=0
            group_file="$(optional_rooted_read_path /etc/group 2>/dev/null)" || group_status=$?
            [ "$group_status" -eq 0 ] || return 2
            scanner_validate_group_database "$group_file" || return 2
        fi

        line_number=0
        while IFS=: read -r user_name _ user_uid user_gid gecos _ shell_path || [ -n "$user_name" ]; do
            line_number=$((line_number + 1))
            case "$shell_path" in
                /bin/false|/usr/bin/false|/sbin/nologin|/usr/sbin/nologin|/bin/nologin) continue ;;
            esac
            gecos_status=0
            gecos_value="$(scanner_u30_gecos_umask "$gecos")" || gecos_status=$?
            if [ "$gecos_status" -eq 0 ]; then
                effective_value="$gecos_value"
                effective_source="/etc/passwd:${line_number}"
            else
                effective_value="$base_value"
                effective_source="$base_source"
                if [ "$usergroups" = on ] && [ "$user_uid" -ne 0 ] && [ "$effective_value" != missing ]; then
                    group_name="$(awk -F: -v gid="$user_gid" '$3 == gid {print $1; exit}' "$group_file")"
                    if [ "$group_name" = "$user_name" ]; then
                        effective_value="$(scanner_u30_usergroup_mask "$effective_value" 2>/dev/null)" || {
                            printf '%s\t%s\tunresolved\tpam:%s:%s\toctal\n' \
                                "$base_value" "$effective_source" "$service" "$user_name"
                            emitted=$((emitted + 1))
                            continue
                        }
                        effective_source="${effective_source}+usergroups"
                    fi
                fi
            fi
            certainty=resolved
            [ "$effective_value" != missing ] || certainty=resolved
            printf '%s\t%s\t%s\tpam:%s:%s\toctal\n' \
                "$effective_value" "$effective_source" "$certainty" "$service" "$user_name"
            emitted=$((emitted + 1))
        done < "$passwd_file"
    done < "$lines_file"

    [ "$emitted" -gt 0 ] || return 2
}

scanner_u30_vsftpd_records() {
    local logical_path=""
    local file=""
    local file_status=0

    if platform_is_debian_family; then logical_path=/etc/vsftpd.conf
    elif platform_is_rhel_family; then logical_path=/etc/vsftpd/vsftpd.conf
    else return 2
    fi
    file="$(optional_rooted_read_path "$logical_path" 2>/dev/null)" || file_status=$?
    [ "$file_status" -ne 2 ] || return 2
    if [ "$file_status" -eq 1 ]; then
        printf '077\tvsftpd-built-in-default\tresolved\tftp:vsftpd\tvsftpd\n'
        return 0
    fi
    awk -v source="$(display_path "$file")" '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            sub(/[[:space:]]+#.*$/, "", line)
            separator=index(line, "=")
            if (separator == 0) next
            name=tolower(substr(line, 1, separator - 1))
            value=substr(line, separator + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (name == "local_umask") {mask=value; mask_line=FNR; found=1}
            if (name == "user_config_dir" && value != "") {user_config=value; user_config_line=FNR}
        }
        END {
            if (found) print mask "\t" source ":" mask_line "\tresolved\tftp:vsftpd\tvsftpd"
            else print "077\tvsftpd-built-in-default\tresolved\tftp:vsftpd\tvsftpd"
            if (user_config != "") print "unknown\t" source ":" user_config_line "\tconditional\tftp:vsftpd\tvsftpd"
        }
    ' "$file"
}

scanner_u30_proftpd_records() {
    local logical_path=""
    local file=""
    local file_status=0

    if platform_is_debian_family; then logical_path=/etc/proftpd/proftpd.conf
    elif platform_is_rhel_family; then logical_path=/etc/proftpd.conf
    else return 2
    fi
    file="$(optional_rooted_read_path "$logical_path" 2>/dev/null)" || file_status=$?
    [ "$file_status" -ne 2 ] || return 2
    if [ "$file_status" -eq 1 ]; then
        printf 'missing\t%s\tresolved\tftp:proftpd:file\tmissing\n' "$logical_path"
        return 0
    fi
    awk -v source="$(display_path "$file")" '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            sub(/[[:space:]]+#.*$/, "", line)
            if (tolower(line) ~ /^include(options)?[[:space:]]/) {
                include_line=FNR
                next
            }
            if (line ~ /^<\//) {if (depth > 0) depth--; next}
            if (line ~ /^</) {depth++; next}
            count=split(line, fields, /[[:space:]]+/)
            if (tolower(fields[1]) != "umask") next
            directory_mask=(fields[3] == "" ? fields[2] : fields[3])
            if (depth == 0) {
                file_mask=fields[2]
                directory_value=directory_mask
                mask_line=FNR
                found=1
            } else {
                conditional_count++
                conditional_file[conditional_count]=fields[2]
                conditional_directory[conditional_count]=directory_mask
                conditional_line[conditional_count]=FNR
            }
        }
        END {
            if (found) {
                print file_mask "\t" source ":" mask_line "\tresolved\tftp:proftpd:file\toctal"
                print directory_value "\t" source ":" mask_line "\tresolved\tftp:proftpd:directory\toctal"
            } else {
                print "missing\t" source "\tresolved\tftp:proftpd:file\tmissing"
            }
            for (index_value=1; index_value<=conditional_count; index_value++) {
                print conditional_file[index_value] "\t" source ":" conditional_line[index_value] \
                    "\tconditional\tftp:proftpd:file\toctal"
                print conditional_directory[index_value] "\t" source ":" conditional_line[index_value] \
                    "\tconditional\tftp:proftpd:directory\toctal"
            }
            if (include_line > 0) print "unknown\t" source ":" include_line "\tconditional\tftp:proftpd\toctal"
        }
    ' "$file"
}

scanner_u30_ftp_records() {
    local provider=""

    declare -F service_detect_ftp >/dev/null 2>&1 || return 2
    service_detect_ftp
    for provider in $SERVICE_FTP_PROVIDERS; do
        case "$provider" in
            vsftpd) scanner_u30_vsftpd_records || return 2 ;;
            proftpd) scanner_u30_proftpd_records || return 2 ;;
            *) printf 'unknown\tftp-provider:%s\tconditional\tftp:%s\toctal\n' "$provider" "$provider" ;;
        esac
    done
    if [ "${SERVICE_FTP_UNCERTAIN:-0}" -eq 1 ] && { runtime_enabled || [ -n "$SERVICE_FTP_PROVIDERS" ]; }; then
        printf 'unknown\tftp-activation\tconditional\tftp:activation\toctal\n'
    fi
}

scanner_u30_value_state() {
    local value="$1"
    local value_kind="$2"
    local decimal_value=""

    case "$value_kind" in
        missing) return 1 ;;
        octal)
            decimal_value="$(mode_to_decimal "$value" 2>/dev/null)" || return 2
            ;;
        vsftpd)
            case "$value" in
                0) decimal_value=0 ;;
                0[0-7]*) decimal_value="$(mode_to_decimal "$value" 2>/dev/null)" || return 2 ;;
                0*) return 2 ;;
                ''|*[!0-9]*) return 2 ;;
                *)
                    [ "${#value}" -le 10 ] || return 2
                    decimal_value=$((10#$value))
                    ;;
            esac
            ;;
        *) return 2 ;;
    esac
    [ "$decimal_value" -le $((0777)) ] || return 2
    [ $((decimal_value & 0022)) -eq $((0022)) ] && return 0
    return 1
}

check_u_30() {
    local records_file=""
    local unique_records_file=""
    local collector_status=0
    local pam_status=0
    local record=""
    local value=""
    local source=""
    local certainty=""
    local scope=""
    local value_kind=""
    local login_record=""
    local value_status=0
    local evidence=""
    local global_records=0
    local good_scopes=0
    local vulnerable_scopes=0
    local manual_scopes=0
    local scope_name=""
    declare -A scope_safe=()
    declare -A scope_weak=()
    declare -A scope_uncertain=()

    records_file="$(new_scratch_file u30-records)" || {
        set_result ERROR "UMASK 점검용 임시 파일을 만들지 못했습니다." "setting=UMASK"
        return
    }
    scanner_umask_records > "$records_file" || collector_status=$?
    [ "$collector_status" -eq 0 ] || {
        set_result ERROR "셸 UMASK 설정 경로를 안전하게 해석하지 못했습니다." "setting=UMASK"
        return
    }

    scanner_u30_pam_records >> "$records_file" || pam_status=$?
    if [ "$pam_status" -eq 1 ]; then
        if ! scanner_capture_optional_value login_record login_defs_value UMASK; then
            set_result ERROR "UMASK 로그인 기본값 경로를 안전하게 해석하지 못했습니다." "setting=UMASK"
            return
        fi
        if [ -z "$login_record" ]; then
            if ! scanner_capture_optional_value login_record pam_default_login_value UMASK; then
                set_result ERROR "UMASK 로그인 기본값 경로를 안전하게 해석하지 못했습니다." "setting=UMASK"
                return
            fi
        fi
        if [ -n "$login_record" ]; then
            printf '%s\t%s\tresolved\tglobal:login\toctal\n' \
                "$(scanner_value_only "$login_record")" "$(scanner_source_only "$login_record")" >> "$records_file"
        fi
    elif [ "$pam_status" -ne 0 ]; then
        set_result ERROR "PAM UMASK 적용 경로를 안전하게 해석하지 못했습니다." "setting=UMASK"
        return
    fi

    collector_status=0
    scanner_u30_ftp_records >> "$records_file" || collector_status=$?
    [ "$collector_status" -eq 0 ] || {
        set_result ERROR "FTP UMASK 적용 경로를 안전하게 해석하지 못했습니다." "setting=UMASK"
        return
    }

    unique_records_file="$(new_scratch_file u30-records-unique)" || {
        set_result ERROR "셸 UMASK 설정 경로를 안전하게 해석하지 못했습니다." "setting=UMASK,normalization=scratch_unavailable"
        return
    }
    awk '!seen[$0]++' "$records_file" > "$unique_records_file" || {
        set_result ERROR "셸 UMASK 설정 경로를 안전하게 해석하지 못했습니다." "setting=UMASK,normalization=failed"
        return
    }
    records_file="$unique_records_file"

    while IFS=$'\t' read -r value source certainty scope value_kind; do
        [ -n "$scope" ] || continue
        case "$scope" in global:*|pam:*) global_records=$((global_records + 1)) ;; esac
        scanner_append_evidence evidence "umask=${value},source=${source},scope=${scope},certainty=${certainty}"
        case "$certainty" in
            conditional)
                scope_uncertain["$scope"]=1
                continue
                ;;
            unresolved)
                scope_safe["$scope"]=0
                scope_weak["$scope"]=0
                scope_uncertain["$scope"]=1
                continue
                ;;
            resolved)
                scope_safe["$scope"]=0
                scope_weak["$scope"]=0
                scope_uncertain["$scope"]=0
                ;;
            *)
                scope_uncertain["$scope"]=1
                continue
                ;;
        esac
        value_status=0
        scanner_u30_value_state "$value" "$value_kind" || value_status=$?
        case "$value_status" in
            0) scope_safe["$scope"]=1 ;;
            1) scope_weak["$scope"]=1 ;;
            *) scope_uncertain["$scope"]=1 ;;
        esac
    done < "$records_file"
    for scope_name in "${!scope_weak[@]}"; do
        [ "${scope_weak[$scope_name]:-0}" -eq 1 ] && vulnerable_scopes=$((vulnerable_scopes + 1))
    done
    for scope_name in "${!scope_uncertain[@]}"; do
        [ "${scope_uncertain[$scope_name]:-0}" -eq 1 ] && manual_scopes=$((manual_scopes + 1))
    done
    for scope_name in "${!scope_safe[@]}"; do
        [ "${scope_safe[$scope_name]:-0}" -eq 1 ] && good_scopes=$((good_scopes + 1))
    done
    scanner_append_evidence evidence "global_records=${global_records}"
    scanner_append_evidence evidence "safe_scopes=${good_scopes},weak_scopes=${vulnerable_scopes},conditional_scopes=${manual_scopes}"

    if [ "$global_records" -eq 0 ]; then
        set_result VULNERABLE "시스템 전역 UMASK 설정을 확인하지 못했습니다." "$evidence"
    elif [ "$vulnerable_scopes" -gt 0 ]; then
        set_result VULNERABLE "022보다 약한 유효 UMASK 적용 경로가 존재합니다." "$evidence"
    elif [ "$manual_scopes" -gt 0 ]; then
        set_result MANUAL "조건부 또는 충돌하는 UMASK 적용 순서를 확인해야 합니다." "$evidence"
    elif [ "$good_scopes" -gt 0 ]; then
        set_result GOOD "확인된 시스템·사용자·활성 FTP UMASK 적용 경로가 022 이상입니다." "$evidence"
    else
        set_result VULNERABLE "시스템 전역 UMASK 설정을 확인하지 못했습니다." "$evidence"
    fi
}

check_u_31() {
    local passwd_file=""
    local user_name=""
    local user_uid=""
    local home_path=""
    local path=""
    local owner_uid=""
    local mode=""
    local scanned=0
    local violations=0
    local errors=0
    local evidence=""
    local database_status=0

    passwd_file="$(fs_path /etc/passwd)"
    [ -r "$passwd_file" ] || {
        set_result ERROR "/etc/passwd를 읽을 수 없습니다." "path=/etc/passwd"
        return
    }
    scanner_validate_passwd_database "$passwd_file"
    database_status=$?
    if [ "$database_status" -ne 0 ]; then
        set_result ERROR "/etc/passwd 계정 데이터가 비어 있거나 올바르지 않습니다." "path=/etc/passwd,status=${database_status}"
        return
    fi
    while IFS=: read -r user_name _ user_uid _ _ home_path _; do
        case "$home_path" in
            /*) ;;
            *)
                errors=$((errors + 1))
                [ "$errors" -le 20 ] && scanner_append_evidence evidence "account=${user_name},home=${home_path:-unset},path_error=true"
                continue
                ;;
        esac
        path="$(fs_path "$home_path" 2>/dev/null || true)"
        if [ -z "$path" ]; then
            errors=$((errors + 1))
            continue
        fi
        [ -d "$path" ] || continue
        scanned=$((scanned + 1))
        owner_uid="$(stat_uid "$path" 2>/dev/null || true)"
        mode="$(stat_mode "$path" 2>/dev/null || true)"
        if [ -z "$owner_uid" ] || [ -z "$mode" ]; then
            errors=$((errors + 1))
        elif [ "$owner_uid" != "$user_uid" ] || mode_other_writable "$mode"; then
            violations=$((violations + 1))
            [ "$violations" -le 20 ] && scanner_append_evidence evidence "$(scanner_evidence_path "$path"):owner_uid=${owner_uid},expected_uid=${user_uid},mode=${mode}"
        fi
    done < "$passwd_file"
    evidence="scanned_homes=${scanned}
violations=${violations}
metadata_errors=${errors}
${evidence}"
    if [ "$errors" -gt 0 ]; then
        set_result ERROR "일부 홈 디렉터리의 메타데이터를 확인하지 못했습니다." "$evidence"
    elif [ "$violations" -gt 0 ]; then
        set_result VULNERABLE "계정 소유가 아니거나 other 쓰기가 허용된 홈 디렉터리가 있습니다." "$evidence"
    else
        set_result GOOD "존재하는 홈 디렉터리는 해당 계정 소유이며 other 쓰기가 차단되어 있습니다." "$evidence"
    fi
}

check_u_32() {
    local passwd_file=""
    local user_name=""
    local home_path=""
    local path=""
    local missing=0
    local checked=0
    local errors=0
    local evidence=""
    local database_status=0
    local path_status=0

    passwd_file="$(fs_path /etc/passwd)"
    [ -r "$passwd_file" ] || {
        set_result ERROR "/etc/passwd를 읽을 수 없습니다." "path=/etc/passwd"
        return
    }
    scanner_validate_passwd_database "$passwd_file"
    database_status=$?
    if [ "$database_status" -ne 0 ]; then
        set_result ERROR "/etc/passwd 계정 데이터가 비어 있거나 올바르지 않습니다." "path=/etc/passwd,status=${database_status}"
        return
    fi
    while IFS=: read -r user_name _ _ _ _ home_path _; do
        checked=$((checked + 1))
        case "$home_path" in
            /*) ;;
            *)
                missing=$((missing + 1))
                [ "$missing" -le 20 ] && scanner_append_evidence evidence "account=${user_name},home=${home_path:-unset}"
                continue
                ;;
        esac
        path_status=0
        path="$(fs_path "$home_path" 2>/dev/null)" || path_status=$?
        if [ "$path_status" -ne 0 ]; then
            errors=$((errors + 1))
            [ "$errors" -le 20 ] && scanner_append_evidence evidence "account=${user_name},home=${home_path},path_error=true"
            continue
        fi
        if [ ! -d "$path" ]; then
            missing=$((missing + 1))
            [ "$missing" -le 20 ] && scanner_append_evidence evidence "account=${user_name},home=${home_path}"
        fi
    done < "$passwd_file"
    evidence="configured_homes_checked=${checked}
missing_configured_homes=${missing}
path_errors=${errors}
${evidence}"
    if [ "$errors" -gt 0 ]; then
        set_result ERROR "일부 홈 디렉터리 경로를 안전하게 해석하지 못했습니다." "$evidence"
    elif [ "$missing" -gt 0 ]; then
        set_result VULNERABLE "/etc/passwd에 설정된 홈 디렉터리가 없는 계정이 있습니다." "$evidence"
    else
        set_result GOOD "/etc/passwd에 설정된 모든 계정의 홈 디렉터리가 존재합니다." "$evidence"
    fi
}

check_u_33() {
    local evidence=""

    scanner_collect_full_filesystem_facts
    if [ "$SCANNER_FULL_FILESYSTEM_SCRATCH_ERROR" -gt 0 ]; then
        set_result ERROR "숨김 경로 목록을 저장할 임시 파일을 만들지 못했습니다."
        return
    fi
    if [ "$SCANNER_FULL_FILESYSTEM_ROOT_STATUS" -ne 0 ]; then
        set_result ERROR "로컬 파일시스템 목록을 완전하게 수집하지 못했습니다." "scope=/,xdev=true"
        return
    fi
    if [ "$SCANNER_FULL_FILESYSTEM_SCAN_ERRORS" -gt 0 ]; then
        scanner_full_filesystem_error_evidence_into evidence
        scanner_note_offline_access_context
        set_result ERROR "루트 파일시스템의 숨김 경로 검색을 완료하지 못했습니다." "$evidence"
        return
    fi
    evidence="hidden_paths=${SCANNER_FULL_FILESYSTEM_U33_COUNT}
${SCANNER_FULL_FILESYSTEM_U33_EVIDENCE}"
    if [ "$SCANNER_FULL_FILESYSTEM_U33_COUNT" -eq 0 ]; then
        if [ "$SCAN_ROOT" != "/" ]; then
            set_result MANUAL "오프라인 루트의 하위 마운트 경계를 확인할 수 없어 숨김 경로 검색 완료를 확정할 수 없습니다." "$evidence"
        else
            set_result GOOD "검사한 파일시스템에서 숨김 파일·디렉터리를 찾지 못했습니다." "$evidence"
        fi
    else
        set_result MANUAL "숨김 파일·디렉터리의 업무 필요성과 무결성을 확인해야 합니다." "$evidence"
    fi
}
