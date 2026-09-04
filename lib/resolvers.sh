# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash

# shellcheck disable=SC2016

# Configuration resolvers preserve subsystem-specific precedence and provenance.

SCAN_EPOCH="${SCAN_EPOCH:-0}"
SCAN_EPOCH_ACTIVE="${SCAN_EPOCH_ACTIVE:-0}"
RESOLVER_CACHE_EPOCH=""
SYSCTL_STATIC_NAMESPACE="${SYSCTL_STATIC_NAMESPACE:-filesystem}"

declare -gA SYSCTL_SNAPSHOT_READY=()
declare -gA SYSCTL_SNAPSHOT_STATUS=()
declare -gA SYSCTL_EXACT_TYPE=()
declare -gA SYSCTL_EXACT_VALUE=()
declare -gA SYSCTL_EXACT_SOURCE=()
declare -gA SYSCTL_GLOB_FILE=()
declare -gA SYSCTL_QUERY_READY=()
declare -gA SYSCTL_QUERY_STATUS=()
declare -gA SYSCTL_QUERY_VALUE=()
declare -gA SYSCTL_RUNTIME_READY=()
declare -gA SYSCTL_RUNTIME_STATUS=()
declare -gA SYSCTL_RUNTIME_VALUE=()

SYSTEMD_CACHE_EPOCH=""
SYSTEMD_CACHE_SCRATCH_DIR=""
SYSTEMD_CACHE_RESET_SEQUENCE=0
SYSTEMD_CACHE_NAMESPACE=""
SYSTEMD_CACHE_FACTS=""
SYSTEMD_CACHE_COMMAND_STATUS=2
SYSTEMD_BULK_STATUS=2
SYSTEMD_PROPERTIES_COMMAND_STATUS=2

LISTENER_CACHE_EPOCH=""
LISTENER_CACHE_SCRATCH_DIR=""
LISTENER_CACHE_RESET_SEQUENCE=0
LISTENER_CACHE_NAMESPACE=""
LISTENER_CACHE_COMMAND_STATUS=2
LISTENER_CACHE_FACTS_FILE=""

resolver_debug_emit() {
    [ "${DEBUG:-0}" = "1" ] || return 0
    declare -F debug_emit >/dev/null 2>&1 || return 0
    debug_emit "$@" || :
}

resolver_reset_epoch_caches() {
    SYSCTL_SNAPSHOT_READY=()
    SYSCTL_SNAPSHOT_STATUS=()
    SYSCTL_EXACT_TYPE=()
    SYSCTL_EXACT_VALUE=()
    SYSCTL_EXACT_SOURCE=()
    SYSCTL_GLOB_FILE=()
    SYSCTL_QUERY_READY=()
    SYSCTL_QUERY_STATUS=()
    SYSCTL_QUERY_VALUE=()
    SYSCTL_RUNTIME_READY=()
    SYSCTL_RUNTIME_STATUS=()
    SYSCTL_RUNTIME_VALUE=()
    RESOLVER_CACHE_EPOCH="${SCAN_EPOCH:-0}"
}

sysctl_reset_epoch_cache() {
    resolver_reset_epoch_caches
}

resolver_ensure_epoch_cache() {
    local current_epoch="${SCAN_EPOCH:-0}"

    case "${SCAN_EPOCH_ACTIVE:-0}" in
        0) return 0 ;;
        1) ;;
        *) return 2 ;;
    esac
    case "$current_epoch" in ''|*[!0-9]*) return 2 ;; esac
    if [ "$RESOLVER_CACHE_EPOCH" != "$current_epoch" ]; then
        resolver_reset_epoch_caches
    fi
}

new_scratch_file() {
    local name="$1"
    local candidate=""
    local attempt=0
    local noclobber_was_set=0

    case "$name" in
        ''|*/*|*$'\n'*|*$'\r'*|*$'\t'*) return 2 ;;
    esac
    [ -n "$SCRATCH_DIR" ] && [ -d "$SCRATCH_DIR" ] && [ ! -L "$SCRATCH_DIR" ] || return 2

    case $- in
        *C*) noclobber_was_set=1 ;;
    esac
    set -C
    while [ "$attempt" -lt 64 ]; do
        candidate="$SCRATCH_DIR/${name}.${BASHPID}.${RANDOM}.${attempt}"
        if : 2>/dev/null > "$candidate"; then
            [ "$noclobber_was_set" -eq 1 ] || set +C
            printf '%s\n' "$candidate"
            return 0
        fi
        attempt=$((attempt + 1))
    done
    [ "$noclobber_was_set" -eq 1 ] || set +C
    return 1
}

select_layered_files() {
    local suffix="$1"
    shift
    local selection_file=""
    local directory=""
    local physical_directory=""
    local candidate=""
    local basename_value=""
    local candidate_file=""
    local unresolved_directory=""
    local sorted_selection_file=""
    local -a physical_directories=()
    declare -A selected_basenames=()

    selection_file="$(new_scratch_file layered)" || return 1

    for directory in "$@"; do
        physical_directory="$(fs_path "$directory" 2>/dev/null)" || {
            if [ "$SCAN_ROOT" != "/" ]; then
                unresolved_directory="${SCAN_ROOT%/}$directory"
                [ -e "$unresolved_directory" ] || [ -L "$unresolved_directory" ] || continue
                return 2
            fi
            return 2
        }
        [ -d "$physical_directory" ] || continue
        [ -r "$physical_directory" ] && [ -x "$physical_directory" ] || return 2
        physical_directories+=("$physical_directory")
    done

    if [ "${#physical_directories[@]}" -gt 0 ]; then
        candidate_file="$(new_scratch_file layered-candidates)" || return 1
        find -P "${physical_directories[@]}" -maxdepth 1 \( -type f -o -type l \) \
            -name "*${suffix}" -print0 > "$candidate_file" 2>/dev/null || return 2
        while IFS= read -r -d '' candidate; do
            basename_value="${candidate##*/}"
            case "$basename_value" in
                *$'\n'*|*$'\t'*) return 2 ;;
            esac
            if [ "${selected_basenames[$basename_value]+present}" != "present" ]; then
                selected_basenames["$basename_value"]=1
                printf '%s\t%s\n' "$basename_value" "$candidate" >> "$selection_file" || return 1
            fi
        done < "$candidate_file"
    fi

    sorted_selection_file="$(new_scratch_file layered-sorted)" || return 1
    LC_ALL=C sort -t $'\t' -k1,1 "$selection_file" > "$sorted_selection_file" || return 1
    while IFS=$'\t' read -r basename_value candidate || [ -n "$basename_value$candidate" ]; do
        [ -n "$basename_value" ] || continue
        printf '%s\n' "$candidate"
    done < "$sorted_selection_file"
}

assignment_from_files_last_wins() {
    local key="$1"
    shift
    local file=""
    local match=""
    local last_match=""

    for file in "$@"; do
        [ -r "$file" ] || continue
        match="$(awk -v target="$key" '
            {
                raw = $0
                sub(/^[[:space:]]+/, "", raw)
                if (raw == "" || raw ~ /^[#;]/) next
                sub(/[[:space:]]+[#;].*$/, "", raw)
                separator = index(raw, "=")
                if (separator > 0) {
                    name = substr(raw, 1, separator - 1)
                    value = substr(raw, separator + 1)
                } else {
                    split(raw, fields, /[[:space:]]+/)
                    name = fields[1]
                    value = substr(raw, length(name) + 1)
                }
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                if (name == target) print value "\t" FNR
            }
        ' "$file" | tail -n 1)"
        if [ -n "$match" ]; then
            last_match="${match%%"$(printf '\t')"*}\t$(display_path "$file"):${match##*"$(printf '\t')"}"
        fi
    done

    [ -n "$last_match" ] || return 1
    printf '%b\n' "$last_match"
}

login_defs_file_value() {
    local key="$1"
    local file="$2"
    local duplicate_mode="$3"
    local comment_mode="$4"

    awk -v target="$key" -v duplicate_mode="$duplicate_mode" -v comment_mode="$comment_mode" '
        {
            raw=$0
            sub(/^[[:space:]]+/, "", raw)
            if (raw == "" || raw ~ /^#/) next
            if (comment_mode == "econf") sub(/[[:space:]]*#.*/, "", raw)
            name=raw
            sub(/[[:space:]].*$/, "", name)
            if (name != target) next
            value=substr(raw, length(name) + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (duplicate_mode == "first") {
                print value "\t" FNR
                exit
            }
            last=value "\t" FNR
        }
        END {if (duplicate_mode != "first" && last != "") print last}
    ' "$file"
}

login_defs_value() {
    local key="$1"
    local file=""
    local selected_files=""
    local selected_status=0
    local resolved_file=""
    local match=""
    local last_match=""
    local file_status=0
    local econf_predecessor_present=0

    resolved_file="$(optional_rooted_read_path /etc/login.defs 2>/dev/null)" || file_status=$?
    if [ "$file_status" -eq 2 ]; then
        return 2
    elif [ "$file_status" -eq 0 ]; then
        if platform_uses_login_defs_dropins; then
            match="$(login_defs_file_value "$key" "$resolved_file" first econf)"
            econf_predecessor_present=1
        else
            match="$(login_defs_file_value "$key" "$resolved_file" last legacy)"
        fi
        [ -n "$match" ] && last_match="${match%%"$(printf '\t')"*}\t$(display_path "$resolved_file"):${match##*"$(printf '\t')"}"
    fi

    if platform_uses_login_defs_dropins; then
        selected_files="$(select_layered_files .defs /etc/login.defs.d)" || selected_status=$?
        [ "$selected_status" -eq 0 ] || return "$selected_status"
        while IFS= read -r file; do
            [ -n "$file" ] || continue
            resolved_file="$(resolve_rooted_read_path "$file" 2>/dev/null)" || return 2
            if [ "$econf_predecessor_present" -eq 1 ]; then
                match="$(login_defs_file_value "$key" "$resolved_file" last econf)"
            else
                match="$(login_defs_file_value "$key" "$resolved_file" first econf)"
            fi
            [ -n "$match" ] && last_match="${match%%"$(printf '\t')"*}\t$(display_path "$resolved_file"):${match##*"$(printf '\t')"}"
            econf_predecessor_present=1
        done <<EOF
$selected_files
EOF
    fi

    [ -n "$last_match" ] || return 1
    printf '%b\n' "$last_match"
}

pam_login_defs_file_values() {
    local key="$1"
    local file="$2"
    local key_mode="${3:-insensitive}"

    awk -v target="$key" -v key_mode="$key_mode" '
        {
            raw=$0
            sub(/^[[:space:]]+/, "", raw)
            if (raw == "" || raw ~ /^#/) next
            separator=match(raw, /[=[:space:]]/)
            if (separator == 0) next
            name=substr(raw, 1, separator - 1)
            value=substr(raw, separator + 1)
            sub(/^[=[:space:]]+/, "", value)
            sub(/#.*/, "", value)
            gsub(/[[:space:]]+$/, "", value)
            if ((key_mode == "exact" && name == target) ||
                (key_mode != "exact" && tolower(name) == tolower(target))) {
                print value "\t" FNR
            }
        }
    ' "$file"
}

pam_econf_login_defs_value() {
    local key="$1"
    shift
    local main_file=""
    local main_status=0
    local selected_files=""
    local selected_status=0
    local file=""
    local first_match=""
    local selected_record=""
    local matches=""
    local root=""
    local index_value=0
    local roots=("$@")
    local dropin_directories=()
    local root_files=""
    local basename_value=""
    declare -A selected_dropins=()

    # libeconf selects one file for each basename across all configuration
    # roots.  Select the highest-priority main file before reading any key so
    # that an administrator file also masks vendor keys it does not repeat.
    for root in "${roots[@]}"; do
        main_status=0
        file="$(optional_rooted_read_path "$root/login.defs" 2>/dev/null)" || main_status=$?
        [ "$main_status" -ne 2 ] || return 2
        if [ "$main_status" -eq 0 ]; then
            main_file="$file"
        fi
    done
    if [ -n "$main_file" ]; then
        matches="$(pam_login_defs_file_values "$key" "$main_file" exact)"
        first_match="$(printf '%s\n' "$matches" | awk 'NF {print; exit}')"
        if [ -n "$first_match" ]; then
            selected_record="${first_match%%"$(printf '\t')"*}"$'\t'"$(display_path "$main_file"):${first_match##*"$(printf '\t')"}"
        fi
    fi

    # select_layered_files expects directories from highest to lowest
    # priority.  The caller supplies libeconf roots from vendor to local.
    for ((index_value=${#roots[@]} - 1; index_value >= 0; index_value--)); do
        dropin_directories+=("${roots[index_value]}/login.defs.d")
    done
    selected_status=0
    selected_files="$(select_layered_files .defs "${dropin_directories[@]}")" || selected_status=$?
    [ "$selected_status" -eq 0 ] || return "$selected_status"
    while IFS= read -r file; do
        [ -n "$file" ] || continue
        selected_dropins["${file##*/}"]="$file"
    done <<EOF
$selected_files
EOF

    # libeconf applies vendor roots before administrator roots, while a file
    # in a higher-priority root masks only the lower file with the same name.
    for root in "${roots[@]}"; do
        selected_status=0
        root_files="$(select_layered_files .defs "$root/login.defs.d")" || selected_status=$?
        [ "$selected_status" -eq 0 ] || return "$selected_status"
        while IFS= read -r file; do
            [ -n "$file" ] || continue
            basename_value="${file##*/}"
            [ "${selected_dropins[$basename_value]:-}" = "$file" ] || continue
            file="$(resolve_rooted_read_path "$file" 2>/dev/null)" || return 2
            matches="$(pam_login_defs_file_values "$key" "$file" exact)"
            first_match="$(printf '%s\n' "$matches" | awk 'NF {print; exit}')"
            [ -n "$first_match" ] || continue
            selected_record="${first_match%%"$(printf '\t')"*}"$'\t'"$(display_path "$file"):${first_match##*"$(printf '\t')"}"
        done <<EOF
$root_files
EOF
    done

    [ -n "$selected_record" ] || return 1
    printf '%s\n' "$selected_record"
}

pam_login_defs_value() {
    local key="$1"
    local main_file=""
    local main_status=0
    local first_match=""
    local selected_record=""
    local base_major=""
    local matches=""

    if platform_is_rhel_family; then
        base_major="$(platform_base_major 2>/dev/null || true)"
    fi

    if [ "$base_major" = "9" ]; then
        pam_econf_login_defs_value "$key" /usr/share /etc
        return $?
    elif [ -n "$base_major" ] && [ "$base_major" -ge 10 ]; then
        pam_econf_login_defs_value "$key" /etc
        return $?
    fi

    main_file="$(optional_rooted_read_path /etc/login.defs 2>/dev/null)" || main_status=$?
    [ "$main_status" -ne 2 ] || return 2
    if [ "$main_status" -eq 0 ]; then
        matches="$(pam_login_defs_file_values "$key" "$main_file" insensitive)"
        first_match="$(printf '%s\n' "$matches" | awk 'NF {print; exit}')"
        if [ -n "$first_match" ]; then
            selected_record="${first_match%%"$(printf '\t')"*}"$'\t'"$(display_path "$main_file"):${first_match##*"$(printf '\t')"}"
        fi
    fi

    [ -n "$selected_record" ] || return 1
    printf '%s\n' "$selected_record"
}

pam_default_login_value() {
    local key="$1"
    local file=""
    local file_status=0
    local first_match=""
    local matches=""

    file="$(optional_rooted_read_path /etc/default/login 2>/dev/null)" || file_status=$?
    [ "$file_status" -ne 2 ] || return 2
    [ "$file_status" -eq 0 ] || return 1
    matches="$(pam_login_defs_file_values "$key" "$file")"
    first_match="$(printf '%s\n' "$matches" | awk 'NF {print; exit}')"
    [ -n "$first_match" ] || return 1
    printf '%s\t%s:%s\n' \
        "${first_match%%"$(printf '\t')"*}" \
        "$(display_path "$file")" \
        "${first_match##*"$(printf '\t')"}"
}

pwquality_files() {
    local file=""
    local selected_files=""
    local resolved_file=""
    local file_status=0

    selected_files="$(select_layered_files .conf /etc/security/pwquality.conf.d /usr/lib/security/pwquality.conf.d)" || return $?
    if [ -n "$selected_files" ]; then
        while IFS= read -r file; do
            resolved_file="$(resolve_rooted_read_path "$file" 2>/dev/null)" || return 2
            printf '%s\n' "$resolved_file"
        done <<EOF
$selected_files
EOF
    fi

    resolved_file="$(optional_rooted_read_path /etc/security/pwquality.conf 2>/dev/null)" || file_status=$?
    if [ "$file_status" -eq 2 ]; then
        return 2
    elif [ "$file_status" -eq 1 ]; then
        file_status=0
        resolved_file="$(optional_rooted_read_path /usr/lib/security/pwquality.conf 2>/dev/null)" || file_status=$?
    fi
    if [ "$file_status" -eq 2 ]; then
        return 2
    elif [ "$file_status" -eq 0 ]; then
        printf '%s\n' "$resolved_file"
    fi
}

pwquality_value() {
    local key="$1"
    local files=""
    local files_status=0

    files="$(pwquality_files)" || files_status=$?
    [ "$files_status" -eq 0 ] || return "$files_status"
    [ -n "$files" ] || return 1
    # Intentional word splitting is avoided by reading the newline-delimited list.
    local arguments_file=""
    arguments_file="$(new_scratch_file pwquality)" || return 1
    printf '%s\n' "$files" > "$arguments_file"
    while IFS= read -r file; do
        [ -n "$file" ] && printf '%s\0' "$file"
    done < "$arguments_file" |
        xargs -0 awk -v target="$key" '
            {
                raw = $0
                sub(/^[[:space:]]+/, "", raw)
                if (raw == "" || raw ~ /^#/) next
                separator = index(raw, "=")
                if (separator == 0) next
                name = substr(raw, 1, separator - 1)
                value = substr(raw, separator + 1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
                sub(/[[:space:]]+#.*$/, "", value)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                if (name == target) print value "\t" FILENAME ":" FNR
            }
        ' 2>/dev/null | tail -n 1 | awk -v root="${SCAN_ROOT%/}" -F '\t' '{path=$2; if (root != "" && root != "/" && index(path, root "/") == 1) path=substr(path,length(root)+1); print $1 "\t" path}'
}

pwquality_custom_files() {
    local logical_main="$1"
    local main_file="$2"
    local dropin_directory=""
    local selected_files=""
    local selected_status=0
    local file=""
    local resolved_file=""

    main_file="$(resolve_rooted_read_path "$main_file" 2>/dev/null)" || return 2
    dropin_directory="${logical_main}.d"
    selected_files="$(select_layered_files .conf "$dropin_directory")" || selected_status=$?
    [ "$selected_status" -eq 0 ] || return "$selected_status"
    while IFS= read -r file; do
        [ -n "$file" ] || continue
        resolved_file="$(resolve_rooted_read_path "$file" 2>/dev/null)" || return 2
        printf '%s\n' "$resolved_file"
    done <<EOF
$selected_files
EOF
    printf '%s\n' "$main_file"
}

pwhistory_file_value() {
    local key="$1"
    local file="$2"

    [ -r "$file" ] || return 1
    awk -v target="$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')" -v source="$(display_path "$file")" '
        {
            raw=$0
            sub(/^[[:space:]]+/, "", raw)
            if (raw == "" || raw ~ /^#/) next
            separator=index(raw, "=")
            if (separator > 0) {
                name=substr(raw, 1, separator - 1)
                value=substr(raw, separator + 1)
            } else {
                split(raw, fields, /[[:space:]]+/)
                name=fields[1]
                value=substr(raw, length(name) + 1)
            }
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
            sub(/#.*/, "", value)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (tolower(name) == target) {
                found=1
                print value "\t" source ":" FNR
                exit
            }
        }
        END {if (!found) exit 1}
    ' "$file"
}

pwhistory_value() {
    local key="$1"
    local file=""
    local file_status=0

    platform_supports_pwhistory_configuration || return 1
    file="$(optional_rooted_read_path /etc/security/pwhistory.conf 2>/dev/null)" || file_status=$?
    [ "$file_status" -eq 0 ] || return "$file_status"
    pwhistory_file_value "$key" "$file"
}

pam_service_file() {
    local service="$1"
    local candidate=""
    local resolved_candidate=""

    if [ "${service#/}" != "$service" ]; then
        candidate="$(fs_path "$service" 2>/dev/null)" || return 2
        [ -e "$candidate" ] || [ -L "$candidate" ] || return 1
        resolved_candidate="$(resolve_rooted_read_path "$candidate" 2>/dev/null)" || return 2
        printf '%s\n' "$resolved_candidate"
        return 0
    fi

    for candidate in "/etc/pam.d/$service" "/usr/lib/pam.d/$service" "/usr/share/pam/pam.d/$service"; do
        candidate="$(fs_path "$candidate" 2>/dev/null)" || return 2
        [ -e "$candidate" ] || [ -L "$candidate" ] || continue
        resolved_candidate="$(resolve_rooted_read_path "$candidate" 2>/dev/null)" || return 2
        printf '%s\n' "$resolved_candidate"
        return 0
    done

    return 1
}

pam_directory_configuration_present() {
    local directory=""
    local physical_directory=""

    for directory in /etc/pam.d /usr/lib/pam.d /usr/share/pam/pam.d; do
        physical_directory="$(fs_path "$directory" 2>/dev/null)" || return 2
        [ -e "$physical_directory" ] || [ -L "$physical_directory" ] || continue
        [ -d "$physical_directory" ] && [ -r "$physical_directory" ] && [ -x "$physical_directory" ] || return 2
        return 0
    done
    return 1
}

pam_legacy_configuration_file() {
    optional_rooted_read_path /etc/pam.conf
}

PAM_CACHE_EPOCH_ID=""
PAM_FILE_PARSE_COUNT=0
PAM_EXPANSION_BUILD_COUNT=0
PAM_NODE_LAST_CLASS=""
PAM_NODE_LAST_REASON=""
PAM_FILE_LAST_STATE=""
PAM_FILE_LAST_REASON=""

declare -gA PAM_SERVICE_STATE=()
declare -gA PAM_SERVICE_PATH=()
declare -gA PAM_SERVICE_MODE=()
declare -gA PAM_FILE_STATE=()
declare -gA PAM_FILE_INTERMEDIATE_PATH=()
declare -gA PAM_FILE_REASON=()
declare -gA PAM_NODE_STATE=()
declare -gA PAM_NODE_OUTPUT_PATH=()
declare -gA PAM_NODE_MAXIMUM_DEPTH=()
declare -gA PAM_NODE_REASON=()
declare -gA PAM_EFFECTIVE_STATE=()
declare -gA PAM_EFFECTIVE_OUTPUT_PATH=()
declare -gA PAM_EFFECTIVE_REASON=()
declare -gA PAM_DFS_COLOR=()

pam_reset_epoch_cache() {
    PAM_SERVICE_STATE=()
    PAM_SERVICE_PATH=()
    PAM_SERVICE_MODE=()
    PAM_FILE_STATE=()
    PAM_FILE_INTERMEDIATE_PATH=()
    PAM_FILE_REASON=()
    PAM_NODE_STATE=()
    PAM_NODE_OUTPUT_PATH=()
    PAM_NODE_MAXIMUM_DEPTH=()
    PAM_NODE_REASON=()
    PAM_EFFECTIVE_STATE=()
    PAM_EFFECTIVE_OUTPUT_PATH=()
    PAM_EFFECTIVE_REASON=()
    PAM_DFS_COLOR=()
    PAM_FILE_PARSE_COUNT=0
    PAM_EXPANSION_BUILD_COUNT=0
    PAM_NODE_LAST_CLASS=""
    PAM_NODE_LAST_REASON=""
    PAM_FILE_LAST_STATE=""
    PAM_FILE_LAST_REASON=""
    PAM_CACHE_EPOCH_ID="${SCAN_EPOCH_ID:-0}"
}

pam_ensure_epoch_cache() {
    local current_epoch="${SCAN_EPOCH_ID:-0}"

    case "$current_epoch" in ''|*[!0-9]*) return 2 ;; esac
    if [ "${SCAN_EPOCH_ACTIVE:-0}" -ne 1 ] || [ "$PAM_CACHE_EPOCH_ID" != "$current_epoch" ]; then
        pam_reset_epoch_cache
    fi
}

pam_pair_key_into() {
    local first_value="$1"
    local second_value="$2"
    local destination_name="$3"

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|first_value|second_value|destination_name) return 2 ;;
    esac
    printf -v "$destination_name" '%d:%s%d:%s' \
        "${#first_value}" "$first_value" "${#second_value}" "$second_value"
}

pam_service_reference_is_valid() {
    local service="$1"

    case "$service" in
        /*)
            case "$service" in *$'\n'*|*$'\r'*|*$'\t'*|*/../*|*/..|*/./*|*/.) return 1 ;; esac
            ;;
        ''|*[!A-Za-z0-9_.+@-]*) return 1 ;;
    esac
}

pam_resolve_service_source_into() {
    local service="$1"
    local path_destination="$2"
    local mode_destination="$3"
    local service_key=""
    local service_path=""
    local resolved_source_mode="pamd"
    local configuration_status=0
    local source_status=0

    case "$path_destination:$mode_destination" in
        *[!A-Za-z0-9_:]*|:*|*:) return 2 ;;
    esac
    printf -v "$path_destination" '%s' ""
    printf -v "$mode_destination" '%s' ""
    pam_service_reference_is_valid "$service" || return 2
    pam_pair_key_into service "$service" service_key || return 2

    if [ -n "${PAM_SERVICE_STATE[$service_key]+present}" ]; then
        case "${PAM_SERVICE_STATE[$service_key]}" in
            ready)
                printf -v "$path_destination" '%s' "${PAM_SERVICE_PATH[$service_key]}"
                printf -v "$mode_destination" '%s' "${PAM_SERVICE_MODE[$service_key]}"
                return 0
                ;;
            absent) return 1 ;;
            *) return 2 ;;
        esac
    fi

    if [ "${service#/}" != "$service" ]; then
        service_path="$(pam_service_file "$service" 2>/dev/null)" || source_status=$?
    else
        pam_directory_configuration_present || configuration_status=$?
        case "$configuration_status" in
            0)
                service_path="$(pam_service_file "$service" 2>/dev/null)" || source_status=$?
                ;;
            1)
                resolved_source_mode="pam.conf"
                service_path="$(pam_legacy_configuration_file 2>/dev/null)" || source_status=$?
                ;;
            *) source_status=2 ;;
        esac
    fi

    case "$source_status" in
        0)
            PAM_SERVICE_STATE["$service_key"]="ready"
            PAM_SERVICE_PATH["$service_key"]="$service_path"
            PAM_SERVICE_MODE["$service_key"]="$resolved_source_mode"
            printf -v "$path_destination" '%s' "$service_path"
            printf -v "$mode_destination" '%s' "$resolved_source_mode"
            return 0
            ;;
        1)
            PAM_SERVICE_STATE["$service_key"]="absent"
            return 1
            ;;
        *)
            PAM_SERVICE_STATE["$service_key"]="error"
            return 2
            ;;
    esac
}

pam_parse_file_once() {
    local service_file="$1"
    local source_mode="$2"
    local destination_name="$3"
    local pam_file_key=""
    local pam_intermediate_file=""
    local pam_displayed_source=""
    local pam_parser_status=0

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|service_file|source_mode|destination_name|pam_file_key|pam_intermediate_file|pam_displayed_source|pam_parser_status)
            return 2
            ;;
    esac
    printf -v "$destination_name" '%s' ""
    PAM_FILE_LAST_STATE=""
    PAM_FILE_LAST_REASON=""
    case "$source_mode" in pamd|pam.conf) ;; *) return 2 ;; esac
    pam_pair_key_into "$source_mode" "$service_file" pam_file_key || return 2

    if [ -n "${PAM_FILE_STATE[$pam_file_key]+present}" ]; then
        PAM_FILE_LAST_STATE="${PAM_FILE_STATE[$pam_file_key]}"
        PAM_FILE_LAST_REASON="${PAM_FILE_REASON[$pam_file_key]}"
        resolver_debug_emit pam_file mode "$source_mode" cache hit status "$PAM_FILE_LAST_STATE"
        if [ "$PAM_FILE_LAST_STATE" = "ready" ]; then
            printf -v "$destination_name" '%s' "${PAM_FILE_INTERMEDIATE_PATH[$pam_file_key]}"
            return 0
        fi
        return 2
    fi
    resolver_debug_emit pam_file mode "$source_mode" cache miss

    pam_intermediate_file="$(new_scratch_file pam-file-intermediate)" || {
        PAM_FILE_STATE["$pam_file_key"]="error"
        PAM_FILE_REASON["$pam_file_key"]="scratch"
        PAM_FILE_LAST_STATE="error"
        PAM_FILE_LAST_REASON="scratch"
        resolver_debug_emit pam_file mode "$source_mode" cache build status error
        return 2
    }
    pam_displayed_source="$(display_path "$service_file" 2>/dev/null)" || {
        PAM_FILE_STATE["$pam_file_key"]="error"
        PAM_FILE_REASON["$pam_file_key"]="display-path"
        PAM_FILE_LAST_STATE="error"
        PAM_FILE_LAST_REASON="display-path"
        resolver_debug_emit pam_file mode "$source_mode" cache build status error
        return 2
    }
    PAM_FILE_PARSE_COUNT=$((PAM_FILE_PARSE_COUNT + 1))
    awk -v source_mode="$source_mode" -v source_path="$pam_displayed_source" '
        function emit(kind, selector, facility, control_kind, control_text,
                      payload, arguments, first_line, last_line, rendered) {
            printf "%s%c%s%c%s%c%s%c%s%c%s%c%s%c%s%c%d%c%d%c%s%c", \
                kind, 0, selector, 0, facility, 0, control_kind, 0, control_text, 0, \
                payload, 0, arguments, 0, source_path, 0, first_line, 0, last_line, 0, rendered, 0
        }
        function process_record(rendered, first_line, last_line, field_count, field_index,
                                selector, facility, control, control_kind, control_text,
                                module_index, payload, arguments, rebuilt, trimmed, parse_line) {
            sub(/[[:space:]]#.*$/, "", rendered)
            trimmed=rendered
            sub(/^[[:space:]]+/, "", trimmed)
            if (trimmed == "" || trimmed ~ /^#/) return

            parse_line=trimmed
            field_count=split(parse_line, fields, /[[:space:]]+/)
            selector=""
            if (source_mode == "pam.conf") {
                selector=tolower(fields[1])
                rebuilt=""
                for (field_index=2; field_index<=field_count; field_index++)
                    rebuilt=rebuilt (rebuilt == "" ? "" : " ") fields[field_index]
                rendered=rebuilt
                if (rendered == "") {
                    emit("malformed", selector, "*", "none", "", "empty-pam-conf-record", "", first_line, last_line, rendered)
                    return
                }
                field_count=split(rendered, fields, /[[:space:]]+/)
            }

            facility=tolower(fields[1])
            sub(/^-/, "", facility)
            if (facility == "@include") {
                payload=(field_count >= 2 ? fields[2] : "")
                arguments=""
                for (field_index=3; field_index<=field_count; field_index++)
                    arguments=arguments (arguments == "" ? "" : " ") fields[field_index]
                emit("at_include", selector, "*", "edge", "@include", payload, arguments,
                     first_line, last_line, rendered)
                return
            }

            control=tolower(fields[2])
            if (control == "include" || control == "substack") {
                payload=(field_count >= 3 ? fields[3] : "")
                arguments=""
                for (field_index=4; field_index<=field_count; field_index++)
                    arguments=arguments (arguments == "" ? "" : " ") fields[field_index]
                emit(control, selector, facility, "edge", control, payload, arguments,
                     first_line, last_line, rendered)
                return
            }

            control_kind="simple"
            control_text=control
            module_index=3
            if (fields[2] ~ /^\[/) {
                control_kind="bracket"
                control_text=""
                module_index=2
                while (module_index <= field_count) {
                    control_text=control_text (control_text == "" ? "" : " ") tolower(fields[module_index])
                    if (fields[module_index] ~ /\]$/) break
                    module_index++
                }
                module_index++
                if (control_text !~ /\]$/) control_kind="malformed-bracket"
            }
            payload=(module_index <= field_count ? fields[module_index] : "")
            arguments=""
            for (field_index=module_index + 1; field_index<=field_count; field_index++)
                arguments=arguments (arguments == "" ? "" : " ") fields[field_index]
            emit("module", selector, facility, control_kind, control_text, payload, arguments,
                 first_line, last_line, rendered)
        }
        {
            if (!continued) {
                record=$0
                record_start=FNR
            } else {
                record=record $0
            }
            if (record ~ /\\[[:space:]]*$/) {
                sub(/\\[[:space:]]*$/, "", record)
                record=record " "
                continued=1
                next
            }
            process_record(record, record_start, FNR)
            record=""
            continued=0
        }
        END {if (continued) exit 2}
    ' "$service_file" > "$pam_intermediate_file" || pam_parser_status=$?

    case "$pam_parser_status" in
        0)
            PAM_FILE_STATE["$pam_file_key"]="ready"
            PAM_FILE_INTERMEDIATE_PATH["$pam_file_key"]="$pam_intermediate_file"
            PAM_FILE_REASON["$pam_file_key"]=""
            PAM_FILE_LAST_STATE="ready"
            printf -v "$destination_name" '%s' "$pam_intermediate_file"
            resolver_debug_emit pam_file mode "$source_mode" cache build status ready
            return 0
            ;;
        2)
            PAM_FILE_STATE["$pam_file_key"]="ambiguous"
            PAM_FILE_REASON["$pam_file_key"]="dangling-continuation"
            PAM_FILE_LAST_STATE="ambiguous"
            PAM_FILE_LAST_REASON="dangling-continuation"
            resolver_debug_emit pam_file mode "$source_mode" cache build status ambiguous
            return 2
            ;;
        *)
            PAM_FILE_STATE["$pam_file_key"]="error"
            PAM_FILE_REASON["$pam_file_key"]="parser"
            PAM_FILE_LAST_STATE="error"
            PAM_FILE_LAST_REASON="parser"
            resolver_debug_emit pam_file mode "$source_mode" cache build status error
            return 2
            ;;
    esac
}

pam_commit_node_result() {
    local node_key="$1"
    local normalized_output=""
    local commit_status=0

    declare -F scan_resolver_commit >/dev/null 2>&1 || return 0
    [ "${SCAN_INCREMENTAL_REEVALUATION_ACTIVE:-0}" -eq 1 ] || return 0
    printf -v normalized_output 'state=%s\nreason=%s\nmaximum_depth=%s' \
        "${PAM_NODE_STATE[$node_key]-unknown}" "${PAM_NODE_REASON[$node_key]-}" \
        "${PAM_NODE_MAXIMUM_DEPTH[$node_key]-0}"
    if [ -n "${PAM_NODE_OUTPUT_PATH[$node_key]-}" ] &&
        [ -f "${PAM_NODE_OUTPUT_PATH[$node_key]}" ] &&
        [ ! -L "${PAM_NODE_OUTPUT_PATH[$node_key]}" ]; then
        normalized_output+=$'\n'"$(< "${PAM_NODE_OUTPUT_PATH[$node_key]}")"
    fi
    scan_resolver_commit "pam-node:$node_key" "$normalized_output" || commit_status=$?
    case "$commit_status" in 0|1) return 0 ;; *) return 2 ;; esac
}

pam_cache_node_failure() {
    local node_key="$1"
    local failure_class="$2"
    local failure_reason="$3"

    PAM_NODE_STATE["$node_key"]="$failure_class"
    PAM_NODE_REASON["$node_key"]="$failure_reason"
    PAM_DFS_COLOR["$node_key"]="black"
    PAM_NODE_LAST_CLASS="$failure_class"
    PAM_NODE_LAST_REASON="$failure_reason"
    pam_commit_node_result "$node_key" || return 2
    return 2
}

pam_expand_node() {
    local service="$1"
    local pam_type="$2"
    local depth="$3"
    local node_key=""
    local service_file=""
    local source_mode=""
    local source_status=0
    local intermediate_path=""
    local output_path=""
    local record_kind=""
    local selector=""
    local record_type=""
    local _ignored_control_kind=""
    local _ignored_control_text=""
    local payload=""
    local _ignored_arguments=""
    local source_path=""
    local _ignored_first_line=""
    local _ignored_last_line=""
    local rendered_line=""
    local requested_service_lower=""
    local child_key=""
    local child_status=0
    local child_depth=0
    local maximum_depth=0
    local failure_class=""
    local failure_reason=""

    PAM_NODE_LAST_CLASS=""
    PAM_NODE_LAST_REASON=""
    case "$pam_type" in auth|account|password|session) ;; *) PAM_NODE_LAST_CLASS="ambiguous"; PAM_NODE_LAST_REASON="invalid-facility"; return 2 ;; esac
    case "$depth" in ''|*[!0-9]*) PAM_NODE_LAST_CLASS="ambiguous"; PAM_NODE_LAST_REASON="invalid-depth"; return 2 ;; esac
    if [ "$depth" -ge 16 ]; then
        PAM_NODE_LAST_CLASS="ambiguous"
        PAM_NODE_LAST_REASON="depth"
        return 2
    fi
    pam_service_reference_is_valid "$service" || {
        PAM_NODE_LAST_CLASS="ambiguous"
        PAM_NODE_LAST_REASON="invalid-service"
        return 2
    }
    pam_pair_key_into "$service" "$pam_type" node_key || return 2

    if [ -n "${PAM_NODE_STATE[$node_key]+present}" ]; then
        PAM_NODE_LAST_CLASS="${PAM_NODE_STATE[$node_key]}"
        PAM_NODE_LAST_REASON="${PAM_NODE_REASON[$node_key]}"
        case "${PAM_NODE_STATE[$node_key]}" in
            ready)
                maximum_depth="${PAM_NODE_MAXIMUM_DEPTH[$node_key]}"
                if [ $((depth + maximum_depth)) -ge 16 ]; then
                    PAM_NODE_LAST_CLASS="ambiguous"
                    PAM_NODE_LAST_REASON="depth"
                    return 2
                fi
                return 0
                ;;
            absent) return 1 ;;
            *) return 2 ;;
        esac
    fi
    if [ "${PAM_DFS_COLOR[$node_key]-white}" = "gray" ]; then
        pam_cache_node_failure "$node_key" ambiguous cycle
        return 2
    fi
    PAM_DFS_COLOR["$node_key"]="gray"

    if declare -F scan_dependency_register >/dev/null 2>&1; then
        scan_dependency_register "pam-service:$service" "pam-node:$node_key" || {
            pam_cache_node_failure "$node_key" error dependency-registration
            return 2
        }
    fi

    pam_resolve_service_source_into "$service" service_file source_mode || source_status=$?
    case "$source_status" in
        0) ;;
        1)
            PAM_NODE_STATE["$node_key"]="absent"
            PAM_NODE_REASON["$node_key"]="source-absent"
            PAM_DFS_COLOR["$node_key"]="black"
            PAM_NODE_LAST_CLASS="absent"
            PAM_NODE_LAST_REASON="source-absent"
            pam_commit_node_result "$node_key" || return 2
            return 1
            ;;
        *)
            pam_cache_node_failure "$node_key" error source-resolution
            return 2
            ;;
    esac

    if declare -F scan_dependency_register >/dev/null 2>&1; then
        scan_dependency_register "pam-source:$service_file" "pam-node:$node_key" || {
            pam_cache_node_failure "$node_key" error dependency-registration
            return 2
        }
    fi
    pam_parse_file_once "$service_file" "$source_mode" intermediate_path || {
        failure_class="${PAM_FILE_LAST_STATE:-error}"
        case "$failure_class" in ambiguous|error) ;; *) failure_class="error" ;; esac
        pam_cache_node_failure "$node_key" "$failure_class" "${PAM_FILE_LAST_REASON:-file-parse}"
        return 2
    }
    output_path="$(new_scratch_file pam-node-output)" || {
        pam_cache_node_failure "$node_key" error scratch
        return 2
    }
    requested_service_lower="${service,,}"

    # shellcheck disable=SC2034
    while IFS= read -r -d '' record_kind &&
        IFS= read -r -d '' selector &&
        IFS= read -r -d '' record_type &&
        IFS= read -r -d '' _ignored_control_kind &&
        IFS= read -r -d '' _ignored_control_text &&
        IFS= read -r -d '' payload &&
        IFS= read -r -d '' _ignored_arguments &&
        IFS= read -r -d '' source_path &&
        IFS= read -r -d '' _ignored_first_line &&
        IFS= read -r -d '' _ignored_last_line &&
        IFS= read -r -d '' rendered_line; do
        [ -z "$selector" ] || [ "$selector" = "$requested_service_lower" ] || continue
        case "$record_kind" in
            module)
                [ "$record_type" = "$pam_type" ] || continue
                printf '%s\t%s\n' "$source_path" "$rendered_line" >> "$output_path" || {
                    pam_cache_node_failure "$node_key" error output-write
                    return 2
                }
                ;;
            at_include|include|substack)
                if [ "$record_kind" = "at_include" ]; then
                    platform_is_debian_family || {
                        pam_cache_node_failure "$node_key" ambiguous unsupported-at-include
                        return 2
                    }
                    [ -n "$payload" ] || {
                        pam_cache_node_failure "$node_key" ambiguous missing-include-target
                        return 2
                    }
                    if [ "$source_mode" = "pam.conf" ] && [ "${payload#/}" = "$payload" ]; then
                        pam_cache_node_failure "$node_key" ambiguous relative-pam-conf-include
                        return 2
                    fi
                else
                    [ "$record_type" = "$pam_type" ] || continue
                    [ -n "$payload" ] || {
                        pam_cache_node_failure "$node_key" ambiguous missing-include-target
                        return 2
                    }
                    if [ "$source_mode" = "pam.conf" ] && [ "${payload#/}" = "$payload" ]; then
                        pam_cache_node_failure "$node_key" ambiguous relative-pam-conf-include
                        return 2
                    fi
                fi
                child_status=0
                pam_expand_node "$payload" "$pam_type" $((depth + 1)) || child_status=$?
                pam_pair_key_into "$payload" "$pam_type" child_key || {
                    pam_cache_node_failure "$node_key" error child-key
                    return 2
                }
                if [ "$child_status" -eq 1 ]; then
                    pam_cache_node_failure "$node_key" ambiguous missing-include-source
                    return 2
                elif [ "$child_status" -eq 2 ]; then
                    failure_class="${PAM_NODE_LAST_CLASS:-ambiguous}"
                    failure_reason="${PAM_NODE_LAST_REASON:-child-expansion}"
                    if [ "$failure_reason" = "depth" ]; then
                        unset 'PAM_DFS_COLOR[$node_key]'
                        PAM_NODE_LAST_CLASS="ambiguous"
                        PAM_NODE_LAST_REASON="depth"
                        return 2
                    fi
                    pam_cache_node_failure "$node_key" "$failure_class" "$failure_reason"
                    return 2
                fi
                cat "${PAM_NODE_OUTPUT_PATH[$child_key]}" >> "$output_path" || {
                    pam_cache_node_failure "$node_key" error child-output-read
                    return 2
                }
                child_depth=$((PAM_NODE_MAXIMUM_DEPTH[$child_key] + 1))
                [ "$child_depth" -le "$maximum_depth" ] || maximum_depth="$child_depth"
                ;;
            malformed)
                if [ "$record_type" = "*" ] || [ "$record_type" = "$pam_type" ]; then
                    pam_cache_node_failure "$node_key" ambiguous "$payload"
                    return 2
                fi
                ;;
        esac
    done < "$intermediate_path"

    PAM_NODE_STATE["$node_key"]="ready"
    PAM_NODE_OUTPUT_PATH["$node_key"]="$output_path"
    PAM_NODE_MAXIMUM_DEPTH["$node_key"]="$maximum_depth"
    PAM_NODE_REASON["$node_key"]=""
    PAM_DFS_COLOR["$node_key"]="black"
    PAM_NODE_LAST_CLASS="ready"
    PAM_NODE_LAST_REASON=""
    pam_commit_node_result "$node_key" || return 2
    return 0
}

pam_expand_service_recursive() {
    local service="$1"
    local pam_type="$2"
    local depth="$3"
    local active_stack="$4"
    local recursion_key="${service}:${pam_type}"
    local node_key=""

    case "|$active_stack|" in *"|$recursion_key|"*) return 2 ;; esac
    pam_expand_node "$service" "$pam_type" "$depth" || return $?
    pam_pair_key_into "$service" "$pam_type" node_key || return 2
    cat "${PAM_NODE_OUTPUT_PATH[$node_key]}"
}

pam_emit_effective_cache() {
    local effective_key="$1"

    PAM_NODE_LAST_REASON="${PAM_EFFECTIVE_REASON[$effective_key]-}"
    case "${PAM_EFFECTIVE_STATE[$effective_key]}" in
        ready)
            cat "${PAM_EFFECTIVE_OUTPUT_PATH[$effective_key]}"
            return $?
            ;;
        absent) return 1 ;;
        *) return 2 ;;
    esac
}

pam_expand_service() {
    local service="$1"
    local pam_type="$2"
    local effective_key=""
    local node_key=""
    local other_key=""
    local effective_output=""
    local expansion_status=0

    case "$pam_type" in auth|account|password|session) ;; *) return 2 ;; esac
    case "$service" in ''|/*|*[!A-Za-z0-9_.+@-]*) return 2 ;; esac
    service="${service,,}"
    pam_ensure_epoch_cache || return 2
    pam_pair_key_into "$service" "$pam_type" effective_key || return 2
    if [ -n "${PAM_EFFECTIVE_STATE[$effective_key]+present}" ]; then
        resolver_debug_emit pam_expansion service "$service" facility "$pam_type" cache hit \
            status "${PAM_EFFECTIVE_STATE[$effective_key]}"
        pam_emit_effective_cache "$effective_key"
        return $?
    fi
    resolver_debug_emit pam_expansion service "$service" facility "$pam_type" cache miss

    PAM_EXPANSION_BUILD_COUNT=$((PAM_EXPANSION_BUILD_COUNT + 1))
    effective_output="$(new_scratch_file pam-effective-output)" || {
        PAM_EFFECTIVE_STATE["$effective_key"]="error"
        PAM_EFFECTIVE_REASON["$effective_key"]="scratch"
        resolver_debug_emit pam_expansion service "$service" facility "$pam_type" cache build \
            status error
        return 2
    }
    pam_expand_node "$service" "$pam_type" 0 || expansion_status=$?
    pam_pair_key_into "$service" "$pam_type" node_key || return 2
    if [ "$expansion_status" -eq 2 ]; then
        PAM_EFFECTIVE_STATE["$effective_key"]="${PAM_NODE_LAST_CLASS:-error}"
        PAM_EFFECTIVE_REASON["$effective_key"]="${PAM_NODE_LAST_REASON:-expansion}"
        resolver_debug_emit pam_expansion service "$service" facility "$pam_type" cache build \
            status "${PAM_EFFECTIVE_STATE[$effective_key]}"
        return 2
    fi
    if [ "$expansion_status" -eq 0 ] && [ -s "${PAM_NODE_OUTPUT_PATH[$node_key]}" ]; then
        cat "${PAM_NODE_OUTPUT_PATH[$node_key]}" > "$effective_output" || return 2
        PAM_EFFECTIVE_STATE["$effective_key"]="ready"
        PAM_EFFECTIVE_OUTPUT_PATH["$effective_key"]="$effective_output"
        resolver_debug_emit pam_expansion service "$service" facility "$pam_type" cache build \
            status ready
        pam_emit_effective_cache "$effective_key"
        return $?
    fi
    if [ "$service" = "other" ]; then
        PAM_EFFECTIVE_STATE["$effective_key"]="absent"
        PAM_EFFECTIVE_REASON["$effective_key"]="empty-other"
        resolver_debug_emit pam_expansion service "$service" facility "$pam_type" cache build \
            status absent
        return 1
    fi

    expansion_status=0
    pam_expand_node other "$pam_type" 0 || expansion_status=$?
    pam_pair_key_into other "$pam_type" other_key || return 2
    case "$expansion_status" in
        0)
            cat "${PAM_NODE_OUTPUT_PATH[$other_key]}" > "$effective_output" || return 2
            PAM_EFFECTIVE_STATE["$effective_key"]="ready"
            PAM_EFFECTIVE_OUTPUT_PATH["$effective_key"]="$effective_output"
            resolver_debug_emit pam_expansion service "$service" facility "$pam_type" cache build \
                status ready
            pam_emit_effective_cache "$effective_key"
            ;;
        1)
            PAM_EFFECTIVE_STATE["$effective_key"]="absent"
            PAM_EFFECTIVE_REASON["$effective_key"]="service-and-other-absent"
            resolver_debug_emit pam_expansion service "$service" facility "$pam_type" cache build \
                status absent
            return 1
            ;;
        *)
            PAM_EFFECTIVE_STATE["$effective_key"]="${PAM_NODE_LAST_CLASS:-error}"
            PAM_EFFECTIVE_REASON["$effective_key"]="${PAM_NODE_LAST_REASON:-other-expansion}"
            resolver_debug_emit pam_expansion service "$service" facility "$pam_type" cache build \
                status "${PAM_EFFECTIVE_STATE[$effective_key]}"
            return 2
            ;;
    esac
}

sshd_effective_config() {
    local sshd_path=""
    local hostname_value=""

    sshd_path="$(trusted_command sshd)" || return 127
    hostname_value="$(hostname 2>/dev/null || printf localhost)"
    "$sshd_path" -t >/dev/null 2>&1 || return 2
    "$sshd_path" -T -C "user=root,host=${hostname_value},addr=127.0.0.1,laddr=127.0.0.1,lport=22"
}

sshd_effective_value() {
    local key="$1"
    sshd_effective_config | awk -v target="$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')" '$1 == target {$1=""; sub(/^ /, ""); print; exit}'
}

sshd_manager_has_custom_invocation() {
    local systemctl_path=""
    local manager_status=0
    local unit=""
    local properties=""
    local load_state=""
    local command_status=0

    if declare -F runtime_systemd_manager_state >/dev/null 2>&1; then
        runtime_systemd_manager_state || manager_status=$?
        [ "$manager_status" -ne 1 ] || return 3
    fi
    systemctl_path="$(trusted_command systemctl)" || return 2
    for unit in ssh.service sshd.service ssh@.service sshd@.service; do
        if [ "${SCAN_EPOCH_ACTIVE:-0}" -eq 1 ]; then
            systemd_epoch_properties_into "$unit" properties || return 2
            command_status="$SYSTEMD_PROPERTIES_COMMAND_STATUS"
        else
            properties="$($systemctl_path show "$unit" -p LoadState -p ExecStart --no-pager 2>/dev/null)" || command_status=$?
        fi
        if declare -F systemd_fact_value_into >/dev/null 2>&1; then
            systemd_fact_value_into "$properties" LoadState load_state || load_state=""
        else
            load_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "LoadState" {print $2; exit}')"
        fi
        if [ "$command_status" -ne 0 ] && [ "$load_state" != "not-found" ]; then
            return 2
        fi
        command_status=0
        [ "$load_state" != "not-found" ] || continue
        if printf '%s\n' "$properties" | grep -Eq '(^|[[:space:]])-[fo]([^[:space:]]*|$)|\$[{A-Za-z_]'; then
            return 0
        fi
    done
    return 1
}

systemd_sysctl_binary() {
    local requested_candidate="${1:-}"
    local candidate=""
    local resolved_candidate=""
    local candidates=()

    runtime_enabled || return 1
    if [ -n "$requested_candidate" ]; then
        case "$requested_candidate" in
            /usr/lib/systemd/systemd-sysctl|/lib/systemd/systemd-sysctl) ;;
            *) return 126 ;;
        esac
        candidates+=("$requested_candidate")
    else
        candidates+=(/usr/lib/systemd/systemd-sysctl /lib/systemd/systemd-sysctl)
    fi
    for candidate in "${candidates[@]}"; do
        [ -x "$candidate" ] || continue
        resolved_candidate="$candidate"
        if [ -x /usr/bin/readlink ]; then
            resolved_candidate="$(/usr/bin/readlink -f -- "$candidate" 2>/dev/null || true)"
        fi
        [ -n "$resolved_candidate" ] && [ -x "$resolved_candidate" ] || continue
        [ "$(stat_owner "$resolved_candidate" 2>/dev/null || true)" = "root" ] || continue
        mode_has_untrusted_write "$(stat_mode "$resolved_candidate" 2>/dev/null || true)" && continue
        trusted_parent_chain "$resolved_candidate" || continue
        printf '%s\n' "$resolved_candidate"
        return 0
    done
    return 127
}

systemd_sysctl_execstart_binary() {
    local properties="$1"

    [ "$(printf '%s\n' "$properties" | grep -c '^ExecStart=')" -eq 1 ] || return 2
    if printf '%s\n' "$properties" | grep -Eq '^ExecStart=\{[[:space:]]*path=/usr/lib/systemd/systemd-sysctl[[:space:]]*;[[:space:]]*argv\[\]=/usr/lib/systemd/systemd-sysctl[[:space:]]*;'; then
        printf '/usr/lib/systemd/systemd-sysctl\n'
    elif printf '%s\n' "$properties" | grep -Eq '^ExecStart=\{[[:space:]]*path=/lib/systemd/systemd-sysctl[[:space:]]*;[[:space:]]*argv\[\]=/lib/systemd/systemd-sysctl[[:space:]]*;'; then
        printf '/lib/systemd/systemd-sysctl\n'
    else
        return 2
    fi
}

systemd_sysctl_unit_binary() {
    local systemctl_path=""
    local properties=""
    local unit_binary=""

    systemctl_path="$(trusted_command systemctl)" || return 2
    if [ "${SCAN_EPOCH_ACTIVE:-0}" -eq 1 ]; then
        systemd_epoch_properties_into systemd-sysctl.service properties || return 2
        [ "$SYSTEMD_PROPERTIES_COMMAND_STATUS" -eq 0 ] || return 2
    else
        properties="$($systemctl_path show systemd-sysctl.service -p ExecStart --no-pager 2>/dev/null)" || return 2
    fi
    unit_binary="$(systemd_sysctl_execstart_binary "$properties")" || return 2
    systemd_sysctl_binary "$unit_binary"
}

systemd_sysctl_stream() {
    local binary=""

    binary="$(systemd_sysctl_unit_binary)" || return $?
    "$binary" --cat-config --no-pager 2>/dev/null
}

systemd_sysctl_value() (
    local key="$1"
    local stream_file=""

    SYSCTL_STATIC_NAMESPACE="systemd-loader"
    stream_file="$(new_scratch_file sysctl-loader-stream)" || return 2
    systemd_sysctl_stream > "$stream_file" || return 2
    sysctl_static_files() {
        printf '%s\n' "$stream_file"
    }
    resolve_sysctl_read_path() {
        [ "$1" = "$stream_file" ] || return 2
        printf '%s\n' "$stream_file"
    }
    sysctl_static_value "$key"
)

sysctl_static_files() {
    select_layered_files .conf /etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d
}

resolve_rooted_path_into() {
    local __kisa_resolve_candidate="$1"
    local __kisa_resolve_expected_type="${2:-file}"
    local __kisa_resolve_destination="$3"
    local __kisa_resolve_current="$__kisa_resolve_candidate"
    local __kisa_resolve_target=""
    local __kisa_resolve_parent=""
    local __kisa_resolve_leaf=""
    local __kisa_resolve_canonical_parent=""
    local __kisa_resolve_canonical_path=""
    local __kisa_resolve_canonical_root=""
    local __kisa_resolve_depth=0

    case "$__kisa_resolve_destination" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|__kisa_resolve_*) return 2 ;;
    esac
    printf -v "$__kisa_resolve_destination" '%s' ""
    case "$__kisa_resolve_expected_type" in
        file|directory|file_or_directory) ;;
        *) return 2 ;;
    esac

    while [ -L "$__kisa_resolve_current" ]; do
        __kisa_resolve_depth=$((__kisa_resolve_depth + 1))
        [ "$__kisa_resolve_depth" -le 40 ] || return 1
        __kisa_resolve_target="$(readlink "$__kisa_resolve_current" 2>/dev/null)" || return 1
        [ "$__kisa_resolve_target" != "/dev/null" ] || return 1

        case "$__kisa_resolve_target" in
            /*)
                if [ "$SCAN_ROOT" = "/" ]; then
                    __kisa_resolve_current="$__kisa_resolve_target"
                else
                    __kisa_resolve_current="${SCAN_ROOT%/}$__kisa_resolve_target"
                fi
                ;;
            *)
                __kisa_resolve_parent="${__kisa_resolve_current%/*}"
                [ -n "$__kisa_resolve_parent" ] || __kisa_resolve_parent="/"
                __kisa_resolve_current="$__kisa_resolve_parent/$__kisa_resolve_target"
                ;;
        esac
    done

    __kisa_resolve_parent="${__kisa_resolve_current%/*}"
    __kisa_resolve_leaf="${__kisa_resolve_current##*/}"
    case "$__kisa_resolve_leaf" in
        .|..) return 1 ;;
    esac
    if [ -d "$__kisa_resolve_current" ]; then
        canonical_directory_into "$__kisa_resolve_current" __kisa_resolve_canonical_path || return 1
    else
        [ -n "$__kisa_resolve_parent" ] || __kisa_resolve_parent="/"
        canonical_directory_into "$__kisa_resolve_parent" __kisa_resolve_canonical_parent || return 1
        __kisa_resolve_canonical_path="${__kisa_resolve_canonical_parent%/}/$__kisa_resolve_leaf"
    fi

    if [ "$SCAN_ROOT" != "/" ]; then
        canonical_scan_root_into __kisa_resolve_canonical_root || return 1
        case "$__kisa_resolve_canonical_path" in
            "${__kisa_resolve_canonical_root%/}"/*) ;;
            *) return 1 ;;
        esac
    fi

    case "$__kisa_resolve_expected_type" in
        file) [ -f "$__kisa_resolve_canonical_path" ] && [ -r "$__kisa_resolve_canonical_path" ] || return 1 ;;
        directory) [ -d "$__kisa_resolve_canonical_path" ] && [ -r "$__kisa_resolve_canonical_path" ] || return 1 ;;
        file_or_directory)
            { [ -f "$__kisa_resolve_canonical_path" ] || [ -d "$__kisa_resolve_canonical_path" ]; } &&
                [ -r "$__kisa_resolve_canonical_path" ] || return 1
            ;;
    esac
    printf -v "$__kisa_resolve_destination" '%s' "$__kisa_resolve_canonical_path"
}

resolve_rooted_path() {
    local resolved_rooted_path=""

    resolve_rooted_path_into "$1" "${2:-file}" resolved_rooted_path || return $?
    printf '%s\n' "$resolved_rooted_path"
}

resolve_rooted_read_path_into() {
    resolve_rooted_path_into "$1" file "$2"
}

resolve_rooted_read_path() {
    resolve_rooted_path "$1" file
}

optional_rooted_read_path_into() {
    local __kisa_optional_logical_path="$1"
    local __kisa_optional_destination="$2"
    local __kisa_optional_raw_path=""
    local __kisa_optional_physical_path=""
    local __kisa_optional_resolved_path=""

    case "$__kisa_optional_destination" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|__kisa_optional_*) return 2 ;;
    esac
    printf -v "$__kisa_optional_destination" '%s' ""

    if [ "$SCAN_ROOT" = "/" ]; then
        __kisa_optional_raw_path="$__kisa_optional_logical_path"
    else
        __kisa_optional_raw_path="${SCAN_ROOT%/}$__kisa_optional_logical_path"
    fi
    [ -e "$__kisa_optional_raw_path" ] || [ -L "$__kisa_optional_raw_path" ] || return 1
    fs_path_into "$__kisa_optional_logical_path" __kisa_optional_physical_path 2>/dev/null || return 2
    resolve_rooted_path_into "$__kisa_optional_physical_path" file __kisa_optional_resolved_path || return 2
    printf -v "$__kisa_optional_destination" '%s' "$__kisa_optional_resolved_path"
}

optional_rooted_read_path() {
    local resolved_optional_path=""

    optional_rooted_read_path_into "$1" resolved_optional_path || return $?
    printf '%s\n' "$resolved_optional_path"
}

resolve_rooted_directory_into() {
    resolve_rooted_path_into "$1" directory "$2"
}

resolve_rooted_directory() {
    resolve_rooted_path "$1" directory
}

resolve_sysctl_read_path() {
    resolve_rooted_read_path "$1"
}

sysctl_file_is_masked() {
    local path="$1"
    local current="$path"
    local target=""
    local parent=""
    local canonical_parent=""
    local canonical_path=""
    local canonical_root=""
    local depth=0

    [ -L "$path" ] || return 1
    while [ -L "$current" ]; do
        depth=$((depth + 1))
        [ "$depth" -le 40 ] || return 1
        target="$(readlink "$current" 2>/dev/null)" || return 1
        [ "$target" = "/dev/null" ] && return 0
        case "$target" in
            /*)
                if [ "$SCAN_ROOT" = "/" ]; then current="$target"; else current="${SCAN_ROOT%/}$target"; fi
                ;;
            *) current="${current%/*}/$target" ;;
        esac
    done
    parent="${current%/*}"
    canonical_directory_into "$parent" canonical_parent || return 1
    canonical_path="${canonical_parent%/}/${current##*/}"
    [ "$canonical_path" = "/dev/null" ] && return 0
    if [ "$SCAN_ROOT" != "/" ]; then
        canonical_scan_root_into canonical_root || return 1
        [ "$canonical_path" = "${canonical_root%/}/dev/null" ] && return 0
    fi
    return 1
}

sysctl_normalize_name_into() {
    local input_name="$1"
    local destination_name="$2"
    local dot_prefix=""
    local slash_prefix=""
    local normalized_name=""
    local character=""
    local index_value=0

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|input_name|destination_name|dot_prefix|slash_prefix|normalized_name|character|index_value)
            return 2
            ;;
    esac
    printf -v "$destination_name" '%s' ""
    [ -n "$input_name" ] || return 2

    if [[ "$input_name" == */* ]]; then
        slash_prefix="${input_name%%/*}"
        if [[ "$input_name" != *.* ]]; then
            printf -v "$destination_name" '%s' "$input_name"
            return 0
        fi
        dot_prefix="${input_name%%.*}"
        if [ "${#slash_prefix}" -lt "${#dot_prefix}" ]; then
            printf -v "$destination_name" '%s' "$input_name"
            return 0
        fi
    fi

    for ((index_value = 0; index_value < ${#input_name}; index_value++)); do
        character="${input_name:index_value:1}"
        case "$character" in
            .) normalized_name+="/" ;;
            /) normalized_name+="." ;;
            *) normalized_name+="$character" ;;
        esac
    done
    printf -v "$destination_name" '%s' "$normalized_name"
}

sysctl_cache_key_into() {
    local namespace="$1"
    local normalized_name="$2"
    local destination_name="$3"

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|namespace|normalized_name|destination_name) return 2 ;;
    esac
    printf -v "$destination_name" '%s' "${#namespace}:$namespace$normalized_name"
}

sysctl_query_dependency_source_into() {
    local namespace="$1"
    local destination_name="$2"

    case "$destination_name" in ''|[0-9]*|*[!A-Za-z0-9_]*) return 2 ;; esac
    case "$namespace" in
        filesystem) printf -v "$destination_name" '%s' file-set:sysctl.d ;;
        systemd-loader) printf -v "$destination_name" '%s' runtime:systemd-sysctl-loader ;;
        ufw) printf -v "$destination_name" '%s' file:ufw-sysctl ;;
        *) printf -v "$destination_name" 'sysctl-source:%s' "$namespace" ;;
    esac
}

sysctl_commit_query_result() {
    local resolver_id="$1"
    local status_value="$2"
    local result_value="$3"
    local commit_status=0

    declare -F scan_resolver_commit >/dev/null 2>&1 || return 0
    scan_resolver_commit "$resolver_id" "status=$status_value"$'\n'"value=$result_value" || commit_status=$?
    case "$commit_status" in 0|1) return 0 ;; *) return 2 ;; esac
}

_sysctl_prepare_static_snapshot() {
    local namespace="${1:-filesystem}"
    local files=""
    local file=""
    local read_path=""
    local display_source=""
    local parsed_file=""
    local glob_file=""
    local directive_name=""
    local directive_type=""
    local line_number=""
    local directive_value=""
    local cache_key=""
    local files_status=0
    local file_count=0
    local directive_count=0

    resolver_ensure_epoch_cache || return 2
    case "$namespace" in
        ''|*[!A-Za-z0-9_.-]*) return 2 ;;
    esac
    if [ "${SYSCTL_SNAPSHOT_READY[$namespace]+present}" = "present" ]; then
        resolver_debug_emit sysctl_snapshot namespace "$namespace" cache hit \
            status "${SYSCTL_SNAPSHOT_STATUS[$namespace]}"
        return "${SYSCTL_SNAPSHOT_STATUS[$namespace]}"
    fi
    resolver_debug_emit sysctl_snapshot namespace "$namespace" cache miss
    SYSCTL_SNAPSHOT_READY["$namespace"]=1
    SYSCTL_SNAPSHOT_STATUS["$namespace"]=2

    files="$(sysctl_static_files)" || files_status=$?
    case "$files_status" in
        0) ;;
        1)
            SYSCTL_SNAPSHOT_STATUS["$namespace"]=1
            resolver_debug_emit sysctl_snapshot namespace "$namespace" cache build \
                status 1 files 0 directives 0
            return 1
            ;;
        *)
            resolver_debug_emit sysctl_snapshot namespace "$namespace" cache build \
                status 2 files 0 directives 0
            return 2
            ;;
    esac
    if [ -z "$files" ]; then
        SYSCTL_SNAPSHOT_STATUS["$namespace"]=1
        resolver_debug_emit sysctl_snapshot namespace "$namespace" cache build \
            status 1 files 0 directives 0
        return 1
    fi
    glob_file="$(new_scratch_file "sysctl-${namespace}-globs")" || return 2
    SYSCTL_GLOB_FILE["$namespace"]="$glob_file"

    while IFS= read -r file; do
        [ -n "$file" ] || continue
        file_count=$((file_count + 1))
        read_path="$(resolve_sysctl_read_path "$file" 2>/dev/null)" || {
            sysctl_file_is_masked "$file" && continue
            return 2
        }
        display_source="$(display_path "$file")" || return 2
        parsed_file="$(new_scratch_file "sysctl-${namespace}-parsed")" || return 2
        awk '
            function trim(value) {gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); return value}
            function canonical(name, first_dot, first_slash, index_value, character, result) {
                first_dot = index(name, ".")
                first_slash = index(name, "/")
                if (first_slash > 0 && (first_dot == 0 || first_slash < first_dot)) return name

                result = ""
                for (index_value = 1; index_value <= length(name); index_value++) {
                    character = substr(name, index_value, 1)
                    if (character == ".") character = "/"
                    else if (character == "/") character = "."
                    result = result character
                }
                return result
            }
            {
                raw=$0
                sub(/^[[:space:]]+/, "", raw)
                if (raw == "" || raw ~ /^[#;]/) next
                separator=index(raw,"=")
                if (separator == 0) {
                    if (substr(raw, 1, 1) != "-") next
                    name=trim(substr(raw, 2))
                    if (name == "" || name ~ /[[:space:]]/) next
                    printf "%s%c%s%c%d%c%c", canonical(name), 0, "exclusion", 0, FNR, 0, 0
                    next
                }

                name=trim(substr(raw,1,separator-1))
                sub(/^-/, "", name)
                if (name == "" || name ~ /[[:space:]]/) next
                value=trim(substr(raw,separator+1))
                printf "%s%c%s%c%d%c%s%c", canonical(name), 0, "assignment", 0, FNR, 0, value, 0
            }
        ' "$read_path" > "$parsed_file" || return 2
        while IFS= read -r -d '' directive_name &&
            IFS= read -r -d '' directive_type &&
            IFS= read -r -d '' line_number &&
            IFS= read -r -d '' directive_value; do
            directive_count=$((directive_count + 1))
            case "$directive_name" in
                *'*'*|*'?'*|*'['*)
                    [ "$directive_type" = "assignment" ] || continue
                    printf '%s\0%s\0%s\0%s\0' "$directive_name" "$directive_value" \
                        "$display_source" "$line_number" >> "$glob_file" || return 2
                    ;;
                *)
                    sysctl_cache_key_into "$namespace" "$directive_name" cache_key || return 2
                    SYSCTL_EXACT_TYPE["$cache_key"]="$directive_type"
                    SYSCTL_EXACT_VALUE["$cache_key"]="$directive_value"
                    SYSCTL_EXACT_SOURCE["$cache_key"]="$display_source:$line_number"
                    ;;
            esac
        done < "$parsed_file"
    done <<EOF
$files
EOF

    SYSCTL_SNAPSHOT_STATUS["$namespace"]=0
    resolver_debug_emit sysctl_snapshot namespace "$namespace" cache build \
        status 0 files "$file_count" directives "$directive_count"
    return 0
}

sysctl_prepare_static_snapshot() {
    case "${SCAN_EPOCH_ACTIVE:-0}" in
        0) resolver_reset_epoch_caches ;;
        1) ;;
        *) return 2 ;;
    esac
    _sysctl_prepare_static_snapshot "${1:-filesystem}"
}

sysctl_prepare_filesystem_snapshot() {
    sysctl_prepare_static_snapshot filesystem
}

sysctl_namespace_value_into() {
    local namespace="$1"
    local key="$2"
    local destination_name="$3"
    local previous_namespace="${SYSCTL_STATIC_NAMESPACE:-filesystem}"
    local lookup_status=0

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|namespace|key|destination_name|previous_namespace|lookup_status)
            return 2
            ;;
    esac
    SYSCTL_STATIC_NAMESPACE="$namespace"
    sysctl_static_value_into "$key" "$destination_name" || lookup_status=$?
    SYSCTL_STATIC_NAMESPACE="$previous_namespace"
    return "$lookup_status"
}

sysctl_static_value_into() {
    local key="$1"
    local destination_name="$2"
    local namespace="${SYSCTL_STATIC_NAMESPACE:-filesystem}"
    local normalized_target=""
    local cache_key=""
    local exact_type=""
    local glob_file=""
    local directive_name=""
    local directive_value=""
    local directive_source=""
    local line_number=""
    local result_value=""
    local snapshot_status=0
    local dependency_source=""
    local resolver_id=""
    local match_kind="none"

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|key|destination_name|namespace|normalized_target|cache_key|exact_type|glob_file|directive_name|directive_value|directive_source|line_number|result_value|snapshot_status|dependency_source|resolver_id)
            return 2
            ;;
    esac
    printf -v "$destination_name" '%s' ""
    case "${SCAN_EPOCH_ACTIVE:-0}" in
        0) resolver_reset_epoch_caches ;;
        1) ;;
        *) return 2 ;;
    esac
    resolver_ensure_epoch_cache || return 2
    sysctl_normalize_name_into "$key" normalized_target || return 2
    sysctl_cache_key_into "$namespace" "$normalized_target" cache_key || return 2
    resolver_id="sysctl:$namespace:$normalized_target"
    if declare -F scan_dependency_register >/dev/null 2>&1; then
        sysctl_query_dependency_source_into "$namespace" dependency_source || return 2
        scan_dependency_register "$dependency_source" "$resolver_id" || return 2
    fi

    if [ "${SYSCTL_QUERY_READY[$cache_key]+present}" = "present" ]; then
        printf -v "$destination_name" '%s' "${SYSCTL_QUERY_VALUE[$cache_key]}"
        resolver_debug_emit sysctl_query source static namespace "$namespace" cache hit \
            status "${SYSCTL_QUERY_STATUS[$cache_key]}"
        return "${SYSCTL_QUERY_STATUS[$cache_key]}"
    fi
    resolver_debug_emit sysctl_query source static namespace "$namespace" cache miss

    _sysctl_prepare_static_snapshot "$namespace" || snapshot_status=$?
    if [ "$snapshot_status" -ne 0 ]; then
        SYSCTL_QUERY_READY["$cache_key"]=1
        SYSCTL_QUERY_STATUS["$cache_key"]="$snapshot_status"
        SYSCTL_QUERY_VALUE["$cache_key"]=""
        sysctl_commit_query_result "$resolver_id" "$snapshot_status" "" || return 2
        resolver_debug_emit sysctl_query source static namespace "$namespace" cache build \
            status "$snapshot_status" match unavailable
        return "$snapshot_status"
    fi

    if [ "${SYSCTL_EXACT_TYPE[$cache_key]+present}" = "present" ]; then
        match_kind="exact"
        exact_type="${SYSCTL_EXACT_TYPE[$cache_key]}"
        if [ "$exact_type" = "assignment" ]; then
            result_value="${SYSCTL_EXACT_VALUE[$cache_key]}"$'\t'"${SYSCTL_EXACT_SOURCE[$cache_key]}"
            SYSCTL_QUERY_STATUS["$cache_key"]=0
        else
            SYSCTL_QUERY_STATUS["$cache_key"]=1
        fi
    else
        glob_file="${SYSCTL_GLOB_FILE[$namespace]}"
        while IFS= read -r -d '' directive_name &&
            IFS= read -r -d '' directive_value &&
            IFS= read -r -d '' directive_source &&
            IFS= read -r -d '' line_number; do
            # The unquoted expansion is the validated sysctl glob pattern.
            # shellcheck disable=SC2254
            case "$normalized_target" in
                $directive_name) result_value="$directive_value"$'\t'"$directive_source:$line_number" ;;
            esac
        done < "$glob_file"
        if [ -n "$result_value" ]; then
            SYSCTL_QUERY_STATUS["$cache_key"]=0
            match_kind="glob"
        else
            SYSCTL_QUERY_STATUS["$cache_key"]=1
        fi
    fi

    SYSCTL_QUERY_READY["$cache_key"]=1
    SYSCTL_QUERY_VALUE["$cache_key"]="$result_value"
    printf -v "$destination_name" '%s' "$result_value"
    sysctl_commit_query_result "$resolver_id" "${SYSCTL_QUERY_STATUS[$cache_key]}" "$result_value" || return 2
    resolver_debug_emit sysctl_query source static namespace "$namespace" cache build \
        status "${SYSCTL_QUERY_STATUS[$cache_key]}" match "$match_kind"
    return "${SYSCTL_QUERY_STATUS[$cache_key]}"
}

sysctl_static_value() {
    local resolved_value=""

    sysctl_static_value_into "$1" resolved_value || return $?
    printf '%s\n' "$resolved_value"
}

sysctl_runtime_value_into() {
    local key="$1"
    local destination_name="$2"
    local cache_key=""
    local runtime_file=""
    local runtime_value=""
    local runtime_line=""
    local runtime_separator=""
    local runtime_status=0
    local resolver_id=""

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|key|destination_name|cache_key|runtime_file|runtime_value|runtime_line|runtime_separator|runtime_status|resolver_id)
            return 2
            ;;
    esac
    printf -v "$destination_name" '%s' ""
    case "${SCAN_EPOCH_ACTIVE:-0}" in
        0) resolver_reset_epoch_caches ;;
        1) ;;
        *) return 2 ;;
    esac
    resolver_ensure_epoch_cache || return 2
    sysctl_cache_key_into runtime "$key" cache_key || return 2
    resolver_id="sysctl:runtime:$key"
    if declare -F scan_dependency_register >/dev/null 2>&1; then
        scan_dependency_register runtime:sysctl "$resolver_id" || return 2
    fi
    if [ "${SYSCTL_RUNTIME_READY[$cache_key]+present}" = "present" ]; then
        printf -v "$destination_name" '%s' "${SYSCTL_RUNTIME_VALUE[$cache_key]}"
        resolver_debug_emit sysctl_query source runtime namespace runtime cache hit \
            status "${SYSCTL_RUNTIME_STATUS[$cache_key]}"
        return "${SYSCTL_RUNTIME_STATUS[$cache_key]}"
    fi
    resolver_debug_emit sysctl_query source runtime namespace runtime cache miss

    runtime_file="$(new_scratch_file sysctl-runtime)" || return 2
    capture_command sysctl -n "$key" > "$runtime_file" 2>/dev/null || runtime_status=$?
    if [ "$runtime_status" -eq 0 ]; then
        while IFS= read -r runtime_line || [ -n "$runtime_line" ]; do
            runtime_value+="$runtime_separator$runtime_line"
            runtime_separator=$'\n'
        done < "$runtime_file"
        while [[ "$runtime_value" == *$'\n' ]]; do
            runtime_value="${runtime_value%$'\n'}"
        done
    fi
    SYSCTL_RUNTIME_READY["$cache_key"]=1
    SYSCTL_RUNTIME_STATUS["$cache_key"]="$runtime_status"
    SYSCTL_RUNTIME_VALUE["$cache_key"]="$runtime_value"
    printf -v "$destination_name" '%s' "$runtime_value"
    sysctl_commit_query_result "$resolver_id" "$runtime_status" "$runtime_value" || return 2
    resolver_debug_emit sysctl_query source runtime namespace runtime cache build \
        status "$runtime_status"
    return "$runtime_status"
}

sysctl_runtime_value() {
    local resolved_value=""

    sysctl_runtime_value_into "$1" resolved_value || return $?
    printf '%s\n' "$resolved_value"
}

sysctl_loader_kind() {
    local systemctl_path=""
    local properties=""
    local command_status=0

    if ! runtime_enabled; then
        printf 'offline-systemd-model\n'
        return 0
    fi

    systemctl_path="$(trusted_command systemctl)" || return 2
    if [ "${SCAN_EPOCH_ACTIVE:-0}" -eq 1 ]; then
        systemd_epoch_properties_into systemd-sysctl.service properties || return 2
        command_status="$SYSTEMD_PROPERTIES_COMMAND_STATUS"
    else
        properties="$($systemctl_path show systemd-sysctl.service \
            -p LoadState -p ExecStart -p LoadCredential -p LoadCredentialEncrypted \
            -p SetCredential -p SetCredentialEncrypted -p ImportCredential \
            --no-pager 2>/dev/null)" || command_status=$?
    fi
    [ "$command_status" -eq 0 ] || return 2
    if printf '%s\n' "$properties" | awk -F= '
        $1 ~ /^(LoadCredential|LoadCredentialEncrypted)$/ && length($2) > 0 && $2 != "sysctl.extra" {found=1}
        $1 ~ /^(SetCredential|SetCredentialEncrypted)$/ && length($2) > 0 {found=1}
        $1 == "ImportCredential" && length($2) > 0 && $2 != "sysctl.*" {found=1}
        END {exit(found ? 0 : 1)}
    '; then
        return 2
    fi
    case "$properties" in
        *systemd-sysctl*)
            if systemd_sysctl_execstart_binary "$properties" >/dev/null 2>&1; then
                printf 'systemd-sysctl\n'
                return 0
            fi
            return 2
            ;;
        *'sysctl --system'*|*'sysctl -p'*) printf 'procps-sysctl\n'; return 0 ;;
        *) return 2 ;;
    esac
}

sysctl_credential_override_present() {
    local candidate=""
    local cmdline=""

    for candidate in /run/credentials/@system/sysctl.extra /run/credentials/systemd-sysctl.service/sysctl.extra; do
        candidate="$(fs_path "$candidate" 2>/dev/null || true)"
        [ -n "$candidate" ] && { [ -e "$candidate" ] || [ -L "$candidate" ]; } && return 0
    done
    cmdline="$(fs_path /proc/cmdline 2>/dev/null || true)"
    if [ -r "$cmdline" ] && grep -Eq 'systemd[.]set_credential(_binary)?=sysctl[.]extra:' "$cmdline"; then
        return 0
    fi
    return 1
}

ufw_static_state() {
    local configuration_file=""
    local configuration_status=0
    local enabled_value=""
    local logical_file=""

    platform_is_debian_family || return 1
    for logical_file in /etc/ufw/ufw.conf /etc/default/ufw; do
        configuration_status=0
        configuration_file="$(optional_rooted_read_path "$logical_file" 2>/dev/null)" || configuration_status=$?
        [ "$configuration_status" -ne 2 ] || return 2
        [ "$configuration_status" -eq 0 ] || continue
        enabled_value="$(awk '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                sub(/^export[[:space:]]+/, "", line)
                if (line !~ /^ENABLED[[:space:]]*=/) next
                sub(/^ENABLED[[:space:]]*=[[:space:]]*/, "", line)
                sub(/[[:space:]]+#.*$/, "", line)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
                if (line ~ /^".*"$/ || line ~ /^\047.*\047$/) line=substr(line, 2, length(line)-2)
                value=tolower(line)
            }
            END {print value}
        ' "$configuration_file")"
        [ -n "$enabled_value" ] && break
    done
    case "$enabled_value" in
        yes|true|1) return 0 ;;
        no|false|0|'') return 1 ;;
        *) return 2 ;;
    esac
}

ufw_effective_state() {
    local output=""
    local static_status=0

    platform_is_debian_family || return 1
    ufw_static_state || static_status=$?
    [ "$static_status" -ne 2 ] || return 2
    [ "$static_status" -eq 0 ] && return 0
    if runtime_enabled; then
        output="$(capture_command ufw status 2>/dev/null || true)"
        printf '%s\n' "$output" | grep -q '^Status:[[:space:]]*active' && return 0
        printf '%s\n' "$output" | grep -q '^Status:[[:space:]]*inactive' && return 1
    fi
    return 1
}

ufw_sysctl_configuration_file() {
    local defaults_file=""
    local defaults_status=0
    local logical_path=""
    local configuration_file=""

    defaults_file="$(optional_rooted_read_path /etc/default/ufw 2>/dev/null)" || defaults_status=$?
    [ "$defaults_status" -ne 2 ] || return 2
    if [ "$defaults_status" -eq 0 ]; then
        logical_path="$(awk '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                sub(/^export[[:space:]]+/, "", line)
                if (line !~ /^IPT_SYSCTL[[:space:]]*=/) next
                sub(/^IPT_SYSCTL[[:space:]]*=[[:space:]]*/, "", line)
                sub(/[[:space:]]+#.*$/, "", line)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
                if (line ~ /^".*"$/ || line ~ /^\047.*\047$/) line=substr(line, 2, length(line)-2)
                value=line
            }
            END {print value}
        ' "$defaults_file")"
        case "$logical_path" in
            *'$'*|*'`'*|*\\*|*[[:space:]]*) return 2 ;;
        esac
        if [ -z "$logical_path" ]; then
            if awk '
                {line=$0; sub(/^[[:space:]]+/, "", line); sub(/^export[[:space:]]+/, "", line)}
                line ~ /^IPT_SYSCTL[[:space:]]*=/ {found=1}
                END {exit(found ? 0 : 1)}
            ' "$defaults_file"; then
                return 1
            fi
            logical_path="/etc/ufw/sysctl.conf"
        fi
    else
        logical_path="/etc/ufw/sysctl.conf"
    fi
    case "$logical_path" in /*) ;; *) return 2 ;; esac
    configuration_file="$(optional_rooted_read_path "$logical_path" 2>/dev/null)" || return $?
    printf '%s\n' "$configuration_file"
}

ufw_sysctl_value() (
    local key="$1"
    local configuration_file=""

    SYSCTL_STATIC_NAMESPACE="ufw"
    ufw_effective_state || return $?
    configuration_file="$(ufw_sysctl_configuration_file)" || return $?
    sysctl_static_files() {
        printf '%s\n' "$configuration_file"
    }
    sysctl_static_value "$key"
)

sysctl_explain() {
    local key="$1"
    local persistent=""
    local runtime=""
    local nonstandard_directory=""
    local drift="unknown"
    local persistent_status=0
    local runtime_status=0
    local loader=""
    local loader_status=0
    local loader_stream_status="not_requested"
    local filesystem_persistent=""
    local loader_persistent=""
    local loader_value_status=0
    local model_drift="unknown"
    local credential_override="not_observed"
    local ufw_state="inactive"
    local ufw_status=0
    local ufw_persistent=""
    local ufw_value_status=0

    loader="$(sysctl_loader_kind 2>/dev/null)" || loader_status=$?
    [ "$loader_status" -eq 0 ] || loader="unresolved"
    sysctl_static_value_into "$key" filesystem_persistent 2>/dev/null || persistent_status=$?
    persistent="$filesystem_persistent"
    if runtime_enabled; then
        sysctl_runtime_value_into "$key" runtime 2>/dev/null || runtime_status=$?
        if [ "$loader" = "systemd-sysctl" ]; then
            if sysctl_credential_override_present; then
                credential_override="present"
                loader_status=2
            fi
            loader_persistent="$(systemd_sysctl_value "$key" 2>/dev/null)" || loader_value_status=$?
            if [ "$loader_value_status" -le 1 ]; then
                loader_stream_status="available"
                if [ "$loader_value_status" -eq 0 ]; then
                    if [ -n "$filesystem_persistent" ] && \
                        [ "${filesystem_persistent%%"$(printf '\t')"*}" = "${loader_persistent%%"$(printf '\t')"*}" ]; then
                        model_drift="none"
                    else
                        model_drift="present"
                    fi
                    persistent="${loader_persistent%%"$(printf '\t')"*}"$'\t'"loader-stream"
                    persistent_status=0
                elif [ -z "$filesystem_persistent" ]; then
                    persistent_status=1
                    model_drift="none"
                else
                    model_drift="present"
                    persistent=""
                    persistent_status=1
                fi
            else
                loader_stream_status="error"
                loader_status=2
            fi
        fi
    else
        runtime_status=3
    fi
    if platform_is_debian_family; then
        ufw_effective_state || ufw_status=$?
        case "$ufw_status" in
            0)
                ufw_state="enabled"
                ufw_persistent="$(ufw_sysctl_value "$key" 2>/dev/null)" || ufw_value_status=$?
                if [ "$ufw_value_status" -eq 0 ]; then
                    persistent="$ufw_persistent"
                    persistent_status=0
                elif [ "$ufw_value_status" -eq 2 ]; then
                    persistent_status=2
                fi
                ;;
            1) ufw_state="disabled" ;;
            *)
                ufw_state="unresolved"
                persistent_status=2
                ;;
        esac
    fi
    nonstandard_directory="$(fs_path /etc/sysctl.conf.d)"

    if [ -n "$persistent" ] && [ -n "$runtime" ]; then
        if [ "${persistent%%"$(printf '\t')"*}" = "$runtime" ]; then
            drift="none"
        else
            drift="present"
        fi
    fi

    printf 'key=%s\n' "$key"
    printf 'loader=%s\n' "$loader"
    printf 'loader_stream=%s\n' "$loader_stream_status"
    printf 'sysctl_extra_credential=%s\n' "$credential_override"
    printf 'ufw_state=%s\n' "$ufw_state"
    printf 'ufw_persistent=%s\n' "${ufw_persistent:-unconfigured}"
    printf 'filesystem_persistent=%s\n' "${filesystem_persistent:-unconfigured}"
    printf 'persistent_model_drift=%s\n' "$model_drift"
    printf 'persistent=%s\n' "${persistent:-unconfigured}"
    printf 'persistent_status=%s\n' "$persistent_status"
    printf 'runtime=%s\n' "${runtime:-unavailable}"
    printf 'runtime_status=%s\n' "$runtime_status"
    printf 'drift=%s\n' "$drift"
    if [ -d "$nonstandard_directory" ]; then
        printf 'inactive_nonstandard_directory=/etc/sysctl.conf.d\n'
    fi
    [ "$loader_status" -eq 0 ] || return 2
    [ "$persistent_status" -le 1 ] || return 2
    if runtime_enabled && [ "$runtime_status" -ne 0 ]; then
        return 2
    fi
    [ "$loader" = "procps-sysctl" ] && return 2
    return 0
}

systemd_reset_epoch_cache() {
    local current_epoch="${SCAN_EPOCH_ID:-0}"

    case "$current_epoch" in ''|*[!0-9]*) current_epoch=0 ;; esac
    SYSTEMD_CACHE_RESET_SEQUENCE=$((SYSTEMD_CACHE_RESET_SEQUENCE + 1))
    SYSTEMD_CACHE_EPOCH="$current_epoch"
    SYSTEMD_CACHE_SCRATCH_DIR="${SCRATCH_DIR:-}"
    SYSTEMD_CACHE_NAMESPACE="${current_epoch}-${SYSTEMD_CACHE_RESET_SEQUENCE}"
    SYSTEMD_CACHE_FACTS=""
    SYSTEMD_CACHE_COMMAND_STATUS=2
    SYSTEMD_BULK_STATUS=2
    SYSTEMD_PROPERTIES_COMMAND_STATUS=2
}

systemd_ensure_epoch_cache() {
    local current_epoch="${SCAN_EPOCH_ID:-0}"

    case "$current_epoch" in ''|*[!0-9]*) return 2 ;; esac
    if [ "$SYSTEMD_CACHE_EPOCH" != "$current_epoch" ] ||
        [ "$SYSTEMD_CACHE_SCRATCH_DIR" != "${SCRATCH_DIR:-}" ] ||
        [ -z "$SYSTEMD_CACHE_NAMESPACE" ]; then
        systemd_reset_epoch_cache
    fi
    [ -n "${SCRATCH_DIR:-}" ] && [ -d "$SCRATCH_DIR" ] && [ ! -L "$SCRATCH_DIR" ]
}

systemd_unit_name_is_valid() {
    local unit="$1"

    case "$unit" in
        ''|-*|*[!A-Za-z0-9_.@:-]*) return 1 ;;
        *.service|*.socket) return 0 ;;
        *) return 1 ;;
    esac
}

systemd_fact_value_into() {
    local facts="$1"
    local property_name="$2"
    local destination_name="$3"
    local line=""

    case "$property_name" in ''|*[!A-Za-z0-9]*) return 2 ;; esac
    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|facts|property_name|destination_name|line) return 2 ;;
    esac
    printf -v "$destination_name" '%s' ""
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            "$property_name="*)
                printf -v "$destination_name" '%s' "${line#*=}"
                return 0
                ;;
        esac
    done <<< "$facts"
    return 1
}

systemd_commit_cached_unit() {
    local unit="$1"
    local commit_status=0

    declare -F scan_resolver_commit >/dev/null 2>&1 || return 0
    [ "${SCAN_INCREMENTAL_REEVALUATION_ACTIVE:-0}" -eq 1 ] || return 0
    scan_resolver_commit "systemd-unit:$unit" \
        "command_status=${SYSTEMD_CACHE_COMMAND_STATUS}"$'\n'"${SYSTEMD_CACHE_FACTS}" || commit_status=$?
    case "$commit_status" in 0|1) return 0 ;; *) return 2 ;; esac
}

systemd_cache_read_status() {
    local status_file="$1"
    local status_value=""

    [ -f "$status_file" ] && [ ! -L "$status_file" ] || return 2
    IFS= read -r status_value < "$status_file" || return 2
    case "$status_value" in ''|*[!0-9]*) return 2 ;; esac
    [ "$status_value" -le 255 ] || return 2
    SYSTEMD_CACHE_COMMAND_STATUS="$status_value"
}

systemd_cache_write_status() {
    local status_file="$1"
    local status_value="$2"
    local temp_file=""

    case "$status_value" in ''|*[!0-9]*) return 2 ;; esac
    [ "$status_value" -le 255 ] || return 2
    temp_file="$(new_scratch_file systemd-status)" || return 2
    printf '%s\n' "$status_value" > "$temp_file" || return 2
    chmod 0600 "$temp_file" || return 2
    mv -f -- "$temp_file" "$status_file" || return 2
}

systemd_cache_install_facts() {
    local source_file="$1"
    local facts_file="$2"

    [ -f "$source_file" ] && [ ! -L "$source_file" ] || return 2
    chmod 0600 "$source_file" || return 2
    mv -f -- "$source_file" "$facts_file" || return 2
}

systemd_show_one_unit() {
    local systemctl_path="$1"
    local unit="$2"

    "$systemctl_path" show "$unit" \
        -p Id -p Names -p LoadState -p ActiveState -p SubState -p UnitFileState \
        -p FragmentPath -p DropInPaths -p Triggers -p TriggeredBy \
        -p MainPID -p ExecStart -p Environment -p EnvironmentFiles \
        -p LoadCredential -p LoadCredentialEncrypted -p SetCredential \
        -p SetCredentialEncrypted -p ImportCredential --no-pager
}

systemd_prepare_bulk_cache() {
    local bulk_file=""
    local bulk_status_file=""
    local alias_file=""
    local temp_file=""
    local alias_temp_file=""
    local systemctl_path=""
    local command_status=0
    local command_availability="available"

    systemd_ensure_epoch_cache || return 2
    bulk_file="$SCRATCH_DIR/.systemd-bulk-${SYSTEMD_CACHE_NAMESPACE}.facts"
    bulk_status_file="$SCRATCH_DIR/.systemd-bulk-${SYSTEMD_CACHE_NAMESPACE}.status"
    alias_file="$SCRATCH_DIR/.systemd-bulk-${SYSTEMD_CACHE_NAMESPACE}.aliases"

    if [ -f "$bulk_status_file" ] && [ ! -L "$bulk_status_file" ]; then
        systemd_cache_read_status "$bulk_status_file" || return 2
        SYSTEMD_BULK_STATUS="$SYSTEMD_CACHE_COMMAND_STATUS"
        resolver_debug_emit systemd_bulk cache hit status "$SYSTEMD_BULK_STATUS"
        return 0
    fi
    resolver_debug_emit systemd_bulk cache miss
    [ ! -e "$bulk_file" ] && [ ! -L "$bulk_file" ] || return 2
    [ ! -e "$bulk_status_file" ] && [ ! -L "$bulk_status_file" ] || return 2
    [ ! -e "$alias_file" ] && [ ! -L "$alias_file" ] || return 2

    temp_file="$(new_scratch_file systemd-bulk)" || return 2
    systemctl_path="$(trusted_command systemctl 2>/dev/null || true)"
    if [ -z "$systemctl_path" ]; then
        command_availability="unavailable"
        command_status=2
        : > "$temp_file" || return 2
    else
        "$systemctl_path" show --all --type=service --type=socket \
            -p Id -p Names -p LoadState -p ActiveState -p SubState -p UnitFileState \
            -p FragmentPath -p DropInPaths -p Triggers -p TriggeredBy \
            -p MainPID -p ExecStart -p Environment -p EnvironmentFiles \
            -p LoadCredential -p LoadCredentialEncrypted -p SetCredential \
            -p SetCredentialEncrypted -p ImportCredential --no-pager \
            > "$temp_file" 2>/dev/null || command_status=$?
    fi

    if [ "$command_status" -eq 0 ] && ! grep -Eq '^Id=[A-Za-z0-9_.@:-]+\.(service|socket)$' "$temp_file"; then
        # Some systemctl versions do not support an unqualified typed show query.
        command_status=2
    fi

    alias_temp_file="$(new_scratch_file systemd-aliases)" || return 2
    if [ "$command_status" -eq 0 ]; then
        awk '
            function valid(value) {
                return value ~ /^[A-Za-z0-9_.@:-]+\.(service|socket)$/
            }
            function flush(    count,index_value,name) {
                if (!valid(identifier)) {identifier=""; names=""; return}
                print identifier "\t" identifier
                count=split(names, name_values, /[[:space:]]+/)
                for (index_value=1; index_value<=count; index_value++) {
                    name=name_values[index_value]
                    if (valid(name)) print name "\t" identifier
                }
                identifier=""
                names=""
            }
            /^Id=/ {
                if (identifier != "") flush()
                identifier=substr($0, 4)
                next
            }
            /^Names=/ {names=substr($0, 7); next}
            /^[[:space:]]*$/ {flush()}
            END {flush()}
        ' "$temp_file" | LC_ALL=C sort -u > "$alias_temp_file" || return 2
    else
        : > "$alias_temp_file" || return 2
    fi

    systemd_cache_install_facts "$temp_file" "$bulk_file" || return 2
    systemd_cache_install_facts "$alias_temp_file" "$alias_file" || return 2
    systemd_cache_write_status "$bulk_status_file" "$command_status" || return 2
    SYSTEMD_BULK_STATUS="$command_status"
    resolver_debug_emit systemd_bulk cache build status "$SYSTEMD_BULK_STATUS" \
        command "$command_availability"
}

systemd_bulk_identifier_for_unit() {
    local unit="$1"
    local alias_file="$SCRATCH_DIR/.systemd-bulk-${SYSTEMD_CACHE_NAMESPACE}.aliases"
    local identifier=""
    local match_count=0
    local result=""

    [ -f "$alias_file" ] && [ ! -L "$alias_file" ] || return 1
    result="$(awk -F '\t' -v unit="$unit" '
        $1 == unit && !seen[$2]++ {count++; value=$2}
        END {
            if (count == 1) print value
            else if (count > 1) exit 2
            else exit 1
        }
    ' "$alias_file")"
    match_count=$?
    [ "$match_count" -eq 0 ] || return "$match_count"
    identifier="$result"
    systemd_unit_name_is_valid "$identifier" || return 2
    printf '%s\n' "$identifier"
}

systemd_extract_bulk_record() {
    local identifier="$1"
    local destination_file="$2"
    local bulk_file="$SCRATCH_DIR/.systemd-bulk-${SYSTEMD_CACHE_NAMESPACE}.facts"

    [ -f "$bulk_file" ] && [ ! -L "$bulk_file" ] || return 2
    awk -v RS='' -v identifier="$identifier" '
        {
            count=split($0, lines, /\n/)
            matched=0
            for (index_value=1; index_value<=count; index_value++) {
                if (lines[index_value] == "Id=" identifier) matched=1
            }
            if (matched) {
                print $0
                found++
            }
        }
        END {exit(found == 1 ? 0 : 1)}
    ' "$bulk_file" > "$destination_file"
}

systemd_cached_unit_facts() {
    local unit="$1"
    local facts_file=""
    local status_file=""
    local temp_file=""
    local identifier=""
    local identifier_status=0
    local systemctl_path=""
    local command_status=0
    local resolution_method="single"

    SYSTEMD_CACHE_FACTS=""
    SYSTEMD_CACHE_COMMAND_STATUS=2
    systemd_unit_name_is_valid "$unit" || return 2
    case "${SCAN_EPOCH_ACTIVE:-0}" in
        0)
            systemctl_path="$(trusted_command systemctl 2>/dev/null || true)"
            [ -n "$systemctl_path" ] || return 2
            temp_file="$(new_scratch_file systemd-uncached)" || return 2
            systemd_show_one_unit "$systemctl_path" "$unit" > "$temp_file" 2>/dev/null || command_status=$?
            SYSTEMD_CACHE_COMMAND_STATUS="$command_status"
            SYSTEMD_CACHE_FACTS="$(< "$temp_file")"
            resolver_debug_emit systemd_unit unit "$unit" cache bypass method single \
                status "$command_status"
            return 0
            ;;
        1) ;;
        *) return 2 ;;
    esac
    systemd_ensure_epoch_cache || return 2
    if declare -F scan_dependency_register >/dev/null 2>&1; then
        scan_dependency_register runtime:systemd "systemd-unit:$unit" || return 2
    fi

    facts_file="$SCRATCH_DIR/.systemd-unit-${SYSTEMD_CACHE_NAMESPACE}-${unit}.facts"
    status_file="$SCRATCH_DIR/.systemd-unit-${SYSTEMD_CACHE_NAMESPACE}-${unit}.status"
    if [ -f "$status_file" ] && [ ! -L "$status_file" ]; then
        [ -f "$facts_file" ] && [ ! -L "$facts_file" ] || return 2
        systemd_cache_read_status "$status_file" || return 2
        SYSTEMD_CACHE_FACTS="$(< "$facts_file")"
        systemd_commit_cached_unit "$unit" || return 2
        resolver_debug_emit systemd_unit unit "$unit" cache hit \
            status "$SYSTEMD_CACHE_COMMAND_STATUS"
        return 0
    fi
    resolver_debug_emit systemd_unit unit "$unit" cache miss
    [ ! -e "$facts_file" ] && [ ! -L "$facts_file" ] || return 2
    [ ! -e "$status_file" ] && [ ! -L "$status_file" ] || return 2

    systemd_prepare_bulk_cache || return 2
    temp_file="$(new_scratch_file systemd-unit)" || return 2
    if [ "$SYSTEMD_BULK_STATUS" -eq 0 ]; then
        identifier="$(systemd_bulk_identifier_for_unit "$unit")" || identifier_status=$?
        if [ "$identifier_status" -eq 0 ] && systemd_extract_bulk_record "$identifier" "$temp_file"; then
            command_status=0
            resolution_method="bulk"
        else
            identifier_status=1
        fi
    else
        identifier_status=1
    fi

    if [ "$identifier_status" -ne 0 ]; then
        : > "$temp_file" || return 2
        systemctl_path="$(trusted_command systemctl 2>/dev/null || true)"
        if [ -z "$systemctl_path" ]; then
            command_status=2
        else
            systemd_show_one_unit "$systemctl_path" "$unit" > "$temp_file" 2>/dev/null || command_status=$?
        fi
    fi

    systemd_cache_install_facts "$temp_file" "$facts_file" || return 2
    systemd_cache_write_status "$status_file" "$command_status" || return 2
    SYSTEMD_CACHE_COMMAND_STATUS="$command_status"
    SYSTEMD_CACHE_FACTS="$(< "$facts_file")"
    systemd_commit_cached_unit "$unit" || return 2
    resolver_debug_emit systemd_unit unit "$unit" cache build method "$resolution_method" \
        status "$command_status"
}

systemd_epoch_properties_into() {
    local unit="$1"
    local destination_name="$2"

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|unit|destination_name) return 2 ;;
    esac
    [ "${SCAN_EPOCH_ACTIVE:-0}" -eq 1 ] || return 2
    systemd_cached_unit_facts "$unit" || return 2
    SYSTEMD_PROPERTIES_COMMAND_STATUS="$SYSTEMD_CACHE_COMMAND_STATUS"
    printf -v "$destination_name" '%s' "$SYSTEMD_CACHE_FACTS"
}

service_state() {
    local unit=""
    local state=""
    local load_state=""
    local active_state=""
    local command_status=0
    local saw_unit=0
    local manager_status=0

    if [ "${EVIDENCE_BUNDLE_ACTIVE:-0}" -eq 1 ] && declare -F evidence_service_state >/dev/null 2>&1; then
        evidence_service_state "$@"
        return $?
    fi
    if runtime_enabled && declare -F runtime_systemd_manager_state >/dev/null 2>&1; then
        runtime_systemd_manager_state || manager_status=$?
        [ "$manager_status" -ne 1 ] || return 3
    fi
    if [ "$#" -eq 0 ]; then
        trusted_command systemctl >/dev/null 2>&1 || return 2
        return 3
    fi

    for unit in "$@"; do
        systemd_cached_unit_facts "$unit" || return 2
        state="$SYSTEMD_CACHE_FACTS"
        command_status="$SYSTEMD_CACHE_COMMAND_STATUS"
        systemd_fact_value_into "$state" LoadState load_state || load_state=""
        systemd_fact_value_into "$state" ActiveState active_state || active_state=""
        if [ "$command_status" -ne 0 ] && [ "$load_state" != "not-found" ]; then
            return 2
        fi
        command_status=0
        [ -n "$load_state" ] || continue
        [ "$load_state" != "not-found" ] || continue
        saw_unit=1
        [ "$active_state" = "active" ] && return 0
    done

    [ "$saw_unit" -eq 1 ] && return 1
    return 3
}

service_facts() {
    local unit=""
    local output=""
    local output_line=""

    if [ "${EVIDENCE_BUNDLE_ACTIVE:-0}" -eq 1 ]; then
        [ "${EVIDENCE_RUNTIME_SYSTEMD_UNITS_STATUS:-}" = "collected" ] || return 2
        for unit in "$@"; do
            awk -F '\t' -v unit="$unit" 'NR > 1 && $1 == unit {
                printf "unit=%s LoadState=%s ActiveState=%s SubState=%s UnitFileState=%s\n", $1, $2, $3, $4, $5
            }' "$EVIDENCE_RUNTIME_SYSTEMD_UNITS_PATH"
        done
        return 0
    fi
    if [ "$#" -eq 0 ]; then
        trusted_command systemctl >/dev/null 2>&1 || return 2
        return 0
    fi

    for unit in "$@"; do
        systemd_cached_unit_facts "$unit" || return 2
        [ "$SYSTEMD_CACHE_COMMAND_STATUS" -eq 0 ] || return 2
        output="$SYSTEMD_CACHE_FACTS"
        while IFS= read -r output_line || [ -n "$output_line" ]; do
            case "$output_line" in Id=*) continue ;; esac
            printf 'unit=%s %s\n' "$unit" "$output_line"
        done <<< "$output"
    done
}

listener_reset_epoch_cache() {
    local current_epoch="${SCAN_EPOCH_ID:-0}"

    case "$current_epoch" in ''|*[!0-9]*) current_epoch=0 ;; esac
    LISTENER_CACHE_RESET_SEQUENCE=$((LISTENER_CACHE_RESET_SEQUENCE + 1))
    LISTENER_CACHE_EPOCH="$current_epoch"
    LISTENER_CACHE_SCRATCH_DIR="${SCRATCH_DIR:-}"
    LISTENER_CACHE_NAMESPACE="${current_epoch}-${LISTENER_CACHE_RESET_SEQUENCE}"
    LISTENER_CACHE_COMMAND_STATUS=2
    LISTENER_CACHE_FACTS_FILE=""
}

listener_ensure_epoch_cache() {
    local current_epoch="${SCAN_EPOCH_ID:-0}"

    case "$current_epoch" in ''|*[!0-9]*) return 2 ;; esac
    if [ "$LISTENER_CACHE_EPOCH" != "$current_epoch" ] ||
        [ "$LISTENER_CACHE_SCRATCH_DIR" != "${SCRATCH_DIR:-}" ] ||
        [ -z "$LISTENER_CACHE_NAMESPACE" ]; then
        listener_reset_epoch_cache
    fi
    [ -n "${SCRATCH_DIR:-}" ] && [ -d "$SCRATCH_DIR" ] && [ ! -L "$SCRATCH_DIR" ]
}

listener_commit_epoch_snapshot() {
    local normalized_output="status=${LISTENER_CACHE_COMMAND_STATUS}"
    local commit_status=0

    declare -F scan_resolver_commit >/dev/null 2>&1 || return 0
    [ "${SCAN_INCREMENTAL_REEVALUATION_ACTIVE:-0}" -eq 1 ] || return 0
    if [ -n "$LISTENER_CACHE_FACTS_FILE" ] && [ -f "$LISTENER_CACHE_FACTS_FILE" ] &&
        [ ! -L "$LISTENER_CACHE_FACTS_FILE" ]; then
        normalized_output+=$'\n'"$(< "$LISTENER_CACHE_FACTS_FILE")"
    fi
    scan_resolver_commit listener:snapshot "$normalized_output" || commit_status=$?
    case "$commit_status" in 0|1) return 0 ;; *) return 2 ;; esac
}

listener_prepare_epoch_snapshot() {
    local snapshot_file=""
    local status_file=""
    local temp_file=""
    local command_status=0
    local proc_rows=""
    local proc_ss_rows=""
    local proc_status=0

    listener_ensure_epoch_cache || return 2
    snapshot_file="$SCRATCH_DIR/.listener-snapshot-mixed-${LISTENER_CACHE_NAMESPACE}"
    status_file="${snapshot_file}.status"
    LISTENER_CACHE_FACTS_FILE="$snapshot_file"

    if [ -f "$status_file" ] && [ ! -L "$status_file" ]; then
        [ -f "$snapshot_file" ] && [ ! -L "$snapshot_file" ] || return 2
        IFS= read -r command_status < "$status_file" || return 2
        case "$command_status" in ''|*[!0-9]*) return 2 ;; esac
        [ "$command_status" -le 255 ] || return 2
        LISTENER_CACHE_COMMAND_STATUS="$command_status"
        listener_commit_epoch_snapshot || return 2
        resolver_debug_emit listener_snapshot transport mixed cache hit status "$command_status"
        return 0
    fi
    resolver_debug_emit listener_snapshot transport mixed cache miss
    [ ! -e "$snapshot_file" ] && [ ! -L "$snapshot_file" ] || return 2
    [ ! -e "$status_file" ] && [ ! -L "$status_file" ] || return 2

    temp_file="$(new_scratch_file listener-mixed)" || return 2
    capture_command ss -H -lntup > "$temp_file" 2>/dev/null || command_status=$?
    if [ "$command_status" -ne 0 ] &&
        declare -F runtime_listener_snapshot_into >/dev/null 2>&1; then
        proc_status=0
        runtime_listener_snapshot_into proc_rows || proc_status=$?
        listener_proc_rows_to_ss_into "$proc_rows" proc_ss_rows || return 2
        printf '%s\n' "$proc_ss_rows" > "$temp_file" || return 2
        case "$proc_status" in
            0) command_status=0 ;;
            3) command_status=3 ;;
            *) command_status=2 ;;
        esac
    fi
    systemd_cache_install_facts "$temp_file" "$snapshot_file" || return 2
    systemd_cache_write_status "$status_file" "$command_status" || return 2
    LISTENER_CACHE_COMMAND_STATUS="$command_status"
    listener_commit_epoch_snapshot || return 2
    resolver_debug_emit listener_snapshot transport mixed cache build status "$command_status"
}

listener_epoch_facts_for_port() {
    local port="$1"
    local transport="$2"

    listener_prepare_epoch_snapshot || return 2
    case "$LISTENER_CACHE_COMMAND_STATUS" in 0|3) ;; *) return "$LISTENER_CACHE_COMMAND_STATUS" ;; esac
    case "$transport" in
        any)
            if awk -v port=":$port" '$5 ~ port "$" {print; found=1} END {exit(found ? 0 : 1)}' \
                "$LISTENER_CACHE_FACTS_FILE"; then
                return 0
            fi
            ;;
        tcp|udp)
            if awk -v transport="$transport" -v port=":$port" '
                $1 == transport && $5 ~ port "$" {
                    $1=""
                    sub(/^[[:space:]]+/, "")
                    print
                    found=1
                }
                END {exit(found ? 0 : 1)}
            ' "$LISTENER_CACHE_FACTS_FILE"; then
                return 0
            fi
            ;;
        *) return 2 ;;
    esac
    [ "$LISTENER_CACHE_COMMAND_STATUS" -eq 0 ] && return 0
    return 2
}

listener_proc_rows_to_ss_into() {
    local proc_rows="$1"
    local destination_name="$2"
    local row=""
    local transport=""
    local local_address=""
    local port=""
    local process_name=""
    local endpoint=""
    local process_field=""
    local normalized_rows=""

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|proc_rows|destination_name|row|transport|local_address|port|process_name|endpoint|process_field|normalized_rows)
            return 2
            ;;
    esac
    while IFS= read -r row || [ -n "$row" ]; do
        [ -n "$row" ] || continue
        IFS=$'\t' read -r transport local_address port process_name _ <<< "$row"
        case "$transport:$port" in
            tcp:[0-9]*|udp:[0-9]*) ;;
            *) return 2 ;;
        esac
        case "$local_address" in
            *:*) endpoint="[${local_address}]:${port}" ;;
            *) endpoint="${local_address}:${port}" ;;
        esac
        process_field=""
        [ "$process_name" = "-" ] || process_field="users:((\"${process_name}\"))"
        [ -z "$normalized_rows" ] || normalized_rows+=$'\n'
        normalized_rows+="${transport} LISTEN 0 0 ${endpoint} * ${process_field}"
    done <<< "$proc_rows"
    printf -v "$destination_name" '%s' "$normalized_rows"
}

port_listener_facts() {
    local port="$1"
    local transport="${2:-any}"
    local output=""
    local local_endpoint_field=0
    local snapshot_file=""
    local snapshot_status_file=""
    local snapshot_status=0
    local snapshot_generation=0
    local ss_arguments=()
    local proc_rows=""
    local proc_status=0
    local native_status=0
    local used_proc_fallback=0

    case "$transport" in
        tcp)
            ss_arguments=(-H -lntp)
            local_endpoint_field=4
            ;;
        udp)
            ss_arguments=(-H -lnup)
            local_endpoint_field=4
            ;;
        any)
            ss_arguments=(-H -lntup)
            local_endpoint_field=5
            ;;
        *) return 2 ;;
    esac

    if [ "${EVIDENCE_BUNDLE_ACTIVE:-0}" -eq 1 ] && declare -F evidence_listener_facts >/dev/null 2>&1; then
        local row_transport=""
        local local_address=""
        local row_port=""
        local process_name=""
        local endpoint=""
        local process_field=""

        [ "${EVIDENCE_RUNTIME_LISTENERS_STATUS:-}" = "collected" ] || return 2
        while IFS=$'\t' read -r row_transport local_address row_port process_name; do
            [ -n "$row_transport" ] || continue
            case "$local_address" in
                *:*) endpoint="[${local_address}]:${row_port}" ;;
                *) endpoint="${local_address}:${row_port}" ;;
            esac
            process_field=""
            [ -z "$process_name" ] || process_field="users:((\"${process_name}\"))"
            if [ "$transport" = "any" ]; then
                printf '%s LISTEN 0 0 %s * %s\n' "$row_transport" "$endpoint" "$process_field"
            else
                printf 'LISTEN 0 0 %s * %s\n' "$endpoint" "$process_field"
            fi
        done < <(evidence_listener_facts "$transport" "$port")
        return 0
    fi

    case "${SCAN_EPOCH_ACTIVE:-0}" in
        0) ;;
        1)
            case "$port" in ''|*[!0-9]*) return 2 ;; esac
            [ "$port" -le 65535 ] || return 2
            if declare -F scan_dependency_register >/dev/null 2>&1; then
                scan_dependency_register runtime:listeners listener:snapshot || return 2
            fi
            listener_epoch_facts_for_port "$port" "$transport"
            return $?
            ;;
        *) return 2 ;;
    esac

    if [ "$LISTENER_SNAPSHOT_CACHE_ENABLED" -eq 1 ]; then
        [ -n "$SCRATCH_DIR" ] && [ -d "$SCRATCH_DIR" ] && [ ! -L "$SCRATCH_DIR" ] || return 2
        snapshot_generation="${LISTENER_SNAPSHOT_GENERATION:-0}"
        case "$snapshot_generation" in
            ''|*[!0-9]*) return 2 ;;
        esac
        if [ "$snapshot_generation" -eq 0 ]; then
            snapshot_file="$SCRATCH_DIR/.listener-snapshot-${transport}"
        else
            snapshot_file="$SCRATCH_DIR/.listener-snapshot-${transport}-${snapshot_generation}"
        fi
        snapshot_status_file="${snapshot_file}.status"
        if [ -f "$snapshot_status_file" ] && [ ! -L "$snapshot_status_file" ]; then
            [ -f "$snapshot_file" ] && [ ! -L "$snapshot_file" ] || return 2
            IFS= read -r snapshot_status < "$snapshot_status_file" || return 2
            case "$snapshot_status" in
                ''|*[!0-9]*) return 2 ;;
            esac
            [ "$snapshot_status" -le 255 ] || return 2
            resolver_debug_emit listener_snapshot transport "$transport" cache hit \
                status "$snapshot_status"
        else
            resolver_debug_emit listener_snapshot transport "$transport" cache miss
            [ ! -e "$snapshot_status_file" ] && [ ! -L "$snapshot_status_file" ] || return 2
            [ ! -e "$snapshot_file" ] && [ ! -L "$snapshot_file" ] || return 2
            capture_command ss "${ss_arguments[@]}" > "$snapshot_file" 2>/dev/null
            snapshot_status=$?
            printf '%s\n' "$snapshot_status" > "$snapshot_status_file" || return 2
            resolver_debug_emit listener_snapshot transport "$transport" cache build \
                status "$snapshot_status"
        fi
        [ "$snapshot_status" -eq 0 ] || return "$snapshot_status"
        awk -v field="$local_endpoint_field" -v port=":$port" \
            '$field ~ port "$" {print}' "$snapshot_file"
        return $?
    fi

    output="$(capture_command ss "${ss_arguments[@]}" 2>/dev/null)" || native_status=$?
    if [ "$native_status" -ne 0 ]; then
        declare -F runtime_listener_facts_for_port_into >/dev/null 2>&1 || return "$native_status"
        proc_status=0
        runtime_listener_facts_for_port_into proc_rows "$port" "$transport" || proc_status=$?
        case "$proc_status" in
            0)
                listener_proc_rows_to_ss_into "$proc_rows" output || return 2
                used_proc_fallback=1
                ;;
            1) output=""; used_proc_fallback=1 ;;
            *) return 2 ;;
        esac
    fi
    if [ "$used_proc_fallback" -eq 1 ] && [ "$transport" != any ]; then
        output="$(printf '%s\n' "$output" | awk '{$1=""; sub(/^[[:space:]]+/, ""); print}')"
    fi
    printf '%s\n' "$output" | awk -v field="$local_endpoint_field" -v port=":$port" \
        '$field ~ port "$" {print}'
}
