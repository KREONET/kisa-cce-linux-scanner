# shellcheck shell=bash

# shellcheck disable=SC2016

# Configuration resolvers preserve subsystem-specific precedence and provenance.

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
        candidate_file="$(new_scratch_file layered-candidates)" || return 1
        find -P "$physical_directory" -maxdepth 1 \( -type f -o -type l \) -name "*${suffix}" -print0 > "$candidate_file" 2>/dev/null || return 2
        while IFS= read -r -d '' candidate; do
            basename_value="${candidate##*/}"
            case "$basename_value" in
                *$'\n'*|*$'\t'*) return 2 ;;
            esac
            if ! cut -f1 "$selection_file" 2>/dev/null | grep -Fqx -- "$basename_value"; then
                printf '%s\t%s\n' "$basename_value" "$candidate" >> "$selection_file" || return 1
            fi
        done < "$candidate_file"
    done

    LC_ALL=C sort -t "$(printf '\t')" -k1,1 "$selection_file" | cut -f2-
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

pam_expand_service_recursive() {
    local service="$1"
    local pam_type="$2"
    local depth="$3"
    local active_stack="$4"
    local recursion_key="${service}:${pam_type}"
    local service_file=""
    local logical_lines_file=""
    local line=""
    local line_type=""
    local control=""
    local include_service=""
    local source_mode="pamd"
    local configuration_status=0
    local record_service=""

    [ "$depth" -lt 16 ] || return 2
    case "$service" in
        /*)
            case "$service" in *$'\n'*|*$'\r'*|*$'\t'*|*/../*|*/..|*/./*|*/.) return 2 ;; esac
            ;;
        ''|*[!A-Za-z0-9_.+@-]*) return 2
            ;;
    esac
    case "|$active_stack|" in *"|$recursion_key|"*) return 2 ;; esac
    active_stack="${active_stack:+$active_stack|}${recursion_key}"

    if [ "${service#/}" != "$service" ]; then
        service_file="$(pam_service_file "$service")" || return $?
    else
        pam_directory_configuration_present || configuration_status=$?
        case "$configuration_status" in
            0)
                service_file="$(pam_service_file "$service")" || return $?
                ;;
            1)
                service_file="$(pam_legacy_configuration_file 2>/dev/null)" || return $?
                source_mode="pam.conf"
                ;;
            *)
                return 2
                ;;
        esac
    fi
    logical_lines_file="$(new_scratch_file pam-logical-lines)" || return 2
    awk '
        {
            if (continued) record=record $0
            else record=$0
            if (record ~ /\\[[:space:]]*$/) {
                sub(/\\[[:space:]]*$/, "", record)
                record=record " "
                continued=1
                next
            }
            print record
            record=""
            continued=0
        }
        END {if (continued) exit 2}
    ' "$service_file" > "$logical_lines_file" || return 2
    # The loop writes only to stdout and never modifies the PAM source file.
    # shellcheck disable=SC2094
    while IFS= read -r line || [ -n "$line" ]; do
        line="$(printf '%s\n' "$line" | sed 's/[[:space:]]#.*$//')"
        printf '%s\n' "$line" | grep -Eq '^[[:space:]]*(#|$)' && continue
        if [ "$source_mode" = "pam.conf" ]; then
            record_service="$(printf '%s\n' "$line" | awk '{print tolower($1); exit}')"
            [ "$record_service" = "$(printf '%s' "$service" | tr '[:upper:]' '[:lower:]')" ] || continue
            line="$(printf '%s\n' "$line" | awk '{$1=""; sub(/^[[:space:]]+/, ""); print}')"
            [ -n "$line" ] || return 2
        fi
        line_type="$(printf '%s\n' "$line" | awk '{type=tolower($1); sub(/^-/, "", type); print type; exit}')"
        if [ "$line_type" = "@include" ]; then
            platform_is_debian_family || return 2
            include_service="$(printf '%s\n' "$line" | awk '{print $2; exit}')"
            [ -n "$include_service" ] || return 2
            if [ "$source_mode" = "pam.conf" ] && [ "${include_service#/}" = "$include_service" ]; then
                return 2
            fi
            pam_expand_service_recursive "$include_service" "$pam_type" $((depth + 1)) "$active_stack" || return 2
            continue
        fi
        [ "$line_type" = "$pam_type" ] || continue
        control="$(printf '%s\n' "$line" | awk '{print tolower($2); exit}')"
        case "$control" in
            include|substack)
                include_service="$(printf '%s\n' "$line" | awk '{print $3; exit}')"
                [ -n "$include_service" ] || return 2
                if [ "$source_mode" = "pam.conf" ] && [ "${include_service#/}" = "$include_service" ]; then
                    return 2
                fi
                pam_expand_service_recursive "$include_service" "$pam_type" $((depth + 1)) "$active_stack" || return 2
                ;;
            *)
                printf '%s\t%s\n' "$(display_path "$service_file")" "$line"
                ;;
        esac
    done < "$logical_lines_file"
}

pam_expand_service() {
    local service="$1"
    local pam_type="$2"
    local expanded_file=""
    local expansion_status=0

    case "$pam_type" in auth|account|password|session) ;; *) return 2 ;; esac
    case "$service" in ''|/*|*[!A-Za-z0-9_.+@-]*) return 2 ;; esac
    service="$(printf '%s' "$service" | tr '[:upper:]' '[:lower:]')"
    expanded_file="$(new_scratch_file pam-expanded)" || return 2
    pam_expand_service_recursive "$service" "$pam_type" 0 "" > "$expanded_file" || expansion_status=$?
    [ "$expansion_status" -ne 2 ] || return 2
    if [ -s "$expanded_file" ]; then
        cat "$expanded_file"
        return 0
    fi
    [ "$service" != "other" ] || return 1
    pam_expand_service_recursive other "$pam_type" 0 ""
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
    local unit=""
    local properties=""
    local load_state=""
    local command_status=0

    systemctl_path="$(trusted_command systemctl)" || return 2
    for unit in ssh.service sshd.service ssh@.service sshd@.service; do
        properties="$($systemctl_path show "$unit" -p LoadState -p ExecStart --no-pager 2>/dev/null)" || command_status=$?
        load_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "LoadState" {print $2; exit}')"
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
    properties="$($systemctl_path show systemd-sysctl.service -p ExecStart --no-pager 2>/dev/null)" || return 2
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

sysctl_static_value() {
    local key="$1"
    local files=""
    local file=""
    local normalized_target=""
    local directive_name=""
    local directive_type=""
    local line_number=""
    local directive_value=""
    local explicit_type=""
    local explicit_value=""
    local explicit_source=""
    local glob_value=""
    local glob_source=""
    local read_path=""

    local files_status=0
    files="$(sysctl_static_files)" || files_status=$?
    [ "$files_status" -eq 0 ] || return "$files_status"
    [ -n "$files" ] || return 1

    normalized_target="$(printf '%s\n' "$key" | awk '
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
        { print canonical($0) }
    ')"

    while IFS= read -r file; do
        read_path="$(resolve_sysctl_read_path "$file" 2>/dev/null)" || {
            sysctl_file_is_masked "$file" && continue
            return 2
        }
        while IFS="$(printf '\t')" read -r directive_name directive_type line_number directive_value; do
            [ -n "$directive_name" ] || continue

            case "$directive_name" in
                *'*'*|*'?'*|*'['*)
                    [ "$directive_type" = "assignment" ] || continue
                    # The unquoted expansion is the validated sysctl glob pattern.
                    # shellcheck disable=SC2254
                    case "$normalized_target" in
                        $directive_name)
                            glob_value="$directive_value"
                            glob_source="$(display_path "$file"):$line_number"
                            ;;
                    esac
                    ;;
                "$normalized_target")
                    explicit_type="$directive_type"
                    explicit_value="$directive_value"
                    explicit_source="$(display_path "$file"):$line_number"
                    ;;
            esac
        done < <(awk '
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
                    print canonical(name) "\texclusion\t" FNR "\t"
                    next
                }

                name=trim(substr(raw,1,separator-1))
                sub(/^-/, "", name)
                if (name == "" || name ~ /[[:space:]]/) next
                value=trim(substr(raw,separator+1))
                print canonical(name) "\tassignment\t" FNR "\t" value
            }
        ' "$read_path")
    done <<EOF
$files
EOF

    if [ "$explicit_type" = "assignment" ]; then
        printf '%s\t%s\n' "$explicit_value" "$explicit_source"
        return 0
    fi
    [ -z "$explicit_type" ] || return 1
    [ -n "$glob_source" ] || return 1
    printf '%s\t%s\n' "$glob_value" "$glob_source"
}

sysctl_runtime_value() {
    local key="$1"
    capture_command sysctl -n "$key" 2>/dev/null
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
    properties="$($systemctl_path show systemd-sysctl.service \
        -p LoadState -p ExecStart -p LoadCredential -p LoadCredentialEncrypted \
        -p SetCredential -p SetCredentialEncrypted -p ImportCredential \
        --no-pager 2>/dev/null)" || command_status=$?
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
    filesystem_persistent="$(sysctl_static_value "$key" 2>/dev/null)" || persistent_status=$?
    persistent="$filesystem_persistent"
    if runtime_enabled; then
        runtime="$(sysctl_runtime_value "$key" 2>/dev/null)" || runtime_status=$?
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

service_state() {
    local unit=""
    local systemctl_path=""
    local state=""
    local load_state=""
    local active_state=""
    local command_status=0
    local saw_unit=0

    systemctl_path="$(trusted_command systemctl)" || return 2

    for unit in "$@"; do
        state="$($systemctl_path show "$unit" -p LoadState -p ActiveState --no-pager 2>/dev/null)" || command_status=$?
        load_state="$(printf '%s\n' "$state" | awk -F= '$1 == "LoadState" {print $2; exit}')"
        active_state="$(printf '%s\n' "$state" | awk -F= '$1 == "ActiveState" {print $2; exit}')"
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
    local systemctl_path=""
    local output=""

    systemctl_path="$(trusted_command systemctl)" || return 2
    for unit in "$@"; do
        output="$($systemctl_path show "$unit" \
            -p Names -p LoadState -p ActiveState -p SubState -p UnitFileState \
            -p FragmentPath -p DropInPaths -p Triggers -p TriggeredBy --no-pager 2>/dev/null)" || return 2
        printf '%s\n' "$output" | sed "s/^/unit=${unit} /"
    done
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
        else
            [ ! -e "$snapshot_status_file" ] && [ ! -L "$snapshot_status_file" ] || return 2
            [ ! -e "$snapshot_file" ] && [ ! -L "$snapshot_file" ] || return 2
            capture_command ss "${ss_arguments[@]}" > "$snapshot_file" 2>/dev/null
            snapshot_status=$?
            printf '%s\n' "$snapshot_status" > "$snapshot_status_file" || return 2
        fi
        [ "$snapshot_status" -eq 0 ] || return "$snapshot_status"
        awk -v field="$local_endpoint_field" -v port=":$port" \
            '$field ~ port "$" {print}' "$snapshot_file"
        return $?
    fi

    output="$(capture_command ss "${ss_arguments[@]}" 2>/dev/null)" || return $?
    printf '%s\n' "$output" | awk -v field="$local_endpoint_field" -v port=":$port" \
        '$field ~ port "$" {print}'
}
