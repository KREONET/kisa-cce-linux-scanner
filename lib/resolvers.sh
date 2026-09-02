# shellcheck shell=bash

# shellcheck disable=SC2016

# Configuration resolvers preserve subsystem-specific precedence and provenance.

new_scratch_file() {
    local name="$1"
    mktemp "$SCRATCH_DIR/${name}.XXXXXXXX"
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

    resolved_file="$(optional_rooted_read_path /etc/login.defs 2>/dev/null)" || file_status=$?
    if [ "$file_status" -eq 2 ]; then
        return 2
    elif [ "$file_status" -eq 0 ]; then
        if [ "$PLATFORM_ID" = "rhel" ]; then
            match="$(login_defs_file_value "$key" "$resolved_file" first econf)"
        else
            match="$(login_defs_file_value "$key" "$resolved_file" last legacy)"
        fi
        [ -n "$match" ] && last_match="${match%%"$(printf '\t')"*}\t$(display_path "$resolved_file"):${match##*"$(printf '\t')"}"
    fi

    if [ "$PLATFORM_ID" = "rhel" ]; then
        selected_files="$(select_layered_files .defs /etc/login.defs.d)" || selected_status=$?
        [ "$selected_status" -eq 0 ] || return "$selected_status"
        while IFS= read -r file; do
            [ -n "$file" ] || continue
            resolved_file="$(resolve_rooted_read_path "$file" 2>/dev/null)" || return 2
            match="$(login_defs_file_value "$key" "$resolved_file" first econf)"
            [ -n "$match" ] && last_match="${match%%"$(printf '\t')"*}\t$(display_path "$resolved_file"):${match##*"$(printf '\t')"}"
        done <<EOF
$selected_files
EOF
    fi

    [ -n "$last_match" ] || return 1
    printf '%b\n' "$last_match"
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

pwhistory_value() {
    local key="$1"
    local file=""

    file="$(fs_path /etc/security/pwhistory.conf)"
    assignment_from_files_last_wins "$key" "$file"
}

pam_service_file() {
    local service="$1"
    local candidate=""
    local resolved_candidate=""

    candidate="$(fs_path "/etc/pam.d/$service")"
    resolved_candidate="$(resolve_rooted_read_path "$candidate" 2>/dev/null || true)"
    if [ -n "$resolved_candidate" ]; then
        printf '%s\n' "$resolved_candidate"
        return 0
    fi

    candidate="$(fs_path "/usr/lib/pam.d/$service")"
    resolved_candidate="$(resolve_rooted_read_path "$candidate" 2>/dev/null || true)"
    if [ -n "$resolved_candidate" ]; then
        printf '%s\n' "$resolved_candidate"
        return 0
    fi

    return 1
}

pam_expand_service() {
    local service="$1"
    local depth="${2:-0}"
    local visited_file="${3:-}"
    local service_file=""
    local line=""
    local include_service=""

    [ "$depth" -lt 24 ] || return 2
    [ -n "$visited_file" ] || visited_file="$(new_scratch_file pam-visited)"
    grep -Fqx -- "$service" "$visited_file" 2>/dev/null && return 2
    printf '%s\n' "$service" >> "$visited_file"

    service_file="$(pam_service_file "$service")" || return 1
    # The loop writes only to stdout and never modifies the PAM source file.
    # shellcheck disable=SC2094
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ''|'#'*) continue ;;
        esac
        include_service="$(printf '%s\n' "$line" | awk '
            $1 == "@include" {print $2; exit}
            $2 == "include" || $2 == "substack" {print $3; exit}
        ')"
        if [ -n "$include_service" ]; then
            pam_expand_service "$include_service" $((depth + 1)) "$visited_file" || return $?
        else
            printf '%s\t%s\n' "$(display_path "$service_file")" "$line"
        fi
    done < "$service_file"
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

systemd_sysctl_stream() {
    local binary="/usr/lib/systemd/systemd-sysctl"

    runtime_enabled || return 1
    [ -x "$binary" ] || return 127
    [ "$(stat_owner "$binary" 2>/dev/null || true)" = "root" ] || return 126
    mode_has_untrusted_write "$(stat_mode "$binary" 2>/dev/null || true)" && return 126
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

resolve_rooted_path() {
    local candidate="$1"
    local expected_type="${2:-file}"
    local current="$candidate"
    local target=""
    local parent=""
    local leaf=""
    local canonical_parent=""
    local canonical_path=""
    local canonical_scan_root=""
    local depth=0

    while [ -L "$current" ]; do
        depth=$((depth + 1))
        [ "$depth" -le 40 ] || return 1
        target="$(readlink "$current" 2>/dev/null)" || return 1
        [ "$target" != "/dev/null" ] || return 1

        case "$target" in
            /*)
                if [ "$SCAN_ROOT" = "/" ]; then
                    current="$target"
                else
                    current="${SCAN_ROOT%/}$target"
                fi
                ;;
            *)
                parent="${current%/*}"
                [ -n "$parent" ] || parent="/"
                current="$parent/$target"
                ;;
        esac
    done

    parent="${current%/*}"
    leaf="${current##*/}"
    [ -n "$parent" ] || parent="/"
    canonical_parent="$(CDPATH='' cd -P -- "$parent" 2>/dev/null && pwd)" || return 1
    canonical_path="${canonical_parent%/}/$leaf"

    if [ "$SCAN_ROOT" != "/" ]; then
        canonical_scan_root="$(CDPATH='' cd -P -- "$SCAN_ROOT" 2>/dev/null && pwd)" || return 1
        case "$canonical_path" in
            "${canonical_scan_root%/}"/*) ;;
            *) return 1 ;;
        esac
    fi

    case "$expected_type" in
        file) [ -f "$canonical_path" ] && [ -r "$canonical_path" ] || return 1 ;;
        directory) [ -d "$canonical_path" ] && [ -r "$canonical_path" ] || return 1 ;;
        *) return 2 ;;
    esac
    printf '%s\n' "$canonical_path"
}

resolve_rooted_read_path() {
    resolve_rooted_path "$1" file
}

optional_rooted_read_path() {
    local logical_path="$1"
    local raw_path=""
    local physical_path=""

    if [ "$SCAN_ROOT" = "/" ]; then raw_path="$logical_path"; else raw_path="${SCAN_ROOT%/}$logical_path"; fi
    [ -e "$raw_path" ] || [ -L "$raw_path" ] || return 1
    physical_path="$(fs_path "$logical_path" 2>/dev/null)" || return 2
    resolve_rooted_read_path "$physical_path" || return 2
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
    canonical_parent="$(CDPATH='' cd -P -- "$parent" 2>/dev/null && pwd)" || return 1
    canonical_path="${canonical_parent%/}/${current##*/}"
    [ "$canonical_path" = "/dev/null" ] && return 0
    if [ "$SCAN_ROOT" != "/" ]; then
        canonical_root="$(CDPATH='' cd -P -- "$SCAN_ROOT" 2>/dev/null && pwd)" || return 1
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
                sub(/[[:space:]]+[#;].*$/, "", raw)
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
        $1 ~ /^(LoadCredential|LoadCredentialEncrypted|SetCredential|SetCredentialEncrypted)$/ && length($2) > 0 {found=1}
        $1 == "ImportCredential" && length($2) > 0 && $2 != "sysctl.*" {found=1}
        END {exit(found ? 0 : 1)}
    '; then
        return 2
    fi
    case "$properties" in
        *systemd-sysctl*)
            if printf '%s\n' "$properties" | grep -Eq 'argv\[\]=/usr/lib/systemd/systemd-sysctl[[:space:]]*;'; then
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
    local output=""
    output="$(capture_command ss -H -lntup 2>/dev/null)" || return $?
    printf '%s\n' "$output" | awk -v port=":$port" '$5 ~ port "$" || $5 ~ port "\\*" {print}'
}
