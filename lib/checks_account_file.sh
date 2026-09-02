# shellcheck shell=bash

# Account and file-system checks cover U-01 through U-33.

scanner_is_integer() {
    [[ "${1:-}" =~ ^-?[0-9]+$ ]]
}

scanner_is_unsigned_integer() {
    [[ "${1:-}" =~ ^[0-9]+$ ]]
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
    local seen_devices=""
    local target=""
    local filesystem_type=""
    local device=""
    local findmnt_path=""

    if [ "$SCAN_ROOT" != "/" ]; then
        printf '%s\n' "${SCAN_ROOT%/}"
        return 0
    fi

    candidates_file="$(new_scratch_file mount-roots)" || return 1
    printf '/\n/usr\n/var\n/home\n/opt\n/srv\n/tmp\n' > "$candidates_file"
    findmnt_path="$(trusted_command findmnt 2>/dev/null || true)"
    if [ -n "$findmnt_path" ]; then
        while read -r target filesystem_type; do
            case "$target" in /*) ;; *) continue ;; esac
            case "$target" in /proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/run|/run/*) continue ;; esac
            case "$filesystem_type" in
                proc|sysfs|devtmpfs|devpts|tmpfs|cgroup*|securityfs|debugfs|tracefs|configfs|pstore|efivarfs|mqueue|hugetlbfs|rpc_pipefs|nfs|nfs4|cifs|smb3|fuse.*) continue ;;
            esac
            printf '%s\n' "$target" >> "$candidates_file"
        done < <("$findmnt_path" -rn -o TARGET,FSTYPE 2>/dev/null)
    fi

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

    display_path "$path" | LC_ALL=C tr '\n\r\t' '???' | LC_ALL=C tr -cd '[:print:]'
}

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

scanner_nonlogin_shell() {
    case "$1" in
        /bin/false|/usr/bin/false|/sbin/nologin|/usr/sbin/nologin|/bin/nologin|'') return 0 ;;
        *) return 1 ;;
    esac
}

scanner_file_uid_allowed() {
    local file_uid="$1"
    shift
    local owner_name=""
    local owner_uid=""
    local passwd_file=""

    passwd_file="$(fs_path /etc/passwd)"
    for owner_name in "$@"; do
        if [ "$owner_name" = "root" ] && [ "$file_uid" = "0" ]; then
            return 0
        fi
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
    scanner_file_uid_allowed "$file_uid" "$@" || return 1
    mode_is_at_most "$file_mode" "$allowed_mode" || return 1
    return 0
}

scanner_password_pam_lines() {
    local service=""

    if [ "$PLATFORM_ID" = "ubuntu" ]; then
        service="common-password"
    else
        service="system-auth"
    fi
    pam_expand_service "$service" 2>/dev/null
}

SCANNER_AUTHSELECT_UNMANAGED=0

scanner_authselect_configuration_valid() {
    local authselect_path=""
    local current_profile=""

    SCANNER_AUTHSELECT_UNMANAGED=0
    [ "$PLATFORM_ID" = "rhel" ] || return 0
    runtime_enabled || return 0
    authselect_path="$(trusted_command authselect)" || return 2
    if "$authselect_path" check >/dev/null 2>&1; then
        return 0
    fi
    current_profile="$($authselect_path current --raw 2>/dev/null || true)"
    if [ -z "$current_profile" ]; then
        SCANNER_AUTHSELECT_UNMANAGED=1
        return 0
    fi
    return 2
}

scanner_authentication_pam_lines() {
    local service=""
    local expansion_status=0

    if [ "$PLATFORM_ID" = "ubuntu" ]; then
        for service in common-auth common-account; do
            pam_expand_service "$service" 2>/dev/null || expansion_status=1
        done
    else
        for service in system-auth password-auth; do
            pam_expand_service "$service" 2>/dev/null || expansion_status=1
        done
    fi
    return "$expansion_status"
}

scanner_pam_has_module() {
    local lines_file="$1"
    local module_name="$2"

    awk -v module="$module_name" '
        /^[^\t]*\t[[:space:]]*#/ {next}
        index($0, module) {found=1}
        END {exit(found ? 0 : 1)}
    ' "$lines_file"
}

scanner_pam_option_values() {
    local lines_file="$1"
    local module_expression="$2"
    local option_name="$3"

    awk -v module_expression="$module_expression" -v option="$option_name" '
        {
            line=$0
            sub(/^[^\t]*\t/, "", line)
            if (line ~ /^[[:space:]]*#/ || line !~ module_expression) next
            count=split(line, fields, /[[:space:]]+/)
            for (index_value=1; index_value<=count; index_value++) {
                if (fields[index_value] ~ ("^" option "=")) {
                    value=fields[index_value]
                    sub("^" option "=", "", value)
                    print value
                }
            }
        }
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

    paths="$(scanner_pam_option_values "$lines_file" "$module_expression" conf | LC_ALL=C sort -u)"
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

    awk -v module="$module_name" '
        {
            line=$0
            sub(/^[^\t]*\t/, "", line)
            if (line ~ /^[[:space:]]*#/) next
            if (!module_line && index(line, module)) module_line=NR
            if (!unix_line && index(line, "pam_unix.so")) unix_line=NR
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
            if (line ~ /^[[:space:]]*#/ || index(line, module) == 0) next
            if (line ~ /^[[:space:]]*(auth|account|password|session)[[:space:]]+(required|requisite)[[:space:]]+/) mandatory++
            else if (line ~ /^[[:space:]]*(auth|account|password|session)[[:space:]]+(optional|sufficient)[[:space:]]+/) bypassable++
            else ambiguous++
        }
        END {print mandatory+0, bypassable+0, ambiguous+0}
    ' "$lines_file"
}

scanner_pam_stack_has_bracket_control() {
    local lines_file="$1"

    awk '
        {
            line=$0
            sub(/^[^\t]*\t/, "", line)
            if (line ~ /^[[:space:]]*-?(auth|account|password|session)[[:space:]]+\[/) found=1
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

    file="$(fs_path /etc/security/pwhistory.conf)"
    scanner_configuration_has_flag "$flag" "$file"
}

scanner_faillock_value() {
    local key="$1"
    local file=""

    file="$(fs_path /etc/security/faillock.conf)"
    assignment_from_files_last_wins "$key" "$file"
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

    selected_files="$(select_layered_files .conf /etc/ssh/sshd_config.d)" || selected_status=$?
    [ "$selected_status" -eq 0 ] || return "$selected_status"
    while IFS= read -r file; do
        [ -n "$file" ] && files+=("$file")
    done <<EOF
$selected_files
EOF
    main_file="$(fs_path /etc/ssh/sshd_config)"
    [ -r "$main_file" ] && files+=("$main_file")

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
    local directory=""
    local file=""
    local dropin_count=0
    local selected_files=""
    local selected_status=0
    local resolved_file=""

    main_file="$(fs_path /etc/ssh/sshd_config)"
    [ -r "$main_file" ] || return 0
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

    inetd_file="$(fs_path /etc/inetd.conf)"
    if [ -r "$inetd_file" ] && awk -v service="$service_name" '
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

    xinetd_file="$(fs_path "/etc/xinetd.d/$service_name")"
    if [ -r "$xinetd_file" ]; then
        ! awk '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                if (line ~ /^disable[[:space:]]*=[[:space:]]*yes([[:space:]]|$)/) disabled=1
                if (line ~ /^disable[[:space:]]*=[[:space:]]*no([[:space:]]|$)/) disabled=0
            }
            END {exit(disabled ? 0 : 1)}
        ' "$xinetd_file"
        return $?
    fi

    return 1
}

check_u_01() {
    local ssh_value_record=""
    local ssh_value=""
    local ssh_state=3
    local telnet_state=3
    local ssh_active=0
    local telnet_enabled=0
    local listener_checked=0
    local static_ambiguous=0
    local evidence=""
    local listener_output=""
    local listener_status=0
    local custom_invocation_status=1
    local ssh_static_status=0
    local ambiguity_status=1

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

    scanner_inetd_service_enabled telnet && telnet_enabled=1
    if runtime_enabled; then
        service_state ssh.service sshd.service ssh.socket sshd.socket >/dev/null 2>&1
        ssh_state=$?
        service_state telnet.socket telnet.service >/dev/null 2>&1
        telnet_state=$?
        [ "$ssh_state" -eq 0 ] && ssh_active=1
        [ "$telnet_state" -eq 0 ] && telnet_enabled=1
        sshd_manager_has_custom_invocation >/dev/null 2>&1
        custom_invocation_status=$?
        [ "$custom_invocation_status" -eq 0 ] && static_ambiguous=1
        if trusted_command ss >/dev/null 2>&1; then
            listener_checked=1
            listener_output="$(port_listener_facts 22 2>/dev/null)" || listener_status=$?
            [ -n "$listener_output" ] && ssh_active=1
            listener_output="$(port_listener_facts 23 2>/dev/null)" || listener_status=$?
            [ -n "$listener_output" ] && telnet_enabled=1
        fi
        scanner_append_evidence evidence "ssh_runtime_state_code=${ssh_state}"
        scanner_append_evidence evidence "telnet_runtime_state_code=${telnet_state}"
        scanner_append_evidence evidence "listener_table_checked=${listener_checked}"
        scanner_append_evidence evidence "ssh_endpoint_active=${ssh_active}"
        scanner_append_evidence evidence "custom_sshd_invocation=$([ "$custom_invocation_status" -eq 0 ] && printf true || printf false_or_unavailable)"

        if [ "$ssh_state" -eq 2 ] || [ "$telnet_state" -eq 2 ] || [ "$custom_invocation_status" -eq 2 ] || [ "$listener_status" -ne 0 ]; then
            set_result ERROR "원격 터미널의 unit, 실행 인수 또는 리스너 상태를 완전히 수집하지 못했습니다." "$evidence"
            return
        fi

        if [ "$ssh_active" -eq 1 ]; then
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
        set_result MANUAL "Telnet이 활성화되어 root 직접 접속 차단을 PAM 및 securetty와 함께 확인해야 합니다." "$evidence"
    elif runtime_enabled && [ "$ssh_active" -eq 0 ] && [ "$listener_checked" -eq 1 ]; then
        set_result GOOD "활성 원격 터미널 서비스를 확인하지 못했습니다." "$evidence"
    elif runtime_enabled && [ "$ssh_active" -eq 0 ]; then
        set_result MANUAL "리스너 표를 확인하지 못해 원격 터미널 비활성 상태를 확정할 수 없습니다." "$evidence"
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

check_u_02() {
    local pam_lines_file=""
    local maximum_days_record=""
    local minimum_days_record=""
    local minimum_length_record=""
    local digit_credit_record=""
    local uppercase_credit_record=""
    local lowercase_credit_record=""
    local other_credit_record=""
    local history_record=""
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

    pam_lines_file="$(new_scratch_file u02-pam)" || {
        set_result ERROR "PAM 설정을 분석할 임시 파일을 만들지 못했습니다."
        return
    }
    if ! scanner_authselect_configuration_valid; then
        set_result ERROR "RHEL authselect 구성이 없거나 무결성 검증에 실패했습니다." "authselect_check=failed"
        return
    fi
    if ! scanner_password_pam_lines > "$pam_lines_file"; then
        set_result ERROR "유효 PAM 비밀번호 스택의 include 그래프를 완전히 해석하지 못했습니다." "pam_graph=incomplete"
        return
    fi

    maximum_days_record="$(login_defs_value PASS_MAX_DAYS 2>/dev/null || true)"
    minimum_days_record="$(login_defs_value PASS_MIN_DAYS 2>/dev/null || true)"
    minimum_length_record="$(pwquality_value minlen 2>/dev/null || true)"
    digit_credit_record="$(pwquality_value dcredit 2>/dev/null || true)"
    uppercase_credit_record="$(pwquality_value ucredit 2>/dev/null || true)"
    lowercase_credit_record="$(pwquality_value lcredit 2>/dev/null || true)"
    other_credit_record="$(pwquality_value ocredit 2>/dev/null || true)"
    history_record="$(pwhistory_value remember 2>/dev/null || true)"

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
    custom_status=0
    history_custom_file="$(scanner_pam_custom_configuration_file "$pam_lines_file" 'pam_pwhistory[.]so' 2>/dev/null)" || custom_status=$?
    if [ "$custom_status" -eq 2 ]; then
        set_result ERROR "pam_pwhistory의 conf= 경로를 안전하게 단일 해석하지 못했습니다." "pam_pwhistory_conf=invalid_or_multiple"
        return
    elif [ "$custom_status" -eq 0 ]; then
        history_custom_file="${history_custom_file#*"$(printf '\t')"}"
        history_record="$(assignment_from_files_last_wins remember "$history_custom_file" 2>/dev/null || true)"
        history_enforce_file="$history_custom_file"
    fi

    value="$(scanner_pam_option_values "$pam_lines_file" 'pam_pwquality[.]so' minlen | tail -n 1)"
    [ -n "$value" ] && minimum_length_record="${value}"$'\t'"PAM"
    value="$(scanner_pam_option_values "$pam_lines_file" 'pam_pwquality[.]so' dcredit | tail -n 1)"
    [ -n "$value" ] && digit_credit_record="${value}"$'\t'"PAM"
    value="$(scanner_pam_option_values "$pam_lines_file" 'pam_pwquality[.]so' ucredit | tail -n 1)"
    [ -n "$value" ] && uppercase_credit_record="${value}"$'\t'"PAM"
    value="$(scanner_pam_option_values "$pam_lines_file" 'pam_pwquality[.]so' lcredit | tail -n 1)"
    [ -n "$value" ] && lowercase_credit_record="${value}"$'\t'"PAM"
    value="$(scanner_pam_option_values "$pam_lines_file" 'pam_pwquality[.]so' ocredit | tail -n 1)"
    [ -n "$value" ] && other_credit_record="${value}"$'\t'"PAM"
    value="$(scanner_pam_option_values "$pam_lines_file" 'pam_(pwhistory|unix)[.]so' remember | tail -n 1)"
    [ -n "$value" ] && history_record="${value}"$'\t'"PAM"

    scanner_pam_has_module "$pam_lines_file" pam_pwquality.so && module_present=1
    if scanner_pam_has_module "$pam_lines_file" pam_pwhistory.so || \
       [ -n "$(scanner_pam_option_values "$pam_lines_file" 'pam_unix[.]so' remember | tail -n 1)" ]; then
        history_module_present=1
    fi
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
    scanner_pam_stack_has_bracket_control "$pam_lines_file" && stack_bracket_controls=1

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
                minimum) [ "$setting_value" -ge 1 ] && compliant=1 ;;
                length) [ "$setting_value" -ge 8 ] && compliant=1 ;;
                credit) [ "$setting_value" -le -1 ] && compliant=1 ;;
                history) [ "$setting_value" -ge 4 ] && compliant=1 ;;
            esac
        fi
        [ "$compliant" -eq 1 ] || failures=$((failures + 1))
        scanner_append_evidence evidence "${setting_name}=${setting_value:-unresolved}"
    done

    [ "$module_present" -eq 1 ] || failures=$((failures + 1))
    [ "$history_module_present" -eq 1 ] || failures=$((failures + 1))
    scanner_pam_module_precedes_unix "$pam_lines_file" pam_pwquality.so || failures=$((failures + 1))
    if scanner_pam_has_module "$pam_lines_file" pam_pwhistory.so; then
        scanner_pam_module_precedes_unix "$pam_lines_file" pam_pwhistory.so || failures=$((failures + 1))
    fi

    if [ -n "$quality_enforce_file" ]; then
        scanner_configuration_has_flag enforce_for_root "${quality_custom_files_array[@]}" && quality_enforce_present=1
    else
        scanner_pwquality_has_flag enforce_for_root && quality_enforce_present=1
    fi
    awk '/pam_pwquality[.]so/ && /(^|[[:space:]])enforce_for_root([[:space:]]|$)/ {found=1} END {exit(found ? 0 : 1)}' "$pam_lines_file" && quality_enforce_present=1
    if [ "$quality_enforce_present" -eq 0 ]; then
        failures=$((failures + 1))
        scanner_append_evidence evidence "pwquality_enforce_for_root=absent"
    else
        scanner_append_evidence evidence "pwquality_enforce_for_root=present"
    fi
    if [ -n "$history_enforce_file" ]; then
        scanner_configuration_has_flag enforce_for_root "$history_enforce_file" && history_enforce_present=1
    else
        scanner_pwhistory_has_flag enforce_for_root && history_enforce_present=1
    fi
    awk '/pam_pwhistory[.]so/ && /(^|[[:space:]])enforce_for_root([[:space:]]|$)/ {found=1} END {exit(found ? 0 : 1)}' "$pam_lines_file" && history_enforce_present=1
    if [ "$history_enforce_present" -eq 0 ]; then
        failures=$((failures + 1))
        scanner_append_evidence evidence "pwhistory_enforce_for_root=absent"
    else
        scanner_append_evidence evidence "pwhistory_enforce_for_root=present"
    fi
    scanner_append_evidence evidence "pam_pwquality_present=${module_present}"
    scanner_append_evidence evidence "password_history_module_present=${history_module_present}"
    scanner_append_evidence evidence "bypassable_pam_controls=${bypassable_controls}"
    scanner_append_evidence evidence "ambiguous_pam_controls=${ambiguous_controls}"
    scanner_append_evidence evidence "stack_bracket_controls=${stack_bracket_controls}"
    scanner_append_evidence evidence "authselect_unmanaged=${SCANNER_AUTHSELECT_UNMANAGED}"
    if [ "$bypassable_controls" -gt 0 ]; then
        set_result VULNERABLE "비밀번호 품질 또는 이력 모듈이 우회 가능한 PAM control로 구성되어 있습니다." "$evidence"
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

check_u_03() {
    local pam_lines_file=""
    local deny_record=""
    local deny_value=""
    local pam_values=""
    local module_present=0
    local faillock_present=0
    local tally_present=0
    local flow_valid=0
    local required_flow_count=1
    local flow_counts=""
    local preauth_count=0
    local authfail_count=0
    local authsucc_count=0
    local account_count=0
    local tally_auth_count=0
    local tally_account_count=0
    local ambiguous_flow_count=0
    local stack_bracket_controls=0
    local faillock_custom_file=""
    local custom_status=0
    local invalid_values=0
    local evidence=""
    local value=""

    pam_lines_file="$(new_scratch_file u03-pam)" || {
        set_result ERROR "PAM 설정을 분석할 임시 파일을 만들지 못했습니다."
        return
    }
    if ! scanner_authselect_configuration_valid; then
        set_result ERROR "RHEL authselect 구성이 없거나 무결성 검증에 실패했습니다." "authselect_check=failed"
        return
    fi
    if ! scanner_authentication_pam_lines > "$pam_lines_file"; then
        set_result ERROR "유효 PAM 인증 스택의 include 그래프를 완전히 해석하지 못했습니다." "pam_graph=incomplete"
        return
    fi
    scanner_pam_has_module "$pam_lines_file" pam_faillock.so && faillock_present=1
    if scanner_pam_has_module "$pam_lines_file" pam_tally.so || \
       scanner_pam_has_module "$pam_lines_file" pam_tally2.so; then
        tally_present=1
    fi
    if [ "$faillock_present" -eq 1 ] || [ "$tally_present" -eq 1 ]; then
        module_present=1
    fi

    flow_counts="$(awk '
        {
            line=$0
            sub(/^[^\t]*\t/, "", line)
            if (line ~ /^[[:space:]]*#/) next
            if (line ~ /pam_faillock[.]so/ && line !~ /[[:space:]](optional|sufficient)[[:space:]]/) {
                if (line ~ /^[[:space:]]*(auth|account)[[:space:]]+\[/) ambiguous++
                if (line ~ /^[[:space:]]*auth[[:space:]]/ && line ~ /(^|[[:space:]])preauth([[:space:]]|$)/) preauth++
                if (line ~ /^[[:space:]]*auth[[:space:]]/ && line ~ /(^|[[:space:]])authfail([[:space:]]|$)/) authfail++
                if (line ~ /^[[:space:]]*auth[[:space:]]/ && line ~ /(^|[[:space:]])authsucc([[:space:]]|$)/) authsucc++
                if (line ~ /^[[:space:]]*account[[:space:]]/) account++
            }
            if (line ~ /pam_(tally|tally2)[.]so/ && line !~ /[[:space:]](optional|sufficient)[[:space:]]/) {
                if (line ~ /^[[:space:]]*auth[[:space:]]/) tally_auth++
                if (line ~ /^[[:space:]]*account[[:space:]]/ && line ~ /(^|[[:space:]])reset([[:space:]]|$)/) tally_account++
            }
        }
        END {print preauth+0, authfail+0, authsucc+0, account+0, tally_auth+0, tally_account+0, ambiguous+0}
    ' "$pam_lines_file")"
    read -r preauth_count authfail_count authsucc_count account_count tally_auth_count tally_account_count ambiguous_flow_count <<< "$flow_counts"
    [ "$PLATFORM_ID" = "rhel" ] && required_flow_count=2
    if [ "$faillock_present" -eq 1 ] && \
       [ "$preauth_count" -ge "$required_flow_count" ] && \
       [ "$authfail_count" -ge "$required_flow_count" ] && \
       { [ "$authsucc_count" -ge "$required_flow_count" ] || [ "$account_count" -ge "$required_flow_count" ]; }; then
        flow_valid=1
    fi
    if [ "$tally_present" -eq 1 ] && \
       [ "$tally_auth_count" -ge "$required_flow_count" ] && \
       [ "$tally_account_count" -ge "$required_flow_count" ]; then
        flow_valid=1
    fi
    [ "$ambiguous_flow_count" -eq 0 ] || flow_valid=0
    if scanner_pam_stack_has_bracket_control "$pam_lines_file"; then
        stack_bracket_controls=1
        flow_valid=0
    fi

    pam_values="$(scanner_pam_option_values "$pam_lines_file" 'pam_(faillock|tally|tally2)[.]so' deny)"
    faillock_custom_file="$(scanner_pam_custom_configuration_file "$pam_lines_file" 'pam_faillock[.]so' 2>/dev/null)" || custom_status=$?
    if [ "$custom_status" -eq 2 ]; then
        set_result ERROR "pam_faillock의 conf= 경로를 안전하게 단일 해석하지 못했습니다." "pam_faillock_conf=invalid_or_multiple"
        return
    elif [ "$custom_status" -eq 0 ]; then
        faillock_custom_file="${faillock_custom_file#*"$(printf '\t')"}"
        deny_record="$(assignment_from_files_last_wins deny "$faillock_custom_file" 2>/dev/null || true)"
    else
        deny_record="$(scanner_faillock_value deny 2>/dev/null || true)"
    fi
    deny_value="$(scanner_value_only "$deny_record")"
    if [ -n "$pam_values" ]; then
        deny_value="$(printf '%s\n' "$pam_values" | tail -n 1)"
    fi

    while IFS= read -r value; do
        [ -n "$value" ] || continue
        if ! scanner_is_unsigned_integer "$value" || [ "$value" -lt 1 ] || [ "$value" -gt 10 ]; then
            invalid_values=$((invalid_values + 1))
        fi
    done <<EOF
${pam_values:-$deny_value}
EOF

    scanner_append_evidence evidence "lock_module_present=${module_present}"
    scanner_append_evidence evidence "deny=${deny_value:-unresolved}"
    scanner_append_evidence evidence "faillock_preauth=${preauth_count}"
    scanner_append_evidence evidence "faillock_authfail=${authfail_count}"
    scanner_append_evidence evidence "faillock_authsucc=${authsucc_count}"
    scanner_append_evidence evidence "faillock_account=${account_count}"
    scanner_append_evidence evidence "lock_flow_valid=${flow_valid}"
    scanner_append_evidence evidence "ambiguous_pam_controls=${ambiguous_flow_count}"
    scanner_append_evidence evidence "stack_bracket_controls=${stack_bracket_controls}"
    scanner_append_evidence evidence "authselect_unmanaged=${SCANNER_AUTHSELECT_UNMANAGED}"
    scanner_append_evidence evidence "authselect_unmanaged=${SCANNER_AUTHSELECT_UNMANAGED}"
    if [ "$module_present" -eq 0 ] || [ -z "$deny_value" ] || [ "$invalid_values" -gt 0 ]; then
        set_result VULNERABLE "계정 잠금 모듈이 없거나 잠금 임계값이 1~10회로 설정되지 않았습니다." "$evidence"
    elif [ "$flow_valid" -eq 0 ] || [ "$SCANNER_AUTHSELECT_UNMANAGED" -eq 1 ]; then
        set_result MANUAL "잠금 임계값은 확인했지만 PAM의 실패 기록·잠금·성공 초기화 흐름을 완전하게 입증하지 못했습니다." "$evidence"
    else
        set_result GOOD "계정 잠금 임계값과 PAM 잠금 흐름이 확인됐습니다." "$evidence"
    fi
}

check_u_04() {
    local passwd_file=""
    local shadow_file=""
    local invalid_accounts=""
    local invalid_count=0
    local evidence=""

    passwd_file="$(fs_path /etc/passwd)"
    shadow_file="$(fs_path /etc/shadow)"
    [ -r "$passwd_file" ] || {
        set_result ERROR "/etc/passwd를 읽을 수 없습니다." "path=/etc/passwd"
        return
    }
    [ -e "$shadow_file" ] || {
        set_result VULNERABLE "쉐도우 비밀번호 파일이 존재하지 않습니다." "path=/etc/shadow"
        return
    }

    invalid_accounts="$(awk -F: '
        NF < 7 {print "[malformed]"; next}
        $2 != "x" && $2 != "*" && $2 != "!" && $2 != "!!" && $2 != "!*" {print $1}
    ' "$passwd_file")"
    invalid_count="$(printf '%s\n' "$invalid_accounts" | awk 'NF {count++} END {print count+0}')"
    scanner_append_evidence evidence "shadow_file=present"
    scanner_append_evidence evidence "non_shadow_password_fields=${invalid_count}"
    if [ "$invalid_count" -gt 0 ]; then
        scanner_append_evidence evidence "affected_accounts=$(printf '%s\n' "$invalid_accounts" | head -n 20 | paste -sd, -)"
        set_result VULNERABLE "/etc/passwd에 쉐도우 방식이 아닌 비밀번호 필드가 존재합니다." "$evidence"
    else
        set_result GOOD "모든 계정이 쉐도우 비밀번호 필드를 사용합니다." "$evidence"
    fi
}

check_u_05() {
    local passwd_file=""
    local accounts=""
    local count=0

    passwd_file="$(fs_path /etc/passwd)"
    [ -r "$passwd_file" ] || {
        set_result ERROR "/etc/passwd를 읽을 수 없습니다." "path=/etc/passwd"
        return
    }
    accounts="$(awk -F: '$3 == 0 && $1 != "root" {print $1}' "$passwd_file")"
    count="$(printf '%s\n' "$accounts" | awk 'NF {count++} END {print count+0}')"
    if [ "$count" -gt 0 ]; then
        local evidence=""
        scanner_append_evidence evidence "count=${count}"
        scanner_append_evidence evidence "accounts=$(printf '%s\n' "$accounts" | head -n 20 | paste -sd, -)"
        set_result VULNERABLE "root 외 UID 0 계정이 존재합니다." "$evidence"
    else
        set_result GOOD "root 외 UID 0 계정이 없습니다." "count=0"
    fi
}

check_u_06() {
    local pam_lines_file=""
    local su_path=""
    local file_uid=""
    local file_gid=""
    local file_mode=""
    local decimal_mode=""
    local pam_restricted=0
    local permission_restricted=0
    local evidence=""
    local pam_group=""
    local stack_bracket_controls=0

    pam_lines_file="$(new_scratch_file u06-pam)" || {
        set_result ERROR "PAM 설정을 분석할 임시 파일을 만들지 못했습니다."
        return
    }
    if ! scanner_authselect_configuration_valid; then
        set_result ERROR "RHEL authselect 구성이 없거나 무결성 검증에 실패했습니다." "authselect_check=failed"
        return
    fi
    if ! pam_expand_service su > "$pam_lines_file" 2>/dev/null; then
        set_result ERROR "su PAM include 그래프를 완전히 해석하지 못했습니다." "pam_service=su"
        return
    fi
    if awk '
        {
            line=$0
            sub(/^[^\t]*\t/, "", line)
            if (line ~ /^[[:space:]]*#/) next
            if (line ~ /(^|[[:space:]])(required|requisite)[[:space:]]+pam_wheel[.]so([[:space:]]|$)/ && line !~ /(^|[[:space:]])deny([[:space:]]|$)/) found=1
        }
        END {exit(found ? 0 : 1)}
    ' "$pam_lines_file"; then
        pam_restricted=1
        pam_group="$(awk '
            {
                line=$0
                sub(/^[^\t]*\t/, "", line)
                if (line !~ /pam_wheel[.]so/) next
                count=split(line, fields, /[[:space:]]+/)
                for (index_value=1; index_value<=count; index_value++) {
                    if (fields[index_value] ~ /^group=/) {sub(/^group=/, "", fields[index_value]); print fields[index_value]; exit}
                }
            }
        ' "$pam_lines_file")"
    fi
    scanner_pam_stack_has_bracket_control "$pam_lines_file" && stack_bracket_controls=1

    su_path="$(fs_path /usr/bin/su)"
    if [ -e "$su_path" ]; then
        file_uid="$(stat_uid "$su_path" 2>/dev/null || true)"
        file_gid="$(scanner_stat_gid "$su_path" 2>/dev/null || true)"
        file_mode="$(stat_mode "$su_path" 2>/dev/null || true)"
        decimal_mode="$(mode_to_decimal "$file_mode" 2>/dev/null || true)"
        if [ "$file_uid" = "0" ] && [ -n "$decimal_mode" ] && \
           [ $((decimal_mode & 0001)) -eq 0 ] && [ $((decimal_mode & 0010)) -ne 0 ]; then
            permission_restricted=1
        fi
    fi

    scanner_append_evidence evidence "pam_wheel_restriction=${pam_restricted}"
    scanner_append_evidence evidence "pam_wheel_group=${pam_group:-wheel-default}"
    scanner_append_evidence evidence "stack_bracket_controls=${stack_bracket_controls}"
    scanner_append_evidence evidence "su_owner_uid=${file_uid:-unresolved}"
    scanner_append_evidence evidence "su_group_gid=${file_gid:-unresolved}"
    scanner_append_evidence evidence "su_mode=${file_mode:-unresolved}"
    if [ "$pam_restricted" -eq 1 ] && [ "$SCANNER_AUTHSELECT_UNMANAGED" -eq 0 ] && [ "$stack_bracket_controls" -eq 0 ] && { [ -z "$pam_group" ] || [ "$pam_group" = "wheel" ] || [ "$pam_group" = "sudo" ]; }; then
        set_result GOOD "su 실행이 필수 PAM 규칙으로 특정 그룹에 제한되어 있습니다." "$evidence"
    elif [ "$pam_restricted" -eq 1 ]; then
        set_result MANUAL "su 제한 그룹의 구성원 범위가 관리 목적에 적합한지 확인해야 합니다." "$evidence"
    elif [ "$permission_restricted" -eq 1 ]; then
        set_result MANUAL "su 파일 권한은 그룹 실행으로 제한되지만 해당 그룹의 업무상 적정성을 확인해야 합니다." "$evidence"
    elif [ ! -e "$su_path" ]; then
        set_result NOT_APPLICABLE "su 명령이 설치되어 있지 않습니다." "path=/usr/bin/su" false
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

    passwd_file="$(fs_path /etc/passwd)"
    [ -r "$passwd_file" ] || {
        set_result ERROR "/etc/passwd를 읽을 수 없습니다." "path=/etc/passwd"
        return
    }
    uid_minimum_record="$(login_defs_value UID_MIN 2>/dev/null || true)"
    scanner_is_unsigned_integer "$(scanner_value_only "$uid_minimum_record")" && uid_minimum="$(scanner_value_only "$uid_minimum_record")"
    accounts="$(awk -F: -v minimum="$uid_minimum" '$3 == 0 || ($3 >= minimum && $3 < 65534) {if ($7 !~ /(nologin|false)$/) print $1}' "$passwd_file")"
    count="$(printf '%s\n' "$accounts" | awk 'NF {count++} END {print count+0}')"
    scanner_append_evidence evidence "login_capable_accounts=${count}"
    scanner_append_evidence evidence "accounts=$(printf '%s\n' "$accounts" | head -n 20 | paste -sd, -)"
    set_result MANUAL "계정의 업무 필요성과 최근 사용 여부는 조직의 계정 대장 및 인증 로그로 확인해야 합니다." "$evidence"
}

check_u_08() {
    local passwd_file=""
    local group_file=""
    local root_gid=""
    local accounts=""
    local count=0
    local evidence=""

    passwd_file="$(fs_path /etc/passwd)"
    group_file="$(fs_path /etc/group)"
    [ -r "$passwd_file" ] && [ -r "$group_file" ] || {
        set_result ERROR "관리자 그룹 구성원을 확인할 계정 파일을 읽을 수 없습니다." "paths=/etc/passwd,/etc/group"
        return
    }
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
    local candidates=""
    local count=0
    local evidence=""

    passwd_file="$(fs_path /etc/passwd)"
    group_file="$(fs_path /etc/group)"
    [ -r "$passwd_file" ] && [ -r "$group_file" ] || {
        set_result ERROR "계정 및 그룹 파일을 읽을 수 없습니다." "paths=/etc/passwd,/etc/group"
        return
    }
    candidates="$(awk -F: '
        NR == FNR {used_gid[$4]=1; account[$1]=1; next}
        {
            used=used_gid[$3]
            count=split($4, members, ",")
            for (index_value=1; index_value<=count; index_value++) {
                if (members[index_value] != "" && account[members[index_value]]) used=1
            }
            if (!used) print $1 ":" $3
        }
    ' "$passwd_file" "$group_file")"
    count="$(printf '%s\n' "$candidates" | awk 'NF {count++} END {print count+0}')"
    if [ "$count" -eq 0 ]; then
        set_result MANUAL "직접 연결되지 않은 그룹은 없지만 전체 그룹의 업무 필요성은 승인 목록과 대조해야 합니다." "unused_group_candidates=0"
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

    passwd_file="$(fs_path /etc/passwd)"
    [ -r "$passwd_file" ] || {
        set_result ERROR "/etc/passwd를 읽을 수 없습니다." "path=/etc/passwd"
        return
    }
    duplicates="$(awk -F: '{accounts[$3]=accounts[$3] (accounts[$3] ? "," : "") $1; counts[$3]++} END {for (uid in counts) if (counts[uid] > 1) print uid ":" accounts[uid]}' "$passwd_file" | LC_ALL=C sort -n)"
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

    passwd_file="$(fs_path /etc/passwd)"
    [ -r "$passwd_file" ] || {
        set_result ERROR "/etc/passwd를 읽을 수 없습니다." "path=/etc/passwd"
        return
    }
    accounts="$(awk -F: '
        BEGIN {
            split("daemon bin sys adm listen nobody nobody4 noaccess diag operator games gopher", names, " ")
            for (index_value in names) checked[names[index_value]]=1
        }
        checked[$1] && $7 !~ /(\/false|\/nologin)$/ {print $1 ":" $7}
    ' "$passwd_file")"
    uid_minimum_record="$(login_defs_value UID_MIN 2>/dev/null || true)"
    scanner_is_unsigned_integer "$(scanner_value_only "$uid_minimum_record")" && uid_minimum="$(scanner_value_only "$uid_minimum_record")"
    additional_accounts="$(awk -F: -v minimum="$uid_minimum" '
        $3 > 0 && $3 < minimum && $7 !~ /(\/false|\/nologin)$/ && $1 !~ /^(sync|shutdown|halt)$/ {print $1 ":" $7}
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
    local directory=""
    local record=""
    local value=""
    local compliant=0
    local noncompliant=0
    local unresolved=0
    local csh_accounts=0
    local evidence=""
    local passwd_file=""

    for file in /etc/profile /etc/bash.bashrc /etc/bashrc; do
        file="$(fs_path "$file")"
        [ -r "$file" ] && files+=("$file")
    done
    directory="$(fs_path /etc/profile.d)"
    if [ -d "$directory" ]; then
        while IFS= read -r file; do files+=("$file"); done < <(find -P "$directory" -maxdepth 1 -type f -name '*.sh' -print 2>/dev/null | LC_ALL=C sort)
    fi

    for file in "${files[@]}"; do
        while IFS= read -r record; do
            [ -n "$record" ] || continue
            value="${record%%:*}"
            if scanner_is_unsigned_integer "$value"; then
                if [ "$value" -gt 0 ] && [ "$value" -le 600 ]; then
                    compliant=$((compliant + 1))
                else
                    noncompliant=$((noncompliant + 1))
                fi
                scanner_append_evidence evidence "TMOUT=${value},source=$(display_path "$file"):${record#*:}"
            else
                unresolved=$((unresolved + 1))
            fi
        done < <(awk '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                if (match(line, /TMOUT[[:space:]]*=[[:space:]]*[0-9]+/)) {
                    value=substr(line, RSTART, RLENGTH)
                    sub(/^TMOUT[[:space:]]*=[[:space:]]*/, "", value)
                    print value ":" FNR
                } else if (line ~ /TMOUT[[:space:]]*=/ || line ~ /(^|[;[:space:]])unset[[:space:]]+TMOUT([;[:space:]]|$)/) {
                    print "dynamic:" FNR
                }
            }
        ' "$file")
    done

    passwd_file="$(fs_path /etc/passwd)"
    [ -r "$passwd_file" ] && csh_accounts="$(awk -F: '$7 ~ /(csh|tcsh)$/ {count++} END {print count+0}' "$passwd_file")"
    if [ "$csh_accounts" -gt 0 ]; then
        local csh_compliant=0
        for file in /etc/csh.cshrc /etc/csh.login; do
            file="$(fs_path "$file")"
            [ -r "$file" ] || continue
            value="$(awk '/^[[:space:]]*set[[:space:]]+autologout[[:space:]]*=[[:space:]]*[0-9]+/ {line=$0; sub(/^.*=[[:space:]]*/, "", line); print line}' "$file" | tail -n 1)"
            if scanner_is_unsigned_integer "$value" && [ "$value" -gt 0 ] && [ "$value" -le 10 ]; then
                csh_compliant=1
                scanner_append_evidence evidence "csh_autologout=${value},source=$(display_path "$file")"
            fi
        done
        [ "$csh_compliant" -eq 1 ] || noncompliant=$((noncompliant + 1))
    fi

    if [ "$noncompliant" -gt 0 ]; then
        set_result VULNERABLE "600초를 초과하거나 비활성화된 세션 시간 제한 설정이 존재합니다." "$evidence"
    elif [ "$compliant" -gt 0 ] && [ "$unresolved" -eq 0 ]; then
        set_result GOOD "전역 셸 설정에서 600초 이하의 세션 시간 제한을 확인했습니다." "$evidence"
    elif [ "$unresolved" -gt 0 ]; then
        set_result MANUAL "동적으로 계산되는 세션 시간 제한의 유효값을 확인해야 합니다." "$evidence"
    else
        set_result VULNERABLE "전역 세션 시간 제한 설정을 확인하지 못했습니다." "$evidence"
    fi
}

check_u_13() {
    local shadow_file=""
    local method_record=""
    local method=""
    local counts=""
    local secure_count=0
    local weak_count=0
    local unknown_count=0
    local empty_count=0
    local method_secure=0
    local evidence=""

    shadow_file="$(fs_path /etc/shadow)"
    [ -r "$shadow_file" ] || {
        set_result MANUAL "/etc/shadow를 읽을 수 없어 실제 비밀번호 알고리즘을 확인하지 못했습니다." "path=/etc/shadow"
        return
    }
    method_record="$(login_defs_value ENCRYPT_METHOD 2>/dev/null || true)"
    method="$(scanner_value_only "$method_record" | tr '[:lower:]' '[:upper:]')"
    case "$method" in
        SHA256|SHA512|YESCRYPT|GOST_YESCRYPT) method_secure=1 ;;
    esac

    counts="$(awk -F: '
        {
            password=$2
            while (substr(password,1,1) == "!") password=substr(password,2)
            if (password == "" && $2 == "") empty++
            else if (password == "" || password == "*" || password == "!!") locked++
            else if (password ~ /^\$(5|6|y|gy|2[abxy]?)\$/) secure++
            else if (password ~ /^\$(1|3|4)\$/ || password !~ /^\$/) weak++
            else unknown++
        }
        END {print secure+0, weak+0, unknown+0, empty+0, locked+0}
    ' "$shadow_file")"
    read -r secure_count weak_count unknown_count empty_count _ <<< "$counts"
    scanner_append_evidence evidence "configured_method=${method:-unresolved}"
    scanner_append_evidence evidence "secure_hashes=${secure_count}"
    scanner_append_evidence evidence "weak_hashes=${weak_count}"
    scanner_append_evidence evidence "unknown_hashes=${unknown_count}"
    scanner_append_evidence evidence "empty_password_fields=${empty_count}"

    if [ "$weak_count" -gt 0 ] || [ "$empty_count" -gt 0 ] || { [ -n "$method" ] && [ "$method_secure" -eq 0 ]; }; then
        set_result VULNERABLE "취약한 비밀번호 해시 또는 향후 생성 비밀번호의 취약한 알고리즘 설정을 확인했습니다." "$evidence"
    elif [ "$unknown_count" -gt 0 ]; then
        set_result MANUAL "알 수 없는 비밀번호 해시 식별자의 안전성을 확인해야 합니다." "$evidence"
    elif [ "$secure_count" -gt 0 ] || [ "$method_secure" -eq 1 ]; then
        set_result GOOD "SHA-2 이상 또는 yescrypt 계열의 비밀번호 알고리즘을 사용합니다." "$evidence"
    else
        set_result MANUAL "활성 비밀번호 해시와 명시적 생성 알고리즘이 없어 정책을 확정할 수 없습니다." "$evidence"
    fi
}

check_u_14() {
    local path_value=""
    local unsafe_count=0
    local evidence=""
    local file=""
    local physical_file=""
    local assignments=""
    local profile_directory=""

    if runtime_enabled && [ "$(id -u)" -eq 0 ]; then
        path_value="$ORIGINAL_PATH"
        if ! printf '%s\n' "$path_value" | awk -F: '
            {
                for (index_value=1; index_value<NF; index_value++) {
                    if ($index_value == "" || $index_value == ".") exit 1
                }
            }
        '; then
            unsafe_count=$((unsafe_count + 1))
        fi
        scanner_append_evidence evidence "runtime_path_checked=true"
    fi

    for file in /root/.profile /root/.bash_profile /root/.bashrc /root/.kshrc /root/.cshrc /root/.login /etc/profile /etc/bash.bashrc /etc/bashrc; do
        physical_file="$(fs_path "$file")"
        [ -r "$physical_file" ] || continue
        assignments="$(awk '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                if (line ~ /(^|[[:space:];])PATH[[:space:]]*=/) print FNR ":" line
            }
        ' "$physical_file")"
        if printf '%s\n' "$assignments" | grep -Eq 'PATH[[:space:]]*=[[:space:]]*[.]:|:[.]:|::|PATH[[:space:]]*=[[:space:]]*:'; then
            unsafe_count=$((unsafe_count + 1))
            scanner_append_evidence evidence "unsafe_path_assignment=${file}"
        fi
    done
    profile_directory="$(fs_path /etc/profile.d 2>/dev/null || true)"
    if [ -d "$profile_directory" ]; then
        while IFS= read -r physical_file; do
            assignments="$(awk '
                {
                    line=$0
                    sub(/^[[:space:]]+/, "", line)
                    if (line == "" || line ~ /^#/) next
                    if (line ~ /(^|[[:space:];])PATH[[:space:]]*=/) print FNR ":" line
                }
            ' "$physical_file")"
            if printf '%s\n' "$assignments" | grep -Eq 'PATH[[:space:]]*=[[:space:]]*:|::|:[.]:|=[.]:'; then
                unsafe_count=$((unsafe_count + 1))
                scanner_append_evidence evidence "unsafe_path_assignment=$(display_path "$physical_file")"
            fi
        done < <(find -P "$profile_directory" -maxdepth 1 -type f -name '*.sh' -print 2>/dev/null | LC_ALL=C sort)
    fi

    if [ "$unsafe_count" -gt 0 ]; then
        set_result VULNERABLE "root PATH에 현재 디렉터리 또는 빈 경로 요소가 포함됩니다." "$evidence"
    elif runtime_enabled && [ "$(id -u)" -eq 0 ]; then
        set_result MANUAL "스캐너의 격리 PATH는 안전하지만 root 로그인 환경의 최종 PATH를 별도 확인해야 합니다." "$evidence"
    else
        set_result MANUAL "정적 환경 파일에는 명백한 취약 PATH가 없지만 root 로그인 시 유효값 확인이 필요합니다." "$evidence"
    fi
}

check_u_15() {
    local scan_list=""
    local orphan_list=""
    local scan_path=""
    local path=""
    local file_uid=""
    local file_gid=""
    local passwd_file=""
    local group_file=""
    local count=0
    local evidence=""
    local filesystem_root=""
    local scan_errors=0

    scan_path="${SCAN_ROOT%/}"
    [ -n "$scan_path" ] || scan_path="/"
    scan_list="$(new_scratch_file u15-scan)" || {
        set_result ERROR "전체 파일 목록을 저장할 임시 파일을 만들지 못했습니다."
        return
    }
    orphan_list="$(new_scratch_file u15-orphans)" || {
        set_result ERROR "소유자 없는 파일 목록을 저장할 임시 파일을 만들지 못했습니다."
        return
    }

    if [ "$SCAN_ROOT" = "/" ]; then
        : > "$orphan_list"
        while IFS= read -r filesystem_root; do
            find -P "$filesystem_root" -xdev \( -nouser -o -nogroup \) -print0 >> "$orphan_list" 2>/dev/null || scan_errors=$((scan_errors + 1))
        done < <(scanner_local_filesystem_roots)
        if [ "$scan_errors" -gt 0 ]; then
            set_result ERROR "루트 파일시스템의 소유자 없는 파일 검색을 완료하지 못했습니다." "scope=/,xdev=true"
            return
        fi
    else
        passwd_file="$(fs_path /etc/passwd)"
        group_file="$(fs_path /etc/group)"
        [ -r "$passwd_file" ] && [ -r "$group_file" ] || {
            set_result ERROR "오프라인 루트의 계정 및 그룹 파일을 읽을 수 없습니다." "paths=/etc/passwd,/etc/group"
            return
        }
        if ! find -P "$scan_path" -xdev -print0 > "$scan_list" 2>/dev/null; then
            set_result ERROR "오프라인 루트의 전체 파일 목록을 수집하지 못했습니다." "scope=$SCAN_ROOT"
            return
        fi
        while IFS= read -r -d '' path; do
            file_uid="$(stat_uid "$path" 2>/dev/null || true)"
            file_gid="$(scanner_stat_gid "$path" 2>/dev/null || true)"
            if [ -z "$file_uid" ] || [ -z "$file_gid" ]; then
                scan_errors=$((scan_errors + 1))
            elif ! awk -F: -v value="$file_uid" '$3 == value {found=1} END {exit(found ? 0 : 1)}' "$passwd_file" || \
               ! awk -F: -v value="$file_gid" '$3 == value {found=1} END {exit(found ? 0 : 1)}' "$group_file"; then
                printf '%s\0' "$path" >> "$orphan_list"
            fi
        done < "$scan_list"
    fi

    if [ "$scan_errors" -gt 0 ]; then
        set_result ERROR "일부 파일의 소유자 메타데이터를 확인하지 못했습니다." "metadata_errors=${scan_errors}"
        return
    fi

    while IFS= read -r -d '' path; do
        count=$((count + 1))
        [ "$count" -le 20 ] && scanner_append_evidence evidence "$(scanner_evidence_path "$path")"
    done < "$orphan_list"
    evidence="orphaned_paths=${count}
${evidence}"
    if [ "$count" -gt 0 ]; then
        set_result VULNERABLE "소유자 또는 그룹이 존재하지 않는 파일·디렉터리가 있습니다." "$evidence"
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

    path="$(fs_path /etc/passwd)"
    [ -e "$path" ] || {
        set_result ERROR "/etc/passwd가 존재하지 않습니다." "path=/etc/passwd"
        return
    }
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
    local directory=""
    local path=""
    local uid=""
    local mode=""
    local decimal_mode=""
    local scanned=0
    local violations=0
    local errors=0
    local evidence=""
    local masks=0

    list_file="$(new_scratch_file u17-files)" || {
        set_result ERROR "시작 스크립트 목록을 저장할 임시 파일을 만들지 못했습니다."
        return
    }
    for directory in /etc/systemd/system /etc/init.d /etc/rc.d/init.d; do
        directory="$(fs_path "$directory")"
        [ -d "$directory" ] || continue
        if ! find -P "$directory" -xdev \( -type f -o -type l \) -print0 >> "$list_file" 2>/dev/null; then
            errors=$((errors + 1))
        fi
    done
    while IFS= read -r -d '' path; do
        scanned=$((scanned + 1))
        if scanner_is_dev_null_mask "$path"; then
            masks=$((masks + 1))
            continue
        fi
        uid="$(stat_uid "$path" 2>/dev/null || true)"
        mode="$(stat_mode "$path" 2>/dev/null || true)"
        decimal_mode="$(mode_to_decimal "$mode" 2>/dev/null || true)"
        if [ -z "$uid" ] || [ -z "$decimal_mode" ]; then
            errors=$((errors + 1))
        elif [ "$uid" != "0" ] || [ $((decimal_mode & 0022)) -ne 0 ]; then
            violations=$((violations + 1))
            [ "$violations" -le 20 ] && scanner_append_evidence evidence "$(scanner_evidence_path "$path"):owner_uid=${uid},mode=${mode}"
        fi
    done < "$list_file"
    evidence="scanned_paths=${scanned}
violations=${violations}
metadata_errors=${errors}
masks=${masks}
${evidence}"
    if [ "$errors" -gt 0 ]; then
        set_result ERROR "일부 시스템 시작 스크립트의 메타데이터를 확인하지 못했습니다." "$evidence"
    elif [ "$violations" -gt 0 ]; then
        set_result VULNERABLE "root 소유가 아니거나 일반 사용자 쓰기가 허용된 시작 스크립트가 있습니다." "$evidence"
    elif [ "$scanned" -eq 0 ]; then
        set_result NOT_APPLICABLE "로컬 시스템 시작 스크립트를 찾지 못했습니다." "$evidence" false
    else
        set_result GOOD "시스템 시작 스크립트가 root 소유이며 일반 사용자 쓰기가 차단되어 있습니다." "$evidence"
    fi
}

check_u_18() {
    local path=""
    local uid=""
    local mode=""
    local result=2

    path="$(fs_path /etc/shadow)"
    [ -e "$path" ] || {
        set_result VULNERABLE "/etc/shadow가 존재하지 않습니다." "path=/etc/shadow"
        return
    }
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

    path="$(fs_path /etc/hosts)"
    [ -e "$path" ] || {
        set_result ERROR "/etc/hosts가 존재하지 않습니다." "path=/etc/hosts"
        return
    }
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
        SCANNER_METADATA_SCANNED=$((SCANNER_METADATA_SCANNED + 1))
        if scanner_is_dev_null_mask "$path"; then
            SCANNER_METADATA_MASKS=$((SCANNER_METADATA_MASKS + 1))
            continue
        fi
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
    local evidence=""
    local scan_errors=0

    list_file="$(new_scratch_file u20-files)" || {
        set_result ERROR "구성 파일 목록을 저장할 임시 파일을 만들지 못했습니다."
        return
    }
    for path in /etc/inetd.conf /etc/xinetd.conf /etc/systemd/system.conf; do
        path="$(fs_path "$path")"
        [ -e "$path" ] && printf '%s\0' "$path" >> "$list_file"
    done
    for directory in /etc/xinetd.d /etc/systemd; do
        directory="$(fs_path "$directory")"
        [ -d "$directory" ] || continue
        find -P "$directory" -xdev \( -type f -o -type l \) -print0 >> "$list_file" 2>/dev/null || scan_errors=$((scan_errors + 1))
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

    list_file="$(new_scratch_file u21-files)" || {
        set_result ERROR "로깅 구성 파일 목록을 저장할 임시 파일을 만들지 못했습니다."
        return
    }
    for path in /etc/syslog.conf /etc/rsyslog.conf; do
        path="$(fs_path "$path")"
        [ -e "$path" ] && printf '%s\0' "$path" >> "$list_file"
    done
    main_file="$(fs_path /etc/rsyslog.conf 2>/dev/null || true)"
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
    directory="$(fs_path /etc/rsyslog.d 2>/dev/null || true)"
    if [ "$standard_include" -eq 1 ] && [ -d "$directory" ]; then
        find -P "$directory" -maxdepth 1 \( -type f -o -type l \) -name '*.conf' -print0 >> "$list_file" 2>/dev/null || scan_errors=$((scan_errors + 1))
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

    path="$(fs_path /etc/services)"
    [ -e "$path" ] || {
        set_result ERROR "/etc/services가 존재하지 않습니다." "path=/etc/services"
        return
    }
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
    local list_file=""
    local path=""
    local count=0
    local evidence=""
    local filesystem_root=""
    local scan_errors=0

    list_file="$(new_scratch_file u23-files)" || {
        set_result ERROR "특수 권한 파일 목록을 저장할 임시 파일을 만들지 못했습니다."
        return
    }
    : > "$list_file"
    while IFS= read -r filesystem_root; do
        find -P "$filesystem_root" -xdev -type f \( -perm -04000 -o -perm -02000 \) -print0 >> "$list_file" 2>/dev/null || scan_errors=$((scan_errors + 1))
    done < <(scanner_local_filesystem_roots)
    if [ "$scan_errors" -gt 0 ]; then
        set_result ERROR "루트 파일시스템의 SUID·SGID 검색을 완료하지 못했습니다." "scope=/,xdev=true"
        return
    fi
    while IFS= read -r -d '' path; do
        count=$((count + 1))
        [ "$count" -le 20 ] && scanner_append_evidence evidence "$(scanner_evidence_path "$path"):mode=$(stat_mode "$path" 2>/dev/null || printf unresolved)"
    done < "$list_file"
    evidence="special_permission_files=${count}
${evidence}"
    if [ "$count" -eq 0 ]; then
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
    local user_uid=""
    local home_path=""
    local shell_path=""
    local logical_file=""
    local path=""
    local file_uid=""
    local mode=""
    local decimal_mode=""
    local scanned=0
    local violations=0
    local errors=0
    local evidence=""

    passwd_file="$(fs_path /etc/passwd)"
    [ -r "$passwd_file" ] || {
        set_result ERROR "/etc/passwd를 읽을 수 없습니다." "path=/etc/passwd"
        return
    }
    while IFS=: read -r user_name _ user_uid _ _ home_path shell_path; do
        case "$home_path" in /*) ;; *) continue ;; esac
        for logical_file in .profile .bash_profile .bash_login .bashrc .kshrc .cshrc .tcshrc .login .exrc .netrc .zprofile .zshenv .zshrc .zlogin .pam_environment .config/fish/config.fish; do
            path="$(fs_path "${home_path%/}/$logical_file")"
            [ -e "$path" ] || continue
            scanned=$((scanned + 1))
            file_uid="$(stat_uid "$path" 2>/dev/null || true)"
            mode="$(stat_mode "$path" 2>/dev/null || true)"
            decimal_mode="$(mode_to_decimal "$mode" 2>/dev/null || true)"
            if [ -z "$file_uid" ] || [ -z "$decimal_mode" ]; then
                errors=$((errors + 1))
            elif { [ "$file_uid" != "0" ] && [ "$file_uid" != "$user_uid" ]; } || [ $((decimal_mode & 0022)) -ne 0 ]; then
                violations=$((violations + 1))
                [ "$violations" -le 20 ] && scanner_append_evidence evidence "$(scanner_evidence_path "$path"):owner_uid=${file_uid},expected_uid=${user_uid},mode=${mode}"
            fi
        done
        path="$(fs_path "${home_path%/}/.config/environment.d" 2>/dev/null || true)"
        if [ -d "$path" ]; then
            while IFS= read -r logical_file; do
                scanned=$((scanned + 1))
                file_uid="$(stat_uid "$logical_file" 2>/dev/null || true)"
                mode="$(stat_mode "$logical_file" 2>/dev/null || true)"
                decimal_mode="$(mode_to_decimal "$mode" 2>/dev/null || true)"
                if [ -z "$file_uid" ] || [ -z "$decimal_mode" ]; then
                    errors=$((errors + 1))
                elif { [ "$file_uid" != "0" ] && [ "$file_uid" != "$user_uid" ]; } || [ $((decimal_mode & 0022)) -ne 0 ]; then
                    violations=$((violations + 1))
                    [ "$violations" -le 20 ] && scanner_append_evidence evidence "$(scanner_evidence_path "$logical_file"):owner_uid=${file_uid},expected_uid=${user_uid},mode=${mode}"
                fi
            done < <(find -P "$path" -maxdepth 1 -type f -name '*.conf' -print 2>/dev/null | LC_ALL=C sort)
        fi
    done < "$passwd_file"
    evidence="scanned_files=${scanned}
violations=${violations}
metadata_errors=${errors}
${evidence}"
    if [ "$errors" -gt 0 ]; then
        set_result ERROR "일부 홈 환경 파일의 메타데이터를 확인하지 못했습니다." "$evidence"
    elif [ "$violations" -gt 0 ]; then
        set_result VULNERABLE "홈 환경 파일의 소유자 또는 쓰기 권한이 기준을 벗어납니다." "$evidence"
    else
        set_result GOOD "발견된 홈 환경 파일은 root 또는 해당 계정 소유이며 타 사용자 쓰기가 차단되어 있습니다." "$evidence"
    fi
}

check_u_25() {
    local list_file=""
    local path=""
    local count=0
    local evidence=""
    local filesystem_root=""
    local scan_errors=0

    list_file="$(new_scratch_file u25-files)" || {
        set_result ERROR "world writable 파일 목록을 저장할 임시 파일을 만들지 못했습니다."
        return
    }
    : > "$list_file"
    while IFS= read -r filesystem_root; do
        find -P "$filesystem_root" -xdev -type f -perm -0002 -print0 >> "$list_file" 2>/dev/null || scan_errors=$((scan_errors + 1))
    done < <(scanner_local_filesystem_roots)
    if [ "$scan_errors" -gt 0 ]; then
        set_result ERROR "루트 파일시스템의 world writable 파일 검색을 완료하지 못했습니다." "scope=/,xdev=true"
        return
    fi
    while IFS= read -r -d '' path; do
        count=$((count + 1))
        [ "$count" -le 20 ] && scanner_append_evidence evidence "$(scanner_evidence_path "$path")"
    done < "$list_file"
    evidence="world_writable_files=${count}
${evidence}"
    if [ "$count" -eq 0 ]; then
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

    device_directory="$(fs_path /dev)"
    [ -d "$device_directory" ] || {
        set_result ERROR "/dev 디렉터리가 존재하지 않습니다." "path=/dev"
        return
    }
    list_file="$(new_scratch_file u26-files)" || {
        set_result ERROR "/dev 일반 파일 목록을 저장할 임시 파일을 만들지 못했습니다."
        return
    }
    if ! find -P "$device_directory" -xdev -type f -print0 > "$list_file" 2>/dev/null; then
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

scanner_rservice_static_enabled() {
    local service=""
    local wants_directory=""
    local candidate=""

    for service in rlogin rsh rexec; do
        scanner_inetd_service_enabled "$service" && return 0
        for wants_directory in /etc/systemd/system/sockets.target.wants /etc/systemd/system/multi-user.target.wants; do
            for candidate in "$service.socket" "$service.service"; do
                [ -e "$(fs_path "$wants_directory/$candidate")" ] && return 0
            done
        done
    done
    return 1
}

scanner_trust_file_violation() {
    local path="$1"
    local expected_uid="$2"
    local uid=""
    local mode=""

    uid="$(stat_uid "$path" 2>/dev/null || true)"
    mode="$(stat_mode "$path" 2>/dev/null || true)"
    [ -n "$uid" ] && [ -n "$mode" ] || return 2
    { [ "$uid" = "0" ] || [ "$uid" = "$expected_uid" ]; } || return 0
    mode_is_at_most "$mode" 600 || return 0
    if awk '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            count=split(line, fields, /[[:space:]]+/)
            for (index_value=1; index_value<=count; index_value++) if (fields[index_value] ~ /^\+/) found=1
        }
        END {exit(found ? 0 : 1)}
    ' "$path"; then
        return 0
    fi
    return 1
}

check_u_27() {
    local service_active=0
    local runtime_known=0
    local state=3
    local path=""
    local passwd_file=""
    local user_name=""
    local user_uid=""
    local home_path=""
    local shell_path=""
    local checked=0
    local violations=0
    local errors=0
    local result=1
    local evidence=""

    scanner_rservice_static_enabled && service_active=1
    if runtime_enabled; then
        service_state rlogin.socket rsh.socket rexec.socket rlogin.service rsh.service rexec.service >/dev/null 2>&1
        state=$?
        [ "$state" -eq 0 ] && service_active=1
        { [ "$state" -eq 0 ] || [ "$state" -eq 1 ]; } && runtime_known=1
        if [ -n "$(port_listener_facts 512 2>/dev/null)$(port_listener_facts 513 2>/dev/null)$(port_listener_facts 514 2>/dev/null)" ]; then
            service_active=1
            runtime_known=1
        fi
    fi

    if [ "$service_active" -eq 0 ]; then
        if runtime_enabled && [ "$runtime_known" -eq 1 ]; then
            set_result GOOD "rlogin·rsh·rexec 서비스가 비활성 상태입니다." "runtime_state_code=${state}"
        else
            set_result NOT_APPLICABLE "r 계열 서비스의 활성 구성 증거가 없습니다." "runtime_checked=$(runtime_enabled && printf true || printf false)" false
        fi
        return
    fi

    path="$(fs_path /etc/hosts.equiv)"
    if [ -e "$path" ]; then
        checked=$((checked + 1))
        scanner_trust_file_violation "$path" 0
        result=$?
        [ "$result" -eq 0 ] && violations=$((violations + 1))
        [ "$result" -eq 2 ] && errors=$((errors + 1))
        [ "$result" -ne 1 ] && scanner_append_evidence evidence "$(scanner_evidence_path "$path"):metadata_or_plus_violation"
    fi
    passwd_file="$(fs_path /etc/passwd)"
    if [ -r "$passwd_file" ]; then
        while IFS=: read -r user_name _ user_uid _ _ home_path shell_path; do
            case "$home_path" in /*) ;; *) continue ;; esac
            path="$(fs_path "${home_path%/}/.rhosts")"
            [ -e "$path" ] || continue
            checked=$((checked + 1))
            scanner_trust_file_violation "$path" "$user_uid"
            result=$?
            [ "$result" -eq 0 ] && violations=$((violations + 1))
            [ "$result" -eq 2 ] && errors=$((errors + 1))
            [ "$result" -ne 1 ] && scanner_append_evidence evidence "$(scanner_evidence_path "$path"):metadata_or_plus_violation"
        done < "$passwd_file"
    else
        errors=$((errors + 1))
    fi
    evidence="trust_files_checked=${checked}
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

scanner_count_active_lines() {
    local file="$1"
    [ -r "$file" ] || {
        printf '0\n'
        return
    }
    awk '{line=$0; sub(/^[[:space:]]+/, "", line); if (line != "" && line !~ /^[#;]/) count++} END {print count+0}' "$file"
}

check_u_28() {
    local providers=0
    local rule_count=0
    local output=""
    local path=""
    local directory=""
    local evidence=""
    local policy_output=""

    for path in /etc/hosts.allow /etc/hosts.deny; do
        path="$(fs_path "$path")"
        rule_count=$((rule_count + $(scanner_count_active_lines "$path")))
    done
    [ "$rule_count" -gt 0 ] && providers=$((providers + 1))
    scanner_append_evidence evidence "tcp_wrapper_rules=${rule_count}"

    if runtime_enabled; then
        if service_state firewalld.service >/dev/null 2>&1; then
            output="$(capture_command firewall-cmd --list-all-zones 2>/dev/null || true)"
            rule_count="$(printf '%s\n' "$output" | awk '/^[[:space:]]*(sources|ports|rich rules):/ {for (index_value=2; index_value<=NF; index_value++) if ($index_value != "") count++} END {print count+0}')"
            policy_output="$(capture_command firewall-cmd --list-all-policies 2>/dev/null || true)"
            rule_count=$((rule_count + $(printf '%s\n' "$policy_output" | awk '/^[^[:space:]].*[[:space:]]*\(active\)/ {count++} END {print count+0}')))
            [ "$rule_count" -gt 0 ] && providers=$((providers + 1))
            scanner_append_evidence evidence "firewalld_rule_indicators=${rule_count}"
        fi
        output="$(capture_command ufw status 2>/dev/null || true)"
        if printf '%s\n' "$output" | grep -q '^Status: active'; then
            rule_count="$(printf '%s\n' "$output" | awk '/(ALLOW|DENY|REJECT)/ {count++} END {print count+0}')"
            [ "$rule_count" -gt 0 ] && providers=$((providers + 1))
            scanner_append_evidence evidence "ufw_rule_indicators=${rule_count}"
        fi
        output="$(capture_command nft list ruleset 2>/dev/null || true)"
        rule_count="$(printf '%s\n' "$output" | awk '/(^|[[:space:]])(accept|drop|reject)([[:space:]]|$)/ {count++} END {print count+0}')"
        [ "$rule_count" -gt 0 ] && providers=$((providers + 1))
        scanner_append_evidence evidence "nftables_rule_indicators=${rule_count}"
        output="$(capture_command iptables -S 2>/dev/null || true)"
        rule_count="$(printf '%s\n' "$output" | awk '$1 == "-A" {count++} END {print count+0}')"
        [ "$rule_count" -gt 0 ] && providers=$((providers + 1))
        scanner_append_evidence evidence "iptables_rules=${rule_count}"
    else
        rule_count=0
        for path in /etc/nftables.conf /etc/ufw/user.rules /etc/ufw/user6.rules /etc/iptables/rules.v4 /etc/iptables/rules.v6 /etc/sysconfig/nftables.conf /etc/sysconfig/iptables; do
            path="$(fs_path "$path")"
            rule_count=$((rule_count + $(scanner_count_active_lines "$path")))
        done
        for directory in /etc/nftables /etc/nftables.d /etc/firewalld/zones /etc/firewalld/policies; do
            directory="$(fs_path "$directory")"
            [ -d "$directory" ] || continue
            while IFS= read -r path; do
                rule_count=$((rule_count + $(scanner_count_active_lines "$path")))
            done < <(find -P "$directory" -maxdepth 1 -type f \( -name '*.nft' -o -name '*.xml' \) -print 2>/dev/null)
        done
        [ "$rule_count" -gt 0 ] && providers=$((providers + 1))
        scanner_append_evidence evidence "persistent_firewall_lines=${rule_count}"
    fi

    if [ "$providers" -eq 0 ]; then
        set_result VULNERABLE "호스트·IP·포트 접근 제한을 입증할 활성 또는 영구 규칙을 찾지 못했습니다." "$evidence"
    else
        set_result MANUAL "접근 제한 규칙은 존재하지만 허용 호스트와 포트가 업무 정책에 맞는지 확인해야 합니다." "$evidence"
    fi
}

check_u_29() {
    local path=""
    local uid=""
    local mode=""
    local result=2

    path="$(fs_path /etc/hosts.lpd)"
    if [ ! -e "$path" ]; then
        set_result GOOD "/etc/hosts.lpd가 존재하지 않습니다." "path=/etc/hosts.lpd"
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

scanner_umask_records() {
    local file=""
    local directory=""

    for file in /etc/profile /etc/bash.bashrc /etc/bashrc; do
        file="$(fs_path "$file")"
        [ -r "$file" ] || continue
        awk '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                if (match(line, /(^|[;[:space:]])umask[[:space:]]+[0-7]{3,4}([;[:space:]]|$)/)) {
                    value=substr(line, RSTART, RLENGTH)
                    sub(/^.*umask[[:space:]]+/, "", value)
                    sub(/[;[:space:]].*$/, "", value)
                    print value "\t" FILENAME ":" FNR
                }
            }
        ' "$file"
    done
    directory="$(fs_path /etc/profile.d)"
    if [ -d "$directory" ]; then
        while IFS= read -r file; do
            awk '
                {
                    line=$0
                    sub(/^[[:space:]]+/, "", line)
                    if (line == "" || line ~ /^#/) next
                    if (match(line, /(^|[;[:space:]])umask[[:space:]]+[0-7]{3,4}([;[:space:]]|$)/)) {
                        value=substr(line, RSTART, RLENGTH)
                        sub(/^.*umask[[:space:]]+/, "", value)
                        sub(/[;[:space:]].*$/, "", value)
                        print value "\t" FILENAME ":" FNR
                    }
                }
            ' "$file"
        done < <(find -P "$directory" -maxdepth 1 -type f -name '*.sh' -print 2>/dev/null | LC_ALL=C sort)
    fi
}

check_u_30() {
    local records=""
    local record=""
    local value=""
    local decimal_value=""
    local compliant=0
    local noncompliant=0
    local evidence=""
    local record_count=0

    records="$(scanner_umask_records)"
    record="$(login_defs_value UMASK 2>/dev/null || true)"
    [ -n "$record" ] && records="${records}${records:+$'\n'}${record}"
    while IFS= read -r record; do
        [ -n "$record" ] || continue
        record_count=$((record_count + 1))
        value="$(scanner_value_only "$record")"
        decimal_value="$(mode_to_decimal "$value" 2>/dev/null || true)"
        if [ -n "$decimal_value" ] && [ $((decimal_value & 0022)) -eq $((0022)) ]; then
            compliant=$((compliant + 1))
        else
            noncompliant=$((noncompliant + 1))
        fi
        scanner_append_evidence evidence "umask=${value},source=$(scanner_source_only "$record")"
    done <<EOF
$records
EOF

    if [ "$record_count" -gt 1 ]; then
        set_result MANUAL "여러 UMASK 선언의 셸 적용 순서와 조건을 확인해야 합니다." "$evidence"
    elif [ "$noncompliant" -gt 0 ]; then
        set_result VULNERABLE "일반 사용자 쓰기를 충분히 제한하지 않는 전역 UMASK 설정이 존재합니다." "$evidence"
    elif [ "$compliant" -gt 0 ]; then
        set_result GOOD "전역 UMASK가 022 이상의 쓰기 제한 비트를 포함합니다." "$evidence"
    else
        set_result VULNERABLE "전역 UMASK 설정을 확인하지 못했습니다." "$evidence"
    fi
}

check_u_31() {
    local passwd_file=""
    local user_name=""
    local user_uid=""
    local home_path=""
    local shell_path=""
    local path=""
    local owner_uid=""
    local mode=""
    local scanned=0
    local violations=0
    local errors=0
    local evidence=""

    passwd_file="$(fs_path /etc/passwd)"
    [ -r "$passwd_file" ] || {
        set_result ERROR "/etc/passwd를 읽을 수 없습니다." "path=/etc/passwd"
        return
    }
    while IFS=: read -r user_name _ user_uid _ _ home_path shell_path; do
        scanner_nonlogin_shell "$shell_path" && continue
        case "$home_path" in /*) ;; *) continue ;; esac
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
    local user_uid=""
    local home_path=""
    local shell_path=""
    local path=""
    local missing=0
    local excluded=0
    local evidence=""

    passwd_file="$(fs_path /etc/passwd)"
    [ -r "$passwd_file" ] || {
        set_result ERROR "/etc/passwd를 읽을 수 없습니다." "path=/etc/passwd"
        return
    }
    while IFS=: read -r user_name _ user_uid _ _ home_path shell_path; do
        if scanner_nonlogin_shell "$shell_path"; then
            excluded=$((excluded + 1))
            continue
        fi
        case "$home_path" in
            /*) ;;
            *)
                missing=$((missing + 1))
                [ "$missing" -le 20 ] && scanner_append_evidence evidence "account=${user_name},home=${home_path:-unset}"
                continue
                ;;
        esac
        path="$(fs_path "$home_path")"
        if [ ! -d "$path" ]; then
            missing=$((missing + 1))
            [ "$missing" -le 20 ] && scanner_append_evidence evidence "account=${user_name},home=${home_path}"
        fi
    done < "$passwd_file"
    evidence="missing_login_homes=${missing}
nonlogin_accounts_excluded=${excluded}
${evidence}"
    if [ "$missing" -gt 0 ]; then
        set_result VULNERABLE "로그인 가능한 계정 중 홈 디렉터리가 없는 계정이 있습니다." "$evidence"
    else
        set_result GOOD "모든 로그인 가능 계정의 홈 디렉터리가 존재합니다." "$evidence"
    fi
}

check_u_33() {
    local list_file=""
    local path=""
    local basename_value=""
    local count=0
    local evidence=""
    local filesystem_root=""
    local scan_errors=0

    list_file="$(new_scratch_file u33-files)" || {
        set_result ERROR "숨김 경로 목록을 저장할 임시 파일을 만들지 못했습니다."
        return
    }
    : > "$list_file"
    while IFS= read -r filesystem_root; do
        find -P "$filesystem_root" -xdev -mindepth 1 -name '.*' -print0 >> "$list_file" 2>/dev/null || scan_errors=$((scan_errors + 1))
    done < <(scanner_local_filesystem_roots)
    if [ "$scan_errors" -gt 0 ]; then
        set_result ERROR "루트 파일시스템의 숨김 경로 검색을 완료하지 못했습니다." "scope=/,xdev=true"
        return
    fi
    while IFS= read -r -d '' path; do
        basename_value="${path##*/}"
        case "$basename_value" in .|..) continue ;; esac
        count=$((count + 1))
        [ "$count" -le 20 ] && scanner_append_evidence evidence "$(scanner_evidence_path "$path")"
    done < "$list_file"
    evidence="hidden_paths=${count}
${evidence}"
    if [ "$count" -eq 0 ]; then
        if [ "$SCAN_ROOT" != "/" ]; then
            set_result MANUAL "오프라인 루트의 하위 마운트 경계를 확인할 수 없어 숨김 경로 검색 완료를 확정할 수 없습니다." "$evidence"
        else
            set_result GOOD "검사한 파일시스템에서 숨김 파일·디렉터리를 찾지 못했습니다." "$evidence"
        fi
    else
        set_result MANUAL "숨김 파일·디렉터리의 업무 필요성과 무결성을 확인해야 합니다." "$evidence"
    fi
}
