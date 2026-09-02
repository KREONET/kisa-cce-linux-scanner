# shellcheck shell=bash

# shellcheck disable=SC2153

# Patch and logging checks cover U-64 through U-67.

check_u_64() {
    local evidence=""
    local path=""
    local command_path=""

    if [ "$PLATFORM_ID" = "ubuntu" ]; then
        for path in /var/lib/apt/periodic/update-success-stamp /var/log/apt/history.log /var/log/unattended-upgrades/unattended-upgrades.log; do
            local physical_path=""
            physical_path="$(fs_path "$path")"
            if [ -e "$physical_path" ]; then
                evidence="${evidence}${path}:mtime=$(date -r "$physical_path" -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf unknown)\n"
            fi
        done
        if runtime_enabled; then
            command_path="$(trusted_command apt-get 2>/dev/null || true)"
            [ -n "$command_path" ] && evidence="${evidence}package_manager=apt\n"
        fi
    elif [ "$PLATFORM_ID" = "rhel" ]; then
        path="$(fs_path /var/log/dnf.log)"
        if [ -e "$path" ]; then
            evidence="${evidence}/var/log/dnf.log:mtime=$(date -r "$path" -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf unknown)\n"
        fi
        if runtime_enabled; then
            command_path="$(trusted_command dnf 2>/dev/null || true)"
            [ -n "$command_path" ] && evidence="${evidence}package_manager=dnf\n"
        fi
    fi

    set_result MANUAL \
        "패치 정책, 승인된 기준일, 벤더 권고 반영 여부는 조직 증적과 함께 확인해야 합니다." \
        "${evidence}network_access=not_performed"
}

chrony_runtime_evidence() {
    local chronyc_path=""
    local tracking=""
    local sources=""
    local selected_count="0"
    local leap_status=""

    chronyc_path="$(trusted_command chronyc)" || return 127
    tracking="$($chronyc_path -n tracking 2>/dev/null)" || return 2
    sources="$($chronyc_path -n sources 2>/dev/null)" || return 2
    leap_status="$(printf '%s\n' "$tracking" | awk -F: '/^Leap status/ {value=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); print value; exit}')"
    selected_count="$(printf '%s\n' "$sources" | awk '/^[\^=#]\*/ {count++} END {print count+0}')"

    printf 'provider=chrony\nleap_status=%s\nselected_sources=%s\n' "$leap_status" "$selected_count"
    [ "$leap_status" = "Normal" ] && [ "$selected_count" -gt 0 ]
}

timesyncd_runtime_evidence() {
    local timedatectl_path=""
    local synchronized=""

    timedatectl_path="$(trusted_command timedatectl)" || return 127
    synchronized="$($timedatectl_path show -p NTPSynchronized --value 2>/dev/null)" || return 2
    printf 'provider=systemd-timesyncd\nsynchronized=%s\n' "$synchronized"
    [ "$synchronized" = "yes" ]
}

CHRONY_OFFLINE_SOURCE_COUNT=0
CHRONY_OFFLINE_RESOLUTION_ERROR=0

chrony_collect_offline_file() {
    local candidate="$1"
    local visited_file="$2"
    local depth="${3:-0}"
    local resolved_file=""
    local directive=""
    local argument=""
    local include_directory=""
    local include_pattern=""
    local resolved_directory=""
    local list_file=""
    local included_file=""

    [ "$depth" -lt 24 ] || { CHRONY_OFFLINE_RESOLUTION_ERROR=1; return 2; }
    resolved_file="$(resolve_rooted_read_path "$candidate" 2>/dev/null || true)"
    [ -n "$resolved_file" ] || { CHRONY_OFFLINE_RESOLUTION_ERROR=1; return 2; }
    if grep -Fqx -- "$resolved_file" "$visited_file" 2>/dev/null; then
        CHRONY_OFFLINE_RESOLUTION_ERROR=1
        return 2
    fi
    printf '%s\n' "$resolved_file" >> "$visited_file"

    while IFS="$(printf '\t')" read -r directive argument; do
        [ -n "$directive" ] || continue
        case "$directive" in
            server|pool|peer)
                CHRONY_OFFLINE_SOURCE_COUNT=$((CHRONY_OFFLINE_SOURCE_COUNT + 1))
                ;;
            include)
                case "$argument" in
                    /*)
                        include_directory="${argument%/*}"
                        include_pattern="${argument##*/}"
                        resolved_directory="$(fs_path "$include_directory" 2>/dev/null || true)"
                        ;;
                    */*)
                        resolved_directory="${resolved_file%/*}/${argument%/*}"
                        include_pattern="${argument##*/}"
                        ;;
                    *)
                        resolved_directory="${resolved_file%/*}"
                        include_pattern="$argument"
                        ;;
                esac
                resolved_directory="$(resolve_rooted_directory "$resolved_directory" 2>/dev/null || true)"
                [ -n "$resolved_directory" ] || { CHRONY_OFFLINE_RESOLUTION_ERROR=1; continue; }
                list_file="$(new_scratch_file chrony-include)" || { CHRONY_OFFLINE_RESOLUTION_ERROR=1; continue; }
                find -P "$resolved_directory" -maxdepth 1 -type f -name "$include_pattern" -print0 > "$list_file" 2>/dev/null || { CHRONY_OFFLINE_RESOLUTION_ERROR=1; continue; }
                while IFS= read -r -d '' included_file; do
                    chrony_collect_offline_file "$included_file" "$visited_file" $((depth + 1)) || true
                done < "$list_file"
                ;;
            confdir|sourcedir)
                case "$argument" in
                    /*) resolved_directory="$(fs_path "$argument" 2>/dev/null || true)" ;;
                    *) resolved_directory="${resolved_file%/*}/$argument" ;;
                esac
                resolved_directory="$(resolve_rooted_directory "$resolved_directory" 2>/dev/null || true)"
                [ -n "$resolved_directory" ] || { CHRONY_OFFLINE_RESOLUTION_ERROR=1; continue; }
                list_file="$(new_scratch_file chrony-directory)" || { CHRONY_OFFLINE_RESOLUTION_ERROR=1; continue; }
                if [ "$directive" = "confdir" ]; then
                    find -P "$resolved_directory" -maxdepth 1 -type f -name '*.conf' -print0 > "$list_file" 2>/dev/null || { CHRONY_OFFLINE_RESOLUTION_ERROR=1; continue; }
                    while IFS= read -r -d '' included_file; do
                        chrony_collect_offline_file "$included_file" "$visited_file" $((depth + 1)) || true
                    done < "$list_file"
                else
                    find -P "$resolved_directory" -maxdepth 1 -type f -name '*.sources' -print0 > "$list_file" 2>/dev/null || { CHRONY_OFFLINE_RESOLUTION_ERROR=1; continue; }
                    while IFS= read -r -d '' included_file; do
                        resolved_file="$(resolve_rooted_read_path "$included_file" 2>/dev/null || true)"
                        if [ -z "$resolved_file" ]; then
                            CHRONY_OFFLINE_RESOLUTION_ERROR=1
                            continue
                        fi
                        CHRONY_OFFLINE_SOURCE_COUNT=$((CHRONY_OFFLINE_SOURCE_COUNT + $(awk '
                            /^[[:space:]]*(server|pool|peer)[[:space:]]+/ && $0 !~ /^[[:space:]]*#/ {count++}
                            END {print count+0}
                        ' "$resolved_file")))
                    done < "$list_file"
                fi
                ;;
        esac
    done < <(awk '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            sub(/[[:space:]]+#.*$/, "", line)
            split(line, fields, /[[:space:]]+/)
            directive=tolower(fields[1])
            if (directive ~ /^(server|pool|peer|include|confdir|sourcedir)$/) print directive "\t" fields[2]
        }
    ' "$resolved_file")
}

time_service_persistence_state() {
    local systemctl_path=""
    local unit=""
    local properties=""
    local load_state=""
    local unit_file_state=""
    local command_status=0

    systemctl_path="$(trusted_command systemctl)" || return 2
    for unit in "$@"; do
        properties="$($systemctl_path show "$unit" -p LoadState -p UnitFileState --no-pager 2>/dev/null)" || command_status=$?
        load_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "LoadState" {print $2; exit}')"
        unit_file_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "UnitFileState" {print $2; exit}')"
        if [ "$command_status" -ne 0 ] && [ "$load_state" != "not-found" ]; then
            return 2
        fi
        command_status=0
        [ "$load_state" != "not-found" ] || continue
        case "$unit_file_state" in
            enabled|enabled-runtime|static|indirect|generated|linked|linked-runtime) return 0 ;;
            masked|masked-runtime|disabled) return 1 ;;
        esac
    done
    return 2
}

chrony_config_evidence() {
    local chronyd_path=""
    local config_path=""
    local output=""
    local source_count="0"
    local visited_file=""

    if [ "$PLATFORM_ID" = "ubuntu" ]; then
        config_path="/etc/chrony/chrony.conf"
    else
        config_path="/etc/chrony.conf"
    fi

    if runtime_enabled; then
        chronyd_path="$(trusted_command chronyd 2>/dev/null || true)"
        if [ -n "$chronyd_path" ] && [ -r "$config_path" ]; then
            output="$($chronyd_path -p -f "$config_path" 2>/dev/null)" || {
                printf 'persistent_config=invalid\n'
                return 2
            }
            source_count="$(printf '%s\n' "$output" | awk '$1 == "server" || $1 == "pool" || $1 == "peer" {count++} END {print count+0}')"
            printf 'persistent_config=valid\nconfigured_sources=%s\n' "$source_count"
            [ "$source_count" -gt 0 ] || return 3
            return 0
        fi
    fi

    config_path="$(fs_path "$config_path")"
    if [ -r "$config_path" ]; then
        visited_file="$(new_scratch_file chrony-visited)" || return 2
        CHRONY_OFFLINE_SOURCE_COUNT=0
        CHRONY_OFFLINE_RESOLUTION_ERROR=0
        chrony_collect_offline_file "$config_path" "$visited_file" 0 || true
        source_count="$CHRONY_OFFLINE_SOURCE_COUNT"
        printf 'persistent_config=%s\nconfigured_sources=%s\nresolution_errors=%s\n' \
            "$(display_path "$config_path")" "$source_count" "$CHRONY_OFFLINE_RESOLUTION_ERROR"
        [ "$CHRONY_OFFLINE_RESOLUTION_ERROR" -eq 0 ] || return 2
        [ "$source_count" -gt 0 ] || return 3
        return 0
    fi

    return 1
}

check_u_65() {
    local runtime_facts=""
    local runtime_status=1
    local config_facts=""
    local config_status=1
    local provider=""
    local chrony_state=1
    local timesyncd_state=1
    local persistence_status=2

    config_facts="$(chrony_config_evidence 2>/dev/null)"
    config_status=$?

    if ! runtime_enabled; then
        set_result MANUAL \
            "오프라인 루트에서는 실제 시각 동기화 상태를 확정할 수 없습니다." \
            "$config_facts"
        return
    fi

    service_state chronyd.service chrony.service >/dev/null 2>&1
    chrony_state=$?
    if [ "$chrony_state" -eq 0 ]; then
        provider="chrony"
        runtime_facts="$(chrony_runtime_evidence 2>/dev/null)"
        runtime_status=$?
    elif [ "$chrony_state" -eq 2 ]; then
        set_result ERROR "Chrony 서비스 상태를 수집하지 못했습니다." "${config_facts}\nservice_state=error"
        return
    else
        service_state systemd-timesyncd.service >/dev/null 2>&1
        timesyncd_state=$?
    fi
    if [ -z "$provider" ] && [ "$timesyncd_state" -eq 0 ]; then
        provider="systemd-timesyncd"
        runtime_facts="$(timesyncd_runtime_evidence 2>/dev/null)"
        runtime_status=$?
    elif [ -z "$provider" ] && [ "$timesyncd_state" -eq 2 ]; then
        set_result ERROR "systemd-timesyncd 서비스 상태를 수집하지 못했습니다." "${config_facts}\nservice_state=error"
        return
    elif [ -z "$provider" ]; then
        set_result VULNERABLE \
            "활성화된 시각 동기화 서비스가 확인되지 않았습니다." \
            "${config_facts}\nruntime_provider=none"
        return
    fi

    if [ "$provider" = "chrony" ]; then
        time_service_persistence_state chronyd.service chrony.service
        persistence_status=$?
    else
        time_service_persistence_state systemd-timesyncd.service
        persistence_status=$?
    fi
    runtime_facts="${runtime_facts}\npersistent_activation_status=${persistence_status}"

    if [ "$persistence_status" -eq 2 ]; then
        set_result ERROR "시각 동기화 서비스의 부팅 지속 상태를 수집하지 못했습니다." "${runtime_facts}\n${config_facts}"
    elif [ "$runtime_status" -eq 0 ] && [ "$persistence_status" -ne 0 ]; then
        set_result MANUAL "현재 시각은 동기화됐지만 재부팅 후 서비스 활성화가 보장되지 않습니다." "${runtime_facts}\n${config_facts}"
    elif [ "$runtime_status" -eq 0 ] && { [ "$provider" != "chrony" ] || [ "$config_status" -eq 0 ]; }; then
        set_result GOOD \
            "시각 동기화 서비스와 실제 동기화 상태가 확인됐습니다." \
            "${runtime_facts}\n${config_facts}"
    elif [ "$runtime_status" -eq 0 ] && [ "$provider" = "chrony" ] && [ "$config_status" -eq 3 ]; then
        set_result MANUAL \
            "Chrony 런타임은 동기화됐지만 영구 소스가 동적 공급인지 확인해야 합니다." \
            "${runtime_facts}\npersistent_config_status=${config_status}\n${config_facts}"
    elif [ "$runtime_status" -eq 0 ] && [ "$provider" = "chrony" ]; then
        set_result ERROR \
            "Chrony 런타임은 동기화됐지만 영구 구성 그래프를 검증하지 못했습니다." \
            "${runtime_facts}\npersistent_config_status=${config_status}\n${config_facts}"
    elif [ "$runtime_status" -eq 127 ] || [ "$runtime_status" -eq 2 ]; then
        set_result ERROR \
            "시각 동기화 서비스는 활성 상태지만 런타임 상태를 수집하지 못했습니다." \
            "${runtime_facts}\n${config_facts}"
    else
        set_result VULNERABLE \
            "서비스는 활성 상태지만 동기화된 소스 또는 정상 상태를 확인하지 못했습니다." \
            "${runtime_facts}\n${config_facts}"
    fi
}

check_u_66() {
    local active_providers=""
    local journal_path=""
    local evidence=""
    local state=1
    local collection_errors=0

    if runtime_enabled; then
        service_state systemd-journald.service >/dev/null 2>&1
        state=$?
        [ "$state" -eq 0 ] && active_providers="journald"
        [ "$state" -eq 2 ] && collection_errors=$((collection_errors + 1))
        service_state rsyslog.service >/dev/null 2>&1
        state=$?
        if [ "$state" -eq 0 ]; then
            active_providers="${active_providers:+${active_providers},}rsyslog"
        fi
        [ "$state" -eq 2 ] && collection_errors=$((collection_errors + 1))
        service_state syslog-ng.service >/dev/null 2>&1
        state=$?
        if [ "$state" -eq 0 ]; then
            active_providers="${active_providers:+${active_providers},}syslog-ng"
        fi
        [ "$state" -eq 2 ] && collection_errors=$((collection_errors + 1))
    else
        [ -d "$(fs_path /var/log/journal)" ] && active_providers="journald-persistent-evidence"
        [ -r "$(fs_path /etc/rsyslog.conf)" ] && active_providers="${active_providers:+${active_providers},}rsyslog-config"
    fi

    journal_path="$(fs_path /var/log/journal)"
    if [ -d "$journal_path" ]; then
        evidence="persistent_journal_directory=/var/log/journal\n"
    else
        evidence="persistent_journal_directory=absent\n"
    fi
    evidence="${evidence}active_providers=${active_providers:-none}\n"
    evidence="${evidence}collection_errors=${collection_errors}\n"

    if [ "$collection_errors" -gt 0 ]; then
        set_result ERROR "시스템 로깅 공급자 상태 일부를 수집하지 못했습니다." "$evidence"
    elif runtime_enabled && [ -z "$active_providers" ]; then
        set_result VULNERABLE "활성화된 시스템 로깅 공급자가 없습니다." "$evidence"
    else
        set_result MANUAL \
            "로그 공급자는 확인했지만 조직의 기록·보존·전송 정책 충족 여부는 정책 증적이 필요합니다." \
            "$evidence"
    fi
}

check_u_67() {
    local log_directory=""
    local list_file=""
    local log_file=""
    local owner=""
    local mode=""
    local scanned=0
    local violations=0
    local evidence=""
    local directory_list_file=""
    local roots_file=""
    local scan_root=""
    local target=""
    local filesystem_type=""
    local findmnt_path=""
    local scan_errors=0
    local directory_violations=0
    local scanned_directories=0
    local mount_output=""
    local mount_status=0
    local excluded_mounts=0
    local stat_errors=0

    log_directory="$(fs_path /var/log 2>/dev/null || true)"
    log_directory="$(resolve_rooted_directory "$log_directory" 2>/dev/null || true)"
    [ -n "$log_directory" ] || {
        set_result ERROR "/var/log 디렉터리를 찾을 수 없습니다." "path=/var/log"
        return
    }

    list_file="$(new_scratch_file u67-files)" || {
        set_result ERROR "안전한 파일 목록을 만들 수 없습니다." "path=/var/log"
        return
    }
    directory_list_file="$(new_scratch_file u67-directories)" || {
        set_result ERROR "안전한 디렉터리 목록을 만들 수 없습니다." "path=/var/log"
        return
    }
    roots_file="$(new_scratch_file u67-roots)" || {
        set_result ERROR "안전한 마운트 목록을 만들 수 없습니다." "path=/var/log"
        return
    }
    printf '%s\n' "$log_directory" > "$roots_file"
    if runtime_enabled; then
        findmnt_path="$(trusted_command findmnt 2>/dev/null || true)"
        if [ -z "$findmnt_path" ]; then
            scan_errors=$((scan_errors + 1))
        else
            mount_output="$($findmnt_path -rn -o TARGET,FSTYPE 2>/dev/null)" || mount_status=$?
            [ "$mount_status" -eq 0 ] || scan_errors=$((scan_errors + 1))
            while read -r target filesystem_type; do
                case "$target" in /var/log/*) ;; *) continue ;; esac
                case "$filesystem_type" in
                    nfs|nfs4|cifs|smb3|fuse.*)
                        excluded_mounts=$((excluded_mounts + 1))
                        continue
                        ;;
                esac
                printf '%s\n' "$target" >> "$roots_file"
            done <<EOF
$mount_output
EOF
        fi
    fi

    : > "$list_file"
    : > "$directory_list_file"
    while IFS= read -r scan_root; do
        [ -d "$scan_root" ] || continue
        find -P "$scan_root" -xdev -type f -print0 >> "$list_file" 2>/dev/null || scan_errors=$((scan_errors + 1))
        find -P "$scan_root" -xdev -type d -print0 >> "$directory_list_file" 2>/dev/null || scan_errors=$((scan_errors + 1))
    done < <(LC_ALL=C sort -u "$roots_file")
    if [ "$scan_errors" -gt 0 ]; then
        set_result ERROR "로그 파일 전체 목록을 수집하지 못했습니다." "path=/var/log"
        return
    fi

    while IFS= read -r -d '' log_file; do
        scanned=$((scanned + 1))
        owner="$(stat_owner "$log_file" 2>/dev/null || true)"
        mode="$(stat_mode "$log_file" 2>/dev/null || true)"
        if [ -z "$owner" ] || [ -z "$mode" ]; then
            stat_errors=$((stat_errors + 1))
            [ "$stat_errors" -le 20 ] && evidence="${evidence}$(display_path "$log_file"):stat_error\n"
        elif [ "$owner" != "root" ] || ! mode_is_at_most "$mode" 644; then
            violations=$((violations + 1))
            [ "$violations" -le 20 ] && evidence="${evidence}$(display_path "$log_file"):owner=${owner},mode=${mode}\n"
        fi
    done < "$list_file"

    while IFS= read -r -d '' log_file; do
        scanned_directories=$((scanned_directories + 1))
        owner="$(stat_owner "$log_file" 2>/dev/null || true)"
        mode="$(stat_mode "$log_file" 2>/dev/null || true)"
        if [ -z "$owner" ] || [ -z "$mode" ]; then
            stat_errors=$((stat_errors + 1))
        elif [ "$owner" != "root" ] || mode_group_or_other_writable "$mode"; then
            directory_violations=$((directory_violations + 1))
        fi
    done < "$directory_list_file"

    evidence="scanned_files=${scanned}\nviolations=${violations}\nscanned_directories=${scanned_directories}\ndirectory_write_violations=${directory_violations}\nexcluded_network_mounts=${excluded_mounts}\nstat_errors=${stat_errors}\n${evidence}"
    if [ "$stat_errors" -gt 0 ]; then
        set_result ERROR "일부 로그 파일 또는 디렉터리의 메타데이터를 수집하지 못했습니다." "$evidence"
    elif [ "$violations" -gt 0 ]; then
        set_result VULNERABLE "/var/log에서 KISA 소유자·권한 기준을 벗어난 파일을 확인했습니다." "$evidence"
    elif [ "$scanned" -eq 0 ]; then
        set_result MANUAL "/var/log에서 일반 로그 파일을 찾지 못해 권한 기준을 확정할 수 없습니다." "$evidence"
    elif [ "$SCAN_ROOT" != "/" ]; then
        set_result MANUAL "오프라인 루트에서는 /var/log 하위 마운트 경계를 확인할 수 없습니다." "$evidence"
    elif [ "$directory_violations" -gt 0 ] || [ "$excluded_mounts" -gt 0 ]; then
        set_result MANUAL "로그 파일은 기준을 충족하지만 일부 로그 디렉터리의 소유자·쓰기 권한을 검토해야 합니다." "$evidence"
    else
        set_result GOOD "/var/log의 모든 일반 파일이 root 소유이며 0644 이하입니다." "$evidence"
    fi
}
