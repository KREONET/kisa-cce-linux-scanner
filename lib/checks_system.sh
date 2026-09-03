# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash

# shellcheck disable=SC2153

# Patch and logging checks cover U-64 through U-67.

check_u_64() {
    local evidence=""
    local path=""
    local physical_path=""
    local command_name=""
    local command_path=""
    local running_kernel=""

    evidence="platform_family=${PLATFORM_FAMILY:-unknown}\nplatform_base=${PLATFORM_BASE_ID:-unknown}:${PLATFORM_BASE_VERSION:-unknown}\n"

    if platform_is_debian_family; then
        evidence="${evidence}package_system=dpkg\n"
        for path in \
            /var/lib/dpkg/status \
            /var/lib/apt/periodic/update-success-stamp \
            /var/log/dpkg.log \
            /var/log/apt/history.log \
            /var/log/unattended-upgrades/unattended-upgrades.log; do
            physical_path="$(fs_path "$path" 2>/dev/null || true)"
            if [ -e "$physical_path" ]; then
                evidence="${evidence}local_metadata=${path},mtime=$(date -r "$physical_path" -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf unknown)\n"
            fi
        done
        if runtime_enabled; then
            command_path="$(trusted_command apt-get 2>/dev/null || true)"
            [ -n "$command_path" ] && evidence="${evidence}package_manager_command=apt-get\n"
        fi
    elif platform_is_rhel_family; then
        evidence="${evidence}package_system=rpm\n"
        for path in \
            /usr/lib/sysimage/rpm/rpmdb.sqlite \
            /var/lib/rpm/rpmdb.sqlite \
            /var/lib/rpm/Packages \
            /var/lib/dnf/history.sqlite \
            /var/log/dnf.log \
            /var/log/dnf.rpm.log \
            /var/log/yum.log; do
            physical_path="$(fs_path "$path" 2>/dev/null || true)"
            if [ -e "$physical_path" ]; then
                evidence="${evidence}local_metadata=${path},mtime=$(date -r "$physical_path" -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf unknown)\n"
            fi
        done
        if runtime_enabled; then
            for command_name in dnf5 dnf yum; do
                command_path="$(trusted_command "$command_name" 2>/dev/null || true)"
                if [ -n "$command_path" ]; then
                    evidence="${evidence}package_manager_command=${command_name}\n"
                    break
                fi
            done
        fi
    fi

    if runtime_enabled; then
        command_path="$(trusted_command uname 2>/dev/null || true)"
        if [ -n "$command_path" ]; then
            running_kernel="$($command_path -r 2>/dev/null || true)"
            [ -n "$running_kernel" ] && evidence="${evidence}running_kernel=${running_kernel}\n"
        fi
        [ -n "$running_kernel" ] || evidence="${evidence}running_kernel=unavailable\n"
    else
        evidence="${evidence}running_kernel=unavailable\n"
    fi

    set_result MANUAL \
        "로컬 패키지 이력만으로 EOL 여부와 최신 보안 패치 적용을 확정할 수 없어 조직 정책 및 벤더 권고와 대조해야 합니다." \
        "${evidence}metadata_is_compliance_proof=false\nnetwork_access=not_performed"
}

chrony_runtime_evidence() {
    local chronyc_path=""
    local tracking=""
    local sources=""
    local selected_count="0"
    local selected_reference_clocks="0"
    local leap_status=""

    chronyc_path="$(trusted_command chronyc)" || return 127
    tracking="$($chronyc_path -n tracking 2>/dev/null)" || return 2
    sources="$($chronyc_path -n sources 2>/dev/null)" || return 2
    leap_status="$(printf '%s\n' "$tracking" | awk -F: '/^Leap status/ {value=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); print value; exit}')"
    selected_count="$(printf '%s\n' "$sources" | awk '/^[[:space:]]*[\^=]\*/ {count++} END {print count+0}')"
    selected_reference_clocks="$(printf '%s\n' "$sources" | awk '/^[[:space:]]*#\*/ {count++} END {print count+0}')"

    printf 'provider=chrony\nleap_status=%s\nselected_sources=%s\nselected_reference_clocks=%s\n' \
        "$leap_status" "$selected_count" "$selected_reference_clocks"
    [ -n "$leap_status" ] || return 2
    [ "$leap_status" = "Normal" ] || return 1
    [ "$selected_count" -gt 0 ] && return 0
    [ "$selected_reference_clocks" -gt 0 ] && return 3
    return 1
}

timesyncd_runtime_evidence() {
    local timedatectl_path=""
    local synchronized=""
    local properties=""
    local server_name=""
    local server_address=""
    local packet_count=""
    local leap_indicator=""
    local system_servers=""
    local runtime_servers=""
    local fallback_servers=""
    local selected_source_origin="dynamic-or-unknown"

    timedatectl_path="$(trusted_command timedatectl)" || return 127
    synchronized="$($timedatectl_path show -p NTPSynchronized --value 2>/dev/null)" || return 2
    properties="$($timedatectl_path show-timesync --all --no-pager 2>/dev/null)" || return 2
    server_name="$(printf '%s\n' "$properties" | awk -F= '$1 == "ServerName" {print substr($0, index($0, "=") + 1); exit}')"
    server_address="$(printf '%s\n' "$properties" | awk -F= '$1 == "ServerAddress" {print substr($0, index($0, "=") + 1); exit}')"
    system_servers="$(printf '%s\n' "$properties" | awk -F= '$1 == "SystemNTPServers" {print substr($0, index($0, "=") + 1); exit}')"
    runtime_servers="$(printf '%s\n' "$properties" | awk -F= '$1 == "RuntimeNTPServers" {print substr($0, index($0, "=") + 1); exit}')"
    fallback_servers="$(printf '%s\n' "$properties" | awk -F= '$1 == "FallbackNTPServers" {print substr($0, index($0, "=") + 1); exit}')"
    packet_count="$(printf '%s\n' "$properties" | sed -n 's/^NTPMessage=.*PacketCount=\([0-9][0-9]*\).*/\1/p' | head -n 1)"
    leap_indicator="$(printf '%s\n' "$properties" | sed -n 's/^NTPMessage={[[:space:]]*Leap=\([0-9][0-9]*\).*/\1/p' | head -n 1)"

    if printf '%s\n' "$system_servers" | awk -v name="$server_name" -v address="$server_address" '
        {for (field=1; field<=NF; field++) if ($field == name || $field == address) found=1}
        END {exit found ? 0 : 1}
    '; then
        selected_source_origin="system"
    elif printf '%s\n' "$fallback_servers" | awk -v name="$server_name" -v address="$server_address" '
        {for (field=1; field<=NF; field++) if ($field == name || $field == address) found=1}
        END {exit found ? 0 : 1}
    '; then
        selected_source_origin="fallback"
    elif printf '%s\n' "$runtime_servers" | awk -v name="$server_name" -v address="$server_address" '
        {for (field=1; field<=NF; field++) if ($field == name || $field == address) found=1}
        END {exit found ? 0 : 1}
    '; then
        selected_source_origin="runtime"
    fi

    printf 'provider=systemd-timesyncd\nsynchronized=%s\nserver_name=%s\nserver_address=%s\npacket_count=%s\nleap_indicator=%s\nselected_source_origin=%s\n' \
        "$synchronized" "${server_name:-unavailable}" "${server_address:-unavailable}" \
        "${packet_count:-unavailable}" "${leap_indicator:-unavailable}" "$selected_source_origin"
    case "$synchronized" in
        no) return 1 ;;
        yes) ;;
        *) return 2 ;;
    esac
    case "$packet_count" in ''|*[!0-9]*) return 2 ;; esac
    case "$leap_indicator" in ''|*[!0-9]*) return 2 ;; esac
    case "${server_name}:${server_address}" in
        ':'|'n/a:'|':n/a'|'n/a:n/a') return 1 ;;
    esac
    [ "$packet_count" -gt 0 ] && [ "$leap_indicator" -eq 0 ]
}

ntpsec_runtime_evidence() {
    local ntpq_path=""
    local peers=""
    local selected_count="0"
    local selected_reference_clocks="0"

    ntpq_path="$(trusted_command ntpq)" || return 127
    peers="$($ntpq_path -pn 2>/dev/null)" || return 2
    selected_count="$(printf '%s\n' "$peers" | awk '/^[[:space:]]*\*/ {count++} END {print count+0}')"
    selected_reference_clocks="$(printf '%s\n' "$peers" | awk '/^[[:space:]]*o/ {count++} END {print count+0}')"

    printf 'provider=ntpsec\nselected_sources=%s\nselected_reference_clocks=%s\n' \
        "$selected_count" "$selected_reference_clocks"
    [ -n "$peers" ] || return 2
    [ "$selected_count" -gt 0 ] && return 0
    [ "$selected_reference_clocks" -gt 0 ] && return 3
    return 1
}

NTPSEC_OFFLINE_SOURCE_COUNT=0
NTPSEC_OFFLINE_RESOLUTION_ERROR=0
NTPSEC_OFFLINE_DISABLED=0

ntpsec_collect_offline_file() {
    local candidate="$1"
    local depth="${2:-0}"
    local active_stack="${3:-}"
    local resolved_file=""
    local recursion_key=""
    local line=""
    local directive=""
    local argument=""
    local include_candidate=""
    local resolved_directory=""
    local list_file=""
    local unsorted_file=""
    local included_file=""

    [ "$depth" -le 5 ] || { NTPSEC_OFFLINE_RESOLUTION_ERROR=1; return 2; }
    resolved_file="$(resolve_rooted_read_path "$candidate" 2>/dev/null || true)"
    [ -n "$resolved_file" ] || { NTPSEC_OFFLINE_RESOLUTION_ERROR=1; return 2; }
    recursion_key="$resolved_file"
    case $'\n'"$active_stack"$'\n' in
        *$'\n'"$recursion_key"$'\n'*)
            NTPSEC_OFFLINE_RESOLUTION_ERROR=1
            return 2
            ;;
    esac
    if [ -n "$active_stack" ]; then
        active_stack="${active_stack}"$'\n'"${recursion_key}"
    else
        active_stack="$recursion_key"
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        line="$(printf '%s\n' "$line" | sed -e 's/^[[:space:]]*//' -e 's/#.*$//')"
        case "$line" in ''|'#'*) continue ;; esac
        directive="$(printf '%s\n' "$line" | awk '{print tolower($1); exit}')"
        case "$directive" in
            server|pool|peer|refclock)
                argument="$(printf '%s\n' "$line" | awk '
                    ($2 == "-4" || $2 == "-6" || $2 == "--ipv4" || $2 == "--ipv6") && NF >= 3 {print $3; exit}
                    NF >= 2 {print $2; exit}
                ')"
                case "$argument" in
                    ''|-4|-6|--ipv4|--ipv6) NTPSEC_OFFLINE_RESOLUTION_ERROR=1 ;;
                    *)
                        if ! printf '%s\n' "$line" | grep -Eq '(^|[[:space:]])noselect([[:space:]]|$)'; then
                            NTPSEC_OFFLINE_SOURCE_COUNT=$((NTPSEC_OFFLINE_SOURCE_COUNT + 1))
                        fi
                        ;;
                esac
                ;;
            disable)
                printf '%s\n' "$line" | grep -Eq '(^|[[:space:]])ntp([[:space:]]|$)' && NTPSEC_OFFLINE_DISABLED=1
                ;;
            enable)
                printf '%s\n' "$line" | grep -Eq '(^|[[:space:]])ntp([[:space:]]|$)' && NTPSEC_OFFLINE_DISABLED=0
                ;;
            includefile)
                argument="$(printf '%s\n' "$line" | awk '{print $2; exit}')"
                case "$argument" in
                    \"*\") argument="${argument#\"}"; argument="${argument%\"}" ;;
                    \'*\') argument="${argument#\'}"; argument="${argument%\'}" ;;
                esac
                case "$argument" in
                    ''|*$'\n'*|*$'\r'*|*$'\t'*) NTPSEC_OFFLINE_RESOLUTION_ERROR=1; continue ;;
                    /*)
                        if [ "$SCAN_ROOT" = "/" ]; then
                            include_candidate="$argument"
                        else
                            include_candidate="${SCAN_ROOT%/}$argument"
                        fi
                        ;;
                    *) include_candidate="${resolved_file%/*}/$argument" ;;
                esac
                if [ -d "$include_candidate" ]; then
                    resolved_directory="$(resolve_rooted_directory "$include_candidate" 2>/dev/null || true)"
                    if [ -z "$resolved_directory" ]; then
                        NTPSEC_OFFLINE_RESOLUTION_ERROR=1
                        continue
                    fi
                    list_file="$(new_scratch_file ntpsec-include-directory)" || {
                        NTPSEC_OFFLINE_RESOLUTION_ERROR=1
                        continue
                    }
                    unsorted_file="$(new_scratch_file ntpsec-include-unsorted)" || {
                        NTPSEC_OFFLINE_RESOLUTION_ERROR=1
                        continue
                    }
                    find -P "$resolved_directory" -maxdepth 1 \( -type f -o -type l \) -name '*.conf' -print0 > "$unsorted_file" 2>/dev/null || {
                        NTPSEC_OFFLINE_RESOLUTION_ERROR=1
                        continue
                    }
                    LC_ALL=C sort -z "$unsorted_file" > "$list_file" || {
                        NTPSEC_OFFLINE_RESOLUTION_ERROR=1
                        continue
                    }
                    while IFS= read -r -d '' included_file; do
                        ntpsec_collect_offline_file "$included_file" $((depth + 1)) "$active_stack" || true
                    done < "$list_file"
                elif [ -f "$include_candidate" ] || [ -L "$include_candidate" ]; then
                    ntpsec_collect_offline_file "$include_candidate" $((depth + 1)) "$active_stack" || true
                else
                    NTPSEC_OFFLINE_RESOLUTION_ERROR=1
                fi
                ;;
        esac
    done < "$resolved_file"
}

ntpsec_config_evidence() {
    local logical_path=""
    local config_path=""
    local candidate_status=0
    local main_resolution_error=0
    local packaged_directory=""
    local resolved_directory=""
    local included_file=""
    local configuration_present=0
    local evidence_path=""
    local list_file=""
    local unsorted_file=""

    for logical_path in /etc/ntpsec/ntp.conf /etc/ntp.conf; do
        config_path="$(optional_rooted_read_path "$logical_path" 2>/dev/null)" || candidate_status=$?
        case "$candidate_status" in
            0)
                configuration_present=1
                evidence_path="$logical_path"
                break
                ;;
            1) config_path="" ;;
            *)
                configuration_present=1
                evidence_path="$logical_path"
                config_path=""
                main_resolution_error=1
                break
                ;;
        esac
        candidate_status=0
    done

    NTPSEC_OFFLINE_SOURCE_COUNT=0
    NTPSEC_OFFLINE_RESOLUTION_ERROR="$main_resolution_error"
    NTPSEC_OFFLINE_DISABLED=0
    if [ -n "$config_path" ]; then
        ntpsec_collect_offline_file "$config_path" 0 "" || true
    fi
    if platform_is_debian_family && { [ -z "$config_path" ] || [ "$evidence_path" = "/etc/ntpsec/ntp.conf" ]; }; then
        if [ "$SCAN_ROOT" = "/" ]; then
            packaged_directory="/etc/ntpsec/ntp.d"
        else
            packaged_directory="${SCAN_ROOT%/}/etc/ntpsec/ntp.d"
        fi
        if [ -e "$packaged_directory" ] || [ -L "$packaged_directory" ]; then
            configuration_present=1
            [ -n "$evidence_path" ] || evidence_path="/etc/ntpsec/ntp.d"
            resolved_directory="$(resolve_rooted_directory "$packaged_directory" 2>/dev/null || true)"
            if [ -z "$resolved_directory" ]; then
                NTPSEC_OFFLINE_RESOLUTION_ERROR=1
            else
                list_file="$(new_scratch_file ntpsec-automatic-directory)" || {
                    NTPSEC_OFFLINE_RESOLUTION_ERROR=1
                    list_file=""
                }
                unsorted_file="$(new_scratch_file ntpsec-automatic-unsorted)" || {
                    NTPSEC_OFFLINE_RESOLUTION_ERROR=1
                    unsorted_file=""
                }
                if [ -n "$list_file" ] && [ -n "$unsorted_file" ]; then
                    find -P "$resolved_directory" -maxdepth 1 \( -type f -o -type l \) -name '*.conf' -print0 > "$unsorted_file" 2>/dev/null ||
                        NTPSEC_OFFLINE_RESOLUTION_ERROR=1
                    LC_ALL=C sort -z "$unsorted_file" > "$list_file" || NTPSEC_OFFLINE_RESOLUTION_ERROR=1
                fi
                while IFS= read -r -d '' included_file; do
                    ntpsec_collect_offline_file "$included_file" 1 "" || true
                done < "${list_file:-/dev/null}"
            fi
        fi
    fi
    [ "$configuration_present" -eq 1 ] || return 1
    printf 'persistent_config=%s\nconfigured_sources=%s\nresolution_errors=%s\nntp_disabled=%s\n' \
        "$evidence_path" "$NTPSEC_OFFLINE_SOURCE_COUNT" "$NTPSEC_OFFLINE_RESOLUTION_ERROR" "$NTPSEC_OFFLINE_DISABLED"
    [ "$NTPSEC_OFFLINE_RESOLUTION_ERROR" -eq 0 ] || return 2
    [ "$NTPSEC_OFFLINE_SOURCE_COUNT" -gt 0 ] && [ "$NTPSEC_OFFLINE_DISABLED" -eq 0 ] || return 3
    return 0
}

CHRONY_OFFLINE_SOURCE_COUNT=0
CHRONY_OFFLINE_DYNAMIC_SOURCE_COUNT=0
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
    local resolved_source_file=""
    local directory_argument=""
    local candidate_file=""
    local candidate_basename=""
    local selection_file=""
    local tab=""
    local -a directory_arguments=()

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
                case "$(display_path "$resolved_file")" in
                    /run/*) CHRONY_OFFLINE_DYNAMIC_SOURCE_COUNT=$((CHRONY_OFFLINE_DYNAMIC_SOURCE_COUNT + 1)) ;;
                    *) CHRONY_OFFLINE_SOURCE_COUNT=$((CHRONY_OFFLINE_SOURCE_COUNT + 1)) ;;
                esac
                ;;
            include)
                [ -n "$argument" ] || { CHRONY_OFFLINE_RESOLUTION_ERROR=1; continue; }
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
                find -P "$resolved_directory" -maxdepth 1 \( -type f -o -type l \) -name "$include_pattern" -print0 > "$list_file" 2>/dev/null || { CHRONY_OFFLINE_RESOLUTION_ERROR=1; continue; }
                [ -s "$list_file" ] || { CHRONY_OFFLINE_RESOLUTION_ERROR=1; continue; }
                while IFS= read -r -d '' included_file; do
                    chrony_collect_offline_file "$included_file" "$visited_file" $((depth + 1)) || true
                done < "$list_file"
                ;;
            confdir|sourcedir)
                [ -n "$argument" ] || { CHRONY_OFFLINE_RESOLUTION_ERROR=1; continue; }
                read -r -a directory_arguments <<< "$argument"
                [ "${#directory_arguments[@]}" -le 10 ] || { CHRONY_OFFLINE_RESOLUTION_ERROR=1; continue; }
                selection_file="$(new_scratch_file chrony-directory-selection)" || { CHRONY_OFFLINE_RESOLUTION_ERROR=1; continue; }
                : > "$selection_file"
                for directory_argument in "${directory_arguments[@]}"; do
                    case "$directory_argument" in
                        /*)
                            if [ "$SCAN_ROOT" = "/" ]; then
                                resolved_directory="$directory_argument"
                            else
                                resolved_directory="${SCAN_ROOT%/}$directory_argument"
                            fi
                            ;;
                        *) resolved_directory="${resolved_file%/*}/$directory_argument" ;;
                    esac
                    if [ ! -e "$resolved_directory" ] && [ ! -L "$resolved_directory" ]; then
                        continue
                    fi
                    resolved_directory="$(resolve_rooted_directory "$resolved_directory" 2>/dev/null || true)"
                    if [ -z "$resolved_directory" ]; then
                        CHRONY_OFFLINE_RESOLUTION_ERROR=1
                        continue
                    fi
                    candidate_file="$(new_scratch_file chrony-directory-candidates)" || {
                        CHRONY_OFFLINE_RESOLUTION_ERROR=1
                        continue
                    }
                    if [ "$directive" = "confdir" ]; then
                        find -P "$resolved_directory" -maxdepth 1 \( -type f -o -type l \) -name '*.conf' -print0 > "$candidate_file" 2>/dev/null || {
                            CHRONY_OFFLINE_RESOLUTION_ERROR=1
                            continue
                        }
                    else
                        find -P "$resolved_directory" -maxdepth 1 \( -type f -o -type l \) -name '*.sources' -print0 > "$candidate_file" 2>/dev/null || {
                            CHRONY_OFFLINE_RESOLUTION_ERROR=1
                            continue
                        }
                    fi
                    while IFS= read -r -d '' included_file; do
                        candidate_basename="${included_file##*/}"
                        case "$candidate_basename:$included_file" in
                            *$'\n'*|*$'\r'*|*$'\t'*) CHRONY_OFFLINE_RESOLUTION_ERROR=1; continue ;;
                        esac
                        if ! awk -F '\t' -v name="$candidate_basename" '$1 == name {found=1} END {exit found ? 0 : 1}' "$selection_file"; then
                            printf '%s\t%s\n' "$candidate_basename" "$included_file" >> "$selection_file" ||
                                CHRONY_OFFLINE_RESOLUTION_ERROR=1
                        fi
                    done < "$candidate_file"
                done
                list_file="$(new_scratch_file chrony-directory)" || { CHRONY_OFFLINE_RESOLUTION_ERROR=1; continue; }
                tab="$(printf '\t')"
                LC_ALL=C sort -t "$tab" -k1,1 "$selection_file" > "$list_file" || { CHRONY_OFFLINE_RESOLUTION_ERROR=1; continue; }
                if [ "$directive" = "confdir" ]; then
                    while IFS="$tab" read -r candidate_basename included_file; do
                        [ -n "$included_file" ] || continue
                        chrony_collect_offline_file "$included_file" "$visited_file" $((depth + 1)) || true
                    done < "$list_file"
                else
                    while IFS="$tab" read -r candidate_basename included_file; do
                        [ -n "$included_file" ] || continue
                        resolved_source_file="$(resolve_rooted_read_path "$included_file" 2>/dev/null || true)"
                        if [ -z "$resolved_source_file" ]; then
                            CHRONY_OFFLINE_RESOLUTION_ERROR=1
                            continue
                        fi
                        CHRONY_OFFLINE_DYNAMIC_SOURCE_COUNT=$((CHRONY_OFFLINE_DYNAMIC_SOURCE_COUNT + $(awk '
                            {
                                line=$0
                                sub(/^[[:space:]]+/, "", line)
                                if (line == "" || line ~ /^#/) next
                                sub(/[[:space:]]+#.*$/, "", line)
                                field_count=split(line, fields, /[[:space:]]+/)
                                if (tolower(fields[1]) !~ /^(server|pool|peer)$/ || field_count < 2) next
                                selectable=1
                                for (field=3; field<=field_count; field++) {
                                    if (tolower(fields[field]) == "noselect") selectable=0
                                }
                                if (selectable) count++
                            }
                            END {print count+0}
                        ' "$resolved_source_file")))
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
            field_count=split(line, fields, /[[:space:]]+/)
            directive=tolower(fields[1])
            if (directive ~ /^(server|pool|peer)$/) {
                selectable=1
                for (field=3; field<=field_count; field++) {
                    if (tolower(fields[field]) == "noselect") selectable=0
                }
                if (selectable && fields[2] != "") print directive "\t" fields[2]
            } else if (directive ~ /^(include|confdir|sourcedir)$/) {
                argument=""
                if (field_count >= 2) {
                    argument=line
                    sub(/^[^[:space:]]+[[:space:]]+/, "", argument)
                }
                print directive "\t" argument
            }
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
    local saw_loaded_unit=0

    systemctl_path="$(trusted_command systemctl)" || return 2
    for unit in "$@"; do
        if [ "${SCAN_EPOCH_ACTIVE:-0}" -eq 1 ]; then
            systemd_epoch_properties_into "$unit" properties || return 2
            command_status="$SYSTEMD_PROPERTIES_COMMAND_STATUS"
            systemd_fact_value_into "$properties" LoadState load_state || load_state=""
            systemd_fact_value_into "$properties" UnitFileState unit_file_state || unit_file_state=""
        else
            properties="$($systemctl_path show "$unit" -p LoadState -p UnitFileState --no-pager 2>/dev/null)" || command_status=$?
            load_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "LoadState" {print $2; exit}')"
            unit_file_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "UnitFileState" {print $2; exit}')"
        fi
        if [ "$command_status" -ne 0 ] && [ "$load_state" != "not-found" ]; then
            return 2
        fi
        command_status=0
        [ "$load_state" != "not-found" ] || continue
        [ -n "$load_state" ] || continue
        saw_loaded_unit=1
        case "$unit_file_state" in
            enabled) return 0 ;;
            alias|'') ;;
            enabled-runtime|static|indirect|generated|linked|linked-runtime|masked|masked-runtime|disabled) ;;
            *) ;;
        esac
    done
    [ "$saw_loaded_unit" -eq 1 ] && return 1
    return 2
}

chrony_config_evidence() {
    local chronyd_path=""
    local logical_config_path=""
    local config_path=""
    local config_status=0
    local output=""
    local source_count="0"
    local native_source_count="unavailable"
    local visited_file=""

    if platform_is_debian_family; then
        logical_config_path="/etc/chrony/chrony.conf"
    elif platform_is_rhel_family; then
        logical_config_path="/etc/chrony.conf"
    else
        return 2
    fi

    config_path="$(optional_rooted_read_path "$logical_config_path" 2>/dev/null)" || config_status=$?
    case "$config_status" in
        0) ;;
        1) return 1 ;;
        *) return 2 ;;
    esac

    if runtime_enabled; then
        chronyd_path="$(trusted_command chronyd 2>/dev/null || true)"
        [ -n "$chronyd_path" ] || return 2
        output="$($chronyd_path -p -f "$config_path" 2>/dev/null)" || {
            printf 'persistent_config=invalid\n'
            return 2
        }
        native_source_count="$(printf '%s\n' "$output" | awk '
            tolower($1) == "server" || tolower($1) == "pool" || tolower($1) == "peer" {
                selectable=1
                for (field=3; field<=NF; field++) if (tolower($field) == "noselect") selectable=0
                if (selectable) count++
            }
            END {print count+0}
        ')"
    fi

    visited_file="$(new_scratch_file chrony-visited)" || return 2
    CHRONY_OFFLINE_SOURCE_COUNT=0
    CHRONY_OFFLINE_DYNAMIC_SOURCE_COUNT=0
    CHRONY_OFFLINE_RESOLUTION_ERROR=0
    chrony_collect_offline_file "$config_path" "$visited_file" 0 || true
    source_count="$CHRONY_OFFLINE_SOURCE_COUNT"
    printf 'persistent_config=%s\nconfigured_sources=%s\ndynamic_sources=%s\nnative_configured_sources=%s\nresolution_errors=%s\n' \
        "$(display_path "$config_path")" "$source_count" "$CHRONY_OFFLINE_DYNAMIC_SOURCE_COUNT" \
        "$native_source_count" "$CHRONY_OFFLINE_RESOLUTION_ERROR"
    [ "$CHRONY_OFFLINE_RESOLUTION_ERROR" -eq 0 ] || return 2
    if [ "$native_source_count" != "unavailable" ] && [ "$native_source_count" -eq 0 ]; then
        return 3
    fi
    [ "$source_count" -gt 0 ] || return 3
    return 0
}

check_u_65() {
    local runtime_facts=""
    local runtime_status=1
    local config_facts=""
    local config_status=1
    local chrony_config_facts=""
    local chrony_config_status=1
    local ntpsec_config_facts=""
    local ntpsec_config_status=1
    local chrony_state=1
    local ntpsec_state=1
    local timesyncd_state=1
    local active_provider_count=0
    local persistence_status=2
    local provider=""
    local expected_provider="ntpd"
    local provider_scope="validated"
    local base_major=""
    local path=""
    local physical_path=""
    local offline_facts=""

    if platform_is_rhel_family; then
        base_major="$(platform_base_major 2>/dev/null || true)"
        if [ -z "$base_major" ]; then
            set_result ERROR "Enterprise Linux 기반 버전을 확인하지 못했습니다." \
                "platform_base=${PLATFORM_BASE_ID:-unknown}:${PLATFORM_BASE_VERSION:-unknown}"
            return
        fi
        if [ "$base_major" -ge 8 ]; then
            expected_provider="chrony"
        fi
    elif ! platform_is_debian_family; then
        set_result MANUAL "지원되지 않은 플랫폼에서는 시각 동기화 구현을 수동 검증해야 합니다." \
            "platform_family=${PLATFORM_FAMILY:-unknown}"
        return
    fi

    if ! runtime_enabled; then
        chrony_config_facts="$(chrony_config_evidence 2>/dev/null)"
        chrony_config_status=$?
        ntpsec_config_facts="$(ntpsec_config_evidence 2>/dev/null)"
        ntpsec_config_status=$?
        for path in /etc/systemd/timesyncd.conf /etc/systemd/timesyncd.conf.d; do
            physical_path="$(fs_path "$path" 2>/dev/null || true)"
            [ -e "$physical_path" ] && offline_facts="${offline_facts}timesyncd_configuration_evidence=${path}\n"
        done
        set_result MANUAL \
            "오프라인 루트에서는 실제 시각 동기화 상태를 확정할 수 없습니다." \
            "expected_provider=${expected_provider}\nchrony_config_status=${chrony_config_status}\n${chrony_config_facts}\nntpsec_config_status=${ntpsec_config_status}\n${ntpsec_config_facts}\n${offline_facts}"
        return
    fi

    service_state chronyd.service chrony.service >/dev/null 2>&1
    chrony_state=$?
    service_state ntpsec.service ntp.service ntpd.service >/dev/null 2>&1
    ntpsec_state=$?
    service_state systemd-timesyncd.service >/dev/null 2>&1
    timesyncd_state=$?

    if [ "$chrony_state" -eq 2 ] || [ "$ntpsec_state" -eq 2 ] || [ "$timesyncd_state" -eq 2 ]; then
        set_result ERROR "시각 동기화 서비스 상태를 수집하지 못했습니다." \
            "chrony_state=${chrony_state}\nntpsec_state=${ntpsec_state}\ntimesyncd_state=${timesyncd_state}"
        return
    fi
    [ "$chrony_state" -eq 0 ] && active_provider_count=$((active_provider_count + 1))
    [ "$ntpsec_state" -eq 0 ] && active_provider_count=$((active_provider_count + 1))
    [ "$timesyncd_state" -eq 0 ] && active_provider_count=$((active_provider_count + 1))
    if [ "$active_provider_count" -gt 1 ]; then
        set_result MANUAL "여러 시각 동기화 서비스가 동시에 활성화되어 실제 공급자를 확인해야 합니다." \
            "chrony_state=${chrony_state}\nntpsec_state=${ntpsec_state}\ntimesyncd_state=${timesyncd_state}"
        return
    elif [ "$active_provider_count" -eq 0 ]; then
        set_result VULNERABLE \
            "활성화된 시각 동기화 서비스가 확인되지 않았습니다." \
            "runtime_provider=none"
        return
    fi

    if [ "$chrony_state" -eq 0 ]; then
        provider="chrony"
        runtime_facts="$(chrony_runtime_evidence 2>/dev/null)"
        runtime_status=$?
        config_facts="$(chrony_config_evidence 2>/dev/null)"
        config_status=$?
        time_service_persistence_state chronyd.service chrony.service
        persistence_status=$?
    elif [ "$ntpsec_state" -eq 0 ]; then
        provider="ntpsec"
        runtime_facts="$(ntpsec_runtime_evidence 2>/dev/null)"
        runtime_status=$?
        config_facts="$(ntpsec_config_evidence 2>/dev/null)"
        config_status=$?
        time_service_persistence_state ntpsec.service ntp.service ntpd.service
        persistence_status=$?
    else
        provider="systemd-timesyncd"
        runtime_facts="$(timesyncd_runtime_evidence 2>/dev/null)"
        runtime_status=$?
        config_facts="effective_source_probe=timedatectl-show-timesync"
        if [ "$runtime_status" -eq 0 ]; then
            if printf '%s\n' "$runtime_facts" | grep -Eq '^selected_source_origin=system$'; then
                config_status=0
            else
                config_status=3
            fi
        fi
        time_service_persistence_state systemd-timesyncd.service
        persistence_status=$?
    fi
    if [ "$expected_provider" = "chrony" ] && [ "$provider" != "chrony" ]; then
        provider_scope="operational-extension"
    elif [ "$expected_provider" = "ntpd" ] && { [ "$provider" = "chrony" ] || [ "$provider" = "systemd-timesyncd" ]; }; then
        provider_scope="operational-extension"
    elif [ "$expected_provider" = "ntpd" ] && [ "$provider" = "ntpsec" ]; then
        provider_scope="validated-extension"
    fi
    runtime_facts="expected_provider=${expected_provider}\nactive_provider=${provider}\nprovider_scope=${provider_scope}\n${runtime_facts}\npersistent_activation_status=${persistence_status}\napproved_source_evidence=unavailable"

    if [ "$runtime_status" -eq 127 ] || [ "$runtime_status" -eq 2 ]; then
        set_result ERROR \
            "시각 동기화 서비스는 활성 상태지만 공급자별 런타임 상태를 수집하지 못했습니다." \
            "${runtime_facts}\n${config_facts}"
    elif [ "$runtime_status" -eq 3 ]; then
        set_result MANUAL \
            "시각은 동기화됐지만 KISA의 NTP 서버 절차가 아닌 로컬 기준 시계를 사용하므로 적합성 검토가 필요합니다." \
            "${runtime_facts}\n${config_facts}"
    elif [ "$runtime_status" -ne 0 ]; then
        set_result VULNERABLE \
            "서비스는 활성 상태지만 동기화된 소스 또는 정상 상태를 확인하지 못했습니다." \
            "${runtime_facts}\n${config_facts}"
    elif [ "$provider_scope" = "operational-extension" ]; then
        set_result MANUAL \
            "현재 시각은 동기화됐지만 이 플랫폼의 KISA 절차에 명시되지 않은 공급자이므로 정책 승인이 필요합니다." \
            "${runtime_facts}\npersistent_config_status=${config_status}\n${config_facts}"
    elif [ "$persistence_status" -eq 2 ]; then
        set_result ERROR "시각 동기화 서비스의 부팅 지속 상태를 수집하지 못했습니다." "${runtime_facts}\n${config_facts}"
    elif [ "$persistence_status" -ne 0 ]; then
        set_result MANUAL "현재 시각은 동기화됐지만 재부팅 후 서비스 활성화가 보장되지 않습니다." "${runtime_facts}\n${config_facts}"
    elif [ "$config_status" -eq 0 ]; then
        set_result MANUAL \
            "시각 동기화와 영구 구성은 확인됐지만 NTP 소스의 조직 승인 증적을 대조해야 합니다." \
            "${runtime_facts}\n${config_facts}"
    elif [ "$config_status" -eq 3 ]; then
        set_result MANUAL \
            "런타임은 동기화됐지만 영구 소스가 동적 공급인지 확인해야 합니다." \
            "${runtime_facts}\npersistent_config_status=${config_status}\n${config_facts}"
    elif [ "$config_status" -eq 1 ]; then
        set_result MANUAL \
            "런타임은 동기화됐지만 기본 위치에서 영구 구성을 찾지 못했습니다." \
            "${runtime_facts}\npersistent_config_status=${config_status}\n${config_facts}"
    else
        set_result ERROR \
            "시각 동기화 런타임은 정상이지만 영구 구성 그래프를 검증하지 못했습니다." \
            "${runtime_facts}\npersistent_config_status=${config_status}\n${config_facts}"
    fi
}

logging_expected_destinations() {
    if platform_is_debian_family; then
        printf 'system\t/var/log/syslog\nauthentication\t/var/log/auth.log\nmail\t/var/log/mail.log\nscheduler\t/var/log/cron.log\n'
    elif platform_is_rhel_family; then
        printf 'system\t/var/log/messages\nauthentication\t/var/log/secure\nmail\t/var/log/maillog\nscheduler\t/var/log/cron\n'
    else
        return 1
    fi
}

rsyslog_configuration_evidence() {
    local main_file=""
    local resolved_file=""
    local include_directory=""
    local included_file=""
    local list_file=""
    local configuration_text=""
    local standard_include=0
    local complex_include=0
    local configuration_files=0
    local resolution_errors=0
    local role=""
    local logical_path=""
    local physical_path=""
    local configured=0
    local present=0
    local main_status=0

    list_file="$(new_scratch_file u66-rsyslog-files)" || return 2
    main_file="$(optional_rooted_read_path /etc/rsyslog.conf 2>/dev/null)" || main_status=$?
    if [ "$main_status" -eq 0 ]; then
        printf '%s\0' "$main_file" >> "$list_file"
        resolved_file="$main_file"
        if awk '
                {
                    line=$0
                    sub(/^[[:space:]]+/, "", line)
                    if (line == "" || line ~ /^#/) next
                    if (line ~ /^\$IncludeConfig[[:space:]]+/ || line ~ /^include[[:space:]]*\(/) print line
                }
            ' "$resolved_file" | grep -Fq '/etc/rsyslog.d/*.conf'; then
            standard_include=1
        fi
        if awk '
                {
                    line=$0
                    sub(/^[[:space:]]+/, "", line)
                    if (line == "" || line ~ /^#/) next
                    if (line ~ /^\$IncludeConfig[[:space:]]+/ || line ~ /^include[[:space:]]*\(/) print line
                }
            ' "$resolved_file" | grep -Fv '/etc/rsyslog.d/*.conf' | grep -q .; then
            complex_include=1
        fi
    elif [ "$main_status" -ne 1 ]; then
        resolution_errors=$((resolution_errors + 1))
    fi

    if [ "$SCAN_ROOT" = "/" ]; then
        include_directory="/etc/rsyslog.d"
    else
        include_directory="${SCAN_ROOT%/}/etc/rsyslog.d"
    fi
    if [ "$standard_include" -eq 1 ] && { [ -e "$include_directory" ] || [ -L "$include_directory" ]; }; then
        include_directory="$(resolve_rooted_directory "$include_directory" 2>/dev/null || true)"
        if [ -z "$include_directory" ]; then
            resolution_errors=$((resolution_errors + 1))
        else
            find -P "$include_directory" -maxdepth 1 \( -type f -o -type l \) -name '*.conf' -print0 >> "$list_file" 2>/dev/null ||
                resolution_errors=$((resolution_errors + 1))
        fi
    fi

    while IFS= read -r -d '' included_file; do
        resolved_file="$(resolve_rooted_read_path "$included_file" 2>/dev/null || true)"
        if [ -z "$resolved_file" ]; then
            resolution_errors=$((resolution_errors + 1))
            continue
        fi
        configuration_files=$((configuration_files + 1))
        configuration_text="${configuration_text}
$(awk '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                print line
            }
        ' "$resolved_file")"
    done < "$list_file"

    printf 'rsyslog_configuration_files=%s\nstandard_include=%s\ncomplex_include=%s\nresolution_errors=%s\n' \
        "$configuration_files" "$standard_include" "$complex_include" "$resolution_errors"
    while IFS="$(printf '\t')" read -r role logical_path; do
        [ -n "$role" ] || continue
        configured=0
        present=0
        printf '%s\n' "$configuration_text" | grep -Fq -- "$logical_path" && configured=1
        physical_path="$(fs_path "$logical_path" 2>/dev/null || true)"
        [ -e "$physical_path" ] && present=1
        printf 'expected_%s_log=%s\nconfigured_%s_destination=%s\npresent_%s_log=%s\n' \
            "$role" "$logical_path" "$role" "$configured" "$role" "$present"
    done < <(logging_expected_destinations 2>/dev/null || true)

    [ "$resolution_errors" -eq 0 ] || return 2
    [ "$configuration_files" -gt 0 ] || return 1
    return 0
}

check_u_66() {
    local active_providers=""
    local journal_path=""
    local volatile_journal_path=""
    local evidence=""
    local collection_errors=0
    local journald_state=3
    local rsyslog_state=3
    local syslog_ng_state=3
    local rsyslog_facts=""
    local rsyslog_config_status=1
    local rsyslog_validation_status="not-run"
    local rsyslogd_path=""
    local rsyslog_main_file=""

    if runtime_snapshot_available; then
        service_state systemd-journald.service >/dev/null 2>&1
        journald_state=$?
        [ "$journald_state" -eq 0 ] && active_providers="journald"
        [ "$journald_state" -eq 2 ] && collection_errors=$((collection_errors + 1))
        service_state rsyslog.service >/dev/null 2>&1
        rsyslog_state=$?
        if [ "$rsyslog_state" -eq 0 ]; then
            active_providers="${active_providers:+${active_providers},}rsyslog"
        fi
        [ "$rsyslog_state" -eq 2 ] && collection_errors=$((collection_errors + 1))
        service_state syslog-ng.service >/dev/null 2>&1
        syslog_ng_state=$?
        if [ "$syslog_ng_state" -eq 0 ]; then
            active_providers="${active_providers:+${active_providers},}syslog-ng"
        fi
        [ "$syslog_ng_state" -eq 2 ] && collection_errors=$((collection_errors + 1))
    else
        [ -d "$(fs_path /var/log/journal)" ] && active_providers="journald-persistent-evidence"
        [ -r "$(fs_path /etc/rsyslog.conf)" ] && active_providers="${active_providers:+${active_providers},}rsyslog-config"
    fi

    rsyslog_facts="$(rsyslog_configuration_evidence 2>/dev/null)"
    rsyslog_config_status=$?
    if runtime_enabled && [ "$rsyslog_state" -eq 0 ]; then
        rsyslogd_path="$(trusted_command rsyslogd 2>/dev/null || true)"
        rsyslog_main_file="$(fs_path /etc/rsyslog.conf 2>/dev/null || true)"
        if [ -n "$rsyslogd_path" ] && [ -r "$rsyslog_main_file" ]; then
            if "$rsyslogd_path" -N1 -f "$rsyslog_main_file" >/dev/null 2>&1; then
                rsyslog_validation_status="valid"
            else
                rsyslog_validation_status="invalid"
            fi
        else
            rsyslog_validation_status="unavailable"
        fi
    fi

    journal_path="$(fs_path /var/log/journal)"
    volatile_journal_path="$(fs_path /run/log/journal)"
    if [ -d "$journal_path" ]; then
        evidence="persistent_journal_directory=/var/log/journal\n"
    else
        evidence="persistent_journal_directory=absent\n"
    fi
    if [ -d "$volatile_journal_path" ]; then
        evidence="${evidence}volatile_journal_directory=/run/log/journal\n"
    else
        evidence="${evidence}volatile_journal_directory=absent\n"
    fi
    evidence="${evidence}active_providers=${active_providers:-none}\n"
    evidence="${evidence}collection_errors=${collection_errors}\n"
    evidence="${evidence}logging_path_profile=${PLATFORM_FAMILY:-unknown}\nrsyslog_config_status=${rsyslog_config_status}\nrsyslog_native_validation=${rsyslog_validation_status}\n${rsyslog_facts}"

    if [ "$collection_errors" -gt 0 ]; then
        set_result ERROR "시스템 로깅 공급자 상태 일부를 수집하지 못했습니다." "$evidence"
    elif [ "$rsyslog_config_status" -eq 2 ]; then
        set_result ERROR "rsyslog 구성 그래프 일부를 안전하게 해석하지 못했습니다." "$evidence"
    elif runtime_enabled && [ -z "$active_providers" ]; then
        set_result VULNERABLE "활성화된 시스템 로깅 공급자가 없습니다." "$evidence"
    else
        set_result MANUAL \
            "배포판별 로그 공급자와 경로는 확인했지만 기록·보존·전송 범위가 조직 정책을 충족하는지는 정책 증적이 필요합니다." \
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
    local symlink_list_file=""
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
    local mount_inventory_file=""
    local bundle_mount_inventory=0
    local excluded_mounts=0
    local stat_errors=0
    local symlinks=0
    local symlink_targets_scanned=0
    local external_symlink_targets=0
    local symlink_directories=0
    local unresolved_symlinks=0
    local resolved_target=""
    local role=""
    local logical_path=""
    local physical_path=""
    local expected_logs_present=0
    local expected_logs_absent=0
    local record_type=""

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
    symlink_list_file="$(new_scratch_file u67-symlinks)" || {
        set_result ERROR "안전한 심볼릭 링크 목록을 만들 수 없습니다." "path=/var/log"
        return
    }
    roots_file="$(new_scratch_file u67-roots)" || {
        set_result ERROR "안전한 마운트 목록을 만들 수 없습니다." "path=/var/log"
        return
    }
    printf '%s\n' "$log_directory" > "$roots_file"
    if [ "${EVIDENCE_BUNDLE_ACTIVE:-0}" -eq 1 ] && declare -F evidence_mount_roots >/dev/null 2>&1; then
        mount_inventory_file="$(new_scratch_file u67-bundle-mounts)" || {
            set_result ERROR "증적 bundle의 마운트 목록을 저장하지 못했습니다." "path=/var/log"
            return
        }
        evidence_mount_roots > "$mount_inventory_file" || mount_status=$?
        if [ "$mount_status" -ne 0 ]; then
            scan_errors=$((scan_errors + 1))
        else
            bundle_mount_inventory=1
            while IFS=$'\t' read -r target filesystem_type; do
                case "$target" in /var/log/*) ;; *) continue ;; esac
                case "$filesystem_type" in
                    nfs|nfs4|cifs|smb3|fuse|fuse.*|sshfs)
                        excluded_mounts=$((excluded_mounts + 1))
                        continue
                        ;;
                esac
                target="$(fs_path "$target" 2>/dev/null || true)"
                target="$(resolve_rooted_directory "$target" 2>/dev/null || true)"
                if [ -z "$target" ]; then
                    scan_errors=$((scan_errors + 1))
                    continue
                fi
                printf '%s\n' "$target" >> "$roots_file"
            done < "$mount_inventory_file"
        fi
    elif [ "$SCAN_ROOT" = "/" ]; then
        findmnt_path="$(trusted_findmnt_command 2>/dev/null || true)"
        if [ -z "$findmnt_path" ]; then
            scan_errors=$((scan_errors + 1))
        else
            mount_output="$($findmnt_path -rn -o TARGET,FSTYPE 2>/dev/null)" || mount_status=$?
            [ "$mount_status" -eq 0 ] || scan_errors=$((scan_errors + 1))
            while read -r target filesystem_type; do
                case "$target" in /var/log/*) ;; *) continue ;; esac
                case "$target" in *\\*) scan_errors=$((scan_errors + 1)); continue ;; esac
                case "$filesystem_type" in
                    nfs|nfs4|cifs|smb3|fuse|fuse.*|sshfs)
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
    : > "$symlink_list_file"
    while IFS= read -r scan_root; do
        [ -d "$scan_root" ] || continue
        find -P "$scan_root" -xdev \
            \( \
                \( -type f -printf 'F\0%p\0%u\0%m\0' \) , \
                \( -type d -printf 'D\0%p\0%u\0%m\0' \) , \
                \( -type l -printf 'L\0%p\0' \) \
            \) >> "$list_file" 2>/dev/null || scan_errors=$((scan_errors + 1))
    done < <(LC_ALL=C sort -u "$roots_file")
    if [ "$scan_errors" -gt 0 ]; then
        set_result ERROR "로그 파일 전체 목록을 수집하지 못했습니다." "path=/var/log"
        return
    fi

    while IFS= read -r -d '' record_type; do
        case "$record_type" in
            F|D)
                IFS= read -r -d '' log_file || { scan_errors=$((scan_errors + 1)); break; }
                IFS= read -r -d '' owner || { scan_errors=$((scan_errors + 1)); break; }
                IFS= read -r -d '' mode || { scan_errors=$((scan_errors + 1)); break; }
                ;;
            L)
                IFS= read -r -d '' log_file || { scan_errors=$((scan_errors + 1)); break; }
                ;;
            *)
                scan_errors=$((scan_errors + 1))
                break
                ;;
        esac

        case "$record_type" in
            F)
                scanned=$((scanned + 1))
                if [ -z "$owner" ] || [ -z "$mode" ]; then
                    stat_errors=$((stat_errors + 1))
                    [ "$stat_errors" -le 20 ] && evidence="${evidence}$(display_path "$log_file"):stat_error\n"
                elif [ "$owner" != "root" ] || ! mode_is_at_most "$mode" 644; then
                    violations=$((violations + 1))
                    [ "$violations" -le 20 ] && evidence="${evidence}$(display_path "$log_file"):owner=${owner},mode=${mode}\n"
                fi
                ;;
            D)
                printf '%s\0%s\0%s\0' "$log_file" "$owner" "$mode" >> "$directory_list_file" ||
                    scan_errors=$((scan_errors + 1))
                ;;
            L)
                printf '%s\0' "$log_file" >> "$symlink_list_file" ||
                    scan_errors=$((scan_errors + 1))
                ;;
        esac
    done < "$list_file"
    if [ -n "$record_type" ]; then
        scan_errors=$((scan_errors + 1))
    fi
    if [ "$scan_errors" -gt 0 ]; then
        set_result ERROR "로그 파일 전체 목록을 수집하지 못했습니다." "path=/var/log"
        return
    fi

    while IFS= read -r -d '' log_file &&
        IFS= read -r -d '' owner &&
        IFS= read -r -d '' mode; do
        scanned_directories=$((scanned_directories + 1))
        if [ -z "$owner" ] || [ -z "$mode" ]; then
            stat_errors=$((stat_errors + 1))
        elif [ "$owner" != "root" ] || mode_group_or_other_writable "$mode"; then
            directory_violations=$((directory_violations + 1))
        fi
    done < "$directory_list_file"

    while IFS= read -r -d '' log_file; do
        symlinks=$((symlinks + 1))
        resolved_target="$(resolve_rooted_read_path "$log_file" 2>/dev/null || true)"
        if [ -n "$resolved_target" ]; then
            case "$resolved_target" in
                "$log_directory"/*) ;;
                *)
                    external_symlink_targets=$((external_symlink_targets + 1))
                    [ "$external_symlink_targets" -le 20 ] && evidence="${evidence}$(display_path "$log_file"):symlink_target_outside_log_root\n"
                    continue
                    ;;
            esac
            symlink_targets_scanned=$((symlink_targets_scanned + 1))
            scanned=$((scanned + 1))
            owner="$(stat_owner "$resolved_target" 2>/dev/null || true)"
            mode="$(stat_mode "$resolved_target" 2>/dev/null || true)"
            if [ -z "$owner" ] || [ -z "$mode" ]; then
                stat_errors=$((stat_errors + 1))
                [ "$stat_errors" -le 20 ] && evidence="${evidence}$(display_path "$log_file"):symlink_target_stat_error\n"
            elif [ "$owner" != "root" ] || ! mode_is_at_most "$mode" 644; then
                violations=$((violations + 1))
                [ "$violations" -le 20 ] && evidence="${evidence}$(display_path "$log_file"):target_owner=${owner},target_mode=${mode}\n"
            fi
        elif resolved_target="$(resolve_rooted_directory "$log_file" 2>/dev/null || true)" && [ -n "$resolved_target" ]; then
            symlink_directories=$((symlink_directories + 1))
            [ "$symlink_directories" -le 20 ] && evidence="${evidence}$(display_path "$log_file"):symlink_directory_unscanned\n"
        else
            unresolved_symlinks=$((unresolved_symlinks + 1))
            [ "$unresolved_symlinks" -le 20 ] && evidence="${evidence}$(display_path "$log_file"):symlink_target_unresolved\n"
        fi
    done < "$symlink_list_file"

    while IFS="$(printf '\t')" read -r role logical_path; do
        [ -n "$role" ] || continue
        physical_path="$(fs_path "$logical_path" 2>/dev/null || true)"
        if [ -e "$physical_path" ]; then
            expected_logs_present=$((expected_logs_present + 1))
        else
            expected_logs_absent=$((expected_logs_absent + 1))
        fi
    done < <(logging_expected_destinations 2>/dev/null || true)

    evidence="logging_root=/var/log\nscanned_files=${scanned}\nviolations=${violations}\nscanned_directories=${scanned_directories}\ndirectory_write_violations=${directory_violations}\nsymlinks=${symlinks}\nsymlink_targets_scanned=${symlink_targets_scanned}\nexternal_symlink_targets=${external_symlink_targets}\nsymlink_directories_unscanned=${symlink_directories}\nunresolved_symlinks=${unresolved_symlinks}\nexpected_profile_logs_present=${expected_logs_present}\nexpected_profile_logs_absent=${expected_logs_absent}\nexcluded_network_mounts=${excluded_mounts}\nbundle_mount_inventory=${bundle_mount_inventory}\nstat_errors=${stat_errors}\n${evidence}"
    if [ "$stat_errors" -gt 0 ]; then
        set_result ERROR "일부 로그 파일 또는 디렉터리의 메타데이터를 수집하지 못했습니다." "$evidence"
    elif [ "$violations" -gt 0 ]; then
        set_result VULNERABLE "/var/log에서 KISA 소유자·권한 기준을 벗어난 파일을 확인했습니다." "$evidence"
    elif [ "$scanned" -eq 0 ]; then
        set_result MANUAL "/var/log에서 일반 로그 파일을 찾지 못해 권한 기준을 확정할 수 없습니다." "$evidence"
    elif [ "$SCAN_ROOT" != "/" ] && [ "$bundle_mount_inventory" -ne 1 ]; then
        set_result MANUAL "오프라인 루트에서는 /var/log 하위 마운트 경계를 확인할 수 없습니다." "$evidence"
    elif [ "$directory_violations" -gt 0 ] || [ "$excluded_mounts" -gt 0 ] || [ "$external_symlink_targets" -gt 0 ] || [ "$symlink_directories" -gt 0 ] || [ "$unresolved_symlinks" -gt 0 ]; then
        set_result MANUAL "일반 로그 파일은 기준을 충족하지만 디렉터리, 제외된 마운트 또는 심볼릭 링크 범위를 추가 검토해야 합니다." "$evidence"
    else
        set_result GOOD "/var/log의 모든 일반 파일이 root 소유이며 0644 이하입니다." "$evidence"
    fi
}
