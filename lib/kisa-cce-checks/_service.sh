# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash

# Service checks cover U-34 through U-63 for supported platform families.

SERVICE_ACTIVATION_EVIDENCE=""
SERVICE_FTP_PROVIDERS=""
SERVICE_FTP_UNCERTAIN=0
SERVICE_MAIL_PROVIDERS=""
SERVICE_MAIL_UNCERTAIN=0
SERVICE_SNMP_CONFIG_UNCERTAIN=0
SERVICE_SNMP_ENDPOINT_ACTIVE=0
SERVICE_LEGACY_UNCERTAIN=0
SERVICE_NAMED_PROCESS_EVIDENCE=""

service_append_word() {
    local current_value="$1"
    local new_value="$2"

    case " $current_value " in
        *" $new_value "*) printf '%s\n' "$current_value" ;;
        *) printf '%s%s%s\n' "$current_value" "${current_value:+ }" "$new_value" ;;
    esac
}

service_unique_evidence_lines_into() {
    local destination_name="$1"
    local evidence_value=""
    local evidence_line=""
    local normalized_value=""
    local combined_value=""
    declare -A seen_lines=()

    shift
    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|destination_name|evidence_value|evidence_line|normalized_value|combined_value)
            return 2
            ;;
    esac
    for evidence_value in "$@"; do
        normalized_value="${evidence_value//\\n/$'\n'}"
        while IFS= read -r evidence_line || [ -n "$evidence_line" ]; do
            [ -n "$evidence_line" ] || continue
            [ "${seen_lines[$evidence_line]+present}" != present ] || continue
            seen_lines["$evidence_line"]=1
            combined_value="${combined_value}${evidence_line}\n"
        done <<< "$normalized_value"
    done
    printf -v "$destination_name" '%s' "$combined_value"
}

service_prefix_evidence_lines_into() {
    local destination_name="$1"
    local key_prefix="$2"
    local evidence_value="$3"
    local evidence_line=""
    local evidence_key=""
    local normalized_value=""
    local prefixed_value=""

    case "$destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|destination_name|key_prefix|evidence_value|evidence_line|evidence_key|normalized_value|prefixed_value)
            return 2
            ;;
    esac
    case "$key_prefix" in ''|[0-9]*|*[!A-Za-z0-9_]*) return 2 ;; esac
    normalized_value="${evidence_value//\\n/$'\n'}"
    while IFS= read -r evidence_line || [ -n "$evidence_line" ]; do
        [ -n "$evidence_line" ] || continue
        case "$evidence_line" in
            *=*) evidence_key="${evidence_line%%=*}" ;;
            *) return 2 ;;
        esac
        case "$evidence_key" in ''|[0-9]*|*[!A-Za-z0-9_]*) return 2 ;; esac
        prefixed_value="${prefixed_value}${key_prefix}${evidence_line}\n"
    done <<< "$normalized_value"
    printf -v "$destination_name" '%s' "$prefixed_value"
}

service_file_has_active_entry() {
    local physical_path="$1"
    local expression="$2"

    [ -r "$physical_path" ] || return 1
    KISA_CCE_SERVICE_EXPRESSION="$expression" awk '
        BEGIN {expression=ENVIRON["KISA_CCE_SERVICE_EXPRESSION"]}
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^[#;]/) next
            if (line ~ expression) found=1
        }
        END {exit(found ? 0 : 1)}
    ' "$physical_path"
}

service_inetd_enabled() {
    local service_expression="$1"
    local configuration_path=""
    local path_status=0

    configuration_path="$(optional_rooted_read_path /etc/inetd.conf 2>/dev/null)" || path_status=$?
    case "$path_status" in
        0) ;;
        1) return 1 ;;
        *)
            SERVICE_LEGACY_UNCERTAIN=1
            return 1
            ;;
    esac
    KISA_CCE_SERVICE_EXPRESSION="$service_expression" awk '
        BEGIN {expression=ENVIRON["KISA_CCE_SERVICE_EXPRESSION"]}
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            split(line, fields, /[[:space:]]+/)
            if (fields[1] ~ expression) found=1
        }
        END {exit(found ? 0 : 1)}
    ' "$configuration_path"
}

service_xinetd_files() {
    local main_path=""
    local physical_directory=""
    local included_directory=""
    local candidate_file=""
    local sorted_file=""
    local candidate=""
    local resolved_candidate=""
    local path_status=0

    main_path="$(optional_rooted_read_path /etc/xinetd.conf 2>/dev/null)" || path_status=$?
    case "$path_status" in
        0) printf '%s\n' "$main_path" ;;
        1) return 0 ;;
        *) return 2 ;;
    esac

    while IFS= read -r included_directory; do
        case "$included_directory" in
            /*) ;;
            *) return 2 ;;
        esac
        physical_directory="$(fs_path "$included_directory" 2>/dev/null)" || return 2
        resolve_rooted_directory_into "$physical_directory" physical_directory 2>/dev/null || return 2
        candidate_file="$(new_scratch_file xinetd-files)" || return 2
        sorted_file="$(new_scratch_file xinetd-files-sorted)" || return 2
        find -P "$physical_directory" -mindepth 1 -maxdepth 1 \
            \( -type f -o -type l \) ! -name '*.*' ! -name '*~' -print0 \
            > "$candidate_file" 2>/dev/null || return 2
        LC_ALL=C sort -z "$candidate_file" > "$sorted_file" || return 2
        while IFS= read -r -d '' candidate; do
            case "$candidate" in *$'\n'*|*$'\r'*|*$'\t'*) return 2 ;; esac
            resolve_rooted_read_path_into "$candidate" resolved_candidate 2>/dev/null || return 2
            case "$resolved_candidate" in *$'\n'*|*$'\r'*|*$'\t'*) return 2 ;; esac
            if awk '
                {
                    line=$0
                    sub(/^[[:space:]]+/, "", line)
                    if (line ~ /^include(dir)?[[:space:]]+/) found=1
                }
                END {exit(found ? 0 : 1)}
            ' "$resolved_candidate"; then
                return 2
            fi
            printf '%s\n' "$resolved_candidate"
        done < "$sorted_file"
    done <<EOF
$(awk '
    /^[[:space:]]*includedir[[:space:]]+/ {
        line=$0
        sub(/^[[:space:]]*includedir[[:space:]]+/, "", line)
        sub(/[[:space:]]*#.*/, "", line)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        print line
    }
' "$main_path")
EOF
}

service_xinetd_graph_uncertain() {
    local main_path=""
    local directive_type=""
    local included_path=""
    local physical_path=""
    local path_status=0

    main_path="$(optional_rooted_read_path /etc/xinetd.conf 2>/dev/null)" || path_status=$?
    [ "$path_status" -eq 0 ] || {
        [ "$path_status" -eq 1 ] && return 1
        return 0
    }
    while IFS=$'\t' read -r directive_type included_path; do
        [ -n "$directive_type" ] || continue
        case "$directive_type:$included_path" in
            include:*) return 0 ;;
            includedir:/*)
                physical_path="$(fs_path "$included_path" 2>/dev/null)" || return 0
                resolve_rooted_directory_into "$physical_path" physical_path 2>/dev/null || return 0
                ;;
            *) return 0 ;;
        esac
    done <<EOF
$(awk '
    /^[[:space:]]*include(dir)?[[:space:]]+/ {
        line=$0
        sub(/^[[:space:]]*/, "", line)
        type=line
        sub(/[[:space:]].*$/, "", type)
        sub(/^[^[:space:]]+[[:space:]]+/, "", line)
        sub(/[[:space:]]*#.*/, "", line)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        print type "\t" line
    }
' "$main_path")
EOF
    return 1
}

service_xinetd_global_state() {
    local configuration_files="${1:-}"
    local configuration_file=""
    local -a parsed_files=()

    while IFS= read -r configuration_file; do
        [ -n "$configuration_file" ] || continue
        [ -r "$configuration_file" ] || return 2
        parsed_files+=("$configuration_file")
    done <<EOF
$configuration_files
EOF
    if [ "${#parsed_files[@]}" -eq 0 ]; then
        printf 'enabled-list\t0\n'
        return 0
    fi
    awk '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            if (line ~ /^defaults([[:space:]{]|$)/) {
                remainder=line
                sub(/^defaults/, "", remainder)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", remainder)
                if (remainder != "" && remainder != "{") ambiguous=1
                in_defaults=1
                next
            }
            if (in_defaults && line ~ /^}/) {in_defaults=0; next}
            if (!in_defaults) next
            if (line ~ /\\[[:space:]]*$/) {ambiguous=1; next}
            separator=index(line, "=")
            if (separator == 0) next
            prefix=substr(line, 1, separator - 1)
            if (prefix ~ /[+-][[:space:]]*$/) {ambiguous=1; next}
            gsub(/[[:space:]]/, "", prefix)
            directive=tolower(prefix)
            if (directive != "disabled" && directive != "enabled") next
            value=substr(line, separator + 1)
            sub(/[[:space:]]*[#;].*$/, "", value)
            count=split(value, names, /[[:space:],]+/)
            if (directive == "enabled") enabled_list=1
            for (index_value=1; index_value<=count; index_value++) {
                name=names[index_value]
                gsub(/^"|"$/, "", name)
                if (name == "") continue
                if (directive == "enabled") enabled_names[name]=1
                else disabled_names[name]=1
            }
        }
        END {
            for (name in enabled_names) {
                if (name in disabled_names) ambiguous=1
            }
            if (ambiguous) exit 2
            print "enabled-list\t" (enabled_list ? 1 : 0)
            for (name in enabled_names) print "enabled\t" name
            for (name in disabled_names) print "disabled\t" name
        }
    ' "${parsed_files[@]}"
}

service_xinetd_enabled() {
    local service_expression="$1"
    local configuration_file=""
    local configuration_files=""
    local global_metadata=""
    local graph_status=1
    local collection_status=0
    local parser_status=1

    service_xinetd_graph_uncertain
    graph_status=$?
    if [ "$graph_status" -ne 1 ]; then
        SERVICE_LEGACY_UNCERTAIN=1
        return 1
    fi

    configuration_files="$(service_xinetd_files)" || collection_status=$?
    if [ "$collection_status" -ne 0 ]; then
        SERVICE_LEGACY_UNCERTAIN=1
        return 1
    fi
    collection_status=0
    global_metadata="$(service_xinetd_global_state "$configuration_files" 2>/dev/null)" || collection_status=$?
    if [ "$collection_status" -ne 0 ]; then
        SERVICE_LEGACY_UNCERTAIN=1
        return 1
    fi

    while IFS= read -r configuration_file; do
        [ -r "$configuration_file" ] || continue
        KISA_CCE_SERVICE_EXPRESSION="$service_expression" \
            KISA_CCE_XINETD_GLOBAL_METADATA="$global_metadata" awk '
            BEGIN {
                expression=ENVIRON["KISA_CCE_SERVICE_EXPRESSION"]
                metadata_count=split(ENVIRON["KISA_CCE_XINETD_GLOBAL_METADATA"], metadata, "\n")
                for (metadata_index=1; metadata_index<=metadata_count; metadata_index++) {
                    field_count=split(metadata[metadata_index], fields, "\t")
                    if (fields[1] == "enabled-list" && field_count == 2) enabled_list=fields[2] + 0
                    else if (fields[1] == "enabled" && field_count == 2) enabled_names[fields[2]]=1
                    else if (fields[1] == "disabled" && field_count == 2) disabled_names[fields[2]]=1
                    else if (metadata[metadata_index] != "") ambiguous=1
                }
            }
            function finish_block() {
                if (in_target) {
                    effective_id=(service_id == "" ? service_name : service_id)
                    if (disable_value != "" && disable_value != "yes" && disable_value != "no") {
                        ambiguous=1
                    } else {
                        globally_enabled=(!enabled_list || (effective_id in enabled_names)) &&
                            !(effective_id in disabled_names)
                        if (globally_enabled && disable_value != "yes") enabled=1
                    }
                }
                in_target=0
                service_name=""
                service_id=""
                disable_value=""
                saw_id=0
                saw_disable=0
            }
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                if (line ~ /^service[[:space:]]+/) {
                    finish_block()
                    name=line
                    sub(/^service[[:space:]]+/, "", name)
                    sub(/[[:space:]{].*$/, "", name)
                    in_target=(name ~ expression)
                    service_name=name
                    remainder=line
                    sub(/^service[[:space:]]+/, "", remainder)
                    sub(/^[^[:space:]{]+/, "", remainder)
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", remainder)
                    if (in_target && remainder != "" && remainder != "{") ambiguous=1
                    next
                }
                if (in_target && line ~ /^id[[:space:]]*=/) {
                    if (saw_id) ambiguous=1
                    saw_id=1
                    value=line
                    sub(/^[^=]*=/, "", value)
                    sub(/[[:space:]]*[#;].*$/, "", value)
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                    if (value ~ /^"[^"]+"$/) {
                        sub(/^"/, "", value)
                        sub(/"$/, "", value)
                    }
                    if (value == "" || value ~ /[[:space:]]/) ambiguous=1
                    else service_id=value
                }
                if (in_target && line ~ /^disable[[:space:]]*=/) {
                    if (saw_disable) ambiguous=1
                    saw_disable=1
                    value=line
                    sub(/^[^=]*=/, "", value)
                    sub(/[[:space:]]*[#;].*$/, "", value)
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                    disable_value=tolower(value)
                }
                if (in_target && line ~ /^}/) finish_block()
            }
            END {
                finish_block()
                if (enabled) exit 0
                if (ambiguous) exit 2
                exit 1
            }
        ' "$configuration_file"
        parser_status=$?
        if [ "$parser_status" -eq 0 ]; then
            return 0
        elif [ "$parser_status" -eq 2 ]; then
            SERVICE_LEGACY_UNCERTAIN=1
        fi
    done <<EOF
$(printf '%s\n' "$configuration_files" | awk 'NF && !seen[$0]++')
EOF

    return 1
}

service_legacy_enabled() {
    local service_expression="$1"

    SERVICE_LEGACY_UNCERTAIN=0
    service_inetd_enabled "$service_expression" || service_xinetd_enabled "$service_expression"
}

service_unit_definition_exists() {
    local unit_name="$1"
    local logical_directory=""
    local physical_directory=""

    for logical_directory in \
        /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system \
        /usr/lib/systemd/system /lib/systemd/system; do
        fs_path_into "$logical_directory" physical_directory || continue
        [ -e "$physical_directory/$unit_name" ] && return 0
    done
    return 1
}

service_unit_statically_enabled() {
    local unit_name="$1"
    local logical_directory=""
    local physical_directory=""
    local first_path=""
    local second_path=""
    local candidate=""
    local result=1
    local path_is_already_activated=0
    local dotglob_was_set=0
    local nullglob_was_set=0
    local failglob_was_set=0
    local nocaseglob_was_set=0
    local nocasematch_was_set=0
    local noglob_was_set=0
    local GLOBIGNORE=""

    shopt -q dotglob && dotglob_was_set=1
    shopt -q nullglob && nullglob_was_set=1
    shopt -q failglob && failglob_was_set=1
    shopt -q nocaseglob && nocaseglob_was_set=1
    shopt -q nocasematch && nocasematch_was_set=1
    case $- in
        *f*) noglob_was_set=1 ;;
    esac

    set +f
    shopt -s dotglob nullglob
    shopt -u failglob nocaseglob nocasematch

    for logical_directory in /etc/systemd/system /run/systemd/system; do
        fs_path_into "$logical_directory" physical_directory || continue
        [ -d "$physical_directory" ] && [ ! -L "$physical_directory" ] || continue
        path_is_already_activated=0
        case "$physical_directory/" in
            *.wants/*|*.requires/*) path_is_already_activated=1 ;;
        esac

        if [ "$path_is_already_activated" -eq 1 ]; then
            for first_path in "$physical_directory"/*; do
                [ -d "$first_path" ] && [ ! -L "$first_path" ] || continue
                candidate="$first_path/$unit_name"
                if [ -e "$candidate" ] || [ -L "$candidate" ]; then
                    result=0
                    break
                fi

                for second_path in "$first_path"/*; do
                    [ -d "$second_path" ] && [ ! -L "$second_path" ] || continue
                    candidate="$second_path/$unit_name"
                    if [ -e "$candidate" ] || [ -L "$candidate" ]; then
                        result=0
                        break
                    fi
                done
                [ "$result" -ne 0 ] || break
            done
            [ "$result" -ne 0 ] || break
            continue
        fi

        for first_path in "$physical_directory"/*.wants "$physical_directory"/*.requires; do
            [ -d "$first_path" ] && [ ! -L "$first_path" ] || continue
            candidate="$first_path/$unit_name"
            if [ -e "$candidate" ] || [ -L "$candidate" ]; then
                result=0
                break
            fi
        done
        [ "$result" -ne 0 ] || break

        for first_path in "$physical_directory"/*.wants "$physical_directory"/*.requires; do
            [ -d "$first_path" ] && [ ! -L "$first_path" ] || continue
            for second_path in "$first_path"/*; do
                [ -d "$second_path" ] && [ ! -L "$second_path" ] || continue
                candidate="$second_path/$unit_name"
                if [ -e "$candidate" ] || [ -L "$candidate" ]; then
                    result=0
                    break
                fi
            done
            [ "$result" -ne 0 ] || break
        done
        [ "$result" -ne 0 ] || break

        for first_path in "$physical_directory"/*; do
            [ -d "$first_path" ] && [ ! -L "$first_path" ] || continue
            case "${first_path##*/}" in
                *.wants|*.requires) continue ;;
            esac
            for second_path in "$first_path"/*.wants "$first_path"/*.requires; do
                [ -d "$second_path" ] && [ ! -L "$second_path" ] || continue
                candidate="$second_path/$unit_name"
                if [ -e "$candidate" ] || [ -L "$candidate" ]; then
                    result=0
                    break
                fi
            done
            [ "$result" -ne 0 ] || break
        done
        [ "$result" -ne 0 ] || break
    done

    [ "$dotglob_was_set" -eq 1 ] || shopt -u dotglob
    [ "$nullglob_was_set" -eq 1 ] || shopt -u nullglob
    [ "$failglob_was_set" -eq 0 ] || shopt -s failglob
    [ "$nocaseglob_was_set" -eq 0 ] || shopt -s nocaseglob
    [ "$nocasematch_was_set" -eq 0 ] || shopt -s nocasematch
    [ "$noglob_was_set" -eq 0 ] || set -f

    return "$result"
}

service_sysv_statically_enabled() {
    local unit_name="$1"
    local service_name=""
    local logical_directory=""
    local physical_directory=""
    local link_path=""
    local resolved_path=""
    local expected_path=""
    local saw_unresolved_link=0

    case "$unit_name" in
        *.service) service_name="${unit_name%.service}" ;;
        *) return 1 ;;
    esac
    case "$service_name" in
        ''|*@*) return 1 ;;
    esac

    if fs_path_into "/etc/init.d/$service_name" expected_path 2>/dev/null; then
        resolve_rooted_read_path_into "$expected_path" expected_path 2>/dev/null || expected_path=""
    fi

    for logical_directory in \
        /etc/rc0.d /etc/rc1.d /etc/rc2.d /etc/rc3.d \
        /etc/rc4.d /etc/rc5.d /etc/rc6.d /etc/rcS.d; do
        fs_path_into "$logical_directory" physical_directory 2>/dev/null || continue
        [ -d "$physical_directory" ] || continue
        for link_path in "$physical_directory"/S[0-9][0-9]"$service_name"; do
            [ -e "$link_path" ] || [ -L "$link_path" ] || continue
            resolve_rooted_read_path_into "$link_path" resolved_path 2>/dev/null || resolved_path=""
            if [ -z "$resolved_path" ] || [ -z "$expected_path" ]; then
                saw_unresolved_link=1
                continue
            fi
            if [ "$resolved_path" != "$expected_path" ] || [ ! -x "$resolved_path" ]; then
                saw_unresolved_link=1
                continue
            fi
            return 0
        done
    done
    [ "$saw_unresolved_link" -eq 0 ] || return 2
    return 1
}

# This helper treats active sockets and enabled units as activation paths because
# a stopped service can still be started by a socket or at the next boot.
service_activation_state() {
    local unit_name=""
    local systemctl_path=""
    local properties=""
    local load_state=""
    local active_state=""
    local unit_file_state=""
    local command_status=0
    local saw_definition=0
    local sysv_status=1
    local runtime_probe_uncertain=0
    local sysv_uncertain=0
    local manager_status=0

    SERVICE_ACTIVATION_EVIDENCE=""

    if [ "${EVIDENCE_BUNDLE_ACTIVE:-0}" -eq 1 ] && declare -F evidence_service_activation_state >/dev/null 2>&1; then
        evidence_service_activation_state "$@"
        command_status=$?
        SERVICE_ACTIVATION_EVIDENCE="${EVIDENCE_SERVICE_ACTIVATION_EVIDENCE:-runtime_bundle_state=unknown}"
        return "$command_status"
    fi

    if runtime_enabled; then
        if declare -F runtime_systemd_manager_state >/dev/null 2>&1; then
            runtime_systemd_manager_state || manager_status=$?
        fi
        if [ "$manager_status" -eq 1 ]; then
            SERVICE_ACTIVATION_EVIDENCE="${SERVICE_ACTIVATION_EVIDENCE}systemd_manager=not_running\n"
        else
            systemctl_path="$(trusted_command systemctl 2>/dev/null || true)"
        fi
        if [ -n "$systemctl_path" ]; then
            for unit_name in "$@"; do
                command_status=0
                if [ "${SCAN_EPOCH_ACTIVE:-0}" -eq 1 ] &&
                    declare -F systemd_cached_unit_facts >/dev/null 2>&1; then
                    systemd_cached_unit_facts "$unit_name" || command_status=$?
                    properties="$SYSTEMD_CACHE_FACTS"
                    [ "$command_status" -ne 0 ] || command_status="$SYSTEMD_CACHE_COMMAND_STATUS"
                else
                    properties="$($systemctl_path show "$unit_name" \
                        -p LoadState -p ActiveState -p UnitFileState --no-pager 2>/dev/null)" || command_status=$?
                fi
                if declare -F systemd_fact_value_into >/dev/null 2>&1; then
                    systemd_fact_value_into "$properties" LoadState load_state || load_state=""
                    systemd_fact_value_into "$properties" ActiveState active_state || active_state=""
                    systemd_fact_value_into "$properties" UnitFileState unit_file_state || unit_file_state=""
                else
                    load_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "LoadState" {print $2; exit}')"
                    active_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "ActiveState" {print $2; exit}')"
                    unit_file_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "UnitFileState" {print $2; exit}')"
                fi
                if [ "$command_status" -ne 0 ] && [ "$load_state" != "not-found" ]; then
                    runtime_probe_uncertain=1
                    SERVICE_ACTIVATION_EVIDENCE="${SERVICE_ACTIVATION_EVIDENCE}unit=${unit_name},runtime_state=unknown\n"
                    continue
                fi
                [ -n "$load_state" ] && [ "$load_state" != "not-found" ] || continue
                SERVICE_ACTIVATION_EVIDENCE="${SERVICE_ACTIVATION_EVIDENCE}unit=${unit_name},active=${active_state:-unknown},enabled=${unit_file_state:-unknown}\n"
                case "$active_state" in
                    active|activating|reloading) return 0 ;;
                esac
                case "$unit_file_state" in
                    enabled|enabled-runtime) return 0 ;;
                esac
            done
        elif [ "$manager_status" -ne 1 ]; then
            runtime_probe_uncertain=1
            SERVICE_ACTIVATION_EVIDENCE="${SERVICE_ACTIVATION_EVIDENCE}systemctl=unavailable\n"
        fi

        for unit_name in "$@"; do
            service_sysv_statically_enabled "$unit_name"
            sysv_status=$?
            case "$sysv_status" in
                0)
                    SERVICE_ACTIVATION_EVIDENCE="${SERVICE_ACTIVATION_EVIDENCE}unit=${unit_name},runtime_sysv_enabled=true\n"
                    return 0
                    ;;
                2)
                    sysv_uncertain=1
                    SERVICE_ACTIVATION_EVIDENCE="${SERVICE_ACTIVATION_EVIDENCE}unit=${unit_name},runtime_sysv_state=unknown\n"
                    ;;
            esac
        done

        if [ "$manager_status" -eq 1 ]; then
            for unit_name in "$@"; do
                if service_unit_statically_enabled "$unit_name"; then
                    SERVICE_ACTIVATION_EVIDENCE="${SERVICE_ACTIVATION_EVIDENCE}unit=${unit_name},static_enabled=true\n"
                    return 0
                fi
            done
        fi

        if [ "$runtime_probe_uncertain" -eq 1 ] || [ "$sysv_uncertain" -eq 1 ]; then
            return 2
        fi
        return 1
    fi

    for unit_name in "$@"; do
        service_sysv_statically_enabled "$unit_name"
        sysv_status=$?
        case "$sysv_status" in
            0)
                SERVICE_ACTIVATION_EVIDENCE="${SERVICE_ACTIVATION_EVIDENCE}unit=${unit_name},offline_sysv_enabled=true\n"
                return 0
                ;;
            2)
                saw_definition=1
                SERVICE_ACTIVATION_EVIDENCE="${SERVICE_ACTIVATION_EVIDENCE}unit=${unit_name},offline_sysv_state=unknown\n"
                ;;
        esac
        if service_unit_statically_enabled "$unit_name"; then
            SERVICE_ACTIVATION_EVIDENCE="${SERVICE_ACTIVATION_EVIDENCE}unit=${unit_name},offline_enabled=true\n"
            return 0
        fi
        if service_unit_definition_exists "$unit_name"; then
            saw_definition=1
            SERVICE_ACTIVATION_EVIDENCE="${SERVICE_ACTIVATION_EVIDENCE}unit=${unit_name},offline_state=unknown\n"
        fi
    done

    [ "$saw_definition" -eq 1 ] && return 2
    return 1
}

service_listener_state() {
    local transport="any"
    local port_number=""
    local listener_output=""
    local listener_status=0

    case "${1:-}" in
        tcp|udp|any)
            transport="$1"
            shift
            ;;
    esac
    [ "$#" -gt 0 ] || return 2
    runtime_snapshot_available || return 2

    for port_number in "$@"; do
        listener_output="$(port_listener_facts "$port_number" "$transport")"
        listener_status=$?
        [ "$listener_status" -eq 0 ] || return 2
        [ -n "$listener_output" ] && return 0
    done
    return 1
}

# A loopback-only systemd-resolved stub is a local resolver, not an
# authoritative DNS service. Unidentified or non-loopback port 53 listeners
# remain applicable so that this exception cannot hide another daemon.
service_dns_listener_state() {
    local listener_output=""
    local listener_status=0

    runtime_snapshot_available || return 2
    listener_output="$(port_listener_facts 53)"
    listener_status=$?
    [ "$listener_status" -eq 0 ] || return 2
    [ -n "$listener_output" ] || return 1

    printf '%s\n' "$listener_output" | awk '
        {
            endpoint=$5
            sub(/:53$/, "", endpoint)
            gsub(/^\[|\]$/, "", endpoint)
            sub(/%.*/, "", endpoint)
            loopback=(endpoint ~ /^127\./ || endpoint == "::1")
            resolved=($0 ~ /systemd-resolve(d)?/)
            if (!loopback || !resolved) other_listener=1
        }
        END {exit(other_listener ? 0 : 3)}
    '
}

service_named_process_state() {
    local process_name=""
    local pgrep_path=""
    local command_status=1
    local procfs_status=2
    local procfs_queried=0

    SERVICE_NAMED_PROCESS_EVIDENCE=""
    runtime_enabled || {
        SERVICE_NAMED_PROCESS_EVIDENCE="process_probe=runtime_disabled\n"
        return 2
    }
    for process_name in "$@"; do
        case "$process_name" in ''|*[!A-Za-z0-9._@:+-]*) return 2 ;; esac
    done
    if declare -F runtime_process_state >/dev/null 2>&1; then
        procfs_queried=1
        runtime_process_state "$@"
        procfs_status=$?
        case "$procfs_status" in
            0)
                SERVICE_NAMED_PROCESS_EVIDENCE="process_probe=procfs,matched=true\n"
                return 0
                ;;
            1)
                SERVICE_NAMED_PROCESS_EVIDENCE="process_probe=procfs,matched=false\n"
                return 1
                ;;
        esac
    fi
    pgrep_path="$(trusted_command pgrep 2>/dev/null || true)"
    [ -n "$pgrep_path" ] || {
        if [ "$procfs_queried" -eq 1 ]; then
            SERVICE_NAMED_PROCESS_EVIDENCE="process_probe=procfs_incomplete,pgrep=unavailable\n"
        else
            SERVICE_NAMED_PROCESS_EVIDENCE="process_probe=unavailable\n"
        fi
        return 2
    }
    for process_name in "$@"; do
        "$pgrep_path" -x -- "$process_name" >/dev/null 2>&1
        command_status=$?
        if [ "$command_status" -eq 0 ]; then
            SERVICE_NAMED_PROCESS_EVIDENCE="process=${process_name},runtime_active=true\n"
            return 0
        elif [ "$command_status" -ne 1 ]; then
            SERVICE_NAMED_PROCESS_EVIDENCE="process=${process_name},probe_error=true\n"
            return 2
        fi
    done
    if [ "$procfs_queried" -eq 1 ] && [ "$procfs_status" -ne 0 ] && [ "$procfs_status" -ne 1 ]; then
        SERVICE_NAMED_PROCESS_EVIDENCE="process_probe=procfs_incomplete,pgrep_matched=false\n"
        return 2
    fi
    SERVICE_NAMED_PROCESS_EVIDENCE="process_probe=inactive\n"
    return 1
}

service_units_have_custom_configuration() {
    local option_expression="$1"
    shift
    local systemctl_path=""
    local unit=""
    local properties=""
    local load_state=""
    local command_status=0
    local manager_status=0

    runtime_enabled || return 2
    if declare -F runtime_systemd_manager_state >/dev/null 2>&1; then
        runtime_systemd_manager_state || manager_status=$?
        [ "$manager_status" -ne 1 ] || return 1
    fi
    systemctl_path="$(trusted_command systemctl)" || return 2
    for unit in "$@"; do
        if [ "${SCAN_EPOCH_ACTIVE:-0}" -eq 1 ]; then
            systemd_epoch_properties_into "$unit" properties || return 2
            command_status="$SYSTEMD_PROPERTIES_COMMAND_STATUS"
            systemd_fact_value_into "$properties" LoadState load_state || load_state=""
        else
            properties="$($systemctl_path show "$unit" -p LoadState -p ExecStart --no-pager 2>/dev/null)" || command_status=$?
            load_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "LoadState" {print $2; exit}')"
        fi
        if [ "$command_status" -ne 0 ] && [ "$load_state" != "not-found" ]; then
            return 2
        fi
        command_status=0
        [ "$load_state" != "not-found" ] || continue
        if printf '%s\n' "$properties" | grep -Eq "$option_expression|\\\$[{A-Za-z_]"; then
            return 0
        fi
    done
    return 1
}

service_ftp_custom_invocation_state() {
    local systemctl_path=""
    local unit=""
    local properties=""
    local load_state=""
    local argument=""
    local command_status=0
    local manager_status=0

    runtime_enabled || return 2
    if declare -F runtime_systemd_manager_state >/dev/null 2>&1; then
        runtime_systemd_manager_state || manager_status=$?
        [ "$manager_status" -ne 1 ] || return 1
    fi
    systemctl_path="$(trusted_command systemctl)" || return 2
    for unit in vsftpd.service proftpd.service pure-ftpd.service; do
        if [ "${SCAN_EPOCH_ACTIVE:-0}" -eq 1 ]; then
            systemd_epoch_properties_into "$unit" properties || return 2
            command_status="$SYSTEMD_PROPERTIES_COMMAND_STATUS"
            systemd_fact_value_into "$properties" LoadState load_state || load_state=""
        else
            properties="$($systemctl_path show "$unit" -p LoadState -p ExecStart --no-pager 2>/dev/null)" || command_status=$?
            load_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "LoadState" {print $2; exit}')"
        fi
        if [ "$command_status" -ne 0 ] && [ "$load_state" != "not-found" ]; then return 2; fi
        command_status=0
        [ "$load_state" != "not-found" ] || continue
        printf '%s\n' "$properties" | grep -Eq '\$[{A-Za-z_]' && return 0
        case "$unit" in
            vsftpd.service)
                argument="$(printf '%s\n' "$properties" | sed -nE 's#.*argv\[\]=[^ ;]*/vsftpd[[:space:]]+([^ ;}]+).*#\1#p' | head -n 1)"
                case "$argument" in
                    ''|/etc/vsftpd.conf|/etc/vsftpd/vsftpd.conf) ;;
                    *) return 0 ;;
                esac
                ;;
            proftpd.service)
                printf '%s\n' "$properties" | grep -Eq '([[:space:]]-c([^[:space:]]*|$)|--config([=[:space:]]|$))' && return 0
                ;;
        esac
    done
    return 1
}

service_mode_has_any_execute() {
    local mode="$1"
    local decimal_mode=""

    decimal_mode="$(mode_to_decimal "$mode")" || return 1
    [ $((decimal_mode & 0111)) -ne 0 ]
}

service_mode_has_other_execute() {
    local mode="$1"
    local decimal_mode=""

    decimal_mode="$(mode_to_decimal "$mode")" || return 1
    [ $((decimal_mode & 0001)) -ne 0 ]
}

service_mode_has_special_bits() {
    local mode="$1"
    local decimal_mode=""

    decimal_mode="$(mode_to_decimal "$mode")" || return 1
    [ $((decimal_mode & 07000)) -ne 0 ]
}

service_mode_has_setuid() {
    local mode="$1"
    local decimal_mode=""

    decimal_mode="$(mode_to_decimal "$mode")" || return 1
    [ $((decimal_mode & 04000)) -ne 0 ]
}

service_read_simple_value() {
    local key="$1"
    shift
    local configuration_file=""
    local match=""
    local last_value=""

    for configuration_file in "$@"; do
        [ -r "$configuration_file" ] || continue
        match="$(awk -v target="$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')" '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^[#;]/) next
                separator=index(line, "=")
                if (separator == 0) next
                name=substr(line, 1, separator - 1)
                value=substr(line, separator + 1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
                sub(/[[:space:]]+[#;].*$/, "", value)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                if (tolower(name) == target) print value
            }
        ' "$configuration_file" | tail -n 1)"
        [ -n "$match" ] && last_value="$match"
    done

    [ -n "$last_value" ] || return 1
    printf '%s\n' "$last_value"
}

service_nfs_export_files() {
    local main_path=""
    local directory_path=""
    local candidate_file=""
    local sorted_file=""
    local listed_file=""
    local resolved_file=""
    local path_status=0
    local collection_error=0

    main_path="$(optional_rooted_read_path /etc/exports 2>/dev/null)" || path_status=$?
    case "$path_status" in
        0) printf '%s\n' "$main_path" ;;
        1) ;;
        *) collection_error=1 ;;
    esac

    path_status=0
    directory_path="$(fs_path /etc/exports.d 2>/dev/null)" || path_status=$?
    if [ "$path_status" -ne 0 ]; then
        collection_error=1
    elif [ -e "$directory_path" ] || [ -L "$directory_path" ]; then
        if [ ! -d "$directory_path" ]; then
            collection_error=1
        else
            resolve_rooted_directory_into "$directory_path" directory_path 2>/dev/null || collection_error=1
            candidate_file="$(new_scratch_file nfs-export-files)" || return 2
            sorted_file="$(new_scratch_file nfs-export-files-sorted)" || return 2
            if [ "$collection_error" -ne 0 ]; then
                :
            elif ! find -P "$directory_path" -mindepth 1 -maxdepth 1 \
                \( -type f -o -type l \) -name '*.exports' -print0 \
                > "$candidate_file" 2>/dev/null; then
                collection_error=1
            elif ! LC_ALL=C sort -z "$candidate_file" > "$sorted_file"; then
                collection_error=1
            else
                while IFS= read -r -d '' listed_file; do
                    resolved_file=""
                    resolve_rooted_read_path_into "$listed_file" resolved_file 2>/dev/null || {
                        collection_error=1
                        continue
                    }
                    case "$resolved_file" in
                        *$'\n'*|*$'\r'*|*$'\t'*) collection_error=1 ;;
                        *) printf '%s\n' "$resolved_file" ;;
                    esac
                done < "$sorted_file"
            fi
        fi
    fi
    [ "$collection_error" -eq 0 ] || return 2
}

service_count_static_exports() {
    local configuration_files=""
    local configuration_file=""

    if [ "$#" -gt 0 ]; then
        configuration_files="$1"
    else
        configuration_files="$(service_nfs_export_files)" || return 2
    fi
    while IFS= read -r configuration_file; do
        [ -r "$configuration_file" ] || continue
        awk '
            function flush() {
                line=record
                record=""
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) return
                sub(/[[:space:]]+#.*/, "", line)
                if (line != "") count++
            }
            {
                current=$0
                if (current ~ /\\[[:space:]]*$/) {
                    sub(/\\[[:space:]]*$/, "", current)
                    record=record " " current
                } else {
                    record=record " " current
                    flush()
                }
            }
            END {flush(); print count+0}
        ' "$configuration_file"
    done <<EOF
$configuration_files
EOF
}

service_static_exports_unrestricted() {
    local configuration_files=""
    local configuration_file=""

    if [ "$#" -gt 0 ]; then
        configuration_files="$1"
    else
        configuration_files="$(service_nfs_export_files)" || return 2
    fi
    while IFS= read -r configuration_file; do
        [ -r "$configuration_file" ] || continue
        if awk '
            function inspect() {
                line=record
                record=""
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) return
                sub(/[[:space:]]+#.*/, "", line)
                fields_count=split(line, fields, /[[:space:]]+/)
                for (index_value=2; index_value<=fields_count; index_value++) {
                    client=fields[index_value]
                    sub(/\(.*/, "", client)
                    if (client == "*" || client == "<world>" || client == "0.0.0.0/0" || client == "::/0") unsafe=1
                }
            }
            {
                current=$0
                if (current ~ /\\[[:space:]]*$/) {
                    sub(/\\[[:space:]]*$/, "", current)
                    record=record " " current
                } else {
                    record=record " " current
                    inspect()
                }
            }
            END {inspect(); exit(unsafe ? 0 : 1)}
        ' "$configuration_file"; then
            return 0
        fi
    done <<EOF
$configuration_files
EOF
    return 1
}

service_static_exports_have_all_squash() {
    local configuration_file=""

    while IFS= read -r configuration_file; do
        [ -r "$configuration_file" ] || continue
        if awk '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                if (line ~ /(^|[, (])all_squash([, )]|$)/) found=1
            }
            END {exit(found ? 0 : 1)}
        ' "$configuration_file"; then
            return 0
        fi
    done <<EOF
$(service_nfs_export_files)
EOF
    return 1
}

# The Linux procedure treats explicit anonymous UID/GID mappings as anonymous
# access. all_squash is included because it maps every remote identity to the
# anonymous account even when anonuid and anongid are omitted.
service_static_exports_have_anonymous_mapping() {
    local configuration_file=""

    while IFS= read -r configuration_file; do
        [ -r "$configuration_file" ] || continue
        if awk '
            function inspect() {
                line=record
                record=""
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) return
                sub(/[[:space:]]+#.*/, "", line)
                if (line ~ /(^|[, (])(anonuid|anongid)[[:space:]]*=/ ||
                    line ~ /(^|[, (])all_squash([, )]|$)/) found=1
            }
            {
                current=$0
                if (current ~ /\\[[:space:]]*$/) {
                    sub(/\\[[:space:]]*$/, "", current)
                    record=record " " current
                } else {
                    record=record " " current
                    inspect()
                }
            }
            END {inspect(); exit(found ? 0 : 1)}
        ' "$configuration_file"; then
            return 0
        fi
    done <<EOF
$(service_nfs_export_files)
EOF
    return 1
}

service_vsftpd_configuration() {
    local candidate=""

    if platform_is_rhel_family; then
        for candidate in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
            candidate="$(fs_path "$candidate")"
            [ -r "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
        done
    elif platform_is_debian_family; then
        for candidate in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
            candidate="$(fs_path "$candidate")"
            [ -r "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
        done
    else
        return 2
    fi
    return 1
}

service_proftpd_files() {
    local candidate=""
    local directory_path=""

    for candidate in /etc/proftpd/proftpd.conf /etc/proftpd.conf; do
        candidate="$(fs_path "$candidate")"
        [ -r "$candidate" ] && printf '%s\n' "$candidate"
    done
    for candidate in /etc/proftpd/conf.d /etc/proftpd.d; do
        directory_path="$(fs_path "$candidate")"
        [ -d "$directory_path" ] || continue
        find -P "$directory_path" -maxdepth 1 -type f -name '*.conf' -print 2>/dev/null | LC_ALL=C sort
    done
}

service_proftpd_has_unresolved_includes() {
    local configuration_file=""

    while IFS= read -r configuration_file; do
        [ -r "$configuration_file" ] || continue
        if service_file_has_active_entry "$configuration_file" \
            '^[[:space:]]*(Include([[:space:]]|$)|<VirtualHost([[:space:]>]|$))'; then
            return 0
        fi
    done <<EOF
$(service_proftpd_files | awk '!seen[$0]++')
EOF
    return 1
}

service_detect_ftp() {
    local activation_status=1
    local listener_status=1

    SERVICE_FTP_PROVIDERS=""
    SERVICE_FTP_UNCERTAIN=0

    service_activation_state vsftpd.service vsftpd.socket
    activation_status=$?
    if [ "$activation_status" -eq 0 ]; then
        SERVICE_FTP_PROVIDERS="$(service_append_word "$SERVICE_FTP_PROVIDERS" vsftpd)"
    elif [ "$activation_status" -eq 2 ]; then
        SERVICE_FTP_UNCERTAIN=1
    fi

    service_activation_state proftpd.service proftpd.socket
    activation_status=$?
    if [ "$activation_status" -eq 0 ]; then
        SERVICE_FTP_PROVIDERS="$(service_append_word "$SERVICE_FTP_PROVIDERS" proftpd)"
    elif [ "$activation_status" -eq 2 ]; then
        SERVICE_FTP_UNCERTAIN=1
    fi

    service_activation_state pure-ftpd.service pure-ftpd.socket
    activation_status=$?
    if [ "$activation_status" -eq 0 ]; then
        SERVICE_FTP_PROVIDERS="$(service_append_word "$SERVICE_FTP_PROVIDERS" pure-ftpd)"
    elif [ "$activation_status" -eq 2 ]; then
        SERVICE_FTP_UNCERTAIN=1
    fi

    service_legacy_enabled '^(ftp|ftps)$' && SERVICE_FTP_PROVIDERS="$(service_append_word "$SERVICE_FTP_PROVIDERS" legacy)"
    [ "$SERVICE_LEGACY_UNCERTAIN" -eq 1 ] && SERVICE_FTP_UNCERTAIN=1

    service_listener_state 21
    listener_status=$?
    if [ "$listener_status" -eq 0 ] && [ -z "$SERVICE_FTP_PROVIDERS" ]; then
        SERVICE_FTP_PROVIDERS="unknown"
    elif [ "$listener_status" -eq 2 ] && [ -z "$SERVICE_FTP_PROVIDERS" ]; then
        SERVICE_FTP_UNCERTAIN=1
    fi
    service_ftp_custom_invocation_state >/dev/null 2>&1
    activation_status=$?
    [ "$activation_status" -eq 0 ] && SERVICE_FTP_UNCERTAIN=1
    [ "$activation_status" -eq 2 ] && SERVICE_FTP_UNCERTAIN=1
    case " $SERVICE_FTP_PROVIDERS " in
        *" proftpd "*) service_proftpd_has_unresolved_includes && SERVICE_FTP_UNCERTAIN=1 ;;
    esac
}

service_postfix_value() {
    local key="$1"
    local postconf_path=""
    local configuration_path=""

    if runtime_enabled; then
        postconf_path="$(trusted_command postconf 2>/dev/null || true)"
        if [ -n "$postconf_path" ]; then
            "$postconf_path" -h "$key" 2>/dev/null
            return $?
        fi
    fi

    configuration_path="$(fs_path /etc/postfix/main.cf)"
    [ -r "$configuration_path" ] || return 1
    awk -v target="$key" '
        function flush() {
            line=record
            record=""
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) return
            separator=index(line, "=")
            if (separator == 0) return
            name=substr(line, 1, separator - 1)
            value=substr(line, separator + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (name == target) last=value
        }
        /^[[:space:]]/ && record != "" {record=record " " $0; next}
        {flush(); record=$0}
        END {flush(); if (last != "") print last}
    ' "$configuration_path"
}

service_postfix_mynetworks_are_loopback_only() {
    local networks="$1"

    [ -n "$networks" ] || return 1
    printf '%s\n' "$networks" | awk '
        function ipv4_loopback(value, address_parts, octets, prefix, count, index_value) {
            count=split(value, address_parts, "/")
            if (count > 2) return 0
            count=split(address_parts[1], octets, ".")
            if (count != 4 || octets[1] != 127) return 0
            for (index_value=1; index_value<=4; index_value++) {
                if (octets[index_value] !~ /^[0-9]+$/ || octets[index_value] > 255) return 0
            }
            if (address_parts[2] == "") return 1
            prefix=address_parts[2] + 0
            return address_parts[2] ~ /^[0-9]+$/ && prefix >= 8 && prefix <= 32
        }
        {
            count=split($0, values, /[[:space:],]+/)
            for (index_value=1; index_value<=count; index_value++) {
                value=values[index_value]
                if (value == "") continue
                found=1
                if (value == "::1" || value == "::1/128" ||
                    value == "[::1]" || value == "[::1]/128") continue
                if (value == "::ffff:127.0.0.0/104" ||
                    value == "[::ffff:127.0.0.0]/104") continue
                if (ipv4_loopback(value)) continue
                non_loopback=1
            }
        }
        END {exit(found && !non_loopback ? 0 : 1)}
    '
}

service_detect_mail() {
    local activation_status=1
    local listener_status=1

    SERVICE_MAIL_PROVIDERS=""
    SERVICE_MAIL_UNCERTAIN=0

    service_activation_state postfix.service postfix@-.service
    activation_status=$?
    if [ "$activation_status" -eq 0 ]; then
        SERVICE_MAIL_PROVIDERS="$(service_append_word "$SERVICE_MAIL_PROVIDERS" postfix)"
    elif [ "$activation_status" -eq 2 ]; then
        SERVICE_MAIL_UNCERTAIN=1
    fi

    service_activation_state sendmail.service sendmail.socket
    activation_status=$?
    if [ "$activation_status" -eq 0 ]; then
        SERVICE_MAIL_PROVIDERS="$(service_append_word "$SERVICE_MAIL_PROVIDERS" sendmail)"
    elif [ "$activation_status" -eq 2 ]; then
        SERVICE_MAIL_UNCERTAIN=1
    fi

    service_activation_state exim.service exim4.service exim.socket exim4.socket
    activation_status=$?
    if [ "$activation_status" -eq 0 ]; then
        SERVICE_MAIL_PROVIDERS="$(service_append_word "$SERVICE_MAIL_PROVIDERS" exim)"
    elif [ "$activation_status" -eq 2 ]; then
        SERVICE_MAIL_UNCERTAIN=1
    fi

    service_listener_state 25 465 587
    listener_status=$?
    if [ "$listener_status" -eq 0 ] && [ -z "$SERVICE_MAIL_PROVIDERS" ]; then
        SERVICE_MAIL_PROVIDERS="unknown"
    elif [ "$listener_status" -eq 2 ]; then
        SERVICE_MAIL_UNCERTAIN=1
    fi
    service_units_have_custom_configuration '([[:space:]]-[cC]([^[:space:]]*|$)|/[^ ;}]*(conf|cf)([ ;}]|$))' \
        postfix.service sendmail.service exim.service exim4.service >/dev/null 2>&1
    activation_status=$?
    [ "$activation_status" -eq 0 ] && SERVICE_MAIL_UNCERTAIN=1
    [ "$activation_status" -eq 2 ] && SERVICE_MAIL_UNCERTAIN=1
}

service_sendmail_privacy_options() {
    local configuration_path=""

    configuration_path="$(fs_path /etc/mail/sendmail.cf)"
    [ -r "$configuration_path" ] || return 1
    awk '
        /^[[:space:]]*O([[:space:]]+PrivacyOptions|PrivacyOptions[[:space:]]*=)/ {
            line=$0
            sub(/^[[:space:]]*O[[:space:]]*/, "", line)
            sub(/^PrivacyOptions[[:space:]]*=?[[:space:]]*/, "", line)
            last=line
        }
        END {if (last != "") print last}
    ' "$configuration_path"
}

service_bind_main_configuration() {
    local candidate=""

    if platform_is_debian_family; then
        for candidate in /etc/bind/named.conf /etc/named.conf; do
            candidate="$(fs_path "$candidate")"
            [ -r "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
        done
    elif platform_is_rhel_family; then
        for candidate in /etc/named.conf /etc/bind/named.conf; do
            candidate="$(fs_path "$candidate")"
            [ -r "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
        done
    else
        return 2
    fi
    return 1
}

# This parser accepts the simple KEY=value form used by stock named and snmpd
# EnvironmentFiles. Unsupported quoting or continuation syntax is indeterminate
# instead of being evaluated as shell code.
service_systemd_environment_file_value() {
    local physical_path="$1"
    local key="$2"

    [ -r "$physical_path" ] || return 1
    awk -v target="$key" '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^[#;]/) next
            if (line ~ /\\$/ || line ~ /^export[[:space:]]/) {invalid=1; next}
            separator=index(line, "=")
            if (separator == 0) next
            name=substr(line, 1, separator - 1)
            value=substr(line, separator + 1)
            gsub(/[[:space:]]+$/, "", name)
            if (name != target) next
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (value ~ /^"[^"\\]*"$/ || value ~ /^\047[^\047\\]*\047$/) {
                value=substr(value, 2, length(value) - 2)
            } else if (value ~ /["\047\\]/) {
                invalid=1
            }
            last=value
            found=1
        }
        END {
            if (invalid) exit 2
            if (!found) exit 1
            print last
        }
    ' "$physical_path"
}

service_bind_arguments_are_standard() {
    local arguments="$1"
    local allowed_configuration="$2"

    printf '%s\n' "$arguments" | awk -v allowed_configuration="$allowed_configuration" '
        {
            executable=$1
            sub(/^.*\//, "", executable)
            if (executable !~ /^(named|named-pkcs11|named-sdb)$/) unsafe=1
            for (index_value=1; index_value<=NF; index_value++) {
                value=$index_value
                gsub(/^[{(]+|[;})]+$/, "", value)
                if (value ~ /\$/) unsafe=1
                if (value == "-t" || value ~ /^-t./) unsafe=1
                if (value == "-c") {
                    index_value++
                    configuration=$index_value
                    gsub(/^[{(]+|[;})]+$/, "", configuration)
                    if (configuration != allowed_configuration) unsafe=1
                } else if (value ~ /^-c./) {
                    configuration=value
                    sub(/^-c/, "", configuration)
                    if (configuration != allowed_configuration) unsafe=1
                }
            }
        }
        END {exit(unsafe ? 1 : 0)}
    '
}

# Stock EL BIND units expand NAMEDCONF and OPTIONS from an EnvironmentFile.
# Reading the live process argv observes those expansions without evaluating a
# configuration file as shell code.
service_bind_custom_invocation_state() {
    local systemctl_path=""
    local unit=""
    local properties=""
    local load_state=""
    local active_state=""
    local unit_file_state=""
    local main_pid=""
    local arguments=""
    local exec_start=""
    local environment_line=""
    local environment_files=""
    local environment_path=""
    local physical_environment_path=""
    local environment_value=""
    local environment_status=1
    local named_configuration=""
    local named_options=""
    local command_status=0
    local saw_relevant_unit=0
    local main_configuration=""
    local allowed_configuration=""
    local manager_status=0

    runtime_enabled || return 2
    if declare -F runtime_systemd_manager_state >/dev/null 2>&1; then
        runtime_systemd_manager_state || manager_status=$?
        [ "$manager_status" -ne 1 ] || return 1
    fi
    systemctl_path="$(trusted_command systemctl)" || return 2
    main_configuration="$(service_bind_main_configuration 2>/dev/null || true)"
    [ -n "$main_configuration" ] || return 2
    allowed_configuration="$(display_path "$main_configuration")"

    for unit in \
        named.service named-chroot.service named-pkcs11.service \
        named-sdb.service named-sdb-chroot.service bind9.service; do
        if [ "${SCAN_EPOCH_ACTIVE:-0}" -eq 1 ]; then
            systemd_epoch_properties_into "$unit" properties || return 2
            command_status="$SYSTEMD_PROPERTIES_COMMAND_STATUS"
            systemd_fact_value_into "$properties" LoadState load_state || load_state=""
        else
            properties="$($systemctl_path show "$unit" \
                -p LoadState -p ActiveState -p UnitFileState -p MainPID \
                -p ExecStart -p Environment -p EnvironmentFiles --no-pager 2>/dev/null)" || command_status=$?
            load_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "LoadState" {print $2; exit}')"
        fi
        if [ "$command_status" -ne 0 ] && [ "$load_state" != "not-found" ]; then
            return 2
        fi
        command_status=0
        [ -n "$load_state" ] && [ "$load_state" != "not-found" ] || continue

        if [ "${SCAN_EPOCH_ACTIVE:-0}" -eq 1 ]; then
            systemd_fact_value_into "$properties" ActiveState active_state || active_state=""
            systemd_fact_value_into "$properties" UnitFileState unit_file_state || unit_file_state=""
        else
            active_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "ActiveState" {print $2; exit}')"
            unit_file_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "UnitFileState" {print $2; exit}')"
        fi
        case "$active_state" in
            active|activating|reloading) ;;
            *)
                case "$unit_file_state" in enabled|enabled-runtime) ;; *) continue ;; esac
                ;;
        esac
        saw_relevant_unit=1

        if [ "${SCAN_EPOCH_ACTIVE:-0}" -eq 1 ]; then
            systemd_fact_value_into "$properties" MainPID main_pid || main_pid=""
        else
            main_pid="$(printf '%s\n' "$properties" | awk -F= '$1 == "MainPID" {print $2; exit}')"
        fi
        case "$main_pid" in
            ''|0|*[!0-9]*) ;;
            *)
                [ -r "/proc/$main_pid/cmdline" ] || return 2
                arguments="$(tr '\000' ' ' < "/proc/$main_pid/cmdline" 2>/dev/null)" || return 2
                ;;
        esac

        if [ -z "$arguments" ]; then
            named_configuration="$allowed_configuration"
            named_options=""
            environment_files="$(printf '%s\n' "$properties" | awk -F= '$1 == "EnvironmentFiles" {print substr($0,index($0,"=")+1); exit}')"
            while IFS= read -r environment_path; do
                [ -n "$environment_path" ] || continue
                environment_path="${environment_path#-}"
                physical_environment_path="$(fs_path "$environment_path" 2>/dev/null || true)"
                [ -r "$physical_environment_path" ] || return 2
                environment_value="$(service_systemd_environment_file_value "$physical_environment_path" NAMEDCONF 2>/dev/null)"
                environment_status=$?
                [ "$environment_status" -eq 2 ] && return 2
                [ "$environment_status" -eq 0 ] && named_configuration="$environment_value"
                environment_value="$(service_systemd_environment_file_value "$physical_environment_path" OPTIONS 2>/dev/null)"
                environment_status=$?
                [ "$environment_status" -eq 2 ] && return 2
                [ "$environment_status" -eq 0 ] && named_options="$environment_value"
            done <<EOF
$(printf '%s\n' "$environment_files" | grep -Eo -- '-?/[^ ;"]+' || true)
EOF

            environment_line="$(printf '%s\n' "$properties" | awk -F= '$1 == "Environment" {print substr($0,index($0,"=")+1); exit}')"
            if printf '%s\n' "$environment_line" | grep -q 'NAMEDCONF=' && \
                ! printf '%s\n' "$environment_line" | grep -Fq "NAMEDCONF=$allowed_configuration"; then
                return 0
            fi
            if printf '%s\n' "$environment_line" | grep -Eq '(^|[[:space:]"=])(-C|-t)([^A-Za-z0-9]|$)'; then
                return 0
            fi
            if printf '%s\n' "$environment_line" | grep -Eq '(^|[[:space:]"=])-c([^A-Za-z0-9]|$)' && \
                ! printf '%s\n' "$environment_line" | grep -Fq -- "-c $allowed_configuration" && \
                ! printf '%s\n' "$environment_line" | grep -Fq -- "-c$allowed_configuration"; then
                return 0
            fi
            [ "$named_configuration" = "$allowed_configuration" ] || return 0

            exec_start="$(printf '%s\n' "$properties" | awk -F= '$1 == "ExecStart" {print substr($0,index($0,"=")+1); exit}')"
            arguments="$(printf '%s\n' "$exec_start" | sed -nE 's/.*argv\[\]=([^;]*);.*/\1/p')"
            [ -n "$arguments" ] || arguments="$exec_start"
            arguments="${arguments//\$\{NAMEDCONF\}/$named_configuration}"
            arguments="${arguments//\$NAMEDCONF/$named_configuration}"
            arguments="${arguments//\$\{OPTIONS\}/$named_options}"
            arguments="${arguments//\$OPTIONS/$named_options}"
        fi
        [ -n "$arguments" ] || return 2
        service_bind_arguments_are_standard "$arguments" "$allowed_configuration" || return 0
        arguments=""
    done

    [ "$saw_relevant_unit" -eq 1 ] && return 1
    return 2
}

service_bind_version() {
    local command_name=""
    local command_path=""
    local version_output=""
    local parsed_version=""

    runtime_enabled || return 1
    for command_name in named named-pkcs11 named-sdb named-checkconf; do
        command_path="$(trusted_command "$command_name" 2>/dev/null || true)"
        [ -n "$command_path" ] || continue
        version_output="$("$command_path" -v 2>/dev/null || true)"
        parsed_version="$(printf '%s\n' "$version_output" | \
            sed -nE 's/.*BIND[[:space:]]+([0-9]+\.[0-9]+)(\.[0-9]+)?.*/\1/p' | head -n 1)"
        [ -n "$parsed_version" ] || continue
        printf '%s\n' "$parsed_version"
        return 0
    done
    return 1
}

service_bind_version_at_least_9_20() {
    local version="$1"
    local major="${version%%.*}"
    local minor="${version#*.}"

    minor="${minor%%.*}"
    case "$major:$minor" in
        *[!0-9:]*|:|*:) return 1 ;;
    esac
    [ "$major" -gt 9 ] || { [ "$major" -eq 9 ] && [ "$minor" -ge 20 ]; }
}

# The validator expands BIND includes and masks key material before analysis.
service_bind_effective_file() {
    local main_configuration=""
    local output_file=""
    local named_checkconf_path=""
    local candidate=""
    local directory_path=""

    main_configuration="$(service_bind_main_configuration)" || return 1
    output_file="$(new_scratch_file bind-effective)" || return 2

    if runtime_enabled; then
        named_checkconf_path="$(trusted_command named-checkconf 2>/dev/null || true)"
        if [ -n "$named_checkconf_path" ] && \
            "$named_checkconf_path" -p -x "$main_configuration" > "$output_file" 2>/dev/null; then
            printf 'validated\t%s\n' "$output_file"
            return 0
        fi
    fi

    : > "$output_file"
    for candidate in /etc/named.conf /etc/bind/named.conf /etc/bind/named.conf.options /etc/bind/named.conf.local; do
        candidate="$(fs_path "$candidate")"
        [ -r "$candidate" ] && awk '{print}' "$candidate" >> "$output_file"
    done
    for candidate in /etc/bind /etc/named; do
        directory_path="$(fs_path "$candidate")"
        [ -d "$directory_path" ] || continue
        while IFS= read -r candidate; do
            [ -r "$candidate" ] && awk '{print}' "$candidate" >> "$output_file"
        done <<EOF
$(find -P "$directory_path" -maxdepth 2 -type f -name '*.conf' -print 2>/dev/null | LC_ALL=C sort)
EOF
    done
    printf 'static\t%s\n' "$output_file"
}

service_detect_dns() {
    local activation_status=1
    local listener_status=1

    service_activation_state \
        named.service named-chroot.service named-pkcs11.service \
        named-sdb.service named-sdb-chroot.service bind9.service \
        named.socket named-pkcs11.socket named-sdb.socket bind9.socket
    activation_status=$?
    if [ "$activation_status" -eq 0 ]; then
        service_bind_custom_invocation_state >/dev/null 2>&1
        listener_status=$?
        [ "$listener_status" -eq 0 ] && return 2
        [ "$listener_status" -eq 2 ] && return 2
        return 0
    fi

    service_dns_listener_state
    listener_status=$?
    [ "$listener_status" -eq 0 ] && return 2

    if [ "$listener_status" -eq 3 ] && [ "$activation_status" -eq 1 ]; then
        return 1
    fi

    if [ "$activation_status" -eq 2 ] || [ "$listener_status" -eq 2 ]; then
        return 2
    fi
    return 1
}

service_snmp_files() {
    local candidate=""
    local directory_path=""

    for candidate in \
        /etc/snmp/snmpd.conf /etc/snmp/snmpd.local.conf \
        /usr/share/snmp/snmpd.conf /usr/share/snmp/snmpd.local.conf \
        /usr/lib/snmp/snmpd.conf /usr/lib/snmp/snmpd.local.conf \
        /usr/lib64/snmp/snmpd.conf /usr/lib64/snmp/snmpd.local.conf \
        /var/lib/snmp/snmpd.conf /var/lib/snmp/snmpd.local.conf \
        /var/lib/net-snmp/snmpd.conf /var/lib/net-snmp/snmpd.local.conf \
        /root/.snmp/snmpd.conf /root/.snmp/snmpd.local.conf \
        /var/lib/snmp/.snmp/snmpd.conf /var/lib/snmp/.snmp/snmpd.local.conf \
        /var/lib/net-snmp/.snmp/snmpd.conf /var/lib/net-snmp/.snmp/snmpd.local.conf; do
        candidate="$(fs_path "$candidate")"
        [ -r "$candidate" ] && printf '%s\n' "$candidate"
    done
    directory_path="$(fs_path /usr/lib 2>/dev/null || true)"
    if [ -d "$directory_path" ]; then
        find -P "$directory_path" -mindepth 2 -maxdepth 2 -type d -name snmp -path '*-linux-gnu/snmp' \
            -print 2>/dev/null | while IFS= read -r directory_path; do
                for candidate in "$directory_path/snmpd.conf" "$directory_path/snmpd.local.conf"; do
                    [ -r "$candidate" ] && printf '%s\n' "$candidate"
                done
            done
    fi
}

service_snmp_common_file_has_custom_configuration() {
    local configuration_file="$1"

    [ -r "$configuration_file" ] || return 1
    awk '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            lower=tolower(line)
            if (lower ~ /^persistentdir([[:space:]]|$)/ ||
                lower ~ /^(include|includefile|includedir)([[:space:]]|$)/ ||
                lower ~ /^\[snmpd([[:space:]]|\])/) found=1
        }
        END {exit(found ? 0 : 1)}
    ' "$configuration_file"
}

service_snmp_file_has_persistent_override() {
    local configuration_file="$1"

    [ -r "$configuration_file" ] || return 1
    awk '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            lower=tolower(line)
            if (lower ~ /^persistentdir([[:space:]]|$)/ ||
                lower ~ /^\[snmp\][[:space:]]*persistentdir([[:space:]]|$)/) found=1
        }
        END {exit(found ? 0 : 1)}
    ' "$configuration_file"
}

# snmp.conf can relocate persistent state or switch into the snmpd token
# namespace. Those cases require a complete configuration graph before a
# conclusive community or access-control result is possible.
service_snmp_has_custom_persistent_configuration() {
    local candidate=""
    local directory_path=""

    for candidate in \
        /etc/snmp/snmp.conf /etc/snmp/snmp.local.conf \
        /usr/share/snmp/snmp.conf /usr/share/snmp/snmp.local.conf \
        /usr/lib/snmp/snmp.conf /usr/lib/snmp/snmp.local.conf \
        /usr/lib64/snmp/snmp.conf /usr/lib64/snmp/snmp.local.conf \
        /root/.snmp/snmp.conf /root/.snmp/snmp.local.conf \
        /var/lib/snmp/.snmp/snmp.conf /var/lib/snmp/.snmp/snmp.local.conf \
        /var/lib/net-snmp/.snmp/snmp.conf /var/lib/net-snmp/.snmp/snmp.local.conf; do
        candidate="$(fs_path "$candidate" 2>/dev/null || true)"
        service_snmp_common_file_has_custom_configuration "$candidate" && return 0
    done

    directory_path="$(fs_path /usr/lib 2>/dev/null || true)"
    if [ -d "$directory_path" ]; then
        while IFS= read -r directory_path; do
            for candidate in "$directory_path/snmp.conf" "$directory_path/snmp.local.conf"; do
                service_snmp_common_file_has_custom_configuration "$candidate" && return 0
            done
        done <<EOF
$(find -P "$directory_path" -mindepth 2 -maxdepth 2 -type d -name snmp -path '*-linux-gnu/snmp' -print 2>/dev/null)
EOF
    fi

    while IFS= read -r candidate; do
        service_snmp_file_has_persistent_override "$candidate" && return 0
    done <<EOF
$(service_snmp_files | awk '!seen[$0]++')
EOF
    return 1
}

service_snmp_arguments_are_standard() {
    local arguments="$1"

    printf '%s\n' "$arguments" | awk '
        {
            executable=$1
            sub(/^.*\//, "", executable)
            if (executable != "snmpd") unsafe=1
            for (index_value=2; index_value<=NF; index_value++) {
                value=$index_value
                if (value ~ /\$/ || value ~ /^--/ || value == "-C" || value == "-c" || value ~ /^-c./) unsafe=1
            }
        }
        END {exit(unsafe ? 1 : 0)}
    '
}

# Stock EL snmpd units expand OPTIONS from /etc/sysconfig/snmpd. Reading the
# active process argv observes the final expansion and detects custom -c/-C use.
service_snmp_custom_invocation_state() {
    local systemctl_path=""
    local properties=""
    local load_state=""
    local active_state=""
    local unit_file_state=""
    local main_pid=""
    local arguments=""
    local exec_start=""
    local environment_line=""
    local environment_files=""
    local environment_path=""
    local physical_environment_path=""
    local environment_value=""
    local environment_status=1
    local parsed_options=""
    local options_value=""
    local snmpdopts_value=""
    local process_environment=""
    local service_home=""
    local command_status=0
    local manager_status=0

    runtime_enabled || return 2
    if declare -F runtime_systemd_manager_state >/dev/null 2>&1; then
        runtime_systemd_manager_state || manager_status=$?
        [ "$manager_status" -ne 1 ] || return 1
    fi
    systemctl_path="$(trusted_command systemctl)" || return 2
    if [ "${SCAN_EPOCH_ACTIVE:-0}" -eq 1 ]; then
        systemd_epoch_properties_into snmpd.service properties || return 2
        command_status="$SYSTEMD_PROPERTIES_COMMAND_STATUS"
        systemd_fact_value_into "$properties" LoadState load_state || load_state=""
    else
        properties="$($systemctl_path show snmpd.service \
            -p LoadState -p ActiveState -p UnitFileState -p MainPID \
            -p ExecStart -p Environment -p EnvironmentFiles --no-pager 2>/dev/null)" || command_status=$?
        load_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "LoadState" {print $2; exit}')"
    fi
    if [ "$command_status" -ne 0 ] && [ "$load_state" != "not-found" ]; then
        return 2
    fi
    [ -n "$load_state" ] && [ "$load_state" != "not-found" ] || return 2
    if [ "${SCAN_EPOCH_ACTIVE:-0}" -eq 1 ]; then
        systemd_fact_value_into "$properties" ActiveState active_state || active_state=""
        systemd_fact_value_into "$properties" UnitFileState unit_file_state || unit_file_state=""
    else
        active_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "ActiveState" {print $2; exit}')"
        unit_file_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "UnitFileState" {print $2; exit}')"
    fi
    case "$active_state" in
        active|activating|reloading) ;;
        *)
            case "$unit_file_state" in enabled|enabled-runtime) ;; *) return 2 ;; esac
            ;;
    esac
    if [ "${SCAN_EPOCH_ACTIVE:-0}" -eq 1 ]; then
        systemd_fact_value_into "$properties" MainPID main_pid || main_pid=""
    else
        main_pid="$(printf '%s\n' "$properties" | awk -F= '$1 == "MainPID" {print $2; exit}')"
    fi
    case "$main_pid" in
        ''|0|*[!0-9]*) ;;
        *)
            [ -r "/proc/$main_pid/cmdline" ] || return 2
            arguments="$(tr '\000' ' ' < "/proc/$main_pid/cmdline" 2>/dev/null)" || return 2
            [ -r "/proc/$main_pid/environ" ] || return 2
            process_environment="$(tr '\000' '\n' < "/proc/$main_pid/environ" 2>/dev/null)" || return 2
            if printf '%s\n' "$process_environment" | \
                grep -Eq '^SNMPCONFPATH=|^SNMP_PERSISTENT_(FILE|DIR)='; then
                return 0
            fi
            service_home="$(printf '%s\n' "$process_environment" | awk -F= '$1 == "HOME" {print substr($0,index($0,"=")+1); exit}')"
            case "$service_home" in
                ''|/|/root|/var/lib/snmp|/var/lib/net-snmp) ;;
                *) return 0 ;;
            esac
            ;;
    esac

    if [ -z "$arguments" ]; then
        environment_files="$(printf '%s\n' "$properties" | awk -F= '$1 == "EnvironmentFiles" {print substr($0,index($0,"=")+1); exit}')"
        while IFS= read -r environment_path; do
            [ -n "$environment_path" ] || continue
            environment_path="${environment_path#-}"
            physical_environment_path="$(fs_path "$environment_path" 2>/dev/null || true)"
            [ -r "$physical_environment_path" ] || return 2
            for environment_value in OPTIONS SNMPDOPTS; do
                parsed_options="$(service_systemd_environment_file_value \
                    "$physical_environment_path" "$environment_value" 2>/dev/null)"
                environment_status=$?
                [ "$environment_status" -eq 2 ] && return 2
                if [ "$environment_status" -eq 0 ]; then
                    case "$environment_value" in
                        OPTIONS) options_value="$parsed_options" ;;
                        SNMPDOPTS) snmpdopts_value="$parsed_options" ;;
                    esac
                fi
            done
            service_home="$(service_systemd_environment_file_value \
                "$physical_environment_path" HOME 2>/dev/null)"
            environment_status=$?
            [ "$environment_status" -eq 2 ] && return 2
            if [ "$environment_status" -eq 0 ]; then
                case "$service_home" in
                    /|/root|/var/lib/snmp|/var/lib/net-snmp) ;;
                    *) return 0 ;;
                esac
            fi
            for environment_value in SNMP_PERSISTENT_FILE SNMP_PERSISTENT_DIR; do
                service_systemd_environment_file_value \
                    "$physical_environment_path" "$environment_value" >/dev/null 2>&1
                environment_status=$?
                [ "$environment_status" -eq 2 ] && return 2
                [ "$environment_status" -eq 0 ] && return 0
            done
        done <<EOF
$(printf '%s\n' "$environment_files" | grep -Eo -- '-?/[^ ;"]+' || true)
EOF

        environment_line="$(printf '%s\n' "$properties" | awk -F= '$1 == "Environment" {print substr($0,index($0,"=")+1); exit}')"
        printf '%s\n' "$environment_line" | \
            grep -Eq 'SNMPCONFPATH=|SNMP_PERSISTENT_(FILE|DIR)=' && return 0
        if printf '%s\n' "$environment_line" | grep -q 'HOME=' && \
            ! printf '%s\n' "$environment_line" | grep -Eq "HOME=(/|/root|/var/lib/snmp|/var/lib/net-snmp)([[:space:]\"']|$)"; then
            return 0
        fi
        if printf '%s\n' "$environment_line" | grep -Eq '(^|[[:space:]"=])(-C|-c)([^A-Za-z0-9]|$)'; then
            return 0
        fi
        printf '%s\n' "$environment_line" | grep -Eq '(^|[[:space:]"=])--[A-Za-z]' && return 0

        exec_start="$(printf '%s\n' "$properties" | awk -F= '$1 == "ExecStart" {print substr($0,index($0,"=")+1); exit}')"
        arguments="$(printf '%s\n' "$exec_start" | sed -nE 's/.*argv\[\]=([^;]*);.*/\1/p')"
        [ -n "$arguments" ] || arguments="$exec_start"
        arguments="${arguments//\$\{OPTIONS\}/$options_value}"
        arguments="${arguments//\$OPTIONS/$options_value}"
        arguments="${arguments//\$\{SNMPDOPTS\}/$snmpdopts_value}"
        arguments="${arguments//\$SNMPDOPTS/$snmpdopts_value}"
    fi
    [ -n "$arguments" ] || return 2
    service_snmp_arguments_are_standard "$arguments" || return 0
    service_snmp_has_custom_persistent_configuration && return 0
    return 1
}

service_detect_snmp() {
    local activation_status=1
    local listener_status=1

    SERVICE_SNMP_CONFIG_UNCERTAIN=0
    SERVICE_SNMP_ENDPOINT_ACTIVE=0
    service_activation_state snmpd.service snmpd.socket snmptrapd.service snmptrapd.socket
    activation_status=$?
    if [ "$activation_status" -eq 0 ]; then
        SERVICE_SNMP_ENDPOINT_ACTIVE=1
        service_snmp_custom_invocation_state >/dev/null 2>&1
        listener_status=$?
        [ "$listener_status" -eq 0 ] && SERVICE_SNMP_CONFIG_UNCERTAIN=1
        [ "$listener_status" -eq 2 ] && SERVICE_SNMP_CONFIG_UNCERTAIN=1
        return 0
    fi

    service_listener_state 161 162
    listener_status=$?
    if [ "$listener_status" -eq 0 ]; then
        SERVICE_SNMP_ENDPOINT_ACTIVE=1
        return 2
    fi

    if [ "$activation_status" -eq 2 ] || [ "$listener_status" -eq 2 ]; then
        return 2
    fi
    return 1
}

service_warning_file_state() {
    local physical_path="$1"
    local grep_status=0

    [ -f "$physical_path" ] && [ -r "$physical_path" ] || return 2
    [ -s "$physical_path" ] || return 1
    grep -Eiq \
        'authori[sz]ed|unauthori[sz]ed|prohibit|monitor|security notice|warning|인가|비인가|금지|모니터링|보안|경고|접근' \
        "$physical_path" 2>/dev/null || grep_status=$?
    [ "$grep_status" -ne 0 ] || return 0
    [ "$grep_status" -ne 2 ] || return 2
    grep_status=0
    grep -Eiq \
        '(^|[^[:alpha:]])(vsftpd|proftpd|pure-ftpd|debian|ubuntu|rhel|red[[:space:]]+hat|almalinux|rocky|oracle[[:space:]]+linux|centos|linux[[:space:]]+mint|pop!?_?os|zorin|elementary|kde[[:space:]]+neon|version|hostname|kernel)([^[:alpha:]]|$)' \
        "$physical_path" 2>/dev/null || grep_status=$?
    [ "$grep_status" -ne 0 ] || return 1
    [ "$grep_status" -ne 2 ] || return 2
    return 2
}

service_login_warning_value_state() {
    local value="$1"
    local state=0

    service_banner_value_state "$value" || state=$?
    [ "$state" -ne 0 ] || return 0
    [ "$state" -ne 1 ] || return 1
    service_banner_discloses_identity "$value" && return 1
    return 2
}

service_nfs_state() {
    local activation_status=1
    local listener_status=1

    service_activation_state \
        nfs-server.service nfs.service nfs-kernel-server.service nfs-server.socket \
        nfs-mountd.service
    activation_status=$?
    [ "$activation_status" -eq 0 ] && return 0

    service_listener_state 2049
    listener_status=$?
    [ "$listener_status" -eq 0 ] && return 0

    if [ "$activation_status" -eq 2 ] || [ "$listener_status" -eq 2 ]; then
        return 2
    fi
    return 1
}

service_samba_state() {
    local activation_status=1
    local listener_status=1

    service_activation_state smb.service smbd.service samba.service samba-ad-dc.service smb.socket smbd.socket
    activation_status=$?
    if [ "$activation_status" -eq 0 ]; then
        service_units_have_custom_configuration '([[:space:]]-s([^[:space:]]*|$)|--configfile([=[:space:]]|$))' \
            smb.service smbd.service samba.service samba-ad-dc.service >/dev/null 2>&1
        listener_status=$?
        [ "$listener_status" -eq 0 ] && return 2
        [ "$listener_status" -eq 2 ] && return 2
        return 0
    fi

    service_listener_state 139 445
    listener_status=$?
    [ "$listener_status" -eq 0 ] && return 2

    if [ "$activation_status" -eq 2 ] || [ "$listener_status" -eq 2 ]; then
        return 2
    fi
    return 1
}

service_ftp_anonymous_state() {
    local provider=""
    local configuration_path=""
    local anonymous_value=""
    local checked_count=0
    local unresolved_count=0
    local configuration_file=""

    for provider in $SERVICE_FTP_PROVIDERS; do
        case "$provider" in
            vsftpd)
                configuration_path="$(service_vsftpd_configuration 2>/dev/null || true)"
                if [ -z "$configuration_path" ]; then
                    unresolved_count=$((unresolved_count + 1))
                    continue
                fi
                anonymous_value="$(service_read_simple_value anonymous_enable "$configuration_path" 2>/dev/null || true)"
                checked_count=$((checked_count + 1))
                case "$(printf '%s' "$anonymous_value" | tr '[:lower:]' '[:upper:]')" in
                    YES|TRUE|1) return 0 ;;
                    NO|FALSE|0) ;;
                    *) unresolved_count=$((unresolved_count + 1)) ;;
                esac
                ;;
            proftpd)
                checked_count=$((checked_count + 1))
                configuration_path="$(service_proftpd_files | awk '!seen[$0]++')"
                if [ -z "$configuration_path" ]; then
                    unresolved_count=$((unresolved_count + 1))
                    continue
                fi
                while IFS= read -r configuration_file; do
                    [ -r "$configuration_file" ] || continue
                    if service_file_has_active_entry "$configuration_file" '^[[:space:]]*<Anonymous([[:space:]>]|$)'; then
                        return 0
                    fi
                done <<EOF
$configuration_path
EOF
                ;;
            legacy|pure-ftpd|unknown)
                if [ "$provider" = "legacy" ] && \
                    awk -F: '$1 == "ftp" || $1 == "anonymous" {found=1} END {exit(found ? 0 : 1)}' \
                        "$(fs_path /etc/passwd)" 2>/dev/null; then
                    return 0
                fi
                unresolved_count=$((unresolved_count + 1))
                ;;
        esac
    done

    [ "$unresolved_count" -gt 0 ] && return 2
    [ "$checked_count" -gt 0 ] && return 1
    return 3
}

service_samba_anonymous_state() {
    local configuration_path=""
    local testparm_path=""
    local effective_configuration=""

    configuration_path="$(fs_path /etc/samba/smb.conf)"
    [ -r "$configuration_path" ] || return 2

    if runtime_enabled; then
        testparm_path="$(trusted_command testparm 2>/dev/null || true)"
        if [ -n "$testparm_path" ]; then
            effective_configuration="$($testparm_path -s --suppress-prompt "$configuration_path" 2>/dev/null)" || return 2
            if printf '%s\n' "$effective_configuration" | awk -F= '
                {
                    name=$1
                    value=substr($0,index($0,"=")+1)
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                    if ((tolower(name) == "guest ok" || tolower(name) == "public") && tolower(value) == "yes") found=1
                }
                END {exit(found ? 0 : 1)}
            '; then
                return 0
            fi
            return 1
        fi
    fi

    if service_file_has_active_entry "$configuration_path" \
        '^[[:space:]]*(guest[[:space:]]+ok|public)[[:space:]]*=[[:space:]]*(yes|true|1)([[:space:]]|$)'; then
        return 0
    fi
    return 2
}

service_r_command_usage_state() {
    local passwd_path=""
    local trust_path=""
    local home_path=""
    local saw_unreadable=0

    trust_path="$(fs_path /etc/hosts.equiv 2>/dev/null || true)"
    if [ -e "$trust_path" ]; then
        [ -r "$trust_path" ] || saw_unreadable=1
        service_file_has_active_entry "$trust_path" '.*' && return 0
    fi

    passwd_path="$(fs_path /etc/passwd 2>/dev/null || true)"
    [ -r "$passwd_path" ] || return 2
    while IFS=: read -r _ _ _ _ _ home_path _; do
        case "$home_path" in /*) ;; *) continue ;; esac
        trust_path="$(fs_path "${home_path%/}/.rhosts" 2>/dev/null || true)"
        [ -n "$trust_path" ] || { saw_unreadable=1; continue; }
        [ -e "$trust_path" ] || continue
        [ -r "$trust_path" ] || { saw_unreadable=1; continue; }
        service_file_has_active_entry "$trust_path" '.*' && return 0
    done < "$passwd_path"

    [ "$saw_unreadable" -eq 1 ] && return 2
    return 1
}

check_u_34() {
    local activation_status=1
    local listener_status=1
    local legacy_active=0
    local evidence=""

    service_activation_state finger.service finger.socket fingerd.service fingerd.socket finger@.service
    activation_status=$?
    evidence="$SERVICE_ACTIVATION_EVIDENCE"
    service_legacy_enabled '^finger$' && legacy_active=1
    local legacy_uncertain="$SERVICE_LEGACY_UNCERTAIN"
    service_listener_state 79
    listener_status=$?

    evidence="${evidence}legacy_activation=${legacy_active}\nlistener_port_79=$([ "$listener_status" -eq 0 ] && printf active || printf inactive_or_unavailable)"
    if [ "$activation_status" -eq 0 ] || [ "$legacy_active" -eq 1 ] || [ "$listener_status" -eq 0 ]; then
        set_result VULNERABLE "Finger 서비스의 활성화 경로가 확인됐습니다." "$evidence"
    elif [ "$activation_status" -eq 2 ] || [ "$listener_status" -eq 2 ] || [ "$legacy_uncertain" -eq 1 ]; then
        set_result MANUAL "오프라인 또는 제한된 런타임에서는 Finger 활성 상태를 확정할 수 없습니다." "$evidence" true runtime
    else
        set_result GOOD "systemd, inetd/xinetd와 수신 포트에서 Finger 서비스가 비활성 상태입니다." "$evidence"
    fi
}

check_u_35() {
    local ftp_state=3
    local nfs_state=1
    local samba_state=1
    local anonymous_state=1
    local active_count=0
    local unresolved_count=0
    local vulnerable_count=0
    local evidence=""

    service_detect_ftp
    if [ -n "$SERVICE_FTP_PROVIDERS" ]; then
        active_count=$((active_count + 1))
        service_ftp_anonymous_state
        ftp_state=$?
        [ "$ftp_state" -eq 0 ] && vulnerable_count=$((vulnerable_count + 1))
        [ "$ftp_state" -eq 2 ] || [ "$ftp_state" -eq 3 ] && unresolved_count=$((unresolved_count + 1))
        [ "$SERVICE_FTP_UNCERTAIN" -eq 1 ] && unresolved_count=$((unresolved_count + 1))
    elif [ "$SERVICE_FTP_UNCERTAIN" -eq 1 ]; then
        unresolved_count=$((unresolved_count + 1))
    fi

    service_nfs_state
    nfs_state=$?
    if [ "$nfs_state" -eq 0 ]; then
        active_count=$((active_count + 1))
        service_static_exports_have_anonymous_mapping && vulnerable_count=$((vulnerable_count + 1))
        unresolved_count=$((unresolved_count + 1))
    elif [ "$nfs_state" -eq 2 ]; then
        unresolved_count=$((unresolved_count + 1))
    fi

    service_samba_state
    samba_state=$?
    if [ "$samba_state" -eq 0 ]; then
        active_count=$((active_count + 1))
        service_samba_anonymous_state
        anonymous_state=$?
        [ "$anonymous_state" -eq 0 ] && vulnerable_count=$((vulnerable_count + 1))
        [ "$anonymous_state" -eq 2 ] && unresolved_count=$((unresolved_count + 1))
    elif [ "$samba_state" -eq 2 ]; then
        unresolved_count=$((unresolved_count + 1))
    fi

    evidence="active_share_providers=${active_count}\nunresolved_providers=${unresolved_count}\nanonymous_access_findings=${vulnerable_count}"
    if [ "$vulnerable_count" -gt 0 ]; then
        set_result VULNERABLE "활성 공유 서비스에서 익명 또는 게스트 접근 설정을 확인했습니다." "$evidence"
    elif [ "$unresolved_count" -gt 0 ]; then
        set_result MANUAL "공유 서비스의 유효 설정 또는 외부 접근 경로를 모두 확정할 수 없습니다." "$evidence" true technical
    elif [ "$active_count" -eq 0 ]; then
        set_result NOT_APPLICABLE "활성 FTP, NFS 또는 Samba 공유 서비스를 확인하지 못했습니다." "$evidence" false
    else
        set_result GOOD "활성 공유 서비스의 로컬 유효 설정에서 익명 접근이 제한되어 있습니다." "$evidence"
    fi
}

check_u_36() {
    local activation_status=1
    local listener_status=1
    local rsync_activation_status=1
    local rsync_listener_status=1
    local usage_status=1
    local legacy_active=0
    local rsync_legacy_active=0
    local legacy_uncertain=0
    local rsync_legacy_uncertain=0
    local evidence=""

    service_activation_state \
        rlogin.service rlogin.socket rlogin@.service \
        rsh.service rsh.socket rsh@.service \
        rexec.service rexec.socket rexec@.service
    activation_status=$?
    evidence="$SERVICE_ACTIVATION_EVIDENCE"
    service_legacy_enabled '^(login|rlogin|shell|rsh|exec|rexec)$' && legacy_active=1
    legacy_uncertain="$SERVICE_LEGACY_UNCERTAIN"
    service_listener_state 512 513 514
    listener_status=$?

    service_activation_state rsync.service rsync.socket rsyncd.service rsyncd.socket
    rsync_activation_status=$?
    service_legacy_enabled '^rsync$' && rsync_legacy_active=1
    rsync_legacy_uncertain="$SERVICE_LEGACY_UNCERTAIN"
    service_listener_state 873
    rsync_listener_status=$?

    service_r_command_usage_state
    usage_status=$?

    evidence="${evidence}legacy_activation=${legacy_active}\nr_service_listener=$([ "$listener_status" -eq 0 ] && printf active || printf inactive_or_unavailable)\ntrust_file_usage_state=${usage_status}\nrsync_activation_state=${rsync_activation_status}\nrsync_legacy_activation=${rsync_legacy_active}\nrsync_listener=$([ "$rsync_listener_status" -eq 0 ] && printf active || printf inactive_or_unavailable)"
    if [ "$activation_status" -eq 0 ] || [ "$legacy_active" -eq 1 ] || [ "$listener_status" -eq 0 ]; then
        if [ "$usage_status" -eq 1 ]; then
            set_result VULNERABLE "사용 근거가 없는 rlogin, rsh 또는 rexec 활성화 경로가 확인됐습니다." "$evidence"
        else
            set_result MANUAL "r 계열 서비스가 활성 상태이며 백업·클러스터링 용도의 필요성을 확인해야 합니다." "$evidence" true policy
        fi
    elif [ "$rsync_activation_status" -eq 0 ] || [ "$rsync_legacy_active" -eq 1 ] || \
        [ "$rsync_listener_status" -eq 0 ]; then
        set_result MANUAL "rsync daemon이 활성 상태이며 가이드의 r-command 범위와 업무 필요성을 확인해야 합니다." "$evidence" true policy
    elif [ "$activation_status" -eq 2 ] || [ "$listener_status" -eq 2 ] || [ "$legacy_uncertain" -eq 1 ]; then
        set_result MANUAL "r 계열 서비스의 실제 활성 상태를 확정할 수 없습니다." "$evidence" true runtime
    elif [ "$rsync_activation_status" -eq 2 ] || [ "$rsync_listener_status" -eq 2 ] || \
        [ "$rsync_legacy_uncertain" -eq 1 ]; then
        set_result MANUAL "rsync daemon의 실제 활성 상태를 확정할 수 없습니다." "$evidence" true runtime
    else
        set_result GOOD "r 계열 서비스가 systemd, inetd/xinetd와 수신 포트에서 비활성 상태입니다." "$evidence"
    fi
}

check_u_37() {
    local command_path=""
    local logical_path=""
    local owner=""
    local mode=""
    local list_file=""
    local candidate_file=""
    local related_file=""
    local resolved_file=""
    local checked_commands=0
    local checked_files=0
    local violations=0
    local stat_failures=0
    local scan_failures=0
    local evidence=""
    local path_status=0

    for logical_path in /usr/bin/crontab /usr/bin/at; do
        path_status=0
        command_path="$(fs_path "$logical_path" 2>/dev/null)" || path_status=$?
        if [ "$path_status" -ne 0 ]; then
            scan_failures=$((scan_failures + 1))
            continue
        elif [ ! -e "$command_path" ]; then
            continue
        elif [ ! -f "$command_path" ]; then
            scan_failures=$((scan_failures + 1))
            continue
        fi
        checked_commands=$((checked_commands + 1))
        owner="$(stat_owner "$command_path" 2>/dev/null || true)"
        mode="$(stat_mode "$command_path" 2>/dev/null || true)"
        if [ -z "$owner" ] || [ -z "$mode" ]; then
            stat_failures=$((stat_failures + 1))
            [ "$stat_failures" -le 20 ] && scanner_append_evidence evidence \
                "$(scanner_evidence_path "$command_path"):owner=${owner:-unknown},mode=${mode:-unknown},metadata_error=true"
        elif [ "$owner" != "root" ] || ! mode_is_at_most "$mode" 750 || service_mode_has_setuid "$mode"; then
            violations=$((violations + 1))
            [ "$violations" -le 20 ] && scanner_append_evidence evidence \
                "$(scanner_evidence_path "$command_path"):owner=${owner},mode=${mode},kind=command"
        fi
    done

    list_file="$(new_scratch_file u37-files)" || {
        set_result ERROR "cron 및 at 파일 목록을 안전하게 만들 수 없습니다." ""
        return
    }
    candidate_file="$(new_scratch_file u37-candidates)" || {
        set_result ERROR "cron 및 at 파일 목록을 안전하게 만들 수 없습니다." ""
        return
    }
    : > "$list_file"
    for logical_path in /etc/crontab /etc/anacrontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
        path_status=0
        related_file="$(fs_path "$logical_path" 2>/dev/null)" || path_status=$?
        if [ "$path_status" -ne 0 ]; then
            scan_failures=$((scan_failures + 1))
        elif [ -f "$related_file" ]; then
            printf '%s\0' "$related_file" >> "$list_file" || scan_failures=$((scan_failures + 1))
        elif [ -e "$related_file" ]; then
            scan_failures=$((scan_failures + 1))
        fi
    done
    for logical_path in \
        /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
        /var/spool/cron /var/spool/cron/crontabs /var/spool/cron/atjobs /var/spool/at /var/spool/anacron; do
        path_status=0
        related_file="$(fs_path "$logical_path" 2>/dev/null)" || path_status=$?
        if [ "$path_status" -ne 0 ]; then
            scan_failures=$((scan_failures + 1))
        elif [ -d "$related_file" ]; then
            : > "$candidate_file" || {
                scan_failures=$((scan_failures + 1))
                continue
            }
            if ! find -P "$related_file" -xdev \( -type f -o -type l \) -print0 \
                > "$candidate_file" 2>/dev/null; then
                scan_failures=$((scan_failures + 1))
                continue
            fi
            while IFS= read -r -d '' resolved_file; do
                related_file=""
                resolve_rooted_read_path_into "$resolved_file" related_file 2>/dev/null || {
                    scan_failures=$((scan_failures + 1))
                    continue
                }
                printf '%s\0' "$related_file" >> "$list_file" || \
                    scan_failures=$((scan_failures + 1))
            done < "$candidate_file"
        elif [ -e "$related_file" ]; then
            scan_failures=$((scan_failures + 1))
        fi
    done

    while IFS= read -r -d '' related_file; do
        checked_files=$((checked_files + 1))
        owner="$(stat_owner "$related_file" 2>/dev/null || true)"
        mode="$(stat_mode "$related_file" 2>/dev/null || true)"
        if [ -z "$owner" ] || [ -z "$mode" ]; then
            stat_failures=$((stat_failures + 1))
            [ "$stat_failures" -le 20 ] && scanner_append_evidence evidence \
                "$(scanner_evidence_path "$related_file"):owner=${owner:-unknown},mode=${mode:-unknown},metadata_error=true"
        elif [ "$owner" != "root" ] || ! mode_is_at_most "$mode" 640; then
            violations=$((violations + 1))
            [ "$violations" -le 20 ] && scanner_append_evidence evidence \
                "$(scanner_evidence_path "$related_file"):owner=${owner},mode=${mode},kind=related_file"
        fi
    done < "$list_file"

    evidence="checked_commands=${checked_commands}\nchecked_related_files=${checked_files}\nviolations=${violations}\nstat_failures=${stat_failures}\nscan_failures=${scan_failures}${evidence:+\n${evidence}}"
    if [ "$stat_failures" -gt 0 ] || [ "$scan_failures" -gt 0 ]; then
        set_result ERROR "cron 또는 at 관련 파일의 소유자·권한을 읽지 못했습니다." "$evidence"
    elif [ "$violations" -gt 0 ]; then
        set_result VULNERABLE "crontab 또는 at 실행 파일과 관련 파일이 KISA 소유자·권한 기준을 벗어났습니다." \
            "$evidence" true technical true metadata.u37.v1
    elif [ "$checked_commands" -eq 0 ] && [ "$checked_files" -eq 0 ]; then
        set_result NOT_APPLICABLE "cron 및 at 구성 요소가 설치된 증거를 확인하지 못했습니다." "$evidence" false
    else
        set_result GOOD "crontab 및 at 실행 파일과 관련 파일이 KISA 소유자·권한 기준을 충족합니다." "$evidence"
    fi
}

check_u_38() {
    local activation_status=1
    local listener_status=1
    local auxiliary_activation_status=1
    local auxiliary_listener_status=1
    local dns_status=1
    local snmp_status=1
    local legacy_active=0
    local legacy_uncertain=0
    local auxiliary_active=0
    local auxiliary_unknown=0
    local evidence=""

    service_activation_state \
        echo.service echo.socket echo-stream.socket echo-dgram.socket \
        discard.service discard.socket discard-stream.socket discard-dgram.socket \
        daytime.service daytime.socket daytime-stream.socket daytime-dgram.socket \
        chargen.service chargen.socket chargen-stream.socket chargen-dgram.socket
    activation_status=$?
    evidence="$SERVICE_ACTIVATION_EVIDENCE"
    service_legacy_enabled '^(echo|discard|daytime|chargen)$' && legacy_active=1
    legacy_uncertain="$SERVICE_LEGACY_UNCERTAIN"
    service_listener_state 7 9 13 19
    listener_status=$?

    service_activation_state \
        chronyd.service chrony.service ntp.service ntpd.service \
        ntpd-rs.service ntpsec.service ntpsec.socket
    auxiliary_activation_status=$?
    service_listener_state 123
    auxiliary_listener_status=$?
    if [ "$auxiliary_activation_status" -eq 0 ] || [ "$auxiliary_listener_status" -eq 0 ]; then
        auxiliary_active=$((auxiliary_active + 1))
    elif [ "$auxiliary_activation_status" -eq 2 ] || [ "$auxiliary_listener_status" -eq 2 ]; then
        auxiliary_unknown=$((auxiliary_unknown + 1))
    fi

    service_detect_dns
    dns_status=$?
    [ "$dns_status" -eq 0 ] && auxiliary_active=$((auxiliary_active + 1))
    [ "$dns_status" -eq 2 ] && auxiliary_unknown=$((auxiliary_unknown + 1))

    service_detect_snmp
    snmp_status=$?
    [ "$SERVICE_SNMP_ENDPOINT_ACTIVE" -eq 1 ] && auxiliary_active=$((auxiliary_active + 1))
    [ "$snmp_status" -eq 2 ] && auxiliary_unknown=$((auxiliary_unknown + 1))

    service_detect_mail
    [ -n "$SERVICE_MAIL_PROVIDERS" ] && auxiliary_active=$((auxiliary_active + 1))
    [ "$SERVICE_MAIL_UNCERTAIN" -eq 1 ] && auxiliary_unknown=$((auxiliary_unknown + 1))

    evidence="${evidence}legacy_activation=${legacy_active}\nlegacy_dos_listener=$([ "$listener_status" -eq 0 ] && printf active || printf inactive_or_unavailable)\nauxiliary_service_groups_active=${auxiliary_active}\nauxiliary_service_groups_unknown=${auxiliary_unknown}"
    if [ "$activation_status" -eq 0 ] || [ "$legacy_active" -eq 1 ] || [ "$listener_status" -eq 0 ]; then
        set_result VULNERABLE "echo, discard, daytime 또는 chargen 서비스 활성화 경로가 확인됐습니다." "$evidence"
    elif [ "$auxiliary_active" -gt 0 ]; then
        set_result MANUAL "NTP, DNS, SNMP 또는 SMTP 서비스가 활성 상태이며 업무상 필요 여부를 확인해야 합니다." "$evidence" true policy
    elif [ "$activation_status" -eq 2 ] || [ "$listener_status" -eq 2 ] || [ "$legacy_uncertain" -eq 1 ]; then
        set_result MANUAL "DoS 공격에 취약한 레거시 서비스의 활성 상태를 확정할 수 없습니다." "$evidence" true runtime
    elif [ "$auxiliary_unknown" -gt 0 ]; then
        set_result MANUAL "NTP, DNS, SNMP 또는 SMTP 서비스의 활성 상태를 모두 확정할 수 없습니다." "$evidence" true runtime
    else
        set_result GOOD "가이드가 열거한 DoS 관련 서비스의 활성화 경로를 확인하지 못했습니다." "$evidence"
    fi
}

check_u_39() {
    local nfs_status=1

    service_nfs_state
    nfs_status=$?
    if [ "$nfs_status" -eq 0 ]; then
        set_result MANUAL \
            "NFS 서비스가 활성 상태이며 업무상 필요 여부는 자산 용도와 함께 확인해야 합니다." \
            "nfs_activation=active" true policy
    elif [ "$nfs_status" -eq 2 ]; then
        set_result MANUAL "NFS 서비스의 실제 활성 상태를 확정할 수 없습니다." "nfs_activation=unknown" true runtime
    else
        set_result GOOD "NFS 서비스의 활성화 경로와 수신 포트를 확인하지 못했습니다." "nfs_activation=inactive"
    fi
}

check_u_40() {
    local nfs_status=1
    local configuration_file=""
    local configuration_files=""
    local configuration_status=0
    local owner=""
    local mode=""
    local export_count=0
    local file_count=0
    local permission_violations=0
    local unrestricted_count=0
    local effective_output=""
    local exportfs_path=""
    local runtime_collection_error=0
    local evidence=""

    service_nfs_state
    nfs_status=$?

    configuration_files="$(service_nfs_export_files)" || configuration_status=$?
    if [ "$configuration_status" -ne 0 ]; then
        set_result ERROR "NFS export 구성 경로를 안전하게 수집하지 못했습니다." \
            "nfs_activation=$([ "$nfs_status" -eq 0 ] && printf active || printf inactive_or_unknown)\nconfiguration_collection_error=1"
        return
    fi

    while IFS= read -r configuration_file; do
        [ -r "$configuration_file" ] || continue
        file_count=$((file_count + 1))
        owner="$(stat_owner "$configuration_file" 2>/dev/null || true)"
        mode="$(stat_mode "$configuration_file" 2>/dev/null || true)"
        if [ "$owner" != "root" ] || [ -z "$mode" ] || ! mode_is_at_most "$mode" 644; then
            permission_violations=$((permission_violations + 1))
        fi
    done <<EOF
$configuration_files
EOF

    export_count="$(service_count_static_exports "$configuration_files" | awk '{sum+=$1} END {print sum+0}')"
    service_static_exports_unrestricted "$configuration_files" && unrestricted_count=$((unrestricted_count + 1))

    if runtime_enabled; then
        exportfs_path="$(trusted_command exportfs 2>/dev/null || true)"
        if [ -n "$exportfs_path" ]; then
            effective_output="$($exportfs_path -v 2>/dev/null)" || runtime_collection_error=1
            [ "$runtime_collection_error" -eq 0 ] && export_count=0
            if [ -n "$effective_output" ]; then
                export_count="$(printf '%s\n' "$effective_output" | awk 'NF >= 2 {count++} END {print count+0}')"
                if printf '%s\n' "$effective_output" | awk '
                    NF >= 2 {
                        client=$2
                        sub(/\(.*/, "", client)
                        if (client == "*" || client == "<world>" || client == "0.0.0.0/0" || client == "::/0") unsafe=1
                    }
                    END {exit(unsafe ? 0 : 1)}
                '; then
                    unrestricted_count=$((unrestricted_count + 1))
                fi
            fi
        elif [ "$nfs_status" -eq 0 ]; then
            runtime_collection_error=1
        fi
    fi

    evidence="nfs_activation=$([ "$nfs_status" -eq 0 ] && printf active || printf inactive_or_unknown)\nconfiguration_files=${file_count}\neffective_exports=${export_count}\npermission_violations=${permission_violations}\nunrestricted_exports=${unrestricted_count}\nruntime_collection_error=${runtime_collection_error}"
    if [ "$nfs_status" -eq 0 ] && \
        { [ "$permission_violations" -gt 0 ] || [ "$unrestricted_count" -gt 0 ]; }; then
        set_result VULNERABLE "NFS 설정 파일 권한 또는 export 접근 통제가 KISA 기준을 벗어났습니다." "$evidence"
    elif [ "$runtime_collection_error" -gt 0 ]; then
        set_result ERROR "활성 NFS export의 런타임 테이블을 수집하지 못했습니다." "$evidence"
    elif [ "$nfs_status" -eq 2 ]; then
        set_result MANUAL "NFS 런타임 상태와 유효 export 구성을 확정할 수 없습니다." "$evidence" true runtime
    elif [ "$nfs_status" -ne 0 ] && [ "$export_count" -eq 0 ]; then
        set_result NOT_APPLICABLE "활성 NFS 서비스와 구성된 export를 확인하지 못했습니다." "$evidence" false
    elif [ "$nfs_status" -ne 0 ]; then
        set_result MANUAL "NFS 서비스는 비활성 상태지만 남아 있는 export의 재활성화 가능성을 확인해야 합니다." "$evidence" true policy
    elif [ "$export_count" -eq 0 ]; then
        set_result MANUAL "NFS 서비스는 활성 상태지만 유효 export를 확인하지 못했습니다." "$evidence" true technical
    else
        set_result MANUAL "NFS export 대상이 조직에서 승인한 호스트인지 자산 정책과 대조해야 합니다." "$evidence" true policy
    fi
}

check_u_41() {
    local activation_status=1
    local process_status=1
    local activation_evidence=""
    local evidence=""

    service_activation_state autofs.service automount.service automountd.service
    activation_status=$?
    activation_evidence="$SERVICE_ACTIVATION_EVIDENCE"
    service_named_process_state automount automountd
    process_status=$?
    evidence="${activation_evidence}${SERVICE_NAMED_PROCESS_EVIDENCE}"
    if [ "$activation_status" -eq 0 ] || [ "$process_status" -eq 0 ]; then
        set_result VULNERABLE "automount 또는 autofs 서비스 활성화 경로가 확인됐습니다." "$evidence"
    elif [ "$activation_status" -eq 2 ] || [ "$process_status" -eq 2 ]; then
        set_result MANUAL "automount 또는 autofs의 실제 활성 상태를 확정할 수 없습니다." "$evidence" true runtime
    else
        set_result GOOD "automount와 autofs 서비스가 비활성 상태입니다." "activation=inactive"
    fi
}

check_u_42() {
    local dangerous_status=1
    local general_status=1
    local nisplus_status=1
    local listener_status=1
    local legacy_active=0
    local legacy_uncertain=0
    local nisplus_legacy_active=0
    local nisplus_legacy_uncertain=0
    local dangerous_evidence=""
    local general_evidence=""
    local combined_evidence=""
    local rpcinfo_path=""
    local rpc_output=""
    local nisplus_rpc_active=0
    local process_status=1

    service_activation_state \
        rpc-cmsd.service rpc.cmsd.service \
        rpc-ttdbserver.service rpc.ttdbserver.service \
        rpc-ttdbserverd.service rpc.ttdbserverd.service \
        sadmind.service rpc-sadmind.service rpc.sadmind.service \
        walld.service rpc-walld.service rpc.walld.service \
        sprayd.service rpc-sprayd.service rpc.sprayd.service \
        rstatd.service rpc-rstatd.service rpc.rstatd.service \
        rusersd.service rpc-rusersd.service rpc.rusersd.service \
        rexd.service rpc-rexd.service rpc.rexd.service \
        pcnfsd.service rpc-pcnfsd.service rpc.pcnfsd.service \
        statd.service rpc-statd.service rpc.statd.service rpc-statd-notify.service \
        rpc-ypupdated.service rpc.ypupdated.service ypupdated.service \
        rquotad.service rpc-rquotad.service rpc.rquotad.service \
        kcms-server.service kcms_server.service cachefsd.service
    dangerous_status=$?
    dangerous_evidence="$SERVICE_ACTIVATION_EVIDENCE"
    if runtime_enabled; then
        service_named_process_state \
            rpc.cmsd rpc.ttdbserver rpc.ttdbserverd sadmind rpc.sadmind walld rpc.walld \
            sprayd rpc.sprayd rstatd rpc.rstatd rusersd rpc.rusersd rexd rpc.rexd \
            pcnfsd rpc.pcnfsd statd rpc.statd ypupdated rpc.ypupdated rquotad rpc.rquotad \
            kcms_server cachefsd
        process_status=$?
        [ "$process_status" -eq 0 ] && dangerous_status=0
        [ "$process_status" -ne 2 ] || [ "$dangerous_status" -eq 0 ] || dangerous_status=2
    fi
    service_legacy_enabled '^((rpc\.)?(cmsd|ttdbserverd?|sadmind|walld|sprayd|rstatd|rusersd|rexd|pcnfsd|statd|ypupdated|rquotad)|kcms_server|cachefsd)$' && legacy_active=1
    legacy_uncertain="$SERVICE_LEGACY_UNCERTAIN"

    service_activation_state nisplus.service rpc-nisd.service rpc.nisd.service
    nisplus_status=$?
    if runtime_enabled; then
        service_named_process_state nisd rpc.nisd
        process_status=$?
        [ "$process_status" -eq 0 ] && nisplus_status=0
        [ "$process_status" -ne 2 ] || [ "$nisplus_status" -eq 0 ] || nisplus_status=2
    fi
    service_legacy_enabled '^(rpc\.)?nisd$' && nisplus_legacy_active=1
    nisplus_legacy_uncertain="$SERVICE_LEGACY_UNCERTAIN"

    service_activation_state \
        rpcbind.service rpcbind.socket rpc-gssd.service rpc-svcgssd.service rpc-idmapd.service
    general_status=$?
    general_evidence="$SERVICE_ACTIVATION_EVIDENCE"
    if runtime_enabled; then
        service_named_process_state rpcbind
        process_status=$?
        [ "$process_status" -eq 0 ] && general_status=0
        [ "$process_status" -ne 2 ] || [ "$general_status" -eq 0 ] || general_status=2
    fi
    service_listener_state 111
    listener_status=$?
    if runtime_enabled; then
        rpcinfo_path="$(trusted_command rpcinfo 2>/dev/null || true)"
        if [ -n "$rpcinfo_path" ]; then
            rpc_output="$($rpcinfo_path -p localhost 2>/dev/null || true)"
            if printf '%s\n' "$rpc_output" | awk '
                $NF ~ /^(rpc\.)?(cmsd|ttdbserverd?|sadmind|walld|sprayd|rstatd|rusersd|rexd|pcnfsd|statd|ypupdated|rquotad)$/ ||
                $NF ~ /^(kcms_server|cachefsd)$/ {found=1}
                END {exit(found ? 0 : 1)}
            '; then
                dangerous_status=0
            fi
            if printf '%s\n' "$rpc_output" | awk '$NF ~ /^(nisd|rpc\.nisd)$/ {found=1} END {exit(found ? 0 : 1)}'; then
                nisplus_rpc_active=1
            fi
        fi
    fi
    service_unique_evidence_lines_into combined_evidence "$dangerous_evidence" "$general_evidence"

    if [ "$dangerous_status" -eq 0 ] || [ "$legacy_active" -eq 1 ]; then
        set_result VULNERABLE \
            "취약한 레거시 RPC 서비스의 활성화 경로가 확인됐습니다." \
            "${dangerous_evidence}legacy_dangerous_rpc=${legacy_active}"
    elif [ "$nisplus_status" -eq 0 ] || [ "$nisplus_legacy_active" -eq 1 ] || \
        [ "$nisplus_rpc_active" -eq 1 ]; then
        set_result MANUAL \
            "rpc.nisd는 U-42의 불필요 RPC 목록과 U-43의 NIS+ 양호 조건이 충돌하여 수동 확인이 필요합니다." \
            "nisplus_rpc_active=true\nguide_conflict=U-42_vs_U-43" true technical
    elif [ "$general_status" -eq 0 ] || [ "$listener_status" -eq 0 ]; then
        set_result MANUAL \
            "RPC 기반 서비스가 활성 상태이며 NFS 등 업무 의존성과 필요성을 확인해야 합니다." \
            "${general_evidence}rpc_listener=$([ "$listener_status" -eq 0 ] && printf active || printf inactive)" true policy
    elif [ "$dangerous_status" -eq 2 ] || [ "$general_status" -eq 2 ] || \
        [ "$nisplus_status" -eq 2 ] || [ "$listener_status" -eq 2 ] || \
        [ "$legacy_uncertain" -eq 1 ] || [ "$nisplus_legacy_uncertain" -eq 1 ]; then
        set_result MANUAL "RPC 서비스의 실제 활성 상태를 확정할 수 없습니다." "$combined_evidence" true runtime
    else
        set_result GOOD "레거시 RPC 서비스와 rpcbind 활성화 경로가 확인되지 않았습니다." "rpc_activation=inactive"
    fi
}

check_u_43() {
    local legacy_status=1
    local nisplus_status=1
    local listener_status=1
    local rpc_output=""
    local rpcinfo_path=""
    local rpcinfo_checked=0
    local legacy_evidence=""
    local nisplus_evidence=""
    local base_major=""
    local distribution_note=""
    local process_status=1

    service_activation_state \
        ypbind.service yppasswdd.service rpc-yppasswdd.service rpc.yppasswdd.service \
        ypserv.service ypxfrd.service \
        ypupdated.service rpc-ypupdated.service rpc.ypupdated.service \
        nis.service
    legacy_status=$?
    legacy_evidence="$SERVICE_ACTIVATION_EVIDENCE"
    if runtime_enabled; then
        service_named_process_state ypbind yppasswdd rpc.yppasswdd ypserv ypxfrd ypupdated rpc.ypupdated
        process_status=$?
        [ "$process_status" -eq 0 ] && legacy_status=0
        [ "$process_status" -ne 2 ] || [ "$legacy_status" -eq 0 ] || legacy_status=2
    fi

    service_activation_state nisplus.service rpc-nisd.service rpc.nisd.service
    nisplus_status=$?
    nisplus_evidence="$SERVICE_ACTIVATION_EVIDENCE"
    if runtime_enabled; then
        service_named_process_state nisd rpc.nisd
        process_status=$?
        [ "$process_status" -eq 0 ] && nisplus_status=0
        [ "$process_status" -ne 2 ] || [ "$nisplus_status" -eq 0 ] || nisplus_status=2
    fi
    if [ -n "$nisplus_evidence" ]; then
        service_prefix_evidence_lines_into nisplus_evidence nisplus_ "$nisplus_evidence" || {
            nisplus_evidence="nisplus_activation_evidence=invalid\n"
            nisplus_status=2
        }
    else
        nisplus_evidence="nisplus_activation_evidence=none\n"
    fi

    service_listener_state 111
    listener_status=$?

    if runtime_enabled; then
        rpcinfo_path="$(trusted_command rpcinfo 2>/dev/null || true)"
        if [ -n "$rpcinfo_path" ]; then
            if rpc_output="$($rpcinfo_path -p localhost 2>/dev/null)"; then
                rpcinfo_checked=1
            fi
            if printf '%s\n' "$rpc_output" | awk '$NF ~ /^(ypbind|yppasswdd|ypserv|ypxfrd|ypupdated|rpc\.ypupdated)$/ {found=1} END {exit(found ? 0 : 1)}'; then
                legacy_status=0
            fi
            if printf '%s\n' "$rpc_output" | awk '$NF ~ /^(nisplus|nisd|rpc\.nisd)$/ {found=1} END {exit(found ? 0 : 1)}'; then
                nisplus_status=0
            fi
        fi
    fi

    if platform_is_rhel_family; then
        base_major="$(platform_base_major 2>/dev/null || true)"
        if [ -n "$base_major" ] && [ "$base_major" -ge 8 ]; then
            distribution_note="yp_rpms_removed_since_rhel_8"
        fi
    fi
    legacy_evidence="${legacy_evidence}${nisplus_evidence}rpcinfo_checked=${rpcinfo_checked}\nrpcbind_listener=$([ "$listener_status" -eq 0 ] && printf active || printf inactive_or_unavailable)\nguide_distribution_note=${distribution_note:-none}"

    if [ "$legacy_status" -eq 0 ]; then
        set_result VULNERABLE "NIS 계열 서비스가 활성 상태입니다." "$legacy_evidence"
    elif [ "$legacy_status" -eq 2 ] || \
        { [ "$listener_status" -eq 0 ] && [ "$rpcinfo_checked" -eq 0 ]; } || \
        [ "$listener_status" -eq 2 ]; then
        set_result MANUAL "NIS 계열 서비스의 실제 활성 상태를 확정할 수 없습니다." "$legacy_evidence" true runtime
    elif [ "$nisplus_status" -eq 0 ]; then
        set_result GOOD "레거시 NIS는 비활성 상태이며 NIS+ 서비스만 확인됐습니다." "$legacy_evidence"
    elif [ "$nisplus_status" -eq 2 ]; then
        set_result MANUAL "NIS+ 서비스의 실제 활성 상태를 확정할 수 없습니다." "$legacy_evidence" true runtime
    else
        set_result GOOD "NIS 계열 서비스가 비활성 상태입니다." \
            "nis_activation=inactive\nguide_distribution_note=${distribution_note:-none}"
    fi
}

check_u_44() {
    local activation_status=1
    local listener_status=1
    local legacy_active=0
    local legacy_uncertain=0
    local base_major=""
    local evidence=""

    service_activation_state \
        tftp.service tftp.socket tftp@.service tftpd.service tftpd.socket tftpd@.service tftpd-hpa.service \
        atftpd.service atftpd.socket atftpd@.service \
        talk.service talk.socket talk@.service ntalk.service ntalk.socket ntalk@.service
    activation_status=$?
    evidence="$SERVICE_ACTIVATION_EVIDENCE"
    service_legacy_enabled '^(tftp|talk|ntalk)$' && legacy_active=1
    legacy_uncertain="$SERVICE_LEGACY_UNCERTAIN"
    service_listener_state 69 517 518
    listener_status=$?

    evidence="${evidence}legacy_activation=${legacy_active}\nservice_listener=$([ "$listener_status" -eq 0 ] && printf active || printf inactive_or_unavailable)"
    if [ "$activation_status" -eq 0 ] || [ "$legacy_active" -eq 1 ] || [ "$listener_status" -eq 0 ]; then
        set_result VULNERABLE "tftp, talk 또는 ntalk 서비스 활성화 경로가 확인됐습니다." "$evidence"
    elif [ "$activation_status" -eq 2 ] || [ "$listener_status" -eq 2 ] || [ "$legacy_uncertain" -eq 1 ]; then
        set_result MANUAL "tftp, talk 또는 ntalk의 실제 활성 상태를 확정할 수 없습니다." "$evidence" true runtime
    else
        platform_is_rhel_family && base_major="$(platform_base_major 2>/dev/null || true)"
        if [ -n "$base_major" ] && [ "$base_major" -ge 7 ]; then
            set_result GOOD "tftp, talk와 ntalk 서비스가 비활성 상태입니다." "${evidence}\nguide_distribution_note=talk_removed_since_rhel_7"
        else
            set_result GOOD "tftp, talk와 ntalk 서비스가 비활성 상태입니다." "$evidence"
        fi
    fi
}

service_mail_command_permission_state() {
    local logical_path="$1"
    local physical_path=""
    local owner_uid=""
    local mode=""

    physical_path="$(fs_path "$logical_path")"
    [ -e "$physical_path" ] || return 2
    owner_uid="$(stat_uid "$physical_path" 2>/dev/null || true)"
    mode="$(stat_mode "$physical_path" 2>/dev/null || true)"
    [ -n "$owner_uid" ] && [ -n "$mode" ] || return 2
    [ "$owner_uid" = "0" ] || return 0
    service_mode_has_other_execute "$mode" && return 0
    return 1
}

service_sendmail_promiscuous_relay() {
    local configuration_file=""

    for configuration_file in /etc/mail/sendmail.mc /etc/mail/sendmail.cf; do
        configuration_file="$(fs_path "$configuration_file")"
        [ -r "$configuration_file" ] || continue
        if awk '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/ || line ~ /^dnl([[:space:]]|$)/) next
                if (tolower(line) ~ /promiscuous_relay/) found=1
            }
            END {exit(found ? 0 : 1)}
        ' "$configuration_file"; then
            return 0
        fi
    done
    return 1
}

check_u_45() {
    service_detect_mail

    if [ -n "$SERVICE_MAIL_PROVIDERS" ]; then
        set_result MANUAL \
            "활성 메일 서비스의 버전이 최신 보안 패치 수준인지 벤더 저장소와 대조해야 합니다." \
            "active_mail_providers=${SERVICE_MAIL_PROVIDERS}\nnetwork_version_check=not_performed" true external
    elif [ "$SERVICE_MAIL_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "메일 서비스의 실제 활성 상태를 확정할 수 없습니다." "active_mail_providers=unknown" true runtime
    else
        set_result NOT_APPLICABLE "활성 SMTP 메일 서비스를 확인하지 못했습니다." "active_mail_providers=none" false
    fi
}

check_u_46() {
    local provider=""
    local privacy_options=""
    local permission_status=2
    local checked_count=0
    local violations=0
    local unresolved_count=0

    service_detect_mail
    if [ -z "$SERVICE_MAIL_PROVIDERS" ]; then
        if [ "$SERVICE_MAIL_UNCERTAIN" -eq 1 ]; then
            set_result MANUAL "메일 서비스 활성 상태와 일반 사용자 실행 제한을 확정할 수 없습니다." "providers=unknown" true runtime
        else
            set_result NOT_APPLICABLE "활성 SMTP 메일 서비스를 확인하지 못했습니다." "providers=none" false
        fi
        return
    fi
    if [ "$SERVICE_MAIL_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "메일 unit의 실제 실행 인수와 구성 경로를 확정할 수 없습니다." "providers=${SERVICE_MAIL_PROVIDERS}\ncustom_invocation_or_listener_error=true" true runtime
        return
    fi

    for provider in $SERVICE_MAIL_PROVIDERS; do
        case "$provider" in
            sendmail)
                checked_count=$((checked_count + 1))
                privacy_options="$(service_sendmail_privacy_options 2>/dev/null || true)"
                if [ -z "$privacy_options" ]; then
                    unresolved_count=$((unresolved_count + 1))
                elif ! printf '%s\n' "$privacy_options" | tr '[:upper:]' '[:lower:]' | \
                    grep -Eq '(^|[ ,])restrictqrun([ ,]|$)'; then
                    violations=$((violations + 1))
                fi
                ;;
            postfix)
                checked_count=$((checked_count + 1))
                service_mail_command_permission_state /usr/sbin/postsuper
                permission_status=$?
                [ "$permission_status" -eq 0 ] && violations=$((violations + 1))
                [ "$permission_status" -eq 2 ] && unresolved_count=$((unresolved_count + 1))
                ;;
            exim)
                checked_count=$((checked_count + 1))
                service_mail_command_permission_state /usr/sbin/exiqgrep
                permission_status=$?
                [ "$permission_status" -eq 0 ] && violations=$((violations + 1))
                [ "$permission_status" -eq 2 ] && unresolved_count=$((unresolved_count + 1))
                ;;
            unknown)
                unresolved_count=$((unresolved_count + 1))
                ;;
        esac
    done

    if [ "$violations" -gt 0 ]; then
        set_result VULNERABLE \
            "활성 메일 서비스에서 일반 사용자 실행 제한 기준 위반을 확인했습니다." \
            "checked_providers=${checked_count}\nviolations=${violations}\nunresolved=${unresolved_count}"
    elif [ "$unresolved_count" -gt 0 ]; then
        set_result MANUAL \
            "활성 메일 서비스 일부의 일반 사용자 실행 제한을 확정할 수 없습니다." \
            "checked_providers=${checked_count}\nviolations=0\nunresolved=${unresolved_count}" true technical
    else
        set_result GOOD \
            "활성 메일 서비스의 일반 사용자 실행 제한이 설정되어 있습니다." \
            "checked_providers=${checked_count}\nviolations=0"
    fi
}

check_u_47() {
    local provider=""
    local relay_restrictions=""
    local recipient_restrictions=""
    local allowed_networks=""
    local restrictions=""
    local postfix_runtime_validated=0
    local multi_instance_enable=""
    local restriction_unknown=0
    local mynetworks_nontrivial=0
    local checked_count=0
    local violations=0
    local unresolved_count=0

    service_detect_mail
    if [ -z "$SERVICE_MAIL_PROVIDERS" ]; then
        if [ "$SERVICE_MAIL_UNCERTAIN" -eq 1 ]; then
            set_result MANUAL "메일 릴레이 제한의 유효 상태를 확정할 수 없습니다." "providers=unknown" true runtime
        else
            set_result NOT_APPLICABLE "활성 SMTP 메일 서비스를 확인하지 못했습니다." "providers=none" false
        fi
        return
    fi
    if [ "$SERVICE_MAIL_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "메일 unit의 실제 릴레이 구성 경로를 확정할 수 없습니다." "providers=${SERVICE_MAIL_PROVIDERS}\ncustom_invocation_or_listener_error=true" true runtime
        return
    fi

    for provider in $SERVICE_MAIL_PROVIDERS; do
        case "$provider" in
            postfix)
                checked_count=$((checked_count + 1))
                if runtime_enabled && [ -n "$(trusted_command postconf 2>/dev/null || true)" ]; then
                    postfix_runtime_validated=1
                else
                    postfix_runtime_validated=0
                fi
                relay_restrictions="$(service_postfix_value smtpd_relay_restrictions 2>/dev/null || true)"
                recipient_restrictions="$(service_postfix_value smtpd_recipient_restrictions 2>/dev/null || true)"
                allowed_networks="$(service_postfix_value mynetworks 2>/dev/null || true)"
                multi_instance_enable="$(service_postfix_value multi_instance_enable 2>/dev/null || true)"
                restrictions="$(printf '%s,%s' "$relay_restrictions" "$recipient_restrictions" | tr '[:upper:]' '[:lower:]')"
                restriction_unknown="$(printf '%s\n' "$restrictions" | tr ',' '\n' | awk '
                    {
                        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
                        if ($0 == "" || $0 == "permit_mynetworks" ||
                            $0 == "permit_sasl_authenticated" ||
                            $0 == "reject_unauth_destination" ||
                            $0 == "defer_unauth_destination") next
                        unknown=1
                    }
                    END {print unknown+0}
                ')"
                printf '%s\n' "$allowed_networks" | \
                    grep -Eq '[$]|(^|[[:space:],])(hash|cidr|regexp|pcre|texthash|lmdb|btree):' && restriction_unknown=1
                service_postfix_mynetworks_are_loopback_only "$allowed_networks" || mynetworks_nontrivial=1
                [ "$mynetworks_nontrivial" -eq 0 ] || restriction_unknown=1
                if printf '%s\n' "$allowed_networks" | grep -Eq '(^|[ ,])(0\.0\.0\.0/0|::/0|\[::\]/0)([ ,]|$)'; then
                    violations=$((violations + 1))
                elif printf '%s\n' "$restrictions" | grep -Eq '^[[:space:],]*permit[[:space:],]'; then
                    violations=$((violations + 1))
                elif printf '%s\n' "$restrictions" | grep -Eq '(^|[ ,])(reject_unauth_destination|defer_unauth_destination)([ ,]|$)'; then
                    if [ "$postfix_runtime_validated" -ne 1 ] || \
                        [ "$(printf '%s' "$multi_instance_enable" | tr '[:upper:]' '[:lower:]')" != "no" ] || \
                        [ "$restriction_unknown" -ne 0 ]; then
                        unresolved_count=$((unresolved_count + 1))
                    fi
                else
                    violations=$((violations + 1))
                fi
                ;;
            sendmail)
                checked_count=$((checked_count + 1))
                if service_sendmail_promiscuous_relay; then
                    violations=$((violations + 1))
                else
                    # Sendmail relay decisions depend on generated rulesets and access maps.
                    unresolved_count=$((unresolved_count + 1))
                fi
                ;;
            exim|unknown)
                # Exim relay behavior is ACL-driven and cannot be inferred from one option.
                checked_count=$((checked_count + 1))
                unresolved_count=$((unresolved_count + 1))
                ;;
        esac
    done

    if [ "$violations" -gt 0 ]; then
        set_result VULNERABLE "활성 메일 서비스에서 제한되지 않은 릴레이 조건을 확인했습니다." \
            "checked_providers=${checked_count}\nviolations=${violations}\nunresolved=${unresolved_count}"
    elif [ "$unresolved_count" -gt 0 ]; then
        set_result MANUAL "메일 ACL과 접근 맵을 포함한 실제 릴레이 동작 검증이 필요합니다." \
            "checked_providers=${checked_count}\nviolations=0\nunresolved=${unresolved_count}" true technical
    else
        set_result GOOD "Postfix 유효 설정에서 인증되지 않은 목적지 릴레이가 제한되어 있습니다." \
            "checked_providers=${checked_count}\nviolations=0"
    fi
}

check_u_48() {
    local provider=""
    local privacy_options=""
    local disable_vrfy=""
    local acl_smtp_vrfy=""
    local acl_smtp_expn=""
    local exim_runtime_validated=0
    local checked_count=0
    local violations=0
    local unresolved_count=0

    service_detect_mail
    if [ -z "$SERVICE_MAIL_PROVIDERS" ]; then
        if [ "$SERVICE_MAIL_UNCERTAIN" -eq 1 ]; then
            set_result MANUAL "메일 명령 제한의 유효 상태를 확정할 수 없습니다." "providers=unknown" true runtime
        else
            set_result NOT_APPLICABLE "활성 SMTP 메일 서비스를 확인하지 못했습니다." "providers=none" false
        fi
        return
    fi
    if [ "$SERVICE_MAIL_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "메일 unit의 실제 명령 제한 구성 경로를 확정할 수 없습니다." "providers=${SERVICE_MAIL_PROVIDERS}\ncustom_invocation_or_listener_error=true" true runtime
        return
    fi

    for provider in $SERVICE_MAIL_PROVIDERS; do
        case "$provider" in
            sendmail)
                checked_count=$((checked_count + 1))
                privacy_options="$(service_sendmail_privacy_options 2>/dev/null || true)"
                if [ -z "$privacy_options" ]; then
                    unresolved_count=$((unresolved_count + 1))
                elif printf '%s\n' "$privacy_options" | tr '[:upper:]' '[:lower:]' | \
                    grep -Eq '(^|[ ,])goaway([ ,]|$)'; then
                    :
                else
                    printf '%s\n' "$privacy_options" | tr '[:upper:]' '[:lower:]' | \
                        grep -Eq '(^|[ ,])noexpn([ ,]|$)' || violations=$((violations + 1))
                    printf '%s\n' "$privacy_options" | tr '[:upper:]' '[:lower:]' | \
                        grep -Eq '(^|[ ,])novrfy([ ,]|$)' || violations=$((violations + 1))
                fi
                ;;
            postfix)
                checked_count=$((checked_count + 1))
                disable_vrfy="$(service_postfix_value disable_vrfy_command 2>/dev/null || true)"
                case "$(printf '%s' "$disable_vrfy" | tr '[:lower:]' '[:upper:]')" in
                    YES|TRUE|1) ;;
                    NO|FALSE|0|'') violations=$((violations + 1)) ;;
                    *) unresolved_count=$((unresolved_count + 1)) ;;
                esac
                ;;
            exim)
                checked_count=$((checked_count + 1))
                if runtime_enabled && \
                    acl_smtp_vrfy="$(service_exim_runtime_value acl_smtp_vrfy 2>/dev/null)" && \
                    acl_smtp_expn="$(service_exim_runtime_value acl_smtp_expn 2>/dev/null)"; then
                    exim_runtime_validated=1
                else
                    acl_smtp_vrfy="$(service_exim_value acl_smtp_vrfy 2>/dev/null || true)"
                    acl_smtp_expn="$(service_exim_value acl_smtp_expn 2>/dev/null || true)"
                fi
                if printf '%s\n%s\n' "$acl_smtp_vrfy" "$acl_smtp_expn" | \
                    grep -Eiq '^[[:space:]]*accept([[:space:]]|$)'; then
                    violations=$((violations + 1))
                elif [ "$exim_runtime_validated" -eq 0 ] || \
                    [ -n "$acl_smtp_vrfy$acl_smtp_expn" ]; then
                    unresolved_count=$((unresolved_count + 1))
                fi
                ;;
            unknown)
                checked_count=$((checked_count + 1))
                unresolved_count=$((unresolved_count + 1))
                ;;
        esac
    done

    if [ "$violations" -gt 0 ]; then
        set_result VULNERABLE "활성 메일 서비스에서 EXPN 또는 VRFY 제한 누락을 확인했습니다." \
            "checked_providers=${checked_count}\nviolations=${violations}\nunresolved=${unresolved_count}"
    elif [ "$unresolved_count" -gt 0 ]; then
        set_result MANUAL "활성 메일 서비스 일부의 EXPN·VRFY 실제 응답을 확인해야 합니다." \
            "checked_providers=${checked_count}\nviolations=0\nunresolved=${unresolved_count}" true runtime
    else
        set_result GOOD "활성 메일 서비스의 EXPN·VRFY 제한 설정이 확인됐습니다." \
            "checked_providers=${checked_count}\nviolations=0"
    fi
}

check_u_49() {
    local dns_status=1

    service_detect_dns
    dns_status=$?
    if [ "$dns_status" -eq 0 ]; then
        set_result MANUAL \
            "활성 DNS 서버 패키지가 최신 보안 패치 수준인지 벤더 저장소와 대조해야 합니다." \
            "dns_activation=active\nnetwork_version_check=not_performed" true external
    elif [ "$dns_status" -eq 2 ]; then
        set_result MANUAL "DNS 서비스의 실제 활성 상태를 확정할 수 없습니다." "dns_activation=unknown" true runtime
    else
        set_result NOT_APPLICABLE "활성 DNS 서비스를 확인하지 못했습니다." "dns_activation=inactive" false
    fi
}

check_u_50() {
    local dns_status=1
    local effective_metadata=""
    local confidence=""
    local configuration_file=""
    local flattened_configuration=""
    local authoritative_zones=0
    local transfer_clauses=0
    local unsafe_clauses=0
    local first_zone_position=0
    local first_transfer_position=0
    local global_restriction=0
    local complex_acl_context=0
    local bind_version=""
    local evidence=""

    service_detect_dns
    dns_status=$?
    if [ "$dns_status" -eq 1 ]; then
        set_result NOT_APPLICABLE "활성 DNS 서비스를 확인하지 못했습니다." "dns_activation=inactive" false
        return
    elif [ "$dns_status" -eq 2 ]; then
        set_result MANUAL "DNS 서비스의 실제 활성 상태를 확정할 수 없습니다." "dns_activation=unknown" true runtime
        return
    fi

    effective_metadata="$(service_bind_effective_file 2>/dev/null || true)"
    confidence="${effective_metadata%%$'\t'*}"
    configuration_file="${effective_metadata#*$'\t'}"
    if [ -z "$effective_metadata" ] || [ ! -r "$configuration_file" ]; then
        set_result MANUAL "BIND 유효 설정을 수집하지 못해 Zone Transfer 제한을 확정할 수 없습니다." "dns_activation=active" true technical
        return
    fi

    flattened_configuration="$(awk '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/ || line ~ /^\/\//) next
            printf "%s ", line
        }
    ' "$configuration_file")"
    authoritative_zones="$(printf '%s\n' "$flattened_configuration" | \
        grep -Eo 'type[[:space:]]+(primary|master|secondary|slave|mirror)[[:space:]]*;' | awk 'END {print NR+0}')"
    transfer_clauses="$(printf '%s\n' "$flattened_configuration" | \
        grep -Eo 'allow-transfer[^;{]*\{[^}]*\}' | awk 'END {print NR+0}')"
    unsafe_clauses="$(printf '%s\n' "$flattened_configuration" | \
        grep -Eo 'allow-transfer[^;{]*\{[^}]*\}' | \
        awk 'tolower($0) ~ /(^|[;{[:space:]])(any|\*|0\/0|0\.0\.0\.0\/0|0\.0\.0\.0\/0\.0\.0\.0|::\/0)[[:space:]]*;/ {count++} END {print count+0}')"
    first_zone_position="$(awk -v value="$flattened_configuration" 'BEGIN {print index(tolower(value), "zone ")}')"
    first_transfer_position="$(awk -v value="$flattened_configuration" 'BEGIN {print index(tolower(value), "allow-transfer")}')"
    if [ "$first_transfer_position" -gt 0 ] && \
        { [ "$first_zone_position" -eq 0 ] || [ "$first_transfer_position" -lt "$first_zone_position" ]; }; then
        global_restriction=1
    fi
    if printf '%s\n' "$flattened_configuration" | grep -Eiq '(^|[;{}[:space:]])(acl|view)[[:space:]]'; then
        complex_acl_context=1
    fi
    bind_version="$(service_bind_version 2>/dev/null || true)"

    evidence="configuration_confidence=${confidence}\nbind_version=${bind_version:-unknown}\nauthoritative_zones=${authoritative_zones}\nallow_transfer_clauses=${transfer_clauses}\nunsafe_clauses=${unsafe_clauses}\nglobal_restriction=${global_restriction}\ncomplex_acl_context=${complex_acl_context}"
    if [ "$confidence" != "validated" ]; then
        set_result MANUAL "include와 실행 인수를 포함한 BIND Zone Transfer 유효 설정을 검증해야 합니다." "$evidence" true technical
    elif [ "$authoritative_zones" -eq 0 ]; then
        set_result NOT_APPLICABLE "권한 있는 DNS zone 구성을 확인하지 못했습니다." "$evidence" false
    elif [ "$unsafe_clauses" -gt 0 ]; then
        set_result VULNERABLE "권한 있는 DNS zone에 전체 대상 Zone Transfer가 허용될 수 있습니다." "$evidence"
    elif [ "$transfer_clauses" -eq 0 ] && service_bind_version_at_least_9_20 "$bind_version"; then
        set_result GOOD "BIND 9.20 이상의 기본 정책으로 Zone Transfer가 거부됩니다." "$evidence"
    elif [ "$transfer_clauses" -eq 0 ] && [ -n "$bind_version" ]; then
        set_result VULNERABLE "BIND 9.20 미만에서 Zone Transfer 제한을 확인하지 못했습니다." "$evidence"
    elif [ "$transfer_clauses" -eq 0 ]; then
        set_result MANUAL "BIND 버전에 따른 Zone Transfer 기본 정책을 확정할 수 없습니다." "$evidence" true technical
    elif [ "$confidence" = "validated" ] && [ "$complex_acl_context" -eq 0 ] && \
        [ "$global_restriction" -eq 1 ]; then
        set_result GOOD "BIND 유효 설정에서 Zone Transfer 대상이 제한되어 있습니다." "$evidence"
    else
        set_result MANUAL "각 view와 zone의 Zone Transfer 상속 범위를 추가 확인해야 합니다." "$evidence" true technical
    fi
}

check_u_51() {
    local dns_status=1
    local effective_metadata=""
    local confidence=""
    local configuration_file=""
    local flattened_configuration=""
    local update_clauses=0
    local non_denial_clauses=0
    local restricted_clauses=0
    local unsafe_clauses=0
    local complex_acl_context=0
    local external_policy_context=0
    local evidence=""

    service_detect_dns
    dns_status=$?
    if [ "$dns_status" -eq 1 ]; then
        set_result NOT_APPLICABLE "활성 DNS 서비스를 확인하지 못했습니다." "dns_activation=inactive" false
        return
    elif [ "$dns_status" -eq 2 ]; then
        set_result MANUAL "DNS 서비스의 실제 활성 상태를 확정할 수 없습니다." "dns_activation=unknown" true runtime
        return
    fi

    effective_metadata="$(service_bind_effective_file 2>/dev/null || true)"
    confidence="${effective_metadata%%$'\t'*}"
    configuration_file="${effective_metadata#*$'\t'}"
    if [ -z "$effective_metadata" ] || [ ! -r "$configuration_file" ]; then
        set_result MANUAL "BIND 유효 설정을 수집하지 못해 동적 업데이트 통제를 확정할 수 없습니다." "dns_activation=active" true technical
        return
    fi

    flattened_configuration="$(awk '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/ || line ~ /^\/\//) next
            printf "%s ", line
        }
    ' "$configuration_file")"
    update_clauses="$(printf '%s\n' "$flattened_configuration" | \
        grep -Eo '(allow-update|allow-update-forwarding)[[:space:]]*\{[^}]*\}|update-policy[[:space:]]*\{[^}]*\}|update-policy[[:space:]]+local[[:space:]]*;' | \
        awk 'END {print NR+0}')"
    unsafe_clauses="$(printf '%s\n' "$flattened_configuration" | \
        grep -Eo '(allow-update|allow-update-forwarding)[[:space:]]*\{[^}]*\}' | \
        awk 'tolower($0) ~ /(^|[;{[:space:]])(any|\*|0\/0|0\.0\.0\.0\/0|0\.0\.0\.0\/0\.0\.0\.0|::\/0)[[:space:]]*;/ {count++} END {print count+0}')"
    non_denial_clauses="$(printf '%s\n' "$flattened_configuration" | \
        grep -Eo '(allow-update|allow-update-forwarding)[[:space:]]*\{[^}]*\}|update-policy[[:space:]]*\{[^}]*\}|update-policy[[:space:]]+local[[:space:]]*;' | \
        awk 'tolower($0) !~ /^(allow-update|allow-update-forwarding)[[:space:]]*\{[[:space:]]*none[[:space:]]*;[[:space:]]*\}$/ {count++} END {print count+0}')"
    restricted_clauses="$(printf '%s\n' "$flattened_configuration" | \
        grep -Eo '(allow-update|allow-update-forwarding)[[:space:]]*\{[^}]*\}' | \
        awk '
            {
                body=tolower($0)
                sub(/^[^{]*\{/, "", body)
                sub(/\}[[:space:]]*$/, "", body)
                gsub(/key[[:space:]]+("[^"]+"|[a-z0-9_.:-]+)[[:space:]]*;/, "", body)
                gsub(/[[:space:]]/, "", body)
                if (body == "") count++
            }
            END {print count+0}
        ')"
    if printf '%s\n' "$flattened_configuration" | grep -Eiq '(^|[;{}[:space:]])(acl|view)[[:space:]]'; then
        complex_acl_context=1
    fi
    if printf '%s\n' "$flattened_configuration" | grep -Eiq '(^|[;{}[:space:]])(dyndb|dlz|catalog-zones?)[[:space:]]'; then
        external_policy_context=1
    fi

    evidence="configuration_confidence=${confidence}\ndynamic_update_clauses=${update_clauses}\nnon_denial_clauses=${non_denial_clauses}\nrestricted_clauses=${restricted_clauses}\nunsafe_clauses=${unsafe_clauses}\ncomplex_acl_context=${complex_acl_context}\nexternal_policy_context=${external_policy_context}"
    if [ "$confidence" = "validated" ] && [ "$unsafe_clauses" -gt 0 ]; then
        set_result VULNERABLE "BIND 동적 업데이트가 제한되지 않은 대상에 허용되어 있습니다." "$evidence"
    elif [ "$confidence" = "validated" ] && [ "$complex_acl_context" -eq 0 ] && \
        [ "$external_policy_context" -eq 0 ] && \
        [ "$non_denial_clauses" -eq "$restricted_clauses" ]; then
        set_result GOOD "BIND 유효 설정에서 동적 업데이트가 비활성화되었거나 명시적 키로 제한되어 있습니다." "$evidence"
    else
        set_result MANUAL "include와 view를 포함한 BIND 동적 업데이트 유효 설정을 검증해야 합니다." "$evidence" true technical
    fi
}

service_proftpd_value() {
    local directive="$1"
    local configuration_file=""
    local last_value=""
    local match=""

    while IFS= read -r configuration_file; do
        [ -r "$configuration_file" ] || continue
        match="$(awk -v target="$(printf '%s' "$directive" | tr '[:upper:]' '[:lower:]')" '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                name=line
                sub(/[[:space:]].*$/, "", name)
                if (tolower(name) != target) next
                value=substr(line, length(name) + 1)
                sub(/[[:space:]]+#.*/, "", value)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                print value
            }
        ' "$configuration_file" | tail -n 1)"
        [ -n "$match" ] && last_value="$match"
    done <<EOF
$(service_proftpd_files | awk '!seen[$0]++')
EOF

    [ -n "$last_value" ] || return 1
    printf '%s\n' "$last_value"
}

service_banner_value_state() {
    local value="$1"

    [ -n "$value" ] || return 1
    if printf '%s\n' "$value" | grep -Eiq \
        'authori[sz]ed|unauthori[sz]ed|prohibit|monitor|security notice|warning|인가|비인가|금지|모니터링|보안|경고|접근'; then
        return 0
    fi
    return 2
}

service_banner_discloses_identity() {
    local value="$1"

    [ -n "$value" ] || return 1
    printf '%s\n' "$value" | grep -Eiq \
        '(^|[^[:alpha:]])(vsftpd|proftpd|pure-ftpd|debian|ubuntu|rhel|red[[:space:]]+hat|almalinux|rocky|oracle[[:space:]]+linux|centos|linux[[:space:]]+mint|pop!?_?os|zorin|elementary|kde[[:space:]]+neon|version|hostname)([^[:alpha:]]|$)'
}

service_vsftpd_effective_banner() {
    local configuration_path=""
    local banner_file=""
    local physical_banner_file=""

    configuration_path="$(service_vsftpd_configuration 2>/dev/null || true)"
    [ -n "$configuration_path" ] || return 2
    banner_file="$(service_read_simple_value banner_file "$configuration_path" 2>/dev/null || true)"
    if [ -n "$banner_file" ]; then
        case "$banner_file" in
            /*) physical_banner_file="$(fs_path "$banner_file" 2>/dev/null || true)" ;;
            *) return 2 ;;
        esac
        [ -r "$physical_banner_file" ] || return 2
        awk '{printf "%s ", $0}' "$physical_banner_file"
        return 0
    fi
    service_read_simple_value ftpd_banner "$configuration_path"
}

service_file_contains_root_entry() {
    local physical_path="$1"

    [ -r "$physical_path" ] || return 1
    awk '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line == "" || line ~ /^#/) next
            sub(/[[:space:]#].*$/, "", line)
            if (line == "root") found=1
        }
        END {exit(found ? 0 : 1)}
    ' "$physical_path"
}

check_u_52() {
    local activation_status=1
    local listener_status=1
    local legacy_active=0
    local legacy_uncertain=0
    local evidence=""

    service_activation_state telnet.service telnet.socket telnet@.service telnetd.service telnetd.socket
    activation_status=$?
    evidence="$SERVICE_ACTIVATION_EVIDENCE"
    service_legacy_enabled '^telnet$' && legacy_active=1
    legacy_uncertain="$SERVICE_LEGACY_UNCERTAIN"
    service_listener_state tcp 23
    listener_status=$?

    evidence="${evidence}legacy_activation=${legacy_active}\ntelnet_listener=$([ "$listener_status" -eq 0 ] && printf active || printf inactive_or_unavailable)"
    if [ "$activation_status" -eq 0 ] || [ "$legacy_active" -eq 1 ] || [ "$listener_status" -eq 0 ]; then
        set_result VULNERABLE "Telnet 서비스 활성화 경로가 확인됐습니다." "$evidence"
    elif [ "$activation_status" -eq 2 ] || [ "$listener_status" -eq 2 ] || [ "$legacy_uncertain" -eq 1 ]; then
        set_result MANUAL "Telnet 서비스의 실제 활성 상태를 확정할 수 없습니다." "$evidence" true runtime
    else
        set_result GOOD "Telnet 서비스가 systemd, inetd/xinetd와 수신 포트에서 비활성 상태입니다." "$evidence"
    fi
}

check_u_53() {
    local provider=""
    local configuration_path=""
    local banner_value=""
    local banner_file=""
    local physical_banner_file=""
    local server_ident=""
    local custom_ident=""
    local banner_state=1
    local checked_count=0
    local violations=0
    local unresolved_count=0

    service_detect_ftp
    if [ -z "$SERVICE_FTP_PROVIDERS" ]; then
        if [ "$SERVICE_FTP_UNCERTAIN" -eq 1 ]; then
            set_result MANUAL "FTP 서비스와 배너 유효 설정을 확정할 수 없습니다." "providers=unknown" true runtime
        else
            set_result NOT_APPLICABLE "활성 FTP 서비스를 확인하지 못했습니다." "providers=none" false
        fi
        return
    fi
    if [ "$SERVICE_FTP_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "FTP unit의 실제 실행 인수와 구성 경로를 확정할 수 없습니다." "providers=${SERVICE_FTP_PROVIDERS}\ncustom_invocation=true" true runtime
        return
    fi

    for provider in $SERVICE_FTP_PROVIDERS; do
        case "$provider" in
            vsftpd)
                checked_count=$((checked_count + 1))
                configuration_path="$(service_vsftpd_configuration 2>/dev/null || true)"
                banner_file="$(service_read_simple_value banner_file "$configuration_path" 2>/dev/null || true)"
                if [ -n "$banner_file" ]; then
                    case "$banner_file" in
                        /*)
                            physical_banner_file="$(fs_path "$banner_file" 2>/dev/null || true)"
                            if [ -r "$physical_banner_file" ]; then
                                banner_value="$(awk '{printf "%s ", $0}' "$physical_banner_file")"
                            else
                                unresolved_count=$((unresolved_count + 1))
                                continue
                            fi
                            ;;
                        *)
                            unresolved_count=$((unresolved_count + 1))
                            continue
                            ;;
                    esac
                else
                    banner_value="$(service_read_simple_value ftpd_banner "$configuration_path" 2>/dev/null || true)"
                fi
                if [ -z "$banner_value" ] || service_banner_discloses_identity "$banner_value"; then
                    violations=$((violations + 1))
                else
                    service_banner_value_state "$banner_value"
                    banner_state=$?
                    [ "$banner_state" -eq 0 ] || unresolved_count=$((unresolved_count + 1))
                fi
                ;;
            proftpd)
                checked_count=$((checked_count + 1))
                server_ident="$(service_proftpd_value ServerIdent 2>/dev/null || true)"
                if [ -z "$server_ident" ]; then
                    violations=$((violations + 1))
                elif printf '%s\n' "$server_ident" | grep -Eiq '^off([[:space:]]|$)'; then
                    :
                else
                    custom_ident="$(printf '%s\n' "$server_ident" | \
                        sed -E 's/^[[:space:]]*[Oo][Nn][[:space:]]*//' | tr -d '"')"
                    if [ -z "$custom_ident" ] || service_banner_discloses_identity "$custom_ident"; then
                        violations=$((violations + 1))
                    else
                        service_banner_value_state "$custom_ident"
                        banner_state=$?
                        [ "$banner_state" -eq 0 ] || unresolved_count=$((unresolved_count + 1))
                    fi
                fi
                ;;
            legacy|pure-ftpd|unknown)
                checked_count=$((checked_count + 1))
                unresolved_count=$((unresolved_count + 1))
                ;;
        esac
    done

    if [ "$violations" -gt 0 ]; then
        set_result VULNERABLE "FTP 기본 배너 또는 제품 정보 노출 가능성을 확인했습니다." \
            "checked_providers=${checked_count}\nviolations=${violations}\nunresolved=${unresolved_count}"
    elif [ "$unresolved_count" -gt 0 ]; then
        set_result MANUAL "FTP 접속 배너의 실제 응답에서 제품·버전 정보 노출 여부를 확인해야 합니다." \
            "checked_providers=${checked_count}\nviolations=0\nunresolved=${unresolved_count}" true runtime
    else
        set_result GOOD "활성 FTP 서비스의 로컬 유효 설정에서 제품·버전 배너 노출이 제한되어 있습니다." \
            "checked_providers=${checked_count}\nviolations=0"
    fi
}

check_u_54() {
    local provider=""
    local configuration_path=""
    local ssl_enable=""
    local force_login_ssl=""
    local force_data_ssl=""
    local anonymous_enable=""
    local allow_anon_ssl=""
    local force_anon_login_ssl=""
    local force_anon_data_ssl=""
    local tls_engine=""
    local tls_required=""
    local checked_count=0
    local violations=0
    local unresolved_count=0

    service_detect_ftp
    if [ -z "$SERVICE_FTP_PROVIDERS" ]; then
        if [ "$SERVICE_FTP_UNCERTAIN" -eq 1 ]; then
            set_result MANUAL "FTP 활성 상태와 전송 암호화 강제 여부를 확정할 수 없습니다." "providers=unknown" true runtime
        else
            set_result GOOD "암호화되지 않은 FTP 서비스 활성화 경로를 확인하지 못했습니다." "providers=none"
        fi
        return
    fi
    if [ "$SERVICE_FTP_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "FTP unit의 실제 실행 인수와 TLS 구성 경로를 확정할 수 없습니다." "providers=${SERVICE_FTP_PROVIDERS}\ncustom_invocation=true" true runtime
        return
    fi

    for provider in $SERVICE_FTP_PROVIDERS; do
        case "$provider" in
            vsftpd)
                checked_count=$((checked_count + 1))
                configuration_path="$(service_vsftpd_configuration 2>/dev/null || true)"
                if [ -z "$configuration_path" ]; then
                    unresolved_count=$((unresolved_count + 1))
                    continue
                fi
                ssl_enable="$(service_read_simple_value ssl_enable "$configuration_path" 2>/dev/null || true)"
                force_login_ssl="$(service_read_simple_value force_local_logins_ssl "$configuration_path" 2>/dev/null || true)"
                force_data_ssl="$(service_read_simple_value force_local_data_ssl "$configuration_path" 2>/dev/null || true)"
                anonymous_enable="$(service_read_simple_value anonymous_enable "$configuration_path" 2>/dev/null || true)"
                allow_anon_ssl="$(service_read_simple_value allow_anon_ssl "$configuration_path" 2>/dev/null || true)"
                force_anon_login_ssl="$(service_read_simple_value force_anon_logins_ssl "$configuration_path" 2>/dev/null || true)"
                force_anon_data_ssl="$(service_read_simple_value force_anon_data_ssl "$configuration_path" 2>/dev/null || true)"
                if [ "$(printf '%s' "$ssl_enable" | tr '[:lower:]' '[:upper:]')" != "YES" ] || \
                    [ "$(printf '%s' "$force_login_ssl" | tr '[:lower:]' '[:upper:]')" = "NO" ] || \
                    [ "$(printf '%s' "$force_data_ssl" | tr '[:lower:]' '[:upper:]')" = "NO" ]; then
                    violations=$((violations + 1))
                elif [ "$(printf '%s' "$anonymous_enable" | tr '[:lower:]' '[:upper:]')" = "YES" ] && \
                    { [ "$(printf '%s' "$allow_anon_ssl" | tr '[:lower:]' '[:upper:]')" != "YES" ] || \
                      [ "$(printf '%s' "$force_anon_login_ssl" | tr '[:lower:]' '[:upper:]')" != "YES" ] || \
                      [ "$(printf '%s' "$force_anon_data_ssl" | tr '[:lower:]' '[:upper:]')" != "YES" ]; }; then
                    violations=$((violations + 1))
                fi
                ;;
            proftpd)
                checked_count=$((checked_count + 1))
                tls_engine="$(service_proftpd_value TLSEngine 2>/dev/null || true)"
                tls_required="$(service_proftpd_value TLSRequired 2>/dev/null || true)"
                if [ -z "$tls_engine" ] || ! printf '%s\n' "$tls_engine" | grep -Eiq '^on([[:space:]]|$)'; then
                    violations=$((violations + 1))
                elif [ -z "$tls_required" ] || ! printf '%s\n' "$tls_required" | grep -Eiq '^on([[:space:]]|$)'; then
                    violations=$((violations + 1))
                fi
                ;;
            legacy)
                checked_count=$((checked_count + 1))
                violations=$((violations + 1))
                ;;
            pure-ftpd|unknown)
                checked_count=$((checked_count + 1))
                unresolved_count=$((unresolved_count + 1))
                ;;
        esac
    done

    if [ "$violations" -gt 0 ]; then
        set_result VULNERABLE "활성 FTP 서비스가 제어·데이터 채널 암호화를 강제하지 않습니다." \
            "checked_providers=${checked_count}\nunencrypted_providers=${violations}\nunresolved=${unresolved_count}"
    elif [ "$unresolved_count" -gt 0 ]; then
        set_result MANUAL "활성 FTP 서비스 일부의 TLS 강제 여부를 확정할 수 없습니다." \
            "checked_providers=${checked_count}\nunresolved=${unresolved_count}" true technical
    else
        set_result GOOD "활성 FTP 서비스가 제어·데이터 채널 TLS를 강제합니다." \
            "checked_providers=${checked_count}\nunresolved=0"
    fi
}

check_u_55() {
    local passwd_path=""
    local ftp_entry=""
    local shell_path=""

    passwd_path="$(fs_path /etc/passwd)"
    [ -r "$passwd_path" ] || {
        set_result ERROR "/etc/passwd 파일을 읽을 수 없습니다." "path=/etc/passwd"
        return
    }

    ftp_entry="$(awk -F: '$1 == "ftp" {print; exit}' "$passwd_path")"
    if [ -z "$ftp_entry" ]; then
        set_result NOT_APPLICABLE "ftp 기본 계정이 존재하지 않습니다." "ftp_account=absent" false
        return
    fi
    shell_path="$(printf '%s\n' "$ftp_entry" | awk -F: '{print $7}')"
    case "$shell_path" in
        /bin/false|/usr/bin/false|/sbin/nologin|/usr/sbin/nologin)
            set_result GOOD "ftp 기본 계정에 비로그인 셸이 지정되어 있습니다." "ftp_account_shell=non_login"
            ;;
        *)
            set_result VULNERABLE "ftp 기본 계정에 대화형 로그인이 가능한 셸이 지정되어 있습니다." "ftp_account_shell=interactive_or_unknown"
            ;;
    esac
}

check_u_56() {
    service_detect_ftp

    if [ -n "$SERVICE_FTP_PROVIDERS" ]; then
        set_result MANUAL \
            "FTP 접근 제어는 daemon 설정, systemd IPAddress 정책, 호스트 방화벽과 외부 방화벽을 함께 확인해야 합니다." \
            "active_ftp_providers=${SERVICE_FTP_PROVIDERS}\nnetwork_policy_validation=required" true runtime
    elif [ "$SERVICE_FTP_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "FTP 서비스와 접근 제어의 실제 상태를 확정할 수 없습니다." "active_ftp_providers=unknown" true runtime
    else
        set_result NOT_APPLICABLE "활성 FTP 서비스를 확인하지 못했습니다." "active_ftp_providers=none" false
    fi
}

check_u_57() {
    local provider=""
    local candidate=""
    local configuration_path=""
    local userlist_enable=""
    local userlist_deny=""
    local userlist_file=""
    local use_ftpusers=""
    local root_login=""
    local checked_count=0
    local violations=0
    local unresolved_count=0
    local root_denied=0

    service_detect_ftp
    if [ -z "$SERVICE_FTP_PROVIDERS" ]; then
        if [ "$SERVICE_FTP_UNCERTAIN" -eq 1 ]; then
            set_result MANUAL "FTP root 접속 차단의 유효 상태를 확정할 수 없습니다." "providers=unknown" true runtime
        else
            set_result NOT_APPLICABLE "활성 FTP 서비스를 확인하지 못했습니다." "providers=none" false
        fi
        return
    fi
    if [ "$SERVICE_FTP_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "FTP unit의 실제 PAM·userlist 구성 경로를 확정할 수 없습니다." "providers=${SERVICE_FTP_PROVIDERS}\ncustom_invocation=true" true runtime
        return
    fi

    for provider in $SERVICE_FTP_PROVIDERS; do
        case "$provider" in
            vsftpd|legacy)
                checked_count=$((checked_count + 1))
                root_denied=0
                if [ "$provider" = "legacy" ]; then
                    for candidate in /etc/ftpusers /etc/ftpd/ftpusers; do
                        candidate="$(fs_path "$candidate")"
                        service_file_contains_root_entry "$candidate" && root_denied=1
                    done
                    if [ "$root_denied" -eq 0 ]; then
                        violations=$((violations + 1))
                    fi
                    continue
                fi

                configuration_path="$(service_vsftpd_configuration 2>/dev/null || true)"
                if [ -z "$configuration_path" ]; then
                    unresolved_count=$((unresolved_count + 1))
                    continue
                fi
                userlist_enable="$(service_read_simple_value userlist_enable "$configuration_path" 2>/dev/null || true)"
                userlist_deny="$(service_read_simple_value userlist_deny "$configuration_path" 2>/dev/null || true)"
                userlist_file="$(service_read_simple_value userlist_file "$configuration_path" 2>/dev/null || true)"
                case "$(printf '%s' "$userlist_enable" | tr '[:lower:]' '[:upper:]')" in
                    YES|TRUE|1)
                        if [ -n "$userlist_file" ]; then
                            case "$userlist_file" in
                                /*) candidate="$(fs_path "$userlist_file" 2>/dev/null || true)" ;;
                                *) candidate="" ;;
                            esac
                        elif platform_is_rhel_family; then
                            candidate="$(fs_path /etc/vsftpd/user_list)"
                        else
                            candidate="$(fs_path /etc/vsftpd.user_list)"
                        fi
                        [ -n "$candidate" ] && service_file_contains_root_entry "$candidate" && root_denied=1
                        case "$(printf '%s' "${userlist_deny:-YES}" | tr '[:lower:]' '[:upper:]')" in
                            YES|TRUE|1) [ "$root_denied" -eq 1 ] || violations=$((violations + 1)) ;;
                            NO|FALSE|0) [ "$root_denied" -eq 0 ] || violations=$((violations + 1)) ;;
                            *) unresolved_count=$((unresolved_count + 1)) ;;
                        esac
                        ;;
                    ''|NO|FALSE|0)
                        for candidate in /etc/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers; do
                            candidate="$(fs_path "$candidate")"
                            service_file_contains_root_entry "$candidate" && root_denied=1
                        done
                        if [ "$root_denied" -eq 0 ]; then
                            violations=$((violations + 1))
                        fi
                        ;;
                    *) unresolved_count=$((unresolved_count + 1)) ;;
                esac
                ;;
            proftpd)
                checked_count=$((checked_count + 1))
                use_ftpusers="$(service_proftpd_value UseFtpUsers 2>/dev/null || true)"
                root_login="$(service_proftpd_value RootLogin 2>/dev/null || true)"
                case "$(printf '%s' "${use_ftpusers:-on}" | tr '[:upper:]' '[:lower:]')" in
                    on|yes|true|1)
                        root_denied=0
                        for candidate in /etc/ftpusers /etc/ftpd/ftpusers; do
                            candidate="$(fs_path "$candidate")"
                            service_file_contains_root_entry "$candidate" && root_denied=1
                        done
                        [ "$root_denied" -eq 1 ] || violations=$((violations + 1))
                        ;;
                    off|no|false|0)
                        if ! printf '%s\n' "$root_login" | grep -Eiq '^off([[:space:]]|$)'; then
                            violations=$((violations + 1))
                        fi
                        ;;
                    *) unresolved_count=$((unresolved_count + 1)) ;;
                esac
                ;;
            pure-ftpd|unknown)
                checked_count=$((checked_count + 1))
                unresolved_count=$((unresolved_count + 1))
                ;;
        esac
    done

    if [ "$violations" -gt 0 ]; then
        set_result VULNERABLE "활성 FTP 서비스에서 root 계정 접속 차단 누락을 확인했습니다." \
            "checked_providers=${checked_count}\nviolations=${violations}\nunresolved=${unresolved_count}"
    elif [ "$unresolved_count" -gt 0 ]; then
        set_result MANUAL "활성 FTP 서비스 일부의 root 접속 차단을 확정할 수 없습니다." \
            "checked_providers=${checked_count}\nviolations=0\nunresolved=${unresolved_count}" true technical
    else
        set_result GOOD "활성 FTP 서비스에서 root 계정 접속이 차단되어 있습니다." \
            "checked_providers=${checked_count}\nviolations=0"
    fi
}

check_u_58() {
    local snmp_status=1

    service_detect_snmp
    snmp_status=$?
    if [ "$SERVICE_SNMP_ENDPOINT_ACTIVE" -eq 1 ]; then
        set_result VULNERABLE "SNMP 서비스 활성화 경로 또는 수신 포트가 확인됐습니다." "snmp_activation=active"
    elif [ "$snmp_status" -eq 2 ]; then
        set_result MANUAL "SNMP 서비스의 실제 활성 상태를 확정할 수 없습니다." "snmp_activation=unknown" true runtime
    else
        set_result GOOD "SNMP 서비스 활성화 경로와 수신 포트를 확인하지 못했습니다." "snmp_activation=inactive"
    fi
}

service_snmp_version_metrics() {
    local configuration_file=""
    local saw_configuration=0

    while IFS= read -r configuration_file; do
        [ -r "$configuration_file" ] || continue
        saw_configuration=1
        awk '
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                split(line, fields, /[[:space:]]+/)
                directive=tolower(fields[1])
                if (directive ~ /^(rocommunity|rwcommunity|rocommunity6|rwcommunity6|com2sec|com2sec6|authcommunity)$/) legacy++
                if (directive == "authgroup") complex++
                if (directive ~ /^(rouser|rwuser|authuser)$/) version3++
                if (directive == "group" && tolower(fields[3]) ~ /^(v1|v2c)$/) legacy++
                if (directive == "group" && tolower(fields[3]) == "usm") version3++
                if (directive ~ /^(include|includefile|includedir)$/) includes++
            }
            END {printf "%d %d %d\n", legacy+0, version3+0, includes+complex+0}
        ' "$configuration_file"
    done <<EOF
$(service_snmp_files | awk '!seen[$0]++')
EOF
    [ "$saw_configuration" -eq 1 ] || printf '0 0 0\n'
}

service_snmp_community_metrics() {
    local configuration_file=""
    local saw_configuration=0

    while IFS= read -r configuration_file; do
        [ -r "$configuration_file" ] || continue
        saw_configuration=1
        awk -v family="$PLATFORM_FAMILY" '
            function classify(value, lower, has_letter, has_digit, has_special, length_value) {
                gsub(/^["\047]|["\047]$/, "", value)
                lower=tolower(value)
                length_value=length(value)
                has_letter=(value ~ /[A-Za-z]/)
                has_digit=(value ~ /[0-9]/)
                has_special=(value ~ /[^A-Za-z0-9]/)
                communities++
                if (lower == "public" || lower == "private") weak++
                else if (has_letter && has_digit && has_special && length_value >= 8) strong++
                else if (has_letter && has_digit && length_value >= 10) strong++
                else weak++
            }
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                split(line, fields, /[[:space:]]+/)
                directive=tolower(fields[1])
                if (directive ~ /^(rocommunity|rwcommunity|rocommunity6|rwcommunity6)$/ && fields[2] != "") {
                    classify(fields[2])
                    if (family != "debian") dialect_mismatch++
                }
                else if (directive ~ /^(com2sec|com2sec6)$/) {
                    if (fields[2] == "-Cn" && fields[6] != "") classify(fields[6])
                    else if (fields[4] != "") classify(fields[4])
                    if (family != "rhel") dialect_mismatch++
                } else if (directive == "authcommunity" && fields[3] != "") {
                    classify(fields[3])
                    dialect_mismatch++
                }
                if (directive ~ /^(rouser|rwuser|authuser)$/ || (directive == "group" && tolower(fields[3]) == "usm")) version3++
                if (directive ~ /^(include|includefile|includedir|authgroup)$/) includes++
            }
            END {printf "%d %d %d %d %d\n", communities+0, weak+0, version3+0, includes+0, dialect_mismatch+0}
        ' "$configuration_file"
    done <<EOF
$(service_snmp_files | awk '!seen[$0]++')
EOF
    [ "$saw_configuration" -eq 1 ] || printf '0 0 0 0 0\n'
}

service_snmp_access_metrics() {
    local configuration_file=""
    local saw_configuration=0

    while IFS= read -r configuration_file; do
        [ -r "$configuration_file" ] || continue
        saw_configuration=1
        awk -v family="$PLATFORM_FAMILY" '
            function is_unrestricted(value, lower) {
                lower=tolower(value)
                return value == "" || lower == "default" || lower == "any" || value == "*" ||
                    value == "0/0" || value == "0.0.0.0" || value == "0.0.0.0/0" ||
                    value == "0.0.0.0/0.0.0.0" || value == "::" || value == "::/0" ||
                    lower ~ /^[0-9a-f:]+\/0+$/ || value ~ /^[0-9.]+\/(0+|0.0.0.0)$/
            }
            function is_valid_source(value) {
                return value ~ /^[0-9.]+(\/[0-9.]+)?$/ ||
                    value ~ /^[0-9A-Fa-f:]+(\/[0-9]+)?$/ ||
                    value ~ /^[A-Za-z0-9][A-Za-z0-9.-]*$/
            }
            function classify_source(value) {
                if (value ~ /^-/) invalid++
                else if (is_unrestricted(value)) unsafe++
                else if (is_valid_source(value)) restricted++
                else invalid++
            }
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                split(line, fields, /[[:space:]]+/)
                directive=tolower(fields[1])
                if (directive ~ /^(rocommunity|rwcommunity|rocommunity6|rwcommunity6)$/) {
                    communities++
                    classify_source(fields[3])
                    if (family != "debian") dialect_mismatch++
                } else if (directive ~ /^(com2sec|com2sec6)$/) {
                    communities++
                    if (fields[2] == "-Cn") source=fields[5]
                    else source=fields[3]
                    classify_source(source)
                    if (family != "rhel") dialect_mismatch++
                } else if (directive == "authcommunity") {
                    communities++
                    classify_source(fields[4])
                    dialect_mismatch++
                }
                if (directive ~ /^(rouser|rwuser|authuser)$/ || (directive == "group" && tolower(fields[3]) == "usm")) version3++
                if (directive ~ /^(include|includefile|includedir|authgroup)$/) includes++
            }
            END {printf "%d %d %d %d %d %d %d\n", communities+0, restricted+0, unsafe+0, version3+0, includes+0, dialect_mismatch+0, invalid+0}
        ' "$configuration_file"
    done <<EOF
$(service_snmp_files | awk '!seen[$0]++')
EOF
    [ "$saw_configuration" -eq 1 ] || printf '0 0 0 0 0 0 0\n'
}

check_u_59() {
    local snmp_status=1
    local metrics=""
    local legacy_count=0
    local version3_count=0
    local include_count=0
    local values=""

    service_detect_snmp
    snmp_status=$?
    if [ "$snmp_status" -eq 1 ]; then
        set_result NOT_APPLICABLE "활성 SNMP 서비스를 확인하지 못했습니다." "snmp_activation=inactive" false
        return
    elif [ "$snmp_status" -eq 2 ]; then
        set_result MANUAL "SNMP 서비스의 실제 활성 상태를 확정할 수 없습니다." "snmp_activation=unknown" true runtime
        return
    fi
    if [ "$SERVICE_SNMP_CONFIG_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "SNMP unit의 실제 구성 경로를 확정할 수 없습니다." "snmp_activation=active\ncustom_invocation=true" true runtime
        return
    fi

    metrics="$(service_snmp_version_metrics)"
    while IFS= read -r values; do
        legacy_count=$((legacy_count + ${values%% *}))
        values="${values#* }"
        version3_count=$((version3_count + ${values%% *}))
        include_count=$((include_count + ${values##* }))
    done <<EOF
$metrics
EOF

    if [ "$legacy_count" -gt 0 ]; then
        set_result VULNERABLE "SNMP v1 또는 v2c를 활성화하는 community/VACM 설정이 확인됐습니다." \
            "legacy_version_directives=${legacy_count}\nversion3_directives=${version3_count}\ncustom_includes=${include_count}"
    elif [ "$version3_count" -gt 0 ] && [ "$include_count" -eq 0 ]; then
        set_result MANUAL "SNMP v3의 실제 인증·암호화 응답과 사용자 유효성을 확인해야 합니다." \
            "legacy_version_directives=0\nversion3_directives=${version3_count}\npacket_validation=required" true runtime
    else
        set_result MANUAL "활성 SNMP 서비스의 실제 프로토콜 버전을 설정과 패킷 응답으로 확인해야 합니다." \
            "legacy_version_directives=${legacy_count}\nversion3_directives=${version3_count}\ncustom_includes=${include_count}" true runtime
    fi
}

check_u_60() {
    local snmp_status=1
    local metrics=""
    local community_count=0
    local weak_count=0
    local version3_count=0
    local include_count=0
    local dialect_mismatch_count=0
    local values=""

    service_detect_snmp
    snmp_status=$?
    if [ "$snmp_status" -eq 1 ]; then
        set_result NOT_APPLICABLE "활성 SNMP 서비스를 확인하지 못했습니다." "snmp_activation=inactive" false
        return
    elif [ "$snmp_status" -eq 2 ]; then
        set_result MANUAL "SNMP 서비스의 실제 활성 상태를 확정할 수 없습니다." "snmp_activation=unknown" true runtime
        return
    fi
    if [ "$SERVICE_SNMP_CONFIG_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "SNMP unit의 실제 구성 경로를 확정할 수 없습니다." "snmp_activation=active\ncustom_invocation=true" true runtime
        return
    fi

    metrics="$(service_snmp_community_metrics)"
    while IFS= read -r values; do
        community_count=$((community_count + ${values%% *}))
        values="${values#* }"
        weak_count=$((weak_count + ${values%% *}))
        values="${values#* }"
        version3_count=$((version3_count + ${values%% *}))
        values="${values#* }"
        include_count=$((include_count + ${values%% *}))
        dialect_mismatch_count=$((dialect_mismatch_count + ${values##* }))
    done <<EOF
$metrics
EOF

    if [ "$weak_count" -gt 0 ]; then
        set_result VULNERABLE "복잡도 기준을 충족하지 않는 SNMP community가 확인됐습니다." \
            "community_count=${community_count}\nweak_community_count=${weak_count}\nsecret_values=redacted"
    elif [ "$community_count" -gt 0 ] && [ "$version3_count" -eq 0 ] && \
        [ "$include_count" -eq 0 ] && [ "$dialect_mismatch_count" -eq 0 ]; then
        set_result GOOD "구성된 SNMP community가 길이와 문자 조합 기준을 충족합니다." \
            "community_count=${community_count}\nweak_community_count=0\nsecret_values=redacted"
    elif [ "$version3_count" -gt 0 ]; then
        set_result MANUAL "SNMP v3 인증 비밀번호 복잡도는 비밀값을 보고서에 노출하지 않고 별도 검증해야 합니다." \
            "version3_directives=${version3_count}\nsecret_values=not_collected" true technical
    else
        set_result MANUAL "활성 SNMP 서비스의 community 또는 v3 인증 설정을 확인하지 못했습니다." \
            "community_count=${community_count}\ncustom_includes=${include_count}\ndialect_mismatches=${dialect_mismatch_count}" true technical
    fi
}

check_u_61() {
    local snmp_status=1
    local metrics=""
    local community_count=0
    local restricted_count=0
    local unsafe_count=0
    local version3_count=0
    local include_count=0
    local dialect_mismatch_count=0
    local invalid_source_count=0
    local values=""

    service_detect_snmp
    snmp_status=$?
    if [ "$snmp_status" -eq 1 ]; then
        set_result NOT_APPLICABLE "활성 SNMP 서비스를 확인하지 못했습니다." "snmp_activation=inactive" false
        return
    elif [ "$snmp_status" -eq 2 ]; then
        set_result MANUAL "SNMP 서비스의 실제 활성 상태를 확정할 수 없습니다." "snmp_activation=unknown" true runtime
        return
    fi
    if [ "$SERVICE_SNMP_CONFIG_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "SNMP unit의 실제 구성 경로를 확정할 수 없습니다." "snmp_activation=active\ncustom_invocation=true" true runtime
        return
    fi

    metrics="$(service_snmp_access_metrics)"
    while IFS= read -r values; do
        community_count=$((community_count + ${values%% *}))
        values="${values#* }"
        restricted_count=$((restricted_count + ${values%% *}))
        values="${values#* }"
        unsafe_count=$((unsafe_count + ${values%% *}))
        values="${values#* }"
        version3_count=$((version3_count + ${values%% *}))
        values="${values#* }"
        include_count=$((include_count + ${values%% *}))
        values="${values#* }"
        dialect_mismatch_count=$((dialect_mismatch_count + ${values%% *}))
        invalid_source_count=$((invalid_source_count + ${values##* }))
    done <<EOF
$metrics
EOF

    if [ "$unsafe_count" -gt 0 ]; then
        set_result VULNERABLE "전체 또는 기본 네트워크에서 접근 가능한 SNMP community 설정이 확인됐습니다." \
            "community_count=${community_count}\nrestricted_sources=${restricted_count}\nunrestricted_sources=${unsafe_count}"
    elif [ "$community_count" -eq 1 ] && [ "$restricted_count" -eq "$community_count" ] && \
        [ "$version3_count" -eq 0 ] && [ "$include_count" -eq 0 ] && \
        [ "$dialect_mismatch_count" -eq 0 ] && [ "$invalid_source_count" -eq 0 ]; then
        set_result GOOD "모든 SNMP community가 특정 네트워크 또는 호스트로 제한되어 있습니다." \
            "community_count=${community_count}\nrestricted_sources=${restricted_count}"
    elif [ "$version3_count" -gt 0 ]; then
        set_result MANUAL "SNMP v3 사용자 인증 외에 네트워크·방화벽 접근 제한을 함께 확인해야 합니다." \
            "version3_directives=${version3_count}\ncustom_includes=${include_count}" true runtime
    else
        set_result MANUAL "활성 SNMP 서비스의 유효 접근 제어 설정을 확정할 수 없습니다." \
            "community_count=${community_count}\ncustom_includes=${include_count}\ndialect_mismatches=${dialect_mismatch_count}\ninvalid_sources=${invalid_source_count}" true technical
    fi
}

service_warning_collection_state() {
    local logical_path=""
    local physical_path=""
    local state=0
    local unresolved_content=0

    for logical_path in "$@"; do
        physical_path="$(fs_path "$logical_path")"
        if [ -f "$physical_path" ]; then
            state=0
            service_warning_file_state "$physical_path" || state=$?
            case "$state" in
                0) return 0 ;;
                1) ;;
                *) unresolved_content=1 ;;
            esac
        elif [ -d "$physical_path" ]; then
            while IFS= read -r physical_path; do
                state=0
                service_warning_file_state "$physical_path" || state=$?
                case "$state" in
                    0) return 0 ;;
                    1) ;;
                    *) unresolved_content=1 ;;
                esac
            done <<EOF
$(find -P "$physical_path" -maxdepth 1 -type f -print 2>/dev/null | LC_ALL=C sort)
EOF
        fi
    done

    [ "$unresolved_content" -eq 1 ] && return 2
    return 1
}

service_sendmail_greeting() {
    local configuration_path=""

    configuration_path="$(fs_path /etc/mail/sendmail.cf)"
    [ -r "$configuration_path" ] || return 1
    awk '
        /^[[:space:]]*O([[:space:]]+SmtpGreetingMessage|SmtpGreetingMessage[[:space:]]*=)/ {
            line=$0
            sub(/^[[:space:]]*O[[:space:]]*/, "", line)
            sub(/^SmtpGreetingMessage[[:space:]]*=?[[:space:]]*/, "", line)
            last=line
        }
        END {if (last != "") print last}
    ' "$configuration_path"
}

service_exim_value() {
    local key="$1"
    local candidate=""
    local match=""
    local last_value=""

    for candidate in /etc/exim4/exim4.conf.template /etc/exim4/exim4.conf /etc/exim/exim.conf; do
        candidate="$(fs_path "$candidate")"
        [ -r "$candidate" ] || continue
        match="$(service_read_simple_value "$key" "$candidate" 2>/dev/null || true)"
        [ -n "$match" ] && last_value="$match"
    done
    [ -n "$last_value" ] || return 1
    printf '%s\n' "$last_value"
}

service_exim_runtime_value() {
    local key="$1"
    local exim_path=""
    local output=""

    runtime_enabled || return 1
    exim_path="$(trusted_command exim4 2>/dev/null || true)"
    [ -n "$exim_path" ] || exim_path="$(trusted_command exim 2>/dev/null || true)"
    [ -n "$exim_path" ] || return 1
    output="$("$exim_path" -bP "$key" 2>/dev/null)" || return 1
    printf '%s\n' "$output" | awk -v target="$key" '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (index(line, target) == 1) {
                sub("^" target "[[:space:]]*=[[:space:]]*", "", line)
                print line
                exit
            }
        }
    '
}

check_u_62() {
    local missing_count=0
    local unresolved_count=0
    local checked_surfaces=0
    local state=1
    local activation_status=1
    local invocation_status=1
    local listener_status=1
    local legacy_active=0
    local legacy_uncertain=0
    local banner_path=""
    local physical_banner_path=""
    local provider=""
    local configuration_path=""
    local banner_value=""
    local banner_status=0
    local effective_metadata=""
    local bind_confidence=""
    local bind_configuration=""
    local bind_version=""

    checked_surfaces=$((checked_surfaces + 2))
    service_warning_collection_state /etc/issue
    state=$?
    [ "$state" -eq 1 ] && missing_count=$((missing_count + 1))
    [ "$state" -eq 2 ] && unresolved_count=$((unresolved_count + 1))
    service_warning_collection_state /etc/motd /run/motd.dynamic
    state=$?
    [ "$state" -eq 1 ] && missing_count=$((missing_count + 1))
    [ "$state" -eq 2 ] && unresolved_count=$((unresolved_count + 1))

    service_activation_state ssh.service sshd.service ssh.socket sshd.socket
    activation_status=$?
    if [ "$activation_status" -eq 0 ]; then
        checked_surfaces=$((checked_surfaces + 1))
        if runtime_enabled; then
            sshd_manager_has_custom_invocation >/dev/null 2>&1
            invocation_status=$?
            if [ "$invocation_status" -ne 1 ]; then
                unresolved_count=$((unresolved_count + 1))
            else
                banner_path="$(sshd_effective_value banner 2>/dev/null || true)"
                case "$(printf '%s' "$banner_path" | tr '[:upper:]' '[:lower:]')" in
                    ''|none) missing_count=$((missing_count + 1)) ;;
                    /*)
                        physical_banner_path="$(fs_path "$banner_path")"
                        service_warning_file_state "$physical_banner_path"
                        state=$?
                        [ "$state" -eq 1 ] && missing_count=$((missing_count + 1))
                        [ "$state" -eq 2 ] && unresolved_count=$((unresolved_count + 1))
                        ;;
                    *) unresolved_count=$((unresolved_count + 1)) ;;
                esac
                if declare -F scanner_sshd_static_ambiguous >/dev/null 2>&1 && \
                    scanner_sshd_static_ambiguous; then
                    unresolved_count=$((unresolved_count + 1))
                fi
            fi
        else
            unresolved_count=$((unresolved_count + 1))
        fi
    elif [ "$activation_status" -eq 2 ]; then
        unresolved_count=$((unresolved_count + 1))
    fi

    service_activation_state telnet.service telnet.socket telnet@.service telnetd.service telnetd.socket
    activation_status=$?
    service_legacy_enabled '^telnet$' && legacy_active=1
    legacy_uncertain="$SERVICE_LEGACY_UNCERTAIN"
    service_listener_state tcp 23
    listener_status=$?
    if [ "$activation_status" -eq 0 ] || [ "$legacy_active" -eq 1 ] || [ "$listener_status" -eq 0 ]; then
        checked_surfaces=$((checked_surfaces + 1))
        service_warning_collection_state /etc/issue.net
        state=$?
        [ "$state" -eq 1 ] && missing_count=$((missing_count + 1))
        [ "$state" -eq 2 ] && unresolved_count=$((unresolved_count + 1))
    elif [ "$activation_status" -eq 2 ] || [ "$listener_status" -eq 2 ] || [ "$legacy_uncertain" -eq 1 ]; then
        unresolved_count=$((unresolved_count + 1))
    fi

    service_detect_ftp
    for provider in $SERVICE_FTP_PROVIDERS; do
        checked_surfaces=$((checked_surfaces + 1))
        case "$provider" in
            vsftpd)
                banner_value="$(service_vsftpd_effective_banner 2>/dev/null)"
                banner_status=$?
                if [ "$banner_status" -eq 1 ]; then
                    missing_count=$((missing_count + 1))
                elif [ "$banner_status" -eq 2 ]; then
                    unresolved_count=$((unresolved_count + 1))
                else
                    service_login_warning_value_state "$banner_value"
                    state=$?
                    [ "$state" -eq 1 ] && missing_count=$((missing_count + 1))
                    [ "$state" -eq 2 ] && unresolved_count=$((unresolved_count + 1))
                fi
                ;;
            proftpd)
                banner_path="$(service_proftpd_value DisplayLogin 2>/dev/null || true)"
                if [ -z "$banner_path" ]; then
                    missing_count=$((missing_count + 1))
                elif [ "${banner_path#/}" != "$banner_path" ]; then
                    physical_banner_path="$(fs_path "$banner_path")"
                    service_warning_file_state "$physical_banner_path"
                    state=$?
                    [ "$state" -eq 1 ] && missing_count=$((missing_count + 1))
                    [ "$state" -eq 2 ] && unresolved_count=$((unresolved_count + 1))
                else
                    unresolved_count=$((unresolved_count + 1))
                fi
                ;;
            *) unresolved_count=$((unresolved_count + 1)) ;;
        esac
    done
    [ "$SERVICE_FTP_UNCERTAIN" -eq 1 ] && unresolved_count=$((unresolved_count + 1))

    service_detect_mail
    for provider in $SERVICE_MAIL_PROVIDERS; do
        checked_surfaces=$((checked_surfaces + 1))
        case "$provider" in
            postfix) banner_value="$(service_postfix_value smtpd_banner 2>/dev/null || true)" ;;
            sendmail) banner_value="$(service_sendmail_greeting 2>/dev/null || true)" ;;
            exim)
                banner_value="$(service_exim_runtime_value smtp_banner 2>/dev/null)"
                banner_status=$?
                if [ "$banner_status" -ne 0 ]; then
                    banner_value="$(service_exim_value smtp_banner 2>/dev/null || true)"
                    unresolved_count=$((unresolved_count + 1))
                fi
                ;;
            *) banner_value="" ;;
        esac
        service_login_warning_value_state "$banner_value"
        state=$?
        [ "$state" -eq 1 ] && missing_count=$((missing_count + 1))
        [ "$state" -eq 2 ] && unresolved_count=$((unresolved_count + 1))
    done
    [ "$SERVICE_MAIL_UNCERTAIN" -eq 1 ] && unresolved_count=$((unresolved_count + 1))

    service_detect_dns
    activation_status=$?
    if [ "$activation_status" -eq 0 ]; then
        checked_surfaces=$((checked_surfaces + 1))
        effective_metadata="$(service_bind_effective_file 2>/dev/null || true)"
        bind_confidence="${effective_metadata%%$'\t'*}"
        bind_configuration="${effective_metadata#*$'\t'}"
        if [ -n "$effective_metadata" ] && [ -r "$bind_configuration" ]; then
            bind_version="$(awk '
                {
                    line=$0
                    sub(/^[[:space:]]+/, "", line)
                    if (line == "" || line ~ /^#/ || line ~ /^\/\//) next
                    if (tolower(line) ~ /^version[[:space:]]+/) {
                        sub(/^[^[:space:]]+[[:space:]]+/, "", line)
                        sub(/;.*/, "", line)
                        last=line
                    }
                }
                END {if (last != "") print last}
            ' "$bind_configuration")"
            service_login_warning_value_state "$bind_version"
            state=$?
            [ "$state" -eq 1 ] && missing_count=$((missing_count + 1))
            [ "$state" -eq 2 ] && unresolved_count=$((unresolved_count + 1))
            [ "$bind_confidence" = "validated" ] || unresolved_count=$((unresolved_count + 1))
        else
            unresolved_count=$((unresolved_count + 1))
        fi
    elif [ "$activation_status" -eq 2 ]; then
        unresolved_count=$((unresolved_count + 1))
    fi

    if [ "$missing_count" -gt 0 ]; then
        if [ "$checked_surfaces" -eq 2 ] && [ "$unresolved_count" -eq 0 ]; then
            set_result VULNERABLE "서버 또는 활성 원격 서비스에서 로그인 경고 메시지 설정 누락을 확인했습니다." \
                "checked_surfaces=${checked_surfaces}\nmissing_warnings=${missing_count}\nunresolved_warnings=${unresolved_count}\nbanner_text=not_collected" \
                true technical true configuration.u62.v1
        else
            set_result VULNERABLE "서버 또는 활성 원격 서비스에서 로그인 경고 메시지 설정 누락을 확인했습니다." \
                "checked_surfaces=${checked_surfaces}\nmissing_warnings=${missing_count}\nunresolved_warnings=${unresolved_count}\nbanner_text=not_collected"
        fi
    elif [ "$unresolved_count" -gt 0 ]; then
        set_result MANUAL "설정된 배너가 조직의 법적·보안 경고 문구를 충족하는지 확인해야 합니다." \
            "checked_surfaces=${checked_surfaces}\nmissing_warnings=0\nunresolved_warnings=${unresolved_count}\nbanner_text=not_collected" true technical
    else
        set_result GOOD "서버와 활성 원격 서비스에 명시적인 보안 경고 문구가 설정되어 있습니다." \
            "checked_surfaces=${checked_surfaces}\nmissing_warnings=0\nbanner_text=not_collected"
    fi
}

service_trusted_absolute_command() {
    local physical_path="$1"
    local owner=""
    local mode=""

    [ -x "$physical_path" ] || return 1
    owner="$(stat_owner "$physical_path" 2>/dev/null || true)"
    mode="$(stat_mode "$physical_path" 2>/dev/null || true)"
    [ "$owner" = "root" ] || return 1
    mode_has_untrusted_write "$mode" && return 1
    printf '%s\n' "$physical_path"
}

service_parent_chain_trusted() {
    local path="$1"
    local parent="${path%/*}"
    local boundary=""
    local owner=""
    local mode=""

    canonical_scan_root_into boundary || return 1
    [ -n "$boundary" ] || boundary="/"
    while [ -n "$parent" ]; do
        owner="$(stat_owner "$parent" 2>/dev/null || true)"
        mode="$(stat_mode "$parent" 2>/dev/null || true)"
        [ "$owner" = "root" ] || return 1
        mode_group_or_other_writable "$mode" && return 1
        [ "$parent" = "$boundary" ] && return 0
        [ "$parent" = "/" ] && return 0
        parent="${parent%/*}"
        [ -n "$parent" ] || parent="/"
    done
    return 1
}

service_sudo_provider() {
    local sudo_path=""
    local rooted_sudo_path=""
    local version_output=""
    local cargo_sudo=""
    local sudo_rs_present=0
    local sudo_ws_present=0

    if runtime_enabled; then
        sudo_path="$(trusted_command sudo 2>/dev/null || true)"
        if [ -n "$sudo_path" ]; then
            version_output="$($sudo_path --version 2>/dev/null | head -n 1 || true)"
            if printf '%s\n' "$version_output" | grep -Eiq 'sudo[- ]?rs'; then
                printf 'sudo-rs\n'
            else
                printf 'sudo.ws\n'
            fi
            return 0
        fi
    fi

    cargo_sudo="$(fs_path /usr/lib/cargo/bin/sudo)"
    rooted_sudo_path="$(fs_path /usr/bin/sudo 2>/dev/null || true)"
    case "$rooted_sudo_path" in
        */usr/lib/cargo/bin/sudo) sudo_rs_present=1 ;;
        '') ;;
        *) [ -x "$rooted_sudo_path" ] && sudo_ws_present=1 ;;
    esac
    if [ -x "$cargo_sudo" ] || [ -e "$(fs_path /etc/sudoers-rs)" ]; then
        sudo_rs_present=1
    fi
    if [ -x "$(fs_path /usr/bin/sudo.ws 2>/dev/null || true)" ]; then
        sudo_ws_present=1
    fi
    if [ "$sudo_rs_present" -eq 1 ] && [ "$sudo_ws_present" -eq 1 ]; then
        printf 'ambiguous\n'
        return 0
    fi
    if [ "$sudo_rs_present" -eq 1 ]; then
        printf 'sudo-rs\n'
        return 0
    fi
    if [ "$sudo_ws_present" -eq 1 ]; then
        printf 'sudo.ws\n'
        return 0
    fi
    if [ -e "$(fs_path /etc/sudoers)" ]; then
        printf 'policy-only\n'
        return 0
    fi
    return 1
}

service_sudoers_directives() {
    local policy_file="$1"

    [ -r "$policy_file" ] || return 1
    awk '
        {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            if (line ~ /^(@include|#include)[[:space:]]+/) type="include"
            else if (line ~ /^(@includedir|#includedir)[[:space:]]+/) type="includedir"
            else next
            sub(/^(@include|#include|@includedir|#includedir)[[:space:]]+/, "", line)
            sub(/[[:space:]]+#.*/, "", line)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            if (line ~ /^".*"$/ || line ~ /^\047.*\047$/) line=substr(line,2,length(line)-2)
            print type "\t" line
        }
    ' "$policy_file"
}

# The collector follows the same include graph that sudoers and sudo-rs use.
# Ambiguous paths are recorded instead of being silently omitted.
service_collect_sudoers_graph() {
    local policy_file="$1"
    local file_list="$2"
    local directory_list="$3"
    local unresolved_list="$4"
    local depth="${5:-0}"
    local directive_type=""
    local include_path=""
    local resolved_path=""
    local safe_resolved_path=""
    local included_file=""
    local basename_value=""

    if [ "$depth" -ge 32 ]; then
        printf 'depth_limit\n' >> "$unresolved_list"
        return
    fi
    [ -r "$policy_file" ] || {
        printf 'unreadable_include\n' >> "$unresolved_list"
        return
    }
    grep -Fqx -- "$policy_file" "$file_list" 2>/dev/null && return
    printf '%s\n' "$policy_file" >> "$file_list"

    while IFS=$'\t' read -r directive_type include_path; do
        [ -n "$directive_type$include_path" ] || continue
        [ -n "$include_path" ] || {
            printf 'empty_include\n' >> "$unresolved_list"
            continue
        }
        case "$include_path" in
            *'%'*|*'*'*|*'?'*|*'['*|*\\*)
                printf 'dynamic_include\n' >> "$unresolved_list"
                continue
                ;;
            /*) resolved_path="$(fs_path "$include_path")" ;;
            *) resolved_path="${policy_file%/*}/$include_path" ;;
        esac

        if [ "$directive_type" = "include" ]; then
            safe_resolved_path="$(resolve_rooted_read_path "$resolved_path" 2>/dev/null || true)"
            if [ -n "$safe_resolved_path" ]; then
                service_collect_sudoers_graph "$safe_resolved_path" "$file_list" "$directory_list" "$unresolved_list" $((depth + 1))
            else
                printf 'missing_include\n' >> "$unresolved_list"
            fi
            continue
        fi

        safe_resolved_path="$(resolve_rooted_directory "$resolved_path" 2>/dev/null || true)"
        if [ -z "$safe_resolved_path" ]; then
            printf 'missing_includedir\n' >> "$unresolved_list"
            continue
        fi
        resolved_path="$safe_resolved_path"
        grep -Fqx -- "$resolved_path" "$directory_list" 2>/dev/null || printf '%s\n' "$resolved_path" >> "$directory_list"
        while IFS= read -r included_file; do
            basename_value="${included_file##*/}"
            case "$basename_value" in
                *.*|*~*) continue ;;
            esac
            safe_resolved_path="$(resolve_rooted_read_path "$included_file" 2>/dev/null || true)"
            if [ -n "$safe_resolved_path" ]; then
                service_collect_sudoers_graph "$safe_resolved_path" "$file_list" "$directory_list" "$unresolved_list" $((depth + 1))
            else
                printf 'unreadable_include\n' >> "$unresolved_list"
            fi
        done <<EOF
$(find -P "$resolved_path" -maxdepth 1 \( -type f -o -type l \) -print 2>/dev/null | LC_ALL=C sort)
EOF
    done <<EOF
$(service_sudoers_directives "$policy_file")
EOF
}

check_u_63() {
    local provider=""
    local sudoers_path=""
    local safe_sudoers_path=""
    local owner_uid=""
    local mode=""
    local decimal_mode=""
    local policy_kind="kisa_sudoers"
    local evidence=""

    provider="$(service_sudo_provider 2>/dev/null || true)"
    if [ -z "$provider" ]; then
        set_result NOT_APPLICABLE "sudo 공급자와 정책 파일을 확인하지 못했습니다." "sudo_provider=absent" false
        return
    fi
    if [ "$provider" = "ambiguous" ]; then
        set_result MANUAL "오프라인 루트에서 sudo와 sudo-rs 중 활성 공급자를 확정할 수 없습니다." \
            "sudo_provider=ambiguous\nactive_policy=unknown" true runtime
        return
    fi

    if [ "$provider" = "sudo-rs" ] && [ -e "$(fs_path /etc/sudoers-rs 2>/dev/null || true)" ]; then
        sudoers_path="$(fs_path /etc/sudoers-rs)"
        policy_kind="sudo_rs_compatibility"
    else
        sudoers_path="$(fs_path /etc/sudoers)"
    fi
    if [ ! -e "$sudoers_path" ]; then
        set_result VULNERABLE "활성 sudo 공급자의 정책 파일이 없습니다." \
            "sudo_provider=${provider}\npolicy_kind=${policy_kind}\nactive_policy=absent"
        return
    fi
    safe_sudoers_path="$(resolve_rooted_read_path "$sudoers_path" 2>/dev/null || true)"
    if [ -z "$safe_sudoers_path" ]; then
        set_result ERROR "활성 sudo 정책 경로가 검사 루트 밖을 가리키거나 읽을 수 없습니다." "sudo_provider=${provider}\nactive_policy=unresolved"
        return
    fi
    sudoers_path="$safe_sudoers_path"

    owner_uid="$(stat_uid "$sudoers_path" 2>/dev/null || true)"
    mode="$(stat_mode "$sudoers_path" 2>/dev/null || true)"
    decimal_mode="$(mode_to_decimal "$mode" 2>/dev/null || true)"
    evidence="sudo_provider=${provider}\npolicy_kind=${policy_kind}\npolicy_path=$(display_path "$sudoers_path")\nowner_uid=${owner_uid:-unknown}\nmode=${mode:-unknown}"

    if [ "$policy_kind" != "kisa_sudoers" ]; then
        set_result MANUAL "sudo-rs 전용 정책 파일은 KISA U-63의 명시 경로가 아니므로 별도 검증이 필요합니다." "$evidence" true technical
    elif [ -z "$owner_uid" ] || [ -z "$decimal_mode" ]; then
        set_result ERROR "sudo 정책 파일의 소유자 또는 권한을 읽지 못했습니다." "$evidence"
    elif [ "$owner_uid" != "0" ] || ! mode_is_at_most "$mode" 640; then
        set_result VULNERABLE "sudo 정책 파일의 소유자 또는 권한이 KISA 기준을 벗어났습니다." "$evidence"
    elif [ "$decimal_mode" -eq $((8#640)) ]; then
        set_result GOOD "sudo 정책 파일이 root 소유이며 권한이 정확히 0640입니다." "$evidence"
    else
        set_result MANUAL "sudo 정책 파일 권한은 0640보다 엄격하지만 가이드의 양호 조건과 정확히 일치하지 않습니다." "$evidence" true technical
    fi
}
