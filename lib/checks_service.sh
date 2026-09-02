# shellcheck shell=bash

# Service checks cover U-34 through U-63 for Ubuntu 26.04 and RHEL 10.

SERVICE_ACTIVATION_EVIDENCE=""
SERVICE_FTP_PROVIDERS=""
SERVICE_FTP_UNCERTAIN=0
SERVICE_MAIL_PROVIDERS=""
SERVICE_MAIL_UNCERTAIN=0
SERVICE_SNMP_CONFIG_UNCERTAIN=0
SERVICE_SNMP_ENDPOINT_ACTIVE=0

service_append_word() {
    local current_value="$1"
    local new_value="$2"

    case " $current_value " in
        *" $new_value "*) printf '%s\n' "$current_value" ;;
        *) printf '%s%s%s\n' "$current_value" "${current_value:+ }" "$new_value" ;;
    esac
}

service_file_has_active_entry() {
    local physical_path="$1"
    local expression="$2"

    [ -r "$physical_path" ] || return 1
    awk -v expression="$expression" '
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

    configuration_path="$(fs_path /etc/inetd.conf)"
    [ -r "$configuration_path" ] || return 1
    awk -v expression="$service_expression" '
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

    main_path="$(fs_path /etc/xinetd.conf)"
    [ -r "$main_path" ] && printf '%s\n' "$main_path"

    included_directory="/etc/xinetd.d"
    physical_directory="$(fs_path "$included_directory")"
    if [ -d "$physical_directory" ]; then
        find -P "$physical_directory" -maxdepth 1 -type f -print 2>/dev/null | LC_ALL=C sort
    fi

    if [ -r "$main_path" ]; then
        while IFS= read -r included_directory; do
            case "$included_directory" in
                /*) ;;
                *) continue ;;
            esac
            physical_directory="$(fs_path "$included_directory")"
            [ -d "$physical_directory" ] || continue
            find -P "$physical_directory" -maxdepth 1 -type f -print 2>/dev/null | LC_ALL=C sort
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
    fi
}

service_xinetd_enabled() {
    local service_expression="$1"
    local configuration_file=""

    while IFS= read -r configuration_file; do
        [ -r "$configuration_file" ] || continue
        if awk -v expression="$service_expression" '
            function finish_block() {
                if (in_target && disable_value != "yes") enabled=1
                in_target=0
                disable_value=""
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
                    next
                }
                if (in_target && line ~ /^disable[[:space:]]*=/) {
                    value=line
                    sub(/^[^=]*=/, "", value)
                    sub(/[[:space:]#].*$/, "", value)
                    gsub(/[[:space:]]/, "", value)
                    disable_value=tolower(value)
                }
                if (in_target && line ~ /^}/) finish_block()
            }
            END {
                finish_block()
                exit(enabled ? 0 : 1)
            }
        ' "$configuration_file"; then
            return 0
        fi
    done <<EOF
$(service_xinetd_files | awk '!seen[$0]++')
EOF

    return 1
}

service_legacy_enabled() {
    local service_expression="$1"

    service_inetd_enabled "$service_expression" || service_xinetd_enabled "$service_expression"
}

service_unit_definition_exists() {
    local unit_name="$1"
    local logical_directory=""
    local physical_directory=""

    for logical_directory in \
        /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system \
        /usr/lib/systemd/system /lib/systemd/system; do
        physical_directory="$(fs_path "$logical_directory")"
        [ -e "$physical_directory/$unit_name" ] && return 0
    done
    return 1
}

service_unit_statically_enabled() {
    local unit_name="$1"
    local logical_directory=""
    local physical_directory=""

    for logical_directory in /etc/systemd/system /run/systemd/system; do
        physical_directory="$(fs_path "$logical_directory")"
        [ -d "$physical_directory" ] || continue
        if find -P "$physical_directory" -mindepth 2 -maxdepth 3 \
            \( -path '*.wants/*' -o -path '*.requires/*' \) \
            -name "$unit_name" -print -quit 2>/dev/null | grep -q .; then
            return 0
        fi
    done
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
    local saw_unit=0
    local saw_definition=0

    SERVICE_ACTIVATION_EVIDENCE=""

    if runtime_enabled; then
        systemctl_path="$(trusted_command systemctl 2>/dev/null || true)"
        [ -n "$systemctl_path" ] || return 2

        for unit_name in "$@"; do
            properties="$($systemctl_path show "$unit_name" \
                -p LoadState -p ActiveState -p UnitFileState --no-pager 2>/dev/null)" || command_status=$?
            load_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "LoadState" {print $2; exit}')"
            active_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "ActiveState" {print $2; exit}')"
            unit_file_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "UnitFileState" {print $2; exit}')"
            if [ "$command_status" -ne 0 ] && [ "$load_state" != "not-found" ]; then
                return 2
            fi
            command_status=0
            [ -n "$load_state" ] && [ "$load_state" != "not-found" ] || continue
            saw_unit=1
            SERVICE_ACTIVATION_EVIDENCE="${SERVICE_ACTIVATION_EVIDENCE}unit=${unit_name},active=${active_state:-unknown},enabled=${unit_file_state:-unknown}\n"
            case "$active_state" in
                active|activating|reloading) return 0 ;;
            esac
            case "$unit_file_state" in
                enabled|enabled-runtime|linked|linked-runtime) return 0 ;;
            esac
        done

        [ "$saw_unit" -eq 1 ] && return 1
        return 1
    fi

    for unit_name in "$@"; do
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
    local port_number=""
    local listener_output=""
    local listener_status=0

    runtime_enabled || return 2
    trusted_command ss >/dev/null 2>&1 || return 2

    for port_number in "$@"; do
        listener_output="$(port_listener_facts "$port_number")"
        listener_status=$?
        [ "$listener_status" -eq 0 ] || return 2
        [ -n "$listener_output" ] && return 0
    done
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

    runtime_enabled || return 1
    systemctl_path="$(trusted_command systemctl)" || return 2
    for unit in "$@"; do
        properties="$($systemctl_path show "$unit" -p LoadState -p ExecStart --no-pager 2>/dev/null)" || command_status=$?
        load_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "LoadState" {print $2; exit}')"
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

    runtime_enabled || return 1
    systemctl_path="$(trusted_command systemctl)" || return 2
    for unit in vsftpd.service proftpd.service pure-ftpd.service; do
        properties="$($systemctl_path show "$unit" -p LoadState -p ExecStart --no-pager 2>/dev/null)" || command_status=$?
        load_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "LoadState" {print $2; exit}')"
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

    main_path="$(fs_path /etc/exports)"
    [ -r "$main_path" ] && printf '%s\n' "$main_path"

    directory_path="$(fs_path /etc/exports.d)"
    if [ -d "$directory_path" ]; then
        find -P "$directory_path" -maxdepth 1 -type f -name '*.exports' -print 2>/dev/null | LC_ALL=C sort
    fi
}

service_count_static_exports() {
    local configuration_file=""

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
$(service_nfs_export_files)
EOF
}

service_static_exports_unrestricted() {
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
$(service_nfs_export_files)
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

service_vsftpd_configuration() {
    local candidate=""

    if [ "$PLATFORM_ID" = "rhel" ]; then
        for candidate in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
            candidate="$(fs_path "$candidate")"
            [ -r "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
        done
    else
        for candidate in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
            candidate="$(fs_path "$candidate")"
            [ -r "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
        done
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

    if [ "$PLATFORM_ID" = "ubuntu" ]; then
        for candidate in /etc/bind/named.conf /etc/named.conf; do
            candidate="$(fs_path "$candidate")"
            [ -r "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
        done
    else
        for candidate in /etc/named.conf /etc/bind/named.conf; do
            candidate="$(fs_path "$candidate")"
            [ -r "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
        done
    fi
    return 1
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

    service_activation_state named.service named-chroot.service bind9.service named.socket bind9.socket
    activation_status=$?
    if [ "$activation_status" -eq 0 ]; then
        service_units_have_custom_configuration '([[:space:]]-[ct]([^[:space:]]*|$))' \
            named.service named-chroot.service bind9.service >/dev/null 2>&1
        listener_status=$?
        [ "$listener_status" -eq 0 ] && return 2
        [ "$listener_status" -eq 2 ] && return 2
        return 0
    fi

    service_listener_state 53
    listener_status=$?
    [ "$listener_status" -eq 0 ] && return 2

    if [ "$activation_status" -eq 2 ] || [ "$listener_status" -eq 2 ]; then
        return 2
    fi
    return 1
}

service_snmp_files() {
    local candidate=""
    local directory_path=""

    for candidate in /etc/snmp/snmpd.conf /usr/share/snmp/snmpd.conf; do
        candidate="$(fs_path "$candidate")"
        [ -r "$candidate" ] && printf '%s\n' "$candidate"
    done
    for candidate in /etc/snmp/snmpd.conf.d /etc/snmp/snmpd.d; do
        directory_path="$(fs_path "$candidate")"
        [ -d "$directory_path" ] || continue
        find -P "$directory_path" -maxdepth 1 -type f -name '*.conf' -print 2>/dev/null | LC_ALL=C sort
    done
}

service_detect_snmp() {
    local activation_status=1
    local listener_status=1

    SERVICE_SNMP_CONFIG_UNCERTAIN=0
    SERVICE_SNMP_ENDPOINT_ACTIVE=0
    service_activation_state snmpd.service snmpd.socket
    activation_status=$?
    if [ "$activation_status" -eq 0 ]; then
        SERVICE_SNMP_ENDPOINT_ACTIVE=1
        service_units_have_custom_configuration '([[:space:]]-[cC]([^[:space:]]*|$))' snmpd.service >/dev/null 2>&1
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

    [ -s "$physical_path" ] || return 1
    if grep -Eiq \
        'authori[sz]ed|unauthori[sz]ed|prohibit|monitor|security notice|warning|인가|비인가|금지|모니터링|보안|경고|접근' \
        "$physical_path" 2>/dev/null; then
        return 0
    fi
    return 2
}

service_nfs_state() {
    local activation_status=1
    local listener_status=1

    service_activation_state nfs-server.service nfs.service nfs-kernel-server.service nfs-server.socket
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
                    if ((tolower(name) == "guest ok" || tolower(name) == "public" || tolower(name) == "guest only") && tolower(value) == "yes") found=1
                }
                END {exit(found ? 0 : 1)}
            '; then
                return 0
            fi
            return 1
        fi
    fi

    if service_file_has_active_entry "$configuration_path" \
        '^[[:space:]]*(guest[[:space:]]+ok|public|guest[[:space:]]+only)[[:space:]]*=[[:space:]]*(yes|true|1)([[:space:]]|$)'; then
        return 0
    fi
    return 2
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
    service_listener_state 79
    listener_status=$?

    evidence="${evidence}legacy_activation=${legacy_active}\nlistener_port_79=$([ "$listener_status" -eq 0 ] && printf active || printf inactive_or_unavailable)"
    if [ "$activation_status" -eq 0 ] || [ "$legacy_active" -eq 1 ] || [ "$listener_status" -eq 0 ]; then
        set_result VULNERABLE "Finger 서비스의 활성화 경로가 확인됐습니다." "$evidence"
    elif [ "$activation_status" -eq 2 ] || [ "$listener_status" -eq 2 ]; then
        set_result MANUAL "오프라인 또는 제한된 런타임에서는 Finger 활성 상태를 확정할 수 없습니다." "$evidence"
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
        service_static_exports_have_all_squash && vulnerable_count=$((vulnerable_count + 1))
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
        set_result MANUAL "공유 서비스의 유효 설정 또는 외부 접근 경로를 모두 확정할 수 없습니다." "$evidence"
    elif [ "$active_count" -eq 0 ]; then
        set_result NOT_APPLICABLE "활성 FTP, NFS 또는 Samba 공유 서비스를 확인하지 못했습니다." "$evidence" false
    else
        set_result GOOD "활성 공유 서비스의 로컬 유효 설정에서 익명 접근이 제한되어 있습니다." "$evidence"
    fi
}

check_u_36() {
    local activation_status=1
    local listener_status=1
    local legacy_active=0
    local evidence=""

    service_activation_state \
        rlogin.service rlogin.socket rlogin@.service \
        rsh.service rsh.socket rsh@.service \
        rexec.service rexec.socket rexec@.service
    activation_status=$?
    evidence="$SERVICE_ACTIVATION_EVIDENCE"
    service_legacy_enabled '^(login|rlogin|shell|rsh|exec|rexec)$' && legacy_active=1
    service_listener_state 512 513 514
    listener_status=$?

    evidence="${evidence}legacy_activation=${legacy_active}\nr_service_listener=$([ "$listener_status" -eq 0 ] && printf active || printf inactive_or_unavailable)"
    if [ "$activation_status" -eq 0 ] || [ "$legacy_active" -eq 1 ] || [ "$listener_status" -eq 0 ]; then
        set_result VULNERABLE "rlogin, rsh 또는 rexec 활성화 경로가 확인됐습니다." "$evidence"
    elif [ "$activation_status" -eq 2 ] || [ "$listener_status" -eq 2 ]; then
        set_result MANUAL "r 계열 서비스의 실제 활성 상태를 확정할 수 없습니다." "$evidence"
    else
        set_result GOOD "r 계열 서비스가 systemd, inetd/xinetd와 수신 포트에서 비활성 상태입니다." "$evidence"
    fi
}

check_u_37() {
    local command_path=""
    local owner=""
    local mode=""
    local list_file=""
    local related_file=""
    local checked_commands=0
    local checked_files=0
    local violations=0
    local stat_failures=0
    local scan_failures=0
    local evidence=""

    for command_path in /usr/bin/crontab /usr/bin/at; do
        command_path="$(fs_path "$command_path")"
        [ -e "$command_path" ] || continue
        checked_commands=$((checked_commands + 1))
        owner="$(stat_owner "$command_path" 2>/dev/null || true)"
        mode="$(stat_mode "$command_path" 2>/dev/null || true)"
        if [ -z "$owner" ] || [ -z "$mode" ]; then
            stat_failures=$((stat_failures + 1))
        elif [ "$owner" != "root" ] || ! mode_is_at_most "$mode" 750 || service_mode_has_special_bits "$mode"; then
            violations=$((violations + 1))
        fi
    done

    list_file="$(new_scratch_file u37-files)" || {
        set_result ERROR "cron 및 at 파일 목록을 안전하게 만들 수 없습니다." ""
        return
    }
    : > "$list_file"
    for related_file in /etc/crontab /etc/anacrontab /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
        related_file="$(fs_path "$related_file")"
        [ -f "$related_file" ] && printf '%s\0' "$related_file" >> "$list_file"
    done
    for related_file in \
        /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
        /var/spool/cron /var/spool/cron/crontabs /var/spool/cron/atjobs /var/spool/at /var/spool/anacron; do
        related_file="$(fs_path "$related_file")"
        [ -d "$related_file" ] || continue
        find -P "$related_file" -xdev -type f -print0 2>/dev/null >> "$list_file" || scan_failures=$((scan_failures + 1))
    done

    while IFS= read -r -d '' related_file; do
        checked_files=$((checked_files + 1))
        owner="$(stat_owner "$related_file" 2>/dev/null || true)"
        mode="$(stat_mode "$related_file" 2>/dev/null || true)"
        if [ -z "$owner" ] || [ -z "$mode" ]; then
            stat_failures=$((stat_failures + 1))
        elif [ "$owner" != "root" ] || ! mode_is_at_most "$mode" 640; then
            violations=$((violations + 1))
        fi
    done < "$list_file"

    evidence="checked_commands=${checked_commands}\nchecked_related_files=${checked_files}\nviolations=${violations}\nstat_failures=${stat_failures}\nscan_failures=${scan_failures}"
    if [ "$violations" -gt 0 ]; then
        set_result VULNERABLE "crontab 또는 at 실행 파일과 관련 파일이 KISA 소유자·권한 기준을 벗어났습니다." "$evidence"
    elif [ "$stat_failures" -gt 0 ] || [ "$scan_failures" -gt 0 ]; then
        set_result ERROR "cron 또는 at 관련 파일의 소유자·권한을 읽지 못했습니다." "$evidence"
    elif [ "$checked_commands" -eq 0 ] && [ "$checked_files" -eq 0 ]; then
        set_result NOT_APPLICABLE "cron 및 at 구성 요소가 설치된 증거를 확인하지 못했습니다." "$evidence" false
    else
        set_result GOOD "crontab 및 at 실행 파일과 관련 파일이 KISA 소유자·권한 기준을 충족합니다." "$evidence"
    fi
}

check_u_38() {
    local activation_status=1
    local listener_status=1
    local legacy_active=0
    local evidence=""

    service_activation_state \
        echo.service echo.socket echo-stream.socket echo-dgram.socket \
        discard.service discard.socket discard-stream.socket discard-dgram.socket \
        daytime.service daytime.socket daytime-stream.socket daytime-dgram.socket \
        chargen.service chargen.socket chargen-stream.socket chargen-dgram.socket
    activation_status=$?
    evidence="$SERVICE_ACTIVATION_EVIDENCE"
    service_legacy_enabled '^(echo|discard|daytime|chargen)$' && legacy_active=1
    service_listener_state 7 9 13 19
    listener_status=$?

    evidence="${evidence}legacy_activation=${legacy_active}\nlegacy_dos_listener=$([ "$listener_status" -eq 0 ] && printf active || printf inactive_or_unavailable)"
    if [ "$activation_status" -eq 0 ] || [ "$legacy_active" -eq 1 ] || [ "$listener_status" -eq 0 ]; then
        set_result VULNERABLE "echo, discard, daytime 또는 chargen 서비스 활성화 경로가 확인됐습니다." "$evidence"
    elif [ "$activation_status" -eq 2 ] || [ "$listener_status" -eq 2 ]; then
        set_result MANUAL "DoS 공격에 취약한 레거시 서비스의 활성 상태를 확정할 수 없습니다." "$evidence"
    else
        set_result GOOD "DoS 공격에 취약한 레거시 서비스가 비활성 상태입니다." "$evidence"
    fi
}

check_u_39() {
    local nfs_status=1

    service_nfs_state
    nfs_status=$?
    if [ "$nfs_status" -eq 0 ]; then
        set_result MANUAL \
            "NFS 서비스가 활성 상태이며 업무상 필요 여부는 자산 용도와 함께 확인해야 합니다." \
            "nfs_activation=active"
    elif [ "$nfs_status" -eq 2 ]; then
        set_result MANUAL "NFS 서비스의 실제 활성 상태를 확정할 수 없습니다." "nfs_activation=unknown"
    else
        set_result GOOD "NFS 서비스의 활성화 경로와 수신 포트를 확인하지 못했습니다." "nfs_activation=inactive"
    fi
}

check_u_40() {
    local nfs_status=1
    local configuration_file=""
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

    while IFS= read -r configuration_file; do
        [ -r "$configuration_file" ] || continue
        file_count=$((file_count + 1))
        owner="$(stat_owner "$configuration_file" 2>/dev/null || true)"
        mode="$(stat_mode "$configuration_file" 2>/dev/null || true)"
        if [ "$owner" != "root" ] || [ -z "$mode" ] || ! mode_is_at_most "$mode" 644; then
            permission_violations=$((permission_violations + 1))
        fi
    done <<EOF
$(service_nfs_export_files)
EOF

    export_count="$(service_count_static_exports | awk '{sum+=$1} END {print sum+0}')"
    service_static_exports_unrestricted && unrestricted_count=$((unrestricted_count + 1))

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
    if [ "$runtime_collection_error" -gt 0 ]; then
        set_result ERROR "활성 NFS export의 런타임 테이블을 수집하지 못했습니다." "$evidence"
    elif [ "$permission_violations" -gt 0 ] || [ "$unrestricted_count" -gt 0 ]; then
        set_result VULNERABLE "NFS 설정 파일 권한 또는 export 접근 통제가 KISA 기준을 벗어났습니다." "$evidence"
    elif [ "$nfs_status" -eq 2 ]; then
        set_result MANUAL "NFS 런타임 상태와 유효 export 구성을 확정할 수 없습니다." "$evidence"
    elif [ "$nfs_status" -ne 0 ] && [ "$export_count" -eq 0 ]; then
        set_result NOT_APPLICABLE "활성 NFS 서비스와 구성된 export를 확인하지 못했습니다." "$evidence" false
    elif [ "$export_count" -eq 0 ]; then
        set_result MANUAL "NFS 서비스는 활성 상태지만 유효 export를 확인하지 못했습니다." "$evidence"
    else
        set_result GOOD "NFS export가 제한된 대상에만 설정됐고 설정 파일 권한이 0644 이하입니다." "$evidence"
    fi
}

check_u_41() {
    local activation_status=1

    service_activation_state autofs.service automount.service
    activation_status=$?
    if [ "$activation_status" -eq 0 ]; then
        set_result VULNERABLE "automount 또는 autofs 서비스 활성화 경로가 확인됐습니다." "$SERVICE_ACTIVATION_EVIDENCE"
    elif [ "$activation_status" -eq 2 ]; then
        set_result MANUAL "automount 또는 autofs의 실제 활성 상태를 확정할 수 없습니다." "$SERVICE_ACTIVATION_EVIDENCE"
    else
        set_result GOOD "automount와 autofs 서비스가 비활성 상태입니다." "activation=inactive"
    fi
}

check_u_42() {
    local dangerous_status=1
    local general_status=1
    local listener_status=1
    local legacy_active=0
    local dangerous_evidence=""
    local general_evidence=""

    service_activation_state \
        rpc-cmsd.service rpc-ttdbserver.service sadmind.service walld.service sprayd.service \
        rstatd.service rusersd.service rexd.service rpc-rquotad.service rpc-yppasswdd.service
    dangerous_status=$?
    dangerous_evidence="$SERVICE_ACTIVATION_EVIDENCE"
    service_legacy_enabled '^(rpc\.(cmsd|ttdbserver|sadmind|walld|sprayd|rstatd|rusersd|rexd|rquotad|yppasswdd))$' && legacy_active=1

    service_activation_state \
        rpcbind.service rpcbind.socket rpc-statd.service rpc-statd-notify.service \
        rpc-gssd.service rpc-svcgssd.service rpc-idmapd.service
    general_status=$?
    general_evidence="$SERVICE_ACTIVATION_EVIDENCE"
    service_listener_state 111
    listener_status=$?

    if [ "$dangerous_status" -eq 0 ] || [ "$legacy_active" -eq 1 ]; then
        set_result VULNERABLE \
            "취약한 레거시 RPC 서비스의 활성화 경로가 확인됐습니다." \
            "${dangerous_evidence}legacy_dangerous_rpc=${legacy_active}"
    elif [ "$general_status" -eq 0 ] || [ "$listener_status" -eq 0 ]; then
        set_result MANUAL \
            "RPC 기반 서비스가 활성 상태이며 NFS 등 업무 의존성과 필요성을 확인해야 합니다." \
            "${general_evidence}rpc_listener=$([ "$listener_status" -eq 0 ] && printf active || printf inactive)"
    elif [ "$dangerous_status" -eq 2 ] || [ "$general_status" -eq 2 ] || [ "$listener_status" -eq 2 ]; then
        set_result MANUAL "RPC 서비스의 실제 활성 상태를 확정할 수 없습니다." "${dangerous_evidence}${general_evidence}"
    else
        set_result GOOD "레거시 RPC 서비스와 rpcbind 활성화 경로가 확인되지 않았습니다." "rpc_activation=inactive"
    fi
}

check_u_43() {
    local activation_status=1
    local rpc_output=""
    local rpcinfo_path=""

    service_activation_state \
        ypbind.service yppasswdd.service ypserv.service ypxfrd.service \
        nis.service nis-domainname.service
    activation_status=$?

    if runtime_enabled; then
        rpcinfo_path="$(trusted_command rpcinfo 2>/dev/null || true)"
        if [ -n "$rpcinfo_path" ]; then
            rpc_output="$($rpcinfo_path -p localhost 2>/dev/null || true)"
            if printf '%s\n' "$rpc_output" | awk '$NF ~ /^(ypbind|yppasswdd|ypserv|ypxfrd)$/ {found=1} END {exit(found ? 0 : 1)}'; then
                activation_status=0
            fi
        fi
    fi

    if [ "$activation_status" -eq 0 ]; then
        set_result VULNERABLE "NIS 계열 서비스가 활성 상태입니다." "$SERVICE_ACTIVATION_EVIDENCE"
    elif [ "$activation_status" -eq 2 ]; then
        set_result MANUAL "NIS 계열 서비스의 실제 활성 상태를 확정할 수 없습니다." "$SERVICE_ACTIVATION_EVIDENCE"
    else
        set_result GOOD "NIS 계열 서비스가 비활성 상태입니다." "nis_activation=inactive"
    fi
}

check_u_44() {
    local activation_status=1
    local listener_status=1
    local legacy_active=0
    local evidence=""

    service_activation_state \
        tftp.service tftp.socket tftpd.service tftpd.socket tftpd-hpa.service \
        talk.service talk.socket ntalk.service ntalk.socket
    activation_status=$?
    evidence="$SERVICE_ACTIVATION_EVIDENCE"
    service_legacy_enabled '^(tftp|talk|ntalk)$' && legacy_active=1
    service_listener_state 69 517 518
    listener_status=$?

    evidence="${evidence}legacy_activation=${legacy_active}\nservice_listener=$([ "$listener_status" -eq 0 ] && printf active || printf inactive_or_unavailable)"
    if [ "$activation_status" -eq 0 ] || [ "$legacy_active" -eq 1 ] || [ "$listener_status" -eq 0 ]; then
        set_result VULNERABLE "tftp, talk 또는 ntalk 서비스 활성화 경로가 확인됐습니다." "$evidence"
    elif [ "$activation_status" -eq 2 ] || [ "$listener_status" -eq 2 ]; then
        set_result MANUAL "tftp, talk 또는 ntalk의 실제 활성 상태를 확정할 수 없습니다." "$evidence"
    else
        set_result GOOD "tftp, talk와 ntalk 서비스가 비활성 상태입니다." "$evidence"
    fi
}

service_mail_command_permission_state() {
    local logical_path="$1"
    local physical_path=""
    local owner=""
    local mode=""

    physical_path="$(fs_path "$logical_path")"
    [ -e "$physical_path" ] || return 2
    owner="$(stat_owner "$physical_path" 2>/dev/null || true)"
    mode="$(stat_mode "$physical_path" 2>/dev/null || true)"
    [ -n "$owner" ] && [ -n "$mode" ] || return 2
    [ "$owner" = "root" ] || return 0
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
            "active_mail_providers=${SERVICE_MAIL_PROVIDERS}\nnetwork_version_check=not_performed"
    elif [ "$SERVICE_MAIL_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "메일 서비스의 실제 활성 상태를 확정할 수 없습니다." "active_mail_providers=unknown"
    else
        set_result NOT_APPLICABLE "활성 SMTP 메일 서비스를 확인하지 못했습니다." "active_mail_providers=none" false
    fi
}

check_u_46() {
    local provider=""
    local privacy_options=""
    local checked_count=0
    local violations=0
    local unresolved_count=0

    service_detect_mail
    if [ -z "$SERVICE_MAIL_PROVIDERS" ]; then
        if [ "$SERVICE_MAIL_UNCERTAIN" -eq 1 ]; then
            set_result MANUAL "메일 서비스 활성 상태와 일반 사용자 실행 제한을 확정할 수 없습니다." "providers=unknown"
        else
            set_result NOT_APPLICABLE "활성 SMTP 메일 서비스를 확인하지 못했습니다." "providers=none" false
        fi
        return
    fi
    if [ "$SERVICE_MAIL_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "메일 unit의 실제 실행 인수와 구성 경로를 확정할 수 없습니다." "providers=${SERVICE_MAIL_PROVIDERS}\ncustom_invocation_or_listener_error=true"
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
                # Postfix enforces postsuper privileges internally, independent of its execute bits.
                unresolved_count=$((unresolved_count + 1))
                ;;
            exim)
                checked_count=$((checked_count + 1))
                unresolved_count=$((unresolved_count + 1))
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
            "checked_providers=${checked_count}\nviolations=0\nunresolved=${unresolved_count}"
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
    local checked_count=0
    local violations=0
    local unresolved_count=0

    service_detect_mail
    if [ -z "$SERVICE_MAIL_PROVIDERS" ]; then
        if [ "$SERVICE_MAIL_UNCERTAIN" -eq 1 ]; then
            set_result MANUAL "메일 릴레이 제한의 유효 상태를 확정할 수 없습니다." "providers=unknown"
        else
            set_result NOT_APPLICABLE "활성 SMTP 메일 서비스를 확인하지 못했습니다." "providers=none" false
        fi
        return
    fi
    if [ "$SERVICE_MAIL_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "메일 unit의 실제 릴레이 구성 경로를 확정할 수 없습니다." "providers=${SERVICE_MAIL_PROVIDERS}\ncustom_invocation_or_listener_error=true"
        return
    fi

    for provider in $SERVICE_MAIL_PROVIDERS; do
        case "$provider" in
            postfix)
                checked_count=$((checked_count + 1))
                relay_restrictions="$(service_postfix_value smtpd_relay_restrictions 2>/dev/null || true)"
                recipient_restrictions="$(service_postfix_value smtpd_recipient_restrictions 2>/dev/null || true)"
                allowed_networks="$(service_postfix_value mynetworks 2>/dev/null || true)"
                restrictions="$(printf '%s,%s' "$relay_restrictions" "$recipient_restrictions" | tr '[:upper:]' '[:lower:]')"
                if printf '%s\n' "$allowed_networks" | grep -Eq '(^|[ ,])(0\.0\.0\.0/0|::/0|\[::\]/0)([ ,]|$)'; then
                    violations=$((violations + 1))
                elif printf '%s\n' "$restrictions" | grep -Eq '^[[:space:],]*permit[[:space:],]'; then
                    violations=$((violations + 1))
                elif printf '%s\n' "$restrictions" | grep -Eq '(^|[ ,])(reject_unauth_destination|defer_unauth_destination)([ ,]|$)'; then
                    unresolved_count=$((unresolved_count + 1))
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
            "checked_providers=${checked_count}\nviolations=0\nunresolved=${unresolved_count}"
    else
        set_result GOOD "Postfix 유효 설정에서 인증되지 않은 목적지 릴레이가 제한되어 있습니다." \
            "checked_providers=${checked_count}\nviolations=0"
    fi
}

check_u_48() {
    local provider=""
    local privacy_options=""
    local disable_vrfy=""
    local checked_count=0
    local violations=0
    local unresolved_count=0

    service_detect_mail
    if [ -z "$SERVICE_MAIL_PROVIDERS" ]; then
        if [ "$SERVICE_MAIL_UNCERTAIN" -eq 1 ]; then
            set_result MANUAL "메일 명령 제한의 유효 상태를 확정할 수 없습니다." "providers=unknown"
        else
            set_result NOT_APPLICABLE "활성 SMTP 메일 서비스를 확인하지 못했습니다." "providers=none" false
        fi
        return
    fi
    if [ "$SERVICE_MAIL_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "메일 unit의 실제 명령 제한 구성 경로를 확정할 수 없습니다." "providers=${SERVICE_MAIL_PROVIDERS}\ncustom_invocation_or_listener_error=true"
        return
    fi

    for provider in $SERVICE_MAIL_PROVIDERS; do
        case "$provider" in
            sendmail)
                checked_count=$((checked_count + 1))
                privacy_options="$(service_sendmail_privacy_options 2>/dev/null || true)"
                if [ -z "$privacy_options" ]; then
                    unresolved_count=$((unresolved_count + 1))
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
            exim|unknown)
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
            "checked_providers=${checked_count}\nviolations=0\nunresolved=${unresolved_count}"
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
            "dns_activation=active\nnetwork_version_check=not_performed"
    elif [ "$dns_status" -eq 2 ]; then
        set_result MANUAL "DNS 서비스의 실제 활성 상태를 확정할 수 없습니다." "dns_activation=unknown"
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
    local evidence=""

    service_detect_dns
    dns_status=$?
    if [ "$dns_status" -eq 1 ]; then
        set_result NOT_APPLICABLE "활성 DNS 서비스를 확인하지 못했습니다." "dns_activation=inactive" false
        return
    elif [ "$dns_status" -eq 2 ]; then
        set_result MANUAL "DNS 서비스의 실제 활성 상태를 확정할 수 없습니다." "dns_activation=unknown"
        return
    fi

    effective_metadata="$(service_bind_effective_file 2>/dev/null || true)"
    confidence="${effective_metadata%%"$(printf '\t')"*}"
    configuration_file="${effective_metadata#*"$(printf '\t')"}"
    if [ -z "$effective_metadata" ] || [ ! -r "$configuration_file" ]; then
        set_result MANUAL "BIND 유효 설정을 수집하지 못해 Zone Transfer 제한을 확정할 수 없습니다." "dns_activation=active"
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
        grep -Eo 'type[[:space:]]+(primary|master|secondary|slave)[[:space:]]*;' | awk 'END {print NR+0}')"
    transfer_clauses="$(printf '%s\n' "$flattened_configuration" | \
        grep -Eo 'allow-transfer[[:space:]]*\{[^}]*\}' | awk 'END {print NR+0}')"
    unsafe_clauses="$(printf '%s\n' "$flattened_configuration" | \
        grep -Eo 'allow-transfer[[:space:]]*\{[^}]*\}' | \
        awk 'tolower($0) ~ /(^|[;{[:space:]])(any|\*)[[:space:]]*;/ {count++} END {print count+0}')"
    first_zone_position="$(awk -v value="$flattened_configuration" 'BEGIN {print index(tolower(value), "zone ")}')"
    first_transfer_position="$(awk -v value="$flattened_configuration" 'BEGIN {print index(tolower(value), "allow-transfer")}')"
    if [ "$first_transfer_position" -gt 0 ] && \
        { [ "$first_zone_position" -eq 0 ] || [ "$first_transfer_position" -lt "$first_zone_position" ]; }; then
        global_restriction=1
    fi
    if printf '%s\n' "$flattened_configuration" | grep -Eiq '(^|[;{}[:space:]])(acl|view)[[:space:]]'; then
        complex_acl_context=1
    fi

    evidence="configuration_confidence=${confidence}\nauthoritative_zones=${authoritative_zones}\nallow_transfer_clauses=${transfer_clauses}\nunsafe_clauses=${unsafe_clauses}\nglobal_restriction=${global_restriction}\ncomplex_acl_context=${complex_acl_context}"
    if [ "$authoritative_zones" -eq 0 ]; then
        set_result NOT_APPLICABLE "권한 있는 DNS zone 구성을 확인하지 못했습니다." "$evidence" false
    elif [ "$unsafe_clauses" -gt 0 ] || [ "$transfer_clauses" -eq 0 ]; then
        set_result VULNERABLE "권한 있는 DNS zone에 전체 대상 Zone Transfer가 허용될 수 있습니다." "$evidence"
    elif [ "$confidence" = "validated" ] && [ "$complex_acl_context" -eq 0 ] && \
        { [ "$global_restriction" -eq 1 ] || [ "$transfer_clauses" -ge "$authoritative_zones" ]; }; then
        set_result GOOD "BIND 유효 설정에서 Zone Transfer 대상이 제한되어 있습니다." "$evidence"
    else
        set_result MANUAL "각 view와 zone의 Zone Transfer 상속 범위를 추가 확인해야 합니다." "$evidence"
    fi
}

check_u_51() {
    local dns_status=1
    local effective_metadata=""
    local confidence=""
    local configuration_file=""
    local flattened_configuration=""
    local update_clauses=0
    local unsafe_clauses=0
    local complex_acl_context=0
    local evidence=""

    service_detect_dns
    dns_status=$?
    if [ "$dns_status" -eq 1 ]; then
        set_result NOT_APPLICABLE "활성 DNS 서비스를 확인하지 못했습니다." "dns_activation=inactive" false
        return
    elif [ "$dns_status" -eq 2 ]; then
        set_result MANUAL "DNS 서비스의 실제 활성 상태를 확정할 수 없습니다." "dns_activation=unknown"
        return
    fi

    effective_metadata="$(service_bind_effective_file 2>/dev/null || true)"
    confidence="${effective_metadata%%"$(printf '\t')"*}"
    configuration_file="${effective_metadata#*"$(printf '\t')"}"
    if [ -z "$effective_metadata" ] || [ ! -r "$configuration_file" ]; then
        set_result MANUAL "BIND 유효 설정을 수집하지 못해 동적 업데이트 통제를 확정할 수 없습니다." "dns_activation=active"
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
        grep -Eo '(allow-update|allow-update-forwarding)[[:space:]]*\{[^}]*\}|update-policy[[:space:]]*\{[^}]*\}' | \
        awk 'tolower($0) ~ /(^|[;{[:space:]])(any|\*)[[:space:]]*;/ || tolower($0) ~ /grant[[:space:]]+\*[[:space:]]/ {count++} END {print count+0}')"
    if printf '%s\n' "$flattened_configuration" | grep -Eiq '(^|[;{}[:space:]])(acl|view)[[:space:]]'; then
        complex_acl_context=1
    fi

    evidence="configuration_confidence=${confidence}\ndynamic_update_clauses=${update_clauses}\nunsafe_clauses=${unsafe_clauses}\ncomplex_acl_context=${complex_acl_context}"
    if [ "$unsafe_clauses" -gt 0 ]; then
        set_result VULNERABLE "BIND 동적 업데이트가 제한되지 않은 대상에 허용되어 있습니다." "$evidence"
    elif [ "$confidence" = "validated" ] && [ "$update_clauses" -eq 0 ] && [ "$complex_acl_context" -eq 0 ]; then
        set_result GOOD "BIND 유효 설정에서 동적 업데이트가 비활성화됐거나 제한된 정책을 사용합니다." "$evidence"
    else
        set_result MANUAL "include와 view를 포함한 BIND 동적 업데이트 유효 설정을 검증해야 합니다." "$evidence"
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
    local evidence=""

    service_activation_state telnet.service telnet.socket telnet@.service telnetd.service telnetd.socket
    activation_status=$?
    evidence="$SERVICE_ACTIVATION_EVIDENCE"
    service_legacy_enabled '^telnet$' && legacy_active=1
    service_listener_state 23
    listener_status=$?

    evidence="${evidence}legacy_activation=${legacy_active}\ntelnet_listener=$([ "$listener_status" -eq 0 ] && printf active || printf inactive_or_unavailable)"
    if [ "$activation_status" -eq 0 ] || [ "$legacy_active" -eq 1 ] || [ "$listener_status" -eq 0 ]; then
        set_result VULNERABLE "Telnet 서비스 활성화 경로가 확인됐습니다." "$evidence"
    elif [ "$activation_status" -eq 2 ] || [ "$listener_status" -eq 2 ]; then
        set_result MANUAL "Telnet 서비스의 실제 활성 상태를 확정할 수 없습니다." "$evidence"
    else
        set_result GOOD "Telnet 서비스가 systemd, inetd/xinetd와 수신 포트에서 비활성 상태입니다." "$evidence"
    fi
}

check_u_53() {
    local provider=""
    local configuration_path=""
    local banner_value=""
    local server_ident=""
    local checked_count=0
    local violations=0
    local unresolved_count=0

    service_detect_ftp
    if [ -z "$SERVICE_FTP_PROVIDERS" ]; then
        if [ "$SERVICE_FTP_UNCERTAIN" -eq 1 ]; then
            set_result MANUAL "FTP 서비스와 배너 유효 설정을 확정할 수 없습니다." "providers=unknown"
        else
            set_result NOT_APPLICABLE "활성 FTP 서비스를 확인하지 못했습니다." "providers=none" false
        fi
        return
    fi
    if [ "$SERVICE_FTP_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "FTP unit의 실제 실행 인수와 구성 경로를 확정할 수 없습니다." "providers=${SERVICE_FTP_PROVIDERS}\ncustom_invocation=true"
        return
    fi

    for provider in $SERVICE_FTP_PROVIDERS; do
        case "$provider" in
            vsftpd)
                checked_count=$((checked_count + 1))
                configuration_path="$(service_vsftpd_configuration 2>/dev/null || true)"
                banner_value="$(service_read_simple_value ftpd_banner "$configuration_path" 2>/dev/null || true)"
                if [ -z "$banner_value" ] || printf '%s\n' "$banner_value" | \
                    grep -Eiq '(^|[^[:alpha:]])(vsftpd|ubuntu|rhel|red[[:space:]]+hat|version|hostname)([^[:alpha:]]|$)'; then
                    violations=$((violations + 1))
                fi
                ;;
            proftpd)
                checked_count=$((checked_count + 1))
                server_ident="$(service_proftpd_value ServerIdent 2>/dev/null || true)"
                if [ -z "$server_ident" ]; then
                    violations=$((violations + 1))
                elif printf '%s\n' "$server_ident" | grep -Eiq '^off([[:space:]]|$)'; then
                    :
                elif printf '%s\n' "$server_ident" | grep -Eiq '^on([[:space:]]|$)|proftpd|ubuntu|rhel|red[[:space:]]+hat|version|hostname'; then
                    violations=$((violations + 1))
                else
                    unresolved_count=$((unresolved_count + 1))
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
            "checked_providers=${checked_count}\nviolations=0\nunresolved=${unresolved_count}"
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
    local tls_engine=""
    local tls_required=""
    local checked_count=0
    local violations=0
    local unresolved_count=0

    service_detect_ftp
    if [ -z "$SERVICE_FTP_PROVIDERS" ]; then
        if [ "$SERVICE_FTP_UNCERTAIN" -eq 1 ]; then
            set_result MANUAL "FTP 활성 상태와 전송 암호화 강제 여부를 확정할 수 없습니다." "providers=unknown"
        else
            set_result GOOD "암호화되지 않은 FTP 서비스 활성화 경로를 확인하지 못했습니다." "providers=none"
        fi
        return
    fi
    if [ "$SERVICE_FTP_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "FTP unit의 실제 실행 인수와 TLS 구성 경로를 확정할 수 없습니다." "providers=${SERVICE_FTP_PROVIDERS}\ncustom_invocation=true"
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
                if [ "$(printf '%s' "$ssl_enable" | tr '[:lower:]' '[:upper:]')" != "YES" ] || \
                    [ "$(printf '%s' "$force_login_ssl" | tr '[:lower:]' '[:upper:]')" = "NO" ] || \
                    [ "$(printf '%s' "$force_data_ssl" | tr '[:lower:]' '[:upper:]')" = "NO" ]; then
                    violations=$((violations + 1))
                elif [ -z "$force_login_ssl" ] || [ -z "$force_data_ssl" ] || \
                    [ "$(printf '%s' "$anonymous_enable" | tr '[:lower:]' '[:upper:]')" = "YES" ]; then
                    unresolved_count=$((unresolved_count + 1))
                fi
                ;;
            proftpd)
                checked_count=$((checked_count + 1))
                tls_engine="$(service_proftpd_value TLSEngine 2>/dev/null || true)"
                tls_required="$(service_proftpd_value TLSRequired 2>/dev/null || true)"
                if [ -n "$tls_engine" ] && ! printf '%s\n' "$tls_engine" | grep -Eiq '^on([[:space:]]|$)'; then
                    violations=$((violations + 1))
                elif [ -n "$tls_required" ] && ! printf '%s\n' "$tls_required" | grep -Eiq '^on([[:space:]]|$)'; then
                    violations=$((violations + 1))
                else
                    unresolved_count=$((unresolved_count + 1))
                fi
                ;;
            legacy)
                checked_count=$((checked_count + 1))
                unresolved_count=$((unresolved_count + 1))
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
            "checked_providers=${checked_count}\nunresolved=${unresolved_count}"
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
        set_result NOT_APPLICABLE "ftp 전용 계정이 존재하지 않습니다." "ftp_account=absent" false
        return
    fi
    shell_path="$(printf '%s\n' "$ftp_entry" | awk -F: '{print $7}')"
    case "$shell_path" in
        /bin/false|/usr/bin/false|/sbin/nologin|/usr/sbin/nologin)
            set_result GOOD "ftp 계정에 비로그인 셸이 지정되어 있습니다." "ftp_account_shell=non_login"
            ;;
        *)
            set_result VULNERABLE "ftp 계정에 대화형 로그인이 가능한 셸이 지정되어 있습니다." "ftp_account_shell=interactive_or_unknown"
            ;;
    esac
}

check_u_56() {
    service_detect_ftp

    if [ -n "$SERVICE_FTP_PROVIDERS" ]; then
        set_result MANUAL \
            "FTP 접근 제어는 daemon 설정, systemd IPAddress 정책, 호스트 방화벽과 외부 방화벽을 함께 확인해야 합니다." \
            "active_ftp_providers=${SERVICE_FTP_PROVIDERS}\nnetwork_policy_validation=required"
    elif [ "$SERVICE_FTP_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "FTP 서비스와 접근 제어의 실제 상태를 확정할 수 없습니다." "active_ftp_providers=unknown"
    else
        set_result NOT_APPLICABLE "활성 FTP 서비스를 확인하지 못했습니다." "active_ftp_providers=none" false
    fi
}

check_u_57() {
    local provider=""
    local candidate=""
    local root_login=""
    local checked_count=0
    local violations=0
    local unresolved_count=0
    local root_denied=0

    service_detect_ftp
    if [ -z "$SERVICE_FTP_PROVIDERS" ]; then
        if [ "$SERVICE_FTP_UNCERTAIN" -eq 1 ]; then
            set_result MANUAL "FTP root 접속 차단의 유효 상태를 확정할 수 없습니다." "providers=unknown"
        else
            set_result NOT_APPLICABLE "활성 FTP 서비스를 확인하지 못했습니다." "providers=none" false
        fi
        return
    fi
    if [ "$SERVICE_FTP_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "FTP unit의 실제 PAM·userlist 구성 경로를 확정할 수 없습니다." "providers=${SERVICE_FTP_PROVIDERS}\ncustom_invocation=true"
        return
    fi

    for provider in $SERVICE_FTP_PROVIDERS; do
        case "$provider" in
            vsftpd|legacy)
                checked_count=$((checked_count + 1))
                root_denied=0
                for candidate in /etc/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers; do
                    candidate="$(fs_path "$candidate")"
                    if service_file_contains_root_entry "$candidate"; then
                        root_denied=1
                        break
                    fi
                done
                if [ "$root_denied" -eq 1 ]; then
                    unresolved_count=$((unresolved_count + 1))
                else
                    violations=$((violations + 1))
                fi
                ;;
            proftpd)
                checked_count=$((checked_count + 1))
                root_login="$(service_proftpd_value RootLogin 2>/dev/null || true)"
                if [ -n "$root_login" ] && ! printf '%s\n' "$root_login" | grep -Eiq '^off([[:space:]]|$)'; then
                    violations=$((violations + 1))
                else
                    unresolved_count=$((unresolved_count + 1))
                fi
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
            "checked_providers=${checked_count}\nviolations=0\nunresolved=${unresolved_count}"
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
        set_result MANUAL "SNMP 서비스의 실제 활성 상태를 확정할 수 없습니다." "snmp_activation=unknown"
    else
        set_result GOOD "SNMP 서비스 활성화 경로와 수신 포트를 확인하지 못했습니다." "snmp_activation=inactive"
    fi
}

service_snmp_version_metrics() {
    local configuration_file=""

    while IFS= read -r configuration_file; do
        [ -r "$configuration_file" ] || continue
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
}

service_snmp_community_metrics() {
    local configuration_file=""

    while IFS= read -r configuration_file; do
        [ -r "$configuration_file" ] || continue
        awk '
            function classify(value, lower, has_alpha, has_digit, has_special, length_value) {
                gsub(/^["\047]|["\047]$/, "", value)
                lower=tolower(value)
                length_value=length(value)
                has_alpha=(value ~ /[[:alpha:]]/)
                has_digit=(value ~ /[[:digit:]]/)
                has_special=(value ~ /[^[:alnum:]]/)
                communities++
                if (lower == "public" || lower == "private") weak++
                else if (has_alpha && has_digit && has_special && length_value >= 8) strong++
                else if (has_alpha && has_digit && length_value >= 10) strong++
                else weak++
            }
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                split(line, fields, /[[:space:]]+/)
                directive=tolower(fields[1])
                if (directive ~ /^(rocommunity|rwcommunity|rocommunity6|rwcommunity6)$/ && fields[2] != "") classify(fields[2])
                else if (directive ~ /^(com2sec|com2sec6)$/) {
                    if (fields[2] == "-Cn" && fields[6] != "") classify(fields[6])
                    else if (fields[4] != "") classify(fields[4])
                } else if (directive == "authcommunity" && fields[3] != "") classify(fields[3])
                if (directive ~ /^(rouser|rwuser|authuser)$/ || (directive == "group" && tolower(fields[3]) == "usm")) version3++
                if (directive ~ /^(include|includefile|includedir|authgroup)$/) includes++
            }
            END {printf "%d %d %d %d\n", communities+0, weak+0, version3+0, includes+0}
        ' "$configuration_file"
    done <<EOF
$(service_snmp_files | awk '!seen[$0]++')
EOF
}

service_snmp_access_metrics() {
    local configuration_file=""

    while IFS= read -r configuration_file; do
        [ -r "$configuration_file" ] || continue
        awk '
            function is_unrestricted(value, lower) {
                lower=tolower(value)
                return value == "" || lower == "default" || lower == "any" || value == "*" || value == "0.0.0.0/0" || value == "::/0"
            }
            {
                line=$0
                sub(/^[[:space:]]+/, "", line)
                if (line == "" || line ~ /^#/) next
                split(line, fields, /[[:space:]]+/)
                directive=tolower(fields[1])
                if (directive ~ /^(rocommunity|rwcommunity|rocommunity6|rwcommunity6)$/) {
                    communities++
                    if (fields[3] ~ /^-/ || is_unrestricted(fields[3])) unsafe++
                    else restricted++
                } else if (directive ~ /^(com2sec|com2sec6)$/) {
                    communities++
                    if (fields[2] == "-Cn") source=fields[5]
                    else source=fields[3]
                    if (is_unrestricted(source)) unsafe++
                    else restricted++
                } else if (directive == "authcommunity") {
                    communities++
                    if (fields[4] ~ /^-/ || is_unrestricted(fields[4])) unsafe++
                    else restricted++
                }
                if (directive ~ /^(rouser|rwuser|authuser)$/ || (directive == "group" && tolower(fields[3]) == "usm")) version3++
                if (directive ~ /^(include|includefile|includedir|authgroup)$/) includes++
            }
            END {printf "%d %d %d %d %d\n", communities+0, restricted+0, unsafe+0, version3+0, includes+0}
        ' "$configuration_file"
    done <<EOF
$(service_snmp_files | awk '!seen[$0]++')
EOF
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
        set_result MANUAL "SNMP 서비스의 실제 활성 상태를 확정할 수 없습니다." "snmp_activation=unknown"
        return
    fi
    if [ "$SERVICE_SNMP_CONFIG_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "SNMP unit의 실제 구성 경로를 확정할 수 없습니다." "snmp_activation=active\ncustom_invocation=true"
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
        set_result GOOD "SNMP 접근 설정이 v3 USM 사용자만 사용합니다." \
            "legacy_version_directives=0\nversion3_directives=${version3_count}"
    else
        set_result MANUAL "활성 SNMP 서비스의 실제 프로토콜 버전을 설정과 패킷 응답으로 확인해야 합니다." \
            "legacy_version_directives=${legacy_count}\nversion3_directives=${version3_count}\ncustom_includes=${include_count}"
    fi
}

check_u_60() {
    local snmp_status=1
    local metrics=""
    local community_count=0
    local weak_count=0
    local version3_count=0
    local include_count=0
    local values=""

    service_detect_snmp
    snmp_status=$?
    if [ "$snmp_status" -eq 1 ]; then
        set_result NOT_APPLICABLE "활성 SNMP 서비스를 확인하지 못했습니다." "snmp_activation=inactive" false
        return
    elif [ "$snmp_status" -eq 2 ]; then
        set_result MANUAL "SNMP 서비스의 실제 활성 상태를 확정할 수 없습니다." "snmp_activation=unknown"
        return
    fi
    if [ "$SERVICE_SNMP_CONFIG_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "SNMP unit의 실제 구성 경로를 확정할 수 없습니다." "snmp_activation=active\ncustom_invocation=true"
        return
    fi

    metrics="$(service_snmp_community_metrics)"
    while IFS= read -r values; do
        community_count=$((community_count + ${values%% *}))
        values="${values#* }"
        weak_count=$((weak_count + ${values%% *}))
        values="${values#* }"
        version3_count=$((version3_count + ${values%% *}))
        include_count=$((include_count + ${values##* }))
    done <<EOF
$metrics
EOF

    if [ "$weak_count" -gt 0 ]; then
        set_result VULNERABLE "복잡도 기준을 충족하지 않는 SNMP community가 확인됐습니다." \
            "community_count=${community_count}\nweak_community_count=${weak_count}\nsecret_values=redacted"
    elif [ "$community_count" -gt 0 ] && [ "$include_count" -eq 0 ]; then
        set_result GOOD "구성된 SNMP community가 길이와 문자 조합 기준을 충족합니다." \
            "community_count=${community_count}\nweak_community_count=0\nsecret_values=redacted"
    elif [ "$version3_count" -gt 0 ]; then
        set_result MANUAL "SNMP v3 인증 비밀번호 복잡도는 비밀값을 보고서에 노출하지 않고 별도 검증해야 합니다." \
            "version3_directives=${version3_count}\nsecret_values=not_collected"
    else
        set_result MANUAL "활성 SNMP 서비스의 community 또는 v3 인증 설정을 확인하지 못했습니다." \
            "community_count=${community_count}\ncustom_includes=${include_count}"
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
    local values=""

    service_detect_snmp
    snmp_status=$?
    if [ "$snmp_status" -eq 1 ]; then
        set_result NOT_APPLICABLE "활성 SNMP 서비스를 확인하지 못했습니다." "snmp_activation=inactive" false
        return
    elif [ "$snmp_status" -eq 2 ]; then
        set_result MANUAL "SNMP 서비스의 실제 활성 상태를 확정할 수 없습니다." "snmp_activation=unknown"
        return
    fi
    if [ "$SERVICE_SNMP_CONFIG_UNCERTAIN" -eq 1 ]; then
        set_result MANUAL "SNMP unit의 실제 구성 경로를 확정할 수 없습니다." "snmp_activation=active\ncustom_invocation=true"
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
        include_count=$((include_count + ${values##* }))
    done <<EOF
$metrics
EOF

    if [ "$unsafe_count" -gt 0 ]; then
        set_result VULNERABLE "전체 또는 기본 네트워크에서 접근 가능한 SNMP community 설정이 확인됐습니다." \
            "community_count=${community_count}\nrestricted_sources=${restricted_count}\nunrestricted_sources=${unsafe_count}"
    elif [ "$community_count" -gt 0 ] && [ "$restricted_count" -eq "$community_count" ] && [ "$include_count" -eq 0 ]; then
        set_result GOOD "모든 SNMP community가 특정 네트워크 또는 호스트로 제한되어 있습니다." \
            "community_count=${community_count}\nrestricted_sources=${restricted_count}"
    elif [ "$version3_count" -gt 0 ]; then
        set_result MANUAL "SNMP v3 사용자 인증 외에 네트워크·방화벽 접근 제한을 함께 확인해야 합니다." \
            "version3_directives=${version3_count}\ncustom_includes=${include_count}"
    else
        set_result MANUAL "활성 SNMP 서비스의 유효 접근 제어 설정을 확정할 수 없습니다." \
            "community_count=${community_count}\ncustom_includes=${include_count}"
    fi
}

service_warning_collection_state() {
    local logical_path=""
    local physical_path=""
    local saw_content=0

    for logical_path in "$@"; do
        physical_path="$(fs_path "$logical_path")"
        if [ -f "$physical_path" ]; then
            if service_warning_file_state "$physical_path"; then
                return 0
            elif [ -s "$physical_path" ]; then
                saw_content=1
            fi
        elif [ -d "$physical_path" ]; then
            while IFS= read -r physical_path; do
                if service_warning_file_state "$physical_path"; then
                    return 0
                elif [ -s "$physical_path" ]; then
                    saw_content=1
                fi
            done <<EOF
$(find -P "$physical_path" -maxdepth 1 -type f -print 2>/dev/null | LC_ALL=C sort)
EOF
        fi
    done

    [ "$saw_content" -eq 1 ] && return 2
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

check_u_62() {
    local missing_count=0
    local unresolved_count=0
    local checked_surfaces=0
    local state=1
    local activation_status=1
    local listener_status=1
    local legacy_active=0
    local banner_path=""
    local physical_banner_path=""
    local provider=""
    local configuration_path=""
    local banner_value=""
    local effective_metadata=""
    local bind_confidence=""
    local bind_configuration=""
    local bind_version=""

    checked_surfaces=$((checked_surfaces + 2))
    service_warning_collection_state /etc/issue /etc/issue.d /run/issue.d /usr/lib/issue.d
    state=$?
    [ "$state" -eq 1 ] && missing_count=$((missing_count + 1))
    [ "$state" -eq 2 ] && unresolved_count=$((unresolved_count + 1))
    service_warning_collection_state /etc/motd /etc/motd.d /run/motd /run/motd.d /usr/lib/motd /usr/lib/motd.d /etc/update-motd.d
    state=$?
    [ "$state" -eq 1 ] && missing_count=$((missing_count + 1))
    [ "$state" -eq 2 ] && unresolved_count=$((unresolved_count + 1))

    service_activation_state ssh.service sshd.service ssh.socket sshd.socket
    activation_status=$?
    if [ "$activation_status" -eq 0 ]; then
        checked_surfaces=$((checked_surfaces + 1))
        if runtime_enabled; then
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
        else
            unresolved_count=$((unresolved_count + 1))
        fi
    elif [ "$activation_status" -eq 2 ]; then
        unresolved_count=$((unresolved_count + 1))
    fi

    service_activation_state telnet.service telnet.socket telnet@.service telnetd.service telnetd.socket
    activation_status=$?
    service_legacy_enabled '^telnet$' && legacy_active=1
    service_listener_state 23
    listener_status=$?
    if [ "$activation_status" -eq 0 ] || [ "$legacy_active" -eq 1 ] || [ "$listener_status" -eq 0 ]; then
        checked_surfaces=$((checked_surfaces + 1))
        service_warning_collection_state /etc/issue.net
        state=$?
        [ "$state" -eq 1 ] && missing_count=$((missing_count + 1))
        [ "$state" -eq 2 ] && unresolved_count=$((unresolved_count + 1))
    elif [ "$activation_status" -eq 2 ] || [ "$listener_status" -eq 2 ]; then
        unresolved_count=$((unresolved_count + 1))
    fi

    service_detect_ftp
    for provider in $SERVICE_FTP_PROVIDERS; do
        checked_surfaces=$((checked_surfaces + 1))
        case "$provider" in
            vsftpd)
                configuration_path="$(service_vsftpd_configuration 2>/dev/null || true)"
                banner_value="$(service_read_simple_value ftpd_banner "$configuration_path" 2>/dev/null || true)"
                service_banner_value_state "$banner_value"
                state=$?
                [ "$state" -eq 1 ] && missing_count=$((missing_count + 1))
                [ "$state" -eq 2 ] && unresolved_count=$((unresolved_count + 1))
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
            exim) banner_value="$(service_exim_value smtp_banner 2>/dev/null || true)" ;;
            *) banner_value="" ;;
        esac
        service_banner_value_state "$banner_value"
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
        bind_confidence="${effective_metadata%%"$(printf '\t')"*}"
        bind_configuration="${effective_metadata#*"$(printf '\t')"}"
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
            service_banner_value_state "$bind_version"
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
        set_result VULNERABLE "서버 또는 활성 원격 서비스에서 로그인 경고 메시지 설정 누락을 확인했습니다." \
            "checked_surfaces=${checked_surfaces}\nmissing_warnings=${missing_count}\nunresolved_warnings=${unresolved_count}\nbanner_text=not_collected"
    elif [ "$unresolved_count" -gt 0 ]; then
        set_result MANUAL "설정된 배너가 조직의 법적·보안 경고 문구를 충족하는지 확인해야 합니다." \
            "checked_surfaces=${checked_surfaces}\nmissing_warnings=0\nunresolved_warnings=${unresolved_count}\nbanner_text=not_collected"
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

    boundary="$(CDPATH='' cd -P -- "$SCAN_ROOT" 2>/dev/null && pwd)" || return 1
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
    local version_output=""
    local cargo_sudo=""

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
    if [ -x "$cargo_sudo" ] || [ -e "$(fs_path /etc/sudoers-rs)" ]; then
        printf 'sudo-rs\n'
        return 0
    fi
    if [ -x "$(fs_path /usr/bin/sudo)" ] || [ -e "$(fs_path /etc/sudoers)" ]; then
        printf 'sudo.ws\n'
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

    while IFS="$(printf '\t')" read -r directive_type include_path; do
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
    local fallback_sudoers_path=""
    local file_list=""
    local directory_list=""
    local unresolved_list=""
    local policy_file=""
    local policy_directory=""
    local owner=""
    local mode=""
    local checked_files=0
    local checked_directories=0
    local violations=0
    local stat_failures=0
    local unresolved_includes=0
    local validator_status="unavailable"
    local visudo_path=""
    local cargo_visudo=""
    local evidence=""

    provider="$(service_sudo_provider 2>/dev/null || true)"
    if [ -z "$provider" ]; then
        set_result NOT_APPLICABLE "sudo 공급자와 정책 파일을 확인하지 못했습니다." "sudo_provider=absent" false
        return
    fi

    fallback_sudoers_path="$(fs_path /etc/sudoers)"
    if [ "$provider" = "sudo-rs" ] && [ -e "$(fs_path /etc/sudoers-rs 2>/dev/null || true)" ]; then
        sudoers_path="$(fs_path /etc/sudoers-rs)"
    else
        sudoers_path="$fallback_sudoers_path"
    fi
    if [ ! -e "$sudoers_path" ]; then
        set_result VULNERABLE "활성 sudo 공급자의 정책 파일이 없습니다." "sudo_provider=${provider}\nactive_policy=absent"
        return
    fi
    safe_sudoers_path="$(resolve_rooted_read_path "$sudoers_path" 2>/dev/null || true)"
    if [ -z "$safe_sudoers_path" ]; then
        set_result ERROR "활성 sudo 정책 경로가 검사 루트 밖을 가리키거나 읽을 수 없습니다." "sudo_provider=${provider}\nactive_policy=unresolved"
        return
    fi
    sudoers_path="$safe_sudoers_path"

    file_list="$(new_scratch_file u63-files)" || {
        set_result ERROR "sudoers include 파일 목록을 안전하게 만들 수 없습니다." ""
        return
    }
    directory_list="$(new_scratch_file u63-directories)" || {
        set_result ERROR "sudoers include 디렉터리 목록을 안전하게 만들 수 없습니다." ""
        return
    }
    unresolved_list="$(new_scratch_file u63-unresolved)" || {
        set_result ERROR "sudoers 미확인 include 목록을 안전하게 만들 수 없습니다." ""
        return
    }
    : > "$file_list"
    : > "$directory_list"
    : > "$unresolved_list"
    service_collect_sudoers_graph "$sudoers_path" "$file_list" "$directory_list" "$unresolved_list" 0

    while IFS= read -r policy_file; do
        [ -n "$policy_file" ] || continue
        checked_files=$((checked_files + 1))
        owner="$(stat_owner "$policy_file" 2>/dev/null || true)"
        mode="$(stat_mode "$policy_file" 2>/dev/null || true)"
        if [ -z "$owner" ] || [ -z "$mode" ]; then
            stat_failures=$((stat_failures + 1))
        elif [ "$owner" != "root" ] || ! mode_is_at_most "$mode" 640; then
            violations=$((violations + 1))
        fi
        if ! service_parent_chain_trusted "$policy_file"; then
            violations=$((violations + 1))
        fi
    done < "$file_list"

    while IFS= read -r policy_directory; do
        [ -n "$policy_directory" ] || continue
        checked_directories=$((checked_directories + 1))
        owner="$(stat_owner "$policy_directory" 2>/dev/null || true)"
        mode="$(stat_mode "$policy_directory" 2>/dev/null || true)"
        if [ -z "$owner" ] || [ -z "$mode" ]; then
            stat_failures=$((stat_failures + 1))
        elif [ "$owner" != "root" ] || mode_group_or_other_writable "$mode"; then
            violations=$((violations + 1))
        fi
    done < "$directory_list"
    unresolved_includes="$(awk 'END {print NR+0}' "$unresolved_list")"

    if runtime_enabled; then
        if [ "$provider" = "sudo-rs" ]; then
            visudo_path="$(trusted_command visudo-rs 2>/dev/null || true)"
            [ -n "$visudo_path" ] || visudo_path="$(trusted_command visudo 2>/dev/null || true)"
            if [ -z "$visudo_path" ]; then
                cargo_visudo="$(service_trusted_absolute_command /usr/lib/cargo/bin/visudo 2>/dev/null || true)"
                [ -n "$cargo_visudo" ] && visudo_path="$cargo_visudo"
            fi
        else
            visudo_path="$(trusted_command visudo.ws 2>/dev/null || true)"
            [ -n "$visudo_path" ] || visudo_path="$(trusted_command visudo 2>/dev/null || true)"
        fi
        if [ -n "$visudo_path" ]; then
            if "$visudo_path" -c -f "$sudoers_path" >/dev/null 2>&1; then
                validator_status="valid"
            else
                validator_status="invalid"
                violations=$((violations + 1))
            fi
        fi
    fi

    evidence="sudo_provider=${provider}\nchecked_policy_files=${checked_files}\nchecked_include_directories=${checked_directories}\npermission_violations=${violations}\nstat_failures=${stat_failures}\nunresolved_includes=${unresolved_includes}\nvisudo_validation=${validator_status}"
    if [ "$violations" -gt 0 ]; then
        set_result VULNERABLE "sudoers 정책 또는 drop-in의 소유자·권한·구문이 KISA 기준을 벗어났습니다." "$evidence"
    elif [ "$stat_failures" -gt 0 ]; then
        set_result ERROR "sudoers 정책 파일의 소유자 또는 권한을 읽지 못했습니다." "$evidence"
    elif [ "$unresolved_includes" -gt 0 ]; then
        set_result MANUAL "sudoers 또는 sudoers-rs include 그래프 일부를 안전하게 해석하지 못했습니다." "$evidence"
    elif runtime_enabled && [ "$validator_status" = "unavailable" ]; then
        set_result MANUAL "활성 sudo 공급자와 일치하는 신뢰된 visudo 검증기를 찾지 못했습니다." "$evidence"
    else
        set_result GOOD "활성 sudo 정책의 전체 include 그래프가 root 소유이며 파일 권한이 0640 이하입니다." "$evidence"
    fi
}
