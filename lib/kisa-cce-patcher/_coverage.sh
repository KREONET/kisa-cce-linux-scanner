# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash
# shellcheck disable=SC2034

# Declares the complete remediation contract independently of implementation availability.

PATCH_COVERAGE_HEADER=$'code\tadapter\trisk\tresolution_requirement\ttransaction_domain\tpostcondition\timplementation_status\ttyped_input\tvalidator\trollback_domain'
PATCH_COVERAGE_ERROR_DETAIL=""

patch_coverage_records() {
    printf '%s\n' "$PATCH_COVERAGE_HEADER"
    printf '%s\n' \
        $'U-01\tremote_root_access\tR3\truntime\tedge-service\tGOOD\tconditional\troot_remote_access_policy\tvalidate_u01_remote_root_access_v2\tedge-service' \
        $'U-02\tpassword_policy\tR3\tpolicy\tpam\tGOOD\tconditional\tpam_password_policy\tpam_transaction_verify\tpam' \
        $'U-03\taccount_lockout\tR3\ttechnical\tpam\tGOOD\tconditional\tpam_lockout_policy\tpam_transaction_verify\tpam' \
        $'U-04\tpassword_store\tR4\ttechnical\taccount\tGOOD\tconditional\tpassword_store_strategy\tpatch_account_verify\taccount' \
        $'U-05\tuid_zero_accounts\tR4\tpolicy\taccount\tGOOD\tconditional\tuid_zero_account_resolution\tpatch_account_verify\taccount' \
        $'U-06\tsu_access\tR3\tpolicy\tpam\tGOOD\tconditional\tpam_approved_su_group\tpam_transaction_verify\tpam' \
        $'U-07\tunnecessary_accounts\tR4\tpolicy\taccount\tGOOD\tconditional\taccount_retention_decisions\tpatch_account_verify\taccount' \
        $'U-08\tadministrator_group\tR3\tpolicy\taccount\tGOOD\tconditional\tadministrator_group_members\tpatch_account_verify\taccount' \
        $'U-09\torphan_groups\tR3\tpolicy\taccount\tGOOD\tconditional\torphan_group_resolution\tpatch_account_verify\taccount' \
        $'U-10\tduplicate_uids\tR4\tpolicy\taccount\tGOOD\tconditional\tduplicate_uid_resolution\tpatch_account_verify\taccount' \
        $'U-11\tlogin_shells\tR3\tpolicy\taccount\tGOOD\tconditional\tallowed_login_shells\tpatch_account_verify\taccount' \
        $'U-12\tsession_timeout\tR1\ttechnical\tconfiguration\tGOOD\tfixed\tnone\tpatch_configuration_verify\tconfiguration' \
        $'U-13\tpassword_hash\tR3\ttechnical\taccount\tGOOD\tconditional\tpassword_hash_policy\tpatch_account_verify\taccount' \
        $'U-14\troot_path\tR3\ttechnical\tinventory\tGOOD\tconditional\troot_path_allowlist\tpatch_inventory_verify\tinventory' \
        $'U-15\torphan_ownership\tR4\tpolicy\tinventory\tGOOD\tconditional\townership_resolution_map\tpatch_inventory_verify\tinventory' \
        $'U-16\tpasswd_metadata\tR1\ttechnical\tmetadata\tGOOD\tfixed\tnone\tpatch_engine_verify\tmetadata' \
        $'U-17\tstartup_metadata\tR3\ttechnical\tfilesystem\tGOOD\tconditional\tstartup_object_policy\tpatch_filesystem_verify\tfilesystem' \
        $'U-18\tshadow_metadata\tR2\ttechnical\tmetadata\tGOOD\tfixed\tnone\tpatch_engine_verify\tmetadata' \
        $'U-19\thosts_metadata\tR1\ttechnical\tmetadata\tGOOD\tfixed\tnone\tpatch_engine_verify\tmetadata' \
        $'U-20\tinetd_metadata\tR2\ttechnical\tfilesystem\tGOOD\tconditional\tinetd_path_set\tpatch_filesystem_verify\tfilesystem' \
        $'U-21\tlogging_metadata\tR2\ttechnical\tfilesystem\tGOOD\tconditional\tlogging_path_set\tpatch_filesystem_verify\tfilesystem' \
        $'U-22\tservices_metadata\tR1\ttechnical\tmetadata\tGOOD\tfixed\tnone\tpatch_engine_verify\tmetadata' \
        $'U-23\tprivileged_bits\tR4\tpolicy\tinventory\tGOOD\tconditional\tprivileged_file_allowlist\tpatch_inventory_verify\tinventory' \
        $'U-24\tenvironment_metadata\tR3\ttechnical\tfilesystem\tGOOD\tconditional\taccount_environment_path_policy\tpatch_filesystem_verify\tfilesystem' \
        $'U-25\tworld_writable_objects\tR4\tpolicy\tfilesystem\tGOOD\tconditional\tworld_writable_path_exceptions\tpatch_filesystem_verify\tfilesystem' \
        $'U-26\tdevice_tree_objects\tR4\tpolicy\tinventory\tGOOD\tconditional\tdevice_tree_object_policy\tpatch_inventory_verify\tinventory' \
        $'U-27\ttrust_files\tR3\ttechnical\tfilesystem\tGOOD\tconditional\ttrust_file_removal_policy\tpatch_filesystem_verify\tfilesystem' \
        $'U-28\tnetwork_access\tR4\tpolicy\tedge-service\tGOOD\tconditional\tnetwork_service_allowlist\tvalidate_u28_network_access_v2\tedge-service' \
        $'U-29\thosts_lpd_metadata\tR1\ttechnical\tmetadata\tGOOD\tfixed\tnone\tpatch_engine_verify\tmetadata' \
        $'U-30\tumask_policy\tR2\ttechnical\tinventory\tGOOD\tconditional\tumask_policy_parameters\tpatch_inventory_verify\tinventory' \
        $'U-31\thome_metadata\tR3\ttechnical\tfilesystem\tGOOD\tconditional\thome_directory_policy\tpatch_filesystem_verify\tfilesystem' \
        $'U-32\thome_presence\tR4\tpolicy\taccount\tGOOD\tconditional\thome_directory_resolution\tpatch_account_verify\taccount' \
        $'U-33\thidden_objects\tR4\tpolicy\tinventory\tGOOD\tconditional\thidden_object_retention_decisions\tpatch_inventory_verify\tinventory' \
        $'U-34\tfinger_service\tR3\truntime\tservice\tGOOD\tconditional\tservice_disable_approval\tpatch_service_verify\tservice' \
        $'U-35\tanonymous_shares\tR4\tpolicy\tnetwork-service\tNOT_APPLICABLE\tconditional\tanonymous_share_policy\tpatch_network_service_verify\tnetwork-service' \
        $'U-36\tr_services\tR3\truntime\tservice\tGOOD\tconditional\tservice_disable_approval\tpatch_service_verify\tservice' \
        $'U-37\tscheduler_metadata\tR2\ttechnical\tmetadata\tGOOD\tfixed\tnone\tpatch_engine_verify\tmetadata' \
        $'U-38\tlegacy_dos_services\tR3\truntime\tservice\tGOOD\tconditional\tservice_disable_approval\tpatch_service_verify\tservice' \
        $'U-39\tnfs_service\tR4\tpolicy\tnetwork-service\tGOOD\tconditional\tnfs_service_requirement\tpatch_network_service_verify\tnetwork-service' \
        $'U-40\tnfs_access\tR4\tpolicy\tnetwork-service\tNOT_APPLICABLE\tconditional\tnfs_client_allowlist\tpatch_network_service_verify\tnetwork-service' \
        $'U-41\tautomount_service\tR3\tpolicy\tservice\tGOOD\tconditional\tservice_disable_approval\tpatch_service_verify\tservice' \
        $'U-42\trpc_services\tR4\tpolicy\tnetwork-service\tGOOD\tconditional\trpc_service_requirements\tpatch_network_service_verify\tnetwork-service' \
        $'U-43\tnis_services\tR4\tpolicy\tservice\tGOOD\tconditional\tservice_disable_approval\tpatch_service_verify\tservice' \
        $'U-44\ttftp_talk_services\tR3\truntime\tservice\tGOOD\tconditional\tservice_disable_approval\tpatch_service_verify\tservice' \
        $'U-45\tmail_version\tR4\texternal\tnetwork-service\tNOT_APPLICABLE\tconditional\tvendor_mail_advisory_snapshot\tpatch_network_service_verify\tnetwork-service' \
        $'U-46\tmail_command_access\tR3\ttechnical\tnetwork-service\tNOT_APPLICABLE\tconditional\tmail_provider_command_set\tpatch_network_service_verify\tnetwork-service' \
        $'U-47\tmail_relay\tR4\tpolicy\tnetwork-service\tNOT_APPLICABLE\tconditional\tmail_relay_policy\tpatch_network_service_verify\tnetwork-service' \
        $'U-48\tmail_enumeration\tR3\ttechnical\tnetwork-service\tNOT_APPLICABLE\tconditional\tmail_provider_policy\tpatch_network_service_verify\tnetwork-service' \
        $'U-49\tdns_version\tR4\texternal\tnetwork-service\tNOT_APPLICABLE\tconditional\tvendor_dns_advisory_snapshot\tpatch_network_service_verify\tnetwork-service' \
        $'U-50\tdns_zone_transfer\tR4\tpolicy\tnetwork-service\tNOT_APPLICABLE\tconditional\tauthorized_secondary_servers\tpatch_network_service_verify\tnetwork-service' \
        $'U-51\tdns_dynamic_update\tR4\tpolicy\tnetwork-service\tNOT_APPLICABLE\tconditional\tdns_update_principals\tpatch_network_service_verify\tnetwork-service' \
        $'U-52\ttelnet_service\tR3\truntime\tservice\tGOOD\tconditional\tservice_disable_approval\tpatch_service_verify\tservice' \
        $'U-53\tftp_banner\tR2\tpolicy\tedge-service\tNOT_APPLICABLE\tconditional\tftp_warning_text\tvalidate_u53_ftp_banner_v2\tedge-service' \
        $'U-54\tplaintext_ftp\tR4\truntime\tservice\tGOOD\tconditional\tservice_disable_approval\tpatch_service_verify\tservice' \
        $'U-55\tftp_account_shell\tR3\ttechnical\taccount\tNOT_APPLICABLE\tconditional\tftp_account_policy\tpatch_account_verify\taccount' \
        $'U-56\tftp_access\tR4\tpolicy\tedge-service\tNOT_APPLICABLE\tconditional\tftp_client_allowlist\tvalidate_u56_ftp_access_v2\tedge-service' \
        $'U-57\tftp_denied_users\tR3\ttechnical\tedge-service\tNOT_APPLICABLE\tconditional\tftp_denied_accounts\tvalidate_u57_ftp_denied_users_v2\tedge-service' \
        $'U-58\tsnmp_service\tR3\tpolicy\tservice\tGOOD\tconditional\tservice_disable_approval\tpatch_service_verify\tservice' \
        $'U-59\tsnmp_version\tR4\ttechnical\tedge-service\tNOT_APPLICABLE\tconditional\tsnmp_security_level\tvalidate_u59_snmp_version_v2\tedge-service' \
        $'U-60\tsnmp_community\tR4\tpolicy\tedge-service\tNOT_APPLICABLE\tconditional\tsnmp_community_secret_reference\tvalidate_u60_snmp_community_v2\tedge-service' \
        $'U-61\tsnmp_access\tR4\tpolicy\tedge-service\tNOT_APPLICABLE\tconditional\tsnmp_manager_allowlist\tvalidate_u61_snmp_access_v2\tedge-service' \
        $'U-62\tlogin_warning\tR1\tpolicy\tconfiguration\tGOOD\tfixed\tnone\tpatch_configuration_verify\tconfiguration' \
        $'U-63\tsudo_access\tR3\tpolicy\tfilesystem\tGOOD\tconditional\tsudo_authorization_policy\tpatch_filesystem_verify\tfilesystem' \
        $'U-64\tpatch_management\tR4\texternal\tpackage\tGOOD\tconditional\tvendor_advisory_snapshot\tvalidate_u64_patch_management_v2\tpackage' \
        $'U-65\ttime_synchronization\tR3\truntime\tsystem\tGOOD\tconditional\tapproved_time_sources\tpatch_system_verify\tsystem' \
        $'U-66\tlogging_policy\tR3\tpolicy\tsystem\tGOOD\tconditional\tlogging_route_policy\tpatch_system_verify\tsystem' \
        $'U-67\tlog_metadata\tR3\ttechnical\tmetadata\tGOOD\tfixed\tnone\tpatch_engine_verify\tmetadata'
}

patch_coverage_adapter_is_known() {
    case "$1" in
        remote_root_access|password_policy|account_lockout|password_store|uid_zero_accounts|su_access|unnecessary_accounts|administrator_group|orphan_groups|duplicate_uids|login_shells|session_timeout|password_hash|root_path|orphan_ownership|passwd_metadata|startup_metadata|shadow_metadata|hosts_metadata|inetd_metadata|logging_metadata|services_metadata|privileged_bits|environment_metadata|world_writable_objects|device_tree_objects|trust_files|network_access|hosts_lpd_metadata|umask_policy|home_metadata|home_presence|hidden_objects|finger_service|anonymous_shares|r_services|scheduler_metadata|legacy_dos_services|nfs_service|nfs_access|automount_service|rpc_services|nis_services|tftp_talk_services|mail_version|mail_command_access|mail_relay|mail_enumeration|dns_version|dns_zone_transfer|dns_dynamic_update|telnet_service|ftp_banner|plaintext_ftp|ftp_account_shell|ftp_access|ftp_denied_users|snmp_service|snmp_version|snmp_community|snmp_access|login_warning|sudo_access|patch_management|time_synchronization|logging_policy|log_metadata)
            return 0
            ;;
        *) return 1 ;;
    esac
}

_patch_coverage_expected_status() {
    case "$1" in
        U-12|U-16|U-18|U-19|U-22|U-29|U-37|U-62|U-67) printf 'fixed\n' ;;
        U-[0-9][0-9]) printf 'conditional\n' ;;
        *) return 1 ;;
    esac
}

_patch_coverage_set_error() {
    PATCH_COVERAGE_ERROR_DETAIL="$1"
    return 2
}

_patch_coverage_validate_stream() {
    local header=""
    local code=""
    local adapter=""
    local risk=""
    local resolution_requirement=""
    local transaction_domain=""
    local postcondition=""
    local implementation_status=""
    local typed_input=""
    local validator=""
    local rollback_domain=""
    local extra=""
    local expected_code=""
    local expected_status=""
    local validator_prefix=""
    local count=0
    local -A seen_adapters=()

    PATCH_COVERAGE_ERROR_DETAIL=""
    IFS= read -r header || {
        _patch_coverage_set_error "coverage contract is empty"
        return 2
    }
    [ "$header" = "$PATCH_COVERAGE_HEADER" ] || {
        _patch_coverage_set_error "coverage contract header is invalid"
        return 2
    }
    while IFS=$'\t' read -r code adapter risk resolution_requirement transaction_domain \
        postcondition implementation_status typed_input validator rollback_domain extra; do
        [ -n "$code" ] || continue
        count=$((count + 1))
        printf -v expected_code 'U-%02d' "$count"
        [ "$code" = "$expected_code" ] || {
            _patch_coverage_set_error "coverage code is missing, duplicated, or out of order: expected $expected_code"
            return 2
        }
        [ -z "$extra" ] || {
            _patch_coverage_set_error "$code has an invalid field count"
            return 2
        }
        patch_coverage_adapter_is_known "$adapter" || {
            _patch_coverage_set_error "$code names an unknown primary adapter: $adapter"
            return 2
        }
        [ -z "${seen_adapters[$adapter]+present}" ] || {
            _patch_coverage_set_error "$code duplicates primary adapter: $adapter"
            return 2
        }
        seen_adapters["$adapter"]="$code"
        case "$risk" in R0|R1|R2|R3|R4) ;; *) _patch_coverage_set_error "$code has an invalid risk"; return 2 ;; esac
        case "$resolution_requirement" in
            technical|policy|runtime|external) ;;
            *) _patch_coverage_set_error "$code has an invalid resolution requirement"; return 2 ;;
        esac
        case "$transaction_domain" in
            metadata|configuration|pam|service|firewall|package|account|filesystem|inventory|system|network-service|edge-service) ;;
            *) _patch_coverage_set_error "$code has an invalid transaction domain"; return 2 ;;
        esac
        [ "$rollback_domain" = "$transaction_domain" ] || {
            _patch_coverage_set_error "$code has a mismatched rollback domain"
            return 2
        }
        case "$postcondition" in GOOD|NOT_APPLICABLE) ;; *) _patch_coverage_set_error "$code has an invalid postcondition"; return 2 ;; esac
        expected_status="$(_patch_coverage_expected_status "$code")" || return 2
        [ "$implementation_status" = "$expected_status" ] || {
            _patch_coverage_set_error "$code has an invalid implementation status"
            return 2
        }
        case "$typed_input:$validator" in
            *[!a-z0-9_:.-]*) _patch_coverage_set_error "$code has an invalid requirement identifier"; return 2 ;;
        esac
        if [ "$implementation_status" = fixed ]; then
            [ "$typed_input" = none ] || {
                _patch_coverage_set_error "$code fixed adapter unexpectedly requires typed input"
                return 2
            }
            case "$transaction_domain:$validator" in
                metadata:patch_engine_verify|configuration:patch_configuration_verify) ;;
                *) _patch_coverage_set_error "$code names an unknown fixed validator"; return 2 ;;
            esac
        elif [ "$implementation_status" = conditional ]; then
            [ "$typed_input" != none ] || {
                _patch_coverage_set_error "$code conditional adapter does not name its typed input"
                return 2
            }
            case "$transaction_domain:$validator" in
                account:patch_account_verify|filesystem:patch_filesystem_verify|inventory:patch_inventory_verify|pam:pam_transaction_verify|service:patch_service_verify|system:patch_system_verify|package:validate_u64_patch_management_v2|network-service:patch_network_service_verify|edge-service:validate_u01_remote_root_access_v2|edge-service:validate_u28_network_access_v2|edge-service:validate_u53_ftp_banner_v2|edge-service:validate_u56_ftp_access_v2|edge-service:validate_u57_ftp_denied_users_v2|edge-service:validate_u59_snmp_version_v2|edge-service:validate_u60_snmp_community_v2|edge-service:validate_u61_snmp_access_v2) ;;
                *) _patch_coverage_set_error "$code names an unknown conditional validator"; return 2 ;;
            esac
        else
            [ "$typed_input" != none ] || {
                _patch_coverage_set_error "$code gated adapter does not name its typed input"
                return 2
            }
            validator_prefix="validate_u${code#U-}_"
            validator_prefix="${validator_prefix//-/}"
            case "$validator" in
                "$validator_prefix"*_v2) ;;
                *) _patch_coverage_set_error "$code gated adapter names an invalid validator"; return 2 ;;
            esac
        fi
    done
    [ "$count" -eq 67 ] || {
        _patch_coverage_set_error "coverage contract contains $count records instead of 67"
        return 2
    }
}

patch_coverage_validate_file() {
    local path="$1"

    [ -f "$path" ] && [ ! -L "$path" ] && [ -r "$path" ] || {
        _patch_coverage_set_error "coverage contract file is unsafe"
        return 2
    }
    _patch_coverage_validate_stream < "$path"
}

patch_coverage_validate() {
    _patch_coverage_validate_stream < <(patch_coverage_records)
}

patch_coverage_record_into() {
    local __kisa_coverage_requested_code="$1"
    local __kisa_coverage_destination_name="$2"
    local __kisa_coverage_header=""
    local __kisa_coverage_row=""
    local __kisa_coverage_row_code=""

    case "$__kisa_coverage_destination_name" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|__kisa_coverage_*) return 2 ;;
    esac
    {
        IFS= read -r __kisa_coverage_header || return 2
        [ "$__kisa_coverage_header" = "$PATCH_COVERAGE_HEADER" ] || return 2
        while IFS= read -r __kisa_coverage_row; do
            __kisa_coverage_row_code="${__kisa_coverage_row%%$'\t'*}"
            if [ "$__kisa_coverage_row_code" = "$__kisa_coverage_requested_code" ]; then
                printf -v "$__kisa_coverage_destination_name" '%s' "$__kisa_coverage_row"
                return 0
            fi
        done
    } < <(patch_coverage_records)
    return 1
}

_patch_coverage_requirements_for_status_into() {
    local __kisa_coverage_expected_status="$1"
    local __kisa_coverage_code="$2"
    local __kisa_coverage_typed_input_destination="$3"
    local __kisa_coverage_validator_destination="$4"
    local __kisa_coverage_rollback_domain_destination="$5"
    local requirement_coverage_record=""
    local __kisa_coverage_record_code=""
    local __kisa_coverage_record_adapter=""
    local __kisa_coverage_record_risk=""
    local __kisa_coverage_record_resolution_requirement=""
    local __kisa_coverage_record_transaction_domain=""
    local __kisa_coverage_record_postcondition=""
    local __kisa_coverage_record_implementation_status=""
    local __kisa_coverage_record_typed_input=""
    local __kisa_coverage_record_validator=""
    local __kisa_coverage_record_rollback_domain=""
    local __kisa_coverage_destination_name=""

    for __kisa_coverage_destination_name in "$__kisa_coverage_typed_input_destination" \
        "$__kisa_coverage_validator_destination" "$__kisa_coverage_rollback_domain_destination"; do
        case "$__kisa_coverage_destination_name" in
            ''|[0-9]*|*[!A-Za-z0-9_]*|__kisa_coverage_*) return 2 ;;
        esac
    done
    case "$__kisa_coverage_expected_status" in conditional|gated) ;; *) return 2 ;; esac
    patch_coverage_record_into "$__kisa_coverage_code" requirement_coverage_record || return 1
    IFS=$'\t' read -r __kisa_coverage_record_code __kisa_coverage_record_adapter \
        __kisa_coverage_record_risk __kisa_coverage_record_resolution_requirement \
        __kisa_coverage_record_transaction_domain __kisa_coverage_record_postcondition \
        __kisa_coverage_record_implementation_status __kisa_coverage_record_typed_input \
        __kisa_coverage_record_validator __kisa_coverage_record_rollback_domain \
        <<< "$requirement_coverage_record"
    [ "$__kisa_coverage_record_code" = "$__kisa_coverage_code" ] || return 2
    [ "$__kisa_coverage_record_implementation_status" = "$__kisa_coverage_expected_status" ] || return 1
    printf -v "$__kisa_coverage_typed_input_destination" '%s' \
        "$__kisa_coverage_record_typed_input"
    printf -v "$__kisa_coverage_validator_destination" '%s' \
        "$__kisa_coverage_record_validator"
    printf -v "$__kisa_coverage_rollback_domain_destination" '%s' \
        "$__kisa_coverage_record_rollback_domain"
}

patch_coverage_conditional_requirements_into() {
    _patch_coverage_requirements_for_status_into conditional "$@"
}

patch_coverage_gated_requirements_into() {
    _patch_coverage_requirements_for_status_into gated "$@"
}
