# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash

# Metadata-only remediation rules for the KISA CCE Linux patcher.

patch_metadata_rule_lookup_into() {
    local __kisa_patch_rule_criterion="$1"
    local __kisa_patch_rule_required_destination="$2"
    local __kisa_patch_rule_path_destination="$3"
    local __kisa_patch_rule_owner_uid_destination="$4"
    local __kisa_patch_rule_group_destination="$5"
    local __kisa_patch_rule_mode_destination="$6"
    local __kisa_patch_rule_required=""
    local __kisa_patch_rule_logical_path=""
    local __kisa_patch_rule_owner_uid=""
    local __kisa_patch_rule_group_policy=""
    local __kisa_patch_rule_maximum_mode=""

    case "$__kisa_patch_rule_required_destination:$__kisa_patch_rule_path_destination:$__kisa_patch_rule_owner_uid_destination:$__kisa_patch_rule_group_destination:$__kisa_patch_rule_mode_destination" in
        *[!A-Za-z0-9_:]*|:*|*:|*::*|__kisa_patch_rule_*)
            return 2
            ;;
    esac

    case "$__kisa_patch_rule_criterion" in
        U-16)
            __kisa_patch_rule_required=required
            __kisa_patch_rule_logical_path=/etc/passwd
            __kisa_patch_rule_owner_uid=0
            __kisa_patch_rule_group_policy=preserve
            __kisa_patch_rule_maximum_mode=0644
            ;;
        U-18)
            __kisa_patch_rule_required=required
            __kisa_patch_rule_logical_path=/etc/shadow
            __kisa_patch_rule_owner_uid=0
            __kisa_patch_rule_group_policy=preserve
            __kisa_patch_rule_maximum_mode=0400
            ;;
        U-19)
            __kisa_patch_rule_required=required
            __kisa_patch_rule_logical_path=/etc/hosts
            __kisa_patch_rule_owner_uid=0
            __kisa_patch_rule_group_policy=preserve
            __kisa_patch_rule_maximum_mode=0644
            ;;
        U-22)
            __kisa_patch_rule_required=optional
            __kisa_patch_rule_logical_path=/etc/services
            __kisa_patch_rule_owner_uid=0
            __kisa_patch_rule_group_policy=preserve
            __kisa_patch_rule_maximum_mode=0644
            ;;
        U-29)
            __kisa_patch_rule_required=optional
            __kisa_patch_rule_logical_path=/etc/hosts.lpd
            __kisa_patch_rule_owner_uid=0
            __kisa_patch_rule_group_policy=preserve
            __kisa_patch_rule_maximum_mode=0600
            ;;
        *)
            return 1
            ;;
    esac

    printf -v "$__kisa_patch_rule_required_destination" '%s' "$__kisa_patch_rule_required"
    printf -v "$__kisa_patch_rule_path_destination" '%s' "$__kisa_patch_rule_logical_path"
    printf -v "$__kisa_patch_rule_owner_uid_destination" '%s' "$__kisa_patch_rule_owner_uid"
    printf -v "$__kisa_patch_rule_group_destination" '%s' "$__kisa_patch_rule_group_policy"
    printf -v "$__kisa_patch_rule_mode_destination" '%s' "$__kisa_patch_rule_maximum_mode"
}

patch_metadata_rule_criteria() {
    printf '%s\n' U-16 U-18 U-19 U-22 U-29 U-37 U-67
}

patch_metadata_rule_allowed_owners_into() {
    local __kisa_patch_rule_criterion="$1"
    local __kisa_patch_rule_destination="$2"
    local __kisa_patch_rule_allowed_owners=""

    case "$__kisa_patch_rule_destination" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|__kisa_patch_rule_*) return 2 ;;
    esac
    case "$__kisa_patch_rule_criterion" in
        U-16|U-18|U-19|U-29|U-37|U-67) __kisa_patch_rule_allowed_owners=root ;;
        U-22) __kisa_patch_rule_allowed_owners='root bin sys' ;;
        *) return 1 ;;
    esac
    printf -v "$__kisa_patch_rule_destination" '%s' "$__kisa_patch_rule_allowed_owners"
}

patch_metadata_rule_kind_into() {
    local __kisa_patch_rule_criterion="$1"
    local __kisa_patch_rule_destination="$2"
    local __kisa_patch_rule_kind=""

    case "$__kisa_patch_rule_destination" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|__kisa_patch_rule_*) return 2 ;;
    esac
    case "$__kisa_patch_rule_criterion" in
        U-16|U-18|U-19|U-22|U-29) __kisa_patch_rule_kind=fixed ;;
        U-37) __kisa_patch_rule_kind=cron_set ;;
        U-67) __kisa_patch_rule_kind=log_set ;;
        *) return 1 ;;
    esac
    printf -v "$__kisa_patch_rule_destination" '%s' "$__kisa_patch_rule_kind"
}

patch_metadata_rule_absent_state_into() {
    local __kisa_patch_rule_criterion="$1"
    local __kisa_patch_rule_destination="$2"
    local __kisa_patch_rule_absent_state=""

    case "$__kisa_patch_rule_destination" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|__kisa_patch_rule_*) return 2 ;;
    esac
    case "$__kisa_patch_rule_criterion" in
        U-22) __kisa_patch_rule_absent_state=not_applicable ;;
        U-29) __kisa_patch_rule_absent_state=compliant ;;
        U-16|U-18|U-19) return 1 ;;
        *) return 2 ;;
    esac
    printf -v "$__kisa_patch_rule_destination" '%s' "$__kisa_patch_rule_absent_state"
}
