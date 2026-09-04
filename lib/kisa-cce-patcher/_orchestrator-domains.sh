# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash
# shellcheck disable=SC2034

# Bridges orchestrator requests to recoverable domain transaction modules.

PATCH_ORCHESTRATOR_DOMAIN_INPUT_HEADER=$'schema\tcriterion\trecord_type\tvalue_one\tvalue_two\tvalue_three\tvalue_four\tvalue_five\tvalue_six\tvalue_seven\tapproval'
PATCH_ORCHESTRATOR_DOMAIN_PLAN_HEADER=$'criterion\tadapter\tinput_type\tinput_value\ttransaction\tstate\tartifact_digest\tcallback_set_digest'
PATCH_ORCHESTRATOR_DOMAINS_ERROR_DETAIL=""
PATCH_ORCHESTRATOR_DOMAINS_PREREQUISITE=""
PATCH_DOMAIN_CALLBACK_SNAPSHOT_DIRECTORY=""
PATCH_DOMAIN_CALLBACK_SNAPSHOT_MODE=""
PATCH_DOMAIN_CALLBACK_SET_DIGEST=""

PATCH_DOMAIN_INPUT_RECORD_TYPES=()
PATCH_DOMAIN_INPUT_VALUE_ONES=()
PATCH_DOMAIN_INPUT_VALUE_TWOS=()
PATCH_DOMAIN_INPUT_VALUE_THREES=()
PATCH_DOMAIN_INPUT_VALUE_FOURS=()
PATCH_DOMAIN_INPUT_VALUE_FIVES=()
PATCH_DOMAIN_INPUT_VALUE_SIXES=()
PATCH_DOMAIN_INPUT_VALUE_SEVENS=()
PATCH_DOMAIN_INPUT_APPROVALS=()

_patch_domains_error() {
    PATCH_ORCHESTRATOR_DOMAINS_ERROR_DETAIL="$1"
    return 2
}

_patch_domains_prerequisite() {
    PATCH_ORCHESTRATOR_DOMAINS_PREREQUISITE="$1"
    PATCH_ORCHESTRATOR_DOMAINS_ERROR_DETAIL="prerequisite not satisfied: $1"
    return 3
}

_patch_domains_stat_into() {
    local path="$1"
    local destination_name="$2"
    local stat_output=""

    case "$destination_name" in ''|[0-9]*|*[!A-Za-z0-9_]*) return 2 ;; esac
    if stat_output="$(/usr/bin/stat -Lc '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' -- "$path" 2>/dev/null)"; then :
    elif stat_output="$(/usr/bin/stat -f '%d:%i:%u:%g:%Lp:%l:%z:%m:%c' "$path" 2>/dev/null)"; then :
    else return 2
    fi
    case "$stat_output" in *[!0-9:]*) return 2 ;; esac
    printf -v "$destination_name" '%s' "$stat_output"
}

_patch_domains_absolute_path_safe() {
    local path="$1"
    local component=""
    local current=/
    local old_ifs="$IFS"
    local -a components=()

    case "$path" in /*) ;; *) return 1 ;; esac
    case "$path" in *$'\n'*|*$'\r'*|*$'\t'*|*'//'*) return 1 ;; esac
    IFS=/ read -r -a components <<< "${path#/}"
    IFS="$old_ifs"
    for component in "${components[@]}"; do
        case "$component" in ''|.|..) return 1 ;; esac
        current="${current%/}/$component"
        [ ! -L "$current" ] || return 1
    done
}

_patch_domains_parent_chain_trusted() {
    local path="$1"
    local canonical_path=""
    local current=/
    local relative=""
    local component=""
    local metadata=""
    local device="" inode="" uid="" gid="" mode="" links="" size="" mtime="" ctime="" extra=""
    local -a components=()

    canonical_path="$(CDPATH='' builtin cd -P -- "$path" 2>/dev/null && pwd -P)" || return 2
    relative="${canonical_path#/}"
    IFS=/ read -r -a components <<< "$relative"
    for component in "${components[@]}"; do
        [ -n "$component" ] || continue
        current="${current%/}/$component"
        _patch_domains_stat_into "$current" metadata || return 2
        IFS=: read -r device inode uid gid mode links size mtime ctime extra <<< "$metadata"
        [ -z "$extra" ] && [ "$uid" = 0 ] || return 2
        if [ $((8#$mode & 0022)) -ne 0 ]; then
            [ $((8#$mode & 01000)) -ne 0 ] &&
                { [ "$current" = /tmp ] || [ "$current" = /var/tmp ] ||
                  [ "$current" = /private/tmp ] || [ "$current" = /private/var/tmp ]; } || return 2
        fi
    done
}

_patch_domains_root_owned_file() {
    local path="$1"
    local metadata=""
    local device="" inode="" uid="" gid="" mode="" links="" size="" mtime="" ctime="" extra=""

    _patch_domains_absolute_path_safe "$path" || return 2
    _patch_domains_parent_chain_trusted "${path%/*}" || return 2
    [ -f "$path" ] && [ ! -L "$path" ] && [ -r "$path" ] || return 2
    _patch_domains_stat_into "$path" metadata || return 2
    IFS=: read -r device inode uid gid mode links size mtime ctime extra <<< "$metadata"
    [ -z "$extra" ] && [ "$uid" = 0 ] && [ "$mode" = 600 ] && [ "$links" = 1 ]
}

_patch_domains_safe_callback() {
    local path="$1"
    local metadata=""
    local device="" inode="" uid="" gid="" mode="" links="" size="" mtime="" ctime="" extra=""

    _patch_domains_absolute_path_safe "$path" || return 2
    _patch_domains_parent_chain_trusted "${path%/*}" || return 2
    [ -f "$path" ] && [ ! -L "$path" ] && [ -x "$path" ] || return 2
    _patch_domains_stat_into "$path" metadata || return 2
    IFS=: read -r device inode uid gid mode links size mtime ctime extra <<< "$metadata"
    [ -z "$extra" ] && [ "$uid" = 0 ] && [ "$links" = 1 ] && [ $((8#$mode & 0022)) -eq 0 ]
}

_patch_domains_safe_field() {
    case "$1" in ''|*$'\n'*|*$'\r'*|*$'\t'*) return 1 ;; *) return 0 ;; esac
}

_patch_domains_safe_token() {
    [ -n "$1" ] && [ "${#1}" -le 512 ] || return 1
    case "$1" in *[!A-Za-z0-9._:@,+%=-]*) return 1 ;; *) return 0 ;; esac
}

_patch_domains_load_input() {
    local path="$1"
    local requested_criterion="$2"
    local line=""
    local line_number=0
    local schema="" criterion="" record_type=""
    local one="" two="" three="" four="" five="" six="" seven="" approval="" extra=""
    local field=""
    local selected_count=0

    PATCH_DOMAIN_INPUT_RECORD_TYPES=()
    PATCH_DOMAIN_INPUT_VALUE_ONES=()
    PATCH_DOMAIN_INPUT_VALUE_TWOS=()
    PATCH_DOMAIN_INPUT_VALUE_THREES=()
    PATCH_DOMAIN_INPUT_VALUE_FOURS=()
    PATCH_DOMAIN_INPUT_VALUE_FIVES=()
    PATCH_DOMAIN_INPUT_VALUE_SIXES=()
    PATCH_DOMAIN_INPUT_VALUE_SEVENS=()
    PATCH_DOMAIN_INPUT_APPROVALS=()
    _patch_domains_root_owned_file "$path" || {
        _patch_domains_prerequisite "root_owned_0600_domain_input:$requested_criterion"
        return 3
    }
    while IFS= read -r line || [ -n "$line" ]; do
        line_number=$((line_number + 1))
        if [ "$line_number" -eq 1 ]; then
            [ "$line" = "$PATCH_ORCHESTRATOR_DOMAIN_INPUT_HEADER" ] || return 2
            continue
        fi
        IFS=$'\t' read -r schema criterion record_type one two three four five six seven approval extra <<< "$line"
        [ -z "$extra" ] && [ "$schema" = 1 ] || return 2
        case "$criterion" in U-[0-9][0-9]) ;; *) return 2 ;; esac
        case "$record_type" in ''|*[!a-z0-9_-]*) return 2 ;; esac
        for field in "$one" "$two" "$three" "$four" "$five" "$six" "$seven" "$approval"; do
            _patch_domains_safe_field "$field" || return 2
        done
        [ "$criterion" = "$requested_criterion" ] || continue
        PATCH_DOMAIN_INPUT_RECORD_TYPES+=("$record_type")
        PATCH_DOMAIN_INPUT_VALUE_ONES+=("$one")
        PATCH_DOMAIN_INPUT_VALUE_TWOS+=("$two")
        PATCH_DOMAIN_INPUT_VALUE_THREES+=("$three")
        PATCH_DOMAIN_INPUT_VALUE_FOURS+=("$four")
        PATCH_DOMAIN_INPUT_VALUE_FIVES+=("$five")
        PATCH_DOMAIN_INPUT_VALUE_SIXES+=("$six")
        PATCH_DOMAIN_INPUT_VALUE_SEVENS+=("$seven")
        PATCH_DOMAIN_INPUT_APPROVALS+=("$approval")
        selected_count=$((selected_count + 1))
    done < "$path"
    [ "$line_number" -gt 1 ] && [ "$selected_count" -gt 0 ]
}

_patch_domains_single_record_into() {
    local record_type="$1"
    local one_destination="$2"
    local two_destination="$3"
    local three_destination="$4"
    local four_destination="$5"
    local five_destination="$6"
    local six_destination="$7"
    local seven_destination="$8"
    local approval_destination="$9"
    local index=0
    local found=0

    while [ "$index" -lt "${#PATCH_DOMAIN_INPUT_RECORD_TYPES[@]}" ]; do
        if [ "${PATCH_DOMAIN_INPUT_RECORD_TYPES[$index]}" = "$record_type" ]; then
            found=$((found + 1))
            printf -v "$one_destination" '%s' "${PATCH_DOMAIN_INPUT_VALUE_ONES[$index]}"
            printf -v "$two_destination" '%s' "${PATCH_DOMAIN_INPUT_VALUE_TWOS[$index]}"
            printf -v "$three_destination" '%s' "${PATCH_DOMAIN_INPUT_VALUE_THREES[$index]}"
            printf -v "$four_destination" '%s' "${PATCH_DOMAIN_INPUT_VALUE_FOURS[$index]}"
            printf -v "$five_destination" '%s' "${PATCH_DOMAIN_INPUT_VALUE_FIVES[$index]}"
            printf -v "$six_destination" '%s' "${PATCH_DOMAIN_INPUT_VALUE_SIXES[$index]}"
            printf -v "$seven_destination" '%s' "${PATCH_DOMAIN_INPUT_VALUE_SEVENS[$index]}"
            printf -v "$approval_destination" '%s' "${PATCH_DOMAIN_INPUT_APPROVALS[$index]}"
        fi
        index=$((index + 1))
    done
    [ "$found" -eq 1 ]
}

_patch_domains_prepare_child() {
    local domain_directory="$1"
    local criterion="$2"
    local destination_name="$3"
    local candidate_child="$domain_directory/transactions/$criterion"

    [ -d "$domain_directory" ] && [ ! -L "$domain_directory" ] || return 2
    if [ ! -d "$domain_directory/transactions" ]; then
        /bin/mkdir -m 0700 "$domain_directory/transactions" || return 2
    fi
    [ ! -e "$candidate_child" ] && [ ! -L "$candidate_child" ] || return 2
    /bin/mkdir -m 0700 "$candidate_child" || return 2
    printf -v "$destination_name" '%s' "$candidate_child"
}

_patch_domains_register_callback_row() {
    local domain="$1"
    local role="$2"
    local path="$3"
    local snapshot_path=""
    local source_digest=""
    local snapshot_digest=""

    _patch_domains_safe_callback "$path" || {
        _patch_domains_prerequisite "trusted_${domain}_${role}_callback"
        return 3
    }
    case "$role" in ''|*[!a-z0-9_-]*) return 2 ;; esac
    if [ -n "$PATCH_DOMAIN_CALLBACK_SNAPSHOT_DIRECTORY" ]; then
        snapshot_path="$PATCH_DOMAIN_CALLBACK_SNAPSHOT_DIRECTORY/$role"
        case "$PATCH_DOMAIN_CALLBACK_SNAPSHOT_MODE" in
            capture)
                _patch_orchestrator_sha256_into "$path" source_digest || return 2
                if [ -e "$snapshot_path" ] || [ -L "$snapshot_path" ]; then
                    _patch_domains_safe_callback "$snapshot_path" || return 2
                    _patch_orchestrator_sha256_into "$snapshot_path" snapshot_digest || return 2
                    [ "$source_digest" = "$snapshot_digest" ] || return 2
                else
                    (umask 077; /bin/cp -- "$path" "$snapshot_path") || return 2
                    /bin/chmod 0700 "$snapshot_path" || return 2
                    _patch_domains_safe_callback "$snapshot_path" || return 2
                    _patch_orchestrator_sha256_into "$snapshot_path" snapshot_digest || return 2
                    [ "$source_digest" = "$snapshot_digest" ] || return 2
                fi
                path="$snapshot_path"
                ;;
            reuse)
                [ "$path" = "$snapshot_path" ] || return 2
                _patch_domains_safe_callback "$snapshot_path" || return 2
                ;;
            *) return 2 ;;
        esac
    fi
    case "$domain" in
        filesystem)
            [ "${PATCH_FILESYSTEM_CALLBACKS[$role]:-}" = "$path" ] ||
                patch_filesystem_register_callback "$role" "$path"
            ;;
        inventory)
            [ "${PATCH_INVENTORY_CALLBACKS[$role]:-}" = "$path" ] ||
                patch_inventory_register_callback "$role" "$path"
            ;;
        system|package)
            [ "${PATCH_SYSTEM_CALLBACKS[$role]:-}" = "$path" ] ||
                patch_system_register_callback "$role" "$path"
            ;;
        network-service)
            [ "${PATCH_NETWORK_SERVICE_CALLBACKS[$role]:-}" = "$path" ] ||
                patch_network_service_register_callback "$role" "$path"
            ;;
        edge-service)
            [ "${PATCH_EDGE_CALLBACKS[$role]:-}" = "$path" ] ||
                patch_edge_register_callback "$role" "$path"
            ;;
        *) return 2 ;;
    esac
}

_patch_domains_register_input_callbacks() {
    local domain="$1"
    local index=0
    local role=""
    local path=""
    local status=0

    while [ "$index" -lt "${#PATCH_DOMAIN_INPUT_RECORD_TYPES[@]}" ]; do
        if [ "${PATCH_DOMAIN_INPUT_RECORD_TYPES[$index]}" = callback ]; then
            role="${PATCH_DOMAIN_INPUT_VALUE_ONES[$index]}"
            path="${PATCH_DOMAIN_INPUT_VALUE_TWOS[$index]}"
            _patch_domains_register_callback_row "$domain" "$role" "$path" || status=$?
            [ "$status" -eq 0 ] || return "$status"
        fi
        index=$((index + 1))
    done
}

_patch_domains_prepare_callback_snapshot() {
    local domain="$1"
    local domain_directory="$2"
    local index=0
    local input_value=""
    local callback_path=""
    local role=""
    local digest=""
    local manifest="$domain_directory/callbacks.tsv"
    local old_nullglob=0
    local status=0

    PATCH_DOMAIN_CALLBACK_SET_DIGEST=""
    case "$domain" in package|filesystem|inventory|system|network-service|edge-service) ;;
        *)
            printf 'role\tsha256\n' > "$manifest" || return 2
            /bin/chmod 0600 "$manifest" || return 2
            _patch_orchestrator_sha256_into "$manifest" PATCH_DOMAIN_CALLBACK_SET_DIGEST
            return
            ;;
    esac
    while [ "$index" -lt "${#PATCH_DOMAIN_REQUEST_CODES[@]}" ]; do
        input_value="${PATCH_DOMAIN_REQUEST_INPUT_VALUES[$index]}"
        if [[ "$input_value" == /* ]]; then
            _patch_domains_load_input "$input_value" "${PATCH_DOMAIN_REQUEST_CODES[$index]}" || return $?
            _patch_domains_register_input_callbacks "$domain" || return $?
        fi
        index=$((index + 1))
    done
    printf 'role\tsha256\n' > "$manifest" || return 2
    shopt -q nullglob && old_nullglob=1
    shopt -s nullglob
    for callback_path in "$PATCH_DOMAIN_CALLBACK_SNAPSHOT_DIRECTORY"/*; do
        role="${callback_path##*/}"
        _patch_orchestrator_sha256_into "$callback_path" digest || { status=2; break; }
        printf '%s\t%s\n' "$role" "$digest" >> "$manifest" || { status=2; break; }
    done
    [ "$old_nullglob" -eq 1 ] || shopt -u nullglob
    [ "$status" -eq 0 ] || return "$status"
    /bin/chmod 0600 "$manifest" || return 2
    _patch_orchestrator_sha256_into "$manifest" PATCH_DOMAIN_CALLBACK_SET_DIGEST
}

_patch_domains_reference_file() {
    local path="$1"

    _patch_domains_root_owned_file "$path" || {
        _patch_domains_prerequisite "root_owned_0600_referenced_input"
        return 3
    }
}

_patch_domains_plan_metadata() {
    local root="$1" child="$2" criterion="$3"

    patch_engine_reset
    patch_engine_plan "$root" "$criterion" || return $?
    patch_engine_write_plan_tsv "$child/plan.tsv" || return 2
    patch_engine_write_transaction_tsv "$child/metadata.tsv" || return 2
}

_patch_domains_plan_configuration() {
    local root="$1" child="$2" criterion="$3"

    patch_configuration_reset
    patch_configuration_plan "$root" "$child" "$criterion" || return $?
    patch_configuration_write_plan_tsv "$child/plan.tsv"
}

_patch_domains_plan_pam() {
    local root="$1" child="$2" criterion="$3" input_value="$4"
    local one="" two="" three="" four="" five="" six="" seven="" approval=""
    local approved_group=ignored
    local status=0

    if [[ "$input_value" == /* ]]; then
        _patch_domains_load_input "$input_value" "$criterion" || return $?
        case "$criterion" in
            U-02)
                _patch_domains_single_record_into password-policy one two three four five six seven approval || return 2
                [ "$one" = kisa-cce-2026 ] && _patch_domains_safe_token "$approval" || return 2
                ;;
            U-03)
                _patch_domains_single_record_into lockout-policy one two three four five six seven approval || return 2
                [ "$one" = kisa-cce-2026 ] && _patch_domains_safe_token "$approval" || return 2
                ;;
            U-06)
                _patch_domains_single_record_into approved-group one two three four five six seven approval || return 2
                approved_group="$one"
                ;;
            *) return 1 ;;
        esac
    else
        if [ "$criterion" = U-06 ]; then
            approved_group="$input_value"
        else
            _patch_domains_safe_token "$input_value" || return 2
        fi
    fi
    pam_transaction_plan "$root" "$child" "$approved_group" "$criterion" || status=$?
    if [ "$status" -eq 3 ]; then
        _patch_domains_prerequisite "pam:${PAM_TRANSACTION_PREREQUISITE_RESULT:-unknown}"
        return 3
    fi
    [ "$status" -eq 0 ] || return "$status"
    pam_transaction_write_plan_tsv "$child/plan.tsv"
}

_patch_domains_plan_account() {
    local root="$1" child="$2" criterion="$3" input_value="$4"
    local index=0

    _patch_domains_load_input "$input_value" "$criterion" || return $?
    patch_account_evidence_reset
    patch_account_decision_reset
    while [ "$index" -lt "${#PATCH_DOMAIN_INPUT_RECORD_TYPES[@]}" ]; do
        case "${PATCH_DOMAIN_INPUT_RECORD_TYPES[$index]}" in
            evidence)
                patch_account_evidence_add "${PATCH_DOMAIN_INPUT_VALUE_ONES[$index]}" \
                    "${PATCH_DOMAIN_INPUT_VALUE_TWOS[$index]}" "${PATCH_DOMAIN_INPUT_VALUE_THREES[$index]}" || return 2
                ;;
            decision)
                patch_account_decision_add "$criterion" "${PATCH_DOMAIN_INPUT_VALUE_ONES[$index]}" \
                    "${PATCH_DOMAIN_INPUT_VALUE_TWOS[$index]}" "${PATCH_DOMAIN_INPUT_VALUE_THREES[$index]}" \
                    "${PATCH_DOMAIN_INPUT_APPROVALS[$index]}" || return 2
                ;;
            *) return 2 ;;
        esac
        index=$((index + 1))
    done
    patch_account_plan "$root" "$child" "$criterion" || return $?
    /bin/cp "$child/account/plan.tsv" "$child/plan.tsv" && /bin/chmod 0600 "$child/plan.tsv"
}

_patch_domains_plan_filesystem() {
    local root="$1" child="$2" criterion="$3" input_value="$4"
    local one="" two="" three="" four="" five="" six="" seven="" approval=""
    local inventory=""
    local status=0

    _patch_domains_load_input "$input_value" "$criterion" || return $?
    _patch_domains_register_input_callbacks filesystem || return $?
    _patch_domains_single_record_into inventory one two three four five six seven approval || return 2
    inventory="$one"
    _patch_domains_reference_file "$inventory" || return $?
    patch_filesystem_plan "$root" "$child" "$inventory" || status=$?
    if [ "$status" -eq 3 ]; then
        _patch_domains_prerequisite "filesystem:${PATCH_FILESYSTEM_PREREQUISITE:-unknown}"
        return 3
    fi
    [ "$status" -eq 0 ] || return "$status"
    patch_filesystem_write_plan_tsv "$child/plan.tsv"
}

_patch_domains_plan_inventory() {
    local root="$1" child="$2" criterion="$3" input_value="$4"
    local one="" two="" three="" four="" five="" six="" seven="" approval=""
    local inventory="" evidence=""
    local status=0

    _patch_domains_load_input "$input_value" "$criterion" || return $?
    _patch_domains_register_input_callbacks inventory || return $?
    _patch_domains_single_record_into inventory one two three four five six seven approval || return 2
    inventory="$one"
    _patch_domains_single_record_into evidence one two three four five six seven approval || return 2
    evidence="$one"
    _patch_domains_reference_file "$inventory" || return $?
    _patch_domains_reference_file "$evidence" || return $?
    patch_inventory_plan "$root" "$child" "$inventory" "$evidence" || status=$?
    if [ "$status" -eq 3 ]; then
        _patch_domains_prerequisite "inventory:${PATCH_INVENTORY_PREREQUISITE:-unknown}"
        return 3
    fi
    [ "$status" -eq 0 ] || return "$status"
    printf '%s\n%s\t%s\n' "$PATCH_ORCHESTRATOR_DOMAIN_PLAN_HEADER" "$criterion" "$child" > "$child/plan.tsv"
    /bin/chmod 0600 "$child/plan.tsv"
}

_patch_domains_plan_service() {
    local root="$1" child="$2" criterion="$3" input_value="$4"
    local one="" two="" three="" four="" five="" six="" seven="" approval=""
    local decision=allow-disable

    patch_service_intent_reset
    if [[ "$input_value" == /* ]]; then
        _patch_domains_load_input "$input_value" "$criterion" || return $?
        _patch_domains_single_record_into intent one two three four five six seven approval || return 2
        decision="$one"
    else
        approval="$input_value"
    fi
    patch_service_intent_add "$criterion" "$decision" "$approval" || return $?
    patch_service_plan "$root" "$child" "$criterion" || return $?
    patch_service_write_plan_tsv "$child/plan.tsv"
}

_patch_domains_plan_system() {
    local root="$1" child="$2" criterion="$3" input_value="$4"
    local one="" two="" three="" four="" five="" six="" seven="" approval=""
    local status=0

    _patch_domains_load_input "$input_value" "$criterion" || return $?
    _patch_domains_register_input_callbacks system || return $?
    case "$criterion" in
        U-65)
            _patch_domains_single_record_into time-source one two three four five six seven approval || return 2
            patch_system_u65_plan "$root" "$child" "$one" "$two" "$three" "$approval" || status=$?
            ;;
        U-66)
            _patch_domains_single_record_into logging-route one two three four five six seven approval || return 2
            patch_system_u66_plan "$root" "$child" "$one" "$two" "$three" "$approval" || status=$?
            ;;
        *) return 1 ;;
    esac
    if [ "$status" -eq 3 ]; then
        _patch_domains_prerequisite "system:${PATCH_SYSTEM_ERROR_DETAIL:-unknown}"
        return 3
    fi
    [ "$status" -eq 0 ] || return "$status"
    patch_system_write_plan_tsv "$child/plan.tsv"
}

_patch_domains_plan_package() {
    local root="$1" child="$2" criterion="$3" input_value="$4"
    local one="" two="" three="" four="" five="" six="" seven="" approval=""
    local status=0

    [ "$criterion" = U-64 ] || return 1
    _patch_domains_load_input "$input_value" "$criterion" || return $?
    _patch_domains_register_input_callbacks package || return $?
    _patch_domains_single_record_into package-evidence one two three four five six seven approval || return 2
    patch_system_u64_plan "$root" "$child" "$one" "$two" "$three" "$four" "$five" \
        "$six" "$seven" || status=$?
    [ "$status" -eq 0 ] || return "$status"
    patch_system_write_plan_tsv "$child/plan.tsv" || return 2
    _patch_domains_prerequisite "U-64:package_update_from_verified_simulation"
    return 3
}

_patch_domains_plan_network() {
    local root="$1" child="$2" criterion="$3" input_value="$4"
    local index=0
    local status=0

    _patch_domains_load_input "$input_value" "$criterion" || return $?
    patch_network_service_intent_reset
    patch_network_service_input_reset
    _patch_domains_register_input_callbacks network-service || return $?
    while [ "$index" -lt "${#PATCH_DOMAIN_INPUT_RECORD_TYPES[@]}" ]; do
        case "${PATCH_DOMAIN_INPUT_RECORD_TYPES[$index]}" in
            callback) ;;
            intent)
                patch_network_service_intent_add "$criterion" "${PATCH_DOMAIN_INPUT_VALUE_ONES[$index]}" \
                    "${PATCH_DOMAIN_INPUT_VALUE_TWOS[$index]}" "${PATCH_DOMAIN_INPUT_APPROVALS[$index]}" || return 2
                ;;
            config)
                patch_network_service_config_set "${PATCH_DOMAIN_INPUT_VALUE_ONES[$index]}" \
                    "${PATCH_DOMAIN_INPUT_VALUE_TWOS[$index]}" "${PATCH_DOMAIN_INPUT_APPROVALS[$index]}" || return 2
                ;;
            command)
                patch_network_service_mail_command_set "${PATCH_DOMAIN_INPUT_VALUE_ONES[$index]}" \
                    "${PATCH_DOMAIN_INPUT_VALUE_TWOS[$index]}" "${PATCH_DOMAIN_INPUT_APPROVALS[$index]}" || return 2
                ;;
            nfs-export)
                patch_network_service_nfs_export_add "${PATCH_DOMAIN_INPUT_VALUE_ONES[$index]}" \
                    "${PATCH_DOMAIN_INPUT_VALUE_TWOS[$index]}" "${PATCH_DOMAIN_INPUT_VALUE_THREES[$index]}" \
                    "${PATCH_DOMAIN_INPUT_APPROVALS[$index]}" || return 2
                ;;
            rpc-allow)
                patch_network_service_rpc_allow_add "${PATCH_DOMAIN_INPUT_VALUE_ONES[$index]}" \
                    "${PATCH_DOMAIN_INPUT_VALUE_TWOS[$index]}" "${PATCH_DOMAIN_INPUT_APPROVALS[$index]}" || return 2
                ;;
            relay-client)
                patch_network_service_mail_relay_client_add "${PATCH_DOMAIN_INPUT_VALUE_ONES[$index]}" \
                    "${PATCH_DOMAIN_INPUT_APPROVALS[$index]}" || return 2
                ;;
            tsig-reference)
                patch_network_service_bind_tsig_add "${PATCH_DOMAIN_INPUT_VALUE_ONES[$index]}" \
                    "${PATCH_DOMAIN_INPUT_VALUE_TWOS[$index]}" "${PATCH_DOMAIN_INPUT_APPROVALS[$index]}" || return 2
                ;;
            transfer-peer)
                patch_network_service_bind_transfer_peer_add "${PATCH_DOMAIN_INPUT_VALUE_ONES[$index]}" \
                    "${PATCH_DOMAIN_INPUT_VALUE_TWOS[$index]}" "${PATCH_DOMAIN_INPUT_APPROVALS[$index]}" || return 2
                ;;
            update-key)
                patch_network_service_bind_update_key_add "${PATCH_DOMAIN_INPUT_VALUE_ONES[$index]}" \
                    "${PATCH_DOMAIN_INPUT_APPROVALS[$index]}" || return 2
                ;;
            advisory)
                patch_network_service_advisory_set "$criterion" "${PATCH_DOMAIN_INPUT_VALUE_ONES[$index]}" \
                    "${PATCH_DOMAIN_INPUT_VALUE_TWOS[$index]}" "${PATCH_DOMAIN_INPUT_VALUE_THREES[$index]}" \
                    "${PATCH_DOMAIN_INPUT_VALUE_FOURS[$index]}" "${PATCH_DOMAIN_INPUT_APPROVALS[$index]}" || return 2
                ;;
            *) return 2 ;;
        esac
        index=$((index + 1))
    done
    patch_network_service_plan "$root" "$child" "$criterion" || status=$?
    if [ "$status" -eq 3 ]; then
        _patch_domains_prerequisite "network-service:${PATCH_NETWORK_SERVICE_ERROR_DETAIL:-external_action_required}"
        return 3
    fi
    [ "$status" -eq 0 ] || return "$status"
    patch_network_service_write_plan_tsv "$child/plan.tsv"
}

_patch_domains_plan_edge() {
    local root="$1" child="$2" criterion="$3" input_value="$4"
    local one="" two="" three="" four="" five="" six="" seven="" approval=""

    _patch_domains_load_input "$input_value" "$criterion" || return $?
    _patch_domains_register_input_callbacks edge-service || return $?
    case "$criterion" in
        U-01)
            _patch_domains_single_record_into remote-root one two three four five six seven approval || return 2
            patch_edge_u01_plan "$root" "$child" "$one" "$approval"
            ;;
        U-28)
            _patch_domains_single_record_into firewall one two three four five six seven approval || return 2
            patch_edge_u28_plan "$root" "$child" "$one" "$two" "$three" "$four" "$approval"
            ;;
        U-53)
            _patch_domains_single_record_into ftp-banner one two three four five six seven approval || return 2
            patch_edge_u53_plan "$root" "$child" "$one" "$two" "$approval"
            ;;
        U-56)
            _patch_domains_single_record_into ftp-firewall one two three four five six seven approval || return 2
            patch_edge_u56_plan "$root" "$child" "$one" "$two" "$three" "$four" "$five" "$approval"
            ;;
        U-57)
            _patch_domains_single_record_into denied-users one two three four five six seven approval || return 2
            patch_edge_u57_plan "$root" "$child" "$one" "$two" "$approval"
            ;;
        U-59|U-60)
            _patch_domains_single_record_into snmp-policy one two three four five six seven approval || return 2
            if [ "$criterion" = U-59 ]; then
                patch_edge_u59_plan "$root" "$child" "$one" "$two" "$three" "$approval"
            else
                patch_edge_u60_plan "$root" "$child" "$one" "$two" "$three" "$approval"
            fi
            ;;
        U-61)
            _patch_domains_single_record_into snmp-access one two three four five six seven approval || return 2
            patch_edge_u61_plan "$root" "$child" "$one" "$two" "$three" "$four" "$five" "$six" "$seven" "$approval"
            ;;
        *) return 1 ;;
    esac
}

_patch_domains_plan_code() {
    local domain="$1" root="$2" child="$3" criterion="$4" input_value="$5"

    case "$domain" in
        metadata) _patch_domains_plan_metadata "$root" "$child" "$criterion" ;;
        configuration) _patch_domains_plan_configuration "$root" "$child" "$criterion" ;;
        pam) _patch_domains_plan_pam "$root" "$child" "$criterion" "$input_value" ;;
        account) _patch_domains_plan_account "$root" "$child" "$criterion" "$input_value" ;;
        filesystem) _patch_domains_plan_filesystem "$root" "$child" "$criterion" "$input_value" ;;
        inventory) _patch_domains_plan_inventory "$root" "$child" "$criterion" "$input_value" ;;
        service) _patch_domains_plan_service "$root" "$child" "$criterion" "$input_value" ;;
        system) _patch_domains_plan_system "$root" "$child" "$criterion" "$input_value" ;;
        package) _patch_domains_plan_package "$root" "$child" "$criterion" "$input_value" ;;
        network-service) _patch_domains_plan_network "$root" "$child" "$criterion" "$input_value" ;;
        edge-service) _patch_domains_plan_edge "$root" "$child" "$criterion" "$input_value" ;;
        *) return 1 ;;
    esac
}

_patch_domains_read_request() {
    local request_path="$1"
    local header=""
    local code="" adapter="" postcondition="" implementation="" input_type="" input_value=""
    local scan_status="" eligible="" rule="" extra=""

    PATCH_DOMAIN_REQUEST_CODES=()
    PATCH_DOMAIN_REQUEST_ADAPTERS=()
    PATCH_DOMAIN_REQUEST_INPUT_TYPES=()
    PATCH_DOMAIN_REQUEST_INPUT_VALUES=()
    _patch_orchestrator_file_safe "$request_path" || return 2
    IFS= read -r header < "$request_path" || return 2
    [ "$header" = "$PATCH_ORCHESTRATOR_REQUEST_HEADER" ] || return 2
    while IFS=$'\t' read -r code adapter postcondition implementation input_type input_value \
        scan_status eligible rule extra; do
        [ -n "$code" ] || continue
        [ -z "$extra" ] || return 2
        case "$code" in U-[0-9][0-9]) ;; *) return 2 ;; esac
        case "$scan_status" in VULNERABLE|MANUAL) ;; *) return 2 ;; esac
        case "$implementation" in fixed|conditional) ;; *) return 2 ;; esac
        case "$postcondition" in GOOD|NOT_APPLICABLE) ;; *) return 2 ;; esac
        PATCH_DOMAIN_REQUEST_CODES+=("$code")
        PATCH_DOMAIN_REQUEST_ADAPTERS+=("$adapter")
        PATCH_DOMAIN_REQUEST_INPUT_TYPES+=("$input_type")
        PATCH_DOMAIN_REQUEST_INPUT_VALUES+=("$input_value")
    done < <(sed -n '2,$p' "$request_path")
    [ "${#PATCH_DOMAIN_REQUEST_CODES[@]}" -gt 0 ]
}

_patch_domains_common_input_path_into() {
    local destination_name="$1"
    local path=""
    local input_value=""

    for input_value in "${PATCH_DOMAIN_REQUEST_INPUT_VALUES[@]}"; do
        [[ "$input_value" == /* ]] || return 2
        if [ -z "$path" ]; then path="$input_value"; else [ "$path" = "$input_value" ] || return 2; fi
    done
    printf -v "$destination_name" '%s' "$path"
}

_patch_domains_selected_criteria_match_requests() {
    local domain="$1"
    local criterion=""
    local selected_count=0
    local -A requested=()

    for criterion in "${PATCH_DOMAIN_REQUEST_CODES[@]}"; do
        [ -z "${requested[$criterion]+present}" ] || return 2
        requested["$criterion"]=1
    done
    case "$domain" in
        filesystem)
            selected_count="${#PATCH_FILESYSTEM_SELECTED_CRITERIA[@]}"
            [ "$selected_count" -eq "${#requested[@]}" ] || return 2
            for criterion in "${!PATCH_FILESYSTEM_SELECTED_CRITERIA[@]}"; do
                [ -n "${requested[$criterion]+present}" ] || return 2
            done
            ;;
        inventory)
            selected_count="${#PATCH_INVENTORY_SELECTED_CRITERIA[@]}"
            [ "$selected_count" -eq "${#requested[@]}" ] || return 2
            for criterion in "${!PATCH_INVENTORY_SELECTED_CRITERIA[@]}"; do
                [ -n "${requested[$criterion]+present}" ] || return 2
            done
            ;;
        *) return 1 ;;
    esac
}

_patch_domains_plan_grouped() {
    local domain="$1" root="$2" domain_directory="$3"
    local child="" common_input="" criterion="" input_value=""
    local one="" two="" three="" four="" five="" six="" seven="" approval=""
    local index=0 record_index=0 status=0 evidence_loaded=0
    local inventory="" evidence="" approved_group=ignored decision=""

    _patch_domains_prepare_child "$domain_directory" all child || return 2
    case "$domain" in
        metadata)
            patch_engine_reset
            patch_engine_plan "$root" "${PATCH_DOMAIN_REQUEST_CODES[@]}" || return $?
            patch_engine_write_plan_tsv "$child/plan.tsv" || return 2
            patch_engine_write_transaction_tsv "$child/metadata.tsv" || return 2
            ;;
        configuration)
            patch_configuration_reset
            patch_configuration_plan "$root" "$child" "${PATCH_DOMAIN_REQUEST_CODES[@]}" || return $?
            patch_configuration_write_plan_tsv "$child/plan.tsv" || return 2
            ;;
        pam)
            for input_value in "${PATCH_DOMAIN_REQUEST_INPUT_VALUES[@]}"; do
                criterion="${PATCH_DOMAIN_REQUEST_CODES[$index]}"
                if [[ "$input_value" == /* ]]; then
                    _patch_domains_load_input "$input_value" "$criterion" || return $?
                    case "$criterion" in
                        U-02)
                            _patch_domains_single_record_into password-policy one two three four five six seven approval || return 2
                            [ "$one" = kisa-cce-2026 ] && _patch_domains_safe_token "$approval" || return 2
                            ;;
                        U-03)
                            _patch_domains_single_record_into lockout-policy one two three four five six seven approval || return 2
                            [ "$one" = kisa-cce-2026 ] && _patch_domains_safe_token "$approval" || return 2
                            ;;
                        U-06)
                            _patch_domains_single_record_into approved-group one two three four five six seven approval || return 2
                            approved_group="$one"
                            ;;
                        *) return 1 ;;
                    esac
                else
                    if [ "$criterion" = U-06 ]; then
                        approved_group="$input_value"
                    else
                        _patch_domains_safe_token "$input_value" || return 2
                    fi
                fi
                index=$((index + 1))
            done
            pam_transaction_plan "$root" "$child" "$approved_group" \
                "${PATCH_DOMAIN_REQUEST_CODES[@]}" || status=$?
            if [ "$status" -eq 3 ]; then _patch_domains_prerequisite "pam:${PAM_TRANSACTION_PREREQUISITE_RESULT:-unknown}"; return 3; fi
            [ "$status" -eq 0 ] || return "$status"
            pam_transaction_write_plan_tsv "$child/plan.tsv" || return 2
            ;;
        account)
            _patch_domains_common_input_path_into common_input || return 2
            patch_account_evidence_reset
            patch_account_decision_reset
            for criterion in "${PATCH_DOMAIN_REQUEST_CODES[@]}"; do
                _patch_domains_load_input "$common_input" "$criterion" || return $?
                record_index=0
                while [ "$record_index" -lt "${#PATCH_DOMAIN_INPUT_RECORD_TYPES[@]}" ]; do
                    case "${PATCH_DOMAIN_INPUT_RECORD_TYPES[$record_index]}" in
                        evidence)
                            if [ "$evidence_loaded" -eq 0 ]; then
                                patch_account_evidence_add "${PATCH_DOMAIN_INPUT_VALUE_ONES[$record_index]}" \
                                    "${PATCH_DOMAIN_INPUT_VALUE_TWOS[$record_index]}" \
                                    "${PATCH_DOMAIN_INPUT_VALUE_THREES[$record_index]}" || return 2
                            fi
                            ;;
                        decision)
                            patch_account_decision_add "$criterion" "${PATCH_DOMAIN_INPUT_VALUE_ONES[$record_index]}" \
                                "${PATCH_DOMAIN_INPUT_VALUE_TWOS[$record_index]}" \
                                "${PATCH_DOMAIN_INPUT_VALUE_THREES[$record_index]}" \
                                "${PATCH_DOMAIN_INPUT_APPROVALS[$record_index]}" || return 2
                            ;;
                        *) return 2 ;;
                    esac
                    record_index=$((record_index + 1))
                done
                evidence_loaded=1
            done
            patch_account_plan "$root" "$child" "${PATCH_DOMAIN_REQUEST_CODES[@]}" || return $?
            /bin/cp "$child/account/plan.tsv" "$child/plan.tsv" && /bin/chmod 0600 "$child/plan.tsv"
            ;;
        filesystem)
            _patch_domains_common_input_path_into common_input || return 2
            _patch_domains_load_input "$common_input" "${PATCH_DOMAIN_REQUEST_CODES[0]}" || return $?
            _patch_domains_register_input_callbacks filesystem || return $?
            _patch_domains_single_record_into inventory one two three four five six seven approval || return 2
            inventory="$one"; _patch_domains_reference_file "$inventory" || return $?
            patch_filesystem_plan "$root" "$child" "$inventory" || status=$?
            if [ "$status" -eq 3 ]; then _patch_domains_prerequisite "filesystem:${PATCH_FILESYSTEM_PREREQUISITE:-unknown}"; return 3; fi
            [ "$status" -eq 0 ] || return "$status"
            _patch_domains_selected_criteria_match_requests filesystem || {
                _patch_domains_error "filesystem inventory criterion scope does not match the orchestrator request"
                return 2
            }
            for criterion in "${PATCH_DOMAIN_REQUEST_CODES[@]}"; do
                patch_filesystem_state_into "$criterion" decision || return 2
            done
            patch_filesystem_write_plan_tsv "$child/plan.tsv" || return 2
            ;;
        inventory)
            _patch_domains_common_input_path_into common_input || return 2
            _patch_domains_load_input "$common_input" "${PATCH_DOMAIN_REQUEST_CODES[0]}" || return $?
            _patch_domains_register_input_callbacks inventory || return $?
            _patch_domains_single_record_into inventory one two three four five six seven approval || return 2
            inventory="$one"
            _patch_domains_single_record_into evidence one two three four five six seven approval || return 2
            evidence="$one"
            _patch_domains_reference_file "$inventory" || return $?
            _patch_domains_reference_file "$evidence" || return $?
            patch_inventory_plan "$root" "$child" "$inventory" "$evidence" || status=$?
            if [ "$status" -eq 3 ]; then _patch_domains_prerequisite "inventory:${PATCH_INVENTORY_PREREQUISITE:-unknown}"; return 3; fi
            [ "$status" -eq 0 ] || return "$status"
            _patch_domains_selected_criteria_match_requests inventory || {
                _patch_domains_error "decision inventory criterion scope does not match the orchestrator request"
                return 2
            }
            for criterion in "${PATCH_DOMAIN_REQUEST_CODES[@]}"; do
                patch_inventory_state_into "$criterion" decision || return 2
            done
            printf 'criterion\ttransaction\n' > "$child/plan.tsv"
            for criterion in "${PATCH_DOMAIN_REQUEST_CODES[@]}"; do printf '%s\t%s\n' "$criterion" "$child" >> "$child/plan.tsv"; done
            /bin/chmod 0600 "$child/plan.tsv"
            ;;
        service)
            patch_service_intent_reset
            index=0
            for criterion in "${PATCH_DOMAIN_REQUEST_CODES[@]}"; do
                input_value="${PATCH_DOMAIN_REQUEST_INPUT_VALUES[$index]}"
                decision=allow-disable
                if [[ "$input_value" == /* ]]; then
                    _patch_domains_load_input "$input_value" "$criterion" || return $?
                    _patch_domains_single_record_into intent one two three four five six seven approval || return 2
                    decision="$one"
                else approval="$input_value"
                fi
                patch_service_intent_add "$criterion" "$decision" "$approval" || return $?
                index=$((index + 1))
            done
            patch_service_plan "$root" "$child" "${PATCH_DOMAIN_REQUEST_CODES[@]}" || return $?
            patch_service_write_plan_tsv "$child/plan.tsv" || return 2
            ;;
        *) return 1 ;;
    esac
    PATCH_DOMAIN_GROUP_CHILD="$child"
}

_patch_domains_module_state_into() {
    local domain="$1" criterion="$2" destination_name="$3"

    case "$domain" in
        metadata) patch_engine_state_into "$criterion" "$destination_name" ;;
        configuration) patch_configuration_state_into "$criterion" "$destination_name" ;;
        pam) pam_transaction_state_into "$criterion" "$destination_name" ;;
        account) patch_account_state_into "$criterion" "$destination_name" ;;
        filesystem) patch_filesystem_state_into "$criterion" "$destination_name" ;;
        inventory) patch_inventory_state_into "$criterion" "$destination_name" ;;
        service) patch_service_state_into "$criterion" "$destination_name" ;;
        system) patch_system_state_into "$destination_name" ;;
        package) patch_system_state_into "$destination_name" ;;
        network-service) patch_network_service_state_into "$criterion" "$destination_name" ;;
        edge-service) patch_edge_state_into "$destination_name" ;;
        *) return 1 ;;
    esac
}

_patch_domains_artifact_digest_into() {
    local domain="$1"
    local child="$2"
    local destination_name="$3"
    local plan_path=""
    local plan_digest=""
    local payload_digest=""
    local result=""

    case "$domain" in
        package|system) plan_path="$child/system/plan.tsv" ;;
        network-service) plan_path="$child/network-service/plan.tsv" ;;
        edge-service) plan_path="$child/edge-service/plan.tsv" ;;
        *) plan_path="$child/plan.tsv" ;;
    esac
    _patch_orchestrator_file_safe "$plan_path" || return 2
    _patch_orchestrator_sha256_into "$plan_path" plan_digest || return 2
    result="$plan_digest"
    if [ "$domain" = package ]; then
        _patch_orchestrator_file_safe "$child/system/simulation.txt" || return 2
        _patch_orchestrator_sha256_into "$child/system/simulation.txt" payload_digest || return 2
        result="$result:$payload_digest"
    fi
    printf -v "$destination_name" '%s' "$result"
}

_patch_domains_write_prerequisite_plan() {
    local domain_directory="$1"
    local index=0
    local criterion=""
    local plan_path="$domain_directory/plan.tsv"

    printf '%s\n' "$PATCH_ORCHESTRATOR_DOMAIN_PLAN_HEADER" > "$plan_path" || return 2
    while [ "$index" -lt "${#PATCH_DOMAIN_REQUEST_CODES[@]}" ]; do
        criterion="${PATCH_DOMAIN_REQUEST_CODES[$index]}"
        printf '%s\t%s\t%s\t%s\t-\texternal_action_required\t-\t%s\n' "$criterion" \
            "${PATCH_DOMAIN_REQUEST_ADAPTERS[$index]}" "${PATCH_DOMAIN_REQUEST_INPUT_TYPES[$index]}" \
            "${PATCH_DOMAIN_REQUEST_INPUT_VALUES[$index]}" "$PATCH_DOMAIN_CALLBACK_SET_DIGEST" >> "$plan_path" || return 2
        index=$((index + 1))
    done
    /bin/chmod 0600 "$plan_path" || return 2
    printf 'criterion\n' > "$domain_directory/applied.tsv" || return 2
    /bin/chmod 0600 "$domain_directory/applied.tsv"
}

patch_orchestrator_builtin_domain_plan() {
    local root="$1" domain_directory="$2" request_path="$3"
    local domain="${domain_directory##*/}"
    local index=0 child="" criterion="" state="" status=0 external_action=0 artifact_digest=""
    local plan_path="$domain_directory/plan.tsv"

    PATCH_ORCHESTRATOR_DOMAINS_ERROR_DETAIL=""
    PATCH_ORCHESTRATOR_DOMAINS_PREREQUISITE=""
    [ ! -e "$domain_directory/callbacks" ] && [ ! -L "$domain_directory/callbacks" ] || return 2
    /bin/mkdir -m 0700 "$domain_directory/callbacks" || return 2
    PATCH_DOMAIN_CALLBACK_SNAPSHOT_DIRECTORY="$domain_directory/callbacks"
    PATCH_DOMAIN_CALLBACK_SNAPSHOT_MODE=capture
    _patch_domains_read_request "$request_path" || return 2
    _patch_domains_prepare_callback_snapshot "$domain" "$domain_directory" || return $?
    case "$domain" in account|configuration|filesystem|inventory|metadata|pam|service)
        _patch_domains_plan_grouped "$domain" "$root" "$domain_directory" || status=$?
        if [ "$status" -eq 3 ]; then
            _patch_domains_write_prerequisite_plan "$domain_directory" || return 2
            return 3
        elif [ "$status" -ne 0 ]; then return "$status"
        fi
        child="$PATCH_DOMAIN_GROUP_CHILD"
        ;;
    esac
    printf '%s\n' "$PATCH_ORCHESTRATOR_DOMAIN_PLAN_HEADER" > "$plan_path" || return 2
    while [ "$index" -lt "${#PATCH_DOMAIN_REQUEST_CODES[@]}" ]; do
        criterion="${PATCH_DOMAIN_REQUEST_CODES[$index]}"
        if [ -z "$child" ]; then
            _patch_domains_prepare_child "$domain_directory" "$criterion" child || return 2
            _patch_domains_plan_code "$domain" "$root" "$child" "$criterion" \
                "${PATCH_DOMAIN_REQUEST_INPUT_VALUES[$index]}" || status=$?
            if [ "$status" -eq 3 ]; then external_action=1; status=0
            elif [ "$status" -ne 0 ]; then return "$status"
            fi
        fi
        _patch_domains_module_state_into "$domain" "$criterion" state || state=planned
        if [ "$state" = external_action_required ]; then
            _patch_domains_prerequisite "$criterion:external_action_required"
            external_action=1
        fi
        artifact_digest="-"
        if [ "$external_action" -eq 0 ] || [ "$domain" = package ]; then
            _patch_domains_artifact_digest_into "$domain" "$child" artifact_digest || return 2
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$criterion" \
            "${PATCH_DOMAIN_REQUEST_ADAPTERS[$index]}" "${PATCH_DOMAIN_REQUEST_INPUT_TYPES[$index]}" \
            "${PATCH_DOMAIN_REQUEST_INPUT_VALUES[$index]}" "${child#"$domain_directory"/}" "$state" \
            "$artifact_digest" "$PATCH_DOMAIN_CALLBACK_SET_DIGEST" >> "$plan_path" || return 2
        if [ "$domain" = package ] || [ "$domain" = system ] || [ "$domain" = network-service ] || [ "$domain" = edge-service ]; then child=""; fi
        index=$((index + 1))
    done
    /bin/chmod 0600 "$plan_path" || return 2
    printf 'criterion\n' > "$domain_directory/applied.tsv" || return 2
    /bin/chmod 0600 "$domain_directory/applied.tsv" || return 2
    [ "$external_action" -eq 0 ] || return 3
}

_patch_domains_register_callbacks_for_code() {
    local domain="$1" criterion="$2" input_value="$3"
    local callback_path=""
    local role=""
    local old_nullglob=0
    local status=0

    if [ -n "$PATCH_DOMAIN_CALLBACK_SNAPSHOT_DIRECTORY" ] &&
        [ -d "$PATCH_DOMAIN_CALLBACK_SNAPSHOT_DIRECTORY" ]; then
        shopt -q nullglob && old_nullglob=1
        shopt -s nullglob
        for callback_path in "$PATCH_DOMAIN_CALLBACK_SNAPSHOT_DIRECTORY"/*; do
            role="${callback_path##*/}"
            _patch_domains_register_callback_row "$domain" "$role" "$callback_path" || {
                status=$?
                break
            }
        done
        [ "$old_nullglob" -eq 1 ] || shopt -u nullglob
        return "$status"
    fi
    [[ "$input_value" == /* ]] || return 0
    _patch_domains_load_input "$input_value" "$criterion" || return $?
    _patch_domains_register_input_callbacks "$domain"
}

_patch_domains_load_module() {
    local domain="$1" root="$2" child="$3" load_mode="${4:-applied}"

    case "$domain" in
        metadata) patch_engine_load_transaction "$root" "$child/metadata.tsv" ;;
        configuration) patch_configuration_load_transaction "$root" "$child" "$load_mode" ;;
        pam) pam_transaction_load_transaction "$root" "$child" "$load_mode" ;;
        account) patch_account_load_transaction "$root" "$child" ;;
        filesystem) patch_filesystem_load_transaction "$root" "$child" "$load_mode" ;;
        inventory) patch_inventory_load_transaction "$root" "$child" "$load_mode" ;;
        service) patch_service_load_transaction "$root" "$child" ;;
        system|package) patch_system_load_transaction "$root" "$child" ;;
        network-service) patch_network_service_load_transaction "$root" "$child" ;;
        edge-service) patch_edge_load_transaction "$root" "$child" ;;
        *) return 1 ;;
    esac
}

_patch_domains_apply_module() {
    case "$1" in
        metadata) patch_engine_apply ;;
        configuration) patch_configuration_apply ;;
        pam) pam_transaction_apply ;;
        account) patch_account_apply ;;
        filesystem) patch_filesystem_apply ;;
        inventory) patch_inventory_apply ;;
        service) patch_service_apply ;;
        system|package) patch_system_apply ;;
        network-service) patch_network_service_apply ;;
        edge-service) patch_edge_apply ;;
        *) return 1 ;;
    esac
}

_patch_domains_verify_module() {
    local domain="$1"

    case "$domain" in
        metadata) patch_engine_verify ;;
        configuration) patch_configuration_verify ;;
        pam) pam_transaction_verify ;;
        account) patch_account_verify ;;
        filesystem) patch_filesystem_verify ;;
        inventory) patch_inventory_verify ;;
        service) patch_service_verify ;;
        system|package) patch_system_verify ;;
        network-service) patch_network_service_verify ;;
        edge-service)
            case "$PATCH_EDGE_STATE" in verified|not_applicable) return 0 ;; *) return 2 ;; esac
            ;;
        *) return 1 ;;
    esac
}

_patch_domains_rollback_module() {
    local domain="$1" root="$2" child="$3" mode="$4"

    case "$domain" in
        metadata) patch_engine_rollback_transaction "$root" "$child/metadata.tsv" "$mode" ;;
        configuration) patch_configuration_rollback_transaction "$root" "$child" "$mode" ;;
        pam) pam_transaction_rollback_transaction "$root" "$child" "$mode" ;;
        account) patch_account_rollback_transaction "$root" "$child" "$mode" ;;
        filesystem) patch_filesystem_rollback_transaction "$root" "$child" "$mode" ;;
        inventory) patch_inventory_rollback_transaction "$root" "$child" "$mode" ;;
        service) patch_service_rollback_transaction "$root" "$child" "$mode" ;;
        system|package) patch_system_rollback_transaction "$root" "$child" "$mode" ;;
        network-service) patch_network_service_rollback_transaction "$root" "$child" "$mode" ;;
        edge-service) patch_edge_rollback_transaction "$root" "$child" "$mode" ;;
        *) return 1 ;;
    esac
}

_patch_domains_callback_set_current() {
    local domain_directory="$1"
    local expected_digest="$2"
    local manifest="$domain_directory/callbacks.tsv"
    local actual_digest=""
    local header=""
    local role=""
    local recorded_digest=""
    local extra=""
    local callback_path=""
    local callback_digest=""
    local row_count=0
    local file_count=0
    local old_nullglob=0

    _patch_orchestrator_file_safe "$manifest" || return 2
    _patch_orchestrator_sha256_into "$manifest" actual_digest || return 2
    [ "$actual_digest" = "$expected_digest" ] || return 2
    IFS= read -r header < "$manifest" || return 2
    [ "$header" = $'role\tsha256' ] || return 2
    while IFS=$'\t' read -r role recorded_digest extra; do
        [ -n "$role" ] || continue
        [ -z "$extra" ] || return 2
        case "$role" in ''|*[!a-z0-9_-]*) return 2 ;; esac
        [ "${#recorded_digest}" -eq 64 ] || return 2
        case "$recorded_digest" in *[!0-9a-f]*) return 2 ;; esac
        callback_path="$domain_directory/callbacks/$role"
        _patch_domains_safe_callback "$callback_path" || return 2
        _patch_orchestrator_sha256_into "$callback_path" callback_digest || return 2
        [ "$callback_digest" = "$recorded_digest" ] || return 2
        row_count=$((row_count + 1))
    done < <(sed -n '2,$p' "$manifest")
    shopt -q nullglob && old_nullglob=1
    shopt -s nullglob
    for callback_path in "$domain_directory/callbacks"/*; do file_count=$((file_count + 1)); done
    [ "$old_nullglob" -eq 1 ] || shopt -u nullglob
    [ "$row_count" -eq "$file_count" ]
}

patch_orchestrator_builtin_domain_artifacts_current() {
    local domain_directory="$1"
    local domain="${domain_directory##*/}"
    local header="" criterion="" adapter="" input_type="" input_value="" transaction="" state=""
    local artifact_digest="" callback_set_digest="" extra="" current_digest=""
    local canonical_callback_digest=""
    local rows=0

    IFS= read -r header < "$domain_directory/plan.tsv" || return 2
    [ "$header" = "$PATCH_ORCHESTRATOR_DOMAIN_PLAN_HEADER" ] || return 2
    while IFS=$'\t' read -r criterion adapter input_type input_value transaction state \
        artifact_digest callback_set_digest extra; do
        [ -n "$criterion" ] || continue
        [ -z "$extra" ] || return 2
        if [ -z "$canonical_callback_digest" ]; then
            canonical_callback_digest="$callback_set_digest"
        else
            [ "$canonical_callback_digest" = "$callback_set_digest" ] || return 2
        fi
        if [ "$transaction" = - ]; then
            [ "$state:$artifact_digest" = external_action_required:- ] || return 2
        else
            case "$transaction" in transactions/U-[0-9][0-9]|transactions/all) ;; *) return 2 ;; esac
            [ -d "$domain_directory/$transaction" ] && [ ! -L "$domain_directory/$transaction" ] || return 2
            if [ "$artifact_digest" != - ]; then
                _patch_domains_artifact_digest_into "$domain" "$domain_directory/$transaction" current_digest || return 2
                [ "$current_digest" = "$artifact_digest" ] || return 2
            fi
        fi
        rows=$((rows + 1))
    done < <(sed -n '2,$p' "$domain_directory/plan.tsv")
    [ "$rows" -gt 0 ] && [ -n "$canonical_callback_digest" ] || return 2
    _patch_domains_callback_set_current "$domain_directory" "$canonical_callback_digest"
}

_patch_domains_plan_rows() {
    local domain_directory="$1"
    local callback_name="$2"
    local header="" criterion="" adapter="" input_type="" input_value="" transaction="" state=""
    local artifact_digest="" callback_set_digest="" extra=""

    IFS= read -r header < "$domain_directory/plan.tsv" || return 2
    [ "$header" = "$PATCH_ORCHESTRATOR_DOMAIN_PLAN_HEADER" ] || return 2
    while IFS=$'\t' read -r criterion adapter input_type input_value transaction state \
        artifact_digest callback_set_digest extra; do
        [ -n "$criterion" ] || continue
        [ -z "$extra" ] || return 2
        "$callback_name" "$criterion" "$adapter" "$input_type" "$input_value" "$transaction" "$state" \
            "$artifact_digest" "$callback_set_digest" || return $?
    done < <(sed -n '2,$p' "$domain_directory/plan.tsv")
}

PATCH_DOMAIN_OPERATION_DOMAIN=""
PATCH_DOMAIN_OPERATION_ROOT=""
PATCH_DOMAIN_OPERATION_DIRECTORY=""
PATCH_DOMAIN_OPERATION_LAST_TRANSACTION=""

_patch_domains_apply_row() {
    local criterion="$1" adapter="$2" input_type="$3" input_value="$4" transaction="$5" state="$6"
    local artifact_digest="$7" callback_set_digest="$8"
    local child="$PATCH_DOMAIN_OPERATION_DIRECTORY/$transaction"

    : "$adapter" "$input_type" "$state" "$artifact_digest" "$callback_set_digest"
    [ "$transaction" != "$PATCH_DOMAIN_OPERATION_LAST_TRANSACTION" ] || return 0
    _patch_domains_register_callbacks_for_code "$PATCH_DOMAIN_OPERATION_DOMAIN" "$criterion" "$input_value" || return $?
    printf '%s\n' "$transaction" >> "$PATCH_DOMAIN_OPERATION_DIRECTORY/applied.tsv" || return 2
    _patch_domains_load_module "$PATCH_DOMAIN_OPERATION_DOMAIN" "$PATCH_DOMAIN_OPERATION_ROOT" "$child" planned || return 2
    _patch_domains_apply_module "$PATCH_DOMAIN_OPERATION_DOMAIN" || return 2
    PATCH_DOMAIN_OPERATION_LAST_TRANSACTION="$transaction"
}

patch_orchestrator_builtin_domain_apply() {
    local root="$1" domain_directory="$2"

    PATCH_DOMAIN_CALLBACK_SNAPSHOT_DIRECTORY="$domain_directory/callbacks"
    PATCH_DOMAIN_CALLBACK_SNAPSHOT_MODE=reuse
    PATCH_DOMAIN_OPERATION_DOMAIN="${domain_directory##*/}"
    PATCH_DOMAIN_OPERATION_ROOT="$root"
    PATCH_DOMAIN_OPERATION_DIRECTORY="$domain_directory"
    PATCH_DOMAIN_OPERATION_LAST_TRANSACTION=""
    _patch_domains_plan_rows "$domain_directory" _patch_domains_apply_row
}

_patch_domains_verify_row() {
    local criterion="$1" adapter="$2" input_type="$3" input_value="$4" transaction="$5" state="$6"
    local artifact_digest="$7" callback_set_digest="$8"
    local child="$PATCH_DOMAIN_OPERATION_DIRECTORY/$transaction"

    : "$adapter" "$input_type" "$state" "$artifact_digest" "$callback_set_digest"
    [ "$transaction" != "$PATCH_DOMAIN_OPERATION_LAST_TRANSACTION" ] || return 0
    _patch_domains_register_callbacks_for_code "$PATCH_DOMAIN_OPERATION_DOMAIN" "$criterion" "$input_value" || return $?
    _patch_domains_load_module "$PATCH_DOMAIN_OPERATION_DOMAIN" "$PATCH_DOMAIN_OPERATION_ROOT" "$child" applied || return 2
    _patch_domains_verify_module "$PATCH_DOMAIN_OPERATION_DOMAIN" || return 2
    PATCH_DOMAIN_OPERATION_LAST_TRANSACTION="$transaction"
}

patch_orchestrator_builtin_domain_verify() {
    local root="$1" domain_directory="$2"

    PATCH_DOMAIN_CALLBACK_SNAPSHOT_DIRECTORY="$domain_directory/callbacks"
    PATCH_DOMAIN_CALLBACK_SNAPSHOT_MODE=reuse
    PATCH_DOMAIN_OPERATION_DOMAIN="${domain_directory##*/}"
    PATCH_DOMAIN_OPERATION_ROOT="$root"
    PATCH_DOMAIN_OPERATION_DIRECTORY="$domain_directory"
    PATCH_DOMAIN_OPERATION_LAST_TRANSACTION=""
    _patch_domains_plan_rows "$domain_directory" _patch_domains_verify_row
}

_patch_domains_input_for_transaction_into() {
    local domain_directory="$1" transaction="$2" criterion_destination="$3" input_destination="$4"
    local header="" row_criterion="" adapter="" input_type="" row_input_value="" row_transaction="" state=""
    local artifact_digest="" callback_set_digest="" extra=""

    IFS= read -r header < "$domain_directory/plan.tsv" || return 2
    [ "$header" = "$PATCH_ORCHESTRATOR_DOMAIN_PLAN_HEADER" ] || return 2
    while IFS=$'\t' read -r row_criterion adapter input_type row_input_value row_transaction state \
        artifact_digest callback_set_digest extra; do
        [ -n "$row_criterion" ] || continue
        [ -z "$extra" ] || return 2
        if [ "$row_transaction" = "$transaction" ]; then
            printf -v "$criterion_destination" '%s' "$row_criterion"
            printf -v "$input_destination" '%s' "$row_input_value"
            return 0
        fi
    done < <(sed -n '2,$p' "$domain_directory/plan.tsv")
    return 1
}

patch_orchestrator_builtin_domain_rollback() {
    local root="$1" domain_directory="$2" mode="$3"
    local domain="${domain_directory##*/}"
    local header="" transaction="" criterion="" input_value=""
    local index=0 failures=0
    local -a applied=()

    case "$mode" in strict|transition) ;; *) return 2 ;; esac
    PATCH_DOMAIN_CALLBACK_SNAPSHOT_DIRECTORY="$domain_directory/callbacks"
    PATCH_DOMAIN_CALLBACK_SNAPSHOT_MODE=reuse
    [ -d "$PATCH_DOMAIN_CALLBACK_SNAPSHOT_DIRECTORY" ] &&
        [ ! -L "$PATCH_DOMAIN_CALLBACK_SNAPSHOT_DIRECTORY" ] || return 2
    IFS= read -r header < "$domain_directory/applied.tsv" || return 2
    [ "$header" = criterion ] || return 2
    while IFS= read -r transaction; do
        [ -n "$transaction" ] || continue
        case "$transaction" in transactions/*) ;; *) return 2 ;; esac
        applied+=("$transaction")
    done < <(sed -n '2,$p' "$domain_directory/applied.tsv")
    index=$(( ${#applied[@]} - 1 ))
    while [ "$index" -ge 0 ]; do
        transaction="${applied[$index]}"
        _patch_domains_input_for_transaction_into "$domain_directory" "$transaction" criterion input_value || failures=$((failures + 1))
        if [ "$failures" -eq 0 ]; then
            _patch_domains_register_callbacks_for_code "$domain" "$criterion" "$input_value" || failures=$((failures + 1))
        fi
        if [ "$failures" -eq 0 ]; then
            _patch_domains_rollback_module "$domain" "$root" "$domain_directory/$transaction" "$mode" || failures=$((failures + 1))
        fi
        index=$((index - 1))
    done
    [ "$failures" -eq 0 ]
}

patch_orchestrator_register_builtin_domains() {
    local domain=""

    for domain in package account configuration filesystem inventory metadata pam service system network-service edge-service; do
        [ -z "${PATCH_ORCHESTRATOR_PLAN_CALLBACKS[$domain]+present}" ] || continue
        patch_orchestrator_register_domain "$domain" patch_orchestrator_builtin_domain_plan \
            patch_orchestrator_builtin_domain_apply patch_orchestrator_builtin_domain_verify \
            patch_orchestrator_builtin_domain_rollback || return 2
    done
}

patch_orchestrator_domains_preflight_profile() {
    local profile_path="$1"
    local header="" profile_id="" max_risk="" code="" adapter="" risk="" resolution="" domain=""
    local postcondition="" implementation="" input_type="" input_value="" validator="" rollback="" extra=""
    local rows=0 status=0 expected_code=""

    PATCH_ORCHESTRATOR_DOMAINS_ERROR_DETAIL=""
    PATCH_ORCHESTRATOR_DOMAINS_PREREQUISITE=""
    _patch_orchestrator_file_safe "$profile_path" || return 2
    IFS= read -r header < "$profile_path" || return 2
    [ "$header" = "$PATCH_ORCHESTRATOR_PROFILE_HEADER" ] || return 2
    while IFS=$'\t' read -r profile_id max_risk code adapter risk resolution domain postcondition \
        implementation input_type input_value validator rollback extra; do
        [ -n "$profile_id" ] || continue
        [ -z "$extra" ] || return 2
        rows=$((rows + 1))
        printf -v expected_code 'U-%02d' "$rows"
        [ "$code" = "$expected_code" ] || return 2
        if [ "$implementation" = fixed ]; then
            [ "$input_type:$input_value" = none:- ] || return 2
            continue
        fi
        case "$input_type:$input_value" in
            pam_password_policy:/*|pam_lockout_policy:/*|pam_approved_su_group:/*|service_disable_approval:/*) ;;
            pam_password_policy:*|pam_lockout_policy:*|pam_approved_su_group:*|service_disable_approval:*) continue ;;
            *:/*) ;;
            *) _patch_domains_prerequisite "absolute_domain_input:$code"; return 3 ;;
        esac
        status=0
        _patch_domains_load_input "$input_value" "$code" || status=$?
        if [ "$status" -eq 3 ]; then return 3; elif [ "$status" -ne 0 ]; then
            _patch_domains_error "invalid domain input TSV: $code"
            return 2
        fi
    done < <(sed -n '2,$p' "$profile_path")
    [ "$rows" -eq 67 ]
}
