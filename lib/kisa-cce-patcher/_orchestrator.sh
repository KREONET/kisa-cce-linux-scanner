# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash
# shellcheck disable=SC2034

# Coordinates domain transactions after validating the complete desired and observed state.

if ! declare -F patch_coverage_records >/dev/null 2>&1; then
    case "${BASH_SOURCE[0]}" in */*) __kisa_orchestrator_source_directory="${BASH_SOURCE[0]%/*}" ;; *) __kisa_orchestrator_source_directory=. ;; esac
    # shellcheck source=_coverage.sh
    . "$__kisa_orchestrator_source_directory/_coverage.sh"
    unset __kisa_orchestrator_source_directory
fi

PATCH_ORCHESTRATOR_DOMAIN_ORDER=(package account configuration filesystem inventory metadata pam service system network-service edge-service)
PATCH_ORCHESTRATOR_PROFILE_HEADER=$'profile_id\tmax_risk\tcode\tadapter\trisk\tresolution_requirement\ttransaction_domain\tpostcondition\timplementation_status\tinput_type\tinput_value\tvalidator\trollback_domain'
PATCH_ORCHESTRATOR_REQUEST_HEADER=$'code\tadapter\tpostcondition\timplementation_status\tinput_type\tinput_value\tscan_status\tremediation_eligible\tremediation_rule_id'
PATCH_ORCHESTRATOR_MANIFEST_HEADER=$'schema\trecord_type\tname\tvalue_one\tvalue_two\tvalue_three'

PATCH_ORCHESTRATOR_ERROR_DETAIL=""
PATCH_ORCHESTRATOR_STATE=""
PATCH_ORCHESTRATOR_ROOT=""
PATCH_ORCHESTRATOR_ROOT_DEVICE=""
PATCH_ORCHESTRATOR_ROOT_INODE=""
PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY=""
PATCH_ORCHESTRATOR_PROFILE_SHA256=""
PATCH_ORCHESTRATOR_SCAN_SHA256=""
PATCH_ORCHESTRATOR_SCAN_DEVICE=""
PATCH_ORCHESTRATOR_SCAN_INODE=""
PATCH_ORCHESTRATOR_MANIFEST_SHA256=""
PATCH_ORCHESTRATOR_PLAN_VALID=0

declare -A PATCH_ORCHESTRATOR_PLAN_CALLBACKS=()
declare -A PATCH_ORCHESTRATOR_APPLY_CALLBACKS=()
declare -A PATCH_ORCHESTRATOR_VERIFY_CALLBACKS=()
declare -A PATCH_ORCHESTRATOR_ROLLBACK_CALLBACKS=()
declare -A PATCH_ORCHESTRATOR_PROFILE_ROWS=()
declare -A PATCH_ORCHESTRATOR_PROFILE_INPUT_TYPES=()
declare -A PATCH_ORCHESTRATOR_PROFILE_INPUT_VALUES=()
declare -A PATCH_ORCHESTRATOR_PROFILE_STATUSES=()
declare -A PATCH_ORCHESTRATOR_PROFILE_DOMAINS=()
declare -A PATCH_ORCHESTRATOR_PROFILE_ADAPTERS=()
declare -A PATCH_ORCHESTRATOR_PROFILE_POSTCONDITIONS=()
declare -A PATCH_ORCHESTRATOR_PROFILE_RESOLUTIONS=()
declare -A PATCH_ORCHESTRATOR_SCAN_STATUSES=()
declare -A PATCH_ORCHESTRATOR_SCAN_ELIGIBLE=()
declare -A PATCH_ORCHESTRATOR_SCAN_RULES=()
declare -A PATCH_ORCHESTRATOR_SCAN_RESOLUTIONS=()
declare -A PATCH_ORCHESTRATOR_ACTIONABLE_DOMAINS=()
declare -A PATCH_ORCHESTRATOR_DOMAIN_PLAN_DIGESTS=()
declare -A PATCH_ORCHESTRATOR_DOMAIN_REQUEST_DIGESTS=()
declare -A PATCH_ORCHESTRATOR_APPLIED_DOMAINS=()

_patch_orchestrator_error() {
    PATCH_ORCHESTRATOR_ERROR_DETAIL="$1"
    return 2
}

_patch_orchestrator_domain_valid() {
    case "$1" in package|account|configuration|filesystem|inventory|metadata|pam|service|system|network-service|edge-service) ;; *) return 1 ;; esac
}

_patch_orchestrator_function_name_valid() {
    case "$1" in ''|[!A-Za-z_]*|*[!A-Za-z0-9_]*) return 1 ;; esac
    declare -F "$1" >/dev/null 2>&1
}

patch_orchestrator_register_domain() {
    local domain="$1" plan_callback="$2" apply_callback="$3" verify_callback="$4" rollback_callback="$5"

    _patch_orchestrator_domain_valid "$domain" || return 1
    [ -z "${PATCH_ORCHESTRATOR_PLAN_CALLBACKS[$domain]+present}" ] || return 2
    _patch_orchestrator_function_name_valid "$plan_callback" || return 2
    _patch_orchestrator_function_name_valid "$apply_callback" || return 2
    _patch_orchestrator_function_name_valid "$verify_callback" || return 2
    _patch_orchestrator_function_name_valid "$rollback_callback" || return 2
    PATCH_ORCHESTRATOR_PLAN_CALLBACKS["$domain"]="$plan_callback"
    PATCH_ORCHESTRATOR_APPLY_CALLBACKS["$domain"]="$apply_callback"
    PATCH_ORCHESTRATOR_VERIFY_CALLBACKS["$domain"]="$verify_callback"
    PATCH_ORCHESTRATOR_ROLLBACK_CALLBACKS["$domain"]="$rollback_callback"
}

patch_orchestrator_reset() {
    PATCH_ORCHESTRATOR_ERROR_DETAIL=""
    PATCH_ORCHESTRATOR_STATE=""
    PATCH_ORCHESTRATOR_ROOT=""
    PATCH_ORCHESTRATOR_ROOT_DEVICE=""
    PATCH_ORCHESTRATOR_ROOT_INODE=""
    PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY=""
    PATCH_ORCHESTRATOR_PROFILE_SHA256=""
    PATCH_ORCHESTRATOR_SCAN_SHA256=""
    PATCH_ORCHESTRATOR_SCAN_DEVICE=""
    PATCH_ORCHESTRATOR_SCAN_INODE=""
    PATCH_ORCHESTRATOR_MANIFEST_SHA256=""
    PATCH_ORCHESTRATOR_PLAN_VALID=0
    PATCH_ORCHESTRATOR_PROFILE_ROWS=()
    PATCH_ORCHESTRATOR_PROFILE_INPUT_TYPES=()
    PATCH_ORCHESTRATOR_PROFILE_INPUT_VALUES=()
    PATCH_ORCHESTRATOR_PROFILE_STATUSES=()
    PATCH_ORCHESTRATOR_PROFILE_DOMAINS=()
    PATCH_ORCHESTRATOR_PROFILE_ADAPTERS=()
    PATCH_ORCHESTRATOR_PROFILE_POSTCONDITIONS=()
    PATCH_ORCHESTRATOR_PROFILE_RESOLUTIONS=()
    PATCH_ORCHESTRATOR_SCAN_STATUSES=()
    PATCH_ORCHESTRATOR_SCAN_ELIGIBLE=()
    PATCH_ORCHESTRATOR_SCAN_RULES=()
    PATCH_ORCHESTRATOR_SCAN_RESOLUTIONS=()
    PATCH_ORCHESTRATOR_ACTIONABLE_DOMAINS=()
    PATCH_ORCHESTRATOR_DOMAIN_PLAN_DIGESTS=()
    PATCH_ORCHESTRATOR_DOMAIN_REQUEST_DIGESTS=()
    PATCH_ORCHESTRATOR_APPLIED_DOMAINS=()
}

_patch_orchestrator_stat_into() {
    local path="$1" device_destination="$2" inode_destination="$3" uid_destination="$4" mode_destination="$5" links_destination="$6"
    local output="" stat_device="" stat_inode="" stat_uid="" stat_mode="" stat_links="" extra=""
    local destination=""

    for destination in "$device_destination" "$inode_destination" "$uid_destination" "$mode_destination" "$links_destination"; do
        case "$destination" in ''|[0-9]*|*[!A-Za-z0-9_]*) return 2 ;; esac
    done
    if output="$(/usr/bin/stat -c '%d:%i:%u:%a:%h' -- "$path" 2>/dev/null)"; then :
    elif output="$(/usr/bin/stat -f '%d:%i:%u:%p:%l' "$path" 2>/dev/null)"; then :
    else return 2
    fi
    IFS=: read -r stat_device stat_inode stat_uid stat_mode stat_links extra <<< "$output"
    [ -z "$extra" ] || return 2
    case "$stat_device:$stat_inode:$stat_uid:$stat_mode:$stat_links" in *[!0-9:]*) return 2 ;; esac
    printf -v "$device_destination" '%s' "$stat_device"
    printf -v "$inode_destination" '%s' "$stat_inode"
    printf -v "$uid_destination" '%s' "$stat_uid"
    printf -v "$mode_destination" '%04o' "$((8#$stat_mode & 07777))"
    printf -v "$links_destination" '%s' "$stat_links"
}

_patch_orchestrator_sha256_into() {
    local path="$1" destination_name="$2" output="" hash_digest=""
    case "$destination_name" in ''|[0-9]*|*[!A-Za-z0-9_]*) return 2 ;; esac
    if [ -x /usr/bin/sha256sum ]; then output="$(/usr/bin/sha256sum "$path")" || return 2
    elif [ -x /bin/sha256sum ]; then output="$(/bin/sha256sum "$path")" || return 2
    else output="$(/usr/bin/shasum -a 256 "$path")" || return 2
    fi
    hash_digest="${output%% *}"
    [ "${#hash_digest}" -eq 64 ] || return 2
    case "$hash_digest" in *[!0-9a-f]*) return 2 ;; esac
    printf -v "$destination_name" '%s' "$hash_digest"
}

_patch_orchestrator_parent_chain_safe() {
    local path="$1" canonical="" current=/ relative="" component=""
    local device="" inode="" uid="" mode="" links=""
    local -a components=()

    canonical="$(CDPATH='' builtin cd -P -- "$path" 2>/dev/null && pwd -P)" || return 2
    relative="${canonical#/}"
    IFS=/ read -r -a components <<< "$relative"
    for component in "${components[@]}"; do
        [ -n "$component" ] || continue
        current="${current%/}/$component"
        _patch_orchestrator_stat_into "$current" device inode uid mode links || return 2
        [ "$uid" = 0 ] || [ "$uid" = "${EUID:-0}" ] || return 2
        if [ $((8#$mode & 0022)) -ne 0 ]; then
            [ "$uid" = 0 ] && [ $((8#$mode & 01000)) -ne 0 ] &&
                { [ "$current" = /tmp ] || [ "$current" = /var/tmp ] ||
                  [ "$current" = /private/tmp ] || [ "$current" = /private/var/tmp ]; } || return 2
        fi
    done
}

_patch_orchestrator_file_safe() {
    local path="$1" device="" inode="" uid="" mode="" links=""
    [ -f "$path" ] && [ ! -L "$path" ] && [ -r "$path" ] || return 2
    _patch_orchestrator_parent_chain_safe "${path%/*}" || return 2
    _patch_orchestrator_stat_into "$path" device inode uid mode links || return 2
    [ "$links" = 1 ] && { [ "$uid" = 0 ] || [ "$uid" = "${EUID:-0}" ]; } && [ $((8#$mode & 0022)) -eq 0 ]
}

_patch_orchestrator_directory_safe() {
    local path="$1" device="" inode="" uid="" mode="" links=""
    [ -d "$path" ] && [ ! -L "$path" ] || return 2
    _patch_orchestrator_parent_chain_safe "$path" || return 2
    _patch_orchestrator_stat_into "$path" device inode uid mode links || return 2
    [ "$uid" = 0 ] || [ "$uid" = "${EUID:-0}" ] || return 2
    [ $((8#$mode & 0022)) -eq 0 ]
}

_patch_orchestrator_initialize_root() {
    local requested="$1" canonical="" uid="" mode="" links=""
    [ -d "$requested" ] && [ ! -L "$requested" ] || return 2
    canonical="$(CDPATH='' builtin cd -P -- "$requested" && pwd -P)" || return 2
    _patch_orchestrator_directory_safe "$canonical" || return 2
    PATCH_ORCHESTRATOR_ROOT="$canonical"
    _patch_orchestrator_stat_into "$canonical" PATCH_ORCHESTRATOR_ROOT_DEVICE \
        PATCH_ORCHESTRATOR_ROOT_INODE uid mode links
}

_patch_orchestrator_json_string_into() {
    local line="$1" key="$2" destination_name="$3" marker="" tail="" value=""
    marker="\"$key\":\""
    case "$line" in *"$marker"*) ;; *) return 1 ;; esac
    tail="${line#*"$marker"}"
    value="${tail%%\"*}"
    case "$value" in *'\\'*|*$'\n'*|*$'\r'*|*$'\t'*) return 2 ;; esac
    printf -v "$destination_name" '%s' "$value"
}

_patch_orchestrator_json_boolean_into() {
    local line="$1" key="$2" destination_name="$3" marker="" tail="" value=""
    marker="\"$key\":"
    case "$line" in *"$marker"*) ;; *) return 1 ;; esac
    tail="${line#*"$marker"}"
    value="${tail%%,*}"
    value="${value%%\}*}"
    case "$value" in true|false) ;; *) return 2 ;; esac
    printf -v "$destination_name" '%s' "$value"
}

_patch_orchestrator_load_profile() {
    local path="$1" header="" profile_id="" max_risk="" code="" adapter="" risk=""
    local resolution="" domain="" postcondition="" implementation="" input_type="" input_value=""
    local validator="" rollback_domain="" extra="" coverage="" expected_code="" canonical_profile="" canonical_risk=""
    local coverage_code="" coverage_adapter="" coverage_risk="" coverage_resolution="" coverage_domain=""
    local coverage_postcondition="" coverage_implementation="" coverage_input="" coverage_validator="" coverage_rollback=""
    local count=0 max_rank=0 risk_rank=0

    _patch_orchestrator_file_safe "$path" || return 2
    _patch_orchestrator_sha256_into "$path" PATCH_ORCHESTRATOR_PROFILE_SHA256 || return 2
    IFS= read -r header < "$path" || return 2
    [ "$header" = "$PATCH_ORCHESTRATOR_PROFILE_HEADER" ] || return 2
    while IFS=$'\t' read -r profile_id max_risk code adapter risk resolution domain postcondition \
        implementation input_type input_value validator rollback_domain extra; do
        [ -n "$profile_id" ] || continue
        count=$((count + 1)); printf -v expected_code 'U-%02d' "$count"
        [ "$code" = "$expected_code" ] && [ -z "$extra" ] || return 2
        if [ "$count" -eq 1 ]; then canonical_profile="$profile_id"; canonical_risk="$max_risk"
        else [ "$profile_id:$max_risk" = "$canonical_profile:$canonical_risk" ] || return 2
        fi
        patch_coverage_record_into "$code" coverage || return 2
        IFS=$'\t' read -r coverage_code coverage_adapter coverage_risk coverage_resolution coverage_domain \
            coverage_postcondition coverage_implementation coverage_input coverage_validator coverage_rollback <<< "$coverage"
        [ "$code:$adapter:$risk:$resolution:$domain:$postcondition:$implementation:$input_type:$validator:$rollback_domain" = \
            "$coverage_code:$coverage_adapter:$coverage_risk:$coverage_resolution:$coverage_domain:$coverage_postcondition:$coverage_implementation:$coverage_input:$coverage_validator:$coverage_rollback" ] || return 2
        case "$canonical_risk" in R0) max_rank=0 ;; R1) max_rank=1 ;; R2) max_rank=2 ;; R3) max_rank=3 ;; R4) max_rank=4 ;; *) return 2 ;; esac
        case "$risk" in R0) risk_rank=0 ;; R1) risk_rank=1 ;; R2) risk_rank=2 ;; R3) risk_rank=3 ;; R4) risk_rank=4 ;; *) return 2 ;; esac
        [ "$risk_rank" -le "$max_rank" ] || return 2
        case "$implementation:$input_value" in fixed:-) ;; conditional:-|gated:-) return 2 ;; fixed:*) return 2 ;; esac
        PATCH_ORCHESTRATOR_PROFILE_ROWS["$code"]="$profile_id\t$max_risk\t$coverage"
        PATCH_ORCHESTRATOR_PROFILE_INPUT_TYPES["$code"]="$input_type"
        PATCH_ORCHESTRATOR_PROFILE_INPUT_VALUES["$code"]="$input_value"
        PATCH_ORCHESTRATOR_PROFILE_STATUSES["$code"]="$implementation"
        PATCH_ORCHESTRATOR_PROFILE_DOMAINS["$code"]="$domain"
        PATCH_ORCHESTRATOR_PROFILE_ADAPTERS["$code"]="$adapter"
        PATCH_ORCHESTRATOR_PROFILE_POSTCONDITIONS["$code"]="$postcondition"
        PATCH_ORCHESTRATOR_PROFILE_RESOLUTIONS["$code"]="$resolution"
    done < <(sed -n '2,$p' "$path")
    [ "$count" -eq 67 ]
}

_patch_orchestrator_load_scan() {
    local path="$1" line="" code="" status="" resolution="" eligible="" rule="" count=0
    local device="" inode="" uid="" mode="" links=""
    local good=0 vulnerable=0 manual=0 not_applicable=0 error=0 summary_seen=0
    local summary_regex='^\{"type":"summary","total":([0-9]+),"good":([0-9]+),"vulnerable":([0-9]+),"manual":([0-9]+),"not_applicable":([0-9]+),"error":([0-9]+),"policy_resolved":([0-9]+)\}$'

    _patch_orchestrator_file_safe "$path" || return 2
    _patch_orchestrator_sha256_into "$path" PATCH_ORCHESTRATOR_SCAN_SHA256 || return 2
    _patch_orchestrator_stat_into "$path" device inode uid mode links || return 2
    PATCH_ORCHESTRATOR_SCAN_DEVICE="$device"; PATCH_ORCHESTRATOR_SCAN_INODE="$inode"
    while IFS= read -r line || [ -n "$line" ]; do
        if [[ "$line" == '{"code":"'* ]]; then
            [ "$summary_seen" -eq 0 ] || return 2
            _patch_orchestrator_json_string_into "$line" code code || return 2
            _patch_orchestrator_json_string_into "$line" status status || return 2
            _patch_orchestrator_json_string_into "$line" resolution_class resolution || return 2
            _patch_orchestrator_json_boolean_into "$line" remediation_eligible eligible || return 2
            _patch_orchestrator_json_string_into "$line" remediation_rule_id rule || return 2
            case "$code" in U-[0-9][0-9]) ;; *) return 2 ;; esac
            case "$resolution" in technical|policy|runtime|external) ;; *) return 2 ;; esac
            case "$status" in
                GOOD) good=$((good + 1)) ;;
                VULNERABLE) vulnerable=$((vulnerable + 1)) ;;
                MANUAL) manual=$((manual + 1)) ;;
                NOT_APPLICABLE) not_applicable=$((not_applicable + 1)) ;;
                ERROR) error=$((error + 1)) ;;
                *) return 2 ;;
            esac
            [ -z "${PATCH_ORCHESTRATOR_SCAN_STATUSES[$code]+present}" ] || return 2
            PATCH_ORCHESTRATOR_SCAN_STATUSES["$code"]="$status"
            PATCH_ORCHESTRATOR_SCAN_RESOLUTIONS["$code"]="$resolution"
            PATCH_ORCHESTRATOR_SCAN_ELIGIBLE["$code"]="$eligible"
            PATCH_ORCHESTRATOR_SCAN_RULES["$code"]="$rule"
            count=$((count + 1))
        elif [[ "$line" =~ $summary_regex ]]; then
            [ "$summary_seen" -eq 0 ] && [ "$count" -eq 67 ] || return 2
            [ "${BASH_REMATCH[1]}" -eq 67 ] && [ "${BASH_REMATCH[2]}" -eq "$good" ] &&
                [ "${BASH_REMATCH[3]}" -eq "$vulnerable" ] && [ "${BASH_REMATCH[4]}" -eq "$manual" ] &&
                [ "${BASH_REMATCH[5]}" -eq "$not_applicable" ] && [ "${BASH_REMATCH[6]}" -eq "$error" ] &&
                [ "${BASH_REMATCH[7]}" -eq 0 ] || return 2
            summary_seen=1
        else
            return 2
        fi
    done < "$path"
    [ "$count" -eq 67 ] && [ "$summary_seen" -eq 1 ] || return 2
    count=0
    while [ "$count" -lt 67 ]; do
        count=$((count + 1))
        printf -v code 'U-%02d' "$count"
        [ -n "${PATCH_ORCHESTRATOR_SCAN_STATUSES[$code]+present}" ] || return 2
    done
}

_patch_orchestrator_expected_rule_into() {
    local code="$1" domain="$2" destination_name="$3"
    local number="${code#U-}"
    local rule=""
    case "$domain" in
        account|configuration|filesystem|inventory|metadata|pam|service|system|network-service|edge-service)
            rule="$domain.u$number.v1"
            ;;
        package) rule="system.u$number.v1" ;;
        *) return 2 ;;
    esac
    printf -v "$destination_name" '%s' "$rule"
}

_patch_orchestrator_preflight() {
    local number=0 code="" scan_status="" scan_resolution="" implementation="" domain="" eligible="" rule="" expected_rule=""

    PATCH_ORCHESTRATOR_ACTIONABLE_DOMAINS=()
    while [ "$number" -lt 67 ]; do
        number=$((number + 1)); printf -v code 'U-%02d' "$number"
        scan_status="${PATCH_ORCHESTRATOR_SCAN_STATUSES[$code]}"
        scan_resolution="${PATCH_ORCHESTRATOR_SCAN_RESOLUTIONS[$code]}"
        implementation="${PATCH_ORCHESTRATOR_PROFILE_STATUSES[$code]}"
        domain="${PATCH_ORCHESTRATOR_PROFILE_DOMAINS[$code]}"
        eligible="${PATCH_ORCHESTRATOR_SCAN_ELIGIBLE[$code]}"
        rule="${PATCH_ORCHESTRATOR_SCAN_RULES[$code]}"
        if [ "$scan_status" = ERROR ]; then
            _patch_orchestrator_error "$code scanner result is ERROR"
            return 2
        fi
        if [ "$eligible" = false ] && [ -n "$rule" ]; then
            _patch_orchestrator_error "$code has a remediation rule without eligibility"
            return 2
        fi
        if [ "$eligible" = true ]; then
            [ "$scan_status" = VULNERABLE ] || { _patch_orchestrator_error "$code has eligibility outside a vulnerable result"; return 2; }
            [ "$scan_resolution" = technical ] || { _patch_orchestrator_error "$code has eligibility outside a technical result"; return 2; }
            _patch_orchestrator_expected_rule_into "$code" "$domain" expected_rule || return 2
            [ "$rule" = "$expected_rule" ] || { _patch_orchestrator_error "$code remediation rule mismatch"; return 2; }
        fi
        if [ "$scan_status" = MANUAL ] && [ "$scan_resolution" != "${PATCH_ORCHESTRATOR_PROFILE_RESOLUTIONS[$code]}" ]; then
            _patch_orchestrator_error "$code manual resolution class does not match its coverage requirement"
            return 2
        fi
        case "$scan_status" in
            GOOD|NOT_APPLICABLE)
                [ "$eligible" = false ] && [ -z "$rule" ] || {
                    _patch_orchestrator_error "$code conforming result carries remediation metadata"
                    return 2
                }
                continue
                ;;
        esac
        [ "$implementation" != gated ] || { _patch_orchestrator_error "$code requires a gated adapter"; return 2; }
        case "$implementation" in fixed|conditional) ;; *) return 2 ;; esac
        if [ "$implementation" = fixed ] && [ "$scan_status" = VULNERABLE ] && [ "$eligible" != true ]; then
            _patch_orchestrator_error "$code fixed vulnerability is not remediation eligible"
            return 2
        fi
        _patch_orchestrator_domain_valid "$domain" || { _patch_orchestrator_error "$code has no routable domain"; return 2; }
        PATCH_ORCHESTRATOR_ACTIONABLE_DOMAINS["$domain"]=1
    done
    for domain in "${!PATCH_ORCHESTRATOR_ACTIONABLE_DOMAINS[@]}"; do
        [ -n "${PATCH_ORCHESTRATOR_PLAN_CALLBACKS[$domain]:-}" ] &&
            [ -n "${PATCH_ORCHESTRATOR_APPLY_CALLBACKS[$domain]:-}" ] &&
            [ -n "${PATCH_ORCHESTRATOR_VERIFY_CALLBACKS[$domain]:-}" ] &&
            [ -n "${PATCH_ORCHESTRATOR_ROLLBACK_CALLBACKS[$domain]:-}" ] || {
            _patch_orchestrator_error "domain callback registry is incomplete: $domain"
            return 2
        }
    done
}

_patch_orchestrator_set_state() {
    local state="$1" path="$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/state" temp=""
    case "$state" in planned|external_action_required|applying|awaiting_post_scan|verified|rollback_in_progress|rolled_back|rollback_failed|failed) ;; *) return 2 ;; esac
    temp="$(umask 077; /usr/bin/mktemp "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/.state.XXXXXXXX")" || return 2
    printf '%s\n' "$state" > "$temp" || return 2
    /bin/chmod 0600 "$temp" || return 2
    /usr/bin/mv -f "$temp" "$path" || return 2
    PATCH_ORCHESTRATOR_STATE="$state"
}

_patch_orchestrator_prepare_directory() {
    local requested="$1" canonical="" directory=""
    _patch_orchestrator_directory_safe "$requested" || return 2
    canonical="$(CDPATH='' builtin cd -P -- "$requested" && pwd -P)" || return 2
    PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY="$canonical"
    [ ! -e "$canonical/orchestrator" ] && [ ! -L "$canonical/orchestrator" ] || return 2
    (umask 077; /bin/mkdir "$canonical/orchestrator" "$canonical/orchestrator/domains" "$canonical/orchestrator/inputs") || return 2
    for directory in "$canonical/orchestrator" "$canonical/orchestrator/domains" "$canonical/orchestrator/inputs"; do
        _patch_orchestrator_directory_safe "$directory" || return 2
    done
}

_patch_orchestrator_copy_input() {
    local source="$1" destination="$2"
    [ ! -e "$destination" ] && [ ! -L "$destination" ] || return 2
    (umask 077; /bin/cp "$source" "$destination") || return 2
    /bin/chmod 0600 "$destination" || return 2
    _patch_orchestrator_file_safe "$destination"
}

_patch_orchestrator_write_requests() {
    local domain="" number=0 code="" path="" status=""
    local -A initialized=()

    for domain in "${PATCH_ORCHESTRATOR_DOMAIN_ORDER[@]}"; do
        [ -n "${PATCH_ORCHESTRATOR_ACTIONABLE_DOMAINS[$domain]+present}" ] || continue
        path="$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/domains/$domain"
        (umask 077; /bin/mkdir "$path") || return 2
        _patch_orchestrator_directory_safe "$path" || return 2
        printf '%s\n' "$PATCH_ORCHESTRATOR_REQUEST_HEADER" > "$path/request.tsv" || return 2
        initialized["$domain"]=1
    done
    while [ "$number" -lt 67 ]; do
        number=$((number + 1)); printf -v code 'U-%02d' "$number"
        status="${PATCH_ORCHESTRATOR_SCAN_STATUSES[$code]}"
        case "$status" in VULNERABLE|MANUAL) ;; *) continue ;; esac
        domain="${PATCH_ORCHESTRATOR_PROFILE_DOMAINS[$code]}"
        [ -n "${initialized[$domain]+present}" ] || return 2
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$code" "${PATCH_ORCHESTRATOR_PROFILE_ADAPTERS[$code]}" \
            "${PATCH_ORCHESTRATOR_PROFILE_POSTCONDITIONS[$code]}" \
            "${PATCH_ORCHESTRATOR_PROFILE_STATUSES[$code]}" \
            "${PATCH_ORCHESTRATOR_PROFILE_INPUT_TYPES[$code]}" \
            "${PATCH_ORCHESTRATOR_PROFILE_INPUT_VALUES[$code]}" "$status" \
            "${PATCH_ORCHESTRATOR_SCAN_ELIGIBLE[$code]}" "${PATCH_ORCHESTRATOR_SCAN_RULES[$code]}" \
            >> "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/domains/$domain/request.tsv" || return 2
    done
    for domain in "${!initialized[@]}"; do
        /bin/chmod 0600 "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/domains/$domain/request.tsv" || return 2
    done
}

_patch_orchestrator_run_domain_plans() {
    local domain="" callback="" directory="" request="" plan="" digest="" request_digest="" callback_status=0
    for domain in "${PATCH_ORCHESTRATOR_DOMAIN_ORDER[@]}"; do
        [ -n "${PATCH_ORCHESTRATOR_ACTIONABLE_DOMAINS[$domain]+present}" ] || continue
        directory="$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/domains/$domain"
        request="$directory/request.tsv"; plan="$directory/plan.tsv"
        callback="${PATCH_ORCHESTRATOR_PLAN_CALLBACKS[$domain]}"
        callback_status=0
        "$callback" "$PATCH_ORCHESTRATOR_ROOT" "$directory" "$request" || callback_status=$?
        case "$callback_status" in 0|3) ;; *) return 2 ;; esac
        _patch_orchestrator_file_safe "$plan" || return 2
        _patch_orchestrator_sha256_into "$plan" digest || return 2
        _patch_orchestrator_sha256_into "$request" request_digest || return 2
        PATCH_ORCHESTRATOR_DOMAIN_PLAN_DIGESTS["$domain"]="$digest"
        PATCH_ORCHESTRATOR_DOMAIN_REQUEST_DIGESTS["$domain"]="$request_digest"
        [ "$callback_status" -ne 3 ] || return 3
    done
}

_patch_orchestrator_write_manifest() {
    local path="$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/manifest.tsv"
    local domain="" request_digest="" order=""
    order="$(IFS=,; printf '%s' "${PATCH_ORCHESTRATOR_DOMAIN_ORDER[*]}")"
    {
        printf '%s\n' "$PATCH_ORCHESTRATOR_MANIFEST_HEADER"
        printf '1\tcontext\troot\t%s\t%s\t%s\n' "$PATCH_ORCHESTRATOR_ROOT" "$PATCH_ORCHESTRATOR_ROOT_DEVICE" "$PATCH_ORCHESTRATOR_ROOT_INODE"
        printf '1\tinput\tprofile\tinputs/profile.tsv\t%s\t-\n' "$PATCH_ORCHESTRATOR_PROFILE_SHA256"
        printf '1\tinput\tscan\tinputs/pre-scan.jsonl\t%s\t%s:%s\n' "$PATCH_ORCHESTRATOR_SCAN_SHA256" "$PATCH_ORCHESTRATOR_SCAN_DEVICE" "$PATCH_ORCHESTRATOR_SCAN_INODE"
        printf '1\tplan\tstate\t%s\t%s\t-\n' "$PATCH_ORCHESTRATOR_STATE" "$order"
        for domain in "${PATCH_ORCHESTRATOR_DOMAIN_ORDER[@]}"; do
            [ -n "${PATCH_ORCHESTRATOR_ACTIONABLE_DOMAINS[$domain]+present}" ] || continue
            request_digest="${PATCH_ORCHESTRATOR_DOMAIN_REQUEST_DIGESTS[$domain]:-}"
            [ -n "$request_digest" ] || {
                _patch_orchestrator_sha256_into "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/domains/$domain/request.tsv" request_digest || return 2
                PATCH_ORCHESTRATOR_DOMAIN_REQUEST_DIGESTS["$domain"]="$request_digest"
            }
            printf '1\tdomain\t%s\tdomains/%s\t%s\t%s\n' "$domain" "$domain" \
                "${PATCH_ORCHESTRATOR_DOMAIN_PLAN_DIGESTS[$domain]}" "$request_digest"
        done
    } > "$path" || return 2
    /bin/chmod 0600 "$path" || return 2
    _patch_orchestrator_sha256_into "$path" PATCH_ORCHESTRATOR_MANIFEST_SHA256 || return 2
    printf '%s  manifest.tsv\n' "$PATCH_ORCHESTRATOR_MANIFEST_SHA256" > "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/manifest.sha256" || return 2
    /bin/chmod 0600 "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/manifest.sha256" || return 2
    printf 'domain\n' > "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/applied.tsv" || return 2
    /bin/chmod 0600 "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/applied.tsv" || return 2
}

patch_orchestrator_plan() {
    local profile="$1" scan="$2" requested_root="$3" transaction="$4" status=0 domain=""

    patch_orchestrator_reset
    patch_coverage_validate || { _patch_orchestrator_error "coverage contract is invalid"; return 2; }
    _patch_orchestrator_initialize_root "$requested_root" || { _patch_orchestrator_error "root is unsafe"; return 2; }
    _patch_orchestrator_load_profile "$profile" || { _patch_orchestrator_error "desired-state profile is not a full valid 67-row v2 profile"; return 2; }
    _patch_orchestrator_load_scan "$scan" || { _patch_orchestrator_error "scanner JSONL is not a complete unique 67-result report"; return 2; }
    _patch_orchestrator_preflight || status=$?
    [ "$status" -ne 2 ] || return 2
    _patch_orchestrator_prepare_directory "$transaction" || { _patch_orchestrator_error "transaction directory is unsafe"; return 2; }
    _patch_orchestrator_copy_input "$profile" "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/inputs/profile.tsv" || return 2
    _patch_orchestrator_copy_input "$scan" "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/inputs/pre-scan.jsonl" || return 2
    if [ "$status" -eq 3 ]; then
        _patch_orchestrator_set_state external_action_required || return 2
        _patch_orchestrator_write_manifest || return 2
        PATCH_ORCHESTRATOR_PLAN_VALID=1
        return 3
    fi
    PATCH_ORCHESTRATOR_STATE=planned
    _patch_orchestrator_write_requests || return 2
    status=0
    _patch_orchestrator_run_domain_plans || status=$?
    if [ "$status" -eq 3 ]; then
        for domain in "${!PATCH_ORCHESTRATOR_ACTIONABLE_DOMAINS[@]}"; do
            [ -n "${PATCH_ORCHESTRATOR_DOMAIN_PLAN_DIGESTS[$domain]:-}" ] ||
                unset 'PATCH_ORCHESTRATOR_ACTIONABLE_DOMAINS[$domain]'
        done
        _patch_orchestrator_set_state external_action_required || return 2
        _patch_orchestrator_write_manifest || return 2
        PATCH_ORCHESTRATOR_PLAN_VALID=1
        return 3
    elif [ "$status" -ne 0 ]; then
        _patch_orchestrator_set_state failed >/dev/null 2>&1 || :
        return 2
    fi
    _patch_orchestrator_set_state planned || return 2
    _patch_orchestrator_write_manifest || return 2
    PATCH_ORCHESTRATOR_PLAN_VALID=1
}

_patch_orchestrator_manifest_current() {
    local path="$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/manifest.tsv" expected="" suffix="" actual=""
    IFS=' ' read -r expected suffix < "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/manifest.sha256" || return 2
    [ "$suffix" = manifest.tsv ] || return 2
    _patch_orchestrator_sha256_into "$path" actual || return 2
    [ "$actual" = "$expected" ] && [ "$actual" = "$PATCH_ORCHESTRATOR_MANIFEST_SHA256" ]
}

_patch_orchestrator_artifacts_current() {
    local digest="" domain=""
    _patch_orchestrator_manifest_current || return 2
    _patch_orchestrator_sha256_into "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/inputs/profile.tsv" digest || return 2
    [ "$digest" = "$PATCH_ORCHESTRATOR_PROFILE_SHA256" ] || return 2
    _patch_orchestrator_sha256_into "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/inputs/pre-scan.jsonl" digest || return 2
    [ "$digest" = "$PATCH_ORCHESTRATOR_SCAN_SHA256" ] || return 2
    for domain in "${!PATCH_ORCHESTRATOR_ACTIONABLE_DOMAINS[@]}"; do
        _patch_orchestrator_sha256_into "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/domains/$domain/request.tsv" digest || return 2
        [ "$digest" = "${PATCH_ORCHESTRATOR_DOMAIN_REQUEST_DIGESTS[$domain]}" ] || return 2
        _patch_orchestrator_sha256_into "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/domains/$domain/plan.tsv" digest || return 2
        [ "$digest" = "${PATCH_ORCHESTRATOR_DOMAIN_PLAN_DIGESTS[$domain]}" ] || return 2
        if declare -F patch_orchestrator_builtin_domain_artifacts_current >/dev/null 2>&1; then
            patch_orchestrator_builtin_domain_artifacts_current \
                "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/domains/$domain" || return 2
        fi
    done
}

_patch_orchestrator_append_applied() {
    local domain="$1" path="$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/applied.tsv"
    [ -z "${PATCH_ORCHESTRATOR_APPLIED_DOMAINS[$domain]+present}" ] || return 2
    printf '%s\n' "$domain" >> "$path" || return 2
    PATCH_ORCHESTRATOR_APPLIED_DOMAINS["$domain"]=1
}

patch_orchestrator_rollback() {
    local mode="${1:-strict}" index=0 domain="" callback="" failures=0
    case "$mode" in strict|transition) ;; *) return 2 ;; esac
    [ "$PATCH_ORCHESTRATOR_PLAN_VALID" -eq 1 ] || return 2
    _patch_orchestrator_artifacts_current || return 2
    if [ "$PATCH_ORCHESTRATOR_STATE" = rolled_back ]; then
        return 0
    fi
    case "$mode:$PATCH_ORCHESTRATOR_STATE" in
        strict:awaiting_post_scan|strict:verified) ;;
        transition:applying|transition:awaiting_post_scan|transition:rollback_in_progress|transition:rollback_failed) ;;
        *) return 2 ;;
    esac
    _patch_orchestrator_set_state rollback_in_progress || return 2
    index=$(( ${#PATCH_ORCHESTRATOR_DOMAIN_ORDER[@]} - 1 ))
    while [ "$index" -ge 0 ]; do
        domain="${PATCH_ORCHESTRATOR_DOMAIN_ORDER[$index]}"
        if [ -n "${PATCH_ORCHESTRATOR_APPLIED_DOMAINS[$domain]+present}" ]; then
            callback="${PATCH_ORCHESTRATOR_ROLLBACK_CALLBACKS[$domain]:-}"
            [ -n "$callback" ] && "$callback" "$PATCH_ORCHESTRATOR_ROOT" \
                "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/domains/$domain" "$mode" || failures=$((failures + 1))
        fi
        index=$((index - 1))
    done
    if [ "$failures" -gt 0 ]; then
        _patch_orchestrator_set_state rollback_failed >/dev/null 2>&1 || :
        PATCH_ORCHESTRATOR_ERROR_DETAIL="domain rollback failed: count=$failures"
        return 2
    fi
    _patch_orchestrator_set_state rolled_back
}

patch_orchestrator_apply() {
    local domain="" callback="" status=0
    [ "${EUID:-$(id -u)}" -eq 0 ] && [ "$PATCH_ORCHESTRATOR_PLAN_VALID" -eq 1 ] || return 2
    [ "$PATCH_ORCHESTRATOR_STATE" = planned ] || return 2
    _patch_orchestrator_artifacts_current || return 2
    _patch_orchestrator_set_state applying || return 2
    for domain in "${PATCH_ORCHESTRATOR_DOMAIN_ORDER[@]}"; do
        [ -n "${PATCH_ORCHESTRATOR_ACTIONABLE_DOMAINS[$domain]+present}" ] || continue
        _patch_orchestrator_append_applied "$domain" || { status=2; break; }
        callback="${PATCH_ORCHESTRATOR_APPLY_CALLBACKS[$domain]}"
        "$callback" "$PATCH_ORCHESTRATOR_ROOT" \
            "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/domains/$domain" || { status=2; break; }
    done
    if [ "$status" -eq 0 ]; then
        for domain in "${PATCH_ORCHESTRATOR_DOMAIN_ORDER[@]}"; do
            [ -n "${PATCH_ORCHESTRATOR_ACTIONABLE_DOMAINS[$domain]+present}" ] || continue
            callback="${PATCH_ORCHESTRATOR_VERIFY_CALLBACKS[$domain]}"
            "$callback" "$PATCH_ORCHESTRATOR_ROOT" \
                "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/domains/$domain" || { status=2; break; }
        done
    fi
    if [ "$status" -ne 0 ]; then
        PATCH_ORCHESTRATOR_ERROR_DETAIL="domain apply or verification failed"
        patch_orchestrator_rollback transition >/dev/null 2>&1 || PATCH_ORCHESTRATOR_ERROR_DETAIL+="; rollback incomplete"
        return 2
    fi
    _patch_orchestrator_set_state awaiting_post_scan
}

_patch_orchestrator_post_scan_is_conforming() {
    local path="$1" line="" code="" status="" count=0 device="" inode="" uid="" mode="" links=""
    local good=0 not_applicable=0 summary_seen=0
    local summary_regex='^\{"type":"summary","total":([0-9]+),"good":([0-9]+),"vulnerable":([0-9]+),"manual":([0-9]+),"not_applicable":([0-9]+),"error":([0-9]+),"policy_resolved":([0-9]+)\}$'
    local -A seen=()
    _patch_orchestrator_file_safe "$path" || return 2
    _patch_orchestrator_stat_into "$path" device inode uid mode links || return 2
    [ "$device:$inode" != "$PATCH_ORCHESTRATOR_SCAN_DEVICE:$PATCH_ORCHESTRATOR_SCAN_INODE" ] || return 2
    while IFS= read -r line || [ -n "$line" ]; do
        if [[ "$line" == *'"code":"U-'* ]]; then
            [ "$summary_seen" -eq 0 ] || return 2
            _patch_orchestrator_json_string_into "$line" code code || return 2
            _patch_orchestrator_json_string_into "$line" status status || return 2
            case "$code" in U-[0-9][0-9]) ;; *) return 2 ;; esac
            [ -z "${seen[$code]+present}" ] || return 2
            case "$status" in
                GOOD) good=$((good + 1)) ;;
                NOT_APPLICABLE) not_applicable=$((not_applicable + 1)) ;;
                *) return 1 ;;
            esac
            seen["$code"]=1; count=$((count + 1))
        elif [[ "$line" =~ $summary_regex ]]; then
            [ "$summary_seen" -eq 0 ] && [ "$count" -eq 67 ] || return 2
            [ "${BASH_REMATCH[1]}" -eq 67 ] && [ "${BASH_REMATCH[2]}" -eq "$good" ] &&
                [ "${BASH_REMATCH[3]}" -eq 0 ] && [ "${BASH_REMATCH[4]}" -eq 0 ] &&
                [ "${BASH_REMATCH[5]}" -eq "$not_applicable" ] && [ "${BASH_REMATCH[6]}" -eq 0 ] &&
                [ "${BASH_REMATCH[7]}" -eq 0 ] || return 2
            summary_seen=1
        else
            return 2
        fi
    done < "$path"
    [ "$count" -eq 67 ] && [ "$summary_seen" -eq 1 ] || return 2
    count=0
    while [ "$count" -lt 67 ]; do
        count=$((count + 1)); printf -v code 'U-%02d' "$count"
        [ -n "${seen[$code]+present}" ] || return 2
    done
}

patch_orchestrator_accept_post_scan() {
    local path="$1" status=0
    [ "$PATCH_ORCHESTRATOR_STATE" = awaiting_post_scan ] || return 2
    _patch_orchestrator_post_scan_is_conforming "$path" || status=$?
    if [ "$status" -ne 0 ]; then
        PATCH_ORCHESTRATOR_ERROR_DETAIL="fresh post-scan is incomplete or nonconforming"
        patch_orchestrator_rollback strict >/dev/null 2>&1 || PATCH_ORCHESTRATOR_ERROR_DETAIL+="; rollback incomplete"
        return 2
    fi
    _patch_orchestrator_set_state verified
}

patch_orchestrator_load_transaction() {
    local requested_root="$1" transaction="$2" manifest="" checksum="" expected="" suffix="" actual=""
    local header="" schema="" record_type="" name="" value_one="" value_two="" value_three="" extra=""
    local context_seen=0 profile_seen=0 scan_seen=0 plan_seen=0 domain="" state="" applied=""
    local profile_digest="" scan_digest="" order="" root_path="" root_device="" root_inode=""

    patch_orchestrator_reset
    _patch_orchestrator_initialize_root "$requested_root" || return 2
    _patch_orchestrator_directory_safe "$transaction" || return 2
    PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY="$(CDPATH='' builtin cd -P -- "$transaction" && pwd -P)" || return 2
    _patch_orchestrator_directory_safe "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator" || return 2
    manifest="$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/manifest.tsv"
    checksum="$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/manifest.sha256"
    _patch_orchestrator_file_safe "$manifest" && _patch_orchestrator_file_safe "$checksum" || return 2
    IFS=' ' read -r expected suffix < "$checksum" || return 2
    [ "$suffix" = manifest.tsv ] || return 2
    _patch_orchestrator_sha256_into "$manifest" actual || return 2
    [ "$actual" = "$expected" ] || return 2
    PATCH_ORCHESTRATOR_MANIFEST_SHA256="$actual"
    IFS= read -r header < "$manifest" || return 2
    [ "$header" = "$PATCH_ORCHESTRATOR_MANIFEST_HEADER" ] || return 2
    while IFS=$'\t' read -r schema record_type name value_one value_two value_three extra; do
        [ -n "$schema" ] || continue
        [ "$schema" = 1 ] && [ -z "$extra" ] || return 2
        case "$record_type:$name" in
            context:root)
                [ "$context_seen" -eq 0 ] || return 2; context_seen=1
                root_path="$value_one"; root_device="$value_two"; root_inode="$value_three"
                ;;
            input:profile)
                [ "$profile_seen" -eq 0 ] && [ "$value_one" = inputs/profile.tsv ] || return 2
                profile_seen=1; profile_digest="$value_two"
                ;;
            input:scan)
                [ "$scan_seen" -eq 0 ] && [ "$value_one" = inputs/pre-scan.jsonl ] || return 2
                scan_seen=1; scan_digest="$value_two"
                PATCH_ORCHESTRATOR_SCAN_DEVICE="${value_three%%:*}"; PATCH_ORCHESTRATOR_SCAN_INODE="${value_three#*:}"
                ;;
            plan:state)
                [ "$plan_seen" -eq 0 ] || return 2; plan_seen=1
                order="$value_two"
                case "$value_one" in planned|external_action_required) ;; *) return 2 ;; esac
                ;;
            domain:*)
                domain="$name"; _patch_orchestrator_domain_valid "$domain" || return 2
                [ "$value_one" = "domains/$domain" ] || return 2
                [ -z "${PATCH_ORCHESTRATOR_ACTIONABLE_DOMAINS[$domain]+present}" ] || return 2
                PATCH_ORCHESTRATOR_ACTIONABLE_DOMAINS["$domain"]=1
                PATCH_ORCHESTRATOR_DOMAIN_PLAN_DIGESTS["$domain"]="$value_two"
                PATCH_ORCHESTRATOR_DOMAIN_REQUEST_DIGESTS["$domain"]="$value_three"
                ;;
            *) return 2 ;;
        esac
    done < <(sed -n '2,$p' "$manifest")
    [ "$context_seen:$profile_seen:$scan_seen:$plan_seen" = 1:1:1:1 ] || return 2
    [ "$root_path:$root_device:$root_inode" = "$PATCH_ORCHESTRATOR_ROOT:$PATCH_ORCHESTRATOR_ROOT_DEVICE:$PATCH_ORCHESTRATOR_ROOT_INODE" ] || return 2
    [ "$order" = "$(IFS=,; printf '%s' "${PATCH_ORCHESTRATOR_DOMAIN_ORDER[*]}")" ] || return 2
    _patch_orchestrator_load_profile "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/inputs/profile.tsv" || return 2
    [ "$PATCH_ORCHESTRATOR_PROFILE_SHA256" = "$profile_digest" ] || return 2
    _patch_orchestrator_load_scan "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/inputs/pre-scan.jsonl" || return 2
    [ "$PATCH_ORCHESTRATOR_SCAN_SHA256" = "$scan_digest" ] || return 2
    for domain in "${!PATCH_ORCHESTRATOR_ACTIONABLE_DOMAINS[@]}"; do
        [ -n "${PATCH_ORCHESTRATOR_ROLLBACK_CALLBACKS[$domain]:-}" ] || return 2
        _patch_orchestrator_file_safe "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/domains/$domain/plan.tsv" || return 2
    done
    _patch_orchestrator_file_safe "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/state" || return 2
    IFS= read -r state < "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/state" || return 2
    case "$state" in planned|external_action_required|applying|awaiting_post_scan|verified|rollback_in_progress|rolled_back|rollback_failed|failed) ;; *) return 2 ;; esac
    PATCH_ORCHESTRATOR_STATE="$state"
    _patch_orchestrator_file_safe "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/applied.tsv" || return 2
    IFS= read -r header < "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/applied.tsv" || return 2
    [ "$header" = domain ] || return 2
    while IFS= read -r applied; do
        [ -n "$applied" ] || continue
        _patch_orchestrator_domain_valid "$applied" || return 2
        [ -n "${PATCH_ORCHESTRATOR_ACTIONABLE_DOMAINS[$applied]+present}" ] || return 2
        [ -z "${PATCH_ORCHESTRATOR_APPLIED_DOMAINS[$applied]+present}" ] || return 2
        PATCH_ORCHESTRATOR_APPLIED_DOMAINS["$applied"]=1
    done < <(sed -n '2,$p' "$PATCH_ORCHESTRATOR_TRANSACTION_DIRECTORY/orchestrator/applied.tsv")
    PATCH_ORCHESTRATOR_PLAN_VALID=1
    _patch_orchestrator_artifacts_current
}

patch_orchestrator_rollback_transaction() {
    local root="$1" transaction="$2" mode="${3:-strict}"
    patch_orchestrator_load_transaction "$root" "$transaction" || return 2
    patch_orchestrator_rollback "$mode"
}
