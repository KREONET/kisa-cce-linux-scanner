# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash
# shellcheck disable=SC2034,SC2317

# Policy attestations convert a reviewed criterion result into an explicit decision.

policy_console_uptime_into() {
    local __kisa_policy_destination="$1"
    local uptime_value=""
    local uptime_seconds=""
    local uptime_fraction=""

    if [ -r /proc/uptime ]; then
        IFS=' ' read -r uptime_value _ < /proc/uptime || uptime_value=""
    fi
    case "$uptime_value" in
        *.*)
            uptime_seconds="${uptime_value%%.*}"
            uptime_fraction="${uptime_value#*.}"
            case "$uptime_seconds:$uptime_fraction" in
                :*|*:|*[!0-9:]*) uptime_seconds="" ;;
            esac
            ;;
        *) uptime_seconds="" ;;
    esac
    if [ -z "$uptime_seconds" ]; then
        uptime_seconds="${SECONDS:-0}"
        case "$uptime_seconds" in
            ''|*[!0-9]*) uptime_seconds=0 ;;
        esac
        uptime_fraction=""
    fi
    uptime_fraction="${uptime_fraction}000000"
    uptime_fraction="${uptime_fraction:0:6}"
    printf -v "$__kisa_policy_destination" '%6s.%s' "$uptime_seconds" "$uptime_fraction"
}

policy_console_emit() {
    local uptime=""

    if declare -F console_emit >/dev/null 2>&1; then
        console_emit "${1-}"
        return
    fi
    policy_console_uptime_into uptime
    printf '[%s] kisa-cce-scan: %s\n' "$uptime" "${1-}"
}

if [ -z "${BASH_VERSINFO+x}" ] ||
    [ "${BASH_VERSINFO[0]:-0}" -lt 4 ] ||
    { [ "${BASH_VERSINFO[0]:-0}" -eq 4 ] && [ "${BASH_VERSINFO[1]:-0}" -lt 3 ]; }; then
    policy_console_emit "POLICY ERROR: Bash 4.3 or newer is required." >&2
    return 2 2>/dev/null || exit 2
fi

declare -gA POLICY_DECISION=()
declare -gA POLICY_REVIEW_ID=()
declare -gA POLICY_TICKET=()
declare -gA POLICY_APPROVER=()
declare -gA POLICY_EXPIRES=()

declare -g POLICY_MATCH_REVIEW_ID=""
declare -g POLICY_MATCH_DECISION=""
declare -g POLICY_MATCH_TICKET=""
declare -g POLICY_MATCH_APPROVER=""
declare -g POLICY_MATCH_EXPIRES=""
declare -g POLICY_SET_DIGEST=""

declare -gA POLICY_TIME_SOURCE_PROVIDER=()
declare -gA POLICY_TIME_SOURCE_HOST=()
declare -gA POLICY_TIME_SOURCE_ADDRESS=()
declare -gA POLICY_TIME_SOURCE_TICKET=()
declare -gA POLICY_TIME_SOURCE_APPROVER=()
declare -gA POLICY_TIME_SOURCE_EXPIRES=()
declare -g POLICY_TIME_SOURCE_FACTS_PRESENT=0
declare -g POLICY_TIME_SOURCE_COUNT=0

declare -g POLICY_TIME_SOURCE_MATCH_STATE=""
declare -g POLICY_TIME_SOURCE_MATCH_REASON=""
declare -g POLICY_TIME_SOURCE_MATCH_PROVIDER=""
declare -g POLICY_TIME_SOURCE_MATCH_HOST=""
declare -g POLICY_TIME_SOURCE_MATCH_ADDRESS=""
declare -g POLICY_TIME_SOURCE_MATCH_TICKET=""
declare -g POLICY_TIME_SOURCE_MATCH_APPROVER=""
declare -g POLICY_TIME_SOURCE_MATCH_EXPIRES=""
declare -g POLICY_TIME_SOURCE_MATCH_EVIDENCE=""

policy_report_error() {
    policy_console_emit "POLICY ERROR: $*" >&2
}

policy_stat_uid() {
    local path="$1"
    local stat_path=""

    stat_path="$(command -v stat 2>/dev/null || true)"
    [ -n "$stat_path" ] || return 127
    "$stat_path" -Lc '%u' -- "$path" 2>/dev/null ||
        "$stat_path" -f '%u' "$path" 2>/dev/null
}

policy_stat_mode() {
    local path="$1"
    local stat_path=""

    stat_path="$(command -v stat 2>/dev/null || true)"
    [ -n "$stat_path" ] || return 127
    "$stat_path" -Lc '%a' -- "$path" 2>/dev/null ||
        "$stat_path" -f '%Lp' "$path" 2>/dev/null
}

policy_path_is_trusted() {
    local path="$1"
    local expected_type="$2"
    local owner_uid=""
    local mode=""
    local decimal_mode=0

    if [ -L "$path" ]; then
        policy_report_error "$expected_type is a symbolic link: $path"
        return 2
    fi
    case "$expected_type" in
        directory)
            if [ ! -d "$path" ] || [ ! -r "$path" ] || [ ! -x "$path" ]; then
                policy_report_error "policy directory is not a readable, searchable directory: $path"
                return 2
            fi
            ;;
        file)
            if [ ! -f "$path" ] || [ ! -r "$path" ]; then
                policy_report_error "policy file is not a readable regular file: $path"
                return 2
            fi
            ;;
        *)
            policy_report_error "internal policy path type is invalid: $expected_type"
            return 2
            ;;
    esac

    owner_uid="$(policy_stat_uid "$path")" || {
        policy_report_error "cannot read owner metadata: $path"
        return 2
    }
    if [ "$owner_uid" != "0" ] && [ "$owner_uid" != "$EUID" ]; then
        policy_report_error "owner must be root or the effective user: $path"
        return 2
    fi

    mode="$(policy_stat_mode "$path")" || {
        policy_report_error "cannot read mode metadata: $path"
        return 2
    }
    case "$mode" in
        ''|*[!0-7]*)
            policy_report_error "invalid mode metadata: $path"
            return 2
            ;;
    esac
    decimal_mode=$((8#$mode))
    if [ $((decimal_mode & 0022)) -ne 0 ]; then
        policy_report_error "group or other write permission is not allowed: $path"
        return 2
    fi
}

policy_code_is_valid() {
    local code="$1"
    local number=""

    case "$code" in
        U-[0-9][0-9]) ;;
        *) return 1 ;;
    esac
    number="${code#U-}"
    [ "$((10#$number))" -ge 1 ] && [ "$((10#$number))" -le 67 ]
}

policy_review_id_is_valid() {
    local review_id="$1"
    local digest=""

    case "$review_id" in
        sha256:*) digest="${review_id#sha256:}" ;;
        *) return 1 ;;
    esac
    [ "${#digest}" -eq 64 ] || return 1
    case "$digest" in
        *[!0-9a-f]*) return 1 ;;
    esac
}

policy_date_is_valid() {
    local value="$1"
    local year=""
    local month=""
    local day=""
    local maximum_day=0
    local year_number=0
    local month_number=0
    local day_number=0

    case "$value" in
        [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
        *) return 1 ;;
    esac
    year="${value%%-*}"
    month="${value#*-}"
    month="${month%%-*}"
    day="${value##*-}"
    year_number=$((10#$year))
    month_number=$((10#$month))
    day_number=$((10#$day))
    [ "$year_number" -ge 1 ] || return 1

    case "$month_number" in
        1|3|5|7|8|10|12) maximum_day=31 ;;
        4|6|9|11) maximum_day=30 ;;
        2)
            maximum_day=28
            if [ $((year_number % 400)) -eq 0 ] ||
                { [ $((year_number % 4)) -eq 0 ] && [ $((year_number % 100)) -ne 0 ]; }; then
                maximum_day=29
            fi
            ;;
        *) return 1 ;;
    esac
    [ "$day_number" -ge 1 ] && [ "$day_number" -le "$maximum_day" ]
}

policy_split_record() {
    local record="$1"
    shift
    local destination=""
    local field=""
    local remaining="$record"
    local field_number=1

    [ "$#" -eq 6 ] || return 2
    for destination in "$@"; do
        case "$destination" in
            ''|[0-9]*|*[!A-Za-z0-9_]*) return 2 ;;
        esac
        if [ "$field_number" -lt 6 ]; then
            case "$remaining" in
                *$'\t'*)
                    field="${remaining%%$'\t'*}"
                    remaining="${remaining#*$'\t'}"
                    ;;
                *) return 1 ;;
            esac
        else
            case "$remaining" in
                *$'\t'*) return 1 ;;
            esac
            field="$remaining"
        fi
        printf -v "$destination" '%s' "$field"
        field_number=$((field_number + 1))
    done
}

policy_time_source_provider_is_valid() {
    case "${1:-}" in
        chrony|ntpsec|systemd-timesyncd) return 0 ;;
        *) return 1 ;;
    esac
}

policy_time_source_host_into() {
    local __kisa_policy_destination="$1"
    local value="${2:-}"
    local label=""
    local old_ifs="$IFS"
    local -a labels=()
    local LC_ALL=C

    [ "$#" -eq 2 ] || return 2
    if [ -z "$value" ] || [ "$value" = "-" ]; then
        printf -v "$__kisa_policy_destination" '%s' '-'
        return 0
    fi
    [ "${#value}" -le 253 ] || return 1
    case "$value" in
        *[!A-Za-z0-9.-]*|.*|-*|*..*|*-) return 1 ;;
    esac
    value="${value%.}"
    [ -n "$value" ] || return 1
    IFS=.
    read -r -a labels <<< "$value"
    IFS="$old_ifs"
    for label in "${labels[@]}"; do
        [ -n "$label" ] && [ "${#label}" -le 63 ] || return 1
        case "$label" in -*|*-) return 1 ;; esac
    done
    printf -v "$__kisa_policy_destination" '%s' "${value,,}"
}

policy_ipv4_address_into() {
    local __kisa_policy_destination="$1"
    local value="$2"
    local old_ifs="$IFS"
    local octet=""
    local __kisa_policy_ipv4_value=""
    local -a octets=()

    IFS=.
    read -r -a octets <<< "$value"
    IFS="$old_ifs"
    [ "${#octets[@]}" -eq 4 ] || return 1
    for octet in "${octets[@]}"; do
        case "$octet" in ''|*[!0-9]*) return 1 ;; esac
        [ "${#octet}" -le 3 ] && [ "$((10#$octet))" -le 255 ] || return 1
        __kisa_policy_ipv4_value="${__kisa_policy_ipv4_value}${__kisa_policy_ipv4_value:+.}$((10#$octet))"
    done
    printf -v "$__kisa_policy_destination" '%s' "$__kisa_policy_ipv4_value"
}

policy_ipv6_address_is_valid() {
    local value="$1"
    local left=""
    local right=""
    local group=""
    local old_ifs="$IFS"
    local -a left_groups=()
    local -a right_groups=()
    local -a all_groups=()

    [ -n "$value" ] && [ "${#value}" -le 39 ] || return 1
    case "$value" in *[!0-9A-Fa-f:]*) return 1 ;; esac
    case "$value" in
        *:::*) return 1 ;;
        *::*::*) return 1 ;;
        *::*)
            left="${value%%::*}"
            right="${value#*::}"
            if [ -n "$left" ]; then
                IFS=:
                read -r -a left_groups <<< "$left"
                IFS="$old_ifs"
            fi
            if [ -n "$right" ]; then
                IFS=:
                read -r -a right_groups <<< "$right"
                IFS="$old_ifs"
            fi
            [ $(( ${#left_groups[@]} + ${#right_groups[@]} )) -lt 8 ] || return 1
            all_groups=("${left_groups[@]}" "${right_groups[@]}")
            ;;
        *)
            IFS=:
            read -r -a all_groups <<< "$value"
            IFS="$old_ifs"
            [ "${#all_groups[@]}" -eq 8 ] || return 1
            ;;
    esac
    for group in "${all_groups[@]}"; do
        [ -n "$group" ] && [ "${#group}" -le 4 ] || return 1
        case "$group" in *[!0-9A-Fa-f]*) return 1 ;; esac
    done
}

policy_time_source_address_into() {
    local __kisa_policy_destination="$1"
    local value="${2:-}"
    local __kisa_policy_address_result=""
    local LC_ALL=C

    [ "$#" -eq 2 ] || return 2
    if [ -z "$value" ] || [ "$value" = "-" ]; then
        printf -v "$__kisa_policy_destination" '%s' '-'
        return 0
    fi
    case "$value" in
        *:*)
            policy_ipv6_address_is_valid "$value" || return 1
            __kisa_policy_address_result="${value,,}"
            ;;
        *)
            policy_ipv4_address_into __kisa_policy_address_result "$value" || return 1
            ;;
    esac
    printf -v "$__kisa_policy_destination" '%s' "$__kisa_policy_address_result"
}

policy_time_source_key_into() {
    local __kisa_policy_destination="$1"
    local provider="$2"
    local host="$3"
    local address="$4"

    printf -v "$__kisa_policy_destination" '%s\t%s\t%s' "$provider" "$host" "$address"
}

policy_clear_time_source_match() {
    POLICY_TIME_SOURCE_MATCH_STATE=""
    POLICY_TIME_SOURCE_MATCH_REASON=""
    POLICY_TIME_SOURCE_MATCH_PROVIDER=""
    POLICY_TIME_SOURCE_MATCH_HOST=""
    POLICY_TIME_SOURCE_MATCH_ADDRESS=""
    POLICY_TIME_SOURCE_MATCH_TICKET=""
    POLICY_TIME_SOURCE_MATCH_APPROVER=""
    POLICY_TIME_SOURCE_MATCH_EXPIRES=""
    POLICY_TIME_SOURCE_MATCH_EVIDENCE=""
}

policy_clear_loaded_values() {
    POLICY_DECISION=()
    POLICY_REVIEW_ID=()
    POLICY_TICKET=()
    POLICY_APPROVER=()
    POLICY_EXPIRES=()
    POLICY_SET_DIGEST=""
    POLICY_TIME_SOURCE_PROVIDER=()
    POLICY_TIME_SOURCE_HOST=()
    POLICY_TIME_SOURCE_ADDRESS=()
    POLICY_TIME_SOURCE_TICKET=()
    POLICY_TIME_SOURCE_APPROVER=()
    POLICY_TIME_SOURCE_EXPIRES=()
    POLICY_TIME_SOURCE_FACTS_PRESENT=0
    POLICY_TIME_SOURCE_COUNT=0
    policy_clear_time_source_match
}

policy_write_set_digest_records() {
    local code=""
    local key=""
    local previous_key=""
    local number=0
    local index_value=0
    local previous_index=0
    local LC_ALL=C
    local -a time_source_keys=()

    for ((number = 1; number <= 67; number++)); do
        printf -v code 'U-%02d' "$number"
        [ -n "${POLICY_DECISION[$code]+present}" ] || continue
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$code" \
            "${POLICY_DECISION[$code]}" "${POLICY_REVIEW_ID[$code]}" \
            "${POLICY_TICKET[$code]}" "${POLICY_APPROVER[$code]}" "${POLICY_EXPIRES[$code]}"
    done
    [ "$POLICY_TIME_SOURCE_FACTS_PRESENT" -eq 1 ] || return 0
    printf 'F\ttime-sources\t1\n'
    [ "$POLICY_TIME_SOURCE_COUNT" -gt 0 ] || return 0
    time_source_keys=("${!POLICY_TIME_SOURCE_PROVIDER[@]}")
    for ((index_value = 1; index_value < ${#time_source_keys[@]}; index_value++)); do
        key="${time_source_keys[$index_value]}"
        previous_index=$index_value
        while [ "$previous_index" -gt 0 ]; do
            previous_key="${time_source_keys[$((previous_index - 1))]}"
            [[ "$key" < "$previous_key" ]] || break
            time_source_keys[previous_index]="$previous_key"
            previous_index=$((previous_index - 1))
        done
        time_source_keys[previous_index]="$key"
    done
    for key in "${time_source_keys[@]}"; do
        printf 'F\ttime-source\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${POLICY_TIME_SOURCE_PROVIDER[$key]}" "${POLICY_TIME_SOURCE_HOST[$key]}" \
            "${POLICY_TIME_SOURCE_ADDRESS[$key]}" "${POLICY_TIME_SOURCE_TICKET[$key]}" \
            "${POLICY_TIME_SOURCE_APPROVER[$key]}" "${POLICY_TIME_SOURCE_EXPIRES[$key]}"
    done
}

policy_compute_set_digest() {
    local hash_command=""
    local hash_output=""
    local digest=""

    if [ -x /usr/bin/sha256sum ]; then
        hash_command=/usr/bin/sha256sum
    elif [ -x /bin/sha256sum ]; then
        hash_command=/bin/sha256sum
    elif [ -x /usr/bin/shasum ]; then
        hash_command=/usr/bin/shasum
    else
        policy_report_error "cannot compute the policy set digest"
        return 2
    fi
    if [ "${hash_command##*/}" = shasum ]; then
        hash_output="$(policy_write_set_digest_records | "$hash_command" -a 256)" || return 2
    else
        hash_output="$(policy_write_set_digest_records | "$hash_command")" || return 2
    fi
    digest="${hash_output%% *}"
    [ "${#digest}" -eq 64 ] || return 2
    case "$digest" in *[!0-9a-f]*) return 2 ;; esac
    POLICY_SET_DIGEST="sha256:$digest"
}

policy_clear_match_values() {
    POLICY_MATCH_REVIEW_ID=""
    POLICY_MATCH_DECISION=""
    POLICY_MATCH_TICKET=""
    POLICY_MATCH_APPROVER=""
    POLICY_MATCH_EXPIRES=""
}

policy_load_dir() {
    local directory="${1:-}"
    local expected_header=$'code\tdecision\treview_id\tticket\tapprover\texpires'
    local expected_time_source_header=$'provider\thost\taddress\tticket\tapprover\texpires'
    local policy_file=""
    local facts_directory=""
    local facts_file=""
    local facts_entry=""
    local line=""
    local line_number=0
    local code=""
    local decision=""
    local review_id=""
    local provider=""
    local host=""
    local address=""
    local normalized_host=""
    local normalized_address=""
    local time_source_key=""
    local ticket=""
    local approver=""
    local expires=""
    local nullglob_was_set=0
    local dotglob_was_set=0
    local loaded_attestation_count=0
    local loaded_time_source_facts_present=0
    local loaded_time_source_count=0
    local LC_ALL=C
    local -a policy_files=()
    local -a facts_entries=()
    local -A loaded_decision=()
    local -A loaded_review_id=()
    local -A loaded_ticket=()
    local -A loaded_approver=()
    local -A loaded_expires=()
    local -A loaded_time_source_provider=()
    local -A loaded_time_source_host=()
    local -A loaded_time_source_address=()
    local -A loaded_time_source_ticket=()
    local -A loaded_time_source_approver=()
    local -A loaded_time_source_expires=()

    policy_clear_loaded_values
    policy_clear_match_values
    if [ "$#" -ne 1 ] || [ -z "$directory" ]; then
        policy_report_error "policy_load_dir requires one non-empty directory path"
        return 2
    fi
    if declare -F output_path_has_no_symlink_components >/dev/null 2>&1; then
        output_path_has_no_symlink_components "$directory" || {
            policy_report_error "policy directory path contains a symbolic link: $directory"
            return 2
        }
    fi
    if declare -F output_path_components_are_trusted >/dev/null 2>&1; then
        output_path_components_are_trusted "$directory" || {
            policy_report_error "policy directory parent path is not trusted: $directory"
            return 2
        }
    fi
    policy_path_is_trusted "$directory" directory || return 2

    shopt -q nullglob && nullglob_was_set=1
    shopt -s nullglob
    policy_files=("$directory"/*.tsv)
    [ "$nullglob_was_set" -eq 1 ] || shopt -u nullglob

    for policy_file in "${policy_files[@]+"${policy_files[@]}"}"; do
        case "${policy_file##*/}" in
            *$'\n'*|*$'\r'*|*$'\t'*)
                policy_report_error "policy filename contains a control separator: $policy_file"
                return 2
                ;;
        esac
        policy_path_is_trusted "$policy_file" file || return 2
        line_number=0
        while IFS= read -r line || [ -n "$line" ]; do
            line_number=$((line_number + 1))
            if [ "$line_number" -eq 1 ]; then
                if [ "$line" != "$expected_header" ]; then
                    policy_report_error "invalid header at $policy_file:1"
                    return 2
                fi
                continue
            fi
            case "$line" in
                *$'\r'*)
                    policy_report_error "control character in record at $policy_file:$line_number"
                    return 2
                    ;;
            esac
            if ! policy_split_record "$line" code decision review_id ticket approver expires; then
                policy_report_error "record must contain exactly six tab-separated fields at $policy_file:$line_number"
                return 2
            fi
            case "$code$decision$review_id$ticket$approver$expires" in
                *[[:cntrl:]]*)
                    policy_report_error "control character in field at $policy_file:$line_number"
                    return 2
                    ;;
            esac
            if ! policy_code_is_valid "$code"; then
                policy_report_error "invalid criterion code at $policy_file:$line_number"
                return 2
            fi
            case "$decision" in
                GOOD|VULNERABLE) ;;
                *)
                    policy_report_error "invalid decision at $policy_file:$line_number"
                    return 2
                    ;;
            esac
            if ! policy_review_id_is_valid "$review_id"; then
                policy_report_error "invalid review_id at $policy_file:$line_number"
                return 2
            fi
            if [ -z "$ticket" ] || [ -z "$approver" ]; then
                policy_report_error "ticket and approver must be non-empty at $policy_file:$line_number"
                return 2
            fi
            if ! policy_date_is_valid "$expires"; then
                policy_report_error "invalid expiration date at $policy_file:$line_number"
                return 2
            fi
            if [ -n "${loaded_decision[$code]+present}" ]; then
                policy_report_error "duplicate criterion code $code at $policy_file:$line_number"
                return 2
            fi
            loaded_decision["$code"]="$decision"
            loaded_review_id["$code"]="$review_id"
            loaded_ticket["$code"]="$ticket"
            loaded_approver["$code"]="$approver"
            loaded_expires["$code"]="$expires"
            loaded_attestation_count=$((loaded_attestation_count + 1))
        done < "$policy_file"
        if [ "$line_number" -eq 0 ]; then
            policy_report_error "policy file is empty: $policy_file"
            return 2
        fi
    done

    facts_directory="${directory%/}/facts"
    if [ -e "$facts_directory" ] || [ -L "$facts_directory" ]; then
        if declare -F output_path_has_no_symlink_components >/dev/null 2>&1; then
            output_path_has_no_symlink_components "$facts_directory" || {
                policy_report_error "policy facts directory path contains a symbolic link: $facts_directory"
                return 2
            }
        fi
        if declare -F output_path_components_are_trusted >/dev/null 2>&1; then
            output_path_components_are_trusted "$facts_directory" || {
                policy_report_error "policy facts directory parent path is not trusted: $facts_directory"
                return 2
            }
        fi
        policy_path_is_trusted "$facts_directory" directory || return 2

        nullglob_was_set=0
        dotglob_was_set=0
        shopt -q nullglob && nullglob_was_set=1
        shopt -q dotglob && dotglob_was_set=1
        shopt -s nullglob dotglob
        facts_entries=("$facts_directory"/*)
        [ "$nullglob_was_set" -eq 1 ] || shopt -u nullglob
        [ "$dotglob_was_set" -eq 1 ] || shopt -u dotglob
        for facts_entry in "${facts_entries[@]+"${facts_entries[@]}"}"; do
            case "${facts_entry##*/}" in
                time-sources.tsv) ;;
                *)
                    policy_report_error "unsupported policy facts entry: $facts_entry"
                    return 2
                    ;;
            esac
        done

        facts_file="$facts_directory/time-sources.tsv"
        if [ -e "$facts_file" ] || [ -L "$facts_file" ]; then
            policy_path_is_trusted "$facts_file" file || return 2
            loaded_time_source_facts_present=1
            line_number=0
            while IFS= read -r line || [ -n "$line" ]; do
                line_number=$((line_number + 1))
                if [ "$line_number" -eq 1 ]; then
                    if [ "$line" != "$expected_time_source_header" ]; then
                        policy_report_error "invalid header at $facts_file:1"
                        return 2
                    fi
                    continue
                fi
                case "$line" in
                    *$'\r'*)
                        policy_report_error "control character in record at $facts_file:$line_number"
                        return 2
                        ;;
                esac
                if ! policy_split_record "$line" provider host address ticket approver expires; then
                    policy_report_error "record must contain exactly six tab-separated fields at $facts_file:$line_number"
                    return 2
                fi
                case "$provider$host$address$ticket$approver$expires" in
                    *[[:cntrl:]]*)
                        policy_report_error "control character in field at $facts_file:$line_number"
                        return 2
                        ;;
                esac
                if ! policy_time_source_provider_is_valid "$provider"; then
                    policy_report_error "invalid time source provider at $facts_file:$line_number"
                    return 2
                fi
                if ! policy_time_source_host_into normalized_host "$host"; then
                    policy_report_error "invalid time source host at $facts_file:$line_number"
                    return 2
                fi
                if ! policy_time_source_address_into normalized_address "$address"; then
                    policy_report_error "invalid time source address at $facts_file:$line_number"
                    return 2
                fi
                if [ "$normalized_host" = "-" ] && [ "$normalized_address" = "-" ]; then
                    policy_report_error "time source host and address cannot both be absent at $facts_file:$line_number"
                    return 2
                fi
                if [ -z "$ticket" ] || [ -z "$approver" ] ||
                    [ "${#ticket}" -gt 128 ] || [ "${#approver}" -gt 128 ] ||
                    [[ "$ticket" != *[![:space:]]* ]] || [[ "$approver" != *[![:space:]]* ]]; then
                    policy_report_error "ticket and approver must contain 1 to 128 characters at $facts_file:$line_number"
                    return 2
                fi
                if ! policy_date_is_valid "$expires"; then
                    policy_report_error "invalid expiration date at $facts_file:$line_number"
                    return 2
                fi
                policy_time_source_key_into time_source_key "$provider" "$normalized_host" "$normalized_address"
                if [ -n "${loaded_time_source_provider[$time_source_key]+present}" ]; then
                    policy_report_error "duplicate approved time source at $facts_file:$line_number"
                    return 2
                fi
                loaded_time_source_provider["$time_source_key"]="$provider"
                loaded_time_source_host["$time_source_key"]="$normalized_host"
                loaded_time_source_address["$time_source_key"]="$normalized_address"
                loaded_time_source_ticket["$time_source_key"]="$ticket"
                loaded_time_source_approver["$time_source_key"]="$approver"
                loaded_time_source_expires["$time_source_key"]="$expires"
                loaded_time_source_count=$((loaded_time_source_count + 1))
            done < "$facts_file"
            if [ "$line_number" -eq 0 ]; then
                policy_report_error "policy facts file is empty: $facts_file"
                return 2
            fi
        fi
    fi

    if [ "$loaded_attestation_count" -gt 0 ]; then
        for code in "${!loaded_decision[@]}"; do
            POLICY_DECISION["$code"]="${loaded_decision[$code]}"
            POLICY_REVIEW_ID["$code"]="${loaded_review_id[$code]}"
            POLICY_TICKET["$code"]="${loaded_ticket[$code]}"
            POLICY_APPROVER["$code"]="${loaded_approver[$code]}"
            POLICY_EXPIRES["$code"]="${loaded_expires[$code]}"
        done
    fi
    if [ "$loaded_time_source_count" -gt 0 ]; then
        for time_source_key in "${!loaded_time_source_provider[@]}"; do
            POLICY_TIME_SOURCE_PROVIDER["$time_source_key"]="${loaded_time_source_provider[$time_source_key]}"
            POLICY_TIME_SOURCE_HOST["$time_source_key"]="${loaded_time_source_host[$time_source_key]}"
            POLICY_TIME_SOURCE_ADDRESS["$time_source_key"]="${loaded_time_source_address[$time_source_key]}"
            POLICY_TIME_SOURCE_TICKET["$time_source_key"]="${loaded_time_source_ticket[$time_source_key]}"
            POLICY_TIME_SOURCE_APPROVER["$time_source_key"]="${loaded_time_source_approver[$time_source_key]}"
            POLICY_TIME_SOURCE_EXPIRES["$time_source_key"]="${loaded_time_source_expires[$time_source_key]}"
        done
    fi
    POLICY_TIME_SOURCE_FACTS_PRESENT="$loaded_time_source_facts_present"
    POLICY_TIME_SOURCE_COUNT="$loaded_time_source_count"
    policy_compute_set_digest || {
        policy_clear_loaded_values
        return 2
    }
}

policy_time_source_match() {
    local provider="${1:-}"
    local host="${2:-}"
    local address="${3:-}"
    local normalized_host=""
    local normalized_address=""
    local key=""
    local fact_host=""
    local fact_address=""
    local match_key=""
    local match_score=0
    local score=0
    local equal_score_matches=0
    local current_date=""

    policy_clear_time_source_match
    if [ "$#" -ne 3 ] || ! policy_time_source_provider_is_valid "$provider" ||
        ! policy_time_source_host_into normalized_host "$host" ||
        ! policy_time_source_address_into normalized_address "$address" ||
        { [ "$normalized_host" = "-" ] && [ "$normalized_address" = "-" ]; }; then
        POLICY_TIME_SOURCE_MATCH_STATE="error"
        POLICY_TIME_SOURCE_MATCH_REASON="invalid_query"
        POLICY_TIME_SOURCE_MATCH_EVIDENCE="time_source_policy=error,error=invalid_query"
        return 2
    fi
    POLICY_TIME_SOURCE_MATCH_PROVIDER="$provider"
    POLICY_TIME_SOURCE_MATCH_HOST="$normalized_host"
    POLICY_TIME_SOURCE_MATCH_ADDRESS="$normalized_address"
    if [ "$POLICY_TIME_SOURCE_FACTS_PRESENT" -ne 1 ]; then
        POLICY_TIME_SOURCE_MATCH_STATE="absent"
        POLICY_TIME_SOURCE_MATCH_REASON="facts_absent"
        POLICY_TIME_SOURCE_MATCH_EVIDENCE="time_source_policy=absent"
        return 3
    fi

    if [ "$POLICY_TIME_SOURCE_COUNT" -gt 0 ]; then
        for key in "${!POLICY_TIME_SOURCE_PROVIDER[@]}"; do
            [ "${POLICY_TIME_SOURCE_PROVIDER[$key]}" = "$provider" ] || continue
            fact_host="${POLICY_TIME_SOURCE_HOST[$key]}"
            fact_address="${POLICY_TIME_SOURCE_ADDRESS[$key]}"
            score=0
            if [ "$fact_host" != "-" ]; then
                [ "$fact_host" = "$normalized_host" ] || continue
                score=$((score + 1))
            fi
            if [ "$fact_address" != "-" ]; then
                [ "$fact_address" = "$normalized_address" ] || continue
                score=$((score + 1))
            fi
            if [ "$score" -gt "$match_score" ]; then
                match_key="$key"
                match_score="$score"
                equal_score_matches=1
            elif [ "$score" -eq "$match_score" ]; then
                equal_score_matches=$((equal_score_matches + 1))
            fi
        done
    fi
    if [ -z "$match_key" ]; then
        POLICY_TIME_SOURCE_MATCH_STATE="not_approved"
        POLICY_TIME_SOURCE_MATCH_REASON="no_match"
        POLICY_TIME_SOURCE_MATCH_EVIDENCE="time_source_policy=not_approved,provider=${provider},host=${normalized_host},address=${normalized_address}"
        return 1
    fi
    if [ "$equal_score_matches" -ne 1 ]; then
        POLICY_TIME_SOURCE_MATCH_STATE="error"
        POLICY_TIME_SOURCE_MATCH_REASON="ambiguous_match"
        POLICY_TIME_SOURCE_MATCH_EVIDENCE="time_source_policy=error,error=ambiguous_match,provider=${provider},host=${normalized_host},address=${normalized_address}"
        return 2
    fi

    POLICY_TIME_SOURCE_MATCH_PROVIDER="${POLICY_TIME_SOURCE_PROVIDER[$match_key]}"
    POLICY_TIME_SOURCE_MATCH_HOST="${POLICY_TIME_SOURCE_HOST[$match_key]}"
    POLICY_TIME_SOURCE_MATCH_ADDRESS="${POLICY_TIME_SOURCE_ADDRESS[$match_key]}"
    POLICY_TIME_SOURCE_MATCH_TICKET="${POLICY_TIME_SOURCE_TICKET[$match_key]}"
    POLICY_TIME_SOURCE_MATCH_APPROVER="${POLICY_TIME_SOURCE_APPROVER[$match_key]}"
    POLICY_TIME_SOURCE_MATCH_EXPIRES="${POLICY_TIME_SOURCE_EXPIRES[$match_key]}"
    current_date="$(/bin/date -u +%Y-%m-%d 2>/dev/null)" || {
        POLICY_TIME_SOURCE_MATCH_STATE="error"
        POLICY_TIME_SOURCE_MATCH_REASON="date_unavailable"
        POLICY_TIME_SOURCE_MATCH_EVIDENCE="time_source_policy=error,error=date_unavailable"
        return 2
    }
    if ! policy_date_is_valid "$current_date"; then
        POLICY_TIME_SOURCE_MATCH_STATE="error"
        POLICY_TIME_SOURCE_MATCH_REASON="date_invalid"
        POLICY_TIME_SOURCE_MATCH_EVIDENCE="time_source_policy=error,error=date_invalid"
        return 2
    fi
    if [[ "$POLICY_TIME_SOURCE_MATCH_EXPIRES" < "$current_date" ]]; then
        POLICY_TIME_SOURCE_MATCH_STATE="error"
        POLICY_TIME_SOURCE_MATCH_REASON="expired"
        POLICY_TIME_SOURCE_MATCH_EVIDENCE="time_source_policy=error,error=expired,provider=${provider},host=${POLICY_TIME_SOURCE_MATCH_HOST},address=${POLICY_TIME_SOURCE_MATCH_ADDRESS},expires=${POLICY_TIME_SOURCE_MATCH_EXPIRES}"
        return 2
    fi

    POLICY_TIME_SOURCE_MATCH_STATE="approved"
    POLICY_TIME_SOURCE_MATCH_REASON="matched"
    POLICY_TIME_SOURCE_MATCH_EVIDENCE="time_source_policy=approved,provider=${provider},host=${POLICY_TIME_SOURCE_MATCH_HOST},address=${POLICY_TIME_SOURCE_MATCH_ADDRESS},expires=${POLICY_TIME_SOURCE_MATCH_EXPIRES}"
    return 0
}

policy_lookup() {
    local code="${1:-}"
    local review_id="${2:-}"
    local current_date=""

    policy_clear_match_values
    if [ "$#" -ne 2 ] || ! policy_code_is_valid "$code" || ! policy_review_id_is_valid "$review_id"; then
        policy_report_error "policy_lookup requires a valid criterion code and review_id"
        return 2
    fi
    [ -n "${POLICY_DECISION[$code]+present}" ] || return 1
    if [ "${POLICY_REVIEW_ID[$code]}" != "$review_id" ]; then
        policy_report_error "review_id does not match the current review for $code"
        return 2
    fi
    current_date="$(/bin/date -u +%Y-%m-%d 2>/dev/null)" || {
        policy_report_error "cannot determine the current UTC date"
        return 2
    }
    if ! policy_date_is_valid "$current_date"; then
        policy_report_error "the current UTC date is invalid"
        return 2
    fi
    if [[ "${POLICY_EXPIRES[$code]}" < "$current_date" ]]; then
        policy_report_error "policy attestation for $code expired on ${POLICY_EXPIRES[$code]}"
        return 2
    fi

    POLICY_MATCH_REVIEW_ID="${POLICY_REVIEW_ID[$code]}"
    POLICY_MATCH_DECISION="${POLICY_DECISION[$code]}"
    POLICY_MATCH_TICKET="${POLICY_TICKET[$code]}"
    POLICY_MATCH_APPROVER="${POLICY_APPROVER[$code]}"
    POLICY_MATCH_EXPIRES="${POLICY_EXPIRES[$code]}"
    printf '%s\n' "${POLICY_DECISION[$code]}"
}
