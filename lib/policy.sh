# SPDX-License-Identifier: LGPL-3.0-or-later
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

policy_clear_loaded_values() {
    POLICY_DECISION=()
    POLICY_REVIEW_ID=()
    POLICY_TICKET=()
    POLICY_APPROVER=()
    POLICY_EXPIRES=()
    POLICY_SET_DIGEST=""
}

policy_compute_set_digest() {
    local hash_command=""
    local hash_output=""
    local digest=""
    local code=""
    local number=0

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
        hash_output="$({
            for ((number = 1; number <= 67; number++)); do
                printf -v code 'U-%02d' "$number"
                [ -n "${POLICY_DECISION[$code]+present}" ] || continue
                printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$code" \
                    "${POLICY_DECISION[$code]}" "${POLICY_REVIEW_ID[$code]}" \
                    "${POLICY_TICKET[$code]}" "${POLICY_APPROVER[$code]}" "${POLICY_EXPIRES[$code]}"
            done
        } | "$hash_command" -a 256)" || return 2
    else
        hash_output="$({
            for ((number = 1; number <= 67; number++)); do
                printf -v code 'U-%02d' "$number"
                [ -n "${POLICY_DECISION[$code]+present}" ] || continue
                printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$code" \
                    "${POLICY_DECISION[$code]}" "${POLICY_REVIEW_ID[$code]}" \
                    "${POLICY_TICKET[$code]}" "${POLICY_APPROVER[$code]}" "${POLICY_EXPIRES[$code]}"
            done
        } | "$hash_command")" || return 2
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
    local policy_file=""
    local line=""
    local line_number=0
    local code=""
    local decision=""
    local review_id=""
    local ticket=""
    local approver=""
    local expires=""
    local nullglob_was_set=0
    local LC_ALL=C
    local -a policy_files=()
    local -A loaded_decision=()
    local -A loaded_review_id=()
    local -A loaded_ticket=()
    local -A loaded_approver=()
    local -A loaded_expires=()

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

    for policy_file in "${policy_files[@]}"; do
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
        done < "$policy_file"
        if [ "$line_number" -eq 0 ]; then
            policy_report_error "policy file is empty: $policy_file"
            return 2
        fi
    done

    for code in "${!loaded_decision[@]}"; do
        POLICY_DECISION["$code"]="${loaded_decision[$code]}"
        POLICY_REVIEW_ID["$code"]="${loaded_review_id[$code]}"
        POLICY_TICKET["$code"]="${loaded_ticket[$code]}"
        POLICY_APPROVER["$code"]="${loaded_approver[$code]}"
        POLICY_EXPIRES["$code"]="${loaded_expires[$code]}"
    done
    policy_compute_set_digest || {
        policy_clear_loaded_values
        return 2
    }
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
