# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash
# shellcheck disable=SC2034

# Compiles a restricted desired-state YAML profile into a coverage-bound TSV plan.

PATCH_DESIRED_STATE_POLICY_SCHEMA=2
PATCH_DESIRED_STATE_TSV_HEADER=$'profile_id\tmax_risk\tcode\tadapter\trisk\tresolution_requirement\ttransaction_domain\tpostcondition\timplementation_status\tinput_type\tinput_value\tvalidator\trollback_domain'
PATCH_DESIRED_STATE_ERROR_DETAIL=""

_patch_desired_state_set_error() {
    PATCH_DESIRED_STATE_ERROR_DETAIL="$1"
    return 2
}

_patch_desired_state_stat_into() {
    local path="$1"
    local uid_destination="$2"
    local mode_destination="$3"
    local links_destination="$4"
    local output=""
    local stat_uid=""
    local stat_mode=""
    local stat_links=""
    local extra=""

    case "$uid_destination:$mode_destination:$links_destination" in
        *[!A-Za-z0-9_:]*|:*|*:|*::*) return 2 ;;
    esac
    if output="$(/usr/bin/stat -c '%u:%a:%h' -- "$path" 2>/dev/null)"; then
        :
    elif output="$(/usr/bin/stat -f '%u:%p:%l' "$path" 2>/dev/null)"; then
        :
    else
        return 2
    fi
    IFS=: read -r stat_uid stat_mode stat_links extra <<< "$output"
    [ -z "$extra" ] || return 2
    case "$stat_uid:$stat_mode:$stat_links" in *[!0-9:]*) return 2 ;; esac
    printf -v "$uid_destination" '%s' "$stat_uid"
    printf -v "$mode_destination" '%04o' "$((8#$stat_mode & 07777))"
    printf -v "$links_destination" '%s' "$stat_links"
}

_patch_desired_state_parent_chain_is_safe() {
    local path="$1"
    local canonical_path=""
    local current=/
    local relative=""
    local component=""
    local uid=""
    local mode=""
    local links=""
    local -a components=()

    canonical_path="$(CDPATH='' builtin cd -P -- "$path" 2>/dev/null && pwd -P)" || return 2
    relative="${canonical_path#/}"
    IFS=/ read -r -a components <<< "$relative"
    for component in "${components[@]}"; do
        [ -n "$component" ] || continue
        current="${current%/}/$component"
        _patch_desired_state_stat_into "$current" uid mode links || return 2
        [ "$uid" = 0 ] || [ "$uid" = "${EUID:-}" ] || return 2
        if [ $((8#$mode & 0022)) -ne 0 ]; then
            [ "$uid" = 0 ] && [ $((8#$mode & 01000)) -ne 0 ] &&
                { [ "$current" = /tmp ] || [ "$current" = /var/tmp ] ||
                  [ "$current" = /private/tmp ] || [ "$current" = /private/var/tmp ]; } || return 2
        fi
    done
}

_patch_desired_state_directory_is_safe() {
    local path="$1"
    local uid=""
    local mode=""
    local links=""

    [ -d "$path" ] && [ ! -L "$path" ] || return 2
    _patch_desired_state_parent_chain_is_safe "$path" || return 2
    _patch_desired_state_stat_into "$path" uid mode links || return 2
    [ "$uid" = 0 ] || [ "$uid" = "${EUID:-}" ] || return 2
    [ $((8#$mode & 0022)) -eq 0 ]
}

_patch_desired_state_file_is_safe() {
    local path="$1"
    local uid=""
    local mode=""
    local links=""

    case "$path" in /*) ;; *) return 2 ;; esac
    [ -f "$path" ] && [ ! -L "$path" ] && [ -r "$path" ] || return 2
    _patch_desired_state_parent_chain_is_safe "${path%/*}" || return 2
    _patch_desired_state_stat_into "$path" uid mode links || return 2
    [ "$links" = 1 ] && { [ "$uid" = 0 ] || [ "$uid" = "${EUID:-}" ]; } &&
        [ $((8#$mode & 0022)) -eq 0 ]
}

_patch_desired_state_parse_yaml() {
    local input_path="$1"
    local raw_path="$2"
    local error_path="$3"
    local control_status=0
    local ascii_status=0

    LC_ALL=C grep -q '[[:cntrl:]]' "$input_path" 2>/dev/null || control_status=$?
    case "$control_status" in
        0) printf '%s\n' 'line 0: control bytes are not allowed' > "$error_path"; return 2 ;;
        1) ;;
        *) printf '%s\n' 'line 0: input bytes could not be validated' > "$error_path"; return 2 ;;
    esac
    LC_ALL=C grep -q '[^ -~]' "$input_path" 2>/dev/null || ascii_status=$?
    case "$ascii_status" in
        0) printf '%s\n' 'line 0: schema version 2 accepts ASCII bytes only' > "$error_path"; return 2 ;;
        1) ;;
        *) printf '%s\n' 'line 0: input bytes could not be validated' > "$error_path"; return 2 ;;
    esac

    awk -v raw_path="$raw_path" -v error_path="$error_path" '
        function trim(value) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            return value
        }
        function fail(reason) {
            if (!failed) print "line " FNR ": " reason > error_path
            failed=1
            exit 2
        }
        function safe_scalar(value) {
            if (value == "-" || value ~ /^[A-Za-z0-9][A-Za-z0-9._:\/@,+%-]*$/) return 1
            if (value !~ /^\/[A-Za-z0-9._@+%-]+(\/[A-Za-z0-9._@+%-]+)*$/) return 0
            return value !~ /(^|\/)\.{1,2}(\/|$)/ && value !~ /\/\//
        }
        function decode_scalar(raw_value, value) {
            value=trim(raw_value)
            if (value == "") fail("mapping values must be non-empty")
            if (length(value) > 512) fail("mapping value exceeds 512 bytes")
            if (!safe_scalar(value)) fail("mapping value is outside the restricted scalar grammar")
            return value
        }
        function clear_record(key) {
            for (key in record_value) delete record_value[key]
            record_active=0
        }
        function require_field(field_name) {
            if (!(field_name in record_value)) fail("missing " field_name " in desired_states item")
        }
        function emit_record() {
            if (!record_active) return
            require_field("code")
            require_field("adapter")
            require_field("postcondition")
            require_field("input_type")
            require_field("input_value")
            print profile_id "\t" max_risk "\t" record_value["code"] "\t" \
                record_value["adapter"] "\t" record_value["postcondition"] "\t" \
                record_value["input_type"] "\t" record_value["input_value"] >> raw_path
            record_count++
            clear_record()
        }
        function parse_record_mapping(mapping, separator, field_name, raw_value) {
            separator=index(mapping, ":")
            if (separator == 0) fail("mapping entry requires a colon")
            field_name=trim(substr(mapping, 1, separator - 1))
            raw_value=substr(mapping, separator + 1)
            if (field_name !~ /^(code|adapter|postcondition|input_type|input_value)$/) {
                fail("unsupported desired_states key")
            }
            if (field_name in record_value) fail("duplicate key in desired_states item")
            record_value[field_name]=decode_scalar(raw_value)
            record_active=1
        }
        function parse_top_level(line, separator, key, raw_value, value) {
            emit_record()
            separator=index(line, ":")
            if (separator == 0) fail("top-level mapping requires a colon")
            key=trim(substr(line, 1, separator - 1))
            raw_value=substr(line, separator + 1)
            if (key !~ /^(schema_version|profile_id|max_risk|desired_states)$/) {
                fail("unsupported top-level key")
            }
            if (key in top_seen) fail("duplicate top-level key")
            top_seen[key]=1
            if (key == "schema_version") {
                value=decode_scalar(raw_value)
                if (value != "2") fail("schema_version must be 2")
                if (top_count != 0) fail("schema_version must be first")
                schema_seen=1
            } else if (key == "profile_id") {
                if (!schema_seen || desired_seen) fail("profile_id must precede desired_states")
                profile_id=decode_scalar(raw_value)
                if (length(profile_id) > 64) fail("profile_id exceeds 64 bytes")
            } else if (key == "max_risk") {
                if (!schema_seen || desired_seen) fail("max_risk must precede desired_states")
                max_risk=decode_scalar(raw_value)
                if (max_risk !~ /^R[0-4]$/) fail("max_risk must be R0 through R4")
            } else {
                if (!schema_seen || profile_id == "" || max_risk == "") {
                    fail("schema_version, profile_id, and max_risk must precede desired_states")
                }
                value=trim(raw_value)
                if (value != "" && value != "[]") fail("desired_states must be a block list or []")
                desired_seen=1
                desired_empty=(value == "[]")
            }
            top_count++
        }
        BEGIN {
            print "profile_id\tmax_risk\tcode\tadapter\tpostcondition\tinput_type\tinput_value" > raw_path
        }
        {
            total_bytes+=length($0) + 1
            if (total_bytes > 1048576) fail("profile exceeds 1048576 bytes")
            if (length($0) > 4096) fail("line exceeds 4096 bytes")
            if ($0 ~ /^[[:space:]]*$/ || $0 ~ /^[[:space:]]*#/) next
            if ($0 !~ /^ /) {
                parse_top_level($0)
            } else if (!desired_seen || desired_empty) {
                fail("indented content appears outside a desired_states block list")
            } else if ($0 ~ /^  - /) {
                emit_record()
                parse_record_mapping(substr($0, 5))
            } else if ($0 ~ /^    [a-z][a-z0-9_]*:/) {
                if (!record_active) fail("continuation mapping appears before a list item")
                parse_record_mapping(substr($0, 5))
            } else {
                fail("invalid indentation or unsupported YAML construct")
            }
        }
        END {
            if (failed) exit 2
            emit_record()
            if (!schema_seen) fail("schema_version is required")
            if (profile_id == "") fail("profile_id is required")
            if (max_risk == "") fail("max_risk is required")
            if (!desired_seen) fail("desired_states is required")
        }
    ' "$input_path"
}

_patch_desired_state_risk_rank_into() {
    local risk="$1"
    local destination_name="$2"
    local rank=""

    case "$destination_name" in ''|[0-9]*|*[!A-Za-z0-9_]*) return 2 ;; esac
    case "$risk" in
        R0) rank=0 ;;
        R1) rank=1 ;;
        R2) rank=2 ;;
        R3) rank=3 ;;
        R4) rank=4 ;;
        *) return 2 ;;
    esac
    printf -v "$destination_name" '%s' "$rank"
}

_patch_desired_state_validate_and_render() {
    local raw_path="$1"
    local output_path="$2"
    local error_path="$3"
    local header=""
    local profile_id=""
    local max_risk=""
    local code=""
    local requested_adapter=""
    local requested_postcondition=""
    local requested_input_type=""
    local input_value=""
    local extra=""
    local coverage_record=""
    local record_code=""
    local adapter=""
    local risk=""
    local resolution_requirement=""
    local transaction_domain=""
    local postcondition=""
    local implementation_status=""
    local typed_input=""
    local validator=""
    local rollback_domain=""
    local max_rank=0
    local risk_rank=0
    local rows=0
    local -A seen_codes=()

    IFS= read -r header < "$raw_path" || return 2
    [ "$header" = $'profile_id\tmax_risk\tcode\tadapter\tpostcondition\tinput_type\tinput_value' ] || return 2
    printf '%s\n' "$PATCH_DESIRED_STATE_TSV_HEADER" > "$output_path" || return 2
    while IFS=$'\t' read -r profile_id max_risk code requested_adapter requested_postcondition \
        requested_input_type input_value extra; do
        [ -n "$profile_id" ] || continue
        [ -z "$extra" ] || {
            printf '%s\n' "$code: parsed field count is invalid" > "$error_path"
            return 2
        }
        [ -z "${seen_codes[$code]+present}" ] || {
            printf '%s\n' "$code: duplicate desired-state entry" > "$error_path"
            return 2
        }
        seen_codes["$code"]=1
        patch_coverage_record_into "$code" coverage_record || {
            printf '%s\n' "$code: criterion is outside the U-01 through U-67 coverage contract" > "$error_path"
            return 2
        }
        IFS=$'\t' read -r record_code adapter risk resolution_requirement transaction_domain \
            postcondition implementation_status typed_input validator rollback_domain <<< "$coverage_record"
        [ "$record_code" = "$code" ] || return 2
        [ "$requested_adapter" = "$adapter" ] || {
            printf '%s\n' "$code: adapter does not match the coverage contract" > "$error_path"
            return 2
        }
        [ "$requested_postcondition" = "$postcondition" ] || {
            printf '%s\n' "$code: postcondition does not match the coverage contract" > "$error_path"
            return 2
        }
        _patch_desired_state_risk_rank_into "$max_risk" max_rank || return 2
        _patch_desired_state_risk_rank_into "$risk" risk_rank || return 2
        [ "$max_rank" -le 4 ] && [ "$risk_rank" -le "$max_rank" ] || {
            printf '%s\n' "$code: risk exceeds profile max_risk" > "$error_path"
            return 2
        }
        [ "$requested_input_type" = "$typed_input" ] || {
            printf '%s\n' "$code: input_type does not match the coverage contract" > "$error_path"
            return 2
        }
        if [ "$implementation_status" = fixed ]; then
            [ "$typed_input" = none ] || return 2
            [ "$input_value" = - ] || {
                printf '%s\n' "$code: fixed adapter requires input_value '-'" > "$error_path"
                return 2
            }
        elif [ "$implementation_status" = conditional ] || [ "$implementation_status" = gated ]; then
            [ "$typed_input" != none ] || return 2
            [ "$input_value" != - ] || {
                printf '%s\n' "$code: $implementation_status adapter requires a typed input value" > "$error_path"
                return 2
            }
        else
            return 2
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$profile_id" "$max_risk" "$code" "$adapter" "$risk" \
            "$resolution_requirement" "$transaction_domain" "$postcondition" \
            "$implementation_status" "$typed_input" "$input_value" "$validator" \
            "$rollback_domain" >> "$output_path" || return 2
        rows=$((rows + 1))
    done < <(sed -n '2,$p' "$raw_path")
    [ "$rows" -ge 0 ]
}

patch_desired_state_policy_compile() {
    local input_path="$1"
    local output_path="$2"
    local output_parent="${output_path%/*}"
    local output_leaf="${output_path##*/}"
    local canonical_parent=""
    local raw_path=""
    local rendered_path=""
    local error_path=""
    local parse_status=0
    local output_uid=""
    local output_mode=""
    local output_links=""

    PATCH_DESIRED_STATE_ERROR_DETAIL=""
    patch_coverage_validate || {
        _patch_desired_state_set_error "coverage contract is invalid: $PATCH_COVERAGE_ERROR_DETAIL"
        return 2
    }
    _patch_desired_state_file_is_safe "$input_path" || {
        _patch_desired_state_set_error "desired-state policy input is unsafe"
        return 2
    }
    case "$output_path" in /*) ;; *) _patch_desired_state_set_error "output path must be absolute"; return 2 ;; esac
    case "$output_leaf" in ''|.|..|*/*|*$'\n'*|*$'\r'*|*$'\t'*)
        _patch_desired_state_set_error "output path is invalid"
        return 2
        ;;
    esac
    _patch_desired_state_directory_is_safe "$output_parent" || {
        _patch_desired_state_set_error "output directory is unsafe"
        return 2
    }
    canonical_parent="$(CDPATH='' builtin cd -P -- "$output_parent" && pwd -P)" || return 2
    output_path="$canonical_parent/$output_leaf"
    [ ! -e "$output_path" ] && [ ! -L "$output_path" ] || {
        _patch_desired_state_set_error "output file already exists"
        return 2
    }
    raw_path="$(umask 077; mktemp "$canonical_parent/.desired-state-raw.XXXXXXXX")" || return 2
    rendered_path="$(umask 077; mktemp "$canonical_parent/.desired-state-tsv.XXXXXXXX")" || {
        rm -f "$raw_path"
        return 2
    }
    error_path="$(umask 077; mktemp "$canonical_parent/.desired-state-error.XXXXXXXX")" || {
        rm -f "$raw_path" "$rendered_path"
        return 2
    }
    _patch_desired_state_parse_yaml "$input_path" "$raw_path" "$error_path" || parse_status=$?
    if [ "$parse_status" -eq 0 ]; then
        _patch_desired_state_validate_and_render "$raw_path" "$rendered_path" "$error_path" || parse_status=$?
    fi
    if [ "$parse_status" -ne 0 ]; then
        PATCH_DESIRED_STATE_ERROR_DETAIL="$(sed -n '1p' "$error_path")"
        [ -n "$PATCH_DESIRED_STATE_ERROR_DETAIL" ] || PATCH_DESIRED_STATE_ERROR_DETAIL="desired-state policy compilation failed"
        rm -f "$raw_path" "$rendered_path" "$error_path"
        return 2
    fi
    chmod 0600 "$rendered_path" || {
        rm -f "$raw_path" "$rendered_path" "$error_path"
        return 2
    }
    mv "$rendered_path" "$output_path" || {
        rm -f "$raw_path" "$rendered_path" "$error_path"
        return 2
    }
    if ! _patch_desired_state_file_is_safe "$output_path" ||
        ! _patch_desired_state_stat_into "$output_path" output_uid output_mode output_links ||
        [ "$output_mode" != 0600 ] || [ "$output_links" != 1 ]; then
        rm -f "$output_path" "$raw_path" "$error_path"
        _patch_desired_state_set_error "compiled desired-state policy is unsafe"
        return 2
    fi
    rm -f "$raw_path" "$error_path"
}
