# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash

# Compiles a deliberately small YAML subset into the scanner's canonical TSV schemas.

policy_yaml_compile() {
    local input_file="$1"
    local attestation_file="$2"
    local time_source_file="$3"
    local error_file="$4"
    local control_status=0

    LC_ALL=C grep -q '[[:cntrl:]]' "$input_file" 2>/dev/null || control_status=$?
    case "$control_status" in
        0)
            printf '%s\n' 'line 0: control bytes are not allowed' > "$error_file"
            return 2
            ;;
        1) ;;
        *)
            printf '%s\n' 'line 0: input bytes could not be validated' > "$error_file"
            return 2
            ;;
    esac

    awk -v attestation_file="$attestation_file" -v time_source_file="$time_source_file" \
        -v error_file="$error_file" '
        function trim(value) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            return value
        }
        function utf8_valid(value, value_length, index_value, byte_value, second_byte, remaining) {
            value_length=length(value)
            for (index_value=1; index_value<=value_length; index_value++) {
                byte_value=byte_code[substr(value, index_value, 1)]
                if (byte_value <= 127) continue
                if (byte_value >= 194 && byte_value <= 223) {
                    if (index_value + 1 > value_length) return 0
                    second_byte=byte_code[substr(value, index_value + 1, 1)]
                    if (byte_value == 194 && second_byte >= 128 && second_byte <= 159) return 0
                    remaining=1
                } else if (byte_value >= 224 && byte_value <= 239) {
                    if (index_value + 1 > value_length) return 0
                    second_byte=byte_code[substr(value, index_value + 1, 1)]
                    if (byte_value == 224 && (second_byte < 160 || second_byte > 191)) return 0
                    if (byte_value == 237 && (second_byte < 128 || second_byte > 159)) return 0
                    if (byte_value != 224 && byte_value != 237 && (second_byte < 128 || second_byte > 191)) return 0
                    remaining=2
                } else if (byte_value >= 240 && byte_value <= 244) {
                    if (index_value + 1 > value_length) return 0
                    second_byte=byte_code[substr(value, index_value + 1, 1)]
                    if (byte_value == 240 && (second_byte < 144 || second_byte > 191)) return 0
                    if (byte_value == 244 && (second_byte < 128 || second_byte > 143)) return 0
                    if (byte_value != 240 && byte_value != 244 && (second_byte < 128 || second_byte > 191)) return 0
                    remaining=3
                } else {
                    return 0
                }
                while (remaining > 0) {
                    index_value++
                    if (index_value > value_length) return 0
                    byte_value=byte_code[substr(value, index_value, 1)]
                    if (byte_value < 128 || byte_value > 191) return 0
                    remaining--
                }
            }
            return 1
        }
        function fail(reason) {
            if (!failed) print "line " FNR ": " reason > error_file
            failed=1
            exit 2
        }
        function clear_record(key) {
            for (key in record_value) delete record_value[key]
            record_active=0
        }
        function field_allowed(section_name, field_name) {
            if (section_name == "attestations") {
                return field_name ~ /^(code|decision|review_id|ticket|approver|expires)$/
            }
            if (section_name == "time_sources") {
                return field_name ~ /^(provider|host|address|ticket|approver|expires)$/
            }
            return 0
        }
        function decode_scalar(raw_value, first, last, inner, result, index_value, character, next_character, quote) {
            raw_value=trim(raw_value)
            if (raw_value == "") fail("mapping values must be non-empty")
            first=substr(raw_value, 1, 1)
            last=substr(raw_value, length(raw_value), 1)
            quote=sprintf("%c", 39)
            if (first == "\"") {
                if (length(raw_value) < 2 || last != "\"") fail("unterminated double-quoted scalar")
                inner=substr(raw_value, 2, length(raw_value) - 2)
                result=""
                for (index_value=1; index_value<=length(inner); index_value++) {
                    character=substr(inner, index_value, 1)
                    if (character == "\\") {
                        index_value++
                        if (index_value > length(inner)) fail("unterminated quoted escape")
                        next_character=substr(inner, index_value, 1)
                        if (next_character != "\\" && next_character != "\"") {
                            fail("only double-quote and backslash escapes are supported")
                        }
                        result=result next_character
                    } else if (character == "\"") {
                        fail("unescaped double quote in scalar")
                    } else {
                        result=result character
                    }
                }
                if (result == "") fail("mapping values must be non-empty")
                return result
            }
            if (first == quote) {
                if (length(raw_value) < 2 || last != quote) fail("unterminated single-quoted scalar")
                inner=substr(raw_value, 2, length(raw_value) - 2)
                result=""
                for (index_value=1; index_value<=length(inner); index_value++) {
                    character=substr(inner, index_value, 1)
                    if (character == quote) {
                        if (substr(inner, index_value + 1, 1) != quote) fail("single quote must be doubled")
                        result=result quote
                        index_value++
                    } else {
                        result=result character
                    }
                }
                if (result == "") fail("mapping values must be non-empty")
                return result
            }
            if (index("[]{}&*!|>@`#%", first) > 0 || raw_value ~ /:[[:space:]]/ || raw_value ~ /[[:space:]]#/) {
                fail("ambiguous plain scalar must be quoted")
            }
            if (first == "\"" || first == quote || last == "\"" || last == quote) {
                fail("mismatched scalar quote")
            }
            return raw_value
        }
        function parse_mapping(mapping, expected_indent, separator, field_name, raw_value) {
            separator=index(mapping, ":")
            if (separator == 0) fail("mapping entry requires a colon")
            field_name=trim(substr(mapping, 1, separator - 1))
            raw_value=substr(mapping, separator + 1)
            if (field_name !~ /^[a-z][a-z0-9_]*$/) fail("invalid mapping key")
            if (!field_allowed(section, field_name)) fail("unsupported key in " section)
            if (field_name in record_value) fail("duplicate key in list item")
            record_value[field_name]=decode_scalar(raw_value)
            record_active=1
        }
        function require_field(field_name) {
            if (!(field_name in record_value)) fail("missing " field_name " in " section " item")
        }
        function emit_record() {
            if (!record_active) return
            if (section == "attestations") {
                require_field("code")
                require_field("decision")
                require_field("review_id")
                require_field("ticket")
                require_field("approver")
                require_field("expires")
                print record_value["code"] "\t" record_value["decision"] "\t" \
                    record_value["review_id"] "\t" record_value["ticket"] "\t" \
                    record_value["approver"] "\t" record_value["expires"] >> attestation_file
            } else if (section == "time_sources") {
                require_field("provider")
                require_field("host")
                require_field("address")
                require_field("ticket")
                require_field("approver")
                require_field("expires")
                print record_value["provider"] "\t" record_value["host"] "\t" \
                    record_value["address"] "\t" record_value["ticket"] "\t" \
                    record_value["approver"] "\t" record_value["expires"] >> time_source_file
            } else {
                fail("list item appears outside a supported section")
            }
            clear_record()
        }
        function parse_top_level(value, separator, key, remainder) {
            emit_record()
            separator=index(value, ":")
            if (separator == 0) fail("top-level mapping requires a colon")
            key=trim(substr(value, 1, separator - 1))
            remainder=trim(substr(value, separator + 1))
            if (key !~ /^(schema_version|attestations|time_sources)$/) fail("unsupported top-level key")
            if (key in top_seen) fail("duplicate top-level key")
            top_seen[key]=1
            if (key == "schema_version") {
                if (remainder != "1") fail("schema_version must be 1")
                schema_seen=1
                section=""
                return
            }
            if (!schema_seen) fail("schema_version must precede policy sections")
            if (remainder != "" && remainder != "[]") fail("policy section must be a block list or []")
            section=key
            section_empty=(remainder == "[]")
            if (key == "attestations") {
                attestations_seen=1
            } else {
                time_sources_seen=1
                print "provider\thost\taddress\tticket\tapprover\texpires" > time_source_file
            }
        }
        BEGIN {
            for (byte_value=1; byte_value<=255; byte_value++) byte_code[sprintf("%c", byte_value)]=byte_value
            print "code\tdecision\treview_id\tticket\tapprover\texpires" > attestation_file
        }
        {
            line=$0
            if (!utf8_valid(line)) fail("invalid UTF-8")
            if (length(line) > 4096) fail("line exceeds 4096 bytes")
            if (line ~ /\r/ || line ~ /\t/) fail("tabs and carriage returns are not allowed")
            if (line ~ /^[[:space:]]*$/ || line ~ /^[[:space:]]*#/) next
            if (line !~ /^ /) {
                parse_top_level(line)
                next
            }
            if (section == "") fail("indented content appears outside a policy section")
            if (section_empty) fail("an explicit empty section cannot contain list items")
            if (line ~ /^  - /) {
                emit_record()
                parse_mapping(substr(line, 5))
            } else if (line ~ /^    [a-z][a-z0-9_]*:/) {
                if (!record_active) fail("continuation mapping appears before a list item")
                parse_mapping(substr(line, 5))
            } else {
                fail("invalid indentation or unsupported YAML construct")
            }
        }
        END {
            if (failed) exit 2
            emit_record()
            if (!schema_seen) fail("schema_version is required")
            if (!attestations_seen) fail("attestations section is required")
        }
    ' "$input_file"
}
