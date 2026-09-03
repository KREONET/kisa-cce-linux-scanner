# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash

# shellcheck disable=SC2034

# Validates and exposes a versioned owner-only runtime evidence directory.

EVIDENCE_BUNDLE_DIRECTORY=""
EVIDENCE_VALIDATION_ERROR=""
EVIDENCE_SCHEMA_VERSION=""
EVIDENCE_CAPTURED_AT=""
EVIDENCE_MACHINE_ID=""
EVIDENCE_BOOT_ID=""
EVIDENCE_KERNEL_RELEASE=""
EVIDENCE_BUNDLE_DIGEST=""
EVIDENCE_AGE_SECONDS=""
EVIDENCE_MANIFEST_PATH=""
EVIDENCE_CHECKSUMS_PATH=""
EVIDENCE_IDENTITY_OS_RELEASE_PATH=""
EVIDENCE_IDENTITY_MACHINE_ID_PATH=""
EVIDENCE_IDENTITY_BOOT_ID_PATH=""
EVIDENCE_IDENTITY_KERNEL_RELEASE_PATH=""
EVIDENCE_RUNTIME_SYSTEMD_UNITS_PATH=""
EVIDENCE_RUNTIME_SYSTEMD_UNIT_FILES_PATH=""
EVIDENCE_RUNTIME_LISTENERS_PATH=""
EVIDENCE_RUNTIME_MOUNTINFO_PATH=""
EVIDENCE_RUNTIME_FIREWALL_PATH=""
EVIDENCE_RUNTIME_TIME_SYNC_PATH=""
EVIDENCE_RUNTIME_SYSTEMD_UNITS_STATUS=""
EVIDENCE_RUNTIME_SYSTEMD_UNIT_FILES_STATUS=""
EVIDENCE_RUNTIME_LISTENERS_STATUS=""
EVIDENCE_RUNTIME_MOUNTINFO_STATUS=""
EVIDENCE_RUNTIME_FIREWALL_STATUS=""
EVIDENCE_RUNTIME_TIME_SYNC_STATUS=""
EVIDENCE_SERVICE_ACTIVATION_EVIDENCE=""

evidence_fail() {
    local message="$*"

    # Failed validation clears every path so callers cannot consume a partially checked bundle.
    evidence_reset
    EVIDENCE_VALIDATION_ERROR="$message"
    return 1
}

evidence_reset() {
    EVIDENCE_BUNDLE_DIRECTORY=""
    EVIDENCE_VALIDATION_ERROR=""
    EVIDENCE_SCHEMA_VERSION=""
    EVIDENCE_CAPTURED_AT=""
    EVIDENCE_MACHINE_ID=""
    EVIDENCE_BOOT_ID=""
    EVIDENCE_KERNEL_RELEASE=""
    EVIDENCE_BUNDLE_DIGEST=""
    EVIDENCE_AGE_SECONDS=""
    EVIDENCE_MANIFEST_PATH=""
    EVIDENCE_CHECKSUMS_PATH=""
    EVIDENCE_IDENTITY_OS_RELEASE_PATH=""
    EVIDENCE_IDENTITY_MACHINE_ID_PATH=""
    EVIDENCE_IDENTITY_BOOT_ID_PATH=""
    EVIDENCE_IDENTITY_KERNEL_RELEASE_PATH=""
    EVIDENCE_RUNTIME_SYSTEMD_UNITS_PATH=""
    EVIDENCE_RUNTIME_SYSTEMD_UNIT_FILES_PATH=""
    EVIDENCE_RUNTIME_LISTENERS_PATH=""
    EVIDENCE_RUNTIME_MOUNTINFO_PATH=""
    EVIDENCE_RUNTIME_FIREWALL_PATH=""
    EVIDENCE_RUNTIME_TIME_SYNC_PATH=""
    EVIDENCE_RUNTIME_SYSTEMD_UNITS_STATUS=""
    EVIDENCE_RUNTIME_SYSTEMD_UNIT_FILES_STATUS=""
    EVIDENCE_RUNTIME_LISTENERS_STATUS=""
    EVIDENCE_RUNTIME_MOUNTINFO_STATUS=""
    EVIDENCE_RUNTIME_FIREWALL_STATUS=""
    EVIDENCE_RUNTIME_TIME_SYNC_STATUS=""
    EVIDENCE_SERVICE_ACTIVATION_EVIDENCE=""
}

evidence_stat() {
    if stat -c '%a %u %h' -- "$1" >/dev/null 2>&1; then
        stat -c '%a %u %h' -- "$1" 2>/dev/null
    else
        stat -f '%Lp %u %l' -- "$1" 2>/dev/null
    fi
}

evidence_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -- "$1" 2>/dev/null | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -- "$1" 2>/dev/null | awk '{print $1}'
    else
        return 1
    fi
}

evidence_read_one_line() {
    local file="$1"
    local value=""
    local line_count=0

    line_count="$(wc -l < "$file" 2>/dev/null)" || return 1
    [ "$line_count" -eq 1 ] || return 1
    IFS= read -r value < "$file" || return 1
    printf '%s\n' "$value"
}

evidence_resolve_root_file_into() {
    local root="$1"
    local logical_path="$2"
    local destination="$3"
    local physical_path=""
    local link_target=""
    local component=""
    local relative_path=""
    local canonical_root=""
    local canonical_parent=""
    local depth=0
    local -a components=()
    local -a resolved_components=()
    local -a target_components=()
    local -a remaining_components=()

    case "$destination" in
        ''|[0-9]*|*[!0-9A-Za-z_]*) return 2 ;;
    esac
    printf -v "$destination" '%s' ""
    case "$logical_path" in
        /*) ;;
        *) return 2 ;;
    esac
    canonical_root="$(CDPATH='' cd -P -- "$root" 2>/dev/null && pwd)" || return 2
    IFS='/' read -r -a components <<< "$logical_path"

    # Each component is resolved as root-relative so an intermediate link cannot escape the image.
    while [ "${#components[@]}" -gt 0 ]; do
        component="${components[0]}"
        components=("${components[@]:1}")
        case "$component" in
            ''|.) continue ;;
            ..)
                [ "${#resolved_components[@]}" -gt 0 ] || return 2
                unset 'resolved_components[${#resolved_components[@]}-1]'
                continue
                ;;
        esac

        relative_path="/$(IFS=/; printf '%s' "${resolved_components[*]}${resolved_components[*]:+/}$component")"
        physical_path="${root%/}$relative_path"
        if [ -L "$physical_path" ]; then
            depth=$((depth + 1))
            [ "$depth" -le 40 ] || return 2
            link_target="$(readlink "$physical_path" 2>/dev/null)" || return 2
            case "$link_target" in
                ''|*$'\n'*|*$'\r'*|*$'\t'*) return 2 ;;
            esac
            remaining_components=("${components[@]}")
            IFS='/' read -r -a target_components <<< "$link_target"
            if [ "${link_target#/}" != "$link_target" ]; then
                resolved_components=()
            fi
            components=("${target_components[@]}" "${remaining_components[@]}")
            continue
        fi

        if [ "${#components[@]}" -gt 0 ]; then
            [ -d "$physical_path" ] || return 1
        fi
        resolved_components+=("$component")
    done

    [ "${#resolved_components[@]}" -gt 0 ] || return 1
    relative_path="/$(IFS=/; printf '%s' "${resolved_components[*]}")"
    physical_path="${root%/}$relative_path"
    [ -f "$physical_path" ] && [ ! -L "$physical_path" ] || return 1
    canonical_parent="$(CDPATH='' cd -P -- "${physical_path%/*}" 2>/dev/null && pwd)" || return 2
    if [ "$canonical_root" != "/" ]; then
        case "$canonical_parent" in
            "$canonical_root"|"$canonical_root"/*) ;;
            *) return 2 ;;
        esac
    fi
    printf -v "$destination" '%s' "$physical_path"
    return 0
}

validate_evidence_bundle() {
    local bundle="${1:-}"
    local expected_root="${2:-}"
    local canonical_bundle=""
    local metadata=""
    local mode=""
    local owner=""
    local link_count=""
    local current_uid=""
    local relative_path=""
    local file=""
    local key=""
    local value=""
    local manifest_line=""
    local line_number=0
    local expected_machine_id_path=""
    local expected_os_release_path=""
    local expected_machine_id=""
    local expected_hash=""
    local actual_hash=""
    local checksum_path=""
    local checksum_line=""
    local seen_checksum_count=0
    local -a expected_manifest_keys=()
    local -A expected_entries=()
    local -A seen_entries=()
    local -A manifest_values=()
    local -A expected_checksum_paths=()
    local -A seen_checksums=()

    evidence_reset
    [ -n "$bundle" ] || { evidence_fail "evidence directory path is empty"; return 1; }
    case "$bundle" in
        /*) ;;
        *) evidence_fail "evidence directory must be an absolute path"; return 1 ;;
    esac
    case "$bundle" in
        *$'\n'*|*$'\r'*|*$'\t'*|*/../*|*/..|*/./*|*/.)
            evidence_fail "evidence directory path is unsafe"
            return 1
            ;;
    esac
    while [ "$bundle" != "/" ] && [ "${bundle%/}" != "$bundle" ]; do
        bundle="${bundle%/}"
    done
    [ -d "$bundle" ] && [ ! -L "$bundle" ] || {
        evidence_fail "evidence path is not a physical directory"
        return 1
    }
    canonical_bundle="$(CDPATH='' cd -P -- "$bundle" 2>/dev/null && pwd)" || {
        evidence_fail "cannot inspect the evidence directory"
        return 1
    }
    [ "$canonical_bundle" = "$bundle" ] || {
        evidence_fail "evidence directory path cannot contain symbolic links"
        return 1
    }

    current_uid="$(id -u)" || { evidence_fail "cannot determine the current user ID"; return 1; }
    metadata="$(evidence_stat "$bundle")" || { evidence_fail "cannot read evidence directory metadata"; return 1; }
    read -r mode owner link_count <<< "$metadata"
    [ "$mode" = "700" ] && [ "$owner" = "$current_uid" ] || {
        evidence_fail "evidence directory must be owned by the current user and have mode 0700"
        return 1
    }

    expected_entries[identity]="directory"
    expected_entries[runtime]="directory"
    expected_entries[manifest.tsv]="file"
    expected_entries[checksums.sha256]="file"
    expected_entries[identity/os-release]="file"
    expected_entries[identity/machine-id]="file"
    expected_entries[identity/boot-id]="file"
    expected_entries[identity/kernel-release]="file"
    expected_entries[runtime/systemd-units.tsv]="file"
    expected_entries[runtime/systemd-unit-files.tsv]="file"
    expected_entries[runtime/listeners.tsv]="file"
    expected_entries[runtime/mountinfo]="file"
    expected_entries[runtime/firewall.txt]="file"
    expected_entries[runtime/time-sync.txt]="file"

    while IFS= read -r -d '' file; do
        relative_path="${file#"$bundle"/}"
        [ -n "${expected_entries[$relative_path]+present}" ] || {
            evidence_fail "evidence directory contains a disallowed entry: $relative_path"
            return 1
        }
        [ -z "${seen_entries[$relative_path]+present}" ] || {
            evidence_fail "evidence directory contains a duplicate entry: $relative_path"
            return 1
        }
        seen_entries["$relative_path"]=1
        case "${expected_entries[$relative_path]}" in
            directory)
                [ -d "$file" ] && [ ! -L "$file" ] || {
                    evidence_fail "evidence subpath is not a physical directory: $relative_path"
                    return 1
                }
                metadata="$(evidence_stat "$file")" || { evidence_fail "cannot read evidence directory metadata: $relative_path"; return 1; }
                read -r mode owner link_count <<< "$metadata"
                [ "$mode" = "700" ] && [ "$owner" = "$current_uid" ] || {
                    evidence_fail "invalid evidence subdirectory permissions or owner: $relative_path"
                    return 1
                }
                ;;
            file)
                [ -f "$file" ] && [ ! -L "$file" ] || {
                    evidence_fail "evidence entry is not a regular file: $relative_path"
                    return 1
                }
                metadata="$(evidence_stat "$file")" || { evidence_fail "cannot read evidence file metadata: $relative_path"; return 1; }
                read -r mode owner link_count <<< "$metadata"
                [ "$mode" = "600" ] && [ "$owner" = "$current_uid" ] && [ "$link_count" = "1" ] || {
                    evidence_fail "invalid evidence file permissions, owner, or link count: $relative_path"
                    return 1
                }
                [ "$(wc -c < "$file" 2>/dev/null)" -le 67108864 ] || {
                    evidence_fail "evidence file exceeds the size limit: $relative_path"
                    return 1
                }
                ;;
        esac
    done < <(find "$bundle" -mindepth 1 -print0 2>/dev/null)

    for relative_path in "${!expected_entries[@]}"; do
        [ -n "${seen_entries[$relative_path]+present}" ] || {
            evidence_fail "required evidence entry is missing: $relative_path"
            return 1
        }
    done

    EVIDENCE_MANIFEST_PATH="$bundle/manifest.tsv"
    EVIDENCE_CHECKSUMS_PATH="$bundle/checksums.sha256"
    EVIDENCE_IDENTITY_OS_RELEASE_PATH="$bundle/identity/os-release"
    EVIDENCE_IDENTITY_MACHINE_ID_PATH="$bundle/identity/machine-id"
    EVIDENCE_IDENTITY_BOOT_ID_PATH="$bundle/identity/boot-id"
    EVIDENCE_IDENTITY_KERNEL_RELEASE_PATH="$bundle/identity/kernel-release"
    EVIDENCE_RUNTIME_SYSTEMD_UNITS_PATH="$bundle/runtime/systemd-units.tsv"
    EVIDENCE_RUNTIME_SYSTEMD_UNIT_FILES_PATH="$bundle/runtime/systemd-unit-files.tsv"
    EVIDENCE_RUNTIME_LISTENERS_PATH="$bundle/runtime/listeners.tsv"
    EVIDENCE_RUNTIME_MOUNTINFO_PATH="$bundle/runtime/mountinfo"
    EVIDENCE_RUNTIME_FIREWALL_PATH="$bundle/runtime/firewall.txt"
    EVIDENCE_RUNTIME_TIME_SYNC_PATH="$bundle/runtime/time-sync.txt"

    expected_manifest_keys=(
        schema_version captured_at machine_id boot_id kernel_release
        identity_os_release_status identity_machine_id_status identity_boot_id_status
        identity_kernel_release_status runtime_systemd_units_status
        runtime_systemd_unit_files_status runtime_listeners_status runtime_mountinfo_status
        runtime_firewall_status runtime_time_sync_status
    )
    while IFS= read -r manifest_line || [ -n "$manifest_line" ]; do
        line_number=$((line_number + 1))
        case "$manifest_line" in
            *$'\t'*)
                key="${manifest_line%%$'\t'*}"
                value="${manifest_line#*$'\t'}"
                ;;
            *) key=""; value="" ;;
        esac
        [ -n "$key" ] && [ -n "$value" ] || {
            evidence_fail "manifest.tsv line $line_number is not strict key/value TSV"
            return 1
        }
        case "$value" in
            *$'\t'*)
                evidence_fail "manifest.tsv line $line_number is not strict key/value TSV"
                return 1
                ;;
        esac
        case "$key" in
            schema_version|captured_at|machine_id|boot_id|kernel_release|identity_os_release_status|identity_machine_id_status|identity_boot_id_status|identity_kernel_release_status|runtime_systemd_units_status|runtime_systemd_unit_files_status|runtime_listeners_status|runtime_mountinfo_status|runtime_firewall_status|runtime_time_sync_status) ;;
            *) evidence_fail "manifest.tsv contains an unknown key: $key"; return 1 ;;
        esac
        [ -z "${manifest_values[$key]+present}" ] || {
            evidence_fail "manifest.tsv contains a duplicate key: $key"
            return 1
        }
        manifest_values["$key"]="$value"
    done < "$EVIDENCE_MANIFEST_PATH"
    for key in "${expected_manifest_keys[@]}"; do
        [ -n "${manifest_values[$key]+present}" ] || {
            evidence_fail "manifest.tsv is missing a required key: $key"
            return 1
        }
    done
    [ "$line_number" -eq "${#expected_manifest_keys[@]}" ] || {
        evidence_fail "manifest.tsv line count does not match the schema"
        return 1
    }

    [ "${manifest_values[schema_version]}" = "1" ] || { evidence_fail "unsupported evidence schema"; return 1; }
    [[ "${manifest_values[captured_at]}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || {
        evidence_fail "manifest.tsv has an invalid captured_at value"
        return 1
    }
    [[ "${manifest_values[machine_id]}" =~ ^[0-9a-f]{32}$ ]] &&
        [ "${manifest_values[machine_id]}" != "00000000000000000000000000000000" ] || {
        evidence_fail "manifest.tsv has an invalid machine_id value"
        return 1
    }
    [[ "${manifest_values[boot_id]}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || {
        evidence_fail "manifest.tsv has an invalid boot_id value"
        return 1
    }
    [[ "${manifest_values[kernel_release]}" =~ ^[0-9A-Za-z._+~-]+$ ]] || {
        evidence_fail "manifest.tsv has an invalid kernel_release value"
        return 1
    }
    for key in identity_os_release_status identity_machine_id_status identity_boot_id_status identity_kernel_release_status; do
        [ "${manifest_values[$key]}" = "collected" ] || {
            evidence_fail "required identity evidence status is not collected: $key"
            return 1
        }
    done
    for key in runtime_systemd_units_status runtime_systemd_unit_files_status runtime_listeners_status runtime_mountinfo_status runtime_firewall_status runtime_time_sync_status; do
        case "${manifest_values[$key]}" in
            collected|partial|unavailable) ;;
            *) evidence_fail "invalid runtime evidence status: $key"; return 1 ;;
        esac
    done

    [ "$(evidence_read_one_line "$EVIDENCE_IDENTITY_MACHINE_ID_PATH")" = "${manifest_values[machine_id]}" ] || {
        evidence_fail "machine-id file does not match manifest.tsv"
        return 1
    }
    [ "$(evidence_read_one_line "$EVIDENCE_IDENTITY_BOOT_ID_PATH")" = "${manifest_values[boot_id]}" ] || {
        evidence_fail "boot-id file does not match manifest.tsv"
        return 1
    }
    [ "$(evidence_read_one_line "$EVIDENCE_IDENTITY_KERNEL_RELEASE_PATH")" = "${manifest_values[kernel_release]}" ] || {
        evidence_fail "kernel-release file does not match manifest.tsv"
        return 1
    }
    [ -s "$EVIDENCE_IDENTITY_OS_RELEASE_PATH" ] || { evidence_fail "os-release evidence is empty"; return 1; }

    expected_checksum_paths[manifest.tsv]=1
    expected_checksum_paths[identity/os-release]=1
    expected_checksum_paths[identity/machine-id]=1
    expected_checksum_paths[identity/boot-id]=1
    expected_checksum_paths[identity/kernel-release]=1
    expected_checksum_paths[runtime/systemd-units.tsv]=1
    expected_checksum_paths[runtime/systemd-unit-files.tsv]=1
    expected_checksum_paths[runtime/listeners.tsv]=1
    expected_checksum_paths[runtime/mountinfo]=1
    expected_checksum_paths[runtime/firewall.txt]=1
    expected_checksum_paths[runtime/time-sync.txt]=1
    while IFS= read -r checksum_line || [ -n "$checksum_line" ]; do
        [[ "$checksum_line" =~ ^([0-9a-f]{64})\ \ ([0-9A-Za-z._/-]+)$ ]] || {
            evidence_fail "invalid checksums.sha256 format"
            return 1
        }
        expected_hash="${BASH_REMATCH[1]}"
        checksum_path="${BASH_REMATCH[2]}"
        [ -n "${expected_checksum_paths[$checksum_path]+present}" ] || {
            evidence_fail "checksums.sha256 contains a disallowed path: $checksum_path"
            return 1
        }
        [ -z "${seen_checksums[$checksum_path]+present}" ] || {
            evidence_fail "checksums.sha256 contains a duplicate path: $checksum_path"
            return 1
        }
        seen_checksums["$checksum_path"]=1
        actual_hash="$(evidence_sha256 "$bundle/$checksum_path")" || {
            evidence_fail "no SHA-256 implementation is available"
            return 1
        }
        [ "$actual_hash" = "$expected_hash" ] || {
            evidence_fail "evidence checksum mismatch: $checksum_path"
            return 1
        }
        seen_checksum_count=$((seen_checksum_count + 1))
    done < "$EVIDENCE_CHECKSUMS_PATH"
    [ "$seen_checksum_count" -eq "${#expected_checksum_paths[@]}" ] || {
        evidence_fail "checksums.sha256 is missing a required path"
        return 1
    }

    [ "$(head -n 1 "$EVIDENCE_RUNTIME_SYSTEMD_UNITS_PATH")" = $'unit\tload_state\tactive_state\tsub_state\tunit_file_state' ] || {
        evidence_fail "invalid systemd-units.tsv header"
        return 1
    }
    [ "$(head -n 1 "$EVIDENCE_RUNTIME_SYSTEMD_UNIT_FILES_PATH")" = $'unit\tunit_file_state\tpreset' ] || {
        evidence_fail "invalid systemd-unit-files.tsv header"
        return 1
    }
    [ "$(head -n 1 "$EVIDENCE_RUNTIME_LISTENERS_PATH")" = $'transport\tlocal_address\tport\tprocess' ] || {
        evidence_fail "invalid listeners.tsv header"
        return 1
    }
    awk -F '\t' '
        NR == 1 {next}
        NF != 5 || $1 == "" ||
            $1 !~ /^([0-9A-Za-z_.@:+~-]|\\x[0-9A-Fa-f][0-9A-Fa-f])+\.(service|socket)$/ ||
            $2 !~ /^[0-9A-Za-z_.:+~-]+$/ || $3 !~ /^[0-9A-Za-z_.:+~-]+$/ ||
            $4 !~ /^[0-9A-Za-z_.:+~-]+$/ || $5 !~ /^[0-9A-Za-z_.:+~-]+$/ {exit 1}
    ' "$EVIDENCE_RUNTIME_SYSTEMD_UNITS_PATH" || {
        evidence_fail "invalid systemd-units.tsv data"
        return 1
    }
    awk -F '\t' '
        NR == 1 {next}
        NF != 3 || $1 == "" ||
            $1 !~ /^([0-9A-Za-z_.@:+~-]|\\x[0-9A-Fa-f][0-9A-Fa-f])+\.(service|socket)$/ ||
            $2 !~ /^[0-9A-Za-z_.:+~-]+$/ || $3 !~ /^[-0-9A-Za-z_.:+~]+$/ {exit 1}
    ' "$EVIDENCE_RUNTIME_SYSTEMD_UNIT_FILES_PATH" || {
        evidence_fail "invalid systemd-unit-files.tsv data"
        return 1
    }
    awk -F '\t' '
        NR == 1 {next}
        NF != 4 || ($1 != "tcp" && $1 != "udp") ||
            $2 !~ /^[0-9A-Za-z_.:%*@+-]+$/ ||
            $3 !~ /^[0-9]+$/ || $3 < 0 || $3 > 65535 ||
            $4 !~ /^[0-9A-Za-z_.@:+-]*$/ {exit 1}
    ' "$EVIDENCE_RUNTIME_LISTENERS_PATH" || {
        evidence_fail "invalid listeners.tsv data"
        return 1
    }

    if [ -n "$expected_root" ]; then
        case "$expected_root" in
            /*) ;;
            *) evidence_fail "scan root must be an absolute path"; return 1 ;;
        esac
        while [ "$expected_root" != "/" ] && [ "${expected_root%/}" != "$expected_root" ]; do
            expected_root="${expected_root%/}"
        done
        [ -d "$expected_root" ] || { evidence_fail "scan root is not a directory"; return 1; }
        evidence_resolve_root_file_into "$expected_root" /etc/machine-id expected_machine_id_path || {
            evidence_fail "cannot read the scan root machine-id safely"
            return 1
        }
        expected_machine_id="$(evidence_read_one_line "$expected_machine_id_path")" || {
            evidence_fail "scan root machine-id has an invalid format"
            return 1
        }
        [ "$expected_machine_id" = "${manifest_values[machine_id]}" ] || {
            evidence_fail "evidence bundle machine-id does not match the scan root"
            return 1
        }
        if ! evidence_resolve_root_file_into "$expected_root" /etc/os-release expected_os_release_path; then
            evidence_resolve_root_file_into "$expected_root" /usr/lib/os-release expected_os_release_path || {
                evidence_fail "cannot read the scan root os-release safely"
                return 1
            }
        fi
        cmp -s -- "$expected_os_release_path" "$EVIDENCE_IDENTITY_OS_RELEASE_PATH" || {
            evidence_fail "evidence bundle os-release does not match the scan root"
            return 1
        }
    fi

    EVIDENCE_BUNDLE_DIRECTORY="$bundle"
    EVIDENCE_SCHEMA_VERSION="${manifest_values[schema_version]}"
    EVIDENCE_CAPTURED_AT="${manifest_values[captured_at]}"
    EVIDENCE_MACHINE_ID="${manifest_values[machine_id]}"
    EVIDENCE_BOOT_ID="${manifest_values[boot_id]}"
    EVIDENCE_KERNEL_RELEASE="${manifest_values[kernel_release]}"
    EVIDENCE_BUNDLE_DIGEST="sha256:$(evidence_sha256 "$EVIDENCE_CHECKSUMS_PATH")"
    EVIDENCE_RUNTIME_SYSTEMD_UNITS_STATUS="${manifest_values[runtime_systemd_units_status]}"
    EVIDENCE_RUNTIME_SYSTEMD_UNIT_FILES_STATUS="${manifest_values[runtime_systemd_unit_files_status]}"
    EVIDENCE_RUNTIME_LISTENERS_STATUS="${manifest_values[runtime_listeners_status]}"
    EVIDENCE_RUNTIME_MOUNTINFO_STATUS="${manifest_values[runtime_mountinfo_status]}"
    EVIDENCE_RUNTIME_FIREWALL_STATUS="${manifest_values[runtime_firewall_status]}"
    EVIDENCE_RUNTIME_TIME_SYNC_STATUS="${manifest_values[runtime_time_sync_status]}"
    return 0
}

# The state helpers mirror the scanner's live return convention: active, inactive, unknown, absent.
evidence_service_state() {
    local unit=""
    local row_unit=""
    local load_state=""
    local active_state=""
    local sub_state=""
    local unit_file_state=""
    local saw_known=0
    local saw_unknown=0

    [ "$#" -gt 0 ] && [ -n "$EVIDENCE_BUNDLE_DIRECTORY" ] || return 2
    case "$EVIDENCE_RUNTIME_SYSTEMD_UNITS_STATUS" in
        collected|partial) ;;
        *) return 2 ;;
    esac
    for unit in "$@"; do
        case "$unit" in
            ''|*$'\t'*|*$'\n'*|*$'\r'*) return 2 ;;
        esac
        active_state=""
        while IFS=$'\t' read -r row_unit load_state active_state sub_state unit_file_state; do
            [ "$row_unit" = "$unit" ] && break
            active_state=""
        done < <(tail -n +2 "$EVIDENCE_RUNTIME_SYSTEMD_UNITS_PATH")
        [ -n "$active_state" ] || continue
        case "$active_state" in
            active) return 0 ;;
            unknown|'') saw_unknown=1 ;;
            *) saw_known=1 ;;
        esac
    done
    [ "$saw_unknown" -eq 0 ] || return 2
    [ "$saw_known" -eq 0 ] || return 1
    [ "$EVIDENCE_RUNTIME_SYSTEMD_UNITS_STATUS" = "collected" ] &&
        [ "$EVIDENCE_RUNTIME_SYSTEMD_UNIT_FILES_STATUS" = "collected" ] || return 2
    return 3
}

evidence_service_activation_state() {
    local unit=""
    local row_unit=""
    local load_state=""
    local active_state=""
    local sub_state=""
    local unit_file_state=""
    local saw_known=0
    local saw_unknown=0

    EVIDENCE_SERVICE_ACTIVATION_EVIDENCE=""
    [ "$#" -gt 0 ] && [ -n "$EVIDENCE_BUNDLE_DIRECTORY" ] || return 2
    case "$EVIDENCE_RUNTIME_SYSTEMD_UNITS_STATUS" in
        collected|partial) ;;
        *) return 2 ;;
    esac

    for unit in "$@"; do
        case "$unit" in
            ''|*$'\t'*|*$'\n'*|*$'\r'*) return 2 ;;
        esac
        load_state=""
        active_state=""
        sub_state=""
        unit_file_state=""
        while IFS=$'\t' read -r row_unit load_state active_state sub_state unit_file_state; do
            [ "$row_unit" = "$unit" ] && break
            load_state=""
            active_state=""
            sub_state=""
            unit_file_state=""
        done < <(tail -n +2 "$EVIDENCE_RUNTIME_SYSTEMD_UNITS_PATH")
        [ -n "$load_state" ] || continue
        EVIDENCE_SERVICE_ACTIVATION_EVIDENCE="${EVIDENCE_SERVICE_ACTIVATION_EVIDENCE}unit=${unit},active=${active_state},enabled=${unit_file_state}\n"
        case "$active_state" in
            active|activating|reloading) return 0 ;;
        esac
        case "$unit_file_state" in
            enabled|enabled-runtime) return 0 ;;
        esac
        case "$active_state:$unit_file_state" in
            *unknown*|*:|:*) saw_unknown=1 ;;
            *) saw_known=1 ;;
        esac
    done

    [ "$saw_unknown" -eq 0 ] || return 2
    [ "$saw_known" -eq 0 ] || return 1
    if [ "$EVIDENCE_RUNTIME_SYSTEMD_UNITS_STATUS" = "collected" ] &&
        [ "$EVIDENCE_RUNTIME_SYSTEMD_UNIT_FILES_STATUS" = "collected" ]; then
        EVIDENCE_SERVICE_ACTIVATION_EVIDENCE="${EVIDENCE_SERVICE_ACTIVATION_EVIDENCE}requested_units=absent\n"
        return 1
    fi
    return 2
}

evidence_listener_facts() {
    local transport="${1:-}"
    local requested_port=""
    local row_transport=""
    local local_address=""
    local row_port=""
    local process_name=""

    [ "$#" -ge 2 ] && [ -n "$EVIDENCE_BUNDLE_DIRECTORY" ] || return 2
    [ "$EVIDENCE_RUNTIME_LISTENERS_STATUS" = "collected" ] || return 2
    shift
    case "$transport" in
        tcp|udp|any) ;;
        *) return 2 ;;
    esac
    for requested_port in "$@"; do
        case "$requested_port" in
            ''|*[!0-9]*) return 2 ;;
        esac
        [ "$requested_port" -le 65535 ] || return 2
    done

    while IFS=$'\t' read -r row_transport local_address row_port process_name; do
        [ "$row_transport" != "transport" ] || continue
        [ "$transport" = "any" ] || [ "$row_transport" = "$transport" ] || continue
        for requested_port in "$@"; do
            if [ "$row_port" = "$requested_port" ]; then
                printf '%s\t%s\t%s\t%s\n' "$row_transport" "$local_address" "$row_port" "$process_name"
                break
            fi
        done
    done < "$EVIDENCE_RUNTIME_LISTENERS_PATH"
}

evidence_listener_state() {
    local transport="${1:-}"
    local port=""

    [ "$#" -ge 2 ] && [ -n "$EVIDENCE_BUNDLE_DIRECTORY" ] || return 2
    case "$EVIDENCE_RUNTIME_LISTENERS_STATUS" in
        collected|partial) ;;
        *) return 2 ;;
    esac
    shift
    case "$transport" in
        tcp|udp|any) ;;
        *) return 2 ;;
    esac
    for port in "$@"; do
        case "$port" in
            ''|*[!0-9]*) return 2 ;;
        esac
        [ "$port" -le 65535 ] || return 2
        if awk -F '\t' -v transport="$transport" -v port="$port" '
            NR > 1 && $3 == port && (transport == "any" || $1 == transport) {found=1; exit}
            END {exit(found ? 0 : 1)}
        ' "$EVIDENCE_RUNTIME_LISTENERS_PATH"; then
            return 0
        fi
    done
    [ "$EVIDENCE_RUNTIME_LISTENERS_STATUS" = "collected" ] || return 2
    return 1
}

evidence_mountinfo_path() {
    [ -n "$EVIDENCE_BUNDLE_DIRECTORY" ] || return 2
    [ "$EVIDENCE_RUNTIME_MOUNTINFO_STATUS" = "collected" ] || return 2
    [ -s "$EVIDENCE_RUNTIME_MOUNTINFO_PATH" ] || return 2
    printf '%s\n' "$EVIDENCE_RUNTIME_MOUNTINFO_PATH"
}

evidence_mount_roots() {
    [ -n "$EVIDENCE_BUNDLE_DIRECTORY" ] || return 2
    [ "$EVIDENCE_RUNTIME_MOUNTINFO_STATUS" = "collected" ] || return 2
    [ -s "$EVIDENCE_RUNTIME_MOUNTINFO_PATH" ] || return 2

    awk '
        {
            separator=0
            for (field_index=7; field_index<=NF; field_index++) {
                if ($field_index == "-") {
                    separator=field_index
                    break
                }
            }
            if (NF < 10 || separator == 0 || separator + 1 > NF || $5 !~ /^\// ||
                $(separator + 1) !~ /^[0-9A-Za-z_.+-]+$/ || $5 ~ /\\(011|012)/) {
                invalid=1
                next
            }
            target=$5
            gsub(/\\040/, " ", target)
            backslash=sprintf("%c", 92)
            gsub(/\\134/, backslash, target)
            targets[++count]=target
            filesystem_types[count]=$(separator + 1)
        }
        END {
            if (invalid || count == 0) exit 2
            for (output_index=1; output_index<=count; output_index++)
                print targets[output_index] "\t" filesystem_types[output_index]
        }
    ' "$EVIDENCE_RUNTIME_MOUNTINFO_PATH"
}

evidence_capture_age_seconds() {
    local captured_epoch=""
    local current_epoch=""
    local age_seconds=""

    [ -n "$EVIDENCE_CAPTURED_AT" ] || return 2
    captured_epoch="$(/bin/date -u -d "$EVIDENCE_CAPTURED_AT" +%s 2>/dev/null)" || return 2
    current_epoch="$(/bin/date -u +%s 2>/dev/null)" || return 2
    age_seconds=$((current_epoch - captured_epoch))
    [ "$age_seconds" -ge -300 ] || return 2
    [ "$age_seconds" -ge 0 ] || age_seconds=0
    EVIDENCE_AGE_SECONDS="$age_seconds"
    printf '%s\n' "$age_seconds"
}
