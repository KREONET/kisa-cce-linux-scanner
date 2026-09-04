# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash

# Plans, applies, verifies, and rolls back the bounded metadata remediations.

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
export LC_ALL=C
export LANG=C
umask 077

SCAN_ROOT="/"
OUTPUT_DIRECTORY=""
SELECTED_CHECKS="U-12,U-16,U-18,U-19,U-22,U-29,U-37"
CHECKS_EXPLICIT=0
ROOT_EXPLICIT=0
OUTPUT_EXPLICIT=0
APPLY_REQUESTED=0
APPLY_EXPLICIT=0
AUTOMATIC_REQUESTED=0
DESIRED_STATE_FILE=""
DESIRED_STATE_EXPLICIT=0
FULL_AUTOMATIC_ACTIVE=0
ROLLBACK_TRANSACTION=""
SCRATCH_DIRECTORY=""
PATCH_TRANSACTION_ACTIVE=0
PATCH_ROLLBACK_IN_PROGRESS=0
PATCH_COMMAND_COMPLETE=0
OUTPUT_DIRECTORY_DEVICE_INODE=""
TRANSACTION_MANIFEST_PATH=""
TRANSACTION_STATE_PATH=""
TRANSACTION_CHECKSUM_PATH=""
TRANSACTION_METADATA_PATH=""
TRANSACTION_PLAN_PATH=""
TRANSACTION_CONFIGURATION_PLAN_PATH=""
TRANSACTION_RECORDED_ROOT=""
TRANSACTION_RECORDED_ROOT_DEVICE=""
TRANSACTION_RECORDED_ROOT_INODE=""
TRANSACTION_RECORDED_CHECKS=""
TRANSACTION_RECORDED_METADATA_CHECKS=""
TRANSACTION_RECORDED_CONFIGURATION_CHECKS=""
SCANNER_COMMAND=""
SCAN_JSONL_PATH=""
SCAN_MARKDOWN_PATH=""
SCAN_ERROR_DETAIL=""
normalized_scan_root=""
transaction_state=""
rollback_policy=""
current_root_identity=""
declare -a PATCH_CHECK_ARRAY=()
declare -a PATCH_METADATA_CHECK_ARRAY=()
declare -a PATCH_CONFIGURATION_CHECK_ARRAY=()
declare -a SCAN_STATUS_CODES=()
declare -a SCAN_STATUS_VALUES=()
declare -a SCAN_RESOLUTION_CLASSES=()
declare -a SCAN_REMEDIATION_ELIGIBILITY=()
declare -a SCAN_REMEDIATION_RULE_IDS=()

console_uptime_into() {
    local destination_name="$1"
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
        case "$uptime_seconds" in ''|*[!0-9]*) uptime_seconds=0 ;; esac
        uptime_fraction=""
    fi
    uptime_fraction="${uptime_fraction}000000"
    uptime_fraction="${uptime_fraction:0:6}"
    printf -v "$destination_name" '%6s.%s' "$uptime_seconds" "$uptime_fraction"
}

console_sanitize_line_into() {
    local input_line="$1"
    local destination_name="$2"
    local character=""
    local escaped_character=""
    local sanitized=""
    local index_value=0
    local byte_value=0

    for ((index_value = 0; index_value < ${#input_line}; index_value++)); do
        character="${input_line:index_value:1}"
        case "$character" in
            $'\t') sanitized+='\\t' ;;
            $'\r') sanitized+='\\r' ;;
            [[:cntrl:]])
                printf -v byte_value '%d' "'$character"
                printf -v escaped_character '\\x%02x' "$byte_value"
                sanitized+="$escaped_character"
                ;;
            *) sanitized+="$character" ;;
        esac
    done
    printf -v "$destination_name" '%s' "$sanitized"
}

console_emit() {
    local payload="${1-}"
    local line=""
    local sanitized_line=""
    local uptime=""

    while IFS= read -r line || [ -n "$line" ]; do
        console_sanitize_line_into "$line" sanitized_line
        console_uptime_into uptime
        printf '[%s] kisa-cce-patch: %s\n' "$uptime" "$sanitized_line"
    done <<< "$payload"
}

attempt_automatic_rollback() {
    local rollback_status=0
    local domain_status=0

    [ "$PATCH_TRANSACTION_ACTIVE" -eq 1 ] || return 0
    [ "$PATCH_ROLLBACK_IN_PROGRESS" -eq 0 ] || return 2
    PATCH_ROLLBACK_IN_PROGRESS=1
    console_emit "automatic_rollback=started" >&2
    if [ "$FULL_AUTOMATIC_ACTIVE" -eq 1 ]; then
        patch_orchestrator_rollback transition >/dev/null 2>&1 || rollback_status=$?
        PATCH_TRANSACTION_ACTIVE=0
        PATCH_ROLLBACK_IN_PROGRESS=0
        if [ "$rollback_status" -eq 0 ]; then
            console_emit "automatic_rollback=completed" >&2
            return 0
        fi
        console_emit "ERROR: automatic full-coverage rollback failed; use the protected transaction directory for recovery" >&2
        return 2
    fi
    if [ "${#PATCH_CONFIGURATION_CHECK_ARRAY[@]}" -gt 0 ]; then
        patch_configuration_rollback transition >/dev/null 2>&1 || domain_status=$?
        [ "$domain_status" -eq 0 ] || rollback_status="$domain_status"
    fi
    domain_status=0
    if [ "${#PATCH_METADATA_CHECK_ARRAY[@]}" -gt 0 ]; then
        patch_engine_rollback transition >/dev/null 2>&1 || domain_status=$?
        [ "$domain_status" -eq 0 ] || rollback_status="$domain_status"
    fi
    PATCH_TRANSACTION_ACTIVE=0
    PATCH_ROLLBACK_IN_PROGRESS=0
    if [ "$rollback_status" -eq 0 ]; then
        transaction_set_state rolled_back >/dev/null 2>&1 || true
        console_emit "automatic_rollback=completed" >&2
        return 0
    fi
    transaction_set_state rollback_failed >/dev/null 2>&1 || true
    console_emit "ERROR: automatic rollback failed; use the protected transaction directory for recovery" >&2
    return 2
}

cleanup_patcher() {
    if [ "$PATCH_COMMAND_COMPLETE" -eq 0 ] && [ "$PATCH_TRANSACTION_ACTIVE" -eq 1 ]; then
        attempt_automatic_rollback || true
    fi
    if [ -n "$SCRATCH_DIRECTORY" ] && [ -d "$SCRATCH_DIRECTORY" ]; then
        rm -rf -- "$SCRATCH_DIRECTORY" 2>/dev/null || true
    fi
}

die() {
    local message="$*"

    attempt_automatic_rollback || true
    if [ "$AUTOMATIC_REQUESTED" -eq 1 ]; then
        console_emit "automatic_status=failed" >&2
    fi
    console_emit "ERROR: $message" >&2
    exit 2
}

handle_signal() {
    local signal_name="$1"
    local exit_status="$2"

    attempt_automatic_rollback || true
    if [ "$AUTOMATIC_REQUESTED" -eq 1 ]; then
        console_emit "automatic_status=failed" >&2
    fi
    console_emit "ERROR: interrupted by $signal_name" >&2
    exit "$exit_status"
}

usage() {
    local line=""

    while IFS= read -r line; do console_emit "$line"; done <<'EOF'
Usage: kisa-cce-patch --output-dir PATH [OPTIONS]
       kisa-cce-patch --automatic --desired-state FILE [--root PATH] [--output-dir PATH]
       kisa-cce-patch --rollback TRANSACTION_DIR [--root PATH]

Plan or apply the bounded KISA CCE file-metadata remediations. Dry-run is the default.

Options:
  --root PATH              Inspect or modify PATH as a root; default: /.
  --output-dir PATH        Create a new owner-only transaction directory at PATH.
  --checks U-12,U-18       Select supported criteria; default: U-12,U-16,U-18,U-19,U-22,U-29,U-37.
  --apply                  Apply the plan, verify it, and run a fresh post-scan.
  --automatic              Apply all supported rules; creates a protected transaction path by default.
  --desired-state FILE     Full 67-row schema-v2 desired-state YAML; required by --automatic.
  --rollback DIRECTORY     Restore a validated transaction created by --apply or --automatic.
  -h, --help               Show this help text.
  --version                Show the patcher version.

Exit status:
  0  The plan, application, verification, or rollback completed successfully.
  2  Invocation, scan, safety validation, patch, verification, or rollback failed.
  3  A verified external prerequisite is required before mutation.
EOF
}

require_option_value() {
    local option_name="$1"
    local remaining_count="$2"
    local option_value="${3:-}"

    [ "$remaining_count" -ge 2 ] || die "$option_name requires a value"
    [ -n "$option_value" ] || die "$option_name requires a value"
}

patcher_stat_device_inode() {
    stat -Lc '%d:%i' -- "$1" 2>/dev/null || stat -f '%d:%i' "$1" 2>/dev/null
}

patcher_stat_uid() {
    stat -Lc '%u' -- "$1" 2>/dev/null || stat -f '%u' "$1" 2>/dev/null
}

patcher_stat_mode() {
    stat -Lc '%a' -- "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null
}

normalize_absolute_path_into() {
    local input_path="$1"
    local destination_name="$2"
    local component=""
    local normalized_path="/"
    local old_ifs="$IFS"
    local -a components=()

    printf -v "$destination_name" '%s' ""
    case "$input_path" in /*) ;; *) return 2 ;; esac
    case "$input_path" in *$'\n'*|*$'\r'*|*$'\t'*) return 2 ;; esac
    IFS=/ read -r -a components <<< "${input_path#/}"
    IFS="$old_ifs"
    for component in "${components[@]}"; do
        case "$component" in
            '') continue ;;
            .|..) return 2 ;;
        esac
        normalized_path="${normalized_path%/}/$component"
    done
    printf -v "$destination_name" '%s' "$normalized_path"
}

path_has_no_symlink_components() {
    local path="$1"
    local current_path="/"
    local component=""
    local old_ifs="$IFS"
    local -a components=()

    IFS=/ read -r -a components <<< "${path#/}"
    IFS="$old_ifs"
    for component in "${components[@]}"; do
        [ -n "$component" ] || continue
        current_path="${current_path%/}/$component"
        [ ! -L "$current_path" ] || return 1
    done
}

directory_components_are_trusted() {
    local path="$1"
    local current_path="/"
    local component=""
    local mode=""
    local owner_uid=""
    local decimal_mode=0
    local old_ifs="$IFS"
    local -a components=()

    IFS=/ read -r -a components <<< "${path#/}"
    IFS="$old_ifs"
    for component in "${components[@]}"; do
        [ -n "$component" ] || continue
        current_path="${current_path%/}/$component"
        [ -d "$current_path" ] && [ ! -L "$current_path" ] || return 1
        owner_uid="$(patcher_stat_uid "$current_path")" || return 1
        [ "$owner_uid" = "0" ] || [ "$owner_uid" = "$EUID" ] || return 1
        mode="$(patcher_stat_mode "$current_path")" || return 1
        case "$mode" in ''|*[!0-7]*) return 1 ;; esac
        decimal_mode=$((8#$mode))
        if [ $((decimal_mode & 0022)) -ne 0 ]; then
            [ $((decimal_mode & 01000)) -ne 0 ] || return 1
            case "$current_path:$owner_uid" in
                /tmp:*|/var/tmp:*|*:0|*:"$EUID") ;;
                *) return 1 ;;
            esac
        fi
    done
}

output_directory_is_current() {
    local lexical_device_inode=""

    [ -d "$OUTPUT_DIRECTORY" ] && [ ! -L "$OUTPUT_DIRECTORY" ] || return 1
    path_has_no_symlink_components "$OUTPUT_DIRECTORY" || return 1
    lexical_device_inode="$(patcher_stat_device_inode "$OUTPUT_DIRECTORY")" || return 1
    [ "$lexical_device_inode" = "$OUTPUT_DIRECTORY_DEVICE_INODE" ]
}

prepare_output_directory() {
    local normalized_output=""
    local parent_directory=""
    local owner_uid=""
    local mode=""

    normalize_absolute_path_into "$OUTPUT_DIRECTORY" normalized_output ||
        die "--output-dir must be a safe absolute path"
    OUTPUT_DIRECTORY="$normalized_output"
    [ "$OUTPUT_DIRECTORY" != "/" ] || die "the root directory cannot be used as --output-dir"
    [ ! -e "$OUTPUT_DIRECTORY" ] && [ ! -L "$OUTPUT_DIRECTORY" ] ||
        die "--output-dir must name a new path: $OUTPUT_DIRECTORY"
    parent_directory="${OUTPUT_DIRECTORY%/*}"
    [ -n "$parent_directory" ] || parent_directory="/"
    [ -d "$parent_directory" ] && [ ! -L "$parent_directory" ] ||
        die "output parent is not a physical directory: $parent_directory"
    path_has_no_symlink_components "$parent_directory" ||
        die "output parent path contains a symbolic link: $parent_directory"
    directory_components_are_trusted "$parent_directory" ||
        die "output parent path is not trusted: $parent_directory"
    mkdir -m 0700 -- "$OUTPUT_DIRECTORY" 2>/dev/null || die "cannot create --output-dir: $OUTPUT_DIRECTORY"
    owner_uid="$(patcher_stat_uid "$OUTPUT_DIRECTORY")" || die "cannot inspect --output-dir ownership"
    mode="$(patcher_stat_mode "$OUTPUT_DIRECTORY")" || die "cannot inspect --output-dir mode"
    [ "$owner_uid" = "$EUID" ] && [ "$mode" = "700" ] ||
        die "--output-dir must be owned by the caller with mode 0700"
    OUTPUT_DIRECTORY_DEVICE_INODE="$(patcher_stat_device_inode "$OUTPUT_DIRECTORY")" ||
        die "cannot bind --output-dir to its device and inode"
    output_directory_is_current || die "--output-dir changed while it was prepared"
}

automatic_parent_directory_is_trusted() {
    local directory="$1"
    local owner_uid=""
    local mode=""
    local decimal_mode=0

    [ -d "$directory" ] && [ ! -L "$directory" ] || return 1
    owner_uid="$(patcher_stat_uid "$directory")" || return 1
    mode="$(patcher_stat_mode "$directory")" || return 1
    case "$mode" in ''|*[!0-7]*) return 1 ;; esac
    decimal_mode=$((8#$mode))
    [ "$owner_uid" = 0 ] && [ $((decimal_mode & 0022)) -eq 0 ]
}

prepare_automatic_output_directory() {
    local automatic_root="/var/lib/kisa-cce-patcher"
    local automatic_parent="$automatic_root/transactions"
    local timestamp=""
    local owner_uid=""
    local mode=""

    [ "$EUID" -eq 0 ] || die "--automatic requires root privileges"
    path_has_no_symlink_components /var/lib || die "automatic transaction parent contains a symbolic link"
    directory_components_are_trusted /var/lib || die "automatic transaction parent is not trusted"
    if [ -e "$automatic_root" ] || [ -L "$automatic_root" ]; then
        automatic_parent_directory_is_trusted "$automatic_root" ||
            die "automatic transaction root is not a trusted root-owned directory: $automatic_root"
    else
        mkdir -m 0700 -- "$automatic_root" 2>/dev/null ||
            die "cannot create the automatic transaction root: $automatic_root"
    fi
    automatic_parent_directory_is_trusted "$automatic_root" ||
        die "automatic transaction root changed during validation: $automatic_root"
    if [ -e "$automatic_parent" ] || [ -L "$automatic_parent" ]; then
        automatic_parent_directory_is_trusted "$automatic_parent" ||
            die "automatic transaction parent is not a trusted root-owned directory: $automatic_parent"
    else
        mkdir -m 0700 -- "$automatic_parent" 2>/dev/null ||
            die "cannot create the automatic transaction parent: $automatic_parent"
    fi
    path_has_no_symlink_components "$automatic_parent" || die "automatic transaction parent contains a symbolic link"
    automatic_parent_directory_is_trusted "$automatic_parent" || die "automatic transaction parent changed during validation"
    timestamp="$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null)" || die "cannot create an automatic transaction timestamp"
    case "$timestamp" in [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z) ;; *) die "invalid automatic transaction timestamp" ;; esac
    OUTPUT_DIRECTORY="$(mktemp -d "$automatic_parent/transaction-$timestamp.XXXXXXXX" 2>/dev/null)" ||
        die "cannot create a unique automatic transaction directory"
    owner_uid="$(patcher_stat_uid "$OUTPUT_DIRECTORY")" || die "cannot inspect the automatic transaction owner"
    mode="$(patcher_stat_mode "$OUTPUT_DIRECTORY")" || die "cannot inspect the automatic transaction mode"
    [ "$owner_uid" = 0 ] && [ "$mode" = 700 ] || die "automatic transaction directory is not protected"
    OUTPUT_DIRECTORY_DEVICE_INODE="$(patcher_stat_device_inode "$OUTPUT_DIRECTORY")" ||
        die "cannot bind the automatic transaction directory to its device and inode"
    output_directory_is_current || die "automatic transaction directory changed while it was prepared"
}

protected_artifact_is_valid() {
    local artifact_path="$1"
    local owner_uid=""
    local mode=""
    local link_count=""

    [ -f "$artifact_path" ] && [ ! -L "$artifact_path" ] || return 1
    owner_uid="$(patcher_stat_uid "$artifact_path")" || return 1
    mode="$(patcher_stat_mode "$artifact_path")" || return 1
    link_count="$(stat -Lc '%h' -- "$artifact_path" 2>/dev/null || stat -f '%l' "$artifact_path" 2>/dev/null)" || return 1
    [ "$owner_uid" = "$EUID" ] && [ "$mode" = "600" ] && [ "$link_count" = "1" ]
}

write_protected_artifact() {
    local artifact_path="$1"
    local content="$2"

    [ ! -e "$artifact_path" ] && [ ! -L "$artifact_path" ] || return 2
    output_directory_is_current || return 2
    if ! (
        umask 077
        set -o noclobber
        printf '%s\n' "$content" > "$artifact_path" && chmod 0600 "$artifact_path"
    ) 2>/dev/null; then
        return 2
    fi
    protected_artifact_is_valid "$artifact_path"
}

patcher_sha256_into() {
    local input_path="$1"
    local destination_name="$2"
    local hash_output=""
    local digest=""

    if [ -x /usr/bin/sha256sum ]; then
        hash_output="$(/usr/bin/sha256sum -- "$input_path" 2>/dev/null)" || return 2
    elif [ -x /bin/sha256sum ]; then
        hash_output="$(/bin/sha256sum -- "$input_path" 2>/dev/null)" || return 2
    elif [ -x /usr/bin/shasum ]; then
        hash_output="$(/usr/bin/shasum -a 256 -- "$input_path" 2>/dev/null)" || return 2
    else
        return 127
    fi
    digest="${hash_output%% *}"
    [ "${#digest}" -eq 64 ] || return 2
    case "$digest" in *[!0-9a-f]*) return 2 ;; esac
    printf -v "$destination_name" '%s' "$digest"
}

transaction_write_manifest() {
    local root_identity=""
    local root_device=""
    local root_inode=""
    local content=""
    local metadata_checks=""
    local configuration_checks=""

    root_identity="$(patcher_stat_device_inode "$SCAN_ROOT")" || return 2
    root_device="${root_identity%%:*}"
    root_inode="${root_identity#*:}"
    case "$root_device:$root_inode" in :*|*:|*:*:*|*[!0-9:]*) return 2 ;; esac
    join_check_array_into metadata_checks "${PATCH_METADATA_CHECK_ARRAY[@]}"
    join_check_array_into configuration_checks "${PATCH_CONFIGURATION_CHECK_ARRAY[@]}"
    printf -v content 'schema\t2\nscanner_version\t%s\nroot\t%s\nroot_device\t%s\nroot_inode\t%s\nchecks\t%s\nmetadata_checks\t%s\nconfiguration_checks\t%s' \
        "$KISA_CCE_VERSION" "$SCAN_ROOT" "$root_device" "$root_inode" "$SELECTED_CHECKS" \
        "$metadata_checks" "$configuration_checks"
    TRANSACTION_MANIFEST_PATH="$OUTPUT_DIRECTORY/manifest.tsv"
    write_protected_artifact "$TRANSACTION_MANIFEST_PATH" "$content"
}

transaction_set_state() {
    local new_state="$1"
    local state_temp=""

    case "$new_state" in
        planned|applying|applied|verified|rollback_in_progress|rolled_back|failed|rollback_failed) ;;
        *) return 2 ;;
    esac
    output_directory_is_current || return 2
    TRANSACTION_STATE_PATH="$OUTPUT_DIRECTORY/state"
    state_temp="$(mktemp "$OUTPUT_DIRECTORY/.state.XXXXXXXX" 2>/dev/null)" || return 2
    if ! printf '%s\n' "$new_state" > "$state_temp" ||
        ! chmod 0600 "$state_temp" 2>/dev/null ||
        ! protected_artifact_is_valid "$state_temp" ||
        ! mv -f -- "$state_temp" "$TRANSACTION_STATE_PATH" 2>/dev/null; then
        rm -f -- "$state_temp" 2>/dev/null || true
        return 2
    fi
    protected_artifact_is_valid "$TRANSACTION_STATE_PATH"
}

transaction_write_checksums() {
    local artifact_name=""
    local artifact_digest=""
    local content=""
    local -a names=(manifest.tsv plan.tsv metadata.tsv)

    if [ "${#PATCH_CONFIGURATION_CHECK_ARRAY[@]}" -gt 0 ]; then
        names+=(configuration-plan.tsv configuration/manifest.tsv)
    fi
    for artifact_name in "${names[@]}"; do
        patcher_sha256_into "$OUTPUT_DIRECTORY/$artifact_name" artifact_digest || return 2
        if [ -n "$content" ]; then
            content+=$'\n'
        fi
        content+="$artifact_digest  $artifact_name"
    done
    TRANSACTION_CHECKSUM_PATH="$OUTPUT_DIRECTORY/checksums.sha256"
    write_protected_artifact "$TRANSACTION_CHECKSUM_PATH" "$content"
}

transaction_validate_checksums() {
    local line=""
    local expected_name=""
    local recorded_digest=""
    local recorded_name=""
    local actual_digest=""
    local index=0
    local -a names=(manifest.tsv plan.tsv metadata.tsv)

    if [ "$TRANSACTION_RECORDED_CONFIGURATION_CHECKS" != "-" ]; then
        names+=(configuration-plan.tsv configuration/manifest.tsv)
    fi

    protected_artifact_is_valid "$TRANSACTION_CHECKSUM_PATH" || return 2
    while IFS= read -r line || [ -n "$line" ]; do
        [ "$index" -lt "${#names[@]}" ] || return 2
        expected_name="${names[$index]}"
        case "$line" in [0-9a-f][0-9a-f]*"  $expected_name") ;; *) return 2 ;; esac
        recorded_digest="${line%%  *}"
        recorded_name="${line#*  }"
        [ "$recorded_name" = "$expected_name" ] && [ "${#recorded_digest}" -eq 64 ] || return 2
        case "$recorded_digest" in *[!0-9a-f]*) return 2 ;; esac
        patcher_sha256_into "$OUTPUT_DIRECTORY/$recorded_name" actual_digest || return 2
        [ "$actual_digest" = "$recorded_digest" ] || return 2
        index=$((index + 1))
    done < "$TRANSACTION_CHECKSUM_PATH"
    [ "$index" -eq "${#names[@]}" ]
}

transaction_load_manifest() {
    local line=""
    local key=""
    local value=""
    local extra=""
    local index=0
    local -a expected_keys=(schema scanner_version root root_device root_inode checks metadata_checks configuration_checks)

    TRANSACTION_RECORDED_ROOT=""
    TRANSACTION_RECORDED_ROOT_DEVICE=""
    TRANSACTION_RECORDED_ROOT_INODE=""
    TRANSACTION_RECORDED_CHECKS=""
    TRANSACTION_RECORDED_METADATA_CHECKS=""
    TRANSACTION_RECORDED_CONFIGURATION_CHECKS=""
    while IFS= read -r line || [ -n "$line" ]; do
        [ "$index" -lt "${#expected_keys[@]}" ] || return 2
        IFS=$'\t' read -r key value extra <<< "$line"
        [ -z "$extra" ] && [ "$key" = "${expected_keys[$index]}" ] && [ -n "$value" ] || return 2
        case "$key" in
            schema) [ "$value" = 2 ] || return 2 ;;
            scanner_version) [ "$value" = "$KISA_CCE_VERSION" ] || return 2 ;;
            root) TRANSACTION_RECORDED_ROOT="$value" ;;
            root_device) TRANSACTION_RECORDED_ROOT_DEVICE="$value" ;;
            root_inode) TRANSACTION_RECORDED_ROOT_INODE="$value" ;;
            checks) TRANSACTION_RECORDED_CHECKS="$value" ;;
            metadata_checks) TRANSACTION_RECORDED_METADATA_CHECKS="$value" ;;
            configuration_checks) TRANSACTION_RECORDED_CONFIGURATION_CHECKS="$value" ;;
        esac
        index=$((index + 1))
    done < "$TRANSACTION_MANIFEST_PATH"
    [ "$index" -eq "${#expected_keys[@]}" ] || return 2
    case "$TRANSACTION_RECORDED_ROOT_DEVICE:$TRANSACTION_RECORDED_ROOT_INODE" in
        :*|*:|*:*:*|*[!0-9:]*) return 2 ;;
    esac
}

transaction_read_state_into() {
    local destination_name="$1"
    local state_value=""
    local line_count=""

    protected_artifact_is_valid "$TRANSACTION_STATE_PATH" || return 2
    line_count="$(wc -l < "$TRANSACTION_STATE_PATH" | tr -d '[:space:]')" || return 2
    [ "$line_count" = 1 ] || return 2
    IFS= read -r state_value < "$TRANSACTION_STATE_PATH" || return 2
    case "$state_value" in
        planned|applying|applied|verified|rollback_in_progress|rolled_back|failed|rollback_failed) ;;
        *) return 2 ;;
    esac
    printf -v "$destination_name" '%s' "$state_value"
}

validate_transaction_directory() {
    local normalized_transaction=""
    local transaction_parent=""
    local owner_uid=""
    local mode=""

    normalize_absolute_path_into "$ROLLBACK_TRANSACTION" normalized_transaction || return 2
    ROLLBACK_TRANSACTION="$normalized_transaction"
    [ -d "$ROLLBACK_TRANSACTION" ] && [ ! -L "$ROLLBACK_TRANSACTION" ] || return 2
    path_has_no_symlink_components "$ROLLBACK_TRANSACTION" || return 2
    directory_components_are_trusted "$ROLLBACK_TRANSACTION" || return 2
    transaction_parent="${ROLLBACK_TRANSACTION%/*}"
    [ -n "$transaction_parent" ] || transaction_parent="/"
    directory_components_are_trusted "$transaction_parent" || return 2
    [ "$(CDPATH='' cd -P -- "$ROLLBACK_TRANSACTION" 2>/dev/null && pwd)" = "$ROLLBACK_TRANSACTION" ] || return 2
    owner_uid="$(patcher_stat_uid "$ROLLBACK_TRANSACTION")" || return 2
    mode="$(patcher_stat_mode "$ROLLBACK_TRANSACTION")" || return 2
    [ "$owner_uid" = "$EUID" ] && [ "$mode" = 700 ] || return 2
    OUTPUT_DIRECTORY="$ROLLBACK_TRANSACTION"
    OUTPUT_DIRECTORY_DEVICE_INODE="$(patcher_stat_device_inode "$OUTPUT_DIRECTORY")" || return 2
    TRANSACTION_MANIFEST_PATH="$OUTPUT_DIRECTORY/manifest.tsv"
    TRANSACTION_PLAN_PATH="$OUTPUT_DIRECTORY/plan.tsv"
    TRANSACTION_METADATA_PATH="$OUTPUT_DIRECTORY/metadata.tsv"
    TRANSACTION_STATE_PATH="$OUTPUT_DIRECTORY/state"
    TRANSACTION_CHECKSUM_PATH="$OUTPUT_DIRECTORY/checksums.sha256"
    TRANSACTION_CONFIGURATION_PLAN_PATH="$OUTPUT_DIRECTORY/configuration-plan.tsv"
    protected_artifact_is_valid "$TRANSACTION_MANIFEST_PATH" || return 2
    protected_artifact_is_valid "$TRANSACTION_PLAN_PATH" || return 2
    protected_artifact_is_valid "$TRANSACTION_METADATA_PATH" || return 2
    transaction_load_manifest || return 2
    if [ "$TRANSACTION_RECORDED_CONFIGURATION_CHECKS" != "-" ]; then
        protected_artifact_is_valid "$TRANSACTION_CONFIGURATION_PLAN_PATH" || return 2
        protected_artifact_is_valid "$OUTPUT_DIRECTORY/configuration/manifest.tsv" || return 2
    fi
    transaction_validate_checksums
}

normalize_checks() {
    local raw_checks="$1"
    local code=""
    local old_ifs="$IFS"
    local normalized_checks=""
    local seen_codes=""

    raw_checks="$(printf '%s' "$raw_checks" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
    case "$raw_checks" in ''|,*|*,|*,,*) die "--checks must be a non-empty comma-separated list" ;; esac
    IFS=,
    read -r -a PATCH_CHECK_ARRAY <<< "$raw_checks"
    IFS="$old_ifs"
    for code in "${PATCH_CHECK_ARRAY[@]}"; do
        case "$code" in U-12|U-16|U-18|U-19|U-22|U-29|U-37|U-62|U-67) ;; *) die "unsupported patch criterion: $code" ;; esac
        case ",$seen_codes," in *",$code,"*) die "duplicate patch criterion: $code" ;; esac
        if [ -n "$seen_codes" ]; then seen_codes+=",$code"; else seen_codes="$code"; fi
        if [ -n "$normalized_checks" ]; then
            normalized_checks+=",$code"
        else
            normalized_checks="$code"
        fi
    done
    SELECTED_CHECKS="$normalized_checks"
}

join_check_array_into() {
    local destination_name="$1"
    shift
    local criterion=""
    local joined=""

    for criterion in "$@"; do
        if [ -n "$joined" ]; then joined+=",$criterion"; else joined="$criterion"; fi
    done
    printf -v "$destination_name" '%s' "${joined:--}"
}

partition_selected_checks() {
    local criterion=""

    PATCH_METADATA_CHECK_ARRAY=()
    PATCH_CONFIGURATION_CHECK_ARRAY=()
    for criterion in "${PATCH_CHECK_ARRAY[@]}"; do
        case "$criterion" in
            U-12|U-62) PATCH_CONFIGURATION_CHECK_ARRAY+=("$criterion") ;;
            U-16|U-18|U-19|U-22|U-29|U-37|U-67) PATCH_METADATA_CHECK_ARRAY+=("$criterion") ;;
            *) die "no patch domain is registered for criterion $criterion" ;;
        esac
    done
}

patcher_plan_state_into() {
    local criterion="$1"
    local destination_name="$2"

    case "$criterion" in
        U-12|U-62) patch_configuration_state_into "$criterion" "$destination_name" ;;
        U-16|U-18|U-19|U-22|U-29|U-37|U-67) patch_engine_state_into "$criterion" "$destination_name" ;;
        *) return 1 ;;
    esac
}

scan_status_set() {
    SCAN_STATUS_CODES+=("$1")
    SCAN_STATUS_VALUES+=("$2")
    SCAN_RESOLUTION_CLASSES+=("$3")
    SCAN_REMEDIATION_ELIGIBILITY+=("$4")
    SCAN_REMEDIATION_RULE_IDS+=("$5")
}

scan_status_into() {
    local requested_code="$1"
    local destination_name="$2"
    local index=0

    while [ "$index" -lt "${#SCAN_STATUS_CODES[@]}" ]; do
        if [ "${SCAN_STATUS_CODES[$index]}" = "$requested_code" ]; then
            printf -v "$destination_name" '%s' "${SCAN_STATUS_VALUES[$index]}"
            return 0
        fi
        index=$((index + 1))
    done
    return 1
}

scan_remediation_facts_into() {
    local requested_code="$1"
    local class_destination="$2"
    local eligibility_destination="$3"
    local rule_destination="$4"
    local index=0

    while [ "$index" -lt "${#SCAN_STATUS_CODES[@]}" ]; do
        if [ "${SCAN_STATUS_CODES[$index]}" = "$requested_code" ]; then
            printf -v "$class_destination" '%s' "${SCAN_RESOLUTION_CLASSES[$index]}"
            printf -v "$eligibility_destination" '%s' "${SCAN_REMEDIATION_ELIGIBILITY[$index]}"
            printf -v "$rule_destination" '%s' "${SCAN_REMEDIATION_RULE_IDS[$index]}"
            return 0
        fi
        index=$((index + 1))
    done
    return 1
}

expected_remediation_rule_into() {
    local criterion="$1"
    local destination_name="$2"

    case "$criterion" in
        U-16) printf -v "$destination_name" '%s' metadata.u16.v1 ;;
        U-18) printf -v "$destination_name" '%s' metadata.u18.v1 ;;
        U-19) printf -v "$destination_name" '%s' metadata.u19.v1 ;;
        U-22) printf -v "$destination_name" '%s' metadata.u22.v1 ;;
        U-29) printf -v "$destination_name" '%s' metadata.u29.v1 ;;
        U-37) printf -v "$destination_name" '%s' metadata.u37.v1 ;;
        U-12) printf -v "$destination_name" '%s' configuration.u12.v1 ;;
        U-62) printf -v "$destination_name" '%s' configuration.u62.v1 ;;
        U-67) printf -v "$destination_name" '%s' metadata.u67.v1 ;;
        *) return 1 ;;
    esac
}

extract_scanner_payload_into() {
    local input_line="$1"
    local destination_name="$2"
    local console_regex='^\[[[:space:]]*[0-9]+\.[0-9]{6}\] kisa-cce-scan: (.*)$'

    printf -v "$destination_name" '%s' ""
    [[ "$input_line" =~ $console_regex ]] || return 2
    printf -v "$destination_name" '%s' "${BASH_REMATCH[1]}"
}

replay_scanner_file() {
    local input_file="$1"
    local stream_name="$2"
    local parse_paths="$3"
    local line=""
    local payload=""
    local path_count_markdown=0
    local path_count_jsonl=0

    while IFS= read -r line || [ -n "$line" ]; do
        if ! extract_scanner_payload_into "$line" payload; then
            SCAN_ERROR_DETAIL="scanner emitted malformed $stream_name output"
            return 2
        fi
        if [ "$stream_name" = "stderr" ]; then
            printf '%s\n' "$line" >&2
        else
            printf '%s\n' "$line"
        fi
        [ "$parse_paths" -eq 1 ] || continue
        case "$payload" in
            markdown_report=*)
                path_count_markdown=$((path_count_markdown + 1))
                SCAN_MARKDOWN_PATH="${payload#markdown_report=}"
                ;;
            jsonl_report=*)
                path_count_jsonl=$((path_count_jsonl + 1))
                SCAN_JSONL_PATH="${payload#jsonl_report=}"
                ;;
            *)
                SCAN_ERROR_DETAIL="scanner emitted an unexpected standard-output payload"
                return 2
                ;;
        esac
    done < "$input_file"
    if [ "$parse_paths" -eq 1 ] &&
        { [ "$path_count_markdown" -ne 1 ] || [ "$path_count_jsonl" -ne 1 ]; }; then
        SCAN_ERROR_DETAIL="scanner did not emit exactly one Markdown and JSONL report path"
        return 2
    fi
}

validate_scan_report_path() {
    local report_path="$1"
    local scan_directory="$2"
    local owner_uid=""
    local mode=""

    case "$report_path" in "$scan_directory"/*) ;; *) return 2 ;; esac
    case "${report_path#"$scan_directory"/}" in ''|*/*) return 2 ;; esac
    [ -f "$report_path" ] && [ ! -L "$report_path" ] || return 2
    owner_uid="$(patcher_stat_uid "$report_path")" || return 2
    mode="$(patcher_stat_mode "$report_path")" || return 2
    [ "$owner_uid" = "$EUID" ] && [ "$mode" = "600" ]
}

parse_scan_report() {
    local report_path="$1"
    local allow_unresolved="${2:-0}"
    local line=""
    local remaining=""
    local code=""
    local status_tail=""
    local status=""
    local technical_tail=""
    local technical_status=""
    local resolution_tail=""
    local resolution_class=""
    local eligibility_tail=""
    local remediation_eligible=""
    local rule_tail=""
    local remediation_rule_id=""
    local status_marker='","status":"'
    local technical_marker='","technical_status":"'
    local resolution_marker='","resolution_class":"'
    local eligibility_marker='","remediation_eligible":'
    local rule_marker=',"remediation_rule_id":"'
    local criterion_url_marker='","criterion_url":"'
    local summary_regex='^\{"type":"summary","total":([0-9]+),"good":([0-9]+),"vulnerable":([0-9]+),"manual":([0-9]+),"not_applicable":([0-9]+),"error":([0-9]+),"policy_resolved":([0-9]+)\}$'
    local summary_seen=0
    local result_count=0
    local observed_good=0
    local observed_vulnerable=0
    local observed_not_applicable=0
    local observed_manual=0
    local observed_error=0
    local expected_count="${#PATCH_CHECK_ARRAY[@]}"
    local seen_codes=""

    SCAN_STATUS_CODES=()
    SCAN_STATUS_VALUES=()
    SCAN_RESOLUTION_CLASSES=()
    SCAN_REMEDIATION_ELIGIBILITY=()
    SCAN_REMEDIATION_RULE_IDS=()
    while IFS= read -r line || [ -n "$line" ]; do
        [ -n "$line" ] || { SCAN_ERROR_DETAIL="scan report contains an empty record"; return 2; }
        if [[ "$line" == '{"code":"'* ]]; then
            [ "$summary_seen" -eq 0 ] || { SCAN_ERROR_DETAIL="scan result follows the summary record"; return 2; }
            remaining="${line#'{"code":"'}"
            code="${remaining%%\"*}"
            [[ "$code" =~ ^U-[0-9][0-9]$ ]] || { SCAN_ERROR_DETAIL="scan report contains an invalid criterion code"; return 2; }
            case "$remaining" in "$code"'","category":"'*) ;; *) SCAN_ERROR_DETAIL="scan report has an invalid criterion boundary for $code"; return 2 ;; esac
            case "$line" in *'"}') ;; *) SCAN_ERROR_DETAIL="scan report has an invalid record terminator for $code"; return 2 ;; esac
            case ",$SELECTED_CHECKS," in *",$code,"*) ;; *) SCAN_ERROR_DETAIL="scan report contains an unrequested criterion: $code"; return 2 ;; esac
            case ",$seen_codes," in *",$code,"*) SCAN_ERROR_DETAIL="scan report repeats criterion: $code"; return 2 ;; esac
            case "$line" in *"$status_marker"*) ;; *) SCAN_ERROR_DETAIL="scan report omits status for $code"; return 2 ;; esac
            status_tail="${line#*"$status_marker"}"
            status="${status_tail%%\"*}"
            case "$status_tail" in "$status$technical_marker"*) ;; *) SCAN_ERROR_DETAIL="scan report has an invalid status boundary for $code"; return 2 ;; esac
            technical_tail="${status_tail#*"$technical_marker"}"
            technical_status="${technical_tail%%\"*}"
            case "$technical_tail" in "$technical_status"'","decision_basis":"'*) ;; *) SCAN_ERROR_DETAIL="scan report has an invalid technical-status boundary for $code"; return 2 ;; esac
            [ "$technical_status" = "$status" ] || { SCAN_ERROR_DETAIL="audit status mismatch for $code"; return 2; }
            case "$line" in *"$resolution_marker"*) ;; *) SCAN_ERROR_DETAIL="scan report omits resolution class for $code"; return 2 ;; esac
            resolution_tail="${line#*"$resolution_marker"}"
            resolution_class="${resolution_tail%%\"*}"
            case "$resolution_class" in technical|policy|runtime|external) ;; *) SCAN_ERROR_DETAIL="scan report has an invalid resolution class for $code"; return 2 ;; esac
            case "$resolution_tail" in "$resolution_class$eligibility_marker"*) ;; *) SCAN_ERROR_DETAIL="scan report has an invalid resolution-class boundary for $code"; return 2 ;; esac
            eligibility_tail="${resolution_tail#*"$eligibility_marker"}"
            remediation_eligible="${eligibility_tail%%,*}"
            case "$remediation_eligible" in true|false) ;; *) SCAN_ERROR_DETAIL="scan report has invalid remediation eligibility for $code"; return 2 ;; esac
            case "$eligibility_tail" in "$remediation_eligible$rule_marker"*) ;; *) SCAN_ERROR_DETAIL="scan report has an invalid remediation-eligibility boundary for $code"; return 2 ;; esac
            rule_tail="${eligibility_tail#*"$rule_marker"}"
            remediation_rule_id="${rule_tail%%\"*}"
            case "$rule_tail" in "$remediation_rule_id$criterion_url_marker"*) ;; *) SCAN_ERROR_DETAIL="scan report has an invalid remediation-rule boundary for $code"; return 2 ;; esac
            case "$remediation_rule_id" in ''|[a-z0-9]*.*) ;; *) SCAN_ERROR_DETAIL="scan report has an invalid remediation rule for $code"; return 2 ;; esac
            if [ "$remediation_eligible" = true ]; then
                [ "$status" = VULNERABLE ] && [ -n "$remediation_rule_id" ] || {
                    SCAN_ERROR_DETAIL="scan report has inconsistent remediation eligibility for $code"
                    return 2
                }
            else
                [ -z "$remediation_rule_id" ] || {
                    SCAN_ERROR_DETAIL="scan report assigns a rule to an ineligible result for $code"
                    return 2
                }
            fi
            case "$status" in
                GOOD) observed_good=$((observed_good + 1)) ;;
                VULNERABLE) observed_vulnerable=$((observed_vulnerable + 1)) ;;
                NOT_APPLICABLE) observed_not_applicable=$((observed_not_applicable + 1)) ;;
                MANUAL)
                    [ "$allow_unresolved" -eq 1 ] || { SCAN_ERROR_DETAIL="criterion $code returned $status"; return 2; }
                    observed_manual=$((observed_manual + 1))
                    ;;
                ERROR)
                    [ "$allow_unresolved" -eq 1 ] || { SCAN_ERROR_DETAIL="criterion $code returned $status"; return 2; }
                    observed_error=$((observed_error + 1))
                    ;;
                *) SCAN_ERROR_DETAIL="criterion $code returned an unsupported status"; return 2 ;;
            esac
            if [ -n "$seen_codes" ]; then seen_codes+=",$code"; else seen_codes="$code"; fi
            scan_status_set "$code" "$status" "$resolution_class" "$remediation_eligible" "$remediation_rule_id"
            result_count=$((result_count + 1))
        elif [[ "$line" =~ $summary_regex ]]; then
            [ "$summary_seen" -eq 0 ] || { SCAN_ERROR_DETAIL="scan report repeats its summary"; return 2; }
            [ "${BASH_REMATCH[1]}" -eq "$expected_count" ] &&
                [ "${BASH_REMATCH[2]}" -eq "$observed_good" ] &&
                [ "${BASH_REMATCH[3]}" -eq "$observed_vulnerable" ] &&
                [ "${BASH_REMATCH[4]}" -eq "$observed_manual" ] &&
                [ "${BASH_REMATCH[5]}" -eq "$observed_not_applicable" ] &&
                [ "${BASH_REMATCH[6]}" -eq "$observed_error" ] &&
                [ "${BASH_REMATCH[7]}" -eq 0 ] || {
                    SCAN_ERROR_DETAIL="scan summary does not match its criterion records"
                    return 2
                }
            summary_seen=1
        else
            SCAN_ERROR_DETAIL="scan report contains an unsupported record"
            return 2
        fi
    done < "$report_path"
    [ "$result_count" -eq "$expected_count" ] && [ "$summary_seen" -eq 1 ] || {
        SCAN_ERROR_DETAIL="scan report is incomplete"
        return 2
    }
    for code in "${PATCH_CHECK_ARRAY[@]}"; do
        case ",$seen_codes," in *",$code,"*) ;; *) SCAN_ERROR_DETAIL="scan report omits criterion: $code"; return 2 ;; esac
    done
}

run_scanner_audit() {
    local phase="$1"
    local scan_directory="$OUTPUT_DIRECTORY/$phase"
    local scanner_stdout="$SCRATCH_DIRECTORY/$phase.stdout"
    local scanner_stderr="$SCRATCH_DIRECTORY/$phase.stderr"
    local scanner_status=0
    local observed_vulnerable=0
    local code=""
    local scan_status=""
    local resolution_class=""
    local remediation_eligible=""
    local remediation_rule_id=""
    local expected_rule_id=""

    SCAN_JSONL_PATH=""
    SCAN_MARKDOWN_PATH=""
    SCAN_ERROR_DETAIL=""
    output_directory_is_current || die "--output-dir changed before the $phase scan"
    [ ! -e "$scan_directory" ] && [ ! -L "$scan_directory" ] || die "$phase scan directory already exists"
    console_emit "scan_phase=$phase status=started" >&2
    "$SCANNER_COMMAND" --root "$SCAN_ROOT" --output-dir "$scan_directory" \
        --checks "$SELECTED_CHECKS" --mode audit --verbose >"$scanner_stdout" 2>"$scanner_stderr" || scanner_status=$?
    replay_scanner_file "$scanner_stderr" stderr 0 || die "$SCAN_ERROR_DETAIL"
    replay_scanner_file "$scanner_stdout" stdout 1 || die "$SCAN_ERROR_DETAIL"
    case "$scanner_status" in 0|1) ;; *) die "$phase scanner audit failed with exit status $scanner_status" ;; esac
    [ -d "$scan_directory" ] && [ ! -L "$scan_directory" ] || die "$phase scanner output directory is invalid"
    validate_scan_report_path "$SCAN_JSONL_PATH" "$scan_directory" || die "$phase JSONL report path failed integrity validation"
    validate_scan_report_path "$SCAN_MARKDOWN_PATH" "$scan_directory" || die "$phase Markdown report path failed integrity validation"
    parse_scan_report "$SCAN_JSONL_PATH" || die "$phase scan is not conclusive: $SCAN_ERROR_DETAIL"
    for code in "${PATCH_CHECK_ARRAY[@]}"; do
        scan_status_into "$code" scan_status || die "$phase scan status lookup failed for $code"
        [ "$scan_status" != "VULNERABLE" ] || observed_vulnerable=1
    done
    if { [ "$scanner_status" -eq 1 ] && [ "$observed_vulnerable" -eq 0 ]; } ||
        { [ "$scanner_status" -eq 0 ] && [ "$observed_vulnerable" -eq 1 ]; }; then
        die "$phase scanner exit status does not match the report"
    fi
    console_emit "scan_phase=$phase status=completed jsonl_report=$SCAN_JSONL_PATH" >&2
}

select_all_criteria() {
    local number=0
    local criterion=""

    SELECTED_CHECKS=""
    PATCH_CHECK_ARRAY=()
    while [ "$number" -lt 67 ]; do
        number=$((number + 1))
        printf -v criterion 'U-%02d' "$number"
        PATCH_CHECK_ARRAY+=("$criterion")
        if [ -n "$SELECTED_CHECKS" ]; then SELECTED_CHECKS+=",$criterion"; else SELECTED_CHECKS="$criterion"; fi
    done
}

run_full_scanner_audit() {
    local phase="$1"
    local scan_directory="$OUTPUT_DIRECTORY/$phase"
    local scanner_stdout="$SCRATCH_DIRECTORY/$phase.stdout"
    local scanner_stderr="$SCRATCH_DIRECTORY/$phase.stderr"
    local scanner_status=0

    SCAN_JSONL_PATH=""
    SCAN_MARKDOWN_PATH=""
    SCAN_ERROR_DETAIL=""
    output_directory_is_current || die "--output-dir changed before the $phase scan"
    [ ! -e "$scan_directory" ] && [ ! -L "$scan_directory" ] || die "$phase scan directory already exists"
    console_emit "scan_phase=$phase scope=U-01..U-67 status=started" >&2
    "$SCANNER_COMMAND" --root "$SCAN_ROOT" --output-dir "$scan_directory" \
        --checks "$SELECTED_CHECKS" --mode audit --verbose >"$scanner_stdout" 2>"$scanner_stderr" || scanner_status=$?
    replay_scanner_file "$scanner_stderr" stderr 0 || die "$SCAN_ERROR_DETAIL"
    replay_scanner_file "$scanner_stdout" stdout 1 || die "$SCAN_ERROR_DETAIL"
    case "$scanner_status" in 0|1) ;; *) die "$phase full scanner audit failed with exit status $scanner_status" ;; esac
    [ -d "$scan_directory" ] && [ ! -L "$scan_directory" ] || die "$phase scanner output directory is invalid"
    validate_scan_report_path "$SCAN_JSONL_PATH" "$scan_directory" || die "$phase JSONL report path failed integrity validation"
    validate_scan_report_path "$SCAN_MARKDOWN_PATH" "$scan_directory" || die "$phase Markdown report path failed integrity validation"
    parse_scan_report "$SCAN_JSONL_PATH" 1 || die "$phase full scan report is invalid: $SCAN_ERROR_DETAIL"
    console_emit "scan_phase=$phase scope=U-01..U-67 status=completed jsonl_report=$SCAN_JSONL_PATH" >&2
}

verify_patch_plan_matches_scan() {
    local code=""
    local engine_state=""
    local expected_state=""
    local scan_status=""

    for code in "${PATCH_CHECK_ARRAY[@]}"; do
        patcher_plan_state_into "$code" engine_state || die "patch plan omitted criterion: $code"
        scan_status_into "$code" scan_status || die "scan status lookup failed for $code"
        scan_remediation_facts_into "$code" resolution_class remediation_eligible remediation_rule_id ||
            die "scan remediation fact lookup failed for $code"
        case "$scan_status" in
            GOOD) expected_state="compliant" ;;
            VULNERABLE) expected_state="ready" ;;
            NOT_APPLICABLE) expected_state="not_applicable" ;;
            *) die "scan returned an unsupported state for $code" ;;
        esac
        [ "$engine_state" = "$expected_state" ] ||
            die "scanner and patch engine disagree for $code: scan=$scan_status engine=$engine_state"
        if [ "$scan_status" = VULNERABLE ]; then
            expected_remediation_rule_into "$code" expected_rule_id ||
                die "no patcher rule is registered for vulnerable criterion $code"
            [ "$resolution_class" = technical ] && [ "$remediation_eligible" = true ] &&
                [ "$remediation_rule_id" = "$expected_rule_id" ] ||
                die "scanner did not authorize the expected remediation rule for $code"
        elif [ "$remediation_eligible" != false ] || [ -n "$remediation_rule_id" ]; then
            die "scanner authorized remediation for a non-vulnerable criterion $code"
        fi
    done
}

verify_post_scan() {
    local code=""
    local scan_status=""

    for code in "${PATCH_CHECK_ARRAY[@]}"; do
        scan_status_into "$code" scan_status || die "post-scan status lookup failed for $code"
        case "$scan_status" in
            GOOD|NOT_APPLICABLE) ;;
            VULNERABLE) die "post-scan still reports $code as VULNERABLE" ;;
            *) die "post-scan returned an unsupported state for $code" ;;
        esac
    done
}

rollback_full_transaction() {
    local normalized_transaction=""
    local manifest=""
    local checksum=""
    local expected=""
    local suffix=""
    local actual=""
    local line=""
    local schema="" record_type="" name="" value_one="" value_two="" value_three="" extra=""
    local recorded_root=""
    local recorded_root_device=""
    local recorded_root_inode=""
    local current_root_identity=""
    local full_state=""
    local rollback_mode=""

    normalize_absolute_path_into "$ROLLBACK_TRANSACTION" normalized_transaction || return 2
    ROLLBACK_TRANSACTION="$normalized_transaction"
    [ -d "$ROLLBACK_TRANSACTION" ] && [ ! -L "$ROLLBACK_TRANSACTION" ] || return 2
    path_has_no_symlink_components "$ROLLBACK_TRANSACTION" && directory_components_are_trusted "$ROLLBACK_TRANSACTION" || return 2
    OUTPUT_DIRECTORY="$ROLLBACK_TRANSACTION"
    OUTPUT_DIRECTORY_DEVICE_INODE="$(patcher_stat_device_inode "$OUTPUT_DIRECTORY")" || return 2
    manifest="$OUTPUT_DIRECTORY/orchestrator/manifest.tsv"
    checksum="$OUTPUT_DIRECTORY/orchestrator/manifest.sha256"
    protected_artifact_is_valid "$manifest" && protected_artifact_is_valid "$checksum" || return 2
    IFS=' ' read -r expected suffix < "$checksum" || return 2
    [ "$suffix" = manifest.tsv ] || return 2
    patcher_sha256_into "$manifest" actual || return 2
    [ "$actual" = "$expected" ] || return 2
    while IFS= read -r line || [ -n "$line" ]; do
        IFS=$'\t' read -r schema record_type name value_one value_two value_three extra <<< "$line"
        if [ "$schema:$record_type:$name" = 1:context:root ]; then
            [ -z "$recorded_root" ] && [ -z "$extra" ] || return 2
            recorded_root="$value_one"
            recorded_root_device="$value_two"
            recorded_root_inode="$value_three"
        fi
    done < "$manifest"
    [ -n "$recorded_root" ] || return 2
    if [ "$ROOT_EXPLICIT" -eq 0 ]; then SCAN_ROOT="$recorded_root"; fi
    normalize_absolute_path_into "$SCAN_ROOT" normalized_scan_root || return 2
    [ -d "$normalized_scan_root" ] && path_has_no_symlink_components "$normalized_scan_root" &&
        directory_components_are_trusted "$normalized_scan_root" || return 2
    SCAN_ROOT="$(CDPATH='' cd -P -- "$normalized_scan_root" 2>/dev/null && pwd)" || return 2
    [ "$SCAN_ROOT" = "$recorded_root" ] || return 2
    current_root_identity="$(patcher_stat_device_inode "$SCAN_ROOT")" || return 2
    [ "$current_root_identity" = "$recorded_root_device:$recorded_root_inode" ] || return 2
    protected_artifact_is_valid "$OUTPUT_DIRECTORY/orchestrator/state" || return 2
    IFS= read -r full_state < "$OUTPUT_DIRECTORY/orchestrator/state" || return 2
    case "$full_state" in
        awaiting_post_scan|verified) rollback_mode=strict ;;
        applying|rollback_in_progress|rollback_failed) rollback_mode=transition ;;
        *) return 2 ;;
    esac
    patch_orchestrator_register_builtin_domains || return 2
    console_emit "transaction=$ROLLBACK_TRANSACTION"
    console_emit "rollback_status=started scope=U-01..U-67" >&2
    patch_orchestrator_rollback_transaction "$SCAN_ROOT" "$OUTPUT_DIRECTORY" "$rollback_mode" || return 2
    console_emit "rollback_status=rolled_back scope=U-01..U-67"
}

trap cleanup_patcher EXIT
trap 'handle_signal INT 130' INT
trap 'handle_signal TERM 143' TERM

case "${BASH_SOURCE[0]}" in */*) source_parent="${BASH_SOURCE[0]%/*}" ;; *) source_parent="." ;; esac
PATCHER_CLI_DIRECTORY="$(CDPATH='' cd -P -- "$source_parent" 2>/dev/null && pwd)" || die "cannot resolve the patcher CLI directory"
unset source_parent
case "$PATCHER_CLI_DIRECTORY" in
    */kisa-cce-cli) SCANNER_LIBRARY_DIR="${PATCHER_CLI_DIRECTORY%/kisa-cce-cli}" ;;
    *) die "patcher CLI directory is invalid" ;;
esac

case "$SCANNER_LIBRARY_DIR" in
    */lib/kisa-cce-linux-scanner)
        installation_prefix="${SCANNER_LIBRARY_DIR%/lib/kisa-cce-linux-scanner}"
        data_directory="$installation_prefix/share/kisa-cce-linux-scanner"
        ;;
    */libexec/kisa-cce-linux-scanner)
        installation_prefix="${SCANNER_LIBRARY_DIR%/libexec/kisa-cce-linux-scanner}"
        data_directory="$installation_prefix/share/kisa-cce-linux-scanner"
        ;;
    */lib)
        installation_prefix="${SCANNER_LIBRARY_DIR%/lib}"
        data_directory="$installation_prefix/data"
        ;;
    *) die "cannot determine the patcher library path" ;;
esac
SCANNER_COMMAND="$installation_prefix/bin/kisa-cce-scan"
[ -f "$SCANNER_COMMAND" ] && [ ! -L "$SCANNER_COMMAND" ] && [ -x "$SCANNER_COMMAND" ] ||
    die "scanner command is unavailable: $SCANNER_COMMAND"
[ -r "$data_directory/VERSION" ] || die "scanner version file is unavailable"
IFS= read -r KISA_CCE_VERSION < "$data_directory/VERSION" || die "cannot read the scanner version"
case "$KISA_CCE_VERSION" in ''|*[!0-9A-Za-z.+~-]*) die "invalid scanner version" ;; esac
[ -r "$SCANNER_LIBRARY_DIR/kisa-cce-patcher/_configuration-transaction.sh" ] &&
    [ -r "$SCANNER_LIBRARY_DIR/kisa-cce-patcher/_coverage.sh" ] &&
    [ -r "$SCANNER_LIBRARY_DIR/kisa-cce-patcher/_metadata-rules.sh" ] &&
    [ -r "$SCANNER_LIBRARY_DIR/kisa-cce-patcher/_engine.sh" ] &&
    [ -r "$SCANNER_LIBRARY_DIR/kisa-cce-patcher/_desired-state-policy.sh" ] &&
    [ -r "$SCANNER_LIBRARY_DIR/kisa-cce-patcher/_orchestrator.sh" ] &&
    [ -r "$SCANNER_LIBRARY_DIR/kisa-cce-patcher/_orchestrator-domains.sh" ] || die "patcher engine libraries are unavailable"
# shellcheck source=/dev/null
if ! . "$SCANNER_LIBRARY_DIR/kisa-cce-patcher/_configuration-transaction.sh" 2>/dev/null; then
    die "cannot load the configuration transaction engine"
fi
# shellcheck source=/dev/null
if ! . "$SCANNER_LIBRARY_DIR/kisa-cce-patcher/_coverage.sh" 2>/dev/null; then
    die "cannot load the remediation coverage contract"
fi
patch_coverage_validate || die "invalid remediation coverage contract: ${PATCH_COVERAGE_ERROR_DETAIL:-unknown error}"
# shellcheck source=/dev/null
if ! . "$SCANNER_LIBRARY_DIR/kisa-cce-patcher/_metadata-rules.sh" 2>/dev/null; then
    die "cannot load the metadata rule registry"
fi
# shellcheck source=/dev/null
if ! . "$SCANNER_LIBRARY_DIR/kisa-cce-patcher/_engine.sh" 2>/dev/null; then
    die "cannot load the patch engine"
fi
for patcher_library in \
    _desired-state-policy.sh _account-transaction.sh _filesystem-transaction.sh \
    _inventory-transaction.sh _pam-transaction.sh _service-transaction.sh \
    _system-transaction.sh _network-service-transaction.sh _edge-service-transaction.sh \
    _orchestrator.sh _orchestrator-domains.sh; do
    [ -r "$SCANNER_LIBRARY_DIR/kisa-cce-patcher/$patcher_library" ] ||
        die "full-coverage patcher library is unavailable: $patcher_library"
    # shellcheck source=/dev/null
    . "$SCANNER_LIBRARY_DIR/kisa-cce-patcher/$patcher_library" 2>/dev/null ||
        die "cannot load the full-coverage patcher library: $patcher_library"
done
unset patcher_library

while [ "$#" -gt 0 ]; do
    case "$1" in
        --root)
            require_option_value "$1" "$#" "${2:-}"
            [ "$ROOT_EXPLICIT" -eq 0 ] || die "--root may be specified only once"
            SCAN_ROOT="$2"
            ROOT_EXPLICIT=1
            shift 2
            ;;
        --root=*)
            require_option_value --root 2 "${1#*=}"
            [ "$ROOT_EXPLICIT" -eq 0 ] || die "--root may be specified only once"
            SCAN_ROOT="${1#*=}"
            ROOT_EXPLICIT=1
            shift
            ;;
        --output-dir)
            require_option_value "$1" "$#" "${2:-}"
            [ "$OUTPUT_EXPLICIT" -eq 0 ] || die "--output-dir may be specified only once"
            OUTPUT_DIRECTORY="$2"
            OUTPUT_EXPLICIT=1
            shift 2
            ;;
        --output-dir=*)
            require_option_value --output-dir 2 "${1#*=}"
            [ "$OUTPUT_EXPLICIT" -eq 0 ] || die "--output-dir may be specified only once"
            OUTPUT_DIRECTORY="${1#*=}"
            OUTPUT_EXPLICIT=1
            shift
            ;;
        --checks)
            require_option_value "$1" "$#" "${2:-}"
            [ "$CHECKS_EXPLICIT" -eq 0 ] || die "--checks may be specified only once"
            SELECTED_CHECKS="$2"
            CHECKS_EXPLICIT=1
            shift 2
            ;;
        --checks=*)
            require_option_value --checks 2 "${1#*=}"
            [ "$CHECKS_EXPLICIT" -eq 0 ] || die "--checks may be specified only once"
            SELECTED_CHECKS="${1#*=}"
            CHECKS_EXPLICIT=1
            shift
            ;;
        --apply)
            [ "$APPLY_EXPLICIT" -eq 0 ] || die "--apply may be specified only once"
            APPLY_REQUESTED=1
            APPLY_EXPLICIT=1
            shift
            ;;
        --automatic)
            [ "$AUTOMATIC_REQUESTED" -eq 0 ] || die "--automatic may be specified only once"
            AUTOMATIC_REQUESTED=1
            shift
            ;;
        --desired-state)
            require_option_value "$1" "$#" "${2:-}"
            [ "$DESIRED_STATE_EXPLICIT" -eq 0 ] || die "--desired-state may be specified only once"
            DESIRED_STATE_FILE="$2"
            DESIRED_STATE_EXPLICIT=1
            shift 2
            ;;
        --desired-state=*)
            require_option_value --desired-state 2 "${1#*=}"
            [ "$DESIRED_STATE_EXPLICIT" -eq 0 ] || die "--desired-state may be specified only once"
            DESIRED_STATE_FILE="${1#*=}"
            DESIRED_STATE_EXPLICIT=1
            shift
            ;;
        --rollback)
            require_option_value "$1" "$#" "${2:-}"
            [ -z "$ROLLBACK_TRANSACTION" ] || die "--rollback may be specified only once"
            ROLLBACK_TRANSACTION="$2"
            shift 2
            ;;
        --rollback=*)
            require_option_value --rollback 2 "${1#*=}"
            [ -z "$ROLLBACK_TRANSACTION" ] || die "--rollback may be specified only once"
            ROLLBACK_TRANSACTION="${1#*=}"
            shift
            ;;
        -h|--help) usage; PATCH_COMMAND_COMPLETE=1; exit 0 ;;
        --version) console_emit "kisa-cce-patch $KISA_CCE_VERSION"; PATCH_COMMAND_COMPLETE=1; exit 0 ;;
        --) shift; [ "$#" -eq 0 ] || die "positional arguments are not supported: $1" ;;
        -*) die "unknown option: $1" ;;
        *) die "positional arguments are not supported: $1" ;;
    esac
done

if [ "$AUTOMATIC_REQUESTED" -eq 1 ]; then
    [ "$CHECKS_EXPLICIT" -eq 0 ] || die "--automatic cannot be used with --checks"
    [ -z "$ROLLBACK_TRANSACTION" ] || die "--automatic cannot be used with --rollback"
    [ "$DESIRED_STATE_EXPLICIT" -eq 1 ] || die "--automatic requires --desired-state FILE"
    APPLY_REQUESTED=1
elif [ "$DESIRED_STATE_EXPLICIT" -eq 1 ]; then
    die "--desired-state requires --automatic"
fi
if [ -n "$ROLLBACK_TRANSACTION" ]; then
    [ "$APPLY_REQUESTED" -eq 0 ] || die "--apply and --rollback cannot be used together"
    [ "$CHECKS_EXPLICIT" -eq 0 ] || die "--checks cannot be used with --rollback"
    [ "$OUTPUT_EXPLICIT" -eq 0 ] || die "--output-dir cannot be used with --rollback"
    [ "$DESIRED_STATE_EXPLICIT" -eq 0 ] || die "--desired-state cannot be used with --rollback"
    [ "$EUID" -eq 0 ] || die "rollback operations require root privileges"
    if [ -d "$ROLLBACK_TRANSACTION/orchestrator" ] && [ ! -L "$ROLLBACK_TRANSACTION/orchestrator" ]; then
        rollback_full_transaction || die "full-coverage transaction rollback failed: ${PATCH_ORCHESTRATOR_ERROR_DETAIL:-${PATCH_ORCHESTRATOR_DOMAINS_ERROR_DETAIL:-validation error}}"
        PATCH_COMMAND_COMPLETE=1
        exit 0
    fi
    validate_transaction_directory || die "transaction directory validation failed: $ROLLBACK_TRANSACTION"
    transaction_read_state_into transaction_state || die "transaction state is invalid"
    case "$transaction_state" in
        planned) die "a dry-run transaction cannot be rolled back" ;;
        applied|verified) rollback_policy=strict ;;
        applying|rollback_in_progress|rollback_failed) rollback_policy=transition ;;
        rolled_back|failed) die "transaction state does not permit rollback: $transaction_state" ;;
        *) die "transaction state does not permit rollback: $transaction_state" ;;
    esac
    SELECTED_CHECKS="$TRANSACTION_RECORDED_CHECKS"
    normalize_checks "$SELECTED_CHECKS"
    partition_selected_checks
    join_check_array_into metadata_checks "${PATCH_METADATA_CHECK_ARRAY[@]}"
    join_check_array_into configuration_checks "${PATCH_CONFIGURATION_CHECK_ARRAY[@]}"
    [ "$metadata_checks" = "$TRANSACTION_RECORDED_METADATA_CHECKS" ] &&
        [ "$configuration_checks" = "$TRANSACTION_RECORDED_CONFIGURATION_CHECKS" ] ||
        die "transaction patch domains do not match the selected criteria"
    if [ "$ROOT_EXPLICIT" -eq 0 ]; then
        SCAN_ROOT="$TRANSACTION_RECORDED_ROOT"
    fi
    normalize_absolute_path_into "$SCAN_ROOT" normalized_scan_root || die "transaction root is not a safe absolute path"
    [ -d "$normalized_scan_root" ] || die "transaction root is not a directory: $normalized_scan_root"
    path_has_no_symlink_components "$normalized_scan_root" || die "transaction root contains a symbolic-link component"
    directory_components_are_trusted "$normalized_scan_root" || die "transaction root parent chain is not trusted"
    SCAN_ROOT="$(CDPATH='' cd -P -- "$normalized_scan_root" 2>/dev/null && pwd)" || die "cannot resolve the transaction root"
    [ "$SCAN_ROOT" = "$TRANSACTION_RECORDED_ROOT" ] || die "requested root does not match the transaction manifest"
    current_root_identity="$(patcher_stat_device_inode "$SCAN_ROOT")" || die "cannot inspect the transaction root"
    [ "$current_root_identity" = "$TRANSACTION_RECORDED_ROOT_DEVICE:$TRANSACTION_RECORDED_ROOT_INODE" ] ||
        die "transaction root device or inode changed"
    transaction_set_state rollback_in_progress || die "cannot mark the transaction rollback in progress"
    console_emit "transaction=$ROLLBACK_TRANSACTION"
    console_emit "rollback_status=started" >&2
    rollback_status=0
    if [ "${#PATCH_CONFIGURATION_CHECK_ARRAY[@]}" -gt 0 ]; then
        patch_configuration_reset
        patch_configuration_rollback_transaction \
            "$SCAN_ROOT" "$OUTPUT_DIRECTORY" "$rollback_policy" >/dev/null 2>&1 || rollback_status=$?
    fi
    if [ "$rollback_status" -eq 0 ] && [ "${#PATCH_METADATA_CHECK_ARRAY[@]}" -gt 0 ]; then
        patch_engine_reset
        patch_engine_rollback_transaction \
            "$SCAN_ROOT" "$TRANSACTION_METADATA_PATH" "$rollback_policy" >/dev/null 2>&1 || rollback_status=$?
    fi
    if [ "$rollback_status" -ne 0 ]; then
        transaction_set_state rollback_failed >/dev/null 2>&1 || true
        die "rollback failed: ${PATCH_CONFIGURATION_ERROR_DETAIL:-${PATCH_ENGINE_ERROR_DETAIL:-unknown engine error}}"
    fi
    transaction_set_state rolled_back || die "rollback completed but its state could not be recorded"
    console_emit "rollback_status=rolled_back"
    PATCH_COMMAND_COMPLETE=1
    exit 0
fi

[ -n "$OUTPUT_DIRECTORY" ] || [ "$AUTOMATIC_REQUESTED" -eq 1 ] || die "--output-dir is required"
if [ "$AUTOMATIC_REQUESTED" -eq 1 ]; then
    select_all_criteria
else
    normalize_checks "$SELECTED_CHECKS"
    partition_selected_checks
fi
normalize_absolute_path_into "$SCAN_ROOT" normalized_scan_root || die "--root must be a safe absolute path"
[ -d "$normalized_scan_root" ] || die "scan root is not a directory: $normalized_scan_root"
path_has_no_symlink_components "$normalized_scan_root" || die "scan root contains a symbolic-link component"
directory_components_are_trusted "$normalized_scan_root" || die "scan root parent chain is not trusted"
SCAN_ROOT="$(CDPATH='' cd -P -- "$normalized_scan_root" 2>/dev/null && pwd)" || die "cannot resolve --root"
if [ "$SCAN_ROOT" = "/" ] || [ "$APPLY_REQUESTED" -eq 1 ]; then
    [ "$EUID" -eq 0 ] || die "live assessment, apply, and rollback operations require root privileges"
fi

if [ "$AUTOMATIC_REQUESTED" -eq 1 ] && [ "$OUTPUT_EXPLICIT" -eq 0 ]; then
    prepare_automatic_output_directory
else
    prepare_output_directory
fi
SCRATCH_DIRECTORY="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-patch.XXXXXXXX" 2>/dev/null)" || die "cannot create a secure temporary directory"
chmod 0700 "$SCRATCH_DIRECTORY" 2>/dev/null || die "cannot protect the temporary directory"
if [ "$AUTOMATIC_REQUESTED" -eq 1 ]; then
    console_emit "automatic_status=started transaction=$OUTPUT_DIRECTORY" >&2
fi

if [ "$AUTOMATIC_REQUESTED" -eq 1 ]; then
    compiled_desired_state="$SCRATCH_DIRECTORY/desired-state.tsv"
    patch_desired_state_policy_compile "$DESIRED_STATE_FILE" "$compiled_desired_state" ||
        die "desired-state compilation failed: ${PATCH_DESIRED_STATE_ERROR_DETAIL:-unknown error}"
    desired_state_preflight_status=0
    patch_orchestrator_domains_preflight_profile "$compiled_desired_state" ||
        desired_state_preflight_status=$?
    if [ "$desired_state_preflight_status" -eq 3 ]; then
        console_emit "transaction=$OUTPUT_DIRECTORY"
        console_emit "automatic_status=external_action_required prerequisite=${PATCH_ORCHESTRATOR_DOMAINS_PREREQUISITE:-domain_input}"
        PATCH_COMMAND_COMPLETE=1
        exit 3
    elif [ "$desired_state_preflight_status" -ne 0 ]; then
        die "desired-state domain preflight failed: ${PATCH_ORCHESTRATOR_DOMAINS_ERROR_DETAIL:-unknown error}"
    fi
    run_full_scanner_audit pre-scan
    patch_orchestrator_register_builtin_domains || die "cannot register built-in patch domains"
    orchestrator_plan_status=0
    patch_orchestrator_plan "$compiled_desired_state" "$SCAN_JSONL_PATH" "$SCAN_ROOT" "$OUTPUT_DIRECTORY" ||
        orchestrator_plan_status=$?
    if [ "$orchestrator_plan_status" -eq 3 ]; then
        console_emit "transaction=$OUTPUT_DIRECTORY"
        console_emit "automatic_status=external_action_required prerequisite=${PATCH_ORCHESTRATOR_DOMAINS_PREREQUISITE:-U-64_or_external_domain_input}"
        PATCH_COMMAND_COMPLETE=1
        exit 3
    elif [ "$orchestrator_plan_status" -ne 0 ]; then
        die "full-coverage preflight failed: ${PATCH_ORCHESTRATOR_DOMAINS_ERROR_DETAIL:-${PATCH_ORCHESTRATOR_ERROR_DETAIL:-unknown error}}"
    fi
    console_emit "transaction=$OUTPUT_DIRECTORY"
    console_emit "orchestrator_plan=$OUTPUT_DIRECTORY/orchestrator/manifest.tsv"
    FULL_AUTOMATIC_ACTIVE=1
    PATCH_TRANSACTION_ACTIVE=1
    console_emit "apply_status=started scope=U-01..U-67" >&2
    patch_orchestrator_apply ||
        die "full-coverage apply failed: ${PATCH_ORCHESTRATOR_ERROR_DETAIL:-unknown domain error}"
    run_full_scanner_audit post-scan
    patch_orchestrator_accept_post_scan "$SCAN_JSONL_PATH" ||
        die "full-coverage post-scan failed: ${PATCH_ORCHESTRATOR_ERROR_DETAIL:-nonconforming result}"
    PATCH_TRANSACTION_ACTIVE=0
    FULL_AUTOMATIC_ACTIVE=0
    console_emit "apply_status=verified scope=U-01..U-67"
    console_emit "automatic_status=verified transaction=$OUTPUT_DIRECTORY"
    PATCH_COMMAND_COMPLETE=1
    exit 0
fi

run_scanner_audit pre-scan
patch_engine_reset
patch_configuration_reset
if [ "${#PATCH_METADATA_CHECK_ARRAY[@]}" -gt 0 ]; then
    patch_engine_plan "$SCAN_ROOT" "${PATCH_METADATA_CHECK_ARRAY[@]}" >/dev/null 2>&1 || engine_plan_status=$?
    case "${engine_plan_status:-0}" in
        0) ;;
        1) die "metadata patch engine rejected an unsupported criterion" ;;
        *) die "metadata patch planning failed: ${PATCH_ENGINE_ERROR_DETAIL:-unknown engine error}" ;;
    esac
fi
if [ "${#PATCH_CONFIGURATION_CHECK_ARRAY[@]}" -gt 0 ]; then
    configuration_plan_status=0
    patch_configuration_plan "$SCAN_ROOT" "$OUTPUT_DIRECTORY" \
        "${PATCH_CONFIGURATION_CHECK_ARRAY[@]}" >/dev/null 2>&1 || configuration_plan_status=$?
    case "$configuration_plan_status" in
        0) ;;
        1) die "configuration patch engine rejected an unsupported criterion" ;;
        *) die "configuration patch planning failed: ${PATCH_CONFIGURATION_ERROR_DETAIL:-unknown engine error}" ;;
    esac
fi
verify_patch_plan_matches_scan
TRANSACTION_PLAN_PATH="$OUTPUT_DIRECTORY/plan.tsv"
TRANSACTION_METADATA_PATH="$OUTPUT_DIRECTORY/metadata.tsv"
TRANSACTION_CONFIGURATION_PLAN_PATH="$OUTPUT_DIRECTORY/configuration-plan.tsv"
output_directory_is_current || die "--output-dir changed before plan publication"
if [ "${#PATCH_METADATA_CHECK_ARRAY[@]}" -gt 0 ]; then
    patch_engine_write_plan_tsv "$TRANSACTION_PLAN_PATH" >/dev/null 2>&1 ||
        die "cannot write the metadata patch plan: ${PATCH_ENGINE_ERROR_DETAIL:-unknown engine error}"
    patch_engine_write_transaction_tsv "$TRANSACTION_METADATA_PATH" >/dev/null 2>&1 ||
        die "cannot write the immutable metadata snapshot: ${PATCH_ENGINE_ERROR_DETAIL:-unknown engine error}"
else
    write_protected_artifact "$TRANSACTION_PLAN_PATH" "$PATCH_ENGINE_TSV_HEADER" ||
        die "cannot write the empty metadata patch plan"
    write_protected_artifact "$TRANSACTION_METADATA_PATH" "$PATCH_ENGINE_TSV_HEADER" ||
        die "cannot write the empty metadata snapshot"
fi
if [ "${#PATCH_CONFIGURATION_CHECK_ARRAY[@]}" -gt 0 ]; then
    patch_configuration_write_plan_tsv "$TRANSACTION_CONFIGURATION_PLAN_PATH" >/dev/null 2>&1 ||
        die "cannot write the configuration patch plan: ${PATCH_CONFIGURATION_ERROR_DETAIL:-unknown engine error}"
fi
transaction_write_manifest || die "cannot write the transaction manifest"
transaction_set_state planned || die "cannot write the transaction state"
transaction_write_checksums || die "cannot write the transaction checksums"
console_emit "transaction=$OUTPUT_DIRECTORY"
total_changes=$((PATCH_ENGINE_CHANGE_COUNT + PATCH_CONFIGURATION_CHANGE_COUNT))
total_compliant=$((PATCH_ENGINE_COMPLIANT_COUNT + PATCH_CONFIGURATION_COMPLIANT_COUNT))
console_emit "plan=$TRANSACTION_PLAN_PATH changes=$total_changes compliant=$total_compliant not_applicable=$PATCH_ENGINE_NOT_APPLICABLE_COUNT"
[ "${#PATCH_CONFIGURATION_CHECK_ARRAY[@]}" -eq 0 ] || \
    console_emit "configuration_plan=$TRANSACTION_CONFIGURATION_PLAN_PATH"

if [ "$APPLY_REQUESTED" -eq 0 ]; then
    console_emit "apply_status=not_requested"
    PATCH_COMMAND_COMPLETE=1
    exit 0
fi

PATCH_TRANSACTION_ACTIVE=1
transaction_set_state applying || die "cannot mark the transaction applying"
console_emit "apply_status=started" >&2
if [ "${#PATCH_METADATA_CHECK_ARRAY[@]}" -gt 0 ]; then
    patch_engine_apply >/dev/null 2>&1 ||
        die "metadata patch application failed: ${PATCH_ENGINE_ERROR_DETAIL:-unknown engine error}"
    patch_engine_verify >/dev/null 2>&1 ||
        die "metadata patch verification failed: ${PATCH_ENGINE_ERROR_DETAIL:-unknown engine error}"
fi
if [ "${#PATCH_CONFIGURATION_CHECK_ARRAY[@]}" -gt 0 ]; then
    patch_configuration_apply >/dev/null 2>&1 ||
        die "configuration patch application failed: ${PATCH_CONFIGURATION_ERROR_DETAIL:-unknown engine error}"
    patch_configuration_verify >/dev/null 2>&1 ||
        die "configuration patch verification failed: ${PATCH_CONFIGURATION_ERROR_DETAIL:-unknown engine error}"
fi
transaction_set_state applied || die "cannot mark the transaction applied"
run_scanner_audit post-scan
verify_post_scan
transaction_set_state verified || die "cannot mark the transaction verified"
PATCH_TRANSACTION_ACTIVE=0
console_emit "apply_status=verified"
if [ "$AUTOMATIC_REQUESTED" -eq 1 ]; then
    console_emit "automatic_status=verified transaction=$OUTPUT_DIRECTORY"
fi
PATCH_COMMAND_COMPLETE=1
exit 0
