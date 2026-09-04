# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash

# Compiles author-friendly policy YAML into strict scanner policy directories.

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
export LC_ALL=C
export LANG=C
umask 077

INPUT_PATH=""
OUTPUT_DIRECTORY=""
OUTPUT_PARENT=""
OUTPUT_LEAF=""
OUTPUT_PARENT_FD=""
OUTPUT_PARENT_FD_PATH=""
OUTPUT_PARENT_DEVICE_INODE=""
INPUT_FD=""
INPUT_FD_PATH=""
INPUT_DEVICE_INODE=""
STAGING_DIRECTORY=""
COMPILER_COMPLETE=0

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
        printf '[%s] kisa-cce-policy-compile: %s\n' "$uptime" "$sanitized_line"
    done <<< "$payload"
}

cleanup_compiler() {
    if [ "$COMPILER_COMPLETE" -eq 0 ] && [ -n "$STAGING_DIRECTORY" ] && [ -d "$STAGING_DIRECTORY" ]; then
        rm -rf -- "$STAGING_DIRECTORY"
    fi
    if [ -n "$INPUT_FD" ]; then exec {INPUT_FD}<&-; fi
    if [ -n "$OUTPUT_PARENT_FD" ]; then exec {OUTPUT_PARENT_FD}<&-; fi
}

die() {
    console_emit "ERROR: $*" >&2
    exit 2
}

usage() {
    local line=""

    while IFS= read -r line; do console_emit "$line"; done <<'EOF'
Usage: kisa-cce-policy-compile --input FILE --output-dir PATH

Compile the strict KISA CCE policy YAML subset into a new canonical TSV policy directory.

Options:
  --input FILE       Read policy YAML from FILE.
  --output-dir PATH  Create a new policy directory at PATH.
  -h, --help         Show this help text.
  --version          Show the compiler and scanner policy schema version.

Exit status:
  0  The policy directory was compiled and validated.
  2  Invocation, YAML grammar, policy validation, or output integrity failed.
EOF
}

require_option_value() {
    local option_name="$1"
    local remaining_count="$2"
    local option_value="${3:-}"

    [ "$remaining_count" -ge 2 ] || die "$option_name requires a value"
    [ -n "$option_value" ] || die "$option_name requires a value"
}

compiler_stat_device_inode() {
    local path="$1"

    stat -Lc '%d:%i' -- "$path" 2>/dev/null || stat -f '%d:%i' "$path" 2>/dev/null
}

compiler_path_has_no_symlink_components() {
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

compiler_directory_components_are_trusted() {
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
        owner_uid="$(policy_stat_uid "$current_path")" || return 1
        [ "$owner_uid" = "0" ] || [ "$owner_uid" = "$EUID" ] || return 1
        mode="$(policy_stat_mode "$current_path")" || return 1
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

compiler_output_parent_is_current() {
    local descriptor_device_inode=""
    local lexical_device_inode=""

    [ -n "$OUTPUT_PARENT_DEVICE_INODE" ] || return 1
    descriptor_device_inode="$(compiler_stat_device_inode "$OUTPUT_PARENT_FD_PATH")" || return 1
    lexical_device_inode="$(compiler_stat_device_inode "$OUTPUT_PARENT")" || return 1
    [ "$descriptor_device_inode" = "$OUTPUT_PARENT_DEVICE_INODE" ] &&
        [ "$lexical_device_inode" = "$OUTPUT_PARENT_DEVICE_INODE" ]
}

case "${BASH_SOURCE[0]}" in */*) source_parent="${BASH_SOURCE[0]%/*}" ;; *) source_parent=. ;; esac
COMPILER_CLI_DIRECTORY="$(CDPATH='' cd -P -- "$source_parent" && pwd)" || exit 2
unset source_parent
case "$COMPILER_CLI_DIRECTORY" in
    */kisa-cce-cli) SCANNER_LIBRARY_DIR="${COMPILER_CLI_DIRECTORY%/kisa-cce-cli}" ;;
    *) die "policy compiler CLI directory is invalid" ;;
esac

case "$SCANNER_LIBRARY_DIR" in
    */lib/kisa-cce-linux-scanner)
        data_directory="${SCANNER_LIBRARY_DIR%/lib/kisa-cce-linux-scanner}/share/kisa-cce-linux-scanner"
        ;;
    */libexec/kisa-cce-linux-scanner)
        data_directory="${SCANNER_LIBRARY_DIR%/libexec/kisa-cce-linux-scanner}/share/kisa-cce-linux-scanner"
        ;;
    */lib) data_directory="${SCANNER_LIBRARY_DIR%/lib}/data" ;;
    *) die "cannot determine the policy compiler library path" ;;
esac
[ -r "$SCANNER_LIBRARY_DIR/kisa-cce-policy/_policy.sh" ] &&
    [ -r "$SCANNER_LIBRARY_DIR/kisa-cce-policy/_policy-yaml.sh" ] ||
    die "policy compiler libraries are unavailable"
[ -r "$data_directory/VERSION" ] || die "scanner version file is unavailable"
IFS= read -r KISA_CCE_VERSION < "$data_directory/VERSION" || die "cannot read the scanner version"

# shellcheck source=/dev/null
. "$SCANNER_LIBRARY_DIR/kisa-cce-policy/_policy.sh"
# shellcheck source=/dev/null
. "$SCANNER_LIBRARY_DIR/kisa-cce-policy/_policy-yaml.sh"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --input)
            require_option_value "$1" "$#" "${2:-}"
            INPUT_PATH="$2"
            shift 2
            ;;
        --input=*)
            require_option_value --input 2 "${1#*=}"
            INPUT_PATH="${1#*=}"
            shift
            ;;
        --output-dir)
            require_option_value "$1" "$#" "${2:-}"
            OUTPUT_DIRECTORY="$2"
            shift 2
            ;;
        --output-dir=*)
            require_option_value --output-dir 2 "${1#*=}"
            OUTPUT_DIRECTORY="${1#*=}"
            shift
            ;;
        -h|--help) usage; exit 0 ;;
        --version) console_emit "kisa-cce-policy-compile $KISA_CCE_VERSION policy-yaml-schema=1"; exit 0 ;;
        --) shift; [ "$#" -eq 0 ] || die "positional arguments are not supported: $1" ;;
        -*) die "unknown option: $1" ;;
        *) die "positional arguments are not supported: $1" ;;
    esac
done

[ -n "$INPUT_PATH" ] || die "--input is required"
[ -n "$OUTPUT_DIRECTORY" ] || die "--output-dir is required"
case "$INPUT_PATH:$OUTPUT_DIRECTORY" in *$'\n'*|*$'\r'*|*$'\t'*) die "paths contain a disallowed control character" ;; esac

while [ "${INPUT_PATH#./}" != "$INPUT_PATH" ]; do INPUT_PATH="${INPUT_PATH#./}"; done
case "$INPUT_PATH" in /*) ;; *) INPUT_PATH="$PWD/$INPUT_PATH" ;; esac
case "$INPUT_PATH" in */./*|*/../*|*/.|*/..) die "input path contains an explicit dot component" ;; esac
input_parent="${INPUT_PATH%/*}"
input_leaf="${INPUT_PATH##*/}"
case "$input_leaf" in ''|.|..) die "invalid input filename" ;; esac
compiler_path_has_no_symlink_components "$input_parent" || die "input parent path contains a symbolic link"
compiler_directory_components_are_trusted "$input_parent" || die "input parent path is not trusted"
input_parent="$(CDPATH='' cd -P -- "$input_parent" && pwd)" || die "cannot resolve the input parent directory"
INPUT_PATH="${input_parent%/}/$input_leaf"
policy_path_is_trusted "$INPUT_PATH" file || die "input policy YAML is not a trusted regular file"
INPUT_DEVICE_INODE="$(compiler_stat_device_inode "$INPUT_PATH")" || die "cannot read the input policy identity"
exec {INPUT_FD}<"$INPUT_PATH" || die "cannot open the input policy YAML"
INPUT_FD_PATH="/proc/self/fd/$INPUT_FD"
[ -f "$INPUT_FD_PATH" ] || die "cannot pin the input policy YAML"
[ "$(compiler_stat_device_inode "$INPUT_FD_PATH")" = "$INPUT_DEVICE_INODE" ] ||
    die "input policy YAML changed while it was opened"

while [ "${OUTPUT_DIRECTORY#./}" != "$OUTPUT_DIRECTORY" ]; do
    OUTPUT_DIRECTORY="${OUTPUT_DIRECTORY#./}"
done
case "$OUTPUT_DIRECTORY" in /*) ;; *) OUTPUT_DIRECTORY="$PWD/$OUTPUT_DIRECTORY" ;; esac
case "$OUTPUT_DIRECTORY" in */./*|*/../*|*/.|*/..) die "output path contains an explicit dot component" ;; esac
while [ "$OUTPUT_DIRECTORY" != "/" ] && [ "${OUTPUT_DIRECTORY%/}" != "$OUTPUT_DIRECTORY" ]; do
    OUTPUT_DIRECTORY="${OUTPUT_DIRECTORY%/}"
done
OUTPUT_PARENT="${OUTPUT_DIRECTORY%/*}"
OUTPUT_LEAF="${OUTPUT_DIRECTORY##*/}"
case "$OUTPUT_LEAF" in ''|.|..) die "invalid output directory name" ;; esac
[ -d "$OUTPUT_PARENT" ] && [ ! -L "$OUTPUT_PARENT" ] || die "output parent must be a physical directory"
compiler_path_has_no_symlink_components "$OUTPUT_PARENT" || die "output parent path contains a symbolic link"
compiler_directory_components_are_trusted "$OUTPUT_PARENT" || die "output parent path is not trusted"
OUTPUT_PARENT="$(CDPATH='' cd -P -- "$OUTPUT_PARENT" && pwd)" || die "cannot resolve the output parent directory"
OUTPUT_DIRECTORY="${OUTPUT_PARENT%/}/$OUTPUT_LEAF"
[ ! -e "$OUTPUT_DIRECTORY" ] && [ ! -L "$OUTPUT_DIRECTORY" ] || die "output directory already exists"
policy_path_is_trusted "$OUTPUT_PARENT" directory || die "output parent directory is not trusted"
OUTPUT_PARENT_DEVICE_INODE="$(compiler_stat_device_inode "$OUTPUT_PARENT")" ||
    die "cannot read the output parent identity"
exec {OUTPUT_PARENT_FD}<"$OUTPUT_PARENT" || die "cannot open the output parent directory"
OUTPUT_PARENT_FD_PATH="/proc/self/fd/$OUTPUT_PARENT_FD"
[ -d "$OUTPUT_PARENT_FD_PATH" ] || die "cannot pin the output parent directory"
compiler_output_parent_is_current || die "output parent directory changed while it was opened"

trap cleanup_compiler EXIT
STAGING_DIRECTORY="$(mktemp -d "$OUTPUT_PARENT_FD_PATH/.kisa-cce-policy.XXXXXXXX")" ||
    die "cannot create the policy staging directory"
chmod 0700 "$STAGING_DIRECTORY" || die "cannot protect the policy staging directory"
mkdir -m 0700 "$STAGING_DIRECTORY/facts" || die "cannot create the policy facts staging directory"
attestation_file="$STAGING_DIRECTORY/50-compiled.tsv"
time_source_file="$STAGING_DIRECTORY/facts/time-sources.tsv"
error_file="$STAGING_DIRECTORY/yaml-error"
: > "$error_file"
chmod 0600 "$error_file" || die "cannot protect the YAML diagnostic file"
if ! policy_yaml_compile "$INPUT_FD_PATH" "$attestation_file" "$time_source_file" "$error_file"; then
    IFS= read -r yaml_error < "$error_file" || yaml_error="invalid YAML structure"
    die "invalid policy YAML: $yaml_error"
fi
rm -f -- "$error_file"
chmod 0600 "$attestation_file" || die "cannot protect the compiled attestation file"
if [ -e "$time_source_file" ]; then
    chmod 0600 "$time_source_file" || die "cannot protect the compiled time-source file"
else
    rmdir "$STAGING_DIRECTORY/facts" || die "cannot finalize the policy facts directory"
fi
policy_load_dir "$STAGING_DIRECTORY" || die "compiled policy failed canonical validation"

[ ! -e "$OUTPUT_DIRECTORY" ] && [ ! -L "$OUTPUT_DIRECTORY" ] || die "output directory appeared during compilation"
compiler_output_parent_is_current || die "output parent directory changed during compilation"
published_directory="$OUTPUT_PARENT_FD_PATH/$OUTPUT_LEAF"
mv -n -T -- "$STAGING_DIRECTORY" "$published_directory" || die "cannot publish the compiled policy directory"
[ ! -e "$STAGING_DIRECTORY" ] || die "output directory appeared during compilation"
STAGING_DIRECTORY=""
[ "$(compiler_stat_device_inode "$OUTPUT_PARENT_FD_PATH/$OUTPUT_LEAF")" = \
    "$(compiler_stat_device_inode "$OUTPUT_DIRECTORY")" ] || die "compiled policy directory binding changed"
[ -d "$OUTPUT_DIRECTORY" ] && [ ! -L "$OUTPUT_DIRECTORY" ] || die "compiled policy directory binding changed"
COMPILER_COMPLETE=1
console_emit "policy_directory=$OUTPUT_DIRECTORY"
console_emit "policy_digest=$POLICY_SET_DIGEST"
