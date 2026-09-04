# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash

# Collects a bounded live-system snapshot for a later offline assessment.

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
export LC_ALL=C
export LANG=C
umask 077

OUTPUT_DIRECTORY=""
OUTPUT_DIRECTORY_FD=""
OUTPUT_DIRECTORY_FD_PATH=""
OUTPUT_DIRECTORY_DEVICE_INODE=""
SCRATCH_DIRECTORY=""
COLLECTOR_COMPLETE=0

console_uptime_into() {
    local __kisa_collect_destination="$1"
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
    printf -v "$__kisa_collect_destination" '%6s.%s' "$uptime_seconds" "$uptime_fraction"
}

console_emit() {
    local payload="${1-}"
    local line=""
    local sanitized_line=""
    local uptime=""

    while IFS= read -r line || [ -n "$line" ]; do
        console_sanitize_line_into "$line" sanitized_line
        console_uptime_into uptime
        printf '[%s] kisa-cce-collect: %s\n' "$uptime" "$sanitized_line"
    done <<< "$payload"
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

die() {
    console_emit "ERROR: $*" >&2
    exit 2
}

warn() {
    console_emit "WARNING: $*" >&2
}

usage() {
    local line=""

    while IFS= read -r line; do
        console_emit "$line"
    done <<'EOF'
Usage: kisa-cce-collect --output-dir PATH

Collect a minimal live Linux runtime snapshot into an owner-only directory.
The command must run as root on the live system being assessed.

Options:
  --output-dir PATH  Create or use an empty absolute directory for the bundle.
  -h, --help         Show this help text.
  --version          Show the evidence schema version.

Exit status:
  0  Collection completed. Individual optional sources may be unavailable.
  2  Invocation, identity, output-integrity, or collection-finalization error.
EOF
}

require_option_value() {
    local option_name="$1"
    local remaining_count="$2"
    local option_value="${3:-}"

    [ "$remaining_count" -ge 2 ] || die "$option_name requires a value"
    [ -n "$option_value" ] || die "$option_name requires a value"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
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
        -h|--help)
            usage
            exit 0
            ;;
        --version)
            console_emit "kisa-cce-collect evidence-schema-2"
            exit 0
            ;;
        --)
            shift
            [ "$#" -eq 0 ] || die "positional arguments are not supported: $1"
            ;;
        -*) die "unknown option: $1" ;;
        *) die "positional arguments are not supported: $1" ;;
    esac
done

[ -n "$OUTPUT_DIRECTORY" ] || die "--output-dir is required"
[ "$(id -u)" -eq 0 ] || die "runtime evidence collection requires root privileges"
[ "$(uname -s 2>/dev/null)" = "Linux" ] || die "runtime evidence collection is supported only on a live Linux root"

case "$OUTPUT_DIRECTORY" in
    /*) ;;
    *) die "--output-dir must be an absolute path: $OUTPUT_DIRECTORY" ;;
esac
case "$OUTPUT_DIRECTORY" in
    *$'\n'*|*$'\r'*|*$'\t'*) die "--output-dir contains a disallowed control character" ;;
    */../*|*/..|*/./*|*/.) die "--output-dir cannot contain . or .. path components" ;;
esac
while [ "$OUTPUT_DIRECTORY" != "/" ] && [ "${OUTPUT_DIRECTORY%/}" != "$OUTPUT_DIRECTORY" ]; do
    OUTPUT_DIRECTORY="${OUTPUT_DIRECTORY%/}"
done
[ "$OUTPUT_DIRECTORY" != "/" ] || die "the root directory cannot be used as the evidence output directory"

stat_mode_owner_inode() {
    stat -c '%a %u %d:%i' -- "$1" 2>/dev/null
}

validate_physical_directory() {
    local directory="$1"
    local canonical_directory=""

    [ -d "$directory" ] && [ ! -L "$directory" ] || return 1
    canonical_directory="$(CDPATH='' cd -P -- "$directory" 2>/dev/null && pwd)" || return 1
    [ "$canonical_directory" = "$directory" ]
}

prepare_output_directory() {
    local parent_directory="${OUTPUT_DIRECTORY%/*}"
    local metadata=""
    local mode=""
    local owner=""
    local entry=""

    [ -n "$parent_directory" ] || parent_directory="/"
    validate_physical_directory "$parent_directory" ||
        die "output parent path contains a symbolic link or is not a directory: $parent_directory"

    if [ -e "$OUTPUT_DIRECTORY" ] || [ -L "$OUTPUT_DIRECTORY" ]; then
        [ -d "$OUTPUT_DIRECTORY" ] && [ ! -L "$OUTPUT_DIRECTORY" ] ||
            die "output path is not a physical directory: $OUTPUT_DIRECTORY"
        validate_physical_directory "$OUTPUT_DIRECTORY" ||
            die "output path cannot contain symbolic links: $OUTPUT_DIRECTORY"
    else
        mkdir -m 0700 -- "$OUTPUT_DIRECTORY" ||
            die "cannot create the output directory: $OUTPUT_DIRECTORY"
    fi

    metadata="$(stat_mode_owner_inode "$OUTPUT_DIRECTORY")" ||
        die "cannot read output directory metadata: $OUTPUT_DIRECTORY"
    read -r mode owner OUTPUT_DIRECTORY_DEVICE_INODE <<< "$metadata"
    [ "$mode" = "700" ] || die "output directory mode must be 0700: $OUTPUT_DIRECTORY"
    [ "$owner" = "0" ] || die "output directory must be owned by root: $OUTPUT_DIRECTORY"

    shopt -s nullglob dotglob
    for entry in "$OUTPUT_DIRECTORY"/*; do
        die "output directory is not empty: $entry"
    done
    shopt -u nullglob dotglob

    exec {OUTPUT_DIRECTORY_FD}<"$OUTPUT_DIRECTORY" ||
        die "cannot pin the output directory: $OUTPUT_DIRECTORY"
    OUTPUT_DIRECTORY_FD_PATH="/proc/self/fd/$OUTPUT_DIRECTORY_FD"
    [ -d "$OUTPUT_DIRECTORY_FD_PATH" ] || die "output directory descriptor is unavailable"
}

cleanup() {
    local status=$?

    if [ -n "$SCRATCH_DIRECTORY" ] && [ -d "$SCRATCH_DIRECTORY" ] && [ ! -L "$SCRATCH_DIRECTORY" ]; then
        rm -rf -- "$SCRATCH_DIRECTORY"
    fi
    if [ -n "$OUTPUT_DIRECTORY_FD" ]; then
        exec {OUTPUT_DIRECTORY_FD}<&-
    fi
    if [ "$status" -ne 0 ] && [ "$COLLECTOR_COMPLETE" -ne 1 ]; then
        warn "an incomplete evidence directory may remain: $OUTPUT_DIRECTORY"
    fi
    return "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

prepare_output_directory
SCRATCH_DIRECTORY="$(mktemp -d /tmp/kisa-cce-collect.XXXXXXXXXX)" ||
    die "cannot create the temporary working directory"
[ -d "$SCRATCH_DIRECTORY" ] && [ ! -L "$SCRATCH_DIRECTORY" ] ||
    die "temporary working directory is unsafe"
chmod 0700 -- "$SCRATCH_DIRECTORY" || die "cannot set temporary working directory permissions"

mkdir -m 0700 -- "$OUTPUT_DIRECTORY_FD_PATH/identity" "$OUTPUT_DIRECTORY_FD_PATH/runtime" ||
    die "cannot create evidence subdirectories"

normalize_single_line() {
    tr -d '\r\n' | tr '\t' ' '
}

machine_id="$(head -n 1 /etc/machine-id 2>/dev/null | normalize_single_line)"
case "$machine_id" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    *) die "cannot collect a valid /etc/machine-id" ;;
esac
[ "$machine_id" != "00000000000000000000000000000000" ] || die "/etc/machine-id is not initialized"

boot_id="$(head -n 1 /proc/sys/kernel/random/boot_id 2>/dev/null | normalize_single_line)"
case "$boot_id" in
    ????????-????-????-????-????????????) ;;
    *) die "cannot collect a valid current boot ID" ;;
esac
case "$boot_id" in
    *[!0-9a-f-]*) die "cannot collect a valid current boot ID" ;;
esac

kernel_release="$(uname -r 2>/dev/null | normalize_single_line)"
case "$kernel_release" in
    ''|*[!0-9A-Za-z._+~-]*) die "cannot collect a valid kernel release" ;;
esac
captured_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')" || die "cannot generate the UTC capture time"

os_release_source=""
for candidate in /etc/os-release /usr/lib/os-release; do
    if [ -f "$candidate" ] && [ -r "$candidate" ]; then
        os_release_source="$candidate"
        break
    fi
done
[ -n "$os_release_source" ] || die "cannot collect an os-release file"
cat -- "$os_release_source" > "$OUTPUT_DIRECTORY_FD_PATH/identity/os-release" ||
    die "cannot write the os-release file"
[ -s "$OUTPUT_DIRECTORY_FD_PATH/identity/os-release" ] || die "os-release file is empty"
printf '%s\n' "$machine_id" > "$OUTPUT_DIRECTORY_FD_PATH/identity/machine-id" || die "cannot write machine-id"
printf '%s\n' "$boot_id" > "$OUTPUT_DIRECTORY_FD_PATH/identity/boot-id" || die "cannot write boot-id"
printf '%s\n' "$kernel_release" > "$OUTPUT_DIRECTORY_FD_PATH/identity/kernel-release" || die "cannot write kernel-release"

systemd_unit_files_status="unavailable"
systemd_units_status="unavailable"
listeners_status="unavailable"
mountinfo_status="unavailable"
firewall_status="unavailable"
time_sync_status="unavailable"

collect_systemd_unit_files() {
    local raw_file="$SCRATCH_DIRECTORY/systemd-unit-files.raw"
    local output_file="$OUTPUT_DIRECTORY_FD_PATH/runtime/systemd-unit-files.tsv"

    printf 'unit\tunit_file_state\tpreset\n' > "$output_file" || return 1
    command -v systemctl >/dev/null 2>&1 || return 2
    if ! systemctl list-unit-files --type=service --type=socket --no-legend --no-pager --plain > "$raw_file" 2>/dev/null; then
        return 2
    fi
    awk '
        $1 ~ /\.(service|socket)$/ && $2 ~ /^[A-Za-z0-9_.:+-]+$/ {
            preset=$3
            if (preset == "" || preset !~ /^[A-Za-z0-9_.:+-]+$/) preset="-"
            print $1 "\t" $2 "\t" preset
        }
    ' "$raw_file" | LC_ALL=C sort -u >> "$output_file" || return 1
    return 0
}

collect_systemd_units() {
    local raw_units="$SCRATCH_DIRECTORY/systemd-units.raw"
    local names_file="$SCRATCH_DIRECTORY/systemd-unit-names"
    local output_file="$OUTPUT_DIRECTORY_FD_PATH/runtime/systemd-units.tsv"
    local unit=""
    local properties=""
    local load_state=""
    local active_state=""
    local sub_state=""
    local unit_file_state=""
    local state_name=""
    local state_value=""
    local partial=0

    printf 'unit\tload_state\tactive_state\tsub_state\tunit_file_state\n' > "$output_file" || return 1
    command -v systemctl >/dev/null 2>&1 || return 2
    if ! systemctl list-units --all --type=service --type=socket --no-legend --no-pager --plain > "$raw_units" 2>/dev/null; then
        return 2
    fi
    {
        awk '$1 ~ /\.(service|socket)$/ {print $1}' "$raw_units"
        if [ -s "$OUTPUT_DIRECTORY_FD_PATH/runtime/systemd-unit-files.tsv" ]; then
            awk -F '\t' 'NR > 1 {print $1}' "$OUTPUT_DIRECTORY_FD_PATH/runtime/systemd-unit-files.tsv"
        fi
    } | LC_ALL=C sort -u > "$names_file" || return 1

    while IFS= read -r unit || [ -n "$unit" ]; do
        case "$unit" in
            ''|-*|*$'\t'*|*$'\n'*|*$'\r'*) partial=1; continue ;;
            *) ;;
        esac
        case "$unit" in
            *.service|*.socket) ;;
            *) partial=1; continue ;;
        esac
        properties="$(systemctl show \
            -p LoadState -p ActiveState -p SubState -p UnitFileState --no-pager \
            -- "$unit" 2>/dev/null)" || partial=1
        load_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "LoadState" {print $2; exit}')"
        active_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "ActiveState" {print $2; exit}')"
        sub_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "SubState" {print $2; exit}')"
        unit_file_state="$(printf '%s\n' "$properties" | awk -F= '$1 == "UnitFileState" {print $2; exit}')"
        for state_name in load_state active_state sub_state unit_file_state; do
            state_value="${!state_name}"
            case "$state_value" in
                ''|*[!0-9A-Za-z_.:+~-]*) printf -v "$state_name" '%s' unknown ;;
            esac
        done
        printf '%s\t%s\t%s\t%s\t%s\n' \
            "$unit" "$load_state" "$active_state" "$sub_state" "$unit_file_state" >> "$output_file" || return 1
    done < "$names_file"

    [ "$partial" -eq 0 ] || return 3
    return 0
}

collect_listeners() {
    local raw_file="$SCRATCH_DIRECTORY/listeners.raw"
    local output_file="$OUTPUT_DIRECTORY_FD_PATH/runtime/listeners.tsv"

    printf 'transport\tlocal_address\tport\tprocess\n' > "$output_file" || return 1
    command -v ss >/dev/null 2>&1 || return 2
    if ! ss -H -lntup > "$raw_file" 2>/dev/null; then
        return 2
    fi
    awk '
        function clean_process(value) {
            gsub(/[^0-9A-Za-z_.@:+-]/, "_", value)
            return value
        }
        {
            transport=tolower($1)
            if (transport != "tcp" && transport != "udp") next
            endpoint=$5
            port=endpoint
            sub(/^.*:/, "", port)
            address=endpoint
            sub(/:[^:]*$/, "", address)
            sub(/^\[/, "", address)
            sub(/\]$/, "", address)
            process=""
            if (match($0, /users:\(\("[^"]+"/)) {
                process=substr($0, RSTART + 9, RLENGTH - 9)
                process=clean_process(process)
            }
            if (port ~ /^[0-9]+$/ && port >= 0 && port <= 65535)
                print transport "\t" address "\t" port "\t" process
        }
    ' "$raw_file" | LC_ALL=C sort -u >> "$output_file" || return 1
    return 0
}

collect_mountinfo() {
    local output_file="$OUTPUT_DIRECTORY_FD_PATH/runtime/mountinfo"

    [ -r /proc/1/mountinfo ] || return 2
    cat -- /proc/1/mountinfo > "$output_file" || return 1
    [ -s "$output_file" ] || return 2
    return 0
}

collect_firewall() {
    local output_file="$OUTPUT_DIRECTORY_FD_PATH/runtime/firewall.txt"
    local raw_file="$SCRATCH_DIRECTORY/firewall.raw"
    local collected=0

    : > "$output_file" || return 1
    if command -v nft >/dev/null 2>&1; then
        if nft -n list ruleset > "$raw_file" 2>/dev/null; then
            {
                printf '%s\n' 'collector=nft'
                sed -E \
                    's/[[:space:]]+comment "([^"\\]|\\.)*"//g; s/[[:space:]]+log prefix "([^"\\]|\\.)*"//g; s/[[:space:]]+counter packets [0-9]+ bytes [0-9]+//g' \
                    "$raw_file"
            } > "$output_file" || return 1
            collected=1
        fi
    fi
    if [ "$collected" -eq 0 ] && command -v iptables-save >/dev/null 2>&1; then
        if iptables-save > "$raw_file" 2>/dev/null; then
            {
                printf '%s\n' 'collector=iptables'
                sed -E 's/[[:space:]]+-m comment --comment ("[^"]*"|[^[:space:]]+)//g' "$raw_file"
                if command -v ip6tables-save >/dev/null 2>&1 && ip6tables-save > "$raw_file.ip6" 2>/dev/null; then
                    printf '%s\n' '[ip6tables]'
                    sed -E 's/[[:space:]]+-m comment --comment ("[^"]*"|[^[:space:]]+)//g' "$raw_file.ip6"
                fi
            } > "$output_file" || return 1
            collected=1
        fi
    fi
    if [ "$collected" -eq 0 ]; then
        printf 'status=unavailable\n' > "$output_file" || return 1
        return 2
    fi
    return 0
}

time_sync_safe_field() {
    case "${1:-}" in
        ''|*[!0-9A-Za-z._:@%+-]*) return 1 ;;
        *) return 0 ;;
    esac
}

time_sync_write_row() {
    local output_file="$1"
    local provider="$2"
    local synchronized="$3"
    local source="$4"
    local source_address="$5"
    local stratum="$6"
    local leap="$7"
    local source_origin="$8"
    local source_type="$9"

    case "$provider" in systemd-timesyncd|chrony|ntpsec) ;; *) return 3 ;; esac
    case "$synchronized" in yes|no|unknown) ;; *) return 3 ;; esac
    if [ "$source" != "-" ]; then time_sync_safe_field "$source" || return 3; fi
    if [ "$source_address" != "-" ]; then time_sync_safe_field "$source_address" || return 3; fi
    [ "${#source}" -le 255 ] && [ "${#source_address}" -le 255 ] || return 3
    case "$stratum" in
        -) ;;
        ''|*[!0-9]*) return 3 ;;
        *) [ "$stratum" -le 16 ] || return 3 ;;
    esac
    case "$leap" in normal|warning|unsynchronized|unknown) ;; *) return 3 ;; esac
    case "$source_origin" in system|runtime|fallback|configured|unknown) ;; *) return 3 ;; esac
    case "$source_type" in network|reference-clock|unknown) ;; *) return 3 ;; esac
    [ "$synchronized" != "yes" ] || [ "$source" != "-" ] || [ "$source_address" != "-" ] || return 3
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$provider" "$synchronized" "$source" "$source_address" \
        "$stratum" "$leap" "$source_origin" "$source_type" >> "$output_file" || return 1
}

time_sync_list_contains() {
    local values="$1"
    local expected_name="$2"
    local expected_address="$3"
    local candidate=""
    local -a candidates=()

    read -r -a candidates <<< "$values"
    for candidate in "${candidates[@]}"; do
        [ -n "$expected_name" ] && [ "$candidate" = "$expected_name" ] && return 0
        [ -n "$expected_address" ] && [ "$candidate" = "$expected_address" ] && return 0
    done
    return 1
}

collect_timesyncd_normalized() {
    local output_file="$1"
    local state_file="$SCRATCH_DIRECTORY/timesyncd-state.raw"
    local properties_file="$SCRATCH_DIRECTORY/timesyncd-properties.raw"
    local synchronized=""
    local source=""
    local source_address=""
    local stratum="-"
    local leap_indicator=""
    local leap="unknown"
    local system_sources=""
    local runtime_sources=""
    local fallback_sources=""
    local source_origin="unknown"
    local source_type="unknown"
    local match_source=""
    local match_address=""

    timedatectl show -p NTPSynchronized --value --no-pager > "$state_file" 2>/dev/null || return 2
    timedatectl show-timesync --all --no-pager > "$properties_file" 2>/dev/null || return 2
    IFS= read -r synchronized < "$state_file" || synchronized=""
    source="$(awk -F= '$1 == "ServerName" {print substr($0, index($0, "=") + 1); exit}' "$properties_file")"
    source_address="$(awk -F= '$1 == "ServerAddress" {print substr($0, index($0, "=") + 1); exit}' "$properties_file")"
    system_sources="$(awk -F= '$1 == "SystemNTPServers" {print substr($0, index($0, "=") + 1); exit}' "$properties_file")"
    runtime_sources="$(awk -F= '$1 == "RuntimeNTPServers" {print substr($0, index($0, "=") + 1); exit}' "$properties_file")"
    fallback_sources="$(awk -F= '$1 == "FallbackNTPServers" {print substr($0, index($0, "=") + 1); exit}' "$properties_file")"
    stratum="$(sed -n 's/^NTPMessage=.*Stratum=\([0-9][0-9]*\).*/\1/p' "$properties_file" | head -n 1)"
    leap_indicator="$(sed -n 's/^NTPMessage=.*Leap=\([0-9][0-9]*\).*/\1/p' "$properties_file" | head -n 1)"

    case "$synchronized" in yes|no) ;; *) synchronized="unknown" ;; esac
    case "$source" in ''|n/a) source="-" ;; esac
    case "$source_address" in
        ''|n/a) source_address="-" ;;
        \[*\]) source_address="${source_address#\[}"; source_address="${source_address%\]}" ;;
    esac
    case "$stratum" in ''|*[!0-9]*) stratum="-" ;; esac
    case "$leap_indicator" in
        0) leap="normal" ;;
        1|2) leap="warning" ;;
        3) leap="unsynchronized" ;;
        *) [ "$synchronized" = "no" ] && leap="unsynchronized" ;;
    esac
    if [ "$source" != "-" ] || [ "$source_address" != "-" ]; then
        source_type="network"
        [ "$source" = "-" ] || match_source="$source"
        [ "$source_address" = "-" ] || match_address="$source_address"
        if time_sync_list_contains "$system_sources" "$match_source" "$match_address"; then
            source_origin="system"
        elif time_sync_list_contains "$fallback_sources" "$match_source" "$match_address"; then
            source_origin="fallback"
        elif time_sync_list_contains "$runtime_sources" "$match_source" "$match_address"; then
            source_origin="runtime"
        fi
    fi
    time_sync_write_row "$output_file" systemd-timesyncd "$synchronized" \
        "$source" "$source_address" "$stratum" "$leap" "$source_origin" "$source_type" || return $?
    [ "$synchronized:$leap" != "yes:unknown" ] || return 3
    return 0
}

collect_chrony_normalized() {
    local output_file="$1"
    local tracking_file="$SCRATCH_DIRECTORY/chrony-tracking.raw"
    local sources_file="$SCRATCH_DIRECTORY/chrony-sources.raw"
    local leap_status=""
    local leap="unknown"
    local selected=""
    local source="-"
    local source_type="unknown"
    local stratum="-"
    local synchronized="no"

    chronyc -n tracking > "$tracking_file" 2>/dev/null || return 2
    chronyc -n sources > "$sources_file" 2>/dev/null || return 2
    leap_status="$(awk -F: '/^Leap status/ {value=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); print value; exit}' "$tracking_file")"
    selected="$(awk '$1 ~ /^[\^=#]\*/ {print substr($1, 1, 1) "\t" $2 "\t" $3; exit}' "$sources_file")"
    if [ -n "$selected" ]; then
        IFS=$'\t' read -r source_type source stratum <<< "$selected"
        case "$source_type" in
            '#') source_type="reference-clock" ;;
            '^'|'=') source_type="network" ;;
            *) source_type="unknown" ;;
        esac
        case "$stratum" in ''|*[!0-9]*) stratum="-" ;; esac
    fi
    case "$leap_status" in
        Normal) leap="normal" ;;
        "Not synchronised"|"Not synchronized") leap="unsynchronized" ;;
        "Insert second"|"Delete second") leap="warning" ;;
        *) leap="unknown" ;;
    esac
    if [ "$leap" = "normal" ] && [ "$source" != "-" ]; then synchronized="yes"; fi
    time_sync_write_row "$output_file" chrony "$synchronized" "$source" "$source" \
        "$stratum" "$leap" runtime "$source_type" || return $?
    [ "$leap" != "unknown" ] || return 3
    return 0
}

collect_ntpsec_normalized() {
    local output_file="$1"
    local peers_file="$SCRATCH_DIRECTORY/ntpsec-peers.raw"
    local selected=""
    local marker=""
    local source="-"
    local source_type="unknown"
    local stratum="-"
    local synchronized="no"

    ntpq -pn > "$peers_file" 2>/dev/null || return 2
    [ -s "$peers_file" ] || return 3
    selected="$(awk '$1 ~ /^[*o]/ {print substr($1, 1, 1) "\t" substr($1, 2) "\t" $3; exit}' "$peers_file")"
    if [ -n "$selected" ]; then
        IFS=$'\t' read -r marker source stratum <<< "$selected"
        synchronized="yes"
        case "$marker" in
            '*') source_type="network" ;;
            o) source_type="reference-clock" ;;
            *) source_type="unknown" ;;
        esac
        case "$stratum" in ''|*[!0-9]*) stratum="-" ;; esac
    fi
    time_sync_write_row "$output_file" ntpsec "$synchronized" "$source" "$source" \
        "$stratum" unknown runtime "$source_type"
}

collect_time_sync() {
    local output_file="$OUTPUT_DIRECTORY_FD_PATH/runtime/time-sync.tsv"
    local collector_status=0
    local partial=0
    local records=0

    printf 'provider\tsynchronized\tsource\tsource_address\tstratum\tleap\tsource_origin\tsource_type\n' > "$output_file" || return 1
    if command -v timedatectl >/dev/null 2>&1; then
        collect_timesyncd_normalized "$output_file" || collector_status=$?
        case "$collector_status" in 0|2) ;; 3) partial=1 ;; *) return 1 ;; esac
        collector_status=0
    fi
    if command -v chronyc >/dev/null 2>&1; then
        collect_chrony_normalized "$output_file" || collector_status=$?
        case "$collector_status" in 0|2) ;; 3) partial=1 ;; *) return 1 ;; esac
        collector_status=0
    fi
    if command -v ntpq >/dev/null 2>&1; then
        collect_ntpsec_normalized "$output_file" || collector_status=$?
        case "$collector_status" in 0|2) ;; 3) partial=1 ;; *) return 1 ;; esac
    fi
    records="$(awk 'END {print (NR > 0 ? NR - 1 : 0)}' "$output_file")" || return 1
    if [ "$records" -eq 0 ]; then
        [ "$partial" -eq 0 ] && return 2
        return 3
    fi
    [ "$partial" -eq 0 ] || return 3
    return 0
}

collect_systemd_unit_files
case $? in
    0) systemd_unit_files_status="collected" ;;
    2) systemd_unit_files_status="unavailable" ;;
    *) systemd_unit_files_status="partial" ;;
esac
collect_systemd_units
case $? in
    0) systemd_units_status="collected" ;;
    2) systemd_units_status="unavailable" ;;
    *) systemd_units_status="partial" ;;
esac
collect_listeners
case $? in
    0) listeners_status="collected" ;;
    2) listeners_status="unavailable" ;;
    *) listeners_status="partial" ;;
esac
collect_mountinfo
case $? in
    0) mountinfo_status="collected" ;;
    2) mountinfo_status="unavailable" ;;
    *) mountinfo_status="partial" ;;
esac
collect_firewall
case $? in
    0) firewall_status="collected" ;;
    2) firewall_status="unavailable" ;;
    *) firewall_status="partial" ;;
esac
collect_time_sync
case $? in
    0) time_sync_status="collected" ;;
    2) time_sync_status="unavailable" ;;
    *) time_sync_status="partial" ;;
esac

# Empty normalized tables remain explicit when the corresponding native collector is unavailable.
[ -e "$OUTPUT_DIRECTORY_FD_PATH/runtime/systemd-unit-files.tsv" ] ||
    printf 'unit\tunit_file_state\tpreset\n' > "$OUTPUT_DIRECTORY_FD_PATH/runtime/systemd-unit-files.tsv"
[ -e "$OUTPUT_DIRECTORY_FD_PATH/runtime/systemd-units.tsv" ] ||
    printf 'unit\tload_state\tactive_state\tsub_state\tunit_file_state\n' > "$OUTPUT_DIRECTORY_FD_PATH/runtime/systemd-units.tsv"
[ -e "$OUTPUT_DIRECTORY_FD_PATH/runtime/listeners.tsv" ] ||
    printf 'transport\tlocal_address\tport\tprocess\n' > "$OUTPUT_DIRECTORY_FD_PATH/runtime/listeners.tsv"
[ -e "$OUTPUT_DIRECTORY_FD_PATH/runtime/mountinfo" ] ||
    printf 'status=unavailable\n' > "$OUTPUT_DIRECTORY_FD_PATH/runtime/mountinfo"
[ -e "$OUTPUT_DIRECTORY_FD_PATH/runtime/firewall.txt" ] ||
    printf 'status=unavailable\n' > "$OUTPUT_DIRECTORY_FD_PATH/runtime/firewall.txt"
[ -e "$OUTPUT_DIRECTORY_FD_PATH/runtime/time-sync.tsv" ] ||
    printf 'provider\tsynchronized\tsource\tsource_address\tstratum\tleap\tsource_origin\tsource_type\n' > "$OUTPUT_DIRECTORY_FD_PATH/runtime/time-sync.tsv"

cat > "$OUTPUT_DIRECTORY_FD_PATH/manifest.tsv" <<EOF
schema_version	2
captured_at	$captured_at
machine_id	$machine_id
boot_id	$boot_id
kernel_release	$kernel_release
identity_os_release_status	collected
identity_machine_id_status	collected
identity_boot_id_status	collected
identity_kernel_release_status	collected
runtime_systemd_units_status	$systemd_units_status
runtime_systemd_unit_files_status	$systemd_unit_files_status
runtime_listeners_status	$listeners_status
runtime_mountinfo_status	$mountinfo_status
runtime_firewall_status	$firewall_status
runtime_time_sync_status	$time_sync_status
EOF

chmod 0600 -- \
    "$OUTPUT_DIRECTORY_FD_PATH/manifest.tsv" \
    "$OUTPUT_DIRECTORY_FD_PATH/identity/os-release" \
    "$OUTPUT_DIRECTORY_FD_PATH/identity/machine-id" \
    "$OUTPUT_DIRECTORY_FD_PATH/identity/boot-id" \
    "$OUTPUT_DIRECTORY_FD_PATH/identity/kernel-release" \
    "$OUTPUT_DIRECTORY_FD_PATH/runtime/systemd-units.tsv" \
    "$OUTPUT_DIRECTORY_FD_PATH/runtime/systemd-unit-files.tsv" \
    "$OUTPUT_DIRECTORY_FD_PATH/runtime/listeners.tsv" \
    "$OUTPUT_DIRECTORY_FD_PATH/runtime/mountinfo" \
    "$OUTPUT_DIRECTORY_FD_PATH/runtime/firewall.txt" \
    "$OUTPUT_DIRECTORY_FD_PATH/runtime/time-sync.tsv" || die "cannot set evidence file permissions"

(
    cd -- "$OUTPUT_DIRECTORY_FD_PATH" || exit 1
    sha256sum -- \
        manifest.tsv \
        identity/os-release \
        identity/machine-id \
        identity/boot-id \
        identity/kernel-release \
        runtime/systemd-units.tsv \
        runtime/systemd-unit-files.tsv \
        runtime/listeners.tsv \
        runtime/mountinfo \
        runtime/firewall.txt \
        runtime/time-sync.tsv > checksums.sha256
) || die "cannot create evidence checksums"
chmod 0600 -- "$OUTPUT_DIRECTORY_FD_PATH/checksums.sha256" || die "cannot set checksum file permissions"

current_metadata="$(stat_mode_owner_inode "$OUTPUT_DIRECTORY")" || die "cannot revalidate the output directory binding"
read -r current_mode current_owner current_device_inode <<< "$current_metadata"
[ "$current_mode" = "700" ] && [ "$current_owner" = "0" ] || die "output directory security attributes changed during collection"
[ "$current_device_inode" = "$OUTPUT_DIRECTORY_DEVICE_INODE" ] || die "output directory path binding changed during collection"
validate_physical_directory "$OUTPUT_DIRECTORY" || die "output directory path changed during collection"

COLLECTOR_COMPLETE=1
console_emit "evidence_bundle=$OUTPUT_DIRECTORY"
