#!/bin/bash

# SPDX-License-Identifier: LGPL-3.0-or-later

# Measures scanner process cost without adding runtime package dependencies.

set -u

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH LC_ALL=C
umask 077

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    printf 'Usage: %s BASELINE_ROOT OPTIMIZED_ROOT [ITERATIONS]\n' "$0" >&2
    exit 2
fi

baseline_root="$1"
optimized_root="$2"
iterations="${3:-20}"
case "$iterations" in ''|*[!0-9]*) exit 2 ;; esac
[ "$iterations" -ge 2 ] || exit 2
for required_command in strace time sha256sum; do
    command -v "$required_command" >/dev/null 2>&1 || {
        printf 'Missing benchmark command: %s\n' "$required_command" >&2
        exit 2
    }
done
for scanner_root in "$baseline_root" "$optimized_root"; do
    [ -x "$scanner_root/bin/kisa-cce-scan" ] || exit 2
done

workspace="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-benchmark.XXXXXXXX")" || exit 2
template_root="$workspace/template-root"
shared_root="$workspace/shared-root"
bundle="$workspace/evidence-bundle"
raw_results="$workspace/raw.tsv"
summary_results="$workspace/summary.tsv"
process_results="$workspace/process.tsv"
process_iterations="${PROCESS_ITERATIONS:-2}"
case "$process_iterations" in ''|*[!0-9]*) exit 2 ;; esac

cleanup() {
    rm -rf -- "$workspace"
}
trap cleanup EXIT

write_fixture_root() {
    local root="$1"

    mkdir -p -- \
        "$root/etc/pam.d" "$root/etc/security" "$root/etc/ssh/sshd_config.d" \
        "$root/etc/sysctl.d" "$root/home/operator" "$root/root" "$root/var/log" "$root/dev"
    printf '%s\n' 'ID=ubuntu' 'VERSION_ID="26.04"' 'PRETTY_NAME="Ubuntu 26.04 LTS"' > "$root/etc/os-release"
    printf '%s\n' '0123456789abcdef0123456789abcdef' > "$root/etc/machine-id"
    printf '%s\n' \
        'root:x:0:0:root:/root:/bin/bash' \
        'operator:x:1000:1000:Operator:/home/operator:/bin/bash' > "$root/etc/passwd"
    printf '%s\n' 'root:x:0:' 'operator:x:1000:' > "$root/etc/group"
    printf '%s\n' 'root:*:20000:0:99999:7:::' 'operator:!:20000:1:90:7:::' > "$root/etc/shadow"
    printf '%s\n' '127.0.0.1 localhost' > "$root/etc/hosts"
    printf '%s\n' 'ssh 22/tcp' > "$root/etc/services"
    printf '%s\n' 'PermitRootLogin no' > "$root/etc/ssh/sshd_config"
    printf '%s\n' 'PASS_MAX_DAYS 90' 'PASS_MIN_DAYS 1' 'ENCRYPT_METHOD YESCRYPT' 'UMASK 027' 'UID_MIN 1000' > "$root/etc/login.defs"
    printf '%s\n' 'minlen = 8' 'dcredit = -1' 'ucredit = -1' 'lcredit = -1' 'ocredit = -1' 'enforce_for_root' > "$root/etc/security/pwquality.conf"
    printf '%s\n' 'remember = 4' 'enforce_for_root' > "$root/etc/security/pwhistory.conf"
    printf '%s\n' 'deny = 10' > "$root/etc/security/faillock.conf"
    printf '%s\n' \
        'password requisite pam_pwquality.so retry=3' \
        'password required pam_pwhistory.so use_authtok remember=4' \
        'password required pam_unix.so use_authtok' > "$root/etc/pam.d/common-password"
    printf '%s\n' \
        'auth required pam_faillock.so preauth silent' \
        'auth required pam_unix.so' \
        'auth required pam_faillock.so authfail' \
        'auth required pam_faillock.so authsucc' > "$root/etc/pam.d/common-auth"
    printf '%s\n' 'account required pam_faillock.so' > "$root/etc/pam.d/common-account"
    printf '%s\n' 'session required pam_umask.so' > "$root/etc/pam.d/common-session"
    printf '%s\n' 'session required pam_umask.so' > "$root/etc/pam.d/common-session-noninteractive"
    printf '%s\n' 'auth required pam_wheel.so use_uid group=sudo' > "$root/etc/pam.d/su"
    printf '%s\n' 'TMOUT=600' 'readonly TMOUT' 'export TMOUT' 'umask 027' > "$root/etc/profile"
    printf '%s\n' 'net.ipv4.ip_forward = 0' 'net.ipv4.conf.*.rp_filter = 1' > "$root/etc/sysctl.d/90-benchmark.conf"
    printf '%s\n' 'Authorized use only.' > "$root/etc/issue"
    printf '%s\n' 'Authorized use only.' > "$root/etc/motd"
    printf '%s\n' 'benchmark log' > "$root/var/log/messages"
    chmod 0600 -- "$root/etc/shadow"
}

write_bundle() {
    local root="$1"
    local destination="$2"
    local listener_process="${3:-sshd}"
    local captured_at=""
    local relative_path=""

    captured_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)" || return 2
    mkdir -p -- "$destination/identity" "$destination/runtime"
    chmod 0700 -- "$destination" "$destination/identity" "$destination/runtime"
    cp -- "$root/etc/os-release" "$destination/identity/os-release"
    cp -- "$root/etc/machine-id" "$destination/identity/machine-id"
    printf '%s\n' '01234567-89ab-cdef-0123-456789abcdef' > "$destination/identity/boot-id"
    printf '%s\n' '6.8.0-benchmark' > "$destination/identity/kernel-release"
    printf '%s\n' \
        $'unit\tload_state\tactive_state\tsub_state\tunit_file_state' \
        $'ssh.service\tloaded\tactive\trunning\tenabled' \
        $'systemd-journald.service\tloaded\tactive\trunning\tstatic' > "$destination/runtime/systemd-units.tsv"
    printf '%s\n' \
        $'unit\tunit_file_state\tpreset' \
        $'ssh.service\tenabled\tenabled' \
        $'systemd-journald.service\tstatic\tenabled' > "$destination/runtime/systemd-unit-files.tsv"
    printf 'transport\tlocal_address\tport\tprocess\ntcp\t0.0.0.0\t22\t%s\n' "$listener_process" > "$destination/runtime/listeners.tsv"
    printf '%s\n' '36 25 8:1 / / rw,relatime - ext4 /dev/root rw' > "$destination/runtime/mountinfo"
    printf '%s\n' 'collector=nft' 'table inet filter {}' > "$destination/runtime/firewall.txt"
    printf '%s\n' '[timedatectl]' 'NTPSynchronized=yes' 'ServerAddress=192.0.2.10' > "$destination/runtime/time-sync.txt"
    cat > "$destination/manifest.tsv" <<EOF
schema_version	1
captured_at	$captured_at
machine_id	0123456789abcdef0123456789abcdef
boot_id	01234567-89ab-cdef-0123-456789abcdef
kernel_release	6.8.0-benchmark
identity_os_release_status	collected
identity_machine_id_status	collected
identity_boot_id_status	collected
identity_kernel_release_status	collected
runtime_systemd_units_status	collected
runtime_systemd_unit_files_status	collected
runtime_listeners_status	collected
runtime_mountinfo_status	collected
runtime_firewall_status	collected
runtime_time_sync_status	collected
EOF
    : > "$destination/checksums.sha256"
    for relative_path in \
        manifest.tsv identity/os-release identity/machine-id identity/boot-id identity/kernel-release \
        runtime/systemd-units.tsv runtime/systemd-unit-files.tsv runtime/listeners.tsv \
        runtime/mountinfo runtime/firewall.txt runtime/time-sync.txt; do
        printf '%s  %s\n' "$(sha256sum "$destination/$relative_path" | awk '{print $1}')" "$relative_path" >> "$destination/checksums.sha256"
    done
    chmod 0600 -- "$destination/manifest.tsv" "$destination/checksums.sha256" \
        "$destination"/identity/* "$destination"/runtime/*
}

refresh_bundle_listener() {
    local process_name="$1"
    local relative_path=""

    printf 'transport\tlocal_address\tport\tprocess\ntcp\t0.0.0.0\t22\t%s\n' "$process_name" > "$bundle/runtime/listeners.tsv"
    : > "$bundle/checksums.sha256"
    for relative_path in \
        manifest.tsv identity/os-release identity/machine-id identity/boot-id identity/kernel-release \
        runtime/systemd-units.tsv runtime/systemd-unit-files.tsv runtime/listeners.tsv \
        runtime/mountinfo runtime/firewall.txt runtime/time-sync.txt; do
        printf '%s  %s\n' "$(sha256sum "$bundle/$relative_path" | awk '{print $1}')" "$relative_path" >> "$bundle/checksums.sha256"
    done
    chmod 0600 -- "$bundle/checksums.sha256" "$bundle/runtime/listeners.tsv"
}

measure_once() {
    local implementation="$1"
    local scanner_root="$2"
    local scenario="$3"
    local iteration="$4"
    local root="$shared_root"
    local output="$workspace/output-$implementation-$scenario-$iteration"
    local timing="$workspace/time-$implementation-$scenario-$iteration"
    local console="$workspace/console-$implementation-$scenario-$iteration"
    local console_output=""
    local status=0
    local wall=""
    local user=""
    local system=""
    local rss=""
    local cpu=""
    local markdown_report=""
    local jsonl_report=""
    local -a scanner_arguments=()

    case "$scenario" in
        cold)
            root="$workspace/cold-$implementation-$iteration"
            cp -a -- "$template_root" "$root"
            ;;
        unchanged) ;;
        config-change)
            if [ $((iteration % 2)) -eq 0 ]; then
                printf '%s\n' 'PermitRootLogin no' > "$root/etc/ssh/sshd_config"
            else
                printf '%s\n' 'PermitRootLogin prohibit-password' > "$root/etc/ssh/sshd_config"
            fi
            ;;
        runtime-only)
            if [ $((iteration % 2)) -eq 0 ]; then refresh_bundle_listener sshd
            else refresh_bundle_listener dropbear
            fi
            scanner_arguments+=(--evidence-bundle "$bundle")
            ;;
        *) return 2 ;;
    esac
    mkdir -m 0700 -- "$output"
    /usr/bin/time -q -f '%e\t%U\t%S\t%M' -o "$timing" \
        "$scanner_root/bin/kisa-cce-scan" --root "$root" --output-dir "$output" \
        "${scanner_arguments[@]}" > "$console" 2>&1 || status=$?
    [ "$status" -eq 1 ] || return 2
    console_output="$(< "$console")"
    markdown_report="$(scanner_console_value markdown_report "$console_output")"
    jsonl_report="$(scanner_console_value jsonl_report "$console_output")"
    [ -s "$markdown_report" ] && [ -s "$jsonl_report" ] || return 2
    IFS=$'\t' read -r wall user system rss < "$timing" || return 2
    cpu="$(awk -v user_time="$user" -v system_time="$system" \
        'BEGIN {printf "%.6f", user_time + system_time}')"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$implementation" "$scenario" "$iteration" "$wall" "$user" "$system" \
        "$cpu" "$rss" "$status" >> "$raw_results"
}

measure_process_count() {
    local implementation="$1"
    local scanner_root="$2"
    local scenario="$3"
    local iteration="$4"
    local root="$shared_root"
    local output="$workspace/process-output-$implementation-$scenario-$iteration"
    local trace="$workspace/process-trace-$implementation-$scenario-$iteration"
    local status=0
    local executions=0
    local console="$workspace/process-console-$implementation-$scenario-$iteration"
    local console_output=""
    local markdown_report=""
    local jsonl_report=""
    local -a scanner_arguments=()

    case "$scenario" in
        cold)
            root="$workspace/process-cold-$implementation-$iteration"
            cp -a -- "$template_root" "$root"
            ;;
        unchanged) ;;
        config-change)
            if [ $((iteration % 2)) -eq 0 ]; then
                printf '%s\n' 'PermitRootLogin no' > "$root/etc/ssh/sshd_config"
            else
                printf '%s\n' 'PermitRootLogin prohibit-password' > "$root/etc/ssh/sshd_config"
            fi
            ;;
        runtime-only)
            if [ $((iteration % 2)) -eq 0 ]; then refresh_bundle_listener sshd
            else refresh_bundle_listener dropbear
            fi
            scanner_arguments+=(--evidence-bundle "$bundle")
            ;;
        *) return 2 ;;
    esac
    mkdir -m 0700 -- "$output"
    strace -f -qq -c -e trace=execve -o "$trace" \
        "$scanner_root/bin/kisa-cce-scan" --root "$root" --output-dir "$output" \
        "${scanner_arguments[@]}" > "$console" 2>&1 || status=$?
    [ "$status" -eq 1 ] || return 2
    console_output="$(< "$console")"
    markdown_report="$(scanner_console_value markdown_report "$console_output")"
    jsonl_report="$(scanner_console_value jsonl_report "$console_output")"
    [ -s "$markdown_report" ] && [ -s "$jsonl_report" ] || return 2
    executions="$(awk '$NF == "execve" {print $4; found=1} END {if (!found) print 0}' "$trace")"
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$implementation" "$scenario" "$iteration" "$executions" "$status" >> "$process_results"
}

summarize_metric() {
    local implementation="$1"
    local scenario="$2"
    local column="$3"
    local metric="$4"
    local source_file="$5"
    local values="$workspace/values"
    local count=0
    local median_index=0
    local p95_index=0
    local median=""
    local p95=""

    awk -F '\t' -v implementation="$implementation" -v scenario="$scenario" -v column="$column" \
        '$1 == implementation && $2 == scenario {print $column}' "$source_file" | sort -n > "$values"
    count="$(wc -l < "$values" | tr -d '[:space:]')"
    p95_index=$(((95 * count + 99) / 100))
    median_index=$(((count + 1) / 2))
    if [ $((count % 2)) -eq 0 ]; then
        median="$(awk -v first="$median_index" -v second="$((median_index + 1))" \
            'NR == first {left=$1} NR == second {printf "%.6f", (left + $1) / 2}' "$values")"
    else
        median="$(sed -n "${median_index}p" "$values")"
    fi
    p95="$(sed -n "${p95_index}p" "$values")"
    printf '%s\t%s\t%s\t%s\t%s\n' "$implementation" "$scenario" "$metric" "$median" "$p95" >> "$summary_results"
}

scanner_console_value() {
    local key="$1"
    local output="$2"

    printf '%s\n' "$output" | sed -n "s/^\\[[^]]*\\] kisa-cce-scan: ${key}=//p"
}

verify_result_equivalence() {
    local scenario="$1"
    local implementation=""
    local scanner_root=""
    local output_directory=""
    local console_output=""
    local command_status=0
    local baseline_status=""
    local optimized_status=""
    local markdown_report=""
    local jsonl_report=""

    local -a scanner_arguments=()

    cp -- "$template_root/etc/ssh/sshd_config" "$shared_root/etc/ssh/sshd_config"
    case "$scenario" in
        cold|unchanged) ;;
        config-change) printf '%s\n' 'PermitRootLogin prohibit-password' > "$shared_root/etc/ssh/sshd_config" ;;
        runtime-only)
            refresh_bundle_listener dropbear
            scanner_arguments+=(--evidence-bundle "$bundle")
            ;;
        *) return 2 ;;
    esac
    for implementation in baseline optimized; do
        if [ "$implementation" = baseline ]; then scanner_root="$baseline_root"
        else scanner_root="$optimized_root"
        fi
        output_directory="$workspace/equivalence-$scenario-$implementation"
        mkdir -m 0700 -- "$output_directory"
        command_status=0
        console_output="$("$scanner_root/bin/kisa-cce-scan" --root "$shared_root" \
            --output-dir "$output_directory" "${scanner_arguments[@]}" 2>&1)" || command_status=$?
        [ "$command_status" -eq 1 ] || return 2
        if [ "$implementation" = baseline ]; then baseline_status="$command_status"
        else optimized_status="$command_status"
        fi
        markdown_report="$(scanner_console_value markdown_report "$console_output")"
        jsonl_report="$(scanner_console_value jsonl_report "$console_output")"
        [ -f "$markdown_report" ] && [ -f "$jsonl_report" ] || return 2
        sed \
            -e 's/^    started_at: .*/    started_at: <timestamp>/' \
            -e 's/^    evidence_age_seconds: .*/    evidence_age_seconds: <elapsed>/' \
            -e 's/^완료 시각: .*/완료 시각: `<timestamp>`/' \
            -e 's/^Completed at: .*/Completed at: `<timestamp>`/' \
            "$markdown_report" > "$workspace/equivalence-$scenario-$implementation.md"
        cp -- "$jsonl_report" "$workspace/equivalence-$scenario-$implementation.jsonl"
    done
    [ "$baseline_status" = "$optimized_status" ] && [ "$baseline_status" = 1 ] || return 1
    cmp -s "$workspace/equivalence-$scenario-baseline.md" "$workspace/equivalence-$scenario-optimized.md" || {
        diff -u "$workspace/equivalence-$scenario-baseline.md" "$workspace/equivalence-$scenario-optimized.md" >&2 || true
        return 1
    }
    cmp -s "$workspace/equivalence-$scenario-baseline.jsonl" "$workspace/equivalence-$scenario-optimized.jsonl" || {
        diff -u "$workspace/equivalence-$scenario-baseline.jsonl" "$workspace/equivalence-$scenario-optimized.jsonl" >&2 || true
        return 1
    }
}

write_fixture_root "$template_root"
cp -a -- "$template_root" "$shared_root"
write_bundle "$shared_root" "$bundle"
printf 'implementation\tscenario\titeration\twall_seconds\tuser_seconds\tsystem_seconds\tcpu_seconds\tmax_rss_kib\texit_status\n' > "$raw_results"
printf 'implementation\tscenario\titeration\texecve_count\texit_status\n' > "$process_results"

for scenario in cold unchanged config-change runtime-only; do
    for ((iteration = 1; iteration <= iterations; iteration++)); do
        cp -- "$template_root/etc/ssh/sshd_config" "$shared_root/etc/ssh/sshd_config"
        if [ $((iteration % 2)) -eq 1 ]; then implementations=(baseline optimized)
        else implementations=(optimized baseline)
        fi
        for implementation in "${implementations[@]}"; do
            if [ "$implementation" = baseline ]; then scanner_root="$baseline_root"
            else scanner_root="$optimized_root"
            fi
            measure_once "$implementation" "$scanner_root" "$scenario" "$iteration" || exit 2
        done
    done
done

if [ "$process_iterations" -gt 0 ]; then
    for scenario in cold unchanged config-change runtime-only; do
        for ((iteration = 1; iteration <= process_iterations; iteration++)); do
            cp -- "$template_root/etc/ssh/sshd_config" "$shared_root/etc/ssh/sshd_config"
            if [ $((iteration % 2)) -eq 1 ]; then implementations=(baseline optimized)
            else implementations=(optimized baseline)
            fi
            for implementation in "${implementations[@]}"; do
                if [ "$implementation" = baseline ]; then scanner_root="$baseline_root"
                else scanner_root="$optimized_root"
                fi
                measure_process_count "$implementation" "$scanner_root" "$scenario" "$iteration" || exit 2
            done
        done
    done
fi

for scenario in cold unchanged config-change runtime-only; do
    verify_result_equivalence "$scenario" || {
        printf 'Optimized %s results differ from the baseline after timestamp normalization.\n' "$scenario" >&2
        exit 1
    }
done

printf 'implementation\tscenario\tmetric\tmedian\tp95\n' > "$summary_results"
for implementation in baseline optimized; do
    for scenario in cold unchanged config-change runtime-only; do
        summarize_metric "$implementation" "$scenario" 4 wall_seconds "$raw_results"
        summarize_metric "$implementation" "$scenario" 7 cpu_seconds "$raw_results"
        summarize_metric "$implementation" "$scenario" 8 max_rss_kib "$raw_results"
        if [ "$process_iterations" -gt 0 ]; then
            summarize_metric "$implementation" "$scenario" 4 execve_count "$process_results"
        fi
    done
done

result_directory="${BENCHMARK_OUTPUT_DIRECTORY:-$PWD}"
mkdir -p -- "$result_directory"
cp -- "$raw_results" "$result_directory/benchmark-raw.tsv"
cp -- "$process_results" "$result_directory/benchmark-process-raw.tsv"
cp -- "$summary_results" "$result_directory/benchmark-summary.tsv"
printf 'raw=%s\nsummary=%s\n' \
    "$result_directory/benchmark-raw.tsv" "$result_directory/benchmark-summary.tsv"
printf 'process_raw=%s\n' "$result_directory/benchmark-process-raw.tsv"
printf 'result_equivalence=pass\n'
