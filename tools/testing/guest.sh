#!/bin/bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

# The host runner invokes this script only inside its disposable Linux guest.
set -uo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
umask 077
if [ "${KISA_CCE_TEST_GUEST:-}" != 1 ] || [ "$(uname -s)" != Linux ] || [ "$EUID" -ne 0 ]; then
    printf 'ERROR: use the host test runner to create a disposable Linux guest.\n' >&2
    exit 2
fi
project="${1:-}"
suite="${2:-}"
prepare="${3:-}"
case "$project" in scanner|patcher) ;; *) exit 2 ;; esac
case "$suite" in all|check|lint|smoke) ;; *) exit 2 ;; esac
case "$prepare" in ''|--prepare) ;; *) exit 2 ;; esac
source_parent="$(CDPATH='' cd -- "${BASH_SOURCE[0]%/*}" && pwd)"
repository="$source_parent/kisa-cce-linux-$project"
results=/tmp/kisa-cce-test-results
mkdir -p "$results" || exit 2
# Apple shared mounts can reject chmod even when the requested mode is already set.
if [ "$(stat -c %a "$results")" != 700 ]; then
    chmod 0700 "$results" || exit 2
fi
[ "$(stat -c %a "$results")" = 700 ] || exit 2
printf 'phase\tstatus\texit_code\n' > "$results/phases.tsv"
failed=0
phase() {
    local name="$1" status=0
    shift
    printf 'RUN %s\n' "$name"
    "$@" > "$results/$name.log" 2>&1 || status=$?
    if [ "$status" -eq 0 ]; then
        printf '%s\tpassed\t0\n' "$name" >> "$results/phases.tsv"
        printf 'PASS %s\n' "$name"
    else
        printf '%s\tfailed\t%s\n' "$name" "$status" >> "$results/phases.tsv"
        printf 'FAIL %s (exit %s)\n' "$name" "$status" >&2
        tail -n 20 "$results/$name.log" >&2
        failed=1
    fi
    return "$status"
}

if [ "$prepare" = --prepare ]; then
    phase prepare /bin/bash -eu -o pipefail -c '
        if command -v apt-get >/dev/null 2>&1; then
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y --no-install-recommends bash make shellcheck mandoc jq \
                findutils util-linux passwd tar gzip
        elif command -v dnf >/dev/null 2>&1; then
            if [ -f /etc/rocky-release ] || [ -f /etc/almalinux-release ]; then
                dnf install -y epel-release
            fi
            dnf install -y bash make ShellCheck mandoc jq findutils util-linux shadow-utils tar gzip \
                coreutils gawk grep sed diffutils
        else
            echo "No supported package manager; use a prepared image." >&2
            exit 2
        fi
    ' || exit 2
fi
phase prerequisites /bin/bash -eu -o pipefail -c '
    for command in bash make shellcheck mandoc jq find stat runuser getent; do
        command -v "$command" >/dev/null || { echo "Missing test tool: $command"; exit 2; }
    done
    test "${BASH_VERSINFO[0]}" -gt 4 || {
        test "${BASH_VERSINFO[0]}" -eq 4 && test "${BASH_VERSINFO[1]}" -ge 3
    }
' || exit 2
{
    uname -a
    cat /etc/os-release
    /bin/bash --version | head -n 1
    shellcheck --version
} > "$results/environment.txt"

if ! getent group 1000 >/dev/null; then
    groupadd -g 1000 kisa-test || exit 2
fi
if ! getent passwd 1000 >/dev/null; then
    useradd -u 1000 -g 1000 -m -s /bin/bash kisa-test || exit 2
fi
test_user="$(getent passwd 1000 | cut -d: -f1)"
test_group="$(getent group 1000 | cut -d: -f1)"
test_home="$(mktemp -d /tmp/kisa-cce-test-home.XXXXXXXX)" || exit 2
chown 1000:1000 "$test_home" || exit 2
trap 'rm -rf -- "$test_home"' EXIT
user_command=(runuser -u "$test_user" -g "$test_group" -- env -i PATH="$PATH" HOME="$test_home" LC_ALL=C)

if [ "$suite" = all ] || [ "$suite" = check ]; then
    phase check-user "${user_command[@]}" /bin/bash -eu -o pipefail -c 'cd "$1"; make check' _ "$repository" || :
    if [ "$project" = patcher ]; then
        phase check-root /bin/bash -eu -o pipefail -c 'cd "$1"; make check' _ "$repository" || :
    fi
fi
if [ "$suite" = all ] || [ "$suite" = lint ]; then
    phase lint "${user_command[@]}" /bin/bash -eu -o pipefail -c '
        cd "$1"
        make lint
        for page in man/*.8; do mandoc -T lint "$page"; done
    ' _ "$repository" || :
fi
if [ "$suite" = all ] || [ "$suite" = smoke ]; then
    if [ "$project" = patcher ]; then
        phase smoke /bin/bash -eu -o pipefail -c '
            cd "$1"
            bash tests/scanner_selection.sh
            bash tests/patch_cli.sh
            bash tests/installed_layouts.sh
        ' _ "$repository" || :
    else
        phase smoke /bin/bash -eu -o pipefail -c '
            cd "$1"
            result="$2"
            platform_id="$(sed -n "s/^ID=//p" /etc/os-release | tr -d \"\")"
            scan_options=()
            if [ "$platform_id" = fedora ]; then
                rejection_status=0
                ./bin/kisa-cce-scan --root / --no-runtime \
                    --output-dir "$result/rejected-report" \
                    > "$result/rejection.stdout" 2> "$result/rejection.stderr" || rejection_status=$?
                test "$rejection_status" -eq 2
                grep -q "unsupported platform: fedora" "$result/rejection.stderr"
                test ! -d "$result/rejected-report"
                scan_options+=(--allow-unsupported)
                printf "Fedora exploratory smoke: default rejection verified; platform support is not asserted.\n"
            fi
            status=0
            ./bin/kisa-cce-scan --root / --no-runtime --debug "${scan_options[@]}" \
                --output-dir "$result/report" > "$result/scan.stdout" 2> "$result/scan.stderr" || status=$?
            if [ "$platform_id" = fedora ]; then
                grep -q "continuing on an unsupported platform: fedora" "$result/scan.stderr"
            fi
            case "$status" in 0|1|2) ;; *) exit "$status" ;; esac
            markdown="$(sed -n "s/^\[[^]]*\] kisa-cce-scan: markdown_report=//p" "$result/scan.stdout")"
            json="$(sed -n "s/^\[[^]]*\] kisa-cce-scan: jsonl_report=//p" "$result/scan.stdout")"
            test -f "$markdown" && test -f "$json"
            test "$(grep -Ec "^## U-[0-9]{2}: " "$markdown")" -eq 67
            test "$(wc -l < "$json")" -eq 68
            jq -e -c . "$json" >/dev/null
            tail -n 1 "$json" | jq -e ".type == \"summary\" and .total == 67" >/dev/null
            test "$(stat -c %a "$result/report")" = 700
            test "$(stat -c %a "$markdown")" = 600
            test "$(stat -c %a "$json")" = 600
            grep -q "DEBUG: schema=1 event=scan_start" "$result/scan.stderr"
            grep -q "DEBUG: schema=1 event=scan_end" "$result/scan.stderr"
            printf "Static scan exit status: %s (criterion results retained in report)\n" "$status"
        ' _ "$repository" "$results" || :
    fi
fi
exit "$failed"
