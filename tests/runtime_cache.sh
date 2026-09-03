#!/bin/bash

# SPDX-License-Identifier: LGPL-3.0-or-later

# shellcheck disable=SC2034

set -u

LC_ALL=C
export LC_ALL
umask 077

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent="." ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-runtime-cache.XXXXXXXX")" || exit 2
scratch="$test_directory/scratch"
systemctl_count_file="$test_directory/systemctl-count"
listener_count_file="$test_directory/listener-count"
systemd_active_file="$test_directory/systemd-active"
listener_failure_file="$test_directory/listener-failure"
dependency_file="$test_directory/dependencies"

cleanup() {
    rm -rf -- "$test_directory"
}
trap cleanup EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_equal() {
    local expected="$1"
    local actual="$2"
    local description="$3"

    [ "$expected" = "$actual" ] || fail "$description: expected=[$expected] actual=[$actual]"
}

assert_contains() {
    local value="$1"
    local expected="$2"
    local description="$3"

    case "$value" in
        *"$expected"*) ;;
        *) fail "$description: missing=[$expected] value=[$value]" ;;
    esac
}

mkdir -p -- "$scratch"
printf '0\n' > "$systemctl_count_file"
printf '0\n' > "$listener_count_file"
printf '1\n' > "$systemd_active_file"
: > "$dependency_file"

SCAN_ROOT="/"
RUNTIME_MODE="on"
SCAN_EPOCH_ID=1
SCAN_EPOCH_ACTIVE=1
LISTENER_SNAPSHOT_CACHE_ENABLED=1
SCRATCH_DIR="$scratch"
IFS= read -r KISA_CCE_VERSION < "$project_directory/data/VERSION" || exit 2

# shellcheck source=../lib/core.sh
. "$project_directory/lib/core.sh"
# shellcheck source=../lib/resolvers.sh
. "$project_directory/lib/resolvers.sh"
# shellcheck source=../lib/checks_service.sh
. "$project_directory/lib/checks_service.sh"
# shellcheck source=../lib/checks_system.sh
. "$project_directory/lib/checks_system.sh"
SCRATCH_DIR="$scratch"

cat > "$test_directory/systemctl" <<EOF
#!/bin/sh
count=0
IFS= read -r count < "$systemctl_count_file" || exit 90
printf '%s\n' "\$((count + 1))" > "$systemctl_count_file" || exit 90
case " \$* " in
    *" --all "*)
        IFS= read -r active < "$systemd_active_file" || exit 90
        if [ "\$active" = 1 ]; then active_state=active; else active_state=inactive; fi
        printf '%s\n' \
            'Id=sshd.service' \
            'Names=sshd.service ssh.service' \
            'LoadState=loaded' \
            "ActiveState=\$active_state" \
            'SubState=running' \
            'UnitFileState=enabled' \
            'FragmentPath=/usr/lib/systemd/system/sshd.service' \
            'DropInPaths=/etc/systemd/system/sshd.service.d/hardening.conf' \
            'Triggers=' \
            'TriggeredBy=sshd.socket' \
            'MainPID=1' \
            'ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd --hardening-flag ; }' \
            'Environment=' \
            'EnvironmentFiles=' \
            ''
        exit 0
        ;;
esac
case "\${2-}" in
    direct.service)
        IFS= read -r active < "$systemd_active_file" || exit 90
        if [ "\$active" = 1 ]; then active_state=active; else active_state=inactive; fi
        printf '%s\n' \
            'Id=direct.service' 'Names=direct.service' 'LoadState=loaded' \
            "ActiveState=\$active_state" 'SubState=running' 'UnitFileState=enabled' \
            'FragmentPath=/usr/lib/systemd/system/direct.service' \
            'DropInPaths=' 'Triggers=' 'TriggeredBy='
        exit 0
        ;;
    missing.service)
        printf '%s\n' \
            'Id=missing.service' 'Names=missing.service' 'LoadState=not-found' \
            'ActiveState=inactive' 'SubState=dead' 'UnitFileState=' \
            'FragmentPath=' 'DropInPaths=' 'Triggers=' 'TriggeredBy='
        exit 1
        ;;
    broken.service)
        printf '%s\n' \
            'Id=broken.service' 'Names=broken.service' 'LoadState=loaded' \
            'ActiveState=inactive'
        exit 42
        ;;
esac
exit 2
EOF
chmod 0755 "$test_directory/systemctl"

trusted_command() {
    [ "$1" = systemctl ] || return 1
    printf '%s\n' "$test_directory/systemctl"
}

scan_dependency_register() {
    printf '%s\t%s\n' "$1" "$2" >> "$dependency_file"
}

capture_command() {
    local command_name="$1"
    local count=0

    shift
    [ "$command_name" = ss ] || return 127
    IFS= read -r count < "$listener_count_file" || return 90
    printf '%s\n' "$((count + 1))" > "$listener_count_file" || return 90
    [ ! -e "$listener_failure_file" ] || return 42
    case "$*" in
        '-H -lntup')
            printf '%s\n' \
                'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))' \
                'udp UNCONN 0 0 127.0.0.1:53 0.0.0.0:* users:(("named",pid=2,fd=4))'
            ;;
        '-H -lntp')
            printf '%s\n' 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))'
            ;;
        *) return 2 ;;
    esac
}

service_state ssh.service || fail "active alias was not resolved from the bulk snapshot"
output="$(service_facts ssh.service)" || fail "cached alias facts failed"
assert_contains "$output" "unit=ssh.service Names=sshd.service ssh.service" "alias facts"
assert_contains "$output" "DropInPaths=/etc/systemd/system/sshd.service.d/hardening.conf" "drop-in facts"
service_activation_state ssh.service || fail "activation state did not reuse cached systemd facts"
time_service_persistence_state ssh.service || fail "persistence state did not reuse cached systemd facts"
service_units_have_custom_configuration hardening-flag ssh.service ||
    fail "custom invocation state did not reuse cached systemd facts"
IFS= read -r count < "$systemctl_count_file"
assert_equal 1 "$count" "one lazy systemd bulk capture"

status=0
service_state missing.service >/dev/null 2>&1 || status=$?
assert_equal 3 "$status" "missing unit service state"
status=0
service_state missing.service >/dev/null 2>&1 || status=$?
assert_equal 3 "$status" "missing unit memoization"
status=0
service_facts missing.service >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "missing unit service facts command contract"

status=0
service_state broken.service >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "failed unit service state"
status=0
service_state broken.service >/dev/null 2>&1 || status=$?
assert_equal 2 "$status" "failed unit memoization"
IFS= read -r count < "$systemctl_count_file"
assert_equal 3 "$count" "missing and failed units use one cached fallback each"

output="$(port_listener_facts 22 tcp)" || fail "cached TCP listener lookup failed"
assert_contains "$output" "LISTEN 0 128 0.0.0.0:22" "TCP listener format"
output="$(port_listener_facts 53 udp)" || fail "cached UDP listener lookup failed"
assert_contains "$output" "UNCONN 0 0 127.0.0.1:53" "UDP listener format"
output="$(port_listener_facts 22 any)" || fail "cached mixed listener lookup failed"
assert_contains "$output" "tcp LISTEN" "mixed listener format"
IFS= read -r count < "$listener_count_file"
assert_equal 1 "$count" "one mixed listener capture per epoch"

printf '0\n' > "$systemd_active_file"
SCAN_EPOCH_ID=2
status=0
service_state ssh.service >/dev/null 2>&1 || status=$?
assert_equal 1 "$status" "new epoch refreshes systemd state"
port_listener_facts 22 tcp >/dev/null || fail "new epoch listener refresh failed"
IFS= read -r count < "$systemctl_count_file"
assert_equal 4 "$count" "new epoch performs a new systemd bulk capture"
IFS= read -r count < "$listener_count_file"
assert_equal 2 "$count" "new epoch performs a new listener capture"

SCAN_EPOCH_ID=3
: > "$listener_failure_file"
status=0
port_listener_facts 22 tcp >/dev/null 2>&1 || status=$?
assert_equal 42 "$status" "listener capture failure status"
status=0
port_listener_facts 53 udp >/dev/null 2>&1 || status=$?
assert_equal 42 "$status" "listener failure memoization"
IFS= read -r count < "$listener_count_file"
assert_equal 3 "$count" "listener failure captured once"

rm -f -- "$listener_failure_file"
listener_reset_epoch_cache
port_listener_facts 22 tcp >/dev/null || fail "listener reset hook did not refresh the epoch"
IFS= read -r count < "$listener_count_file"
assert_equal 4 "$count" "listener reset hook refresh count"

printf '1\n' > "$systemd_active_file"
systemd_reset_epoch_cache
output="$(service_facts ssh.service)" || fail "systemd reset hook did not refresh the epoch"
assert_contains "$output" "ActiveState=active" "systemd reset hook facts"
service_state ssh.service || fail "systemd cache created in a command substitution was not reused"
IFS= read -r count < "$systemctl_count_file"
assert_equal 5 "$count" "systemd reset hook refresh count"

grep -Fq $'runtime:systemd\tsystemd-unit:ssh.service' "$dependency_file" ||
    fail "systemd dependency hook was not called"
grep -Fq $'runtime:listeners\tlistener:snapshot' "$dependency_file" ||
    fail "listener dependency hook was not called"

SCAN_EPOCH_ACTIVE=0
LISTENER_SNAPSHOT_CACHE_ENABLED=0
printf '1\n' > "$systemd_active_file"
service_state direct.service || fail "uncached direct service state failed"
printf '0\n' > "$systemd_active_file"
status=0
service_state direct.service >/dev/null 2>&1 || status=$?
assert_equal 1 "$status" "inactive epoch observes direct systemd mutation"
port_listener_facts 22 tcp >/dev/null || fail "first uncached listener lookup failed"
port_listener_facts 22 tcp >/dev/null || fail "second uncached listener lookup failed"
IFS= read -r count < "$listener_count_file"
assert_equal 6 "$count" "inactive epoch preserves uncached listener behavior"

EVIDENCE_BUNDLE_ACTIVE=1
EVIDENCE_BUNDLE_DIRECTORY="$test_directory/evidence"
EVIDENCE_RUNTIME_LISTENERS_STATUS=collected
evidence_service_state() { return 1; }
evidence_listener_facts() { printf 'tcp\t127.0.0.1\t22\tsshd\n'; }
status=0
service_state evidence.service >/dev/null 2>&1 || status=$?
assert_equal 1 "$status" "evidence service state remains first"
output="$(port_listener_facts 22 tcp)" || fail "evidence listener facts failed"
assert_contains "$output" "127.0.0.1:22" "evidence listener output"
IFS= read -r count < "$systemctl_count_file"
assert_equal 7 "$count" "evidence service state bypasses live systemd"
IFS= read -r count < "$listener_count_file"
assert_equal 6 "$count" "evidence listener facts bypass live ss"

printf 'PASS: runtime epoch cache\n'
