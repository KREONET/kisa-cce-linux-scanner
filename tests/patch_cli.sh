#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

set -u

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
LC_ALL=C
export LC_ALL
umask 077

if [ "$(uname -s 2>/dev/null)" != Linux ]; then
    printf 'SKIP: patch CLI integration requires Linux Bash and stat semantics\n'
    exit 0
fi

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_equal() {
    local expected="$1"
    local actual="$2"
    local context="$3"

    [ "$expected" = "$actual" ] || fail "$context: expected=[$expected] actual=[$actual]"
}

assert_contains() {
    local actual="$1"
    local expected="$2"
    local context="$3"

    case "$actual" in
        *"$expected"*) ;;
        *) fail "$context: missing=[$expected] actual=[$actual]" ;;
    esac
}

file_mode() {
    local path="$1"

    stat -Lc '%a' -- "$path" 2>/dev/null || stat -f '%Lp' "$path" 2>/dev/null
}

file_metadata() {
    local path="$1"

    stat -Lc '%d:%i:%u:%g:%a' -- "$path" 2>/dev/null ||
        stat -f '%d:%i:%u:%g:%Lp' "$path" 2>/dev/null
}

assert_dmesg_framing() {
    local path="$1"
    local context="$2"

    awk '
        $0 !~ /^\[[[:space:]]*[0-9]+\.[0-9]{6}\] kisa-cce-(patch|scan): / {bad=1}
        END {exit(bad ? 1 : 0)}
    ' "$path" || fail "$context contains a non-dmesg terminal line"
}

run_patcher() {
    local output_prefix="$1"

    shift
    RUN_STATUS=0
    "$patcher" "$@" > "$output_prefix.stdout" 2> "$output_prefix.stderr" || RUN_STATUS=$?
    assert_dmesg_framing "$output_prefix.stdout" "$output_prefix standard output"
    assert_dmesg_framing "$output_prefix.stderr" "$output_prefix standard error"
}

write_ubuntu_root() {
    local root="$1"

    mkdir -p "$root/etc/profile.d" "$root/var/log"
    printf '%s\n' \
        'ID=ubuntu' \
        'VERSION_ID="26.04"' \
        'PRETTY_NAME="Ubuntu 26.04 LTS"' > "$root/etc/os-release"
    printf 'root:x:0:0:root:/root:/bin/bash\n' > "$root/etc/passwd"
    printf 'root:*:1:0:99999:7:::\n' > "$root/etc/shadow"
    printf '127.0.0.1 localhost\n' > "$root/etc/hosts"
    printf 'Ubuntu 26.04 LTS \\n \\l\n' > "$root/etc/issue"
    printf 'Ubuntu 26.04 LTS\n' > "$root/etc/issue.net"
    printf 'Ubuntu 26.04 LTS\n' > "$root/etc/motd"
    printf 'fixture log\n' > "$root/var/log/messages"
    chmod 0666 "$root/etc/passwd" "$root/etc/hosts"
    chmod 0640 "$root/etc/shadow"
    chmod 0600 "$root/etc/issue"
    chmod 0640 "$root/etc/issue.net"
    chmod 0644 "$root/etc/motd"
    chmod 0644 "$root/var/log/messages"
}

case "${BASH_SOURCE[0]}" in
    */*) test_parent="${BASH_SOURCE[0]%/*}" ;;
    *) test_parent=. ;;
esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
patcher="$project_directory/bin/kisa-cce-patch"
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-patch-cli.XXXXXXXX")" || exit 2
test_directory="$(CDPATH='' cd -P -- "$test_directory" && pwd)" || exit 2
scan_root="$test_directory/ubuntu-26.04"
trap 'chmod -R u+rwX "$test_directory" 2>/dev/null || :; rm -rf -- "$test_directory"' EXIT

[ -x "$patcher" ] || fail "patcher executable is unavailable: $patcher"
write_ubuntu_root "$scan_root"

passwd_original="$(file_metadata "$scan_root/etc/passwd")"
shadow_original="$(file_metadata "$scan_root/etc/shadow")"
hosts_original="$(file_metadata "$scan_root/etc/hosts")"
issue_original="$(file_metadata "$scan_root/etc/issue")"
issue_content_original="$(< "$scan_root/etc/issue")"

dry_run_directory="$test_directory/dry-run"
run_patcher "$test_directory/dry-run-command" \
    --root "$scan_root" --output-dir "$dry_run_directory"
assert_equal 0 "$RUN_STATUS" "offline dry-run status"
assert_equal planned "$(< "$dry_run_directory/state")" "offline dry-run transaction state"
assert_equal "$passwd_original" "$(file_metadata "$scan_root/etc/passwd")" "dry-run passwd metadata"
assert_equal "$shadow_original" "$(file_metadata "$scan_root/etc/shadow")" "dry-run shadow metadata"
assert_equal "$hosts_original" "$(file_metadata "$scan_root/etc/hosts")" "dry-run hosts metadata"
assert_equal "$issue_original" "$(file_metadata "$scan_root/etc/issue")" "dry-run issue metadata"
assert_equal "$issue_content_original" "$(< "$scan_root/etc/issue")" "dry-run issue content"
[ ! -e "$scan_root/etc/profile.d/99-kisa-cce-session-timeout.sh" ] ||
    fail "dry-run created the session timeout configuration"
[ ! -e "$dry_run_directory/post-scan" ] || fail "dry-run created a post-scan directory"
for artifact in manifest.tsv plan.tsv metadata.tsv state checksums.sha256; do
    [ -f "$dry_run_directory/$artifact" ] || fail "dry-run artifact is absent: $artifact"
    assert_equal 600 "$(file_mode "$dry_run_directory/$artifact")" "dry-run $artifact mode"
done
[ -f "$dry_run_directory/configuration-plan.tsv" ] || fail "dry-run configuration plan is absent"
[ -f "$dry_run_directory/configuration/manifest.tsv" ] || fail "dry-run configuration manifest is absent"
assert_equal 2 "$(awk -F '\t' 'NR == 2 {print $1}' "$dry_run_directory/metadata.tsv")" \
    "dry-run engine schema"
assert_contains "$(< "$test_directory/dry-run-command.stdout")" \
    "transaction=$dry_run_directory" "dry-run transaction output"
assert_contains "$(< "$test_directory/dry-run-command.stdout")" \
    'apply_status=not_requested' "dry-run apply output"

unsupported_directory="$test_directory/unsupported"
run_patcher "$test_directory/unsupported-command" \
    --root "$scan_root" --output-dir "$unsupported_directory" --checks U-01
assert_equal 2 "$RUN_STATUS" "unsupported criterion status"
assert_contains "$(< "$test_directory/unsupported-command.stderr")" \
    'unsupported patch criterion: U-01' "unsupported criterion diagnostic"
[ ! -e "$unsupported_directory" ] || fail "unsupported criterion created a transaction"

conflict_directory="$test_directory/conflict"
run_patcher "$test_directory/conflict-command" \
    --root "$scan_root" --output-dir "$conflict_directory" --automatic --checks U-16
assert_equal 2 "$RUN_STATUS" "automatic option conflict status"
assert_contains "$(< "$test_directory/conflict-command.stderr")" \
    '--automatic cannot be used with --checks' "automatic option conflict diagnostic"
[ ! -e "$conflict_directory" ] || fail "option conflict created a transaction"

symlink_root="$test_directory/symlink-root"
ln -s "$scan_root" "$symlink_root"
symlink_directory="$test_directory/symlink-output"
run_patcher "$test_directory/symlink-command" \
    --root "$symlink_root" --output-dir "$symlink_directory" --checks U-16
assert_equal 2 "$RUN_STATUS" "symlink root status"
assert_contains "$(< "$test_directory/symlink-command.stderr")" \
    'scan root contains a symbolic-link component' "symlink root diagnostic"
[ ! -e "$symlink_directory" ] || fail "symlink root created a transaction"

missing_root="$test_directory/missing-root"
mkdir -p "$missing_root/etc"
printf '%s\n' \
    'ID=ubuntu' \
    'VERSION_ID="26.04"' \
    'PRETTY_NAME="Ubuntu 26.04 LTS"' > "$missing_root/etc/os-release"
missing_directory="$test_directory/missing-output"
run_patcher "$test_directory/missing-command" \
    --root "$missing_root" --output-dir "$missing_directory" --checks U-16
assert_equal 2 "$RUN_STATUS" "required file absence status"
assert_contains "$(< "$test_directory/missing-command.stderr")" \
    'pre-scan scanner audit failed with exit status 2' "required file absence diagnostic"
[ ! -e "$missing_directory/plan.tsv" ] || fail "required file absence published a plan"
[ ! -e "$missing_directory/metadata.tsv" ] || fail "required file absence published rollback metadata"
[ ! -e "$missing_directory/state" ] || fail "required file absence published transaction state"

if [ "${EUID:-$(id -u)}" -eq 0 ]; then
    apply_directory="$test_directory/apply"
    run_patcher "$test_directory/apply-command" \
        --root "$scan_root" --output-dir "$apply_directory" --apply
    assert_equal 0 "$RUN_STATUS" "root apply status"
    assert_equal verified "$(< "$apply_directory/state")" "root apply transaction state"
    assert_equal 644 "$(file_mode "$scan_root/etc/passwd")" "applied passwd mode"
    assert_equal 400 "$(file_mode "$scan_root/etc/shadow")" "applied shadow mode"
    assert_equal 644 "$(file_mode "$scan_root/etc/hosts")" "applied hosts mode"
    assert_equal "$issue_original" "$(file_metadata "$scan_root/etc/issue")" \
        "unselected issue metadata"
    assert_equal "$issue_content_original" "$(< "$scan_root/etc/issue")" \
        "unselected issue content"
    assert_equal $'TMOUT=600\nreadonly TMOUT\nexport TMOUT' \
        "$(< "$scan_root/etc/profile.d/99-kisa-cce-session-timeout.sh")" \
        "applied session timeout"
    [ -d "$apply_directory/post-scan" ] || fail "root apply omitted the post-scan directory"
    assert_contains "$(< "$test_directory/apply-command.stdout")" \
        'apply_status=verified' "root apply verification output"

    run_patcher "$test_directory/rollback-command" \
        --root "$scan_root" --rollback "$apply_directory"
    assert_equal 0 "$RUN_STATUS" "manual rollback status"
    assert_equal rolled_back "$(< "$apply_directory/state")" "manual rollback transaction state"
    assert_equal "$passwd_original" "$(file_metadata "$scan_root/etc/passwd")" "rollback passwd metadata"
    assert_equal "$shadow_original" "$(file_metadata "$scan_root/etc/shadow")" "rollback shadow metadata"
    assert_equal "$hosts_original" "$(file_metadata "$scan_root/etc/hosts")" "rollback hosts metadata"
    assert_equal "$issue_original" "$(file_metadata "$scan_root/etc/issue")" "rollback issue metadata"
    assert_equal "$issue_content_original" "$(< "$scan_root/etc/issue")" "rollback issue content"
    [ ! -e "$scan_root/etc/profile.d/99-kisa-cce-session-timeout.sh" ] ||
        fail "rollback retained the session timeout configuration"
    assert_contains "$(< "$test_directory/rollback-command.stdout")" \
        'rollback_status=rolled_back' "manual rollback output"

    automatic_directory="$test_directory/automatic"
    run_patcher "$test_directory/automatic-command" \
        --root "$scan_root" --output-dir "$automatic_directory" --automatic
    assert_equal 2 "$RUN_STATUS" "automatic desired-state requirement status"
    assert_contains "$(< "$test_directory/automatic-command.stderr")" \
        "--automatic requires --desired-state FILE" "automatic desired-state diagnostic"
    [ ! -e "$automatic_directory" ] || fail "missing desired-state created an automatic transaction"

    configuration_only_directory="$test_directory/configuration-only"
    run_patcher "$test_directory/configuration-only-command" \
        --root "$scan_root" --output-dir "$configuration_only_directory" --checks U-12 --apply
    assert_equal 0 "$RUN_STATUS" "configuration-only apply status"
    assert_equal verified "$(< "$configuration_only_directory/state")" \
        "configuration-only transaction state"
    assert_equal 1 "$(wc -l < "$configuration_only_directory/metadata.tsv" | tr -d '[:space:]')" \
        "configuration-only empty metadata snapshot"
    run_patcher "$test_directory/configuration-only-rollback-command" \
        --root "$scan_root" --rollback "$configuration_only_directory"
    assert_equal 0 "$RUN_STATUS" "configuration-only rollback status"
    [ ! -e "$scan_root/etc/profile.d/99-kisa-cce-session-timeout.sh" ] ||
        fail "configuration-only rollback retained the session timeout configuration"
fi

printf 'PASS: patch CLI\n'
