#!/bin/bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

set -u

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

file_mode() {
    stat -Lc '%a' -- "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null
}

case "${BASH_SOURCE[0]}" in */*) test_parent="${BASH_SOURCE[0]%/*}" ;; *) test_parent=. ;; esac
project_directory="$(CDPATH='' cd -P -- "$test_parent/.." && pwd)" || exit 2
test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-policy-compile.XXXXXXXX")" || exit 2
trap 'chmod -R u+rwX "$test_directory" 2>/dev/null || :; rm -rf -- "$test_directory"' EXIT

run_compiler() {
    local stdout_file="$1"
    local stderr_file="$2"
    shift 2
    "$project_directory/bin/kisa-cce-policy-compile" "$@" > "$stdout_file" 2> "$stderr_file"
}

assert_framed() {
    local file="$1"

    if grep -Ev '^\[[[:space:]]*[0-9]+\.[0-9]{6}\] kisa-cce-policy-compile: .*$' "$file" | grep -q .; then
        fail "terminal output is not dmesg framed: $file"
    fi
}

valid_yaml="$test_directory/valid.yml"
cat > "$valid_yaml" <<'EOF'
schema_version: 1
attestations:
  - code: U-07
    decision: GOOD
    review_id: sha256:0000000000000000000000000000000000000000000000000000000000000000
    ticket: "SEC #42 🌐"
    approver: '보안 담당자'
    expires: 2099-12-31
time_sources:
  - provider: chrony
    host: Time.Example.
    address: -
    ticket: TIME-42
    approver: time-owners
    expires: 2099-12-31
EOF
chmod 0600 "$valid_yaml"
stdout_file="$test_directory/valid.stdout"
stderr_file="$test_directory/valid.stderr"
output_directory="$test_directory/compiled"
run_compiler "$stdout_file" "$stderr_file" --input "$valid_yaml" --output-dir "$output_directory" ||
    fail "valid policy YAML was rejected: $(< "$stderr_file")"
[ ! -s "$stderr_file" ] || fail "valid compilation wrote standard error"
assert_framed "$stdout_file"
grep -Fq "policy_directory=$output_directory" "$stdout_file" || fail "compiled policy path was not printed"
grep -Eq 'policy_digest=sha256:[0-9a-f]{64}$' "$stdout_file" || fail "compiled policy digest was not printed"
assert_equal 700 "$(file_mode "$output_directory")" "compiled directory mode"
assert_equal 600 "$(file_mode "$output_directory/50-compiled.tsv")" "compiled attestation mode"
assert_equal 600 "$(file_mode "$output_directory/facts/time-sources.tsv")" "compiled fact mode"
grep -Fq $'U-07\tGOOD\tsha256:0000000000000000000000000000000000000000000000000000000000000000\tSEC #42 🌐\t보안 담당자\t2099-12-31' \
    "$output_directory/50-compiled.tsv" || fail "compiled attestation row differs"
grep -Fq $'chrony\tTime.Example.\t-\tTIME-42\ttime-owners\t2099-12-31' \
    "$output_directory/facts/time-sources.tsv" || fail "compiled time-source row differs"

neutral_yaml="$test_directory/neutral.yml"
cp "$project_directory/examples/policy.yml" "$neutral_yaml"
chmod 0600 "$neutral_yaml"
neutral_output="$test_directory/neutral"
run_compiler "$test_directory/neutral.stdout" "$test_directory/neutral.stderr" \
    --input "$neutral_yaml" --output-dir "$neutral_output" || fail "neutral YAML was rejected"
[ -f "$neutral_output/50-compiled.tsv" ] || fail "neutral attestation file is absent"
[ ! -e "$neutral_output/facts" ] || fail "omitted time_sources created a fact namespace"
assert_equal 1 "$(wc -l < "$neutral_output/50-compiled.tsv" | tr -d '[:space:]')" \
    "neutral attestation line count"

(
    cd "$test_directory" || exit 2
    "$project_directory/bin/kisa-cce-policy-compile" \
        --input ./neutral.yml --output-dir ./relative-output >/dev/null 2>relative.stderr
) || fail "leading-dot relative paths were rejected"
[ -d "$test_directory/relative-output" ] || fail "relative output directory is absent"

empty_facts_yaml="$test_directory/empty-facts.yml"
cat > "$empty_facts_yaml" <<'EOF'
schema_version: 1
attestations: []
time_sources: []
EOF
chmod 0600 "$empty_facts_yaml"
empty_facts_output="$test_directory/empty-facts"
run_compiler "$test_directory/empty.stdout" "$test_directory/empty.stderr" \
    --input "$empty_facts_yaml" --output-dir "$empty_facts_output" || fail "explicit empty facts were rejected"
assert_equal 1 "$(wc -l < "$empty_facts_output/facts/time-sources.tsv" | tr -d '[:space:]')" \
    "explicit empty fact-set line count"

invalid_yaml="$test_directory/invalid.yml"
cat > "$invalid_yaml" <<'EOF'
schema_version: 1
attestations:
  - code: U-07
    decision: ACCEPT
    review_id: sha256:0000000000000000000000000000000000000000000000000000000000000000
    ticket: SEC-42
    approver: owner
    expires: 2099-12-31
EOF
chmod 0600 "$invalid_yaml"
invalid_output="$test_directory/invalid"
status=0
run_compiler "$test_directory/invalid.stdout" "$test_directory/invalid.stderr" \
    --input "$invalid_yaml" --output-dir "$invalid_output" || status=$?
assert_equal 2 "$status" "invalid semantic policy status"
[ ! -e "$invalid_output" ] || fail "invalid semantic policy published output"
assert_framed "$test_directory/invalid.stderr"

ambiguous_yaml="$test_directory/ambiguous.yml"
cat > "$ambiguous_yaml" <<'EOF'
schema_version: 1
attestations:
  - &decision
    code: U-07
EOF
chmod 0600 "$ambiguous_yaml"
status=0
run_compiler "$test_directory/ambiguous.stdout" "$test_directory/ambiguous.stderr" \
    --input "$ambiguous_yaml" --output-dir "$test_directory/ambiguous" || status=$?
assert_equal 2 "$status" "unsupported YAML feature status"
[ ! -e "$test_directory/ambiguous" ] || fail "unsupported YAML feature published output"

comment_scalar_yaml="$test_directory/comment-scalar.yml"
cat > "$comment_scalar_yaml" <<'EOF'
schema_version: 1
attestations:
  - code: U-07
    decision: GOOD
    review_id: sha256:0000000000000000000000000000000000000000000000000000000000000000
    ticket: #not-a-value
    approver: owner
    expires: 2099-12-31
EOF
chmod 0600 "$comment_scalar_yaml"
status=0
run_compiler "$test_directory/comment-scalar.stdout" "$test_directory/comment-scalar.stderr" \
    --input "$comment_scalar_yaml" --output-dir "$test_directory/comment-scalar-output" || status=$?
assert_equal 2 "$status" "inline comment scalar status"
[ ! -e "$test_directory/comment-scalar-output" ] || fail "inline comment scalar published output"

control_yaml="$test_directory/control.yml"
printf 'schema_version: 1\nattestations:\n  - code: U-07\n    decision: GOOD\000\n' > "$control_yaml"
chmod 0600 "$control_yaml"
status=0
run_compiler "$test_directory/control.stdout" "$test_directory/control.stderr" \
    --input "$control_yaml" --output-dir "$test_directory/control-output" || status=$?
assert_equal 2 "$status" "NUL byte input status"
[ ! -e "$test_directory/control-output" ] || fail "NUL byte input published output"

invalid_utf8_yaml="$test_directory/invalid-utf8.yml"
printf 'schema_version: 1\nattestations: []\n# invalid: \300\257\n' > "$invalid_utf8_yaml"
chmod 0600 "$invalid_utf8_yaml"
status=0
run_compiler "$test_directory/invalid-utf8.stdout" "$test_directory/invalid-utf8.stderr" \
    --input "$invalid_utf8_yaml" --output-dir "$test_directory/invalid-utf8-output" || status=$?
assert_equal 2 "$status" "invalid UTF-8 input status"
[ ! -e "$test_directory/invalid-utf8-output" ] || fail "invalid UTF-8 input published output"

c1_control_yaml="$test_directory/c1-control.yml"
printf 'schema_version: 1\nattestations: []\n# invalid: \302\205\n' > "$c1_control_yaml"
chmod 0600 "$c1_control_yaml"
status=0
run_compiler "$test_directory/c1.stdout" "$test_directory/c1.stderr" \
    --input "$c1_control_yaml" --output-dir "$test_directory/c1-output" || status=$?
assert_equal 2 "$status" "Unicode C1 control input status"
[ ! -e "$test_directory/c1-output" ] || fail "Unicode C1 control input published output"

injection_marker="$test_directory/injection-executed"
injection_yaml="$test_directory/injection.yml"
{
    printf '%s\n' 'schema_version: 1' 'attestations:'
    printf '%s\n' '  - code: U-07' '    decision: GOOD'
    printf '%s\n' '    review_id: sha256:0000000000000000000000000000000000000000000000000000000000000000'
    printf '    ticket: "$(touch %s)"\n' "$injection_marker"
    printf '%s\n' '    approver: owner' '    expires: 2099-12-31'
} > "$injection_yaml"
chmod 0600 "$injection_yaml"
run_compiler "$test_directory/injection.stdout" "$test_directory/injection.stderr" \
    --input "$injection_yaml" --output-dir "$test_directory/injection-output" ||
    fail "literal shell syntax was rejected"
[ ! -e "$injection_marker" ] || fail "policy scalar executed shell syntax"
grep -Fq "\$(touch $injection_marker)" "$test_directory/injection-output/50-compiled.tsv" ||
    fail "literal shell syntax was not preserved"

mkdir -m 0700 "$test_directory/existing"
printf '%s\n' preserve > "$test_directory/existing/sentinel"
status=0
run_compiler "$test_directory/existing.stdout" "$test_directory/existing.stderr" \
    --input "$neutral_yaml" --output-dir "$test_directory/existing" || status=$?
assert_equal 2 "$status" "existing output directory status"
assert_equal preserve "$(< "$test_directory/existing/sentinel")" "existing output preservation"

ln -s "$neutral_yaml" "$test_directory/policy-link.yml"
status=0
run_compiler "$test_directory/symlink.stdout" "$test_directory/symlink.stderr" \
    --input "$test_directory/policy-link.yml" --output-dir "$test_directory/symlink-output" || status=$?
assert_equal 2 "$status" "symbolic-link input status"
[ ! -e "$test_directory/symlink-output" ] || fail "symbolic-link input published output"

if [ "$EUID" -eq 0 ]; then
    untrusted_ancestor="$test_directory/untrusted-ancestor"
    mkdir -m 0755 "$untrusted_ancestor"
    chown 12345:12345 "$untrusted_ancestor"
    mkdir -m 0700 "$untrusted_ancestor/root-owned"
    cp "$neutral_yaml" "$untrusted_ancestor/root-owned/policy.yml"
    chmod 0600 "$untrusted_ancestor/root-owned/policy.yml"
    status=0
    run_compiler "$test_directory/untrusted.stdout" "$test_directory/untrusted.stderr" \
        --input "$untrusted_ancestor/root-owned/policy.yml" \
        --output-dir "$untrusted_ancestor/root-owned/compiled" || status=$?
    assert_equal 2 "$status" "untrusted ancestor status"
    [ ! -e "$untrusted_ancestor/root-owned/compiled" ] || fail "untrusted ancestor published output"
fi

run_compiler "$test_directory/help.stdout" "$test_directory/help.stderr" --help || fail "help failed"
run_compiler "$test_directory/version.stdout" "$test_directory/version.stderr" --version || fail "version failed"
assert_framed "$test_directory/help.stdout"
assert_framed "$test_directory/version.stdout"
grep -Fq 'policy-yaml-schema=1' "$test_directory/version.stdout" || fail "version omitted YAML schema"

environment_file="$test_directory/untrusted-environment.sh"
environment_marker="$test_directory/environment-loaded"
printf '/usr/bin/touch %s\n' "$environment_marker" > "$environment_file"
BASH_ENV="$environment_file" ENV="$environment_file" \
    run_compiler "$test_directory/environment.stdout" "$test_directory/environment.stderr" --version ||
    fail "clean-environment compiler invocation failed"
[ ! -e "$environment_marker" ] || fail "compiler wrapper loaded the caller shell environment"

printf 'PASS: policy YAML compiler\n'
