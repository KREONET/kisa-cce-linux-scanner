#!/usr/bin/env bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

set -u

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
LC_ALL=C
export LC_ALL
umask 077

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

platform_id="$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null | tr -d '"' | head -n 1)"
platform_version="$(sed -n 's/^VERSION_ID=//p' /etc/os-release 2>/dev/null | tr -d '"' | head -n 1)"
if [ "$platform_id:$platform_version" != ubuntu:26.04 ]; then
    printf 'SKIP: rust-coreutils compatibility requires Ubuntu 26.04\n'
    exit 0
fi

test_directory="$(mktemp -d "${TMPDIR:-/tmp}/kisa-cce-uutils.XXXXXXXX")" || exit 2
trap 'rm -rf -- "$test_directory"' EXIT
source_file="$test_directory/source"
link_path="$test_directory/link"
sorted_file="$test_directory/sorted"
installed_directory="$test_directory/installed"
printf 'scanner compatibility\n' > "$source_file"
ln -s source "$link_path"

metadata="$(stat -Lc '%d:%i:%u:%g:%a:%h:%s:%Y:%Z' -- "$source_file")" ||
    fail "stat lacks the metadata format used by the scanner"
case "$metadata" in *[!0-9:]*) fail "stat returned an incompatible metadata record" ;; esac
[ "$(readlink -f -- "$link_path")" = "$source_file" ] ||
    fail "readlink -f does not resolve scanner paths"
printf 'z\0a\0' | sort -z > "$sorted_file" || fail "sort -z is unavailable"
[ "$(od -An -tx1 "$sorted_file" | tr -d ' \n')" = 61007a00 ] ||
    fail "sort -z returned an incompatible record order"
timestamp="$(date -r "$source_file" -u +%Y-%m-%dT%H:%M:%SZ)" ||
    fail "date -r lacks the scanner timestamp form"
case "$timestamp" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z) ;;
    *) fail "date returned an incompatible UTC timestamp" ;;
esac
digest="$(sha256sum -- "$source_file" | awk '{print $1}')" ||
    fail "sha256sum rejected the scanner option form"
case "$digest" in
    [0-9a-f][0-9a-f]*) [ "${#digest}" -eq 64 ] || fail "sha256sum digest length differs" ;;
    *) fail "sha256sum returned an invalid digest" ;;
esac
install -d -m 0755 "$installed_directory" || fail "install -d is incompatible"
install -m 0644 "$source_file" "$installed_directory/copied" || fail "install file mode is incompatible"
[ "$(stat -Lc '%a' -- "$installed_directory/copied")" = 644 ] ||
    fail "install did not apply the requested mode"

printf 'PASS: Ubuntu 26.04 rust-coreutils compatibility\n'
