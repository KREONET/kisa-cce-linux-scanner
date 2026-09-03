#!/bin/bash

# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause

# This test validates repository-local targets in inline Markdown links.

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
LC_ALL=C
export LC_ALL

case "${BASH_SOURCE[0]}" in
    */*) source_parent="${BASH_SOURCE[0]%/*}" ;;
    *) source_parent="." ;;
esac
TEST_DIR="$(CDPATH='' cd -P -- "$source_parent" && pwd)" || exit 2
PROJECT_DIR="$(CDPATH='' cd -P -- "$TEST_DIR/.." && pwd)" || exit 2

CHECKED=0
FAILED=0

check_markdown_file() {
    local source_file="$1"
    local source_relative="${source_file#"$PROJECT_DIR/"}"
    local line=""
    local remaining=""
    local match=""
    local destination=""
    local target=""
    local candidate=""
    local line_number=0

    while IFS= read -r line || [ -n "$line" ]; do
        line_number=$((line_number + 1))
        remaining="$line"
        while [[ "$remaining" =~ \]\(([^\)]*)\) ]]; do
            match="${BASH_REMATCH[0]}"
            destination="${BASH_REMATCH[1]}"
            remaining="${remaining#*"$match"}"

            destination="${destination#"${destination%%[![:space:]]*}"}"
            destination="${destination%"${destination##*[![:space:]]}"}"
            if [[ "$destination" == \<*\>* ]]; then
                destination="${destination#<}"
                destination="${destination%%>*}"
            else
                destination="${destination%%[[:space:]]*}"
            fi

            case "$destination" in
                ""|\#*|//* ) continue ;;
            esac
            if [[ "$destination" =~ ^[A-Za-z][A-Za-z0-9+.-]*: ]]; then
                continue
            fi

            target="${destination%%#*}"
            target="${target%%\?*}"
            [ -n "$target" ] || continue
            if [[ "$target" == /* ]]; then
                candidate="$PROJECT_DIR/${target#/}"
            else
                candidate="${source_file%/*}/$target"
            fi

            CHECKED=$((CHECKED + 1))
            if [ ! -e "$candidate" ]; then
                printf 'BROKEN %s:%d target=%s\n' "$source_relative" "$line_number" "$destination" >&2
                FAILED=$((FAILED + 1))
            fi
        done
    done < "$source_file"
}

while IFS= read -r -d '' markdown_file; do
    check_markdown_file "$markdown_file"
done < <(
    find "$PROJECT_DIR" \
        -path "$PROJECT_DIR/.git" -prune -o \
        -type f -name '*.md' -print0
)

printf 'RESULT checked=%d failed=%d\n' "$CHECKED" "$FAILED"
[ "$FAILED" -eq 0 ]
