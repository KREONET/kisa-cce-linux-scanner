# SPDX-License-Identifier: LGPL-3.0-or-later OR BSD-3-Clause
# shellcheck shell=bash
# shellcheck disable=SC2034

# Coordinates immutable run-scoped snapshots and their dependency graph.

SCAN_EPOCH_SEQUENCE=0
SCAN_EPOCH_ID=0
SCAN_EPOCH=0
SCAN_EPOCH_ACTIVE=0
SCAN_ACTIVE_CRITERION=""
SCAN_RESOLVER_SCHEMA_VERSION=2
SCAN_EPOCH_CONTEXT=""
SCAN_EPOCH_UTC_DATE=""
SCAN_INCREMENTAL_REEVALUATION_ACTIVE=0

declare -gA SCAN_SOURCE_RESOLVERS=()
declare -gA SCAN_RESOLVER_CRITERIA=()
declare -gA SCAN_SOURCE_DIRTY=()
declare -gA SCAN_RESOLVER_DIRTY=()
declare -gA SCAN_CRITERION_DIRTY=()
declare -gA SCAN_RESOLVER_NORMALIZED_OUTPUT=()
declare -gA SCAN_CONTEXT_VALUE=()
declare -gA SCAN_ALL_RESOLVERS=()

scan_epoch_identifier_is_valid() {
    local value="${1-}"

    [ -n "$value" ] || return 1
    case "$value" in *$'\n'*|*$'\r'*|*$'\t'*|*$'\034'*) return 1 ;; esac
}

scan_epoch_append_unique() {
    local map_name="$1"
    local key="$2"
    local value="$3"
    local item=""
    local -n map_reference="$map_name"

    scan_epoch_identifier_is_valid "$key" || return 2
    scan_epoch_identifier_is_valid "$value" || return 2
    if [ -n "${map_reference[$key]+present}" ]; then
        while IFS= read -r item; do
            [ "$item" = "$value" ] && return 0
        done <<< "${map_reference[$key]}"
        map_reference["$key"]+=$'\n'"$value"
    else
        map_reference["$key"]="$value"
    fi
}

scan_dependency_register() {
    local source_id="${1-}"
    local resolver_id="${2-}"

    [ "$SCAN_EPOCH_ACTIVE" -eq 1 ] || return 0
    [ "$SCAN_INCREMENTAL_REEVALUATION_ACTIVE" -eq 1 ] || return 0
    scan_epoch_append_unique SCAN_SOURCE_RESOLVERS "$source_id" "$resolver_id" || return 2
    SCAN_ALL_RESOLVERS["$resolver_id"]=1
    if [ -n "$SCAN_ACTIVE_CRITERION" ]; then
        scan_epoch_append_unique SCAN_RESOLVER_CRITERIA "$resolver_id" "$SCAN_ACTIVE_CRITERION" || return 2
    fi
}

scan_source_mark_dirty() {
    local source_id="${1-}"
    local resolver_id=""

    scan_epoch_identifier_is_valid "$source_id" || return 2
    SCAN_SOURCE_DIRTY["$source_id"]=1
    while IFS= read -r resolver_id; do
        [ -n "$resolver_id" ] || continue
        SCAN_RESOLVER_DIRTY["$resolver_id"]=1
    done <<< "${SCAN_SOURCE_RESOLVERS[$source_id]-}"
}

scan_resolver_commit() {
    local resolver_id="${1-}"
    local normalized_output="${2-}"
    local criterion_code=""

    scan_epoch_identifier_is_valid "$resolver_id" || return 2
    case "$SCAN_INCREMENTAL_REEVALUATION_ACTIVE" in
        0) return 0 ;;
        1) ;;
        *) return 2 ;;
    esac
    if [ -n "${SCAN_RESOLVER_NORMALIZED_OUTPUT[$resolver_id]+present}" ] &&
        [ "${SCAN_RESOLVER_NORMALIZED_OUTPUT[$resolver_id]}" = "$normalized_output" ]; then
        SCAN_RESOLVER_DIRTY["$resolver_id"]=0
        return 1
    fi
    SCAN_RESOLVER_NORMALIZED_OUTPUT["$resolver_id"]="$normalized_output"
    SCAN_RESOLVER_DIRTY["$resolver_id"]=1
    while IFS= read -r criterion_code; do
        [ -n "$criterion_code" ] || continue
        SCAN_CRITERION_DIRTY["$criterion_code"]=1
    done <<< "${SCAN_RESOLVER_CRITERIA[$resolver_id]-}"
    return 0
}

scan_epoch_reset_dirty_state() {
    SCAN_SOURCE_DIRTY=()
    SCAN_RESOLVER_DIRTY=()
    SCAN_CRITERION_DIRTY=()
}

scan_epoch_update_context_source() {
    local source_id="$1"
    local value="$2"
    local resolver_id=""

    if [ -n "${SCAN_CONTEXT_VALUE[$source_id]+present}" ] &&
        [ "${SCAN_CONTEXT_VALUE[$source_id]}" != "$value" ]; then
        SCAN_SOURCE_DIRTY["$source_id"]=1
        for resolver_id in "${!SCAN_ALL_RESOLVERS[@]}"; do
            SCAN_RESOLVER_DIRTY["$resolver_id"]=1
        done
    fi
    SCAN_CONTEXT_VALUE["$source_id"]="$value"
}

scan_epoch_begin() {
    local context=""
    local evidence_context="inactive"
    local policy_context="inactive"

    [ -n "${SCRATCH_DIR:-}" ] && [ -d "$SCRATCH_DIR" ] && [ ! -L "$SCRATCH_DIR" ] || return 2
    SCAN_EPOCH_SEQUENCE=$((SCAN_EPOCH_SEQUENCE + 1))
    SCAN_EPOCH_ID="$SCAN_EPOCH_SEQUENCE"
    SCAN_EPOCH="$SCAN_EPOCH_ID"
    SCAN_EPOCH_ACTIVE=1
    SCAN_ACTIVE_CRITERION=""
    scan_epoch_reset_dirty_state

    SCAN_EPOCH_UTC_DATE="$(/bin/date -u +%Y-%m-%d 2>/dev/null)" || return 2
    case "$SCAN_EPOCH_UTC_DATE" in
        [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
        *) return 2 ;;
    esac
    if [ "$SCAN_EPOCH_SEQUENCE" -gt 1 ]; then
        scan_source_mark_dirty runtime:systemd || return 2
        scan_source_mark_dirty runtime:listeners || return 2
        scan_source_mark_dirty runtime:processes || return 2
        scan_source_mark_dirty runtime:system-manager || return 2
        scan_source_mark_dirty runtime:sysctl || return 2
    fi

    printf -v context 'resolver_schema=%s\nscanner_version=%s\nplatform=%s:%s:%s:%s\npolicy_digest=%s\nevidence_digest=%s' \
        "$SCAN_RESOLVER_SCHEMA_VERSION" "${KISA_CCE_VERSION:-unknown}" \
        "${PLATFORM_ID:-unknown}" "${PLATFORM_VERSION:-unknown}" \
        "${PLATFORM_BASE_ID:-unknown}" "${PLATFORM_BASE_VERSION:-unknown}" \
        "${POLICY_SET_DIGEST:-none}" "${EVIDENCE_BUNDLE_DIGEST:-none}"
    SCAN_EPOCH_CONTEXT="$context"
    scan_epoch_update_context_source context:resolver-schema "$SCAN_RESOLVER_SCHEMA_VERSION" || return 2
    scan_epoch_update_context_source context:scanner-version "${KISA_CCE_VERSION:-unknown}" || return 2
    scan_epoch_update_context_source context:platform-profile \
        "${PLATFORM_ID:-unknown}:${PLATFORM_VERSION:-unknown}:${PLATFORM_BASE_ID:-unknown}:${PLATFORM_BASE_VERSION:-unknown}" || return 2
    scan_epoch_update_context_source context:policy-digest "${POLICY_SET_DIGEST:-none}" || return 2
    scan_epoch_update_context_source context:policy-date "$SCAN_EPOCH_UTC_DATE" || return 2
    scan_epoch_update_context_source context:evidence-digest "${EVIDENCE_BUNDLE_DIGEST:-none}" || return 2

    if declare -F resolver_reset_epoch_caches >/dev/null 2>&1; then resolver_reset_epoch_caches || return 2; fi
    if declare -F pam_reset_epoch_cache >/dev/null 2>&1; then pam_reset_epoch_cache || return 2; fi
    if declare -F systemd_reset_epoch_cache >/dev/null 2>&1; then systemd_reset_epoch_cache || return 2; fi
    if declare -F listener_reset_epoch_cache >/dev/null 2>&1; then listener_reset_epoch_cache || return 2; fi
    if declare -F runtime_fallback_reset_epoch_cache >/dev/null 2>&1; then runtime_fallback_reset_epoch_cache || return 2; fi
    if declare -F scanner_reset_full_filesystem_cache >/dev/null 2>&1; then scanner_reset_full_filesystem_cache || return 2; fi
    [ "${POLICY_SET_DIGEST:-none}" = "none" ] || policy_context="active"
    case "${EVIDENCE_BUNDLE_ACTIVE:-0}" in 1) evidence_context="active" ;; esac
    if declare -F debug_emit >/dev/null 2>&1; then
        debug_emit scan_epoch phase begin epoch "$SCAN_EPOCH_ID" \
            resolver_schema "$SCAN_RESOLVER_SCHEMA_VERSION" \
            incremental "$SCAN_INCREMENTAL_REEVALUATION_ACTIVE" \
            policy "$policy_context" evidence "$evidence_context" || :
    fi
    return 0
}

scan_epoch_end() {
    if declare -F debug_emit >/dev/null 2>&1; then
        debug_emit scan_epoch phase end epoch "$SCAN_EPOCH_ID" || :
    fi
    SCAN_ACTIVE_CRITERION=""
    SCAN_EPOCH_ACTIVE=0
}
