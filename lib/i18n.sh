# SPDX-License-Identifier: LGPL-3.0-or-later
# shellcheck shell=bash

# Provides strict, deterministic localization lookups without gettext.

KISA_CCE_LANGUAGE="${KISA_CCE_LANGUAGE:-ko}"
: "${DATA_DIR:?DATA_DIR must be set before loading i18n.sh}"
if [ -z "${I18N_LOCALE_DIRECTORY:-}" ]; then
    case "$DATA_DIR" in
        */data)
            I18N_LOCALE_DIRECTORY="${DATA_DIR%/data}/share/kisa-cce-linux-scanner/locale"
            ;;
        */share/kisa-cce-linux-scanner) I18N_LOCALE_DIRECTORY="$DATA_DIR/locale" ;;
        *) I18N_LOCALE_DIRECTORY="" ;;
    esac
fi
I18N_CATALOG_LOADED=0
I18N_CONSOLE_CATALOG_LOADED=0
declare -A I18N_CATALOG=()
declare -A I18N_CONSOLE_CATALOG=()

i18n_validate_language() {
    case "$KISA_CCE_LANGUAGE" in
        ko|en) return 0 ;;
        *) return 2 ;;
    esac
}

i18n_validate_destination() {
    case "$1" in
        ''|[0-9]*|*[!A-Za-z0-9_]*|__kisa_i18n_*|I18N_*) return 2 ;;
        *) return 0 ;;
    esac
}

i18n_decode_po_string_into() {
    local __kisa_i18n_encoded_text="$1"
    local __kisa_i18n_destination="$2"
    local __kisa_i18n_decoded_text=""
    local __kisa_i18n_current_character=""
    local __kisa_i18n_escaped_character=""
    local __kisa_i18n_index=0

    i18n_validate_destination "$__kisa_i18n_destination" || return 2
    while [ "$__kisa_i18n_index" -lt "${#__kisa_i18n_encoded_text}" ]; do
        __kisa_i18n_current_character="${__kisa_i18n_encoded_text:__kisa_i18n_index:1}"
        if [ "$__kisa_i18n_current_character" = '"' ]; then
            return 2
        elif [ "$__kisa_i18n_current_character" = "\\" ]; then
            __kisa_i18n_index=$((__kisa_i18n_index + 1))
            [ "$__kisa_i18n_index" -lt "${#__kisa_i18n_encoded_text}" ] || return 2
            __kisa_i18n_escaped_character="${__kisa_i18n_encoded_text:__kisa_i18n_index:1}"
            if [ "$__kisa_i18n_escaped_character" != '"' ] &&
                [ "$__kisa_i18n_escaped_character" != "\\" ]; then
                return 2
            fi
            __kisa_i18n_decoded_text+="$__kisa_i18n_escaped_character"
        else
            __kisa_i18n_decoded_text+="$__kisa_i18n_current_character"
        fi
        __kisa_i18n_index=$((__kisa_i18n_index + 1))
    done
    printf -v "$__kisa_i18n_destination" '%s' "$__kisa_i18n_decoded_text"
}

i18n_parse_po_line_into() {
    local __kisa_i18n_line="$1"
    local __kisa_i18n_keyword="$2"
    local __kisa_i18n_destination="$3"
    local __kisa_i18n_encoded_text=""

    i18n_validate_destination "$__kisa_i18n_destination" || return 2
    case "$__kisa_i18n_line" in
        "$__kisa_i18n_keyword "'"'*'"') ;;
        *) return 2 ;;
    esac
    __kisa_i18n_encoded_text="${__kisa_i18n_line#"$__kisa_i18n_keyword \""}"
    __kisa_i18n_encoded_text="${__kisa_i18n_encoded_text%\"}"
    i18n_decode_po_string_into "$__kisa_i18n_encoded_text" "$__kisa_i18n_destination"
}

i18n_load_po_catalog() {
    local catalog_file="$1"
    local catalog_kind="$2"
    local line=""
    local source_text=""
    local translated_text=""
    local parser_state="msgid"
    local entry_count=0

    [ -r "$catalog_file" ] || return 2

    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            *$'\r') return 2 ;;
        esac
        if [ -z "$line" ]; then
            [ "$parser_state" = "msgid" ] || return 2
            continue
        fi

        case "$parser_state" in
            msgid)
                i18n_parse_po_line_into "$line" msgid source_text || return 2
                [ -n "$source_text" ] || return 2
                parser_state="msgstr"
                ;;
            msgstr)
                i18n_parse_po_line_into "$line" msgstr translated_text || return 2
                [ -n "$translated_text" ] || return 2
                case "$catalog_kind" in
                    report)
                        [ -z "${I18N_CATALOG[$source_text]+set}" ] || return 2
                        I18N_CATALOG["$source_text"]="$translated_text"
                        ;;
                    console)
                        [ -z "${I18N_CONSOLE_CATALOG[$source_text]+set}" ] || return 2
                        I18N_CONSOLE_CATALOG["$source_text"]="$translated_text"
                        ;;
                    *) return 2 ;;
                esac
                entry_count=$((entry_count + 1))
                source_text=""
                translated_text=""
                parser_state="msgid"
                ;;
            *) return 2 ;;
        esac
    done < "$catalog_file"

    [ "$parser_state" = "msgid" ] || return 2
    [ "$entry_count" -gt 0 ] || return 2
}

i18n_load_catalog() {
    local catalog_file=""

    [ "$I18N_CATALOG_LOADED" -eq 0 ] || return 0
    i18n_validate_language || return 2
    catalog_file="$I18N_LOCALE_DIRECTORY/$KISA_CCE_LANGUAGE/LC_MESSAGES/kisa-cce-linux-scanner.po"
    I18N_CATALOG=()
    i18n_load_po_catalog "$catalog_file" report || return 2
    I18N_CATALOG_LOADED=1
}

i18n_load_console_catalog() {
    local source_text=""
    local catalog_file="$I18N_LOCALE_DIRECTORY/en/LC_MESSAGES/kisa-cce-linux-scanner.po"

    [ "$I18N_CONSOLE_CATALOG_LOADED" -eq 0 ] || return 0
    I18N_CONSOLE_CATALOG=()
    if [ "$KISA_CCE_LANGUAGE" = "en" ] && [ "$I18N_CATALOG_LOADED" -eq 1 ]; then
        for source_text in "${!I18N_CATALOG[@]}"; do
            I18N_CONSOLE_CATALOG["$source_text"]="${I18N_CATALOG[$source_text]}"
        done
    else
        i18n_load_po_catalog "$catalog_file" console || return 2
    fi
    [ "${#I18N_CONSOLE_CATALOG[@]}" -gt 0 ] || return 2
    I18N_CONSOLE_CATALOG_LOADED=1
}

i18n_translate_into() {
    local __kisa_i18n_source_text="$1"
    local __kisa_i18n_destination="$2"

    i18n_validate_destination "$__kisa_i18n_destination" || return 2
    i18n_load_catalog || return 2
    [ -n "${I18N_CATALOG[$__kisa_i18n_source_text]+set}" ] || return 1
    printf -v "$__kisa_i18n_destination" '%s' "${I18N_CATALOG[$__kisa_i18n_source_text]}"
}

i18n_translate() {
    local translated_text=""

    i18n_translate_into "$1" translated_text || return $?
    printf '%s\n' "$translated_text"
}

i18n_console_translate_into() {
    local __kisa_i18n_source_text="$1"
    local __kisa_i18n_destination="$2"

    i18n_validate_destination "$__kisa_i18n_destination" || return 2
    i18n_load_console_catalog || return 2
    [ -n "${I18N_CONSOLE_CATALOG[$__kisa_i18n_source_text]+set}" ] || return 1
    printf -v "$__kisa_i18n_destination" '%s' "${I18N_CONSOLE_CATALOG[$__kisa_i18n_source_text]}"
}

i18n_criterion_title_into() {
    local __kisa_i18n_criterion_code="$1"
    local __kisa_i18n_korean_title="$2"
    local __kisa_i18n_destination="$3"

    case "$__kisa_i18n_criterion_code" in
        U-[0-9][0-9]) ;;
        *) return 2 ;;
    esac
    i18n_translate_into "$__kisa_i18n_korean_title" "$__kisa_i18n_destination"
}

i18n_criterion_title() {
    local translated_title=""

    i18n_criterion_title_into "$1" "$2" translated_title || return $?
    printf '%s\n' "$translated_title"
}

i18n_summary_into() {
    i18n_translate_into "$1" "$2"
}

i18n_summary() {
    local translated_summary=""

    i18n_summary_into "$1" translated_summary || return $?
    printf '%s\n' "$translated_summary"
}

i18n_ui_label_source_into() {
    local __kisa_i18n_label_key="$1"
    local __kisa_i18n_destination="$2"
    local __kisa_i18n_source_text=""

    i18n_validate_destination "$__kisa_i18n_destination" || return 2
    case "$__kisa_i18n_label_key" in
        report_title) __kisa_i18n_source_text="KISA CCE 2026 Linux 보안 점검 보고서" ;;
        scan_information) __kisa_i18n_source_text="점검 정보" ;;
        field) __kisa_i18n_source_text="항목" ;;
        value) __kisa_i18n_source_text="값" ;;
        generated_at) __kisa_i18n_source_text="생성 시각" ;;
        completed_at) __kisa_i18n_source_text="완료 시각" ;;
        scanner_version) __kisa_i18n_source_text="스캐너 버전" ;;
        platform) __kisa_i18n_source_text="플랫폼" ;;
        scan_root) __kisa_i18n_source_text="검사 루트" ;;
        runtime_mode) __kisa_i18n_source_text="런타임 모드" ;;
        scan_mode) __kisa_i18n_source_text="검사 모드" ;;
        criterion) __kisa_i18n_source_text="점검 항목" ;;
        category) __kisa_i18n_source_text="분류" ;;
        severity) __kisa_i18n_source_text="중요도" ;;
        applicable) __kisa_i18n_source_text="적용 여부" ;;
        status) __kisa_i18n_source_text="상태" ;;
        final_status) __kisa_i18n_source_text="최종 판정" ;;
        technical_status) __kisa_i18n_source_text="기술 판정" ;;
        decision_basis) __kisa_i18n_source_text="판정 근거" ;;
        review_id) __kisa_i18n_source_text="검토 ID" ;;
        attestation_ticket) __kisa_i18n_source_text="승인 티켓" ;;
        attestation_approver) __kisa_i18n_source_text="승인자" ;;
        attestation_expires) __kisa_i18n_source_text="승인 만료일" ;;
        summary) __kisa_i18n_source_text="요약" ;;
        evidence) __kisa_i18n_source_text="근거" ;;
        guide) __kisa_i18n_source_text="가이드" ;;
        reference) __kisa_i18n_source_text="기준" ;;
        result_summary) __kisa_i18n_source_text="결과 요약" ;;
        total) __kisa_i18n_source_text="전체" ;;
        count) __kisa_i18n_source_text="개수" ;;
        good) __kisa_i18n_source_text="양호" ;;
        vulnerable) __kisa_i18n_source_text="취약" ;;
        manual) __kisa_i18n_source_text="수동 확인" ;;
        not_applicable) __kisa_i18n_source_text="해당 없음" ;;
        error) __kisa_i18n_source_text="오류" ;;
        policy_resolved) __kisa_i18n_source_text="정책 승인으로 확정" ;;
        *) return 1 ;;
    esac
    printf -v "$__kisa_i18n_destination" '%s' "$__kisa_i18n_source_text"
}

i18n_ui_label_into() {
    local __kisa_i18n_label_key="$1"
    local __kisa_i18n_destination="$2"
    local __kisa_i18n_source_text=""
    local label_source=""

    i18n_ui_label_source_into "$__kisa_i18n_label_key" label_source || return $?
    __kisa_i18n_source_text="$label_source"
    i18n_translate_into "$__kisa_i18n_source_text" "$__kisa_i18n_destination"
}

i18n_ui_label() {
    local translated_label=""

    i18n_ui_label_into "$1" translated_label || return $?
    printf '%s\n' "$translated_label"
}
