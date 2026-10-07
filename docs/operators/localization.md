# Localization

Reports are available in Korean (`ko`) and English (`en`). The launcher reads
`LANG` and passes the normalized language identifier to the runtime as
`KISA_CCE_LANGUAGE`. Command output is always parsed in the C locale,
regardless of the report language.

## Selecting a language

Set `LANG` for the scanner process to select the report language. An English
locale selects English. Korean is the default when `LANG` is unset or specifies
Korean, `C`, `POSIX`, or any other locale.

```bash
LANG=ko_KR.UTF-8 kisa-cce-scan
LANG=en_US.UTF-8 kisa-cce-scan
```

Console help, progress, warning, and error messages are always English. `LANG`
selects only localized report titles, criterion titles, summaries, and labels.

The host does not need to have the named locale generated. The launcher reads
only the `LANG` prefix and passes `ko` or `en` to the runtime.

## Catalogs

The source catalogs are
`share/kisa-cce-linux-scanner/locale/ko/LC_MESSAGES/kisa-cce-linux-scanner.po`
and
`share/kisa-cce-linux-scanner/locale/en/LC_MESSAGES/kisa-cce-linux-scanner.po`.
Packages install them under `/usr/share/kisa-cce-linux-scanner/locale`. Each
Korean criterion title, summary, and user-interface label is an exact `msgid`.
The Korean catalog maps each source string to itself, while the English catalog
supplies its English translation.

The scanner parses a restricted PO subset directly in Bash. Each entry has
one single-line `msgid` followed immediately by one single-line `msgstr`. A
blank line may separate entries:

```po
msgid "검사 모드"
msgstr "Scan mode"
```

Lookups must match exactly, including leading and trailing whitespace,
punctuation, and letter case. The parser rejects duplicate or empty strings,
contexts, plurals, fuzzy entries, multiline strings, unknown directives, and
escapes other than `\"` and `\\`. If a requested criterion title, summary, or UI
label is missing, English output fails rather than falling back to Korean.
Neither a gettext runtime nor a `msgfmt` build dependency is required.

## Translator workflow

1. Copy each Korean criterion title or summary exactly from `data/criteria.tsv`
   or the corresponding `set_result` call.
2. Add the same `msgid` to both catalogs. Use the unchanged source string as
   the Korean `msgstr` and a natural technical translation as the English
   `msgstr`.
3. Keep every `msgid` unique and use only the supported two-line entry form.
4. Keep both catalogs UTF-8 encoded with LF line endings.
5. Run the project syntax, lint, and test targets before submitting changes.

Leave machine-readable evidence fields, enum values such as `GOOD` and
`MANUAL`, paths, command names, and configuration keys untranslated so that
automation can continue to consume the same JSONL values.
