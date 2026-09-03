# Localization

The scanner supports Korean (`ko`) and English (`en`) report output. The
launcher derives the language from `LANG`, normalizes it, and passes the result
to the runtime as `KISA_CCE_LANGUAGE`. The scanner does not change the locale
used for parsing command output; internal command processing continues to use
the C locale.

## Selecting a language

Set `LANG` for the scanner process. An English locale selects English reports.
Korean is the default for Korean, unset, `C`, `POSIX`, and other locale values.

```bash
LANG=ko_KR.UTF-8 kisa-cce-scan
LANG=en_US.UTF-8 kisa-cce-scan
```

Console help, progress, warning, and error messages are always English. `LANG`
selects only localized report titles, criterion titles, summaries, and labels.

The named locale does not need to be generated on the host. The launcher uses
only the `LANG` prefix and passes a normalized `ko` or `en` identifier.

## Catalogs

The source catalogs are
`share/kisa-cce-linux-scanner/locale/ko/LC_MESSAGES/kisa-cce-linux-scanner.po`
and
`share/kisa-cce-linux-scanner/locale/en/LC_MESSAGES/kisa-cce-linux-scanner.po`.
Packages install them under `/usr/share/kisa-cce-linux-scanner/locale`. Each
Korean criterion title, summary, and user-interface label is an exact `msgid`.
The Korean catalog maps each source string to itself, while the English catalog
supplies its English translation.

The scanner parses a deliberately restricted PO subset directly in Bash. Each
entry consists of one single-line `msgid`, one immediately following
single-line `msgstr`, and an optional blank separator:

```po
msgid "검사 모드"
msgstr "Scan mode"
```

Lookup is exact. Leading or trailing whitespace, punctuation, and letter case
are significant. Duplicate or empty strings make a catalog invalid. The parser
also rejects contexts, plurals, fuzzy entries, multiline strings, unknown
directives, and escapes other than `\"` and `\\`. English output fails closed
when a requested criterion title, summary, or UI label is absent; it does not
mix a Korean fallback into an English report. No gettext runtime or `msgfmt`
build dependency is required.

## Translator workflow

1. Copy each Korean criterion title or summary exactly from `data/criteria.tsv`
   or the corresponding `set_result` call.
2. Add the same `msgid` to both catalogs. Use the unchanged source string as
   the Korean `msgstr` and a natural technical translation as the English
   `msgstr`.
3. Keep every `msgid` unique and use only the supported two-line entry form.
4. Keep both catalogs UTF-8 encoded with LF line endings.
5. Run the project syntax, lint, and test targets before submitting changes.

Machine-readable evidence fields, enum values such as `GOOD` and `MANUAL`,
paths, command names, and configuration keys are not translated. This keeps
JSONL output stable for downstream automation.
