# Policy attestation format

## Purpose

Policy attestations record decisions that require an authorized organizational review. They do not replace technical evidence collected by a criterion check. An attestation applies only when its criterion code and `review_id` match the current review basis and its expiration date has not passed.

The loader is implemented as a Bash 4.3 or newer source module in `lib/policy.sh`. It parses policy files as data and never evaluates their contents as shell code.

## Directory contract

`policy_load_dir PATH` reads direct children of `PATH` whose names end in `.tsv`. Bash expands the file names in `LC_ALL=C` lexical order. Files in subdirectories and names without the `.tsv` suffix are not read. A directory with no matching files is valid and loads no attestations.

The directory and every matching file must meet all of these requirements:

- The path itself is not a symbolic link.
- The directory is readable and searchable.
- Each policy file is a readable regular file.
- The owner is UID 0 or the scanner's effective UID.
- Group and other write bits are clear.

The loader rejects a matching symbolic link instead of following it. When loaded by the scanner, every existing path component must also pass the scanner's trusted-parent checks.

## TSV grammar

Every file starts with this exact header, using literal tab characters between fields:

```text
code	decision	review_id	ticket	approver	expires
```

Every subsequent line contains exactly six tab-separated fields:

| Field | Required value |
|---|---|
| `code` | One criterion code from `U-01` through `U-67`. |
| `decision` | `GOOD` or `VULNERABLE`. |
| `review_id` | `sha256:` followed by exactly 64 lowercase hexadecimal characters. |
| `ticket` | A non-empty change, exception, or approval record identifier. |
| `approver` | A non-empty identifier for the approving authority. |
| `expires` | A real Gregorian calendar date in `YYYY-MM-DD` form. |

Blank lines, comments, extra columns, missing columns, carriage returns, and other control characters are invalid. UTF-8 text and spaces are allowed in `ticket` and `approver`, but tabs and line breaks are not.

Example, where the field separators are literal tabs:

```text
code	decision	review_id	ticket	approver	expires
U-64	GOOD	sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef	SEC-2026-0142	security-governance	2026-12-31
```

## Merge and failure behavior

Files do not override one another. A criterion code may occur only once across the complete directory. A duplicate code, malformed file, untrusted path, or unreadable metadata makes `policy_load_dir` return status 2.

Loading is atomic from the caller's perspective. The exported arrays are cleared before validation and remain empty if validation fails. A successful load populates these associative arrays, keyed by criterion code:

```text
POLICY_DECISION
POLICY_REVIEW_ID
POLICY_TICKET
POLICY_APPROVER
POLICY_EXPIRES
```

`policy_load_dir` returns 0 after a successful load, including an empty directory.

## Lookup contract

Call `policy_lookup CODE REVIEW_ID` with the review identifier calculated by the current criterion implementation. The function has these outcomes:

| Status | Meaning | Standard output |
|---|---|---|
| 0 | A matching, unexpired attestation exists. | `GOOD` or `VULNERABLE`, followed by a newline. |
| 1 | No attestation exists for `CODE`. | Empty. |
| 2 | Arguments are invalid, the review ID differs, the attestation expired, or the current UTC date cannot be established. | Empty; a diagnostic is written to standard error. |

Expiration is inclusive. An attestation whose `expires` value equals the current UTC date remains valid through that date.

After status 0, the function also populates the following scalar variables:

```text
POLICY_MATCH_REVIEW_ID
POLICY_MATCH_DECISION
POLICY_MATCH_TICKET
POLICY_MATCH_APPROVER
POLICY_MATCH_EXPIRES
```

The match variables are cleared at the start of every lookup. Callers must use them only after a status 0 result. Call `policy_lookup` directly when consuming these variables because command substitution executes the function in a subshell and cannot preserve variable assignments in the caller. `POLICY_MATCH_DECISION` provides the decision without command substitution; standard output remains available for stream-oriented callers.

A matching `review_id` proves that the attestation was issued for the review basis supplied by the caller; it does not authenticate the file. File provenance, distribution, and integrity controls remain deployment responsibilities.
