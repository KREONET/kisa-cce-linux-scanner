# Policy input format

## Purpose

Policy attestations record decisions that require an authorized organizational review. Typed policy facts record approved values that a criterion can compare with collected technical evidence. Neither form replaces the technical evidence collected by a criterion check.

An attestation applies only when its criterion code and `review_id` match the current review basis and its expiration date has not passed. A typed fact applies only when its type-specific identity matches the current observation and its expiration date has not passed.

The loader is implemented as a Bash 4.3 or newer source module in `lib/policy.sh`. It parses policy files as data and never evaluates their contents as shell code.

## Directory contract

`policy_load_dir PATH` reads two namespaces:

- Direct children of `PATH` whose names end in `.tsv` contain final decision attestations. Bash expands these names in `LC_ALL=C` lexical order. Other direct children at this level are not attestation inputs.
- The optional `PATH/facts/time-sources.tsv` file contains approved time-source facts. When `facts` exists, it may contain only this file. Unknown, hidden, or nested entries are rejected so that a misspelled or unsupported fact file is not silently ignored.

A directory with no matching attestation files and no `facts/time-sources.tsv` file is valid. An existing `facts` directory without the time-source file is also valid and means that no typed time-source fact set was supplied.

The policy directory, the optional `facts` directory, and every consumed file must meet all of these requirements:

- The path itself is not a symbolic link.
- The directory is readable and searchable.
- Each policy file is a readable regular file.
- The owner is UID 0 or the scanner's effective UID.
- Group and other write bits are clear.

The loader rejects a matching symbolic link instead of following it. When loaded by the scanner, every existing path component must also pass the scanner's trusted-parent checks.

## Final attestation TSV grammar

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

## Approved time-source facts

### File and schema

Approved time sources are stored only in:

```text
PATH/facts/time-sources.tsv
```

The file starts with this exact header, using literal tab characters:

```text
provider	host	address	ticket	approver	expires
```

Each subsequent row contains exactly six fields:

| Field | Required value |
|---|---|
| `provider` | `chrony`, `ntpsec`, or `systemd-timesyncd`. |
| `host` | An ASCII DNS-style source name, or `-` when approval is bound only to an address. Names are limited to 253 characters, normalized to lowercase, and normalized without one final root dot. Labels are limited to 63 characters. Wildcards are not accepted. |
| `address` | An IPv4 or IPv6 address, or `-` when approval is bound only to a host. IPv4 octets are normalized to decimal without leading zeroes. IPv6 hexadecimal digits are normalized to lowercase; compressed and uncompressed forms remain textually distinct. IPv4-embedded IPv6 spelling is not accepted. |
| `ticket` | A non-empty approval or change record identifier of at most 128 characters. |
| `approver` | A non-empty approving-authority identifier of at most 128 characters. |
| `expires` | A real Gregorian date in `YYYY-MM-DD` form. |

At least one of `host` and `address` must be present. A row with both values binds approval to that exact host and address pair. Duplicate provider, normalized-host, and normalized-address triples are invalid. A header-only file is a valid explicit empty fact set; it differs from an absent file during lookup and digest calculation.

Example:

```text
provider	host	address	ticket	approver	expires
chrony	time1.example.net	192.0.2.10	TIME-2026-001	security-governance	2026-12-31
systemd-timesyncd	time2.example.net	-	TIME-2026-002	security-governance	2026-12-31
```

The separators in the actual file are literal tabs. Blank lines, comments, carriage returns, extra columns, missing columns, control characters, and an empty file are invalid.

### Query contract

Call the function directly so that its result globals remain in the current shell:

```bash
policy_time_source_match PROVIDER HOST ADDRESS
```

Use `-` or an empty argument for an unavailable host or address. At least one identity argument must be present. The function performs no DNS query and does not infer equivalence between different IPv6 spellings.

| Status | Meaning |
|---:|---|
| `0` | One unexpired approved fact matched. |
| `1` | A time-source fact set was supplied, but no fact matched. |
| `2` | The query was invalid, equally specific facts were ambiguous, the matching fact expired, or the current UTC date could not be established safely. |
| `3` | `facts/time-sources.tsv` was absent. |

A row that supplies both host and address is more specific than a row that supplies only one. If multiple matching rows have the same highest specificity, lookup returns status `2` rather than selecting approval metadata arbitrarily.

Every call clears and then populates these scalar globals:

```text
POLICY_TIME_SOURCE_MATCH_STATE
POLICY_TIME_SOURCE_MATCH_REASON
POLICY_TIME_SOURCE_MATCH_PROVIDER
POLICY_TIME_SOURCE_MATCH_HOST
POLICY_TIME_SOURCE_MATCH_ADDRESS
POLICY_TIME_SOURCE_MATCH_TICKET
POLICY_TIME_SOURCE_MATCH_APPROVER
POLICY_TIME_SOURCE_MATCH_EXPIRES
POLICY_TIME_SOURCE_MATCH_EVIDENCE
```

`POLICY_TIME_SOURCE_MATCH_STATE` is `approved`, `not_approved`, `error`, or `absent`. The evidence value contains only bounded normalized identity, state, applicable error reason, and expiration fields; ticket and approver remain available through their dedicated globals.

After a successful load, `POLICY_TIME_SOURCE_FACTS_PRESENT` distinguishes an explicit fact set from absence, and `POLICY_TIME_SOURCE_COUNT` contains the number of approved rows.

### Digest and failure behavior

Typed facts participate in `POLICY_SET_DIGEST`. The digest input includes a schema marker for an existing `time-sources.tsv` file and canonical records sorted by provider, normalized host, and normalized address. Reordering valid rows therefore does not change the digest. An explicit header-only file and an absent file produce different digests.

When no typed fact file exists, the digest input for final attestations is unchanged from the original attestation-only format. Expired facts remain part of the digest because the digest identifies the loaded policy content; expiration is enforced during lookup.

Loading remains atomic. A malformed, duplicate, unsupported, or unsafe typed fact clears both attestation and typed-fact globals and leaves `POLICY_SET_DIGEST` empty.
