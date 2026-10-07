# Policy input format

## Purpose

Policy attestations record decisions made by authorized organizational
reviewers. Typed policy facts supply approved values for comparison with
collected technical evidence. Checks still require their own technical,
runtime, or external evidence.

An attestation applies only to a policy-class `MANUAL` result whose criterion
code and `review_id` match the current review basis and whose expiration date
has not passed. A typed fact applies only when its type-specific identity
matches the current observation and its expiration date has not passed.

The loader, `lib/kisa-cce-policy/_policy.sh`, requires Bash 4.3 or newer. It reads
policy files as data and never evaluates their contents as shell code.

The scanner uses policy schema version 1. The separate desired-state schema
version 2 used by
`kisa-cce-patch --automatic --desired-state FILE` is documented in
[Autopatcher coverage](https://github.com/KREONET/kisa-cce-linux-patcher/blob/main/docs/reference/autopatcher-coverage.md). The two formats are not
interchangeable.

## Directory contract

`policy_load_dir PATH` reads two namespaces:

- Files directly under `PATH` with names ending in `.tsv` contain final decision attestations. Bash expands these names in `LC_ALL=C` lexical order. Other entries at this level are not read as attestations.
- The optional `PATH/facts/time-sources.tsv` file contains approved time sources. If `facts` exists, it may contain only this file. The loader rejects unknown, hidden, or nested entries so that misspelled or unsupported fact files cannot be silently ignored.

A directory with no attestation files and no `facts/time-sources.tsv` is valid.
An empty `facts` directory is also valid. Both cases mean that no typed
time-source facts were supplied.

## Shipped default directory

The source tree provides `etc/kisa-cce-scanner/policy.d/00-default.tsv`. `make install` creates the following default configuration without replacing an existing file:

```text
/etc/kisa-cce-scanner/policy.d/00-default.tsv
```

Complete and automation modes use the installed directory when `--policy-dir`
is omitted. An explicit `--policy-dir` takes precedence. Runs from a source
checkout do not automatically use the repository copy: the scanner may run as
root while the checkout belongs to a non-root developer. If no directory is
specified and the installed directory is absent, the scanner rejects the
invocation because policy input is missing.

`00-default.tsv` contains only the attestation header and approves no criterion
result. Installation leaves `facts/time-sources.tsv` absent. A header-only
time-source file would create an explicit empty allowlist and change the U-65
assessment. Administrators must supply organizational decisions; the default
file cannot resolve incomplete evidence to `GOOD`.

The installed directory uses mode `0700`, and the file uses mode `0600`. Distribution packages should preserve administrator changes by treating this path as a configuration file, using the native conffile or no-replace mechanism.

## YAML authoring and compilation

Use `kisa-cce-policy-compile` to convert the supported YAML subset into a new
TSV policy directory. Policies can be written in YAML, but `kisa-cce-scan`
reads only the TSV schemas described below.

```bash
sudo install -m 0600 ./policy.yml /etc/kisa-cce-scanner/policy.yml
sudo kisa-cce-policy-compile \
  --input /etc/kisa-cce-scanner/policy.yml \
  --output-dir /etc/kisa-cce-scanner/policy-20260904
```

The output directory must not exist. The compiler stages files under the
target's trusted parent directory, validates them with `policy_load_dir`, and
renames the staging directory into place without replacing an existing path.
It writes `50-compiled.tsv` and adds `facts/time-sources.tsv` only if the YAML
contains `time_sources`. Directories use mode `0700`; files use mode `0600`.

Example with attestations and approved time sources:

```yaml
schema_version: 1
attestations:
  - code: U-07
    decision: GOOD
    review_id: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    ticket: IAM-2026-0142
    approver: identity-governance
    expires: 2026-12-31
time_sources:
  - provider: chrony
    host: time1.example.net
    address: 192.0.2.10
    ticket: TIME-2026-001
    approver: time-owners
    expires: 2026-12-31
  - provider: ntpd-rs
    host: rust-time.example.net
    address: 192.0.2.40
    ticket: TIME-2026-002
    approver: time-owners
    expires: 2026-12-31
```

`schema_version: 1` is the policy YAML grammar version and must precede the
policy sections. It is independent from review-basis schema version 2 described
below. `attestations` is required and may be `[]`. `time_sources` is optional;
omission means no typed fact set, while `time_sources: []` deliberately creates
an explicit empty allowlist. Mapping field order is unrestricted, but every
required field must occur exactly once.

The parser accepts blank lines, full-line comments, block lists, plain scalars, and restricted single- or double-quoted scalars. List markers use exactly two spaces; continuation fields use exactly four. Double quotes support only `\"` and `\\`; single quotes use `''` for one literal quote. Ambiguous plain scalars must be quoted.

It rejects ASCII and Unicode C1 control characters, malformed UTF-8, tabs, carriage returns, anchors, aliases, tags, merge keys, flow collections, block scalars, multiple documents, unknown keys, duplicate keys, invalid indentation, and inline comments in plain scalars. The input is never sourced or evaluated. The existing policy loader performs the final criterion, review ID, date, provider, address, duplicate, and digest validation.

[`examples/policy.yml`](../../examples/policy.yml) provides a template with no approvals.

The policy directory, the optional `facts` directory, and every consumed file must meet all of these requirements:

- The path itself is not a symbolic link.
- The directory is readable and searchable.
- Each policy file is a readable regular file.
- The owner is UID 0 or the scanner's effective UID.
- Group and other write bits are clear.

The loader rejects a matching symbolic link instead of following it. When loaded by the scanner, every existing path component must also pass the scanner's trusted-parent checks.

## Review basis schema

New review IDs use `review_schema:2`. The hash input includes the
scanner version, detected platform and base platform, evidence-bundle identity,
criterion metadata, applicability, `resolution_class`, complete normalized
summary, and complete redacted evidence. Adding `resolution_class` prevents an
approval for an organization-policy question from being reused for a
technically or operationally incomplete result with otherwise similar text.

Review schema 1 IDs do not match schema 2. Regenerate attestations from a
current audit after upgrading. `review_schema` is an internal marker in the
canonical hash input; it is not a separate JSONL field. JSONL exposes the
resulting `review_id` and `resolution_class`.

Attestation lookup is allowed only for `resolution_class=policy`.
`technical`, `runtime`, and `external` manual results become `ERROR` in complete
and automation modes regardless of whether an old or manually constructed
attestation exists.

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
| `review_id` | `sha256:` followed by exactly 64 lowercase hexadecimal characters, generated from review-basis schema 2. |
| `ticket` | A non-empty change, exception, or approval record identifier. |
| `approver` | A non-empty identifier for the approving authority. |
| `expires` | A real Gregorian calendar date in `YYYY-MM-DD` form. |

Blank lines, comments, extra columns, missing columns, carriage returns, and other control characters are invalid. UTF-8 text and spaces are allowed in `ticket` and `approver`, but tabs and line breaks are not.

Example, where the field separators are literal tabs:

```text
code	decision	review_id	ticket	approver	expires
U-07	GOOD	sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef	IAM-2026-0142	identity-governance	2026-12-31
```

## Merge and failure behavior

Files do not override one another. A criterion code may occur only once across the complete directory. A duplicate code, malformed file, untrusted path, or unreadable metadata makes `policy_load_dir` return status 2.

The loader clears its exported arrays before validation. They remain empty
if any input fails validation. On success, the loader populates these
associative arrays, keyed by criterion code:

```text
POLICY_DECISION
POLICY_REVIEW_ID
POLICY_TICKET
POLICY_APPROVER
POLICY_EXPIRES
```

`policy_load_dir` returns 0 after a successful load, including an empty directory.

## Lookup contract

Call `policy_lookup CODE REVIEW_ID` with the review ID calculated by the
current criterion implementation:

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

Each lookup clears the match variables. Read them only after a status 0 result.
Call `policy_lookup` directly if these values are needed in the calling shell:
command substitution runs the function in a subshell and loses its variable
assignments. Read the decision from `POLICY_MATCH_DECISION` or use standard
output when only the printed value is needed.

A matching `review_id` proves that the attestation was issued for the review basis supplied by the caller; it does not authenticate the file. File provenance, distribution, and integrity controls remain deployment responsibilities.

In complete mode, a missing policy-class attestation is an error. In automation
mode, a missing attestation makes that result `VULNERABLE` with
`decision_basis=fail_closed_policy`; the result remains
`remediation_eligible=false`. Invalid, expired, or mismatched attestations are
errors in both modes.

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
| `provider` | `chrony`, `ntpd-rs`, `ntpsec`, or `systemd-timesyncd`. |
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
ntpd-rs	rust-time.example.net	192.0.2.40	TIME-2026-002	time-owners	2026-12-31
systemd-timesyncd	time2.example.net	-	TIME-2026-003	security-governance	2026-12-31
```

The ntpd-rs provider name limits the source approval to a selected ntpd-rs
installation. It does not change Ubuntu 26.04's default time daemon. The scanner also requires
`/etc/ntpd-rs/ntp.toml`, `ntpd-rs.service` persistence, and normalized
`ntp-ctl status` evidence. See the
[Resolute package](https://packages.ubuntu.com/resolute/ntpd-rs) and
[ntpd-rs upstream](https://github.com/pendulum-project/ntpd-rs).

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

`POLICY_SET_DIGEST` includes typed facts. If `time-sources.tsv` exists, the
digest input contains its schema marker and canonical records sorted by
provider, normalized host, and normalized address. Reordering valid rows does
not change the digest. A header-only file and an absent file produce different
digests.

When no typed fact file exists, the digest input for final attestations is unchanged from the original attestation-only format. Expired facts remain part of the digest because the digest identifies the loaded policy content; expiration is enforced during lookup.

A malformed, duplicate, unsupported, or unsafe typed fact invalidates the
entire load. Both attestation and typed-fact globals are cleared, and
`POLICY_SET_DIGEST` remains empty.
