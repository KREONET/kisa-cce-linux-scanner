# Runtime evidence bundle

An evidence bundle preserves a bounded snapshot of live Linux state for later use with an offline filesystem root. It is an owner-only directory, not an archive. The collector never creates or extracts `tar`, ZIP, or another container format.

The bundle records the state observed at `captured_at`. It does not establish the current state of a host after that time.

## Collection

Run the collector as root on the live system that will be imaged:

```bash
sudo install -d -m 0700 /var/lib/kisa-cce-evidence
sudo kisa-cce-collect \
  --output-dir /var/lib/kisa-cce-evidence/host-20260903T120000Z
```

The output path must be absolute. Its parent must already exist and must not contain a symbolic-link component. The collector creates the leaf directory with mode `0700`, or accepts an existing empty directory only when it is a real root-owned directory with mode `0700`. Existing content is never overwritten.

The public command clears the caller environment, fixes `PATH`, and applies umask `077` before loading collector code. The collector reads the live `/` filesystem and PID 1 mount namespace. It does not accept an alternate root.

The command prints one dmesg-framed machine-readable line after final integrity
checks. The `evidence_bundle` automation key remains unchanged in the payload:

```text
[    12.345678] kisa-cce-collect: evidence_bundle=/var/lib/kisa-cce-evidence/host-20260903T120000Z
```

An exit status of `0` means the directory and essential identity evidence were finalized. Optional runtime sources can still have the manifest state `partial` or `unavailable`. Exit status `2` means the directory must not be used as a complete bundle.

## Directory format

The current collector writes schema version 2. The scanner validator continues to accept existing schema version 1 bundles.

Schema version 2 has this fixed inventory:

```text
host-20260903T120000Z/
├── manifest.tsv
├── checksums.sha256
├── identity/
│   ├── os-release
│   ├── machine-id
│   ├── boot-id
│   └── kernel-release
└── runtime/
    ├── systemd-units.tsv
    ├── systemd-unit-files.tsv
    ├── listeners.tsv
    ├── mountinfo
    ├── firewall.txt
    └── time-sync.tsv
```

Schema version 1 uses the same layout except that `runtime/time-sync.txt` replaces `runtime/time-sync.tsv`. A bundle must contain exactly the time-sync artifact selected by its manifest schema; including both files is invalid.

The root and the two child directories use mode `0700`. Every regular file uses mode `0600` and has one hard link. Validation rejects symbolic links, unknown entries, missing entries, ownership changes, and looser permissions.

`manifest.tsv` is strict two-column TSV without a header. Keys are unique. Schema version 2 defines these identity fields:

```text
schema_version	2
captured_at	2026-09-03T12:00:00Z
machine_id	0123456789abcdef0123456789abcdef
boot_id	01234567-89ab-cdef-0123-456789abcdef
kernel_release	6.8.0-79-generic
```

The remaining manifest keys record `collected`, `partial`, or `unavailable` for each runtime artifact. Essential identity artifacts must be `collected`. `checksums.sha256` covers the manifest and every identity and runtime artifact. The checksum list does not cover itself.

## Collected data

| Artifact | Contents | Deliberate exclusion |
|---|---|---|
| `systemd-units.tsv` | Unit, load, active, substate, and unit-file state for service and socket units | Descriptions, environment, command lines, and unit file contents |
| `systemd-unit-files.tsv` | Service and socket enablement state and vendor preset | Unit file contents |
| `listeners.tsv` | TCP or UDP transport, local address, numeric port, and process name when available | PID, file descriptor, peer traffic, and command-line arguments |
| `mountinfo` | Raw `/proc/1/mountinfo` | File contents from mounted filesystems |
| `firewall.txt` | Effective nftables or iptables rules, with rule comments removed | Firewall counters and rule comments |
| `time-sync.tsv` | Normalized provider synchronization state and the selected source, address, stratum, leap state, origin, and source type | Raw native-client output, authentication keys, and daemon configuration files |

Schema version 2 `time-sync.tsv` uses this exact header:

```text
provider	synchronized	source	source_address	stratum	leap	source_origin	source_type
```

Each provider occurs at most once. The normalized fields use these values:

| Field | Values |
|---|---|
| `provider` | `systemd-timesyncd`, `chrony`, `ntpd-rs`, or `ntpsec` |
| `synchronized` | `yes`, `no`, or `unknown` |
| `source`, `source_address` | A bounded token without whitespace or control characters, or `-` when unavailable |
| `stratum` | `0` through `16`, or `-` when unavailable |
| `leap` | `normal`, `warning`, `unsynchronized`, or `unknown` |
| `source_origin` | `system`, `runtime`, `fallback`, `configured`, or `unknown` |
| `source_type` | `network`, `reference-clock`, or `unknown` |

`collected` requires at least one normalized provider row. `unavailable` requires a header-only table. `partial` can retain valid rows, but a criterion must not treat them as conclusive. The collector discards raw client output after normalization.

When `ntp-ctl` is installed, the collector runs `ntp-ctl status` and parses the
overall stratum and complete reported source set. Repeated addresses for one
pool name become one `provider=ntpd-rs` row; the address is `-` when the pool
resolved to multiple peers. More than one distinct source identity makes the
snapshot `partial` because schema version 2 cannot represent that set without
discarding policy-relevant peers. The raw status output is discarded.
Activation and persistence remain separate `ntpd-rs.service` facts in the
systemd tables. The upstream command interface is documented by the
[ntpd-rs project](https://github.com/pendulum-project/ntpd-rs).
During an offline U-65 scan, these runtime records are paired with the selected
root's `/etc/ntpd-rs/ntp.toml`; the configuration file itself is not copied into
the evidence bundle.

Ubuntu 26.04 uses Chrony by default; an ntpd-rs bundle row means the optional
provider was installed and observed, not that the distribution default changed.
See the [Ubuntu 26.04 Chrony note](https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/#chrony).

Schema version 1 retains the original bounded `time-sync.txt` artifact for compatibility. It is validated as a protected checksummed file, but it is not promoted to normalized facts because its native-client sections do not provide the strict v2 record contract.

Systemd unit names retain systemd's canonical `\xHH` escape sequences. The
validator accepts only complete hexadecimal escapes and continues to reject
literal whitespace, path separators, control characters, and malformed escape
sequences.

Collection is local. The collector does not refresh packages, contact an assessment server, probe listening services, or read authentication secrets. Network addresses, mount paths, unit names, and executable names remain sensitive infrastructure metadata. Store and transfer the directory as security assessment data.

## Validation and identity binding

The scanner-side library validates the complete fixed inventory, ownership, modes, hard-link count, strict manifest schema, SHA-256 list, file headers, and identity-file consistency before exposing any artifact path.

When an offline root is supplied, validation also requires:

- the bundle `machine_id` to equal the offline root `/etc/machine-id`;
- the captured `os-release` bytes to equal the safely resolved offline root `os-release` file.

`boot_id` and `kernel_release` preserve capture provenance. An offline filesystem has no current boot ID, and its installed modules do not conclusively prove which kernel was running at capture time.

A mismatch, altered checksum, unsupported schema, unsafe path, missing identity, or invalid permission is a bundle validation error. A valid bundle can still contain an unavailable runtime artifact. Checks that require that artifact must remain indeterminate instead of treating absence as a secure state.

## Library interface

Source `lib/kisa-cce-runtime/_evidence.sh` from the scanner process, then validate before reading global paths:

```bash
if ! validate_evidence_bundle "$EVIDENCE_BUNDLE_OPTION" "$SCAN_ROOT"; then
    die "$EVIDENCE_VALIDATION_ERROR"
fi
```

On success, the library sets `EVIDENCE_BUNDLE_DIRECTORY`, capture identity variables, artifact status variables, and absolute `EVIDENCE_*_PATH` variables. It does not extract archives or copy evidence into the scan root.

The state helpers use the scanner's existing return convention:

| Helper | `0` | `1` | `2` | `3` |
|---|---|---|---|---|
| `evidence_service_state UNIT...` | At least one unit is active | A recorded unit exists but none is active | Evidence is incomplete or invalid | No requested unit exists |
| `evidence_listener_state TRANSPORT PORT...` | At least one matching listener exists | No matching listener exists | Evidence is incomplete or arguments are invalid | Not used |
| `evidence_time_sync_facts` | Exactly one synchronized network source is established | One or more normalized providers are unsynchronized | Schema 1, unavailable, partial, malformed, unknown, or multiple synchronized providers | A selected local/reference-clock source requires review |

`TRANSPORT` is `tcp`, `udp`, or `any`. `evidence_mountinfo_path` prints the validated raw mountinfo path and returns `0`; it returns `2` when mount evidence was not collected.

`evidence_service_activation_state UNIT...` also treats `activating`, `reloading`, `enabled`, and `enabled-runtime` as an activation path. It returns `0` for an observed path, `1` when the complete evidence has no activation path, and `2` when the answer is indeterminate. `EVIDENCE_SERVICE_ACTIVATION_EVIDENCE` contains its bounded unit-state summary.

`evidence_listener_facts TRANSPORT PORT...` prints matching validated listener rows without the TSV header. `evidence_mount_roots` converts validated mountinfo into `target<TAB>filesystem_type` rows and rejects mount targets that cannot be represented safely as TSV.

`evidence_time_sync_facts` prints normalized `provider`, `synchronized`, `source`, `source_address`, `stratum`, `leap`, `source_origin`, and `source_type` facts. `evidence_time_sync_facts_into DESTINATION` provides the same facts through a caller-supplied variable without command substitution. Both helpers require a validated schema version 2 bundle whose time-sync status is `collected`. A normalized ntpd-rs row follows the same provider-selection and ambiguity rules as the other supported providers.

## Operational boundary

Capture the bundle immediately before creating a quiescent offline filesystem snapshot. Preserve both artifacts together. The directory is integrity-checked but not cryptographically signed, so SHA-256 detects changes only after a trusted capture and transfer process has established provenance. Package signature validation, trusted transport, freshness policy, and optional detached signatures remain deployment responsibilities.
