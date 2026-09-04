# Scan performance architecture

The scanner uses subsystem-aware snapshots rather than a suffix tree, full-text
index, or generic parser. Configuration precedence and native syntax remain part
of each resolver's contract.

## Scan epoch

`lib/kisa-cce-core/_scan-epoch.sh` defines one immutable scan epoch. The main process starts an
epoch after the protected scratch directory and platform context are available.
The epoch key includes the resolver schema, scanner version, platform profile,
policy digest, policy evaluation date, and evidence-bundle digest.

Snapshots memoize successful, absent, ambiguous, and error states. A transient
read error therefore remains an error for the epoch and cannot become `GOOD`
through a later cache lookup. A new epoch resets configuration and runtime
snapshots. Runtime systemd, listener, and sysctl sources are always dirty at an
epoch boundary.

The in-memory reverse dependency graph records:

```text
source -> resolver -> U-NN or final criterion result
```

A dirty source first invalidates its resolvers. Criterion propagation occurs
only after the resolver commits a changed normalized output. Identical output
clears resolver dirtiness without marking the criterion.

The current one-shot CLI does not retain dependency edges or normalized result
bodies for a second evaluation because it exposes no in-process rescan entry
point. The DAG and propagation engine are enabled by an in-process re-evaluator;
their behavior is covered by `tests/scan_epoch.sh` without adding dormant CPU
or memory cost to normal scans.

## Subsystem snapshots

### Layered files and sysctl

Layered directories are enumerated together. An associative set keeps the first
path for each basename according to directory priority, followed by one lexical
sort. This removes the previous `cut | grep` process pair for every candidate.

The sysctl resolver parses each selected file once per epoch. Exact directives
use an associative lookup map. Ordered glob directives and exclusions use a
NUL-framed scratch IR. Successful, absent, excluded, and failed key lookups are
memoized. Filesystem `sysctl.d`, the systemd loader stream, UFW, `sysctl.extra`,
and runtime kernel values remain separate namespaces and evidence sources.

### PAM

Each PAM source file is parsed once into a NUL-framed typed IR. The IR preserves
module records and distinct `include`, `substack`, and Debian `@include` edges.
Effective expansion is memoized by `(service, facility)`. Tri-color DFS detects
cycles, and cached subtree height preserves the existing depth limit.

PAM directory priority, Debian `common-*`, RHEL authselect inputs,
`/etc/pam.conf`, absolute rooted includes, and the `other` fallback retain their
existing error and fallback boundaries. Direct library calls outside an active
epoch remain uncached so fixture and diagnostic mutations are immediately
visible.

### systemd and listeners

The first live systemd request in an epoch attempts one typed bulk `systemctl
show` snapshot. `Id` and `Names` build an alias index. Units absent from the bulk
stream use one cached single-unit fallback, preserving `not-found` and command
error states. Facts include load, active, unit-file, fragment, drop-in, trigger,
invocation, environment, and credential properties needed by existing
resolvers. Bulk-query incompatibility falls back conservatively.

Listeners use one mixed `ss -H -lntup` snapshot for the epoch. TCP, UDP, and
mixed queries use an associative `transport:port` index built with that
snapshot, without recollection or repeated file scans. A failed collection is
also memoized. When procfs supplies the listener snapshot, its normalized rows
use the same indexed query contract.

The system-manager probe reads only PID 1's `comm` record and the systemd runtime
marker. It does not build the full process snapshot. Named-process queries use
the epoch process map first; `pgrep` is only a positive fallback when procfs is
unavailable or incomplete. A negative `pgrep` result cannot turn incomplete
procfs evidence into a conclusive absence. Evidence-bundle helpers remain
authoritative for offline bundle scans and never execute host runtime commands.

### Shell startup parsing and evidence paths

U-30 recognizes direct dot and `source` directives with Bash built-ins before
expanding the shell startup graph. It preserves the prior conditional,
unresolved-source, cycle, and depth-limit boundaries without starting one
`awk` process per input line. Each expanded file still has a separate
single-pass UMASK control-flow parser because shell startup syntax is not
interchangeable with PAM, sysctl, or another drop-in format.

Filesystem evidence paths are normalized with Bash built-ins after rooted path
resolution. Newline, carriage-return, and tab bytes retain the previous `?`
replacement, and non-printable bytes are discarded without starting `tr` for
each path.

## Cache boundaries

The current CLI has no daemon, watcher, persistent cache, or rescan option.
Snapshots exist only inside one process and its protected scratch directory.
The dependency graph provides the invalidation boundary for a future in-process
rescan interface without defining that interface now.

A future persistent cache cannot accept metadata-only hits. Its source identity
must include a content digest, mode, UID, GID, device, inode, size, mtime, ctime,
symlink target, and sorted directory entries. It must invalidate additions,
deletions, renames, masks, and new higher-priority files. Runtime facts must
never cross a process run. Full-filesystem checks must traverse again unless a
trusted change journal or immutable snapshot identifier proves equivalence.

## Deterministic tests

The cache tests assert parser and collector invocation counts instead of relying
on wall-clock thresholds:

- `tests/performance_cache.sh`: layered selection and sysctl snapshots;
- `tests/pam_cache.sh`: PAM IR, DFS, fallback, and status caching;
- `tests/runtime_cache.sh`: systemd, aliases, listeners, and runtime failures;
- `tests/scan_epoch.sh`: dependency invalidation and normalized-output change
  propagation;
- `tests/u30_comment_sources.sh`: direct, conditional, indirect, and commented
  shell source parsing without per-line external commands.

## Benchmark procedure

`tests/benchmark.sh` compares two source trees with the same generated fixture.
It interleaves baseline and optimized separate-process invocations for a cold
full scan, an unchanged repeated invocation, one configuration change, and one
runtime-evidence change. These measurements cover process startup and each
run's parse-once behavior; the deterministic cache tests cover in-process epoch
reuse and invalidation. Each scenario records wall time, CPU time, maximum RSS,
`execve` count, and exit status. The summary reports median and p95. `execve`
uses a separately controlled sample count because tracing changes wall time.
Every sample must produce both reports. The script compares every scenario's
JSONL byte-for-byte and Markdown after normalizing only generated timestamps
and the timestamp-derived evidence age.

The benchmark requires Linux development tools `strace` and GNU `time`; they
are not production dependencies.

```bash
BENCHMARK_OUTPUT_DIRECTORY=/tmp/kisa-cce-benchmark \
  PROCESS_ITERATIONS=2 \
  ./tests/benchmark.sh /path/to/baseline /path/to/optimized 20
```

## Measured result

The 2026-09-03 benchmark used a Debian bookworm aarch64 container. Wall, CPU,
and RSS have 10 interleaved samples per implementation and scenario. `execve`
has two separately traced samples. The generated offline fixture produced all
67 results and exit status `1`. All four scenario comparisons passed.

| Scenario | Wall median, baseline → optimized | CPU median, baseline → optimized | RSS median KiB, baseline → optimized | `execve` median, baseline → optimized |
|---|---:|---:|---:|---:|
| Cold | 3.375 → 3.340 | 3.140 → 3.115 | 14,496 → 15,904 | 911 → 850 |
| Unchanged invocation | 3.290 → 3.335 | 3.065 → 3.135 | 14,372 → 15,932 | 911 → 850 |
| Configuration change | 3.250 → 3.260 | 3.025 → 3.035 | 14,494 → 16,032 | 911.5 → 850.5 |
| Runtime evidence change | 2.585 → 2.570 | 2.525 → 2.500 | 14,500 → 15,904 | 1,136 → 1,075 |

The optimization removed 61 process executions per full scan: 6.7% for the
first three scenarios and 5.4% with an evidence bundle. On this small fixture,
cold wall median improved 1.0% and runtime-evidence median improved 0.6%; the
unchanged and configuration-change medians regressed 1.4% and 0.3%. Wall p95
improved in all four scenarios by 0.6–3.1%. RSS increased by about 1.4–1.6 MiB.
The measurements establish the external-process reduction and modest tail
latency improvement, but not a consistent median wall-time improvement. Larger
real PAM and systemd graphs need target-host measurement before stronger
end-to-end latency claims.

The complete median and p95 data is stored in
[`benchmarks/2026-09-03-aarch64.tsv`](benchmarks/2026-09-03-aarch64.tsv).

### 2026-09-04 live Ubuntu 26.04 acceptance

A second benchmark compared commit `3006285` with the working tree in the same
Apple container Ubuntu 26.04 VM. It used one warm-up and 20 interleaved live
full scans per implementation. The result set remained 27 `GOOD`, 13
`VULNERABLE`, 7 `MANUAL`, 20 `NOT_APPLICABLE`, and 0 `ERROR` in both trees.

| Metric | Baseline median / p95 | Optimized median / p95 | Median change |
|---|---:|---:|---:|
| Wall time, seconds | 2.984 / 3.194 | 2.811 / 2.997 | -5.8% |
| Shell and child CPU, seconds | 2.912 / 3.130 | 2.693 / 2.876 | -7.5% |
| `/proc/stat` process-creation delta | 3,444 / 3,446 | 2,845 / 2,845 | -17.4% |
| Scanner-process RSS, KiB | 11,962 / 11,976 | 12,100 / 12,112 | +1.2% |

Wall and CPU use Bash's reserved-word timer. The process counter includes fork
and clone events and is therefore a process-creation proxy, not an `execve`
count. RSS has 10 interleaved samples and measures the scanner process rather
than an aggregate child-process high-water mark. The image did not contain GNU
`time` or `strace`, and network access was unavailable, so those tools were not
installed for this run. Runtime call-count regressions separately establish
that the process-map and listener indexes remove 39 `pgrep` and 67 listener
filter `awk` invocations from the measured fixture.

The complete values are stored in
[`benchmarks/2026-09-04-ubuntu-26.04-live.tsv`](benchmarks/2026-09-04-ubuntu-26.04-live.tsv).
