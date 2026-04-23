# cpctl Refactor — Design Notes

Working notes for the `refactor-cpctl-cli` branch. Captures the audit of the
current `cpctl` CLI, why it is hostile to AI/tool consumption, and the
proposed redesign.

---

## 1. Current State

### Command tree

`cpctl` is built with [cobra](https://github.com/spf13/cobra). The entire
tree today is:

| Command | File | Flags |
|---|---|---|
| `cpctl version` | `cpctl/cmd/version.go:16` | none |
| `cpctl worker` | `cpctl/cmd/worker/worker.go:7` | none — parent only, no `Run` |
| `cpctl worker stats` | `cpctl/cmd/worker/stats.go:24` | `--unix` (required) |

Total: **3 commands, 2 functional**. `worker` is a grouping node with no
behavior of its own.

### Backend RPC surface

`cpworker/src/main.c:145` registers exactly one RPC:

```c
unix_manager_register_command("collect_stats_summary",
                              task_manager_collect_stats_summary_command, NULL);
```

The wire protocol in `cpgolib/cpworker/unix_client.go:119` (`RunCommand`) is
generic JSON-in / JSON-out, but the C side only answers
`collect_stats_summary`.

### How `stats` actually works

`cpctl/cmd/worker/stats.go:24`:

```go
var statsCmd = &cobra.Command{
    Use:   "stats",
    Short: "Show worker stats",
    RunE: func(cmd *cobra.Command, args []string) error {
        client, err := cpworker.NewClient(statsCfg.control)
        // ...
        tm := time.NewTimer(0)
        var lastStats *cpworker.StatsSummary
        for {
            select {
            case <-ctx.Done():
                return nil
            case <-tm.C:
                stats, err := client.CollectStatsSummary(cmd.Context())
                if lastStats != nil {
                    printSummaryStats(stats, *lastStats)   // diff vs previous
                }
                lastStats = &stats
                tm.Reset(2 * time.Second)
            }
        }
    },
}
```

Flow:

1. Dial unix socket at `--unix` (e.g. `/var/run/cloud-probe/cpworker.sock`).
2. Handshake — send `{"version":"v1"}`, expect `{"status":"OK"}` (`unix_client.go:77`).
3. Tick every 2s — send `{"command":"collect_stats_summary"}` over the same
   persistent connection.
4. Diff the new snapshot against the previous one and print rates.
5. Repeat forever until SIGINT/SIGTERM/SIGHUP cancels the context (`base.go:50`).

Notes:

- **Polling-as-streaming, not push streaming.** cpworker is request/response.
  Cadence and rate-calc live entirely on the client side.
- **Connection is reused across ticks.** `UnixClient.RunCommand` only dials
  once.
- **The "diff" is the actual feature.** A single `collect_stats_summary`
  returns cumulative counters; rates exist only because the client subtracts
  `lastStats` and divides by elapsed seconds. The first tick prints nothing.
- **The wire protocol is generic, the surface is narrow.** Adding a new
  command is a C-side `unix_manager_register_command` + a thin Go wrapper.

---

## 2. Why this is hostile to AI / tool usage

1. **Output is human-formatted.** `printSummaryStats` writes a left-padded
   table with strings like `"1.2 GB; (45.3 MB / s)"`.
2. **Stats blocks forever.** No `--once`, no `--count N`. LLM tool-call
   wrappers time out.
3. **Errors aren't typed.** `Execute()` (`base.go:39`) prints `slog.Error(...)`
   and `os.Exit(1)`.
4. **No discovery / no machine-readable schema.**
5. **Single-command coverage.** Only `stats`. No liveness check, no info, no
   way to discover which config file is loaded.

---

## 3. Confirmed Decisions

- ✅ **Drop the `worker` subcommand layer.** cpctl targets cpworker only.
  cpdaemon already has its own CLI (`cpdaemon server`) over HTTP and is
  protocol-disjoint from cpworker; trying to unify them in one CLI would
  force two unrelated client stacks. If a daemon-control CLI is ever needed,
  build `cpdctl` as a sibling.
- ✅ **`--count`**, default `0` (no limit).
- ✅ **`--format text|jsonl`**, default `text`. `ndjson` is accepted as an
  alias for `jsonl` (same wire format; see section 5.2).
- ✅ **No `--target` flag** — rely on shell redirection (`>`, `2>`, `tee`).
  See section 5.1.
- ✅ **`ping` uses a real C-side RPC** (option (a) below).
- ✅ **`cpctl completion`** — cobra builtin, free.
- ✅ **Minimize changes to cpworker.** Per-task stats stay removed (cloud
  volume reasons; cpm doesn't need them). The only new C-side RPC is `ping`
  + an `info` RPC that returns the loaded config path and a few cheap
  process facts.
- ⏸ **`cpctl reload`** — TBD, separate task.
- ❌ **No `cpctl tasks` / `cpctl task <id>`** — per-task metrics were
  deliberately removed; do not resurrect.
- ❌ **No `cpctl tail-logs`** — cpworker logs to stderr and does not manage
  its own log file (no `log_file` config; `main.c:49` only takes `-c
  config`). Tail logs via the service manager (`journalctl -u cpworker`,
  Docker `logs`, etc.). cpctl will surface "where logs go" in `info` if
  there's anything to surface.

---

## 4. Global Flags — Unix conventions

| Flag | Short | Purpose | Notes |
|---|---|---|---|
| `--unix` | `-u` | unix socket path | raw path, no `unix://` prefix |
| `--count` | `-n` | sample count, 0 = forever | matches `top -n`, `head -n` |
| `--interval` | `-i` | poll interval | matches `ping -i` |
| `--format` | `-f` | `text\|jsonl` | default `text` |
| `--timeout` | `-W` | per-RPC timeout | matches `ping -W` |
| `--quiet` | `-q` | (ping only) suppress per-tick output, only summary | matches `ping -q` |

### Why `-n` for count, not `-c`

The two precedents split:

- `ping -c COUNT` — count of pings.
- `top -n NUMBER` / `head -n NUMBER` / `tail -n NUMBER` — iteration/line count.

cpctl's primary streaming command is `stats`, which is closer to `top`
(iterative dashboard) than to `ping`. Using `-n` matches that mental model,
keeps `-c` free for a future `--config` flag if cpctl ever grows one, and
avoids any short-flag confusion with cpworker's own `-c <config>`
(`cpworker/src/main.c:49`).

Cost: small break from `ping -c` muscle memory. Users who reflexively type
`-c` get an error and switch to `-n` or `--count`. We do **not** add `-c`
as an alias — keeping the short flag space clean is worth more than one
keystroke of compatibility.

(`watch -n SECONDS` uses `-n` for interval, not count — the opposite
meaning. Acceptable collision: `watch` is a wrapper that runs other
commands, so users aren't composing `watch` with `cpctl` in a way that
mixes the two `-n` meanings.)

---

## 5. Format and Output Destination

### 5.1 Why no `--target`

Initial design had `--target stdout|stderr|<path>`. Dropped after
reconsideration: shell redirection already does this without baking I/O
plumbing into the tool.

```sh
cpctl stats -f jsonl > probe-stats.jsonl       # to file (truncate)
cpctl stats -f jsonl >> probe-stats.jsonl      # to file (append)
cpctl stats -f jsonl 2> /dev/null              # silence stderr noise
cpctl stats -f jsonl | jq .                    # pipe live to jq
cpctl stats -f jsonl | tee probe.jsonl | jq .  # tee + display
```

This is the Unix way. The only thing the tool must do to make redirection
work for a streaming command is **flush stdout after every record** — without
that, `cpctl stats -f jsonl > file.jsonl` interrupted with Ctrl-C loses the
buffer.

### 5.2 jsonl vs ndjson — same format, pick one name

The two specs (jsonlines.org and ndjson.org) describe the same thing:

- One complete JSON value per line.
- Lines separated by `\n` (LF).
- No enclosing `[...]`, no trailing commas.
- UTF-8 encoded.

Differences are pedantic-only (e.g. ndjson explicitly forbids BOM; jsonl is
silent). In practice **`jsonl` is more recognized** — pandas
(`read_json(lines=True)`), jq (`-c` produces jsonl by default), OpenAI
fine-tuning files, and most log-aggregation tools default to `.jsonl`.

**Both names are accepted.** `--format jsonl` and `--format ndjson` produce
identical output. Implementation: normalize at flag-parse time so downstream
code only sees the canonical `jsonl`:

```go
// in PreRunE, after flag parsing:
switch strings.ToLower(globalCfg.format) {
case "jsonl", "ndjson":
    globalCfg.format = "jsonl"
case "text":
    // canonical
default:
    return fmt.Errorf("invalid --format %q (text|jsonl)", globalCfg.format)
}
```

Help text lists `text|jsonl` as the canonical choices and mentions
`ndjson` as an alias in the longer description, so users from either camp
can use the name they expect without bloating the visible flag surface.

### 5.3 Streaming-friendly behavior

For any command emitting `jsonl`:

- Each tick = one complete JSON object on one line, with its own `ts` field.
- `Stdout.Sync()` (or `bufio.Writer.Flush()`) after every line.
- Errors during a stream go to **stderr** as a single jsonl line:
  `{"level":"error","ts":"...","msg":"...","err":"..."}`.

---

## 6. Proposed Command Set

```
cpctl ping           # liveness + RTT, ping-style UX
cpctl stats          # counter stream (current behavior, made one-shot capable)
cpctl info           # config_path, version, pid, uptime, log_destination
cpctl config         # convenience: dump the loaded config file (reads file from info's config_path)
cpctl version        # cpctl's own version
cpctl completion     # cobra builtin
```

### 6.1 ping

Confirmed: **add a real C-side `ping` RPC.** ~15 lines of C in
`cpworker/src/`:

```c
static int unix_ping_command(cJSON *args, cJSON *resp, void *data) {
    cJSON_AddStringToObject(resp, "status", "OK");
    cJSON_AddNumberToObject(resp, "ts_ms", current_time_ms());
    return 0;
}
// in main.c, alongside collect_stats_summary registration:
unix_manager_register_command("ping", unix_ping_command, NULL);
```

UX mirrors `ping(8)`:

```
PING cpworker (unix:///var/run/cloud-probe/cpworker.sock)
seq=0 time=0.42 ms
seq=1 time=0.31 ms
^C
--- cpworker ping statistics ---
2 transmitted, 2 received, 0% loss
rtt min/avg/max/stddev = 0.31/0.36/0.42/0.06 ms
```

In `jsonl` mode, each line is `{"seq":N,"ts":"...","rtt_ms":X.XX}`, summary
becomes a single trailing object `{"summary":{"sent":N,"received":M,...}}`.

### 6.2 stats

Top-level (no `worker` parent). Same flag conventions as `ping`.

`-n 1` behavior: **raw cumulative counters when `-n == 1`, diffs/rates
when `-n >= 2`** (option (c), confirmed). Fast for the common AI use case
("give me current totals" — a single RPC, no waiting); rates emerge
naturally as soon as the caller asks for two or more samples.

Considered and rejected:

- **(a) Raw counters always.** Loses the rate display that makes the
  current `stats` useful for humans.
- **(b) Force one extra tick so even `-n 1` returns a rate.** Slow — every
  one-shot call would block for one `--interval`. AI tool-calls would
  feel sluggish for no good reason.

Implementation note: in `text` mode with `-n 1`, print just the raw
counters table (no `-------` separator, no "per second" suffix). In
`jsonl` mode with `-n 1`, emit one object with the counters and a
`"rates": null` field so consumers can detect that no rate is available
yet.

### 6.3 info

Minimum useful set, all derivable from data cpworker already has:

```json
{
  "version": "0.9.x-...",
  "pid": 12345,
  "uptime_sec": 3601,
  "config_path": "/etc/cloud-probe/cpworker.json",
  "log_destination": "stderr",
  "started_at": "2026-04-21T08:12:00Z"
}
```

C-side cost is trivial:

- `config_path` — already stored at `cpworker/src/main.c:20` (`static const
  char *config_file`).
- `pid` — `getpid()`.
- `uptime_sec` — store `time(NULL)` at startup, subtract on request.
- `version` — already a build-time constant.
- `log_destination` — literal `"stderr"` for now (no log_file config exists).
- `started_at` — derived from the startup timestamp.

One new RPC: `unix_manager_register_command("info", ...)`.
**No per-task fields** — that road is closed by the team's earlier decision.

### 6.4 config

Convenience wrapper, **no new C-side RPC needed**:

1. Call `info` to get `config_path`.
2. Read and dump the file from disk.

In `text` mode just stream the raw file. In `jsonl` mode emit a single line:
`{"path":"...","content":<parsed-json>}`.

This sidesteps the need for cpworker to ever serve config content over the
wire — fits "minimize cpworker changes."

### 6.5 reload — TBD

Out of scope for this refactor. Will need a C-side RPC plus careful
task-restart logic. Tracked as a separate task.

---

## 7. Things considered and dropped

### 7.1 `cpctl raw <cmd> [--args '<json>']`

Earlier proposal was a thin escape hatch over the existing generic
`RunCommand`. Use cases that motivated it:

- **U1 — Developer iteration.** Test new C-side RPCs without touching cpctl
  during cpworker development.
- **U2 — Forward compatibility for AI agents.** Let agents call new RPCs
  before cpctl ships wrappers for them.
- **U3 — Debugging the RPC layer itself.** Inject malformed/edge-case
  payloads to test cpworker's parser.

Reality check against the current scope:

- After this refactor, the C-side RPC list is `{collect_stats_summary, ping,
  info}` — **three commands**. They are stable, all wrapped, and the team
  wants to **minimize cpworker changes**.
- U1 is satisfied by `socat` or a 10-line Python script during dev.
- U2 doesn't matter if the RPC list isn't growing.
- U3 is a developer tool, not a user tool.

**Dropped from v1.** Trivial to add later (~30 lines) if the RPC count
grows.

### 7.2 `cpctl tasks` / `cpctl task <id>`

Dropped — per-task stats were deliberately removed from cpworker for cloud
volume reasons, and cpm doesn't consume them. Re-introducing the CLI surface
would push back toward re-adding the tracking on the cpworker side.

### 7.3 `cpctl tail-logs`

Dropped — cpworker has no log-file management (`main.c:49` only knows about
`-c <config>`; no `log_file` field in the schema). Logs go to stderr; the
service manager handles aggregation. `cpctl info` will surface
`log_destination: "stderr"` so callers know not to look elsewhere.

---

## 8. AI-friendliness rationale

- **`--format jsonl` rewards stream-by-default thinking.** Each tick is a
  complete, self-contained JSON object. Stream consumers don't have to wait
  for a stream to end (it never does in `--count 0` mode).
- **`-n 1` makes streaming commands one-shot capable.** With
  `-n 1 -f jsonl`, every streaming command also serves as a single-RPC tool
  call — perfect for LLM tool-use wrappers.
- **`-n` (count) follows `top -n` / `head -n`. `-i` (interval) follows
  `ping -i`.** No single tool uses both letters with these meanings —
  `top` uses `-d` (delay) for interval, `ping` uses `-c` for count — so we
  borrow each from the closer analog: `top` for iterative dashboards,
  `ping` for latency. `cpctl stats -n 5 -i 0.5` reads cleanly under either
  mental model.
- **`info` is the discovery anchor.** An agent calling `cpctl info -f jsonl`
  gets enough to bootstrap: which config is loaded, where logs go, how long
  the process has been up.

---

## 9. Open Decisions

None — all design forks resolved.

| ID | Decision | Resolution |
|---|---|---|
| D1 | ping protocol | real C-side `ping` RPC (section 6.1) |
| D2 | `info` content | minimum set (section 6.3) |
| D3 | default `--format` | `text` |
| D4 | `raw` command | dropped (section 7.1) |
| D-stats-1 | `-n 1` behavior | option (c) — raw counters at `-n==1`, diffs at `-n>=2` |
| D-target | `--target` flag | dropped, use shell redirection (section 5.1) |
| D-format-alias | accept `ndjson`? | yes, alias for `jsonl` (section 5.2) |
| D-count-short | short flag for count | `-n` (section 4) |

Refactor is ready to scaffold.

---

## 10. cpworker changes summary

The smallest possible surface that supports this refactor:

| Change | File | Size | Purpose |
|---|---|---|---|
| Register `ping` RPC | `cpworker/src/main.c` (+ small new file or inline) | ~15 LOC | enables `cpctl ping` |
| Register `info` RPC | `cpworker/src/main.c` (+ small new file or inline) | ~30 LOC | enables `cpctl info` and (transitively) `cpctl config` |
| Capture startup timestamp | `cpworker/src/main.c` | 1 LOC | needed by `info.uptime_sec` |

That's it. No changes to capturer, output, task, or stats subsystems.
