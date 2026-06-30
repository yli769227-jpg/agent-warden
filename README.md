# agent-warden 🛡️

> A local MCP audit proxy that logs every tool call, enforces allow/deny policies, rate-limits runaway agents, and gives you a kill switch — before the agent does something you can't undo.

[![CI](https://github.com/yli769227-jpg/agent-warden/actions/workflows/ci.yml/badge.svg)](https://github.com/yli769227-jpg/agent-warden/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/agent-warden)](https://www.npmjs.com/package/agent-warden)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP compatible](https://img.shields.io/badge/MCP-compatible-blue)](https://modelcontextprotocol.io)

---

## The Problem

MCP changed what AI agents can do. In 2026, a single `claude --mcp-server filesystem` gives Claude Code read/write access to your entire home directory. Add a GitHub MCP server and it can push code. Add a shell server and it can run arbitrary commands.

Once you say "go," you have no intercept layer. The agent talks directly to the MCP server. Nothing in between.

Enterprise teams have answered this with cloud-hosted MCP gateways — paid, SaaS, requiring you to route all tool calls through their infrastructure. That's the wrong tradeoff for most developers: you're adding an external dependency to solve a local security problem.

agent-warden is the local answer.

---

## What agent-warden does

Warden sits as a transparent proxy in the stdio chain between your MCP client (Claude Code, Claude Desktop, or any MCP-compatible tool) and your MCP servers. Every tool call passes through Warden first.

**Audit logging** — Every tool invocation is written to a JSONL audit log: tool name, full arguments, verdict, duration, and timestamp. The log is append-only. Secrets are scrubbed before writing.

**Policy engine** — Define allow/deny rules by tool name with glob support. `filesystem/write_*` can be blocked entirely. Rules are evaluated in order; first match wins.

**Dangerous tool auto-detection** — Warden ships with a built-in list of patterns that warrant extra caution: shell execution, file deletion, truncate, purge. These are flagged in the audit log automatically.

**Secret scrubbing** — Before any log line is written, Warden scrubs argument payloads. AWS keys, GitHub tokens, SSH private keys, Bearer tokens, and high-entropy strings are replaced with `[REDACTED]`. The downstream server still receives the original payload — scrubbing is log-side only.

**Rate limiting** — Per-tool call rate limits with token-bucket semantics. Protect against runaway agents that call the same tool dozens of times per minute without blocking legitimate use.

**Webhook alerts** — Push HTTP(S) notifications to Slack, PagerDuty, or any endpoint when Warden blocks or kills a call. Know what your agent did even when you're not watching.

**Kill switch** — One command pauses all tool call forwarding instantly. No restart required.

---

## Architecture

```
Claude Code ──stdio──▶ agent-warden ──stdio──▶ filesystem MCP server
                              │
                         audit.jsonl
                       (secrets scrubbed)
```

Warden implements the MCP protocol on both sides. To your MCP client it looks like an MCP server. To your downstream MCP servers it looks like an MCP client.

Multiple downstream servers are supported. Warden fans out to each server defined in config and merges their tool namespaces, prefixed by server name:

```
Claude Code ──stdio──▶ agent-warden ──stdio──▶ filesystem MCP server
                              │       ──stdio──▶ github MCP server
                              │       ──stdio──▶ shell MCP server
                              │
                         audit.jsonl
                       (webhook alerts)
```

**Request evaluation order (each tool call):**

```
1. Kill switch active? ──yes──▶ deny (verdict: "killed")
2. Rate limit exceeded? ─yes──▶ deny (verdict: "deny")
3. Policy rule match? ───yes──▶ enforce/log
4. Dangerous pattern? ───yes──▶ flag (enforce mode: deny)
5. Default action ────────────▶ allow or deny
6. Forward to downstream server
```

---

## Quick Start

**30-second setup with auto-install:**

```bash
# Install globally
npm install -g agent-warden

# Auto-detect your existing MCP servers and inject warden in front of them
warden install

# Restart Claude Desktop or Claude Code
# That's it — all tool calls are now audited
```

`warden install` reads your Claude Desktop / Claude Code config, generates a per-server `warden.config.yaml`, and replaces each MCP server entry with a warden proxy. Fully reversible with `warden uninstall`.

**Manual setup:**

```bash
# Generate warden.config.yaml from your existing Claude config
warden config-gen

# Or start from a blank template
warden init

# Verify Warden can connect to all downstream servers
warden check

# Start the proxy (stdio mode, ready for MCP client connection)
warden run
```

**Wire it into Claude Code manually** by editing `.claude/settings.json`:

```json
{
  "mcpServers": {
    "warden": {
      "command": "warden",
      "args": ["run", "/path/to/warden.config.yaml"]
    }
  }
}
```

Remove the direct MCP server entries — Warden takes over routing to them. Your tool calls still work. Now they're logged and policy-checked.

---

## Config Reference

Full annotated reference: [`warden.config.example.yaml`](warden.config.example.yaml)

Minimal working example:

```yaml
mode: enforce

servers:
  filesystem:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/Users/you/projects"]

policy:
  defaultAction: allow
  rules:
    - tool: "filesystem/write_file"
      action: deny
      reason: "Filesystem writes require explicit approval"

scrubber:
  enabled: true
```

---

## Commands

### Proxy

| Command | Description |
|---|---|
| `warden run [config]` | Start the proxy in stdio mode |
| `warden kill [reason]` | Arm the kill switch — all tool calls denied immediately |
| `warden unkill` | Disarm the kill switch and resume normal proxying |

### Configuration

| Command | Description |
|---|---|
| `warden init` | Generate `warden.config.yaml` in the current directory |
| `warden validate [config]` | Validate config file and report all errors with field paths |
| `warden config-gen` | Scan Claude Desktop / Claude Code configs and generate `warden.config.yaml` |
| `warden install` | Auto-inject warden into Claude Desktop / Claude Code (backup + restore) |
| `warden uninstall` | Restore original MCP config from backup |
| `warden check [config]` | Verify config and probe **all** downstream servers in parallel |
| `warden doctor` | Run a diagnostic health check (Node version, config, kill switch, log) |

### Audit Log

| Command | Description |
|---|---|
| `warden log` | Stream the audit log (`--tool`, `--verdict`, `--since`, `--tail N`, `--no-follow`, `--json`) |
| `warden stats` | Print tool call counts, deny rates, avg latency (`--since`, `--json`) |
| `warden export` | Export audit log to CSV (`--output`, `--since`, `--tool`, `--verdict`) |
| `warden rotate` | Manually rotate the audit log (`--list`, `--no-compress`) |

### Analysis

| Command | Description |
|---|---|
| `warden diff` | Compare stats before/after a split point (`--split`, `--window`, `--json`) |
| `warden timeline` | ASCII bar chart of tool call activity over time (`--bucket`, `--split-verdict`, `--tool`) |
| `warden trending` | Show rising/falling tool call rates across two halves of a window (`--window`, `--json`) |
| `warden top` | Live dashboard — top-N tools by call count, refreshed every interval |
| `warden watch` | Smart real-time watcher — alerts on bursts, cascading denies, kill events |
| `warden profile` | Tool call distribution and session behavioural fingerprint (`--since`, `--json`) |
| `warden heat-map` | Hour × weekday density heat map — spot anomalous time patterns (`--since`, `--tool`, `--json`) |
| `warden blame` | Find activity spikes and attribute them to responsible tools (`--window`, `--bucket-mins`, `--json`) |
| `warden scope` | Map which files, URLs, and repos the agent touched (`--since`, `--window`, `--tool`, `--json`) |

### Intelligence

| Command | Description |
|---|---|
| `warden anomaly-score` | Compute a 0–100 risk score (`--window`, `--threshold`, `--json`) |
| `warden suggest` | Analyse audit log and suggest policy rules (`--since`, `--yaml`, `--json`) |
| `warden report` | Generate a Markdown audit summary (`--output`, `--since`, `--title`) |
| `warden summary` | Plain-English security summary for stakeholders (`--since`, `--title`, `--output`, `--json`) |
| `warden export-html` | Generate a self-contained interactive HTML report (`--output`, `--title`, `--since`, `--open`) |
| `warden token-estimate` | Estimate LLM input tokens consumed by tool args (`--since`, `--tool`, `--json`) |
| `warden session-summary` | Cluster calls into sessions and report per-session risk (`--gap-mins`, `--last`, `--json`) |
| `warden alert-history` | Incident log of all deny/kill events, with burst clustering (`--burst-secs`, `--verdict`, `--json`) |
| `warden policy-stats` | Policy rule hit analysis — which rules fire, which are dead (`--since`, `--json`) |
| `warden redact-scan` | Post-hoc secret leak detector — scan log for unredacted tokens/keys (`--exit-code`, `--json`) |
| `warden verify-integrity` | Check audit log for tampering: JSON validity, required fields, timestamp monotonicity (`--strict-exit`) |

### CI/CD

| Command | Description |
|---|---|
| `warden snapshot` | Save a timestamped JSON snapshot of current audit stats (`--output`, `--tag`, `--print`) |
| `warden compare` | Compare two snapshots and detect regressions (`--json`, `--fail-on-regression`) |
| `warden ci-check` | Run all CI safety checks, exit 1 if any fail (`--max-deny-rate`, `--max-score`, `--baseline`) |
| `warden replay` | Re-evaluate historical entries against current policy (`--config`, `--diff-only`, `--json`) |
| `warden bench` | Measure per-call policy+scrubber overhead (`--iterations N`, `--json`) |

### Log Management

| Command | Description |
|---|---|
| `warden rotate` | Manually rotate the audit log (`--list`, `--no-compress`) |
| `warden archive` | Compress old entries to gzip, trim live log, write index (`--before`, `--dry-run`, `--index`) |

### Debugging

| Command | Description |
|---|---|
| `warden policy-check` | Dry-run a tool call through the policy engine (`--args`, `--json`) |
| `warden scrub-test` | Preview which fields in a payload would be redacted (`--input`, `--json`) |
| `warden alert-test` | Send test webhook to all configured targets (`--url`, `--json`) |
| `warden latency-percentiles` | P50/P75/P90/P95/P99 latency report per tool (`--since`, `--top`, `--json`) |
| `warden version` | Print version |

---

## Modes

### `audit` mode (default)

Every tool call is logged and scrubbed. Policy rules are evaluated and recorded, but calls are **never blocked** — even if a matching rule says `deny`. Use this while writing your policy.

```yaml
mode: audit
```

### `enforce` mode

Policy rules are authoritative. A `deny` verdict blocks the call and returns an error to the MCP client.

```yaml
mode: enforce
```

Workflow: start with `audit`, review the log with `warden log` and `warden stats`, add `allow` rules for legitimate patterns, then switch to `enforce`.

---

## Policy Rules

Rules are evaluated top-to-bottom; first match wins. `*` is the wildcard character.

```yaml
policy:
  defaultAction: allow    # or "deny" for strict allowlist mode
  rules:
    # Server-specific rules using prefix
    - tool: "filesystem/read_file"
      action: allow

    - tool: "filesystem/write_file"
      action: deny
      reason: "Writes require explicit approval"

    # Cross-server glob patterns
    - tool: "*delete*"
      action: deny
      reason: "Deletion requires policy exception"

    # Allow all GitHub read operations
    - tool: "github/get_*"
      action: allow
    - tool: "github/list_*"
      action: allow

    # Block all GitHub mutations
    - tool: "github/create_*"
      action: deny
```

With `defaultAction: deny`, every tool must be explicitly allowed — a strict allowlist. With `defaultAction: allow`, only listed tools are blocked — a denylist. Most teams start with `allow` and add denies for specific tools they want to gate.

---

## Rate Limiting

Prevent runaway agents from calling the same tool too many times within a window.

```yaml
rateLimit:
  enabled: true
  rules:
    # At most 3 delete calls per 5 minutes
    - tool: "*delete*"
      capacity: 3
      windowMs: 300000

    # At most 10 filesystem writes per minute
    - tool: "filesystem/write_file"
      capacity: 10
      windowMs: 60000

    # Conservative global fallback
    - tool: "*"
      capacity: 60
      windowMs: 60000
```

**Semantics:**
- Token-bucket with continuous refill — capacity tokens per window, one consumed per call.
- Each tool name has its own independent bucket. `github/*` with capacity 5 means each individual GitHub tool can be called 5 times, not 5 calls total across all GitHub tools.
- First matching rule wins (same evaluation order as policy).
- Rate-limited calls are logged with verdict `deny` and a retryAfterMs hint.
- When no rule matches, the tool is not rate-limited.

---

## Webhook Alerts

Push notifications to Slack, PagerDuty, or any HTTP(S) endpoint when Warden blocks or kills a call.

```yaml
webhook:
  enabled: true
  on:
    - deny
    - kill
    - rate-limit

  targets:
    - url: "https://hooks.slack.com/services/T000/B000/xxxx"
      maxRetries: 3

    - url: "https://ops.example.com/warden-alerts"
      secret: "${WARDEN_WEBHOOK_SECRET}"   # sent as X-Warden-Secret header
```

**Payload shape:**

```json
{
  "source":  "agent-warden",
  "version": "0.1.0",
  "ts":      "2024-01-01T00:00:00.000Z",
  "event":   "deny",
  "tool":    "filesystem/delete_file",
  "reason":  "Deletion is irreversible",
  "args":    { "path": "/Users/you/important.txt" }
}
```

Delivery is fire-and-forget with exponential retry (default 3 attempts, base 1 s, cap 30 s). A webhook failure never blocks the proxy response path.

---

## Log Rotation

Prevent the audit log from growing forever with size-based or time-based rotation.

```yaml
rotate:
  enabled: true
  maxBytes: 10485760   # rotate at 10 MiB (default)
  maxAgeMs: 86400000   # also rotate after 24 hours (optional)
  maxFiles: 5          # keep 5 backups (default)
  compress: true       # gzip-compress rotated files (default)
```

Rotation happens automatically at the start of each tool call when either threshold is exceeded. The current log is renamed to `audit.jsonl.1.gz` (and existing backups shifted up), then a fresh log starts. Compression uses gzip — backups are typically 5–10× smaller than the source.

You can also trigger rotation manually at any time:

```bash
# Rotate now (gzip compressed)
warden rotate

# Rotate without compressing
warden rotate --no-compress

# List existing backups
warden rotate --list
```

---

## Kill Switch

The kill switch is a circuit breaker for situations where you need to stop an agent immediately without restarting your entire development environment.

```bash
# Block all tool calls right now
warden kill "suspicious activity detected"

# Resume normal operation
warden unkill
```

When the kill switch is active, Warden returns an MCP error response to every tool call. The agent sees the error and typically stops or asks for guidance. Your session stays open.

The kill switch is implemented as a sentinel file (`~/.warden/killswitch` by default, overridable via `WARDEN_KILLSWITCH` env var). This means:
- It survives Warden restarts
- It can be triggered from any terminal or script
- You can bind it to a keyboard shortcut: `alias panic='warden kill "emergency stop"'`

---

## Audit Log

The log is JSONL — one JSON object per line:

```jsonl
{"ts":"2024-01-01T00:00:00.000Z","tool":"filesystem/read_file","args":{"path":"/home/user/file.txt"},"verdict":"allow","durationMs":12}
{"ts":"2024-01-01T00:00:01.000Z","tool":"filesystem/write_file","args":{"path":"/etc/passwd","content":"[REDACTED]"},"verdict":"deny","reason":"Filesystem writes require explicit approval"}
{"ts":"2024-01-01T00:00:02.000Z","tool":"github/delete_repo","args":{"owner":"you","repo":"myrepo"},"verdict":"killed","reason":"kill switch active — emergency stop"}
```

Stream it live:

```bash
warden log
```

Get statistics:

```bash
warden stats
```

Ship to a SIEM:

```bash
tail -f ~/.warden/audit.jsonl | jq -c . | nc your-siem-host 5514
```

---

## Secret Scrubbing

Warden scrubs the following patterns from logged payloads before writing to disk:

| Pattern | Example |
|---|---|
| AWS access key IDs | `AKIA...` → `[REDACTED]` |
| GitHub tokens | `ghp_...`, `ghs_...`, `gho_...` → `[REDACTED]` |
| Bearer tokens | `Bearer abc123` → `Bearer [REDACTED]` |
| SSH private keys | `-----BEGIN ...` → `[REDACTED]` |
| `.env`-style assignments | `API_KEY=abc123` → `[REDACTED]` |

Add custom patterns in config:

```yaml
scrubber:
  enabled: true
  patterns:
    - "svc_[A-Za-z0-9]{32,}"           # internal service tokens
    - "postgres://[^:]+:[^@]+@[^/\\s]+"  # database connection strings
```

---

## Multi-Server Setup

Configure multiple downstream servers. Warden fans out connections at startup and prefixes tool names to avoid collisions:

```yaml
servers:
  filesystem:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/path"]

  github:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-github"]
    env:
      GITHUB_TOKEN: "${GITHUB_TOKEN}"

  myserver:
    command: node
    args: ["/path/to/my-mcp-server/dist/index.js"]
```

Tool names become:
- `filesystem/read_file`, `filesystem/write_file`, …
- `github/get_file`, `github/create_issue`, …
- `myserver/custom_tool`, …

Policy rules can target a specific server with the prefix:

```yaml
rules:
  - tool: "filesystem/*"    # all filesystem tools
    action: allow
  - tool: "github/create_*" # only GitHub create operations
    action: deny
  - tool: "*"               # catch-all for all servers
    action: deny
```

---

## Why not just use [X]?

**Enterprise MCP gateways** (Invariant, Portkey, others): cloud-hosted, paid, require routing your tool calls through external infrastructure. Useful for large teams. Overkill for individual developers who want visibility into their own machine.

**MCP server built-in auth**: per-server and inconsistent. No cross-server audit trail, no unified policy layer, no kill switch.

**Reading Claude's output carefully**: prompt injection attacks are designed to not surface in visible reasoning. The tool calls happen; you don't see them until it's too late.

**agent-warden**: runs locally, free, zero external dependencies, open source. Installs in 30 seconds. Doesn't require a SaaS contract.

---

## Roadmap

- [x] Multi-server proxy with tool name prefixing
- [x] Policy engine with glob rules and dangerous-tool detection
- [x] JSONL audit log with secret scrubbing
- [x] Kill switch (file-based, instant)
- [x] Rate limiting (token-bucket per tool)
- [x] Webhook alerts (deny / kill / rate-limit events)
- [x] `warden log` with `--tool`, `--verdict`, `--since`, `--tail N`, `--json` filters
- [x] `warden stats` with `--since`, `--json`, avg latency per tool
- [x] `warden export` — CSV export for spreadsheet analysis
- [x] `warden bench` — in-process latency benchmark
- [x] `warden check` — probes all configured servers in parallel
- [x] `${VAR}` expansion in server env and webhook targets
- [x] Log rotation — size + time-based with optional gzip, `warden rotate` command
- [x] `warden diff` — before/after comparison with configurable split point and window
- [x] `warden top` — live dashboard, configurable interval and top-N
- [x] `warden watch` — real-time anomaly detection (burst, deny-streak, kill-switch alerts)
- [x] `warden policy-check` — dry-run policy evaluation without starting the proxy
- [x] `warden scrub-test` — preview secret redaction on any JSON payload
- [x] `warden report` — Markdown audit summary for sharing with teams
- [x] `warden_status` built-in MCP tool — query proxy status from inside a Claude session
- [x] `warden install` / `warden uninstall` — one-command Claude Desktop integration
- [x] `warden config-gen` — auto-generate config from existing Claude Desktop/Code setup
- [x] `warden validate` — deep config validation with field-path errors
- [x] `warden alert-test` — verify webhook delivery before going live
- [x] `warden watch` — real-time anomaly detection with configurable thresholds
- [x] `warden scrub-test` — preview secret scrubbing on any JSON payload
- [x] `warden log --grep` — regex filter across entire audit entry
- [x] `warden timeline` — ASCII bar chart of tool call activity over time
- [x] `warden server-list` — list all available tools across configured MCP servers
- [x] `warden doctor` — comprehensive health check (`brew doctor`-style with hints)
- [x] `warden run --mode/--log-file/--no-rotate` — runtime overrides without editing config
- [x] 300 unit + integration tests across 24 test suites
- [ ] Web dashboard — local browser UI to view audit log and visualize call patterns
- [ ] OPA integration — use Open Policy Agent `.rego` files as the policy engine
- [ ] OpenTelemetry export — emit audit entries as OTEL spans

---

## Development

```bash
git clone https://github.com/yli769227-jpg/agent-warden.git
cd agent-warden
npm install --include=optional
npm run build
npm test              # 300 tests (287 unit + 13 integration)
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev workflow and PR checklist.

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

---

## License

MIT — see [LICENSE](LICENSE).

---

Built because the security layer for local AI agents shouldn't require a SaaS contract.  
Issues and PRs welcome.
