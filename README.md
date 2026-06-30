# agent-warden 🛡️

> A local MCP audit proxy that logs every tool call, enforces allow/deny policies, and gives you a kill switch — before the agent does something you can't undo.

[![npm version](https://img.shields.io/npm/v/agent-warden)](https://www.npmjs.com/package/agent-warden)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP compatible](https://img.shields.io/badge/MCP-compatible-blue)](https://modelcontextprotocol.io)

---

## The Problem

MCP changed what AI agents can do. In 2026, a single `claude --mcp-server filesystem` gives Claude Code read/write access to your entire home directory. Add a GitHub MCP server and it can push code. Add a shell server and it can run arbitrary commands.

Once you say "go," you have no intercept layer. The agent talks directly to the MCP server. Nothing in between.

**The numbers are not reassuring:**
- **30 CVEs** filed against MCP infrastructure in the first 60 days after widespread adoption
- **492 MCP servers** found exposed on the public internet with zero authentication
- Prompt injection attacks that redirect tool calls mid-task — with no audit trail to reconstruct what happened

The core issue isn't that MCP is poorly designed. It's that the threat model assumes you'll be watching. You won't always be watching.

Enterprise teams have answered this with cloud-hosted MCP gateways — paid, SaaS, requiring you to route all tool calls through their infrastructure. That's the wrong tradeoff for most developers: you're adding an external dependency to solve a local security problem.

agent-warden is the local answer.

---

## What agent-warden does

Warden sits as a transparent proxy in the stdio chain between your MCP client (Claude Code, Claude Desktop, or any MCP-compatible tool) and your MCP servers. Every tool call passes through Warden first.

**Audit logging**
Every tool invocation is written to a JSONL audit log: tool name, full arguments, response status, duration in milliseconds, and a timestamp. The log is append-only. Secrets are scrubbed before writing.

**Policy engine**
Define allow/deny rules by tool name with glob support. `filesystem/write_*` can be blocked entirely. `filesystem/read_file` can be allowed only for paths under `/Users/you/project`. Rules are evaluated in order; first match wins. Unmatched calls fall through to a configurable default (`allow` in audit mode, `deny` in enforce mode).

**Dangerous tool auto-detection**
Warden ships with a built-in list of tool patterns that warrant extra caution: shell execution, file deletion, git force-push, network egress, credential access. These are flagged in the audit log automatically, even if you haven't written a policy for them. You can extend or override the list in config.

**Secret scrubbing**
Before any log line is written to disk, Warden runs a scrubber over argument payloads. Patterns covering AWS keys, GitHub tokens, SSH private keys, Bearer tokens, and generic high-entropy strings are redacted and replaced with `[REDACTED]`. The upstream MCP server still receives the original payload — scrubbing is log-side only.

**Kill switch**
One command pauses all tool call forwarding instantly. No restart required. Claude Code (or whatever client you're using) sees its next tool call return an error. You have time to inspect the audit log, understand what happened, and decide whether to resume or terminate the session.

---

## Architecture

```
Claude Code ──stdio──▶ agent-warden ──stdio──▶ filesystem MCP server
                             │
                        audit.jsonl
                      (secrets scrubbed)
```

Warden implements the MCP protocol on both sides. To your MCP client it looks like an MCP server. To your downstream MCP servers it looks like an MCP client. It proxies the full protocol — tool listings, resource reads, prompt requests — and intercepts at the tool-call layer.

Multiple downstream servers are supported. Warden fans out to each server defined in config and merges their tool namespaces, prefixed by server name to avoid collisions.

```
Claude Code ──stdio──▶ agent-warden ──stdio──▶ filesystem MCP server
                             │       ──stdio──▶ github MCP server
                             │       ──stdio──▶ shell MCP server
                             │
                        audit.jsonl
```

---

## Quick Start

```bash
# Install globally
npm install -g agent-warden

# Or use without installing
npx agent-warden init
```

```bash
# Generate warden.config.yaml in the current directory
npx agent-warden init

# Verify Warden can connect to all downstream servers defined in config
npx agent-warden check

# Start the proxy (stdio mode, ready for MCP client connection)
npx agent-warden start
```

**Wire it into Claude Code** by editing `.claude/settings.json`:

```json
{
  "mcpServers": {
    "warden": {
      "command": "npx",
      "args": ["agent-warden", "start", "--config", "/path/to/warden.config.yaml"],
      "env": {}
    }
  }
}
```

Remove the direct MCP server entries from your settings — Warden takes over routing to them. Your tool calls still work. Now they're logged and policy-checked.

**Claude Desktop** users: same pattern in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "warden": {
      "command": "npx",
      "args": ["agent-warden", "start"],
      "cwd": "/Users/you/your-project"
    }
  }
}
```

---

## Config Reference

`warden.config.yaml` — generated by `npx agent-warden init`, annotated here in full:

```yaml
# agent-warden configuration
# https://github.com/yli769227-jpg/agent-warden

# Downstream MCP servers Warden proxies to.
# Tool names will be prefixed with the server key (e.g., "filesystem/read_file").
servers:
  filesystem:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/Users/you"]
  github:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-github"]
    env:
      GITHUB_TOKEN: "${GITHUB_TOKEN}"  # resolved from environment at startup

# Audit log settings
audit:
  # Path to the JSONL audit log. Rotated daily by default.
  path: "./warden-audit.jsonl"
  # Rotate logs when they exceed this size (bytes). 0 = no size-based rotation.
  max_size_bytes: 10485760  # 10 MB
  # Keep this many rotated log files before deleting old ones.
  keep_rotated: 7
  # Write a summary line to stdout for each tool call (useful during development).
  console: true

# Secret scrubbing — applied to all log writes, not to upstream payloads.
scrubbing:
  enabled: true
  # Built-in patterns: aws_key, github_token, bearer_token, ssh_private_key,
  # high_entropy_string. List patterns here to disable specific built-ins.
  disable_patterns: []
  # Add your own regex patterns. Matched groups are replaced with [REDACTED].
  custom_patterns:
    - 'MY_INTERNAL_SECRET_[A-Z0-9]{32}'

# Policy engine
policy:
  # "audit"   — log everything, block nothing. Good for day-one visibility.
  # "enforce" — apply rules below; deny by default if no rule matches.
  mode: audit

  # Rules are evaluated top-to-bottom. First match wins.
  # Glob patterns are supported for tool names.
  rules:
    # Allow read-only filesystem access anywhere
    - tool: "filesystem/read_*"
      action: allow

    # Block all write operations outside the project directory
    - tool: "filesystem/write_file"
      action: deny
      reason: "Write access restricted — switch to enforce mode and add an allow rule for your project path."

    # Block file deletion entirely
    - tool: "filesystem/*delete*"
      action: deny
      reason: "Deletion blocked by policy."

    # Allow all GitHub read operations
    - tool: "github/get_*"
      action: allow
    - tool: "github/list_*"
      action: allow

    # Block force push
    - tool: "github/push_files"
      action: deny
      when:
        args_match:
          force: true
      reason: "Force push blocked by policy."

# Dangerous tool detection — these patterns are flagged in the audit log
# regardless of policy outcome. Extend or replace the built-in list here.
dangerous_tools:
  # Use "extend" to add to the built-in list, "replace" to define your own.
  mode: extend
  patterns:
    - "*exec*"
    - "*shell*"
    - "*run_command*"
    - "*delete*"
    - "*destroy*"
    - "*drop_*"

# Kill switch
kill_switch:
  # Path to the kill switch file. When this file exists, all tool calls are blocked.
  # Create it with: npx agent-warden kill
  # Remove it with: npx agent-warden resume
  path: "/tmp/warden.kill"
  # Message returned to the MCP client when the kill switch is active.
  message: "agent-warden kill switch is active. Run `npx agent-warden resume` to unblock."
```

---

## Commands

| Command | Description |
|---|---|
| `agent-warden init` | Generate `warden.config.yaml` in the current directory with safe defaults |
| `agent-warden start` | Start the proxy in stdio mode (for use as an MCP server) |
| `agent-warden check` | Connect to all downstream servers and verify tool listings are reachable |
| `agent-warden kill` | Activate the kill switch — all subsequent tool calls return an error immediately |
| `agent-warden resume` | Deactivate the kill switch and resume normal proxying |
| `agent-warden tail` | Stream the audit log to stdout in human-readable format |
| `agent-warden stats` | Print tool call counts, deny rates, and flagged calls from the current log |
| `agent-warden scrub <file>` | Re-run secret scrubbing over an existing log file (in-place, with backup) |
| `agent-warden validate` | Parse and validate `warden.config.yaml` without starting the proxy |

All commands accept `--config <path>` to specify a non-default config file location.

---

## Modes

### `audit` mode (default)

Every tool call is logged and secret-scrubbed. Policy rules are evaluated and their outcome is recorded, but calls are **never blocked** — even if a matching rule says `deny`. This is the right starting point: run a session, review the log, understand what tools your agent actually calls, then write rules based on observed behavior.

```yaml
policy:
  mode: audit
```

No traffic is interrupted. The audit log is your output.

### `enforce` mode

Policy rules are enforced. A `deny` rule blocks the call and returns an error to the MCP client. Calls that match no rule are **denied by default** — you must explicitly allow what you want. This is the right mode for production or any session where the agent has access to sensitive resources.

```yaml
policy:
  mode: enforce
```

Start with `audit`, review the log with `agent-warden stats`, add `allow` rules for legitimate tool patterns, then switch to `enforce`.

---

## Kill Switch

The kill switch is a circuit breaker for situations where you need to stop an agent immediately without restarting your entire development environment.

```bash
# Block all tool calls right now
npx agent-warden kill

# Resume normal operation
npx agent-warden resume
```

When the kill switch is active, Warden returns an MCP error response to every tool call. The agent sees the error and typically stops or asks for guidance. Your session stays open. No restarts.

**Why this matters:** MCP agents can move fast. A misunderstood instruction or a prompt injection mid-task can trigger a cascade of tool calls in seconds. The kill switch is the difference between pausing to investigate and spending an hour on `git reflog`.

The kill switch is implemented as a file on disk (`/tmp/warden.kill` by default, configurable). This means it survives Warden restarts and can be triggered from any terminal — a separate shell, a script, a keyboard shortcut bound to `npx agent-warden kill`.

---

## Why not just use [X]?

**Enterprise MCP gateways** (Invariant, Portkey, others): cloud-hosted, paid, require you to route your tool calls through external infrastructure. Useful if your team is large and you need centralized policy management. Overkill if you're a developer who wants visibility into what's happening on your own machine.

**MCP server built-in auth**: some servers implement their own access controls. This is good, but it's per-server and inconsistent. You get no cross-server audit trail, no unified policy layer, and no kill switch.

**Reading Claude's output carefully**: works until it doesn't. Prompt injection attacks are specifically designed to not surface in Claude's visible reasoning. The tool calls happen; you don't see them until the log already has the answer.

**agent-warden**: runs locally, free, zero external dependencies, open source, installs in 30 seconds. It doesn't try to replace enterprise infrastructure — it gives individual developers the observability layer that should have been there from the start.

---

## Roadmap

- **Web dashboard** — a local browser UI to view the audit log, filter by tool/server/outcome, and visualize call patterns over a session
- **OPA policy integration** — use Open Policy Agent `.rego` files as the policy engine for teams that already have OPA in their stack
- **Rate limiting** — cap tool calls per minute per tool or per server, with configurable backoff behavior
- **Slack/webhook alerts on deny** — push a notification when a policy deny fires or the kill switch is activated, so you know something unexpected happened even when you're not watching the terminal

---

## License

MIT — see [LICENSE](LICENSE).

---

Built because the security layer for local AI agents shouldn't require a SaaS contract.  
Issues and PRs welcome.
