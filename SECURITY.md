# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x     | ✅ Yes    |

agent-warden is currently pre-1.0. Security fixes are backported to the latest 0.x release only.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.** Doing so exposes all users to risk before a fix is available.

Instead, use one of:

- **GitHub private vulnerability reporting** — [Security → Report a vulnerability](../../security/advisories/new) (recommended)
- **Email** — yli769227@gmail.com with subject `[agent-warden] Security`

### What to include

| Field | Notes |
|-------|-------|
| Description | What is the vulnerability and what can an attacker do? |
| Reproduction | Minimal config + commands to trigger it |
| Impact | What data / systems are at risk? |
| Severity | Your assessment (Critical / High / Medium / Low) |
| Fix suggestion | Optional — patches welcome |

We aim to acknowledge reports within **48 hours** and to publish a fix within **14 days** for critical issues.

---

## Threat Model

agent-warden is an **audit proxy**, not a sandbox. Understanding its threat model helps you use it correctly.

### What agent-warden protects against

- **Unintended AI-driven tool calls** — an AI agent calling `delete_file` or `run_shell` unintentionally; warden intercepts and blocks.
- **Secret exfiltration via logs** — credentials in tool arguments are scrubbed before they reach the audit log.
- **Runaway agent loops** — the kill switch (`warden kill`) terminates all downstream tool calls immediately without stopping the AI process.
- **Audit gaps** — every tools/call is logged with timestamp, verdict, and scrubbed args; the log is append-only and can be piped to a SIEM.

### What agent-warden does NOT protect against

- **Prompt injection** — a malicious document fed to the AI that instructs it to call allowed tools in harmful combinations. Policy rules operate on tool names, not on intent.
- **Compromise of the agent-warden process itself** — if the host where warden runs is compromised, the proxy offers no protection. Use OS-level isolation (containers, VMs) for high-risk deployments.
- **Side-channel leakage** — arguments scrubbing is regex-based; novel secret formats may not be caught. Add custom patterns via `scrubber.patterns` in your config.
- **Tool call contents after allow** — warden evaluates and logs arguments, then forwards the call. It does not inspect the downstream server's response for secrets.
- **MCP transport security** — agent-warden uses stdio (local process). If you expose MCP over a network transport, secure it with mutual TLS at the network layer; warden does not add transport encryption.

### Privilege posture

agent-warden runs as the same user as the AI client (e.g., Claude Code). It has no elevated privileges. The kill switch sentinel file is in `~/.warden/` by default; any process running as the same user can arm or disarm it. In multi-user environments, set `WARDEN_KILLSWITCH` to a path with restricted write permissions.

---

## Hardening Recommendations

### Production deployments

```yaml
# warden.config.yaml — recommended production settings
mode: enforce            # audit is for dev only; enforce blocks in prod

policy:
  defaultAction: deny    # allowlist model: every tool must be explicitly permitted
  rules:
    - tool: "myserver/safe_read"
      action: allow

scrubber:
  enabled: true
  patterns:
    # Add your internal secret formats here
    - "svc_[A-Za-z0-9]{32,}"
```

### Log integrity

The audit log is JSONL, append-only. For tamper evidence:

```sh
# Ship logs to an immutable destination (e.g., S3 object lock)
warden log | aws s3 cp - s3://my-audit-bucket/warden/$(date +%Y-%m-%d).jsonl

# Or verify no lines were deleted (use a rolling hash)
sha256sum ~/.warden/audit.jsonl > ~/.warden/audit.jsonl.sha256
```

### Kill switch path hardening

```sh
# Restrict the killswitch directory to root-write only
sudo mkdir -p /opt/warden
sudo chown root:staff /opt/warden
sudo chmod 755 /opt/warden

export WARDEN_KILLSWITCH=/opt/warden/killswitch
```

With this setup, `warden kill` requires `sudo` — preventing an AI agent from disarming its own kill switch.

---

## Dependency Security

| Package | Role | Version pin |
|---------|------|-------------|
| `@modelcontextprotocol/sdk` | MCP protocol | `^1.29.0` |
| `js-yaml` | Config parsing | `^4.1.0` |
| `zod` | Schema validation | `^4.4.3` |
| `picocolors` | Terminal colors | `^1.1.1` |

We follow npm audit as part of CI. Run `npm audit` before deploying to verify no new advisories exist for pinned versions.

---

## Disclosure Policy

We follow **coordinated disclosure**:

1. Reporter submits private report.
2. Maintainer acknowledges within 48 hours.
3. Fix developed privately.
4. Security advisory published with CVE request (if warranted) on the same day as the fix release.
5. Reporter credited (unless they prefer anonymity).

We do not offer a bug bounty at this time.
