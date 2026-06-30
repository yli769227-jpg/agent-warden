# Contributing to agent-warden

Thank you for your interest. agent-warden is a security-focused tool — contributions are welcome, but correctness and threat-model clarity matter more than feature velocity.

## Ground rules

- **Security first** — if your change touches policy enforcement, kill switch, or log scrubbing, include a test that verifies the security property, not just the happy path.
- **One concern per PR** — split feature + refactor into separate PRs. It keeps review tractable.
- **Minimal diffs** — prefer editing existing files over adding new ones. Don't fix style while fixing bugs.
- **No lock file surprises** — run `npm install --include=optional` so the lock file includes cross-platform optional deps.

## Development setup

```sh
git clone https://github.com/yli769227-jpg/agent-warden.git
cd agent-warden
npm install --include=optional

# Verify the baseline is clean
npm run build
npm test
```

Requirements: Node.js ≥ 18.

## Project layout

```
src/
  cli.ts         # warden CLI (run / kill / unkill / log / stats / check / init)
  proxy.ts       # Core MCP proxy engine; spawns downstream servers
  policy.ts      # Glob-match policy engine (audit vs enforce mode)
  audit.ts       # JSONL append-only audit logger
  killswitch.ts  # Sentinel-file-based emergency stop
  scrubber.ts    # Regex-based secret redaction
  config.ts      # YAML config loader with ~ expansion and defaults
  types.ts       # Shared TypeScript interfaces
  index.ts       # Public API barrel export

tests/
  unit/          # Fast, no spawning — mock or directly call exported functions
  integration/   # Spawn real proxy + inline echo servers via StdioClientTransport
```

## Test conventions

- Unit tests live in `tests/unit/` and must not spawn processes.
- Integration tests live in `tests/integration/` and write to `os.tmpdir()` only.
- Every integration test cleans up its tmp dir in `afterAll`.
- Kill switch tests inject `WARDEN_KILLSWITCH` via a wrapper so they don't touch `~/.warden/`.

Run just unit tests (faster iteration):

```sh
npm run test:unit
```

Run integration tests (require a prior `npm run build`):

```sh
npm run build && npm run test:integration
```

## Commit style

```
type: short summary (≤ 72 chars)

Optional body with context — why, not what.
```

Types: `feat`, `fix`, `test`, `docs`, `refactor`, `chore`.

Security fixes: prefix with `fix(security):`.

## Pull request checklist

- [ ] `npm run build` succeeds with zero TypeScript errors
- [ ] `npm test` passes all 46 tests
- [ ] New behaviour covered by a test (unit or integration)
- [ ] `warden.config.example.yaml` updated if config schema changed
- [ ] README updated if CLI or behaviour changed
- [ ] SECURITY.md threat model still accurate after change

## What we're looking for

High priority:

- **Rate limiting** — per-tool call rate limits with configurable windows
- **Webhook / Slack alerts** — push notifications on deny/kill events
- **Log rotation** — size or time-based JSONL rotation with compression
- **OpenTelemetry export** — emit audit entries as OTEL spans

Lower priority / needs discussion first:

- Network transport support (HTTP, WebSocket) — significant threat model change
- A web dashboard — useful but out of scope for the core proxy
- Python bindings — valid but maintenance burden

When in doubt, open an issue to discuss before coding.

## Reporting vulnerabilities

Do not open public issues for security bugs. See [SECURITY.md](SECURITY.md).
