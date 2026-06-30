/**
 * Configuration for a single downstream MCP server.
 *
 * command: Executable to spawn (e.g. "npx").
 * args:    Arguments passed to the executable.
 * env:     Additional environment variables merged into the child process env.
 */
export interface ServerConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

/**
 * Top-level warden configuration.
 *
 * mode:
 *   'audit'   – log every intercepted call but always forward it downstream.
 *   'enforce' – apply policy rules; deny/kill actions are enforced.
 *
 * Downstream servers can be declared in two ways:
 *
 *   (a) Multi-server (preferred): `servers` maps named keys to ServerConfig.
 *       Tool names are prefixed with the server key: "filesystem/read_file".
 *
 *   (b) Single-server (legacy): `downstreamCommand` is a flat string array.
 *       Tool names are not prefixed.
 *
 * Exactly one of `servers` or `downstreamCommand` must be non-empty.
 */
export interface WardenConfig {
  mode: 'audit' | 'enforce';
  /**
   * Named downstream MCP servers (preferred).
   * Tool names will be prefixed with the server key, e.g. "filesystem/read_file".
   */
  servers?: Record<string, ServerConfig>;
  /**
   * @deprecated Use `servers` instead.
   * Shell command (and arguments) used to spawn a single downstream MCP server.
   * The first element is the executable; remaining elements are the arguments.
   */
  downstreamCommand?: string[];
  /** Absolute or relative path to the JSONL audit log file. */
  logFile: string;
  policy: PolicyConfig;
  scrubber: ScrubberConfig;
  /** Optional per-tool rate limiting. */
  rateLimit?: RateLimitConfig;
  /** Optional webhook alerts on deny/kill events. */
  webhook?: WebhookConfig;
}

/**
 * Webhook alert configuration.
 */
export interface WebhookConfig {
  enabled: boolean;
  /** HTTP(S) endpoints to POST alert payloads to. */
  targets?: Array<{
    url: string;
    secret?: string;
    maxRetries?: number;
  }>;
  /** Which event types trigger delivery. Defaults to all. */
  on?: Array<'deny' | 'kill' | 'rate-limit'>;
}

/**
 * Rate-limiting configuration applied per tool call.
 */
export interface RateLimitConfig {
  enabled: boolean;
  /** Ordered list of rules; first matching rule's limit is applied. */
  rules?: RateLimitRule[];
}

/**
 * A single rate-limit rule.
 *
 * tool:      Exact tool name or glob pattern (e.g. "github/*", "*").
 * capacity:  Maximum number of calls allowed within windowMs.
 * windowMs:  Rolling window length in milliseconds.
 */
export interface RateLimitRule {
  tool: string;
  capacity: number;
  windowMs: number;
}

/**
 * Policy configuration applied to every intercepted tools/call.
 */
export interface PolicyConfig {
  /** Fallback verdict when no rule matches the tool name. */
  defaultAction: 'allow' | 'deny';
  /** Ordered list of rules; first match wins. */
  rules?: PolicyRule[];
  /**
   * Working directory used for out-of-cwd filesystem-write checks.
   * Defaults to process.cwd() when omitted.
   */
  cwd?: string;
  /**
   * Warden operating mode forwarded from WardenConfig.  When 'enforce',
   * dangerous tool calls are denied; when 'audit' they are allowed with a
   * warning.  Defaults to 'audit'.
   */
  mode?: 'audit' | 'enforce';
}

/**
 * A single policy rule.
 *
 * tool:   Exact tool name or minimatch glob (e.g. "bash", "fs/*", "*").
 * action: Verdict to apply when the rule matches.
 * reason: Optional human-readable explanation recorded in the audit log.
 */
export interface PolicyRule {
  tool: string;
  action: 'allow' | 'deny';
  reason?: string;
}

/**
 * Configuration for the secret-scrubbing layer applied before log writes.
 */
export interface ScrubberConfig {
  enabled: boolean;
  /**
   * Additional regex patterns (as strings) to redact from logged payloads.
   * Built-in patterns (API keys, tokens, passwords, etc.) are always applied
   * when enabled is true.
   */
  patterns?: string[];
}

/**
 * A single line written to the JSONL audit log.
 */
export interface AuditEntry {
  /** ISO-8601 timestamp of when the call was intercepted. */
  ts: string;
  /** Name of the MCP tool that was called. */
  tool: string;
  /** Scrubbed copy of the arguments passed to the tool. */
  args: unknown;
  /** Policy verdict or kill-switch outcome. */
  verdict: 'allow' | 'deny' | 'killed';
  /** Human-readable explanation for the verdict. */
  reason?: string;
  /** Round-trip latency in milliseconds (only present for forwarded calls). */
  durationMs?: number;
  /** Serialised error message if the downstream call failed. */
  error?: string;
}

/**
 * Persistent kill-switch state shared across all active warden instances.
 *
 * When killed is true, all tools/call messages are denied immediately
 * without being forwarded, regardless of policy rules.
 */
export interface KillSwitchState {
  /** True when the sentinel file exists and the kill switch is active. */
  killed: boolean;
  /** Reason the kill switch was activated. */
  reason?: string;
  /** ISO-8601 timestamp of activation. */
  killedAt?: string;
  /** Absolute path to the sentinel file being watched. */
  path?: string;
}
