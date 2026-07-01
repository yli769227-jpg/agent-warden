/**
 * Secret scrubber for agent-warden.
 *
 * Redacts secrets from arbitrary values (objects, arrays, strings) before
 * they are written to audit logs.  Recursively walks the value graph and
 * replaces any string leaf that matches a known-secret pattern with the
 * literal token `[REDACTED]`.
 */

import { ScrubberConfig } from './types.js';

const PREFIX = '[warden:scrubber]';
const REDACTED = '[REDACTED]';

// ---------------------------------------------------------------------------
// Default patterns
//
// Stored as { source, flags } tuples so that each createScrubber() call can
// build its own fresh RegExp instances — this prevents shared .lastIndex state
// across concurrent (or serial) invocations of different scrubbers.
// ---------------------------------------------------------------------------

/** Default regex patterns expressed as literals for readability. */
const _DEFAULT_REGEXES: readonly RegExp[] = [
  // AWS access-key IDs
  /AKIA[0-9A-Z]{16}/g,

  // Generic key/secret/token/password assignments wrapped in quotes, e.g.
  //   "sk": "abc123…"  |  'token' = 'abc123…'
  /['"](sk|pk|api[_-]?key|token|secret|password|passwd|pwd)['"]\s*[:=]\s*['"][^'"]{8,}['"]/gi,

  // PEM private keys (RSA, EC, DSA, …)
  /-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----/g,

  // GitHub personal-access / fine-grained / OAuth / refresh tokens
  /gh[pousr]_[A-Za-z0-9]{36}/g,

  // HTTP Authorization: Bearer …
  /Bearer\s+[A-Za-z0-9\-._~+/]+=*/g,
];

/** Compiled { source, flags } used to stamp out fresh RegExp instances. */
const DEFAULT_PATTERN_DEFS: ReadonlyArray<{ source: string; flags: string }> =
  _DEFAULT_REGEXES.map(re => ({ source: re.source, flags: re.flags }));

// ---------------------------------------------------------------------------
// .env-style heuristic
//
// Pattern: ^[A-Z_]+=.+$  (multiline)
// Only treat the value as a secret when length > 12 AND the value contains
// characters from at least two distinct classes (uppercase, lowercase,
// digit, special).  This avoids redacting innocuous values like VERSION=1.2.3.
// ---------------------------------------------------------------------------

const ENV_LINE_SOURCE = '^([A-Z_]+=)(.+)$';
const ENV_LINE_FLAGS = 'gm';

// ---------------------------------------------------------------------------
// Key-name heuristic
//
// The format regexes above only fire when a secret's *value* matches a known
// shape AND (for the quoted-assignment rule) the key+value live in the same
// string.  Structured MCP args like { "password": "hunter2long" } are walked
// key-by-key, so the value leaf "hunter2long" never matches any format regex
// and leaks.  We close that gap by redacting the whole string value whenever
// its *key* looks sensitive.
// ---------------------------------------------------------------------------

const SENSITIVE_KEY_RE =
  /(secret|token|passwd|password|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|client[_-]?secret|bearer|auth[_-]?token)/i;

function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY_RE.test(key);
}

function looksLikeSecret(value: string): boolean {
  if (value.length <= 12) return false;

  const hasUpper   = /[A-Z]/.test(value);
  const hasLower   = /[a-z]/.test(value);
  const hasDigit   = /[0-9]/.test(value);
  const hasSpecial = /[^A-Za-z0-9]/.test(value);

  const classes = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;
  return classes >= 2;
}

// ---------------------------------------------------------------------------
// Core scrubbing logic
// ---------------------------------------------------------------------------

/**
 * Scrubs a single string, returning the (possibly redacted) string and the
 * number of replacements made.
 */
function scrubString(
  str: string,
  patterns: RegExp[],
): { result: string; count: number } {
  let result = str;
  let count = 0;

  for (const re of patterns) {
    // String.prototype.replace resets lastIndex for global regexes, but we
    // reset it explicitly here as well for defensive correctness.
    re.lastIndex = 0;
    result = result.replace(re, () => {
      count++;
      return REDACTED;
    });
  }

  // .env-style heuristic (conditional — length + mixed-char check)
  const envRe = new RegExp(ENV_LINE_SOURCE, ENV_LINE_FLAGS);
  result = result.replace(envRe, (_match, key: string, value: string) => {
    if (looksLikeSecret(value)) {
      count++;
      return `${key}${REDACTED}`;
    }
    return _match;
  });

  return { result, count };
}

/**
 * Recursively walks `value`, scrubbing every string leaf it encounters.
 * Returns a structurally identical fresh copy (objects and arrays are rebuilt;
 * primitives are returned as-is).
 */
function walkAndScrub(
  value: unknown,
  patterns: RegExp[],
): { result: unknown; count: number } {
  // String leaf — apply all patterns.
  if (typeof value === 'string') {
    return scrubString(value, patterns);
  }

  // Array — map each element recursively.
  if (Array.isArray(value)) {
    let total = 0;
    const arr: unknown[] = value.map(item => {
      const { result, count } = walkAndScrub(item, patterns);
      total += count;
      return result;
    });
    return { result: arr, count: total };
  }

  // Plain object — rebuild key-by-key.
  if (value !== null && typeof value === 'object') {
    let total = 0;
    const obj: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      // Key-aware redaction: a non-empty string under a sensitive-looking key
      // is redacted wholesale, regardless of whether its value matches any
      // format pattern.  Non-string values (nested objects/arrays) still
      // recurse so we don't blanket-blackhole structured data.
      if (isSensitiveKey(k) && typeof v === 'string' && v.length > 0) {
        obj[k] = REDACTED;
        total += 1;
        continue;
      }
      const { result, count } = walkAndScrub(v, patterns);
      total += count;
      obj[k] = result;
    }
    return { result: obj, count: total };
  }

  // Primitives (number, boolean, null, undefined, bigint, symbol) — pass through.
  return { result: value, count: 0 };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Creates a scrubber function that redacts secrets from arbitrary values
 * before they are written to audit logs.
 *
 * Built-in patterns cover AWS keys, generic API key/secret/token/password
 * assignments, PEM private keys, GitHub tokens, Bearer auth headers, and
 * `.env`-style lines whose values pass a mixed-character heuristic.
 *
 * @param patterns - Optional additional patterns (as regex source strings).
 *   Each is compiled with the `g` flag and applied on top of the defaults.
 * @returns A function that deep-walks any value and returns a fresh clone
 *   with secrets replaced by `[REDACTED]`.  Logs the redaction count to
 *   stderr as `[warden:scrubber] Redacted N secrets`.
 *
 * @see {@link ScrubberConfig} for the field shape used in {@link WardenConfig}.
 */
export function createScrubber(
  patterns?: string[],
): (value: unknown) => unknown {
  // Stamp out fresh RegExp instances to avoid shared .lastIndex state.
  const compiled: RegExp[] = DEFAULT_PATTERN_DEFS.map(
    ({ source, flags }) => new RegExp(source, flags),
  );

  for (const src of patterns ?? []) {
    compiled.push(new RegExp(src, 'g'));
  }

  return (value: unknown): unknown => {
    // structuredClone first so Date/Map/Set/circular-ref edge cases in the
    // caller's data are preserved before the walker rebuilds plain objects.
    const cloned = structuredClone(value);
    const { result, count } = walkAndScrub(cloned, compiled);

    if (count > 0) {
      process.stderr.write(`${PREFIX} Redacted ${count} secrets\n`);
    }

    return result;
  };
}

/**
 * Convenience factory that accepts a {@link ScrubberConfig} directly,
 * matching the shape stored in {@link WardenConfig}.
 *
 * When `config.enabled` is `false` the returned scrubber is a no-op passthrough.
 */
export function createScrubberFromConfig(
  config: ScrubberConfig,
): (value: unknown) => unknown {
  if (!config.enabled) {
    return (value: unknown) => structuredClone(value);
  }
  return createScrubber(config.patterns);
}
