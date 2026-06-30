/**
 * Token-bucket rate limiter for agent-warden.
 *
 * Each configured rule gets its own bucket per tool-name pattern.
 * Evaluation order mirrors the policy engine: first matching rule wins.
 * If no rule matches a tool, the call is not rate-limited.
 *
 * Bucket semantics:
 *   - capacity: maximum number of calls allowed in the window
 *   - windowMs: rolling window length in milliseconds
 *   - Each call removes one token; tokens are restored at a continuous
 *     rate of (capacity / windowMs) per millisecond (leaky-bucket style).
 *   - When tokens reach 0 the call is rejected with a RateLimitError.
 */

import type { RateLimitConfig, RateLimitRule } from './types.js';

export type { RateLimitConfig, RateLimitRule };

export class RateLimitError extends Error {
  constructor(
    public readonly tool: string,
    public readonly rule: RateLimitRule,
    public readonly retryAfterMs: number,
  ) {
    super(
      `Rate limit exceeded for tool "${tool}" — ` +
        `limit is ${rule.capacity} calls per ${rule.windowMs}ms. ` +
        `Retry after ${Math.ceil(retryAfterMs)}ms.`,
    );
    this.name = 'RateLimitError';
  }
}

// ─── Bucket ──────────────────────────────────────────────────────────────────

interface Bucket {
  tokens: number;
  lastRefillAt: number;
}

// ─── Glob match (reused from policy.ts logic) ─────────────────────────────────

function globMatch(pattern: string, value: string): boolean {
  if (!pattern.includes('*')) return pattern === value;
  const escapedPattern = pattern
    .split('*')
    .map((s) => s.replace(/[.+^${}()|[\]\\]/g, '\\$&'))
    .join('.*');
  return new RegExp(`^${escapedPattern}$`).test(value);
}

// ─── RateLimiter ─────────────────────────────────────────────────────────────

export class RateLimiter {
  private readonly rules: RateLimitRule[];
  /** key = `${ruleIndex}:${toolName}` → bucket */
  private readonly buckets = new Map<string, Bucket>();

  constructor(rules: RateLimitRule[]) {
    this.rules = rules;
  }

  /**
   * Attempts to consume one token for `toolName`.
   *
   * @throws {RateLimitError} when the matching bucket is exhausted.
   * Returns the matching rule (or undefined if no rule matched).
   */
  consume(toolName: string): RateLimitRule | undefined {
    const matchIndex = this.rules.findIndex((r) => globMatch(r.tool, toolName));
    if (matchIndex === -1) return undefined;

    const rule = this.rules[matchIndex]!;
    const bucketKey = `${matchIndex}:${toolName}`;
    const now = Date.now();

    let bucket = this.buckets.get(bucketKey);
    if (!bucket) {
      bucket = { tokens: rule.capacity, lastRefillAt: now };
      this.buckets.set(bucketKey, bucket);
    }

    // Refill tokens proportionally to elapsed time (continuous rate).
    const elapsedMs = now - bucket.lastRefillAt;
    const refillAmount = (elapsedMs / rule.windowMs) * rule.capacity;
    bucket.tokens = Math.min(rule.capacity, bucket.tokens + refillAmount);
    bucket.lastRefillAt = now;

    if (bucket.tokens < 1) {
      // Time until the next token becomes available.
      const msPerToken = rule.windowMs / rule.capacity;
      const retryAfterMs = msPerToken * (1 - bucket.tokens);
      throw new RateLimitError(toolName, rule, retryAfterMs);
    }

    bucket.tokens -= 1;
    return rule;
  }

  /**
   * Returns the current state of all active buckets — useful for diagnostics
   * and the `warden stats` command.
   */
  snapshot(): Array<{ key: string; tokens: number; capacity: number; windowMs: number }> {
    return Array.from(this.buckets.entries()).map(([key, bucket]) => {
      const ruleIndex = parseInt(key.split(':')[0]!, 10);
      const rule = this.rules[ruleIndex]!;
      return {
        key,
        tokens: Math.min(rule.capacity, bucket.tokens),
        capacity: rule.capacity,
        windowMs: rule.windowMs,
      };
    });
  }

  /** Resets all buckets — useful in tests. */
  reset(): void {
    this.buckets.clear();
  }
}

// ─── Factory ─────────────────────────────────────────────────────────────────

export function createRateLimiter(config: RateLimitConfig): RateLimiter | null {
  if (!config.enabled || !config.rules || config.rules.length === 0) return null;
  return new RateLimiter(config.rules);
}
