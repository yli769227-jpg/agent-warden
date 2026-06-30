import { RateLimiter, RateLimitError, createRateLimiter } from '../../src/ratelimit.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeLimiter(tool: string, capacity: number, windowMs: number): RateLimiter {
  return new RateLimiter([{ tool, capacity, windowMs }]);
}

// ─── Basic operation ──────────────────────────────────────────────────────────

describe('RateLimiter — basic bucket operation', () => {
  test('1. allows calls up to capacity', () => {
    const limiter = makeLimiter('echo_tool', 3, 1000);
    expect(() => limiter.consume('echo_tool')).not.toThrow();
    expect(() => limiter.consume('echo_tool')).not.toThrow();
    expect(() => limiter.consume('echo_tool')).not.toThrow();
  });

  test('2. blocks the call after capacity exhausted', () => {
    const limiter = makeLimiter('echo_tool', 2, 1000);
    limiter.consume('echo_tool');
    limiter.consume('echo_tool');
    expect(() => limiter.consume('echo_tool')).toThrow(RateLimitError);
  });

  test('3. RateLimitError carries tool name and rule', () => {
    const limiter = makeLimiter('write_file', 1, 500);
    limiter.consume('write_file');
    let caught: RateLimitError | null = null;
    try { limiter.consume('write_file'); } catch (e) { caught = e as RateLimitError; }
    expect(caught).not.toBeNull();
    expect(caught?.tool).toBe('write_file');
    expect(caught?.rule.capacity).toBe(1);
    expect(caught?.rule.windowMs).toBe(500);
    expect(caught?.retryAfterMs).toBeGreaterThan(0);
    expect(caught?.message).toMatch(/Rate limit exceeded/);
    expect(caught?.message).toMatch(/write_file/);
  });

  test('4. tools not matching any rule are never rate-limited', () => {
    const limiter = makeLimiter('blocked_tool', 0, 1000);
    // Capacity 0 means even the first call would fail — but only for matching tools.
    // A completely different tool should not be affected.
    const limiterSafe = makeLimiter('blocked_tool', 1, 1000);
    expect(limiterSafe.consume('other_tool')).toBeUndefined();
    expect(limiterSafe.consume('other_tool')).toBeUndefined(); // unlimited
  });

  test('5. reset() clears all buckets so capacity is restored', () => {
    const limiter = makeLimiter('echo_tool', 1, 10_000);
    limiter.consume('echo_tool');
    expect(() => limiter.consume('echo_tool')).toThrow(RateLimitError);
    limiter.reset();
    expect(() => limiter.consume('echo_tool')).not.toThrow();
  });
});

// ─── Glob matching ────────────────────────────────────────────────────────────

describe('RateLimiter — glob matching', () => {
  test('6. wildcard rule limits each matching tool independently', () => {
    // Each tool matched by a glob gets its own per-tool bucket.
    // capacity:2 means each individual tool is limited to 2 calls per window.
    const limiter = new RateLimiter([{ tool: 'github/*', capacity: 2, windowMs: 1000 }]);

    // github/list_repos gets 2 calls before being blocked
    limiter.consume('github/list_repos');
    limiter.consume('github/list_repos');
    expect(() => limiter.consume('github/list_repos')).toThrow(RateLimitError);

    // github/get_file has its own bucket — also allows 2 before blocking
    limiter.consume('github/get_file');
    limiter.consume('github/get_file');
    expect(() => limiter.consume('github/get_file')).toThrow(RateLimitError);
  });

  test('7. global wildcard "*" limits each tool to its own capacity', () => {
    // The "*" rule matches every tool, but each tool has its own bucket.
    const limiter = new RateLimiter([{ tool: '*', capacity: 2, windowMs: 1000 }]);

    limiter.consume('read_file');
    limiter.consume('read_file');
    expect(() => limiter.consume('read_file')).toThrow(RateLimitError);

    // write_file starts fresh — it has not used its 2 tokens yet
    limiter.consume('write_file');
    limiter.consume('write_file');
    expect(() => limiter.consume('write_file')).toThrow(RateLimitError);
  });

  test('8. first matching rule wins; later rules are ignored', () => {
    const limiter = new RateLimiter([
      { tool: 'echo_tool', capacity: 10, windowMs: 1000 }, // generous limit
      { tool: '*',         capacity: 1,  windowMs: 1000 }, // tight global limit
    ]);
    // echo_tool matches the first rule (capacity 10), not the second (capacity 1)
    for (let i = 0; i < 5; i++) {
      expect(() => limiter.consume('echo_tool')).not.toThrow();
    }
  });
});

// ─── Token refill ─────────────────────────────────────────────────────────────

describe('RateLimiter — token refill', () => {
  test('9. tokens partially refill after elapsed time', async () => {
    const limiter = makeLimiter('read_file', 2, 100); // 2 calls / 100ms
    limiter.consume('read_file');
    limiter.consume('read_file');
    expect(() => limiter.consume('read_file')).toThrow(RateLimitError);

    // Wait for roughly half a window — should refill ~1 token
    await new Promise((r) => setTimeout(r, 55));

    // Should allow at least one more call
    expect(() => limiter.consume('read_file')).not.toThrow();
  });
});

// ─── Snapshot ─────────────────────────────────────────────────────────────────

describe('RateLimiter — snapshot', () => {
  test('10. snapshot returns bucket state for consumed tools', () => {
    const limiter = makeLimiter('ping', 5, 1000);
    expect(limiter.snapshot()).toHaveLength(0); // no bucket yet

    limiter.consume('ping');
    limiter.consume('ping');
    const snap = limiter.snapshot();
    expect(snap).toHaveLength(1);
    expect(snap[0]?.capacity).toBe(5);
    expect(snap[0]?.tokens).toBeLessThanOrEqual(3); // 5 - 2 = 3 (or slightly less)
    expect(snap[0]?.windowMs).toBe(1000);
  });
});

// ─── Factory ─────────────────────────────────────────────────────────────────

describe('createRateLimiter', () => {
  test('11. returns null when disabled', () => {
    expect(createRateLimiter({ enabled: false })).toBeNull();
  });

  test('12. returns null when enabled but no rules', () => {
    expect(createRateLimiter({ enabled: true, rules: [] })).toBeNull();
  });

  test('13. returns RateLimiter when enabled with rules', () => {
    const rl = createRateLimiter({
      enabled: true,
      rules: [{ tool: '*', capacity: 10, windowMs: 1000 }],
    });
    expect(rl).toBeInstanceOf(RateLimiter);
  });
});
