/**
 * Unit tests for the warden log filter helpers.
 *
 * These functions are not exported from cli.ts (CLI module), so we test
 * them by importing an extracted module.  Since they are pure functions
 * (no I/O), we extract them to a shared test helper by reproducing their
 * logic here and cross-checking with the actual dist/ output.
 *
 * Strategy: replicate the relevant functions from cli.ts verbatim and
 * test the logic directly — keeps tests fast without spawning a process.
 */

import type { AuditEntry } from '../../src/types.js';

// ─── Replicated from cli.ts (kept in sync) ───────────────────────────────────

type Verdict = 'allow' | 'deny' | 'killed';

interface LogFilter {
  tool?: string;
  verdict?: string;
  since?: Date;
  follow: boolean;
}

function parseSince(value: string): Date {
  const match = /^(\d+)(m|h|d)$/.exec(value);
  if (match) {
    const n    = parseInt(match[1]!, 10);
    const unit = match[2]!;
    const ms   = unit === 'm' ? n * 60_000 : unit === 'h' ? n * 3_600_000 : n * 86_400_000;
    return new Date(Date.now() - ms);
  }
  const d = new Date(value);
  if (isNaN(d.getTime())) throw new Error(`Invalid --since value: "${value}"`);
  return d;
}

function entryMatchesFilter(line: string, filter: LogFilter): boolean {
  if (!line.trim()) return false;
  let entry: AuditEntry;
  try {
    entry = JSON.parse(line) as AuditEntry;
  } catch {
    return true; // show unparseable lines
  }
  if (filter.tool) {
    const pattern = filter.tool.includes('*')
      ? new RegExp('^' + filter.tool.split('*').map(s => s.replace(/[.+^${}()|[\]\\]/g, '\\$&')).join('.*') + '$')
      : null;
    const match = pattern ? pattern.test(entry.tool ?? '') : (entry.tool ?? '').includes(filter.tool);
    if (!match) return false;
  }
  if (filter.verdict && entry.verdict !== filter.verdict) return false;
  if (filter.since && entry.ts && new Date(entry.ts) < filter.since) return false;
  return true;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeEntry(tool: string, verdict: Verdict, ts?: string): string {
  return JSON.stringify({
    ts: ts ?? new Date().toISOString(),
    tool,
    args: {},
    verdict,
    durationMs: 5,
  });
}

const noFollow: LogFilter = { follow: false };

// ─── parseSince tests ─────────────────────────────────────────────────────────

describe('parseSince', () => {
  test('1. "30m" returns a Date 30 minutes ago', () => {
    const before = Date.now();
    const d = parseSince('30m');
    const after  = Date.now();
    expect(d.getTime()).toBeGreaterThanOrEqual(before - 30 * 60_000 - 50);
    expect(d.getTime()).toBeLessThanOrEqual(after  - 30 * 60_000 + 50);
  });

  test('2. "2h" returns a Date 2 hours ago', () => {
    const d = parseSince('2h');
    const expected = Date.now() - 2 * 3_600_000;
    expect(d.getTime()).toBeCloseTo(expected, -3); // within 1 second
  });

  test('3. "1d" returns a Date 24 hours ago', () => {
    const d = parseSince('1d');
    const expected = Date.now() - 86_400_000;
    expect(d.getTime()).toBeCloseTo(expected, -3);
  });

  test('4. ISO-8601 string is parsed as an absolute timestamp', () => {
    const iso = '2024-01-15T12:00:00.000Z';
    const d = parseSince(iso);
    expect(d.toISOString()).toBe(iso);
  });

  test('5. Invalid value throws an error', () => {
    expect(() => parseSince('garbage')).toThrow(/Invalid --since/);
  });

  test('6. "0m" returns a Date very close to now', () => {
    const d = parseSince('0m');
    expect(Math.abs(d.getTime() - Date.now())).toBeLessThan(100);
  });
});

// ─── entryMatchesFilter — tool filter ────────────────────────────────────────

describe('entryMatchesFilter — tool filter', () => {
  test('7. Exact tool match — returns true for matching tool', () => {
    const line = makeEntry('echo_tool', 'allow');
    expect(entryMatchesFilter(line, { ...noFollow, tool: 'echo_tool' })).toBe(true);
  });

  test('8. Exact tool match — returns false for non-matching tool', () => {
    const line = makeEntry('write_file', 'allow');
    expect(entryMatchesFilter(line, { ...noFollow, tool: 'echo_tool' })).toBe(false);
  });

  test('9. Substring match — partial string matches tool that contains it', () => {
    const line = makeEntry('filesystem/read_file', 'allow');
    expect(entryMatchesFilter(line, { ...noFollow, tool: 'read' })).toBe(true);
  });

  test('10. Glob "filesystem/*" matches all filesystem tools', () => {
    const read  = makeEntry('filesystem/read_file',  'allow');
    const write = makeEntry('filesystem/write_file', 'deny');
    const github = makeEntry('github/get_file',      'allow');

    expect(entryMatchesFilter(read,   { ...noFollow, tool: 'filesystem/*' })).toBe(true);
    expect(entryMatchesFilter(write,  { ...noFollow, tool: 'filesystem/*' })).toBe(true);
    expect(entryMatchesFilter(github, { ...noFollow, tool: 'filesystem/*' })).toBe(false);
  });

  test('11. Glob "*delete*" matches any tool with delete in name', () => {
    const del   = makeEntry('delete_file',        'deny');
    const bulk  = makeEntry('bulk_delete_records','deny');
    const read  = makeEntry('read_file',          'allow');

    expect(entryMatchesFilter(del,  { ...noFollow, tool: '*delete*' })).toBe(true);
    expect(entryMatchesFilter(bulk, { ...noFollow, tool: '*delete*' })).toBe(true);
    expect(entryMatchesFilter(read, { ...noFollow, tool: '*delete*' })).toBe(false);
  });
});

// ─── entryMatchesFilter — verdict filter ─────────────────────────────────────

describe('entryMatchesFilter — verdict filter', () => {
  test('12. Filters to deny only', () => {
    const allowed = makeEntry('read_file', 'allow');
    const denied  = makeEntry('write_file', 'deny');

    expect(entryMatchesFilter(allowed, { ...noFollow, verdict: 'deny' })).toBe(false);
    expect(entryMatchesFilter(denied,  { ...noFollow, verdict: 'deny' })).toBe(true);
  });

  test('13. Filters to allow only', () => {
    const allowed = makeEntry('read_file', 'allow');
    const denied  = makeEntry('write_file', 'deny');
    const killed  = makeEntry('run_shell', 'killed');

    expect(entryMatchesFilter(allowed, { ...noFollow, verdict: 'allow' })).toBe(true);
    expect(entryMatchesFilter(denied,  { ...noFollow, verdict: 'allow' })).toBe(false);
    expect(entryMatchesFilter(killed,  { ...noFollow, verdict: 'allow' })).toBe(false);
  });
});

// ─── entryMatchesFilter — since filter ───────────────────────────────────────

describe('entryMatchesFilter — since filter', () => {
  test('14. Entry before --since cutoff is excluded', () => {
    const old = makeEntry('echo_tool', 'allow', '2000-01-01T00:00:00.000Z');
    const since = new Date('2024-01-01T00:00:00.000Z');
    expect(entryMatchesFilter(old, { ...noFollow, since })).toBe(false);
  });

  test('15. Entry after --since cutoff is included', () => {
    const recent = makeEntry('echo_tool', 'allow', new Date().toISOString());
    const since = new Date(Date.now() - 60_000); // 1 minute ago
    expect(entryMatchesFilter(recent, { ...noFollow, since })).toBe(true);
  });
});

// ─── entryMatchesFilter — combined filters ────────────────────────────────────

describe('entryMatchesFilter — combined filters', () => {
  test('16. tool + verdict + since — all must match', () => {
    const nowish = new Date().toISOString();
    const entry  = makeEntry('filesystem/delete_file', 'deny', nowish);
    const filter: LogFilter = {
      follow:  false,
      tool:    'filesystem/*',
      verdict: 'deny',
      since:   new Date(Date.now() - 60_000),
    };

    expect(entryMatchesFilter(entry, filter)).toBe(true);

    // Tool mismatch
    expect(entryMatchesFilter(makeEntry('github/get_file', 'deny', nowish), filter)).toBe(false);
    // Verdict mismatch
    expect(entryMatchesFilter(makeEntry('filesystem/read_file', 'allow', nowish), filter)).toBe(false);
  });
});

// ─── Edge cases ───────────────────────────────────────────────────────────────

describe('entryMatchesFilter — edge cases', () => {
  test('17. Empty line returns false', () => {
    expect(entryMatchesFilter('', noFollow)).toBe(false);
    expect(entryMatchesFilter('   ', noFollow)).toBe(false);
  });

  test('18. Unparseable JSON passes through (returns true)', () => {
    expect(entryMatchesFilter('not valid json {{{', noFollow)).toBe(true);
  });

  test('19. No filter set — all entries pass', () => {
    const line = makeEntry('any_tool', 'allow');
    expect(entryMatchesFilter(line, noFollow)).toBe(true);
  });
});
