/**
 * Unit tests for `warden policy-stats` — policy rule hit analysis.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-pstats-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeLog(tmpDir: string, entries: object[]): string {
  const logFile = path.join(tmpDir, 'audit.jsonl');
  fs.writeFileSync(logFile, entries.map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');
  return logFile;
}

function run(
  args: string[],
  logFile: string,
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'policy-stats', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

const SINCE = '2026-01-01T00:00:00.000Z';

// Entries with known reason strings and verdicts:
// "no-writes" fired 3 times (deny×2, allow×1)
// "no-shell" fired 2 times (deny×2)
// 2 entries have no reason = default action
const ENTRIES = [
  { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read',   verdict: 'allow', durationMs: 5 },
  { ts: '2026-01-01T10:01:00.000Z', tool: 'fs/write',  verdict: 'deny',  durationMs: 3, reason: 'no-writes' },
  { ts: '2026-01-01T10:02:00.000Z', tool: 'bash/exec', verdict: 'deny',  durationMs: 2, reason: 'no-shell' },
  { ts: '2026-01-01T10:03:00.000Z', tool: 'fs/write',  verdict: 'deny',  durationMs: 3, reason: 'no-writes' },
  { ts: '2026-01-01T10:04:00.000Z', tool: 'bash/exec', verdict: 'deny',  durationMs: 2, reason: 'no-shell' },
  { ts: '2026-01-01T10:05:00.000Z', tool: 'fs/write',  verdict: 'allow', durationMs: 4, reason: 'no-writes' },
  { ts: '2026-01-01T10:06:00.000Z', tool: 'github/list', verdict: 'allow', durationMs: 20 }, // no reason
];

describe('warden policy-stats', () => {
  let tmpDir: string;
  let logFile: string;

  beforeEach(() => {
    tmpDir  = makeTmpDir();
    logFile = writeLog(tmpDir, ENTRIES);
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0', () => {
    expect(run(['--since', SINCE], logFile).status).toBe(0);
  });

  test('2. output contains "policy-stats" header', () => {
    const { stdout } = run(['--since', SINCE], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/policy.?stats/i);
  });

  test('3. --json produces valid JSON', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('4. --json total = 7', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { total: number };
    expect(r.total).toBe(7);
  });

  test('5. --json uncaught = 2 (no reason field)', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { uncaught: number };
    expect(r.uncaught).toBe(2);
  });

  test('6. --json rules contains "no-writes" with hits = 3', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { rules: Array<{ reason: string; hits: number }> };
    const nw = r.rules.find(x => x.reason === 'no-writes');
    expect(nw).toBeDefined();
    expect(nw!.hits).toBe(3);
  });

  test('7. --json "no-writes" denied = 2, allowed = 1', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { rules: Array<{ reason: string; denied: number; allowed: number }> };
    const nw = r.rules.find(x => x.reason === 'no-writes');
    expect(nw!.denied).toBe(2);
    expect(nw!.allowed).toBe(1);
  });

  test('8. --json rules sorted by hits desc', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { rules: Array<{ hits: number }> };
    for (let i = 1; i < r.rules.length; i++) {
      expect(r.rules[i - 1]!.hits).toBeGreaterThanOrEqual(r.rules[i]!.hits);
    }
  });

  test('9. --json rules contains "no-shell" with hits = 2', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { rules: Array<{ reason: string; hits: number }> };
    const ns = r.rules.find(x => x.reason === 'no-shell');
    expect(ns).toBeDefined();
    expect(ns!.hits).toBe(2);
  });

  test('10. --min-hits 3 excludes "no-shell" (2 hits)', () => {
    const { stdout } = run(['--since', SINCE, '--json', '--min-hits', '3'], logFile);
    const r = JSON.parse(stdout) as { rules: Array<{ reason: string }> };
    const ns = r.rules.find(x => x.reason === 'no-shell');
    expect(ns).toBeUndefined();
  });

  test('11. text output mentions "no-writes"', () => {
    const { stdout } = run(['--since', SINCE], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/no-writes/);
  });

  test('12. --json has uncaughtPct field', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { uncaughtPct: number };
    expect(typeof r.uncaughtPct).toBe('number');
    // 2 uncaught / 7 total = 28%
    expect(r.uncaughtPct).toBe(29); // round(2/7*100) = round(28.57) = 29
  });

  test('13. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const { status } = run(['--since', SINCE], missing);
    expect(status).toBe(1);
  });

  test('14. --json deadRules is an array', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { deadRules: unknown[] };
    expect(Array.isArray(r.deadRules)).toBe(true);
  });
});
