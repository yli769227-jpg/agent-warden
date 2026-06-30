/**
 * Unit tests for `warden sparkline` — vertical block-char activity timeline.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-sl-test-${suffix}`);
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
  const r = spawnSync(process.execPath, [CLI, 'sparkline', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

const SINCE = '2026-01-01T10:00:00.000Z'; // entries start at 10:00
const WINDOW_H = 2; // 2-hour window: 10:00 → 12:00, covers all entries

// 6 calls spread across the 2-hour window
const ENTRIES = [
  { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read',   verdict: 'allow', durationMs: 5 },
  { ts: '2026-01-01T10:15:00.000Z', tool: 'fs/write',  verdict: 'deny',  durationMs: 3 },
  { ts: '2026-01-01T10:30:00.000Z', tool: 'fs/read',   verdict: 'allow', durationMs: 5 },
  { ts: '2026-01-01T10:45:00.000Z', tool: 'git/commit', verdict: 'allow', durationMs: 10 },
  { ts: '2026-01-01T11:00:00.000Z', tool: 'bash/exec',  verdict: 'deny',  durationMs: 5 },
  { ts: '2026-01-01T11:30:00.000Z', tool: 'fs/read',   verdict: 'allow', durationMs: 5 },
];

describe('warden sparkline', () => {
  let tmpDir: string;
  let logFile: string;

  beforeEach(() => {
    tmpDir  = makeTmpDir();
    logFile = writeLog(tmpDir, ENTRIES);
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0', () => {
    expect(run(['--since', SINCE, '--window', String(WINDOW_H)], logFile).status).toBe(0);
  });

  test('2. output contains "sparkline" header', () => {
    const { stdout } = run(['--since', SINCE, '--window', String(WINDOW_H)], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/sparkline/i);
  });

  test('3. --json produces valid JSON', () => {
    const { stdout } = run(['--since', SINCE, '--window', String(WINDOW_H), '--json'], logFile);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('4. --json has since, end, windowHours, totalCalls, buckets', () => {
    const { stdout } = run(['--since', SINCE, '--window', String(WINDOW_H), '--json'], logFile);
    const r = JSON.parse(stdout) as { since: string; end: string; windowHours: number; totalCalls: number; buckets: unknown[] };
    expect(typeof r.since).toBe('string');
    expect(typeof r.end).toBe('string');
    expect(r.windowHours).toBe(WINDOW_H);
    expect(r.totalCalls).toBe(6);
    expect(Array.isArray(r.buckets)).toBe(true);
  });

  test('5. --json buckets count equals --buckets N', () => {
    const { stdout } = run(['--since', SINCE, '--window', String(WINDOW_H), '--json', '--buckets', '10'], logFile);
    const r = JSON.parse(stdout) as { buckets: unknown[] };
    expect(r.buckets.length).toBe(10);
  });

  test('6. --json each bucket has total and denied fields', () => {
    const { stdout } = run(['--since', SINCE, '--window', String(WINDOW_H), '--json', '--buckets', '4'], logFile);
    const r = JSON.parse(stdout) as { buckets: Array<{ total: number; denied: number }> };
    for (const b of r.buckets) {
      expect(typeof b.total).toBe('number');
      expect(typeof b.denied).toBe('number');
    }
  });

  test('7. --json totalCalls = sum of all bucket totals', () => {
    const { stdout } = run(['--since', SINCE, '--window', String(WINDOW_H), '--json', '--buckets', '8'], logFile);
    const r = JSON.parse(stdout) as { totalCalls: number; buckets: Array<{ total: number }> };
    const sum = r.buckets.reduce((s, b) => s + b.total, 0);
    expect(sum).toBe(r.totalCalls);
  });

  test('8. --json denied buckets have denied > 0', () => {
    const { stdout } = run(['--since', SINCE, '--window', String(WINDOW_H), '--json', '--buckets', '8'], logFile);
    const r = JSON.parse(stdout) as { buckets: Array<{ denied: number }> };
    const anyDenied = r.buckets.some(b => b.denied > 0);
    expect(anyDenied).toBe(true); // we have 2 denied entries
  });

  test('9. output has multiple rows (height > 1)', () => {
    const { stdout } = run(['--since', SINCE, '--window', String(WINDOW_H), '--height', '3'], logFile);
    const plainLines = stdout.replace(/\x1b\[[0-9;]*m/g, '').split('\n');
    // At least 3 non-empty lines (3 chart rows + header/footer)
    const nonEmpty = plainLines.filter(l => l.trim().length > 0);
    expect(nonEmpty.length).toBeGreaterThanOrEqual(3);
  });

  test('10. --tool fs/read filters to only read calls', () => {
    const { stdout } = run(['--since', SINCE, '--window', String(WINDOW_H), '--json', '--tool', 'fs/read'], logFile);
    const r = JSON.parse(stdout) as { totalCalls: number };
    expect(r.totalCalls).toBe(3); // 3 fs/read calls in ENTRIES
  });

  test('11. --buckets 1 produces single bucket with all calls', () => {
    const { stdout } = run(['--since', SINCE, '--window', String(WINDOW_H), '--json', '--buckets', '1'], logFile);
    const r = JSON.parse(stdout) as { buckets: Array<{ total: number }> };
    expect(r.buckets.length).toBe(1);
    expect(r.buckets[0]!.total).toBe(6);
  });

  test('12. entries outside window are excluded', () => {
    // Use a very short window that covers only the first two entries
    const tinyWindow = 0.3; // 18 minutes from SINCE, covers first entry only
    const { stdout } = run(['--since', SINCE, '--window', String(tinyWindow), '--json'], logFile);
    const r = JSON.parse(stdout) as { totalCalls: number };
    expect(r.totalCalls).toBeLessThan(6);
  });

  test('13. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const { status } = run(['--since', SINCE, '--window', String(WINDOW_H)], missing);
    expect(status).toBe(1);
  });

  test('14. empty log produces output with totalCalls = 0', () => {
    const empty = writeLog(tmpDir, []);
    const { stdout } = run(['--since', SINCE, '--window', String(WINDOW_H), '--json'], empty);
    const r = JSON.parse(stdout) as { totalCalls: number };
    expect(r.totalCalls).toBe(0);
  });
});
