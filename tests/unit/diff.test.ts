/**
 * Unit tests for `warden diff` — before/after period comparison.
 *
 * diff compares tool call patterns across two time windows around a split point.
 * We write a synthetic JSONL log with known timestamps and verify the comparison.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-diff-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeLog(tmpDir: string, entries: object[]): string {
  const logFile = path.join(tmpDir, 'audit.jsonl');
  fs.writeFileSync(logFile, entries.map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');
  return logFile;
}

function runDiff(
  args: string[],
  logFile: string,
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'diff', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

// Split at 12:00; before = 10:00–12:00; after = 12:00–14:00
const SPLIT = '2026-01-01T12:00:00.000Z';
const ENTRIES = [
  // Before period (10:00–11:59)
  { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read_file',  verdict: 'allow', durationMs: 10 },
  { ts: '2026-01-01T10:30:00.000Z', tool: 'fs/read_file',  verdict: 'allow', durationMs: 12 },
  { ts: '2026-01-01T11:00:00.000Z', tool: 'fs/write_file', verdict: 'deny',  durationMs: 5  },
  // After period (12:01–13:59) — note: 12:01 not 12:00 to avoid boundary overlap
  { ts: '2026-01-01T12:01:00.000Z', tool: 'fs/read_file',  verdict: 'allow', durationMs: 8  },
  { ts: '2026-01-01T12:30:00.000Z', tool: 'fs/write_file', verdict: 'allow', durationMs: 6  },
  { ts: '2026-01-01T13:00:00.000Z', tool: 'github/create', verdict: 'allow', durationMs: 20 },
  { ts: '2026-01-01T13:30:00.000Z', tool: 'github/create', verdict: 'deny',  durationMs: 3  },
];

describe('warden diff', () => {
  let tmpDir: string;
  let logFile: string;

  beforeEach(() => {
    tmpDir  = makeTmpDir();
    logFile = writeLog(tmpDir, ENTRIES);
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0', () => {
    const { status } = runDiff(['--split', SPLIT, '--window', '2h'], logFile);
    expect(status).toBe(0);
  });

  test('2. text output contains "Warden diff" header', () => {
    const { stdout } = runDiff(['--split', SPLIT, '--window', '2h'], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/warden diff/i);
  });

  test('3. --json produces valid JSON', () => {
    const { stdout, status } = runDiff(['--split', SPLIT, '--window', '2h', '--json'], logFile);
    expect(status).toBe(0);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('4. --json output has "before" and "after" fields', () => {
    const { stdout } = runDiff(['--split', SPLIT, '--window', '2h', '--json'], logFile);
    const result = JSON.parse(stdout) as { before: unknown; after: unknown; split: string };
    expect(result.before).toBeDefined();
    expect(result.after).toBeDefined();
    expect(result.split).toBe(SPLIT);
  });

  test('5. --json before period has correct total count', () => {
    const { stdout } = runDiff(['--split', SPLIT, '--window', '2h', '--json'], logFile);
    const result = JSON.parse(stdout) as { before: { total: number } };
    // Before: 3 entries between 10:00 and 12:00
    expect(result.before.total).toBe(3);
  });

  test('6. --json after period has correct total count', () => {
    const { stdout } = runDiff(['--split', SPLIT, '--window', '2h', '--json'], logFile);
    const result = JSON.parse(stdout) as { after: { total: number } };
    // After: 4 entries between 12:00 and 14:00
    expect(result.after.total).toBe(4);
  });

  test('7. --json before period shows deny count via byVerdict', () => {
    const { stdout } = runDiff(['--split', SPLIT, '--window', '2h', '--json'], logFile);
    const result = JSON.parse(stdout) as { before: { byVerdict: Record<string, number> } };
    expect(result.before.byVerdict['deny']).toBe(1); // write_file was denied
  });

  test('8. --json window field reflects the window size', () => {
    const { stdout } = runDiff(['--split', SPLIT, '--window', '2h', '--json'], logFile);
    const result = JSON.parse(stdout) as { window: string };
    expect(result.window).toMatch(/2h/);
  });

  test('9. text output shows "Before" and "After" column headers', () => {
    const { stdout } = runDiff(['--split', SPLIT, '--window', '2h'], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/before/i);
    expect(plain).toMatch(/after/i);
  });

  test('10. empty log produces valid output (no crash)', () => {
    const emptyLog = path.join(tmpDir, 'empty.jsonl');
    fs.writeFileSync(emptyLog, '', 'utf8');
    const { status } = runDiff(['--split', SPLIT, '--window', '2h'], emptyLog);
    expect(status).toBe(0);
  });
});
