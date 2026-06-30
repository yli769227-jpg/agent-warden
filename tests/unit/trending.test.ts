/**
 * Unit tests for `warden trending` — shows rising/falling tool call rates.
 *
 * Strategy: write entries with explicit timestamps using an old "now" (so
 * the window comparison is deterministic) and pass --window large enough to
 * capture all entries.
 *
 * We use a window of 200 hours so we can place test entries 0-200 hours
 * before "now" without depending on the real wall clock.
 *
 * Because trending splits the window in half, entries in the FIRST half
 * should show "first=N", entries in SECOND half should show "second=N".
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-trending-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeLog(tmpDir: string, entries: object[]): string {
  const logFile = path.join(tmpDir, 'audit.jsonl');
  fs.writeFileSync(logFile, entries.map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');
  return logFile;
}

function runTrending(
  args: string[],
  logFile: string,
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'trending', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

// All timestamps relative to "now" (test runtime) so we use a big window
// to make results deterministic without mocking Date.now.
const NOW = Date.now();
function hoursAgo(h: number): string {
  return new Date(NOW - h * 3_600_000).toISOString();
}

// With window=24h, midpoint is at -12h:
//   first half  = entries between 24h ago and 12h ago
//   second half = entries between 12h ago and now

const ENTRIES = [
  // fs/read_file: 1 in first half, 5 in second half → rising
  { ts: hoursAgo(20), tool: 'fs/read_file', verdict: 'allow', durationMs: 5 },
  { ts: hoursAgo(3),  tool: 'fs/read_file', verdict: 'allow', durationMs: 5 },
  { ts: hoursAgo(2),  tool: 'fs/read_file', verdict: 'allow', durationMs: 5 },
  { ts: hoursAgo(1),  tool: 'fs/read_file', verdict: 'allow', durationMs: 5 },
  { ts: hoursAgo(0.5),tool: 'fs/read_file', verdict: 'allow', durationMs: 5 },
  { ts: hoursAgo(0.1),tool: 'fs/read_file', verdict: 'allow', durationMs: 5 },
  // fs/write_file: 4 in first half, 1 in second half → falling
  { ts: hoursAgo(23), tool: 'fs/write_file', verdict: 'deny', durationMs: 3 },
  { ts: hoursAgo(22), tool: 'fs/write_file', verdict: 'deny', durationMs: 3 },
  { ts: hoursAgo(21), tool: 'fs/write_file', verdict: 'deny', durationMs: 3 },
  { ts: hoursAgo(15), tool: 'fs/write_file', verdict: 'deny', durationMs: 3 },
  { ts: hoursAgo(2),  tool: 'fs/write_file', verdict: 'deny', durationMs: 3 },
  // github/list: 2+2 = stable
  { ts: hoursAgo(20), tool: 'github/list', verdict: 'allow', durationMs: 10 },
  { ts: hoursAgo(16), tool: 'github/list', verdict: 'allow', durationMs: 10 },
  { ts: hoursAgo(5),  tool: 'github/list', verdict: 'allow', durationMs: 10 },
  { ts: hoursAgo(1),  tool: 'github/list', verdict: 'allow', durationMs: 10 },
];

describe('warden trending', () => {
  let tmpDir: string;
  let logFile: string;

  beforeEach(() => {
    tmpDir  = makeTmpDir();
    logFile = writeLog(tmpDir, ENTRIES);
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0', () => {
    const { status } = runTrending(['--window', '24'], logFile);
    expect(status).toBe(0);
  });

  test('2. output contains "trending" header', () => {
    const { stdout } = runTrending(['--window', '24'], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/trending/i);
  });

  test('3. fs/read_file appears in rising section', () => {
    const { stdout } = runTrending(['--window', '24', '--min-calls', '2'], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    // Rising section + tool name
    const risingIdx = plain.indexOf('Rising');
    const fsIdx     = plain.indexOf('fs/read_file');
    expect(risingIdx).toBeGreaterThan(-1);
    expect(fsIdx).toBeGreaterThan(-1);
    expect(fsIdx).toBeGreaterThan(risingIdx);
  });

  test('4. fs/write_file appears in falling section', () => {
    const { stdout } = runTrending(['--window', '24', '--min-calls', '2'], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    const fallingIdx = plain.indexOf('Falling');
    const writeIdx   = plain.indexOf('fs/write_file');
    expect(fallingIdx).toBeGreaterThan(-1);
    expect(writeIdx).toBeGreaterThan(-1);
    expect(writeIdx).toBeGreaterThan(fallingIdx);
  });

  test('5. --json produces valid JSON', () => {
    const { stdout } = runTrending(['--window', '24', '--json', '--min-calls', '2'], logFile);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('6. --json has "rising" array with fs/read_file', () => {
    const { stdout } = runTrending(['--window', '24', '--json', '--min-calls', '2'], logFile);
    const result = JSON.parse(stdout) as { rising: Array<{ tool: string }> };
    expect(Array.isArray(result.rising)).toBe(true);
    const entry = result.rising.find(t => t.tool === 'fs/read_file');
    expect(entry).toBeDefined();
  });

  test('7. --json has "falling" array with fs/write_file', () => {
    const { stdout } = runTrending(['--window', '24', '--json', '--min-calls', '2'], logFile);
    const result = JSON.parse(stdout) as { falling: Array<{ tool: string }> };
    const entry = result.falling.find(t => t.tool === 'fs/write_file');
    expect(entry).toBeDefined();
  });

  test('8. --json rising entry has delta>0', () => {
    const { stdout } = runTrending(['--window', '24', '--json', '--min-calls', '2'], logFile);
    const result = JSON.parse(stdout) as { rising: Array<{ tool: string; delta: number }> };
    const entry = result.rising.find(t => t.tool === 'fs/read_file');
    expect(entry!.delta).toBeGreaterThan(0);
  });

  test('9. --json falling entry has delta<0', () => {
    const { stdout } = runTrending(['--window', '24', '--json', '--min-calls', '2'], logFile);
    const result = JSON.parse(stdout) as { falling: Array<{ tool: string; delta: number }> };
    const entry = result.falling.find(t => t.tool === 'fs/write_file');
    expect(entry!.delta).toBeLessThan(0);
  });

  test('10. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const r = spawnSync(process.execPath, [CLI, 'trending', '--window', '24'], {
      encoding: 'utf8',
      env: { ...process.env, WARDEN_LOG: missing },
    });
    expect(r.status).toBe(1);
  });

  test('11. --min-calls filter excludes low-count tools', () => {
    // With min-calls=100, nothing should appear (all tools have <16 calls)
    const { stdout } = runTrending(['--window', '24', '--json', '--min-calls', '100'], logFile);
    const result = JSON.parse(stdout) as { rising: unknown[]; falling: unknown[] };
    expect(result.rising.length).toBe(0);
    expect(result.falling.length).toBe(0);
  });

  test('12. --window affects how many entries are included', () => {
    // With window=1h, only entries in last 1 hour are included
    // (only ~3 fs/read_file entries at 0.5h, 0.1h, 3h — 3h would be excluded)
    const { stdout } = runTrending(['--window', '1', '--json', '--min-calls', '1'], logFile);
    const result = JSON.parse(stdout) as { rising: unknown[]; falling: unknown[]; flat: unknown[] };
    // Fewer tools visible than with 24h window
    const total24 = (() => {
      const r = spawnSync(process.execPath, [CLI, 'trending', '--window', '24', '--json', '--min-calls', '1'], {
        encoding: 'utf8',
        env: { ...process.env, WARDEN_LOG: logFile },
      });
      const res = JSON.parse(r.stdout) as { rising: unknown[]; falling: unknown[]; flat: unknown[] };
      return res.rising.length + res.falling.length + res.flat.length;
    })();
    const total1h = result.rising.length + result.falling.length + result.flat.length;
    expect(total1h).toBeLessThanOrEqual(total24);
  });
});
