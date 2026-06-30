/**
 * Unit tests for `warden heat-map` — hour × weekday activity heat map.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-hmap-test-${suffix}`);
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
  const r = spawnSync(process.execPath, [CLI, 'heat-map', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

// Known timestamps: 2026-01-01 (Thursday UTC = weekday 4)
// Hours 10 and 15 have entries
const ENTRIES = [
  { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read_file', verdict: 'allow', durationMs: 5 },
  { ts: '2026-01-01T10:05:00.000Z', tool: 'fs/read_file', verdict: 'allow', durationMs: 5 },
  { ts: '2026-01-01T10:10:00.000Z', tool: 'fs/write_file', verdict: 'deny', durationMs: 3 },
  { ts: '2026-01-01T15:00:00.000Z', tool: 'github/create', verdict: 'allow', durationMs: 12 },
  // 2026-01-02 = Friday (weekday 5)
  { ts: '2026-01-02T09:00:00.000Z', tool: 'fs/read_file', verdict: 'allow', durationMs: 8 },
  { ts: '2026-01-02T09:15:00.000Z', tool: 'fs/read_file', verdict: 'killed', durationMs: 1 },
];

describe('warden heat-map', () => {
  let tmpDir: string;
  let logFile: string;

  beforeEach(() => {
    tmpDir  = makeTmpDir();
    logFile = writeLog(tmpDir, ENTRIES);
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0', () => {
    expect(run([], logFile).status).toBe(0);
  });

  test('2. output contains "heat-map" header', () => {
    const { stdout } = run([], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/heat.?map/i);
  });

  test('3. output shows total call count (6)', () => {
    const { stdout } = run([], logFile);
    expect(stdout).toMatch(/6 calls/);
  });

  test('4. --json produces valid JSON', () => {
    const { stdout } = run(['--json'], logFile);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('5. --json total = 6', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { total: number };
    expect(r.total).toBe(6);
  });

  test('6. --json has rows array with 7 elements (weekdays)', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { rows: unknown[] };
    expect(r.rows.length).toBe(7);
  });

  test('7. --json Thu row has calls at hour 10', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { rows: Array<{ day: string; hours: Array<{ hour: number; calls: number }> }> };
    const thu = r.rows.find(row => row.day === 'Thu');
    expect(thu).toBeDefined();
    const hour10 = thu!.hours.find(h => h.hour === 10);
    expect(hour10?.calls).toBe(3); // 2 allow + 1 deny
  });

  test('8. --json Thu row hour 10 has 1 denied call', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { rows: Array<{ day: string; hours: Array<{ hour: number; denied: number }> }> };
    const thu = r.rows.find(row => row.day === 'Thu');
    const hour10 = thu!.hours.find(h => h.hour === 10);
    expect(hour10?.denied).toBe(1);
  });

  test('9. --json Fri row has 2 calls at hour 9', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { rows: Array<{ day: string; hours: Array<{ hour: number; calls: number }> }> };
    const fri = r.rows.find(row => row.day === 'Fri');
    const hour9 = fri!.hours.find(h => h.hour === 9);
    expect(hour9?.calls).toBe(2);
  });

  test('10. --tool filter restricts to matching tools', () => {
    const { stdout } = run(['--json', '--tool', 'fs/read_file'], logFile);
    const r = JSON.parse(stdout) as { total: number };
    // fs/read_file entries: 10:00, 10:05, 09:00, 09:15 = 4 entries
    expect(r.total).toBe(4);
  });

  test('11. --since filters entries', () => {
    const { stdout } = run(['--json', '--since', '2026-01-02T00:00:00.000Z'], logFile);
    const r = JSON.parse(stdout) as { total: number };
    // Only 2026-01-02 entries
    expect(r.total).toBe(2);
  });

  test('12. output shows day labels (Mon-Sun)', () => {
    const { stdout } = run([], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/Mon|Tue|Wed|Thu|Fri|Sat|Sun/);
  });

  test('13. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const { status } = run([], missing);
    expect(status).toBe(1);
  });

  test('14. --json rows have "day" and "hours" fields', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { rows: Array<{ day: string; hours: Array<{ hour: number }> }> };
    for (const row of r.rows) {
      expect(typeof row.day).toBe('string');
      expect(Array.isArray(row.hours)).toBe(true);
      expect(row.hours.length).toBe(24);
    }
  });
});
