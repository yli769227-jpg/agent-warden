/**
 * Unit tests for `warden profile` — behavioural fingerprint of agent activity.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-profile-test-${suffix}`);
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
  const r = spawnSync(process.execPath, [CLI, 'profile', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

// Known timestamps for deterministic entropy / pair tests
const ENTRIES = [
  { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read_file',  verdict: 'allow', durationMs: 10 },
  { ts: '2026-01-01T10:01:00.000Z', tool: 'fs/read_file',  verdict: 'allow', durationMs: 20 },
  { ts: '2026-01-01T10:02:00.000Z', tool: 'fs/write_file', verdict: 'deny',  durationMs: 5  },
  { ts: '2026-01-01T10:03:00.000Z', tool: 'fs/read_file',  verdict: 'allow', durationMs: 15 },
  { ts: '2026-01-01T10:04:00.000Z', tool: 'github/create', verdict: 'allow', durationMs: 30 },
  { ts: '2026-01-01T10:05:00.000Z', tool: 'fs/read_file',  verdict: 'allow', durationMs: 12 },
  { ts: '2026-01-01T10:06:00.000Z', tool: 'github/list',   verdict: 'allow', durationMs: 8  },
  { ts: '2026-01-01T10:07:00.000Z', tool: 'fs/read_file',  verdict: 'allow', durationMs: 11 },
];

describe('warden profile', () => {
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

  test('2. output contains "profile" header', () => {
    const { stdout } = run([], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/profile/i);
  });

  test('3. output shows total call count (8)', () => {
    const { stdout } = run([], logFile);
    expect(stdout).toMatch(/8/);
  });

  test('4. --json produces valid JSON', () => {
    const { stdout } = run(['--json'], logFile);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('5. --json total = 8', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { total: number };
    expect(r.total).toBe(8);
  });

  test('6. --json uniqueTools = 4', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { uniqueTools: number };
    expect(r.uniqueTools).toBe(4);
  });

  test('7. --json top tool is fs/read_file (5 calls)', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { topTools: Array<{ tool: string; calls: number }> };
    expect(r.topTools[0]!.tool).toBe('fs/read_file');
    expect(r.topTools[0]!.calls).toBe(5);
  });

  test('8. --json entropy > 0 (diverse tools)', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { entropy: number };
    expect(r.entropy).toBeGreaterThan(0);
  });

  test('9. --json topPairs shows adjacent tool transitions', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { topPairs: Array<{ pair: string; count: number }> };
    // fs/read_file → fs/read_file should appear (entries 0→1, 2→3)
    // or fs/read_file → fs/write_file (entry 1→2)
    expect(r.topPairs.length).toBeGreaterThan(0);
    expect(typeof r.topPairs[0]!.pair).toBe('string');
    expect(r.topPairs[0]!.pair).toContain('→');
  });

  test('10. --json avgMs is computed per tool', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { topTools: Array<{ tool: string; avgMs: number }> };
    const readTool = r.topTools.find(t => t.tool === 'fs/read_file');
    expect(readTool).toBeDefined();
    // (10 + 20 + 15 + 12 + 11) / 5 = 68/5 = 13.6 → 14ms
    expect(readTool!.avgMs).toBe(14);
  });

  test('11. --json denied count for fs/write_file = 1', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { topTools: Array<{ tool: string; denied: number }> };
    const writeTool = r.topTools.find(t => t.tool === 'fs/write_file');
    expect(writeTool?.denied).toBe(1);
  });

  test('12. --since filters entries', () => {
    const { stdout } = run(['--json', '--since', '2026-01-01T10:05:00.000Z'], logFile);
    const r = JSON.parse(stdout) as { total: number };
    // Entries at 10:05, 10:06, 10:07 = 3 entries
    expect(r.total).toBe(3);
  });

  test('13. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const { status } = run([], missing);
    expect(status).toBe(1);
  });

  test('14. --top N limits tool list', () => {
    const { stdout } = run(['--json', '--top', '2'], logFile);
    const r = JSON.parse(stdout) as { topTools: unknown[] };
    expect(r.topTools.length).toBe(2);
  });
});
