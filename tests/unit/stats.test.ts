/**
 * Unit tests for `warden stats` — aggregate statistics from audit log.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-stats-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeLog(tmpDir: string, entries: object[]): string {
  const logFile = path.join(tmpDir, 'audit.jsonl');
  fs.writeFileSync(logFile, entries.map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');
  return logFile;
}

function runStats(
  args: string[],
  logFile: string,
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'stats', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

const ENTRIES = [
  { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read_file',  verdict: 'allow',  durationMs: 10 },
  { ts: '2026-01-01T10:01:00.000Z', tool: 'fs/read_file',  verdict: 'allow',  durationMs: 20 },
  { ts: '2026-01-01T10:02:00.000Z', tool: 'fs/write_file', verdict: 'deny',   durationMs: 5  },
  { ts: '2026-01-01T10:03:00.000Z', tool: 'github/create', verdict: 'allow',  durationMs: 30 },
  { ts: '2026-01-01T11:00:00.000Z', tool: 'fs/read_file',  verdict: 'killed', durationMs: 1  },
];

describe('warden stats', () => {
  let tmpDir: string;
  let logFile: string;

  beforeEach(() => {
    tmpDir  = makeTmpDir();
    logFile = writeLog(tmpDir, ENTRIES);
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0 on valid log', () => {
    const { status } = runStats([], logFile);
    expect(status).toBe(0);
  });

  test('2. --json outputs valid JSON', () => {
    const { stdout, status } = runStats(['--json'], logFile);
    expect(status).toBe(0);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('3. --json total matches entry count', () => {
    const { stdout } = runStats(['--json'], logFile);
    const result = JSON.parse(stdout) as { total: number };
    expect(result.total).toBe(5);
  });

  test('4. --json byVerdict has correct counts', () => {
    const { stdout } = runStats(['--json'], logFile);
    const result = JSON.parse(stdout) as { byVerdict: Record<string, number> };
    expect(result.byVerdict['allow']).toBe(3);
    expect(result.byVerdict['deny']).toBe(1);
    expect(result.byVerdict['killed']).toBe(1);
  });

  test('5. --json topTools orders by descending call count', () => {
    const { stdout } = runStats(['--json'], logFile);
    const result = JSON.parse(stdout) as { topTools: Array<{ tool: string; count: number }> };
    // fs/read_file has 3 calls (most), github/create has 1
    expect(result.topTools[0]!.tool).toBe('fs/read_file');
    expect(result.topTools[0]!.count).toBe(3);
  });

  test('6. --since filters entries by timestamp', () => {
    // Only entry at 11:00 is after 10:30
    const { stdout } = runStats(['--json', '--since', '2026-01-01T10:30:00.000Z'], logFile);
    const result = JSON.parse(stdout) as { total: number };
    expect(result.total).toBe(1);
  });

  test('7. exits 1 when log file is missing', () => {
    const missingLog = path.join(tmpDir, 'missing.jsonl');
    const { status } = runStats([], missingLog);
    expect(status).toBe(1);
  });

  test('8. --json on missing file returns JSON error object', () => {
    const missingLog = path.join(tmpDir, 'missing.jsonl');
    const { stdout } = runStats(['--json'], missingLog);
    const result = JSON.parse(stdout) as { error: string };
    expect(result.error).toMatch(/not found/i);
  });

  test('9. text output contains allow / deny counts', () => {
    const { stdout } = runStats([], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/allow/i);
    expect(plain).toMatch(/deny|kill/i);
  });

  test('10. text output contains tool name', () => {
    const { stdout } = runStats([], logFile);
    expect(stdout).toMatch(/fs\/read_file/);
  });
});
