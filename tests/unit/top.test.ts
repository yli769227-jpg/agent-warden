/**
 * Unit tests for `warden top` — tool call leaderboard.
 *
 * Uses --once flag so the process exits after one render (no live loop).
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-top-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeLog(tmpDir: string, entries: object[]): string {
  const logFile = path.join(tmpDir, 'audit.jsonl');
  fs.writeFileSync(logFile, entries.map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');
  return logFile;
}

function runTop(
  args: string[],
  logFile: string,
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'top', '--once', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
    timeout: 10_000,
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

const ENTRIES = [
  // fs/read_file: 4 calls (3 allow, 1 deny) — most popular
  { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read_file',  verdict: 'allow',  durationMs: 10 },
  { ts: '2026-01-01T10:01:00.000Z', tool: 'fs/read_file',  verdict: 'allow',  durationMs: 8  },
  { ts: '2026-01-01T10:02:00.000Z', tool: 'fs/read_file',  verdict: 'deny',   durationMs: 2  },
  { ts: '2026-01-01T10:03:00.000Z', tool: 'fs/read_file',  verdict: 'allow',  durationMs: 6  },
  // fs/write_file: 2 calls (1 allow, 1 killed)
  { ts: '2026-01-01T10:04:00.000Z', tool: 'fs/write_file', verdict: 'allow',  durationMs: 15 },
  { ts: '2026-01-01T10:05:00.000Z', tool: 'fs/write_file', verdict: 'killed', durationMs: 1  },
  // github/list: 1 call
  { ts: '2026-01-01T10:06:00.000Z', tool: 'github/list',   verdict: 'allow',  durationMs: 50 },
];

describe('warden top --once', () => {
  let tmpDir: string;
  let logFile: string;

  beforeEach(() => {
    tmpDir  = makeTmpDir();
    logFile = writeLog(tmpDir, ENTRIES);
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0', () => {
    const { status } = runTop([], logFile);
    expect(status).toBe(0);
  });

  test('2. output contains "warden top" header', () => {
    const { stdout } = runTop([], logFile);
    // strip ANSI for matching
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '').replace(/\x1b\[[0-9;]*[A-Z]/g, '');
    expect(plain).toMatch(/warden top/i);
  });

  test('3. most-called tool appears first', () => {
    const { stdout } = runTop([], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    const readPos  = plain.indexOf('fs/read_file');
    const writePos = plain.indexOf('fs/write_file');
    expect(readPos).toBeGreaterThanOrEqual(0);
    expect(writePos).toBeGreaterThanOrEqual(0);
    expect(readPos).toBeLessThan(writePos); // read appears before write
  });

  test('4. all three tools appear in output', () => {
    const { stdout } = runTop([], logFile);
    expect(stdout).toMatch(/fs\/read_file/);
    expect(stdout).toMatch(/fs\/write_file/);
    expect(stdout).toMatch(/github\/list/);
  });

  test('5. --n 2 limits output to top 2 tools', () => {
    const { stdout } = runTop(['--n', '2'], logFile);
    // fs/read_file and fs/write_file should appear; github/list should not
    expect(stdout).toMatch(/fs\/read_file/);
    expect(stdout).toMatch(/fs\/write_file/);
    expect(stdout).not.toMatch(/github\/list/);
  });

  test('6. shows call count totals for each tool', () => {
    const { stdout } = runTop([], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    // fs/read_file has 4 total calls
    expect(plain).toMatch(/4/);
    // fs/write_file has 2 total calls
    expect(plain).toMatch(/2/);
  });

  test('7. shows column headers: Calls / Allow / Deny / Killed', () => {
    const { stdout } = runTop([], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/calls/i);
    expect(plain).toMatch(/allow/i);
    expect(plain).toMatch(/deny/i);
    expect(plain).toMatch(/killed/i);
  });

  test('8. shows avg ms column', () => {
    const { stdout } = runTop([], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/avg ms/i);
  });

  test('9. empty log → "No data" message, exits 0', () => {
    const emptyLog = path.join(tmpDir, 'empty.jsonl');
    fs.writeFileSync(emptyLog, '', 'utf8');
    const { stdout, status } = runTop([], emptyLog);
    expect(status).toBe(0);
    expect(stdout).toMatch(/no data/i);
  });

  test('10. missing log → "No data" message (not a crash), exits 0', () => {
    const missingLog = path.join(tmpDir, 'missing.jsonl');
    const { stdout, status } = runTop([], missingLog);
    // top doesn't exit(1) on missing log — just shows no data
    expect(status).toBe(0);
    expect(stdout).toMatch(/no data/i);
  });
});
