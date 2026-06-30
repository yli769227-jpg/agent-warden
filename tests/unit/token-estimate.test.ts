/**
 * Unit tests for `warden token-estimate` — LLM token consumption estimator.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-tke-test-${suffix}`);
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
  const r = spawnSync(process.execPath, [CLI, 'token-estimate', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

const SINCE = '2026-01-01T00:00:00.000Z';

// Entries with known args sizes:
// fs/read_file: args = {"path":"/home/user/file.txt"} = 27 chars
// github/list: args = {"repo":"org/repo","per_page":100} = 36 chars
// bash/exec: args = {"cmd":"ls -la /home/user"} = 26 chars
const ENTRIES = [
  {
    ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read_file',
    verdict: 'allow', durationMs: 5,
    args: { path: '/home/user/file.txt' },
  },
  {
    ts: '2026-01-01T10:01:00.000Z', tool: 'fs/read_file',
    verdict: 'allow', durationMs: 5,
    args: { path: '/home/user/file.txt' },
  },
  {
    ts: '2026-01-01T10:02:00.000Z', tool: 'github/list',
    verdict: 'allow', durationMs: 20,
    args: { repo: 'org/repo', per_page: 100 },
  },
  {
    ts: '2026-01-01T10:03:00.000Z', tool: 'bash/exec',
    verdict: 'deny', durationMs: 2,
    args: { cmd: 'ls -la /home/user' },
  },
];

describe('warden token-estimate', () => {
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

  test('2. output contains "token-estimate" header', () => {
    const { stdout } = run(['--since', SINCE], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/token.?estimate/i);
  });

  test('3. --json produces valid JSON', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('4. --json totalCalls = 4', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { totalCalls: number };
    expect(r.totalCalls).toBe(4);
  });

  test('5. --json totalChars is positive', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { totalChars: number };
    expect(r.totalChars).toBeGreaterThan(0);
  });

  test('6. --json totalTokens = ceil(totalChars / 4)', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { totalChars: number; totalTokens: number };
    expect(r.totalTokens).toBe(Math.round(r.totalChars / 4));
  });

  test('7. --json topTools is sorted by chars desc', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { topTools: Array<{ chars: number }> };
    for (let i = 1; i < r.topTools.length; i++) {
      expect(r.topTools[i - 1]!.chars).toBeGreaterThanOrEqual(r.topTools[i]!.chars);
    }
  });

  test('8. --json topTools fs/read_file has calls = 2', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { topTools: Array<{ tool: string; calls: number }> };
    const read = r.topTools.find(t => t.tool === 'fs/read_file');
    expect(read).toBeDefined();
    expect(read!.calls).toBe(2);
  });

  test('9. --json topTools entry has pctOfTotal field', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { topTools: Array<{ pctOfTotal: number }> };
    for (const t of r.topTools) {
      expect(typeof t.pctOfTotal).toBe('number');
      expect(t.pctOfTotal).toBeGreaterThanOrEqual(0);
    }
  });

  test('10. --tool filter restricts totalCalls to 2', () => {
    const { stdout } = run(['--since', SINCE, '--json', '--tool', 'fs/read_file'], logFile);
    const r = JSON.parse(stdout) as { totalCalls: number };
    expect(r.totalCalls).toBe(2);
  });

  test('11. --chars-per-token 2 doubles the token count', () => {
    const { stdout4 } = run(['--since', SINCE, '--json'], logFile) as unknown as { stdout4: string };
    const { stdout: std4 } = run(['--since', SINCE, '--json'], logFile);
    const { stdout: std2 } = run(['--since', SINCE, '--json', '--chars-per-token', '2'], logFile);
    const r4 = JSON.parse(std4) as { totalTokens: number; totalChars: number };
    const r2 = JSON.parse(std2) as { totalTokens: number };
    expect(r2.totalTokens).toBe(Math.round(r4.totalChars / 2));
  });

  test('12. --json has "since" and "charsPerToken" fields', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { since: string; charsPerToken: number };
    expect(r.since).toBe(SINCE);
    expect(r.charsPerToken).toBe(4);
  });

  test('13. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const { status } = run(['--since', SINCE], missing);
    expect(status).toBe(1);
  });

  test('14. no-args log shows 0 tokens (no args field)', () => {
    const noArgsLog = writeLog(tmpDir, [
      { ts: '2026-01-01T10:00:00.000Z', tool: 'noop', verdict: 'allow', durationMs: 1 },
    ]);
    const { stdout } = run(['--since', SINCE, '--json'], noArgsLog);
    const r = JSON.parse(stdout) as { totalTokens: number };
    expect(r.totalTokens).toBe(0);
  });
});
