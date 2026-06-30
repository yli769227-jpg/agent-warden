/**
 * Unit tests for `warden scope` — resource access map.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-scope-test-${suffix}`);
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
  const r = spawnSync(process.execPath, [CLI, 'scope', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

// Use timestamps 2 minutes ago so they're within the default 1h window
const NOW = Date.now();
function minsAgo(m: number): string {
  return new Date(NOW - m * 60_000).toISOString();
}

const ENTRIES = [
  {
    ts: minsAgo(55), tool: 'fs/read_file', verdict: 'allow', durationMs: 8,
    args: { path: '/home/user/project/main.ts' },
  },
  {
    ts: minsAgo(50), tool: 'fs/write_file', verdict: 'deny', durationMs: 3,
    args: { path: '/home/user/project/output.txt' },
  },
  {
    ts: minsAgo(45), tool: 'fs/read_file', verdict: 'allow', durationMs: 5,
    args: { path: '/home/user/project/main.ts' }, // same path = should increment count
  },
  {
    ts: minsAgo(40), tool: 'github/get_file', verdict: 'allow', durationMs: 200,
    args: { repo: 'my-org/my-repo', path: '/README.md' },
  },
  {
    ts: minsAgo(35), tool: 'web/fetch', verdict: 'allow', durationMs: 350,
    args: { url: 'https://api.example.com/v1/data' },
  },
  {
    ts: minsAgo(30), tool: 'fs/delete', verdict: 'killed', durationMs: 1,
    args: { path: '/home/user/project/sensitive.key' },
  },
  // Entry outside the default 1h window — should be excluded
  {
    ts: new Date(NOW - 90 * 60_000).toISOString(), // 90 mins ago
    tool: 'fs/read_file', verdict: 'allow', durationMs: 5,
    args: { path: '/old/file.txt' },
  },
];

describe('warden scope', () => {
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

  test('2. output contains "scope" header', () => {
    const { stdout } = run([], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/scope/i);
  });

  test('3. --json produces valid JSON', () => {
    const { stdout } = run(['--json'], logFile);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('4. --json filesystem contains /home/user/project/main.ts', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { filesystem: Array<{ resource: string; calls: number }> };
    const entry = r.filesystem.find(e => e.resource === '/home/user/project/main.ts');
    expect(entry).toBeDefined();
    expect(entry!.calls).toBe(2); // appears twice within window
  });

  test('5. --json filesystem contains /home/user/project/output.txt', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { filesystem: Array<{ resource: string }> };
    const paths = r.filesystem.map(e => e.resource);
    expect(paths).toContain('/home/user/project/output.txt');
  });

  test('6. --json url contains https://api.example.com/v1/data', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { url: Array<{ resource: string }> };
    expect(r.url.length).toBeGreaterThan(0);
    expect(r.url[0]!.resource).toBe('https://api.example.com/v1/data');
  });

  test('7. --json entry includes tools array', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { filesystem: Array<{ resource: string; tools: string[] }> };
    const main = r.filesystem.find(e => e.resource === '/home/user/project/main.ts');
    expect(Array.isArray(main!.tools)).toBe(true);
    expect(main!.tools).toContain('fs/read_file');
  });

  test('8. --json excludes entry from 90 minutes ago (outside default 1h window)', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { filesystem: Array<{ resource: string }> };
    const paths = r.filesystem.map(e => e.resource);
    expect(paths).not.toContain('/old/file.txt');
  });

  test('9. --window 2 includes all entries', () => {
    const { stdout } = run(['--json', '--window', '2'], logFile);
    const r = JSON.parse(stdout) as { filesystem: Array<{ resource: string }> };
    const paths = r.filesystem.map(e => e.resource);
    expect(paths).toContain('/old/file.txt');
  });

  test('10. --json totalCalls is correct (6 entries within 1h window)', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { totalCalls: number };
    expect(r.totalCalls).toBe(6);
  });

  test('11. --tool filters to matching tool', () => {
    const { stdout } = run(['--json', '--tool', 'fs/read_file'], logFile);
    const r = JSON.parse(stdout) as { totalCalls: number };
    expect(r.totalCalls).toBe(2); // only 2 fs/read_file within 1h
  });

  test('12. output shows filesystem paths in text mode', () => {
    const { stdout } = run([], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/\/home\/user\/project/);
  });

  test('13. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const { status } = run([], missing);
    expect(status).toBe(1);
  });

  test('14. --json has "since" field', () => {
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { since: string };
    expect(typeof r.since).toBe('string');
    expect(r.since).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});
