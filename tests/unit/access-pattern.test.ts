/**
 * Unit tests for `warden access-pattern` — resource access analysis.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-ap-test-${suffix}`);
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
  const r = spawnSync(process.execPath, [CLI, 'access-pattern', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

const SINCE = '2026-01-01T00:00:00.000Z';

// Known distribution:
//   /home/user/config.yaml → 4 accesses (3 read, 1 write, 1 denied)
//   /tmp/scratch.txt       → 2 accesses (2 write)
//   /etc/passwd            → 1 access (1 read, 1 denied)
const ENTRIES = [
  { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read',  verdict: 'allow', durationMs: 5, args: { path: '/home/user/config.yaml' } },
  { ts: '2026-01-01T10:01:00.000Z', tool: 'fs/read',  verdict: 'allow', durationMs: 5, args: { path: '/home/user/config.yaml' } },
  { ts: '2026-01-01T10:02:00.000Z', tool: 'fs/read',  verdict: 'allow', durationMs: 5, args: { path: '/home/user/config.yaml' } },
  { ts: '2026-01-01T10:03:00.000Z', tool: 'fs/write', verdict: 'deny',  durationMs: 3, args: { path: '/home/user/config.yaml' } },
  { ts: '2026-01-01T10:04:00.000Z', tool: 'fs/write', verdict: 'allow', durationMs: 3, args: { path: '/tmp/scratch.txt' } },
  { ts: '2026-01-01T10:05:00.000Z', tool: 'fs/write', verdict: 'allow', durationMs: 3, args: { path: '/tmp/scratch.txt' } },
  { ts: '2026-01-01T10:06:00.000Z', tool: 'fs/read',  verdict: 'deny',  durationMs: 5, args: { path: '/etc/passwd' } },
];

describe('warden access-pattern', () => {
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

  test('2. output contains "access-pattern" header', () => {
    const { stdout } = run(['--since', SINCE], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/access.?pattern/i);
  });

  test('3. --json produces valid JSON', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('4. --json resources[0] is /home/user/config.yaml (total 4)', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { resources: Array<{ resource: string; total: number }> };
    expect(r.resources[0]?.resource).toBe('/home/user/config.yaml');
    expect(r.resources[0]?.total).toBe(4);
  });

  test('5. --json /home/user/config.yaml has read=3, write=1', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { resources: Array<{ resource: string; read: number; write: number }> };
    const cfg = r.resources.find(x => x.resource === '/home/user/config.yaml');
    expect(cfg?.read).toBe(3);
    expect(cfg?.write).toBe(1);
  });

  test('6. --json /home/user/config.yaml has denied=1', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { resources: Array<{ resource: string; denied: number; denyRate: number }> };
    const cfg = r.resources.find(x => x.resource === '/home/user/config.yaml');
    expect(cfg?.denied).toBe(1);
    expect(cfg?.denyRate).toBe(25); // 1/4 = 25%
  });

  test('7. --json /tmp/scratch.txt has write=2', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { resources: Array<{ resource: string; write: number }> };
    const tmp = r.resources.find(x => x.resource === '/tmp/scratch.txt');
    expect(tmp?.write).toBe(2);
  });

  test('8. --json resources sorted by total desc', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { resources: Array<{ total: number }> };
    for (let i = 1; i < r.resources.length; i++) {
      expect(r.resources[i - 1]!.total).toBeGreaterThanOrEqual(r.resources[i]!.total);
    }
  });

  test('9. --json each resource has topTools array', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { resources: Array<{ topTools: unknown[] }> };
    for (const res of r.resources) {
      expect(Array.isArray(res.topTools)).toBe(true);
    }
  });

  test('10. --top 1 limits to 1 resource', () => {
    const { stdout } = run(['--since', SINCE, '--json', '--top', '1'], logFile);
    const r = JSON.parse(stdout) as { resources: unknown[] };
    expect(r.resources.length).toBe(1);
  });

  test('11. --min-count 3 excludes /etc/passwd (1 access)', () => {
    const { stdout } = run(['--since', SINCE, '--json', '--min-count', '3'], logFile);
    const r = JSON.parse(stdout) as { resources: Array<{ resource: string }> };
    expect(r.resources.find(x => x.resource === '/etc/passwd')).toBeUndefined();
  });

  test('12. --tool fs/write filters to write-only entries', () => {
    const { stdout } = run(['--since', SINCE, '--json', '--tool', 'fs/write'], logFile);
    const r = JSON.parse(stdout) as { resources: Array<{ resource: string; read: number }> };
    // Only /tmp/scratch.txt has fs/write accesses (config also has 1 write but also reads)
    // All resources found via --tool fs/write should have 0 reads (filter excludes fs/read entries)
    for (const res of r.resources) {
      expect(res.read).toBe(0);
    }
  });

  test('13. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const { status } = run(['--since', SINCE], missing);
    expect(status).toBe(1);
  });

  test('14. log with no args fields outputs "No resource paths found"', () => {
    const noArgsLog = writeLog(tmpDir, [
      { ts: '2026-01-01T10:00:00.000Z', tool: 'noop', verdict: 'allow', durationMs: 5 },
    ]);
    const { stdout } = run(['--since', SINCE], noArgsLog);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/No resource paths found/i);
  });
});
