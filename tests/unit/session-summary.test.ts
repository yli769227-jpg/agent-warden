/**
 * Unit tests for `warden session-summary` — session clustering and per-session metrics.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-ss-test-${suffix}`);
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
  const r = spawnSync(process.execPath, [CLI, 'session-summary', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

// Two sessions separated by 20 minutes (default gap=10min → split into 2 sessions)
// Session A: 10:00-10:04
// Session B: 10:25-10:27
const BASE = '2026-01-01T';
const SINCE = '2026-01-01T00:00:00.000Z';

const ENTRIES = [
  // Session A: 5 calls, 10:00-10:04
  { ts: `${BASE}10:00:00.000Z`, tool: 'fs/read_file',  verdict: 'allow',  durationMs: 5,  args: { path: '/home/user/a.ts' } },
  { ts: `${BASE}10:01:00.000Z`, tool: 'fs/read_file',  verdict: 'allow',  durationMs: 5,  args: { path: '/home/user/a.ts' } },
  { ts: `${BASE}10:02:00.000Z`, tool: 'fs/write_file', verdict: 'deny',   durationMs: 3,  args: { path: '/home/user/b.ts' } },
  { ts: `${BASE}10:03:00.000Z`, tool: 'fs/read_file',  verdict: 'allow',  durationMs: 5,  args: {} },
  { ts: `${BASE}10:04:00.000Z`, tool: 'bash/exec',     verdict: 'killed', durationMs: 1,  args: {} },

  // Gap of 21 minutes → triggers new session

  // Session B: 3 calls, 10:25-10:27
  { ts: `${BASE}10:25:00.000Z`, tool: 'github/list',   verdict: 'allow',  durationMs: 20, args: { url: 'https://api.github.com' } },
  { ts: `${BASE}10:26:00.000Z`, tool: 'github/list',   verdict: 'allow',  durationMs: 20, args: {} },
  { ts: `${BASE}10:27:00.000Z`, tool: 'github/create', verdict: 'deny',   durationMs: 5,  args: {} },
];

const BASE_FLAGS = ['--since', SINCE];

describe('warden session-summary', () => {
  let tmpDir: string;
  let logFile: string;

  beforeEach(() => {
    tmpDir  = makeTmpDir();
    logFile = writeLog(tmpDir, ENTRIES);
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0', () => {
    expect(run(BASE_FLAGS, logFile).status).toBe(0);
  });

  test('2. output contains "session-summary" header', () => {
    const { stdout } = run(BASE_FLAGS, logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/session.?summary/i);
  });

  test('3. --json produces valid JSON', () => {
    const { stdout } = run([...BASE_FLAGS, '--json'], logFile);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('4. --json detects 2 sessions (gap=10min)', () => {
    const { stdout } = run([...BASE_FLAGS, '--json'], logFile);
    const r = JSON.parse(stdout) as { totalSessions: number };
    expect(r.totalSessions).toBe(2);
  });

  test('5. --json session A has 5 calls', () => {
    const { stdout } = run([...BASE_FLAGS, '--json'], logFile);
    const r = JSON.parse(stdout) as { sessions: Array<{ calls: number }> };
    expect(r.sessions[0]!.calls).toBe(5);
  });

  test('6. --json session B has 3 calls', () => {
    const { stdout } = run([...BASE_FLAGS, '--json'], logFile);
    const r = JSON.parse(stdout) as { sessions: Array<{ calls: number }> };
    expect(r.sessions[1]!.calls).toBe(3);
  });

  test('7. --json session A denied=1, killed=1', () => {
    const { stdout } = run([...BASE_FLAGS, '--json'], logFile);
    const r = JSON.parse(stdout) as { sessions: Array<{ denied: number; killed: number }> };
    expect(r.sessions[0]!.denied).toBe(1);
    expect(r.sessions[0]!.killed).toBe(1);
  });

  test('8. --json session A top tool is fs/read_file', () => {
    const { stdout } = run([...BASE_FLAGS, '--json'], logFile);
    const r = JSON.parse(stdout) as { sessions: Array<{ topTools: Array<{ tool: string }> }> };
    expect(r.sessions[0]!.topTools[0]!.tool).toBe('fs/read_file');
  });

  test('9. --json session A topPaths contains /home/user/a.ts', () => {
    const { stdout } = run([...BASE_FLAGS, '--json'], logFile);
    const r = JSON.parse(stdout) as { sessions: Array<{ topPaths: Array<{ path: string }> }> };
    const paths = r.sessions[0]!.topPaths.map(p => p.path);
    expect(paths).toContain('/home/user/a.ts');
  });

  test('10. --gap-mins 30 merges both sessions into one', () => {
    const { stdout } = run([...BASE_FLAGS, '--json', '--gap-mins', '30'], logFile);
    const r = JSON.parse(stdout) as { totalSessions: number };
    expect(r.totalSessions).toBe(1);
  });

  test('11. --last 1 returns only the last session', () => {
    const { stdout } = run([...BASE_FLAGS, '--json', '--last', '1'], logFile);
    const r = JSON.parse(stdout) as { sessions: Array<{ id: number }> };
    expect(r.sessions.length).toBe(1);
    expect(r.sessions[0]!.id).toBe(2); // Session B is id=2
  });

  test('12. --json session has grade field', () => {
    const { stdout } = run([...BASE_FLAGS, '--json'], logFile);
    const r = JSON.parse(stdout) as { sessions: Array<{ grade: string }> };
    expect(typeof r.sessions[0]!.grade).toBe('string');
    expect(['CLEAN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).toContain(r.sessions[0]!.grade);
  });

  test('13. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const { status } = run(BASE_FLAGS, missing);
    expect(status).toBe(1);
  });

  test('14. --min-calls 4 excludes session B (3 calls)', () => {
    const { stdout } = run([...BASE_FLAGS, '--json', '--min-calls', '4'], logFile);
    const r = JSON.parse(stdout) as { totalSessions: number };
    expect(r.totalSessions).toBe(1); // only session A (5 calls) passes
  });
});
