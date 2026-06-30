/**
 * Unit tests for `warden top-denied` — most-blocked tools and denial reasons.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-td-test-${suffix}`);
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
  const r = spawnSync(process.execPath, [CLI, 'top-denied', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

const SINCE = '2026-01-01T00:00:00.000Z';

// Known distribution:
//   bash/exec → denied 5× (reason: no-shell ×4, unverified ×1) + killed 1× (no-shell)
//   fs/write  → denied 3× (reason: no-writes ×3)
//   fs/read   → allowed 4×
// Total denied+killed: bash/exec=6, fs/write=3, fs/read=0
const ENTRIES = [
  { ts: '2026-01-01T10:00:00.000Z', tool: 'bash/exec', verdict: 'deny',   reason: 'no-shell',  durationMs: 5 },
  { ts: '2026-01-01T10:01:00.000Z', tool: 'bash/exec', verdict: 'deny',   reason: 'no-shell',  durationMs: 5 },
  { ts: '2026-01-01T10:02:00.000Z', tool: 'bash/exec', verdict: 'deny',   reason: 'no-shell',  durationMs: 5 },
  { ts: '2026-01-01T10:03:00.000Z', tool: 'bash/exec', verdict: 'deny',   reason: 'no-shell',  durationMs: 5 },
  { ts: '2026-01-01T10:04:00.000Z', tool: 'bash/exec', verdict: 'deny',   reason: 'unverified', durationMs: 5 },
  { ts: '2026-01-01T10:05:00.000Z', tool: 'bash/exec', verdict: 'killed', reason: 'no-shell',  durationMs: 5 },
  { ts: '2026-01-01T10:06:00.000Z', tool: 'fs/write',  verdict: 'deny',   reason: 'no-writes', durationMs: 3 },
  { ts: '2026-01-01T10:07:00.000Z', tool: 'fs/write',  verdict: 'deny',   reason: 'no-writes', durationMs: 3 },
  { ts: '2026-01-01T10:08:00.000Z', tool: 'fs/write',  verdict: 'deny',   reason: 'no-writes', durationMs: 3 },
  { ts: '2026-01-01T10:09:00.000Z', tool: 'fs/read',   verdict: 'allow',  durationMs: 2 },
  { ts: '2026-01-01T10:10:00.000Z', tool: 'fs/read',   verdict: 'allow',  durationMs: 2 },
  { ts: '2026-01-01T10:11:00.000Z', tool: 'fs/read',   verdict: 'allow',  durationMs: 2 },
  { ts: '2026-01-01T10:12:00.000Z', tool: 'fs/read',   verdict: 'allow',  durationMs: 2 },
];

describe('warden top-denied', () => {
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

  test('2. output contains "top-denied" header', () => {
    const { stdout } = run(['--since', SINCE], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/top.?denied/i);
  });

  test('3. --json produces valid JSON', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('4. --json topTools[0] is bash/exec (6 total denials)', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { topTools: Array<{ tool: string; total: number }> };
    expect(r.topTools[0]?.tool).toBe('bash/exec');
    expect(r.topTools[0]?.total).toBe(6);
  });

  test('5. --json topTools[1] is fs/write (3 denials)', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { topTools: Array<{ tool: string; total: number }> };
    expect(r.topTools[1]?.tool).toBe('fs/write');
    expect(r.topTools[1]?.total).toBe(3);
  });

  test('6. --json fs/read does NOT appear in topTools (0 denials)', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { topTools: Array<{ tool: string }> };
    expect(r.topTools.find(t => t.tool === 'fs/read')).toBeUndefined();
  });

  test('7. --json topTools bash/exec has denied=5, killed=1', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { topTools: Array<{ tool: string; denied: number; killed: number }> };
    const be = r.topTools.find(t => t.tool === 'bash/exec');
    expect(be?.denied).toBe(5);
    expect(be?.killed).toBe(1);
  });

  test('8. --json bash/exec top reason is no-shell (5 hits)', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as {
      topTools: Array<{ tool: string; reasons: Array<{ reason: string; count: number }> }>
    };
    const be = r.topTools.find(t => t.tool === 'bash/exec');
    expect(be?.reasons[0]?.reason).toBe('no-shell');
    expect(be?.reasons[0]?.count).toBe(5);
  });

  test('9. --json topReasons[0] is no-shell (5 denials)', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { topReasons: Array<{ reason: string; total: number }> };
    expect(r.topReasons[0]?.reason).toBe('no-shell');
    expect(r.topReasons[0]?.total).toBe(5);
  });

  test('10. --json topReasons has tools array in each entry', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { topReasons: Array<{ tools: unknown[] }> };
    for (const entry of r.topReasons) {
      expect(Array.isArray(entry.tools)).toBe(true);
    }
  });

  test('11. --top 1 limits topTools to 1 entry', () => {
    const { stdout } = run(['--since', SINCE, '--json', '--top', '1'], logFile);
    const r = JSON.parse(stdout) as { topTools: unknown[] };
    expect(r.topTools.length).toBe(1);
  });

  test('12. --min-count 4 excludes fs/write (3 total)', () => {
    const { stdout } = run(['--since', SINCE, '--json', '--min-count', '4'], logFile);
    const r = JSON.parse(stdout) as { topTools: Array<{ tool: string }> };
    expect(r.topTools.find(t => t.tool === 'fs/write')).toBeUndefined();
  });

  test('13. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const { status } = run(['--since', SINCE], missing);
    expect(status).toBe(1);
  });

  test('14. all-allow log outputs "No denied or killed calls found"', () => {
    const allowLog = writeLog(tmpDir, [
      { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read', verdict: 'allow', durationMs: 2 },
    ]);
    const { stdout } = run(['--since', SINCE], allowLog);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/No denied or killed calls found/i);
  });
});
