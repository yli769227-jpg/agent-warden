/**
 * Unit tests for `warden snapshot` — save timestamped JSON audit stats.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-snapshot-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeLog(tmpDir: string, entries: object[]): string {
  const logFile = path.join(tmpDir, 'audit.jsonl');
  fs.writeFileSync(logFile, entries.map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');
  return logFile;
}

function runSnapshot(
  args: string[],
  logFile: string,
  cwd: string,
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'snapshot', ...args], {
    encoding: 'utf8',
    cwd,
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

const ENTRIES = [
  { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read_file',  verdict: 'allow',  durationMs: 10 },
  { ts: '2026-01-01T10:01:00.000Z', tool: 'fs/read_file',  verdict: 'allow',  durationMs: 20 },
  { ts: '2026-01-01T10:02:00.000Z', tool: 'fs/write_file', verdict: 'deny',   durationMs: 5  },
  { ts: '2026-01-01T10:03:00.000Z', tool: 'github/create', verdict: 'allow',  durationMs: 30 },
  { ts: '2026-01-01T10:04:00.000Z', tool: 'fs/read_file',  verdict: 'killed', durationMs: 1  },
];

type Snapshot = {
  version:    number;
  snapshotAt: string;
  logFile:    string;
  tag?:       string;
  period:     { first: string | null; last: string | null };
  totals:     { calls: number; allow: number; deny: number; killed: number; denyRate: number };
  latency:    { avgMs: number | null; p95Ms: number | null };
  topTools:   Array<{ tool: string; total: number }>;
};

describe('warden snapshot', () => {
  let tmpDir: string;
  let logFile: string;

  beforeEach(() => {
    tmpDir  = makeTmpDir();
    logFile = writeLog(tmpDir, ENTRIES);
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0', () => {
    const outPath = path.join(tmpDir, 'snap.json');
    const { status } = runSnapshot(['--output', outPath], logFile, tmpDir);
    expect(status).toBe(0);
  });

  test('2. creates the output file', () => {
    const outPath = path.join(tmpDir, 'snap.json');
    runSnapshot(['--output', outPath], logFile, tmpDir);
    expect(fs.existsSync(outPath)).toBe(true);
  });

  test('3. output file is valid JSON', () => {
    const outPath = path.join(tmpDir, 'snap.json');
    runSnapshot(['--output', outPath], logFile, tmpDir);
    const content = fs.readFileSync(outPath, 'utf8');
    expect(() => JSON.parse(content)).not.toThrow();
  });

  test('4. snapshot has correct total call count', () => {
    const outPath = path.join(tmpDir, 'snap.json');
    runSnapshot(['--output', outPath], logFile, tmpDir);
    const snap = JSON.parse(fs.readFileSync(outPath, 'utf8')) as Snapshot;
    expect(snap.totals.calls).toBe(5);
  });

  test('5. snapshot has correct allow/deny/killed breakdown', () => {
    const outPath = path.join(tmpDir, 'snap.json');
    runSnapshot(['--output', outPath], logFile, tmpDir);
    const snap = JSON.parse(fs.readFileSync(outPath, 'utf8')) as Snapshot;
    expect(snap.totals.allow).toBe(3);
    expect(snap.totals.deny).toBe(1);
    expect(snap.totals.killed).toBe(1);
  });

  test('6. deny rate is computed correctly (40%)', () => {
    const outPath = path.join(tmpDir, 'snap.json');
    runSnapshot(['--output', outPath], logFile, tmpDir);
    const snap = JSON.parse(fs.readFileSync(outPath, 'utf8')) as Snapshot;
    expect(snap.totals.denyRate).toBe(40);
  });

  test('7. --tag embeds label in snapshot', () => {
    const outPath = path.join(tmpDir, 'snap.json');
    runSnapshot(['--output', outPath, '--tag', 'pr-99'], logFile, tmpDir);
    const snap = JSON.parse(fs.readFileSync(outPath, 'utf8')) as Snapshot;
    expect(snap.tag).toBe('pr-99');
  });

  test('8. snapshot has version field', () => {
    const outPath = path.join(tmpDir, 'snap.json');
    runSnapshot(['--output', outPath], logFile, tmpDir);
    const snap = JSON.parse(fs.readFileSync(outPath, 'utf8')) as Snapshot;
    expect(snap.version).toBe(1);
  });

  test('9. topTools sorted by descending call count', () => {
    const outPath = path.join(tmpDir, 'snap.json');
    runSnapshot(['--output', outPath], logFile, tmpDir);
    const snap = JSON.parse(fs.readFileSync(outPath, 'utf8')) as Snapshot;
    // fs/read_file has 3 calls (most)
    expect(snap.topTools[0]!.tool).toBe('fs/read_file');
    expect(snap.topTools[0]!.total).toBe(3);
  });

  test('10. latency avgMs is populated', () => {
    const outPath = path.join(tmpDir, 'snap.json');
    runSnapshot(['--output', outPath], logFile, tmpDir);
    const snap = JSON.parse(fs.readFileSync(outPath, 'utf8')) as Snapshot;
    expect(snap.latency.avgMs).not.toBeNull();
    expect(typeof snap.latency.avgMs).toBe('number');
  });

  test('11. --since filters entries', () => {
    const outPath = path.join(tmpDir, 'snap.json');
    runSnapshot([
      '--output', outPath,
      '--since', '2026-01-01T10:03:00.000Z',
    ], logFile, tmpDir);
    const snap = JSON.parse(fs.readFileSync(outPath, 'utf8')) as Snapshot;
    // Only entries at 10:03 and 10:04
    expect(snap.totals.calls).toBe(2);
  });

  test('12. stdout shows "Snapshot saved" confirmation', () => {
    const outPath = path.join(tmpDir, 'snap.json');
    const { stdout } = runSnapshot(['--output', outPath], logFile, tmpDir);
    expect(stdout).toMatch(/snapshot saved/i);
  });

  test('13. missing log file → snapshot with 0 calls (no crash)', () => {
    const missingLog = path.join(tmpDir, 'missing.jsonl');
    const outPath    = path.join(tmpDir, 'snap.json');
    const { status } = runSnapshot(['--output', outPath], missingLog, tmpDir);
    expect(status).toBe(0);
    const snap = JSON.parse(fs.readFileSync(outPath, 'utf8')) as Snapshot;
    expect(snap.totals.calls).toBe(0);
  });

  test('14. --print emits JSON to stdout', () => {
    const outPath = path.join(tmpDir, 'snap.json');
    const { stdout } = runSnapshot(['--output', outPath, '--print'], logFile, tmpDir);
    // --print also shows the full JSON
    expect(() => {
      // Extract the JSON part (after the "Snapshot saved" line)
      const jsonStart = stdout.indexOf('{');
      JSON.parse(stdout.slice(jsonStart));
    }).not.toThrow();
  });

  test('15. default output path is created in CWD', () => {
    // Run without --output — should create warden-snapshot-*.json in CWD
    const { stdout } = runSnapshot([], logFile, tmpDir);
    const match = stdout.match(/warden-snapshot-[\dT-]+\.json/);
    expect(match).not.toBeNull();
    const defaultPath = path.join(tmpDir, match![0]!);
    expect(fs.existsSync(defaultPath)).toBe(true);
    // Clean up
    if (fs.existsSync(defaultPath)) fs.unlinkSync(defaultPath);
  });
});
