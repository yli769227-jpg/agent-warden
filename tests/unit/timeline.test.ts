/**
 * Unit tests for `warden timeline` — ASCII bar chart of tool call activity.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-timeline-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeLog(tmpDir: string, entries: object[]): string {
  const logFile = path.join(tmpDir, 'audit.jsonl');
  fs.writeFileSync(logFile, entries.map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');
  return logFile;
}

function runTimeline(
  args: string[],
  logFile: string,
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'timeline', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

// Build a batch of entries spread across 3 hours
const NOW_TS = '2026-06-01T';
const ENTRIES = [
  // 10:00 bucket (3 allow)
  { ts: `${NOW_TS}10:00:00.000Z`, tool: 'fs/read_file', verdict: 'allow', durationMs: 5 },
  { ts: `${NOW_TS}10:10:00.000Z`, tool: 'fs/read_file', verdict: 'allow', durationMs: 5 },
  { ts: `${NOW_TS}10:20:00.000Z`, tool: 'fs/read_file', verdict: 'allow', durationMs: 5 },
  // 10:30 bucket (1 deny)
  { ts: `${NOW_TS}10:30:00.000Z`, tool: 'fs/write_file', verdict: 'deny', durationMs: 3 },
  // 11:00 bucket (2 allow, 1 killed)
  { ts: `${NOW_TS}11:00:00.000Z`, tool: 'github/create', verdict: 'allow', durationMs: 12 },
  { ts: `${NOW_TS}11:10:00.000Z`, tool: 'github/create', verdict: 'allow', durationMs: 8 },
  { ts: `${NOW_TS}11:20:00.000Z`, tool: 'github/delete', verdict: 'killed', durationMs: 1 },
];

describe('warden timeline', () => {
  let tmpDir: string;
  let logFile: string;

  beforeEach(() => {
    tmpDir  = makeTmpDir();
    logFile = writeLog(tmpDir, ENTRIES);
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0', () => {
    const { status } = runTimeline(['--since', '2026-06-01T09:00:00.000Z'], logFile);
    expect(status).toBe(0);
  });

  test('2. output contains "Timeline" header', () => {
    const { stdout } = runTimeline(['--since', '2026-06-01T09:00:00.000Z'], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/timeline/i);
  });

  test('3. output shows total call count', () => {
    const { stdout } = runTimeline(['--since', '2026-06-01T09:00:00.000Z'], logFile);
    // 7 entries total
    expect(stdout).toMatch(/7 calls/i);
  });

  test('4. --bucket 30 groups into 30-minute buckets', () => {
    const { stdout } = runTimeline(['--since', '2026-06-01T09:00:00.000Z', '--bucket', '30'], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    // Should see 10:00 bucket header in output
    expect(plain).toMatch(/10:00/);
  });

  test('5. --split-verdict shows legend with allow/deny/killed', () => {
    const { stdout } = runTimeline(['--since', '2026-06-01T09:00:00.000Z', '--split-verdict'], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/allow/i);
    expect(plain).toMatch(/deny|kill/i);
  });

  test('6. --tool filter restricts to matching entries', () => {
    const { stdout } = runTimeline([
      '--since', '2026-06-01T09:00:00.000Z',
      '--tool', 'fs/read_file',
    ], logFile);
    // Only 3 fs/read_file entries
    expect(stdout).toMatch(/3 calls/i);
  });

  test('7. "bucket:" shows in header', () => {
    const { stdout } = runTimeline(['--since', '2026-06-01T09:00:00.000Z', '--bucket', '60'], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/bucket/i);
  });

  test('8. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'no.jsonl');
    const r = spawnSync(process.execPath, [CLI, 'timeline', '--since', '2026-06-01T09:00:00.000Z'], {
      encoding: 'utf8',
      env: { ...process.env, WARDEN_LOG: missing },
    });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/not found/i);
  });

  test('9. --since after all entries → "No entries found"', () => {
    const { stdout, status } = runTimeline(['--since', '2099-01-01T00:00:00.000Z'], logFile);
    expect(status).toBe(0);
    expect(stdout).toMatch(/no entries found/i);
  });

  test('10. output shows time labels in HH:MM format', () => {
    const { stdout } = runTimeline(['--since', '2026-06-01T09:00:00.000Z', '--bucket', '30'], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    // Time labels should match HH:MM pattern
    expect(plain).toMatch(/\d{2}:\d{2}/);
  });
});
