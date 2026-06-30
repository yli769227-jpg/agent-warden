/**
 * Unit tests for `warden blame` — activity spike finder.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-blame-test-${suffix}`);
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
  const r = spawnSync(process.execPath, [CLI, 'blame', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

// Fixed timestamps: 2026-01-01
// 10:00-10:14: 5 calls → first bucket (bucket 0 of 15-min window from 10:00)
// 10:30-10:44: 3 calls → different bucket
// 11:00-11:14: 1 call
const BASE = '2026-01-01T';

const ENTRIES = [
  // Bucket 10:00-10:14 (5 calls — should be #1)
  { ts: `${BASE}10:00:00.000Z`, tool: 'fs/read_file',  verdict: 'allow',  durationMs: 5 },
  { ts: `${BASE}10:01:00.000Z`, tool: 'fs/read_file',  verdict: 'allow',  durationMs: 5 },
  { ts: `${BASE}10:02:00.000Z`, tool: 'fs/write_file', verdict: 'deny',   durationMs: 3 },
  { ts: `${BASE}10:03:00.000Z`, tool: 'fs/read_file',  verdict: 'allow',  durationMs: 5 },
  { ts: `${BASE}10:04:00.000Z`, tool: 'bash/exec',     verdict: 'killed', durationMs: 1 },

  // Bucket 10:30-10:44 (3 calls — should be #2)
  { ts: `${BASE}10:30:00.000Z`, tool: 'github/list',   verdict: 'allow',  durationMs: 20 },
  { ts: `${BASE}10:31:00.000Z`, tool: 'github/list',   verdict: 'allow',  durationMs: 20 },
  { ts: `${BASE}10:32:00.000Z`, tool: 'github/create', verdict: 'deny',   durationMs: 5  },

  // Bucket 11:00-11:14 (1 call — should be #3)
  { ts: `${BASE}11:00:00.000Z`, tool: 'fs/read_file',  verdict: 'allow',  durationMs: 8  },
];

// Use --since fixed timestamp so tests are deterministic
const SINCE = '2026-01-01T00:00:00.000Z';
const BASE_FLAGS = ['--since', SINCE, '--window', '24'];

describe('warden blame', () => {
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

  test('2. output contains "blame" header', () => {
    const { stdout } = run(BASE_FLAGS, logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/blame/i);
  });

  test('3. --json produces valid JSON', () => {
    const { stdout } = run([...BASE_FLAGS, '--json'], logFile);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('4. --json hotBuckets is an array', () => {
    const { stdout } = run([...BASE_FLAGS, '--json'], logFile);
    const r = JSON.parse(stdout) as { hotBuckets: unknown[] };
    expect(Array.isArray(r.hotBuckets)).toBe(true);
  });

  test('5. --json hotBuckets top bucket has 5 calls', () => {
    const { stdout } = run([...BASE_FLAGS, '--json'], logFile);
    const r = JSON.parse(stdout) as { hotBuckets: Array<{ calls: number; bucketStart: string }> };
    expect(r.hotBuckets[0]!.calls).toBe(5);
  });

  test('6. --json top bucket start is in 10:00 bucket', () => {
    const { stdout } = run([...BASE_FLAGS, '--json'], logFile);
    const r = JSON.parse(stdout) as { hotBuckets: Array<{ bucketStart: string }> };
    expect(r.hotBuckets[0]!.bucketStart).toMatch(/T10:00/);
  });

  test('7. --json second bucket has 3 calls', () => {
    const { stdout } = run([...BASE_FLAGS, '--json'], logFile);
    const r = JSON.parse(stdout) as { hotBuckets: Array<{ calls: number }> };
    expect(r.hotBuckets[1]!.calls).toBe(3);
  });

  test('8. --json top bucket reports denied count', () => {
    const { stdout } = run([...BASE_FLAGS, '--json'], logFile);
    const r = JSON.parse(stdout) as { hotBuckets: Array<{ denied: number }> };
    // First bucket: deny + killed = 2
    expect(r.hotBuckets[0]!.denied).toBe(2);
  });

  test('9. --json topTools is sorted by calls desc', () => {
    const { stdout } = run([...BASE_FLAGS, '--json'], logFile);
    const r = JSON.parse(stdout) as { hotBuckets: Array<{ topTools: Array<{ tool: string; calls: number }> }> };
    const topT = r.hotBuckets[0]!.topTools;
    expect(topT.length).toBeGreaterThan(0);
    expect(topT[0]!.tool).toBe('fs/read_file'); // 3 calls in first bucket
    expect(topT[0]!.calls).toBe(3);
  });

  test('10. --top-buckets 2 limits hotBuckets to 2', () => {
    const { stdout } = run([...BASE_FLAGS, '--json', '--top-buckets', '2'], logFile);
    const r = JSON.parse(stdout) as { hotBuckets: unknown[] };
    expect(r.hotBuckets.length).toBe(2);
  });

  test('11. --threshold 3 excludes bucket with 1 call', () => {
    const { stdout } = run([...BASE_FLAGS, '--json', '--threshold', '3'], logFile);
    const r = JSON.parse(stdout) as { hotBuckets: Array<{ calls: number }> };
    for (const b of r.hotBuckets) {
      expect(b.calls).toBeGreaterThanOrEqual(3);
    }
  });

  test('12. --json totalCalls = 9', () => {
    const { stdout } = run([...BASE_FLAGS, '--json'], logFile);
    const r = JSON.parse(stdout) as { totalCalls: number };
    expect(r.totalCalls).toBe(9);
  });

  test('13. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const { status } = run(BASE_FLAGS, missing);
    expect(status).toBe(1);
  });

  test('14. --json has since, windowH, bucketMins fields', () => {
    const { stdout } = run([...BASE_FLAGS, '--json', '--bucket-mins', '30'], logFile);
    const r = JSON.parse(stdout) as { since: string; windowH: number; bucketMins: number };
    expect(typeof r.since).toBe('string');
    expect(r.windowH).toBe(24);
    expect(r.bucketMins).toBe(30);
  });
});
