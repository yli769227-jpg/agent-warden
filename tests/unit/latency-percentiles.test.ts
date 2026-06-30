/**
 * Unit tests for `warden latency-percentiles` — P50/P75/P90/P95/P99 latency report.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-lp-test-${suffix}`);
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
  const r = spawnSync(process.execPath, [CLI, 'latency-percentiles', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

const SINCE = '2026-01-01T00:00:00.000Z';

// Known latency values for deterministic percentile computation.
// 10 values: [5, 10, 15, 20, 25, 30, 50, 100, 200, 500]
// Sorted: P50 = 25ms, P90 = 200ms, P95 = 500ms, P99 = 500ms
// Tool split: fs/* = first 5 (5-25ms), slow_tool = last 5 (30-500ms)
const ENTRIES = [
  { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read',   verdict: 'allow', durationMs: 5   },
  { ts: '2026-01-01T10:01:00.000Z', tool: 'fs/read',   verdict: 'allow', durationMs: 10  },
  { ts: '2026-01-01T10:02:00.000Z', tool: 'fs/write',  verdict: 'deny',  durationMs: 15  },
  { ts: '2026-01-01T10:03:00.000Z', tool: 'fs/read',   verdict: 'allow', durationMs: 20  },
  { ts: '2026-01-01T10:04:00.000Z', tool: 'fs/read',   verdict: 'allow', durationMs: 25  },
  { ts: '2026-01-01T10:05:00.000Z', tool: 'slow/call', verdict: 'allow', durationMs: 30  },
  { ts: '2026-01-01T10:06:00.000Z', tool: 'slow/call', verdict: 'allow', durationMs: 50  },
  { ts: '2026-01-01T10:07:00.000Z', tool: 'slow/call', verdict: 'allow', durationMs: 100 },
  { ts: '2026-01-01T10:08:00.000Z', tool: 'slow/call', verdict: 'allow', durationMs: 200 },
  { ts: '2026-01-01T10:09:00.000Z', tool: 'slow/call', verdict: 'allow', durationMs: 500 },
];

describe('warden latency-percentiles', () => {
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

  test('2. output contains "latency-percentiles" header', () => {
    const { stdout } = run(['--since', SINCE], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/latency.?percentile/i);
  });

  test('3. --json produces valid JSON', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('4. --json total = 10', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { total: number };
    expect(r.total).toBe(10);
  });

  test('5. --json overall.50 = 25 (median of sorted 10-element array)', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { overall: Record<string, number> };
    // sorted: [5,10,15,20,25,30,50,100,200,500]
    // P50 = ceil(50/100*10)-1 = idx 4 = 25
    expect(r.overall['50']).toBe(25);
  });

  test('6. --json overall.90 = 200 (9th element)', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { overall: Record<string, number> };
    // P90 = ceil(0.90*10)-1 = idx 8 = 200
    expect(r.overall['90']).toBe(200);
  });

  test('7. --json overall.99 = 500 (last element)', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { overall: Record<string, number> };
    expect(r.overall['99']).toBe(500);
  });

  test('8. --json byTool is sorted by P95 desc', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { byTool: Array<Record<string, number>> };
    // slow/call should appear first (P95=500ms)
    expect(r.byTool[0]!['tool']).toBe('slow/call');
  });

  test('9. --json byTool slow/call has calls = 5', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { byTool: Array<{ tool: string; calls: number }> };
    const slow = r.byTool.find(t => t.tool === 'slow/call');
    expect(slow?.calls).toBe(5);
  });

  test('10. --json byTool entry has avg, min, max fields', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { byTool: Array<{ avg: number; min: number; max: number }> };
    for (const t of r.byTool) {
      expect(typeof t.avg).toBe('number');
      expect(typeof t.min).toBe('number');
      expect(typeof t.max).toBe('number');
    }
  });

  test('11. --tool fs/read restricts to 4 calls', () => {
    const { stdout } = run(['--since', SINCE, '--json', '--tool', 'fs/read'], logFile);
    const r = JSON.parse(stdout) as { total: number };
    expect(r.total).toBe(4);
  });

  test('12. --top 1 limits byTool to 1 entry', () => {
    const { stdout } = run(['--since', SINCE, '--json', '--top', '1'], logFile);
    const r = JSON.parse(stdout) as { byTool: unknown[] };
    expect(r.byTool.length).toBe(1);
  });

  test('13. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const { status } = run(['--since', SINCE], missing);
    expect(status).toBe(1);
  });

  test('14. entries without durationMs are excluded from total', () => {
    // Add one entry with no durationMs
    const entries = [...ENTRIES, { ts: '2026-01-01T10:10:00.000Z', tool: 'noop', verdict: 'allow' }];
    const extraLog = writeLog(tmpDir, entries);
    const { stdout } = run(['--since', SINCE, '--json'], extraLog);
    const r = JSON.parse(stdout) as { total: number };
    expect(r.total).toBe(10); // no-durationMs entry excluded
  });
});
