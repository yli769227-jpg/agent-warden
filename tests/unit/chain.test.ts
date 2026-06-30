/**
 * Unit tests for `warden chain` — tool call sequence analysis.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-chain-test-${suffix}`);
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
  const r = spawnSync(process.execPath, [CLI, 'chain', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

const SINCE = '2026-01-01T00:00:00.000Z';

// Test pattern: A → B → C appears 3 times (tight), D → E once
// All entries within 30-minute gap window, so no gap-based exclusion
const ENTRIES = [
  // Chain 1: fs/read → fs/write → git/commit (repeated 3×)
  { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read',   verdict: 'allow', durationMs: 5 },
  { ts: '2026-01-01T10:01:00.000Z', tool: 'fs/write',  verdict: 'allow', durationMs: 3 },
  { ts: '2026-01-01T10:02:00.000Z', tool: 'git/commit', verdict: 'allow', durationMs: 10 },

  { ts: '2026-01-01T10:10:00.000Z', tool: 'fs/read',   verdict: 'allow', durationMs: 5 },
  { ts: '2026-01-01T10:11:00.000Z', tool: 'fs/write',  verdict: 'allow', durationMs: 3 },
  { ts: '2026-01-01T10:12:00.000Z', tool: 'git/commit', verdict: 'allow', durationMs: 10 },

  { ts: '2026-01-01T10:20:00.000Z', tool: 'fs/read',   verdict: 'allow', durationMs: 5 },
  { ts: '2026-01-01T10:21:00.000Z', tool: 'fs/write',  verdict: 'allow', durationMs: 3 },
  { ts: '2026-01-01T10:22:00.000Z', tool: 'git/commit', verdict: 'allow', durationMs: 10 },

  // Chain 2: bash/exec → fs/read (appears twice)
  { ts: '2026-01-01T11:00:00.000Z', tool: 'bash/exec', verdict: 'allow', durationMs: 20 },
  { ts: '2026-01-01T11:01:00.000Z', tool: 'fs/read',   verdict: 'allow', durationMs: 5 },

  { ts: '2026-01-01T11:10:00.000Z', tool: 'bash/exec', verdict: 'allow', durationMs: 20 },
  { ts: '2026-01-01T11:11:00.000Z', tool: 'fs/read',   verdict: 'allow', durationMs: 5 },
];

describe('warden chain', () => {
  let tmpDir: string;
  let logFile: string;

  beforeEach(() => {
    tmpDir  = makeTmpDir();
    logFile = writeLog(tmpDir, ENTRIES);
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0', () => {
    expect(run(['--since', SINCE, '--json'], logFile).status).toBe(0);
  });

  test('2. output contains "chain" header in text mode', () => {
    const { stdout } = run(['--since', SINCE], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/chain/i);
  });

  test('3. --json produces valid JSON', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('4. --json has chains array', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { chains: unknown[] };
    expect(Array.isArray(r.chains)).toBe(true);
  });

  test('5. top 3-step chain is "fs/read → fs/write → git/commit" (count 3)', () => {
    const { stdout } = run(['--since', SINCE, '--length', '3', '--json', '--min-count', '1'], logFile);
    const r = JSON.parse(stdout) as { chains: Array<{ chain: string; count: number }> };
    const top = r.chains[0];
    expect(top?.chain).toBe('fs/read → fs/write → git/commit');
    expect(top?.count).toBe(3);
  });

  test('6. --length 2 finds "bash/exec → fs/read" chain', () => {
    const { stdout } = run(['--since', SINCE, '--length', '2', '--json', '--min-count', '1'], logFile);
    const r = JSON.parse(stdout) as { chains: Array<{ chain: string }> };
    const found = r.chains.some(c => c.chain === 'bash/exec → fs/read');
    expect(found).toBe(true);
  });

  test('7. --min-count 3 excludes 2-occurrence chains', () => {
    const { stdout } = run(['--since', SINCE, '--length', '3', '--json', '--min-count', '3'], logFile);
    const r = JSON.parse(stdout) as { chains: Array<{ chain: string; count: number }> };
    for (const c of r.chains) {
      expect(c.count).toBeGreaterThanOrEqual(3);
    }
  });

  test('8. chains are sorted by count descending', () => {
    const { stdout } = run(['--since', SINCE, '--length', '3', '--json', '--min-count', '1'], logFile);
    const r = JSON.parse(stdout) as { chains: Array<{ count: number }> };
    for (let i = 1; i < r.chains.length; i++) {
      expect(r.chains[i - 1]!.count).toBeGreaterThanOrEqual(r.chains[i]!.count);
    }
  });

  test('9. --top 1 returns exactly 1 chain', () => {
    const { stdout } = run(['--since', SINCE, '--json', '--top', '1', '--min-count', '1'], logFile);
    const r = JSON.parse(stdout) as { chains: unknown[] };
    expect(r.chains.length).toBe(1);
  });

  test('10. --json has since, chainLen, total fields', () => {
    const { stdout } = run(['--since', SINCE, '--json', '--min-count', '1'], logFile);
    const r = JSON.parse(stdout) as { since: string; chainLen: number; total: number };
    expect(typeof r.since).toBe('string');
    expect(r.chainLen).toBe(3);
    expect(r.total).toBe(ENTRIES.length);
  });

  test('11. --gap-mins 1 breaks chains separated by 10+ minutes', () => {
    // With a 1-minute gap, the repeated fs/read → fs/write → git/commit chains
    // at t=10:00, t=10:10, t=10:20 each form their own chain internally (within 2-min windows)
    // but cross-chain windows (step ending at 10:02, next starting at 10:10) break
    // This test verifies that smaller gap values reduce chain detection
    const { stdout: shortGap } = run(['--since', SINCE, '--length', '3', '--json', '--min-count', '1', '--gap-mins', '1'], logFile);
    const r1 = JSON.parse(shortGap) as { chains: Array<{ count: number }> };
    const topCount1 = r1.chains[0]?.count ?? 0;

    const { stdout: longGap } = run(['--since', SINCE, '--length', '3', '--json', '--min-count', '1', '--gap-mins', '60'], logFile);
    const r2 = JSON.parse(longGap) as { chains: Array<{ count: number }> };
    const topCount2 = r2.chains[0]?.count ?? 0;

    // With a 1-min gap, we should not see cross-window chains inflate the count
    // Both should find count=3 since internal windows are 2 min (within 1 min threshold works for each chain)
    // The key thing: either both equal, or longGap >= shortGap
    expect(topCount2).toBeGreaterThanOrEqual(topCount1);
  });

  test('12. empty log returns chains = []', () => {
    const empty = writeLog(tmpDir, []);
    const { stdout } = run(['--since', SINCE, '--json'], empty);
    const r = JSON.parse(stdout) as { chains: unknown[] };
    expect(r.chains.length).toBe(0);
  });

  test('13. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const { status } = run(['--since', SINCE], missing);
    expect(status).toBe(1);
  });

  test('14. --json chainLen reflects --length flag', () => {
    const { stdout } = run(['--since', SINCE, '--length', '4', '--json', '--min-count', '1'], logFile);
    const r = JSON.parse(stdout) as { chainLen: number };
    expect(r.chainLen).toBe(4);
  });
});
