/**
 * Unit tests for `warden compare` — compare two audit snapshots.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-compare-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeSnapshot(tmpDir: string, name: string, data: object): string {
  const p = path.join(tmpDir, `${name}.json`);
  fs.writeFileSync(p, JSON.stringify(data, null, 2) + '\n', 'utf8');
  return p;
}

function run(
  args: string[],
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'compare', ...args], { encoding: 'utf8' });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

// Minimal valid snapshot shape
function snap(overrides: object = {}): object {
  return {
    version:    1,
    snapshotAt: '2026-01-01T10:00:00.000Z',
    totals:     { calls: 100, allow: 90, deny: 5, killed: 5, denyRate: 10 },
    latency:    { avgMs: 15, p95Ms: 30 },
    topTools: [
      { tool: 'fs/read_file',  total: 80, allow: 80, deny: 0, killed: 0 },
      { tool: 'fs/write_file', total: 10, allow:  5, deny: 5, killed: 0 },
      { tool: 'github/push',   total: 10, allow:  5, deny: 0, killed: 5 },
    ],
    ...overrides,
  };
}

describe('warden compare', () => {
  let tmpDir: string;

  beforeEach(() => { tmpDir = makeTmpDir(); });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0 when no regression', () => {
    const b = writeSnapshot(tmpDir, 'baseline', snap());
    const c = writeSnapshot(tmpDir, 'current',  snap()); // identical
    const { status } = run([b, c]);
    expect(status).toBe(0);
  });

  test('2. text output shows "No regressions" when identical', () => {
    const b = writeSnapshot(tmpDir, 'baseline', snap());
    const c = writeSnapshot(tmpDir, 'current',  snap());
    const { stdout } = run([b, c]);
    expect(stdout).toMatch(/no regressions/i);
  });

  test('3. exits 1 with --fail-on-regression when regression found', () => {
    const b = writeSnapshot(tmpDir, 'baseline', snap({ totals: { calls: 100, allow: 90, deny: 5, killed: 5, denyRate: 10 } }));
    const c = writeSnapshot(tmpDir, 'current',  snap({
      totals:  { calls: 100, allow: 80, deny: 15, killed: 5, denyRate: 20 },
      topTools: [
        { tool: 'fs/read_file',  total: 80, allow: 80, deny: 0, killed: 0 },
        { tool: 'bash/run',      total: 20, allow:  5, deny: 15, killed: 0 }, // newly blocked
      ],
    }));
    const { status } = run([b, c, '--fail-on-regression']);
    expect(status).toBe(1);
  });

  test('4. text output shows "Regression detected" on regression', () => {
    const b = writeSnapshot(tmpDir, 'baseline', snap());
    const c = writeSnapshot(tmpDir, 'current',  snap({
      topTools: [
        { tool: 'fs/read_file',  total: 80, allow: 80, deny: 0, killed: 0 },
        { tool: 'bash/run',      total: 20, allow:  5, deny: 15, killed: 0 },
      ],
    }));
    const { stdout } = run([b, c]);
    expect(stdout).toMatch(/regression detected/i);
  });

  test('5. --json produces valid JSON', () => {
    const b = writeSnapshot(tmpDir, 'baseline', snap());
    const c = writeSnapshot(tmpDir, 'current',  snap());
    const { stdout, status } = run([b, c, '--json']);
    expect(status).toBe(0);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('6. --json has "hasRegression" field', () => {
    const b = writeSnapshot(tmpDir, 'baseline', snap());
    const c = writeSnapshot(tmpDir, 'current',  snap());
    const { stdout } = run([b, c, '--json']);
    const result = JSON.parse(stdout) as { hasRegression: boolean };
    expect(typeof result.hasRegression).toBe('boolean');
    expect(result.hasRegression).toBe(false);
  });

  test('7. --json newlyBlocked contains new tools', () => {
    const b = writeSnapshot(tmpDir, 'baseline', snap());
    const c = writeSnapshot(tmpDir, 'current',  snap({
      topTools: [
        ...snap()['topTools' as keyof object] as object[],
        { tool: 'bash/exec', total: 5, allow: 0, deny: 5, killed: 0 },
      ],
    }));
    const { stdout } = run([b, c, '--json']);
    const result = JSON.parse(stdout) as { regressions: { newlyBlocked: string[] } };
    expect(result.regressions.newlyBlocked).toContain('bash/exec');
  });

  test('8. --json denyRate delta computed correctly', () => {
    const b = writeSnapshot(tmpDir, 'baseline', snap({ totals: { calls: 100, allow: 90, deny: 5, killed: 5, denyRate: 10 } }));
    const c = writeSnapshot(tmpDir, 'current',  snap({ totals: { calls: 100, allow: 80, deny: 15, killed: 5, denyRate: 20 } }));
    const { stdout } = run([b, c, '--json']);
    const result = JSON.parse(stdout) as { deltas: { denyRate: number } };
    expect(result.deltas.denyRate).toBe(10); // 20 - 10 = 10
  });

  test('9. exits 1 with no arguments', () => {
    const { status } = run([]);
    expect(status).toBe(1);
  });

  test('10. exits 1 when baseline file is missing', () => {
    const missing = path.join(tmpDir, 'missing.json');
    const c = writeSnapshot(tmpDir, 'current', snap());
    const { status } = run([missing, c]);
    expect(status).toBe(1);
  });

  test('11. exits 0 without --fail-on-regression even on regression', () => {
    const b = writeSnapshot(tmpDir, 'baseline', snap());
    const c = writeSnapshot(tmpDir, 'current',  snap({
      topTools: [
        { tool: 'bash/run', total: 20, allow: 5, deny: 15, killed: 0 },
      ],
    }));
    const { status } = run([b, c]); // no --fail-on-regression
    expect(status).toBe(0);
  });

  test('12. newlyAllowed shows tools that were blocked in baseline but not current', () => {
    const b = writeSnapshot(tmpDir, 'baseline', snap());  // github/push has killed=5
    const c = writeSnapshot(tmpDir, 'current',  snap({
      topTools: [
        { tool: 'fs/read_file',  total: 80, allow: 80, deny: 0, killed: 0 },
        { tool: 'fs/write_file', total: 10, allow: 10, deny: 0, killed: 0 },
        { tool: 'github/push',   total: 10, allow: 10, deny: 0, killed: 0 }, // now clean
      ],
    }));
    const { stdout } = run([b, c, '--json']);
    const result = JSON.parse(stdout) as { regressions: { newlyAllowed: string[] } };
    expect(result.regressions.newlyAllowed).toContain('github/push');
  });
});
