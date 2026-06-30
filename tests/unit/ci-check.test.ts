/**
 * Unit tests for `warden ci-check` — battery of CI safety checks.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-ci-test-${suffix}`);
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
  const r = spawnSync(process.execPath, [CLI, 'ci-check', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

const NOW = Date.now();
function minsAgo(m: number): string {
  return new Date(NOW - m * 60_000).toISOString();
}

function entry(tool: string, verdict: 'allow' | 'deny' | 'killed', minsBack = 5): object {
  return { ts: minsAgo(minsBack), tool, verdict, durationMs: 5 };
}

describe('warden ci-check', () => {
  let tmpDir: string;
  let logFile: string;

  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  describe('all-clean traffic', () => {
    beforeEach(() => {
      tmpDir  = makeTmpDir();
      logFile = writeLog(tmpDir, [
        entry('fs/read_file', 'allow', 5),
        entry('fs/read_file', 'allow', 4),
        entry('fs/read_file', 'allow', 3),
      ]);
    });

    test('1. exits 0 on clean traffic', () => {
      expect(run(['--window', '1'], logFile).status).toBe(0);
    });

    test('2. text shows "All CI checks passed"', () => {
      const { stdout } = run(['--window', '1'], logFile);
      expect(stdout).toMatch(/all ci checks passed/i);
    });

    test('3. --json has passed=true', () => {
      const { stdout } = run(['--window', '1', '--json'], logFile);
      const r = JSON.parse(stdout) as { passed: boolean };
      expect(r.passed).toBe(true);
    });

    test('4. --json has checks array', () => {
      const { stdout } = run(['--window', '1', '--json'], logFile);
      const r = JSON.parse(stdout) as { checks: unknown[] };
      expect(Array.isArray(r.checks)).toBe(true);
      expect(r.checks.length).toBeGreaterThan(0);
    });
  });

  describe('high deny rate', () => {
    beforeEach(() => {
      tmpDir = makeTmpDir();
      logFile = writeLog(tmpDir, [
        // 80% deny rate
        entry('fs/read', 'allow', 5),
        entry('fs/read', 'deny',  4),
        entry('fs/read', 'deny',  3),
        entry('fs/read', 'deny',  2),
        entry('fs/read', 'deny',  1),
      ]);
    });

    test('5. exits 1 when deny rate exceeds threshold', () => {
      const { status } = run(['--window', '1', '--max-deny-rate', '30'], logFile);
      expect(status).toBe(1);
    });

    test('6. exits 0 when deny rate below threshold', () => {
      const { status } = run(['--window', '1', '--max-deny-rate', '90'], logFile);
      expect(status).toBe(0);
    });

    test('7. --json deny-rate check shows passed=false when over limit', () => {
      const { stdout } = run(['--window', '1', '--max-deny-rate', '30', '--json'], logFile);
      const r = JSON.parse(stdout) as { checks: Array<{ name: string; passed: boolean }> };
      const denyCheck = r.checks.find(c => c.name === 'deny-rate');
      expect(denyCheck?.passed).toBe(false);
    });
  });

  describe('dangerous tool calls', () => {
    beforeEach(() => {
      tmpDir = makeTmpDir();
      logFile = writeLog(tmpDir, [
        entry('bash/exec', 'allow', 5),
        entry('fs/read',   'allow', 4),
      ]);
    });

    test('8. exits 1 on dangerous tool call', () => {
      const { status } = run(['--window', '1'], logFile);
      expect(status).toBe(1);
    });

    test('9. exits 0 with --allow-dangerous', () => {
      const { status } = run(['--window', '1', '--allow-dangerous'], logFile);
      expect(status).toBe(0);
    });
  });

  describe('kill-switch events', () => {
    beforeEach(() => {
      tmpDir = makeTmpDir();
      logFile = writeLog(tmpDir, [
        entry('fs/read', 'allow',  5),
        entry('fs/read', 'killed', 3),
      ]);
    });

    test('10. exits 1 on killed event', () => {
      const { status } = run(['--window', '1', '--allow-dangerous'], logFile);
      expect(status).toBe(1);
    });

    test('11. exits 0 with --allow-killed', () => {
      const { status } = run(['--window', '1', '--allow-dangerous', '--allow-killed'], logFile);
      expect(status).toBe(0);
    });
  });

  describe('missing log file', () => {
    test('12. exits 1 when log file is missing', () => {
      tmpDir  = makeTmpDir();
      const missing = path.join(tmpDir, 'missing.jsonl');
      const { status } = run(['--window', '1'], missing);
      expect(status).toBe(1);
    });

    test('13. --json audit-log-exists check fails', () => {
      tmpDir  = makeTmpDir();
      const missing = path.join(tmpDir, 'missing.jsonl');
      const { stdout } = run(['--window', '1', '--json'], missing);
      const r = JSON.parse(stdout) as { checks: Array<{ name: string; passed: boolean }> };
      const logCheck = r.checks.find(c => c.name === 'audit-log-exists');
      expect(logCheck?.passed).toBe(false);
    });
  });

  describe('--json shape', () => {
    beforeEach(() => {
      tmpDir  = makeTmpDir();
      logFile = writeLog(tmpDir, [entry('fs/read', 'allow', 5)]);
    });

    test('14. each check has name, passed, detail', () => {
      const { stdout } = run(['--window', '1', '--json'], logFile);
      const r = JSON.parse(stdout) as { checks: Array<{ name: string; passed: boolean; detail: string }> };
      for (const c of r.checks) {
        expect(typeof c.name).toBe('string');
        expect(typeof c.passed).toBe('boolean');
        expect(typeof c.detail).toBe('string');
      }
    });
  });
});
