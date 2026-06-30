/**
 * Unit tests for `warden anomaly-score` — 0–100 risk scoring of audit behaviour.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-score-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeLog(tmpDir: string, entries: object[]): string {
  const logFile = path.join(tmpDir, 'audit.jsonl');
  fs.writeFileSync(logFile, entries.map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');
  return logFile;
}

function runScore(
  args: string[],
  logFile: string,
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'anomaly-score', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

// All entries use recent timestamps so they fall within the window
const NOW = Date.now();
function minsAgo(m: number): string {
  return new Date(NOW - m * 60_000).toISOString();
}

function entry(
  tool: string,
  verdict: 'allow' | 'deny' | 'killed',
  minsBack = 5,
): object {
  return { ts: minsAgo(minsBack), tool, verdict, durationMs: 5 };
}

describe('warden anomaly-score', () => {
  let tmpDir: string;
  let logFile: string;

  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  describe('clean traffic', () => {
    beforeEach(() => {
      tmpDir = makeTmpDir();
      // All allowed, safe tools
      const entries = Array.from({ length: 10 }, (_, i) =>
        entry('fs/read_file', 'allow', i + 1),
      );
      logFile = writeLog(tmpDir, entries);
    });

    test('1. exits 0', () => {
      expect(runScore(['--window', '1'], logFile).status).toBe(0);
    });

    test('2. score is low for clean traffic', () => {
      const { stdout } = runScore(['--window', '1', '--json'], logFile);
      const r = JSON.parse(stdout) as { score: number };
      expect(r.score).toBeLessThan(40);
    });

    test('3. grade is CLEAN or LOW for clean traffic', () => {
      const { stdout } = runScore(['--window', '1', '--json'], logFile);
      const r = JSON.parse(stdout) as { grade: string };
      expect(['CLEAN', 'LOW']).toContain(r.grade);
    });
  });

  describe('high deny rate', () => {
    beforeEach(() => {
      tmpDir = makeTmpDir();
      // 80% deny rate
      const entries = [
        ...Array.from({ length: 2 }, (_, i) => entry('fs/read_file', 'allow',  i + 1)),
        ...Array.from({ length: 8 }, (_, i) => entry('fs/read_file', 'deny',   i + 3)),
      ];
      logFile = writeLog(tmpDir, entries);
    });

    test('4. high deny rate raises score', () => {
      const { stdout } = runScore(['--window', '1', '--json'], logFile);
      const r = JSON.parse(stdout) as { score: number };
      expect(r.score).toBeGreaterThan(20);
    });

    test('5. breakdown.denyScore is elevated', () => {
      const { stdout } = runScore(['--window', '1', '--json'], logFile);
      const r = JSON.parse(stdout) as { breakdown: { denyScore: number } };
      expect(r.breakdown.denyScore).toBeGreaterThan(50);
    });
  });

  describe('dangerous tools', () => {
    beforeEach(() => {
      tmpDir = makeTmpDir();
      // Calls to bash/exec (matches /bash|exec/i)
      const entries = Array.from({ length: 5 }, (_, i) =>
        entry('bash/exec', 'allow', i + 1),
      );
      logFile = writeLog(tmpDir, entries);
    });

    test('6. dangerous tool name raises score', () => {
      const { stdout } = runScore(['--window', '1', '--json'], logFile);
      const r = JSON.parse(stdout) as { score: number };
      expect(r.score).toBeGreaterThan(10);
    });

    test('7. breakdown.dangerScore is elevated', () => {
      const { stdout } = runScore(['--window', '1', '--json'], logFile);
      const r = JSON.parse(stdout) as { breakdown: { dangerScore: number } };
      expect(r.breakdown.dangerScore).toBeGreaterThan(0);
    });
  });

  describe('--json output', () => {
    beforeEach(() => {
      tmpDir = makeTmpDir();
      logFile = writeLog(tmpDir, [entry('fs/read', 'allow', 1)]);
    });

    test('8. --json produces valid JSON', () => {
      const { stdout } = runScore(['--window', '1', '--json'], logFile);
      expect(() => JSON.parse(stdout)).not.toThrow();
    });

    test('9. --json has score 0-100', () => {
      const { stdout } = runScore(['--window', '1', '--json'], logFile);
      const r = JSON.parse(stdout) as { score: number };
      expect(r.score).toBeGreaterThanOrEqual(0);
      expect(r.score).toBeLessThanOrEqual(100);
    });

    test('10. --json has grade field', () => {
      const { stdout } = runScore(['--window', '1', '--json'], logFile);
      const r = JSON.parse(stdout) as { grade: string };
      expect(['CLEAN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).toContain(r.grade);
    });

    test('11. --json has breakdown with 4 sub-scores', () => {
      const { stdout } = runScore(['--window', '1', '--json'], logFile);
      const r = JSON.parse(stdout) as { breakdown: Record<string, number> };
      expect(Object.keys(r.breakdown).length).toBe(4);
    });

    test('12. --json has total call count', () => {
      const { stdout } = runScore(['--window', '1', '--json'], logFile);
      const r = JSON.parse(stdout) as { total: number };
      expect(r.total).toBe(1);
    });
  });

  describe('--threshold flag', () => {
    beforeEach(() => {
      tmpDir = makeTmpDir();
      // All denied — score should be very high
      const entries = Array.from({ length: 10 }, (_, i) =>
        entry('fs/read_file', 'deny', i + 1),
      );
      logFile = writeLog(tmpDir, entries);
    });

    test('13. exits 1 when score exceeds threshold', () => {
      // score = 40 (100% deny rate × 40% weight), so threshold=30 should trigger
      const { status } = runScore(['--window', '1', '--threshold', '10'], logFile);
      expect(status).toBe(1);
    });

    test('14. exits 0 when score is below threshold', () => {
      const { status } = runScore(['--window', '1', '--threshold', '101'], logFile);
      expect(status).toBe(0);
    });
  });

  describe('edge cases', () => {
    test('15. exits 1 when log file is missing', () => {
      tmpDir = makeTmpDir();
      const missing = path.join(tmpDir, 'missing.jsonl');
      const { status } = runScore(['--window', '1'], missing);
      expect(status).toBe(1);
    });
  });
});
