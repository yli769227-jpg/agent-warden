/**
 * Unit tests for `warden summary` — plain-English security summary.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-summary-test-${suffix}`);
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
  const r = spawnSync(process.execPath, [CLI, 'summary', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

// All entries within last 24h so they're included by default
const NOW  = Date.now();
function minsAgo(m: number): string {
  return new Date(NOW - m * 60_000).toISOString();
}

describe('warden summary', () => {
  let tmpDir: string;
  let logFile: string;

  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  describe('clean traffic', () => {
    beforeEach(() => {
      tmpDir = makeTmpDir();
      logFile = writeLog(tmpDir, [
        { ts: minsAgo(30), tool: 'fs/read_file', verdict: 'allow', durationMs: 10 },
        { ts: minsAgo(20), tool: 'fs/read_file', verdict: 'allow', durationMs: 15 },
        { ts: minsAgo(10), tool: 'fs/read_file', verdict: 'allow', durationMs: 12 },
      ]);
    });

    test('1. exits 0', () => {
      expect(run([], logFile).status).toBe(0);
    });

    test('2. output contains "normally" or "CLEAN"', () => {
      const { stdout } = run([], logFile);
      const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
      expect(plain).toMatch(/normally|clean/i);
    });

    test('3. --json grade is CLEAN', () => {
      const { stdout } = run(['--json'], logFile);
      const r = JSON.parse(stdout) as { grade: string };
      expect(r.grade).toBe('CLEAN');
    });

    test('4. --json has executiveSummary field', () => {
      const { stdout } = run(['--json'], logFile);
      const r = JSON.parse(stdout) as { executiveSummary: string };
      expect(typeof r.executiveSummary).toBe('string');
      expect(r.executiveSummary.length).toBeGreaterThan(0);
    });
  });

  describe('high risk traffic', () => {
    beforeEach(() => {
      tmpDir = makeTmpDir();
      logFile = writeLog(tmpDir, [
        { ts: minsAgo(50), tool: 'fs/read',    verdict: 'allow',  durationMs: 5 },
        { ts: minsAgo(40), tool: 'bash/exec',  verdict: 'allow',  durationMs: 5 },
        { ts: minsAgo(30), tool: 'bash/exec',  verdict: 'deny',   durationMs: 5 },
        { ts: minsAgo(20), tool: 'fs/delete',  verdict: 'killed', durationMs: 5 },
        { ts: minsAgo(10), tool: 'bash/exec',  verdict: 'deny',   durationMs: 5 },
      ]);
    });

    test('5. --json grade is MEDIUM+ for risky traffic', () => {
      const { stdout } = run(['--json'], logFile);
      const r = JSON.parse(stdout) as { grade: string; riskScore: number };
      expect(r.riskScore).toBeGreaterThan(20); // above LOW
      expect(['MEDIUM', 'HIGH', 'CRITICAL']).toContain(r.grade);
    });

    test('6. --json metrics.denied = 2', () => {
      const { stdout } = run(['--json'], logFile);
      const r = JSON.parse(stdout) as { metrics: { denied: number } };
      expect(r.metrics.denied).toBe(2);
    });

    test('7. --json metrics.killed = 1', () => {
      const { stdout } = run(['--json'], logFile);
      const r = JSON.parse(stdout) as { metrics: { killed: number } };
      expect(r.metrics.killed).toBe(1);
    });

    test('8. --json notableEvents is non-empty', () => {
      const { stdout } = run(['--json'], logFile);
      const r = JSON.parse(stdout) as { notableEvents: string[] };
      expect(r.notableEvents.length).toBeGreaterThan(0);
    });

    test('9. --json notableEvents mentions denied or dangerous tool', () => {
      const { stdout } = run(['--json'], logFile);
      const r = JSON.parse(stdout) as { notableEvents: string[] };
      const text = r.notableEvents.join(' ');
      expect(text).toMatch(/bash\/exec|fs\/delete|denied|kill|dangerous/i);
    });
  });

  describe('--json output', () => {
    beforeEach(() => {
      tmpDir  = makeTmpDir();
      logFile = writeLog(tmpDir, [
        { ts: minsAgo(5), tool: 'fs/read', verdict: 'allow', durationMs: 8 },
      ]);
    });

    test('10. --json is valid JSON', () => {
      const { stdout } = run(['--json'], logFile);
      expect(() => JSON.parse(stdout)).not.toThrow();
    });

    test('11. --json has metrics.total = 1', () => {
      const { stdout } = run(['--json'], logFile);
      const r = JSON.parse(stdout) as { metrics: { total: number } };
      expect(r.metrics.total).toBe(1);
    });

    test('12. --json has title field', () => {
      const { stdout } = run(['--title', 'Custom Title', '--json'], logFile);
      const r = JSON.parse(stdout) as { title: string };
      expect(r.title).toBe('Custom Title');
    });

    test('13. --output saves report to file', () => {
      const outPath = path.join(tmpDir, 'report.txt');
      run(['--output', outPath], logFile);
      expect(fs.existsSync(outPath)).toBe(true);
      expect(fs.readFileSync(outPath, 'utf8').length).toBeGreaterThan(0);
    });
  });

  describe('edge cases', () => {
    test('14. exits 1 when log file is missing', () => {
      tmpDir = makeTmpDir();
      const missing = path.join(tmpDir, 'missing.jsonl');
      const { status } = run([], missing);
      expect(status).toBe(1);
    });
  });
});
