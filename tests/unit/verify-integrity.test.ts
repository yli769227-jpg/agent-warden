/**
 * Unit tests for `warden verify-integrity` — audit log integrity checker.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-vi-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function run(
  args: string[],
  logFile: string,
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'verify-integrity', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

const GOOD_ENTRIES = [
  { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read', verdict: 'allow', durationMs: 5 },
  { ts: '2026-01-01T10:01:00.000Z', tool: 'fs/write', verdict: 'deny',  durationMs: 3 },
  { ts: '2026-01-01T10:02:00.000Z', tool: 'bash/exec', verdict: 'killed', durationMs: 1 },
];

describe('warden verify-integrity', () => {
  let tmpDir: string;

  beforeEach(() => { tmpDir = makeTmpDir(); });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0 on a valid log', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(logFile, GOOD_ENTRIES.map(e => JSON.stringify(e)).join('\n') + '\n');
    expect(run([], logFile).status).toBe(0);
  });

  test('2. output contains "verify-integrity" header', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(logFile, GOOD_ENTRIES.map(e => JSON.stringify(e)).join('\n') + '\n');
    const { stdout } = run([], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/verify.?integrity/i);
  });

  test('3. valid log outputs "integrity OK"', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(logFile, GOOD_ENTRIES.map(e => JSON.stringify(e)).join('\n') + '\n');
    const { stdout } = run([], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/integrity OK|no violations/i);
  });

  test('4. --json produces valid JSON', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(logFile, GOOD_ENTRIES.map(e => JSON.stringify(e)).join('\n') + '\n');
    const { stdout } = run(['--json'], logFile);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('5. --json passed = true for valid log', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(logFile, GOOD_ENTRIES.map(e => JSON.stringify(e)).join('\n') + '\n');
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { passed: boolean };
    expect(r.passed).toBe(true);
  });

  test('6. --json violations = [] for valid log', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(logFile, GOOD_ENTRIES.map(e => JSON.stringify(e)).join('\n') + '\n');
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { violations: unknown[] };
    expect(r.violations.length).toBe(0);
  });

  test('7. detects invalid JSON line', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(logFile,
      JSON.stringify(GOOD_ENTRIES[0]) + '\n' +
      '{bad json\n' +
      JSON.stringify(GOOD_ENTRIES[2]) + '\n',
    );
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { violations: Array<{ type: string; lineNo: number }> };
    expect(r.violations.some(v => v.type === 'invalid-json')).toBe(true);
    expect(r.violations.find(v => v.type === 'invalid-json')!.lineNo).toBe(2);
  });

  test('8. detects missing ts field', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(logFile,
      JSON.stringify({ tool: 'fs/read', verdict: 'allow', durationMs: 5 }) + '\n',
    );
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { violations: Array<{ type: string }> };
    expect(r.violations.some(v => v.type === 'missing-ts')).toBe(true);
  });

  test('9. detects missing verdict field', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(logFile,
      JSON.stringify({ ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read', durationMs: 5 }) + '\n',
    );
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { violations: Array<{ type: string }> };
    expect(r.violations.some(v => v.type === 'missing-verdict')).toBe(true);
  });

  test('10. detects timestamp regression (out-of-order)', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(logFile, [
      { ts: '2026-01-01T10:05:00.000Z', tool: 'fs/read', verdict: 'allow' },
      { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read', verdict: 'allow' }, // earlier!
    ].map(e => JSON.stringify(e)).join('\n') + '\n');
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { violations: Array<{ type: string }> };
    expect(r.violations.some(v => v.type === 'ts-regression')).toBe(true);
  });

  test('11. --strict-exit exits 1 when violations exist', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(logFile, '{bad json\n');
    const { status } = run(['--strict-exit'], logFile);
    expect(status).toBe(1);
  });

  test('12. --strict-exit exits 0 on valid log', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(logFile, GOOD_ENTRIES.map(e => JSON.stringify(e)).join('\n') + '\n');
    const { status } = run(['--strict-exit'], logFile);
    expect(status).toBe(0);
  });

  test('13. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const { status } = run([], missing);
    expect(status).toBe(1);
  });

  test('14. --json has total and logFile fields', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(logFile, GOOD_ENTRIES.map(e => JSON.stringify(e)).join('\n') + '\n');
    const { stdout } = run(['--json'], logFile);
    const r = JSON.parse(stdout) as { total: number; logFile: string };
    expect(r.total).toBe(3);
    expect(typeof r.logFile).toBe('string');
  });
});
