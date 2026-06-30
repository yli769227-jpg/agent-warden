/**
 * Unit tests for `warden redact-scan` — post-hoc secret leak detector.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-rs-test-${suffix}`);
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
  const r = spawnSync(process.execPath, [CLI, 'redact-scan', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

const SINCE = '2026-01-01T00:00:00.000Z';

describe('warden redact-scan', () => {
  let tmpDir: string;

  beforeEach(() => { tmpDir = makeTmpDir(); });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0 on clean log', () => {
    const logFile = writeLog(tmpDir, [
      { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read', verdict: 'allow', durationMs: 5, args: { path: '/home/user/file.txt' } },
    ]);
    expect(run(['--since', SINCE], logFile).status).toBe(0);
  });

  test('2. output contains "redact-scan" header', () => {
    const logFile = writeLog(tmpDir, [
      { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read', verdict: 'allow', durationMs: 5 },
    ]);
    const { stdout } = run(['--since', SINCE], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/redact.?scan/i);
  });

  test('3. clean log outputs "No potential secrets found"', () => {
    const logFile = writeLog(tmpDir, [
      { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read', verdict: 'allow', durationMs: 5, args: { path: '/home/user/file.txt' } },
    ]);
    const { stdout } = run(['--since', SINCE], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/No potential secrets found/i);
  });

  test('4. detects GitHub personal access token (ghp_)', () => {
    const fakeToken = 'ghp_' + 'A'.repeat(36);
    const logFile = writeLog(tmpDir, [
      { ts: '2026-01-01T10:00:00.000Z', tool: 'github/push', verdict: 'allow', durationMs: 5, args: { token: fakeToken } },
    ]);
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { total: number };
    expect(r.total).toBeGreaterThan(0);
  });

  test('5. --json produces valid JSON', () => {
    const logFile = writeLog(tmpDir, [
      { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read', verdict: 'allow', durationMs: 5 },
    ]);
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('6. --json total = 0 for clean log', () => {
    const logFile = writeLog(tmpDir, [
      { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read', verdict: 'allow', durationMs: 5, args: { path: '/safe/path' } },
    ]);
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { total: number };
    expect(r.total).toBe(0);
  });

  test('7. --json findings array is empty for clean log', () => {
    const logFile = writeLog(tmpDir, [
      { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read', verdict: 'allow', durationMs: 5 },
    ]);
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { findings: unknown[] };
    expect(r.findings.length).toBe(0);
  });

  test('8. finding has lineNo, tool, category fields', () => {
    const fakeToken = 'ghp_' + 'B'.repeat(36);
    const logFile = writeLog(tmpDir, [
      { ts: '2026-01-01T10:00:00.000Z', tool: 'github/push', verdict: 'allow', durationMs: 5, args: { auth: fakeToken } },
    ]);
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { findings: Array<{ lineNo: number; tool: string; category: string; match: string }> };
    expect(r.findings.length).toBeGreaterThan(0);
    expect(typeof r.findings[0]!.lineNo).toBe('number');
    expect(r.findings[0]!.tool).toBe('github/push');
    expect(typeof r.findings[0]!.category).toBe('string');
  });

  test('9. detects AWS access key pattern (AKIA...)', () => {
    const fakeAwsKey = 'AKIAIOSFODNN7EXAMPLE';
    const logFile = writeLog(tmpDir, [
      { ts: '2026-01-01T10:00:00.000Z', tool: 'aws/s3', verdict: 'allow', durationMs: 5, args: { key_id: fakeAwsKey } },
    ]);
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { findings: Array<{ category: string }> };
    expect(r.findings.some(f => f.category.includes('AWS'))).toBe(true);
  });

  test('10. detects JWT token pattern', () => {
    const fakeJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const logFile = writeLog(tmpDir, [
      { ts: '2026-01-01T10:00:00.000Z', tool: 'api/call', verdict: 'allow', durationMs: 5, args: { authorization: fakeJwt } },
    ]);
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { findings: Array<{ category: string }> };
    expect(r.findings.some(f => f.category.toLowerCase().includes('jwt'))).toBe(true);
  });

  test('11. --limit caps findings count', () => {
    const tokens = Array.from({ length: 5 }, (_, i) => `ghp_${'C'.repeat(35)}${i}`);
    const logFile = writeLog(tmpDir, tokens.map((t, i) => ({
      ts: `2026-01-01T10:0${i}:00.000Z`, tool: 'github/push', verdict: 'allow', durationMs: 5,
      args: { token: t },
    })));
    const { stdout } = run(['--since', SINCE, '--json', '--limit', '2'], logFile);
    const r = JSON.parse(stdout) as { findings: unknown[] };
    expect(r.findings.length).toBeLessThanOrEqual(2);
  });

  test('12. --exit-code causes exit 1 when findings exist', () => {
    const fakeToken = 'ghp_' + 'D'.repeat(36);
    const logFile = writeLog(tmpDir, [
      { ts: '2026-01-01T10:00:00.000Z', tool: 'github/push', verdict: 'allow', durationMs: 5, args: { token: fakeToken } },
    ]);
    const { status } = run(['--since', SINCE, '--exit-code'], logFile);
    expect(status).toBe(1);
  });

  test('13. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const { status } = run(['--since', SINCE], missing);
    expect(status).toBe(1);
  });

  test('14. --json has "logFile" field', () => {
    const logFile = writeLog(tmpDir, [
      { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read', verdict: 'allow', durationMs: 5 },
    ]);
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { logFile: string };
    expect(typeof r.logFile).toBe('string');
    expect(r.logFile.length).toBeGreaterThan(0);
  });
});
