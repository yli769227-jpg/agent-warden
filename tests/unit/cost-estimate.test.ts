/**
 * Unit tests for `warden cost-estimate` — LLM cost estimation.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-ce-test-${suffix}`);
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
  const r = spawnSync(process.execPath, [CLI, 'cost-estimate', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

const SINCE = '2026-01-01T00:00:00.000Z';

// Known args: {"path":"/file.txt"} = 18 chars, {"url":"https://example.com"} = 26 chars
// totalChars = 18 + 26 = 44
// inputTokens = round(44/4) = 11
// outputTokens = round(11 * 0.3) = 3
// inputUsd = 11/1M * $3 (sonnet-4) = $0.000033
// outputUsd = 3/1M * $15 (sonnet-4) = $0.000045
// totalUsd ≈ $0.000078
const ENTRIES = [
  { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read',  verdict: 'allow', durationMs: 5,  args: { path: '/file.txt' } },
  { ts: '2026-01-01T10:01:00.000Z', tool: 'api/call', verdict: 'allow', durationMs: 10, args: { url: 'https://example.com' } },
];

describe('warden cost-estimate', () => {
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

  test('2. output contains "cost-estimate" header', () => {
    const { stdout } = run(['--since', SINCE], logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/cost.?estimate/i);
  });

  test('3. --json produces valid JSON', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('4. --json totalCalls = 2', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { totalCalls: number };
    expect(r.totalCalls).toBe(2);
  });

  test('5. --json totalChars matches actual JSON serialization', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { totalChars: number };
    // {"path":"/file.txt"} = 20 chars, {"url":"https://example.com"} = 29 chars
    const expected = JSON.stringify({ path: '/file.txt' }).length + JSON.stringify({ url: 'https://example.com' }).length;
    expect(r.totalChars).toBe(expected);
  });

  test('6. --json inputTokens = round(totalChars / 4)', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { totalChars: number; inputTokens: number };
    expect(r.inputTokens).toBe(Math.round(r.totalChars / 4));
  });

  test('7. --json has totalUsd, inputUsd, outputUsd fields', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { totalUsd: number; inputUsd: number; outputUsd: number };
    expect(typeof r.totalUsd).toBe('number');
    expect(typeof r.inputUsd).toBe('number');
    expect(typeof r.outputUsd).toBe('number');
    expect(r.totalUsd).toBeGreaterThan(0);
  });

  test('8. --json totalUsd = inputUsd + outputUsd', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { totalUsd: number; inputUsd: number; outputUsd: number };
    expect(r.totalUsd).toBeCloseTo(r.inputUsd + r.outputUsd, 10);
  });

  test('9. --json byTool contains entries with tool and totalUsd', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { byTool: Array<{ tool: string; totalUsd: number }> };
    expect(r.byTool.length).toBeGreaterThan(0);
    for (const t of r.byTool) {
      expect(typeof t.tool).toBe('string');
      expect(typeof t.totalUsd).toBe('number');
    }
  });

  test('10. --model gpt-4o uses different pricing than default', () => {
    const { stdout: s1 } = run(['--since', SINCE, '--json', '--model', 'claude-sonnet-4'], logFile);
    const { stdout: s2 } = run(['--since', SINCE, '--json', '--model', 'claude-opus-4'],   logFile);
    const r1 = JSON.parse(s1) as { totalUsd: number };
    const r2 = JSON.parse(s2) as { totalUsd: number };
    // Opus is more expensive than Sonnet
    expect(r2.totalUsd).toBeGreaterThan(r1.totalUsd);
  });

  test('11. --chars-per-token 2 gives more tokens than --chars-per-token 4', () => {
    const { stdout: s1 } = run(['--since', SINCE, '--json', '--chars-per-token', '4'], logFile);
    const { stdout: s2 } = run(['--since', SINCE, '--json', '--chars-per-token', '2'], logFile);
    const r1 = JSON.parse(s1) as { inputTokens: number };
    const r2 = JSON.parse(s2) as { inputTokens: number };
    // Half the chars/token → roughly double the tokens (rounding may differ slightly)
    expect(r2.inputTokens).toBeGreaterThan(r1.inputTokens);
    expect(r2.inputTokens).toBeGreaterThanOrEqual(r1.inputTokens * 2 - 1);
  });

  test('12. --list-models outputs available model keys', () => {
    const { stdout } = run(['--list-models'], logFile);
    expect(stdout).toMatch(/claude-sonnet-4/);
    expect(stdout).toMatch(/claude-opus-4/);
  });

  test('13. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const { status } = run(['--since', SINCE], missing);
    expect(status).toBe(1);
  });

  test('14. entries without args field contribute 0 chars', () => {
    const noArgsLog = writeLog(tmpDir, [
      { ts: '2026-01-01T10:00:00.000Z', tool: 'noop', verdict: 'allow', durationMs: 5 },
    ]);
    const { stdout } = run(['--since', SINCE, '--json'], noArgsLog);
    const r = JSON.parse(stdout) as { totalChars: number };
    expect(r.totalChars).toBe(0);
  });
});
