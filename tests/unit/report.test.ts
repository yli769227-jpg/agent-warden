/**
 * Unit tests for `warden report` — Markdown audit summary generation.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-report-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeLog(tmpDir: string, entries: object[]): string {
  const logFile = path.join(tmpDir, 'audit.jsonl');
  fs.writeFileSync(logFile, entries.map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');
  return logFile;
}

function runReport(
  args: string[],
  logFile: string,
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'report', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

const BASE_ENTRIES = [
  { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read_file',  verdict: 'allow',  durationMs: 5  },
  { ts: '2026-01-01T10:01:00.000Z', tool: 'fs/write_file', verdict: 'deny',   durationMs: 3, reason: 'policy' },
  { ts: '2026-01-01T10:02:00.000Z', tool: 'github/create', verdict: 'allow',  durationMs: 12 },
  { ts: '2026-01-01T10:03:00.000Z', tool: 'fs/read_file',  verdict: 'allow',  durationMs: 4  },
  { ts: '2026-01-01T10:04:00.000Z', tool: 'fs/read_file',  verdict: 'killed', durationMs: 1  },
];

describe('warden report', () => {
  let tmpDir: string;
  let logFile: string;

  beforeEach(() => {
    tmpDir  = makeTmpDir();
    logFile = writeLog(tmpDir, BASE_ENTRIES);
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0 and outputs Markdown to stdout', () => {
    const { stdout, status } = runReport([], logFile);
    expect(status).toBe(0);
    expect(stdout).toMatch(/^#/m); // Markdown heading
  });

  test('2. report header contains default title', () => {
    const { stdout } = runReport([], logFile);
    expect(stdout).toMatch(/agent-warden audit report/i);
  });

  test('3. --title overrides the Markdown heading', () => {
    const { stdout } = runReport(['--title', 'My Custom Report'], logFile);
    expect(stdout).toMatch(/My Custom Report/);
  });

  test('4. summary table shows total call count', () => {
    const { stdout } = runReport([], logFile);
    // 5 entries in the log
    expect(stdout).toMatch(/5/);
  });

  test('5. summary table includes allow / deny / killed counts', () => {
    const { stdout } = runReport([], logFile);
    expect(stdout).toMatch(/allow/i);
    expect(stdout).toMatch(/deny/i);
    expect(stdout).toMatch(/killed/i);
  });

  test('6. top tools section lists tool names', () => {
    const { stdout } = runReport([], logFile);
    expect(stdout).toMatch(/fs\/read_file/);
    expect(stdout).toMatch(/fs\/write_file/);
  });

  test('7. recent blocked calls section shows denied entries', () => {
    const { stdout } = runReport([], logFile);
    // Should mention the denied write_file call
    expect(stdout).toMatch(/write_file|deny|blocked/i);
  });

  test('8. --output writes Markdown to file instead of stdout', () => {
    const outPath = path.join(tmpDir, 'report.md');
    const { stdout, status } = runReport(['--output', outPath], logFile);
    expect(status).toBe(0);
    expect(fs.existsSync(outPath)).toBe(true);
    const content = fs.readFileSync(outPath, 'utf8');
    expect(content).toMatch(/^#/m);
  });

  test('9. --since filters entries — total count decreases', () => {
    // Only entries from 10:03 onward → 2 entries
    const { stdout } = runReport(['--since', '2026-01-01T10:03:00.000Z'], logFile);
    // Total should be 2 now (entries at 10:03 and 10:04)
    expect(stdout).toMatch(/2/);
    // fs/write_file was before 10:03, should not appear in top tools with traffic
    expect(stdout).not.toMatch(/write_file/);
  });

  test('10. exits 1 when log file is missing', () => {
    const missingLog = path.join(tmpDir, 'does-not-exist.jsonl');
    const r = spawnSync(process.execPath, [CLI, 'report'], {
      encoding: 'utf8',
      env: { ...process.env, WARDEN_LOG: missingLog },
    });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/not found/i);
  });

  test('11. deny rate is included in the report', () => {
    const { stdout } = runReport([], logFile);
    // 2 blocked out of 5 total = 40%
    expect(stdout).toMatch(/40\.0%|deny rate|block rate/i);
  });

  test('12. -o shorthand works same as --output', () => {
    const outPath = path.join(tmpDir, 'short.md');
    const { status } = runReport(['-o', outPath], logFile);
    expect(status).toBe(0);
    expect(fs.existsSync(outPath)).toBe(true);
  });
});
