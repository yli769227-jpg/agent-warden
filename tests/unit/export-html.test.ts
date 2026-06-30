/**
 * Unit tests for `warden export-html` — self-contained interactive HTML report.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-ehtml-test-${suffix}`);
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
  cwd?: string,
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'export-html', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
    cwd: cwd ?? process.cwd(),
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

const ENTRIES = [
  { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read_file',  verdict: 'allow',  durationMs: 10 },
  { ts: '2026-01-01T10:01:00.000Z', tool: 'fs/write_file', verdict: 'deny',   durationMs: 5,  reason: 'policy' },
  { ts: '2026-01-01T10:02:00.000Z', tool: 'github/list',   verdict: 'allow',  durationMs: 12 },
  { ts: '2026-01-01T10:03:00.000Z', tool: 'fs/read_file',  verdict: 'allow',  durationMs: 8  },
  { ts: '2026-01-01T10:04:00.000Z', tool: 'bash/exec',     verdict: 'killed', durationMs: 2  },
];

describe('warden export-html', () => {
  let tmpDir: string;
  let logFile: string;

  beforeEach(() => {
    tmpDir  = makeTmpDir();
    logFile = writeLog(tmpDir, ENTRIES);
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0', () => {
    const outFile = path.join(tmpDir, 'report.html');
    expect(run(['--output', outFile], logFile).status).toBe(0);
  });

  test('2. creates HTML file at --output path', () => {
    const outFile = path.join(tmpDir, 'report.html');
    run(['--output', outFile], logFile);
    expect(fs.existsSync(outFile)).toBe(true);
  });

  test('3. output is non-empty HTML', () => {
    const outFile = path.join(tmpDir, 'report.html');
    run(['--output', outFile], logFile);
    const content = fs.readFileSync(outFile, 'utf8');
    expect(content).toMatch(/<!DOCTYPE html>/i);
    expect(content.length).toBeGreaterThan(1000);
  });

  test('4. HTML contains total call count (5)', () => {
    const outFile = path.join(tmpDir, 'report.html');
    run(['--output', outFile], logFile);
    const content = fs.readFileSync(outFile, 'utf8');
    expect(content).toMatch(/"total":5/);
  });

  test('5. HTML contains deny count (1)', () => {
    const outFile = path.join(tmpDir, 'report.html');
    run(['--output', outFile], logFile);
    const content = fs.readFileSync(outFile, 'utf8');
    expect(content).toMatch(/"denied":1/);
  });

  test('6. HTML contains killed count (1)', () => {
    const outFile = path.join(tmpDir, 'report.html');
    run(['--output', outFile], logFile);
    const content = fs.readFileSync(outFile, 'utf8');
    expect(content).toMatch(/"killed":1/);
  });

  test('7. --title sets page title', () => {
    const outFile = path.join(tmpDir, 'report.html');
    run(['--output', outFile, '--title', 'My Custom Report'], logFile);
    const content = fs.readFileSync(outFile, 'utf8');
    expect(content).toMatch(/My Custom Report/);
    expect(content).toMatch(/<title>My Custom Report<\/title>/);
  });

  test('8. HTML contains embedded row data', () => {
    const outFile = path.join(tmpDir, 'report.html');
    run(['--output', outFile], logFile);
    const content = fs.readFileSync(outFile, 'utf8');
    expect(content).toMatch(/fs\/read_file/);
    expect(content).toMatch(/fs\/write_file/);
    expect(content).toMatch(/bash\/exec/);
  });

  test('9. --since filters embedded rows', () => {
    const outFile = path.join(tmpDir, 'report.html');
    run(['--output', outFile, '--since', '2026-01-01T10:03:00.000Z'], logFile);
    const content = fs.readFileSync(outFile, 'utf8');
    // Only entries at 10:03 and 10:04 pass the filter → total = 2
    expect(content).toMatch(/"total":2/);
  });

  test('10. stdout confirms file path', () => {
    const outFile = path.join(tmpDir, 'report.html');
    const { stdout } = run(['--output', outFile], logFile);
    expect(stdout).toMatch(/report\.html/);
  });

  test('11. default output path contains "warden-report" when using cwd', () => {
    const { stdout } = run([], logFile, tmpDir);
    expect(stdout).toMatch(/warden-report/);
    // Verify the file was created
    const files = fs.readdirSync(tmpDir).filter(f => f.startsWith('warden-report') && f.endsWith('.html'));
    expect(files.length).toBe(1);
  });

  test('12. --max-rows limits embedded data', () => {
    const outFile = path.join(tmpDir, 'report.html');
    run(['--output', outFile, '--max-rows', '2'], logFile);
    const content = fs.readFileSync(outFile, 'utf8');
    // Should say "up to 2 rows" in the meta line
    expect(content).toMatch(/up to 2 rows/);
  });

  test('13. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const outFile  = path.join(tmpDir, 'report.html');
    const { status } = run(['--output', outFile], missing);
    expect(status).toBe(1);
  });

  test('14. HTML contains interactive table script', () => {
    const outFile = path.join(tmpDir, 'report.html');
    run(['--output', outFile], logFile);
    const content = fs.readFileSync(outFile, 'utf8');
    expect(content).toMatch(/<script>/);
    // Filter function is present
    expect(content).toMatch(/applyF/);
  });
});
