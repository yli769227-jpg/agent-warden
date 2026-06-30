/**
 * Unit tests for `warden export` CSV output.
 *
 * Runs the CLI binary with a temp audit log and inspects the CSV output.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-export-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeLog(tmpDir: string, entries: object[]): string {
  const logFile = path.join(tmpDir, 'audit.jsonl');
  fs.writeFileSync(logFile, entries.map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');
  return logFile;
}

function runExport(
  args: string[],
  logFile: string,
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'export', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

function parseCSV(csv: string): Array<Record<string, string>> {
  const lines = csv.trim().split('\n').filter(l => l.trim());
  if (lines.length === 0) return [];
  const headers = lines[0]!.split(',');
  return lines.slice(1).map(line => {
    const values = line.split(',');
    const row: Record<string, string> = {};
    headers.forEach((h, i) => { row[h!] = values[i] ?? ''; });
    return row;
  });
}

const SAMPLE_ENTRIES = [
  { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read_file',  verdict: 'allow', durationMs: 5,  args: { path: '/tmp' } },
  { ts: '2026-01-01T10:01:00.000Z', tool: 'fs/write_file', verdict: 'deny',  durationMs: 3,  args: { path: '/etc/passwd' }, reason: 'policy', dangerous: true },
  { ts: '2026-01-01T10:02:00.000Z', tool: 'github/create', verdict: 'allow', durationMs: 12, args: {} },
  { ts: '2026-01-01T11:00:00.000Z', tool: 'fs/read_file',  verdict: 'killed', durationMs: 1, args: {} },
];

describe('warden export', () => {
  let tmpDir: string;
  let logFile: string;

  beforeEach(() => {
    tmpDir   = makeTmpDir();
    logFile  = writeLog(tmpDir, SAMPLE_ENTRIES);
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. outputs CSV header row', () => {
    const { stdout, status } = runExport([], logFile);
    expect(status).toBe(0);
    expect(stdout).toMatch(/^ts,tool,verdict/);
  });

  test('2. all entries exported by default', () => {
    const { stdout } = runExport([], logFile);
    const rows = parseCSV(stdout);
    expect(rows).toHaveLength(4);
  });

  test('3. --verdict deny filters to matching rows only', () => {
    const { stdout } = runExport(['--verdict', 'deny'], logFile);
    const rows = parseCSV(stdout);
    expect(rows).toHaveLength(1);
    expect(rows[0]!['tool']).toContain('write_file');
  });

  test('4. --tool fs/read_file filters to matching rows', () => {
    const { stdout } = runExport(['--tool', 'fs/read_file'], logFile);
    const rows = parseCSV(stdout);
    expect(rows.length).toBeGreaterThanOrEqual(2);
    for (const row of rows) {
      expect(row['tool']).toContain('read_file');
    }
  });

  test('5. --since 10:30 restricts to entries after that time', () => {
    // Only the 11:00 entry is after 10:30
    const { stdout } = runExport(['--since', '2026-01-01T10:30:00.000Z'], logFile);
    const rows = parseCSV(stdout);
    expect(rows).toHaveLength(1);
    expect(rows[0]!['verdict']).toBe('killed');
  });

  test('6. --output writes to file instead of stdout', () => {
    const outPath = path.join(tmpDir, 'out.csv');
    const { stdout, status } = runExport(['--output', outPath], logFile);
    expect(status).toBe(0);
    // Stdout should be empty (data goes to file)
    expect(stdout.trim()).toBe('');
    expect(fs.existsSync(outPath)).toBe(true);
    const content = fs.readFileSync(outPath, 'utf8');
    expect(content).toMatch(/^ts,tool,verdict/);
    const rows = parseCSV(content);
    expect(rows).toHaveLength(4);
  });

  test('7. exported rows include durationMs column', () => {
    const { stdout } = runExport(['--verdict', 'deny'], logFile);
    const rows = parseCSV(stdout);
    expect(rows[0]!['durationMs']).toBe('3');
  });

  test('8. exits 1 when log file is missing', () => {
    const missingLog = path.join(tmpDir, 'no-such-file.jsonl');
    const r = spawnSync(process.execPath, [CLI, 'export'], {
      encoding: 'utf8',
      env: { ...process.env, WARDEN_LOG: missingLog },
    });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/not found/i);
  });

  test('9. empty log file exports only header row', () => {
    const emptyLog = path.join(tmpDir, 'empty.jsonl');
    fs.writeFileSync(emptyLog, '', 'utf8');
    const { stdout, status } = runExport([], emptyLog);
    expect(status).toBe(0);
    const rows = parseCSV(stdout);
    expect(rows).toHaveLength(0);
    expect(stdout).toMatch(/^ts,tool,verdict/);
  });

  test('10. -o shorthand works the same as --output', () => {
    const outPath = path.join(tmpDir, 'short.csv');
    const { status } = runExport(['-o', outPath], logFile);
    expect(status).toBe(0);
    expect(fs.existsSync(outPath)).toBe(true);
  });
});
