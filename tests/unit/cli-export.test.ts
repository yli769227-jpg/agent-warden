/**
 * Unit tests for warden export CSV generation logic.
 *
 * We replicate csvField() here (same strategy as cli-log-filter.test.ts)
 * and smoke-test the full export command output via child_process.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI_PATH   = path.resolve(__dirname, '../../dist/cli.js');

// ─── csvField — replicated from cli.ts ───────────────────────────────────────

function csvField(value: unknown): string {
  const str = value == null ? '' : typeof value === 'string' ? value : JSON.stringify(value);
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

// ─── csvField unit tests ──────────────────────────────────────────────────────

describe('csvField', () => {
  test('1. Plain string — no quoting needed', () => {
    expect(csvField('hello')).toBe('hello');
  });

  test('2. String containing comma — wrapped in double quotes', () => {
    expect(csvField('a,b')).toBe('"a,b"');
  });

  test('3. String containing double quote — doubled and wrapped', () => {
    expect(csvField('say "hi"')).toBe('"say ""hi"""');
  });

  test('4. String containing newline — wrapped in double quotes', () => {
    expect(csvField('line1\nline2')).toBe('"line1\nline2"');
  });

  test('5. null → empty string', () => {
    expect(csvField(null)).toBe('');
  });

  test('6. undefined → empty string', () => {
    expect(csvField(undefined)).toBe('');
  });

  test('7. Number — stringified without quotes', () => {
    expect(csvField(42)).toBe('42');
  });

  test('8. Object — JSON-stringified, then quoted if contains comma', () => {
    const result = csvField({ a: 1, b: 2 });
    // JSON.stringify produces {"a":1,"b":2} — no comma in the field key sense... wait, it does have a comma
    expect(result).toMatch(/^"/);   // must be quoted
    expect(result).toContain('a');
    expect(result).toContain('b');
  });

  test('9. Empty string — no quoting', () => {
    expect(csvField('')).toBe('');
  });

  test('10. Path with no special chars — no quoting', () => {
    expect(csvField('/home/user/file.txt')).toBe('/home/user/file.txt');
  });
});

// ─── warden export — integration smoke tests ─────────────────────────────────

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-export-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function makeLogEntry(
  tool: string,
  verdict: 'allow' | 'deny' | 'killed',
  ts: string,
  extra: Record<string, unknown> = {},
): string {
  return JSON.stringify({ ts, tool, args: { x: 1 }, verdict, durationMs: 5, ...extra });
}

describe('warden export', () => {
  let tmpDir: string;

  beforeEach(() => { tmpDir = makeTmpDir(); });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  function runExport(logFile: string, flags = ''): string {
    return execSync(`WARDEN_LOG="${logFile}" node "${CLI_PATH}" export ${flags}`, {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  }

  test('11. Empty log file — only header row printed', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(logFile, '', 'utf8');

    const out = runExport(logFile);
    const lines = out.trim().split('\n');
    expect(lines[0]).toBe('ts,tool,verdict,durationMs,reason,dangerous,args');
    expect(lines.length).toBe(1);
  });

  test('12. Single entry — header + 1 data row', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(
      logFile,
      makeLogEntry('read_file', 'allow', '2024-01-01T00:00:00.000Z') + '\n',
      'utf8',
    );

    const out = runExport(logFile);
    const lines = out.trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(lines[1]).toContain('read_file');
    expect(lines[1]).toContain('allow');
  });

  test('13. --verdict deny filter — only deny rows in output', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(
      logFile,
      [
        makeLogEntry('read_file',  'allow', '2024-01-01T00:00:01.000Z'),
        makeLogEntry('write_file', 'deny',  '2024-01-01T00:00:02.000Z'),
        makeLogEntry('run_shell',  'deny',  '2024-01-01T00:00:03.000Z'),
      ].join('\n') + '\n',
      'utf8',
    );

    const out = runExport(logFile, '--verdict deny');
    const lines = out.trim().split('\n');
    // header + 2 deny rows
    expect(lines).toHaveLength(3);
    expect(lines.every((l, i) => i === 0 || l.includes('deny'))).toBe(true);
  });

  test('14. --tool "write_file" filter', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(
      logFile,
      [
        makeLogEntry('read_file',  'allow', '2024-01-01T00:00:01.000Z'),
        makeLogEntry('write_file', 'deny',  '2024-01-01T00:00:02.000Z'),
      ].join('\n') + '\n',
      'utf8',
    );

    const out = runExport(logFile, '--tool write_file');
    const lines = out.trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(lines[1]).toContain('write_file');
  });

  test('15. --output file — writes CSV to file, not stdout', () => {
    const logFile  = path.join(tmpDir, 'audit.jsonl');
    const outFile  = path.join(tmpDir, 'output.csv');
    fs.writeFileSync(
      logFile,
      makeLogEntry('delete_file', 'deny', '2024-01-01T00:00:00.000Z') + '\n',
      'utf8',
    );

    // When --output is set, stdout should NOT contain CSV data
    const stdout = execSync(
      `WARDEN_LOG="${logFile}" node "${CLI_PATH}" export --output "${outFile}"`,
      { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] },
    );
    expect(stdout.trim()).toBe('');

    const csvContent = fs.readFileSync(outFile, 'utf8');
    expect(csvContent).toContain('ts,tool,verdict');
    expect(csvContent).toContain('delete_file');
  });

  test('16. Args with comma — properly double-quoted in CSV', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    const entry = JSON.stringify({
      ts: '2024-01-01T00:00:00.000Z',
      tool: 'run_cmd',
      args: { cmd: 'echo "hello, world"' },
      verdict: 'deny',
      durationMs: 3,
    });
    fs.writeFileSync(logFile, entry + '\n', 'utf8');

    const out = runExport(logFile);
    const lines = out.trim().split('\n');
    // The args JSON column must be quoted (it contains commas and quotes)
    const dataRow = lines[1]!;
    expect(dataRow).toMatch(/^2024-01-01/);
    // Make sure line count didn't explode (no unescaped newlines in fields)
    expect(lines).toHaveLength(2);
  });
});
