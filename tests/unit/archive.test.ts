/**
 * Unit tests for `warden archive` — audit log compression and trimming.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import zlib from 'node:zlib';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-archive-test-${suffix}`);
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
  const r = spawnSync(process.execPath, [CLI, 'archive', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

function readGzip(filePath: string): string {
  const compressed = fs.readFileSync(filePath);
  return zlib.gunzipSync(compressed).toString('utf8');
}

// Old entries: 2025-01-01 (will be archived)
// New entries: 2026-06-01 (will be kept)
// archive --before 2026-01-01 → archives 3 old entries
const OLD_ENTRIES = [
  { ts: '2025-01-01T10:00:00.000Z', tool: 'fs/read',  verdict: 'allow', durationMs: 5 },
  { ts: '2025-01-01T11:00:00.000Z', tool: 'fs/write', verdict: 'deny',  durationMs: 3 },
  { ts: '2025-06-01T09:00:00.000Z', tool: 'bash/exec', verdict: 'killed', durationMs: 1 },
];

const NEW_ENTRIES = [
  { ts: '2026-06-01T10:00:00.000Z', tool: 'github/list', verdict: 'allow', durationMs: 20 },
  { ts: '2026-06-01T11:00:00.000Z', tool: 'github/get',  verdict: 'allow', durationMs: 15 },
];

const BEFORE_DATE = '2026-01-01T00:00:00.000Z';

describe('warden archive', () => {
  let tmpDir: string;
  let logFile: string;

  beforeEach(() => {
    tmpDir  = makeTmpDir();
    logFile = writeLog(tmpDir, [...OLD_ENTRIES, ...NEW_ENTRIES]);
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0', () => {
    const archiveFile = path.join(tmpDir, 'archive.gz');
    const { status } = run(['--before', BEFORE_DATE, '--output', archiveFile], logFile);
    expect(status).toBe(0);
  });

  test('2. creates a gzip archive file', () => {
    const archiveFile = path.join(tmpDir, 'archive.gz');
    run(['--before', BEFORE_DATE, '--output', archiveFile], logFile);
    expect(fs.existsSync(archiveFile)).toBe(true);
    expect(fs.statSync(archiveFile).size).toBeGreaterThan(0);
  });

  test('3. archive contains the 3 old entries', () => {
    const archiveFile = path.join(tmpDir, 'archive.gz');
    run(['--before', BEFORE_DATE, '--output', archiveFile], logFile);
    const content = readGzip(archiveFile);
    const lines   = content.trim().split('\n').filter(Boolean);
    expect(lines.length).toBe(3);
  });

  test('4. archive contains the deny entry', () => {
    const archiveFile = path.join(tmpDir, 'archive.gz');
    run(['--before', BEFORE_DATE, '--output', archiveFile], logFile);
    const content = readGzip(archiveFile);
    expect(content).toMatch(/"verdict":"deny"/);
  });

  test('5. live log is trimmed to 2 new entries after archive', () => {
    const archiveFile = path.join(tmpDir, 'archive.gz');
    run(['--before', BEFORE_DATE, '--output', archiveFile], logFile);
    const lines = fs.readFileSync(logFile, 'utf8').trim().split('\n').filter(Boolean);
    expect(lines.length).toBe(2);
  });

  test('6. live log retains only new entries', () => {
    const archiveFile = path.join(tmpDir, 'archive.gz');
    run(['--before', BEFORE_DATE, '--output', archiveFile], logFile);
    const content = fs.readFileSync(logFile, 'utf8');
    expect(content).toMatch(/2026-06-01/);
    expect(content).not.toMatch(/2025-01-01/);
  });

  test('7. --no-delete keeps live log unchanged', () => {
    const archiveFile = path.join(tmpDir, 'archive.gz');
    run(['--before', BEFORE_DATE, '--output', archiveFile, '--no-delete'], logFile);
    const lines = fs.readFileSync(logFile, 'utf8').trim().split('\n').filter(Boolean);
    expect(lines.length).toBe(5); // all 5 entries still in log
  });

  test('8. --dry-run does not create archive file', () => {
    const archiveFile = path.join(tmpDir, 'archive.gz');
    run(['--before', BEFORE_DATE, '--output', archiveFile, '--dry-run'], logFile);
    expect(fs.existsSync(archiveFile)).toBe(false);
  });

  test('9. --dry-run does not modify live log', () => {
    const archiveFile = path.join(tmpDir, 'archive.gz');
    const before = fs.readFileSync(logFile, 'utf8');
    run(['--before', BEFORE_DATE, '--output', archiveFile, '--dry-run'], logFile);
    const after = fs.readFileSync(logFile, 'utf8');
    expect(before).toBe(after);
  });

  test('10. --dry-run output mentions entry count', () => {
    const archiveFile = path.join(tmpDir, 'archive.gz');
    const { stdout } = run(['--before', BEFORE_DATE, '--output', archiveFile, '--dry-run'], logFile);
    expect(stdout).toMatch(/3/); // 3 old entries
  });

  test('11. --index writes an index JSONL file', () => {
    const archiveFile = path.join(tmpDir, 'archive.gz');
    const indexFile   = path.join(tmpDir, 'archive-index.jsonl');
    run(['--before', BEFORE_DATE, '--output', archiveFile, '--index', indexFile], logFile);
    expect(fs.existsSync(indexFile)).toBe(true);
    const idx = JSON.parse(fs.readFileSync(indexFile, 'utf8').trim());
    expect(idx.calls).toBe(3);
    expect(idx.denied).toBe(1);
    expect(idx.killed).toBe(1);
  });

  test('12. exits 0 when no entries to archive', () => {
    // Only new entries, nothing older than BEFORE_DATE
    const newOnlyLog = writeLog(tmpDir, NEW_ENTRIES);
    const archiveFile = path.join(tmpDir, 'archive.gz');
    const { status } = run(['--before', BEFORE_DATE, '--output', archiveFile], newOnlyLog);
    expect(status).toBe(0);
  });

  test('13. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const { status } = run(['--before', BEFORE_DATE], missing);
    expect(status).toBe(1);
  });

  test('14. stdout confirms archive path and entry count', () => {
    const archiveFile = path.join(tmpDir, 'archive.gz');
    const { stdout } = run(['--before', BEFORE_DATE, '--output', archiveFile], logFile);
    expect(stdout).toMatch(/archive\.gz/);
    expect(stdout).toMatch(/3/);
  });
});
