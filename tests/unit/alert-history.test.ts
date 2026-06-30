/**
 * Unit tests for `warden alert-history` — incident log of deny/kill events.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-ahist-test-${suffix}`);
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
  const r = spawnSync(process.execPath, [CLI, 'alert-history', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

// Incident A: 10:00 — 2 denies + 1 kill within 30s (one burst incident)
// Incident B: 10:05 — 1 deny (separate incident, > 60s gap)
// Allow events are interleaved but should NOT appear in alert-history
const BASE = '2026-01-01T';
const SINCE = '2026-01-01T00:00:00.000Z';

const ENTRIES = [
  { ts: `${BASE}10:00:00.000Z`, tool: 'fs/read_file',  verdict: 'allow',  durationMs: 5 },
  { ts: `${BASE}10:00:05.000Z`, tool: 'fs/write_file', verdict: 'deny',   durationMs: 3, reason: 'policy' },
  { ts: `${BASE}10:00:10.000Z`, tool: 'fs/delete',     verdict: 'killed', durationMs: 1, reason: 'kill-switch' },
  { ts: `${BASE}10:00:30.000Z`, tool: 'bash/exec',     verdict: 'deny',   durationMs: 2, reason: 'policy' },
  { ts: `${BASE}10:01:00.000Z`, tool: 'github/list',   verdict: 'allow',  durationMs: 20 },
  // gap > 60s before next deny → new incident
  { ts: `${BASE}10:05:00.000Z`, tool: 'github/create', verdict: 'deny',   durationMs: 5, reason: 'blocked' },
  { ts: `${BASE}10:06:00.000Z`, tool: 'fs/read_file',  verdict: 'allow',  durationMs: 8 },
];

const BASE_FLAGS = ['--since', SINCE];

describe('warden alert-history', () => {
  let tmpDir: string;
  let logFile: string;

  beforeEach(() => {
    tmpDir  = makeTmpDir();
    logFile = writeLog(tmpDir, ENTRIES);
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0', () => {
    expect(run(BASE_FLAGS, logFile).status).toBe(0);
  });

  test('2. output contains "alert-history" header', () => {
    const { stdout } = run(BASE_FLAGS, logFile);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/alert.?history/i);
  });

  test('3. --json produces valid JSON', () => {
    const { stdout } = run([...BASE_FLAGS, '--json'], logFile);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('4. --json totalIncidents = 2 (burst window=60s)', () => {
    const { stdout } = run([...BASE_FLAGS, '--json'], logFile);
    const r = JSON.parse(stdout) as { totalIncidents: number };
    expect(r.totalIncidents).toBe(2);
  });

  test('5. --json first incident (newest first) is 10:05 deny', () => {
    const { stdout } = run([...BASE_FLAGS, '--json'], logFile);
    const r = JSON.parse(stdout) as { incidents: Array<{ firstAt: string; count: number }> };
    // newest-first: incidents[0] should be the 10:05 incident
    expect(r.incidents[0]!.firstAt).toMatch(/T10:05/);
    expect(r.incidents[0]!.count).toBe(1);
  });

  test('6. --reverse shows oldest first', () => {
    const { stdout } = run([...BASE_FLAGS, '--json', '--reverse'], logFile);
    const r = JSON.parse(stdout) as { incidents: Array<{ firstAt: string }> };
    expect(r.incidents[0]!.firstAt).toMatch(/T10:00/);
  });

  test('7. --json incident A has denied=2, killed=1', () => {
    const { stdout } = run([...BASE_FLAGS, '--json', '--reverse'], logFile);
    const r = JSON.parse(stdout) as { incidents: Array<{ denied: number; killed: number }> };
    expect(r.incidents[0]!.denied).toBe(2);
    expect(r.incidents[0]!.killed).toBe(1);
  });

  test('8. --json incident A tools contain fs/write_file', () => {
    const { stdout } = run([...BASE_FLAGS, '--json', '--reverse'], logFile);
    const r = JSON.parse(stdout) as { incidents: Array<{ tools: string[] }> };
    expect(r.incidents[0]!.tools).toContain('fs/write_file');
  });

  test('9. --json incident A reasons contain "policy"', () => {
    const { stdout } = run([...BASE_FLAGS, '--json', '--reverse'], logFile);
    const r = JSON.parse(stdout) as { incidents: Array<{ reasons: string[] }> };
    expect(r.incidents[0]!.reasons).toContain('policy');
  });

  test('10. --burst-secs 400 merges into 1 incident', () => {
    const { stdout } = run([...BASE_FLAGS, '--json', '--burst-secs', '400'], logFile);
    const r = JSON.parse(stdout) as { totalIncidents: number };
    expect(r.totalIncidents).toBe(1);
  });

  test('11. --verdict killed shows only killed events', () => {
    const { stdout } = run([...BASE_FLAGS, '--json', '--verdict', 'killed'], logFile);
    const r = JSON.parse(stdout) as { totalIncidents: number; incidents: Array<{ denied: number; killed: number }> };
    expect(r.totalIncidents).toBe(1);
    expect(r.incidents[0]!.killed).toBe(1);
    expect(r.incidents[0]!.denied).toBe(0);
  });

  test('12. --limit 1 returns at most 1 incident', () => {
    const { stdout } = run([...BASE_FLAGS, '--json', '--limit', '1'], logFile);
    const r = JSON.parse(stdout) as { incidents: unknown[] };
    expect(r.incidents.length).toBe(1);
  });

  test('13. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const { status } = run(BASE_FLAGS, missing);
    expect(status).toBe(1);
  });

  test('14. allow-only log prints "No deny or kill events"', () => {
    const cleanLog = writeLog(tmpDir, [
      { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read', verdict: 'allow', durationMs: 5 },
    ]);
    const { stdout } = run([...BASE_FLAGS], cleanLog);
    const plain = stdout.replace(/\x1b\[[0-9;]*m/g, '');
    expect(plain).toMatch(/No deny or kill/i);
  });
});
