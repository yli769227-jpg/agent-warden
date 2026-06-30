/**
 * Unit tests for `warden tool-graph` — tool sequential relationship DOT output.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-tg-test-${suffix}`);
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
  const r = spawnSync(process.execPath, [CLI, 'tool-graph', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

const SINCE = '2026-01-01T00:00:00.000Z';

// Known sequence: fs/read (×3) → fs/write (×2) → git/commit (×2)
// Gap between entries: 1 min (within default 30-min window)
const ENTRIES = [
  { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read',    verdict: 'allow', durationMs: 5 },
  { ts: '2026-01-01T10:01:00.000Z', tool: 'fs/write',   verdict: 'deny',  durationMs: 3 },
  { ts: '2026-01-01T10:02:00.000Z', tool: 'git/commit', verdict: 'allow', durationMs: 10 },
  { ts: '2026-01-01T10:03:00.000Z', tool: 'fs/read',    verdict: 'allow', durationMs: 5 },
  { ts: '2026-01-01T10:04:00.000Z', tool: 'fs/write',   verdict: 'deny',  durationMs: 3 },
  { ts: '2026-01-01T10:05:00.000Z', tool: 'git/commit', verdict: 'allow', durationMs: 10 },
  { ts: '2026-01-01T10:06:00.000Z', tool: 'fs/read',    verdict: 'allow', durationMs: 5 },
];

describe('warden tool-graph', () => {
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

  test('2. default output starts with "digraph"', () => {
    const { stdout } = run(['--since', SINCE], logFile);
    expect(stdout.trim()).toMatch(/^digraph/);
  });

  test('3. DOT output contains node declarations', () => {
    const { stdout } = run(['--since', SINCE], logFile);
    expect(stdout).toMatch(/\[label=/);
  });

  test('4. DOT output contains edge declarations with "->"', () => {
    const { stdout } = run(['--since', SINCE], logFile);
    expect(stdout).toMatch(/->/);
  });

  test('5. DOT output mentions "fs/read"', () => {
    const { stdout } = run(['--since', SINCE], logFile);
    expect(stdout).toMatch(/fs\/read/);
  });

  test('6. fs/read → fs/write edge appears in DOT (count 2)', () => {
    const { stdout } = run(['--since', SINCE], logFile);
    // Edge: "fs/read" -> "fs/write" with label 2
    expect(stdout).toMatch(/"fs\/read".*->.*"fs\/write"/s);
    expect(stdout).toMatch(/label="2"/);
  });

  test('7. --json produces valid JSON', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('8. --json has nodes and edges arrays', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { nodes: unknown[]; edges: unknown[] };
    expect(Array.isArray(r.nodes)).toBe(true);
    expect(Array.isArray(r.edges)).toBe(true);
  });

  test('9. --json nodes contain tool, calls, denyRate fields', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { nodes: Array<{ tool: string; calls: number; denyRate: number }> };
    for (const n of r.nodes) {
      expect(typeof n.tool).toBe('string');
      expect(typeof n.calls).toBe('number');
      expect(typeof n.denyRate).toBe('number');
    }
  });

  test('10. --json fs/write node has denyRate = 100 (2/2 denied)', () => {
    const { stdout } = run(['--since', SINCE, '--json'], logFile);
    const r = JSON.parse(stdout) as { nodes: Array<{ tool: string; denyRate: number }> };
    const fw = r.nodes.find(n => n.tool === 'fs/write');
    expect(fw?.denyRate).toBe(100);
  });

  test('11. --output writes DOT to file', () => {
    const dotFile = path.join(tmpDir, 'graph.dot');
    run(['--since', SINCE, '--output', dotFile], logFile);
    expect(fs.existsSync(dotFile)).toBe(true);
    const content = fs.readFileSync(dotFile, 'utf8');
    expect(content).toMatch(/digraph/);
  });

  test('12. --min-weight 3 removes edges with count < 3', () => {
    // fs/read → fs/write appears 2× — should be excluded with --min-weight 3
    const { stdout } = run(['--since', SINCE, '--json', '--min-weight', '3'], logFile);
    const r = JSON.parse(stdout) as { edges: Array<{ from: string; to: string; count: number }> };
    for (const e of r.edges) {
      expect(e.count).toBeGreaterThanOrEqual(3);
    }
  });

  test('13. exits 1 when log file is missing', () => {
    const missing = path.join(tmpDir, 'missing.jsonl');
    const { status } = run(['--since', SINCE], missing);
    expect(status).toBe(1);
  });

  test('14. empty log outputs valid DOT with no edges', () => {
    const empty = writeLog(tmpDir, []);
    const { stdout } = run(['--since', SINCE], empty);
    expect(stdout).toMatch(/digraph/);
    expect(stdout).not.toMatch(/->/); // no edges
  });
});
