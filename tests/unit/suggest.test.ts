/**
 * Unit tests for `warden suggest` — policy rule suggestions from audit log.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-suggest-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeLog(tmpDir: string, entries: object[]): string {
  const logFile = path.join(tmpDir, 'audit.jsonl');
  fs.writeFileSync(logFile, entries.map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');
  return logFile;
}

function runSuggest(
  args: string[],
  logFile: string,
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'suggest', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

function repeat<T>(item: T, n: number): T[] {
  return Array.from({ length: n }, () => item);
}

const makeEntry = (tool: string, verdict: 'allow' | 'deny' | 'killed') => ({
  ts: '2026-01-01T10:00:00.000Z',
  tool,
  verdict,
  durationMs: 5,
});

describe('warden suggest', () => {
  let tmpDir: string;
  let logFile: string;

  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  describe('high deny rate → deny suggestion', () => {
    beforeEach(() => {
      tmpDir  = makeTmpDir();
      const entries = [
        ...repeat(makeEntry('fs/delete_file', 'allow'), 2),
        ...repeat(makeEntry('fs/delete_file', 'deny'),  4), // 67% deny rate
      ];
      logFile = writeLog(tmpDir, entries);
    });

    test('1. exits 0', () => {
      expect(runSuggest([], logFile).status).toBe(0);
    });

    test('2. text output contains tool name', () => {
      const { stdout } = runSuggest([], logFile);
      expect(stdout).toMatch(/fs\/delete_file/);
    });

    test('3. text output mentions "deny"', () => {
      const { stdout } = runSuggest([], logFile);
      expect(stdout).toMatch(/deny/i);
    });

    test('4. --json has suggestions array', () => {
      const { stdout } = runSuggest(['--json'], logFile);
      const result = JSON.parse(stdout) as { suggestions: unknown[] };
      expect(Array.isArray(result.suggestions)).toBe(true);
      expect(result.suggestions.length).toBeGreaterThan(0);
    });

    test('5. --json suggestion has action=deny', () => {
      const { stdout } = runSuggest(['--json'], logFile);
      const result = JSON.parse(stdout) as { suggestions: Array<{ tool: string; action: string }> };
      const s = result.suggestions.find(x => x.tool === 'fs/delete_file');
      expect(s?.action).toBe('deny');
    });
  });

  describe('dangerous tool name → deny suggestion', () => {
    beforeEach(() => {
      tmpDir  = makeTmpDir();
      const entries = repeat(makeEntry('bash/run', 'allow'), 5);
      logFile = writeLog(tmpDir, entries);
    });

    test('6. bash/run gets a deny suggestion despite all-allow', () => {
      const { stdout } = runSuggest([], logFile);
      expect(stdout).toMatch(/bash\/run/);
      expect(stdout).toMatch(/deny/i);
    });

    test('7. --json suggestion for dangerous tool', () => {
      const { stdout } = runSuggest(['--json'], logFile);
      const result = JSON.parse(stdout) as { suggestions: Array<{ tool: string; action: string }> };
      const s = result.suggestions.find(x => x.tool === 'bash/run');
      expect(s?.action).toBe('deny');
    });
  });

  describe('high-volume all-allowed → rate-limit suggestion', () => {
    beforeEach(() => {
      tmpDir  = makeTmpDir();
      const entries = repeat(makeEntry('fs/read_file', 'allow'), 15);
      logFile = writeLog(tmpDir, entries);
    });

    test('8. high-volume safe tool gets rate-limit suggestion', () => {
      const { stdout } = runSuggest(['--min-calls', '3'], logFile);
      expect(stdout).toMatch(/rate.?limit/i);
    });

    test('9. --json rate-limit suggestion has action=rate-limit', () => {
      const { stdout } = runSuggest(['--json', '--min-calls', '3'], logFile);
      const result = JSON.parse(stdout) as { suggestions: Array<{ tool: string; action: string }> };
      const s = result.suggestions.find(x => x.tool === 'fs/read_file');
      expect(s?.action).toBe('rate-limit');
    });
  });

  describe('filters and output modes', () => {
    beforeEach(() => {
      tmpDir  = makeTmpDir();
      const entries = repeat(makeEntry('fs/delete_file', 'deny'), 5);
      logFile = writeLog(tmpDir, entries);
    });

    test('10. --yaml outputs policy: rules: section', () => {
      const { stdout } = runSuggest(['--yaml'], logFile);
      expect(stdout).toMatch(/policy:/);
      expect(stdout).toMatch(/rules:/);
    });

    test('11. --yaml output is not JSON', () => {
      const { stdout } = runSuggest(['--yaml'], logFile);
      expect(() => JSON.parse(stdout)).toThrow();
    });

    test('12. --min-calls filters out low-count tools', () => {
      // Only 5 entries for fs/delete_file — with min-calls=10 it should not suggest
      const { stdout } = runSuggest(['--min-calls', '10'], logFile);
      // Either "no suggestions" or output without the tool
      const suggests = !stdout.match(/fs\/delete_file/);
      const noData = stdout.match(/no suggestions|insufficient data/i);
      expect(suggests || noData).toBeTruthy();
    });
  });

  describe('edge cases', () => {
    test('13. empty log → no suggestions message', () => {
      tmpDir  = makeTmpDir();
      logFile = writeLog(tmpDir, []);
      const { stdout, status } = runSuggest([], logFile);
      expect(status).toBe(0);
      expect(stdout).toMatch(/no suggestions|insufficient/i);
    });

    test('14. exits 1 when log file is missing', () => {
      tmpDir = makeTmpDir();
      const missing = path.join(tmpDir, 'no.jsonl');
      const { status } = runSuggest([], missing);
      expect(status).toBe(1);
    });

    test('15. --since filters out old entries', () => {
      tmpDir = makeTmpDir();
      const entries = [
        ...repeat({ ts: '2026-01-01T09:00:00.000Z', tool: 'fs/delete_file', verdict: 'deny', durationMs: 5 }, 5),
      ];
      logFile = writeLog(tmpDir, entries);
      // --since 10:00 means the 09:00 entries are excluded
      const { stdout } = runSuggest(['--since', '2026-01-01T10:00:00.000Z'], logFile);
      expect(stdout).toMatch(/no suggestions|insufficient/i);
    });
  });
});
