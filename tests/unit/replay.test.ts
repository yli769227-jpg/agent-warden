/**
 * Unit tests for `warden replay` — re-evaluate audit entries against current policy.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-replay-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeConfig(tmpDir: string, rulesYaml: string, mode = 'enforce'): string {
  const cfgPath = path.join(tmpDir, 'warden.config.yaml');
  fs.writeFileSync(cfgPath, `
mode: ${mode}
logFile: "${tmpDir}/audit.jsonl"
servers:
  placeholder:
    command: echo
    args: ["placeholder"]
policy:
  defaultAction: allow
  rules:
${rulesYaml}
`.trim() + '\n', 'utf8');
  return cfgPath;
}

function writeLog(tmpDir: string, entries: object[]): string {
  const logFile = path.join(tmpDir, 'audit.jsonl');
  fs.writeFileSync(logFile, entries.map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');
  return logFile;
}

function runReplay(
  args: string[],
  logFile: string,
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'replay', ...args], {
    encoding: 'utf8',
    env: { ...process.env, WARDEN_LOG: logFile },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

// Config that DENIES fs/write_file (indented 4 spaces = under "rules:")
const DENY_WRITE_YAML = '    - tool: "fs/write_file"\n      action: deny\n      reason: "writes not allowed"\n';

// Config that ALLOWS everything (no deny rules)
const ALLOW_ALL_YAML = '    - tool: "*"\n      action: allow\n';

const ENTRIES = [
  { ts: '2026-01-01T10:00:00.000Z', tool: 'fs/read_file',  verdict: 'allow', args: {}, durationMs: 5 },
  { ts: '2026-01-01T10:01:00.000Z', tool: 'fs/write_file', verdict: 'allow', args: {}, durationMs: 5 }, // was allowed, now should be denied
  { ts: '2026-01-01T10:02:00.000Z', tool: 'fs/read_file',  verdict: 'allow', args: {}, durationMs: 5 },
  { ts: '2026-01-01T10:03:00.000Z', tool: 'fs/write_file', verdict: 'allow', args: {}, durationMs: 5 }, // also now denied
];

describe('warden replay', () => {
  let tmpDir: string;
  let logFile: string;

  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  describe('policy matches history (no changes)', () => {
    beforeEach(() => {
      tmpDir  = makeTmpDir();
      const cfg = writeConfig(tmpDir, ALLOW_ALL_YAML, 'enforce');
      logFile = writeLog(tmpDir, ENTRIES);
    });

    test('1. exits 0', () => {
      const cfg = path.join(tmpDir, 'warden.config.yaml');
      const { status } = runReplay(['--config', cfg], logFile);
      expect(status).toBe(0);
    });

    test('2. shows "No verdict changes" when policy matches history', () => {
      const cfg = path.join(tmpDir, 'warden.config.yaml');
      const { stdout } = runReplay(['--config', cfg], logFile);
      expect(stdout).toMatch(/no verdict changes/i);
    });
  });

  describe('policy change detected (fs/write_file now denied)', () => {
    beforeEach(() => {
      tmpDir  = makeTmpDir();
      writeConfig(tmpDir, DENY_WRITE_YAML, 'enforce');
      logFile = writeLog(tmpDir, ENTRIES);
    });

    test('3. exits 0 even with changes', () => {
      const cfg = path.join(tmpDir, 'warden.config.yaml');
      const { status } = runReplay(['--config', cfg], logFile);
      expect(status).toBe(0);
    });

    test('4. text shows verdict change warning', () => {
      const cfg = path.join(tmpDir, 'warden.config.yaml');
      const { stdout } = runReplay(['--config', cfg], logFile);
      expect(stdout).toMatch(/verdict change|changed/i);
    });

    test('5. text shows fs/write_file changed', () => {
      const cfg = path.join(tmpDir, 'warden.config.yaml');
      const { stdout } = runReplay(['--config', cfg], logFile);
      expect(stdout).toMatch(/fs\/write_file/);
    });

    test('6. --json is valid JSON', () => {
      const cfg = path.join(tmpDir, 'warden.config.yaml');
      const { stdout } = runReplay(['--config', cfg, '--json'], logFile);
      expect(() => JSON.parse(stdout)).not.toThrow();
    });

    test('7. --json changedCount = 2', () => {
      const cfg = path.join(tmpDir, 'warden.config.yaml');
      const { stdout } = runReplay(['--config', cfg, '--json'], logFile);
      const r = JSON.parse(stdout) as { changedCount: number };
      expect(r.changedCount).toBe(2);
    });

    test('8. --json replayedTotal = 4', () => {
      const cfg = path.join(tmpDir, 'warden.config.yaml');
      const { stdout } = runReplay(['--config', cfg, '--json'], logFile);
      const r = JSON.parse(stdout) as { replayedTotal: number };
      expect(r.replayedTotal).toBe(4);
    });

    test('9. --json results contains entry with changed=true', () => {
      const cfg = path.join(tmpDir, 'warden.config.yaml');
      const { stdout } = runReplay(['--config', cfg, '--json'], logFile);
      const r = JSON.parse(stdout) as { results: Array<{ changed: boolean; tool: string }> };
      const changed = r.results.filter(x => x.changed && x.tool === 'fs/write_file');
      expect(changed.length).toBe(2);
    });

    test('10. --diff-only shows only changed entries', () => {
      const cfg = path.join(tmpDir, 'warden.config.yaml');
      const { stdout } = runReplay(['--config', cfg, '--diff-only', '--json'], logFile);
      const r = JSON.parse(stdout) as { results: Array<{ changed: boolean }> };
      for (const entry of r.results) {
        expect(entry.changed).toBe(true);
      }
    });

    test('11. --since filters entries', () => {
      const cfg = path.join(tmpDir, 'warden.config.yaml');
      // Only entries at 10:02 and 10:03 (2 entries: 1 allow + 1 now-denied write)
      const { stdout } = runReplay([
        '--config', cfg,
        '--since', '2026-01-01T10:02:00.000Z',
        '--json',
      ], logFile);
      const r = JSON.parse(stdout) as { replayedTotal: number };
      expect(r.replayedTotal).toBe(2);
    });

    test('12. --limit caps replayed entries', () => {
      const cfg = path.join(tmpDir, 'warden.config.yaml');
      const { stdout } = runReplay(['--config', cfg, '--limit', '2', '--json'], logFile);
      const r = JSON.parse(stdout) as { replayedTotal: number };
      expect(r.replayedTotal).toBe(2);
    });
  });

  describe('edge cases', () => {
    test('13. exits 1 when log file is missing', () => {
      tmpDir = makeTmpDir();
      writeConfig(tmpDir, ALLOW_ALL_YAML);
      const cfg     = path.join(tmpDir, 'warden.config.yaml');
      const missing = path.join(tmpDir, 'missing.jsonl');
      const { status } = runReplay(['--config', cfg], missing);
      expect(status).toBe(1);
    });

    test('14. exits 1 when config is missing', () => {
      tmpDir  = makeTmpDir();
      logFile = writeLog(tmpDir, ENTRIES);
      const missing = path.join(tmpDir, 'missing.yaml');
      const { status } = runReplay(['--config', missing], logFile);
      expect(status).toBe(1);
    });
  });
});
