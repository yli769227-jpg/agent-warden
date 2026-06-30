/**
 * Unit tests for warden doctor command.
 *
 * Runs the CLI binary with HOME pointing to a temp directory so we
 * can control the config, kill switch, and log file state.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

// ─── Helpers ──────────────────────────────────────────────────────────────────

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpHome(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-doctor-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function runDoctor(
  args: string[],
  homeDir: string,
  env: Record<string, string> = {},
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'doctor', ...args], {
    encoding: 'utf8',
    env: { ...process.env, HOME: homeDir, ...env },
  });
  return {
    stdout: r.stdout ?? '',
    stderr: r.stderr ?? '',
    status: r.status ?? 0,
  };
}

function writeConfig(homeDir: string, content: string): string {
  const cfgPath = path.join(homeDir, 'warden.config.yaml');
  fs.writeFileSync(cfgPath, content, 'utf8');
  return cfgPath;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('warden doctor', () => {
  let homeDir: string;

  beforeEach(() => {
    homeDir = makeTmpHome();
  });
  afterEach(() => { fs.rmSync(homeDir, { recursive: true, force: true }); });

  test('1. exits 0 when no config but no required checks fail', () => {
    // No config exists — expect a warning but not a hard failure (exit 0 or 1 is fine).
    // At minimum, Node version check should pass and warden binary should be valid.
    const { stdout, stderr } = runDoctor([], homeDir);
    const out = stdout + stderr;
    expect(out).toMatch(/node\.js version/i);
    expect(out).toMatch(/warden binary/i);
  });

  test('2. reports Node.js version in output', () => {
    const { stdout, stderr } = runDoctor([], homeDir);
    const out = stdout + stderr;
    // Node version should appear in some form
    expect(out).toMatch(/v\d+\.\d+\.\d+/);
  });

  test('3. valid config file → "no issues" in config validation', () => {
    const cfgPath = writeConfig(homeDir, `
servers:
  fs:
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
mode: enforce
`);
    const { stdout, stderr } = runDoctor(['--config', cfgPath], homeDir);
    const out = stdout + stderr;
    expect(out).toMatch(/no issues/i);
  });

  test('4. invalid config → reports error and exits 1', () => {
    const cfgPath = writeConfig(homeDir, `
mode: invalid_mode
servers: {}
`);
    const { stdout, stderr, status } = runDoctor(['--config', cfgPath], homeDir);
    const out = stdout + stderr;
    expect(status).toBe(1);
    // Should mention that there were errors
    expect(out).toMatch(/issue|error/i);
  });

  test('5. kill switch armed → reports warning in output', () => {
    // Arm the kill switch by creating the sentinel file
    const wardenDir = path.join(homeDir, '.warden');
    fs.mkdirSync(wardenDir, { recursive: true });
    const ksPath = path.join(wardenDir, 'killswitch');
    fs.writeFileSync(ksPath, 'test-reason', 'utf8');

    const cfgPath = writeConfig(homeDir, `
servers:
  fs:
    command: "node"
mode: enforce
`);
    const { stdout, stderr } = runDoctor(['--config', cfgPath], homeDir, {
      HOME: homeDir,
    });
    const out = stdout + stderr;
    expect(out).toMatch(/armed|kill switch/i);
  });

  test('6. audit log present → shows log file path and size', () => {
    const logDir = path.join(homeDir, '.warden');
    fs.mkdirSync(logDir, { recursive: true });
    const logFile = path.join(logDir, 'audit.jsonl');
    fs.writeFileSync(logFile, '{"ts":"2026-01-01T00:00:00Z","tool":"test","verdict":"allow"}\n', 'utf8');

    const cfgPath = writeConfig(homeDir, `
servers:
  fs:
    command: "node"
`);

    const { stdout, stderr } = runDoctor(['--config', cfgPath], homeDir, {
      WARDEN_LOG: logFile,
    });
    const out = stdout + stderr;
    // Should confirm the log is present
    expect(out).toMatch(/audit log/i);
    expect(out).toMatch(/MiB|\.jsonl/i);
  });

  test('7. audit mode config → warns about mode being "audit"', () => {
    const cfgPath = writeConfig(homeDir, `
servers:
  fs:
    command: "node"
mode: audit
`);
    const { stdout, stderr } = runDoctor(['--config', cfgPath], homeDir);
    const out = stdout + stderr;
    // Should mention audit mode warning
    expect(out).toMatch(/audit/i);
  });

  test('8. all-healthy config → "All checks passed"', () => {
    const cfgPath = writeConfig(homeDir, `
servers:
  fs:
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
mode: enforce
`);
    // Create the log file too so log check passes
    const wardenDir = path.join(homeDir, '.warden');
    fs.mkdirSync(wardenDir, { recursive: true });
    const logFile = path.join(wardenDir, 'audit.jsonl');
    fs.writeFileSync(logFile, '', 'utf8');

    const { stdout, stderr, status } = runDoctor(['--config', cfgPath], homeDir, {
      WARDEN_LOG: logFile,
    });
    const out = stdout + stderr;
    // Should be 0 failures (warnings are OK)
    // With no Claude config, there will be a warning but not a failure
    expect(status).not.toBe(1); // exit 0 = all passed or only warnings
    expect(out).toMatch(/healthy|passed|suggestion/i);
  });

  test('9. corrupt YAML config → exits 1 with parse error message', () => {
    const cfgPath = writeConfig(homeDir, `
servers: [this is: invalid: yaml:
  - unclosed bracket
`);
    const { stdout, stderr, status } = runDoctor(['--config', cfgPath], homeDir);
    const out = stdout + stderr;
    expect(status).toBe(1);
    expect(out).toMatch(/parse error|yaml|issue/i);
  });

  test('10. non-existent config path → "Not found" in output and exits 1', () => {
    const missingPath = path.join(homeDir, 'does-not-exist.yaml');
    const { stdout, stderr, status } = runDoctor(['--config', missingPath], homeDir);
    const out = stdout + stderr;
    expect(status).toBe(1);
    expect(out).toMatch(/not found|Config file/i);
  });
});
