/**
 * Unit tests for `warden policy-check` — evaluate policy for a given tool call.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-policy-check-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeConfig(tmpDir: string, yaml: string): string {
  const cfgPath = path.join(tmpDir, 'warden.config.yaml');
  fs.writeFileSync(cfgPath, yaml, 'utf8');
  return cfgPath;
}

function runCheck(
  args: string[],
  cfgPath?: string,
): { stdout: string; stderr: string; status: number } {
  const cfgArgs = cfgPath ? ['--config', cfgPath] : [];
  const r = spawnSync(process.execPath, [CLI, 'policy-check', ...cfgArgs, ...args], {
    encoding: 'utf8',
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

const ALLOW_CONFIG = `
servers:
  fs:
    command: "node"
policy:
  defaultAction: allow
  rules: []
`;

const DENY_CONFIG = `
servers:
  fs:
    command: "node"
mode: enforce
policy:
  defaultAction: deny
  rules: []
`;

const RULE_CONFIG = `
servers:
  fs:
    command: "node"
mode: enforce
policy:
  defaultAction: allow
  rules:
    - tool: "fs/write_file"
      action: deny
      reason: "writes require approval"
    - tool: "fs/read_file"
      action: allow
`;

describe('warden policy-check', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0 for allowed tool', () => {
    const cfgPath = writeConfig(tmpDir, ALLOW_CONFIG);
    const { status } = runCheck(['fs/list_dir'], cfgPath);
    expect(status).toBe(0);
  });

  test('2. text output shows "allow" for allowed tool', () => {
    const cfgPath = writeConfig(tmpDir, ALLOW_CONFIG);
    const { stdout } = runCheck(['fs/list_dir'], cfgPath);
    expect(stdout).toMatch(/allow/i);
  });

  test('3. shows "deny" verdict for denied tool in enforce mode', () => {
    const cfgPath = writeConfig(tmpDir, DENY_CONFIG);
    const { stdout, status } = runCheck(['any/tool'], cfgPath);
    expect(status).toBe(0); // policy-check always exits 0 — it's a dry-run tool
    expect(stdout).toMatch(/deny/i);
  });

  test('4. text output shows "deny" for denied tool', () => {
    const cfgPath = writeConfig(tmpDir, DENY_CONFIG);
    const { stdout } = runCheck(['any/tool'], cfgPath);
    expect(stdout).toMatch(/deny/i);
  });

  test('5. --json produces valid JSON', () => {
    const cfgPath = writeConfig(tmpDir, ALLOW_CONFIG);
    const { stdout, status } = runCheck(['fs/list_dir', '--json'], cfgPath);
    expect(status).toBe(0);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('6. --json has "action" field', () => {
    const cfgPath = writeConfig(tmpDir, ALLOW_CONFIG);
    const { stdout } = runCheck(['fs/list_dir', '--json'], cfgPath);
    const result = JSON.parse(stdout) as { action: string };
    expect(['allow', 'deny']).toContain(result.action);
  });

  test('7. rule: fs/write_file → deny', () => {
    const cfgPath = writeConfig(tmpDir, RULE_CONFIG);
    const { stdout } = runCheck(['fs/write_file'], cfgPath);
    expect(stdout).toMatch(/deny/i);
  });

  test('8. rule: fs/read_file → allow', () => {
    const cfgPath = writeConfig(tmpDir, RULE_CONFIG);
    const { status } = runCheck(['fs/read_file'], cfgPath);
    expect(status).toBe(0);
  });

  test('9. --json deny result has "reason" field', () => {
    const cfgPath = writeConfig(tmpDir, RULE_CONFIG);
    const { stdout } = runCheck(['fs/write_file', '--json'], cfgPath);
    const result = JSON.parse(stdout) as { action: string; reason?: string };
    expect(result.action).toBe('deny');
    expect(result.reason).toMatch(/approval|write/i);
  });

  test('10. exits 1 with no tool name provided', () => {
    const cfgPath = writeConfig(tmpDir, ALLOW_CONFIG);
    const { status, stderr } = runCheck([], cfgPath);
    expect(status).toBe(1);
    expect(stderr).toMatch(/usage|toolname/i);
  });
});
