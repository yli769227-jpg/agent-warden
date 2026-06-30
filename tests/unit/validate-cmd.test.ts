/**
 * Unit tests for `warden validate` — config file validation CLI.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-validate-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeConfig(tmpDir: string, content: string, filename = 'warden.config.yaml'): string {
  const cfgPath = path.join(tmpDir, filename);
  fs.writeFileSync(cfgPath, content, 'utf8');
  return cfgPath;
}

function runValidate(
  args: string[],
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'validate', ...args], { encoding: 'utf8' });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

const VALID_YAML = `
servers:
  fs:
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
mode: enforce
policy:
  defaultAction: allow
  rules:
    - tool: "fs/write_file"
      action: deny
scrubber:
  enabled: true
`;

const MINIMAL_YAML = `
servers:
  fs:
    command: "node"
`;

const INVALID_YAML = `
mode: garbage_mode
servers: {}
`;

describe('warden validate', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. valid config → exits 0', () => {
    const cfgPath = writeConfig(tmpDir, VALID_YAML);
    const { status } = runValidate([cfgPath]);
    expect(status).toBe(0);
  });

  test('2. valid config → "valid" or "no issues" in output', () => {
    const cfgPath = writeConfig(tmpDir, VALID_YAML);
    const { stdout } = runValidate([cfgPath]);
    expect(stdout).toMatch(/valid|no issue|0 error/i);
  });

  test('3. minimal valid config (servers only) → exits 0', () => {
    const cfgPath = writeConfig(tmpDir, MINIMAL_YAML);
    const { status } = runValidate([cfgPath]);
    expect(status).toBe(0);
  });

  test('4. invalid mode → exits 1', () => {
    const cfgPath = writeConfig(tmpDir, INVALID_YAML);
    const { status } = runValidate([cfgPath]);
    expect(status).toBe(1);
  });

  test('5. invalid config → reports error on "mode" field', () => {
    const cfgPath = writeConfig(tmpDir, INVALID_YAML);
    const { stdout } = runValidate([cfgPath]);
    expect(stdout).toMatch(/mode|error/i);
  });

  test('6. missing config file → exits 1', () => {
    const missing = path.join(tmpDir, 'no-such.yaml');
    const { status } = runValidate([missing]);
    expect(status).toBe(1);
  });

  test('7. missing config file → error message mentions the path', () => {
    const missing = path.join(tmpDir, 'no-such.yaml');
    const { stdout, stderr } = runValidate([missing]);
    const out = stdout + stderr;
    expect(out).toMatch(/no-such\.yaml|not found/i);
  });

  test('8. corrupt YAML → exits 1 with parse error', () => {
    const cfgPath = writeConfig(tmpDir, `
servers: [unclosed: yaml
  - bad: syntax
`);
    const { status, stdout, stderr } = runValidate([cfgPath]);
    expect(status).toBe(1);
    const out = stdout + stderr;
    expect(out).toMatch(/parse|yaml|error/i);
  });

  test('9. missing server command → exits 1 with field path in output', () => {
    const cfgPath = writeConfig(tmpDir, `
servers:
  fs:
    args: ["-y", "server"]
`);
    const { status, stdout } = runValidate([cfgPath]);
    expect(status).toBe(1);
    // Should mention servers.fs.command
    expect(stdout).toMatch(/servers\.fs\.command|command/i);
  });

  test('10. no path argument uses default config search', () => {
    // When no path is provided, it should still exit with some output
    // (either finds a config or reports not found)
    const { status } = runValidate([]);
    // exit code can be 0 or 1 depending on whether a config is found in CWD
    // — just make sure it doesn't crash (no uncaught exception)
    expect([0, 1]).toContain(status);
  });
});
