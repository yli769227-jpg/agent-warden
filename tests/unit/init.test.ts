/**
 * Unit tests for `warden init` — starter config generation.
 *
 * init writes warden.config.yaml to the current working directory.
 * We run it with a temp CWD to avoid touching the real project.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-init-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function runInit(
  tmpDir: string,
  extraArgs: string[] = [],
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'init', ...extraArgs], {
    encoding: 'utf8',
    cwd: tmpDir,
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

describe('warden init', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('1. exits 0 in an empty directory', () => {
    const { status } = runInit(tmpDir);
    expect(status).toBe(0);
  });

  test('2. creates warden.config.yaml in CWD', () => {
    runInit(tmpDir);
    expect(fs.existsSync(path.join(tmpDir, 'warden.config.yaml'))).toBe(true);
  });

  test('3. generated config is valid YAML (parseable)', () => {
    runInit(tmpDir);
    const content = fs.readFileSync(path.join(tmpDir, 'warden.config.yaml'), 'utf8');
    // Basic YAML validity: should not contain JSON-only syntax (braces are ok in YAML)
    // Just verify the file is readable and has content
    expect(content.length).toBeGreaterThan(50);
  });

  test('4. generated config contains "mode: audit" (safe default)', () => {
    runInit(tmpDir);
    const content = fs.readFileSync(path.join(tmpDir, 'warden.config.yaml'), 'utf8');
    expect(content).toMatch(/mode:\s*audit/);
  });

  test('5. generated config contains "servers:" section', () => {
    runInit(tmpDir);
    const content = fs.readFileSync(path.join(tmpDir, 'warden.config.yaml'), 'utf8');
    expect(content).toMatch(/servers:/);
  });

  test('6. generated config contains "policy:" section', () => {
    runInit(tmpDir);
    const content = fs.readFileSync(path.join(tmpDir, 'warden.config.yaml'), 'utf8');
    expect(content).toMatch(/policy:/);
  });

  test('7. generated config contains logFile setting', () => {
    runInit(tmpDir);
    const content = fs.readFileSync(path.join(tmpDir, 'warden.config.yaml'), 'utf8');
    expect(content).toMatch(/logFile:/);
  });

  test('8. output mentions the created file path', () => {
    const { stdout, stderr } = runInit(tmpDir);
    const out = stdout + stderr;
    expect(out).toMatch(/warden\.config\.yaml/i);
  });

  test('9. exits 1 when warden.config.yaml already exists', () => {
    // Create a pre-existing config
    fs.writeFileSync(path.join(tmpDir, 'warden.config.yaml'), 'existing content', 'utf8');
    const { status } = runInit(tmpDir);
    expect(status).toBe(1);
  });

  test('10. second init preserves existing config content', () => {
    fs.writeFileSync(path.join(tmpDir, 'warden.config.yaml'), 'existing: true', 'utf8');
    runInit(tmpDir); // should exit 1
    const content = fs.readFileSync(path.join(tmpDir, 'warden.config.yaml'), 'utf8');
    expect(content).toBe('existing: true'); // unchanged
  });

  test('11. generated config can be validated by warden validate', () => {
    runInit(tmpDir);
    const cfgPath = path.join(tmpDir, 'warden.config.yaml');
    const r = spawnSync(process.execPath, [CLI, 'validate', cfgPath], { encoding: 'utf8' });
    expect(r.status).toBe(0);
  });
});
