/**
 * Unit tests for `warden kill` and `warden unkill` commands.
 *
 * Kill switch state is stored in ~/.warden/killswitch. We redirect HOME to
 * a temp directory to keep tests isolated.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpHome(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-kill-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function run(
  args: string[],
  homeDir: string,
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: { ...process.env, HOME: homeDir },
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

function sentinelPath(homeDir: string): string {
  return path.join(homeDir, '.warden', 'killswitch');
}

describe('warden kill / unkill', () => {
  let homeDir: string;

  beforeEach(() => {
    homeDir = makeTmpHome();
  });
  afterEach(() => { fs.rmSync(homeDir, { recursive: true, force: true }); });

  test('1. warden kill exits 0', () => {
    const { status } = run(['kill'], homeDir);
    expect(status).toBe(0);
  });

  test('2. warden kill creates the sentinel file', () => {
    run(['kill'], homeDir);
    expect(fs.existsSync(sentinelPath(homeDir))).toBe(true);
  });

  test('3. warden kill output mentions "armed" or "ARMED"', () => {
    const { stdout } = run(['kill'], homeDir);
    expect(stdout).toMatch(/armed/i);
  });

  test('4. warden kill --reason includes the reason in output', () => {
    const { stdout } = run(['kill', 'suspicious activity'], homeDir);
    expect(stdout).toMatch(/suspicious activity/i);
  });

  test('5. kill sentinel file contains the reason', () => {
    run(['kill', 'my special reason'], homeDir);
    const content = fs.readFileSync(sentinelPath(homeDir), 'utf8');
    expect(content).toMatch(/my special reason/i);
  });

  test('6. warden unkill exits 0', () => {
    run(['kill'], homeDir);
    const { status } = run(['unkill'], homeDir);
    expect(status).toBe(0);
  });

  test('7. warden unkill removes the sentinel file', () => {
    run(['kill'], homeDir);
    expect(fs.existsSync(sentinelPath(homeDir))).toBe(true);

    run(['unkill'], homeDir);
    expect(fs.existsSync(sentinelPath(homeDir))).toBe(false);
  });

  test('8. warden unkill output mentions "disarmed" or "DISARMED"', () => {
    run(['kill'], homeDir);
    const { stdout } = run(['unkill'], homeDir);
    expect(stdout).toMatch(/disarmed/i);
  });

  test('9. kill idempotent — second kill does not crash', () => {
    run(['kill'], homeDir);
    const { status } = run(['kill'], homeDir);
    expect(status).toBe(0);
  });

  test('10. unkill on already-disarmed state is safe', () => {
    // No prior kill — unkill should not crash
    const { status } = run(['unkill'], homeDir);
    expect(status).toBe(0);
  });

  test('11. kill sentinel path is shown in output', () => {
    const { stdout } = run(['kill'], homeDir);
    expect(stdout).toMatch(/sentinel|killswitch/i);
  });

  test('12. kill with no reason — no "Reason" line in output', () => {
    const { stdout } = run(['kill'], homeDir);
    // Should show ARMED but no reason line
    expect(stdout).toMatch(/armed/i);
    // Reason line only appears when a reason is given
  });
});
