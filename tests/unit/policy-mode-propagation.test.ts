/**
 * Regression tests for two security fixes:
 *
 *  1. Critical — top-level `mode: enforce` must reach the policy engine.
 *     Previously `PolicyConfig.mode` was never populated from `WardenConfig.mode`,
 *     so the built-in dangerous-pattern enforcement branch was dead and every
 *     dangerous call was silently allowed even in enforce mode.
 *
 *  2. High — the built-in dangerous checks must see through the "<server>/<tool>"
 *     prefix used in multi-server mode. Previously "filesystem/write_file"
 *     matched neither the fs-write name set nor the "*_write" suffix, so the
 *     out-of-cwd write protection never ran under the recommended config.
 */

/// <reference types="jest" />
import { jest } from '@jest/globals';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadConfig } from '../../src/config.js';
import { createPolicyEngine } from '../../src/policy.js';
import type { PolicyConfig } from '../../src/types.js';

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-mode-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

describe('mode propagation into policy engine (Critical fix)', () => {
  let tmpDir: string;
  let stderrSpy: jest.SpyInstance;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });
  afterEach(() => {
    stderrSpy.mockRestore();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('loadConfig copies top-level enforce mode into config.policy.mode', () => {
    const file = path.join(tmpDir, 'c.yaml');
    fs.writeFileSync(
      file,
      'mode: enforce\ndownstreamCommand: ["echo", "hi"]\n',
      'utf8',
    );
    const cfg = loadConfig(file);
    expect(cfg.mode).toBe('enforce');
    expect(cfg.policy.mode).toBe('enforce');
  });

  test('enforce mode from loadConfig denies a dangerous-keyword tool', () => {
    const file = path.join(tmpDir, 'c.yaml');
    fs.writeFileSync(
      file,
      'mode: enforce\ndownstreamCommand: ["echo", "hi"]\n',
      'utf8',
    );
    const cfg = loadConfig(file);
    const engine = createPolicyEngine(cfg.policy);
    const decision = engine.evaluate('delete_everything', {});
    expect(decision.action).toBe('deny');
    expect(decision.isDangerous).toBe(true);
  });

  test('audit mode (default) still allows the same dangerous tool with a warning', () => {
    const file = path.join(tmpDir, 'c.yaml');
    fs.writeFileSync(file, 'downstreamCommand: ["echo", "hi"]\n', 'utf8');
    const cfg = loadConfig(file);
    expect(cfg.policy.mode).toBe('audit');
    const engine = createPolicyEngine(cfg.policy);
    const decision = engine.evaluate('delete_everything', {});
    expect(decision.action).toBe('allow');
    expect(decision.isDangerous).toBe(true);
  });

  test('an explicit per-block policy.mode is not overridden by top-level mode', () => {
    const file = path.join(tmpDir, 'c.yaml');
    fs.writeFileSync(
      file,
      'mode: audit\npolicy:\n  mode: enforce\ndownstreamCommand: ["echo", "hi"]\n',
      'utf8',
    );
    const cfg = loadConfig(file);
    expect(cfg.policy.mode).toBe('enforce');
  });
});

describe('server-prefix normalization for built-in checks (High fix)', () => {
  let stderrSpy: jest.SpyInstance;
  const cfg = (c: Partial<PolicyConfig>): PolicyConfig =>
    ({ defaultAction: 'allow', rules: [], ...c } as unknown as PolicyConfig);

  beforeEach(() => {
    stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });
  afterEach(() => stderrSpy.mockRestore());

  test('prefixed fs-write to an out-of-cwd path is denied in enforce mode', () => {
    const engine = createPolicyEngine(
      cfg({ mode: 'enforce', cwd: '/home/user/project' }),
    );
    const decision = engine.evaluate('filesystem/write_file', {
      path: '/etc/cron.d/pwn',
      content: 'x',
    });
    expect(decision.action).toBe('deny');
    expect(decision.isDangerous).toBe(true);
  });

  test('prefixed fs-write inside cwd is allowed', () => {
    const engine = createPolicyEngine(
      cfg({ mode: 'enforce', cwd: '/home/user/project' }),
    );
    const decision = engine.evaluate('filesystem/write_file', {
      path: '/home/user/project/notes.txt',
      content: 'x',
    });
    expect(decision.action).toBe('allow');
  });

  test('prefixed dangerous-keyword tool is denied in enforce mode', () => {
    const engine = createPolicyEngine(cfg({ mode: 'enforce' }));
    const decision = engine.evaluate('shell/exec', { cmd: 'rm -rf /' });
    expect(decision.action).toBe('deny');
    expect(decision.isDangerous).toBe(true);
  });
});
