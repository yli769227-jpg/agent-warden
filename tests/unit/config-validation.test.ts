/**
 * Regression tests for config enum validation (Medium fix).
 * A typo in an enum field must fail loudly rather than silently degrade to a
 * permissive default.
 */

/// <reference types="jest" />
import { jest } from '@jest/globals';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadConfig } from '../../src/config.js';

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-cfgval-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeCfg(dir: string, body: string): string {
  const file = path.join(dir, 'c.yaml');
  fs.writeFileSync(file, body, 'utf8');
  return file;
}

describe('config enum validation', () => {
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

  test('rejects a typo in top-level mode', () => {
    const file = writeCfg(tmpDir, 'mode: enforcee\ndownstreamCommand: ["echo","hi"]\n');
    expect(() => loadConfig(file)).toThrow(/Invalid mode "enforcee"/);
  });

  test('rejects a typo in policy.defaultAction', () => {
    const file = writeCfg(
      tmpDir,
      'downstreamCommand: ["echo","hi"]\npolicy:\n  defaultAction: deney\n',
    );
    expect(() => loadConfig(file)).toThrow(/Invalid policy\.defaultAction "deney"/);
  });

  test('rejects a typo in a rule action', () => {
    const file = writeCfg(
      tmpDir,
      'downstreamCommand: ["echo","hi"]\npolicy:\n  rules:\n    - tool: "bash"\n      action: allowe\n',
    );
    expect(() => loadConfig(file)).toThrow(/Invalid policy\.rules\[0\]\.action "allowe"/);
  });

  test('accepts a valid enforce config', () => {
    const file = writeCfg(
      tmpDir,
      'mode: enforce\ndownstreamCommand: ["echo","hi"]\npolicy:\n  defaultAction: deny\n  rules:\n    - tool: "fs/read"\n      action: allow\n',
    );
    expect(() => loadConfig(file)).not.toThrow();
  });
});
