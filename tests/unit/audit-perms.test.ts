/**
 * Regression test for audit-log file/dir permissions (Low fix).
 * The audit log holds tool args/reasons and must not be group/world readable
 * on shared hosts.
 */

/// <reference types="jest" />
import { jest } from '@jest/globals';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createAuditLogger } from '../../src/audit.js';
import type { AuditEntry } from '../../src/types.js';

const isWindows = process.platform === 'win32';
const d = isWindows ? describe.skip : describe;

d('audit log permissions', () => {
  let tmpDir: string;
  let stderrSpy: jest.SpyInstance;

  beforeEach(() => {
    const suffix = Math.random().toString(36).slice(2);
    tmpDir = path.join(os.tmpdir(), `warden-perms-test-${suffix}`);
    stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });
  afterEach(() => {
    stderrSpy.mockRestore();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('creates the log dir 0700 and file 0600', () => {
    const logFile = path.join(tmpDir, 'nested', 'audit.jsonl');
    const logger = createAuditLogger(logFile);
    const entry = {
      ts: '2026-01-01T00:00:00.000Z',
      tool: 'fs/read',
      verdict: 'allow',
      durationMs: 1,
    } as unknown as AuditEntry;
    logger.log(entry);
    logger.close();

    const fileMode = fs.statSync(logFile).mode & 0o777;
    const dirMode = fs.statSync(path.dirname(logFile)).mode & 0o777;
    expect(fileMode).toBe(0o600);
    expect(dirMode).toBe(0o700);
  });
});
