/// <reference types="jest" />
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createAuditLogger } from '../../src/audit.js';
import { AuditEntry } from '../../src/types.js';

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-audit-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function makeEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    ts: new Date().toISOString(),
    tool: 'bash',
    args: { command: 'ls' },
    verdict: 'allow',
    durationMs: 10,
    ...overrides,
  };
}

describe('createAuditLogger', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('1. Creates log directory if it does not exist', () => {
    const nestedDir = path.join(tmpDir, 'deep', 'nested', 'dir');
    const logFile = path.join(nestedDir, 'audit.jsonl');

    expect(fs.existsSync(nestedDir)).toBe(false);
    createAuditLogger(logFile);
    expect(fs.existsSync(nestedDir)).toBe(true);
  });

  test('2. Writes a valid JSONL entry when log() is called', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    const logger = createAuditLogger(logFile);
    const entry = makeEntry();

    logger.log(entry);

    const raw = fs.readFileSync(logFile, 'utf8');
    const lines = raw.trim().split('\n');
    expect(lines).toHaveLength(1);
    expect(() => JSON.parse(lines[0])).not.toThrow();
    expect(JSON.parse(lines[0])).toMatchObject(entry);
  });

  test('3. Multiple entries — each on its own line, all valid JSON', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    const logger = createAuditLogger(logFile);

    const entries: AuditEntry[] = [
      makeEntry({ tool: 'bash', verdict: 'allow' }),
      makeEntry({ tool: 'fs/read', verdict: 'deny' }),
      makeEntry({ tool: 'network', verdict: 'killed' }),
    ];

    for (const e of entries) {
      logger.log(e);
    }

    const raw = fs.readFileSync(logFile, 'utf8');
    const lines = raw.trim().split('\n');
    expect(lines).toHaveLength(3);

    for (let i = 0; i < lines.length; i++) {
      expect(() => JSON.parse(lines[i])).not.toThrow();
      expect(JSON.parse(lines[i])).toMatchObject(entries[i]);
    }
  });

  test('4. Stats tracking — 3 allow + 1 deny + 1 killed', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    const logger = createAuditLogger(logFile);

    logger.log(makeEntry({ verdict: 'allow' }));
    logger.log(makeEntry({ verdict: 'allow' }));
    logger.log(makeEntry({ verdict: 'allow' }));
    logger.log(makeEntry({ verdict: 'deny' }));
    logger.log(makeEntry({ verdict: 'killed' }));

    const stats = logger.getStats();
    expect(stats.total).toBe(5);
    expect(stats.allowed).toBe(3);
    expect(stats.denied).toBe(1);
    expect(stats.killed).toBe(1);
  });

  test('5. Entry shape — written entry contains ts, tool, args, verdict fields', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    const logger = createAuditLogger(logFile);

    const entry = makeEntry({
      ts: '2026-06-29T12:00:00.000Z',
      tool: 'fs/write',
      args: { path: '/etc/passwd', content: 'data' },
      verdict: 'deny',
      reason: 'policy block',
    });

    logger.log(entry);

    const raw = fs.readFileSync(logFile, 'utf8');
    const parsed = JSON.parse(raw.trim());

    expect(parsed).toHaveProperty('ts', entry.ts);
    expect(parsed).toHaveProperty('tool', entry.tool);
    expect(parsed).toHaveProperty('args');
    expect(parsed.args).toEqual(entry.args);
    expect(parsed).toHaveProperty('verdict', entry.verdict);
  });

  test('6. flush() does not throw', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    const logger = createAuditLogger(logFile);

    expect(() => logger.flush()).not.toThrow();
  });

  test('7. close() does not throw after logging', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    const logger = createAuditLogger(logFile);

    logger.log(makeEntry());
    expect(() => logger.close()).not.toThrow();
  });
});
