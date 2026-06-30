/**
 * Unit tests for LogRotator (src/rotate.ts).
 *
 * We manipulate file sizes and mtimes via the filesystem to trigger
 * rotation conditions, then verify the file-system state after rotation.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { createLogRotator, LogRotator } from '../../src/rotate.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-rotate-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeBytes(file: string, bytes: number): void {
  fs.writeFileSync(file, Buffer.alloc(bytes, 'x'), 'utf8');
}

function touchMtime(file: string, ageMs: number): void {
  const mtime = new Date(Date.now() - ageMs);
  fs.utimesSync(file, mtime, mtime);
}

// ─── createLogRotator ─────────────────────────────────────────────────────────

describe('createLogRotator', () => {
  test('1. returns null when enabled is false', () => {
    expect(createLogRotator('/any/path', { enabled: false })).toBeNull();
  });

  test('2. returns a LogRotator when enabled is true', () => {
    expect(createLogRotator('/any/path', { enabled: true })).toBeInstanceOf(LogRotator);
  });
});

// ─── needsRotation ────────────────────────────────────────────────────────────

describe('LogRotator.needsRotation()', () => {
  let tmpDir: string;

  beforeEach(() => { tmpDir = makeTmpDir(); });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('3. non-existent file → false', () => {
    const rotator = new LogRotator(path.join(tmpDir, 'nonexistent.jsonl'), {
      enabled: true,
      maxBytes: 1024,
    });
    expect(rotator.needsRotation()).toBe(false);
  });

  test('4. file size below maxBytes → false', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    writeBytes(logFile, 100);

    const rotator = new LogRotator(logFile, { enabled: true, maxBytes: 1024 });
    expect(rotator.needsRotation()).toBe(false);
  });

  test('5. file size at maxBytes → true', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    writeBytes(logFile, 1024);

    const rotator = new LogRotator(logFile, { enabled: true, maxBytes: 1024 });
    expect(rotator.needsRotation()).toBe(true);
  });

  test('6. file size exceeds maxBytes → true', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    writeBytes(logFile, 2048);

    const rotator = new LogRotator(logFile, { enabled: true, maxBytes: 1024 });
    expect(rotator.needsRotation()).toBe(true);
  });

  test('7. maxAgeMs exceeded → true even if file is small', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    writeBytes(logFile, 10);
    touchMtime(logFile, 2 * 60 * 60 * 1000); // 2 hours old

    const rotator = new LogRotator(logFile, {
      enabled:  true,
      maxBytes: 1024 * 1024,    // 1 MiB — won't trigger
      maxAgeMs: 60 * 60 * 1000, // 1 hour — will trigger
    });
    expect(rotator.needsRotation()).toBe(true);
  });

  test('8. file within age limit → false', () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    writeBytes(logFile, 10);
    touchMtime(logFile, 30 * 60 * 1000); // 30 min old

    const rotator = new LogRotator(logFile, {
      enabled:  true,
      maxBytes: 1024 * 1024,
      maxAgeMs: 60 * 60 * 1000, // 1 hour
    });
    expect(rotator.needsRotation()).toBe(false);
  });
});

// ─── rotate() — compression off ───────────────────────────────────────────────

describe('LogRotator.rotate() — compress: false', () => {
  let tmpDir: string;

  beforeEach(() => { tmpDir = makeTmpDir(); });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('9. rotates current file to .1', async () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(logFile, 'line1\nline2\n', 'utf8');

    const rotator = new LogRotator(logFile, { enabled: true, compress: false });
    await rotator.rotate();

    expect(fs.existsSync(`${logFile}.1`)).toBe(true);
    expect(fs.existsSync(logFile)).toBe(false);
    expect(fs.readFileSync(`${logFile}.1`, 'utf8')).toBe('line1\nline2\n');
  });

  test('10. rotates: .1 → .2, .current → .1', async () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(`${logFile}.1`, 'old-backup', 'utf8');
    fs.writeFileSync(logFile, 'new-content', 'utf8');

    const rotator = new LogRotator(logFile, {
      enabled: true,
      compress: false,
      maxFiles: 5,
    });
    await rotator.rotate();

    expect(fs.readFileSync(`${logFile}.2`, 'utf8')).toBe('old-backup');
    expect(fs.readFileSync(`${logFile}.1`, 'utf8')).toBe('new-content');
  });

  test('11. prunes backups beyond maxFiles', async () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    // Pre-populate backups 1-3 (maxFiles=2 → .3 should be pruned)
    for (let i = 1; i <= 3; i++) {
      fs.writeFileSync(`${logFile}.${i}`, `backup${i}`, 'utf8');
    }
    fs.writeFileSync(logFile, 'current', 'utf8');

    const rotator = new LogRotator(logFile, {
      enabled:  true,
      compress: false,
      maxFiles: 2,
    });
    await rotator.rotate();

    // After shift: .1→.2, .2→.3, but maxFiles=2 means .3 should be pruned
    expect(fs.existsSync(`${logFile}.1`)).toBe(true);
    expect(fs.existsSync(`${logFile}.2`)).toBe(true);
    expect(fs.existsSync(`${logFile}.3`)).toBe(false);
  });
});

// ─── rotate() — compression on ────────────────────────────────────────────────

describe('LogRotator.rotate() — compress: true (default)', () => {
  let tmpDir: string;

  beforeEach(() => { tmpDir = makeTmpDir(); });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  test('12. rotated file is gzip-compressed (.1.gz)', async () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    const content = 'secret line\n'.repeat(100);
    fs.writeFileSync(logFile, content, 'utf8');

    const rotator = new LogRotator(logFile, { enabled: true, compress: true });
    const finalPath = await rotator.rotate();

    expect(finalPath).toBe(`${logFile}.1.gz`);
    expect(fs.existsSync(`${logFile}.1.gz`)).toBe(true);
    expect(fs.existsSync(`${logFile}.1`)).toBe(false); // uncompressed temp deleted
    expect(fs.existsSync(logFile)).toBe(false);        // original renamed away

    // Verify gzip is readable and contains original content
    const compressed = fs.readFileSync(`${logFile}.1.gz`);
    const decompressed = zlib.gunzipSync(compressed).toString('utf8');
    expect(decompressed).toBe(content);
  });

  test('13. listBackups() returns metadata for existing .gz backups', async () => {
    const logFile = path.join(tmpDir, 'audit.jsonl');
    fs.writeFileSync(logFile, 'data\n', 'utf8');

    const rotator = new LogRotator(logFile, { enabled: true, compress: true });
    await rotator.rotate();

    const backups = rotator.listBackups();
    expect(backups).toHaveLength(1);
    expect(backups[0]!.path).toBe(`${logFile}.1.gz`);
    expect(backups[0]!.sizeBytes).toBeGreaterThan(0);
    expect(typeof backups[0]!.mtime.toISOString()).toBe('string');
  });
});
