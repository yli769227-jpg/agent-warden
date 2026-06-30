/**
 * Log rotation for agent-warden audit logs.
 *
 * Rotation strategy:
 *  - Size-based: rotate when the current file exceeds maxBytes
 *  - Time-based: rotate when the file is older than maxAgeMs (checked at startup)
 *  - Both conditions can be combined; either triggers a rotation
 *
 * On rotation:
 *  1. Rename audit.jsonl → audit.jsonl.1 (shift existing backups up)
 *  2. Compress the rotated file to .gz (optional)
 *  3. Delete backups beyond maxFiles
 *
 * The rotation never interrupts an in-progress write — it operates on
 * the file system level using rename (atomic on POSIX).
 */

import fs from 'node:fs';
import zlib from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import type { RotateConfig } from './types.js';

export type { RotateConfig };

const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;   // 10 MiB
const DEFAULT_MAX_FILES = 5;

export class LogRotator {
  private readonly logFile: string;
  private readonly maxBytes: number;
  private readonly maxAgeMs:  number | undefined;
  private readonly maxFiles:  number;
  private readonly compress:  boolean;

  constructor(logFile: string, config: RotateConfig) {
    this.logFile  = logFile;
    this.maxBytes = config.maxBytes ?? DEFAULT_MAX_BYTES;
    this.maxAgeMs = config.maxAgeMs;
    this.maxFiles = config.maxFiles ?? DEFAULT_MAX_FILES;
    this.compress = config.compress ?? true;
  }

  /** Returns true if the current log file needs to be rotated. */
  needsRotation(): boolean {
    if (!fs.existsSync(this.logFile)) return false;

    const stat = fs.statSync(this.logFile);

    if (stat.size >= this.maxBytes) return true;

    if (this.maxAgeMs != null) {
      const ageMs = Date.now() - stat.mtimeMs;
      if (ageMs >= this.maxAgeMs) return true;
    }

    return false;
  }

  /**
   * Perform rotation:
   * 1. Shift existing backups: .3.gz → .4.gz, .2.gz → .3.gz, etc.
   * 2. Rename current log → .1 (or .1.gz after compression)
   * 3. Delete backups beyond maxFiles
   *
   * Returns the path of the newly created backup file.
   */
  async rotate(): Promise<string> {
    const ext = this.compress ? '.gz' : '';

    // Shift existing backups up
    for (let i = this.maxFiles - 1; i >= 1; i--) {
      const older = `${this.logFile}.${i}${ext}`;
      const newer = `${this.logFile}.${i + 1}${ext}`;
      if (fs.existsSync(older)) {
        fs.renameSync(older, newer);
      }
    }

    // Rename current → .1 (uncompressed placeholder)
    const rotatedRaw = `${this.logFile}.1`;
    fs.renameSync(this.logFile, rotatedRaw);

    let finalPath: string;

    if (this.compress) {
      // Compress .1 → .1.gz, then delete .1
      finalPath = `${rotatedRaw}.gz`;
      const src  = fs.createReadStream(rotatedRaw);
      const gz   = zlib.createGzip({ level: zlib.constants.Z_BEST_COMPRESSION });
      const dest = fs.createWriteStream(finalPath);
      await pipeline(src, gz, dest);
      fs.unlinkSync(rotatedRaw);
    } else {
      finalPath = rotatedRaw;
    }

    // Prune backups beyond maxFiles
    this.pruneOldBackups(ext);

    process.stderr.write(
      `[warden:rotate] Rotated ${this.logFile} → ${finalPath}\n`,
    );

    return finalPath;
  }

  private pruneOldBackups(ext: string): void {
    for (let i = this.maxFiles + 1; i <= this.maxFiles + 10; i++) {
      const old = `${this.logFile}.${i}${ext}`;
      if (fs.existsSync(old)) {
        fs.unlinkSync(old);
        process.stderr.write(`[warden:rotate] Deleted old backup ${old}\n`);
      } else {
        break;
      }
    }
  }

  /** Returns metadata about existing backups. */
  listBackups(): Array<{ path: string; sizeBytes: number; mtime: Date }> {
    const ext = this.compress ? '.gz' : '';
    const results: Array<{ path: string; sizeBytes: number; mtime: Date }> = [];

    for (let i = 1; i <= this.maxFiles; i++) {
      const p = `${this.logFile}.${i}${ext}`;
      if (fs.existsSync(p)) {
        const s = fs.statSync(p);
        results.push({ path: p, sizeBytes: s.size, mtime: s.mtime });
      } else {
        break;
      }
    }

    return results;
  }
}

export function createLogRotator(logFile: string, config: RotateConfig): LogRotator | null {
  if (!config.enabled) return null;
  return new LogRotator(logFile, config);
}
