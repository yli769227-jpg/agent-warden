import fs from 'fs';
import path from 'path';
import { AuditEntry } from './types.js';

export interface AuditLogger {
  log(entry: AuditEntry): void;
  flush(): void;
  close(): void;
  getStats(): { total: number; allowed: number; denied: number; killed: number };
}

interface Stats {
  total: number;
  allowed: number;
  denied: number;
  killed: number;
}

export function createAuditLogger(logFile: string): AuditLogger {
  const resolvedPath = path.resolve(logFile);
  const dir = path.dirname(resolvedPath);

  // The audit log records tool names, args and reasons — sensitive on shared
  // hosts. Create the directory owner-only (0700) and, if the log file does
  // not yet exist, pre-create it owner-only (0600) so it never briefly exists
  // with the default group/world-readable mode.
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(resolvedPath)) {
    fs.writeFileSync(resolvedPath, '', { encoding: 'utf8', mode: 0o600 });
  }

  const stats: Stats = { total: 0, allowed: 0, denied: 0, killed: 0 };
  let firstWrite = true;
  let closed = false;

  function log(entry: AuditEntry): void {
    if (closed) {
      throw new Error('[warden:audit] Logger is closed');
    }

    if (firstWrite) {
      process.stderr.write(`[warden:audit] Logging to ${resolvedPath}\n`);
      firstWrite = false;
    }

    const line = JSON.stringify(entry) + '\n';
    fs.appendFileSync(resolvedPath, line, { encoding: 'utf8', mode: 0o600 });

    stats.total += 1;
    if (entry.verdict === 'allow') {
      stats.allowed += 1;
    } else if (entry.verdict === 'deny') {
      stats.denied += 1;
    } else if (entry.verdict === 'killed') {
      stats.killed += 1;
    }

    process.stderr.write(
      `[warden:audit] ${entry.verdict} ${entry.tool} (${entry.durationMs}ms)\n`
    );
  }

  function flush(): void {
    // appendFileSync is synchronous — nothing buffered; no-op.
  }

  function close(): void {
    closed = true;
  }

  function getStats(): Stats {
    return { ...stats };
  }

  return { log, flush, close, getStats };
}
