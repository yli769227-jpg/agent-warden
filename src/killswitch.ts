/**
 * Kill switch for agent-warden.
 *
 * Mechanism: watches a sentinel file (default: ~/.warden/killswitch).
 *   File EXISTS  → kill switch ON  (all tool calls denied)
 *   File ABSENT  → kill switch OFF
 *
 * Uses fs.watch on the parent directory for immediate notification, with a
 * 500 ms periodic poll as a fallback (handles cross-device renames, NFS, etc.).
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { KillSwitchState } from './types.js';

const DEFAULT_PATH = path.join(os.homedir(), '.warden', 'killswitch');
const POLL_INTERVAL_MS = 500;
const PREFIX = '[warden:killswitch]';

function log(msg: string): void {
  process.stderr.write(`${PREFIX} ${msg}\n`);
}

// ---------------------------------------------------------------------------
// Payload stored inside the sentinel file (optional, best-effort).
// ---------------------------------------------------------------------------
interface SentinelPayload {
  reason?: string;
  since?: string; // ISO-8601
}

// ---------------------------------------------------------------------------
// KillSwitch class
// ---------------------------------------------------------------------------

export class KillSwitch {
  private readonly filePath: string;

  private _active: boolean = false;
  private _reason?: string;
  private _since?: Date;

  private _watcher?: fs.FSWatcher;
  private _pollTimer?: ReturnType<typeof setInterval>;

  constructor(filePath?: string) {
    this.filePath =
      filePath ?? process.env['WARDEN_KILLSWITCH'] ?? DEFAULT_PATH;
  }

  // --------------------------------------------------------------------------
  // Public API
  // --------------------------------------------------------------------------

  /** Returns true when the sentinel file exists (kill switch is ON). */
  isKilled(): boolean {
    return this._active;
  }

  /** Returns a snapshot of the current kill-switch state. */
  getState(): KillSwitchState {
    return {
      killed:   this._active,
      reason:   this._reason,
      killedAt: this._since?.toISOString(),
      path:     this.filePath,
    };
  }

  /**
   * Arms the kill switch: creates the sentinel file.
   * If `reason` is provided it is embedded in the file as JSON so that
   * operators can record why the switch was thrown.
   */
  arm(reason?: string): void {
    const dir = path.dirname(this.filePath);
    fs.mkdirSync(dir, { recursive: true });

    const payload: SentinelPayload = { since: new Date().toISOString() };
    if (reason) payload.reason = reason;
    fs.writeFileSync(this.filePath, JSON.stringify(payload), 'utf8');

    // Synchronously reflect state so callers don't have to wait for the watcher.
    this._setArmed(reason);
  }

  /**
   * Disarms the kill switch: removes the sentinel file.
   * Silently ignores ENOENT (already disarmed).
   */
  disarm(): void {
    try {
      fs.unlinkSync(this.filePath);
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== 'ENOENT') throw err;
    }
    this._setDisarmed();
  }

  /**
   * Starts watching the sentinel file.
   * Safe to call multiple times — subsequent calls are no-ops until `close()`.
   */
  watch(): void {
    if (this._pollTimer) return; // already watching

    log(`Watching ${this.filePath}`);

    // Perform an immediate check so the state is current before the first poll.
    this._checkFile();

    // fs.watch on the *directory* so we see both create and delete events.
    const dir = path.dirname(this.filePath);
    const base = path.basename(this.filePath);

    try {
      // Ensure the directory exists before attaching the watcher.
      fs.mkdirSync(dir, { recursive: true });

      this._watcher = fs.watch(dir, { persistent: false }, (_event, filename) => {
        if (filename === base) {
          this._checkFile();
        }
      });

      this._watcher.on('error', (_err) => {
        // Watcher failed (e.g. directory removed). Fall back to polling only.
        this._watcher = undefined;
      });
    } catch {
      // fs.watch unavailable or dir creation failed — polling is the safety net.
    }

    // Periodic fallback poll (catches edge cases: NFS, cross-device renames, …).
    this._pollTimer = setInterval(() => this._checkFile(), POLL_INTERVAL_MS);
    // unref so a process can exit even if close() is never called.
    this._pollTimer.unref?.();
  }

  /** Stops watching. After this call `isKilled()` reflects the last seen state. */
  close(): void {
    this._watcher?.close();
    this._watcher = undefined;

    if (this._pollTimer !== undefined) {
      clearInterval(this._pollTimer);
      this._pollTimer = undefined;
    }
  }

  // --------------------------------------------------------------------------
  // Private helpers
  // --------------------------------------------------------------------------

  private _checkFile(): void {
    const wasActive = this._active;
    const nowExists = fs.existsSync(this.filePath);

    if (nowExists && !wasActive) {
      // Transition: OFF → ON
      const reason = this._readReason();
      this._setArmed(reason);
    } else if (!nowExists && wasActive) {
      // Transition: ON → OFF
      this._setDisarmed();
    }
    // No state change → nothing to do.
  }

  /**
   * Attempts to read the optional reason from the sentinel file.
   * Returns undefined on any error (missing file, malformed JSON, etc.).
   */
  private _readReason(): string | undefined {
    try {
      const raw = fs.readFileSync(this.filePath, 'utf8').trim();
      if (!raw) return undefined;
      const parsed = JSON.parse(raw) as SentinelPayload;
      return parsed.reason;
    } catch {
      return undefined;
    }
  }

  private _setArmed(reason?: string): void {
    this._active = true;
    this._reason = reason;
    this._since = new Date();
    log(`Armed${reason ? ` — ${reason}` : ''}`);
  }

  private _setDisarmed(): void {
    this._active = false;
    this._reason = undefined;
    this._since = undefined;
    log('Disarmed');
  }
}

// ---------------------------------------------------------------------------
// Factory function
// ---------------------------------------------------------------------------

/**
 * Creates a new KillSwitch instance.
 *
 * @param filePath - Override the sentinel file path. Defaults to
 *   `$WARDEN_KILLSWITCH` env var or `~/.warden/killswitch`.
 */
export function createKillSwitch(filePath?: string): KillSwitch {
  return new KillSwitch(filePath);
}
