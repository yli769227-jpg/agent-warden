/**
 * Webhook alert system for agent-warden.
 *
 * When warden denies or kills a tool call, it can POST a JSON payload to one
 * or more HTTP(S) endpoints so that operations teams receive real-time
 * notification without tailing the audit log.
 *
 * Delivery guarantees:
 *   - Each alert is attempted up to `maxRetries` times (default 3) with
 *     exponential back-off (base 1 s, capped at 30 s).
 *   - Failed alerts after all retries are logged to stderr but never throw
 *     — a webhook failure must never block the proxy response path.
 *   - Alerts are sent in the background (fire-and-forget from the caller).
 *
 * Payload shape (AlertPayload):
 *   {
 *     "source":  "agent-warden",
 *     "version": "0.1.0",
 *     "ts":      "2024-01-01T00:00:00.000Z",
 *     "event":   "deny" | "kill",
 *     "tool":    "filesystem/write_file",
 *     "reason":  "Denied by policy — Deletion is irreversible",
 *     "args":    { ... }   // scrubbed copy
 *   }
 */

import https from 'node:https';
import http  from 'node:http';
import type { WebhookConfig } from './types.js';

export type { WebhookConfig };

// ─── Types ────────────────────────────────────────────────────────────────────

export type AlertEvent = 'deny' | 'kill' | 'rate-limit';

export interface WebhookTarget {
  /** Full URL to POST to (http:// or https://). */
  url: string;
  /** Optional secret included as the X-Warden-Secret request header. */
  secret?: string;
  /** Maximum retries on failure (default 3). */
  maxRetries?: number;
}

export interface AlertPayload {
  source:  'agent-warden';
  version: string;
  ts:      string;
  event:   AlertEvent;
  tool:    string;
  reason:  string;
  args:    unknown;
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

const PREFIX = '[warden:webhook]';

function log(msg: string): void {
  process.stderr.write(`${PREFIX} ${msg}\n`);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms).unref?.());
}

/**
 * Sends a single HTTP(S) POST with the JSON payload.
 * Returns the HTTP status code, or throws on network error.
 */
async function postOnce(
  target: WebhookTarget,
  body: string,
): Promise<number> {
  return new Promise((resolve, reject) => {
    const url    = new URL(target.url);
    const isHttps = url.protocol === 'https:';
    const lib    = isHttps ? https : http;

    const headers: Record<string, string> = {
      'Content-Type':   'application/json',
      'Content-Length': Buffer.byteLength(body).toString(),
      'User-Agent':     'agent-warden/0.1.0',
    };
    if (target.secret) {
      headers['X-Warden-Secret'] = target.secret;
    }

    const req = lib.request(
      {
        hostname: url.hostname,
        port:     url.port || (isHttps ? 443 : 80),
        path:     url.pathname + url.search,
        method:   'POST',
        headers,
        timeout:  5000,
      },
      (res) => {
        res.resume(); // consume response body
        resolve(res.statusCode ?? 0);
      },
    );

    req.on('error',   reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Webhook POST timed out')); });
    req.write(body);
    req.end();
  });
}

/**
 * Posts to a single target with exponential retry.
 * Never rejects — logs failures instead.
 */
async function deliverToTarget(
  target: WebhookTarget,
  body: string,
  tool: string,
): Promise<void> {
  const maxRetries = target.maxRetries ?? 3;
  let attempt      = 0;

  while (attempt <= maxRetries) {
    try {
      const status = await postOnce(target, body);
      if (status >= 200 && status < 300) {
        log(`Delivered alert for "${tool}" → ${target.url} (${status})`);
        return;
      }
      // Non-2xx is treated as a retriable failure
      log(`Attempt ${attempt + 1}/${maxRetries + 1} failed (HTTP ${status}) → ${target.url}`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      log(`Attempt ${attempt + 1}/${maxRetries + 1} error — ${msg} → ${target.url}`);
    }

    attempt++;
    if (attempt <= maxRetries) {
      const backoffMs = Math.min(1000 * 2 ** (attempt - 1), 30_000);
      await sleep(backoffMs);
    }
  }

  log(`Giving up on "${tool}" alert → ${target.url} after ${maxRetries + 1} attempts`);
}

// ─── WebhookAlerter ───────────────────────────────────────────────────────────

export class WebhookAlerter {
  private readonly targets:  WebhookTarget[];
  private readonly allowedEvents: Set<AlertEvent>;
  private readonly version:  string;

  constructor(config: WebhookConfig, version = '0.1.0') {
    this.targets       = config.targets ?? [];
    this.allowedEvents = new Set(config.on ?? ['deny', 'kill', 'rate-limit']);
    this.version       = version;

    // Alert payloads carry the shared secret (X-Warden-Secret) and scrubbed
    // args over the wire. Warn loudly when a target uses plaintext http:// so
    // operators don't unknowingly ship those over an interceptable channel.
    for (const t of this.targets) {
      if (/^http:\/\//i.test(t.url)) {
        log(`WARNING: webhook target uses insecure http:// — secret and payload are sent in cleartext → ${t.url}`);
      }
    }
  }

  /**
   * Fires webhook alerts for the given event.
   *
   * This method is ALWAYS fire-and-forget — it returns immediately and
   * delivers in the background.  It never throws.
   */
  alert(event: AlertEvent, tool: string, reason: string, args: unknown): void {
    if (!this.allowedEvents.has(event) || this.targets.length === 0) return;

    const payload: AlertPayload = {
      source:  'agent-warden',
      version: this.version,
      ts:      new Date().toISOString(),
      event,
      tool,
      reason,
      args,
    };
    const body = JSON.stringify(payload);

    // Fire all targets concurrently in the background.
    for (const target of this.targets) {
      deliverToTarget(target, body, tool).catch((_err) => {
        // deliverToTarget never rejects, but guard anyway.
      });
    }
  }
}

// ─── Factory ─────────────────────────────────────────────────────────────────

export function createWebhookAlerter(
  config: WebhookConfig,
  version = '0.1.0',
): WebhookAlerter | null {
  if (!config.enabled || !config.targets || config.targets.length === 0) return null;
  return new WebhookAlerter(config, version);
}
