import type { AuditEntry } from './types.js';

export interface WatchAlert {
  type: 'burst' | 'deny-streak' | 'kill-switch';
  tool: string;
  message: string;
  count: number;
}

export interface WatchAnalyzerConfig {
  burstThreshold?: number;   // default 10
  burstWindowMs?:  number;   // default 60_000
  denyStreak?:     number;   // default 3
  alertCooldownMs?: number;  // default 30_000
}

export class WatchAnalyzer {
  private readonly burstThreshold: number;
  private readonly burstWindowMs:  number;
  private readonly denyStreak:     number;
  private readonly alertCooldownMs: number;

  private readonly burstBuckets: Map<string, number[]> = new Map();
  private readonly denyStreaks:   Map<string, number>  = new Map();
  private readonly lastBurstAlert: Map<string, number> = new Map();

  constructor(config: WatchAnalyzerConfig = {}) {
    this.burstThreshold  = config.burstThreshold  ?? 10;
    this.burstWindowMs   = config.burstWindowMs   ?? 60_000;
    this.denyStreak      = config.denyStreak      ?? 3;
    this.alertCooldownMs = config.alertCooldownMs ?? 30_000;
  }

  analyze(entry: AuditEntry, nowMs?: number): WatchAlert[] {
    const alerts: WatchAlert[] = [];
    const tool    = entry.tool ?? 'unknown';
    const verdict = entry.verdict ?? 'unknown';
    const ts      = entry.ts ? new Date(entry.ts).getTime() : (nowMs ?? Date.now());
    const now     = nowMs ?? ts;

    // ── Burst detection ───────────────────────────────────────────────────────
    const calls  = this.burstBuckets.get(tool) ?? [];
    const cutoff = ts - this.burstWindowMs;
    const recent = calls.filter(t => t >= cutoff);
    recent.push(ts);
    this.burstBuckets.set(tool, recent);

    if (recent.length >= this.burstThreshold) {
      const lastAlert = this.lastBurstAlert.get(tool) ?? 0;
      if (now - lastAlert >= this.alertCooldownMs) {
        this.lastBurstAlert.set(tool, now);
        alerts.push({
          type:    'burst',
          tool,
          message: `${tool} called ${recent.length} times in the last ${Math.round(this.burstWindowMs / 1000)}s`,
          count:   recent.length,
        });
      }
    }

    // ── Consecutive deny streak ───────────────────────────────────────────────
    if (verdict === 'deny' || verdict === 'killed') {
      const streak = (this.denyStreaks.get(tool) ?? 0) + 1;
      this.denyStreaks.set(tool, streak);

      if (streak >= this.denyStreak) {
        alerts.push({
          type:    'deny-streak',
          tool,
          message: `${tool} denied ${streak} times in a row`,
          count:   streak,
        });
      }
    } else {
      this.denyStreaks.delete(tool);
    }

    // ── Kill switch event ─────────────────────────────────────────────────────
    if (verdict === 'killed') {
      const reason = (entry as unknown as Record<string, unknown>)['reason'] as string | undefined;
      alerts.push({
        type:    'kill-switch',
        tool,
        message: `${tool} blocked by kill switch${reason ? `: ${reason}` : ''}`,
        count:   1,
      });
    }

    return alerts;
  }

  /** Reset all state — useful for testing. */
  reset(): void {
    this.burstBuckets.clear();
    this.denyStreaks.clear();
    this.lastBurstAlert.clear();
  }
}
