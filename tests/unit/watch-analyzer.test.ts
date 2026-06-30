/**
 * Unit tests for WatchAnalyzer (src/watch-analyzer.ts).
 *
 * All time is injected via the nowMs parameter so tests never sleep.
 */

import { WatchAnalyzer } from '../../src/watch-analyzer.js';
import type { AuditEntry } from '../../src/types.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

const T0 = 1_000_000_000_000; // arbitrary epoch

function entry(
  tool: string,
  verdict: AuditEntry['verdict'],
  offsetMs: number = 0,
  reason?: string,
): AuditEntry {
  return {
    ts:         new Date(T0 + offsetMs).toISOString(),
    tool,
    verdict,
    args:       {},
    durationMs: 1,
    ...(reason ? { reason } : {}),
  } as AuditEntry;
}

// ─── Burst detection ──────────────────────────────────────────────────────────

describe('WatchAnalyzer — burst detection', () => {
  test('1. no alert below threshold', () => {
    const a = new WatchAnalyzer({ burstThreshold: 5, burstWindowMs: 10_000, alertCooldownMs: 0 });
    for (let i = 0; i < 4; i++) {
      const alerts = a.analyze(entry('fs/read_file', 'allow', i * 100), T0 + i * 100);
      expect(alerts.filter(x => x.type === 'burst')).toHaveLength(0);
    }
  });

  test('2. alert fires exactly at threshold', () => {
    const a = new WatchAnalyzer({ burstThreshold: 5, burstWindowMs: 10_000, alertCooldownMs: 0 });
    for (let i = 0; i < 4; i++) {
      a.analyze(entry('fs/read_file', 'allow', i * 100), T0 + i * 100);
    }
    const alerts = a.analyze(entry('fs/read_file', 'allow', 400), T0 + 400);
    expect(alerts.filter(x => x.type === 'burst')).toHaveLength(1);
    expect(alerts[0]!.count).toBe(5);
  });

  test('3. old calls outside window do not count toward burst', () => {
    const a = new WatchAnalyzer({ burstThreshold: 3, burstWindowMs: 5_000, alertCooldownMs: 0 });
    // Two calls at T0 (outside 5-second window)
    a.analyze(entry('fs/read_file', 'allow', 0), T0);
    a.analyze(entry('fs/read_file', 'allow', 100), T0 + 100);
    // Now jump 6 seconds ahead — those two are stale
    const now = T0 + 6_000;
    a.analyze(entry('fs/read_file', 'allow', 6_000), now); // 1 in window
    const alerts = a.analyze(entry('fs/read_file', 'allow', 6_100), now + 100); // 2 in window
    expect(alerts.filter(x => x.type === 'burst')).toHaveLength(0);
  });

  test('4. burst alert respects cooldown — no duplicate within cooldown window', () => {
    const COOLDOWN = 30_000;
    const a = new WatchAnalyzer({ burstThreshold: 3, burstWindowMs: 60_000, alertCooldownMs: COOLDOWN });
    // Trigger first burst
    for (let i = 0; i < 3; i++) a.analyze(entry('fs/read_file', 'allow', i * 10), T0 + i * 10);
    // Immediately trigger again (same second) — should be suppressed
    const secondAlerts = a.analyze(entry('fs/read_file', 'allow', 30), T0 + 30);
    expect(secondAlerts.filter(x => x.type === 'burst')).toHaveLength(0);
  });

  test('5. burst alert fires again after cooldown expires', () => {
    const COOLDOWN = 30_000;
    const a = new WatchAnalyzer({ burstThreshold: 3, burstWindowMs: 60_000, alertCooldownMs: COOLDOWN });
    // 3 calls at T0, T0+10, T0+20 — third triggers burst, sets lastBurstAlert = T0+20
    for (let i = 0; i < 3; i++) a.analyze(entry('tool', 'allow', i * 10), T0 + i * 10);
    // Need now - lastBurstAlert(=T0+20) >= COOLDOWN → laterNow >= T0 + 20 + COOLDOWN
    const laterNow = T0 + COOLDOWN + 21;
    const alerts = a.analyze(entry('tool', 'allow', COOLDOWN + 21), laterNow);
    expect(alerts.filter(x => x.type === 'burst')).toHaveLength(1);
  });

  test('6. different tools have independent burst buckets', () => {
    const a = new WatchAnalyzer({ burstThreshold: 3, burstWindowMs: 10_000, alertCooldownMs: 0 });
    // 2 calls each — neither should burst
    a.analyze(entry('tool_a', 'allow', 0), T0);
    a.analyze(entry('tool_b', 'allow', 0), T0);
    a.analyze(entry('tool_a', 'allow', 100), T0 + 100);
    const alerts = a.analyze(entry('tool_b', 'allow', 100), T0 + 100);
    expect(alerts.filter(x => x.type === 'burst')).toHaveLength(0);
  });
});

// ─── Deny streak ──────────────────────────────────────────────────────────────

describe('WatchAnalyzer — deny streak', () => {
  test('7. no alert below streak threshold', () => {
    const a = new WatchAnalyzer({ denyStreak: 3, alertCooldownMs: 0 });
    a.analyze(entry('tool', 'deny', 0), T0);
    const alerts = a.analyze(entry('tool', 'deny', 10), T0 + 10);
    expect(alerts.filter(x => x.type === 'deny-streak')).toHaveLength(0);
  });

  test('8. alert fires at exactly the streak threshold', () => {
    const a = new WatchAnalyzer({ denyStreak: 3, alertCooldownMs: 0 });
    a.analyze(entry('tool', 'deny', 0), T0);
    a.analyze(entry('tool', 'deny', 10), T0 + 10);
    const alerts = a.analyze(entry('tool', 'deny', 20), T0 + 20);
    expect(alerts.filter(x => x.type === 'deny-streak')).toHaveLength(1);
    expect(alerts.find(x => x.type === 'deny-streak')!.count).toBe(3);
  });

  test('9. allow resets the streak for that tool', () => {
    const a = new WatchAnalyzer({ denyStreak: 2, alertCooldownMs: 0 });
    a.analyze(entry('tool', 'deny', 0), T0);
    a.analyze(entry('tool', 'allow', 10), T0 + 10); // resets streak
    const alerts = a.analyze(entry('tool', 'deny', 20), T0 + 20); // only 1 deny since reset
    expect(alerts.filter(x => x.type === 'deny-streak')).toHaveLength(0);
  });

  test('10. killed verdict counts toward deny streak', () => {
    const a = new WatchAnalyzer({ denyStreak: 2, alertCooldownMs: 0 });
    a.analyze(entry('tool', 'deny', 0), T0);
    const alerts = a.analyze(entry('tool', 'killed', 10), T0 + 10);
    expect(alerts.filter(x => x.type === 'deny-streak')).toHaveLength(1);
  });

  test('11. streak continues beyond threshold (fires every call)', () => {
    const a = new WatchAnalyzer({ denyStreak: 2, alertCooldownMs: 0 });
    a.analyze(entry('tool', 'deny', 0), T0);
    a.analyze(entry('tool', 'deny', 10), T0 + 10); // streak=2 → alert
    const alerts = a.analyze(entry('tool', 'deny', 20), T0 + 20); // streak=3 → alert
    expect(alerts.filter(x => x.type === 'deny-streak')).toHaveLength(1);
    expect(alerts.find(x => x.type === 'deny-streak')!.count).toBe(3);
  });
});

// ─── Kill switch ──────────────────────────────────────────────────────────────

describe('WatchAnalyzer — kill switch', () => {
  test('12. killed verdict always produces a kill-switch alert', () => {
    const a = new WatchAnalyzer();
    const alerts = a.analyze(entry('github/delete_repo', 'killed', 0, 'emergency'), T0);
    expect(alerts.filter(x => x.type === 'kill-switch')).toHaveLength(1);
    expect(alerts.find(x => x.type === 'kill-switch')!.tool).toBe('github/delete_repo');
  });

  test('13. deny verdict does not produce kill-switch alert', () => {
    const a = new WatchAnalyzer();
    const alerts = a.analyze(entry('tool', 'deny', 0), T0);
    expect(alerts.filter(x => x.type === 'kill-switch')).toHaveLength(0);
  });
});

// ─── Multiple alerts ──────────────────────────────────────────────────────────

describe('WatchAnalyzer — multiple alert types at once', () => {
  test('14. killed entry can produce both deny-streak and kill-switch alerts', () => {
    const a = new WatchAnalyzer({ denyStreak: 2, alertCooldownMs: 0 });
    a.analyze(entry('tool', 'deny', 0), T0);
    const alerts = a.analyze(entry('tool', 'killed', 10), T0 + 10);
    const types = alerts.map(x => x.type);
    expect(types).toContain('deny-streak');
    expect(types).toContain('kill-switch');
  });

  test('15. reset() clears all state', () => {
    const a = new WatchAnalyzer({ burstThreshold: 3, denyStreak: 2, alertCooldownMs: 0 });
    // Build up state
    for (let i = 0; i < 3; i++) a.analyze(entry('tool', 'deny', i * 10), T0 + i * 10);
    a.reset();
    // After reset, counter starts fresh — one deny should not produce streak alert
    const alerts = a.analyze(entry('tool', 'deny', 1000), T0 + 1000);
    expect(alerts.filter(x => x.type === 'deny-streak')).toHaveLength(0);
  });
});
