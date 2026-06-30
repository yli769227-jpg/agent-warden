/// <reference types="jest" />
import { jest } from '@jest/globals';
import { createPolicyEngine } from '../../src/policy.js';
import type { PolicyConfig } from '../../src/types.js';

/** Small helper so test configs are concise. */
const cfg = (c: {
  defaultAction: 'allow' | 'deny';
  rules: { tool: string; action: 'allow' | 'deny'; reason?: string }[];
  mode?: 'audit' | 'enforce';
  cwd?: string;
}): PolicyConfig => c as unknown as PolicyConfig;

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('createPolicyEngine', () => {
  // Suppress [warden:policy] stderr noise so test output stays clean.
  let stderrSpy: jest.SpyInstance;

  beforeEach(() => {
    stderrSpy = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation(() => true);
  });

  afterEach(() => {
    stderrSpy.mockRestore();
  });

  // ── 1. Default allow ──────────────────────────────────────────────────────

  it('1. Default allow — allows an unknown tool when defaultAction is allow', () => {
    const engine = createPolicyEngine(
      cfg({ defaultAction: 'allow', rules: [] }),
    );
    const decision = engine.evaluate('get_user', {});
    expect(decision.action).toBe('allow');
    expect(decision.isDangerous).toBe(false);
  });

  // ── 2. Default deny ───────────────────────────────────────────────────────

  it('2. Default deny — denies an unknown tool when defaultAction is deny', () => {
    const engine = createPolicyEngine(
      cfg({ defaultAction: 'deny', rules: [] }),
    );
    const decision = engine.evaluate('get_user', {});
    expect(decision.action).toBe('deny');
    expect(decision.isDangerous).toBe(false);
  });

  // ── 3. Explicit allow rule ────────────────────────────────────────────────

  it('3. Explicit allow rule — allows read_file when a matching allow rule exists', () => {
    const engine = createPolicyEngine(
      cfg({
        defaultAction: 'deny', // deny by default so the rule is what grants access
        rules: [{ tool: 'read_file', action: 'allow' }],
      }),
    );
    const decision = engine.evaluate('read_file', {});
    expect(decision.action).toBe('allow');
  });

  // ── 4. Explicit deny rule ─────────────────────────────────────────────────

  it('4. Explicit deny rule — denies delete_file when a matching deny rule exists', () => {
    const engine = createPolicyEngine(
      cfg({
        defaultAction: 'allow',
        rules: [{ tool: 'delete_file', action: 'deny' }],
      }),
    );
    const decision = engine.evaluate('delete_file', {});
    expect(decision.action).toBe('deny');
    // Explicit rules match at step 1, so isDangerous should be false here
    // (dangerous-keyword detection is step 2, never reached).
    expect(decision.isDangerous).toBe(false);
  });

  // ── 5. Glob rule ──────────────────────────────────────────────────────────

  it('5. Glob rule — *delete* pattern denies bulk_delete_records', () => {
    const engine = createPolicyEngine(
      cfg({
        defaultAction: 'allow',
        rules: [{ tool: '*delete*', action: 'deny' }],
      }),
    );
    const decision = engine.evaluate('bulk_delete_records', {});
    expect(decision.action).toBe('deny');
  });

  // ── 6. First match wins ───────────────────────────────────────────────────

  it('6. First match wins — allow rule before deny rule grants access', () => {
    const engine = createPolicyEngine(
      cfg({
        defaultAction: 'deny',
        rules: [
          { tool: 'read_file', action: 'allow' },
          { tool: 'read_file', action: 'deny' },
        ],
      }),
    );
    const decision = engine.evaluate('read_file', {});
    expect(decision.action).toBe('allow');
  });

  // ── 7. Dangerous tool detection ───────────────────────────────────────────

  it('7. Dangerous tool detection — exec_shell is marked isDangerous', () => {
    const engine = createPolicyEngine(
      cfg({ defaultAction: 'allow', rules: [], mode: 'audit' }),
    );
    const decision = engine.evaluate('exec_shell', {});
    expect(decision.isDangerous).toBe(true);
  });

  // ── 8. Dangerous tool in audit mode ──────────────────────────────────────

  it('8. Dangerous tool in audit mode — action is allow but isDangerous is true', () => {
    const engine = createPolicyEngine(
      cfg({ defaultAction: 'allow', rules: [], mode: 'audit' }),
    );
    const decision = engine.evaluate('exec_shell', {});
    expect(decision.action).toBe('allow');
    expect(decision.isDangerous).toBe(true);
  });

  // ── 9. Reason field ───────────────────────────────────────────────────────

  it('9. Reason field — deny decision carries a non-empty reason string', () => {
    const engine = createPolicyEngine(
      cfg({ defaultAction: 'deny', rules: [] }),
    );
    const decision = engine.evaluate('list_items', {});
    expect(typeof decision.reason).toBe('string');
    expect(decision.reason.length).toBeGreaterThan(0);
  });

  // ── 10. Case handling ─────────────────────────────────────────────────────

  it('10a. Case handling — glob matching is case-sensitive (uppercase tool does not match lowercase pattern)', () => {
    const engine = createPolicyEngine(
      cfg({
        defaultAction: 'allow',
        rules: [{ tool: 'read_file', action: 'deny' }],
      }),
    );
    // Pattern 'read_file' must NOT match 'READ_FILE'; tool falls through to default (allow).
    const decision = engine.evaluate('READ_FILE', {});
    expect(decision.action).toBe('allow');
  });

  it('10b. Case handling — dangerous keyword detection is case-insensitive (EXEC_SHELL is still dangerous)', () => {
    const engine = createPolicyEngine(
      cfg({ defaultAction: 'allow', rules: [], mode: 'audit' }),
    );
    const decision = engine.evaluate('EXEC_SHELL', {});
    expect(decision.isDangerous).toBe(true);
  });
});
