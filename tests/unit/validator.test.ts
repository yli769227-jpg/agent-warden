/**
 * Unit tests for validateConfigObject (src/validator.ts).
 *
 * Each test exercises one validation concern in isolation by supplying
 * the minimal config structure needed to trigger or suppress that issue.
 */

import { validateConfigObject } from '../../src/validator.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function minValidCfg(): Record<string, unknown> {
  return {
    servers: { fs: { command: 'node' } },
  };
}

function errors(cfg: Record<string, unknown>): string[] {
  return validateConfigObject(cfg)
    .filter(i => i.level === 'error')
    .map(i => i.path);
}

function warnings(cfg: Record<string, unknown>): string[] {
  return validateConfigObject(cfg)
    .filter(i => i.level === 'warning')
    .map(i => i.path);
}

// ─── mode ─────────────────────────────────────────────────────────────────────

describe('validateConfigObject — mode', () => {
  test('1. valid mode "audit" → no error', () => {
    expect(errors({ ...minValidCfg(), mode: 'audit' })).not.toContain('mode');
  });

  test('2. valid mode "enforce" → no error', () => {
    expect(errors({ ...minValidCfg(), mode: 'enforce' })).not.toContain('mode');
  });

  test('3. missing mode → no error (optional field)', () => {
    expect(errors(minValidCfg())).not.toContain('mode');
  });

  test('4. invalid mode → error on "mode"', () => {
    expect(errors({ ...minValidCfg(), mode: 'strict' })).toContain('mode');
  });
});

// ─── servers ──────────────────────────────────────────────────────────────────

describe('validateConfigObject — servers', () => {
  test('5. missing servers → error', () => {
    expect(errors({})).toContain('servers');
  });

  test('6. empty servers → error', () => {
    expect(errors({ servers: {} })).toContain('servers');
  });

  test('7. servers is an array → error', () => {
    expect(errors({ servers: ['bad'] })).toContain('servers');
  });

  test('8. server missing command → error on path', () => {
    const cfg = { servers: { fs: { args: ['x'] } } };
    expect(errors(cfg)).toContain('servers.fs.command');
  });

  test('9. server command is empty string → error', () => {
    const cfg = { servers: { fs: { command: '' } } };
    expect(errors(cfg)).toContain('servers.fs.command');
  });

  test('10. server args is not an array → error', () => {
    const cfg = { servers: { fs: { command: 'node', args: 'bad' } } };
    expect(errors(cfg)).toContain('servers.fs.args');
  });

  test('11. valid server → no server-related errors', () => {
    const cfg = { servers: { fs: { command: 'node', args: ['server.js'] } } };
    expect(errors(cfg).filter(p => p.startsWith('servers'))).toHaveLength(0);
  });
});

// ─── policy ───────────────────────────────────────────────────────────────────

describe('validateConfigObject — policy', () => {
  test('12. valid defaultAction "allow" → no error', () => {
    const cfg = { ...minValidCfg(), policy: { defaultAction: 'allow' } };
    expect(errors(cfg)).not.toContain('policy.defaultAction');
  });

  test('13. invalid defaultAction → error', () => {
    const cfg = { ...minValidCfg(), policy: { defaultAction: 'maybe' } };
    expect(errors(cfg)).toContain('policy.defaultAction');
  });

  test('14. policy.rules is not an array → error', () => {
    const cfg = { ...minValidCfg(), policy: { rules: 'bad' } };
    expect(errors(cfg)).toContain('policy.rules');
  });

  test('15. rule with missing tool → error on rules[0].tool', () => {
    const cfg = { ...minValidCfg(), policy: { rules: [{ action: 'deny' }] } };
    expect(errors(cfg)).toContain('policy.rules[0].tool');
  });

  test('16. rule with invalid action → error on rules[0].action', () => {
    const cfg = { ...minValidCfg(), policy: { rules: [{ tool: 'fs/*', action: 'permit' }] } };
    expect(errors(cfg)).toContain('policy.rules[0].action');
  });

  test('17. valid rule → no error', () => {
    const cfg = { ...minValidCfg(), policy: { rules: [{ tool: 'fs/*', action: 'deny' }] } };
    expect(errors(cfg).filter(p => p.startsWith('policy'))).toHaveLength(0);
  });
});

// ─── scrubber ─────────────────────────────────────────────────────────────────

describe('validateConfigObject — scrubber', () => {
  test('18. scrubber.enabled as string → error', () => {
    const cfg = { ...minValidCfg(), scrubber: { enabled: 'yes' } };
    expect(errors(cfg)).toContain('scrubber.enabled');
  });

  test('19. scrubber.enabled as boolean → no error', () => {
    const cfg = { ...minValidCfg(), scrubber: { enabled: false } };
    expect(errors(cfg)).not.toContain('scrubber.enabled');
  });

  test('20. scrubber.patterns as non-array → error', () => {
    const cfg = { ...minValidCfg(), scrubber: { patterns: 'bad' } };
    expect(errors(cfg)).toContain('scrubber.patterns');
  });
});

// ─── rateLimit ────────────────────────────────────────────────────────────────

describe('validateConfigObject — rateLimit', () => {
  test('21. capacity of 0 → error', () => {
    const cfg = { ...minValidCfg(), rateLimit: { rules: [{ tool: '*', capacity: 0, windowMs: 1000 }] } };
    expect(errors(cfg)).toContain('rateLimit.rules[0].capacity');
  });

  test('22. negative windowMs → error', () => {
    const cfg = { ...minValidCfg(), rateLimit: { rules: [{ tool: '*', capacity: 10, windowMs: -1 }] } };
    expect(errors(cfg)).toContain('rateLimit.rules[0].windowMs');
  });

  test('23. valid rateLimit rule → no error', () => {
    const cfg = { ...minValidCfg(), rateLimit: { rules: [{ tool: '*', capacity: 10, windowMs: 60000 }] } };
    expect(errors(cfg).filter(p => p.startsWith('rateLimit'))).toHaveLength(0);
  });
});

// ─── webhook ──────────────────────────────────────────────────────────────────

describe('validateConfigObject — webhook', () => {
  test('24. enabled=true with empty targets → warning (not error)', () => {
    const cfg = { ...minValidCfg(), webhook: { enabled: true, targets: [] } };
    expect(warnings(cfg)).toContain('webhook.targets');
    expect(errors(cfg)).not.toContain('webhook.targets');
  });

  test('25. enabled=false with empty targets → no warning', () => {
    const cfg = { ...minValidCfg(), webhook: { enabled: false, targets: [] } };
    expect(warnings(cfg)).not.toContain('webhook.targets');
  });

  test('26. targets entry missing url → error', () => {
    const cfg = { ...minValidCfg(), webhook: { targets: [{ maxRetries: 3 }] } };
    expect(errors(cfg)).toContain('webhook.targets[0].url');
  });

  test('27. targets null → no error (equivalent to no targets)', () => {
    const cfg = { ...minValidCfg(), webhook: { targets: null } };
    expect(errors(cfg)).not.toContain('webhook.targets');
  });

  test('28. valid webhook target → no error', () => {
    const cfg = { ...minValidCfg(), webhook: { targets: [{ url: 'https://example.com' }] } };
    expect(errors(cfg).filter(p => p.startsWith('webhook'))).toHaveLength(0);
  });
});

// ─── rotate ───────────────────────────────────────────────────────────────────

describe('validateConfigObject — rotate', () => {
  test('29. rotate.maxBytes of 0 → error', () => {
    const cfg = { ...minValidCfg(), rotate: { enabled: true, maxBytes: 0 } };
    expect(errors(cfg)).toContain('rotate.maxBytes');
  });

  test('30. rotate.maxFiles of 0 → error', () => {
    const cfg = { ...minValidCfg(), rotate: { enabled: true, maxFiles: 0 } };
    expect(errors(cfg)).toContain('rotate.maxFiles');
  });

  test('31. valid rotate config → no error', () => {
    const cfg = { ...minValidCfg(), rotate: { enabled: true, maxBytes: 10485760, maxFiles: 5 } };
    expect(errors(cfg).filter(p => p.startsWith('rotate'))).toHaveLength(0);
  });
});

// ─── logFile ──────────────────────────────────────────────────────────────────

describe('validateConfigObject — logFile', () => {
  test('32. logFile as number → error', () => {
    const cfg = { ...minValidCfg(), logFile: 42 };
    expect(errors(cfg)).toContain('logFile');
  });

  test('33. logFile as string → no error', () => {
    const cfg = { ...minValidCfg(), logFile: '/tmp/audit.jsonl' };
    expect(errors(cfg)).not.toContain('logFile');
  });
});

// ─── Full valid config → zero issues ──────────────────────────────────────────

describe('validateConfigObject — complete valid config', () => {
  test('34. fully-specified valid config produces no issues', () => {
    const cfg = {
      mode: 'enforce',
      logFile: '~/.warden/audit.jsonl',
      servers: {
        fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'] },
      },
      policy: {
        defaultAction: 'allow',
        rules: [
          { tool: 'fs/write_file', action: 'deny', reason: 'writes need approval' },
        ],
      },
      scrubber: { enabled: true, patterns: ['svc_[A-Za-z0-9]{32,}'] },
      rateLimit: {
        enabled: true,
        rules: [{ tool: '*delete*', capacity: 3, windowMs: 300000 }],
      },
      webhook: {
        enabled: true,
        targets: [{ url: 'https://example.com/hook', maxRetries: 3 }],
      },
      rotate: { enabled: true, maxBytes: 10485760, maxFiles: 5, compress: true },
    };
    const issues = validateConfigObject(cfg);
    expect(issues).toHaveLength(0);
  });
});
