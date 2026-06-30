/// <reference types="jest" />
import { jest } from '@jest/globals';
import { createScrubber } from '../../src/scrubber.js';

const REDACTED = '[REDACTED]';

describe('createScrubber', () => {
  // Suppress [warden:scrubber] stderr noise in test output.
  let stderrSpy: jest.SpyInstance;

  beforeEach(() => {
    stderrSpy = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation(() => true);
  });

  afterEach(() => {
    stderrSpy.mockRestore();
  });

  // -------------------------------------------------------------------------
  // 1. No secrets — plain object passthrough
  // -------------------------------------------------------------------------
  test('1. No secrets — plain object passes through with equal value', () => {
    const scrub = createScrubber();
    const input = { name: 'alice', role: 'admin', version: '1.2.3' };
    const result = scrub(input);
    expect(result).toEqual(input);
  });

  // -------------------------------------------------------------------------
  // 2. AWS key redaction
  // -------------------------------------------------------------------------
  test('2. AWS key — AKIAIOSFODNN7EXAMPLE replaced with [REDACTED]', () => {
    const scrub = createScrubber();
    const input = { key: 'AKIAIOSFODNN7EXAMPLE' };
    const result = scrub(input) as typeof input;
    expect(result.key).toBe(REDACTED);
  });

  // -------------------------------------------------------------------------
  // 3. GitHub token redaction
  // -------------------------------------------------------------------------
  test('3. GitHub token — ghp_ token replaced with [REDACTED]', () => {
    const scrub = createScrubber();
    // Pattern: gh[pousr]_[A-Za-z0-9]{36}
    const token = 'ghp_' + 'x'.repeat(36);
    const input = { token };
    const result = scrub(input) as typeof input;
    expect(result.token).toBe(REDACTED);
  });

  // -------------------------------------------------------------------------
  // 4. Bearer token redaction — prefix line preserved, token portion redacted
  // -------------------------------------------------------------------------
  test('4. Bearer token — token portion redacted, "Authorization: " prefix kept', () => {
    const scrub = createScrubber();
    const input = {
      header: 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
    };
    const result = scrub(input) as typeof input;
    expect(result.header).toBe(`Authorization: ${REDACTED}`);
    expect(result.header).not.toContain('eyJ');
  });

  // -------------------------------------------------------------------------
  // 5. Nested object — secret deep inside still gets redacted
  // -------------------------------------------------------------------------
  test('5. Nested object — secret three levels deep is still redacted', () => {
    const scrub = createScrubber();
    const input = {
      outer: {
        middle: {
          inner: { awsKey: 'AKIAIOSFODNN7EXAMPLE' },
        },
      },
    };
    const result = scrub(input) as typeof input;
    expect(
      (result as typeof input).outer.middle.inner.awsKey,
    ).toBe(REDACTED);
  });

  // -------------------------------------------------------------------------
  // 6. Array — only element with secret is redacted; others unchanged
  // -------------------------------------------------------------------------
  test('6. Array — secret element redacted, non-secret element unchanged', () => {
    const scrub = createScrubber();
    const input = [
      { id: 1, credential: 'AKIAIOSFODNN7EXAMPLE' },
      { id: 2, credential: 'plain-value' },
    ];
    const result = scrub(input) as typeof input;
    expect((result as Array<{ id: number; credential: string }>)[0].credential).toBe(REDACTED);
    expect((result as Array<{ id: number; credential: string }>)[1].credential).toBe('plain-value');
  });

  // -------------------------------------------------------------------------
  // 7. API key pattern via custom pattern injection
  // -------------------------------------------------------------------------
  test('7. API key pattern — custom sk- pattern redacts apiKey field value', () => {
    const scrub = createScrubber(['sk-[A-Za-z0-9]+']);
    const input = { apiKey: 'sk-abc123def456ghi789' };
    const result = scrub(input) as typeof input;
    expect(result.apiKey).toBe(REDACTED);
  });

  // -------------------------------------------------------------------------
  // 8. Non-string leaf — numbers and booleans pass through unchanged
  // -------------------------------------------------------------------------
  test('8. Non-string leaf — numbers and booleans are not altered', () => {
    const scrub = createScrubber();
    const input = { count: 42, active: true, ratio: 3.14 };
    const result = scrub(input) as typeof input;
    expect(result.count).toBe(42);
    expect(result.active).toBe(true);
    expect(result.ratio).toBe(3.14);
  });

  // -------------------------------------------------------------------------
  // 9. Null / undefined handling — no crash
  // -------------------------------------------------------------------------
  test('9. Null input does not throw', () => {
    const scrub = createScrubber();
    expect(() => scrub(null)).not.toThrow();
  });

  test('9b. Undefined input does not throw', () => {
    const scrub = createScrubber();
    expect(() => scrub(undefined)).not.toThrow();
  });

  // -------------------------------------------------------------------------
  // 10. structuredClone — original object is not mutated; result is a fresh copy
  // -------------------------------------------------------------------------
  test('10. structuredClone — original is not mutated and result is a new reference', () => {
    const scrub = createScrubber();
    const original = { secret: 'AKIAIOSFODNN7EXAMPLE', safe: 'hello' };
    const snapshotBefore = JSON.stringify(original);

    const result = scrub(original) as typeof original;

    // Original object must be completely unchanged.
    expect(JSON.stringify(original)).toBe(snapshotBefore);
    expect(original.secret).toBe('AKIAIOSFODNN7EXAMPLE');

    // Result must be a distinct object reference.
    expect(result).not.toBe(original);

    // Result must have the secret redacted while safe field survives.
    expect(result.secret).toBe(REDACTED);
    expect(result.safe).toBe('hello');
  });
});
