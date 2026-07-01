/**
 * Regression tests for GitHub token scrubbing (Medium fix):
 *  - fine-grained PATs (github_pat_...) are now redacted
 *  - classic tokens longer than the historical 36-char body still match
 */

/// <reference types="jest" />
import { jest } from '@jest/globals';
import { createScrubber } from '../../src/scrubber.js';

const REDACTED = '[REDACTED]';

describe('GitHub token patterns', () => {
  let stderrSpy: jest.SpyInstance;
  beforeEach(() => {
    stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });
  afterEach(() => stderrSpy.mockRestore());

  test('redacts a fine-grained PAT (github_pat_)', () => {
    const scrub = createScrubber();
    const pat =
      'github_pat_11ABCDE0Y0abcdefghijkl_' +
      '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJ';
    const out = scrub({ note: `token is ${pat}` }) as { note: string };
    expect(out.note).toContain(REDACTED);
    expect(out.note).not.toContain(pat);
  });

  test('redacts a classic token in a bare string leaf', () => {
    const scrub = createScrubber();
    const tok = 'ghp_' + 'A'.repeat(36);
    const out = scrub({ note: `authorization ${tok}` }) as { note: string };
    expect(out.note).toContain(REDACTED);
    expect(out.note).not.toContain(tok);
  });

  test('redacts a classic token longer than 36 body chars', () => {
    const scrub = createScrubber();
    const tok = 'ghp_' + 'B'.repeat(40);
    const out = scrub({ note: tok }) as { note: string };
    expect(out.note).toBe(REDACTED);
  });
});
