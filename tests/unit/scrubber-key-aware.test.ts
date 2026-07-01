/**
 * Regression tests for the key-aware scrubbing fix (High).
 *
 * Structured MCP args like { "password": "hunter2long" } are walked
 * key-by-key, so the value leaf never matches a format regex. The scrubber
 * must redact string values whose *key* looks sensitive, regardless of value
 * shape, so credentials don't leak into audit.jsonl / webhook payloads.
 */

/// <reference types="jest" />
import { jest } from '@jest/globals';
import { createScrubber } from '../../src/scrubber.js';

const REDACTED = '[REDACTED]';

describe('key-aware scrubbing', () => {
  let stderrSpy: jest.SpyInstance;
  beforeEach(() => {
    stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });
  afterEach(() => stderrSpy.mockRestore());

  test.each([
    'password',
    'passwd',
    'apiKey',
    'api_key',
    'api-key',
    'token',
    'accessToken',
    'secret',
    'client_secret',
    'privateKey',
    'credential',
  ])('redacts value under sensitive key "%s"', (key) => {
    const scrub = createScrubber();
    const input = { [key]: 'value-with-no-recognizable-format-1234' };
    const result = scrub(input) as Record<string, unknown>;
    expect(result[key]).toBe(REDACTED);
  });

  test('leaves non-sensitive keys untouched', () => {
    const scrub = createScrubber();
    const input = { username: 'alice', path: '/tmp/notes.txt', count: 3 };
    const result = scrub(input) as typeof input;
    expect(result.username).toBe('alice');
    expect(result.path).toBe('/tmp/notes.txt');
    expect(result.count).toBe(3);
  });

  test('redacts sensitive key nested inside objects and arrays', () => {
    const scrub = createScrubber();
    const input = {
      connections: [
        { host: 'db1', password: 'super-secret-pw-01' },
        { host: 'db2', password: 'super-secret-pw-02' },
      ],
    };
    const result = scrub(input) as typeof input;
    expect(result.connections[0]!.password).toBe(REDACTED);
    expect(result.connections[1]!.password).toBe(REDACTED);
    expect(result.connections[0]!.host).toBe('db1');
  });

  test('does not blanket-redact a sensitive key whose value is an object', () => {
    const scrub = createScrubber();
    const input = { credentials: { username: 'bob', note: 'not a secret string' } };
    const result = scrub(input) as typeof input;
    // Object value recurses rather than being blackholed to a string token.
    expect(typeof result.credentials).toBe('object');
    expect(result.credentials.username).toBe('bob');
  });

  test('empty sensitive value is left as-is (nothing to hide)', () => {
    const scrub = createScrubber();
    const input = { password: '' };
    const result = scrub(input) as typeof input;
    expect(result.password).toBe('');
  });
});
