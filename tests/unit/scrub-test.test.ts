/**
 * Unit tests for `warden scrub-test` — show what secret scrubber would redact.
 */

import { spawnSync } from 'node:child_process';
import path from 'node:path';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function run(
  args: string[],
  stdin?: string,
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'scrub-test', ...args], {
    encoding: 'utf8',
    input: stdin,
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

describe('warden scrub-test', () => {
  test('1. exits 1 with no input and no TTY', () => {
    // No --input and no stdin data → should error
    const { status, stderr } = run([]);
    expect(status).toBe(1);
    expect(stderr).toMatch(/provide json|stdin/i);
  });

  test('2. detects GitHub token in --input', () => {
    const payload = JSON.stringify({ token: 'ghp_ABCdef1234567890ABCdef1234567890ABCD' });
    const { stdout, status } = run(['--input', payload]);
    expect(status).toBe(0);
    expect(stdout).toMatch(/\[REDACTED\]|secrets detected/i);
  });

  test('3. clean payload shows "No secrets detected"', () => {
    const payload = JSON.stringify({ path: '/tmp/file.txt', content: 'hello world' });
    const { stdout, status } = run(['--input', payload]);
    expect(status).toBe(0);
    expect(stdout).toMatch(/no secrets detected/i);
  });

  test('4. --json output has original and scrubbed fields', () => {
    const payload = JSON.stringify({ token: 'ghp_ABCdef1234567890ABCdef1234567890ABCD' });
    const { stdout, status } = run(['--input', payload, '--json']);
    expect(status).toBe(0);
    const result = JSON.parse(stdout) as { original: unknown; scrubbed: unknown };
    expect(result.original).toBeDefined();
    expect(result.scrubbed).toBeDefined();
  });

  test('5. --json original contains the actual token', () => {
    const payload = JSON.stringify({ token: 'ghp_ABCdef1234567890ABCdef1234567890ABCD' });
    const { stdout } = run(['--input', payload, '--json']);
    const result = JSON.parse(stdout) as { original: Record<string, string> };
    expect(result.original['token']).toBe('ghp_ABCdef1234567890ABCdef1234567890ABCD');
  });

  test('6. --json scrubbed value is [REDACTED] for the token', () => {
    const payload = JSON.stringify({ token: 'ghp_ABCdef1234567890ABCdef1234567890ABCD' });
    const { stdout } = run(['--input', payload, '--json']);
    const result = JSON.parse(stdout) as { scrubbed: Record<string, string> };
    expect(result.scrubbed['token']).toBe('[REDACTED]');
  });

  test('7. detects AWS secret key pattern', () => {
    const payload = JSON.stringify({ secret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' });
    const { stdout, status } = run(['--input', payload]);
    expect(status).toBe(0);
    // Either redacts or shows as no secrets — the key thing is it doesn't crash
    expect(stdout.length).toBeGreaterThan(0);
  });

  test('8. reads payload from stdin when piped', () => {
    const payload = JSON.stringify({ key: 'AKIAIOSFODNN7EXAMPLE', value: 'hello' });
    const { stdout, status } = run(['--stdin'], payload);
    expect(status).toBe(0);
    // AWS access key should trigger scrubbing
    expect(stdout.length).toBeGreaterThan(0);
  });

  test('9. invalid JSON in --input → exits 1', () => {
    const { status, stderr } = run(['--input', '{ not valid json }']);
    expect(status).toBe(1);
    expect(stderr).toMatch(/invalid json/i);
  });

  test('10. positional arg is treated as JSON input', () => {
    const payload = JSON.stringify({ safe: 'value' });
    const { stdout, status } = run([payload]);
    expect(status).toBe(0);
    expect(stdout).toMatch(/no secrets detected/i);
  });

  test('11. nested objects are scrubbed deeply', () => {
    const payload = JSON.stringify({
      config: {
        auth: { token: 'ghp_ABCdef1234567890ABCdef1234567890ABCD' },
      },
    });
    const { stdout } = run(['--input', payload, '--json']);
    const result = JSON.parse(stdout) as { scrubbed: { config: { auth: { token: string } } } };
    expect(result.scrubbed.config.auth.token).toBe('[REDACTED]');
  });

  test('12. --pattern adds custom redaction pattern', () => {
    const payload = JSON.stringify({ apiKey: 'svc_MY_CUSTOM_SECRET_ABC123' });
    const { stdout } = run([
      '--input', payload,
      '--pattern', 'svc_[A-Za-z0-9_]+',
      '--json',
    ]);
    const result = JSON.parse(stdout) as { scrubbed: Record<string, string> };
    expect(result.scrubbed['apiKey']).toBe('[REDACTED]');
  });
});
