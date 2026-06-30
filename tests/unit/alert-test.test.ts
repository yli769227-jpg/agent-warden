/**
 * Unit tests for `warden alert-test` — send test webhook to configured targets.
 *
 * Spawns a real child mock HTTP server so spawnSync doesn't block the event loop.
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn, spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-alert-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function runAlertTest(
  args: string[],
): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'alert-test', '--timeout', '2000', ...args], {
    encoding: 'utf8',
    timeout: 8_000,
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

// ── Async mock HTTP server helper ─────────────────────────────────────────────
// Starts the server in THIS process but captures data asynchronously.
// Works because we use async test helpers (beforeEach/afterEach are async).

async function startMockServer(statusCode = 200): Promise<{
  url:      string;
  received: () => string | null;
  close:    () => Promise<void>;
}> {
  let lastBody: string | null = null;

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      lastBody = Buffer.concat(chunks).toString();
      res.writeHead(statusCode, { 'Content-Type': 'text/plain' });
      res.end('ok');
    });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address() as { port: number };
  const url  = `http://127.0.0.1:${addr.port}/webhook`;

  return {
    url,
    received: () => lastBody,
    close:    () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

// ── Helper to call warden alert-test asynchronously ──────────────────────────
// spawnSync blocks the Node.js event loop, so the in-process mock server
// cannot respond while it runs. We use spawn + promise instead.

function runAlertTestAsync(args: string[]): Promise<{ stdout: string; stderr: string; status: number }> {
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    const child = spawn(
      process.execPath,
      [CLI, 'alert-test', '--timeout', '3000', ...args],
      { encoding: 'buffer' },
    );
    child.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
    child.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
    child.on('close', (code) => resolve({ stdout, stderr, status: code ?? 0 }));
  });
}

describe('warden alert-test', () => {
  let tmpDir: string;
  let mock: Awaited<ReturnType<typeof startMockServer>>;

  beforeEach(async () => {
    tmpDir = makeTmpDir();
    mock   = await startMockServer();
  });

  afterEach(async () => {
    await mock.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('1. exits 0 when webhook returns 200', async () => {
    const { status } = await runAlertTestAsync(['--url', mock.url]);
    expect(status).toBe(0);
  });

  test('2. stdout shows delivery confirmation', async () => {
    const { stdout } = await runAlertTestAsync(['--url', mock.url]);
    expect(stdout).toMatch(/✅|sent|success|200/i);
  });

  test('3. server receives POST with JSON body', async () => {
    await runAlertTestAsync(['--url', mock.url]);
    const body = mock.received();
    expect(body).not.toBeNull();
    const parsed = JSON.parse(body!) as { event: string };
    expect(parsed.event).toBe('test');
  });

  test('4. payload has "source" = "agent-warden"', async () => {
    await runAlertTestAsync(['--url', mock.url]);
    const parsed = JSON.parse(mock.received()!) as { source: string };
    expect(parsed.source).toBe('agent-warden');
  });

  test('5. payload has "tool" = "_alert_test"', async () => {
    await runAlertTestAsync(['--url', mock.url]);
    const parsed = JSON.parse(mock.received()!) as { tool: string };
    expect(parsed.tool).toBe('_alert_test');
  });

  test('6. --json produces valid JSON output', async () => {
    const { stdout } = await runAlertTestAsync(['--url', mock.url, '--json']);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  test('7. --json result has ok=true for 200 response', async () => {
    const { stdout } = await runAlertTestAsync(['--url', mock.url, '--json']);
    const result = JSON.parse(stdout) as { targets: Array<{ ok: boolean }> };
    expect(result.targets[0]!.ok).toBe(true);
  });

  test('8. shows error on 500 response (non-zero exit)', async () => {
    const failMock = await startMockServer(500);
    try {
      const { stdout, status } = await runAlertTestAsync(['--url', failMock.url]);
      expect(status).not.toBe(0); // failures → non-zero exit
      expect(stdout).toMatch(/500|❌|failed|error/i);
    } finally {
      await failMock.close();
    }
  });

  test('9. --json result has ok=false for 500 response', async () => {
    const failMock = await startMockServer(500);
    try {
      const { stdout } = await runAlertTestAsync(['--url', failMock.url, '--json']);
      const result = JSON.parse(stdout) as { targets: Array<{ ok: boolean }> };
      expect(result.targets[0]!.ok).toBe(false);
    } finally {
      await failMock.close();
    }
  });

  test('10. exits 1 when no targets provided and no config', () => {
    const { status } = runAlertTest(['--config', path.join(tmpDir, 'nonexistent.yaml')]);
    expect(status).toBe(1);
  });

  test('11. --json result has url field', async () => {
    const { stdout } = await runAlertTestAsync(['--url', mock.url, '--json']);
    const result = JSON.parse(stdout) as { targets: Array<{ url: string }> };
    expect(result.targets[0]!.url).toBe(mock.url);
  });

  test('12. --json result has durationMs field', async () => {
    const { stdout } = await runAlertTestAsync(['--url', mock.url, '--json']);
    const result = JSON.parse(stdout) as { targets: Array<{ durationMs: number }> };
    expect(typeof result.targets[0]!.durationMs).toBe('number');
    expect(result.targets[0]!.durationMs).toBeGreaterThanOrEqual(0);
  });
}, 30_000);
