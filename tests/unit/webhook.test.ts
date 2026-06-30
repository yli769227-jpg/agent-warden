/**
 * Unit tests for WebhookAlerter.
 *
 * Tests use a lightweight HTTP server (Node http module) as the target
 * so we can verify the real POST payload without mocking internals.
 */

import http from 'node:http';
import { WebhookAlerter, createWebhookAlerter } from '../../src/webhook.js';
import { jest } from '@jest/globals';

jest.setTimeout(10_000);

// ─── Minimal HTTP receiver ────────────────────────────────────────────────────

interface ReceivedRequest {
  method: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

function startReceiver(): Promise<{
  port:    number;
  requests: ReceivedRequest[];
  close:   () => Promise<void>;
}> {
  const requests: ReceivedRequest[] = [];

  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        requests.push({
          method:  req.method ?? '',
          headers: req.headers,
          body:    Buffer.concat(chunks).toString(),
        });
        res.writeHead(200);
        res.end();
      });
    });

    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      const close = () => new Promise<void>((r, e) => server.close((err) => (err ? e(err) : r())));
      resolve({ port: addr.port, requests, close });
    });
  });
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('WebhookAlerter', () => {
  test('1. POSTs JSON payload on deny event', async () => {
    const { port, requests, close } = await startReceiver();
    try {
      const alerter = new WebhookAlerter({
        enabled:  true,
        targets:  [{ url: `http://127.0.0.1:${port}/hook` }],
      });

      alerter.alert('deny', 'delete_file', 'policy deny', { path: '/etc/passwd' });
      await delay(200);

      expect(requests).toHaveLength(1);
      const req = requests[0]!;
      expect(req.method).toBe('POST');
      expect(req.headers['content-type']).toContain('application/json');

      const payload = JSON.parse(req.body);
      expect(payload.source).toBe('agent-warden');
      expect(payload.event).toBe('deny');
      expect(payload.tool).toBe('delete_file');
      expect(payload.reason).toBe('policy deny');
      expect(payload).toHaveProperty('ts');
      expect(payload).toHaveProperty('version');
    } finally {
      await close();
    }
  });

  test('2. POSTs on kill event', async () => {
    const { port, requests, close } = await startReceiver();
    try {
      const alerter = new WebhookAlerter({ enabled: true, targets: [{ url: `http://127.0.0.1:${port}` }] });
      alerter.alert('kill', 'run_shell', 'kill switch active', {});
      await delay(200);

      const payload = JSON.parse(requests[0]!.body);
      expect(payload.event).toBe('kill');
    } finally {
      await close();
    }
  });

  test('3. Secret is sent as X-Warden-Secret header', async () => {
    const { port, requests, close } = await startReceiver();
    try {
      const alerter = new WebhookAlerter({
        enabled: true,
        targets: [{ url: `http://127.0.0.1:${port}`, secret: 'my-shared-secret' }],
      });
      alerter.alert('deny', 'some_tool', 'test', {});
      await delay(200);

      expect(requests[0]!.headers['x-warden-secret']).toBe('my-shared-secret');
    } finally {
      await close();
    }
  });

  test('4. Event filter — only configured events are delivered', async () => {
    const { port, requests, close } = await startReceiver();
    try {
      const alerter = new WebhookAlerter({
        enabled: true,
        targets: [{ url: `http://127.0.0.1:${port}` }],
        on:      ['kill'], // only kill events
      });

      alerter.alert('deny',  'some_tool', 'denied', {});
      alerter.alert('kill',  'other_tool', 'killed', {});
      alerter.alert('rate-limit', 'tool', 'limited', {});
      await delay(300);

      // Only the "kill" alert should have been delivered
      expect(requests).toHaveLength(1);
      expect(JSON.parse(requests[0]!.body).event).toBe('kill');
    } finally {
      await close();
    }
  });

  test('5. Multiple targets — each receives the alert', async () => {
    const r1 = await startReceiver();
    const r2 = await startReceiver();
    try {
      const alerter = new WebhookAlerter({
        enabled: true,
        targets: [
          { url: `http://127.0.0.1:${r1.port}` },
          { url: `http://127.0.0.1:${r2.port}` },
        ],
      });

      alerter.alert('deny', 'write_file', 'denied', {});
      await delay(300);

      expect(r1.requests).toHaveLength(1);
      expect(r2.requests).toHaveLength(1);
    } finally {
      await r1.close();
      await r2.close();
    }
  });

  test('6. Failed delivery does not throw — alert() is fire-and-forget', async () => {
    const alerter = new WebhookAlerter({
      enabled:     true,
      targets:     [{ url: 'http://127.0.0.1:1', maxRetries: 0 }], // port 1 is refused
    });
    // Should not throw even with maxRetries=0 and an unreachable server
    expect(() => {
      alerter.alert('deny', 'some_tool', 'reason', {});
    }).not.toThrow();
    await delay(300); // give background delivery time to fail silently
  });

  test('7. No targets — alert() is a no-op', async () => {
    const alerter = new WebhookAlerter({ enabled: true, targets: [] });
    expect(() => alerter.alert('deny', 'tool', 'reason', {})).not.toThrow();
  });

  test('8. rate-limit event is sent when included in on filter', async () => {
    const { port, requests, close } = await startReceiver();
    try {
      const alerter = new WebhookAlerter({
        enabled: true,
        targets: [{ url: `http://127.0.0.1:${port}` }],
        on:      ['rate-limit'],
      });
      alerter.alert('rate-limit', 'echo_tool', 'limit exceeded', { count: 5 });
      await delay(200);

      const payload = JSON.parse(requests[0]!.body);
      expect(payload.event).toBe('rate-limit');
      expect(payload.tool).toBe('echo_tool');
    } finally {
      await close();
    }
  });
});

// ─── Factory ─────────────────────────────────────────────────────────────────

describe('createWebhookAlerter', () => {
  test('9. returns null when disabled', () => {
    expect(createWebhookAlerter({ enabled: false })).toBeNull();
  });

  test('10. returns null when no targets', () => {
    expect(createWebhookAlerter({ enabled: true, targets: [] })).toBeNull();
  });

  test('11. returns WebhookAlerter when enabled with targets', () => {
    const alerter = createWebhookAlerter({
      enabled: true,
      targets: [{ url: 'http://example.com/hook' }],
    });
    expect(alerter).toBeInstanceOf(WebhookAlerter);
  });
});
