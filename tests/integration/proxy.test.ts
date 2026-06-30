/**
 * Integration tests for agent-warden proxy.
 *
 * Strategy:
 *   1. Write tiny self-contained MCP echo servers to tmp files — pure
 *      readline JSON-RPC over stdio, no external deps.
 *   2. Write a thin proxy-launcher that accepts a JSON config on stdin,
 *      calls runProxy(), and exits cleanly.
 *   3. Each test spawns the proxy (which spawns the echo server downstream).
 *   4. Tests connect via StdioClientTransport and make real tool calls.
 *
 * Requires a prior `npm run build` (dist/ must exist).
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { jest } from '@jest/globals';

jest.setTimeout(30_000);

// ─── Paths ──────────────────────────────────────────────────────────────────

const PROJECT_ROOT = process.cwd();
const DIST_DIR     = path.join(PROJECT_ROOT, 'dist');
const TEST_TMP     = path.join(os.tmpdir(), `warden-it-${process.pid}`);

let ECHO_SERVER_SCRIPT  = '';
let ECHO_SERVER2_SCRIPT = '';
let PROXY_LAUNCHER      = '';

// ─── Helpers ────────────────────────────────────────────────────────────────

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function makeTestDir(name: string): string {
  const dir = path.join(TEST_TMP, name);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

// ─── Inline echo MCP server ─────────────────────────────────────────────────

/** A minimal MCP server that exposes one tool: echo_tool(message) → message. */
const ECHO_SERVER_SRC = /* js */ `
const readline = require('node:readline');

const rl = readline.createInterface({ input: process.stdin, terminal: false });
const lines = [];

rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  let msg;
  try { msg = JSON.parse(trimmed); } catch { return; }

  if (msg.method === 'initialize') {
    respond(msg.id, {
      protocolVersion: '2024-11-05',
      capabilities: { tools: {} },
      serverInfo: { name: 'echo-server', version: '0.1.0' },
    });
  } else if (msg.method === 'notifications/initialized') {
    // ignore
  } else if (msg.method === 'tools/list') {
    respond(msg.id, {
      tools: [{
        name: 'echo_tool',
        description: 'Echoes the input message',
        inputSchema: {
          type: 'object',
          properties: { message: { type: 'string' } },
          required: ['message'],
        },
      }],
    });
  } else if (msg.method === 'tools/call') {
    const toolName = msg.params && msg.params.name;
    const args     = msg.params && msg.params.arguments;
    if (toolName === 'echo_tool') {
      respond(msg.id, { content: [{ type: 'text', text: args.message }] });
    } else {
      error(msg.id, -32601, 'Tool not found: ' + toolName);
    }
  } else if (msg.id !== undefined) {
    error(msg.id, -32601, 'Method not found: ' + msg.method);
  }
});

function respond(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\\n');
}
function error(id, code, message) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } }) + '\\n');
}

process.on('SIGTERM', () => process.exit(0));
`;

/** A second echo server that exposes: ping_tool() → "pong" */
const ECHO_SERVER2_SRC = /* js */ `
const readline = require('node:readline');
const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  let msg;
  try { msg = JSON.parse(trimmed); } catch { return; }
  if (msg.method === 'initialize') {
    respond(msg.id, {
      protocolVersion: '2024-11-05',
      capabilities: { tools: {} },
      serverInfo: { name: 'ping-server', version: '0.1.0' },
    });
  } else if (msg.method === 'notifications/initialized') {
    // ignore
  } else if (msg.method === 'tools/list') {
    respond(msg.id, { tools: [{
      name: 'ping_tool',
      description: 'Returns pong',
      inputSchema: { type: 'object', properties: {} },
    }] });
  } else if (msg.method === 'tools/call' && msg.params && msg.params.name === 'ping_tool') {
    respond(msg.id, { content: [{ type: 'text', text: 'pong' }] });
  } else if (msg.id !== undefined) {
    respond(msg.id, { content: [{ type: 'text', text: 'unknown' }] });
  }
});
function respond(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\\n');
}
process.on('SIGTERM', () => process.exit(0));
`;

/** Launcher that reads a WardenConfig JSON from stdin, calls runProxy(). */
const PROXY_LAUNCHER_SRC = /* js */ `
import { runProxy } from '${DIST_DIR}/proxy.js';
const chunks = [];
process.stdin.on('data', c => chunks.push(c));
process.stdin.on('end', async () => {
  const config = JSON.parse(Buffer.concat(chunks).toString());
  try { await runProxy(config); }
  catch (err) { process.stderr.write('LAUNCHER ERROR: ' + err.message + '\\n'); process.exit(1); }
});
`;

// ─── Before / After ─────────────────────────────────────────────────────────

beforeAll(() => {
  fs.mkdirSync(TEST_TMP, { recursive: true });

  ECHO_SERVER_SCRIPT  = path.join(TEST_TMP, 'echo-server.cjs');
  ECHO_SERVER2_SCRIPT = path.join(TEST_TMP, 'ping-server.cjs');
  PROXY_LAUNCHER      = path.join(TEST_TMP, 'launcher.mjs');

  fs.writeFileSync(ECHO_SERVER_SCRIPT,  ECHO_SERVER_SRC);
  fs.writeFileSync(ECHO_SERVER2_SCRIPT, ECHO_SERVER2_SRC);
  // Launcher references DIST_DIR at write time — safe because it's a constant.
  fs.writeFileSync(PROXY_LAUNCHER, `
import { runProxy } from '${DIST_DIR}/proxy.js';
const chunks = [];
process.stdin.on('data', c => chunks.push(c));
process.stdin.on('end', async () => {
  const config = JSON.parse(Buffer.concat(chunks).toString());
  try { await runProxy(config); }
  catch (err) { process.stderr.write('LAUNCHER ERROR: ' + err.message + '\\n'); process.exit(1); }
});
`);
});

afterAll(() => {
  fs.rmSync(TEST_TMP, { recursive: true, force: true });
});

// ─── Config builders ─────────────────────────────────────────────────────────

function singleServerConfig(logFile: string, overrides: Record<string, unknown> = {}) {
  return {
    mode: 'audit',
    // Legacy single-server format (no prefix)
    downstreamCommand: [process.execPath, ECHO_SERVER_SCRIPT],
    logFile,
    policy: { defaultAction: 'allow', rules: [] },
    scrubber: { enabled: true },
    ...overrides,
  };
}

function multiServerConfig(logFile: string, overrides: Record<string, unknown> = {}) {
  return {
    mode: 'audit',
    servers: {
      echo:  { command: process.execPath, args: [ECHO_SERVER_SCRIPT]  },
      pings: { command: process.execPath, args: [ECHO_SERVER2_SCRIPT] },
    },
    logFile,
    policy: { defaultAction: 'allow', rules: [] },
    scrubber: { enabled: true },
    ...overrides,
  };
}

// ─── Helper: spawn warden + connect client ───────────────────────────────────

async function spawnWarden(config: unknown): Promise<{ client: Client; cleanup: () => Promise<void> }> {
  const configJson = JSON.stringify(config);

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ['--input-type=module', PROXY_LAUNCHER],
    stdin: 'pipe',
    stderr: 'pipe',
  });

  // Write config JSON to the launcher's stdin before connecting
  (transport as unknown as { _process?: { stdin: NodeJS.WritableStream } });

  const client = new Client(
    { name: 'test-client', version: '0.1.0' },
    { capabilities: {} },
  );

  // Pipe config via environment instead of stdin (stdin is used by MCP protocol)
  const configPath = path.join(TEST_TMP, `config-${Date.now()}-${Math.random()}.json`);
  fs.writeFileSync(configPath, configJson);

  // Use a wrapper that reads config from a file path in argv
  const wrapperPath = path.join(TEST_TMP, `wrap-${Date.now()}.mjs`);
  fs.writeFileSync(wrapperPath, `
import { runProxy } from '${DIST_DIR}/proxy.js';
import * as fs from 'node:fs';
const config = JSON.parse(fs.readFileSync(${JSON.stringify(configPath)}, 'utf8'));
await runProxy(config).catch(err => { process.stderr.write('ERR: ' + err.message); process.exit(1); });
`);

  const realTransport = new StdioClientTransport({
    command: process.execPath,
    args: [wrapperPath],
    stderr: 'inherit',
  });

  const realClient = new Client(
    { name: 'test-client', version: '0.1.0' },
    { capabilities: {} },
  );

  await realClient.connect(realTransport);
  await delay(300);

  const cleanup = async () => {
    try { await realClient.close(); } catch {}
    fs.rmSync(wrapperPath, { force: true });
    fs.rmSync(configPath, { force: true });
    await delay(100);
  };

  return { client: realClient, cleanup };
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('Single-server proxy (legacy downstreamCommand)', () => {
  test('1. Tool passthrough — echo_tool returns echoed message', async () => {
    const dir     = makeTestDir('test1');
    const logFile = path.join(dir, 'audit.jsonl');
    const { client, cleanup } = await spawnWarden(singleServerConfig(logFile));

    try {
      const tools = await client.listTools();
      expect(tools.tools.map(t => t.name)).toContain('echo_tool');

      const result = await client.callTool({ name: 'echo_tool', arguments: { message: 'hello world' } });
      const content = (result as { content: Array<{ type: string; text: string }> }).content;
      expect(content[0]?.text).toBe('hello world');
    } finally {
      await cleanup();
    }
  });

  test('2. Audit log written — JSONL entry exists after tool call', async () => {
    const dir     = makeTestDir('test2');
    const logFile = path.join(dir, 'audit.jsonl');
    const { client, cleanup } = await spawnWarden(singleServerConfig(logFile));

    try {
      await client.callTool({ name: 'echo_tool', arguments: { message: 'audit-test' } });
      await delay(200);

      expect(fs.existsSync(logFile)).toBe(true);
      const lines = fs.readFileSync(logFile, 'utf8').trim().split('\n').filter(Boolean);
      expect(lines.length).toBeGreaterThanOrEqual(1);
      const entry = JSON.parse(lines[lines.length - 1]!);
      expect(entry.tool).toBe('echo_tool');
      expect(entry.verdict).toBe('allow');
      expect(entry).toHaveProperty('ts');
    } finally {
      await cleanup();
    }
  });

  test('3. Policy enforce deny — tool call returns error', async () => {
    const dir     = makeTestDir('test3');
    const logFile = path.join(dir, 'audit.jsonl');
    const config  = singleServerConfig(logFile, {
      mode: 'enforce',
      policy: {
        defaultAction: 'allow',
        rules: [{ tool: 'echo_tool', action: 'deny', reason: 'blocked in test' }],
      },
    });

    const { client, cleanup } = await spawnWarden(config);
    try {
      const result = await client.callTool({ name: 'echo_tool', arguments: { message: 'x' } });
      const res = result as { isError?: boolean; content: Array<{ type: string; text: string }> };
      expect(res.isError).toBe(true);
      expect(res.content[0]?.text).toMatch(/[Dd]enied/);
    } finally {
      await cleanup();
    }
  });

  test('4. Secret scrubbing — API key redacted in audit log', async () => {
    const dir     = makeTestDir('test4');
    const logFile = path.join(dir, 'audit.jsonl');
    const { client, cleanup } = await spawnWarden(singleServerConfig(logFile));

    try {
      // AKIAIOSFODNN7EXAMPLE is the canonical AWS test key from AWS docs
      await client.callTool({
        name:      'echo_tool',
        arguments: { message: 'AKIAIOSFODNN7EXAMPLE secret key value' },
      });
      await delay(200);

      const raw = fs.readFileSync(logFile, 'utf8');
      expect(raw).toContain('[REDACTED]');
      expect(raw).not.toContain('AKIAIOSFODNN7EXAMPLE');
    } finally {
      await cleanup();
    }
  });
});

describe('Multi-server proxy (servers map)', () => {
  test('5. Both servers reachable — tools from both are listed', async () => {
    const dir     = makeTestDir('test5');
    const logFile = path.join(dir, 'audit.jsonl');
    const { client, cleanup } = await spawnWarden(multiServerConfig(logFile));

    try {
      const { tools } = await client.listTools();
      const names = tools.map(t => t.name);

      // Prefixed tools from both servers
      expect(names).toContain('echo/echo_tool');
      expect(names).toContain('pings/ping_tool');
    } finally {
      await cleanup();
    }
  });

  test('6. Prefixed tool call — echo/echo_tool works', async () => {
    const dir     = makeTestDir('test6');
    const logFile = path.join(dir, 'audit.jsonl');
    const { client, cleanup } = await spawnWarden(multiServerConfig(logFile));

    try {
      const result = await client.callTool({
        name:      'echo/echo_tool',
        arguments: { message: 'multi-server test' },
      });
      const content = (result as { content: Array<{ type: string; text: string }> }).content;
      expect(content[0]?.text).toBe('multi-server test');
    } finally {
      await cleanup();
    }
  });

  test('7. Prefixed tool call — pings/ping_tool returns pong', async () => {
    const dir     = makeTestDir('test7');
    const logFile = path.join(dir, 'audit.jsonl');
    const { client, cleanup } = await spawnWarden(multiServerConfig(logFile));

    try {
      const result = await client.callTool({ name: 'pings/ping_tool', arguments: {} });
      const content = (result as { content: Array<{ type: string; text: string }> }).content;
      expect(content[0]?.text).toBe('pong');
    } finally {
      await cleanup();
    }
  });

  test('8. Cross-server prefix policy — deny echo/* allow pings/*', async () => {
    const dir     = makeTestDir('test8');
    const logFile = path.join(dir, 'audit.jsonl');
    const config  = multiServerConfig(logFile, {
      mode: 'enforce',
      policy: {
        defaultAction: 'allow',
        rules: [
          { tool: 'echo/*', action: 'deny', reason: 'echo server disabled' },
        ],
      },
    });

    const { client, cleanup } = await spawnWarden(config);
    try {
      const denied = await client.callTool({
        name: 'echo/echo_tool', arguments: { message: 'should be denied' },
      });
      expect((denied as { isError?: boolean }).isError).toBe(true);

      const allowed = await client.callTool({ name: 'pings/ping_tool', arguments: {} });
      expect((allowed as { isError?: boolean }).isError).toBeFalsy();
    } finally {
      await cleanup();
    }
  });
});
