/**
 * Integration tests for agent-warden proxy.
 *
 * Strategy:
 *   1. Write a tiny self-contained MCP echo server to a tmp file (no external deps —
 *      pure readline-based JSON-RPC over stdio).
 *   2. Write a thin proxy-launcher script that imports runProxy() from dist/ and
 *      accepts a JSON config string as argv[2].  This bypasses the YAML loader so
 *      the test controls every config field directly.
 *   3. Each test spawns the warden proxy via StdioClientTransport (which in turn
 *      spawns the echo server as the downstream).
 *   4. Tests connect an MCP Client to the proxy and make real tool calls.
 *
 * Why a proxy-launcher wrapper instead of calling dist/cli.js run <yaml>?
 *   - dist/proxy.ts passes config.downstreamCommand directly to
 *     StdioClientTransport's `command` field (expects string), but the YAML
 *     loader always produces an array.  Passing JSON lets us split command/args
 *     ourselves without touching source code.
 *   - Avoids writing + resolving YAML config files in every test.
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
// In Jest ESM mode the `jest` global is not auto-injected; import explicitly.
import { jest } from '@jest/globals';

// ─── Global Jest timeout ────────────────────────────────────────────────────

jest.setTimeout(30_000);

// ─── Paths ──────────────────────────────────────────────────────────────────

/** Project root — cwd when jest is invoked from the package root. */
const PROJECT_ROOT = process.cwd();
const DIST_DIR = path.join(PROJECT_ROOT, 'dist');

/** Unique tmp dir for this test run. */
const TEST_TMP = path.join(os.tmpdir(), `warden-it-${process.pid}`);

// Script paths are set in beforeAll after the tmp dir is created.
let ECHO_SERVER_SCRIPT = '';
let PROXY_LAUNCHER_SCRIPT = '';

// ─── Runtime config type ────────────────────────────────────────────────────

/**
 * The shape actually read at runtime by policy.ts (uses `pattern`, not `tool`
 * which is what the TypeScript interface incorrectly declares).
 */
interface RuntimePolicyRule {
  pattern: string;
  action: 'allow' | 'deny';
  reason?: string;
}

interface RuntimeWardenConfig {
  mode: 'audit' | 'enforce';
  downstreamCommand: string;
  downstreamArgs: string[];
  logFile: string;
  policy: {
    defaultAction: 'allow' | 'deny';
    rules: RuntimePolicyRule[];
  };
  scrubber: { enabled: boolean; patterns?: string[] };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function makeTestDir(name: string): string {
  const dir = path.join(TEST_TMP, name);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/** Build a base audit-mode config for the echo server. */
function baseConfig(logFile: string): RuntimeWardenConfig {
  return {
    mode: 'audit',
    downstreamCommand: process.execPath,   // absolute path to the node binary
    downstreamArgs: [ECHO_SERVER_SCRIPT],
    logFile,
    policy: { defaultAction: 'allow', rules: [] },
    scrubber: { enabled: true },
  };
}

// Track every Client opened so afterAll can close them all.
const openClients: Client[] = [];

/**
 * Spawn a warden proxy (via proxy-launcher.mjs) connected to the echo server,
 * and return an MCP Client already connected to it.
 *
 * @param config   The full runtime WardenConfig forwarded to runProxy().
 * @param extraEnv Additional environment variables injected into the proxy process.
 */
async function createClient(
  config: RuntimeWardenConfig,
  extraEnv: Record<string, string> = {},
): Promise<Client> {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [PROXY_LAUNCHER_SCRIPT, JSON.stringify(config)],
    // StdioClientTransport merges extraEnv with its safe default env (PATH, HOME …)
    env: extraEnv,
    // Pipe stderr so proxy logs don't pollute test output; visible on failure.
    stderr: 'pipe',
  });

  const client = new Client(
    { name: 'test-client', version: '1.0.0' },
    { capabilities: {} },
  );

  await client.connect(transport);
  openClients.push(client);
  return client;
}

// ─── Inline server + launcher scripts ───────────────────────────────────────

/**
 * Returns the source for a self-contained MCP echo server that speaks newline-
 * delimited JSON-RPC over stdio (same wire format as the SDK's StdioServerTransport).
 * No external dependencies — uses only Node.js built-in `readline`.
 *
 * Exposes one tool: echo_tool(message: string) → returns the message unchanged.
 */
function echoServerSource(): string {
  // Written as a string array to avoid nested template-literal escaping issues.
  return [
    'import readline from "node:readline";',
    '',
    'const rl = readline.createInterface({ input: process.stdin, terminal: false });',
    '',
    'rl.on("line", (line) => {',
    '  const trimmed = line.trim();',
    '  if (!trimmed) return;',
    '  let msg;',
    '  try { msg = JSON.parse(trimmed); } catch { return; }',
    '',
    '  // Notifications have no id — no response required.',
    '  if (msg.id === undefined && msg.id !== 0) return;',
    '',
    '  const respond = (result) =>',
    '    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result }) + "\\n");',
    '',
    '  const respondError = (code, message) =>',
    '    process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id,',
    '      error: { code, message } }) + "\\n");',
    '',
    '  if (msg.method === "initialize") {',
    '    respond({',
    '      protocolVersion: "2024-11-05",',
    '      serverInfo: { name: "echo-server", version: "1.0.0" },',
    '      capabilities: { tools: {} },',
    '    });',
    '  } else if (msg.method === "tools/list") {',
    '    respond({',
    '      tools: [{',
    '        name: "echo_tool",',
    '        description: "Echoes the message argument back to the caller.",',
    '        inputSchema: {',
    '          type: "object",',
    '          properties: { message: { type: "string" } },',
    '          required: ["message"],',
    '        },',
    '      }],',
    '    });',
    '  } else if (msg.method === "tools/call") {',
    '    const { name, arguments: args } = msg.params;',
    '    if (name === "echo_tool") {',
    '      respond({ content: [{ type: "text", text: args.message }] });',
    '    } else {',
    '      respondError(-32601, "Unknown tool: " + name);',
    '    }',
    '  } else {',
    '    respondError(-32601, "Unknown method: " + msg.method);',
    '  }',
    '});',
  ].join('\n');
}

/**
 * Returns the source for the proxy-launcher wrapper.
 * Imports runProxy() from dist/ using an absolute file URL, then calls it with
 * the JSON config passed as argv[2].
 */
function proxyLauncherSource(distDir: string): string {
  // Use file:// URL for the import to avoid module resolution ambiguity.
  const proxyUrl = `file://${distDir}/proxy.js`;
  return [
    `import { runProxy } from "${proxyUrl}";`,
    'const config = JSON.parse(process.argv[2]);',
    'await runProxy(config);',
  ].join('\n');
}

// ─── Lifecycle ───────────────────────────────────────────────────────────────

beforeAll(() => {
  fs.mkdirSync(TEST_TMP, { recursive: true });

  ECHO_SERVER_SCRIPT = path.join(TEST_TMP, 'echo-server.mjs');
  PROXY_LAUNCHER_SCRIPT = path.join(TEST_TMP, 'proxy-launcher.mjs');

  fs.writeFileSync(ECHO_SERVER_SCRIPT, echoServerSource(), 'utf8');
  fs.writeFileSync(PROXY_LAUNCHER_SCRIPT, proxyLauncherSource(DIST_DIR), 'utf8');
});

afterAll(async () => {
  // Close every open client; the SDK will send stdin-EOF + SIGTERM to each proxy.
  const closeResults = await Promise.allSettled(
    openClients.map((c) => c.close()),
  );
  closeResults.forEach((r, i) => {
    if (r.status === 'rejected') {
      // eslint-disable-next-line no-console
      console.warn(`[afterAll] client[${i}].close() error:`, r.reason);
    }
  });

  // Remove the shared tmp dir.
  try {
    fs.rmSync(TEST_TMP, { recursive: true, force: true });
  } catch {
    // best-effort
  }
});

// ─── Tests ───────────────────────────────────────────────────────────────────

// ── 1. Tool passthrough ──────────────────────────────────────────────────────

test('tool passthrough — warden audit mode forwards echo_tool and returns result', async () => {
  const dir = makeTestDir('passthrough');
  const logFile = path.join(dir, 'audit.jsonl');

  const client = await createClient(baseConfig(logFile));

  const result = await client.callTool({
    name: 'echo_tool',
    arguments: { message: 'hello warden' },
  });

  expect(result.isError).toBeFalsy();

  const content = result.content as Array<{ type: string; text: string }>;
  expect(content).toHaveLength(1);
  expect(content[0].type).toBe('text');
  expect(content[0].text).toBe('hello warden');
});

// ── 2. Kill switch blocks ────────────────────────────────────────────────────

test('kill switch — armed sentinel file causes tool call to return MCP error', async () => {
  const dir = makeTestDir('killswitch');
  const logFile = path.join(dir, 'audit.jsonl');
  const ksFile = path.join(dir, 'killswitch-sentinel');

  // Ensure sentinel does not exist before starting the proxy.
  try {
    fs.unlinkSync(ksFile);
  } catch {
    // fine if it did not exist
  }

  const client = await createClient(
    baseConfig(logFile),
    // Override the sentinel file path so the proxy watches our controlled file.
    { WARDEN_KILLSWITCH: ksFile },
  );

  // Arm the kill switch by writing the sentinel file.
  fs.writeFileSync(
    ksFile,
    JSON.stringify({ since: new Date().toISOString(), reason: 'integration test' }),
    'utf8',
  );

  // Wait for the proxy to detect the sentinel (poll interval is 500 ms).
  await delay(800);

  const result = await client.callTool({
    name: 'echo_tool',
    arguments: { message: 'should be blocked' },
  });

  expect(result.isError).toBe(true);

  const content = result.content as Array<{ type: string; text: string }>;
  expect(content[0].text).toMatch(/kill switch/i);
});

// ── 3. Policy deny ───────────────────────────────────────────────────────────

test('policy deny — enforce mode with deny rule blocks echo_tool and returns error', async () => {
  const dir = makeTestDir('policy-deny');
  const logFile = path.join(dir, 'audit.jsonl');

  const config: RuntimeWardenConfig = {
    ...baseConfig(logFile),
    mode: 'enforce',
    policy: {
      defaultAction: 'allow',
      rules: [
        {
          pattern: 'echo_tool',
          action: 'deny',
          reason: 'blocked by integration test policy',
        },
      ],
    },
  };

  const client = await createClient(config);

  const result = await client.callTool({
    name: 'echo_tool',
    arguments: { message: 'will this be denied?' },
  });

  expect(result.isError).toBe(true);

  const content = result.content as Array<{ type: string; text: string }>;
  // Proxy emits "[warden] Denied: <reason>" for policy denials.
  expect(content[0].text).toMatch(/denied/i);
});

// ── 4. Audit log written ─────────────────────────────────────────────────────

test('audit log — after a tool call audit.jsonl exists and contains a valid entry', async () => {
  const dir = makeTestDir('audit-log');
  const logFile = path.join(dir, 'audit.jsonl');

  const client = await createClient(baseConfig(logFile));

  await client.callTool({
    name: 'echo_tool',
    arguments: { message: 'audit this call' },
  });

  // Allow the audit logger (appendFileSync) a moment to complete the write.
  await delay(200);

  expect(fs.existsSync(logFile)).toBe(true);

  const lines = fs
    .readFileSync(logFile, 'utf8')
    .split('\n')
    .filter((l) => l.trim().length > 0);

  expect(lines.length).toBeGreaterThanOrEqual(1);

  const entry = JSON.parse(lines[lines.length - 1]) as {
    ts: string;
    tool: string;
    verdict: string;
    args: unknown;
    durationMs: number;
  };

  expect(entry.tool).toBe('echo_tool');
  expect(entry.verdict).toBe('allow');
  expect(typeof entry.ts).toBe('string');
  // ts should be a valid ISO-8601 date
  expect(new Date(entry.ts).getFullYear()).toBeGreaterThan(2020);
  expect(typeof entry.durationMs).toBe('number');
});

// ── 5. Secret scrubbing ──────────────────────────────────────────────────────

test('secret scrubbing — AWS key in echo_tool args is [REDACTED] in audit log', async () => {
  const dir = makeTestDir('scrubbing');
  const logFile = path.join(dir, 'audit.jsonl');

  const client = await createClient(baseConfig(logFile));

  // A syntactically valid fake AWS access key.
  // Matches the built-in pattern /AKIA[0-9A-Z]{16}/g — 20 chars total.
  const fakeAwsKey = 'AKIAIOSFODNN7EXAMPLE';

  await client.callTool({
    name: 'echo_tool',
    arguments: { message: fakeAwsKey },
  });

  await delay(200);

  expect(fs.existsSync(logFile)).toBe(true);

  const raw = fs.readFileSync(logFile, 'utf8');

  // The scrubber must have replaced the key with [REDACTED].
  expect(raw).toContain('[REDACTED]');

  // The original secret must NOT appear anywhere in the log.
  expect(raw).not.toContain(fakeAwsKey);
});
