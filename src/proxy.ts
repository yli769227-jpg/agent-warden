/**
 * proxy.ts — core engine for agent-warden.
 *
 * Sits between an upstream MCP client (e.g. Claude Code) and a downstream
 * MCP server process.  Every tools/call is intercepted, checked against the
 * kill switch and policy engine, optionally forwarded to downstream, and
 * written to the JSONL audit log.
 *
 * Flow per call:
 *   1. Kill switch active?  → verdict 'killed', return MCP error immediately.
 *   2. Policy.evaluate()   → in enforce mode, 'deny' blocks the call.
 *                             In audit mode all calls are forwarded regardless.
 *   3. Forward to downstream client.callTool().
 *   4. Scrub result + log audit entry.
 *   5. Return downstream result to upstream caller.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import {
  ListResourcesRequestSchema,
  ListPromptsRequestSchema,
  type CallToolResult,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

import { createPolicyEngine } from './policy.js';
import { createScrubberFromConfig } from './scrubber.js';
import { createAuditLogger } from './audit.js';
import { KillSwitch } from './killswitch.js';
import { createRateLimiter, RateLimitError } from './ratelimit.js';
import { createWebhookAlerter } from './webhook.js';
import type { AuditEntry, ServerConfig, WardenConfig } from './types.js';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const PREFIX = '[warden:proxy]';

function log(msg: string): void {
  process.stderr.write(`${PREFIX} ${msg}\n`);
}

/**
 * Passthrough schema used for every dynamically-registered tool.
 * We don't know tool shapes at compile time; the real JSON Schema is
 * advertised to the upstream caller in the tool descriptor via McpServer's
 * capabilities, but we accept any arg shape here and forward it verbatim.
 */
const passthroughSchema = z.object({}).passthrough();

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Starts the warden proxy.
 *
 * - Spawns the downstream MCP server as a child process via StdioClientTransport.
 * - Presents itself as an MCP server upstream via McpServer + StdioServerTransport.
 * - Discovers downstream tools and registers each with an intercepting handler.
 * - Proxies resources and prompts lists from downstream transparently.
 * - Installs SIGINT / SIGTERM handlers for graceful shutdown.
 *
 * This function blocks (the process keeps running) until a signal is received.
 */
export async function runProxy(config: WardenConfig): Promise<void> {
  log('Starting');

  // ── Components ─────────────────────────────────────────────────────────────
  const policy      = createPolicyEngine(config.policy);
  const scrub       = createScrubberFromConfig(config.scrubber);
  const audit       = createAuditLogger(config.logFile);
  const ks          = new KillSwitch();
  const rateLimiter = config.rateLimit ? createRateLimiter(config.rateLimit) : null;
  const alerter     = config.webhook   ? createWebhookAlerter(config.webhook)  : null;

  // Start watching the sentinel file immediately.
  ks.watch();

  // ── Normalise server list ──────────────────────────────────────────────────
  // Support both the modern `servers` map and the legacy `downstreamCommand`.
  const serverMap: Record<string, ServerConfig> = {};

  if (config.servers && Object.keys(config.servers).length > 0) {
    Object.assign(serverMap, config.servers);
  } else if (config.downstreamCommand && config.downstreamCommand.length > 0) {
    const [command, ...args] = config.downstreamCommand;
    serverMap['_default'] = { command, args };
    log('Using legacy downstreamCommand (single server, no tool prefix)');
  } else {
    throw new Error('[warden:proxy] No downstream servers configured. Set "servers" or "downstreamCommand" in warden.config.yaml');
  }

  const serverKeys = Object.keys(serverMap);
  log(`Connecting to ${serverKeys.length} downstream server(s): ${serverKeys.join(', ')}`);

  // ── Connect all downstream clients ─────────────────────────────────────────
  const clients: Array<{ key: string; client: Client; prefix: string }> = [];

  for (const [key, serverCfg] of Object.entries(serverMap)) {
    const transport = new StdioClientTransport({
      command: serverCfg.command,
      args:    serverCfg.args ?? [],
      env:     serverCfg.env
        ? { ...process.env, ...serverCfg.env } as Record<string, string>
        : undefined,
      stderr: 'inherit',
    });

    const client = new Client(
      { name: `agent-warden-client-${key}`, version: '0.1.0' },
      { capabilities: {} },
    );

    await client.connect(transport);
    // Single default server → no prefix; named servers → "key/" prefix
    const prefix = key === '_default' ? '' : `${key}/`;
    clients.push({ key, client, prefix });
    log(`Connected to downstream server "${key}"`);
  }

  // Use the first client for resource/prompt proxying (primary server)
  const primaryClient = clients[0]!.client;

  // ── Upstream MCP server ─────────────────────────────────────────────────────
  const server = new McpServer(
    { name: 'agent-warden', version: '0.1.0' },
    {
      capabilities: {
        tools:     {},
        resources: {},
        prompts:   {},
      },
    },
  );

  // ── Tool discovery + registration (all servers) ─────────────────────────────
  let totalTools = 0;
  for (const { key, client, prefix } of clients) {
    const { tools } = await client.listTools();
    log(`Discovered ${tools.length} tools from "${key}"`);
    totalTools += tools.length;

  for (const toolDef of tools) {
    const toolName        = `${prefix}${toolDef.name}`;
    const toolDescription = toolDef.description ?? '';

    /*
     * Register each downstream tool on the upstream McpServer.
     *
     * inputSchema: z.object({}).passthrough()
     *   – Accepts any key/value payload so we can forward args verbatim
     *     without knowing each tool's specific field set at compile time.
     *
     * The raw downstream inputSchema (JSON Schema object) is preserved in
     * the tool descriptor for introspection but is NOT used for validation
     * here — that is the downstream server's responsibility.
     */
    server.registerTool(
      toolName,
      {
        description: toolDescription,
        inputSchema: passthroughSchema,
      },
      async (args) => {
        const startMs = Date.now();

        // Scrub args once; reused for audit regardless of verdict.
        const scrubbedArgs = scrub(args);

        // ── 1. Kill switch ───────────────────────────────────────────────
        if (ks.isKilled()) {
          const state   = ks.getState();
          const ksReason =
            state.reason
              ? `kill switch active — ${state.reason}`
              : 'kill switch active';

          const entry: AuditEntry = {
            ts:         new Date().toISOString(),
            tool:       toolName,
            args:       scrubbedArgs,
            verdict:    'killed',
            reason:     ksReason,
            durationMs: Date.now() - startMs,
          };
          audit.log(entry);
          alerter?.alert('kill', toolName, ksReason, scrubbedArgs);

          log(`KILLED ${toolName} — ${ksReason}`);
          return {
            content: [{ type: 'text' as const, text: `[warden] ${ksReason}` }],
            isError: true,
          };
        }

        // ── 2. Rate limit check ──────────────────────────────────────────
        if (rateLimiter) {
          try {
            rateLimiter.consume(toolName);
          } catch (err: unknown) {
            if (err instanceof RateLimitError) {
              const rlReason = err.message;
              const entry: AuditEntry = {
                ts:         new Date().toISOString(),
                tool:       toolName,
                args:       scrubbedArgs,
                verdict:    'deny',
                reason:     rlReason,
                durationMs: Date.now() - startMs,
              };
              audit.log(entry);
              alerter?.alert('rate-limit', toolName, rlReason, scrubbedArgs);
              log(`RATE-LIMITED ${toolName} — retry after ${Math.ceil(err.retryAfterMs)}ms`);
              return {
                content: [{ type: 'text' as const, text: `[warden] ${rlReason}` }],
                isError: true,
              };
            }
            throw err;
          }
        }

        // ── 3. Policy check ──────────────────────────────────────────────
        const decision = policy.evaluate(toolName, args);

        if (config.mode === 'enforce' && decision.action === 'deny') {
          const entry: AuditEntry = {
            ts:         new Date().toISOString(),
            tool:       toolName,
            args:       scrubbedArgs,
            verdict:    'deny',
            reason:     decision.reason,
            durationMs: Date.now() - startMs,
          };
          audit.log(entry);
          alerter?.alert('deny', toolName, decision.reason ?? 'policy deny', scrubbedArgs);

          log(`DENY ${toolName} — ${decision.reason}`);
          return {
            content: [
              { type: 'text' as const, text: `[warden] Denied: ${decision.reason}` },
            ],
            isError: true,
          };
        }

        // ── 4. Forward to downstream ─────────────────────────────────────
        // Strip the server prefix before forwarding (downstream doesn't know about it)
        const downstreamToolName = prefix ? toolName.slice(prefix.length) : toolName;
        let downstreamResult: Awaited<ReturnType<typeof client.callTool>>;
        try {
          downstreamResult = await client.callTool({
            name:      downstreamToolName,
            arguments: args as Record<string, unknown>,
          });
        } catch (err: unknown) {
          const errMsg = err instanceof Error ? err.message : String(err);
          const durationMs = Date.now() - startMs;

          const entry: AuditEntry = {
            ts:         new Date().toISOString(),
            tool:       toolName,
            args:       scrubbedArgs,
            verdict:    'allow',
            reason:     `forwarded — downstream threw: ${errMsg}`,
            durationMs,
            error:      errMsg,
          };
          audit.log(entry);

          log(`ERROR ${toolName} (${durationMs}ms) — ${errMsg}`);
          return {
            content: [
              { type: 'text' as const, text: `[warden] Downstream error: ${errMsg}` },
            ],
            isError: true,
          };
        }

        const durationMs = Date.now() - startMs;

        // ── 4. Scrub result + build audit entry ──────────────────────────
        const scrubbedResult = scrub(downstreamResult);

        // Surface the isDangerous flag in the audit reason so operators can
        // grep for warnings without changing the verdict field.
        const dangerousSuffix = decision.isDangerous ? ' [isDangerous=true]' : '';
        const auditReason     = `${decision.reason}${dangerousSuffix}`;

        const entry: AuditEntry = {
          ts:         new Date().toISOString(),
          tool:       toolName,
          args:       scrubbedArgs,
          verdict:    'allow',
          reason:     auditReason,
          durationMs,
        };
        audit.log(entry);

        if (decision.isDangerous) {
          log(`WARN ${toolName} forwarded in audit mode — dangerous tool`);
        }

        // ── 5. Return result to upstream ─────────────────────────────────
        // The downstream may return the modern { content: [...] } shape or the
        // legacy { toolResult: unknown } shape.  Normalise to modern form so
        // the upstream always receives a well-formed CallToolResult.
        //
        // We cast through `unknown` because `client.callTool()` returns a
        // discriminated union whose branches TypeScript cannot narrow reliably
        // inside a generic async handler context.
        const raw = downstreamResult as unknown as Record<string, unknown>;

        if (Array.isArray(raw['content'])) {
          // Modern CallToolResult shape — pass through to upstream.
          const modern = downstreamResult as CallToolResult;
          return {
            content:           modern.content,
            isError:           modern.isError,
            structuredContent: modern.structuredContent,
          } satisfies CallToolResult;
        }

        // Legacy toolResult shape (protocol ≤ 2024-10-07) — wrap in text.
        if ('toolResult' in raw) {
          const legacy = raw['toolResult'];
          const text =
            typeof legacy === 'string' ? legacy : JSON.stringify(legacy);
          return {
            content: [{ type: 'text' as const, text }],
          } satisfies CallToolResult;
        }

        // Fallback: unknown shape — serialise the scrubbed copy.
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(scrubbedResult),
            },
          ],
        } satisfies CallToolResult;
      },
    );
  } // end for toolDef
  } // end for clients

  log(`Registered ${totalTools} tools from ${clients.length} server(s)`);

  // ── Transparent resource list proxy (primary server) ───────────────────────
  server.server.setRequestHandler(
    ListResourcesRequestSchema,
    async (request) => {
      try {
        return await primaryClient.listResources(request.params);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        log(`resources/list error — ${msg}`);
        return { resources: [] };
      }
    },
  );

  // ── Transparent prompt list proxy (primary server) ─────────────────────────
  server.server.setRequestHandler(
    ListPromptsRequestSchema,
    async (request) => {
      try {
        return await primaryClient.listPrompts(request.params);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        log(`prompts/list error — ${msg}`);
        return { prompts: [] };
      }
    },
  );

  // ── Connect upstream server ─────────────────────────────────────────────────
  const serverTransport = new StdioServerTransport();
  await server.connect(serverTransport);
  log('Ready');

  // ── Graceful shutdown ───────────────────────────────────────────────────────
  let shuttingDown = false;

  async function shutdown(signal: string): Promise<void> {
    if (shuttingDown) return;
    shuttingDown = true;

    log(`Received ${signal} — shutting down`);

    try {
      audit.flush();
    } catch {
      // flush is a no-op for sync loggers; swallow any edge-case errors
    }

    try {
      audit.close();
    } catch (err: unknown) {
      log(`audit.close error: ${err instanceof Error ? err.message : String(err)}`);
    }

    ks.close();

    for (const { key, client } of clients) {
      try {
        await client.close();
      } catch (err: unknown) {
        log(`client.close error (${key}): ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    try {
      await server.close();
    } catch (err: unknown) {
      log(`server.close error: ${err instanceof Error ? err.message : String(err)}`);
    }

    log('Shutdown complete');
    process.exit(0);
  }

  // Use once() semantics so multiple signals don't race through shutdown.
  process.once('SIGINT',  () => { void shutdown('SIGINT');  });
  process.once('SIGTERM', () => { void shutdown('SIGTERM'); });
}
