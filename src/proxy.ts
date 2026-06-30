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
import type { AuditEntry, WardenConfig } from './types.js';

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
  const policy  = createPolicyEngine(config.policy);
  const scrub   = createScrubberFromConfig(config.scrubber);
  const audit   = createAuditLogger(config.logFile);
  const ks      = new KillSwitch();

  // Start watching the sentinel file immediately.
  ks.watch();

  // ── Downstream client ───────────────────────────────────────────────────────
  const [downstreamExe, ...downstreamArgs] = config.downstreamCommand;
  const downstreamTransport = new StdioClientTransport({
    command: downstreamExe,
    args:    downstreamArgs,
    // Inherit stderr so downstream server logs surface in the warden process.
    stderr: 'inherit',
  });

  const client = new Client(
    { name: 'agent-warden-client', version: '0.1.0' },
    { capabilities: {} },
  );

  await client.connect(downstreamTransport);
  log('Connected to downstream');

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

  // ── Tool discovery + registration ───────────────────────────────────────────
  const { tools } = await client.listTools();
  log(`Discovered ${tools.length} tools from downstream`);

  for (const toolDef of tools) {
    const toolName        = toolDef.name;
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

          log(`KILLED ${toolName} — ${ksReason}`);
          return {
            content: [{ type: 'text' as const, text: `[warden] ${ksReason}` }],
            isError: true,
          };
        }

        // ── 2. Policy check ──────────────────────────────────────────────
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

          log(`DENY ${toolName} — ${decision.reason}`);
          return {
            content: [
              { type: 'text' as const, text: `[warden] Denied: ${decision.reason}` },
            ],
            isError: true,
          };
        }

        // ── 3. Forward to downstream ─────────────────────────────────────
        let downstreamResult: Awaited<ReturnType<typeof client.callTool>>;
        try {
          downstreamResult = await client.callTool({
            name:      toolName,
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
  }

  log(`Registered ${tools.length} tools`);

  // ── Transparent resource list proxy ────────────────────────────────────────
  // Use the underlying Server to install a raw handler so we can forward the
  // downstream's resource catalogue without re-implementing pagination logic.
  server.server.setRequestHandler(
    ListResourcesRequestSchema,
    async (request) => {
      try {
        return await client.listResources(request.params);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        log(`resources/list error — ${msg}`);
        return { resources: [] };
      }
    },
  );

  // ── Transparent prompt list proxy ───────────────────────────────────────────
  server.server.setRequestHandler(
    ListPromptsRequestSchema,
    async (request) => {
      try {
        return await client.listPrompts(request.params);
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

    try {
      await client.close();
    } catch (err: unknown) {
      log(`client.close error: ${err instanceof Error ? err.message : String(err)}`);
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
