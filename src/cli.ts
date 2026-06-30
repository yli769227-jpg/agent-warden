#!/usr/bin/env node
/**
 * agent-warden CLI entry point.
 *
 * Commands:
 *   warden run [config]   – start the proxy (default command)
 *   warden kill [reason]  – arm the kill switch (denies all tool calls)
 *   warden unkill         – disarm the kill switch
 *   warden log            – tail ~/.warden/audit.jsonl in follow mode
 *   warden stats          – audit log stats aggregated by verdict / tool
 *   warden check          – verify config + downstream server reachability
 *   warden init           – write a starter warden.config.yaml in cwd
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import readline from 'node:readline';
import { spawn } from 'node:child_process';
import pc from 'picocolors';
import { loadConfig } from './config.js';
import { runProxy } from './proxy.js';
import { KillSwitch } from './killswitch.js';
import type { AuditEntry } from './types.js';

// ─── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_LOG_FILE = path.join(os.homedir(), '.warden', 'audit.jsonl');

// ─── Usage / help ─────────────────────────────────────────────────────────────

function printUsage(): void {
  console.log(
    [
      '',
      `${pc.bold('agent-warden')} — local MCP audit proxy`,
      '',
      `${pc.bold('Usage:')}`,
      `  warden <command> [options]`,
      '',
      `${pc.bold('Commands:')}`,
      `  ${pc.cyan('run [config]')}      Start the warden proxy (reads config file)`,
      `  ${pc.cyan('kill [reason]')}     Arm the kill switch — all tool calls denied`,
      `  ${pc.cyan('unkill')}            Disarm the kill switch`,
      `  ${pc.cyan('log')}               Tail the audit log in follow mode`,
      `  ${pc.cyan('stats')}             Show audit statistics (counts by verdict / tool)`,
      `  ${pc.cyan('check [config]')}    Verify config and downstream server reachability`,
      `  ${pc.cyan('init')}              Write a starter warden.config.yaml in the current directory`,
      '',
      `${pc.bold('Options:')}`,
      `  -h, --help        Show this help message`,
      '',
      `${pc.bold('Examples:')}`,
      `  warden run`,
      `  warden run ./my-warden.config.yaml`,
      `  warden kill "suspicious activity detected"`,
      `  warden log`,
      `  warden stats`,
      `  warden check`,
      '',
    ].join('\n'),
  );
}

// ─── Command: run ─────────────────────────────────────────────────────────────

async function cmdRun(configArg?: string): Promise<void> {
  const config = loadConfig(configArg);
  await runProxy(config);
}

// ─── Command: kill ────────────────────────────────────────────────────────────

function cmdKill(reason?: string): void {
  const ks = new KillSwitch();
  ks.arm(reason);

  // The actual sentinel path lives inside KillSwitch; getState() exposes it
  // as a non-typed field — access defensively.
  const state = ks.getState() as unknown as Record<string, unknown>;
  const sentinelPath =
    typeof state['path'] === 'string'
      ? state['path']
      : path.join(os.homedir(), '.warden', 'killswitch');

  console.log(pc.red('Kill switch ARMED'));
  if (reason) {
    console.log(`  Reason   : ${pc.yellow(reason)}`);
  }
  console.log(`  Sentinel : ${sentinelPath}`);
}

// ─── Command: unkill ──────────────────────────────────────────────────────────

function cmdUnkill(): void {
  const ks = new KillSwitch();
  ks.disarm();
  console.log(pc.green('Kill switch DISARMED'));
}

// ─── Command: log ─────────────────────────────────────────────────────────────

function formatAuditLine(line: string): string {
  if (!line.trim()) return '';

  let entry: AuditEntry;
  try {
    entry = JSON.parse(line) as AuditEntry;
  } catch {
    return pc.dim(line);
  }

  const ts = pc.dim(entry.ts ?? '');
  const tool = pc.bold(entry.tool ?? '?');

  let verdict: string;
  switch (entry.verdict) {
    case 'allow':
      verdict = pc.green('ALLOW ');
      break;
    case 'deny':
      verdict = pc.red('DENY  ');
      break;
    case 'killed':
      verdict = pc.bgRed(pc.white('KILLED'));
      break;
    default:
      verdict = pc.yellow(String(entry.verdict).padEnd(6));
  }

  const duration = entry.durationMs != null ? pc.dim(` (${entry.durationMs}ms)`) : '';
  const reason = entry.reason ? pc.dim(` — ${entry.reason}`) : '';
  const error = entry.error ? pc.red(` [error: ${entry.error}]`) : '';

  return `${ts} ${verdict} ${tool}${duration}${reason}${error}`;
}

/** Poll until `filePath` exists, checking every 500 ms. */
async function waitForFile(filePath: string): Promise<void> {
  if (fs.existsSync(filePath)) return;
  return new Promise((resolve) => {
    const interval = setInterval(() => {
      if (fs.existsSync(filePath)) {
        clearInterval(interval);
        resolve();
      }
    }, 500);
  });
}

async function cmdLog(): Promise<void> {
  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.log(pc.yellow(`Log file not found: ${logFile}`));
    console.log('Waiting for it to be created…');
  }

  await waitForFile(logFile);

  // ── Print existing content ─────────────────────────────────────────────────
  const readStream = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: readStream, crlfDelay: Infinity });

  for await (const line of rl) {
    const formatted = formatAuditLine(line);
    if (formatted) console.log(formatted);
  }

  // ── Follow mode ───────────────────────────────────────────────────────────
  let position = fs.statSync(logFile).size;
  process.stdout.write(pc.dim('--- following (Ctrl+C to stop) ---\n'));

  const watcher = fs.watch(logFile, () => {
    try {
      const stat = fs.statSync(logFile);
      if (stat.size <= position) return;

      const buf = Buffer.alloc(stat.size - position);
      const fd = fs.openSync(logFile, 'r');
      fs.readSync(fd, buf, 0, buf.length, position);
      fs.closeSync(fd);
      position = stat.size;

      for (const line of buf.toString('utf8').split('\n')) {
        const formatted = formatAuditLine(line);
        if (formatted) console.log(formatted);
      }
    } catch {
      // Log file may have been rotated; ignore transient errors.
    }
  });

  await new Promise<void>((resolve) => {
    process.once('SIGINT', () => {
      watcher.close();
      console.log(''); // newline after ^C
      resolve();
    });
  });
}

// ─── Command: stats ───────────────────────────────────────────────────────────

async function cmdStats(): Promise<void> {
  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.yellow(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  const content = fs.readFileSync(logFile, 'utf8');
  const lines = content.split('\n').filter((l) => l.trim());

  const byVerdict: Record<string, number> = {};
  const byTool: Record<string, number> = {};
  let total = 0;
  let parseErrors = 0;

  for (const line of lines) {
    let entry: AuditEntry;
    try {
      entry = JSON.parse(line) as AuditEntry;
    } catch {
      parseErrors++;
      continue;
    }

    total++;
    const v = entry.verdict ?? 'unknown';
    byVerdict[v] = (byVerdict[v] ?? 0) + 1;

    const t = entry.tool ?? '<unknown>';
    byTool[t] = (byTool[t] ?? 0) + 1;
  }

  console.log(`\n${pc.bold('Audit Log Stats')} — ${logFile}`);
  console.log(pc.dim(`Total entries : ${total}`));
  if (parseErrors > 0) {
    console.log(pc.yellow(`Parse errors  : ${parseErrors}`));
  }

  // ── Verdict breakdown ──────────────────────────────────────────────────────
  console.log(`\n${pc.bold('By Verdict:')}`);

  const verdictOrder = ['allow', 'deny', 'killed'];
  const sortedVerdicts = [
    ...verdictOrder.filter((v) => v in byVerdict),
    ...Object.keys(byVerdict)
      .filter((v) => !verdictOrder.includes(v))
      .sort(),
  ];

  for (const verdict of sortedVerdicts) {
    const count = byVerdict[verdict] ?? 0;
    const pct = total > 0 ? ((count / total) * 100).toFixed(1) : '0.0';

    let label: string;
    switch (verdict) {
      case 'allow':
        label = pc.green(verdict.padEnd(8));
        break;
      case 'deny':
        label = pc.red(verdict.padEnd(8));
        break;
      case 'killed':
        label = pc.bgRed(pc.white(verdict.padEnd(8)));
        break;
      default:
        label = pc.yellow(verdict.padEnd(8));
    }

    console.log(`  ${label}  ${String(count).padStart(7)}  (${pct}%)`);
  }

  // ── Tool breakdown (top 20) ────────────────────────────────────────────────
  const topTools = Object.entries(byTool)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 20);

  if (topTools.length > 0) {
    console.log(`\n${pc.bold('By Tool (top 20):')}`);
    for (const [tool, count] of topTools) {
      const pct = total > 0 ? ((count / total) * 100).toFixed(1) : '0.0';
      console.log(
        `  ${pc.cyan(tool.padEnd(32))}  ${String(count).padStart(7)}  (${pct}%)`,
      );
    }
  }

  console.log();
}

// ─── Command: check ───────────────────────────────────────────────────────────

async function cmdCheck(configArg?: string): Promise<void> {
  console.log(`${pc.bold('Checking warden configuration…')}\n`);

  // 1. Load config
  let config: ReturnType<typeof loadConfig>;
  try {
    config = loadConfig(configArg);
    console.log(`${pc.green('✅')} Config loaded`);
  } catch (err) {
    console.log(`${pc.red('❌')} Config error: ${(err as Error).message}`);
    process.exit(1);
  }

  // 2. Check log directory is writable
  const logDir = path.dirname(config.logFile);
  try {
    fs.mkdirSync(logDir, { recursive: true });
    fs.accessSync(logDir, fs.constants.W_OK);
    console.log(`${pc.green('✅')} Log directory writable: ${logDir}`);
  } catch {
    console.log(`${pc.red('❌')} Log directory not writable: ${logDir}`);
  }

  // 3. Probe downstream command(s)
  // Resolve to the first server command (legacy or first in servers map)
  let cmdParts: string[];
  if (config.servers && Object.keys(config.servers).length > 0) {
    const firstServer = Object.values(config.servers)[0]!;
    cmdParts = [firstServer.command, ...(firstServer.args ?? [])];
  } else if (config.downstreamCommand && config.downstreamCommand.length > 0) {
    cmdParts = config.downstreamCommand;
  } else {
    console.log(`${pc.red('❌')} No downstream server configured`);
    return;
  }
  const [executable, ...cmdArgs] = cmdParts;
  console.log(`\nProbing downstream: ${pc.cyan(cmdParts.join(' '))}`);

  const spawnResult = await new Promise<'started' | 'error' | 'exited'>((resolve) => {
    let settled = false;

    const child = spawn(executable, cmdArgs, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: process.env,
    });

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill('SIGTERM');
      resolve('started');
    }, 2000);

    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      console.log(`${pc.red('❌')} Downstream spawn error: ${err.message}`);
      resolve('error');
    });

    child.on('exit', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      console.log(
        `${pc.yellow('⚠️')}  Downstream exited quickly (code ${code ?? '?'}) — ` +
          'may need stdin / MCP handshake to stay alive',
      );
      resolve('exited');
    });
  });

  if (spawnResult === 'started') {
    console.log(
      `${pc.green('✅')} Downstream process started (killed after 2 s probe timeout)`,
    );
  }

  // 4. Print config summary
  console.log(`\n${pc.bold('Configuration summary:')}`);
  console.log(`  Mode            : ${config.mode}`);
  console.log(`  Log file        : ${config.logFile}`);
  console.log(`  Default action  : ${config.policy.defaultAction}`);
  console.log(`  Policy rules    : ${config.policy.rules?.length ?? 0}`);
  console.log(`  Scrubber        : ${config.scrubber.enabled ? 'enabled' : 'disabled'}`);
}

// ─── Command: init ────────────────────────────────────────────────────────────

function cmdInit(): void {
  const outPath = path.join(process.cwd(), 'warden.config.yaml');

  if (fs.existsSync(outPath)) {
    console.log(pc.yellow(`Config file already exists: ${outPath}`));
    console.log('Remove it first or specify a different location.');
    process.exit(1);
  }

  const starter = `# warden.config.yaml — agent-warden starter configuration
# Full reference: https://github.com/your-org/agent-warden

# 'audit'   — log every intercepted call but always forward it downstream.
# 'enforce' — apply policy rules; deny/kill actions are enforced.
mode: audit

# Path to the JSONL audit log.  Supports ~/ home expansion.
logFile: ~/.warden/audit.jsonl

# Downstream MCP servers Warden proxies to.
# Tool names are prefixed: "filesystem/read_file", "github/create_issue".
# Add as many servers as you need — Warden fans out to all of them.
servers:
  filesystem:
    command: npx
    args:
      - -y
      - "@modelcontextprotocol/server-filesystem"
      - /path/to/allowed/directory

  # Uncomment to add a GitHub MCP server:
  # github:
  #   command: npx
  #   args: ["-y", "@modelcontextprotocol/server-github"]
  #   env:
  #     GITHUB_TOKEN: "\${GITHUB_TOKEN}"

policy:
  # Fallback verdict when no rule matches the tool name.
  defaultAction: allow

  # Ordered rules — first match wins.
  # 'tool' accepts an exact name or a glob (e.g. "filesystem/*", "*delete*").
  rules:
    - tool: "filesystem/write_file"
      action: deny
      reason: "Filesystem writes require explicit approval"

    - tool: "filesystem/read_file"
      action: allow

    # Uncomment to block all shell access:
    # - tool: "*bash*"
    #   action: deny
    #   reason: "Shell access disabled"

scrubber:
  # Redact secrets from payloads before they are written to the audit log.
  enabled: true

  # Additional regex patterns (as strings) to scrub beyond the built-in set.
  # patterns:
  #   - "MY_SECRET_\\\\w+"
`;

  fs.writeFileSync(outPath, starter, 'utf8');
  console.log(`${pc.green('✅')} Created ${outPath}`);
  console.log(`Edit the file, then start the proxy with: ${pc.cyan('warden run')}`);
}

// ─── Entry point ──────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const argv = process.argv.slice(2);

  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') {
    printUsage();
    process.exit(0);
  }

  const command = argv[0];

  switch (command) {
    case 'run':
      await cmdRun(argv[1]);
      break;

    case 'kill':
      cmdKill(argv[1]);
      break;

    case 'unkill':
      cmdUnkill();
      break;

    case 'log':
      await cmdLog();
      break;

    case 'stats':
      await cmdStats();
      break;

    case 'check':
      await cmdCheck(argv[1]);
      break;

    case 'init':
      cmdInit();
      break;

    default:
      console.error(pc.red(`Unknown command: ${command}`));
      console.error(`Run ${pc.cyan('warden --help')} for usage.`);
      process.exit(1);
  }
}

main().catch((err: unknown) => {
  console.error(pc.red(`Fatal: ${(err as Error).message}`));
  process.exit(1);
});
