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
import url from 'node:url';
import readline from 'node:readline';
import { spawn } from 'node:child_process';
import pc from 'picocolors';
import { loadConfig } from './config.js';
import { runProxy } from './proxy.js';
import { KillSwitch } from './killswitch.js';
import { WatchAnalyzer } from './watch-analyzer.js';
import type { AuditEntry } from './types.js';

// ─── Version (read once from package.json at module load) ─────────────────────

function readVersion(): string {
  try {
    const pkgPath = path.resolve(
      path.dirname(url.fileURLToPath(import.meta.url)),
      '..',
      'package.json',
    );
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as { version: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

const VERSION = readVersion();

// ─── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_LOG_FILE = path.join(os.homedir(), '.warden', 'audit.jsonl');

// ─── Usage / help ─────────────────────────────────────────────────────────────

function printUsage(): void {
  console.log(
    [
      '',
      `${pc.bold('agent-warden')} ${pc.dim(`v${VERSION}`)} — local MCP audit proxy`,
      '',
      `${pc.bold('Usage:')}`,
      `  warden <command> [options]`,
      '',
      `${pc.bold('Commands:')}`,
      `  ${pc.cyan('run [config]')}      Start the warden proxy (reads config file)`,
      `  ${pc.cyan('kill [reason]')}     Arm the kill switch — all tool calls denied`,
      `  ${pc.cyan('unkill')}            Disarm the kill switch`,
      `  ${pc.cyan('log')}               Tail the audit log (--tool, --verdict, --since, --tail N, --no-follow, --json)`,
      `  ${pc.cyan('stats')}             Show audit statistics (--since, --json for machine output)`,
      `  ${pc.cyan('check [config]')}    Verify config and downstream server reachability`,
      `  ${pc.cyan('init')}              Write a starter warden.config.yaml in the current directory`,
      `  ${pc.cyan('version')}           Print version and exit`,
      `  ${pc.cyan('export [config]')}   Export audit log to CSV (--output, --since, --tool, --verdict)`,
      `  ${pc.cyan('bench')}             Measure per-call policy+scrubber overhead (--iterations N, --json)`,
      `  ${pc.cyan('rotate')}            Manually rotate the audit log (--no-compress, --list)`,
      `  ${pc.cyan('diff')}              Compare before/after stats around a split point (--split, --window, --json)`,
      `  ${pc.cyan('top')}               Live top-N tools by call count, refreshed every N seconds`,
      `  ${pc.cyan('policy-check')}      Dry-run a tool call through the policy engine without proxying`,
      `  ${pc.cyan('scrub-test')}        Show which fields in a JSON payload would be redacted`,
      `  ${pc.cyan('report')}            Generate a Markdown audit summary report (--output, --since)`,
      `  ${pc.cyan('watch')}             Smart real-time watcher — alerts on bursts, cascading denies, kill events`,
      `  ${pc.cyan('validate')}          Validate config file and report all errors with field paths`,
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

interface LogFilter {
  tool?: string;
  verdict?: string;
  since?: Date;
  follow: boolean;
  json: boolean;   // emit raw JSON instead of human-readable output
  tail?: number;   // show only the last N matching entries before follow
}

/** Parses `--since` values: "1h", "30m", "2d", or an ISO-8601 timestamp. */
function parseSince(value: string): Date {
  const match = /^(\d+)(m|h|d)$/.exec(value);
  if (match) {
    const n    = parseInt(match[1]!, 10);
    const unit = match[2]!;
    const ms   = unit === 'm' ? n * 60_000 : unit === 'h' ? n * 3_600_000 : n * 86_400_000;
    return new Date(Date.now() - ms);
  }
  const d = new Date(value);
  if (isNaN(d.getTime())) throw new Error(`Invalid --since value: "${value}"`);
  return d;
}

function entryMatchesFilter(line: string, filter: LogFilter): boolean {
  if (!line.trim()) return false;
  let entry: AuditEntry;
  try {
    entry = JSON.parse(line) as AuditEntry;
  } catch {
    return true; // show unparseable lines
  }
  if (filter.tool) {
    const pattern = filter.tool.includes('*')
      ? new RegExp('^' + filter.tool.split('*').map(s => s.replace(/[.+^${}()|[\]\\]/g, '\\$&')).join('.*') + '$')
      : null;
    const match = pattern ? pattern.test(entry.tool ?? '') : (entry.tool ?? '').includes(filter.tool);
    if (!match) return false;
  }
  if (filter.verdict && entry.verdict !== filter.verdict) return false;
  if (filter.since && entry.ts && new Date(entry.ts) < filter.since) return false;
  return true;
}

function printLogLine(line: string, filter: LogFilter): void {
  if (!entryMatchesFilter(line, filter)) return;
  if (filter.json) {
    const trimmed = line.trim();
    if (trimmed) process.stdout.write(trimmed + '\n');
  } else {
    const formatted = formatAuditLine(line);
    if (formatted) console.log(formatted);
  }
}

async function cmdLog(flags: string[]): Promise<void> {
  // Parse flags: --tool, --verdict, --since, --no-follow, --json, --tail N
  const filter: LogFilter = { follow: true, json: false };

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if (f === '--no-follow' || f === '-n') {
      filter.follow = false;
    } else if (f === '--json' || f === '-j') {
      filter.json = true;
    } else if ((f === '--tool' || f === '-t') && flags[i + 1]) {
      filter.tool = flags[++i];
    } else if ((f === '--verdict' || f === '-v') && flags[i + 1]) {
      filter.verdict = flags[++i];
    } else if ((f === '--since' || f === '-s') && flags[i + 1]) {
      filter.since = parseSince(flags[++i]!);
    } else if ((f === '--tail' || f === '-N') && flags[i + 1]) {
      const n = parseInt(flags[++i]!, 10);
      if (!isNaN(n) && n > 0) filter.tail = n;
    }
  }

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    if (!filter.json) {
      console.log(pc.yellow(`Log file not found: ${logFile}`));
    }
    if (!filter.follow) { process.exit(0); }
    if (!filter.json) console.log('Waiting for it to be created…');
  }

  await waitForFile(logFile);

  // ── Print existing content (or last N lines when --tail N is set) ──────────
  if (filter.tail != null) {
    // Collect all matching lines then print the last N
    const allLines: string[] = [];
    const scanStream = fs.createReadStream(logFile, { encoding: 'utf8' });
    const scanRl     = readline.createInterface({ input: scanStream, crlfDelay: Infinity });
    for await (const line of scanRl) {
      if (entryMatchesFilter(line, filter)) allLines.push(line);
    }
    const startIdx = Math.max(0, allLines.length - filter.tail);
    for (const line of allLines.slice(startIdx)) {
      printLogLine(line, filter);
    }
  } else {
    const readStream = fs.createReadStream(logFile, { encoding: 'utf8' });
    const rl = readline.createInterface({ input: readStream, crlfDelay: Infinity });
    for await (const line of rl) {
      printLogLine(line, filter);
    }
  }

  if (!filter.follow) return;

  // ── Follow mode ───────────────────────────────────────────────────────────
  let position = fs.statSync(logFile).size;
  if (!filter.json) {
    process.stdout.write(pc.dim('--- following (Ctrl+C to stop) ---\n'));
  }

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
        printLogLine(line, filter);
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

async function cmdStats(flags: string[]): Promise<void> {
  // Parse flags: --since <spec>, --json
  let since: Date | undefined;
  let jsonMode = false;
  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if (f === '--json' || f === '-j') {
      jsonMode = true;
    } else if ((f === '--since' || f === '-s') && flags[i + 1]) {
      since = parseSince(flags[++i]!);
    }
  }

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    if (jsonMode) {
      process.stdout.write(JSON.stringify({ error: 'log file not found', logFile }) + '\n');
    } else {
      console.error(pc.yellow(`Log file not found: ${logFile}`));
    }
    process.exit(1);
  }

  const content = fs.readFileSync(logFile, 'utf8');
  const lines   = content.split('\n').filter((l) => l.trim());

  const byVerdict:    Record<string, number> = {};
  const byTool:       Record<string, number> = {};
  const avgDurationByTool: Record<string, number[]> = {};
  let total       = 0;
  let parseErrors = 0;

  for (const line of lines) {
    let entry: AuditEntry;
    try {
      entry = JSON.parse(line) as AuditEntry;
    } catch {
      parseErrors++;
      continue;
    }

    // Apply --since filter
    if (since && entry.ts && new Date(entry.ts) < since) continue;

    total++;
    const v = entry.verdict ?? 'unknown';
    byVerdict[v] = (byVerdict[v] ?? 0) + 1;

    const t = entry.tool ?? '<unknown>';
    byTool[t] = (byTool[t] ?? 0) + 1;
    if (entry.durationMs != null) {
      (avgDurationByTool[t] ??= []).push(entry.durationMs);
    }
  }

  // ── JSON output ─────────────────────────────────────────────────────────────
  if (jsonMode) {
    const topTools = Object.entries(byTool)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 50)
      .map(([tool, count]) => ({
        tool,
        count,
        avgDurationMs: avgDurationByTool[tool]
          ? Math.round(avgDurationByTool[tool]!.reduce((a, b) => a + b, 0) / avgDurationByTool[tool]!.length)
          : null,
      }));

    process.stdout.write(JSON.stringify({
      logFile,
      since:        since?.toISOString() ?? null,
      total,
      parseErrors,
      byVerdict,
      topTools,
    }, null, 2) + '\n');
    return;
  }

  // ── Human-readable output ────────────────────────────────────────────────────
  const sinceLabel = since ? ` (since ${since.toISOString()})` : '';
  console.log(`\n${pc.bold('Audit Log Stats')} — ${logFile}${sinceLabel}`);
  console.log(pc.dim(`Total entries : ${total}`));
  if (parseErrors > 0) {
    console.log(pc.yellow(`Parse errors  : ${parseErrors}`));
  }

  // ── Verdict breakdown ──────────────────────────────────────────────────────
  console.log(`\n${pc.bold('By Verdict:')}`);

  const verdictOrder = ['allow', 'deny', 'killed'];
  const sortedVerdicts = [
    ...verdictOrder.filter((v) => v in byVerdict),
    ...Object.keys(byVerdict).filter((v) => !verdictOrder.includes(v)).sort(),
  ];

  for (const verdict of sortedVerdicts) {
    const count = byVerdict[verdict] ?? 0;
    const pct   = total > 0 ? ((count / total) * 100).toFixed(1) : '0.0';

    let label: string;
    switch (verdict) {
      case 'allow':  label = pc.green(verdict.padEnd(8));                break;
      case 'deny':   label = pc.red(verdict.padEnd(8));                  break;
      case 'killed': label = pc.bgRed(pc.white(verdict.padEnd(8)));      break;
      default:       label = pc.yellow(verdict.padEnd(8));
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
      const pct  = total > 0 ? ((count / total) * 100).toFixed(1) : '0.0';
      const durs = avgDurationByTool[tool];
      const avg  = durs ? ` avg ${Math.round(durs.reduce((a, b) => a + b, 0) / durs.length)}ms` : '';
      console.log(
        `  ${pc.cyan(tool.padEnd(36))}  ${String(count).padStart(6)}  (${pct}%)${pc.dim(avg)}`,
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

  // 3. Probe all downstream servers in parallel
  interface ServerProbeTarget {
    label: string;
    cmdParts: string[];
    env?: Record<string, string>;
  }

  const probeTargets: ServerProbeTarget[] = [];

  if (config.servers && Object.keys(config.servers).length > 0) {
    for (const [name, srv] of Object.entries(config.servers)) {
      probeTargets.push({
        label: name,
        cmdParts: [srv.command, ...(srv.args ?? [])],
        env: srv.env as Record<string, string> | undefined,
      });
    }
  } else if (config.downstreamCommand && config.downstreamCommand.length > 0) {
    probeTargets.push({ label: '(legacy)', cmdParts: config.downstreamCommand });
  } else {
    console.log(`${pc.red('❌')} No downstream server configured`);
    return;
  }

  async function probeServer(target: ServerProbeTarget): Promise<'started' | 'error' | 'exited'> {
    const [executable, ...cmdArgs] = target.cmdParts;
    const mergedEnv = target.env ? { ...process.env, ...target.env } : process.env;

    return new Promise<'started' | 'error' | 'exited'>((resolve) => {
      let settled = false;

      const child = spawn(executable, cmdArgs, {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: mergedEnv,
      });

      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        child.kill('SIGTERM');
        resolve('started');
      }, 2000);

      child.on('error', () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve('error');
      });

      child.on('exit', () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve('exited');
      });
    });
  }

  console.log(`\nProbing ${probeTargets.length} downstream server${probeTargets.length !== 1 ? 's' : ''}…`);

  let anyFailed = false;
  const probeResults = await Promise.all(probeTargets.map((t) => probeServer(t)));

  for (let i = 0; i < probeTargets.length; i++) {
    const target = probeTargets[i]!;
    const result = probeResults[i]!;
    const cmdStr = target.cmdParts.join(' ');

    if (result === 'started') {
      console.log(`  ${pc.green('✅')} ${pc.cyan(target.label.padEnd(16))} ${pc.dim(cmdStr)}`);
    } else if (result === 'exited') {
      console.log(
        `  ${pc.yellow('⚠️')}  ${pc.cyan(target.label.padEnd(16))} exited quickly — ` +
          `may need MCP handshake to stay alive  ${pc.dim(cmdStr)}`,
      );
    } else {
      console.log(`  ${pc.red('❌')} ${pc.cyan(target.label.padEnd(16))} spawn error  ${pc.dim(cmdStr)}`);
      anyFailed = true;
    }
  }

  if (anyFailed) {
    console.log(pc.yellow('\n⚠️  One or more servers could not be started.'));
  }

  // 4. Print config summary
  console.log(`\n${pc.bold('Configuration summary:')}`);
  console.log(`  Mode            : ${config.mode}`);
  console.log(`  Log file        : ${config.logFile}`);
  console.log(`  Default action  : ${config.policy.defaultAction}`);
  console.log(`  Policy rules    : ${config.policy.rules?.length ?? 0}`);
  console.log(`  Scrubber        : ${config.scrubber.enabled ? 'enabled' : 'disabled'}`);

  if (config.rateLimit) {
    const rl = config.rateLimit;
    const ruleCount = rl.rules?.length ?? 0;
    console.log(`  Rate limiting   : ${rl.enabled ? `enabled (${ruleCount} rule${ruleCount !== 1 ? 's' : ''})` : 'disabled'}`);
  } else {
    console.log(`  Rate limiting   : not configured`);
  }

  if (config.webhook) {
    const wh = config.webhook;
    const targetCount = wh.targets?.length ?? 0;
    const events = wh.on?.join(', ') ?? 'deny, kill, rate-limit';
    console.log(`  Webhook alerts  : ${wh.enabled ? `enabled (${targetCount} target${targetCount !== 1 ? 's' : ''}, on: ${events})` : 'disabled'}`);
  } else {
    console.log(`  Webhook alerts  : not configured`);
  }
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

// ─── Command: export ──────────────────────────────────────────────────────────

/** Escape a CSV field: wrap in quotes if it contains comma, quote, or newline. */
function csvField(value: unknown): string {
  const str = value == null ? '' : typeof value === 'string' ? value : JSON.stringify(value);
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

async function cmdExport(flags: string[]): Promise<void> {
  // Flags: --output/-o <file>, --since/-s, --tool/-t, --verdict/-v
  let outputPath: string | undefined;
  const filter: LogFilter = { follow: false, json: false };

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--output' || f === '-o') && flags[i + 1]) {
      outputPath = flags[++i];
    } else if ((f === '--tool' || f === '-t') && flags[i + 1]) {
      filter.tool = flags[++i];
    } else if ((f === '--verdict' || f === '-v') && flags[i + 1]) {
      filter.verdict = flags[++i];
    } else if ((f === '--since' || f === '-s') && flags[i + 1]) {
      filter.since = parseSince(flags[++i]!);
    }
  }

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  const CSV_HEADER = 'ts,tool,verdict,durationMs,reason,dangerous,args\n';

  const dest = outputPath ? fs.createWriteStream(outputPath, { encoding: 'utf8' }) : process.stdout;

  if (outputPath) dest.write(CSV_HEADER);
  else process.stdout.write(CSV_HEADER);

  const readStream = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: readStream, crlfDelay: Infinity });

  let rowCount = 0;

  for await (const line of rl) {
    if (!line.trim()) continue;
    if (!entryMatchesFilter(line, filter)) continue;

    let entry: AuditEntry;
    try {
      entry = JSON.parse(line) as AuditEntry;
    } catch {
      continue;
    }

    const row = [
      csvField(entry.ts),
      csvField(entry.tool),
      csvField(entry.verdict),
      csvField(entry.durationMs),
      csvField((entry as unknown as Record<string, unknown>)['reason']),
      csvField((entry as unknown as Record<string, unknown>)['dangerous']),
      csvField(JSON.stringify(entry.args)),
    ].join(',') + '\n';

    if (outputPath) (dest as fs.WriteStream).write(row);
    else process.stdout.write(row);

    rowCount++;
  }

  if (outputPath) {
    (dest as fs.WriteStream).end();
    console.error(pc.green(`✅ Exported ${rowCount} rows → ${outputPath}`));
  } else {
    process.stderr.write(pc.dim(`${rowCount} rows exported\n`));
  }
}

// ─── Entry point ──────────────────────────────────────────────────────────────

// ─── Command: bench ───────────────────────────────────────────────────────────

async function cmdBench(flags: string[]): Promise<void> {
  // Flags: --iterations N (default 50), --tool <name> (default "warden/ping"),
  //        --json (machine output), --config <path>
  let iterations = 50;
  let toolName   = '__warden_bench__';
  let jsonOutput = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--iterations' || f === '-i') && flags[i + 1]) {
      const n = parseInt(flags[++i]!, 10);
      if (!isNaN(n) && n > 0) iterations = n;
    } else if ((f === '--tool' || f === '-t') && flags[i + 1]) {
      toolName = flags[++i]!;
    } else if (f === '--json' || f === '-j') {
      jsonOutput = true;
    }
  }

  if (!jsonOutput) {
    console.log(pc.bold(`Warden bench — ${iterations} iterations`));
    console.log(pc.dim(`Measuring policy + scrubber overhead (no downstream server)\n`));
  }

  // We measure the pure in-process overhead: policy evaluation + scrubbing
  // on a synthetic tool call, without spawning any MCP process.
  // This reflects the latency warden adds to each call.

  const { createPolicyEngine }      = await import('./policy.js');
  const { createScrubberFromConfig } = await import('./scrubber.js');

  // Suppress debug logs to stderr during the hot loop
  const origStderrWrite = process.stderr.write.bind(process.stderr);
  process.stderr.write = () => true;

  const policy   = createPolicyEngine({ defaultAction: 'allow', rules: [] });
  const scrub    = createScrubberFromConfig({ enabled: true });

  const syntheticArgs = {
    path:    '/Users/you/file.txt',
    content: 'Hello, world! This is a synthetic payload for benchmarking.',
    token:   'ghp_1234567890abcdef1234567890abcdef1234',
  };

  const timings: number[] = [];

  // Warmup — 5 iterations, discarded
  for (let i = 0; i < 5; i++) {
    const verdict = policy.evaluate(toolName, syntheticArgs);
    if (verdict.action !== 'deny') scrub(syntheticArgs);
  }

  // Measured run
  for (let i = 0; i < iterations; i++) {
    const t0 = performance.now();
    const verdict = policy.evaluate(toolName, syntheticArgs);
    if (verdict.action !== 'deny') scrub(syntheticArgs);
    timings.push(performance.now() - t0);
  }

  // Restore stderr
  process.stderr.write = origStderrWrite;

  timings.sort((a, b) => a - b);

  const mean   = timings.reduce((a, b) => a + b, 0) / timings.length;
  const p50    = timings[Math.floor(timings.length * 0.50)]!;
  const p95    = timings[Math.floor(timings.length * 0.95)]!;
  const p99    = timings[Math.floor(timings.length * 0.99)]!;
  const minVal = timings[0]!;
  const maxVal = timings[timings.length - 1]!;

  const fmt = (n: number): string => n.toFixed(3) + 'ms';

  if (jsonOutput) {
    console.log(JSON.stringify({
      iterations,
      tool: toolName,
      mean_ms:  parseFloat(mean.toFixed(3)),
      p50_ms:   parseFloat(p50.toFixed(3)),
      p95_ms:   parseFloat(p95.toFixed(3)),
      p99_ms:   parseFloat(p99.toFixed(3)),
      min_ms:   parseFloat(minVal.toFixed(3)),
      max_ms:   parseFloat(maxVal.toFixed(3)),
    }, null, 2));
  } else {
    console.log(`  ${pc.cyan('mean')}   ${fmt(mean)}`);
    console.log(`  ${pc.cyan('p50')}    ${fmt(p50)}`);
    console.log(`  ${pc.cyan('p95')}    ${fmt(p95)}`);
    console.log(`  ${pc.cyan('p99')}    ${fmt(p99)}`);
    console.log(`  ${pc.cyan('min')}    ${fmt(minVal)}`);
    console.log(`  ${pc.cyan('max')}    ${fmt(maxVal)}`);
    console.log();

    const grade =
      mean < 0.5  ? pc.green('Excellent (< 0.5ms per call)') :
      mean < 2.0  ? pc.green('Good (< 2ms per call)') :
      mean < 5.0  ? pc.yellow('Acceptable (< 5ms per call)') :
                    pc.red('Slow (> 5ms — check for heavy policy rules)');

    console.log(`  Overhead grade: ${grade}`);
    console.log(
      pc.dim(`\n  (This measures policy evaluation + secret scrubbing only.\n` +
             `   Actual MCP round-trip will add stdio serialisation overhead.)`),
    );
  }
}

// ─── Command: rotate ──────────────────────────────────────────────────────────

async function cmdRotate(flags: string[]): Promise<void> {
  // Flags: --compress/--no-compress, --max-files N, --list
  let compress    = true;
  let maxFiles    = 5;
  let listOnly    = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if (f === '--no-compress')   { compress = false; }
    else if (f === '--compress') { compress = true; }
    else if (f === '--list' || f === '-l') { listOnly = true; }
    else if (f === '--max-files' && flags[i + 1]) {
      const n = parseInt(flags[++i]!, 10);
      if (!isNaN(n) && n > 0) maxFiles = n;
    }
  }

  const { createLogRotator: makeRotator } = await import('./rotate.js');

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;
  const rotator = makeRotator(logFile, { enabled: true, compress, maxFiles });

  if (!rotator) {
    console.error(pc.red('Rotation is disabled in config.'));
    process.exit(1);
  }

  const backups = rotator.listBackups();

  if (listOnly) {
    if (backups.length === 0) {
      console.log(pc.dim('No rotated backups found.'));
      return;
    }
    console.log(pc.bold('Rotated backups:'));
    for (const b of backups) {
      const kb = (b.sizeBytes / 1024).toFixed(1);
      console.log(`  ${pc.cyan(b.path.split('/').pop()!)}  ${kb} KB  ${b.mtime.toISOString()}`);
    }
    return;
  }

  if (!fs.existsSync(logFile)) {
    console.log(pc.yellow(`Log file not found: ${logFile}`));
    return;
  }

  const size = fs.statSync(logFile).size;
  if (size === 0) {
    console.log(pc.yellow('Log file is empty — nothing to rotate.'));
    return;
  }

  process.stderr.write = () => true;   // suppress rotate log lines from output
  const finalPath = await rotator.rotate();
  const origWrite = process.stderr.write;
  process.stderr.write = origWrite;

  const kb = (size / 1024).toFixed(1);
  console.log(`${pc.green('✅')} Rotated ${kb} KB → ${pc.cyan(finalPath)}`);

  if (backups.length > 0) {
    console.log(pc.dim(`  (${backups.length} older backup${backups.length !== 1 ? 's' : ''} remain)`));
  }
}

// ─── Command: validate ────────────────────────────────────────────────────────

interface ValidationIssue {
  level: 'error' | 'warning';
  path:  string;
  msg:   string;
  hint?: string;
}

function validateConfigObject(cfg: Record<string, unknown>): ValidationIssue[] {
  const issues: ValidationIssue[] = [];

  function err(path: string, msg: string, hint?: string): void {
    issues.push({ level: 'error', path, msg, hint });
  }
  function warn(path: string, msg: string, hint?: string): void {
    issues.push({ level: 'warning', path, msg, hint });
  }

  // ── mode ──────────────────────────────────────────────────────────────────
  const mode = cfg['mode'];
  if (mode !== undefined && mode !== 'audit' && mode !== 'enforce') {
    err('mode', `Invalid value "${String(mode)}"`, 'Must be "audit" or "enforce"');
  }

  // ── servers ───────────────────────────────────────────────────────────────
  const servers = cfg['servers'];
  if (servers === undefined || servers === null) {
    err('servers', 'Missing required field', 'At least one server must be defined');
  } else if (typeof servers !== 'object' || Array.isArray(servers)) {
    err('servers', 'Must be an object (map of server name → { command, args? })', '');
  } else {
    const serverMap = servers as Record<string, unknown>;
    if (Object.keys(serverMap).length === 0) {
      err('servers', 'Must define at least one server', '');
    }
    for (const [name, def] of Object.entries(serverMap)) {
      if (!def || typeof def !== 'object' || Array.isArray(def)) {
        err(`servers.${name}`, 'Must be an object with "command" field', '');
        continue;
      }
      const serverDef = def as Record<string, unknown>;
      if (!serverDef['command'] || typeof serverDef['command'] !== 'string') {
        err(`servers.${name}.command`, 'Missing or invalid — must be a non-empty string', '');
      }
      if (serverDef['args'] !== undefined && !Array.isArray(serverDef['args'])) {
        err(`servers.${name}.args`, 'Must be an array of strings', '');
      }
      if (serverDef['env'] !== undefined && typeof serverDef['env'] !== 'object') {
        err(`servers.${name}.env`, 'Must be an object (string → string)', '');
      }
    }
  }

  // ── policy ────────────────────────────────────────────────────────────────
  const policy = cfg['policy'];
  if (policy !== undefined) {
    if (typeof policy !== 'object' || Array.isArray(policy)) {
      err('policy', 'Must be an object', '');
    } else {
      const p = policy as Record<string, unknown>;
      if (p['defaultAction'] !== undefined &&
          p['defaultAction'] !== 'allow' && p['defaultAction'] !== 'deny') {
        err('policy.defaultAction', `Invalid value "${String(p['defaultAction'])}"`,
          'Must be "allow" or "deny"');
      }
      if (p['rules'] !== undefined) {
        if (!Array.isArray(p['rules'])) {
          err('policy.rules', 'Must be an array', '');
        } else {
          const rules = p['rules'] as unknown[];
          rules.forEach((rule, idx) => {
            if (!rule || typeof rule !== 'object') {
              err(`policy.rules[${idx}]`, 'Must be an object', '');
              return;
            }
            const r = rule as Record<string, unknown>;
            if (!r['tool'] || typeof r['tool'] !== 'string') {
              err(`policy.rules[${idx}].tool`, 'Missing or invalid — must be a non-empty string', '');
            }
            if (r['action'] !== 'allow' && r['action'] !== 'deny') {
              err(`policy.rules[${idx}].action`, `Invalid value "${String(r['action'])}"`,
                'Must be "allow" or "deny"');
            }
          });
        }
      }
    }
  }

  // ── scrubber ──────────────────────────────────────────────────────────────
  const scrubber = cfg['scrubber'];
  if (scrubber !== undefined) {
    if (typeof scrubber !== 'object' || Array.isArray(scrubber)) {
      err('scrubber', 'Must be an object', '');
    } else {
      const s = scrubber as Record<string, unknown>;
      if (s['enabled'] !== undefined && typeof s['enabled'] !== 'boolean') {
        err('scrubber.enabled', 'Must be a boolean', '');
      }
      if (s['patterns'] !== undefined && !Array.isArray(s['patterns'])) {
        err('scrubber.patterns', 'Must be an array of regex strings', '');
      }
    }
  }

  // ── rateLimit ─────────────────────────────────────────────────────────────
  const rl = cfg['rateLimit'];
  if (rl !== undefined) {
    if (typeof rl !== 'object' || Array.isArray(rl)) {
      err('rateLimit', 'Must be an object', '');
    } else {
      const r = rl as Record<string, unknown>;
      if (r['rules'] !== undefined && !Array.isArray(r['rules'])) {
        err('rateLimit.rules', 'Must be an array', '');
      } else if (Array.isArray(r['rules'])) {
        const rules = r['rules'] as unknown[];
        rules.forEach((rule, idx) => {
          if (!rule || typeof rule !== 'object') return;
          const rr = rule as Record<string, unknown>;
          if (rr['capacity'] !== undefined && (typeof rr['capacity'] !== 'number' || rr['capacity'] <= 0)) {
            err(`rateLimit.rules[${idx}].capacity`, 'Must be a positive number', '');
          }
          if (rr['windowMs'] !== undefined && (typeof rr['windowMs'] !== 'number' || rr['windowMs'] <= 0)) {
            err(`rateLimit.rules[${idx}].windowMs`, 'Must be a positive number in milliseconds', '');
          }
        });
      }
    }
  }

  // ── webhook ───────────────────────────────────────────────────────────────
  const wh = cfg['webhook'];
  if (wh !== undefined) {
    if (typeof wh !== 'object' || Array.isArray(wh)) {
      err('webhook', 'Must be an object', '');
    } else {
      const w = wh as Record<string, unknown>;
      if (w['targets'] !== undefined && w['targets'] !== null && !Array.isArray(w['targets'])) {
        err('webhook.targets', 'Must be an array of { url, secret?, maxRetries? }', '');
      } else if (Array.isArray(w['targets'])) {
        const targets = w['targets'] as unknown[];
        if (targets.length === 0 && w['enabled'] === true) {
          warn('webhook.targets', 'Webhook is enabled but no targets defined — no alerts will fire', '');
        }
        targets.forEach((t, idx) => {
          if (!t || typeof t !== 'object') return;
          const tt = t as Record<string, unknown>;
          if (!tt['url'] || typeof tt['url'] !== 'string') {
            err(`webhook.targets[${idx}].url`, 'Missing or invalid URL', '');
          }
        });
      }
    }
  }

  // ── rotate ────────────────────────────────────────────────────────────────
  const rotate = cfg['rotate'];
  if (rotate !== undefined) {
    if (typeof rotate !== 'object' || Array.isArray(rotate)) {
      err('rotate', 'Must be an object', '');
    } else {
      const rot = rotate as Record<string, unknown>;
      if (rot['maxBytes'] !== undefined && (typeof rot['maxBytes'] !== 'number' || rot['maxBytes'] <= 0)) {
        err('rotate.maxBytes', 'Must be a positive number (bytes)', '');
      }
      if (rot['maxFiles'] !== undefined && (typeof rot['maxFiles'] !== 'number' || rot['maxFiles'] < 1)) {
        err('rotate.maxFiles', 'Must be a positive integer', '');
      }
    }
  }

  // ── logFile ───────────────────────────────────────────────────────────────
  const logFile = cfg['logFile'];
  if (logFile !== undefined && typeof logFile !== 'string') {
    err('logFile', 'Must be a string path', '');
  }

  return issues;
}

async function cmdValidate(flags: string[]): Promise<void> {
  let configArg: string | undefined;
  let strict    = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--config' || f === '-c') && flags[i + 1]) {
      configArg = flags[++i];
    } else if (f === '--strict') {
      strict = true;
    } else if (!f.startsWith('-') && configArg == null) {
      configArg = f;
    }
  }

  // Load raw YAML without the defaults merge so we can validate structure
  const { resolveConfigPath } = await import('./config.js');
  const { load: yamlLoad }    = await import('js-yaml');

  const cfgPath = configArg ? (await import('node:path')).resolve(configArg) : resolveConfigPath();
  console.log(`${pc.bold('Validating')} ${pc.cyan(cfgPath)}\n`);

  // Read the file
  let rawContent: string;
  try {
    rawContent = fs.readFileSync(cfgPath, 'utf8');
  } catch (err) {
    console.error(pc.red(`❌ Cannot read config file: ${(err as Error).message}`));
    process.exit(1);
  }

  // Parse YAML
  let parsed: Record<string, unknown>;
  try {
    const rawParsed = yamlLoad(rawContent);
    if (rawParsed === null || rawParsed === undefined) {
      console.error(pc.red('❌ Config file is empty'));
      process.exit(1);
    }
    if (typeof rawParsed !== 'object' || Array.isArray(rawParsed)) {
      console.error(pc.red('❌ Config file must be a YAML object (mapping), not a list or scalar'));
      process.exit(1);
    }
    parsed = rawParsed as Record<string, unknown>;
  } catch (err) {
    console.error(pc.red(`❌ YAML parse error: ${(err as Error).message}`));
    process.exit(1);
  }

  // Validate fields
  const issues = validateConfigObject(parsed);
  const errors   = issues.filter(i => i.level === 'error');
  const warnings = issues.filter(i => i.level === 'warning');

  if (issues.length === 0) {
    console.log(pc.green('✅ Config is valid — no issues found'));

    // Also try loadConfig to catch runtime errors (env var expansion, etc.)
    try {
      loadConfig(cfgPath);
      console.log(pc.dim('   Runtime load (with defaults): OK'));
    } catch (err) {
      console.log(pc.yellow(`⚠️  Runtime load warning: ${(err as Error).message}`));
    }
    return;
  }

  if (warnings.length > 0) {
    console.log(pc.yellow(`⚠️  ${warnings.length} warning${warnings.length > 1 ? 's' : ''}:`));
    for (const w of warnings) {
      console.log(`   ${pc.yellow('→')} ${pc.bold(w.path)}: ${w.msg}`);
      if (w.hint) console.log(`      ${pc.dim(w.hint)}`);
    }
    console.log();
  }

  if (errors.length > 0) {
    console.log(pc.red(`❌ ${errors.length} error${errors.length > 1 ? 's' : ''}:`));
    for (const e of errors) {
      console.log(`   ${pc.red('→')} ${pc.bold(e.path)}: ${e.msg}`);
      if (e.hint) console.log(`      ${pc.dim(e.hint)}`);
    }
    console.log();
    process.exit(1);
  }

  if (strict && warnings.length > 0) {
    process.exit(1);
  }
}

// ─── Command: watch ───────────────────────────────────────────────────────────

async function cmdWatch(flags: string[]): Promise<void> {
  // Smart real-time watcher with anomaly detection
  // Flags:
  //   --burst-threshold N    Alert if any tool called >N times in burst window (default 10)
  //   --burst-window-ms N    Burst detection window in ms (default 60000)
  //   --deny-streak N        Alert after N consecutive denies for same tool (default 3)
  //   --no-color             Disable colored output
  //   --silent               Only show alerts, not normal tool calls

  let burstThreshold = 10;
  let burstWindowMs  = 60_000;
  let denyStreak     = 3;
  let silent         = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if (f === '--silent') {
      silent = true;
    } else if (f === '--burst-threshold' && flags[i + 1]) {
      burstThreshold = parseInt(flags[++i]!, 10);
    } else if (f === '--burst-window-ms' && flags[i + 1]) {
      burstWindowMs = parseInt(flags[++i]!, 10);
    } else if (f === '--deny-streak' && flags[i + 1]) {
      denyStreak = parseInt(flags[++i]!, 10);
    }
  }

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.yellow(`Waiting for log file: ${logFile}`));
  }

  const analyzer = new WatchAnalyzer({ burstThreshold, burstWindowMs, denyStreak });

  function printAlert(label: string, msg: string): void {
    const ts = new Date().toLocaleTimeString();
    console.log(`\n${pc.bgRed(pc.white(` ${label} `))} ${pc.dim(ts)} ${msg}\n`);
  }

  function analyzeEntry(entry: AuditEntry): void {
    const tool    = entry.tool ?? 'unknown';
    const verdict = (entry.verdict ?? 'unknown') as string;

    const alerts = analyzer.analyze(entry);
    for (const alert of alerts) {
      if (alert.type === 'burst') {
        printAlert('BURST', `${pc.bold(alert.tool)} called ${pc.yellow(String(alert.count))} times in the last ${Math.round(burstWindowMs / 1000)}s`);
      } else if (alert.type === 'deny-streak') {
        printAlert('DENY STREAK', `${pc.bold(alert.tool)} denied ${pc.red(String(alert.count))} times in a row`);
      } else if (alert.type === 'kill-switch') {
        printAlert('KILL SWITCH', `${pc.bold(alert.tool)} blocked — kill switch is active`);
      }
    }

    // ── Normal output (unless silent) ─────────────────────────────────────────
    if (!silent) {
      const verdictStr =
        verdict === 'allow'  ? pc.green('ALLOW ')  :
        verdict === 'deny'   ? pc.red('DENY  ')    :
        verdict === 'killed' ? pc.bgRed(pc.white('KILLED')) :
                               pc.yellow(String(verdict).padEnd(6));
      const dur = entry.durationMs != null ? pc.dim(` ${entry.durationMs}ms`) : '';
      console.log(`${pc.dim(entry.ts ?? '')} ${verdictStr} ${pc.bold(tool)}${dur}`);
    }
  }

  // ── Tail the log file from the end ────────────────────────────────────────
  console.log(`${pc.bold('agent-warden watch')} — monitoring ${pc.cyan(logFile)}`);
  console.log(pc.dim(`  Burst alert: >${burstThreshold} calls/${Math.round(burstWindowMs/1000)}s · Deny streak: ${denyStreak}x`));
  console.log(pc.dim('  Press Ctrl+C to stop'));
  console.log();

  let fd: number | null = null;
  let fileOffset = 0;
  let buffer = '';

  function openFile(): boolean {
    if (!fs.existsSync(logFile)) return false;
    try {
      fd = fs.openSync(logFile, 'r');
      // Start at end of file
      fileOffset = fs.fstatSync(fd).size;
      return true;
    } catch {
      return false;
    }
  }

  function readNew(): void {
    if (fd === null) {
      if (!openFile()) return;
    }

    try {
      const stat = fs.fstatSync(fd!);
      if (stat.size < fileOffset) {
        // File was truncated/rotated — reopen
        fs.closeSync(fd!);
        fd = null;
        fileOffset = 0;
        buffer = '';
        openFile();
        return;
      }

      if (stat.size > fileOffset) {
        const toRead = stat.size - fileOffset;
        const chunk  = Buffer.alloc(toRead);
        const read   = fs.readSync(fd!, chunk, 0, toRead, fileOffset);
        fileOffset += read;
        buffer += chunk.slice(0, read).toString('utf8');

        const lines = buffer.split('\n');
        buffer = lines.pop() ?? ''; // keep incomplete last line

        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const entry = JSON.parse(line) as AuditEntry;
            analyzeEntry(entry);
          } catch {
            // malformed line — skip
          }
        }
      }
    } catch {
      // fd may have become invalid after rotation
      fd = null;
    }
  }

  openFile();

  const interval = setInterval(readNew, 250);

  process.on('SIGINT', () => {
    clearInterval(interval);
    if (fd !== null) { try { fs.closeSync(fd); } catch { /* ignore */ } }
    console.log('\n' + pc.dim('Watch stopped.'));
    process.exit(0);
  });

  // Keep alive
  await new Promise<void>(() => { /* never resolves — SIGINT exits */ });
}

// ─── Command: report ──────────────────────────────────────────────────────────

async function cmdReport(flags: string[]): Promise<void> {
  // Flags: --output/-o <file.md>, --since/-s <expr>, --title/-t <str>
  let outputPath: string | undefined;
  let sinceDate:  Date | undefined;
  let title      = 'agent-warden Audit Report';

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--output' || f === '-o') && flags[i + 1]) {
      outputPath = flags[++i];
    } else if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate = parseSince(flags[++i]!);
    } else if ((f === '--title' || f === '-t') && flags[i + 1]) {
      title = flags[++i]!;
    }
  }

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Read and aggregate stats ───────────────────────────────────────────────
  let total = 0;
  const byVerdict: Record<string, number>                   = {};
  const byTool:    Record<string, { allow: number; deny: number; killed: number; durations: number[] }> = {};
  let firstTs: string | undefined;
  let lastTs:  string | undefined;
  const recentDenies: Array<{ ts: string; tool: string; reason?: string }> = [];

  const readStream = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl         = readline.createInterface({ input: readStream, crlfDelay: Infinity });

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

    if (sinceDate && entry.ts && new Date(entry.ts) < sinceDate) continue;

    total++;
    byVerdict[entry.verdict] = (byVerdict[entry.verdict] ?? 0) + 1;

    if (!byTool[entry.tool]) byTool[entry.tool] = { allow: 0, deny: 0, killed: 0, durations: [] };
    const ts = byTool[entry.tool]!;
    if (entry.verdict === 'allow')  ts.allow++;
    if (entry.verdict === 'deny')   ts.deny++;
    if (entry.verdict === 'killed') ts.killed++;
    if (typeof entry.durationMs === 'number') ts.durations.push(entry.durationMs);

    if (!firstTs || entry.ts < firstTs) firstTs = entry.ts;
    if (!lastTs  || entry.ts > lastTs)  lastTs   = entry.ts;

    if (entry.verdict === 'deny' || entry.verdict === 'killed') {
      recentDenies.push({
        ts:     entry.ts ?? '',
        tool:   entry.tool ?? '',
        reason: (entry as unknown as Record<string, unknown>)['reason'] as string | undefined,
      });
    }
  }

  const generatedAt = new Date().toISOString();
  const sinceLabel  = sinceDate
    ? sinceDate.toISOString()
    : (firstTs ?? '(no entries)');

  const denyCount   = byVerdict['deny']   ?? 0;
  const killCount   = byVerdict['killed'] ?? 0;
  const allowCount  = byVerdict['allow']  ?? 0;
  const denyRate    = total > 0 ? ((denyCount + killCount) / total * 100).toFixed(1) : '0.0';

  // Top 10 tools by total calls
  const topTools = Object.entries(byTool)
    .sort(([, a], [, b]) => (b.allow + b.deny + b.killed) - (a.allow + a.deny + a.killed))
    .slice(0, 10);

  // ── Render Markdown ────────────────────────────────────────────────────────
  const md: string[] = [];

  md.push(`# ${title}`);
  md.push('');
  md.push(`**Generated:** ${generatedAt}  `);
  md.push(`**Log file:** \`${logFile}\`  `);
  if (sinceDate) {
    md.push(`**Period:** since ${sinceLabel}  `);
  } else {
    md.push(`**Period:** ${sinceLabel ?? '—'} → ${lastTs ?? '—'}  `);
  }
  md.push('');
  md.push('---');
  md.push('');
  md.push('## Summary');
  md.push('');
  md.push('| Metric | Value |');
  md.push('|---|---|');
  md.push(`| Total calls | **${total}** |`);
  md.push(`| Allow | ${allowCount} (${total > 0 ? ((allowCount / total) * 100).toFixed(1) : '0.0'}%) |`);
  md.push(`| Deny | ${denyCount} (${total > 0 ? ((denyCount / total) * 100).toFixed(1) : '0.0'}%) |`);
  md.push(`| Killed | ${killCount} (${total > 0 ? ((killCount / total) * 100).toFixed(1) : '0.0'}%) |`);
  md.push(`| Block rate | **${denyRate}%** |`);
  md.push('');

  if (topTools.length > 0) {
    md.push('## Top Tools');
    md.push('');
    md.push('| Tool | Total | Allow | Deny | Killed | Avg ms |');
    md.push('|---|---|---|---|---|---|');

    for (const [tool, s] of topTools) {
      const toolTotal = s.allow + s.deny + s.killed;
      const avg = s.durations.length > 0
        ? Math.round(s.durations.reduce((a, b) => a + b, 0) / s.durations.length)
        : '—';
      md.push(`| \`${tool}\` | ${toolTotal} | ${s.allow} | ${s.deny} | ${s.killed} | ${avg} |`);
    }
    md.push('');
  }

  if (recentDenies.length > 0) {
    const shown = recentDenies.slice(-20);
    md.push('## Recent Blocked Calls (last 20)');
    md.push('');
    md.push('| Timestamp | Tool | Verdict | Reason |');
    md.push('|---|---|---|---|');
    for (const d of shown) {
      md.push(`| ${d.ts} | \`${d.tool}\` | deny/killed | ${d.reason ?? '—'} |`);
    }
    md.push('');
  }

  md.push('---');
  md.push('');
  md.push('*Generated by [agent-warden](https://github.com/yli769227-jpg/agent-warden)*');
  md.push('');

  const content = md.join('\n');

  if (outputPath) {
    fs.writeFileSync(outputPath, content, 'utf8');
    console.log(`${pc.green('✅')} Report written to ${pc.cyan(outputPath)}`);
    console.log(pc.dim(`  ${total} calls · ${denyRate}% block rate`));
  } else {
    process.stdout.write(content);
  }
}

// ─── Command: scrub-test ──────────────────────────────────────────────────────

async function cmdScrubTest(flags: string[]): Promise<void> {
  // Usage: warden scrub-test [--input '{"key":"val"}'] [--stdin] [--json] [--config path]
  // Shows what the scrubber would redact in a given payload.

  let inputJson: string | undefined;
  let useStdin  = false;
  let jsonOutput = false;
  let configArg: string | undefined;
  let customPatterns: string[] = [];

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if (f === '--stdin' || f === '-') {
      useStdin = true;
    } else if (f === '--json' || f === '-j') {
      jsonOutput = true;
    } else if ((f === '--input' || f === '-i') && flags[i + 1]) {
      inputJson = flags[++i];
    } else if ((f === '--config' || f === '-c') && flags[i + 1]) {
      configArg = flags[++i];
    } else if ((f === '--pattern' || f === '-p') && flags[i + 1]) {
      customPatterns.push(flags[++i]!);
    } else if (!f.startsWith('-') && inputJson == null) {
      inputJson = f;
    }
  }

  // Read from stdin if requested or if no input provided and not a tty
  if (useStdin || (inputJson == null && !process.stdin.isTTY)) {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin as unknown as AsyncIterable<Buffer>) {
      chunks.push(chunk);
    }
    inputJson = Buffer.concat(chunks).toString('utf8').trim();
  }

  if (!inputJson) {
    console.error(pc.red('Provide JSON via --input \'{"key":"val"}\' or pipe to stdin'));
    console.error(pc.dim('  Example: echo \'{"token":"ghp_abc123"}\' | warden scrub-test'));
    process.exit(1);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(inputJson);
  } catch {
    console.error(pc.red(`Invalid JSON: ${inputJson.slice(0, 80)}`));
    process.exit(1);
  }

  // Load scrubber config
  const { createScrubber, createScrubberFromConfig } = await import('./scrubber.js');

  let scrub: (v: unknown) => unknown;

  if (configArg || customPatterns.length === 0) {
    // Load from config
    const origStderr = process.stderr.write.bind(process.stderr);
    process.stderr.write = () => true;
    try {
      const cfg = loadConfig(configArg);
      const allPatterns = [...(cfg.scrubber.patterns ?? []), ...customPatterns];
      scrub = createScrubber(allPatterns);
    } catch {
      // Config not found — use defaults + custom patterns
      scrub = createScrubber(customPatterns);
    }
    process.stderr.write = origStderr;
  } else {
    scrub = createScrubber(customPatterns);
  }

  const scrubbed = scrub(parsed);

  if (jsonOutput) {
    console.log(JSON.stringify({ original: parsed, scrubbed }, null, 2));
    return;
  }

  // Diff-style output — show what changed
  const origStr    = JSON.stringify(parsed,   null, 2);
  const scrubbedStr = JSON.stringify(scrubbed, null, 2);

  if (origStr === scrubbedStr) {
    console.log(pc.green('✅ No secrets detected — payload would be logged as-is'));
    console.log(pc.dim(origStr));
    return;
  }

  console.log(pc.yellow('⚠️  Secrets detected — redacted fields:'));
  console.log();

  // Line-by-line comparison — highlight changed lines
  const origLines     = origStr.split('\n');
  const scrubbedLines = scrubbedStr.split('\n');

  for (let i = 0; i < Math.max(origLines.length, scrubbedLines.length); i++) {
    const o = origLines[i] ?? '';
    const s = scrubbedLines[i] ?? '';

    if (o === s) {
      console.log(`  ${pc.dim(s)}`);
    } else {
      console.log(`  ${pc.red('- ' + o)}`);
      console.log(`  ${pc.green('+ ' + s)}`);
    }
  }

  console.log();
}

// ─── Command: policy-check ────────────────────────────────────────────────────

async function cmdPolicyCheck(flags: string[]): Promise<void> {
  // Usage: warden policy-check <toolName> [--args '{...}'] [--config <path>] [--json]
  // Evaluates the policy engine for a given tool + args and prints the decision.

  let toolName   = '';
  let argsJson   = '{}';
  let configArg: string | undefined;
  let jsonOutput = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if (f === '--json' || f === '-j') {
      jsonOutput = true;
    } else if ((f === '--args' || f === '-a') && flags[i + 1]) {
      argsJson = flags[++i]!;
    } else if ((f === '--config' || f === '-c') && flags[i + 1]) {
      configArg = flags[++i];
    } else if (!f.startsWith('-')) {
      toolName = f;
    }
  }

  if (!toolName) {
    console.error(pc.red('Usage: warden policy-check <toolName> [--args \'{"key":"val"}\'] [--config path] [--json]'));
    process.exit(1);
  }

  let parsedArgs: unknown;
  try {
    parsedArgs = JSON.parse(argsJson);
  } catch {
    console.error(pc.red(`Invalid --args JSON: ${argsJson}`));
    process.exit(1);
  }

  // Load config (suppressing the debug log line)
  const origStderr = process.stderr.write.bind(process.stderr);
  process.stderr.write = () => true;
  let config: ReturnType<typeof loadConfig>;
  try {
    config = loadConfig(configArg);
  } catch (err) {
    process.stderr.write = origStderr;
    console.error(pc.red(`Config error: ${(err as Error).message}`));
    process.exit(1);
  }
  process.stderr.write = origStderr;

  const { createPolicyEngine } = await import('./policy.js');
  const { createScrubberFromConfig } = await import('./scrubber.js');

  const policyConfig = { ...config.policy, mode: config.mode };
  const engine   = createPolicyEngine(policyConfig);
  const scrub    = createScrubberFromConfig(config.scrubber);

  process.stderr.write = () => true;
  const decision     = engine.evaluate(toolName, parsedArgs);
  const scrubbedArgs = config.scrubber.enabled ? scrub(parsedArgs) : parsedArgs;
  process.stderr.write = origStderr;

  const verdict =
    config.mode === 'enforce' && decision.action === 'deny'
      ? 'deny'
      : 'allow';

  if (jsonOutput) {
    console.log(JSON.stringify({
      tool:         toolName,
      args:         parsedArgs,
      scrubbedArgs,
      mode:         config.mode,
      action:      decision.action,
      verdict,
      reason:      decision.reason,
      isDangerous: decision.isDangerous,
    }, null, 2));
    return;
  }

  const verdictLabel =
    verdict === 'allow'
      ? pc.green('ALLOW')
      : pc.red('DENY');

  console.log(`\n${pc.bold('Policy dry-run')}  tool: ${pc.cyan(toolName)}  mode: ${config.mode}`);
  console.log(`\n  Verdict       ${verdictLabel}`);
  if (decision.reason) {
    console.log(`  Reason        ${decision.reason}`);
  }
  if (decision.isDangerous) {
    console.log(`  ${pc.yellow('⚠️')}  Tool matched a dangerous-pattern heuristic`);
  }
  if (config.scrubber.enabled) {
    const hasSecrets = JSON.stringify(parsedArgs) !== JSON.stringify(scrubbedArgs);
    if (hasSecrets) {
      console.log(`  ${pc.dim('Secrets detected in args — would be redacted in audit log')}`);
    }
  }
  console.log();
}

// ─── Command: top ─────────────────────────────────────────────────────────────

async function cmdTop(flags: string[]): Promise<void> {
  // Flags: --n N (default 10), --interval N (seconds, default 5), --once/-1
  let topN     = 10;
  let interval = 5;
  let once     = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--n' || f === '-n') && flags[i + 1]) {
      const n = parseInt(flags[++i]!, 10);
      if (!isNaN(n) && n > 0) topN = n;
    } else if ((f === '--interval' || f === '-i') && flags[i + 1]) {
      const n = parseInt(flags[++i]!, 10);
      if (!isNaN(n) && n > 0) interval = n;
    } else if (f === '--once' || f === '-1') {
      once = true;
    }
  }

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  async function readTopN(): Promise<{
    tool: string;
    total: number;
    allow: number;
    deny: number;
    killed: number;
    avgMs: number | null;
  }[]> {
    const toolStats: Record<string, {
      total: number; allow: number; deny: number; killed: number;
      durations: number[];
    }> = {};

    if (!fs.existsSync(logFile)) return [];

    const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
    const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

    for await (const line of rl) {
      if (!line.trim()) continue;
      let entry: AuditEntry;
      try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

      const t = entry.tool ?? '(unknown)';
      if (!toolStats[t]) toolStats[t] = { total: 0, allow: 0, deny: 0, killed: 0, durations: [] };
      toolStats[t]!.total++;
      if (entry.verdict === 'allow')  toolStats[t]!.allow++;
      if (entry.verdict === 'deny')   toolStats[t]!.deny++;
      if (entry.verdict === 'killed') toolStats[t]!.killed++;
      if (typeof entry.durationMs === 'number') toolStats[t]!.durations.push(entry.durationMs);
    }

    return Object.entries(toolStats)
      .sort(([, a], [, b]) => b.total - a.total)
      .slice(0, topN)
      .map(([tool, s]) => ({
        tool,
        total:  s.total,
        allow:  s.allow,
        deny:   s.deny,
        killed: s.killed,
        avgMs:  s.durations.length > 0
          ? Math.round(s.durations.reduce((a, b) => a + b, 0) / s.durations.length)
          : null,
      }));
  }

  function render(rows: Awaited<ReturnType<typeof readTopN>>): void {
    if (!once) {
      // Move cursor up to overwrite previous output (after first render)
      process.stdout.write('\x1b[2J\x1b[H'); // clear screen
    }

    const now = new Date().toISOString();
    console.log(`${pc.bold('warden top')} — ${pc.dim(now)}  ${pc.dim(`(refreshes every ${interval}s, Ctrl+C to stop)`)}`);
    console.log();

    if (rows.length === 0) {
      console.log(pc.dim(`  No data in ${logFile}`));
      return;
    }

    const headerTool    = 'Tool'.padEnd(36);
    const headerTotal   = 'Calls'.padStart(7);
    const headerAllow   = 'Allow'.padStart(7);
    const headerDeny    = 'Deny'.padStart(7);
    const headerKilled  = 'Killed'.padStart(7);
    const headerAvg     = 'Avg ms'.padStart(8);
    console.log(pc.dim(`  ${headerTool}  ${headerTotal}  ${headerAllow}  ${headerDeny}  ${headerKilled}  ${headerAvg}`));
    console.log(pc.dim(`  ${'─'.repeat(80)}`));

    for (const row of rows) {
      const toolStr   = row.tool.padEnd(36);
      const totalStr  = String(row.total).padStart(7);
      const allowStr  = String(row.allow).padStart(7);
      const denyStr   = String(row.deny).padStart(7);
      const killedStr = String(row.killed).padStart(7);
      const avgStr    = row.avgMs != null ? String(row.avgMs).padStart(8) : '       —';

      const denyColored  = row.deny   > 0 ? pc.red(denyStr)   : denyStr;
      const killedColored = row.killed > 0 ? pc.bgRed(pc.white(killedStr)) : killedStr;

      console.log(`  ${pc.cyan(toolStr)}  ${totalStr}  ${pc.green(allowStr)}  ${denyColored}  ${killedColored}  ${pc.dim(avgStr)}`);
    }

    console.log();
  }

  // First render
  const rows = await readTopN();
  render(rows);

  if (once) return;

  // Live-refresh loop
  const refreshInterval = setInterval(async () => {
    try {
      const freshRows = await readTopN();
      render(freshRows);
    } catch {
      // ignore read errors during refresh
    }
  }, interval * 1000);

  process.on('SIGINT', () => {
    clearInterval(refreshInterval);
    console.log(pc.dim('\n(stopped)'));
    process.exit(0);
  });

  // Keep the process alive
  await new Promise<void>(() => { /* never resolves; SIGINT exits */ });
}

// ─── Command: diff ────────────────────────────────────────────────────────────

interface PeriodStats {
  total: number;
  byVerdict: Record<string, number>;
  byTool: Record<string, number>;
}

async function readPeriodStats(logFile: string, from: Date, to: Date): Promise<PeriodStats> {
  const stats: PeriodStats = { total: 0, byVerdict: {}, byTool: {} };

  if (!fs.existsSync(logFile)) return stats;

  const readStream = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl         = readline.createInterface({ input: readStream, crlfDelay: Infinity });

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

    const ts = entry.ts ? new Date(entry.ts) : null;
    if (!ts || ts < from || ts > to) continue;

    stats.total++;
    stats.byVerdict[entry.verdict] = (stats.byVerdict[entry.verdict] ?? 0) + 1;
    stats.byTool[entry.tool]       = (stats.byTool[entry.tool] ?? 0) + 1;
  }

  return stats;
}

async function cmdDiff(flags: string[]): Promise<void> {
  // Compare [--before T] window vs [--after T] window.
  // Default: split the last 24h in half (first 12h vs last 12h).
  // --before <timestamp-or-expr>: end of the "before" period
  // --after  <timestamp-or-expr>: start of the "after" period
  // --window <expr>: half-window length (default "12h")
  // --json: machine-readable output

  let splitPoint = new Date(Date.now() - 12 * 3_600_000); // 12h ago
  let windowMs   = 12 * 3_600_000;
  let jsonOutput = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if (f === '--json' || f === '-j') {
      jsonOutput = true;
    } else if ((f === '--split' || f === '-s') && flags[i + 1]) {
      splitPoint = parseSince(flags[++i]!);
    } else if ((f === '--window' || f === '-w') && flags[i + 1]) {
      const windowDate = parseSince(flags[++i]!);
      windowMs = Date.now() - windowDate.getTime();
    }
  }

  const beforeFrom = new Date(splitPoint.getTime() - windowMs);
  const beforeTo   = splitPoint;
  const afterFrom  = splitPoint;
  const afterTo    = new Date(splitPoint.getTime() + windowMs);

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  const [before, after] = await Promise.all([
    readPeriodStats(logFile, beforeFrom, beforeTo),
    readPeriodStats(logFile, afterFrom, afterTo),
  ]);

  if (jsonOutput) {
    console.log(JSON.stringify({
      split:  splitPoint.toISOString(),
      window: `${Math.round(windowMs / 3_600_000)}h`,
      before: { from: beforeFrom.toISOString(), to: beforeTo.toISOString(), ...before },
      after:  { from: afterFrom.toISOString(),  to: afterTo.toISOString(),  ...after  },
    }, null, 2));
    return;
  }

  const fmtPct  = (n: number, total: number): string =>
    total === 0 ? '—' : `${((n / total) * 100).toFixed(1)}%`;

  const fmtDiff = (a: number, b: number): string => {
    const d = b - a;
    if (d === 0) return pc.dim('±0');
    return d > 0 ? pc.red(`+${d}`) : pc.green(`${d}`);
  };

  const fmtPctDiff = (a: number, ta: number, b: number, tb: number): string => {
    const pa = ta === 0 ? 0 : (a / ta) * 100;
    const pb = tb === 0 ? 0 : (b / tb) * 100;
    const d  = pb - pa;
    if (Math.abs(d) < 0.05) return pc.dim('±0%');
    const s = d.toFixed(1) + '%';
    return d > 0 ? pc.red(`+${s}`) : pc.green(`${s}`);
  };

  console.log(`\n${pc.bold('Warden diff')}  split: ${pc.cyan(splitPoint.toISOString())}\n`);
  console.log(
    `  ${pc.dim('Period')}          ${pc.bold('Before'.padEnd(12))}  ${pc.bold('After'.padEnd(12))}  ${pc.bold('Δ')}`,
  );
  console.log(`  ${pc.dim('─'.repeat(50))}`);
  console.log(
    `  ${'Total calls'.padEnd(16)}  ${String(before.total).padEnd(12)}  ${String(after.total).padEnd(12)}  ${fmtDiff(before.total, after.total)}`,
  );

  const verdictOrder = ['allow', 'deny', 'killed'];
  const verdictSet = new Set([...Object.keys(before.byVerdict), ...Object.keys(after.byVerdict)]);
  const verdicts = [
    ...verdictOrder.filter((v) => verdictSet.has(v)),
    ...Array.from(verdictSet).filter((v) => !verdictOrder.includes(v)).sort(),
  ];
  for (const v of verdicts) {
    const b = before.byVerdict[v] ?? 0;
    const a = after.byVerdict[v]  ?? 0;
    const label =
      v === 'allow'  ? pc.green('allow') :
      v === 'deny'   ? pc.red('deny') :
      v === 'killed' ? pc.bgRed(pc.white('killed')) :
                       pc.yellow(v);

    console.log(
      `  ${(label + '  rate').padEnd(24)}  ` +
      `${fmtPct(b, before.total).padEnd(12)}  ` +
      `${fmtPct(a, after.total).padEnd(12)}  ` +
      `${fmtPctDiff(b, before.total, a, after.total)}`,
    );
  }

  // Top tools that changed
  const allTools = new Set([...Object.keys(before.byTool), ...Object.keys(after.byTool)]);
  const toolDeltas = Array.from(allTools).map((t) => ({
    t,
    delta: (after.byTool[t] ?? 0) - (before.byTool[t] ?? 0),
  })).sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta)).slice(0, 5);

  if (toolDeltas.some(({ delta }) => delta !== 0)) {
    console.log(`\n${pc.bold('Top tool changes:')}`);
    for (const { t, delta } of toolDeltas) {
      if (delta === 0) continue;
      const b = before.byTool[t] ?? 0;
      const a = after.byTool[t]  ?? 0;
      console.log(
        `  ${pc.cyan(t.padEnd(36))}  ${String(b).padEnd(6)} → ${String(a).padEnd(6)}  ${fmtDiff(b, a)}`,
      );
    }
  }

  console.log();
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);

  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') {
    printUsage();
    process.exit(0);
  }

  if (argv[0] === '--version' || argv[0] === '-V') {
    console.log(VERSION);
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
      await cmdLog(argv.slice(1));
      break;

    case 'stats':
      await cmdStats(argv.slice(1));
      break;

    case 'check':
      await cmdCheck(argv[1]);
      break;

    case 'init':
      cmdInit();
      break;

    case 'version':
      console.log(VERSION);
      break;

    case 'export':
      await cmdExport(argv.slice(1));
      break;

    case 'bench':
      await cmdBench(argv.slice(1));
      break;

    case 'rotate':
      await cmdRotate(argv.slice(1));
      break;

    case 'diff':
      await cmdDiff(argv.slice(1));
      break;

    case 'top':
      await cmdTop(argv.slice(1));
      break;

    case 'policy-check':
    case 'policy':
      await cmdPolicyCheck(argv.slice(1));
      break;

    case 'scrub-test':
    case 'scrub':
      await cmdScrubTest(argv.slice(1));
      break;

    case 'report':
      await cmdReport(argv.slice(1));
      break;

    case 'watch':
      await cmdWatch(argv.slice(1));
      break;

    case 'validate':
      await cmdValidate(argv.slice(1));
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
