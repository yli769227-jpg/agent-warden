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
import zlib from 'node:zlib';
import { spawn, spawnSync } from 'node:child_process';
import pc from 'picocolors';
import { loadConfig } from './config.js';
import { runProxy } from './proxy.js';
import { KillSwitch } from './killswitch.js';
import { WatchAnalyzer } from './watch-analyzer.js';
import { validateConfigObject } from './validator.js';
import type { ValidationIssue } from './validator.js';
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
      `  ${pc.cyan('alert-test')}        Send a test webhook to all configured targets and report results`,
      `  ${pc.cyan('config-gen')}        Scan Claude Desktop / Claude Code config and generate warden.config.yaml`,
      `  ${pc.cyan('server-list')}        Connect to all configured servers and list available tools`,
      `  ${pc.cyan('timeline')}           ASCII timeline of tool calls grouped by time bucket`,
      `  ${pc.cyan('doctor')}             Full health check of warden installation and config`,
      `  ${pc.cyan('suggest')}            Analyse audit log and suggest policy rules`,
      `  ${pc.cyan('snapshot')}           Save a timestamped JSON snapshot of current audit stats`,
      `  ${pc.cyan('compare')}            Compare two snapshot files and show regressions`,
      `  ${pc.cyan('trending')}           Show which tools are rising or falling in call rate`,
      `  ${pc.cyan('anomaly-score')}      Compute a 0-100 risk score from recent audit behaviour`,
      `  ${pc.cyan('replay')}             Re-evaluate audit log entries against current policy`,
      `  ${pc.cyan('ci-check')}           Run all CI safety checks and exit 1 if any fail`,
      `  ${pc.cyan('profile')}            Show tool call distribution and session behaviour profile`,
      `  ${pc.cyan('summary')}            Generate a plain-English security summary for stakeholders`,
      `  ${pc.cyan('heat-map')}           Show tool-call density as an hour × day heat map`,
      `  ${pc.cyan('install')}           Inject warden proxy into Claude Desktop / Claude Code (backs up original)`,
      `  ${pc.cyan('uninstall')}         Restore original MCP server config from backup`,
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

async function cmdRun(argv: string[]): Promise<void> {
  // Parse run-specific flags that can override config values
  // Supported: [config] --mode audit|enforce --log-file <path> --no-rotate
  let configArg:   string | undefined;
  let modeOverride:    string | undefined;
  let logFileOverride: string | undefined;
  let noRotate         = false;

  for (let i = 0; i < argv.length; i++) {
    const f = argv[i]!;
    if ((f === '--mode' || f === '-m') && argv[i + 1]) {
      modeOverride = argv[++i];
    } else if (f === '--log-file' && argv[i + 1]) {
      logFileOverride = argv[++i];
    } else if (f === '--no-rotate') {
      noRotate = true;
    } else if (!f.startsWith('-') && configArg == null) {
      configArg = f;
    }
  }

  const config = loadConfig(configArg);

  // Apply CLI overrides
  if (modeOverride) {
    if (modeOverride !== 'audit' && modeOverride !== 'enforce') {
      console.error(pc.red(`Invalid --mode value: "${modeOverride}" (must be "audit" or "enforce")`));
      process.exit(1);
    }
    config.mode = modeOverride as 'audit' | 'enforce';
    process.stderr.write(`[warden:run] mode overridden to "${modeOverride}" by --mode flag\n`);
  }

  if (logFileOverride) {
    config.logFile = logFileOverride;
    process.stderr.write(`[warden:run] logFile overridden to "${logFileOverride}" by --log-file flag\n`);
  }

  if (noRotate && config.rotate) {
    config.rotate.enabled = false;
    process.stderr.write('[warden:run] log rotation disabled by --no-rotate flag\n');
  }

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
  grep?: RegExp;   // match raw JSON line or any field value
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
  if (filter.grep && !filter.grep.test(line)) return false;
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
  // Parse flags: --tool, --verdict, --since, --no-follow, --json, --tail N, --grep
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
    } else if ((f === '--grep' || f === '-g') && flags[i + 1]) {
      try {
        filter.grep = new RegExp(flags[++i]!, 'i');
      } catch {
        console.error(pc.red(`Invalid --grep pattern: ${flags[i]}`));
        process.exit(1);
      }
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

// ─── Command: export-html ─────────────────────────────────────────────────────

async function cmdExportHtml(flags: string[]): Promise<void> {
  // Generates a self-contained interactive HTML report from the audit log.
  // All JS and CSS is inlined — no external dependencies.
  //
  // Flags:
  //   --output/-o <path>   Output file (default: warden-report-<ts>.html)
  //   --since/-s <expr>    Only include entries since this date
  //   --title/-t <text>    Page title
  //   --max-rows <N>       Maximum rows to embed (default 5000)
  //   --open               Open in default browser after generating

  let outputPath: string | undefined;
  let sinceDate: Date | undefined;
  let title    = 'Warden Audit Report';
  let maxRows  = 5000;
  let autoOpen = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--output' || f === '-o') && flags[i + 1]) {
      outputPath = flags[++i];
    } else if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate  = parseSince(flags[++i]!);
    } else if ((f === '--title' || f === '-t') && flags[i + 1]) {
      title      = flags[++i]!;
    } else if (f === '--max-rows' && flags[i + 1]) {
      maxRows    = parseInt(flags[++i]!, 10) || 5000;
    } else if (f === '--open') {
      autoOpen   = true;
    }
  }

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Read and aggregate entries ──────────────────────────────────────────────
  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  const rows: AuditEntry[] = [];
  let   total = 0, allowed = 0, denied = 0, killed = 0, totalMs = 0;
  const toolCounts: Record<string, number> = {};

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

    if (sinceDate && entry.ts && new Date(entry.ts) < sinceDate) continue;

    total++;
    if (entry.verdict === 'allow')        allowed++;
    else if (entry.verdict === 'deny')    denied++;
    else if (entry.verdict === 'killed')  killed++;
    totalMs += entry.durationMs ?? 0;

    const t = entry.tool ?? '(unknown)';
    toolCounts[t] = (toolCounts[t] ?? 0) + 1;

    if (rows.length < maxRows) rows.push(entry);
  }

  const avgMs  = total > 0 ? Math.round(totalMs / total) : 0;
  const topTools = Object.entries(toolCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15)
    .map(([tool, count]) => ({ tool, count, pct: Math.round(count / total * 100) }));

  // ── Inline JSON data into the HTML ─────────────────────────────────────────
  const rowsJson  = JSON.stringify(rows);
  const topJson   = JSON.stringify(topTools);
  const statsJson = JSON.stringify({
    total, allowed, denied, killed, avgMs,
    denyRate: total > 0 ? Math.round(denied / total * 100) : 0,
  });
  const generatedAt = new Date().toISOString();

  const escHtml = (s: string) =>
    s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escHtml(title)}</title>
<style>
:root {
  --bg:#0f1117;--surface:#1a1d27;--border:#2a2d3e;
  --text:#e2e4ec;--muted:#6b7280;--accent:#6366f1;
  --green:#22c55e;--yellow:#f59e0b;--red:#ef4444;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif;padding:24px}
h1{font-size:1.5rem;font-weight:700;margin-bottom:4px}
.meta{color:var(--muted);font-size:12px;margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:16px;margin-bottom:24px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px}
.card .label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px}
.card .value{font-size:1.75rem;font-weight:700}
.card.green .value{color:var(--green)}.card.yellow .value{color:var(--yellow)}.card.red .value{color:var(--red)}
.section{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:24px}
.section h2{font-size:1rem;font-weight:600;margin-bottom:12px}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:6px;font-size:12px}
.bar-row .tname{width:200px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--muted)}
.bar-row .bwrap{flex:1;background:var(--border);border-radius:4px;height:8px}
.bar-row .bar{background:var(--accent);border-radius:4px;height:8px}
.controls{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap}
.controls input,.controls select{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:6px;font-size:13px}
.controls input{flex:1;min-width:180px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);color:var(--muted);font-weight:500;white-space:nowrap;cursor:pointer;user-select:none}
th:hover{color:var(--text)}
td{padding:7px 10px;border-bottom:1px solid #1e2130;vertical-align:top}
tr:hover td{background:#1e2130}
.badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:500}
.badge.allow{background:#14532d;color:#4ade80}.badge.deny{background:#450a0a;color:#f87171}
.badge.killed{background:#3b0764;color:#e879f9}.badge.other{background:var(--border);color:var(--muted)}
.args{max-width:350px;white-space:pre-wrap;word-break:break-all;color:var(--muted)}
.pager{display:flex;gap:8px;align-items:center;justify-content:flex-end;margin-top:12px}
.pager button{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:4px 12px;border-radius:6px;cursor:pointer;font-size:12px}
.pager button:disabled{opacity:.4;cursor:default}
.pager .info{color:var(--muted);font-size:12px}
</style>
</head>
<body>
<h1>${escHtml(title)}</h1>
<div class="meta">Generated ${generatedAt} · Log: ${escHtml(logFile)} · Showing up to ${maxRows.toLocaleString()} rows</div>
<div class="grid" id="sg"></div>
<div class="section"><h2>Top Tools</h2><div id="tt"></div></div>
<div class="section">
  <h2>Audit Log</h2>
  <div class="controls">
    <input id="q" type="search" placeholder="Filter by tool, verdict, reason…" oninput="applyF()">
    <select id="vf" onchange="applyF()">
      <option value="">All verdicts</option>
      <option value="allow">allow</option>
      <option value="deny">deny</option>
      <option value="killed">killed</option>
    </select>
  </div>
  <table>
    <thead><tr>
      <th onclick="sb('ts')">Timestamp</th>
      <th onclick="sb('tool')">Tool</th>
      <th onclick="sb('verdict')">Verdict</th>
      <th onclick="sb('durationMs')">Latency</th>
      <th>Args / Reason</th>
    </tr></thead>
    <tbody id="lb"></tbody>
  </table>
  <div class="pager">
    <button id="pb" onclick="pp()">← Prev</button>
    <span class="info" id="pi"></span>
    <button id="nb" onclick="np()">Next →</button>
  </div>
</div>
<script>
const ROWS=${rowsJson};
const TOP=${topJson};
const S=${statsJson};
(function(){
  const g=document.getElementById('sg');
  const cards=[
    {l:'Total Calls',v:S.total.toLocaleString(),c:''},
    {l:'Allowed',v:S.allowed.toLocaleString(),c:'green'},
    {l:'Denied',v:S.denied.toLocaleString(),c:S.denied>0?'yellow':''},
    {l:'Killed',v:S.killed.toLocaleString(),c:S.killed>0?'red':''},
    {l:'Deny Rate',v:S.denyRate+'%',c:S.denyRate>=20?'red':S.denyRate>0?'yellow':'green'},
    {l:'Avg Latency',v:S.avgMs+'ms',c:''},
  ];
  g.innerHTML=cards.map(c=>\`<div class="card \${c.c}"><div class="label">\${c.l}</div><div class="value">\${c.v}</div></div>\`).join('');
})();
(function(){
  const el=document.getElementById('tt');
  const mx=TOP.length?TOP[0].pct:1;
  el.innerHTML=TOP.map(t=>\`<div class="bar-row"><div class="tname" title="\${t.tool}">\${t.tool}</div><div class="bwrap"><div class="bar" style="width:\${(t.pct/Math.max(mx,1)*100).toFixed(1)}%"></div></div><div style="width:40px;text-align:right;font-size:12px">\${t.count}</div></div>\`).join('');
})();
let fil=[...ROWS],sk='ts',sd=-1,pg=0;
const PS=50;
function fts(ts){if(!ts)return'';try{return new Date(ts).toLocaleString();}catch{return ts;}}
function fa(e){const p=[];if(e.reason)p.push('reason: '+e.reason);if(e.args&&Object.keys(e.args).length){const s=JSON.stringify(e.args);p.push(s.length>200?s.slice(0,200)+'…':s);}return p.join('\\n');}
function vb(v){const c=v==='allow'?'allow':v==='deny'?'deny':v==='killed'?'killed':'other';return\`<span class="badge \${c}">\${v??''}</span>\`;}
function render(){
  const sl=fil.slice(pg*PS,(pg+1)*PS);
  document.getElementById('lb').innerHTML=sl.map(e=>\`<tr><td style="white-space:nowrap;color:var(--muted)">\${fts(e.ts)}</td><td>\${e.tool??''}</td><td>\${vb(e.verdict)}</td><td style="white-space:nowrap">\${e.durationMs!=null?e.durationMs+'ms':''}</td><td class="args">\${fa(e)}</td></tr>\`).join('');
  const tp=Math.max(1,Math.ceil(fil.length/PS));
  document.getElementById('pi').textContent=fil.length.toLocaleString()+' rows · page '+(pg+1)+' / '+tp;
  document.getElementById('pb').disabled=pg===0;
  document.getElementById('nb').disabled=pg>=tp-1;
}
function applyF(){
  const q=document.getElementById('q').value.toLowerCase();
  const v=document.getElementById('vf').value;
  fil=ROWS.filter(e=>{
    if(v&&e.verdict!==v)return false;
    if(q){const h=(e.tool??'')+' '+(e.verdict??'')+' '+(e.reason??'')+' '+JSON.stringify(e.args??'');if(!h.toLowerCase().includes(q))return false;}
    return true;
  });pg=0;render();
}
function sb(k){if(sk===k)sd*=-1;else{sk=k;sd=-1;}fil.sort((a,b)=>{const av=a[k]??'',bv=b[k]??'';return av<bv?sd:av>bv?-sd:0;});pg=0;render();}
function pp(){if(pg>0){pg--;render();}}
function np(){pg++;render();}
render();
</script>
</body>
</html>`;

  // ── Write output ────────────────────────────────────────────────────────────
  const ts      = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const outFile = outputPath ?? `warden-report-${ts}.html`;

  fs.writeFileSync(outFile, html, 'utf8');
  const kb = (Buffer.byteLength(html) / 1024).toFixed(1);
  console.log(`${pc.green('✓')} Report written to ${pc.bold(outFile)} (${rows.length.toLocaleString()} rows, ${kb} KB)`);

  if (autoOpen) {
    const opener = process.platform === 'darwin' ? 'open'
                 : process.platform === 'win32'  ? 'start'
                 : 'xdg-open';
    spawnSync(opener, [outFile], { stdio: 'ignore' });
  }
}

// ─── Command: scope ───────────────────────────────────────────────────────────

async function cmdScope(flags: string[]): Promise<void> {
  // Analyses tool call arguments to build a map of what file paths, URLs,
  // GitHub repos, and other resources were accessed by each tool.
  //
  // "What files did the agent touch in the last hour?"
  //
  // Heuristics for resource extraction (applied to args JSON):
  //   - Keys containing "path", "file", "dir", "url", "repo", "target",
  //     "resource", "src", "dest", "source", "destination" are extracted.
  //   - Values that look like absolute paths (/foo/bar) or relative (./foo)
  //     are classified as filesystem resources.
  //   - Values matching https?:// are URLs.
  //   - owner/repo patterns are GitHub repos.
  //
  // Flags:
  //   --since/-s <expr>   Only include entries since this date (default: 1h)
  //   --window/-w <h>     Window in hours (overrides --since)
  //   --tool/-t <glob>    Filter to matching tools
  //   --json/-j           Machine-readable output
  //   --top <N>           Top resources per category (default 20)

  let sinceDate: Date | undefined;
  let toolFilter: string | undefined;
  let jsonOutput  = false;
  let topN        = 20;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate  = parseSince(flags[++i]!);
    } else if ((f === '--window' || f === '-w') && flags[i + 1]) {
      const h    = parseFloat(flags[++i]!);
      sinceDate  = new Date(Date.now() - h * 3_600_000);
    } else if ((f === '--tool' || f === '-t') && flags[i + 1]) {
      toolFilter = flags[++i];
    } else if (f === '--json' || f === '-j') {
      jsonOutput = true;
    } else if (f === '--top' && flags[i + 1]) {
      topN       = parseInt(flags[++i]!, 10) || 20;
    }
  }

  // Default window: 1 hour
  if (!sinceDate) sinceDate = new Date(Date.now() - 3_600_000);

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Resource extraction helpers ─────────────────────────────────────────────
  const RESOURCE_KEYS = new Set([
    'path', 'file', 'dir', 'url', 'repo', 'target', 'resource',
    'src', 'dest', 'source', 'destination', 'filename', 'filepath',
    'directory', 'location', 'bucket', 'key',
  ]);

  type Category = 'filesystem' | 'url' | 'github' | 'other';

  function classify(value: string): Category {
    if (/^https?:\/\//i.test(value))         return 'url';
    if (/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(value) && !value.includes('//', 1)) return 'github';
    if (/^(\/|\.\/|\.\.\/)/.test(value) || /^[A-Z]:\\/i.test(value)) return 'filesystem';
    return 'other';
  }

  function extractResources(args: unknown, tool: string): Array<{ resource: string; category: Category; tool: string }> {
    const out: Array<{ resource: string; category: Category; tool: string }> = [];
    if (!args || typeof args !== 'object') return out;

    function walk(obj: unknown): void {
      if (typeof obj === 'string') {
        const v = obj.trim();
        if (v.length < 2 || v.length > 512) return;
        if (/^https?:\/\//i.test(v)) {
          out.push({ resource: v, category: 'url', tool });
        } else if (/^(\/|\.\/|\.\.\/)/.test(v)) {
          out.push({ resource: v, category: 'filesystem', tool });
        }
        return;
      }
      if (Array.isArray(obj)) { obj.forEach(walk); return; }
      if (typeof obj === 'object' && obj !== null) {
        for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
          if (RESOURCE_KEYS.has(k.toLowerCase())) {
            if (typeof v === 'string' && v.trim().length > 0) {
              const val = v.trim();
              out.push({ resource: val, category: classify(val), tool });
            } else {
              walk(v);
            }
          } else {
            walk(v);
          }
        }
      }
    }

    walk(args);
    return out;
  }

  // ── Read log ────────────────────────────────────────────────────────────────
  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  type ResourceCount = { resource: string; category: Category; tools: Set<string>; calls: number };
  const byResource = new Map<string, ResourceCount>();
  let   total      = 0;

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

    if (entry.ts && new Date(entry.ts) < sinceDate) continue;

    const tool = entry.tool ?? '(unknown)';
    if (toolFilter) {
      const pattern = toolFilter.replace(/\*/g, '.*').replace(/\?/g, '.');
      if (!new RegExp(`^${pattern}$`, 'i').test(tool)) continue;
    }

    total++;
    const extracted = extractResources(entry.args, tool);
    for (const { resource, category } of extracted) {
      const key = `${category}::${resource}`;
      if (!byResource.has(key)) {
        byResource.set(key, { resource, category, tools: new Set(), calls: 0 });
      }
      const r = byResource.get(key)!;
      r.tools.add(tool);
      r.calls++;
    }
  }

  // ── Group by category ───────────────────────────────────────────────────────
  const categories: Record<Category, ResourceCount[]> = {
    filesystem: [],
    url:        [],
    github:     [],
    other:      [],
  };

  for (const rc of byResource.values()) {
    categories[rc.category].push(rc);
  }
  for (const cat of Object.values(categories)) {
    cat.sort((a, b) => b.calls - a.calls);
    if (cat.length > topN) cat.splice(topN);
  }

  const sinceStr = sinceDate.toISOString();

  if (jsonOutput) {
    const toJson = (cat: ResourceCount[]) =>
      cat.map(r => ({
        resource: r.resource,
        calls:    r.calls,
        tools:    [...r.tools].sort(),
      }));
    console.log(JSON.stringify({
      since:      sinceStr,
      totalCalls: total,
      filesystem: toJson(categories.filesystem),
      url:        toJson(categories.url),
      github:     toJson(categories.github),
      other:      toJson(categories.other),
    }, null, 2));
    return;
  }

  // ── Text output ─────────────────────────────────────────────────────────────
  const totalResources = categories.filesystem.length + categories.url.length
                       + categories.github.length + categories.other.length;

  console.log(`\n${pc.bold('warden scope')} — resource access map`);
  console.log(pc.dim(`  Since ${sinceStr} · ${total} tool calls · ${totalResources} unique resources`));
  console.log();

  function printSection(label: string, items: ResourceCount[], colour: (s: string) => string): void {
    if (items.length === 0) return;
    console.log(pc.bold(label));
    for (const r of items) {
      const toolList = [...r.tools].sort().join(', ');
      console.log(`  ${colour(r.resource.padEnd(55))} ${pc.dim(String(r.calls).padStart(4) + 'x  ')}${pc.dim(toolList)}`);
    }
    console.log();
  }

  printSection('Filesystem Paths', categories.filesystem, pc.cyan);
  printSection('URLs', categories.url, pc.blue);
  printSection('GitHub Repos', categories.github, pc.green);
  printSection('Other Resources', categories.other, pc.yellow);

  if (totalResources === 0) {
    console.log(pc.dim('  No resources found in this window. Tool args may not contain path/url fields.'));
    console.log();
  }
}

// ─── Command: blame ───────────────────────────────────────────────────────────

async function cmdBlame(flags: string[]): Promise<void> {
  // Identifies the busiest time buckets in the audit log and reports which
  // tool(s) were "responsible" (most calls in that bucket).
  //
  // Useful for answering: "When was the agent most active, and what was it doing?"
  //
  // Algorithm:
  //   1. Divide the window into fixed-size buckets
  //   2. Count calls per bucket
  //   3. Rank buckets by call volume
  //   4. For each hot bucket, report the top tools driving the activity
  //
  // Flags:
  //   --since/-s <expr>    Start of window
  //   --window/-w <h>      Window in hours (default 24h)
  //   --bucket-mins <N>    Bucket size in minutes (default 15)
  //   --top-buckets <N>    Number of hot buckets to report (default 5)
  //   --top-tools <N>      Tools per bucket (default 3)
  //   --json/-j            Machine-readable output
  //   --threshold <N>      Only report buckets with >= N calls

  let sinceDate: Date | undefined;
  let windowH       = 24;
  let bucketMins    = 15;
  let topBuckets    = 5;
  let topToolsN     = 3;
  let jsonOutput    = false;
  let thresholdCalls = 1;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate     = parseSince(flags[++i]!);
    } else if ((f === '--window' || f === '-w') && flags[i + 1]) {
      windowH       = parseFloat(flags[++i]!) || 24;
    } else if (f === '--bucket-mins' && flags[i + 1]) {
      bucketMins    = parseInt(flags[++i]!, 10) || 15;
    } else if (f === '--top-buckets' && flags[i + 1]) {
      topBuckets    = parseInt(flags[++i]!, 10) || 5;
    } else if (f === '--top-tools' && flags[i + 1]) {
      topToolsN     = parseInt(flags[++i]!, 10) || 3;
    } else if (f === '--threshold' && flags[i + 1]) {
      thresholdCalls = parseInt(flags[++i]!, 10) || 1;
    } else if (f === '--json' || f === '-j') {
      jsonOutput    = true;
    }
  }

  const windowMs  = windowH * 3_600_000;
  const effectiveSince = sinceDate ?? new Date(Date.now() - windowMs);
  const bucketMs  = bucketMins * 60_000;

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Read log into buckets ──────────────────────────────────────────────────
  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  // bucket index = floor((ts - sinceMs) / bucketMs)
  const sinceMs    = effectiveSince.getTime();
  const bucketCalls = new Map<number, { total: number; tools: Record<string, number>; denied: number }>();
  let   totalCalls  = 0;

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

    if (!entry.ts) continue;
    const ts = new Date(entry.ts).getTime();
    if (ts < sinceMs) continue;
    if (ts > sinceMs + windowMs) continue;

    const bIdx = Math.floor((ts - sinceMs) / bucketMs);
    if (!bucketCalls.has(bIdx)) {
      bucketCalls.set(bIdx, { total: 0, tools: {}, denied: 0 });
    }
    const b = bucketCalls.get(bIdx)!;
    b.total++;
    const tool = entry.tool ?? '(unknown)';
    b.tools[tool] = (b.tools[tool] ?? 0) + 1;
    if (entry.verdict === 'deny' || entry.verdict === 'killed') b.denied++;
    totalCalls++;
  }

  // ── Rank buckets ──────────────────────────────────────────────────────────
  const ranked = [...bucketCalls.entries()]
    .filter(([, b]) => b.total >= thresholdCalls)
    .sort((a, b) => b[1].total - a[1].total)
    .slice(0, topBuckets);

  type BucketResult = {
    bucketStart: string;
    bucketEnd:   string;
    calls:       number;
    denied:      number;
    topTools:    Array<{ tool: string; calls: number }>;
  };

  const results: BucketResult[] = ranked.map(([idx, b]) => {
    const startMs  = sinceMs + idx * bucketMs;
    const endMs    = startMs + bucketMs;
    const topT     = Object.entries(b.tools)
      .sort((a, z) => z[1] - a[1])
      .slice(0, topToolsN)
      .map(([tool, calls]) => ({ tool, calls }));
    return {
      bucketStart: new Date(startMs).toISOString(),
      bucketEnd:   new Date(endMs).toISOString(),
      calls:       b.total,
      denied:      b.denied,
      topTools:    topT,
    };
  });

  if (jsonOutput) {
    console.log(JSON.stringify({
      since:        effectiveSince.toISOString(),
      windowH,
      bucketMins,
      totalCalls,
      hotBuckets:   results,
    }, null, 2));
    return;
  }

  // ── Text output ─────────────────────────────────────────────────────────────
  console.log(`\n${pc.bold('warden blame')} — top ${topBuckets} activity spikes`);
  console.log(pc.dim(`  Since ${effectiveSince.toISOString()} · ${windowH}h window · ${bucketMins}min buckets · ${totalCalls} total calls`));
  console.log();

  if (results.length === 0) {
    console.log(pc.dim('  No activity above threshold in this window.'));
    console.log();
    return;
  }

  for (const [rank, r] of results.entries()) {
    const start  = new Date(r.bucketStart);
    const hhmm   = `${String(start.getUTCHours()).padStart(2, '0')}:${String(start.getUTCMinutes()).padStart(2, '0')} UTC`;
    const date   = r.bucketStart.slice(0, 10);
    const denied = r.denied > 0 ? pc.red(` (${r.denied} denied)`) : '';
    console.log(`  ${pc.bold(`#${rank + 1}`)} ${pc.cyan(date + ' ' + hhmm)} — ${pc.bold(String(r.calls))} calls${denied}`);
    for (const t of r.topTools) {
      const bar = '█'.repeat(Math.min(20, Math.ceil(t.calls / r.calls * 20)));
      console.log(`      ${pc.dim(bar.padEnd(20))}  ${t.tool} (${t.calls})`);
    }
    console.log();
  }
}

// ─── Command: session-summary ─────────────────────────────────────────────────

async function cmdSessionSummary(flags: string[]): Promise<void> {
  // Detects logical "sessions" in the audit log by clustering consecutive
  // entries with inter-call gaps shorter than --gap-mins.
  //
  // For each session, reports:
  //   - start/end time and duration
  //   - total, allowed, denied, killed call counts
  //   - top tools used
  //   - top file paths accessed (from args.path / args.file keys)
  //   - risk grade for the session
  //
  // Flags:
  //   --since/-s <expr>    Filter entries (default: last 24h)
  //   --gap-mins <N>       Gap in minutes that separates sessions (default 10)
  //   --last <N>           Only show last N sessions (default show all)
  //   --json/-j            Machine-readable output
  //   --min-calls <N>      Skip sessions shorter than N calls (default 1)

  let sinceDate: Date | undefined;
  let gapMins    = 10;
  let lastN      = 0;
  let jsonOutput = false;
  let minCalls   = 1;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate  = parseSince(flags[++i]!);
    } else if (f === '--gap-mins' && flags[i + 1]) {
      gapMins    = parseInt(flags[++i]!, 10) || 10;
    } else if (f === '--last' && flags[i + 1]) {
      lastN      = parseInt(flags[++i]!, 10) || 0;
    } else if (f === '--min-calls' && flags[i + 1]) {
      minCalls   = parseInt(flags[++i]!, 10) || 1;
    } else if (f === '--json' || f === '-j') {
      jsonOutput = true;
    }
  }

  if (!sinceDate) sinceDate = new Date(Date.now() - 24 * 3_600_000);
  const gapMs = gapMins * 60_000;

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Read all entries ────────────────────────────────────────────────────────
  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  const entries: AuditEntry[] = [];

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }
    if (entry.ts && new Date(entry.ts) >= sinceDate) entries.push(entry);
  }

  entries.sort((a, b) => {
    const ta = a.ts ? new Date(a.ts).getTime() : 0;
    const tb = b.ts ? new Date(b.ts).getTime() : 0;
    return ta - tb;
  });

  // ── Cluster into sessions ───────────────────────────────────────────────────
  type Session = {
    id:       number;
    start:    string;
    end:      string;
    durationMs: number;
    calls:    number;
    allowed:  number;
    denied:   number;
    killed:   number;
    grade:    string;
    riskScore: number;
    topTools: Array<{ tool: string; calls: number }>;
    topPaths: Array<{ path: string; calls: number }>;
  };

  const PATH_KEYS = new Set(['path', 'file', 'dir', 'filename', 'filepath', 'directory']);

  function extractPaths(args: unknown): string[] {
    const out: string[] = [];
    function walk(o: unknown): void {
      if (typeof o === 'string') {
        if (/^(\/|\.\/|\.\.\/)/.test(o.trim())) out.push(o.trim());
        return;
      }
      if (Array.isArray(o)) { o.forEach(walk); return; }
      if (typeof o === 'object' && o !== null) {
        for (const [k, v] of Object.entries(o as Record<string, unknown>)) {
          if (PATH_KEYS.has(k.toLowerCase()) && typeof v === 'string' && v.trim().length > 0) {
            out.push(v.trim());
          } else { walk(v); }
        }
      }
    }
    walk(args);
    return out;
  }

  function gradeSession(denied: number, killed: number, calls: number): { grade: string; riskScore: number } {
    const denyRate   = calls > 0 ? denied / calls : 0;
    const riskScore  = Math.round(denyRate * 40 + (killed > 0 ? 40 : 0) + Math.min(30, denyRate * 60));
    const grade = riskScore >= 80 ? 'CRITICAL'
                : riskScore >= 60 ? 'HIGH'
                : riskScore >= 40 ? 'MEDIUM'
                : riskScore >= 10 ? 'LOW'
                : 'CLEAN';
    return { grade, riskScore };
  }

  const sessions: Session[] = [];
  let sessionId  = 0;
  let current: AuditEntry[] = [];
  let lastTs = 0;

  function flushSession(): void {
    if (current.length < minCalls) { current = []; return; }
    const toolCounts: Record<string, number> = {};
    const pathCounts: Record<string, number> = {};
    let allowed = 0, denied = 0, killed = 0;

    for (const e of current) {
      const t = e.tool ?? '(unknown)';
      toolCounts[t] = (toolCounts[t] ?? 0) + 1;
      if (e.verdict === 'allow')       allowed++;
      else if (e.verdict === 'deny')   denied++;
      else if (e.verdict === 'killed') killed++;
      for (const p of extractPaths(e.args)) {
        pathCounts[p] = (pathCounts[p] ?? 0) + 1;
      }
    }

    const startTs = current[0]!.ts ?? '';
    const endTs   = current[current.length - 1]!.ts ?? '';
    const durationMs = endTs && startTs
      ? new Date(endTs).getTime() - new Date(startTs).getTime()
      : 0;

    const topTools = Object.entries(toolCounts).sort((a, b) => b[1] - a[1]).slice(0, 5)
      .map(([tool, c]) => ({ tool, calls: c }));
    const topPaths = Object.entries(pathCounts).sort((a, b) => b[1] - a[1]).slice(0, 5)
      .map(([path, c]) => ({ path, calls: c }));

    const { grade, riskScore } = gradeSession(denied, killed, current.length);

    sessions.push({
      id: ++sessionId,
      start: startTs, end: endTs, durationMs,
      calls: current.length, allowed, denied, killed,
      grade, riskScore, topTools, topPaths,
    });
    current = [];
  }

  for (const entry of entries) {
    const ts = entry.ts ? new Date(entry.ts).getTime() : 0;
    if (lastTs > 0 && ts - lastTs > gapMs) {
      flushSession();
    }
    current.push(entry);
    lastTs = ts;
  }
  if (current.length > 0) flushSession();

  let displaySessions = sessions;
  if (lastN > 0) displaySessions = sessions.slice(-lastN);

  if (jsonOutput) {
    console.log(JSON.stringify({
      since:      sinceDate.toISOString(),
      gapMins,
      totalSessions: sessions.length,
      sessions:   displaySessions,
    }, null, 2));
    return;
  }

  // ── Text output ─────────────────────────────────────────────────────────────
  const GRADE_COLOUR: Record<string, (s: string) => string> = {
    CLEAN:    pc.green,
    LOW:      pc.cyan,
    MEDIUM:   pc.yellow,
    HIGH:     (s) => pc.bold(pc.yellow(s)),
    CRITICAL: (s) => pc.bold(pc.red(s)),
  };

  console.log(`\n${pc.bold('warden session-summary')} — ${displaySessions.length} of ${sessions.length} sessions`);
  console.log(pc.dim(`  Since ${sinceDate.toISOString()} · gap=${gapMins}min`));
  console.log();

  if (displaySessions.length === 0) {
    console.log(pc.dim('  No sessions found in this window.'));
    console.log();
    return;
  }

  for (const s of displaySessions) {
    const colour = GRADE_COLOUR[s.grade] ?? pc.white;
    const dur    = s.durationMs < 60_000
      ? `${Math.round(s.durationMs / 1000)}s`
      : `${Math.round(s.durationMs / 60_000)}m`;
    const denied = s.denied > 0 ? pc.red(` ${s.denied} denied`) : '';
    const killed = s.killed > 0 ? pc.red(` ${s.killed} killed`) : '';
    console.log(`  Session #${s.id}  ${colour(`[${s.grade}]`)}  ${pc.dim(s.start.slice(0, 19).replace('T', ' '))} → ${dur}`);
    console.log(`    ${s.calls} calls${denied}${killed}  ·  tools: ${s.topTools.map(t => t.tool).join(', ')}`);
    if (s.topPaths.length > 0) {
      console.log(`    paths: ${s.topPaths.map(p => p.path).join(', ')}`);
    }
    console.log();
  }
}

// ─── Command: alert-history ───────────────────────────────────────────────────

async function cmdAlertHistory(flags: string[]): Promise<void> {
  // Shows all security incidents (deny + killed verdicts) from the audit log.
  // Useful for reviewing "what triggered alerts?" without having to grep.
  //
  // Groups consecutive deny/kill events within a configurable burst window,
  // so a rapid cascade of denies appears as a single incident entry.
  //
  // Flags:
  //   --since/-s <expr>    Start of window (default: all)
  //   --verdict <v>        Filter: deny | killed | all (default: all)
  //   --burst-secs <N>     Group events within N seconds (default 60)
  //   --limit <N>          Max incidents to show (default 50)
  //   --json/-j            Machine-readable output
  //   --reverse/-r         Show oldest first (default: newest first)

  let sinceDate: Date | undefined;
  let verdictFilter: string | undefined;
  let burstSecs   = 60;
  let limit       = 50;
  let jsonOutput  = false;
  let newestFirst = true;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate     = parseSince(flags[++i]!);
    } else if (f === '--verdict' && flags[i + 1]) {
      verdictFilter = flags[++i];
    } else if (f === '--burst-secs' && flags[i + 1]) {
      burstSecs     = parseInt(flags[++i]!, 10) || 60;
    } else if (f === '--limit' && flags[i + 1]) {
      limit         = parseInt(flags[++i]!, 10) || 50;
    } else if (f === '--json' || f === '-j') {
      jsonOutput    = true;
    } else if (f === '--reverse' || f === '-r') {
      newestFirst   = false;
    }
  }

  const burstMs = burstSecs * 1000;

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Collect alert entries ──────────────────────────────────────────────────
  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  const alertEntries: AuditEntry[] = [];

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

    if (sinceDate && entry.ts && new Date(entry.ts) < sinceDate) continue;

    const v = entry.verdict;
    if (v !== 'deny' && v !== 'killed') continue;

    if (verdictFilter && verdictFilter !== 'all' && v !== verdictFilter) continue;

    alertEntries.push(entry);
  }

  // Sort oldest first for clustering
  alertEntries.sort((a, b) => {
    const ta = a.ts ? new Date(a.ts).getTime() : 0;
    const tb = b.ts ? new Date(b.ts).getTime() : 0;
    return ta - tb;
  });

  // ── Cluster into incidents ─────────────────────────────────────────────────
  type Incident = {
    id:        number;
    firstAt:   string;
    lastAt:    string;
    count:     number;
    denied:    number;
    killed:    number;
    tools:     string[];
    reasons:   string[];
  };

  const incidents: Incident[] = [];
  let   incidentId = 0;
  let   lastAlertTs = 0;
  let   current: AuditEntry[] = [];

  function flushIncident(): void {
    if (current.length === 0) return;
    const denied  = current.filter(e => e.verdict === 'deny').length;
    const killed  = current.filter(e => e.verdict === 'killed').length;
    const tools   = [...new Set(current.map(e => e.tool ?? '(unknown)'))].sort();
    const reasons = [...new Set(current.map(e => e.reason).filter((r): r is string => Boolean(r)))];
    incidents.push({
      id:      ++incidentId,
      firstAt: current[0]!.ts ?? '',
      lastAt:  current[current.length - 1]!.ts ?? '',
      count:   current.length,
      denied, killed, tools, reasons,
    });
    current = [];
  }

  for (const entry of alertEntries) {
    const ts = entry.ts ? new Date(entry.ts).getTime() : 0;
    if (lastAlertTs > 0 && ts - lastAlertTs > burstMs) {
      flushIncident();
    }
    current.push(entry);
    lastAlertTs = ts;
  }
  flushIncident();

  let display = [...incidents];
  if (newestFirst) display.reverse();
  display = display.slice(0, limit);

  if (jsonOutput) {
    console.log(JSON.stringify({
      since:          sinceDate?.toISOString(),
      verdictFilter:  verdictFilter ?? 'all',
      burstSecs,
      totalIncidents: incidents.length,
      incidents:      display,
    }, null, 2));
    return;
  }

  // ── Text output ─────────────────────────────────────────────────────────────
  console.log(`\n${pc.bold('warden alert-history')} — ${display.length} of ${incidents.length} incidents`);
  if (sinceDate) console.log(pc.dim(`  Since ${sinceDate.toISOString()}`));
  console.log();

  if (display.length === 0) {
    console.log(pc.dim('  No deny or kill events in this window. ✓'));
    console.log();
    return;
  }

  for (const inc of display) {
    const killBadge  = inc.killed > 0 ? pc.red(` [KILL×${inc.killed}]`) : '';
    const denyBadge  = inc.denied > 0 ? pc.yellow(` [DENY×${inc.denied}]`) : '';
    const timeStr    = inc.firstAt.slice(0, 19).replace('T', ' ');
    const burst      = inc.count > 1 ? pc.dim(` (${inc.count} events)`) : '';
    console.log(`  ${pc.bold(timeStr)}${killBadge}${denyBadge}${burst}`);
    console.log(`    tools:  ${inc.tools.join(', ')}`);
    if (inc.reasons.length > 0) {
      console.log(`    reason: ${inc.reasons.join('; ')}`);
    }
    console.log();
  }
}

// ─── Command: token-estimate ──────────────────────────────────────────────────

async function cmdTokenEstimate(flags: string[]): Promise<void> {
  // Estimates the number of LLM input tokens consumed by tool call arguments
  // (and optionally results) in a time window.
  //
  // Uses a simple character-based heuristic: 1 token ≈ 4 characters of text.
  // This matches OpenAI / Anthropic rule-of-thumb and is accurate within ±15%.
  //
  // Useful for cost attribution:
  //   "How many input tokens did filesystem reads consume this session?"
  //
  // Flags:
  //   --since/-s <expr>    Start of window (default: last 24h)
  //   --window/-w <h>      Window in hours (overrides --since)
  //   --tool/-t <glob>     Filter to matching tools
  //   --json/-j            Machine-readable output
  //   --chars-per-token N  Override chars-per-token ratio (default: 4)

  let sinceDate: Date | undefined;
  let toolFilter: string | undefined;
  let jsonOutput     = false;
  let charsPerToken  = 4;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate      = parseSince(flags[++i]!);
    } else if ((f === '--window' || f === '-w') && flags[i + 1]) {
      sinceDate      = new Date(Date.now() - parseFloat(flags[++i]!) * 3_600_000);
    } else if ((f === '--tool' || f === '-t') && flags[i + 1]) {
      toolFilter     = flags[++i];
    } else if (f === '--json' || f === '-j') {
      jsonOutput     = true;
    } else if (f === '--chars-per-token' && flags[i + 1]) {
      charsPerToken  = parseFloat(flags[++i]!) || 4;
    }
  }

  if (!sinceDate) sinceDate = new Date(Date.now() - 24 * 3_600_000);

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Read log ────────────────────────────────────────────────────────────────
  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  let   totalCalls   = 0;
  let   totalChars   = 0;
  const toolChars: Record<string, { calls: number; chars: number }> = {};

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

    if (entry.ts && new Date(entry.ts) < sinceDate) continue;

    const tool = entry.tool ?? '(unknown)';
    if (toolFilter) {
      const pattern = toolFilter.replace(/\*/g, '.*').replace(/\?/g, '.');
      if (!new RegExp(`^${pattern}$`, 'i').test(tool)) continue;
    }

    // Count chars in args (and result if present)
    const argsStr   = entry.args  != null ? JSON.stringify(entry.args)  : '';
    const chars     = argsStr.length;

    totalCalls++;
    totalChars += chars;

    if (!toolChars[tool]) toolChars[tool] = { calls: 0, chars: 0 };
    toolChars[tool]!.calls++;
    toolChars[tool]!.chars += chars;
  }

  const totalTokens = Math.round(totalChars / charsPerToken);

  const topTools = Object.entries(toolChars)
    .sort((a, b) => b[1].chars - a[1].chars)
    .slice(0, 10)
    .map(([tool, { calls, chars }]) => ({
      tool,
      calls,
      chars,
      tokens:  Math.round(chars / charsPerToken),
      pctOfTotal: totalChars > 0 ? Math.round(chars / totalChars * 100) : 0,
      avgTokensPerCall: calls > 0 ? Math.round(chars / charsPerToken / calls) : 0,
    }));

  if (jsonOutput) {
    console.log(JSON.stringify({
      since:        sinceDate.toISOString(),
      charsPerToken,
      totalCalls,
      totalChars,
      totalTokens,
      topTools,
    }, null, 2));
    return;
  }

  // ── Text output ─────────────────────────────────────────────────────────────
  function fmtTokens(n: number): string {
    return n >= 1_000_000 ? `${(n / 1_000_000).toFixed(1)}M`
         : n >= 1_000     ? `${(n / 1_000).toFixed(1)}K`
         : String(n);
  }

  console.log(`\n${pc.bold('warden token-estimate')} — arg token usage`);
  console.log(pc.dim(`  Since ${sinceDate.toISOString()} · ratio=1 token per ${charsPerToken} chars`));
  console.log();
  console.log(`  Total calls:  ${pc.bold(String(totalCalls))}`);
  console.log(`  Total chars:  ${totalChars.toLocaleString()}`);
  console.log(`  Est. tokens:  ${pc.bold(pc.cyan(fmtTokens(totalTokens)))}`);
  console.log();

  if (topTools.length > 0) {
    console.log(`  ${pc.bold('Top tools by token consumption:')}`);
    for (const t of topTools) {
      const bar = '█'.repeat(Math.min(20, Math.ceil(t.pctOfTotal / 5)));
      console.log(`    ${pc.dim(bar.padEnd(20))}  ${t.tool.padEnd(30)} ${fmtTokens(t.tokens).padStart(8)} (${t.pctOfTotal}%)`);
    }
    console.log();
  }
}

// ─── Command: latency-percentiles ────────────────────────────────────────────

function computePercentiles(sorted: number[], pcts: number[]): Record<number, number> {
  const result: Record<number, number> = {};
  for (const p of pcts) {
    if (sorted.length === 0) { result[p] = 0; continue; }
    const idx = Math.ceil((p / 100) * sorted.length) - 1;
    result[p] = sorted[Math.max(0, Math.min(idx, sorted.length - 1))]!;
  }
  return result;
}

async function cmdLatencyPercentiles(flags: string[]): Promise<void> {
  // Reports tool call latency percentiles: P50, P75, P90, P95, P99 overall
  // and per-tool. Useful for spotting slow tools or latency regressions.
  //
  // Flags:
  //   --since/-s <expr>    Start of window (default: last 24h)
  //   --window/-w <h>      Window in hours (overrides --since)
  //   --tool/-t <glob>     Filter to matching tools
  //   --top <N>            Top tools to show per-tool breakdown (default 10)
  //   --json/-j            Machine-readable output

  let sinceDate: Date | undefined;
  let toolFilter: string | undefined;
  let topN       = 10;
  let jsonOutput = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate  = parseSince(flags[++i]!);
    } else if ((f === '--window' || f === '-w') && flags[i + 1]) {
      sinceDate  = new Date(Date.now() - parseFloat(flags[++i]!) * 3_600_000);
    } else if ((f === '--tool' || f === '-t') && flags[i + 1]) {
      toolFilter = flags[++i];
    } else if (f === '--top' && flags[i + 1]) {
      topN       = parseInt(flags[++i]!, 10) || 10;
    } else if (f === '--json' || f === '-j') {
      jsonOutput = true;
    }
  }

  if (!sinceDate) sinceDate = new Date(Date.now() - 24 * 3_600_000);

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Read log ────────────────────────────────────────────────────────────────
  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  const allMs: number[] = [];
  const toolMs: Record<string, number[]> = {};

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

    if (entry.ts && new Date(entry.ts) < sinceDate) continue;

    const tool = entry.tool ?? '(unknown)';
    if (toolFilter) {
      const pattern = toolFilter.replace(/\*/g, '.*').replace(/\?/g, '.');
      if (!new RegExp(`^${pattern}$`, 'i').test(tool)) continue;
    }

    if (entry.durationMs == null) continue;
    const d = entry.durationMs;

    allMs.push(d);
    if (!toolMs[tool]) toolMs[tool] = [];
    toolMs[tool]!.push(d);
  }

  allMs.sort((a, b) => a - b);

  const PCTS = [50, 75, 90, 95, 99];
  const overall = computePercentiles(allMs, PCTS);

  const byTool = Object.entries(toolMs)
    .map(([tool, ms]) => {
      const sorted = [...ms].sort((a, b) => a - b);
      return {
        tool,
        calls:  sorted.length,
        avg:    Math.round(sorted.reduce((s, v) => s + v, 0) / sorted.length),
        min:    sorted[0] ?? 0,
        max:    sorted[sorted.length - 1] ?? 0,
        pct:    computePercentiles(sorted, PCTS),
      };
    })
    .sort((a, b) => b.pct[95]! - a.pct[95]!)
    .slice(0, topN);

  if (jsonOutput) {
    console.log(JSON.stringify({
      since:    sinceDate.toISOString(),
      total:    allMs.length,
      overall:  { avg: allMs.length ? Math.round(allMs.reduce((s, v) => s + v, 0) / allMs.length) : 0, ...overall },
      byTool:   byTool.map(t => ({ tool: t.tool, calls: t.calls, avg: t.avg, min: t.min, max: t.max, ...t.pct })),
    }, null, 2));
    return;
  }

  // ── Text output ─────────────────────────────────────────────────────────────
  console.log(`\n${pc.bold('warden latency-percentiles')} — ${allMs.length} calls with timing data`);
  console.log(pc.dim(`  Since ${sinceDate.toISOString()}`));
  console.log();

  function fmtMs(n: number): string { return `${n}ms`; }

  if (allMs.length === 0) {
    console.log(pc.dim('  No timing data in this window.'));
    console.log();
    return;
  }

  const avgAll = Math.round(allMs.reduce((s, v) => s + v, 0) / allMs.length);
  console.log(`  Overall (${allMs.length} calls):`);
  console.log(`    avg=${fmtMs(avgAll)}  p50=${fmtMs(overall[50]!)}  p75=${fmtMs(overall[75]!)}  p90=${fmtMs(overall[90]!)}  p95=${fmtMs(overall[95]!)}  p99=${fmtMs(overall[99]!)}`);
  console.log();

  if (byTool.length > 0) {
    console.log(`  ${pc.bold(`Per-tool breakdown (top ${byTool.length} by P95):`)}`);
    const toolColW = Math.max(10, ...byTool.map(t => t.tool.length)) + 2;
    console.log(pc.dim(`    ${'Tool'.padEnd(toolColW)} calls   avg   P50   P75   P90   P95   P99`));
    for (const t of byTool) {
      const p95colour = t.pct[95]! >= 500 ? pc.red : t.pct[95]! >= 200 ? pc.yellow : pc.green;
      console.log(
        `    ${t.tool.padEnd(toolColW)}` +
        `${String(t.calls).padStart(5)}  ` +
        `${fmtMs(t.avg).padStart(6)}  ` +
        `${fmtMs(t.pct[50]!).padStart(6)}  ` +
        `${fmtMs(t.pct[75]!).padStart(6)}  ` +
        `${fmtMs(t.pct[90]!).padStart(6)}  ` +
        p95colour(`${fmtMs(t.pct[95]!).padStart(6)}`) + `  ` +
        `${fmtMs(t.pct[99]!).padStart(6)}`,
      );
    }
    console.log();
  }
}

// ─── Command: policy-stats ────────────────────────────────────────────────────

async function cmdPolicyStats(flags: string[]): Promise<void> {
  // Analyses the audit log and reports which policy rules fired most often.
  //
  // Reasons recorded in audit entries (via the `reason` field) represent the
  // policy rule that matched. This command aggregates those reason strings,
  // shows how often each fired (allow vs deny), and flags any reasons that
  // appear in the config but never showed up in the log (potentially dead rules).
  //
  // Also reports: uncaught calls (no reason recorded = default action applied).
  //
  // Flags:
  //   --since/-s <expr>    Start of window (default: last 24h)
  //   --config/-c <path>   Load config to cross-reference policy rules
  //   --json/-j            Machine-readable output
  //   --min-hits <N>       Only show rules with >= N hits (default: 1)

  let sinceDate: Date | undefined;
  let configPath: string | undefined;
  let jsonOutput = false;
  let minHits    = 1;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate  = parseSince(flags[++i]!);
    } else if ((f === '--config' || f === '-c') && flags[i + 1]) {
      configPath = flags[++i];
    } else if (f === '--json' || f === '-j') {
      jsonOutput = true;
    } else if (f === '--min-hits' && flags[i + 1]) {
      minHits    = parseInt(flags[++i]!, 10) || 1;
    }
  }

  if (!sinceDate) sinceDate = new Date(Date.now() - 24 * 3_600_000);

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Read log ────────────────────────────────────────────────────────────────
  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  type RuleStat = { reason: string; hits: number; allowed: number; denied: number; killed: number };
  const byReason = new Map<string, RuleStat>();
  let   total         = 0;
  let   uncaught      = 0;

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

    if (entry.ts && new Date(entry.ts) < sinceDate) continue;

    total++;
    const reason = (entry.reason ?? '').trim();

    if (!reason) { uncaught++; continue; }

    if (!byReason.has(reason)) {
      byReason.set(reason, { reason, hits: 0, allowed: 0, denied: 0, killed: 0 });
    }
    const s = byReason.get(reason)!;
    s.hits++;
    if (entry.verdict === 'allow')        s.allowed++;
    else if (entry.verdict === 'deny')    s.denied++;
    else if (entry.verdict === 'killed')  s.killed++;
  }

  // ── Load config policy rules for cross-referencing ─────────────────────────
  let configRules: string[] = [];
  if (configPath) {
    try {
      const cfg   = await loadConfig(configPath);
      const rules = (cfg as unknown as Record<string, unknown>)['policy'] as { rules?: Array<{ reason?: string }> } | undefined;
      configRules = (rules?.rules ?? [])
        .map(r => r.reason ?? '')
        .filter(r => r.length > 0);
    } catch { /* ignore config load errors */ }
  }

  const ruleStats = [...byReason.values()]
    .filter(r => r.hits >= minHits)
    .sort((a, b) => b.hits - a.hits);

  const deadRules = configRules.filter(r => !byReason.has(r));

  if (jsonOutput) {
    console.log(JSON.stringify({
      since:      sinceDate.toISOString(),
      total,
      uncaught,
      uncaughtPct: total > 0 ? Math.round(uncaught / total * 100) : 0,
      rules:      ruleStats,
      deadRules,
    }, null, 2));
    return;
  }

  // ── Text output ─────────────────────────────────────────────────────────────
  console.log(`\n${pc.bold('warden policy-stats')} — rule hit analysis`);
  console.log(pc.dim(`  Since ${sinceDate.toISOString()} · ${total} total calls`));
  console.log();

  if (total === 0) {
    console.log(pc.dim('  No entries in this window.'));
    console.log();
    return;
  }

  const uncaughtPct = Math.round(uncaught / total * 100);
  console.log(`  Default action (no rule matched):  ${uncaught} calls (${uncaughtPct}%)`);
  console.log();

  if (ruleStats.length === 0) {
    console.log(pc.dim('  No named policy rules fired in this window.'));
  } else {
    console.log(`  ${pc.bold('Rules by hit count:')}`);
    for (const r of ruleStats) {
      const denyStr  = r.denied > 0  ? pc.red(` deny=${r.denied}`)   : '';
      const killStr  = r.killed > 0  ? pc.red(` kill=${r.killed}`)   : '';
      const allowStr = r.allowed > 0 ? pc.green(` allow=${r.allowed}`) : '';
      const pct      = Math.round(r.hits / total * 100);
      console.log(`    ${String(r.hits).padStart(5)} (${String(pct).padStart(2)}%)  ${r.reason}${allowStr}${denyStr}${killStr}`);
    }
  }

  if (deadRules.length > 0) {
    console.log();
    console.log(`  ${pc.bold(pc.yellow(`Dead rules (in config but never matched, ${deadRules.length}):`))} `);
    for (const r of deadRules) {
      console.log(`    ${pc.dim('─')} ${r}`);
    }
  }

  console.log();
}

// ─── Command: archive ─────────────────────────────────────────────────────────

async function cmdArchive(flags: string[]): Promise<void> {
  // Compresses audit log entries older than --before into a gzip archive and
  // optionally removes them from the live log, keeping the active log lean.
  //
  // A single-line "archive index" JSONL entry is appended to an index file
  // so `warden stats` can still account for archived history.
  //
  // Flags:
  //   --before/-b <expr>   Archive entries older than this date (default: 7d ago)
  //   --output/-o <path>   Archive file path (default: <logfile>.YYYY-MM-DD.gz)
  //   --dry-run            Show what would be archived without writing
  //   --no-delete          Keep archived entries in the live log (default: delete)
  //   --index <path>       Write archive index entry to this JSONL file

  let beforeDate: Date = new Date(Date.now() - 7 * 24 * 3_600_000);
  let outputPath: string | undefined;
  let dryRun    = false;
  let noDelete  = false;
  let indexPath: string | undefined;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--before' || f === '-b') && flags[i + 1]) {
      beforeDate = parseSince(flags[++i]!) ?? beforeDate;
    } else if ((f === '--output' || f === '-o') && flags[i + 1]) {
      outputPath = flags[++i];
    } else if (f === '--dry-run') {
      dryRun     = true;
    } else if (f === '--no-delete') {
      noDelete   = true;
    } else if (f === '--index' && flags[i + 1]) {
      indexPath  = flags[++i];
    }
  }

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Pass 1: scan, count, and collect entries to archive ────────────────────
  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  const toArchive: string[] = [];
  const toKeep:    string[] = [];
  let   archiveCalls   = 0, keepCalls = 0;
  let   archiveAllowed = 0, archiveDenied = 0, archiveKilled = 0;
  let   firstTs: string | undefined, lastTs: string | undefined;

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { toKeep.push(line); continue; }

    const ts = entry.ts ? new Date(entry.ts) : null;
    if (ts && ts < beforeDate) {
      toArchive.push(line);
      archiveCalls++;
      if (entry.verdict === 'allow')        archiveAllowed++;
      else if (entry.verdict === 'deny')    archiveDenied++;
      else if (entry.verdict === 'killed')  archiveKilled++;
      if (!firstTs || entry.ts! < firstTs) firstTs = entry.ts!;
      if (!lastTs  || entry.ts! > lastTs)  lastTs  = entry.ts!;
    } else {
      toKeep.push(line);
      keepCalls++;
    }
  }

  if (toArchive.length === 0) {
    console.log(pc.dim(`No entries older than ${beforeDate.toISOString()} to archive.`));
    return;
  }

  const dateStr    = beforeDate.toISOString().slice(0, 10);
  const archiveFile = outputPath ?? `${logFile}.${dateStr}.gz`;

  if (dryRun) {
    console.log(`${pc.bold('[dry-run]')} Would archive ${archiveCalls} entries to ${archiveFile}`);
    console.log(`  First: ${firstTs ?? 'n/a'}  Last: ${lastTs ?? 'n/a'}`);
    console.log(`  Live log would retain ${keepCalls} entries`);
    return;
  }

  // ── Write gzip archive ─────────────────────────────────────────────────────
  await new Promise<void>((resolve, reject) => {
    const gzip = zlib.createGzip({ level: 9 });
    const out  = fs.createWriteStream(archiveFile);
    gzip.pipe(out);
    for (const line of toArchive) gzip.write(line + '\n');
    gzip.end();
    out.on('finish', resolve);
    out.on('error', reject);
  });

  // ── Rewrite live log without archived entries ──────────────────────────────
  if (!noDelete) {
    const tmp = logFile + '.tmp';
    fs.writeFileSync(tmp, toKeep.join('\n') + (toKeep.length > 0 ? '\n' : ''), 'utf8');
    fs.renameSync(tmp, logFile);
  }

  // ── Write index entry ──────────────────────────────────────────────────────
  if (indexPath) {
    const indexEntry = JSON.stringify({
      ts:       new Date().toISOString(),
      archive:  archiveFile,
      firstTs, lastTs,
      calls:    archiveCalls,
      allowed:  archiveAllowed,
      denied:   archiveDenied,
      killed:   archiveKilled,
    });
    fs.appendFileSync(indexPath, indexEntry + '\n', 'utf8');
  }

  const archiveSizeKb = (fs.statSync(archiveFile).size / 1024).toFixed(1);
  console.log(`${pc.green('✓')} Archived ${pc.bold(String(archiveCalls))} entries to ${pc.bold(archiveFile)} (${archiveSizeKb} KB)`);
  if (!noDelete) {
    console.log(`  Live log trimmed to ${keepCalls} entries.`);
  }
  if (indexPath) {
    console.log(`  Index appended to ${indexPath}`);
  }
}

// ─── Command: redact-scan ─────────────────────────────────────────────────────

interface RedactFinding {
  lineNo:   number;
  ts:       string;
  tool:     string;
  field:    string;
  match:    string;   // first 60 chars of matched value
  category: string;
}

const REDACT_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: 'AWS Access Key',      pattern: /AKIA[0-9A-Z]{16}/g },
  { name: 'AWS Secret Key',      pattern: /(?<![A-Z0-9])[A-Za-z0-9+/]{40}(?![A-Za-z0-9+/])/g },
  { name: 'GitHub Token',        pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}/g },
  { name: 'Bearer Token',        pattern: /Bearer\s+[A-Za-z0-9._\-]{20,}/g },
  { name: 'Private Key Header',  pattern: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY/g },
  { name: 'JWT',                 pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { name: 'Password in URL',     pattern: /:[^:@\s]{6,}@(?:[a-z0-9.-]+\.[a-z]{2,})/gi },
  { name: 'Slack Token',         pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/g },
];

async function cmdRedactScan(flags: string[]): Promise<void> {
  // Scans the live audit log for potential secrets that may have slipped through
  // the scrubber. Produces a list of suspicious matches with line numbers.
  //
  // This is a post-hoc audit; it does NOT modify the log. It reports findings
  // so the user can rotate the affected credentials and improve scrubber config.
  //
  // Flags:
  //   --since/-s <expr>   Start of window (default: all)
  //   --limit <N>         Max findings to report (default: 100)
  //   --json/-j           Machine-readable output
  //   --exit-code         Exit 1 if any findings are found (for CI use)

  let sinceDate: Date | undefined;
  let limit      = 100;
  let jsonOutput = false;
  let exitOnFind = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate  = parseSince(flags[++i]!);
    } else if (f === '--limit' && flags[i + 1]) {
      limit      = parseInt(flags[++i]!, 10) || 100;
    } else if (f === '--json' || f === '-j') {
      jsonOutput = true;
    } else if (f === '--exit-code') {
      exitOnFind = true;
    }
  }

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Scan log ───────────────────────────────────────────────────────────────
  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  const findings: RedactFinding[] = [];
  let lineNo = 0;

  for await (const line of rl) {
    lineNo++;
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

    if (sinceDate && entry.ts && new Date(entry.ts) < sinceDate) continue;
    if (findings.length >= limit) break;

    // Scan all string fields
    const payload = JSON.stringify({ args: entry.args, reason: entry.reason });
    for (const { name, pattern } of REDACT_PATTERNS) {
      pattern.lastIndex = 0;
      const m = pattern.exec(payload);
      if (m) {
        findings.push({
          lineNo,
          ts:       entry.ts ?? '',
          tool:     entry.tool ?? '(unknown)',
          field:    'args',
          match:    m[0].slice(0, 60),
          category: name,
        });
      }
    }
  }

  if (jsonOutput) {
    console.log(JSON.stringify({ logFile, total: findings.length, findings }, null, 2));
    if (exitOnFind && findings.length > 0) process.exit(1);
    return;
  }

  // ── Text output ─────────────────────────────────────────────────────────────
  console.log(`\n${pc.bold('warden redact-scan')} — secret leak detector`);
  console.log(pc.dim(`  Log: ${logFile}`));
  console.log();

  if (findings.length === 0) {
    console.log(`${pc.green('✓')} No potential secrets found.`);
    console.log();
    return;
  }

  console.log(pc.red(`⚠ ${findings.length} potential secret(s) found:`));
  console.log();
  for (const f of findings) {
    console.log(`  Line ${f.lineNo}  ${pc.bold(f.category)}`);
    console.log(`    Tool:  ${f.tool}`);
    console.log(`    Time:  ${f.ts}`);
    console.log(`    Match: ${pc.dim(f.match.length < f.match.length ? f.match + '…' : f.match)}`);
    console.log();
  }
  console.log(pc.dim('  Rotate the affected credentials and check your scrubber config.'));
  console.log();

  if (exitOnFind) process.exit(1);
}

// ─── Command: verify-integrity ────────────────────────────────────────────────

async function cmdVerifyIntegrity(flags: string[]): Promise<void> {
  // Checks the audit log for signs of tampering or corruption:
  //
  //   1. Valid JSON — every line must parse successfully
  //   2. Required fields — each entry must have `ts`, `tool`, `verdict`
  //   3. Timestamp monotonicity — ts values must not go backwards
  //   4. No duplicate timestamps — exact same ts twice in a row is suspicious
  //
  // Exits 1 if any violations are found (with --strict-exit) or reports them
  // and exits 0 (for informational scans).
  //
  // Flags:
  //   --since/-s <expr>   Start of window (default: all)
  //   --json/-j           Machine-readable output
  //   --strict-exit       Exit 1 if any violations found (CI use)

  let sinceDate: Date | undefined;
  let jsonOutput   = false;
  let strictExit   = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate  = parseSince(flags[++i]!);
    } else if (f === '--json' || f === '-j') {
      jsonOutput = true;
    } else if (f === '--strict-exit') {
      strictExit = true;
    }
  }

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Scan ───────────────────────────────────────────────────────────────────
  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  type Violation = { lineNo: number; type: string; detail: string };
  const violations: Violation[] = [];

  let lineNo    = 0;
  let lastTsMs  = 0;
  let total     = 0;
  let skipped   = 0;

  for await (const line of rl) {
    lineNo++;
    if (!line.trim()) continue;

    // Check 1: valid JSON
    let entry: AuditEntry;
    try {
      entry = JSON.parse(line) as AuditEntry;
    } catch (e) {
      violations.push({ lineNo, type: 'invalid-json', detail: String(e) });
      continue;
    }

    if (sinceDate && entry.ts && new Date(entry.ts) < sinceDate) { skipped++; continue; }
    total++;

    // Check 2: required fields
    if (!entry.ts) {
      violations.push({ lineNo, type: 'missing-ts', detail: 'Entry has no ts field' });
    }
    if (!entry.tool) {
      violations.push({ lineNo, type: 'missing-tool', detail: 'Entry has no tool field' });
    }
    if (!entry.verdict) {
      violations.push({ lineNo, type: 'missing-verdict', detail: 'Entry has no verdict field' });
    }

    // Check 3 + 4: timestamp monotonicity and duplicates
    if (entry.ts) {
      let tsMs: number;
      try { tsMs = new Date(entry.ts).getTime(); } catch { tsMs = NaN; }

      if (isNaN(tsMs)) {
        violations.push({ lineNo, type: 'invalid-ts', detail: `Cannot parse ts: ${entry.ts}` });
      } else if (lastTsMs > 0 && tsMs < lastTsMs) {
        violations.push({ lineNo, type: 'ts-regression', detail: `Timestamp goes backward: ${entry.ts}` });
      } else if (lastTsMs > 0 && tsMs === lastTsMs) {
        violations.push({ lineNo, type: 'ts-duplicate', detail: `Duplicate timestamp: ${entry.ts}` });
      }
      if (!isNaN(tsMs)) lastTsMs = tsMs;
    }
  }

  const passed = violations.length === 0;

  if (jsonOutput) {
    console.log(JSON.stringify({ logFile, total, skipped, passed, violations }, null, 2));
    if (strictExit && !passed) process.exit(1);
    return;
  }

  // ── Text output ─────────────────────────────────────────────────────────────
  console.log(`\n${pc.bold('warden verify-integrity')} — audit log integrity check`);
  console.log(pc.dim(`  Log: ${logFile} · ${total} entries checked`));
  console.log();

  if (passed) {
    console.log(`${pc.green('✓')} Log integrity OK — no violations found.`);
    console.log();
    return;
  }

  console.log(pc.red(`✗ ${violations.length} violation(s) found:`));
  console.log();
  for (const v of violations) {
    console.log(`  Line ${v.lineNo}  ${pc.bold(pc.red(v.type))}`);
    console.log(`    ${v.detail}`);
    console.log();
  }

  if (strictExit) process.exit(1);
}

// ─── Command: chain ───────────────────────────────────────────────────────────

async function cmdChain(flags: string[]): Promise<void> {
  // Finds the most common N-step tool call chains (sequences) in the audit log.
  // Deeper than `profile`'s top-pairs: supports chains of length 2, 3, or 4.
  //
  // Algorithm: sliding window of size --length over the chronologically-sorted
  // entries. Each window produces one chain key "A → B → C".
  //
  // Flags:
  //   --since/-s <expr>    Start of window (default: last 24h)
  //   --length/-l <N>      Chain length (2-4, default: 3)
  //   --top <N>            Top chains to show (default: 10)
  //   --min-count <N>      Only show chains that occur >= N times (default: 2)
  //   --json/-j            Machine-readable output
  //   --gap-mins <G>       Max gap between chain steps in minutes (default: 30)
  //                        A gap larger than this breaks the chain.

  let sinceDate: Date | undefined;
  let chainLen   = 3;
  let topN       = 10;
  let minCount   = 2;
  let gapMins    = 30;
  let jsonOutput = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate = parseSince(flags[++i]!);
    } else if ((f === '--length' || f === '-l') && flags[i + 1]) {
      chainLen  = Math.min(4, Math.max(2, parseInt(flags[++i]!, 10) || 3));
    } else if (f === '--top' && flags[i + 1]) {
      topN      = parseInt(flags[++i]!, 10) || 10;
    } else if (f === '--min-count' && flags[i + 1]) {
      minCount  = parseInt(flags[++i]!, 10) || 2;
    } else if (f === '--gap-mins' && flags[i + 1]) {
      gapMins   = parseInt(flags[++i]!, 10) || 30;
    } else if (f === '--json' || f === '-j') {
      jsonOutput = true;
    }
  }

  if (!sinceDate) sinceDate = new Date(Date.now() - 24 * 3_600_000);
  const gapMs = gapMins * 60_000;

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Read and sort entries ──────────────────────────────────────────────────
  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  const entries: Array<{ tool: string; tsMs: number }> = [];

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }
    if (!entry.ts) continue;
    const tsMs = new Date(entry.ts).getTime();
    if (tsMs < sinceDate.getTime()) continue;
    entries.push({ tool: entry.tool ?? '(unknown)', tsMs });
  }

  entries.sort((a, b) => a.tsMs - b.tsMs);

  // ── Build chains using sliding window ─────────────────────────────────────
  const chainCounts = new Map<string, number>();

  for (let i = 0; i <= entries.length - chainLen; i++) {
    const window = entries.slice(i, i + chainLen);

    // Check that no gap between consecutive steps exceeds gapMs
    let valid = true;
    for (let j = 1; j < window.length; j++) {
      if (window[j]!.tsMs - window[j - 1]!.tsMs > gapMs) { valid = false; break; }
    }
    if (!valid) continue;

    const key = window.map(e => e.tool).join(' → ');
    chainCounts.set(key, (chainCounts.get(key) ?? 0) + 1);
  }

  const topChains = [...chainCounts.entries()]
    .filter(([, count]) => count >= minCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, topN)
    .map(([chain, count]) => ({ chain, count }));

  if (jsonOutput) {
    console.log(JSON.stringify({
      since:    sinceDate.toISOString(),
      chainLen,
      gapMins,
      total:    entries.length,
      chains:   topChains,
    }, null, 2));
    return;
  }

  // ── Text output ─────────────────────────────────────────────────────────────
  const maxCount = topChains.length > 0 ? topChains[0]!.count : 1;

  console.log(`\n${pc.bold('warden chain')} — top ${topN} tool call sequences (length ${chainLen})`);
  console.log(pc.dim(`  Since ${sinceDate.toISOString()} · ${entries.length} entries · gap<${gapMins}m`));
  console.log();

  if (topChains.length === 0) {
    console.log(pc.dim(`  No chains with count >= ${minCount} found.`));
    console.log();
    return;
  }

  for (const { chain, count } of topChains) {
    const bar = '█'.repeat(Math.ceil(count / maxCount * 20));
    console.log(`  ${String(count).padStart(5)}  ${pc.dim(bar.padEnd(20))}  ${chain}`);
  }
  console.log();
}

// ─── Command: top-denied ──────────────────────────────────────────────────────

async function cmdTopDenied(flags: string[]): Promise<void> {
  // Ranks tools by denial count and shows the reasons behind each denial.
  // Useful for debugging overly-aggressive policy rules and finding what the
  // agent tries to do but keeps getting blocked on.
  //
  // Output: two ranked tables
  //   1. Tools — by total deny+kill count, with allow rate
  //   2. Reasons — by total deny+kill count, with affected tools
  //
  // Flags:
  //   --since/-s <expr>   Start of window (default: last 24h)
  //   --top <N>           Top entries to show in each table (default: 10)
  //   --min-count <N>     Only show entries with >= N denials (default: 1)
  //   --json/-j           Machine-readable output

  let sinceDate: Date | undefined;
  let topN      = 10;
  let minCount  = 1;
  let jsonOutput = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate  = parseSince(flags[++i]!);
    } else if (f === '--top' && flags[i + 1]) {
      topN       = parseInt(flags[++i]!, 10) || 10;
    } else if (f === '--min-count' && flags[i + 1]) {
      minCount   = parseInt(flags[++i]!, 10) || 1;
    } else if (f === '--json' || f === '-j') {
      jsonOutput = true;
    }
  }

  if (!sinceDate) sinceDate = new Date(Date.now() - 24 * 3_600_000);

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Read entries ──────────────────────────────────────────────────────────
  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  // Per-tool aggregation
  const toolMap = new Map<string, { denied: number; killed: number; allowed: number; reasons: Map<string, number> }>();
  // Per-reason aggregation
  const reasonMap = new Map<string, { denied: number; killed: number; tools: Map<string, number> }>();

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }
    if (!entry.ts || new Date(entry.ts) < sinceDate) continue;

    const tool    = entry.tool ?? '(unknown)';
    const verdict = entry.verdict ?? 'allow';
    const reason  = entry.reason ?? '';

    if (!toolMap.has(tool)) {
      toolMap.set(tool, { denied: 0, killed: 0, allowed: 0, reasons: new Map() });
    }
    const ts = toolMap.get(tool)!;

    if (verdict === 'deny') {
      ts.denied++;
      if (reason) ts.reasons.set(reason, (ts.reasons.get(reason) ?? 0) + 1);
    } else if (verdict === 'killed') {
      ts.killed++;
      if (reason) ts.reasons.set(reason, (ts.reasons.get(reason) ?? 0) + 1);
    } else {
      ts.allowed++;
    }

    if (verdict === 'deny' || verdict === 'killed') {
      const rkey = reason || '(no reason)';
      if (!reasonMap.has(rkey)) reasonMap.set(rkey, { denied: 0, killed: 0, tools: new Map() });
      const rs2 = reasonMap.get(rkey)!;
      if (verdict === 'deny') rs2.denied++;
      else rs2.killed++;
      rs2.tools.set(tool, (rs2.tools.get(tool) ?? 0) + 1);
    }
  }

  // ── Build sorted result arrays ─────────────────────────────────────────────
  const topTools = [...toolMap.entries()]
    .map(([tool, s]) => ({
      tool,
      denied:  s.denied,
      killed:  s.killed,
      total:   s.denied + s.killed,
      allowed: s.allowed,
      denyRate: s.denied + s.killed + s.allowed > 0
        ? Math.round((s.denied + s.killed) / (s.denied + s.killed + s.allowed) * 100)
        : 0,
      reasons: [...s.reasons.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([r, c]) => ({ reason: r, count: c })),
    }))
    .filter(t => t.total >= minCount)
    .sort((a, b) => b.total - a.total)
    .slice(0, topN);

  const topReasons = [...reasonMap.entries()]
    .map(([reason, s]) => ({
      reason,
      denied:  s.denied,
      killed:  s.killed,
      total:   s.denied + s.killed,
      tools:   [...s.tools.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([t, c]) => ({ tool: t, count: c })),
    }))
    .filter(r => r.total >= minCount)
    .sort((a, b) => b.total - a.total)
    .slice(0, topN);

  if (jsonOutput) {
    console.log(JSON.stringify({
      since:     sinceDate.toISOString(),
      topTools,
      topReasons,
    }, null, 2));
    return;
  }

  // ── Text output ─────────────────────────────────────────────────────────────
  console.log(`\n${pc.bold('warden top-denied')} — most-blocked tools and reasons`);
  console.log(pc.dim(`  Since ${sinceDate.toISOString()}`));
  console.log();

  if (topTools.length === 0) {
    console.log(pc.dim(`  No denied or killed calls found.`));
    console.log();
    return;
  }

  console.log(pc.bold('  Top Denied Tools:'));
  console.log();
  const maxTotal = topTools[0]!.total;
  for (const t of topTools) {
    const bar = '█'.repeat(Math.ceil(t.total / maxTotal * 16));
    const topR = t.reasons[0]?.reason ?? '';
    console.log(
      `  ${String(t.total).padStart(5)} ${pc.dim(bar.padEnd(16))} ` +
      `${pc.bold(t.tool)} ${pc.dim(`(${t.denyRate}% blocked)`)}` +
      (topR ? `  → ${pc.yellow(topR)}` : ''),
    );
  }

  console.log();
  console.log(pc.bold('  Top Denial Reasons:'));
  console.log();
  const maxR = topReasons[0]?.total ?? 1;
  for (const r of topReasons) {
    const bar = '█'.repeat(Math.ceil(r.total / maxR * 16));
    const topT = r.tools[0]?.tool ?? '';
    console.log(
      `  ${String(r.total).padStart(5)} ${pc.dim(bar.padEnd(16))} ` +
      `${pc.bold(r.reason)}` +
      (topT ? `  via ${pc.cyan(topT)}` : ''),
    );
  }
  console.log();
}

// ─── Command: heat-map ────────────────────────────────────────────────────────

async function cmdHeatMap(flags: string[]): Promise<void> {
  // Shows a heat map of tool calls per UTC hour across weekdays.
  // Cells use block characters (░▒▓█) to encode density.
  // Useful for spotting anomalous time patterns (2am file deletes, etc.)
  //
  // Flags:
  //   --since/-s <expr>   Only include entries since this date
  //   --tool/-t <glob>    Filter to matching tool names
  //   --json/-j           Machine-readable output (hourly totals per weekday)
  //   --verdict           Colour cells red for deny/killed vs green for allow

  let sinceDate: Date | undefined;
  let toolFilter: string | undefined;
  let jsonOutput  = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate  = parseSince(flags[++i]!);
    } else if ((f === '--tool' || f === '-t') && flags[i + 1]) {
      toolFilter = flags[++i];
    } else if (f === '--json' || f === '-j') {
      jsonOutput = true;
    }
  }

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // Grid: [weekday 0-6][hour 0-23] = { calls, denied }
  // weekday: 0=Sun, 1=Mon, ..., 6=Sat
  const grid: Array<Array<{ calls: number; denied: number }>> = Array.from(
    { length: 7 },
    () => Array.from({ length: 24 }, () => ({ calls: 0, denied: 0 })),
  );

  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  let total = 0;

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

    if (sinceDate && entry.ts && new Date(entry.ts) < sinceDate) continue;

    const tool = entry.tool ?? '(unknown)';
    if (toolFilter) {
      const pattern = toolFilter.replace(/\*/g, '.*').replace(/\?/g, '.');
      if (!new RegExp(`^${pattern}$`, 'i').test(tool)) continue;
    }

    if (!entry.ts) continue;
    const d       = new Date(entry.ts);
    const weekday = d.getUTCDay();   // 0=Sun
    const hour    = d.getUTCHours(); // 0-23

    grid[weekday]![hour]!.calls++;
    if (entry.verdict === 'deny' || entry.verdict === 'killed') {
      grid[weekday]![hour]!.denied++;
    }
    total++;
  }

  if (jsonOutput) {
    const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    console.log(JSON.stringify({
      total,
      rows: grid.map((row, d) => ({
        day:   DAYS[d]!,
        hours: row.map((cell, h) => ({ hour: h, calls: cell.calls, denied: cell.denied })),
      })),
    }, null, 2));
    return;
  }

  // ── ASCII heat map ─────────────────────────────────────────────────────────
  // Find max for normalisation
  const maxCalls = Math.max(1, ...grid.flatMap(row => row.map(c => c.calls)));

  const BLOCKS = [' ', '░', '▒', '▓', '█'];

  function cellChar(c: { calls: number; denied: number }): string {
    if (c.calls === 0) return pc.dim(' ');
    const idx  = Math.ceil((c.calls / maxCalls) * (BLOCKS.length - 1));
    const ch   = BLOCKS[Math.min(idx, BLOCKS.length - 1)]!;
    const frac = c.denied / c.calls;
    return frac >= 0.5
      ? pc.red(ch)
      : frac > 0
        ? pc.yellow(ch)
        : pc.green(ch);
  }

  const DAYS  = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const HOURS = Array.from({ length: 24 }, (_, h) => String(h).padStart(2, '0'));

  console.log(`\n${pc.bold('warden heat-map')} — ${total} calls`);
  console.log(pc.dim('  (green=allow, yellow=mixed, red=deny/killed)'));
  console.log();

  // Hour labels
  const hourLabel = '    ' + HOURS.map((h, i) => (i % 3 === 0 ? h : ' ')).join(' ');
  console.log(pc.dim(hourLabel));

  for (let d = 0; d < 7; d++) {
    const row = grid[d]!;
    const cells = row.map(c => cellChar(c)).join(' ');
    console.log(`  ${pc.bold(DAYS[d]!.padEnd(3))} ${cells}`);
  }

  console.log();
  const busiest = grid.flatMap((row, d) =>
    row.map((c, h) => ({ d, h, calls: c.calls })),
  ).sort((a, b) => b.calls - a.calls)[0];

  if (busiest && busiest.calls > 0) {
    console.log(pc.dim(`  Busiest slot: ${DAYS[busiest.d]!} ${String(busiest.h).padStart(2, '0')}:00 UTC (${busiest.calls} calls)`));
  }
  console.log();
}

// ─── Command: summary ─────────────────────────────────────────────────────────

async function cmdSummary(flags: string[]): Promise<void> {
  // Generates a plain-English security summary of agent activity.
  // Designed to be readable by non-technical stakeholders (team leads, security teams).
  //
  // Output includes:
  //   - Executive paragraph: what happened, how risky
  //   - Key metrics table
  //   - Notable events (denies, kills, dangerous tools)
  //   - Risk assessment: CLEAN / LOW / MEDIUM / HIGH / CRITICAL
  //
  // Flags:
  //   --since/-s <expr>   Only summarise entries since this date (default: last 24h)
  //   --title/-t <str>    Custom title for the report
  //   --output/-o <file>  Save report to file (default: stdout only)
  //   --json/-j           Machine-readable output (structured data)

  let sinceDate: Date  = new Date(Date.now() - 24 * 3_600_000); // last 24h
  let title:     string = 'Agent Security Summary';
  let outputPath: string | undefined;
  let jsonOutput = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate = parseSince(flags[++i]!)!;
    } else if ((f === '--title' || f === '-t') && flags[i + 1]) {
      title = flags[++i]!;
    } else if ((f === '--output' || f === '-o') && flags[i + 1]) {
      outputPath = flags[++i];
    } else if (f === '--json' || f === '-j') {
      jsonOutput = true;
    }
  }

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Aggregate ──────────────────────────────────────────────────────────────
  const DANGEROUS = /delete|remove|bash|shell|exec|sudo|kill|rm|drop|truncate|format/i;

  let total          = 0;
  let allowed        = 0;
  let denied         = 0;
  let killed         = 0;
  let dangerousCalls = 0;
  let firstTs:       string | undefined;
  let lastTs:        string | undefined;
  const toolCounts:  Record<string, number> = {};
  const deniedTools: Set<string>   = new Set();
  const killedTools: Set<string>   = new Set();
  const dangerousOnes: Set<string> = new Set();
  const durations:   number[] = [];

  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

    if (entry.ts && new Date(entry.ts) < sinceDate) continue;

    total++;
    if (entry.verdict === 'allow')  allowed++;
    if (entry.verdict === 'deny')   denied++;
    if (entry.verdict === 'killed') killed++;

    const tool = entry.tool ?? '(unknown)';
    toolCounts[tool] = (toolCounts[tool] ?? 0) + 1;

    if (entry.verdict === 'deny')   deniedTools.add(tool);
    if (entry.verdict === 'killed') killedTools.add(tool);
    if (DANGEROUS.test(tool)) { dangerousCalls++; dangerousOnes.add(tool); }

    if (!firstTs || (entry.ts && entry.ts < firstTs)) firstTs = entry.ts;
    if (!lastTs  || (entry.ts && entry.ts > lastTs))  lastTs   = entry.ts;
    if (typeof entry.durationMs === 'number') durations.push(entry.durationMs);
  }

  const denyRate   = total > 0 ? parseFloat((denied / total * 100).toFixed(1)) : 0;
  const killRate   = total > 0 ? parseFloat((killed / total * 100).toFixed(1)) : 0;
  const avgMs      = durations.length > 0
    ? Math.round(durations.reduce((a, b) => a + b, 0) / durations.length)
    : null;
  const uniqueTools = Object.keys(toolCounts).length;
  const topTool    = Object.entries(toolCounts).sort((a, b) => b[1] - a[1])[0];

  // ── Risk grade ─────────────────────────────────────────────────────────────
  const riskScore = Math.min(100, Math.round(
    denyRate * 0.40 +
    Math.min(100, dangerousCalls / Math.max(total, 1) * 100 * 1.5) * 0.30 +
    (killed > 0 ? 40 : 0) * 0.30,
  ));
  const grade =
    riskScore >= 80 ? 'CRITICAL' :
    riskScore >= 60 ? 'HIGH'     :
    riskScore >= 40 ? 'MEDIUM'   :
    riskScore >= 20 ? 'LOW'      :
                      'CLEAN';

  // ── Generate executive paragraph ───────────────────────────────────────────
  const periodStr = firstTs && lastTs
    ? `from ${firstTs.slice(0, 16).replace('T', ' ')} to ${lastTs.slice(0, 16).replace('T', ' ')} UTC`
    : 'in the specified period';

  let execPara: string;
  if (total === 0) {
    execPara = 'No agent activity was recorded in the specified time window.';
  } else if (grade === 'CLEAN') {
    execPara = `The agent operated normally ${periodStr}, making ${total} tool call${total > 1 ? 's' : ''} with no security concerns. All requests were approved and no unusual patterns were detected.`;
  } else if (grade === 'LOW') {
    execPara = `The agent was generally well-behaved ${periodStr} with ${total} tool calls. A small number of requests (${denied} denied, ${killRate}% killed) were blocked, which is within acceptable limits.`;
  } else if (grade === 'MEDIUM') {
    execPara = `The agent showed moderate security signals ${periodStr}. Out of ${total} tool calls, ${denied} were denied (${denyRate}% deny rate)${killedTools.size > 0 ? ` and the kill switch was activated for ${killedTools.size} tool(s)` : ''}. Security review is recommended.`;
  } else if (grade === 'HIGH') {
    execPara = `The agent raised significant security concerns ${periodStr}. ${denyRate}% of ${total} tool calls were blocked${dangerousOnes.size > 0 ? `, including calls to ${dangerousOnes.size} potentially dangerous tool(s)` : ''}. Immediate review is recommended.`;
  } else {
    execPara = `CRITICAL: The agent exhibited highly anomalous behaviour ${periodStr}. ${denyRate}% deny rate, ${killed} kill-switch event(s), and ${dangerousCalls} dangerous tool call(s) detected. Escalation required.`;
  }

  // ── Notable events ─────────────────────────────────────────────────────────
  const notableEvents: string[] = [];
  if (deniedTools.size > 0) {
    notableEvents.push(`Tools denied: ${[...deniedTools].slice(0, 5).join(', ')}${deniedTools.size > 5 ? ` and ${deniedTools.size - 5} more` : ''}`);
  }
  if (killedTools.size > 0) {
    notableEvents.push(`Kill switch triggered for: ${[...killedTools].slice(0, 3).join(', ')}`);
  }
  if (dangerousOnes.size > 0) {
    notableEvents.push(`Dangerous tools called: ${[...dangerousOnes].slice(0, 3).join(', ')}`);
  }
  if (topTool && topTool[1] > total * 0.5) {
    notableEvents.push(`Dominant tool: ${topTool[0]} (${topTool[1]}/${total} calls = ${(topTool[1]/total*100).toFixed(0)}%)`);
  }

  // ── Output ─────────────────────────────────────────────────────────────────
  const data = {
    title,
    generatedAt: new Date().toISOString(),
    period: { since: sinceDate.toISOString(), first: firstTs ?? null, last: lastTs ?? null },
    grade,
    riskScore,
    metrics: {
      total, allowed, denied, killed,
      denyRate, killRate,
      uniqueTools,
      dangerousCalls,
      avgMs,
      topTool: topTool ? { tool: topTool[0], calls: topTool[1] } : null,
    },
    executiveSummary: execPara,
    notableEvents,
  };

  if (jsonOutput) {
    const out = JSON.stringify(data, null, 2);
    console.log(out);
    if (outputPath) fs.writeFileSync(outputPath, out + '\n', 'utf8');
    return;
  }

  // Plain-text report
  const sep = '─'.repeat(60);
  const lines: string[] = [
    `\n${pc.bold(title)}`,
    pc.dim(`Generated: ${new Date().toLocaleString()}`),
    pc.dim(`Period   : ${sinceDate.toLocaleString()} →`),
    '',
    pc.dim(sep),
    '',
    execPara,
    '',
    pc.dim(sep),
    '',
    pc.bold('Key Metrics:'),
    `  Total calls   : ${total}`,
    `  Allowed       : ${allowed}  (${total > 0 ? (100 - denyRate - killRate).toFixed(1) : '0'}%)`,
    `  Denied        : ${denied}   (${denyRate}%)`,
    `  Kill-switch   : ${killed}   (${killRate}%)`,
    `  Unique tools  : ${uniqueTools}`,
    ...(avgMs != null ? [`  Avg latency   : ${avgMs}ms`] : []),
    '',
  ];

  if (notableEvents.length > 0) {
    lines.push(pc.bold('Notable Events:'));
    for (const e of notableEvents) lines.push(`  • ${e}`);
    lines.push('');
  }

  const gradeColor =
    grade === 'CRITICAL' ? pc.bgRed(pc.white(` ${grade} `)) :
    grade === 'HIGH'     ? pc.red(`[${grade}]`)    :
    grade === 'MEDIUM'   ? pc.yellow(`[${grade}]`) :
    grade === 'LOW'      ? pc.blue(`[${grade}]`)   :
                           pc.green(`[${grade}]`);

  lines.push(`${pc.bold('Risk Assessment:')} ${gradeColor}`);
  lines.push('');

  const report = lines.join('\n');
  console.log(report);

  if (outputPath) {
    const plainReport = report.replace(/\x1b\[[0-9;]*m/g, '');
    fs.writeFileSync(outputPath, plainReport + '\n', 'utf8');
    console.log(pc.dim(`Report saved → ${outputPath}`));
  }
}

// ─── Command: profile ─────────────────────────────────────────────────────────

async function cmdProfile(flags: string[]): Promise<void> {
  // Shows a compact behavioural profile of agent activity:
  //   - top tools by call frequency and average latency
  //   - tool diversity (Shannon entropy)
  //   - common call pairs (A immediately followed by B)
  //   - busiest hour of day
  //
  // Flags:
  //   --since/-s <expr>   Only include entries since this date
  //   --top N             Show top N tools (default 15)
  //   --json/-j           Machine-readable output

  let sinceDate:  Date | undefined;
  let topN     = 15;
  let jsonOutput = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate = parseSince(flags[++i]!);
    } else if (f === '--top' && flags[i + 1]) {
      topN = parseInt(flags[++i]!, 10);
    } else if (f === '--json' || f === '-j') {
      jsonOutput = true;
    }
  }

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Aggregate ──────────────────────────────────────────────────────────────
  const toolStats:    Record<string, { calls: number; totalMs: number; denied: number }> = {};
  const hourCounts:   number[] = Array.from({ length: 24 }, () => 0);
  const callPairs:    Record<string, number> = {};
  const allTools:     string[] = [];  // in order (for pair computation)
  let lastTool:       string | null = null;
  let total           = 0;

  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

    if (sinceDate && entry.ts && new Date(entry.ts) < sinceDate) continue;

    const tool = entry.tool ?? '(unknown)';
    total++;

    if (!toolStats[tool]) toolStats[tool] = { calls: 0, totalMs: 0, denied: 0 };
    toolStats[tool]!.calls++;
    if (typeof entry.durationMs === 'number') toolStats[tool]!.totalMs += entry.durationMs;
    if (entry.verdict === 'deny' || entry.verdict === 'killed') toolStats[tool]!.denied++;

    if (entry.ts) {
      const hour = new Date(entry.ts).getUTCHours();
      hourCounts[hour]++;
    }

    if (lastTool) {
      const pair = `${lastTool} → ${tool}`;
      callPairs[pair] = (callPairs[pair] ?? 0) + 1;
    }
    lastTool = tool;
    allTools.push(tool);
  }

  // ── Computed metrics ───────────────────────────────────────────────────────
  const topTools = Object.entries(toolStats)
    .map(([tool, s]) => ({
      tool,
      calls:   s.calls,
      pct:     total > 0 ? parseFloat((s.calls / total * 100).toFixed(1)) : 0,
      avgMs:   s.calls > 0 ? Math.round(s.totalMs / s.calls) : 0,
      denied:  s.denied,
    }))
    .sort((a, b) => b.calls - a.calls)
    .slice(0, topN);

  // Shannon entropy (tool diversity): H = -sum(p * log2(p))
  let entropy = 0;
  for (const s of Object.values(toolStats)) {
    const p = s.calls / Math.max(total, 1);
    if (p > 0) entropy -= p * Math.log2(p);
  }
  entropy = parseFloat(entropy.toFixed(3));

  const topPairs = Object.entries(callPairs)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([pair, count]) => ({ pair, count }));

  const busiestHour = hourCounts.indexOf(Math.max(...hourCounts));
  const uniqueTools = Object.keys(toolStats).length;

  // ── Output ─────────────────────────────────────────────────────────────────
  if (jsonOutput) {
    console.log(JSON.stringify({
      total,
      uniqueTools,
      entropy,
      busiestHour,
      topTools,
      topPairs,
    }, null, 2));
    return;
  }

  console.log(`\n${pc.bold('warden profile')}\n`);
  console.log(`  Total calls   : ${total}`);
  console.log(`  Unique tools  : ${uniqueTools}`);
  console.log(`  Entropy       : ${entropy}  ${pc.dim('(higher = more diverse)')}`);
  console.log(`  Busiest hour  : ${String(busiestHour).padStart(2, '0')}:00 UTC`);
  console.log();

  if (topTools.length > 0) {
    console.log(pc.bold('  Top tools:'));
    console.log(pc.dim(`  ${'Tool'.padEnd(35)} ${'Calls'.padEnd(8)} ${'%'.padEnd(7)} ${'AvgMs'.padEnd(8)} Denied`));
    for (const t of topTools) {
      const bar  = '█'.repeat(Math.min(Math.round(t.pct / 5), 20));
      const dStr = t.denied > 0 ? pc.red(String(t.denied)) : pc.dim('0');
      console.log(`  ${t.tool.padEnd(35)} ${String(t.calls).padEnd(8)} ${String(t.pct).padEnd(7)} ${String(t.avgMs + 'ms').padEnd(8)} ${dStr}  ${pc.dim(bar)}`);
    }
    console.log();
  }

  if (topPairs.length > 0) {
    console.log(pc.bold('  Common call pairs:'));
    for (const p of topPairs) {
      console.log(`  ${pc.dim('×' + p.count)} ${p.pair}`);
    }
    console.log();
  }
}

// ─── Command: ci-check ────────────────────────────────────────────────────────

async function cmdCiCheck(flags: string[]): Promise<void> {
  // Runs a battery of CI safety checks against the audit log and exits 1
  // if ANY check fails. Designed for use in GitHub Actions / CI pipelines.
  //
  // Checks run:
  //   1. Audit log exists and is non-empty
  //   2. Deny rate in window is below threshold (default 50%)
  //   3. No dangerous tool calls (delete/bash/exec/sudo/…)
  //   4. Anomaly score below threshold (default 60)
  //   5. No killed entries (kill switch fired)
  //   6. If --baseline given: warden compare regression check
  //
  // Flags:
  //   --window/-w <hours>        Window to analyse (default 1)
  //   --max-deny-rate N          Max allowed deny rate 0-100 (default 50)
  //   --max-score N              Max allowed anomaly score (default 60)
  //   --allow-dangerous          Skip dangerous-tool check
  //   --allow-killed             Skip kill-switch check
  //   --baseline <snapshot.json> Path to baseline snapshot for regression check
  //   --json/-j                  Machine-readable output

  let windowHours   = 1;
  let maxDenyRate   = 50;
  let maxScore      = 60;
  let allowDangerous = false;
  let allowKilled   = false;
  let baselinePath: string | undefined;
  let jsonOutput    = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--window' || f === '-w') && flags[i + 1]) {
      windowHours = parseFloat(flags[++i]!);
    } else if (f === '--max-deny-rate' && flags[i + 1]) {
      maxDenyRate = parseFloat(flags[++i]!);
    } else if (f === '--max-score' && flags[i + 1]) {
      maxScore = parseInt(flags[++i]!, 10);
    } else if (f === '--allow-dangerous') {
      allowDangerous = true;
    } else if (f === '--allow-killed') {
      allowKilled = true;
    } else if (f === '--baseline' && flags[i + 1]) {
      baselinePath = flags[++i];
    } else if (f === '--json' || f === '-j') {
      jsonOutput = true;
    }
  }

  const DANGEROUS = /delete|remove|bash|shell|exec|sudo|kill|rm|drop|truncate|format/i;
  const logFile   = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;
  const now       = Date.now();
  const cutoff    = now - windowHours * 3_600_000;

  type CheckResult = {
    name:    string;
    passed:  boolean;
    detail:  string;
  };

  const checks: CheckResult[] = [];

  // ── Check 1: Log exists and is non-empty ──────────────────────────────────
  const logExists = fs.existsSync(logFile);
  const logSize   = logExists ? fs.statSync(logFile).size : 0;
  checks.push({
    name:   'audit-log-exists',
    passed: logExists && logSize > 0,
    detail: logExists
      ? logSize > 0 ? `exists (${logSize} bytes)` : 'exists but is empty'
      : `not found: ${logFile}`,
  });

  // Only proceed with log checks if the file exists
  let total          = 0;
  let denied         = 0;
  let killedCount    = 0;
  let dangerousCalls = 0;

  if (logExists && logSize > 0) {
    const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
    const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

    for await (const line of rl) {
      if (!line.trim()) continue;
      let entry: AuditEntry;
      try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

      const ts = entry.ts ? new Date(entry.ts).getTime() : 0;
      if (ts < cutoff) continue;

      total++;
      if (entry.verdict === 'deny')   denied++;
      if (entry.verdict === 'killed') killedCount++;

      const tool = entry.tool ?? '';
      if (DANGEROUS.test(tool)) dangerousCalls++;
    }
  }

  // ── Check 2: Deny rate ────────────────────────────────────────────────────
  const denyRate = total > 0 ? Math.round((denied / total) * 100) : 0;
  checks.push({
    name:   'deny-rate',
    passed: denyRate <= maxDenyRate,
    detail: `deny rate = ${denyRate}%  (max allowed: ${maxDenyRate}%)`,
  });

  // ── Check 3: Dangerous tools ──────────────────────────────────────────────
  if (!allowDangerous) {
    checks.push({
      name:   'no-dangerous-tools',
      passed: dangerousCalls === 0,
      detail: dangerousCalls === 0
        ? 'no dangerous tool calls detected'
        : `${dangerousCalls} dangerous tool call${dangerousCalls > 1 ? 's' : ''} (matches /delete|bash|exec|sudo|…/)`,
    });
  }

  // ── Check 4: Anomaly score ────────────────────────────────────────────────
  // Compute inline (simplified version of cmdAnomalyScore logic)
  const toolCounts: Record<string, number> = {};
  if (logExists && logSize > 0) {
    const rs2 = fs.createReadStream(logFile, { encoding: 'utf8' });
    const rl2 = readline.createInterface({ input: rs2, crlfDelay: Infinity });
    for await (const line of rl2) {
      if (!line.trim()) continue;
      let entry: AuditEntry;
      try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }
      const ts = entry.ts ? new Date(entry.ts).getTime() : 0;
      if (ts < cutoff) continue;
      const tool = entry.tool ?? '(unknown)';
      toolCounts[tool] = (toolCounts[tool] ?? 0) + 1;
    }
  }

  const dangerRate  = total > 0 ? dangerousCalls / total : 0;
  const maxCalls    = total > 0 ? Math.max(...Object.values(toolCounts)) : 0;
  const burstRatio  = total > 0 ? maxCalls / total : 0;
  const anomScore   = Math.min(100, Math.round(
    Math.round((denied / Math.max(total, 1)) * 100) * 0.40 +
    Math.min(100, Math.round(dangerRate * 150))      * 0.30 +
    (burstRatio > 0.5 ? Math.round((burstRatio - 0.5) * 200) : 0) * 0.15,
  ));

  checks.push({
    name:   'anomaly-score',
    passed: anomScore <= maxScore,
    detail: `score = ${anomScore}/100  (max allowed: ${maxScore})`,
  });

  // ── Check 5: No kill-switch events ───────────────────────────────────────
  if (!allowKilled) {
    checks.push({
      name:   'no-kill-switch',
      passed: killedCount === 0,
      detail: killedCount === 0
        ? 'no kill-switch events'
        : `${killedCount} kill-switch event${killedCount > 1 ? 's' : ''} detected`,
    });
  }

  // ── Check 6: Baseline regression (optional) ───────────────────────────────
  if (baselinePath) {
    let passed   = true;
    let detail   = '';
    if (!fs.existsSync(baselinePath)) {
      passed = false;
      detail = `baseline file not found: ${baselinePath}`;
    } else {
      try {
        type SnapTotals = { denyRate: number };
        type Snap = { totals: SnapTotals; topTools: Array<{ tool: string; deny: number; killed: number }> };
        const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8')) as Snap;
        const bDenyRate = baseline.totals.denyRate;
        const delta     = denyRate - bDenyRate;
        const baseBlocked = new Set(
          baseline.topTools.filter(t => t.deny + t.killed > 0).map(t => t.tool),
        );
        const newlyBlocked = Object.keys(toolCounts).filter(t => {
          return !baseBlocked.has(t) && (denied > 0);
        });
        passed = delta <= 5 && newlyBlocked.length === 0;
        detail = passed
          ? `deny rate delta: +${delta}pp — no regression`
          : `regression: deny rate delta +${delta}pp, ${newlyBlocked.length} newly blocked tools`;
      } catch {
        passed = false;
        detail = `failed to parse baseline: ${baselinePath}`;
      }
    }
    checks.push({ name: 'baseline-regression', passed, detail });
  }

  // ── Output ─────────────────────────────────────────────────────────────────
  const allPassed = checks.every(c => c.passed);

  if (jsonOutput) {
    console.log(JSON.stringify({ passed: allPassed, checks }, null, 2));
  } else {
    console.log(`\n${pc.bold('warden ci-check')} — ${windowHours}h window\n`);
    for (const check of checks) {
      const icon = check.passed ? pc.green('✅') : pc.red('❌');
      console.log(`  ${icon}  ${check.name.padEnd(25)} ${pc.dim(check.detail)}`);
    }
    console.log();
    if (allPassed) {
      console.log(pc.green('✅ All CI checks passed'));
    } else {
      const failures = checks.filter(c => !c.passed).map(c => c.name);
      console.log(pc.red(`❌ CI check failed: ${failures.join(', ')}`));
    }
    console.log();
  }

  if (!allPassed) {
    process.exit(1);
  }
}

// ─── Command: replay ──────────────────────────────────────────────────────────

async function cmdReplay(flags: string[]): Promise<void> {
  // Re-evaluates historical audit log entries against a (possibly new) policy.
  // Shows how the CURRENT policy would have treated HISTORICAL calls —
  // useful for validating policy changes before deploying them.
  //
  // Flags:
  //   --config/-c <path>    Policy config to evaluate against
  //   --since/-s <expr>     Only replay entries since this date
  //   --json/-j             Machine-readable diff output
  //   --diff-only           Only show entries where NEW verdict ≠ ORIGINAL verdict
  //   --limit N             Max entries to replay (default 500)

  let configArg: string | undefined;
  let sinceDate: Date | undefined;
  let jsonOutput = false;
  let diffOnly   = false;
  let limit      = 500;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--config' || f === '-c') && flags[i + 1]) {
      configArg = flags[++i];
    } else if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate = parseSince(flags[++i]!);
    } else if (f === '--json' || f === '-j') {
      jsonOutput = true;
    } else if (f === '--diff-only') {
      diffOnly = true;
    } else if (f === '--limit' && flags[i + 1]) {
      limit = parseInt(flags[++i]!, 10);
    }
  }

  // Load config
  const origStderr = process.stderr.write.bind(process.stderr);
  process.stderr.write = () => true;
  let config: ReturnType<typeof loadConfig>;
  try {
    config = loadConfig(configArg);
  } catch (err) {
    process.stderr.write = origStderr;
    console.error(pc.red(`Config error: ${(err as Error).message}`));
    process.exit(1);
    return;
  }
  process.stderr.write = origStderr;

  const { createPolicyEngine } = await import('./policy.js');
  const policyConfig = { ...config.policy, mode: config.mode };
  const engine = createPolicyEngine(policyConfig);

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Replay entries ─────────────────────────────────────────────────────────
  type ReplayResult = {
    ts:              string;
    tool:            string;
    originalVerdict: string;
    newVerdict:      string;
    changed:         boolean;
    reason?:         string;
  };

  const results: ReplayResult[] = [];
  let replayedTotal = 0;
  let changedCount  = 0;

  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  for await (const line of rl) {
    if (replayedTotal >= limit) break;
    if (!line.trim()) continue;

    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

    if (sinceDate && entry.ts && new Date(entry.ts) < sinceDate) continue;

    const tool    = entry.tool ?? '(unknown)';
    const args    = entry.args ?? {};
    const origV   = entry.verdict ?? 'unknown';

    // Re-evaluate with current policy
    process.stderr.write = () => true;
    const decision = engine.evaluate(tool, args);
    process.stderr.write = origStderr;

    const newV =
      config.mode === 'enforce' && decision.action === 'deny' ? 'deny' : 'allow';

    // If original was 'killed' (kill switch), we keep that as-is in the original column
    const changed = origV !== newV && !(origV === 'killed' && newV === 'deny');

    const result: ReplayResult = {
      ts:              entry.ts ?? '',
      tool,
      originalVerdict: origV,
      newVerdict:      newV,
      changed,
      ...(decision.reason ? { reason: decision.reason } : {}),
    };

    replayedTotal++;
    if (changed) changedCount++;

    if (!diffOnly || changed) {
      results.push(result);
    }
  }

  // ── Output ─────────────────────────────────────────────────────────────────
  if (jsonOutput) {
    console.log(JSON.stringify({
      replayedTotal,
      changedCount,
      results,
    }, null, 2));
    return;
  }

  console.log(`\n${pc.bold('warden replay')} — re-evaluating ${replayedTotal} entries against current policy\n`);

  if (changedCount === 0) {
    console.log(pc.green('✅ No verdict changes — current policy matches original behaviour'));
    console.log();
    return;
  }

  console.log(pc.yellow(`⚠️  ${changedCount} verdict change${changedCount > 1 ? 's' : ''} detected:\n`));

  for (const r of results) {
    if (!r.changed && diffOnly) continue;
    const origLabel =
      r.originalVerdict === 'allow'  ? pc.green(r.originalVerdict.padEnd(7))  :
      r.originalVerdict === 'deny'   ? pc.red(r.originalVerdict.padEnd(7))    :
      r.originalVerdict === 'killed' ? pc.bgRed(pc.white('killed '))           :
      pc.dim(r.originalVerdict.padEnd(7));

    const newLabel =
      r.newVerdict === 'allow' ? pc.green(r.newVerdict.padEnd(7)) :
      r.newVerdict === 'deny'  ? pc.red(r.newVerdict.padEnd(7))   :
      pc.dim(r.newVerdict.padEnd(7));

    const arrow = r.changed ? pc.yellow('→') : pc.dim('=');
    const mark  = r.changed ? pc.yellow('!') : ' ';
    console.log(` ${mark} ${pc.dim(r.ts.slice(0, 19))} ${pc.bold(r.tool.padEnd(35))} ${origLabel} ${arrow} ${newLabel}${r.reason ? pc.dim(` (${r.reason})`) : ''}`);
  }

  console.log();
  console.log(pc.dim(`Total replayed: ${replayedTotal}  Changed: ${changedCount}`));
  console.log();
}

// ─── Command: anomaly-score ───────────────────────────────────────────────────

async function cmdAnomalyScore(flags: string[]): Promise<void> {
  // Computes a composite 0–100 risk score from recent audit log behaviour.
  //
  // Score is built from weighted sub-scores:
  //   denyRate        (40%)  — fraction of calls denied or killed
  //   dangerousTool   (30%)  — calls to known-dangerous tool patterns
  //   burstActivity   (15%)  — single tool with >20% of all calls in window
  //   uniqueTools     (15%)  — very high or very low tool diversity (anomalous)
  //
  // Flags:
  //   --window/-w <hours>   Window to analyse in hours (default 1)
  //   --json/-j             Machine-readable output
  //   --threshold N         Exit 1 if score exceeds this value (default disabled)

  const DANGEROUS = /delete|remove|bash|shell|exec|sudo|kill|rm|drop|truncate|format/i;

  let windowHours = 1;
  let jsonOutput  = false;
  let threshold: number | null = null;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--window' || f === '-w') && flags[i + 1]) {
      windowHours = parseFloat(flags[++i]!);
    } else if (f === '--json' || f === '-j') {
      jsonOutput = true;
    } else if (f === '--threshold' && flags[i + 1]) {
      threshold = parseInt(flags[++i]!, 10);
    }
  }

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Aggregate stats in window ──────────────────────────────────────────────
  const now    = Date.now();
  const cutoff = now - windowHours * 3_600_000;

  let total          = 0;
  let denied         = 0;
  let dangerousCalls = 0;
  const toolCounts: Record<string, number> = {};

  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

    const ts = entry.ts ? new Date(entry.ts).getTime() : 0;
    if (ts < cutoff) continue;

    total++;
    if (entry.verdict === 'deny' || entry.verdict === 'killed') denied++;

    const tool = entry.tool ?? '(unknown)';
    if (DANGEROUS.test(tool)) dangerousCalls++;
    toolCounts[tool] = (toolCounts[tool] ?? 0) + 1;
  }

  // ── Sub-scores ─────────────────────────────────────────────────────────────
  // 1. Deny rate score (0–100, linear)
  const denyRate     = total > 0 ? denied / total : 0;
  const denyScore    = Math.round(denyRate * 100);

  // 2. Dangerous tool score
  const dangerRate   = total > 0 ? dangerousCalls / total : 0;
  const dangerScore  = Math.min(100, Math.round(dangerRate * 150)); // amplified

  // 3. Burst activity score — one tool dominates (>50% of calls) → high risk
  const maxToolCalls  = total > 0 ? Math.max(...Object.values(toolCounts)) : 0;
  const burstRatio    = total > 0 ? maxToolCalls / total : 0;
  const burstScore    = burstRatio > 0.5 ? Math.round((burstRatio - 0.5) * 200) : 0;

  // 4. Tool diversity score
  //    Too few tools in a long session → suspicious narrow focus
  //    Too many tools → possible wild tool-calling
  const uniqueCount = Object.keys(toolCounts).length;
  let diversityScore = 0;
  if (total > 10) {
    if (uniqueCount <= 1) diversityScore = 30;       // only 1 tool + many calls = suspicious
    else if (uniqueCount > total * 0.8) diversityScore = 20; // each call is a different tool
  }

  // ── Composite score ────────────────────────────────────────────────────────
  const composite = Math.min(100, Math.round(
    denyScore   * 0.40 +
    dangerScore * 0.30 +
    burstScore  * 0.15 +
    diversityScore * 0.15,
  ));

  const grade =
    composite >= 80 ? 'CRITICAL' :
    composite >= 60 ? 'HIGH'     :
    composite >= 40 ? 'MEDIUM'   :
    composite >= 20 ? 'LOW'      :
                      'CLEAN';

  const breakdown = { denyScore, dangerScore, burstScore, diversityScore };

  // ── Output ─────────────────────────────────────────────────────────────────
  if (jsonOutput) {
    console.log(JSON.stringify({
      windowHours,
      total,
      score: composite,
      grade,
      breakdown,
      inputs: { denyRate: parseFloat(denyRate.toFixed(3)), dangerousCalls, burstRatio: parseFloat(burstRatio.toFixed(3)), uniqueTools: uniqueCount },
    }, null, 2));
  } else {
    const gradeColor =
      grade === 'CRITICAL' ? pc.bgRed(pc.white(` ${grade} `)) :
      grade === 'HIGH'     ? pc.red(grade)       :
      grade === 'MEDIUM'   ? pc.yellow(grade)    :
      grade === 'LOW'      ? pc.blue(grade)      :
                             pc.green(grade);

    console.log(`\n${pc.bold('warden anomaly-score')} — last ${windowHours}h\n`);
    console.log(`  Score : ${pc.bold(String(composite))}/100  ${gradeColor}`);
    console.log(`  Calls : ${total}  (denied: ${denied}, dangerous: ${dangerousCalls})`);
    console.log();
    console.log(pc.dim(`  Breakdown:`));
    console.log(pc.dim(`    deny rate      ${denyScore.toString().padStart(3)} pts  (weight 40%)`));
    console.log(pc.dim(`    dangerous tool ${dangerScore.toString().padStart(3)} pts  (weight 30%)`));
    console.log(pc.dim(`    burst activity ${burstScore.toString().padStart(3)} pts  (weight 15%)`));
    console.log(pc.dim(`    tool diversity ${diversityScore.toString().padStart(3)} pts  (weight 15%)`));
    console.log();
    if (total === 0) {
      console.log(pc.dim('  (No calls in window — score may not be meaningful)'));
    }
  }

  if (threshold !== null && composite >= threshold) {
    process.exit(1);
  }
}

// ─── Command: trending ────────────────────────────────────────────────────────

async function cmdTrending(flags: string[]): Promise<void> {
  // Shows tools sorted by change in call rate between two halves of a time window.
  // "Rising" = more calls in second half than first half.
  // "Falling" = fewer calls in second half than first half.
  //
  // Flags:
  //   --window/-w <hours>    Total window to analyse in hours (default 24)
  //   --n <count>            Max number of tools to show per list (default 10)
  //   --json/-j              Machine-readable output
  //   --min-calls N          Minimum total calls to appear in list (default 2)

  let windowHours = 24;
  let maxN         = 10;
  let jsonOutput   = false;
  let minCalls     = 2;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--window' || f === '-w') && flags[i + 1]) {
      windowHours = parseFloat(flags[++i]!);
    } else if (f === '--n' && flags[i + 1]) {
      maxN = parseInt(flags[++i]!, 10);
    } else if ((f === '--json' || f === '-j')) {
      jsonOutput = true;
    } else if (f === '--min-calls' && flags[i + 1]) {
      minCalls = parseInt(flags[++i]!, 10);
    }
  }

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Load entries in the window ─────────────────────────────────────────────
  const now     = Date.now();
  const windowMs = windowHours * 60 * 60 * 1000;
  const cutoff   = now - windowMs;
  const midpoint = now - windowMs / 2;

  const toolFirst:  Record<string, number> = {};  // calls in first half
  const toolSecond: Record<string, number> = {};  // calls in second half

  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

    const ts = entry.ts ? new Date(entry.ts).getTime() : 0;
    if (ts < cutoff) continue;

    const tool = entry.tool ?? '(unknown)';
    if (ts < midpoint) {
      toolFirst[tool] = (toolFirst[tool] ?? 0) + 1;
    } else {
      toolSecond[tool] = (toolSecond[tool] ?? 0) + 1;
    }
  }

  // ── Compute deltas ─────────────────────────────────────────────────────────
  const allTools = new Set([...Object.keys(toolFirst), ...Object.keys(toolSecond)]);

  const trends = Array.from(allTools).map(tool => {
    const first  = toolFirst[tool]  ?? 0;
    const second = toolSecond[tool] ?? 0;
    const total  = first + second;
    const delta  = second - first;
    const pct    = first === 0
      ? (second > 0 ? 100 : 0)
      : Math.round((delta / first) * 100);
    return { tool, first, second, total, delta, pct };
  }).filter(t => t.total >= minCalls);

  const rising  = trends.filter(t => t.delta > 0).sort((a, b) => b.delta - a.delta).slice(0, maxN);
  const falling = trends.filter(t => t.delta < 0).sort((a, b) => a.delta - b.delta).slice(0, maxN);
  const flat    = trends.filter(t => t.delta === 0).sort((a, b) => b.total - a.total).slice(0, maxN);

  // ── Output ─────────────────────────────────────────────────────────────────
  if (jsonOutput) {
    console.log(JSON.stringify({ windowHours, rising, falling, flat }, null, 2));
    return;
  }

  const halfH = windowHours / 2;
  console.log(`\n${pc.bold('warden trending')} — last ${windowHours}h (first ${halfH}h vs last ${halfH}h)\n`);

  if (rising.length === 0 && falling.length === 0) {
    console.log(pc.dim('  No trend data (not enough calls in window)'));
    return;
  }

  if (rising.length > 0) {
    console.log(pc.green('  Rising ↑'));
    for (const t of rising) {
      const bar = '▲'.repeat(Math.min(t.delta, 10));
      console.log(`    ${pc.green(bar.padEnd(11))} ${pc.bold(t.tool.padEnd(35))} ${t.first} → ${t.second}  ${pc.green(`+${t.pct}%`)}`);
    }
    console.log();
  }

  if (falling.length > 0) {
    console.log(pc.red('  Falling ↓'));
    for (const t of falling) {
      const bar = '▼'.repeat(Math.min(Math.abs(t.delta), 10));
      console.log(`    ${pc.red(bar.padEnd(11))} ${pc.bold(t.tool.padEnd(35))} ${t.first} → ${t.second}  ${pc.red(`${t.pct}%`)}`);
    }
    console.log();
  }

  if (flat.length > 0 && rising.length === 0 && falling.length === 0) {
    console.log(pc.dim('  Stable (no change)'));
    for (const t of flat.slice(0, 5)) {
      console.log(pc.dim(`    ${t.tool.padEnd(35)} ${t.total} calls`));
    }
  }
}

// ─── Command: compare ─────────────────────────────────────────────────────────

async function cmdCompare(flags: string[]): Promise<void> {
  // Compare two snapshot JSON files (produced by warden snapshot).
  // Reports regressions: deny rate increase, new blocked tools, etc.
  //
  // Usage: warden compare <baseline.json> <current.json> [--json] [--fail-on-regression]

  let baselinePath: string | undefined;
  let currentPath:  string | undefined;
  let jsonOutput    = false;
  let failOnRegress = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if (f === '--json' || f === '-j') {
      jsonOutput = true;
    } else if (f === '--fail-on-regression' || f === '-f') {
      failOnRegress = true;
    } else if (!f.startsWith('-')) {
      if (!baselinePath) baselinePath = f;
      else if (!currentPath) currentPath = f;
    }
  }

  if (!baselinePath || !currentPath) {
    console.error(pc.red('Usage: warden compare <baseline.json> <current.json> [--json] [--fail-on-regression]'));
    process.exit(1);
  }

  if (!fs.existsSync(baselinePath)) {
    console.error(pc.red(`Baseline snapshot not found: ${baselinePath}`));
    process.exit(1);
  }
  if (!fs.existsSync(currentPath)) {
    console.error(pc.red(`Current snapshot not found: ${currentPath}`));
    process.exit(1);
  }

  // ── Load snapshots ─────────────────────────────────────────────────────────
  type SnapshotDoc = {
    version:  number;
    snapshotAt: string;
    tag?:    string;
    totals:  { calls: number; allow: number; deny: number; killed: number; denyRate: number };
    latency: { avgMs: number | null; p95Ms: number | null };
    topTools: Array<{ tool: string; total: number; allow: number; deny: number; killed: number }>;
  };

  let baseline: SnapshotDoc;
  let current:  SnapshotDoc;

  try {
    baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8')) as SnapshotDoc;
    current  = JSON.parse(fs.readFileSync(currentPath,  'utf8')) as SnapshotDoc;
  } catch (err) {
    console.error(pc.red(`Failed to parse snapshot: ${(err as Error).message}`));
    process.exit(1);
  }

  // ── Compute deltas ─────────────────────────────────────────────────────────
  const denyRateDelta  = current.totals.denyRate - baseline.totals.denyRate;
  const callsDelta     = current.totals.calls    - baseline.totals.calls;
  const avgMsDelta     = current.latency.avgMs != null && baseline.latency.avgMs != null
    ? current.latency.avgMs - baseline.latency.avgMs
    : null;

  // Tools that are now blocked but weren't in baseline
  const baselineToolMap = new Map(baseline.topTools.map(t => [t.tool, t]));
  const currentToolMap  = new Map(current.topTools.map(t => [t.tool, t]));

  const newlyBlocked: string[] = [];
  const increaseBlocked: Array<{ tool: string; baseline: number; current: number }> = [];
  const newlyAllowed: string[] = [];

  for (const [tool, ct] of currentToolMap.entries()) {
    const bt = baselineToolMap.get(tool);
    const cBlocked = ct.deny + ct.killed;
    const bBlocked = bt ? bt.deny + bt.killed : 0;

    if (cBlocked > 0 && bBlocked === 0) {
      newlyBlocked.push(tool);
    } else if (cBlocked > bBlocked && bt) {
      increaseBlocked.push({ tool, baseline: bBlocked, current: cBlocked });
    }
  }

  for (const [tool, bt] of baselineToolMap.entries()) {
    const ct = currentToolMap.get(tool);
    const bBlocked = bt.deny + bt.killed;
    const cBlocked = ct ? ct.deny + ct.killed : 0;
    if (bBlocked > 0 && cBlocked === 0) {
      newlyAllowed.push(tool);
    }
  }

  const hasRegression =
    denyRateDelta > 1 ||          // deny rate increased by more than 1pp
    newlyBlocked.length > 0 ||
    increaseBlocked.length > 0;

  // ── Output ─────────────────────────────────────────────────────────────────
  if (jsonOutput) {
    console.log(JSON.stringify({
      baseline: { path: baselinePath, tag: baseline.tag, snapshotAt: baseline.snapshotAt },
      current:  { path: currentPath,  tag: current.tag,  snapshotAt: current.snapshotAt },
      deltas: {
        calls:      callsDelta,
        denyRate:   parseFloat(denyRateDelta.toFixed(2)),
        avgMs:      avgMsDelta,
      },
      regressions: {
        denyRateIncreased: denyRateDelta > 1,
        newlyBlocked,
        increaseBlocked,
        newlyAllowed,
      },
      hasRegression,
    }, null, 2));
  } else {
    const baseLabel = baseline.tag ?? path.basename(baselinePath);
    const currLabel = current.tag  ?? path.basename(currentPath);

    console.log(`\n${pc.bold('warden compare')}`);
    console.log(`  Baseline : ${pc.dim(baseLabel)}`);
    console.log(`  Current  : ${pc.dim(currLabel)}`);
    console.log();

    const fmtDelta = (d: number, unit = ''): string => {
      if (d === 0) return pc.dim(`±0${unit}`);
      return d > 0 ? pc.red(`+${d}${unit}`) : pc.green(`${d}${unit}`);
    };

    console.log(`  Calls       ${current.totals.calls}  ${fmtDelta(callsDelta)}`);
    console.log(`  Deny rate   ${current.totals.denyRate}%  ${fmtDelta(parseFloat(denyRateDelta.toFixed(1)), 'pp')}`);
    if (avgMsDelta != null) {
      console.log(`  Avg latency ${current.latency.avgMs}ms  ${fmtDelta(Math.round(avgMsDelta), 'ms')}`);
    }

    if (newlyBlocked.length > 0) {
      console.log(`\n  ${pc.red('New blocked tools:')}`);
      for (const t of newlyBlocked) console.log(`    ${pc.red('+')} ${t}`);
    }
    if (increaseBlocked.length > 0) {
      console.log(`\n  ${pc.yellow('Increased blocks:')}`);
      for (const t of increaseBlocked) {
        console.log(`    ${pc.yellow('↑')} ${t.tool}  ${t.baseline} → ${t.current}`);
      }
    }
    if (newlyAllowed.length > 0) {
      console.log(`\n  ${pc.green('Previously blocked, now allowed:')}`);
      for (const t of newlyAllowed) console.log(`    ${pc.green('-')} ${t}`);
    }

    console.log();
    if (hasRegression) {
      console.log(pc.red('❌ Regression detected'));
    } else {
      console.log(pc.green('✅ No regressions'));
    }
  }

  if (failOnRegress && hasRegression) {
    process.exit(1);
  }
}

// ─── Command: snapshot ────────────────────────────────────────────────────────

async function cmdSnapshot(flags: string[]): Promise<void> {
  // Save a timestamped snapshot of the current audit stats to a JSON file.
  // Useful in CI/CD to persist metrics across runs and compare later.
  //
  // Flags:
  //   --output/-o <file>    Where to save the snapshot (default: warden-snapshot-<ts>.json)
  //   --since/-s <expr>     Only count entries since this point
  //   --tag <label>         Optional label to embed in the snapshot (e.g., PR number, branch)
  //   --print               Also print the snapshot to stdout after saving

  let outputPath: string | undefined;
  let sinceDate:  Date | undefined;
  let tag:        string | undefined;
  let printOutput = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--output' || f === '-o') && flags[i + 1]) {
      outputPath = flags[++i];
    } else if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate = parseSince(flags[++i]!);
    } else if (f === '--tag' && flags[i + 1]) {
      tag = flags[++i];
    } else if (f === '--print' || f === '-p') {
      printOutput = true;
    }
  }

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  // ── Aggregate stats ────────────────────────────────────────────────────────
  const byVerdict: Record<string, number> = {};
  const byTool:    Record<string, { allow: number; deny: number; killed: number }> = {};
  let total     = 0;
  let firstTs:  string | undefined;
  let lastTs:   string | undefined;
  const durations: number[] = [];

  if (fs.existsSync(logFile)) {
    const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
    const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

    for await (const line of rl) {
      if (!line.trim()) continue;
      let entry: AuditEntry;
      try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

      if (sinceDate && entry.ts && new Date(entry.ts) < sinceDate) continue;

      total++;
      byVerdict[entry.verdict] = (byVerdict[entry.verdict] ?? 0) + 1;

      const t = entry.tool ?? '(unknown)';
      if (!byTool[t]) byTool[t] = { allow: 0, deny: 0, killed: 0 };
      if (entry.verdict === 'allow')  byTool[t]!.allow++;
      if (entry.verdict === 'deny')   byTool[t]!.deny++;
      if (entry.verdict === 'killed') byTool[t]!.killed++;

      if (!firstTs || (entry.ts && entry.ts < firstTs)) firstTs = entry.ts;
      if (!lastTs  || (entry.ts && entry.ts > lastTs))  lastTs   = entry.ts;
      if (typeof entry.durationMs === 'number') durations.push(entry.durationMs);
    }
  }

  const avgDurationMs = durations.length > 0
    ? Math.round(durations.reduce((a, b) => a + b, 0) / durations.length)
    : null;

  const p95DurationMs = durations.length > 0
    ? (() => { durations.sort((a, b) => a - b); return durations[Math.floor(durations.length * 0.95)] ?? null; })()
    : null;

  const topTools = Object.entries(byTool)
    .map(([tool, s]) => ({ tool, total: s.allow + s.deny + s.killed, ...s }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 20);

  const snapshot = {
    version:      1,
    snapshotAt:   new Date().toISOString(),
    logFile,
    ...(tag ? { tag } : {}),
    ...(sinceDate ? { since: sinceDate.toISOString() } : {}),
    period: {
      first: firstTs ?? null,
      last:  lastTs  ?? null,
    },
    totals: {
      calls:   total,
      allow:   byVerdict['allow']  ?? 0,
      deny:    byVerdict['deny']   ?? 0,
      killed:  byVerdict['killed'] ?? 0,
      denyRate: total > 0
        ? parseFloat((((byVerdict['deny'] ?? 0) + (byVerdict['killed'] ?? 0)) / total * 100).toFixed(2))
        : 0,
    },
    latency: {
      avgMs: avgDurationMs,
      p95Ms: p95DurationMs,
    },
    topTools,
  };

  // ── Write snapshot ─────────────────────────────────────────────────────────
  const snapshotJson = JSON.stringify(snapshot, null, 2);

  if (!outputPath) {
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    outputPath = path.join(process.cwd(), `warden-snapshot-${ts}.json`);
  }

  fs.writeFileSync(outputPath, snapshotJson + '\n', 'utf8');
  console.log(pc.green(`✅ Snapshot saved → ${outputPath}`));
  console.log(pc.dim(`   ${total} calls | allow: ${snapshot.totals.allow}, deny: ${snapshot.totals.deny}, killed: ${snapshot.totals.killed} | deny rate: ${snapshot.totals.denyRate}%`));

  if (printOutput) {
    console.log('\n' + snapshotJson);
  }
}

// ─── Command: suggest ─────────────────────────────────────────────────────────

async function cmdSuggest(flags: string[]): Promise<void> {
  // Analyse the audit log and suggest policy rules based on observed patterns.
  //
  // Strategy:
  //  1. Count allow/deny verdicts per tool (from actual logged calls)
  //  2. Flag tools that:
  //     - Are frequently denied  → suggest explicit deny rule
  //     - Are always allowed and very common → suggest explicit allow rule
  //     - Match dangerous-tool name patterns → suggest review / deny rule
  //  3. Identify tools called with suspiciously high frequency → suggest rate limit
  //  4. Output as YAML policy snippet or JSON
  //
  // Flags:
  //   --since/-s <expr>      Look at entries since this point (default: all)
  //   --min-calls <N>        Minimum total calls to include a tool (default: 3)
  //   --deny-ratio <0-1>     Ratio of deny/(allow+deny) to suggest deny rule (default: 0.3)
  //   --json/-j              Machine-readable JSON output
  //   --yaml/-y              Output as YAML policy snippet (default: text)

  let sinceDate:  Date | undefined;
  let minCalls    = 3;
  let denyRatio   = 0.3;
  let jsonOutput  = false;
  let yamlOutput  = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate = parseSince(flags[++i]!);
    } else if (f === '--min-calls' && flags[i + 1]) {
      minCalls = parseInt(flags[++i]!, 10) || minCalls;
    } else if (f === '--deny-ratio' && flags[i + 1]) {
      denyRatio = parseFloat(flags[++i]!) || denyRatio;
    } else if (f === '--json' || f === '-j') {
      jsonOutput = true;
    } else if (f === '--yaml' || f === '-y') {
      yamlOutput = true;
    }
  }

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Read audit log ────────────────────────────────────────────────────────
  const toolStats: Map<string, { allow: number; deny: number; killed: number; durations: number[] }> = new Map();

  const rs = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: rs, crlfDelay: Infinity });

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }

    if (sinceDate && entry.ts && new Date(entry.ts) < sinceDate) continue;

    const t = entry.tool ?? '(unknown)';
    if (!toolStats.has(t)) toolStats.set(t, { allow: 0, deny: 0, killed: 0, durations: [] });
    const s = toolStats.get(t)!;
    if (entry.verdict === 'allow')  s.allow++;
    if (entry.verdict === 'deny')   s.deny++;
    if (entry.verdict === 'killed') s.killed++;
    if (typeof entry.durationMs === 'number') s.durations.push(entry.durationMs);
  }

  // ── Dangerous pattern heuristics ──────────────────────────────────────────
  // These are tools whose names suggest destructive or sensitive operations.
  const DANGEROUS_PATTERNS = [
    /delete/i, /remove/i, /destroy/i, /drop/i, /truncate/i,
    /purge/i, /reset/i, /wipe/i, /overwrite/i, /bash/i, /shell/i, /exec/i,
    /sudo/i, /chmod/i, /chown/i, /format/i, /rm\b/i, /kill/i,
  ];

  function isDangerous(name: string): boolean {
    return DANGEROUS_PATTERNS.some(re => re.test(name));
  }

  // ── Build suggestions ─────────────────────────────────────────────────────
  interface Suggestion {
    tool:    string;
    action:  'deny' | 'allow' | 'rate-limit';
    reason:  string;
    urgency: 'high' | 'medium' | 'low';
    stats:   { allow: number; deny: number; killed: number; total: number; denyRate: number };
  }

  const suggestions: Suggestion[] = [];

  for (const [tool, stats] of toolStats.entries()) {
    const total   = stats.allow + stats.deny + stats.killed;
    if (total < minCalls) continue;

    const denyRate = (stats.deny + stats.killed) / total;

    // High deny rate → suggest explicit deny rule
    if (denyRate >= denyRatio) {
      suggestions.push({
        tool,
        action:  'deny',
        reason:  `High block rate: ${(denyRate * 100).toFixed(0)}% of ${total} calls were blocked`,
        urgency: denyRate >= 0.7 ? 'high' : 'medium',
        stats:   { ...stats, total, denyRate },
      });
      continue;
    }

    // Dangerous-pattern tool that was allowed → flag for review
    if (isDangerous(tool) && stats.allow > 0) {
      suggestions.push({
        tool,
        action:  'deny',
        reason:  `Tool name matches dangerous-operation pattern — review whether to allow`,
        urgency: 'medium',
        stats:   { ...stats, total, denyRate },
      });
      continue;
    }

    // High call volume, all allowed → suggest explicit allow rule + rate limit
    const callsPerEntry = total;
    if (callsPerEntry >= minCalls * 3 && denyRate === 0) {
      const avgMs = stats.durations.length > 0
        ? Math.round(stats.durations.reduce((a, b) => a + b, 0) / stats.durations.length)
        : null;
      suggestions.push({
        tool,
        action:  'rate-limit',
        reason:  `High call volume (${total} calls, all allowed). Consider rate-limiting to prevent runaway use.${avgMs != null ? ` Avg latency: ${avgMs}ms` : ''}`,
        urgency: 'low',
        stats:   { ...stats, total, denyRate },
      });
    }
  }

  // Sort by urgency
  const urgencyOrder = { high: 0, medium: 1, low: 2 };
  suggestions.sort((a, b) => (urgencyOrder[a.urgency] - urgencyOrder[b.urgency]) || (b.stats.total - a.stats.total));

  if (suggestions.length === 0) {
    if (jsonOutput) {
      console.log(JSON.stringify({ suggestions: [], note: 'No suggestions — policy looks healthy or not enough data' }, null, 2));
    } else {
      console.log(pc.green('✅ No suggestions — policy looks healthy or insufficient data (need ≥' + minCalls + ' calls per tool)'));
    }
    return;
  }

  // ── JSON output ────────────────────────────────────────────────────────────
  if (jsonOutput) {
    console.log(JSON.stringify({ suggestions }, null, 2));
    return;
  }

  // ── YAML snippet output ────────────────────────────────────────────────────
  if (yamlOutput) {
    console.log('# agent-warden suggested policy rules');
    console.log('# Generated by: warden suggest');
    console.log('# Review each rule before adding to warden.config.yaml');
    console.log('');
    console.log('policy:');
    console.log('  rules:');
    for (const s of suggestions) {
      if (s.action === 'rate-limit') {
        console.log(`    # ${s.reason}`);
        console.log(`    # Consider adding to rateLimit.rules instead`);
      } else {
        console.log(`    # ${s.urgency.toUpperCase()}: ${s.reason}`);
        console.log(`    - tool: "${s.tool}"`);
        console.log(`      action: ${s.action}`);
        console.log(`      reason: "Auto-suggested: ${s.reason.split('.')[0]}"`);
      }
      console.log('');
    }
    return;
  }

  // ── Text output ────────────────────────────────────────────────────────────
  const urgencyIcon = { high: pc.red('❗'), medium: pc.yellow('⚠️ '), low: pc.dim('💡') };

  console.log(`${pc.bold('warden suggest')} — ${suggestions.length} suggestion${suggestions.length > 1 ? 's' : ''} from audit log`);
  if (sinceDate) console.log(pc.dim(`  since ${sinceDate.toISOString()}`));
  console.log();

  for (const s of suggestions) {
    const icon  = urgencyIcon[s.urgency];
    const label = s.action === 'rate-limit'
      ? pc.blue('[rate-limit]')
      : s.action === 'deny'
        ? pc.red('[deny]')
        : pc.green('[allow]');

    console.log(`  ${icon} ${pc.cyan(s.tool)}  ${label}`);
    console.log(`     ${s.reason}`);
    console.log(`     ${pc.dim(`Calls: ${s.stats.total} (allow: ${s.stats.allow}, deny: ${s.stats.deny}, killed: ${s.stats.killed})`)}`);
    console.log();
  }

  console.log(pc.dim('Run `warden suggest --yaml` to output a policy snippet you can paste into warden.config.yaml'));
}

// ─── Command: doctor ──────────────────────────────────────────────────────────

async function cmdDoctor(flags: string[]): Promise<void> {
  // Comprehensive health check for warden installation and config.
  // Does NOT make network connections — purely local checks.

  let configArg: string | undefined;
  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--config' || f === '-c') && flags[i + 1]) {
      configArg = flags[++i];
    }
  }

  console.log(`${pc.bold('agent-warden doctor')} — running health checks\n`);

  type CheckResult = { label: string; ok: boolean; detail: string; hint?: string };
  const checks: CheckResult[] = [];

  function pass(label: string, detail: string): void {
    checks.push({ label, ok: true, detail });
  }
  function fail(label: string, detail: string, hint?: string): void {
    checks.push({ label, ok: false, detail, hint });
  }
  function warn(label: string, detail: string, hint?: string): void {
    checks.push({ label, ok: true, detail, hint }); // warn treated as pass but with hint
  }

  // ── 1. Node.js version ────────────────────────────────────────────────────
  const nodeVer = process.versions.node;
  const [nodeMajor] = nodeVer.split('.').map(Number);
  if ((nodeMajor ?? 0) >= 18) {
    pass('Node.js version', `v${nodeVer}`);
  } else {
    fail('Node.js version', `v${nodeVer}`, 'agent-warden requires Node.js 18 or later');
  }

  // ── 2. warden binary is runnable ──────────────────────────────────────────
  pass('warden binary', `v${VERSION} (${process.argv[1] ?? 'unknown path'})`);

  // ── 3. Config file ────────────────────────────────────────────────────────
  const { resolveConfigPath } = await import('./config.js');
  const cfgPath = configArg ? (await import('node:path')).resolve(configArg) : resolveConfigPath();

  if (fs.existsSync(cfgPath)) {
    pass('Config file exists', cfgPath);

    // Validate the config
    const { load: yamlLoad } = await import('js-yaml');
    let rawContent: string;
    try {
      rawContent = fs.readFileSync(cfgPath, 'utf8');
      try {
        const parsed = yamlLoad(rawContent) as Record<string, unknown>;
        const issues = validateConfigObject(parsed ?? {});
        const errs = issues.filter(i => i.level === 'error');
        const warns = issues.filter(i => i.level === 'warning');

        if (errs.length > 0) {
          fail('Config validation', `${errs.length} error${errs.length > 1 ? 's' : ''}`,
            errs.map(e => `${e.path}: ${e.msg}`).join('; '));
        } else if (warns.length > 0) {
          warn('Config validation', `valid (${warns.length} warning${warns.length > 1 ? 's' : ''})`,
            warns.map(w => `${w.path}: ${w.msg}`).join('; '));
        } else {
          pass('Config validation', 'no issues');
        }

        // Check mode
        const mode = String(parsed?.['mode'] ?? 'audit');
        if (mode === 'audit') {
          warn('Mode', '"audit" — tool calls are logged but not blocked',
            'Switch to "enforce" to actually block denied tool calls');
        } else {
          pass('Mode', `"${mode}"`);
        }
      } catch {
        fail('Config validation', 'YAML parse error', `Run: warden validate ${cfgPath}`);
      }
    } catch {
      fail('Config readable', `Cannot read ${cfgPath}`, 'Check file permissions');
    }
  } else {
    fail('Config file exists', `Not found at ${cfgPath}`,
      'Run: warden init  (or: warden config-gen)');
  }

  // ── 4. Kill switch state ──────────────────────────────────────────────────
  const ks = new KillSwitch();
  const ksState = ks.getState();
  if (ksState.killed) {
    warn('Kill switch', `ARMED — all tool calls will be blocked`,
      `Run: warden unkill   (reason: ${ksState.reason ?? '(none)'})`);
  } else {
    pass('Kill switch', 'disarmed (normal operation)');
  }

  // ── 5. Audit log ──────────────────────────────────────────────────────────
  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;
  const logDir  = path.dirname(logFile);

  if (fs.existsSync(logFile)) {
    const stat = fs.statSync(logFile);
    const sizeMiB = (stat.size / (1024 * 1024)).toFixed(1);
    pass('Audit log', `${logFile} (${sizeMiB} MiB)`);
  } else if (fs.existsSync(logDir)) {
    warn('Audit log', `not yet created at ${logFile}`,
      'Will be created when warden first runs');
  } else {
    warn('Audit log directory', `${logDir} does not exist`,
      `Will be created at first run (mkdir ${logDir})`);
  }

  // ── 6. Claude Desktop / Code integration ──────────────────────────────────
  const claudeFound = findClaudeConfigs();
  if (claudeFound.length > 0) {
    let wardenCount = 0;
    for (const { path: cfgFilePath } of claudeFound) {
      try {
        const c = JSON.parse(fs.readFileSync(cfgFilePath, 'utf8')) as Record<string, unknown>;
        const servers = c['mcpServers'] as Record<string, unknown> | undefined;
        if (servers) {
          for (const def of Object.values(servers)) {
            const d = def as Record<string, unknown>;
            if (d['command'] === 'warden') wardenCount++;
          }
        }
      } catch { /* ignore */ }
    }

    if (wardenCount > 0) {
      pass('Claude integration', `${wardenCount} server${wardenCount > 1 ? 's' : ''} proxied by warden`);
    } else {
      warn('Claude integration', 'warden not yet injected into Claude config',
        'Run: warden install  to auto-inject warden in front of your MCP servers');
    }
  } else {
    warn('Claude config', 'no Claude Desktop or Claude Code config found', '');
  }

  // ── Render results ────────────────────────────────────────────────────────
  console.log();
  let failCount = 0;
  let warnCount = 0;

  for (const c of checks) {
    const errs    = c.ok && !c.hint ? pc.green('✅') : c.ok && c.hint ? pc.yellow('⚠️ ') : pc.red('❌');
    const label   = c.label.padEnd(28);
    const detail  = c.detail;
    console.log(`  ${errs} ${pc.bold(label)} ${detail}`);
    if (c.hint) {
      console.log(`       ${pc.dim(c.hint)}`);
    }
    if (!c.ok) failCount++;
    else if (c.hint) warnCount++;
  }

  console.log();
  if (failCount > 0) {
    console.log(pc.red(`${failCount} issue${failCount > 1 ? 's' : ''} found — fix before running warden`));
    process.exit(1);
  } else if (warnCount > 0) {
    console.log(pc.yellow(`${warnCount} suggestion${warnCount > 1 ? 's' : ''} — warden should work but see hints above`));
  } else {
    console.log(pc.green('✅ All checks passed — warden is healthy'));
  }
}

// ─── Command: timeline ────────────────────────────────────────────────────────

async function cmdTimeline(flags: string[]): Promise<void> {
  // ASCII timeline of tool call activity grouped into time buckets.
  // Flags:
  //   --since/-s <expr>     Only include entries after this point (default: 1h)
  //   --bucket <mins>       Bucket size in minutes (default: auto from range)
  //   --width <cols>        Width of bar chart (default: 60)
  //   --tool/-t <pattern>   Filter to specific tool pattern
  //   --split-verdict       Show allow/deny breakdown per bucket

  let sinceDate: Date | undefined;
  let bucketMins: number | undefined;
  let barWidth       = 60;
  let toolFilter: string | undefined;
  let splitVerdict   = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--since' || f === '-s') && flags[i + 1]) {
      sinceDate = parseSince(flags[++i]!);
    } else if (f === '--bucket' && flags[i + 1]) {
      bucketMins = parseInt(flags[++i]!, 10);
    } else if (f === '--width' && flags[i + 1]) {
      barWidth = parseInt(flags[++i]!, 10);
    } else if ((f === '--tool' || f === '-t') && flags[i + 1]) {
      toolFilter = flags[++i];
    } else if (f === '--split-verdict') {
      splitVerdict = true;
    }
  }

  // Default: last 1 hour
  if (!sinceDate) sinceDate = parseSince('1h');

  const logFile = process.env['WARDEN_LOG'] ?? DEFAULT_LOG_FILE;

  if (!fs.existsSync(logFile)) {
    console.error(pc.red(`Log file not found: ${logFile}`));
    process.exit(1);
  }

  // ── Read and bucket entries ────────────────────────────────────────────────
  let firstTs: Date | undefined;
  let lastTs:  Date | undefined;

  const raw: Array<{ ts: Date; tool: string; verdict: string }> = [];

  const readStream = fs.createReadStream(logFile, { encoding: 'utf8' });
  const rl         = readline.createInterface({ input: readStream, crlfDelay: Infinity });

  for await (const line of rl) {
    if (!line.trim()) continue;
    let entry: AuditEntry;
    try { entry = JSON.parse(line) as AuditEntry; } catch { continue; }
    if (!entry.ts) continue;

    const ts = new Date(entry.ts);
    if (ts < sinceDate) continue;

    if (toolFilter) {
      const pattern = toolFilter.includes('*')
        ? new RegExp('^' + toolFilter.split('*').map(s => s.replace(/[.+^${}()|[\]\\]/g, '\\$&')).join('.*') + '$')
        : null;
      const match = pattern ? pattern.test(entry.tool ?? '') : (entry.tool ?? '').includes(toolFilter);
      if (!match) continue;
    }

    raw.push({ ts, tool: entry.tool ?? 'unknown', verdict: entry.verdict ?? 'unknown' });

    if (!firstTs || ts < firstTs) firstTs = ts;
    if (!lastTs  || ts > lastTs)  lastTs   = ts;
  }

  if (raw.length === 0) {
    console.log(pc.yellow('No entries found in the specified time range'));
    return;
  }

  const rangeMs = (lastTs!.getTime() - firstTs!.getTime()) || 60_000;

  // Auto-select bucket size if not specified
  if (!bucketMins) {
    if (rangeMs <= 5 * 60_000)       bucketMins = 1;
    else if (rangeMs <= 30 * 60_000)  bucketMins = 5;
    else if (rangeMs <= 2 * 3600_000) bucketMins = 15;
    else if (rangeMs <= 12 * 3600_000) bucketMins = 60;
    else                               bucketMins = 360;
  }

  const bucketMs = bucketMins * 60_000;

  // Build buckets: epoch bucket index → { allow, deny, killed }
  const buckets: Map<number, { allow: number; deny: number; killed: number }> = new Map();

  for (const r of raw) {
    const key = Math.floor(r.ts.getTime() / bucketMs);
    const b   = buckets.get(key) ?? { allow: 0, deny: 0, killed: 0 };
    if (r.verdict === 'allow')  b.allow++;
    if (r.verdict === 'deny')   b.deny++;
    if (r.verdict === 'killed') b.killed++;
    buckets.set(key, b);
  }

  // Fill in empty buckets for continuity
  const minKey = Math.floor(firstTs!.getTime() / bucketMs);
  const maxKey = Math.floor(lastTs!.getTime()  / bucketMs);
  for (let k = minKey; k <= maxKey; k++) {
    if (!buckets.has(k)) buckets.set(k, { allow: 0, deny: 0, killed: 0 });
  }

  const sortedKeys = [...buckets.keys()].sort((a, b) => a - b);

  const maxTotal = Math.max(...sortedKeys.map(k => {
    const b = buckets.get(k)!;
    return b.allow + b.deny + b.killed;
  }));

  // ── Render ────────────────────────────────────────────────────────────────
  const toolLabel = toolFilter ? ` · tool: ${toolFilter}` : '';
  const bucketLabel = bucketMins >= 60 ? `${bucketMins / 60}h` : `${bucketMins}m`;
  console.log(`${pc.bold('Timeline')}${toolLabel} · bucket: ${bucketLabel} · ${raw.length} calls`);
  console.log(pc.dim(`  ${firstTs!.toISOString()} → ${lastTs!.toISOString()}`));
  console.log();

  const labelWidth = 6; // "HH:MM " or "Www "

  for (const key of sortedKeys) {
    const b     = buckets.get(key)!;
    const total = b.allow + b.deny + b.killed;
    const time  = new Date(key * bucketMs);

    // Format time label
    const timeStr = bucketMins >= 1440
      ? `${time.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}`
      : `${String(time.getHours()).padStart(2, '0')}:${String(time.getMinutes()).padStart(2, '0')}`;

    const label = timeStr.padEnd(labelWidth);
    const count = String(total).padStart(4);

    if (maxTotal === 0 || total === 0) {
      console.log(`${pc.dim(label)} ${count} ${pc.dim('·')}`);
      continue;
    }

    const filled = Math.round((total / maxTotal) * barWidth);

    let bar: string;
    if (splitVerdict) {
      const aFilled = Math.round((b.allow  / total) * filled);
      const dFilled = Math.round((b.deny   / total) * filled);
      const kFilled = filled - aFilled - dFilled;
      bar  = pc.green('█'.repeat(aFilled));
      bar += pc.red(   '█'.repeat(dFilled));
      bar += pc.bgRed(pc.white('█'.repeat(Math.max(0, kFilled))));
    } else {
      bar = (b.deny + b.killed > 0 ? pc.red : pc.green)('█'.repeat(filled));
    }

    const denyNote = (b.deny + b.killed > 0 && !splitVerdict)
      ? pc.red(` (${b.deny + b.killed} blocked)`)
      : '';

    console.log(`${pc.dim(label)} ${count} ${bar}${denyNote}`);
  }

  console.log();
  if (splitVerdict) {
    console.log(pc.dim(`  ${pc.green('█')} allow   ${pc.red('█')} deny   ${pc.bgRed(pc.white('█'))} killed`));
  } else {
    console.log(pc.dim(`  ${pc.green('█')} calls with all-allow   ${pc.red('█')} calls with any block`));
  }
}

// ─── Command: server-list ─────────────────────────────────────────────────────

async function cmdServerList(flags: string[]): Promise<void> {
  // Connects to all configured MCP servers and lists their tools + descriptions.
  // Helps users write accurate glob rules in policy config.
  //
  // Flags:
  //   --server/-s <name>   Only list tools for this server
  //   --json/-j            Machine-readable output
  //   --config/-c <path>   Config file path

  let serverFilter: string | undefined;
  let jsonOutput  = false;
  let configArg: string | undefined;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--server' || f === '-s') && flags[i + 1]) {
      serverFilter = flags[++i];
    } else if (f === '--json' || f === '-j') {
      jsonOutput = true;
    } else if ((f === '--config' || f === '-c') && flags[i + 1]) {
      configArg = flags[++i];
    }
  }

  const { Client }              = await import('@modelcontextprotocol/sdk/client/index.js');
  const { StdioClientTransport } = await import('@modelcontextprotocol/sdk/client/stdio.js');

  // Suppress config/proxy stderr during tool-list phase
  const origStderr = process.stderr.write.bind(process.stderr);
  process.stderr.write = () => true;
  let config: ReturnType<typeof loadConfig>;
  try {
    config = loadConfig(configArg);
  } finally {
    process.stderr.write = origStderr;
  }

  const serverMap = config.servers ?? {};
  const serverNames = Object.keys(serverMap).filter(n => !serverFilter || n === serverFilter);

  if (serverNames.length === 0) {
    if (serverFilter) {
      console.error(pc.red(`No server named "${serverFilter}" in config`));
    } else {
      console.error(pc.red('No servers configured'));
    }
    process.exit(1);
  }

  type ToolEntry = { server: string; tool: string; description: string };
  const all: ToolEntry[] = [];
  const errors: Array<{ server: string; error: string }> = [];

  if (!jsonOutput) {
    console.log(`${pc.bold('Connecting to')} ${serverNames.length} server${serverNames.length > 1 ? 's' : ''}...\n`);
  }

  for (const serverName of serverNames) {
    const serverCfg = serverMap[serverName];
    if (!serverCfg) continue;

    // Build env for this server (merge process.env + server-specific env)
    const serverEnv: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) {
      if (v !== undefined) serverEnv[k] = v;
    }
    for (const [k, v] of Object.entries(serverCfg.env ?? {})) {
      serverEnv[k] = v;
    }

    const client = new Client({ name: 'warden-server-list', version: VERSION });
    const transport = new StdioClientTransport({
      command: serverCfg.command,
      args:    serverCfg.args ?? [],
      env:     serverEnv,
      stderr:  'pipe',
    });

    try {
      await client.connect(transport);
      const { tools } = await client.listTools();
      await client.close();

      for (const tool of tools) {
        const prefixed = `${serverName}/${tool.name}`;
        all.push({
          server:      serverName,
          tool:        prefixed,
          description: tool.description ?? '',
        });
      }

      if (!jsonOutput) {
        console.log(`  ${pc.green('✓')} ${pc.bold(serverName)} — ${tools.length} tool${tools.length !== 1 ? 's' : ''}`);
        for (const tool of tools) {
          const prefixed = `${serverName}/${tool.name}`;
          const desc     = tool.description ? pc.dim(` — ${tool.description.slice(0, 80)}`) : '';
          console.log(`      ${pc.cyan(prefixed)}${desc}`);
        }
        console.log();
      }
    } catch (err) {
      const msg = (err as Error).message ?? String(err);
      errors.push({ server: serverName, error: msg });
      if (!jsonOutput) {
        console.log(`  ${pc.red('✗')} ${pc.bold(serverName)} — ${pc.red(msg.slice(0, 100))}`);
        console.log();
      }
    }
  }

  if (jsonOutput) {
    console.log(JSON.stringify({ tools: all, errors }, null, 2));
    return;
  }

  if (errors.length > 0) {
    process.exit(1);
  }

  console.log(pc.dim(`${all.length} tools across ${serverNames.length - errors.length} server${serverNames.length - errors.length !== 1 ? 's' : ''}`));
  console.log();
  console.log(pc.dim('Tip: use these exact tool names in policy rules:'));
  console.log(pc.dim('  - tool: "fs/read_file"    action: allow'));
  console.log(pc.dim('  - tool: "fs/*delete*"     action: deny'));
}

// ─── Command: install / uninstall ─────────────────────────────────────────────

const CLAUDE_CONFIGS: Array<{ label: string; path: string }> = (() => {
  const home = os.homedir();
  return [
    { label: 'Claude Desktop (macOS)',
      path: path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json') },
    { label: 'Claude Code (global)',
      path: path.join(home, '.claude', 'settings.json') },
    { label: 'Claude Desktop (Linux)',
      path: path.join(home, '.config', 'Claude', 'claude_desktop_config.json') },
  ];
})();

function findClaudeConfigs(): Array<{ label: string; path: string }> {
  return CLAUDE_CONFIGS.filter(c => fs.existsSync(c.path));
}

async function cmdInstall(flags: string[]): Promise<void> {
  // Injects warden as a transparent proxy in front of all existing MCP servers.
  //
  // For each discovered MCP server named "X" in the Claude config, install:
  //   warden → { command: "warden", args: ["run", <configPath>], env: {} }
  //     pointing to a generated warden.config.yaml that contains X's original def.
  //
  // This is conservative: one warden per server, each with its own config file,
  // so configs are isolated and easy to revert.
  //
  // Flags:
  //   --config-dir <path>   Directory where warden configs are written (default: ~/.warden/configs)
  //   --dry-run/-n          Preview changes without writing
  //   --yes/-y              Skip confirmation prompt

  let configDir  = path.join(os.homedir(), '.warden', 'configs');
  let dryRun     = false;
  let autoYes    = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--config-dir') && flags[i + 1]) {
      configDir = flags[++i]!;
    } else if (f === '--dry-run' || f === '-n') {
      dryRun = true;
    } else if (f === '--yes' || f === '-y') {
      autoYes = true;
    }
  }

  const found = findClaudeConfigs();
  if (found.length === 0) {
    console.log(pc.yellow('No Claude Desktop or Claude Code config found.'));
    console.log(pc.dim('  Run: warden config-gen   to generate a warden config manually'));
    return;
  }

  console.log(`${pc.bold('Found')} ${found.length} Claude config${found.length > 1 ? 's' : ''}:\n`);

  type Change = {
    cfgPath:       string;
    cfgLabel:      string;
    serverName:    string;
    originalDef:   Record<string, unknown>;
    wardenCfgPath: string;
  };

  const changes: Change[] = [];

  for (const { label, path: cfgPath } of found) {
    let raw: string;
    try { raw = fs.readFileSync(cfgPath, 'utf8'); } catch { continue; }

    let parsed: Record<string, unknown>;
    try { parsed = JSON.parse(raw) as Record<string, unknown>; } catch { continue; }

    const mcpServers = parsed['mcpServers'] as Record<string, unknown> | undefined;
    if (!mcpServers) { continue; }

    for (const [name, def] of Object.entries(mcpServers)) {
      if (!def || typeof def !== 'object') continue;
      const d = def as Record<string, unknown>;

      // Skip if already a warden proxy
      if (d['command'] === 'warden') continue;
      if (Array.isArray(d['args']) && (d['args'][0] === 'run' || d['args'][0] === '--')) continue;

      const wardenCfgPath = path.join(configDir, `${name}.yaml`);
      changes.push({ cfgPath, cfgLabel: label, serverName: name, originalDef: d, wardenCfgPath });

      console.log(`  ${pc.cyan(name)} in ${pc.dim(label)}`);
      console.log(`    ${pc.dim('Original:')} ${d['command'] ?? '?'} ${Array.isArray(d['args']) ? d['args'].join(' ') : ''}`);
      console.log(`    ${pc.dim('Warden:  ')} warden run ${wardenCfgPath}`);
      console.log();
    }
  }

  if (changes.length === 0) {
    console.log(pc.green('✅ All servers are already proxied by warden — nothing to do'));
    return;
  }

  if (dryRun) {
    console.log(pc.dim('(dry run — no files written)'));
    return;
  }

  if (!autoYes) {
    // Simple confirmation without readline (avoid TTY dependencies)
    process.stdout.write(pc.bold(`Proceed with injecting warden for ${changes.length} server${changes.length > 1 ? 's' : ''}? [y/N] `));
    const answer = await new Promise<string>((resolve) => {
      process.stdin.setEncoding('utf8');
      process.stdin.resume();
      process.stdin.once('data', (data) => {
        process.stdin.pause();
        resolve(String(data).trim().toLowerCase());
      });
    });
    if (answer !== 'y' && answer !== 'yes') {
      console.log('Aborted.');
      return;
    }
  }

  fs.mkdirSync(configDir, { recursive: true });

  // Group changes by config file so we only rewrite each file once
  const byConfig = new Map<string, Change[]>();
  for (const change of changes) {
    const list = byConfig.get(change.cfgPath) ?? [];
    list.push(change);
    byConfig.set(change.cfgPath, list);
  }

  for (const [cfgPath, cfgChanges] of byConfig) {
    // Read current state (may differ from what we read above if multiple iters)
    const raw = fs.readFileSync(cfgPath, 'utf8');
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const mcpServers = parsed['mcpServers'] as Record<string, unknown>;

    // Backup original
    const backupPath = `${cfgPath}.warden-backup`;
    if (!fs.existsSync(backupPath)) {
      fs.writeFileSync(backupPath, raw, 'utf8');
      console.log(pc.dim(`  Backup: ${backupPath}`));
    }

    // Write per-server warden config + replace entry
    for (const change of cfgChanges) {
      // Generate minimal warden.config.yaml for this server
      const wCfgLines = [
        `# warden proxy config for: ${change.serverName}`,
        '# Generated by: warden install',
        `# Original config: ${change.cfgPath}`,
        '',
        'mode: audit',
        '',
        'servers:',
        `  ${change.serverName}:`,
        `    command: ${JSON.stringify(String(change.originalDef['command']))}`,
      ];
      if (Array.isArray(change.originalDef['args']) && change.originalDef['args'].length > 0) {
        wCfgLines.push(`    args: [${(change.originalDef['args'] as string[]).map(a => JSON.stringify(a)).join(', ')}]`);
      }
      if (change.originalDef['env'] && typeof change.originalDef['env'] === 'object') {
        wCfgLines.push('    env:');
        for (const [k, v] of Object.entries(change.originalDef['env'] as Record<string, string>)) {
          wCfgLines.push(`      ${k}: ${JSON.stringify(v)}`);
        }
      }
      wCfgLines.push('', 'policy:', '  defaultAction: allow', '', 'scrubber:', '  enabled: true', '');

      fs.writeFileSync(change.wardenCfgPath, wCfgLines.join('\n'), 'utf8');

      // Replace MCP server entry with warden proxy
      mcpServers[change.serverName] = {
        command: 'warden',
        args:    ['run', change.wardenCfgPath],
      };

      console.log(`${pc.green('✅')} ${change.serverName}: config written to ${pc.cyan(change.wardenCfgPath)}`);
    }

    // Write back modified Claude config
    fs.writeFileSync(cfgPath, JSON.stringify(parsed, null, 2) + '\n', 'utf8');
    console.log(`${pc.green('✅')} Updated ${pc.cyan(cfgPath)}`);
  }

  console.log();
  console.log(pc.bold('Installation complete!'));
  console.log(`${pc.dim('Restart Claude Desktop / Claude Code to pick up the new config.')}`);
  console.log(`${pc.dim('To revert:  ')}${pc.cyan('warden uninstall')}`);
}

async function cmdUninstall(flags: string[]): Promise<void> {
  // Restores Claude configs from .warden-backup files created by warden install
  let dryRun  = false;
  let autoYes = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if (f === '--dry-run' || f === '-n') dryRun = true;
    if (f === '--yes' || f === '-y')     autoYes = true;
  }

  const found = findClaudeConfigs();
  const toRestore: Array<{ original: string; backup: string; label: string }> = [];

  for (const { label, path: cfgPath } of found) {
    const backup = `${cfgPath}.warden-backup`;
    if (fs.existsSync(backup)) {
      toRestore.push({ original: cfgPath, backup, label });
    }
  }

  if (toRestore.length === 0) {
    console.log(pc.yellow('No warden backups found — nothing to uninstall'));
    console.log(pc.dim('  (Backups are created at <config>.warden-backup by warden install)'));
    return;
  }

  console.log(`${pc.bold('Found')} ${toRestore.length} backup${toRestore.length > 1 ? 's' : ''}:\n`);
  for (const r of toRestore) {
    console.log(`  ${pc.cyan(r.label)}`);
    console.log(`    Restore: ${r.backup} → ${r.original}`);
    console.log();
  }

  if (dryRun) {
    console.log(pc.dim('(dry run — no files written)'));
    return;
  }

  if (!autoYes) {
    process.stdout.write(pc.bold(`Restore ${toRestore.length} original config${toRestore.length > 1 ? 's' : ''}? [y/N] `));
    const answer = await new Promise<string>((resolve) => {
      process.stdin.setEncoding('utf8');
      process.stdin.resume();
      process.stdin.once('data', (data) => {
        process.stdin.pause();
        resolve(String(data).trim().toLowerCase());
      });
    });
    if (answer !== 'y' && answer !== 'yes') {
      console.log('Aborted.');
      return;
    }
  }

  for (const r of toRestore) {
    fs.copyFileSync(r.backup, r.original);
    fs.unlinkSync(r.backup);
    console.log(`${pc.green('✅')} Restored ${pc.cyan(r.original)}`);
  }

  console.log();
  console.log(pc.bold('Uninstall complete!'));
  console.log(pc.dim('Restart Claude Desktop / Claude Code to pick up the restored config.'));
}

// ─── Command: config-gen ──────────────────────────────────────────────────────

interface McpServerDef {
  command: string;
  args?:   string[];
  env?:    Record<string, string>;
}

async function cmdConfigGen(flags: string[]): Promise<void> {
  // Scans Claude Desktop / Claude Code configs, finds existing MCP servers,
  // and generates a warden.config.yaml that proxies all of them.

  let outputPath: string | undefined;
  let dryRun     = false;
  let mode       = 'audit';

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--output' || f === '-o') && flags[i + 1]) {
      outputPath = flags[++i];
    } else if (f === '--enforce') {
      mode = 'enforce';
    } else if (f === '--dry-run' || f === '-n') {
      dryRun = true;
    }
  }

  // Known config file locations (mac-focused, with linux fallback)
  const home = os.homedir();
  const candidates: Array<{ label: string; path: string }> = [
    { label: 'Claude Desktop (macOS)',  path: path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json') },
    { label: 'Claude Code (global)',    path: path.join(home, '.claude', 'settings.json') },
    { label: 'Claude Code (local)',     path: path.join(process.cwd(), '.claude', 'settings.json') },
    { label: 'Claude Desktop (Linux)',  path: path.join(home, '.config', 'Claude', 'claude_desktop_config.json') },
  ];

  const discovered: Map<string, McpServerDef> = new Map();
  const sourcedFrom: string[] = [];

  for (const { label, path: cfgPath } of candidates) {
    if (!fs.existsSync(cfgPath)) continue;

    let content: string;
    try {
      content = fs.readFileSync(cfgPath, 'utf8');
    } catch { continue; }

    let parsed: unknown;
    try {
      parsed = JSON.parse(content);
    } catch { continue; }

    if (!parsed || typeof parsed !== 'object') continue;
    const obj = parsed as Record<string, unknown>;

    // Both Claude Desktop and Claude Code use mcpServers
    const mcpServers = obj['mcpServers'] as Record<string, unknown> | undefined;
    if (!mcpServers || typeof mcpServers !== 'object') continue;

    let count = 0;
    for (const [name, def] of Object.entries(mcpServers)) {
      if (!def || typeof def !== 'object') continue;
      const d = def as Record<string, unknown>;
      if (!d['command'] || typeof d['command'] !== 'string') continue;
      // Skip if it's already a warden proxy
      if (d['command'] === 'warden' || (Array.isArray(d['args']) && d['args'][0] === 'run')) continue;

      discovered.set(name, {
        command: d['command'],
        args:    Array.isArray(d['args']) ? d['args'] as string[] : undefined,
        env:     d['env'] as Record<string, string> | undefined,
      });
      count++;
    }

    if (count > 0) {
      sourcedFrom.push(`${label} (${cfgPath}) — ${count} server${count > 1 ? 's' : ''}`);
    }
  }

  if (discovered.size === 0) {
    console.log(pc.yellow('No MCP servers found in Claude Desktop or Claude Code configs.'));
    console.log(pc.dim('  Checked:'));
    for (const { label, path: cfgPath } of candidates) {
      const exists = fs.existsSync(cfgPath);
      console.log(pc.dim(`    ${exists ? '✓' : '✗'} ${label} (${cfgPath})`));
    }
    console.log();
    console.log(`Run ${pc.cyan('warden init')} for a blank starter config instead.`);
    return;
  }

  console.log(`${pc.bold('Discovered')} ${discovered.size} MCP server${discovered.size > 1 ? 's' : ''}:`);
  for (const [name, def] of discovered) {
    console.log(`  ${pc.cyan(name)}  ${pc.dim(def.command + (def.args ? ' ' + def.args.join(' ') : ''))}`);
  }
  console.log();
  for (const src of sourcedFrom) {
    console.log(`  ${pc.dim('Source: ' + src)}`);
  }
  console.log();

  // ── Generate YAML ──────────────────────────────────────────────────────────
  const lines: string[] = [];

  lines.push(`# warden.config.yaml — generated by: warden config-gen`);
  lines.push(`# ${discovered.size} server${discovered.size > 1 ? 's' : ''} from: ${sourcedFrom.join(', ')}`);
  lines.push('');
  lines.push(`mode: ${mode}  # start with "audit" to log without blocking, switch to "enforce" when ready`);
  lines.push('');
  lines.push('servers:');

  for (const [name, def] of discovered) {
    lines.push(`  ${name}:`);
    lines.push(`    command: ${JSON.stringify(def.command)}`);
    if (def.args?.length) {
      lines.push(`    args: [${def.args.map(a => JSON.stringify(a)).join(', ')}]`);
    }
    if (def.env && Object.keys(def.env).length > 0) {
      lines.push('    env:');
      for (const [k, v] of Object.entries(def.env)) {
        lines.push(`      ${k}: ${JSON.stringify(v)}`);
      }
    }
  }

  lines.push('');
  lines.push('policy:');
  lines.push('  defaultAction: allow');
  lines.push('  rules:');
  lines.push('    # Add deny rules here. Examples:');
  lines.push('    # - tool: "*delete*"');
  lines.push('    #   action: deny');
  lines.push('    #   reason: "Deletion is irreversible"');
  lines.push('    # - tool: "filesystem/write_file"');
  lines.push('    #   action: deny');
  lines.push('    #   reason: "Writes require approval"');
  lines.push('');
  lines.push('scrubber:');
  lines.push('  enabled: true');
  lines.push('');

  const yaml = lines.join('\n');

  if (dryRun) {
    console.log(pc.bold('Generated config (dry run):'));
    console.log(pc.dim('─'.repeat(50)));
    console.log(yaml);
    return;
  }

  const dest = outputPath ?? path.resolve('warden.config.yaml');

  if (fs.existsSync(dest)) {
    console.log(pc.yellow(`⚠️  File already exists: ${dest}`));
    console.log(pc.dim('   Use --output <path> to write to a different file, or --dry-run to preview'));
    process.exit(1);
  }

  fs.writeFileSync(dest, yaml, 'utf8');
  console.log(pc.green(`✅ Config written to ${pc.cyan(dest)}`));
  console.log();
  console.log(`Next steps:`);
  console.log(`  1. Review and edit ${pc.cyan(dest)} — add deny rules for risky tools`);
  console.log(`  2. Run ${pc.cyan('warden check')} to verify downstream server connectivity`);
  console.log(`  3. Run ${pc.cyan('warden run')} and wire it into Claude (see warden --help)`);
}

// ─── Command: alert-test ──────────────────────────────────────────────────────

async function cmdAlertTest(flags: string[]): Promise<void> {
  // Sends a test webhook to all configured targets and reports status
  // Flags:
  //   --config/-c <path>   Config file to load
  //   --url/-u <url>       Send to specific URL (overrides config targets)
  //   --secret/-s <str>    HMAC secret or static token to use with --url
  //   --timeout N          HTTP timeout in ms (default 5000)
  //   --json/-j            Machine-readable output

  let configArg:  string | undefined;
  let customUrl:  string | undefined;
  let customSecret: string | undefined;
  let timeoutMs = 5_000;
  let jsonOutput = false;

  for (let i = 0; i < flags.length; i++) {
    const f = flags[i]!;
    if ((f === '--config' || f === '-c') && flags[i + 1]) {
      configArg = flags[++i];
    } else if ((f === '--url' || f === '-u') && flags[i + 1]) {
      customUrl = flags[++i];
    } else if ((f === '--secret' || f === '-s') && flags[i + 1]) {
      customSecret = flags[++i];
    } else if (f === '--timeout' && flags[i + 1]) {
      timeoutMs = parseInt(flags[++i]!, 10);
    } else if (f === '--json' || f === '-j') {
      jsonOutput = true;
    }
  }

  type Target = { url: string; secret?: string; label: string };
  const targets: Target[] = [];

  if (customUrl) {
    targets.push({ url: customUrl, secret: customSecret, label: customUrl });
  } else {
    // Load from config
    const origStderr = process.stderr.write.bind(process.stderr);
    process.stderr.write = () => true;
    let cfg: ReturnType<typeof loadConfig> | null = null;
    try {
      cfg = loadConfig(configArg);
    } catch { /* config not found */ }
    process.stderr.write = origStderr;

    if (!cfg) {
      console.error(pc.red('No config found — pass --config <path> or --url <url>'));
      process.exit(1);
    }

    const whCfg = cfg.webhook;
    if (!whCfg?.enabled) {
      console.log(pc.yellow('⚠️  Webhook is not enabled in config'));
      if (!whCfg?.targets?.length) {
        console.log(pc.dim('   No targets configured either — nothing to test'));
        process.exit(0);
      }
    }

    for (const t of whCfg?.targets ?? []) {
      targets.push({ url: t.url, secret: t.secret, label: t.url });
    }
  }

  if (targets.length === 0) {
    console.error(pc.red('No webhook targets to test'));
    process.exit(1);
  }

  const testPayload = {
    source:  'agent-warden',
    version: VERSION,
    ts:      new Date().toISOString(),
    event:   'test',
    tool:    '_alert_test',
    reason:  'Manual alert test — verifying webhook delivery',
    args:    {},
  };

  if (!jsonOutput) {
    console.log(`${pc.bold('Sending test webhook')} to ${targets.length} target${targets.length > 1 ? 's' : ''}...\n`);
  }

  type Result = {
    url: string;
    ok: boolean;
    status?: number;
    error?: string;
    durationMs: number;
  };

  const results: Result[] = [];

  for (const target of targets) {
    const start = performance.now();
    let result: Result;

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'User-Agent':   `agent-warden/${VERSION}`,
      };
      if (target.secret) {
        headers['X-Warden-Secret'] = target.secret;
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      const resp = await fetch(target.url, {
        method:  'POST',
        headers,
        body:    JSON.stringify(testPayload),
        signal:  controller.signal,
      });
      clearTimeout(timer);

      result = {
        url:        target.url,
        ok:         resp.ok,
        status:     resp.status,
        durationMs: Math.round(performance.now() - start),
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      result = {
        url:        target.url,
        ok:         false,
        error:      msg.includes('abort') ? `Timeout (>${timeoutMs}ms)` : msg,
        durationMs: Math.round(performance.now() - start),
      };
    }

    results.push(result);

    if (!jsonOutput) {
      const icon = result.ok ? pc.green('✅') : pc.red('❌');
      const dur  = pc.dim(`${result.durationMs}ms`);
      if (result.ok) {
        console.log(`${icon} ${pc.cyan(result.url)}  HTTP ${result.status}  ${dur}`);
      } else {
        const detail = result.error ?? `HTTP ${result.status ?? '?'}`;
        console.log(`${icon} ${pc.cyan(result.url)}  ${pc.red(detail)}  ${dur}`);
      }
    }
  }

  if (jsonOutput) {
    console.log(JSON.stringify({ targets: results }, null, 2));
  } else {
    console.log();
    const passed = results.filter(r => r.ok).length;
    const failed = results.filter(r => !r.ok).length;
    if (failed === 0) {
      console.log(pc.green(`✅ All ${passed} target${passed > 1 ? 's' : ''} responded successfully`));
    } else {
      console.log(pc.red(`❌ ${failed} of ${results.length} target${results.length > 1 ? 's' : ''} failed`));
      process.exit(1);
    }
  }
}

// ─── Command: validate ────────────────────────────────────────────────────────

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
      await cmdRun(argv.slice(1));
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

    case 'alert-test':
    case 'webhook-test':
      await cmdAlertTest(argv.slice(1));
      break;

    case 'config-gen':
    case 'generate':
      await cmdConfigGen(argv.slice(1));
      break;

    case 'install':
      await cmdInstall(argv.slice(1));
      break;

    case 'uninstall':
      await cmdUninstall(argv.slice(1));
      break;

    case 'server-list':
    case 'list-tools':
      await cmdServerList(argv.slice(1));
      break;

    case 'timeline':
      await cmdTimeline(argv.slice(1));
      break;

    case 'doctor':
      await cmdDoctor(argv.slice(1));
      break;

    case 'suggest':
      await cmdSuggest(argv.slice(1));
      break;

    case 'snapshot':
      await cmdSnapshot(argv.slice(1));
      break;

    case 'compare':
      await cmdCompare(argv.slice(1));
      break;

    case 'trending':
      await cmdTrending(argv.slice(1));
      break;

    case 'anomaly-score':
    case 'score':
      await cmdAnomalyScore(argv.slice(1));
      break;

    case 'replay':
      await cmdReplay(argv.slice(1));
      break;

    case 'ci-check':
      await cmdCiCheck(argv.slice(1));
      break;

    case 'profile':
      await cmdProfile(argv.slice(1));
      break;

    case 'summary':
      await cmdSummary(argv.slice(1));
      break;

    case 'heat-map':
    case 'heatmap':
      await cmdHeatMap(argv.slice(1));
      break;

    case 'export-html':
      await cmdExportHtml(argv.slice(1));
      break;

    case 'scope':
      await cmdScope(argv.slice(1));
      break;

    case 'blame':
      await cmdBlame(argv.slice(1));
      break;

    case 'session-summary':
      await cmdSessionSummary(argv.slice(1));
      break;

    case 'alert-history':
      await cmdAlertHistory(argv.slice(1));
      break;

    case 'token-estimate':
      await cmdTokenEstimate(argv.slice(1));
      break;

    case 'latency-percentiles':
    case 'latency':
      await cmdLatencyPercentiles(argv.slice(1));
      break;

    case 'policy-stats':
      await cmdPolicyStats(argv.slice(1));
      break;

    case 'archive':
      await cmdArchive(argv.slice(1));
      break;

    case 'redact-scan':
      await cmdRedactScan(argv.slice(1));
      break;

    case 'verify-integrity':
      await cmdVerifyIntegrity(argv.slice(1));
      break;

    case 'chain':
      await cmdChain(argv.slice(1));
      break;

    case 'top-denied':
      await cmdTopDenied(argv.slice(1));
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
