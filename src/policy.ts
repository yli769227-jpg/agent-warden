/**
 * Policy engine for agent-warden.
 *
 * Decides allow/deny for each tools/call invocation.  Evaluation order:
 *
 *   1. Explicit rules (first match wins, `*` glob supported)
 *   2. Built-in dangerous patterns
 *      - Dangerous name keywords  → always flag; audit=warn+allow, enforce=deny
 *      - Filesystem-write tools with out-of-cwd path args → same treatment
 *   3. Config `defaultAction` fall-through
 *
 * All decisions are emitted to stderr as:
 *   [warden:policy] <allow|DENY> <toolName> — <reason>
 */

import path from 'node:path';
import { PolicyConfig, PolicyRule } from './types.js';

// ---------------------------------------------------------------------------
// Public interfaces
// ---------------------------------------------------------------------------

export interface PolicyEngine {
  evaluate(toolName: string, args: unknown): PolicyDecision;
}

export interface PolicyDecision {
  action: 'allow' | 'deny';
  reason: string;
  isDangerous: boolean;
}

// ---------------------------------------------------------------------------
// Built-in dangerous patterns
// ---------------------------------------------------------------------------

/**
 * Tool names containing any of these keywords (case-insensitive substring
 * match) are treated as dangerous.
 */
const DANGEROUS_NAME_KEYWORDS: readonly string[] = [
  'delete',
  'remove',
  'drop',
  'truncate',
  'destroy',
  'wipe',
  'purge',
  'exec',
  'execute',
  'run',
  'shell',
  'bash',
  'eval',
];

/**
 * Exact tool names that perform filesystem writes and are subject to the
 * out-of-cwd path check.
 */
const FS_WRITE_EXACT_NAMES: ReadonlySet<string> = new Set([
  'write_file',
  'create_file',
  'edit_file',
  'move_file',
]);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Minimal glob matcher.  Only `*` (zero or more of any character) is
 * supported as a wildcard.  The match is case-sensitive.
 *
 * Examples:
 *   globMatch('*delete*', 'bash_delete_files') → true
 *   globMatch('write_file', 'write_file')       → true
 *   globMatch('*_write', 'file_write')          → true
 *   globMatch('*_create', 'table_create')       → true
 */
function globMatch(pattern: string, value: string): boolean {
  // 1. Escape regex metacharacters (all except *).
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  // 2. Replace literal * with .* to form a regex.
  const regexStr = escaped.split('*').join('.*');
  return new RegExp(`^${regexStr}$`).test(value);
}

/**
 * Returns true when `toolName` (case-insensitive) contains one of the
 * built-in dangerous name keywords.
 */
function hasDangerousNameKeyword(toolName: string): boolean {
  const lower = toolName.toLowerCase();
  return DANGEROUS_NAME_KEYWORDS.some(kw => lower.includes(kw));
}

/**
 * Returns true when `toolName` matches the filesystem-write pattern set:
 *   - One of the exact names in FS_WRITE_EXACT_NAMES
 *   - Any name ending in `_write` or `_create`
 */
function isFsWriteToolName(toolName: string): boolean {
  return (
    FS_WRITE_EXACT_NAMES.has(toolName) ||
    toolName.endsWith('_write') ||
    toolName.endsWith('_create')
  );
}

/**
 * Recursively extracts every string leaf from an arbitrary value.
 * Depth-limited to 6 levels to avoid DoS on deeply nested args.
 */
function extractStrings(value: unknown, depth = 0): string[] {
  if (depth > 6) return [];
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) {
    return value.flatMap(v => extractStrings(v, depth + 1));
  }
  if (value !== null && typeof value === 'object') {
    return Object.values(value as Record<string, unknown>).flatMap(v =>
      extractStrings(v, depth + 1),
    );
  }
  return [];
}

/**
 * Returns true when `filePath` resolves to a location that is NOT inside
 * (or equal to) `cwd`.
 */
function isOutsideCwd(filePath: string, cwd: string): boolean {
  const resolved = path.isAbsolute(filePath)
    ? path.normalize(filePath)
    : path.resolve(cwd, filePath);
  const normalizedCwd = path.resolve(cwd);
  return (
    resolved !== normalizedCwd &&
    !resolved.startsWith(normalizedCwd + path.sep)
  );
}

/**
 * Heuristic: a string value that contains `/` or `\` is treated as a
 * potential file path.  Returns true when at least one such value in `args`
 * resolves outside `cwd`.
 */
function argsContainOutsideCwdPath(args: unknown, cwd: string): boolean {
  return extractStrings(args).some(s => {
    // Ignore strings that don't look like file paths.
    if (!s.includes('/') && !s.includes('\\')) return false;
    return isOutsideCwd(s, cwd);
  });
}

/** Emit a single decision line to stderr in the standard warden format. */
function logDecision(
  action: 'allow' | 'DENY',
  toolName: string,
  reason: string,
): void {
  process.stderr.write(`[warden:policy] ${action} ${toolName} — ${reason}\n`);
}

// ---------------------------------------------------------------------------
// Public factory
// ---------------------------------------------------------------------------

export function createPolicyEngine(config: PolicyConfig): PolicyEngine {
  const cwd = config.cwd ?? process.cwd();

  return {
    evaluate(toolName: string, args: unknown): PolicyDecision {
      // ── 1. Explicit rules (first match wins) ─────────────────────────────
      for (const rule of config.rules ?? []) {
        if (globMatch(rule.tool, toolName)) {
          const reason =
            rule.reason ??
            `matched explicit rule for tool "${rule.tool}"`;
          const { action } = rule;
          logDecision(action === 'allow' ? 'allow' : 'DENY', toolName, reason);
          return { action, reason, isDangerous: false };
        }
      }

      // ── 2. Built-in dangerous patterns ───────────────────────────────────
      // Multi-server mode registers tools as "<server>/<tool>" (see proxy.ts).
      // The built-in name heuristics match on the bare tool name, so strip any
      // server prefix first — otherwise "filesystem/write_file" matches neither
      // the exact fs-write set nor the "*_write"/"*_create" suffix and the
      // out-of-cwd write protection never runs. Explicit rules above still
      // match the full prefixed name.
      const baseName = toolName.includes('/')
        ? toolName.slice(toolName.lastIndexOf('/') + 1)
        : toolName;
      const dangerousName = hasDangerousNameKeyword(baseName);
      const dangerousFs =
        isFsWriteToolName(baseName) &&
        argsContainOutsideCwdPath(args, cwd);

      if (dangerousName || dangerousFs) {
        const dangerDescription = dangerousName
          ? `tool name matches dangerous keyword`
          : `filesystem write targets path outside cwd (${cwd})`;

        if (config.mode === 'enforce') {
          const reason = `${dangerDescription} — denied in enforce mode`;
          logDecision('DENY', toolName, reason);
          return { action: 'deny', reason, isDangerous: true };
        }

        // audit mode: allow but surface the warning via isDangerous=true
        const reason = `${dangerDescription} — WARNING: allowed in audit mode`;
        logDecision('allow', toolName, reason);
        return { action: 'allow', reason, isDangerous: true };
      }

      // ── 3. Default fall-through ───────────────────────────────────────────
      const reason = `no rule matched — defaultAction=${config.defaultAction}`;
      logDecision(
        config.defaultAction === 'allow' ? 'allow' : 'DENY',
        toolName,
        reason,
      );
      return {
        action: config.defaultAction,
        reason,
        isDangerous: false,
      };
    },
  };
}
