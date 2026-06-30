/**
 * Configuration loading and resolution for agent-warden.
 *
 * Resolution order for the config file path:
 *   1. Explicit argument passed to loadConfig()
 *   2. WARDEN_CONFIG environment variable
 *   3. ./warden.config.yaml  (cwd)
 *   4. ~/.warden/config.yaml (home fallback)
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { load as yamlLoad, YAMLException } from 'js-yaml';
import type { WardenConfig } from './types.js';

// ─── Defaults ────────────────────────────────────────────────────────────────

/**
 * Sensible defaults merged underneath every loaded config.
 * Either `servers` or `downstreamCommand` MUST be supplied in the config file;
 * loadConfig() will throw a descriptive error if both are absent/empty.
 */
export const DEFAULT_CONFIG: WardenConfig = {
  mode: 'audit',
  logFile: '~/.warden/audit.jsonl',
  policy: {
    defaultAction: 'allow',
  },
  scrubber: {
    enabled: true,
  },
};

// ─── Path resolution ─────────────────────────────────────────────────────────

/**
 * Returns the absolute path of the config file to load, without reading it.
 *
 * Checks (in order):
 *   1. `WARDEN_CONFIG` environment variable
 *   2. `./warden.config.yaml` relative to cwd (only if the file exists)
 *   3. `~/.warden/config.yaml`
 */
export function resolveConfigPath(): string {
  const envPath = process.env['WARDEN_CONFIG'];
  if (envPath) {
    return path.resolve(envPath);
  }

  const localPath = path.resolve(process.cwd(), 'warden.config.yaml');
  if (fs.existsSync(localPath)) {
    return localPath;
  }

  return path.join(os.homedir(), '.warden', 'config.yaml');
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Expand a leading `~` to the user's home directory. */
function expandTilde(filePath: string): string {
  if (filePath === '~') {
    return os.homedir();
  }
  if (filePath.startsWith('~/') || filePath.startsWith('~\\')) {
    return path.join(os.homedir(), filePath.slice(2));
  }
  return filePath;
}

/**
 * Expands `${VAR}` and `$VAR` references in a string using `process.env`.
 * Unrecognised variable names are left as-is (not replaced with empty string).
 */
function expandEnvVars(value: string): string {
  // ${VAR} form
  let result = value.replace(/\$\{([^}]+)\}/g, (_match, name: string) => {
    return process.env[name] ?? _match;
  });
  // $VAR form (word boundary — must come after ${} to avoid double-expanding)
  result = result.replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, (_match, name: string) => {
    return process.env[name] ?? _match;
  });
  return result;
}

/**
 * Recursively expands `${VAR}` / `$VAR` in string leaves of a plain-object tree.
 * Mutates strings inside the object but does not replace top-level non-objects.
 */
function expandEnvVarsInObject(obj: Record<string, unknown>): void {
  for (const key of Object.keys(obj)) {
    const val = obj[key];
    if (typeof val === 'string') {
      obj[key] = expandEnvVars(val);
    } else if (isPlainObject(val)) {
      expandEnvVarsInObject(val as Record<string, unknown>);
    }
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Recursively merges `override` into `base`, returning a new object.
 * Plain-object values at the same key are merged depth-first; all other
 * values (arrays, primitives, null) in `override` replace those in `base`.
 */
function deepMerge(
  base: Record<string, unknown>,
  override: Record<string, unknown>,
): Record<string, unknown> {
  const result: Record<string, unknown> = { ...base };
  for (const key of Object.keys(override)) {
    const overrideVal = override[key];
    const baseVal = base[key];
    if (isPlainObject(overrideVal) && isPlainObject(baseVal)) {
      result[key] = deepMerge(baseVal, overrideVal);
    } else if (overrideVal !== undefined) {
      result[key] = overrideVal;
    }
  }
  return result;
}

// ─── Main loader ─────────────────────────────────────────────────────────────

/**
 * Reads a warden config YAML file, deep-merges it with DEFAULT_CONFIG, and
 * returns the resulting WardenConfig.
 *
 * @param configPath - Absolute or relative path to the YAML file.
 *   Defaults to resolveConfigPath() when omitted.
 *
 * @throws {Error} If the file cannot be read, contains YAML parse errors, or
 *   is missing the required `downstreamCommand` field.
 */
export function loadConfig(configPath?: string): WardenConfig {
  const resolvedPath = configPath != null ? path.resolve(configPath) : resolveConfigPath();

  // ── Read file ──────────────────────────────────────────────────────────────
  let rawContent: string;
  try {
    rawContent = fs.readFileSync(resolvedPath, 'utf8');
  } catch (err) {
    const nodeErr = err as NodeJS.ErrnoException;
    throw new Error(
      `[warden:config] Cannot read config file at "${resolvedPath}": ${nodeErr.message}`,
    );
  }

  // ── Parse YAML ────────────────────────────────────────────────────────────
  // js-yaml v4 exposes `load` (not `parseDocument`); it throws YAMLException
  // on malformed input and returns null for an empty document.
  let parsed: Record<string, unknown>;
  try {
    parsed = (yamlLoad(rawContent) ?? {}) as Record<string, unknown>;
  } catch (err) {
    if (err instanceof YAMLException) {
      throw new Error(
        `[warden:config] YAML parse error in "${resolvedPath}": ${err.message}`,
      );
    }
    throw err;
  }

  // ── Deep-merge with defaults ───────────────────────────────────────────────
  const merged = deepMerge(
    DEFAULT_CONFIG as unknown as Record<string, unknown>,
    parsed,
  ) as unknown as WardenConfig;

  // ── Validate required fields ───────────────────────────────────────────────
  const hasServers =
    merged.servers != null && Object.keys(merged.servers).length > 0;
  const hasLegacyCommand =
    Array.isArray(merged.downstreamCommand) &&
    (merged.downstreamCommand as string[]).length > 0;

  if (!hasServers && !hasLegacyCommand) {
    throw new Error(
      `[warden:config] No downstream server configured in "${resolvedPath}".\n` +
        'Provide either a "servers" map (recommended):\n' +
        '  servers:\n' +
        '    filesystem:\n' +
        '      command: npx\n' +
        '      args: ["-y", "@modelcontextprotocol/server-filesystem", "/path"]\n' +
        'Or the legacy single-server "downstreamCommand" array:\n' +
        '  downstreamCommand:\n' +
        '    - npx\n' +
        '    - -y\n' +
        '    - "@modelcontextprotocol/server-filesystem"\n' +
        '    - /your/allowed/path',
    );
  }

  // ── Expand ~ in logFile ────────────────────────────────────────────────────
  if (merged.logFile) {
    merged.logFile = expandTilde(merged.logFile);
  }

  // ── Expand ${VAR} in server env values ────────────────────────────────────
  // Example: GITHUB_TOKEN: "${GITHUB_TOKEN}" → resolved from process.env
  if (merged.servers) {
    for (const serverCfg of Object.values(merged.servers)) {
      if (serverCfg.env) {
        expandEnvVarsInObject(serverCfg.env as unknown as Record<string, unknown>);
      }
    }
  }

  // ── Expand ${VAR} in webhook target URLs / secrets ────────────────────────
  if (merged.webhook?.targets) {
    for (const target of merged.webhook.targets) {
      const t = target as Record<string, unknown>;
      expandEnvVarsInObject(t);
    }
  }

  // ── Debug log ──────────────────────────────────────────────────────────────
  process.stderr.write(`[warden:config] Loaded config from ${resolvedPath}\n`);

  return merged;
}
