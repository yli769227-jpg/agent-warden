export interface ValidationIssue {
  level: 'error' | 'warning';
  path:  string;
  msg:   string;
  hint?: string;
}

export function validateConfigObject(cfg: Record<string, unknown>): ValidationIssue[] {
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
