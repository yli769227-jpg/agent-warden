/**
 * Regression test: `warden tool-graph` must not let a tool name with a quote
 * inject arbitrary DOT node attributes (Low finding). Requires a prior build.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-tg-inj-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

describe('tool-graph DOT injection hardening', () => {
  let tmpDir: string;
  let logFile: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    logFile = path.join(tmpDir, 'audit.jsonl');
    const evil = 'evil" color="red" xlabel="pwn';
    const entries = [
      { ts: '2026-01-01T10:00:00.000Z', tool: evil, verdict: 'allow', durationMs: 5 },
      { ts: '2026-01-01T10:01:00.000Z', tool: 'fs/read', verdict: 'allow', durationMs: 5 },
      { ts: '2026-01-01T10:02:00.000Z', tool: evil, verdict: 'allow', durationMs: 5 },
    ];
    fs.writeFileSync(logFile, entries.map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');
  });
  afterEach(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  test('quote in a tool name is escaped, not injected as DOT attributes', () => {
    const r = spawnSync(process.execPath, [CLI, 'tool-graph', '--since', '2026-01-01'], {
      encoding: 'utf8',
      env: { ...process.env, WARDEN_LOG: logFile },
    });
    expect(r.status).toBe(0);
    const dot = r.stdout ?? '';
    // The injected attribute must not appear as live DOT (unescaped quote+attr).
    expect(dot).not.toContain('" color="red"');
    // The quote from the tool name must be backslash-escaped in the output.
    expect(dot).toContain('evil\\"');
  });
});
