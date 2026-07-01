/**
 * Regression tests for the export-html stored-XSS fix (Critical).
 *
 * Tool names / reasons / args in the audit log originate from downstream MCP
 * servers and are attacker-influenced. They must not be able to (a) break out
 * of the inline <script> data block via "</script>", nor (b) inject markup
 * through the client-side innerHTML sinks.
 *
 * Requires a prior `npm run build` (reads dist/cli.js), matching the sibling
 * export-html.test.ts harness.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-xss-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

const PAYLOAD_TOOL = 'evil</script><img src=x onerror=alert(1)>';
const PAYLOAD_REASON = 'blocked <script>alert(2)</script>';

describe('export-html XSS hardening', () => {
  let tmpDir: string;
  let logFile: string;
  let outFile: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    logFile = path.join(tmpDir, 'audit.jsonl');
    outFile = path.join(tmpDir, 'report.html');
    const entries = [
      { ts: '2026-01-01T10:00:00.000Z', tool: PAYLOAD_TOOL, verdict: 'deny', durationMs: 5, reason: PAYLOAD_REASON, args: { note: '<b>x</b>' } },
      { ts: '2026-01-01T10:01:00.000Z', tool: 'fs/read_file', verdict: 'allow', durationMs: 10 },
    ];
    fs.writeFileSync(logFile, entries.map(e => JSON.stringify(e)).join('\n') + '\n', 'utf8');
    const r = spawnSync(process.execPath, [CLI, 'export-html', '--output', outFile], {
      encoding: 'utf8',
      env: { ...process.env, WARDEN_LOG: logFile },
    });
    expect(r.status).toBe(0);
  });
  afterEach(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  test('malicious tool name cannot break out of the inline <script> data block', () => {
    const html = fs.readFileSync(outFile, 'utf8');
    // The payload must never appear as a real closing tag + injected markup.
    expect(html).not.toContain('</script><img');
    // It must survive in neutralized < form inside the data block.
    expect(html).toContain('\\u003c/script\\u003e');
  });

  test('raw injected markup does not appear verbatim anywhere in the output', () => {
    const html = fs.readFileSync(outFile, 'utf8');
    expect(html).not.toContain('<img src=x onerror=alert(1)>');
    expect(html).not.toContain('<script>alert(2)</script>');
  });

  test('report still renders the expected structure', () => {
    const html = fs.readFileSync(outFile, 'utf8');
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('const ROWS=');
  });
});
