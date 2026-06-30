/**
 * Unit tests for `warden bench` — in-process policy+scrubber micro-benchmark.
 *
 * bench does not need a log file or an MCP server; it synthesises its own
 * payload and runs entirely in-process.
 */

import { spawnSync } from 'node:child_process';
import path from 'node:path';

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function runBench(args: string[]): { stdout: string; stderr: string; status: number } {
  const r = spawnSync(process.execPath, [CLI, 'bench', ...args], { encoding: 'utf8' });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status ?? 0 };
}

describe('warden bench', () => {
  test('1. exits 0 with default args', () => {
    const { status } = runBench([]);
    expect(status).toBe(0);
  }, 15_000);

  test('2. text output contains mean/p50/p95/p99', () => {
    const { stdout, stderr } = runBench(['--iterations', '10']);
    const out = stdout + stderr;
    expect(out).toMatch(/mean/i);
    expect(out).toMatch(/p50/i);
    expect(out).toMatch(/p95/i);
    expect(out).toMatch(/p99/i);
  }, 15_000);

  test('3. --json produces valid JSON with all required fields', () => {
    const { stdout, status } = runBench(['--iterations', '10', '--json']);
    expect(status).toBe(0);
    let parsed: Record<string, unknown>;
    expect(() => { parsed = JSON.parse(stdout); }).not.toThrow();
    const result = JSON.parse(stdout) as Record<string, unknown>;
    expect(typeof result['iterations']).toBe('number');
    expect(typeof result['mean_ms']).toBe('number');
    expect(typeof result['p50_ms']).toBe('number');
    expect(typeof result['p95_ms']).toBe('number');
    expect(typeof result['p99_ms']).toBe('number');
    expect(typeof result['min_ms']).toBe('number');
    expect(typeof result['max_ms']).toBe('number');
  }, 15_000);

  test('4. --iterations count matches JSON output', () => {
    const { stdout } = runBench(['--iterations', '7', '--json']);
    const result = JSON.parse(stdout) as Record<string, unknown>;
    expect(result['iterations']).toBe(7);
  }, 15_000);

  test('5. --json output contains the tool name', () => {
    const { stdout } = runBench(['--iterations', '5', '--tool', 'my/custom_tool', '--json']);
    const result = JSON.parse(stdout) as Record<string, unknown>;
    expect(result['tool']).toBe('my/custom_tool');
  }, 15_000);

  test('6. mean_ms is a reasonable latency (< 100ms per call)', () => {
    const { stdout } = runBench(['--iterations', '20', '--json']);
    const result = JSON.parse(stdout) as { mean_ms: number };
    // Policy evaluation + scrubbing should be well under 100ms on any modern machine
    expect(result.mean_ms).toBeLessThan(100);
  }, 30_000);

  test('7. p99 >= p50 (timing distribution is monotonic)', () => {
    const { stdout } = runBench(['--iterations', '20', '--json']);
    const result = JSON.parse(stdout) as { p50_ms: number; p99_ms: number };
    expect(result.p99_ms).toBeGreaterThanOrEqual(result.p50_ms);
  }, 15_000);

  test('8. text output shows "Overhead grade"', () => {
    const { stdout } = runBench(['--iterations', '10']);
    expect(stdout).toMatch(/overhead grade/i);
  }, 15_000);
});
