/**
 * Unit tests for warden install / uninstall behaviour.
 *
 * We test the logic by creating temporary Claude Desktop config files
 * and running warden install / uninstall via the dist/cli.js binary
 * with HOME pointing at a temp directory.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

// ─── Helpers ──────────────────────────────────────────────────────────────────

const CLI = path.resolve(process.cwd(), 'dist', 'cli.js');

function makeTmpHome(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-install-test-${suffix}`);
  // macOS Claude Desktop path
  const claudeDir = path.join(dir, 'Library', 'Application Support', 'Claude');
  fs.mkdirSync(claudeDir, { recursive: true });
  return dir;
}

function writeClaudioCfg(homeDir: string, cfg: Record<string, unknown>): string {
  const cfgPath = path.join(homeDir, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
  fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2), 'utf8');
  return cfgPath;
}

function readJSON(filePath: string): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(filePath, 'utf8')) as Record<string, unknown>;
}

function runCLI(args: string[], homeDir: string, configDir?: string): { stdout: string; stderr: string; status: number } {
  const extraArgs = configDir ? ['--config-dir', configDir] : [];
  const r = spawnSync(process.execPath, [CLI, ...args, '--yes', ...extraArgs], {
    encoding: 'utf8',
    env: { ...process.env, HOME: homeDir },
  });
  return {
    stdout: r.stdout ?? '',
    stderr: r.stderr ?? '',
    status: r.status ?? 0,
  };
}

// ─── install ──────────────────────────────────────────────────────────────────

describe('warden install', () => {
  let homeDir: string;
  let configDir: string;

  beforeEach(() => {
    homeDir   = makeTmpHome();
    configDir = path.join(homeDir, 'warden-configs');
  });
  afterEach(() => { fs.rmSync(homeDir, { recursive: true, force: true }); });

  test('1. replaces npx server with warden proxy', () => {
    const cfgPath = writeClaudioCfg(homeDir, {
      mcpServers: {
        fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'] },
      },
    });

    const { status } = runCLI(['install'], homeDir, configDir);
    expect(status).toBe(0);

    const after = readJSON(cfgPath) as { mcpServers: Record<string, { command: string; args: string[] }> };
    expect(after.mcpServers['fs']?.command).toBe('warden');
    expect(after.mcpServers['fs']?.args[0]).toBe('run');
  });

  test('2. generates per-server warden config YAML', () => {
    writeClaudioCfg(homeDir, {
      mcpServers: {
        gh: { command: 'node', args: ['/path/to/github-mcp.js'], env: { GITHUB_TOKEN: 'tok' } },
      },
    });

    runCLI(['install'], homeDir, configDir);

    const wardenCfgPath = path.join(configDir, 'gh.yaml');
    expect(fs.existsSync(wardenCfgPath)).toBe(true);

    const content = fs.readFileSync(wardenCfgPath, 'utf8');
    expect(content).toContain('command: "node"');
    expect(content).toContain('GITHUB_TOKEN');
    expect(content).toContain('mode: audit');
  });

  test('3. creates a .warden-backup before modifying', () => {
    const cfgPath = writeClaudioCfg(homeDir, {
      mcpServers: { fs: { command: 'npx', args: [] } },
    });

    runCLI(['install'], homeDir, configDir);

    const backup = `${cfgPath}.warden-backup`;
    expect(fs.existsSync(backup)).toBe(true);

    const backupContent = readJSON(backup) as { mcpServers: Record<string, unknown> };
    // Backup has the ORIGINAL command, not warden
    const orig = backupContent.mcpServers['fs'] as { command: string } | undefined;
    expect(orig?.command).toBe('npx');
  });

  test('4. dry-run does not modify files', () => {
    const cfgPath = writeClaudioCfg(homeDir, {
      mcpServers: { fs: { command: 'npx', args: [] } },
    });
    const before = fs.readFileSync(cfgPath, 'utf8');

    const r = spawnSync(process.execPath, [CLI, 'install', '--dry-run'], {
      encoding: 'utf8',
      env: { ...process.env, HOME: homeDir },
    });

    expect(fs.readFileSync(cfgPath, 'utf8')).toBe(before);
    expect(`${r.stdout}${r.stderr}`).toMatch(/dry run/i);
  });

  test('5. skips servers already proxied by warden', () => {
    const cfgPath = writeClaudioCfg(homeDir, {
      mcpServers: {
        existing: { command: 'warden', args: ['run', '/path/to/config.yaml'] },
        fresh:    { command: 'node',   args: ['/path/to/server.js'] },
      },
    });

    runCLI(['install'], homeDir, configDir);

    const after = readJSON(cfgPath) as { mcpServers: Record<string, { command: string }> };
    // 'existing' stays as warden (unchanged)
    expect(after.mcpServers['existing']?.command).toBe('warden');
    // 'fresh' gets wrapped by a NEW warden entry
    expect(after.mcpServers['fresh']?.command).toBe('warden');
  });

  test('6. multiple servers in one config are all proxied', () => {
    const cfgPath = writeClaudioCfg(homeDir, {
      mcpServers: {
        a: { command: 'node', args: ['a.js'] },
        b: { command: 'node', args: ['b.js'] },
        c: { command: 'node', args: ['c.js'] },
      },
    });

    runCLI(['install'], homeDir, configDir);

    const after = readJSON(cfgPath) as { mcpServers: Record<string, { command: string }> };
    expect(after.mcpServers['a']?.command).toBe('warden');
    expect(after.mcpServers['b']?.command).toBe('warden');
    expect(after.mcpServers['c']?.command).toBe('warden');

    expect(fs.existsSync(path.join(configDir, 'a.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(configDir, 'b.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(configDir, 'c.yaml'))).toBe(true);
  });

  test('7. no-config: exits cleanly with informative message', () => {
    // No Claude config file in homeDir
    const r = runCLI(['install'], homeDir, configDir);
    expect(`${r.stdout}${r.stderr}`).toMatch(/no claude|not found|config-gen/i);
  });
});

// ─── uninstall ────────────────────────────────────────────────────────────────

describe('warden uninstall', () => {
  let homeDir: string;
  let configDir: string;

  beforeEach(() => {
    homeDir   = makeTmpHome();
    configDir = path.join(homeDir, 'warden-configs');
  });
  afterEach(() => { fs.rmSync(homeDir, { recursive: true, force: true }); });

  test('8. restores original config from backup', () => {
    const original = {
      mcpServers: { fs: { command: 'npx', args: ['-y', 'server'] } },
    };
    const cfgPath = writeClaudioCfg(homeDir, original);

    // Install first
    runCLI(['install'], homeDir, configDir);

    // Verify it changed
    const after = readJSON(cfgPath) as { mcpServers: Record<string, { command: string }> };
    expect(after.mcpServers['fs']?.command).toBe('warden');

    // Uninstall
    const { status } = runCLI(['uninstall'], homeDir, configDir);
    expect(status).toBe(0);

    // Should be restored to original
    const restored = readJSON(cfgPath) as typeof original;
    expect(restored.mcpServers['fs'].command).toBe('npx');
  });

  test('9. deletes backup file after successful restore', () => {
    const cfgPath = writeClaudioCfg(homeDir, {
      mcpServers: { fs: { command: 'npx', args: [] } },
    });

    runCLI(['install'], homeDir, configDir);
    const backup = `${cfgPath}.warden-backup`;
    expect(fs.existsSync(backup)).toBe(true);

    runCLI(['uninstall'], homeDir, configDir);
    expect(fs.existsSync(backup)).toBe(false);
  });

  test('10. no backups: exits cleanly with informative message', () => {
    const r = runCLI(['uninstall'], homeDir, configDir);
    expect(`${r.stdout}${r.stderr}`).toMatch(/no.*backup|nothing to uninstall/i);
  });

  test('11. dry-run does not restore files', () => {
    const cfgPath = writeClaudioCfg(homeDir, {
      mcpServers: { fs: { command: 'npx', args: [] } },
    });

    runCLI(['install'], homeDir, configDir);
    const afterInstall = fs.readFileSync(cfgPath, 'utf8');

    const r = spawnSync(process.execPath, [CLI, 'uninstall', '--dry-run'], {
      encoding: 'utf8',
      env: { ...process.env, HOME: homeDir },
    });

    // File should still show warden (not restored)
    expect(fs.readFileSync(cfgPath, 'utf8')).toBe(afterInstall);
    expect(`${r.stdout}${r.stderr}`).toMatch(/dry run/i);
  });
});
