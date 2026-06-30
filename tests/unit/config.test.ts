import fs from 'fs';
import os from 'os';
import path from 'path';
import { loadConfig, resolveConfigPath, DEFAULT_CONFIG } from '../../src/config.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeTmpDir(): string {
  const suffix = Math.random().toString(36).slice(2);
  const dir = path.join(os.tmpdir(), `warden-config-test-${suffix}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

/** Write `content` as a YAML file inside `dir` and return the full path. */
function writeTmpYaml(dir: string, content: string): string {
  const file = path.join(dir, `config-${Date.now()}.yaml`);
  fs.writeFileSync(file, content, 'utf8');
  return file;
}

// ─── loadConfig ───────────────────────────────────────────────────────────────

describe('loadConfig', () => {
  let tmpDir: string;
  let savedWardenConfig: string | undefined;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    savedWardenConfig = process.env['WARDEN_CONFIG'];
    delete process.env['WARDEN_CONFIG'];
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    if (savedWardenConfig === undefined) {
      delete process.env['WARDEN_CONFIG'];
    } else {
      process.env['WARDEN_CONFIG'] = savedWardenConfig;
    }
  });

  test('1. valid YAML file — returns WardenConfig with correct values', () => {
    const file = writeTmpYaml(
      tmpDir,
      `
mode: enforce
logFile: /tmp/my-audit.jsonl
downstreamCommand:
  - npx
  - -y
  - "@modelcontextprotocol/server-filesystem"
  - /my/allowed/path
policy:
  defaultAction: deny
scrubber:
  enabled: false
`,
    );

    const config = loadConfig(file);

    expect(config.mode).toBe('enforce');
    expect(config.logFile).toBe('/tmp/my-audit.jsonl');
    expect(config.downstreamCommand).toEqual([
      'npx',
      '-y',
      '@modelcontextprotocol/server-filesystem',
      '/my/allowed/path',
    ]);
    expect(config.policy.defaultAction).toBe('deny');
    expect(config.scrubber.enabled).toBe(false);
  });

  test('2. missing downstreamCommand — throws descriptive error', () => {
    const file = writeTmpYaml(
      tmpDir,
      `
mode: audit
logFile: /tmp/audit.jsonl
`,
    );

    expect(() => loadConfig(file)).toThrow(/\[warden:config\]/);
    expect(() => loadConfig(file)).toThrow(/downstreamCommand/);
    expect(() => loadConfig(file)).toThrow(/missing or empty/);
  });

  test('3. partial config merges with defaults — gets default logFile and policy', () => {
    const file = writeTmpYaml(
      tmpDir,
      `
downstreamCommand:
  - node
  - server.js
`,
    );

    const config = loadConfig(file);

    // DEFAULT_CONFIG.logFile is '~/.warden/audit.jsonl'; tilde is expanded on load
    expect(config.logFile).toBe(path.join(os.homedir(), '.warden', 'audit.jsonl'));
    // Default policy.defaultAction from DEFAULT_CONFIG
    expect(config.policy.defaultAction).toBe(DEFAULT_CONFIG.policy.defaultAction);
    // Default mode from DEFAULT_CONFIG
    expect(config.mode).toBe(DEFAULT_CONFIG.mode);
    // Explicitly supplied command is preserved
    expect(config.downstreamCommand).toEqual(['node', 'server.js']);
  });

  test('6. tilde expansion in logFile — ~/some/path expands to absolute path', () => {
    const file = writeTmpYaml(
      tmpDir,
      `
downstreamCommand:
  - node
  - server.js
logFile: ~/some/path/audit.jsonl
`,
    );

    const config = loadConfig(file);

    expect(config.logFile).toBe(path.join(os.homedir(), 'some', 'path', 'audit.jsonl'));
    expect(config.logFile).not.toMatch(/^~/);
  });

  test('7. non-existent file — throws with clear message including the path', () => {
    const nonExistent = path.join(tmpDir, 'does-not-exist.yaml');

    expect(() => loadConfig(nonExistent)).toThrow(/\[warden:config\]/);
    expect(() => loadConfig(nonExistent)).toThrow(nonExistent);
  });
});

// ─── resolveConfigPath ────────────────────────────────────────────────────────

describe('resolveConfigPath', () => {
  let savedWardenConfig: string | undefined;

  beforeEach(() => {
    savedWardenConfig = process.env['WARDEN_CONFIG'];
  });

  afterEach(() => {
    if (savedWardenConfig === undefined) {
      delete process.env['WARDEN_CONFIG'];
    } else {
      process.env['WARDEN_CONFIG'] = savedWardenConfig;
    }
  });

  test('4. WARDEN_CONFIG env var set — returns that path (resolved to absolute)', () => {
    const envPath = '/custom/path/warden.yaml';
    process.env['WARDEN_CONFIG'] = envPath;

    expect(resolveConfigPath()).toBe(path.resolve(envPath));
  });

  test('5. no env var and no local warden.config.yaml — returns ~/.warden/config.yaml', () => {
    delete process.env['WARDEN_CONFIG'];

    // Only assert the home fallback when the local sentinel does not exist;
    // if someone placed a warden.config.yaml in the project root the function
    // would legitimately return that path instead.
    const localPath = path.resolve(process.cwd(), 'warden.config.yaml');
    if (fs.existsSync(localPath)) {
      expect(resolveConfigPath()).toBe(localPath);
    } else {
      expect(resolveConfigPath()).toBe(path.join(os.homedir(), '.warden', 'config.yaml'));
    }
  });
});
