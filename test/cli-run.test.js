// End-to-end CLI behaviour for increment 5: --settings, --fail-on, filters, placeholders, npm pack allowlist.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.dirname(here);
const projects = path.join(here, 'fixtures/projects');
const cli = (args, opts = {}) => spawnSync(process.execPath, [path.join(root, 'bin/hook-replay.js'), '--projects-dir', projects, '--allow-network', ...args],
  { encoding: 'utf8', cwd: root, ...opts });
const tmpDir = (t) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-cli-')); t.after(() => fs.rmSync(d, { recursive: true, force: true })); return d; };
const denyRm = ['--hook', `node ${root}/examples/hooks/deny-rm.js`, '--event', 'PreToolUse', '--matcher', 'Bash'];

test('--fail-on exits 4 when a listed outcome occurred, 0 otherwise; an unknown outcome is a usage error', () => {
  assert.equal(cli([...denyRm, '--json', '--fail-on', 'block']).status, 4);
  assert.equal(cli([...denyRm, '--json', '--fail-on', 'stop,timeout']).status, 0);
  assert.equal(cli([...denyRm, '--fail-on', 'nonsense']).status, 2);
});

test('--settings runs every hook of a settings file and reports each', (t) => {
  const d = tmpDir(t);
  const f = path.join(d, 'settings.json');
  fs.writeFileSync(f, JSON.stringify({ hooks: {
    PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: `node ${root}/examples/hooks/deny-rm.js` }] }],
    PostToolUse: [{ matcher: 'Edit|Write', hooks: [{ type: 'command', command: 'sh', args: [`${root}/examples/hooks/post-generated.sh`] }] }],
    SessionStart: [{ hooks: [{ type: 'command', command: 'true' }] }],
  } }));
  const r = cli(['--settings', f, '--json']);
  assert.equal(r.status, 0, r.stderr);
  const m = JSON.parse(r.stdout);
  assert.deepEqual(m.hooks.map(h => [h.id, h.event, h.runs, h.counts.block]), [['h1', 'PreToolUse', 23, 3], ['h2', 'PostToolUse', 2, 1]]);
  assert.ok(m.warnings.some(w => /SessionStart/.test(w)));
});

test('exec-form placeholders resolve to --plugin-root and --project-dir; CLAUDE_* are exported to shell form', (t) => {
  const d = tmpDir(t);
  fs.mkdirSync(path.join(d, 'plug'));
  fs.writeFileSync(path.join(d, 'plug', 'h.sh'), '#!/bin/sh\ncat >/dev/null\necho "{\\"systemMessage\\":\\"root=$1 proj=$CLAUDE_PROJECT_DIR data=$CLAUDE_PLUGIN_DATA replay=$CLAUDE_HOOK_REPLAY\\"}"\n');
  const f = path.join(d, 'hooks.json');
  fs.writeFileSync(f, JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: 'command', command: 'sh', args: ['${CLAUDE_PLUGIN_ROOT}/h.sh', '${CLAUDE_PLUGIN_ROOT}'] }] }] } }));
  const r = cli(['--settings', f, '--plugin-root', path.join(d, 'plug'), '--project-dir', d, '--session', 'aaaaaaaa-0000-4000-8000-000000000001', '--json', '--show-raw']);
  assert.equal(r.status, 0, r.stderr);
  const s = JSON.parse(r.stdout).hooks[0].samples[0];
  assert.match(s.reason, new RegExp(`^root=${path.join(d, 'plug')} proj=${d} data=/.*hook-replay-[^/]+/work/plugin-data replay=1$`));
  assert.equal(cli(['--settings', f, '--dry-run']).status, 2, 'refused without --plugin-root');
});

test('--session, --project, --since and --limit filter what runs; the JSON config records them', () => {
  const one = JSON.parse(cli([...denyRm, '--json', '--session', 'aaaaaaaa-0000-4000-8000-000000000001']).stdout);
  assert.equal(one.hooks[0].runs, 4);
  assert.equal(one.config.filters.session, 'aaaaaaaa-0000-4000-8000-000000000001');
  assert.equal(JSON.parse(cli([...denyRm, '--json', '--project', 'no-such-project']).stdout).hooks[0].runs, 0);
  assert.equal(JSON.parse(cli([...denyRm, '--json', '--since', '2026-10-04T00:00:00Z']).stdout).hooks[0].runs, 16);
  const lim = JSON.parse(cli([...denyRm, '--json', '--limit', '3']).stdout);
  assert.deepEqual([lim.hooks[0].runs, lim.hooks[0].truncated, lim.config.limit], [3, true, 3]);
});

test('--no-subagents drops subagent files and isSidechain lines', () => {
  const m = JSON.parse(cli([...denyRm, '--json', '--no-subagents']).stdout);
  assert.equal(m.hooks[0].runs, 21);
});

test('npm pack ships only the files allowlist (no test fixtures)', () => {
  const r = spawnSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: root, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const files = JSON.parse(r.stdout)[0].files.map(f => f.path);
  assert.ok(files.includes('bin/hook-replay.js') && files.includes('examples/hooks/deny-rm.js'));
  for (const f of files) assert.match(f, /^(bin\/|src\/|examples\/|docs\/|README\.md$|LICENSE$|package\.json$)/, f);
});

test('--out into a missing directory is a usage error before anything runs', (t) => {
  const d = tmpDir(t);
  const r = cli([...denyRm, '--out', path.join(d, 'no-such-dir', 'report.json')]);
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, /--out/);
  assert.doesNotMatch(r.stderr, /replay EXECUTES/, 'no hook ran');
});

test('--help lists every option with a description', async () => {
  const { OPTIONS } = await import('../src/cli.js');
  const r = cli(['--help']);
  assert.equal(r.status, 0);
  for (const name of Object.keys(OPTIONS)) assert.match(r.stdout, new RegExp(`^\\s+(-\\w, )?--${name}\\b.*\\S+\\s{2,}\\S`, 'm'), `--${name}`);
});

test('--dry-run says when --limit truncated the point set', () => {
  const human = cli([...denyRm, '--dry-run', '--limit', '3']);
  assert.equal(human.status, 0, human.stderr);
  assert.match(human.stdout, /h1 truncated by --limit 3: 3 of 23 matching points selected/);
  const json = JSON.parse(cli([...denyRm, '--dry-run', '--json', '--limit', '3']).stdout);
  assert.deepEqual([json.hooks[0].truncated, json.hooks[0].points, json.hooks[0].matched], [true, 3, 23]);
  assert.doesNotMatch(cli([...denyRm, '--dry-run']).stdout, /truncated/);
});

const sandboxed = (args) => spawnSync(process.execPath, [path.join(root, 'bin/hook-replay.js'), '--projects-dir', projects,
  '--session', 'cccccccc-0000-4000-8000-000000000003', '--hook', 'true', '--event', 'PreToolUse', '--json', ...args], { encoding: 'utf8', cwd: root });
const noBwrap = spawnSync('bwrap', ['--version']).error ? 'bwrap is not installed' : false;

test('the filesystem is read-only by default; --writable-fs opts out with a warning; --readonly-fs is a deprecated no-op', { skip: noBwrap }, () => {
  const def = sandboxed([]);
  assert.equal(def.status, 0, def.stderr);
  assert.equal(JSON.parse(def.stdout).isolation.readonly_fs, true);
  assert.doesNotMatch(def.stderr, /WARNING/);
  const rw = sandboxed(['--writable-fs']);
  assert.equal(rw.status, 0, rw.stderr);
  assert.equal(JSON.parse(rw.stdout).isolation.readonly_fs, false);
  assert.match(rw.stderr, /WARNING: --writable-fs: hooks can write anywhere you can/);
  assert.ok(JSON.parse(rw.stdout).warnings.some(w => /--writable-fs/.test(w)));
  const old = sandboxed(['--readonly-fs']);
  assert.equal(old.status, 0, old.stderr);
  assert.equal(JSON.parse(old.stdout).isolation.readonly_fs, true);
  assert.match(old.stderr, /--readonly-fs is deprecated/);
});

test('a relative hook script path that exists from the current directory is a usage error (hooks run in a temp dir)', (t) => {
  for (const hook of ['node examples/hooks/deny-rm.js', 'sh ./examples/hooks/post-generated.sh', 'examples/hooks/post-generated.sh',
    'FOO=1 node examples/hooks/deny-rm.js', '/usr/bin/env node examples/hooks/deny-rm.js', 'env -i FOO=1 BAR=2 node examples/hooks/deny-rm.js',
    'env -u HOME node examples/hooks/deny-rm.js', 'LANG=C ./examples/hooks/post-generated.sh']) {
    const r = cli(['--hook', hook, '--event', 'PreToolUse', '--dry-run']);
    assert.equal(r.status, 2, hook);
    assert.match(r.stderr, /is a relative path, and replay runs hooks in a temp directory.*absolute path or \$CLAUDE_PROJECT_DIR\/examples\/hooks\//, hook);
  }
  // --cwd recorded runs a hook in each point's recorded cwd, not a temp directory, and the message says so.
  const rec = cli(['--hook', 'node examples/hooks/deny-rm.js', '--event', 'PreToolUse', '--cwd', 'recorded', '--dry-run']);
  assert.equal(rec.status, 2);
  assert.match(rec.stderr, /is a relative path, and with --cwd recorded replay runs hooks in each call's recorded cwd \(a temp directory when it no longer exists\)/);
  assert.doesNotMatch(rec.stderr, /runs hooks in a temp directory;/);
  const d = tmpDir(t);
  const f = path.join(d, 'settings.json');
  fs.writeFileSync(f, JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ type: 'command', command: 'node', args: ['examples/hooks/deny-rm.js'] }] }] } }));
  assert.equal(cli(['--settings', f, '--dry-run']).status, 2);
  // Absolute, $CLAUDE_PROJECT_DIR and bare PATH names are fine; so is a relative name that does not exist here.
  for (const hook of [`node ${root}/examples/hooks/deny-rm.js`, 'node $CLAUDE_PROJECT_DIR/examples/hooks/deny-rm.js', 'true', 'node no/such/file.js']) {
    assert.equal(cli(['--hook', hook, '--event', 'PreToolUse', '--dry-run']).status, 0, hook);
  }
});
