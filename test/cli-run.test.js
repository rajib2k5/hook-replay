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
  assert.match(s.reason, new RegExp(`^root=${path.join(d, 'plug')} proj=${d} data=/.*hook-replay-[^/]+/plugin-data replay=1$`));
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
