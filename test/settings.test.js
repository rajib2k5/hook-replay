import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadSettings, UsageError } from '../src/hooks.js';
import { commandArgv } from '../src/runner.js';

const write = (t, obj) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-settings-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const f = path.join(d, 'settings.json');
  fs.writeFileSync(f, typeof obj === 'string' ? obj : JSON.stringify(obj));
  return f;
};

test('reads command hooks for the three events in load order, with timeout, onFailure and args', (t) => {
  const f = write(t, { hooks: {
    PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'a.sh', timeout: 5, onFailure: 'block' }, { type: 'command', command: 'node', args: ['b.js'] }] }],
    Stop: [{ hooks: [{ type: 'command', command: 'c.sh' }] }],
    PostToolUse: [{ matcher: 'Edit|Write', hooks: [{ type: 'command', command: 'd.sh' }] }],
  } });
  const { hooks, warnings } = loadSettings(f, {});
  assert.deepEqual(hooks.map(h => [h.id, h.event, h.matcher, h.command, h.args, h.timeoutS, h.onFailure]), [
    ['h1', 'PreToolUse', 'Bash', 'a.sh', undefined, 5, 'block'],
    ['h2', 'PreToolUse', 'Bash', 'node', ['b.js'], 600, 'continue'],
    ['h3', 'PostToolUse', 'Edit|Write', 'd.sh', undefined, 600, 'continue'],
    ['h4', 'Stop', undefined, 'c.sh', undefined, 600, 'continue'],
  ]);
  assert.equal(hooks[1].source, `${f}#hooks.PreToolUse[0].hooks[1]`);
  assert.deepEqual(warnings, []);
  assert.notEqual(hooks[0].key, hooks[1].key);
});

test('skips other events, non-command types, async, powershell and user_config references with a warning', (t) => {
  const f = write(t, { hooks: {
    SessionStart: [{ hooks: [{ type: 'command', command: 'x' }] }],
    PreToolUse: [{ hooks: [
      { type: 'http', url: 'http://localhost' }, { type: 'command', command: 'y', async: true },
      { type: 'command', command: 'z', asyncRewake: true }, { type: 'command', command: 'w', shell: 'powershell' },
      { type: 'command', command: 'v ${user_config.key}' }, { type: 'command', command: 'ok.sh' },
    ] }],
  } });
  const { hooks, warnings } = loadSettings(f, {});
  assert.deepEqual(hooks.map(h => h.command), ['ok.sh']);
  assert.equal(warnings.length, 6);
  assert.ok(warnings.every(w => /skipped/.test(w)));
});

test('a hook with `if` is refused unless --ignore-if, which marks it if_ignored', (t) => {
  const f = write(t, { hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'a', if: 'Bash(git *)' }] }] } });
  assert.throws(() => loadSettings(f, {}), (e) => e instanceof UsageError && /--ignore-if/.test(e.message));
  const { hooks } = loadSettings(f, { ignoreIf: true });
  assert.equal(hooks[0].ifIgnored, true);
});

test('an invalid matcher regex and unparseable JSON are load errors', (t) => {
  assert.throws(() => loadSettings(write(t, { hooks: { PreToolUse: [{ matcher: 'Bash(', hooks: [{ type: 'command', command: 'a' }] }] } }), {}), UsageError);
  assert.throws(() => loadSettings(write(t, '{nope'), {}), UsageError);
});

test('a hook referencing CLAUDE_PLUGIN_ROOT is refused without --plugin-root', (t) => {
  const f = write(t, { hooks: { Stop: [{ hooks: [{ type: 'command', command: '${CLAUDE_PLUGIN_ROOT}/s.sh' }] }] } });
  assert.throws(() => loadSettings(f, {}), /--plugin-root/);
  assert.equal(loadSettings(f, { pluginRoot: '/plug' }).hooks.length, 1);
});

test('exec form substitutes the three placeholders in command and args; shell form leaves them to sh', () => {
  const vars = { CLAUDE_PROJECT_DIR: '/proj', CLAUDE_PLUGIN_ROOT: '/plug', CLAUDE_PLUGIN_DATA: '/data' };
  assert.deepEqual(commandArgv({ command: '${CLAUDE_PLUGIN_ROOT}/bin/run', args: ['--dir', '${CLAUDE_PROJECT_DIR}/x', '$CLAUDE_PLUGIN_DATA'] }, vars),
    ['/plug/bin/run', '--dir', '/proj/x', '/data']);
  assert.deepEqual(commandArgv({ command: 'echo ${CLAUDE_PROJECT_DIR}' }, vars), ['sh', '-c', 'echo ${CLAUDE_PROJECT_DIR}']);
});
