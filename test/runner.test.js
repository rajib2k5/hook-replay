import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runHook, buildEnv, commandArgv, OUTPUT_CAP } from '../src/runner.js';

const base = { env: { PATH: process.env.PATH }, cwd: process.cwd(), timeoutMs: 5000, timeoutSource: 'replay_cap' };

test('delivers stdin and captures exit code, stdout and stderr', async () => {
  const r = await runHook({ ...base, argv: ['sh', '-c', 'read x; echo "out:$x"; echo err >&2; exit 7'], stdin: 'hello\n' });
  assert.deepEqual([r.exitCode, r.signal, r.stdout, r.stderr, r.timedOut, r.spawnError], [7, null, 'out:hello\n', 'err\n', false, null]);
  assert.ok(r.latencyMs > 0);
});

test('stdout over 1 MiB is capped and flagged', async () => {
  const r = await runHook({ ...base, argv: ['sh', '-c', 'head -c 2000000 /dev/zero | tr "\\0" a'], stdin: '' });
  assert.equal(r.stdout.length, OUTPUT_CAP);
  assert.equal(r.stdoutTruncated, true);
});

test('a hook that never reads stdin does not crash the runner (EPIPE ignored)', async () => {
  const r = await runHook({ ...base, argv: ['sh', '-c', 'exit 0'], stdin: 'x'.repeat(4 * 1024 * 1024) });
  assert.equal(r.exitCode, 0);
});

test('timeout kills the hook and reports the timeout source', async () => {
  const t0 = Date.now();
  const r = await runHook({ ...base, argv: ['sh', '-c', 'sleep 5'], stdin: '', timeoutMs: 200, timeoutSource: 'hook' });
  assert.deepEqual([r.timedOut, r.timeoutSource, r.exitCode, r.signal], [true, 'hook', null, 'SIGKILL']);
  assert.ok(Date.now() - t0 < 3000);
});

test('a missing executable is a spawn error', async () => {
  const r = await runHook({ ...base, argv: ['/nonexistent/hook-replay-no-such-binary'], stdin: '' });
  assert.match(r.spawnError, /ENOENT/);
  assert.equal(r.exitCode, null);
});

test('commandArgv: shell form is sh -c, exec form is command + args', () => {
  assert.deepEqual(commandArgv({ command: 'echo $HOME' }), ['sh', '-c', 'echo $HOME']);
  assert.deepEqual(commandArgv({ command: 'node', args: ['a.js', '--x'] }), ['node', 'a.js', '--x']);
});

test('buildEnv keeps only the allowlist plus replay variables and named --env vars', () => {
  const src = { PATH: '/bin', HOME: '/home/u', USER: 'u', SSH_AUTH_SOCK: '/tmp/agent', AWS_SECRET_ACCESS_KEY: 'x', LANG: 'C', MYVAR: 'v' };
  const env = buildEnv({ source: src, work: '/t', projectDir: '/p', pluginRoot: undefined, envNames: ['MYVAR'] });
  assert.deepEqual(env, {
    PATH: '/bin', HOME: '/home/u', USER: 'u', LANG: 'C', TMPDIR: '/t/tmp',
    CLAUDE_PROJECT_DIR: '/p', CLAUDE_PLUGIN_DATA: '/t/plugin-data', CLAUDE_HOOK_REPLAY: '1', MYVAR: 'v',
  });
});
