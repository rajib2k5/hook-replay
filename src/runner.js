// Run one hook process on one payload (DESIGN.md §5 "Process" and "Timeout"). Knows nothing about transcripts.
import { spawn } from 'node:child_process';
import path from 'node:path';

export const OUTPUT_CAP = 1024 * 1024;
const PIPE_GRACE_MS = 100;
const ENV_ALLOW = ['PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ'];

// Exec form (args set): the CLAUDE_* placeholders are substituted textually; shell form leaves expansion to sh.
export function commandArgv(hook, vars = {}) {
  if (!Array.isArray(hook.args)) return ['sh', '-c', hook.command];
  const sub = (s) => s.replace(/\$\{(CLAUDE_PROJECT_DIR|CLAUDE_PLUGIN_ROOT|CLAUDE_PLUGIN_DATA)\}|\$(CLAUDE_PROJECT_DIR|CLAUDE_PLUGIN_ROOT|CLAUDE_PLUGIN_DATA)\b/g,
    (m, a, b) => vars[a || b] ?? m);
  return [sub(hook.command), ...hook.args.map(sub)];
}

export function buildEnv({ source = process.env, tmp, projectDir, pluginRoot, envNames = [] }) {
  const env = {};
  for (const k of ENV_ALLOW) if (source[k] !== undefined) env[k] = source[k];
  env.TMPDIR = path.join(tmp, 'tmp');
  env.CLAUDE_PROJECT_DIR = projectDir;
  if (pluginRoot !== undefined) env.CLAUDE_PLUGIN_ROOT = pluginRoot;
  env.CLAUDE_PLUGIN_DATA = path.join(tmp, 'plugin-data');
  env.CLAUDE_HOOK_REPLAY = '1';
  for (const k of envNames) if (source[k] !== undefined) env[k] = source[k];
  return env;
}

// argv: full argv including any wrapper. Resolves to a RunResult; never rejects.
export function runHook({ argv, stdin, env, cwd, timeoutMs, timeoutSource, killGroup = false }) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint();
    const res = { exitCode: null, signal: null, stdout: '', stderr: '', stdoutTruncated: false, timedOut: false,
      timeoutSource: null, spawnError: null, latencyMs: 0 };
    const out = { stdout: [], stderr: [] };
    const len = { stdout: 0, stderr: 0 };
    let child;
    try {
      child = spawn(argv[0], argv.slice(1), { env, cwd, stdio: ['pipe', 'pipe', 'pipe'], detached: killGroup });
    } catch (e) {
      res.spawnError = String(e.code || e.message);
      res.latencyMs = Number(process.hrtime.bigint() - t0) / 1e6;
      resolve(res);
      return;
    }
    let done = false;
    let timer = null;
    let grace = null;
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      clearTimeout(grace);
      res.latencyMs = Number(process.hrtime.bigint() - t0) / 1e6;
      res.stdout = Buffer.concat(out.stdout).toString('utf8');
      res.stderr = Buffer.concat(out.stderr).toString('utf8');
      resolve(res);
    };
    const kill = () => {
      try {
        if (killGroup && child.pid) process.kill(-child.pid, 'SIGKILL'); else child.kill('SIGKILL');
      } catch { try { child.kill('SIGKILL'); } catch { /* already gone */ } }
    };
    for (const name of ['stdout', 'stderr']) {
      child[name].on('data', (chunk) => {
        const room = OUTPUT_CAP - len[name];
        if (room <= 0) { if (name === 'stdout') res.stdoutTruncated = true; return; }
        if (chunk.length > room) { if (name === 'stdout') res.stdoutTruncated = true; chunk = chunk.subarray(0, room); }
        out[name].push(chunk);
        len[name] += chunk.length;
      });
      child[name].on('error', () => {});
    }
    child.stdin.on('error', () => {}); // EPIPE: the hook did not read its stdin
    child.on('error', (e) => {
      if (res.exitCode === null && res.signal === null) res.spawnError = String(e.code || e.message);
      finish();
    });
    child.on('exit', (code, signal) => {
      res.exitCode = code;
      res.signal = signal;
      grace = setTimeout(() => { child.stdout.destroy(); child.stderr.destroy(); finish(); }, PIPE_GRACE_MS);
    });
    child.on('close', finish);
    timer = setTimeout(() => { res.timedOut = true; res.timeoutSource = timeoutSource; kill(); }, timeoutMs);
    child.stdin.end(stdin);
  });
}
