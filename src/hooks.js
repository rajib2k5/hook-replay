// HookSpec construction: from --hook flags (shell form) or from a settings.json / plugin hooks.json.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { validateMatcher } from './matcher.js';

export const EVENTS = ['PreToolUse', 'PostToolUse', 'Stop'];
export const DEFAULT_HOOK_TIMEOUT_S = 600;

export class UsageError extends Error {}

const hookKey = (h) => crypto.createHash('sha256')
  .update(JSON.stringify([h.event, h.matcher ?? null, h.command, h.args ?? null, ...(h.shell ? [h.shell] : [])])).digest('hex').slice(0, 16);

export function hookFromFlags({ hook, event, matcher, hookTimeout, onFailure }) {
  if (!EVENTS.includes(event)) throw new UsageError(`--event must be one of ${EVENTS.join(', ')}`);
  if (event === 'Stop' && matcher !== undefined) throw new UsageError('--matcher cannot be used with --event Stop (Stop has no matcher)');
  if (matcher !== undefined) {
    try { validateMatcher(matcher); } catch (e) { throw new UsageError(e.message); }
  }
  const timeoutS = hookTimeout === undefined ? DEFAULT_HOOK_TIMEOUT_S : Number(hookTimeout);
  if (!(timeoutS > 0)) throw new UsageError('--hook-timeout must be a positive number of seconds');
  const of = onFailure ?? 'continue';
  if (!['continue', 'block'].includes(of)) throw new UsageError('--on-failure must be continue or block');
  const h = { id: 'h1', event, matcher, command: hook, timeoutS, onFailure: of, source: '--hook', ifIgnored: false };
  h.key = hookKey(h);
  return h;
}

export { hookKey };

const INTERPRETERS = new Set(['node', 'nodejs', 'deno', 'bun', 'python', 'python3', 'sh', 'bash', 'zsh', 'dash', 'ruby', 'perl', 'php', 'tsx', 'ts-node']);

// Hooks run in a temp cwd, so `node examples/hooks/x.js` would fail on every point (exit 1) if replay ran it. When
// the script argument is a relative path that exists from hook-replay's own cwd, stop at load time instead (exit 2).
// Resolving it for the user is not done: it would not be what the hook does where it is configured.
// Leading NAME=value assignments and an `env` prefix (with its options and assignments) are skipped to reach the
// command. A command nested in `sh -c '...'` is not looked into.
const ENV_ARG_OPTS = new Set(['-u', '--unset', '-C', '--chdir', '-S', '--split-string']);
const ASSIGN = /^[A-Za-z_][A-Za-z0-9_]*=/;
function skipPrefix(toks) {
  let i = 0;
  while (i < toks.length && ASSIGN.test(toks[i])) i++;
  if (toks[i] && toks[i].split('/').pop() === 'env') {
    i++;
    while (i < toks.length && (toks[i].startsWith('-') || ASSIGN.test(toks[i]))) i += ENV_ARG_OPTS.has(toks[i]) ? 2 : 1;
  }
  return toks.slice(i);
}

export function checkRelativeScript(h, { cwd = process.cwd(), cwdMode = 'temp' } = {}) {
  const toks = skipPrefix((Array.isArray(h.args) ? [h.command, ...h.args] : h.command.trim().split(/\s+/)).map(t => t.replace(/^['"]|['"]$/g, '')));
  const cands = [];
  if (toks[0] && toks[0].includes('/')) cands.push(toks[0]);
  if (toks[0] && INTERPRETERS.has(toks[0].split('/').pop())) { const arg = toks.slice(1).find(t => !t.startsWith('-')); if (arg) cands.push(arg); }
  for (const c of cands) {
    if (path.isAbsolute(c) || c.startsWith('$') || c.startsWith('~')) continue;
    let isFile = false;
    try { isFile = fs.statSync(path.resolve(cwd, c)).isFile(); } catch { /* not here */ }
    if (isFile) {
      const rel = c.replace(/^\.\//, '');
      const where = cwdMode === 'recorded' ? "with --cwd recorded replay runs hooks in each call's recorded cwd (a temp directory when it no longer exists)"
        : 'replay runs hooks in a temp directory';
      throw new UsageError(`hook ${h.id} (${h.source}): script ${c} is a relative path, and ${where}; ` +
        `use an absolute path or $CLAUDE_PROJECT_DIR/${rel}`);
    }
  }
}

const PLUGIN_ROOT_RE = /\$\{?CLAUDE_PLUGIN_ROOT\b/;

export function checkPluginRoot(h, pluginRoot) {
  const text = [h.command, ...(h.args || [])].join(' ');
  if (pluginRoot === undefined && PLUGIN_ROOT_RE.test(text)) {
    throw new UsageError(`hook ${h.id} (${h.source}) references CLAUDE_PLUGIN_ROOT; pass --plugin-root`);
  }
}

// Reads .hooks.{PreToolUse,PostToolUse,Stop}[] of a settings.json or plugin hooks.json. Returns {hooks, warnings}.
export function loadSettings(file, { ignoreIf = false, pluginRoot, cwdMode = 'temp' } = {}) {
  let doc;
  try { doc = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { throw new UsageError(`cannot load ${file}: ${e.message}`); }
  const all = doc && typeof doc === 'object' && doc.hooks && typeof doc.hooks === 'object' ? doc.hooks : {};
  const hooks = [];
  const warnings = [];
  for (const event of Object.keys(all)) {
    if (!EVENTS.includes(event)) { warnings.push(`skipped ${event} hooks in ${file}: event not supported in v0.1`); }
  }
  for (const event of EVENTS) {
    const groups = Array.isArray(all[event]) ? all[event] : [];
    groups.forEach((g, gi) => {
      const matcher = event === 'Stop' ? undefined : (g.matcher === undefined || g.matcher === null ? undefined : String(g.matcher));
      if (matcher !== undefined) {
        try { validateMatcher(matcher); } catch (e) { throw new UsageError(`${file}#hooks.${event}[${gi}]: ${e.message}`); }
      }
      (Array.isArray(g.hooks) ? g.hooks : []).forEach((x, hi) => {
        const source = `${file}#hooks.${event}[${gi}].hooks[${hi}]`;
        const skip = (why) => warnings.push(`skipped ${source}: ${why}`);
        if (!x || x.type !== 'command') return skip(`type ${JSON.stringify(x && x.type)} is not command`);
        if (x.async || x.asyncRewake) return skip('async hooks are not replayed');
        const args = Array.isArray(x.args) ? x.args.map(String) : undefined;
        // "shell" accepts "bash" or "powershell" and is ignored when args is set (hooks reference).
        if (!args && x.shell === 'powershell') return skip('shell powershell is not supported');
        if (!args && x.shell !== undefined && x.shell !== 'bash') return skip(`shell ${JSON.stringify(x.shell)} is not supported`);
        if (typeof x.command !== 'string' || x.command === '') return skip('no command');
        if ([x.command, ...(args || [])].some(s => s.includes('${user_config.'))) return skip('references ${user_config.*}');
        if (x.if !== undefined && !ignoreIf) throw new UsageError(`${source} has an "if" field, which replay cannot evaluate; pass --ignore-if to run it on every matcher hit`);
        const timeoutS = x.timeout === undefined ? DEFAULT_HOOK_TIMEOUT_S : Number(x.timeout);
        if (!(timeoutS > 0)) throw new UsageError(`${source}: timeout must be a positive number`);
        const onFailure = x.onFailure ?? 'continue';
        if (!['continue', 'block'].includes(onFailure)) throw new UsageError(`${source}: onFailure must be continue or block`);
        const h = { id: `h${hooks.length + 1}`, event, matcher, command: x.command, args, timeoutS, onFailure, source, ifIgnored: x.if !== undefined };
        if (!args && x.shell === 'bash') h.shell = 'bash';
        h.key = hookKey(h);
        checkPluginRoot(h, pluginRoot);
        checkRelativeScript(h, { cwdMode });
        hooks.push(h);
      });
    });
  }
  return { hooks, warnings };
}
