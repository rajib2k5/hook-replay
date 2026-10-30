// Command-line front end: parse flags, then hand off to scan (dry run) or replay.
import os from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { discover } from './corpus.js';
import { scan } from './scan.js';
import { hookFromFlags, loadSettings, checkPluginRoot, UsageError } from './hooks.js';
import { parseFilters, keepFile } from './filters.js';
import { DEFAULT_MAX_LINE_BYTES } from './lines.js';
import fs from 'node:fs';
import { replay, IsolationError, DEFAULT_TIMEOUT_S } from './replay.js';
import { buildReport, renderHuman, renderJson, OUTCOMES } from './report.js';
import { makeRedactor, escapeControl } from './redact.js';

export const VERSION = '0.1.0';

const OPTIONS = {
  'projects-dir': { type: 'string' },
  hook: { type: 'string' }, event: { type: 'string' }, matcher: { type: 'string' },
  'hook-timeout': { type: 'string' }, 'on-failure': { type: 'string' },
  settings: { type: 'string' }, 'ignore-if': { type: 'boolean' },
  'project-dir': { type: 'string' }, 'plugin-root': { type: 'string' },
  timeout: { type: 'string' }, concurrency: { type: 'string' }, cwd: { type: 'string' },
  env: { type: 'string', multiple: true },
  'allow-network': { type: 'boolean' }, 'readonly-fs': { type: 'boolean' },
  'no-subagents': { type: 'boolean' },
  project: { type: 'string', multiple: true }, session: { type: 'string' },
  since: { type: 'string' }, until: { type: 'string' }, sample: { type: 'string' }, limit: { type: 'string' },
  samples: { type: 'string' },
  json: { type: 'boolean' }, out: { type: 'string' }, 'show-raw': { type: 'boolean' },
  'fail-on': { type: 'string' }, 'dry-run': { type: 'boolean' },
  'max-line-bytes': { type: 'string' },
  help: { type: 'boolean', short: 'h' }, version: { type: 'boolean' },
};

const USAGE = `usage: hook-replay (--hook "<cmd>" --event <PreToolUse|PostToolUse|Stop> [--matcher <m>] | --settings <file>)
                   [--projects-dir <dir>] [--dry-run] [--json] [--out <file>] [options]
Runs a Claude Code hook against past sessions' tool calls and reports what it would block, ask or warn on.`;

const posInt = (v, name, dflt) => {
  if (v === undefined) return dflt;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1) throw new UsageError(`${name} must be a positive integer`);
  return n;
};

export function parseCli(argv) {
  let parsed;
  try { parsed = parseArgs({ args: argv, options: OPTIONS, allowPositionals: false, strict: true }); } catch (e) { throw new UsageError(e.message); }
  const v = parsed.values;
  if (v.help || v.version) return { help: !!v.help, version: !!v.version };
  if (!!v.hook === !!v.settings) throw new UsageError('give exactly one of --hook or --settings');
  if (v.hook && !v.event) throw new UsageError('--hook needs --event');
  const opts = {
    projectsDir: path.resolve(v['projects-dir'] ?? path.join(os.homedir(), '.claude', 'projects')),
    dryRun: !!v['dry-run'], json: !!v.json, out: v.out,
    includeSubagents: !v['no-subagents'],
    maxLineBytes: posInt(v['max-line-bytes'], '--max-line-bytes', DEFAULT_MAX_LINE_BYTES),
    limit: posInt(v.limit, '--limit', 5000),
    samples: v.samples === undefined ? 5 : Number(v.samples),
    concurrency: posInt(v.concurrency, '--concurrency', 4),
    timeoutS: v.timeout === undefined ? DEFAULT_TIMEOUT_S : Number(v.timeout),
    cwdMode: v.cwd ?? 'temp',
    envNames: v.env ?? [],
    allowNetwork: !!v['allow-network'], readonlyFs: !!v['readonly-fs'],
    projectDir: path.resolve(v['project-dir'] ?? process.cwd()),
    pluginRoot: v['plugin-root'] === undefined ? undefined : path.resolve(v['plugin-root']),
    showRaw: !!v['show-raw'],
  };
  if (!Number.isInteger(opts.samples) || opts.samples < 0) throw new UsageError('--samples must be a non-negative integer');
  if (!(opts.timeoutS > 0)) throw new UsageError('--timeout must be a positive number of seconds');
  if (!['temp', 'recorded'].includes(opts.cwdMode)) throw new UsageError('--cwd must be temp or recorded');
  opts.filters = parseFilters({ project: v.project, session: v.session, since: v.since, until: v.until, sample: v.sample });
  opts.failOn = [];
  if (v['fail-on'] !== undefined) {
    opts.failOn = v['fail-on'].split(',').map(x => x.trim()).filter(Boolean);
    const bad = opts.failOn.filter(o => !OUTCOMES.includes(o));
    if (bad.length || !opts.failOn.length) throw new UsageError(`--fail-on takes outcomes from ${OUTCOMES.join(',')}; got ${v['fail-on']}`);
  }
  opts.loadWarnings = [];
  if (v.settings) {
    const { hooks, warnings } = loadSettings(path.resolve(v.settings), { ignoreIf: !!v['ignore-if'], pluginRoot: opts.pluginRoot });
    opts.hooks = hooks;
    opts.loadWarnings = warnings;
  } else {
    const h = hookFromFlags({ hook: v.hook, event: v.event, matcher: v.matcher, hookTimeout: v['hook-timeout'], onFailure: v['on-failure'] });
    checkPluginRoot(h, opts.pluginRoot);
    opts.hooks = [h];
  }
  return opts;
}

// Everything this prints goes through the redactor (off only with --show-raw, and only once it is parsed).
export async function main(argv, io = { stdout: process.stdout, stderr: process.stderr }, env = process.env) {
  let red = makeRedactor();
  try {
    return await run(argv, io, (r) => { red = r; return r; });
  } catch (e) {
    const msg = e && e.message !== undefined ? e.message : String(e);
    io.stderr.write(`hook-replay: internal error: ${red(msg)}\n`);
    if (env.HOOK_REPLAY_DEBUG === '1' && e && e.stack) io.stderr.write(red(e.stack) + '\n');
    return 1;
  }
}

async function run(argv, io, setRedactor) {
  let red = makeRedactor();
  let opts;
  try {
    opts = parseCli(argv);
  } catch (e) {
    if (e instanceof UsageError) { io.stderr.write(red(`hook-replay: ${e.message}`) + `\n${USAGE}\n`); return 2; }
    throw e;
  }
  if (opts.help) { io.stdout.write(USAGE + '\n'); return 0; }
  if (opts.version) { io.stdout.write(VERSION + '\n'); return 0; }
  red = setRedactor(makeRedactor({ enabled: !opts.showRaw }));
  for (const w of opts.loadWarnings) io.stderr.write(`hook-replay: warning: ${red(w)}\n`);
  if (opts.dryRun) {
    const files = discover(opts.projectsDir).filter(f => keepFile(f, opts.filters));
    const s = await scan({ files, hooks: opts.hooks, filters: opts.filters, includeSubagents: opts.includeSubagents, maxLineBytes: opts.maxLineBytes, limit: opts.limit });
    io.stderr.write(`hook-replay ${VERSION}: dry run, nothing executed\n`);
    const hooks = opts.hooks.map(h => ({ id: h.id, event: h.event, matcher: h.matcher === undefined ? null : red(h.matcher), ...s.perHook[h.id],
      by_tool: Object.fromEntries(Object.entries(s.perHook[h.id].by_tool).map(([t, n]) => [red(t), n])) }));
    if (opts.json) io.stdout.write(JSON.stringify({ dry_run: true, corpus: s.corpus, hooks }, null, 2) + '\n');
    else {
      io.stdout.write(`files ${s.corpus.files}  lines ${s.corpus.lines}  sessions ${s.corpus.sessions}\n`);
      io.stdout.write('HOOK EVENT TOOL POINTS\n');
      for (const h of hooks) for (const [tool, n] of Object.entries(h.by_tool)) io.stdout.write(escapeControl(`${h.id} ${h.event} ${tool} ${n}`) + '\n');
    }
    return 0;
  }
  if (opts.showRaw) io.stderr.write('hook-replay: WARNING: --show-raw: redaction OFF, the report contains raw transcript text\n');
  let res;
  try {
    res = await replay({ ...opts, stderr: io.stderr, redact: red });
  } catch (e) {
    if (e instanceof IsolationError) { io.stderr.write(`hook-replay: ${red(e.message)}\n`); return 3; }
    throw e;
  }
  const warnings = [...opts.loadWarnings];
  if (opts.hooks.some(h => h.ifIgnored)) warnings.push('--ignore-if: hooks with an if field ran on every matcher hit, so their counts are an upper bound');
  if (opts.showRaw) warnings.push('redaction OFF (--show-raw): this report contains raw transcript text');
  if (res.isolation.network === 'NOT ISOLATED') warnings.push('NOT ISOLATED (--allow-network): hooks ran unwrapped and could reach the network, Unix sockets and other processes');
  const model = buildReport({
    res, hooks: opts.hooks, samples: opts.samples, warnings, version: VERSION, redacted: !opts.showRaw,
    redact: red,
    config: { timeout_s: opts.timeoutS, concurrency: opts.concurrency, cwd_mode: opts.cwdMode, project_dir: opts.projectDir,
      filters: opts.filters.raw, sample: opts.filters.sample, limit: opts.limit },
  });
  const text = opts.json || opts.out ? renderJson(model) : renderHuman(model);
  if (opts.out) {
    fs.writeFileSync(opts.out, text, { mode: 0o600 });
    fs.chmodSync(opts.out, 0o600);
    if (!opts.json) io.stdout.write(renderHuman(model));
  } else io.stdout.write(text);
  if (opts.failOn.some(o => model.hooks.some(h => h.counts[o] > 0))) return 4;
  return 0;
}
