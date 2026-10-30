// Command-line front end: parse flags, then hand off to scan (dry run) or replay.
import os from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { discover } from './corpus.js';
import { scan } from './scan.js';
import { hookFromFlags, UsageError } from './hooks.js';
import { DEFAULT_MAX_LINE_BYTES } from './lines.js';

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
  };
  opts.hooks = [hookFromFlags({ hook: v.hook, event: v.event, matcher: v.matcher, hookTimeout: v['hook-timeout'], onFailure: v['on-failure'] })];
  return opts;
}

export async function main(argv, io = { stdout: process.stdout, stderr: process.stderr }) {
  let opts;
  try {
    opts = parseCli(argv);
  } catch (e) {
    if (e instanceof UsageError) { io.stderr.write(`hook-replay: ${e.message}\n${USAGE}\n`); return 2; }
    throw e;
  }
  if (opts.help) { io.stdout.write(USAGE + '\n'); return 0; }
  if (opts.version) { io.stdout.write(VERSION + '\n'); return 0; }
  const files = discover(opts.projectsDir);
  const s = await scan({ files, hooks: opts.hooks, includeSubagents: opts.includeSubagents, maxLineBytes: opts.maxLineBytes, limit: opts.limit });
  if (opts.dryRun) {
    io.stderr.write(`hook-replay ${VERSION}: dry run, nothing executed\n`);
    const hooks = opts.hooks.map(h => ({ id: h.id, event: h.event, matcher: h.matcher ?? null, ...s.perHook[h.id] }));
    if (opts.json) io.stdout.write(JSON.stringify({ dry_run: true, corpus: s.corpus, hooks }, null, 2) + '\n');
    else {
      io.stdout.write(`files ${s.corpus.files}  lines ${s.corpus.lines}  sessions ${s.corpus.sessions}\n`);
      io.stdout.write('HOOK EVENT TOOL POINTS\n');
      for (const h of hooks) for (const [tool, n] of Object.entries(h.by_tool)) io.stdout.write(`${h.id} ${h.event} ${tool} ${n}\n`);
    }
    return 0;
  }
  io.stderr.write('hook-replay: only --dry-run is implemented\n');
  return 1;
}
