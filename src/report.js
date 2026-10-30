// Report model (DESIGN.md §7). Redaction happens here, when a string is stored in the model, so neither
// renderer can see raw text.
import crypto from 'node:crypto';
import { latencySummary } from './stats.js';
import { escapeControl } from './redact.js';

export const SCHEMA = 'hook-replay/report@1';
export const OUTCOMES = ['pass', 'allow', 'ask', 'defer', 'block', 'warn', 'stop', 'error', 'timeout', 'replay_timeout'];
export const FLAGGED = ['block', 'ask', 'defer', 'warn', 'stop'];
const EXCERPT = 300;

// DESIGN.md §10, stated in every report.
export const FIDELITY_WARNINGS = [
  'counterfactual history: the transcripts were recorded without this hook, so a replayed deny does not change later calls, and text the hook would have injected is absent',
  'transcript lag: the real hook may have seen less of the transcript than the snapshot holds',
  'approximated: output schema, stop_hook_active, permission_mode, tool_response without toolUseResult; not reproduced: the if field, parallel hooks, the 8-continuation cap; absent: prompt_id, effort, mcp_server, duration_ms, agent_type, scratchpad_dir',
  'transcript_path is a snapshot (no files beside it); env allowlist, temp cwd and no sockets differ from a live session; stateful hooks see thousands of calls in minutes',
];

const zero = () => Object.fromEntries(OUTCOMES.map(o => [o, 0]));
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const round = (x) => x === null ? null : Math.round(x * 10) / 10;

const realNote = (event, real) => {
  if (event === 'Stop') {
    return { user_prompt: 'after this turn the real session waited for the user; if stopping was fine, this flag is a candidate false positive',
      assistant_continued: 'the real session continued after this turn', eof: 'the transcript ends after this turn' }[real] ?? real;
  }
  return { ok: 'the real session ran this call and it succeeded; if that was fine, this flag is a candidate false positive',
    error: 'the real session ran this call and it failed', none: 'no result for this call was recorded' }[real] ?? real;
};

function redactDeep(v, redact) {
  if (typeof v === 'string') return redact(v);
  if (Array.isArray(v)) return v.map(x => redactDeep(x, redact));
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [redact(k), redactDeep(x, redact)]));
  return v;
}
const cut = (s) => s === null || s === undefined ? null : String(s).slice(0, EXCERPT);

function sample(r, hook, redact) {
  const input = r.event === 'Stop' ? r.payload.last_assistant_message : r.payload.tool_input;
  const s = {
    sample_id: sha(r.key + hook.key).slice(0, 12),
    outcome: r.verdict.outcome, mechanism: r.verdict.mechanism,
    session: redact(r.sessionId), file: redact(r.file), line: r.lineNo, timestamp: r.timestamp,
    tool: redact(r.tool),
  };
  const excerpt = typeof input === 'string' ? redact(input) : JSON.stringify(redactDeep(input ?? null, redact));
  s[r.event === 'Stop' ? 'last_assistant_message' : 'tool_input'] = cut(excerpt);
  s.reason = cut(redact(r.verdict.reason ?? (r.run.stderr || null)));
  s.exit_code = r.run.exitCode;
  s.signal = r.run.signal;
  s.latency_ms = round(r.run.latencyMs);
  s.fidelity = r.fidelity;
  s.real_signal = r.realSignal;
  s.real_signal_note = realNote(r.event, r.realSignal);
  return s;
}

export function buildReport({ res, hooks, config, redact, samples = 5, now = new Date().toISOString(), warnings = [], version = '0.1.0', redacted = true }) {
  const hookModels = hooks.map((h) => {
    const rs = res.results.filter(r => r.hookId === h.id);
    const counts = zero();
    const byTool = {};
    const mechanisms = {};
    let flaggedRealOk = 0;
    for (const r of rs) {
      const o = r.verdict.outcome;
      counts[o]++;
      const t = redact(r.tool);
      byTool[t] = byTool[t] || {};
      byTool[t][o] = (byTool[t][o] || 0) + 1;
      const mech = redact(r.verdict.mechanism);
      mechanisms[mech] = (mechanisms[mech] || 0) + 1;
      if (FLAGGED.includes(o) && r.realSignal === 'ok') flaggedRealOk++;
    }
    for (const t of Object.keys(byTool)) byTool[t] = Object.fromEntries(OUTCOMES.filter(o => byTool[t][o]).map(o => [o, byTool[t][o]]));
    const lat = latencySummary(rs.filter(r => !r.run.timedOut && !r.run.spawnError).map(r => r.run.latencyMs));
    const picked = [];
    for (const o of FLAGGED) {
      picked.push(...rs.filter(r => r.verdict.outcome === o)
        .map(r => ({ r, h: sha(r.key + h.key) })).sort((a, b) => a.h < b.h ? -1 : a.h > b.h ? 1 : 0)
        .slice(0, samples).map(({ r }) => sample(r, h, redact)));
    }
    return {
      id: h.id, key: h.key, event: h.event, matcher: h.matcher === undefined ? null : redact(h.matcher),
      command: redact(h.args ? [h.command, ...h.args].join(' ') : h.command), source: redact(h.source), if_ignored: !!h.ifIgnored,
      runs: rs.length, truncated: !!(res.perHook[h.id] && res.perHook[h.id].truncated), counts, by_tool: byTool, mechanisms,
      flagged_real_ok: flaggedRealOk, latency_ms: { n: lat.n, p50: round(lat.p50), p95: round(lat.p95), max: round(lat.max) }, samples: picked,
    };
  });
  return {
    schema: SCHEMA, tool_version: version, generated_at: now, redacted,
    isolation: { network: res.isolation.network, readonly_fs: !!res.isolation.readonly_fs, probe: redact(res.isolation.probe ?? '') },
    config: { ...config, project_dir: redact(config.project_dir) },
    corpus: res.corpus,
    sandbox_overhead_ms: res.sandboxOverheadMs,
    warnings: [...warnings.map(w => redact(w)), ...FIDELITY_WARNINGS],
    hooks: hookModels,
  };
}

const pad = (rows) => {
  const w = rows[0].map((_, i) => Math.max(...rows.map(r => String(r[i]).length)));
  return rows.map(r => r.map((c, i) => i < 3 ? String(c).padEnd(w[i]) : String(c).padStart(w[i])).join('  ').trimEnd()).join('\n');
};
const fmt = (x) => x === null ? '-' : String(x);

export function renderHuman(m) {
  const out = [];
  out.push(`hook-replay ${m.tool_version}  points ${Object.values(m.corpus.points_by_event).reduce((a, b) => a + b, 0)}  sessions ${m.corpus.sessions}` +
    `  isolation ${m.isolation.network}${m.isolation.readonly_fs ? ' (readonly fs)' : ''}  cwd ${m.config.cwd_mode}` +
    `  redaction ${m.redacted ? 'on' : 'OFF'}  project-dir ${m.config.project_dir}`);
  for (const w of m.warnings) out.push(`warning: ${w}`);
  out.push('');
  const rows = [['HOOK', 'EVENT', 'MATCHER', 'RUNS', 'BLOCK', 'ASK', 'WARN', 'STOP', 'DEFER', 'ERROR', 'TIMEOUT', 'RTO', 'P50ms', 'P95ms', 'MAXms']];
  for (const h of m.hooks) {
    const c = h.counts;
    rows.push([h.id, h.event, h.matcher ?? '-', h.runs, c.block, c.ask, c.warn, c.stop, c.defer, c.error, c.timeout, c.replay_timeout,
      fmt(h.latency_ms.p50), fmt(h.latency_ms.p95), fmt(h.latency_ms.max)]);
  }
  out.push(pad(rows));
  out.push(`latency measured at concurrency ${m.config.concurrency}; sandbox overhead p50 ${m.sandbox_overhead_ms.p50} ms, p95 ${m.sandbox_overhead_ms.p95} ms`);
  for (const h of m.hooks) {
    out.push('', `== ${h.id}: ${h.command}${h.truncated ? ' (truncated by --limit)' : ''}${h.if_ignored ? ' (if ignored: counts are an upper bound)' : ''}`);
    const flaggedBy = (t) => FLAGGED.reduce((a, o) => a + (h.by_tool[t][o] || 0), 0);
    const tools = Object.keys(h.by_tool).filter(t => flaggedBy(t) > 0).sort((a, b) => flaggedBy(b) - flaggedBy(a) || (a < b ? -1 : 1)).slice(0, 10);
    if (tools.length) out.push('top tools by flagged count: ' + tools.map(t => `${t} ${flaggedBy(t)}`).join(', '));
    const errs = Object.entries(h.mechanisms).filter(([k]) => /^(spawn$|exit_|exit2_missing_file|signal_|invalid_json|hook_timeout|replay_cap|on_failure_block)/.test(k));
    if (errs.length) out.push('error mechanisms: ' + errs.map(([k, n]) => `${k} ${n}`).join(', '));
    out.push(`flagged and the real call succeeded: ${h.flagged_real_ok}`);
    for (const s of h.samples) {
      out.push(`  [${s.sample_id}] ${s.outcome}/${s.mechanism} ${s.tool} ${s.file}:${s.line} ${s.timestamp ?? ''} exit ${s.exit_code ?? s.signal} ${s.latency_ms} ms`);
      const input = s.tool_input ?? s.last_assistant_message;
      if (input) out.push(`      input:  ${input}`);
      if (s.reason) out.push(`      reason: ${s.reason}`);
      if (s.fidelity.length) out.push(`      fidelity: ${s.fidelity.join(', ')}`);
      out.push(`      real session: ${s.real_signal_note}`);
    }
  }
  return escapeControl(out.join('\n')) + '\n';
}

export function renderJson(m) {
  return JSON.stringify(m, null, 2) + '\n';
}
