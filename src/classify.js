// Outcome classification (DESIGN.md §6): a pure function of a RunResult and the hook's event / onFailure.
// Taken from the hooks reference exit-code x stdout table and per-event decision fields; valid() is our
// approximation of the unpublished output schema.

const KNOWN = ['continue', 'stopReason', 'systemMessage', 'terminalSequence', 'reason', 'suppressOutput', 'decision', 'hookSpecificOutput'];
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const nonEmpty = (s) => typeof s === 'string' && s !== '';

export function valid(o, event) {
  if ('continue' in o && typeof o.continue !== 'boolean') return false;
  if ('suppressOutput' in o && typeof o.suppressOutput !== 'boolean') return false;
  for (const k of ['stopReason', 'systemMessage', 'terminalSequence', 'reason']) if (k in o && typeof o[k] !== 'string') return false;
  if ('decision' in o) {
    const ok = event === 'PreToolUse' ? ['approve', 'block'] : ['block'];
    if (!ok.includes(o.decision)) return false;
  }
  if ('hookSpecificOutput' in o) {
    const h = o.hookSpecificOutput;
    if (!isObj(h) || h.hookEventName !== event) return false;
    if ('additionalContext' in h && typeof h.additionalContext !== 'string') return false;
    if (event === 'PreToolUse' && 'permissionDecision' in h && !['allow', 'deny', 'ask', 'defer'].includes(h.permissionDecision)) return false;
  }
  return true;
}

// Step 1. Returns {kind:'PLAIN'} | {kind:'JSON', o} | {kind:'INVALID', r}.
export function parseStdout(stdout, truncated, event) {
  if (truncated) return { kind: 'INVALID', r: 'stdout_over_cap' };
  const s = stdout.trim();
  if (s === '' || !s.startsWith('{') || !s.endsWith('}')) return { kind: 'PLAIN' };
  try {
    const o = JSON.parse(s);
    if (!isObj(o)) return { kind: 'PLAIN' };
    return valid(o, event) ? { kind: 'JSON', o } : { kind: 'INVALID', r: 'schema' };
  } catch {
    const lines = s.split('\n').filter(l => l.trim() !== '');
    if (lines.length >= 2) {
      const parsed = [];
      for (const l of lines) { try { parsed.push(JSON.parse(l)); } catch { return { kind: 'INVALID', r: 'parse' }; } }
      return parsed.some(x => isObj(x) && KNOWN.some(k => k in x)) ? { kind: 'INVALID', r: 'multi_json' } : { kind: 'PLAIN' };
    }
    return { kind: 'INVALID', r: 'parse' };
  }
}

const verdict = (outcome, mechanism, reason = null, annotations) => {
  const v = { outcome, mechanism, reason };
  if (annotations) v.annotations = annotations;
  return v;
};

// With exit 2 the reason is stderr, unless the JSON itself makes a blocking decision [docs: Exit code 2].
const blockingReason = (o, event) => {
  const h = isObj(o.hookSpecificOutput) ? o.hookSpecificOutput : {};
  if (event === 'PreToolUse' && h.permissionDecision !== undefined) return h.permissionDecision === 'deny' && nonEmpty(h.permissionDecisionReason) ? h.permissionDecisionReason : null;
  return o.decision === 'block' && nonEmpty(o.reason) ? o.reason : null;
};

export function fields(o, event) {
  const h = isObj(o.hookSpecificOutput) ? o.hookSpecificOutput : {};
  if (o.continue === false) return verdict('stop', 'continue_false', o.stopReason ?? null);
  let decided = null;
  if (event === 'PreToolUse') {
    const fromH = h.permissionDecision;
    const d = fromH ?? { approve: 'allow', block: 'deny' }[o.decision];
    if (d !== undefined) {
      const mech = fromH !== undefined ? 'permission_decision' : 'deprecated_decision';
      const outcome = { deny: 'block', defer: 'defer', ask: 'ask', allow: 'allow' }[d];
      const reason = nonEmpty(h.permissionDecisionReason) ? h.permissionDecisionReason : (o.reason ?? null);
      decided = verdict(outcome, mech, reason);
    }
  } else if (event === 'PostToolUse') {
    // The tool already ran: a PostToolUse block is feedback to Claude, named so the report can say so.
    if (o.decision === 'block') return verdict('block', 'decision_block_feedback', o.reason ?? null);
  } else if (event === 'Stop') {
    if (o.decision === 'block') return verdict('block', 'decision_block', o.reason ?? null);
    if (nonEmpty(h.additionalContext)) return verdict('block', 'additional_context', h.additionalContext);
  }
  if (decided) {
    if (decided.outcome === 'allow' && nonEmpty(h.additionalContext)) decided.annotations = ['additional_context'];
    return decided;
  }
  if (event !== 'Stop' && nonEmpty(h.additionalContext)) return verdict('warn', 'additional_context', h.additionalContext);
  if (nonEmpty(o.systemMessage)) return verdict('warn', 'system_message', o.systemMessage);
  if (event === 'PostToolUse' && 'updatedToolOutput' in h) return verdict('warn', 'updated_tool_output');
  if (event === 'PostToolUse' && 'updatedMCPToolOutput' in h) return verdict('warn', 'updated_mcp_tool_output');
  if (event === 'PreToolUse' && 'updatedInput' in h) return verdict('warn', 'updated_input');
  return verdict('pass', 'json_no_decision');
}

// Step 2. run: RunResult; hook: {event, onFailure}.
export function classify(run, { event, onFailure = 'continue' }) {
  const fail = (v) => onFailure === 'block' && event !== 'Stop' ? verdict('block', 'on_failure_block', v.reason) : v;
  const stderr = (run.stderr || '').trim() || null;
  if (run.timedOut && run.timeoutSource === 'replay_cap') return verdict('replay_timeout', 'replay_cap');
  if (run.timedOut) return fail(verdict('timeout', 'hook_timeout'));
  if (run.spawnError) return fail(verdict('error', 'spawn', run.spawnError));
  const p = parseStdout(run.stdout || '', run.stdoutTruncated, event);
  const code = run.exitCode;
  if (code === 2) {
    if (event === 'Stop' && (run.stdout || '') === '' && /No such file or directory/.test(run.stderr || '')) return verdict('error', 'exit2_missing_file', stderr);
    if (p.kind === 'JSON' && p.o.continue === false) return verdict('stop', 'continue_false', p.o.stopReason ?? stderr);
    return verdict('block', event === 'PostToolUse' ? 'exit2_feedback' : 'exit2', (p.kind === 'JSON' && blockingReason(p.o, event)) || stderr);
  }
  if (p.kind === 'JSON') {
    const v = fields(p.o, event);
    return code !== 0 ? fail(v) : v;
  }
  if (code === 0 && p.kind === 'PLAIN') return verdict('pass', 'exit0');
  if (code === 0) return fail(verdict('error', `invalid_json:${p.r}`, stderr));
  const mech = code === null || code === undefined ? `signal_${run.signal}` : `exit_${code}`;
  return fail(verdict('error', mech, stderr));
}
