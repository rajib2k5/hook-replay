// Rebuild hook payloads (PayloadPoints, DESIGN.md §3) from transcript lines. Knows nothing about hooks.
// Pure over its input: the caller supplies the lines and the context (relPath, session uuid, home dir).
import path from 'node:path';

const PENDING_MAX = 10000;
const PATH_TOOLS = new Set(['Read', 'Write', 'Edit', 'NotebookEdit']);
const KNOWN_TYPES = new Set(['user', 'assistant']);
const PERMISSION_MODES = new Set(['default', 'plan', 'acceptEdits', 'auto', 'dontAsk', 'bypassPermissions']);

export function emptyStats() {
  return {
    lines: 0, lines_malformed: 0, lines_oversize: 0, orphan_tool_results: 0,
    skipped: { post_tool_use_failure: 0, duplicate_uuid: 0, duplicate_tool_use_id: 0, subagent_excluded: 0 },
    points_by_event: { PreToolUse: 0, PostToolUse: 0, Stop: 0 },
  };
}

export class Reconstructor {
  // ctx: {relPath, sessionUuid, subagent, homedir, includeSubagents=true}
  constructor(ctx, stats = emptyStats()) {
    this.ctx = { includeSubagents: true, ...ctx };
    this.stats = stats;
    this.permissionMode = 'default';
    this.lastCwd = null;
    this.pending = new Map();
    this.seenUuids = new Set();
    this.seenToolUseIds = new Set();
    this.msgText = new Map();
    this.hadStop = false;
    this.promptSinceStop = false;
    this.pendingStop = null;
  }

  push(line) {
    const out = [];
    this.stats.lines++;
    if (line.bytes === null) { this.stats.lines_oversize++; return out; }
    let o;
    try { o = JSON.parse(line.bytes.toString('utf8')); } catch { this.stats.lines_malformed++; return out; }
    if (o === null || typeof o !== 'object' || Array.isArray(o)) { this.stats.lines_malformed++; return out; }
    if (typeof o.permissionMode === 'string') this.permissionMode = o.permissionMode;
    if (typeof o.cwd === 'string') this.lastCwd = o.cwd;
    if (!KNOWN_TYPES.has(o.type)) return out;
    if (typeof o.uuid === 'string') {
      if (this.seenUuids.has(o.uuid)) { this.stats.skipped.duplicate_uuid++; return out; }
      this.seenUuids.add(o.uuid);
    }
    const sidechain = this.ctx.subagent || o.isSidechain === true;
    if (sidechain && !this.ctx.includeSubagents) { this.stats.skipped.subagent_excluded++; return out; }
    const content = o.message && o.message.content;
    if (o.type === 'assistant') this.#assistant(o, line, content, sidechain, out);
    else this.#user(o, line, content, sidechain, out);
    return out;
  }

  finish() {
    const out = [];
    for (const [id, p] of this.pending) { this.pending.delete(id); out.push(this.#emitPre(p, 'none')); }
    if (this.pendingStop) { out.push(this.#emit({ ...this.pendingStop, realSignal: 'eof' })); this.pendingStop = null; }
    return out;
  }

  // Common payload fields, and the fidelity marks they need. cwd falls back to the last cwd seen in this file
  // (any line type); agent_id only on subagent lines; an undocumented permission mode becomes "default".
  #common(o, event, sidechain) {
    const fidelity = [];
    const p = { session_id: typeof o.sessionId === 'string' ? o.sessionId : this.ctx.sessionUuid };
    if (this.lastCwd !== null) p.cwd = this.lastCwd; else fidelity.push('cwd_missing');
    if (PERMISSION_MODES.has(this.permissionMode)) p.permission_mode = this.permissionMode;
    else { p.permission_mode = 'default'; fidelity.push('permission_mode_unknown'); }
    p.hook_event_name = event;
    if (sidechain && typeof o.agentId === 'string') p.agent_id = o.agentId;
    if (typeof o.promptId === 'string') p.prompt_id = o.promptId;
    return { p, fidelity };
  }

  #emit(pt) {
    this.stats.points_by_event[pt.event]++;
    return pt;
  }

  #emitPre(p, realSignal) {
    return this.#emit({ ...p.point, realSignal });
  }

  #point(event, line, o, snapshotEnd, payload, toolUseId, fidelity = []) {
    return {
      key: `${this.ctx.relPath}:${line.lineNo}:${event}:${toolUseId ?? ''}`,
      event, file: this.ctx.relPath, lineNo: line.lineNo,
      timestamp: typeof o.timestamp === 'string' ? o.timestamp : null,
      snapshotEnd, payload, realSignal: 'none', fidelity,
    };
  }

  #resolveInput(name, input, cwd) {
    if (!PATH_TOOLS.has(name) || input === null || typeof input !== 'object') return input;
    const r = { ...input };
    for (const k of ['file_path', 'notebook_path']) {
      const v = r[k];
      if (typeof v !== 'string' || v === '') continue;
      if (v === '~' || v.startsWith('~/')) r[k] = path.join(this.ctx.homedir, v.slice(1));
      else if (!path.isAbsolute(v) && typeof cwd === 'string') r[k] = path.resolve(cwd, v);
    }
    return r;
  }

  #assistant(o, line, content, sidechain, out) {
    if (this.pendingStop && !sidechain) { out.push(this.#emit({ ...this.pendingStop, realSignal: 'assistant_continued' })); this.pendingStop = null; }
    const msgId = o.message && o.message.id;
    if (typeof content === 'string' && content !== '' && msgId !== undefined) {
      if (!this.msgText.has(msgId)) this.msgText.set(msgId, []);
      this.msgText.get(msgId).push(content);
    }
    if (Array.isArray(content)) {
      for (const b of content) {
        if (!b || typeof b !== 'object') continue;
        if (b.type === 'text' && typeof b.text === 'string' && msgId !== undefined) {
          if (!this.msgText.has(msgId)) this.msgText.set(msgId, []);
          this.msgText.get(msgId).push(b.text);
        } else if (b.type === 'tool_use' && typeof b.id === 'string') {
          if (this.seenToolUseIds.has(b.id)) { this.stats.skipped.duplicate_tool_use_id++; continue; }
          this.seenToolUseIds.add(b.id);
          const input = this.#resolveInput(b.name, b.input, this.lastCwd);
          const { p: common, fidelity } = this.#common(o, 'PreToolUse', sidechain);
          const payload = { ...common, tool_name: b.name, tool_input: input, tool_use_id: b.id };
          const point = this.#point('PreToolUse', line, o, line.offset + line.length + 1, payload, b.id, fidelity);
          this.pending.set(b.id, { name: b.name, input, lineNo: line.lineNo, point });
          if (this.pending.size > PENDING_MAX) {
            const [oldId, oldest] = this.pending.entries().next().value;
            this.pending.delete(oldId);
            out.push(this.#emitPre(oldest, 'none'));
          }
        }
      }
    }
    if (o.message && o.message.stop_reason === 'end_turn' && !sidechain) {
      const { p: common, fidelity } = this.#common(o, 'Stop', sidechain);
      const payload = {
        ...common,
        stop_hook_active: this.hadStop && !this.promptSinceStop,
        last_assistant_message: (this.msgText.get(msgId) || []).join('\n'),
        background_tasks: [], session_crons: [],
      };
      this.pendingStop = this.#point('Stop', line, o, line.offset + line.length + 1, payload, null, fidelity);
      this.hadStop = true;
      this.promptSinceStop = false;
    }
  }

  #user(o, line, content, sidechain, out) {
    const realPrompt = o.isMeta !== true && (typeof content === 'string' ||
      (Array.isArray(content) && content.length > 0 && content.every(b => b && b.type === 'text')));
    if (realPrompt) {
      this.promptSinceStop = true;
      if (this.pendingStop && !sidechain) { out.push(this.#emit({ ...this.pendingStop, realSignal: 'user_prompt' })); this.pendingStop = null; }
      return;
    }
    if (!Array.isArray(content)) return;
    for (const b of content) {
      if (!b || b.type !== 'tool_result') continue;
      if (!this.pending.has(b.tool_use_id)) { this.stats.orphan_tool_results++; continue; }
      const p = this.pending.get(b.tool_use_id);
      this.pending.delete(b.tool_use_id);
      const isError = b.is_error === true;
      out.push(this.#emitPre(p, isError ? 'error' : 'ok'));
      if (isError) { this.stats.skipped.post_tool_use_failure++; continue; }
      let response;
      const { p: common, fidelity } = this.#common(o, 'PostToolUse', sidechain);
      if (o.toolUseResult !== null && typeof o.toolUseResult === 'object') response = o.toolUseResult;
      else {
        fidelity.push('tool_response_from_content');
        if (typeof b.content === 'string') response = b.content;
        else response = (Array.isArray(b.content) ? b.content : [])
          .filter(c => c && c.type === 'text' && typeof c.text === 'string').map(c => c.text).join('\n');
      }
      const payload = { ...common, tool_name: p.name, tool_input: p.input, tool_response: response, tool_use_id: b.tool_use_id };
      const pt = this.#point('PostToolUse', line, o, line.offset, payload, b.tool_use_id, fidelity);
      pt.realSignal = 'ok';
      out.push(this.#emit(pt));
    }
  }
}

export function reconstruct(lines, ctx) {
  const r = new Reconstructor(ctx);
  const points = [];
  for (const l of lines) points.push(...r.push(l));
  points.push(...r.finish());
  return { points, stats: r.stats };
}
