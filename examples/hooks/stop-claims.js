#!/usr/bin/env node
// Example Stop hook: if the turn claims "tests pass" without a test result in the same turn, ask Claude to show
// the evidence (additionalContext, which continues the conversation). Reads the tail of transcript_path, and
// strips its own <claims-policy> block first, because that block quotes the very phrases it looks for.
// For tests: sleeps past any timeout when last_assistant_message contains FIXTURE_SLOW.
import fs from 'node:fs';

const TAIL_BYTES = 60 * 1024;
const CLAIM = /\b(all )?tests (pass|passed|are passing)\b/i;
const EVIDENCE = /# pass \d+|\b\d+ (passed|passing)\b/i;

const payload = JSON.parse(fs.readFileSync(0, 'utf8'));
if (String(payload.last_assistant_message || '').includes('FIXTURE_SLOW')) {
  setTimeout(() => {}, 30000);
} else {
  main();
}

function main() {
  if (payload.stop_hook_active) return;
  let tail = '';
  try {
    const fd = fs.openSync(payload.transcript_path, 'r');
    const size = fs.fstatSync(fd).size;
    const len = Math.min(size, TAIL_BYTES);
    const buf = Buffer.alloc(len);
    fs.readSync(fd, buf, 0, len, size - len);
    fs.closeSync(fd);
    tail = buf.toString('utf8');
  } catch {
    return;
  }
  tail = tail.replace(/<claims-policy>[\s\S]*?<\/claims-policy>/g, '');
  const entries = [];
  for (const l of tail.split('\n')) { try { entries.push(JSON.parse(l)); } catch { /* first line may be cut */ } }
  const isPrompt = (e) => e.type === 'user' && !e.isMeta && e.message &&
    (typeof e.message.content === 'string' || (Array.isArray(e.message.content) && e.message.content.every(b => b.type === 'text')));
  let start = 0;
  entries.forEach((e, i) => { if (isPrompt(e)) start = i + 1; });
  const turn = entries.slice(start);
  const texts = (pred) => turn.filter(pred).map(e => JSON.stringify(e.message ? e.message.content : e.attachment ?? '')).join('\n');
  const said = texts(e => e.type === 'assistant' || e.type === 'attachment');
  const results = texts(e => e.type === 'user');
  if (CLAIM.test(said) && !EVIDENCE.test(results)) {
    process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'Stop',
      additionalContext: 'You said the tests pass, but this turn has no test output. Run them and show the result.' } }) + '\n');
  }
}
