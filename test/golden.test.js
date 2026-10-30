// Golden tests (a)-(c) of DESIGN.md §11 over the fixture transcripts and the example hooks.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { replay } from '../src/replay.js';
import { hookFromFlags } from '../src/hooks.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.dirname(here);
const projectsDir = path.join(here, 'fixtures/projects');
const readJson = (p) => JSON.parse(fs.readFileSync(path.join(here, 'fixtures/expected', p), 'utf8'));
const withoutComment = ({ _comment, ...rest }) => rest;
const tmpDir = (t) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-golden-')); t.after(() => fs.rmSync(d, { recursive: true, force: true })); return d; };
const quiet = { write() {} };

const HOOKS = {
  'deny-rm': { hook: `node ${root}/examples/hooks/deny-rm.js`, event: 'PreToolUse', matcher: 'Bash' },
  'post-generated': { hook: `sh ${root}/examples/hooks/post-generated.sh`, event: 'PostToolUse', matcher: 'Edit|Write' },
  'stop-claims': { hook: `node ${root}/examples/hooks/stop-claims.js`, event: 'Stop', hookTimeout: '1' },
};

const runFixtureHook = (name, extra = {}) => replay({
  projectsDir, hooks: [hookFromFlags(HOOKS[name])], allowNetwork: true, concurrency: 2, stderr: quiet, ...extra,
});

// Source bytes [0, end) — what the snapshot handed to the hook must contain.
const prefix = (relPath, end) => fs.readFileSync(path.join(projectsDir, relPath)).subarray(0, end);
const prefixLines = (relPath, n) => {
  const buf = fs.readFileSync(path.join(projectsDir, relPath));
  let end = 0;
  for (let i = 0; i < n; i++) end = buf.indexOf(0x0a, end) + 1;
  return buf.subarray(0, end);
};
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

for (const name of Object.keys(HOOKS)) {
  test(`(a) ${name}: replay outcomes equal the hand-written expected.json`, async () => {
    const { results } = await runFixtureHook(name);
    const got = Object.fromEntries(results.map(r => [r.key, { outcome: r.verdict.outcome, mechanism: r.verdict.mechanism }]));
    assert.deepEqual(got, withoutComment(readJson(`${name}.json`)));
  });

  test(`(c) ${name}: running the hook directly on each recorded payload gives the same exit code and stdout`, async (t) => {
    const { results } = await runFixtureHook(name);
    const expected = withoutComment(readJson(`${name}.json`));
    const d = tmpDir(t);
    assert.ok(results.length > 0);
    for (const [i, r] of results.entries()) {
      const snap = path.join(d, `snap-${i}.jsonl`);
      fs.writeFileSync(snap, prefix(r.file, r.snapshotEnd));
      const { session_id, ...rest } = r.payload;
      const input = JSON.stringify({ session_id, transcript_path: snap, ...rest });
      const direct = spawnSync('sh', ['-c', HOOKS[name].hook], {
        input, encoding: 'utf8', cwd: d, timeout: r.hook.timeoutS * 1000, killSignal: 'SIGKILL',
      });
      assert.deepEqual({ exitCode: direct.status, signal: direct.signal, stdout: direct.stdout },
        { exitCode: r.run.exitCode, signal: r.run.signal, stdout: r.run.stdout }, r.key);
      assert.deepEqual({ outcome: r.verdict.outcome, mechanism: r.verdict.mechanism }, expected[r.key], r.key);
    }
  });
}

test('(b) pipeline fidelity: captured stdin equals hand-written payloads and transcript_path is the exact byte prefix', async (t) => {
  const d = tmpDir(t);
  const out = path.join(d, 'capture.tsv');
  process.env.CAPTURE_OUT = out;
  const hooks = ['PreToolUse', 'PostToolUse', 'Stop'].map((event, i) => ({ ...hookFromFlags({ hook: `sh ${root}/test/hooks/capture.sh`, event }), id: `h${i + 1}` }));
  const res = await replay({ projectsDir, hooks, allowNetwork: true, concurrency: 1, envNames: ['CAPTURE_OUT'], stderr: quiet });
  const captured = fs.readFileSync(out, 'utf8').trim().split('\n').map(l => {
    const [hash, json] = l.split('\t');
    return { hash, payload: JSON.parse(json) };
  });
  assert.equal(captured.length, 59);
  assert.equal(res.results.length, 59);
  for (const e of readJson('payloads.json').entries) {
    const ident = (p) => p.hook_event_name === 'Stop' ? `${p.session_id}|${p.last_assistant_message}` : `${p.hook_event_name}|${p.tool_use_id}`;
    const hits = captured.filter(c => ident(c.payload) === ident(e.payload));
    assert.equal(hits.length, 1, ident(e.payload));
    const { transcript_path, ...payload } = hits[0].payload;
    assert.deepEqual(payload, e.payload);
    assert.ok(path.isAbsolute(transcript_path) && transcript_path !== path.join(projectsDir, e.file), transcript_path);
    assert.equal(hits[0].hash, sha(prefixLines(e.file, e.snapshotLines)), `snapshot of ${ident(e.payload)}`);
  }
  assert.equal(fs.existsSync(res.tmpDir), false, 'temp dir removed after the run');
});

test('results are sorted by (file, line, hook id) whatever the concurrency', async () => {
  const a = await runFixtureHook('deny-rm', { concurrency: 1 });
  const b = await runFixtureHook('deny-rm', { concurrency: 6 });
  assert.deepEqual(a.results.map(r => r.key), b.results.map(r => r.key));
  const keys = a.results.map(r => [r.file, r.lineNo]);
  const sorted = [...keys].sort((x, y) => Buffer.compare(Buffer.from(x[0]), Buffer.from(y[0])) || x[1] - y[1]);
  assert.deepEqual(keys, sorted);
});
