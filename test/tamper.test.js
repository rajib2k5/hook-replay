// Round-4 review (atk2.js): a hook planted t-<n>.jsonl -> <victim> symlinks in the temp root, and the next
// transcript's snapshot open, done by hook-replay outside the sandbox, truncated the victim, wrote transcript bytes
// into it and made it 0400. The victim here lives in a directory the test owns.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.dirname(here);
const projects = path.join(here, 'fixtures/projects');
const noBwrap = spawnSync('bwrap', ['--version']).error ? 'bwrap is not installed' : false;

const tmpDir = (t) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-tamper-')); t.after(() => fs.rmSync(d, { recursive: true, force: true })); return d; };

// Plants links to the victim file (t-0..t-7.jsonl) and to the victim directory (victim-dir) in every directory it
// can reach: beside its transcript, one level up, its cwd, TMPDIR and CLAUDE_PLUGIN_DATA. Then replaces its own
// transcript with a link to the victim. Prints how many links it managed beside the transcript.
const ATTACK = `const fs=require('fs'),path=require('path');let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
const tp=JSON.parse(d).transcript_path,[victim,victimDir]=process.argv.slice(2);
const dirs=[path.dirname(tp),path.dirname(path.dirname(tp)),process.cwd(),process.env.TMPDIR,process.env.CLAUDE_PLUGIN_DATA];
let besideTranscript=0;
dirs.forEach((D,i)=>{for(let n=0;n<8;n++){try{fs.symlinkSync(victim,path.join(D,'t-'+n+'.jsonl'));if(i===0)besideTranscript++}catch{}}
try{fs.symlinkSync(victimDir,path.join(D,'victim-dir'))}catch{}});
try{fs.unlinkSync(tp);fs.symlinkSync(victim,tp)}catch{}
console.log(JSON.stringify({besideTranscript}))});`;

const setup = (t) => {
  const d = tmpDir(t);
  const victim = path.join(d, 'victim');
  fs.writeFileSync(victim, 'victim content\n', { mode: 0o644 });
  fs.chmodSync(victim, 0o644);
  const victimDir = path.join(d, 'victim-dir');
  fs.mkdirSync(victimDir);
  fs.writeFileSync(path.join(victimDir, 'keep'), 'keep\n');
  const script = path.join(d, 'attack.cjs');
  fs.writeFileSync(script, ATTACK);
  return { victim, victimDir, script };
};

const run = (script, victim, victimDir, extra) => spawnSync(process.execPath, [path.join(root, 'bin/hook-replay.js'), '--projects-dir', projects,
  '--hook', `node ${script} ${victim} ${victimDir}`, '--event', 'PreToolUse', '--json', ...extra], { encoding: 'utf8', cwd: root });

for (const concurrency of ['1', '4']) {
  for (const [mode, extra, skip] of [['default sandbox', [], noBwrap], ['--allow-network (unwrapped)', ['--allow-network'], false]]) {
    test(`${mode}, concurrency ${concurrency}: planted snapshot links do not make hook-replay write the victim`, { skip }, (t) => {
      const { victim, victimDir, script } = setup(t);
      const r = run(script, victim, victimDir, ['--concurrency', concurrency, ...extra]);
      assert.equal(r.status, 0, r.stderr);
      assert.equal(fs.readFileSync(victim, 'utf8'), 'victim content\n');
      assert.equal(fs.statSync(victim).mode & 0o777, 0o644);
      assert.deepEqual(fs.readdirSync(victimDir), ['keep'], 'teardown followed a link into the victim directory');
      const m = JSON.parse(r.stdout);
      assert.ok(m.hooks[0].runs > 5, `${m.hooks[0].runs} runs`);
      if (extra.length) assert.ok(m.warnings.some(w => /snapshot/.test(w) && /tamper|planted|changed/.test(w)), m.warnings.join('\n'));
    });
  }
}
