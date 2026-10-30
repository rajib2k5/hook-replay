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

// Round-5 review (ren.sh, snapln.sh): with --writable-fs the hook renamed the temp root (or, unwrapped, the snap dir)
// and put a link to another directory at the old path. O_NOFOLLOW covers only the last component, so hook-replay
// created the next snapshot inside the link's target, and the raw prefix in the renamed root stayed after exit.
// Each run the hook records what it sees in the target (<target>.seen), since a snapshot there is unlinked at close.
const RENAME = `const fs=require('fs'),path=require('path');let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
const tp=JSON.parse(d).transcript_path,[mode,target]=process.argv.slice(2),D=path.dirname(tp),R=path.dirname(D);
const seen=fs.readdirSync(target);if(seen.length)fs.appendFileSync(target+'.seen',seen.join('\\n')+'\\n');
try{if(mode==='root'&&!fs.existsSync(R+'.old')){fs.renameSync(R,R+'.old');fs.mkdirSync(R);fs.symlinkSync(target,path.join(R,'snap'));
for(const w of ['cwd','tmp','plugin-data'])fs.mkdirSync(path.join(R,'work',w),{recursive:true});console.log('renamed')}
if(mode==='snap'&&!fs.lstatSync(D).isSymbolicLink()){fs.renameSync(D,D+'.old');fs.symlinkSync(target,D);console.log('renamed')}}
catch(e){console.log('error '+e.code)}})`;

// Every regular file under dir whose name looks like a snapshot (t-<n>[-<rand>].jsonl), at any depth.
const snapshotsUnder = (dir) => fs.readdirSync(dir, { recursive: true, withFileTypes: true })
  .filter(e => e.isFile() && /^t-\d+/.test(e.name)).map(e => path.join(e.parentPath, e.name));

for (const [mode, what, extra, skip] of [
  ['--writable-fs', 'root', ['--writable-fs'], noBwrap],
  ['--allow-network (unwrapped)', 'root', ['--allow-network'], false],
  ['--allow-network (unwrapped)', 'snap', ['--allow-network'], false],
]) {
  test(`${mode}: a hook that renames the ${what} dir and links the old path elsewhere does not redirect snapshot creates`, { skip }, (t) => {
    const d = tmpDir(t);
    const [target, tmpdir] = [path.join(d, 'target'), path.join(d, 'tmpdir')];
    fs.mkdirSync(target);
    fs.mkdirSync(tmpdir);
    const script = path.join(d, 'rename.cjs');
    fs.writeFileSync(script, RENAME);
    const r = spawnSync(process.execPath, [path.join(root, 'bin/hook-replay.js'), '--projects-dir', projects, '--hook', `node ${script} ${what} ${target}`,
      '--event', 'PreToolUse', '--json', '--concurrency', '1', ...extra], { encoding: 'utf8', cwd: root, env: { ...process.env, TMPDIR: tmpdir } });
    assert.deepEqual(fs.readdirSync(target), [], 'hook-replay created a snapshot in the link target');
    assert.equal(fs.existsSync(`${target}.seen`) && fs.readFileSync(`${target}.seen`, 'utf8'), false, 'a hook run saw a snapshot in the link target');
    assert.deepEqual(snapshotsUnder(tmpdir), [], 'a raw transcript prefix stayed after exit');
    assert.deepEqual(fs.readdirSync(tmpdir).filter(n => n.endsWith('.old')), [], 'the renamed root stayed after exit');
    if (extra[0] === '--writable-fs') {
      assert.equal(r.status, 0, r.stderr);
      assert.ok(JSON.parse(r.stdout).hooks[0].runs > 5);
    } else {
      assert.equal(r.status, 1, r.stdout + r.stderr);
      assert.match(r.stderr, /hook-replay: .*no longer the snapshot directory/);
      assert.doesNotMatch(r.stderr, /internal error/);
    }
  });
}
