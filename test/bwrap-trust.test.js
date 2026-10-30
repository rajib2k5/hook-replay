// Round-5 review (fake-bwrap): the probe trusted whatever `bwrap` came first on PATH, and a fake in ~/.local/bin that
// printed the probe's expected answers and then ran the hook unwrapped was accepted. bwrap is now taken only from
// root-owned system paths that no other user can write, or from --bwrap <path>, which the report prints.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolveBwrap, SYSTEM_BWRAP } from '../src/sandbox.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.dirname(here);
const projects = path.join(here, 'fixtures/projects');
const trusted = SYSTEM_BWRAP.find(p => { try { return fs.statSync(p).uid === 0; } catch { return false; } });
const noBwrap = (spawnSync('bwrap', ['--version']).error || !trusted) ? 'no root-owned bwrap in a system path' : false;

const tmpDir = (t) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-bwt-')); t.after(() => fs.rmSync(d, { recursive: true, force: true })); return d; };

// Prints what the probe wants to see (EACCES everywhere, its own namespaces), then runs anything else unwrapped.
const FAKE = `#!/bin/sh
while [ "$1" != "--" ]; do shift; done; shift
case "$*" in
  true) exit 0;;
  *"ts=JSON.parse"*) node -e 'const t=JSON.parse(process.argv[1]);const o={netlink:"error EACCES","ns net":"net:[1]","ns pid":"pid:[1]"};for(const x of t)o[x.name]="error EACCES";console.log(JSON.stringify(o))' "$(eval echo \\\${$#})"; exit 0;;
  *"import socket"*) echo '{"packet":"error EACCES","raw inet":"error EACCES","raw inet6":"error EACCES"}'; exit 0;;
  *) exec "$@";;
esac
`;
const plantFake = (t) => {
  const bin = path.join(tmpDir(t), 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'bwrap'), FAKE, { mode: 0o755 });
  return bin;
};

const cli = (args, env) => new Promise((resolve) => {
  const c = spawn(process.execPath, [path.join(root, 'bin/hook-replay.js'), '--projects-dir', projects, '--session', 'cccccccc-0000-4000-8000-000000000003',
    '--event', 'PreToolUse', '--json', ...args], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = ''; let stderr = '';
  c.stdout.on('data', d => { stdout += d; }); c.stderr.on('data', d => { stderr += d; });
  c.on('close', (status) => resolve({ status, stdout, stderr }));
});

test('resolveBwrap rejects a bwrap in a directory the user owns and one in a world-writable directory', (t) => {
  const fake = path.join(plantFake(t), 'bwrap');
  const inTmp = path.join('/tmp', `hr-bwt-${process.pid}-bwrap`);
  fs.writeFileSync(inTmp, FAKE, { mode: 0o755 });
  t.after(() => fs.rmSync(inTmp, { force: true }));
  const r = resolveBwrap([fake, inTmp, '/nonexistent/bwrap']);
  assert.equal(r.binary, null);
  assert.equal(r.rejected.length, 3, r.rejected.join('\n'));
  assert.match(r.rejected[0], /owned by uid \d+/);
  assert.match(r.rejected[1], /^\/tmp\/hr-bwt-.*writable by group or others/);
  assert.match(r.rejected[2], /ENOENT/);
});

test('resolveBwrap takes a root-owned bwrap from the system paths, and the real path of a link to one', { skip: noBwrap }, (t) => {
  assert.equal(resolveBwrap().binary, fs.realpathSync(trusted));
  const link = path.join(tmpDir(t), 'bwrap');
  fs.symlinkSync(trusted, link);
  assert.equal(resolveBwrap([link]).binary, fs.realpathSync(trusted), 'the link (user-owned) is not what runs');
});

test('a fake bwrap first on PATH is not used: the hook still cannot connect to a host port', { skip: noBwrap }, async (t) => {
  const server = net.createServer((s) => s.destroy()).listen(0, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  t.after(() => server.close());
  // exit 2 (block) if the hook reached the port.
  const hook = `${process.execPath} -e "require('net').connect(${server.address().port},'127.0.0.1').on('connect',()=>process.exit(2)).on('error',()=>process.exit(0))"`;
  const r = await cli(['--hook', hook], { PATH: `${plantFake(t)}:${process.env.PATH}` });
  assert.equal(r.status, 0, r.stderr);
  const m = JSON.parse(r.stdout);
  assert.deepEqual([m.hooks[0].runs, m.hooks[0].counts.block], [1, 0], 'the hook connected: it ran under the fake bwrap');
  assert.deepEqual(m.isolation.bwrap, { path: fs.realpathSync(trusted), from: 'system path' });
});

test('--bwrap <path> overrides the system paths and is printed in the report; a missing one is exit 3', { skip: noBwrap }, async () => {
  const r = await cli(['--hook', 'true', '--bwrap', trusted], {});
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout).isolation.bwrap, { path: trusted, from: '--bwrap' });
  const missing = await cli(['--hook', 'true', '--bwrap', '/nonexistent/bwrap'], {});
  assert.equal(missing.status, 3, missing.stderr);
  assert.match(missing.stderr, /\/nonexistent\/bwrap/);
});
