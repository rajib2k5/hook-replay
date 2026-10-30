// Golden test (d): the real CLI on the planted-secrets fixture leaks none of them, on stdout or stderr, in table,
// --json, --out or --dry-run output; with --show-raw every one of them appears, which proves this test can fail.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { main } from '../src/cli.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.dirname(here);
const SECRETS = 'dddddddd-0000-4000-8000-000000000004.jsonl';

const PLANTED = [
  'FAKEKEYMATERIALnotreal', 'BEGIN RSA PRIVATE KEY',
  'sk-ant-api03-FAKEfakeFAKEfake0000', 'sk-proj-FAKEfakeFAKEfakeFAKEfake00',
  'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 'github_pat_FAKE0000fake0000FAKE0000xx',
  'AKIAXXXXXXXXFAKEXXXX', 'xoxb-0000000000-fakefakefake', 'AIzaFAKEfakeFAKEfakeFAKEfakeFAKEfake123',
  'eyJmYWtlaGVhZGVy.eyJmYWtlcGF5bG9hZA.ZmFrZXNpZ25hdHVyZQ', 'fakeBearerValue0000', 'fake-pass-0000',
  'fakepw0000', 'alice@example.com', 'FAKEentropyQ7wX2mZ9pL4vK8nR3tB6yH1cJ5dG0s',
  'alice', '/home/',
];

// A test hook that denies every call and echoes the command into its reason and its stderr.
const ECHO_DENY = `node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const c=JSON.parse(s).tool_input.command;` +
  `process.stderr.write('saw '+c);console.log(JSON.stringify({hookSpecificOutput:{hookEventName:'PreToolUse',permissionDecision:'deny',permissionDecisionReason:'saw: '+c}}))})"`;

// Values for the review's redaction gaps, generated here (fresh, fake, used nowhere else) so the hand counts of
// the checked-in fixture stay as they are. The real user's name and home are read at run time, never written down.
const me = (() => { try { return os.userInfo().username; } catch { return ''; } })();
const GAP_TOOL = 'mcp__vault__glpat-FAKEtoolNameTok0000abcd__read';
const GAP_COMMANDS = [
  `curl -d '{"api_key": "cliJsonApiKey7001", "password": "cliJsonPw7002", "db_password": "cliJsonDbPw7003"}' https://h.invalid`,
  'deploy --password cliFlagPw7004 --api-key cliFlagKey7005 --token cliFlagTok7006 --secret cliFlagSec7007',
  'mysql -u admin -pcliMysqlPw7008 prod',
  'curl -H "X-Api-Key: cliHdrKey7009" -H "Api-Key: cliHdrKey7010" https://h.invalid',
  'pay sk_live_cliStripeLive7011abcd sk_test_cliStripeTest7012abcd rk_live_cliStripeRk7013abcd',
  'npm config set //r/:_authToken npm_cliNpmTok7014abcdefghijklmnopqrstuvw',
  'hf auth login hf_cliHuggingFaceTok7015abcdefghijklm',
  'curl "https://h.invalid?x=1" -H "X-Signature: 7e6d5c4b3a291807f6e5d4c3b2a1908f7e6d5c4b"',
  `cp -r /root/.cliRootSecret7016 /tmp/${me.toUpperCase()}_backup && ls /home/${me}x/${me}_old`,
];
const GAP_PLANTED = ['cliJsonApiKey7001', 'cliJsonPw7002', 'cliJsonDbPw7003', 'cliFlagPw7004', 'cliFlagKey7005', 'cliFlagTok7006',
  'cliFlagSec7007', 'cliMysqlPw7008', 'cliHdrKey7009', 'cliHdrKey7010', 'cliStripeLive7011', 'cliStripeTest7012', 'cliStripeRk7013',
  'npm_cliNpmTok7014', 'hf_cliHuggingFaceTok7015', '7e6d5c4b3a291807f6e5d4c3b2a1908f7e6d5c4b', '/root/', 'glpat-FAKEtoolNameTok0000abcd',
  'keyowner7017@example.org'];
const RUNTIME_PLANTED = me.length >= 3 ? [os.homedir(), me, me.toUpperCase()] : [os.homedir()];
const GAP_SESSION = 'ffffffff-0000-4000-8000-000000000006';

function gapTranscript() {
  const env = (type, uuid, message) => JSON.stringify({ parentUuid: null, isSidechain: false, cwd: '/home/alice/proj', sessionId: GAP_SESSION,
    type, message, uuid, timestamp: '2026-10-05T07:00:00.000Z' });
  const tools = [...GAP_COMMANDS.map(c => ['Bash', { command: c }]), [GAP_TOOL, { 'keyowner7017@example.org': 'x' }]];
  const lines = [env('user', 'g-u-0', { role: 'user', content: 'go' })];
  tools.forEach(([name, input], i) => {
    lines.push(env('assistant', `g-a-${i}`, { id: `msg_G${i}`, role: 'assistant', content: [{ type: 'tool_use', id: `toolu_G${i}`, name, input }], stop_reason: 'tool_use' }));
    lines.push(env('user', `g-r-${i}`, { role: 'user', content: [{ tool_use_id: `toolu_G${i}`, type: 'tool_result', content: 'ok' }] }));
  });
  return lines.join('\n') + '\n';
}

const setup = (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-redact-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  fs.mkdirSync(path.join(d, 'projects', '-home-fixture-proj'), { recursive: true });
  fs.copyFileSync(path.join(here, 'fixtures/projects/-home-fixture-proj', SECRETS), path.join(d, 'projects', '-home-fixture-proj', SECRETS));
  return d;
};
const setupGaps = (t) => {
  const d = setup(t);
  fs.writeFileSync(path.join(d, 'projects', '-home-fixture-proj', `${GAP_SESSION}.jsonl`), gapTranscript());
  return d;
};
const cli = (d, extra, hook = ECHO_DENY) => spawnSync(process.execPath, [path.join(root, 'bin/hook-replay.js'), '--projects-dir', path.join(d, 'projects'),
  '--hook', hook, '--event', 'PreToolUse', '--samples', '50', '--allow-network', ...extra], { encoding: 'utf8', cwd: root });
// The banner prints the hook command: give it a planted value and the repo path (under the real home).
const BANNER_HOOK = `${ECHO_DENY} # --api-key cliBannerKey7018 ${root}`;

for (const mode of ['table', 'json']) {
  test(`(d) ${mode}: no planted secret, "alice" or "/home/" appears in the report; all appear with --show-raw`, (t) => {
    const d = setup(t);
    const flags = mode === 'json' ? ['--json'] : [];
    const red = cli(d, flags);
    assert.equal(red.status, 0, red.stderr);
    if (mode === 'json') {
      const m = JSON.parse(red.stdout);
      assert.equal(m.redacted, true);
      assert.equal(m.hooks[0].counts.block, 15);
      assert.equal(m.hooks[0].samples.length, 15);
    } else {
      assert.match(red.stdout, /h1\s+PreToolUse\s+-\s+15\s+15\b/);
    }
    for (const v of PLANTED) assert.ok(!(red.stdout + red.stderr).includes(v), `redacted ${mode} output contains ${v}`);

    const raw = cli(d, [...flags, '--show-raw']);
    assert.equal(raw.status, 0, raw.stderr);
    for (const v of PLANTED) assert.ok(raw.stdout.includes(v), `--show-raw ${mode} output lacks ${v}`);
    assert.match(raw.stderr + raw.stdout, /redaction OFF/);
  });
}

test('(d) --out writes the JSON report with mode 0600', (t) => {
  const d = setup(t);
  const out = path.join(d, 'report.json');
  const r = cli(d, ['--json', '--out', out]);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(fs.statSync(out).mode & 0o777, 0o600);
  assert.equal(JSON.parse(fs.readFileSync(out, 'utf8')).schema, 'hook-replay/report@1');
});

const ALL = [...PLANTED, ...GAP_PLANTED, ...RUNTIME_PLANTED, 'cliBannerKey7018'];
const MODES = { table: [], json: ['--json'], out: ['--out', null], 'dry-run': ['--dry-run'], 'dry-run json': ['--dry-run', '--json'] };

for (const [mode, flags] of Object.entries(MODES)) {
  test(`(d) ${mode}: nothing planted reaches stdout, stderr or the --out file; --show-raw shows it`, (t) => {
    const d = setupGaps(t);
    // A settings warning names the settings path (under the real home) and the hook command is in the banner.
    const sdir = fs.mkdtempSync(path.join(root, '.hook-replay-redact-'));
    t.after(() => fs.rmSync(sdir, { recursive: true, force: true }));
    const settings = path.join(sdir, 'settings.json');
    fs.writeFileSync(settings, JSON.stringify({ hooks: { SessionStart: [{ hooks: [{ type: 'command', command: 'true' }] }],
      PreToolUse: [{ hooks: [{ type: 'command', command: BANNER_HOOK }] }] } }));
    const run = (extra) => {
      const out = path.join(d, `report-${extra.length}.json`);
      const args = flags.map(f => f === null ? out : f);
      const r = spawnSync(process.execPath, [path.join(root, 'bin/hook-replay.js'), '--projects-dir', path.join(d, 'projects'),
        '--settings', settings, '--samples', '50', '--allow-network', ...args, ...extra], { encoding: 'utf8', cwd: root });
      assert.equal(r.status, 0, r.stderr);
      return r.stdout + r.stderr + (fs.existsSync(out) ? fs.readFileSync(out, 'utf8') : '');
    };
    const red = run([]);
    assert.match(red, mode.startsWith('dry-run') ? /dry run/ : /replay EXECUTES/);
    for (const v of ALL) assert.ok(!red.includes(v), `redacted ${mode} output contains ${v}`);
    const raw = run(['--show-raw']);
    const shown = mode.startsWith('dry-run') ? [GAP_TOOL, os.homedir()] : [...PLANTED, ...GAP_PLANTED, 'cliBannerKey7018', os.homedir()];
    for (const v of shown) assert.ok(raw.includes(v), `--show-raw ${mode} output lacks ${v}`);
  });
}

test('usage and load errors print redacted paths', (t) => {
  const missing = path.join(root, '.hook-replay-missing', 'cliMissingKey7019', 'settings.json');
  const r = spawnSync(process.execPath, [path.join(root, 'bin/hook-replay.js'), '--settings', missing], { encoding: 'utf8', cwd: root });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /cannot load ~\//);
  for (const v of RUNTIME_PLANTED) assert.ok(!r.stderr.includes(v), `stderr contains ${v}`);
});

test('an internal error prints a redacted message and no stack trace, unless HOOK_REPLAY_DEBUG=1', async () => {
  const boom = () => { throw new Error(`EBOOM ${os.homedir()}/cliInternal7020 api_key=cliInternalKey7021`); };
  const capture = () => { const io = { err: '', stdout: { write: boom }, stderr: { write: (x) => { io.err += x; } } }; return io; };
  const args = ['--hook', 'true', '--event', 'PreToolUse', '--dry-run', '--projects-dir', path.join(here, 'fixtures/projects')];
  const io = capture();
  assert.equal(await main(args, io, {}), 1);
  assert.match(io.err, /\nhook-replay: internal error: EBOOM ~\/cliInternal7020 api_key=\[REDACTED:value\]\n$/);
  assert.doesNotMatch(io.err, /\n    at /);
  const dbg = capture();
  assert.equal(await main(args, dbg, { HOOK_REPLAY_DEBUG: '1' }), 1);
  assert.match(dbg.err, /\n    at /);
  assert.ok(!dbg.err.includes('cliInternalKey7021') && !dbg.err.includes(os.homedir()));
});

// Round-3 review: structured MCP credentials and header/CLI forms that leaked through the real CLI.
const R3_SESSION = 'ffffffff-0000-4000-8000-000000000007';
const R3_TOOLS = [
  ['mcp__db__connect', { host: 'db', user: 'u', password: 'r3CliMcpPw8840', port: 55443322, opts: { api_token: ['r3CliNested8841'] } }],
  ['Bash', { command: 'curl -H "Authorization: Basic cjNDbGlCYXNpYzg4NDI=" https://h.invalid' }],
  ['Bash', { command: 'DB_PASS=r3CliDbPass8843 ./run && curl -u admin:r3CliCurlU8844 "https://h.invalid/?token=r3CliUrlTok8845"' }],
];
const R3_PLANTED = ['r3CliMcpPw8840', 'r3CliNested8841', 'cjNDbGlCYXNpYzg4NDI', 'r3CliDbPass8843', 'r3CliCurlU8844', 'r3CliUrlTok8845'];
const ANY_DENY = `node -e "process.stdin.resume().on('end',()=>console.log(JSON.stringify({hookSpecificOutput:{hookEventName:'PreToolUse',permissionDecision:'deny',permissionDecisionReason:'no'}})))"`;

for (const mode of ['table', 'json']) {
  test(`(d) round 3, ${mode}: structured MCP credentials and Basic/-u/DB_PASS/URL tokens do not leak; --show-raw shows them`, (t) => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-redact-'));
    t.after(() => fs.rmSync(d, { recursive: true, force: true }));
    const dir = path.join(d, 'projects', '-srv-proj');
    fs.mkdirSync(dir, { recursive: true });
    const env = (type, uuid, message) => JSON.stringify({ parentUuid: null, isSidechain: false, cwd: '/srv/proj', sessionId: R3_SESSION,
      type, message, uuid, timestamp: '2026-10-05T07:00:00.000Z' });
    const lines = [env('user', 'r3-u', { role: 'user', content: 'go' })];
    R3_TOOLS.forEach(([name, input], i) => {
      lines.push(env('assistant', `r3-a-${i}`, { id: `msg_R3${i}`, role: 'assistant', content: [{ type: 'tool_use', id: `toolu_R3${i}`, name, input }], stop_reason: 'tool_use' }));
      lines.push(env('user', `r3-r-${i}`, { role: 'user', content: [{ tool_use_id: `toolu_R3${i}`, type: 'tool_result', content: 'ok' }] }));
    });
    fs.writeFileSync(path.join(dir, `${R3_SESSION}.jsonl`), lines.join('\n') + '\n');
    const flags = mode === 'json' ? ['--json'] : [];
    const red = cli(d, flags, ANY_DENY);
    assert.equal(red.status, 0, red.stderr);
    for (const v of R3_PLANTED) assert.ok(!(red.stdout + red.stderr).includes(v), `redacted ${mode} output contains ${v}`);
    const raw = cli(d, [...flags, '--show-raw'], ANY_DENY);
    for (const v of R3_PLANTED) assert.ok(raw.stdout.includes(v), `--show-raw ${mode} output lacks ${v}`);
  });
}

test('an uncaught exception prints one redacted line (exit 1), not Node\'s raw stack; the stack only with HOOK_REPLAY_DEBUG=1', (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-crash-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  // Throws from outside main()'s promise chain, after the first stderr write; the Error is made inside src/, so a
  // raw stack would name the install path.
  const boom = path.join(d, 'boom.mjs');
  fs.writeFileSync(boom, `import os from 'node:os';
const w = process.stderr.write.bind(process.stderr); let armed = true;
process.stderr.write = (...a) => { if (armed) { armed = false; const e = new Error('EBOOM ' + os.homedir() + '/x api_key=r3CrashKey8850');
  setImmediate(() => { throw e; }); } return w(...a); };\n`);
  const args = ['--import', `file://${boom}`, path.join(root, 'bin/hook-replay.js'), '--hook', 'true', '--event', 'PreToolUse', '--dry-run',
    '--projects-dir', path.join(here, 'fixtures/projects')];
  const r = spawnSync(process.execPath, args, { encoding: 'utf8', cwd: root, env: { ...process.env, HOOK_REPLAY_DEBUG: '' } });
  assert.equal(r.status, 1, r.stderr);
  assert.match(r.stderr, /\nhook-replay: internal error: EBOOM ~\/x api_key=\[REDACTED:value\]\n$/);
  for (const v of ['r3CrashKey8850', os.homedir(), root, '    at ']) assert.ok(!r.stderr.includes(v), `stderr contains ${v}`);
  const dbg = spawnSync(process.execPath, args, { encoding: 'utf8', cwd: root, env: { ...process.env, HOOK_REPLAY_DEBUG: '1' } });
  assert.equal(dbg.status, 1);
  assert.match(dbg.stderr, /\n    at /);
  for (const v of ['r3CrashKey8850', os.homedir()]) assert.ok(!dbg.stderr.includes(v), `debug stderr contains ${v}`);
});
