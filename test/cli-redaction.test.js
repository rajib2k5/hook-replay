// Golden test (d): the real CLI on the planted-secrets fixture leaks none of them, in table or --json output;
// with --show-raw every one of them appears, which proves this test can fail.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

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

const setup = (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-redact-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  fs.mkdirSync(path.join(d, 'projects', '-home-fixture-proj'), { recursive: true });
  fs.copyFileSync(path.join(here, 'fixtures/projects/-home-fixture-proj', SECRETS), path.join(d, 'projects', '-home-fixture-proj', SECRETS));
  return d;
};
const cli = (d, extra) => spawnSync(process.execPath, [path.join(root, 'bin/hook-replay.js'), '--projects-dir', path.join(d, 'projects'),
  '--hook', ECHO_DENY, '--event', 'PreToolUse', '--samples', '50', '--allow-network', ...extra], { encoding: 'utf8', cwd: root });

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
    for (const v of PLANTED) assert.ok(!red.stdout.includes(v), `redacted ${mode} output contains ${v}`);

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
