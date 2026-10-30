import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.dirname(here);
const cli = (args) => spawnSync(process.execPath, [path.join(root, 'bin/hook-replay.js'), ...args], { encoding: 'utf8', cwd: root });
const base = ['--projects-dir', path.join(here, 'fixtures/projects')];

// Counts below were checked by hand against the fixture files (see test/fixtures/README.md).
test('dry run --json reports corpus counts and per-tool point counts, and runs nothing', () => {
  const r = cli([...base, '--hook', 'exit 7', '--event', 'PreToolUse', '--dry-run', '--json']);
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.deepEqual(out.corpus, {
    files: 6, files_unreadable: 0, lines: 86, lines_malformed: 3, lines_oversize: 0, orphan_tool_results: 0, sessions: 5,
    points_by_event: { PreToolUse: 27, PostToolUse: 25, Stop: 7 },
  });
  assert.equal(out.hooks.length, 1);
  assert.deepEqual(out.hooks[0].by_tool, { Bash: 23, Read: 1, Edit: 1, Write: 1, Task: 1 });
  assert.equal(out.hooks[0].points, 27);
  assert.match(r.stderr, /dry run/i);
});

test('dry run with a matcher counts only matching tools', () => {
  const r = cli([...base, '--hook', 'true', '--event', 'PostToolUse', '--matcher', 'Edit|Write', '--dry-run', '--json']);
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(r.stdout).hooks[0].by_tool, { Edit: 1, Write: 1 });
});

test('dry run human output prints one line per hook x tool', () => {
  const r = cli([...base, '--hook', 'true', '--event', 'Stop', '--dry-run']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /h1\s+Stop\s+-\s+7\b/);
});

test('--matcher with Stop is a usage error (exit 2)', () => {
  const r = cli([...base, '--hook', 'true', '--event', 'Stop', '--matcher', 'Bash', '--dry-run']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /matcher/);
});

test('--hook without --event is a usage error (exit 2)', () => {
  assert.equal(cli([...base, '--hook', 'true', '--dry-run']).status, 2);
});
