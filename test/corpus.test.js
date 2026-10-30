import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { discover } from '../src/corpus.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const projects = path.join(here, 'fixtures/projects');

test('discover lists main and subagent transcripts, sorted bytewise, with project and session uuid', () => {
  const files = discover(projects);
  assert.deepEqual(files.map(f => [f.relPath, f.project, f.sessionUuid, f.subagent]), [
    ['-home-fixture-proj/aaaaaaaa-0000-4000-8000-000000000001.jsonl', '-home-fixture-proj', 'aaaaaaaa-0000-4000-8000-000000000001', false],
    ['-home-fixture-proj/bbbbbbbb-0000-4000-8000-000000000002.jsonl', '-home-fixture-proj', 'bbbbbbbb-0000-4000-8000-000000000002', false],
    ['-home-fixture-proj/bbbbbbbb-0000-4000-8000-000000000002/subagents/agent-a1b2c3.jsonl', '-home-fixture-proj', 'bbbbbbbb-0000-4000-8000-000000000002', true],
    ['-home-fixture-proj/cccccccc-0000-4000-8000-000000000003.jsonl', '-home-fixture-proj', 'cccccccc-0000-4000-8000-000000000003', false],
    ['-home-fixture-proj/dddddddd-0000-4000-8000-000000000004.jsonl', '-home-fixture-proj', 'dddddddd-0000-4000-8000-000000000004', false],
    ['-home-fixture-proj/eeeeeeee-0000-4000-8000-000000000005.jsonl', '-home-fixture-proj', 'eeeeeeee-0000-4000-8000-000000000005', false],
  ]);
  assert.equal(files[0].path, path.join(projects, files[0].relPath));
});

test('discover does not follow symlinks and ignores non-jsonl files', (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hr-corpus-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  fs.mkdirSync(path.join(d, 'p'));
  fs.writeFileSync(path.join(d, 'p', 's1.jsonl'), '');
  fs.writeFileSync(path.join(d, 'p', 'notes.txt'), '');
  fs.symlinkSync(path.join(d, 'p', 's1.jsonl'), path.join(d, 'p', 's2.jsonl'));
  fs.symlinkSync(path.join(d, 'p'), path.join(d, 'linkdir'));
  assert.deepEqual(discover(d).map(f => f.relPath), ['p/s1.jsonl']);
});
