import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matches, validateMatcher } from '../src/matcher.js';

// Every example from the hooks reference, "Matcher patterns".
const cases = [
  [undefined, 'Bash', true], ['', 'Anything', true], ['*', 'Read', true],
  ['Bash', 'Bash', true], ['Bash', 'BashOutput', false], ['Bash', 'bash', false],
  ['Edit|Write', 'Edit', true], ['Edit|Write', 'Write', true], ['Edit|Write', 'Read', false],
  ['Edit, Write', 'Write', true], ['Edit, Write', 'Edit', true], ['Edit, Write', 'NotebookEdit', false],
  ['^Notebook', 'NotebookEdit', true], ['^Notebook', 'MyNotebook', false],
  ['mcp__memory__.*', 'mcp__memory__create_entities', true], ['mcp__memory__.*', 'mcp__github__x', false],
  ['Edit.*', 'NotebookEdit', true], ['Edit.*', 'Edit', true],
  ['Edit', 'NotebookEdit', false],
];

for (const [m, name, want] of cases) {
  test(`matches(${JSON.stringify(m)}, ${name}) is ${want}`, () => assert.equal(matches(m, name), want));
}

test('an invalid regex matcher is a load error', () => {
  assert.throws(() => validateMatcher('Bash('), /invalid matcher/);
  assert.doesNotThrow(() => validateMatcher('Edit|Write'));
});
