import { test } from 'node:test';
import assert from 'node:assert/strict';
import { percentile, latencySummary } from '../src/stats.js';

test('percentile, n=1: every quantile is the single value', () => {
  assert.deepEqual([percentile([7], 0.5), percentile([7], 0.95), percentile([7], 1)], [7, 7, 7]);
});

test('percentile, n=20: nearest rank xs[ceil(q*n)-1] on sorted input', () => {
  const xs = Array.from({ length: 20 }, (_, i) => 20 - i); // 20..1, unsorted on purpose
  assert.equal(percentile(xs, 0.5), 10);
  assert.equal(percentile(xs, 0.95), 19);
  assert.equal(percentile(xs, 0.05), 1);
});

test('percentile with ties', () => {
  assert.equal(percentile([5, 5, 5, 1], 0.5), 5);
  assert.equal(percentile([1, 1, 9, 9], 0.5), 1);
});

test('percentile of nothing is null, and the input is not mutated', () => {
  assert.equal(percentile([], 0.5), null);
  const xs = [3, 1, 2];
  percentile(xs, 0.5);
  assert.deepEqual(xs, [3, 1, 2]);
});

test('latencySummary gives n, p50, p95, max', () => {
  assert.deepEqual(latencySummary([4, 1, 3, 2]), { n: 4, p50: 2, p95: 4, max: 4 });
  assert.deepEqual(latencySummary([]), { n: 0, p50: null, p95: null, max: null });
});
