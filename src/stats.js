// Nearest-rank percentile (DESIGN.md §7 "Latency"): sort ascending, p(q) = xs[ceil(q*n) - 1].
export function percentile(xs, q) {
  if (xs.length === 0) return null;
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.max(0, Math.ceil(q * s.length) - 1)];
}

export function latencySummary(xs) {
  return { n: xs.length, p50: percentile(xs, 0.5), p95: percentile(xs, 0.95), max: xs.length ? Math.max(...xs) : null };
}
