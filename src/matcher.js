// Matcher semantics from the hooks reference ("Matcher patterns"), applied to tool_name. Stop ignores matchers.
export const matches = (m, name) => m === undefined || m === null || m === '' || m === '*' ? true
  : /^[A-Za-z0-9_\- ,|]+$/.test(m) ? m.split(/[|,]/).map(s => s.trim()).filter(Boolean).includes(name)
  : new RegExp(m).test(name); // unanchored

export function validateMatcher(m) {
  if (m === undefined || m === null || m === '' || m === '*' || /^[A-Za-z0-9_\- ,|]+$/.test(m)) return;
  try { new RegExp(m); } catch (e) { throw new Error(`invalid matcher ${JSON.stringify(m)}: ${e.message}`); }
}
