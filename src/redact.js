// Best-effort secret redaction (DESIGN.md §8), applied in order. Pattern matching, not a guarantee.
import os from 'node:os';

const R = (kind) => `[REDACTED:${kind}]`;
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function entropy(s) {
  const counts = new Map();
  for (const c of s) counts.set(c, (counts.get(c) || 0) + 1);
  let h = 0;
  for (const n of counts.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

const RULES = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, R('private_key')],
  [/sk-ant-[A-Za-z0-9_-]{10,}/g, R('api_key')],
  [/sk-(proj-)?[A-Za-z0-9_-]{20,}/g, R('api_key')],
  [/gh[pousr]_[A-Za-z0-9]{20,}/g, R('github_token')],
  [/github_pat_[A-Za-z0-9_]{20,}/g, R('github_token')],
  [/\b(AKIA|ASIA)[A-Z0-9]{16}\b/g, R('aws_key')],
  [/xox[abprs]-[A-Za-z0-9-]{10,}/g, R('slack_token')],
  [/AIza[0-9A-Za-z_-]{35}/g, R('google_key')],
  [/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, R('jwt')],
  // "Authorization: Bearer <t>" is one header: the optional Bearer keeps the token from surviving (see Deviations).
  [/(Authorization:\s*(?:Bearer\s+)?|Bearer\s+)\S+/g, `$1${R('token')}`],
  [/\b([A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY|PRIVATE_KEY)[A-Z0-9_]*)\s*[=:]\s*("[^"]*"|'[^']*'|\S+)/gi,
    (m, _name, _kw, value) => m.slice(0, m.length - value.length) + R('value')],
  [/([a-z][a-z0-9+.-]*:\/\/)[^/\s:@]+:[^/\s@]+@/g, `$1${R('userinfo')}@`],
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, R('email')],
];

export function redact(s, { homedir = os.homedir(), username = safeUsername() } = {}) {
  if (typeof s !== 'string' || s === '') return s;
  let out = s;
  for (const [re, rep] of RULES) out = out.replace(re, rep);
  if (homedir && homedir !== '/') out = out.split(homedir).join('~');
  out = out.replace(/\/home\/[^/\s]+/g, '~').replace(/\/Users\/[^/\s]+/g, '~').replace(/[A-Z]:\\Users\\[^\\\s]+/g, '~');
  if (username && username.length >= 3) out = out.replace(new RegExp(`(?<![A-Za-z0-9_])${escapeRe(username)}(?![A-Za-z0-9_])`, 'g'), '[user]');
  out = out.replace(/[A-Za-z0-9+/=_-]{32,}/g, (tok) => entropy(tok) >= 4.5 ? R('high_entropy') : tok);
  return out;
}

function safeUsername() {
  try { return os.userInfo().username; } catch { return process.env.USER || ''; }
}

export function makeRedactor({ enabled = true, homedir, username } = {}) {
  if (!enabled) return (s) => s;
  return (s) => redact(s, { homedir, username });
}

// Escape C0/C1 control characters other than \n and \t as \xNN (transcripts can hold terminal escapes).
export function escapeControl(s) {
  return s.replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`);
}
