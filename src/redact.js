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

// Rule 7's names, also with '-' (X-Api-Key, Api-Key) and with a closing quote before the separator ("api_key": ...).
const KEY_NAME = String.raw`\b([A-Z0-9_-]*(SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|ACCESS[_-]KEY|PRIVATE[_-]KEY)[A-Z0-9_-]*)(\\?["']?)`;
const VALUE = String.raw`(\\"(?:[^"\\]|\\[^"])*\\"|"(?:[^"\\]|\\.)*"|'[^']*'|\S+)`;

const RULES = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, R('private_key')],
  [/sk-ant-[A-Za-z0-9_-]{10,}/g, R('api_key')],
  [/sk-(proj-)?[A-Za-z0-9_-]{20,}/g, R('api_key')],
  [/(?<![A-Za-z0-9])[sr]k_(?:live|test)_[A-Za-z0-9]{10,}/g, R('api_key')], // Stripe
  [/gh[pousr]_[A-Za-z0-9]{20,}/g, R('github_token')],
  [/github_pat_[A-Za-z0-9_]{20,}/g, R('github_token')],
  [/(?<![A-Za-z0-9])glpat-[A-Za-z0-9_-]{20,}/g, R('gitlab_token')],
  [/(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])/g, R('npm_token')],
  [/(?<![A-Za-z0-9])hf_[A-Za-z0-9]{30,}/g, R('hf_token')],
  [/\b(AKIA|ASIA)[A-Z0-9]{16}\b/g, R('aws_key')],
  [/xox[abprs]-[A-Za-z0-9-]{10,}/g, R('slack_token')],
  [/AIza[0-9A-Za-z_-]{35}/g, R('google_key')],
  [/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, R('jwt')],
  // "Authorization: Bearer <t>" is one header: the optional Bearer keeps the token from surviving (see Deviations).
  [/(Authorization:\s*(?:Bearer\s+)?|Bearer\s+)\S+/g, `$1${R('token')}`],
  [new RegExp(`${KEY_NAME}\\s*[=:]\\s*${VALUE}`, 'gi'), (m, _name, _kw, _q, value) => m.slice(0, m.length - value.length) + R('value')],
  // CLI flags with a space before the value (--password=X is the rule above). The value may not look like a flag.
  [/(--(?:[a-z0-9]+-)*(?:password|passwd|pass|token|secret|api-?key|access-key|private-key)(?:-[a-z0-9]+)*)(\s+)("[^"]*"|'[^']*'|[^\s-]\S*)/gi, `$1$2${R('value')}`],
  // mysql/mariadb family only: -p directly followed by >= 4 non-space characters is the password.
  [/(\b(?:mysql|mariadb)[\w-]*\s(?:[^\n|;&]*?\s)?)-p(\S{4,})/g, `$1-p${R('value')}`],
  // Hex (>= 32) is redacted only after a key-like name or an X- header: bare git SHAs must survive.
  [/(\b[\w-]*(?:key|token|secret|auth|signature|sig|session|cookie|credential|pass)[\w-]*\\?["']?\s*[=:]\s*\\?["']?)[0-9a-f]{32,}(?![0-9a-z])/gi, `$1${R('hex_secret')}`],
  [/(\bX-[\w-]+\s*:\s*)[0-9a-f]{32,}(?![0-9a-z])/gi, `$1${R('hex_secret')}`],
  [/([a-z][a-z0-9+.-]*:\/\/)[^/\s:@]+:[^/\s@]+@/g, `$1${R('userinfo')}@`],
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, R('email')],
];

// Usernames of 6+ characters are replaced anywhere, case-insensitively (quokka7_backup, QUOKKA7_HOME,
// xquokka7y); 3-5 characters only when no letter touches them, so a name like "emu" leaves "lemur" alone.
function userRe(username) {
  const u = escapeRe(username);
  return username.length >= 6 ? new RegExp(u, 'gi') : new RegExp(`(?<![A-Za-z])${u}(?![A-Za-z])`, 'gi');
}

export function redact(s, { homedir = os.homedir(), username = safeUsername() } = {}) {
  if (typeof s !== 'string' || s === '') return s;
  let out = s;
  for (const [re, rep] of RULES) out = out.replace(re, rep);
  if (homedir && homedir !== '/') out = out.split(homedir).join('~');
  out = out.replace(/\/home\/[^/\s]+/g, '~').replace(/\/Users\/[^/\s]+/g, '~').replace(/[A-Z]:\\Users\\[^\\\s]+/g, '~')
    .replace(/\/root(?![\w.-])/g, '~');
  if (username && username.length >= 3) out = out.replace(userRe(username), '[user]');
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
