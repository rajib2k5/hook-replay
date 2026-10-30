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
const NAMES = String.raw`SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE|CREDENTIALS?|API[_-]?KEY|ACCESS[_-]KEY|PRIVATE[_-]KEY|ACCOUNT[_-]?KEY|SHARED[_-]?ACCESS[_-]?KEY`;
const KEY_NAME = String.raw`\b([A-Z0-9_-]*(${NAMES})[A-Z0-9_-]*)(\\?["']?)`;
// A value: a JSON string inside a JSON string (\"...\", where an inner quote is \\\" and an inner backslash \\\\),
// a JSON string, a single-quoted string, or a word that is not an earlier rule's [REDACTED:...] marker.
const VALUE = String.raw`(?!\\?["']?\[REDACTED:)(\\"(?:[^"\\]|\\\\\\"|\\\\\\\\|\\\\[^"\\]|\\[^"\\])*\\"|"(?:[^"\\]|\\.)*"|'[^']*'|(?!\[REDACTED:)\S+)`;
// Object keys whose whole value is redacted (report.js redactDeep): rule 7's names, plus a key that is or ends in
// pass/pwd, Authorization, Cookie.
const SECRET_KEY = new RegExp(String.raw`^[A-Z0-9_-]*(${NAMES})[A-Z0-9_-]*$|^([A-Z0-9_-]*[_-])?(PASS|PWD)$|AUTHORIZATION|^(SET-)?COOKIE$`, 'i');
export const isSecretKey = (k) => typeof k === 'string' && SECRET_KEY.test(k);
const AUTH_SCHEMES = 'Bearer|Basic|Token|Negotiate|NTLM|ApiKey';
const AUTH_PARAM_SCHEMES = String.raw`Digest|OAuth|Hawk|AWS4-HMAC-SHA256|SCRAM-SHA-\d+`;

const RULES = [
  // A key cut short (BEGIN without END: a truncated excerpt or output cap) is redacted to the end of the string.
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, R('private_key')],
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
  // "Authorization: <scheme> <credential>" is one header: the scheme is consumed with it, so the credential cannot
  // survive (see Deviations). Schemes with comma-separated parameters (Digest, ...) are redacted to the end of the line.
  [new RegExp(String.raw`((?:Proxy-)?Authorization\\?["']?\s*:\s*\\?["']?)(?:(${AUTH_PARAM_SCHEMES})\s+[^\r\n]*|((?:${AUTH_SCHEMES})\s+)?(?!["']?\[REDACTED:)\S+)|\b(Bearer\s+)(?!\[REDACTED:)\S+`, 'gi'),
    (m, pre, pscheme, scheme, bearer) => pre === undefined ? bearer + R('token') : pre + (pscheme ? `${pscheme} ` : scheme ?? '') + R('token')],
  // Cookie and Set-Cookie headers: the whole value, up to a quote or the end of the line.
  [/(\b(?:Set-)?Cookie\\?["']?\s*:\s*\\?["']?)[^"'\\\r\n]+/gi, `$1${R('cookie')}`],
  // URL query parameters that carry a credential (SAS sig=, ?token=, ...): the value up to & # or a quote.
  [/([?&;](?:token|access_token|refresh_token|id_token|api_key|apikey|key|secret|client_secret|password|passwd|sig|signature)=)[^&#\s"'\\]+/gi, `$1${R('value')}`],
  // HTTP basic auth on the command line (curl -u user:pw, --user=user:pw); a value without ':' (a uid:gid is digits) is left.
  [/(\s(?:-u|--user)(?:\s+|=)?)("[^"\s:]*:[^"]*"|'[^'\s:]*:[^']*'|(?!\d+:\d+(?:\s|$))[^\s"':-][^\s"':]*:\S+)/g, `$1${R('value')}`],
  // sshpass -p <password> (also -p'x').
  [/(\bsshpass\b[^\n|;&]*?\s-p\s*)("[^"]*"|'[^']*'|\S+)/g, `$1${R('value')}`],
  [new RegExp(`${KEY_NAME}\\s*[=:]\\s*${VALUE}`, 'gi'), (m, _name, _kw, _q, value) => m.slice(0, m.length - value.length) + R('value')],
  // Environment-style names that are or end in PASS/PWD (DB_PASS=, MYSQL_PWD=, pass=); a bare PWD= (the shell's cwd) is left.
  [new RegExp(String.raw`\b((?:[A-Z0-9]+_)+(?:PASS|PWD)|PASS)(\\?["']?)\s*[=:]\s*${VALUE}`, 'gi'), (m, _n, _q, value) => m.slice(0, m.length - value.length) + R('value')],
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
  // '/' is not part of a token, so a long path is judged segment by segment. A standard-base64 run with '/' (an AWS
  // secret key, say) is judged whole when it has upper case, lower case and a digit and no segment is a lowercase word.
  out = out.replace(/(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/=_-])/g, (tok) => tok.includes('/') && /[A-Z]/.test(tok) && /[a-z]/.test(tok) &&
    /[0-9]/.test(tok) && !tok.split('/').some(seg => /^[a-z]{3,}$/.test(seg)) && entropy(tok) >= 4.5 ? R('high_entropy') : tok);
  out = out.replace(/[A-Za-z0-9+=_-]{32,}/g, (tok) => entropy(tok) >= 4.5 ? R('high_entropy') : tok);
  return out;
}

function safeUsername() {
  try { return os.userInfo().username; } catch { return process.env.USER || ''; }
}

export function makeRedactor({ enabled = true, homedir, username } = {}) {
  if (!enabled) return Object.assign((s) => s, { enabled: false });
  return Object.assign((s) => redact(s, { homedir, username }), { enabled: true });
}

// Escape C0/C1 control characters other than \n and \t as \xNN (transcripts can hold terminal escapes).
export function escapeControl(s) {
  return s.replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`);
}
