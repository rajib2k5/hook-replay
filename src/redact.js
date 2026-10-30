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
// A bare word: non-space characters up to whitespace, except a closing quote (also \" or \') that ends the word, i.e.
// is followed by whitespace, an escaped \n, , ; ) ] } or the end: "X-Api-Key: v" keeps its quote (round-5 review).
const WORD = String.raw`(?:(?!\\?["'](?:[\s,;)\]}]|\\[nrt]|$))\S)+`;
// A value: a number or boolean (kept by keepScalar unless the name ends in a secret word), a JSON string inside a
// JSON string (\"...\", where an inner quote is \\\" and an inner backslash \\\\), a JSON string, a single-quoted
// string, a flat [...] array or {...} object (every element goes, also inside a string), or a WORD that is not an
// earlier rule's [REDACTED:...] marker.
const VALUE = String.raw`(?!\\?["']?\[REDACTED:)(-?\d+(?:\.\d+)?(?![\w.:/-])|(?:true|false|null)(?![\w-])|\\"(?:[^"\\]|\\\\\\"|\\\\\\\\|\\\\[^"\\]|\\[^"\\])*\\"|"(?:[^"\\]|\\.)*"|'[^']*'|\[[^\[\]\n]*\]|\{[^{}\n]*\}|(?!\[REDACTED:)${WORD})`;
// Key-context redaction keeps a number or boolean (max_tokens: 4096, PASSWORD_MIN_LENGTH=8,
// TOKENIZERS_PARALLELISM=false); a number is still redacted when the name ends in a secret word (PASSWORD=1234).
const SECRET_END = /(SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE|CREDENTIALS?|KEY|PASS|PWD|AUTHORIZATION|COOKIE)\\?["']?$/i;
export function keepScalar(name, value) {
  if (typeof value === 'boolean' || value === null) return true;
  if (typeof value === 'number') return !SECRET_END.test(name);
  if (typeof value !== 'string') return false;
  const v = value.replace(/^\\?["']|\\?["']$/g, '');
  return /^(true|false|null)$/i.test(v) || (/^-?\d+(\.\d+)?$/.test(v) && !SECRET_END.test(name));
}
const keepOr = (m, name, value) => keepScalar(name, value) ? m : m.slice(0, m.length - value.length) + R('value');
// Object keys whose whole value is redacted (report.js redactDeep): rule 7's names, plus a key that is or ends in
// pass/pwd, Authorization, Cookie, and a key that is exactly auth (docker config.json "auth").
const SECRET_KEY = new RegExp(String.raw`^[A-Z0-9_-]*(${NAMES})[A-Z0-9_-]*$|^([A-Z0-9_-]*[_-])?(PASS|PWD)$|AUTHORIZATION|^(SET-)?COOKIE$|^AUTH$`, 'i');
// Upper-case environment names that are or end in _KEY (OPENAI_KEY, KEY); lower case (sort_key) is left.
const ENV_KEY = String.raw`(?:[A-Z0-9]+_)*KEY`;
export const isSecretKey = (k) => typeof k === 'string' && (SECRET_KEY.test(k) || new RegExp(`^${ENV_KEY}$`).test(k));
// A secret-named value in an object (name/key field) or a word that names one, for the {"name": X, "value": Y} pair.
const SECRET_NAME = String.raw`[A-Z0-9_-]*(?:${NAMES})[A-Z0-9_-]*|(?:[A-Z0-9]+_)+(?:PASS|PWD|KEY)|KEY`;
// A long flag that takes a secret; --password-stdin, --token-file and the like take none.
const SECRET_FLAG = String.raw`--(?:[a-z0-9]+-)*(?:password|passwd|pass|pw|token|secret|api-?key|access-key|private-key)(?:-[a-z0-9]+)*(?<!-(?:stdin|file|env|cmd|command|prompt))`;
export const isSecretFlag = (s) => typeof s === 'string' && new RegExp(`^${SECRET_FLAG}$`, 'i').test(s);
// .netrc tokens are separated by whitespace, also an escaped \n inside a JSON string.
const SEP = String.raw`(?:\s|\\[nrt])+`;
const AUTH_SCHEMES = 'Bearer|Basic|Token|Negotiate|NTLM|ApiKey';
// A YAML line break (also an escaped \n) and the rest of a line up to one.
const YAML_NL = String.raw`(?:\n|\\n)`;
const YAML_LINE = String.raw`(?:[^\n\\]|\\(?!n))*`;
// A .pgpass field: an escaped colon (\:) or a backslash is part of it, except the \ of a \" that ends a value inside
// a JSON string. A field that starts with // is the rest of a URL (https://x), so it never is one.
const PG_FIELD = String.raw`(?!\/\/)(?:\\:|\\(?![":])|[^\s:"'\\])+`;
const AUTH_PARAM_SCHEMES = String.raw`Digest|OAuth|Hawk|AWS4-HMAC-SHA256|SCRAM-SHA-\d+`;

const RULES = [
  // A key cut short (BEGIN without END: a truncated excerpt or output cap) is redacted to the end of the string.
  // Also a PGP key (-----BEGIN PGP PRIVATE KEY BLOCK-----).
  [/-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)/g, R('private_key')],
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
  // Slack incoming-webhook and workflow URLs: the path after services/ (or workflows/, triggers/) is the credential.
  [/(\bhttps?:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/)[A-Za-z0-9_\/-]+/g, `$1${R('slack_webhook')}`],
  [/AIza[0-9A-Za-z_-]{35}/g, R('google_key')],
  [/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, R('jwt')],
  // "Authorization: <scheme> <credential>" is one header: the scheme is consumed with it, so the credential cannot
  // survive (see Deviations). Schemes with comma-separated parameters (Digest, ...) are redacted to the end of the line.
  [new RegExp(String.raw`((?:Proxy-)?Authorization\\?["']?\s*:\s*\\?["']?)(?:(${AUTH_PARAM_SCHEMES})\s+[^\r\n]*|((?:${AUTH_SCHEMES})\s+)?(?!["']?\[REDACTED:)${WORD})|\b(Bearer\s+)(?!\[REDACTED:)${WORD}`, 'gi'),
    (m, pre, pscheme, scheme, bearer) => pre === undefined ? bearer + R('token') : pre + (pscheme ? `${pscheme} ` : scheme ?? '') + R('token')],
  // Cookie and Set-Cookie headers: the whole value, up to a quote or the end of the line.
  [/(\b(?:Set-)?Cookie\\?["']?\s*:\s*\\?["']?)[^"'\\\r\n]+/gi, `$1${R('cookie')}`],
  // URL query parameters that carry a credential (SAS sig=, ?token=, ...): the value up to & # or a quote.
  [/([?&;](?:token|access_token|refresh_token|id_token|api_key|apikey|key|secret|client_secret|password|passwd|sig|signature)=)[^&#\s"'\\]+/gi, `$1${R('value')}`],
  // HTTP basic auth on the command line (curl -u user:pw, --user=user:pw); a value without ':' (a uid:gid is digits) is left.
  [/(\s(?:-u|--user)(?:\s+|=)?)("[^"\s:]*:[^"]*"|'[^'\s:]*:[^']*'|(?!\d+:\d+(?:\s|$))[^\s"':-][^\s"':]*:\S+)/g, `$1${R('value')}`],
  // sshpass -p <password> (also -p'x').
  [/(\bsshpass\b[^\n|;&]*?\s-p\s*)("[^"]*"|'[^']*'|\S+)/g, `$1${R('value')}`],
  // docker/podman login -p <password> (--password-stdin takes none).
  [/(\b(?:docker|podman|nerdctl|buildah|skopeo)\s+login\b[^\n|;&]*?\s-p\s*)("[^"]*"|'[^']*'|\S+)/g, `$1${R('value')}`],
  // aws configure set [<profile>.]aws_secret_access_key | aws_session_token <value>.
  [/(\baws\s+configure\b[^\n|;&]*?\bset\s+(?:[\w-]+\.)?(?:aws_secret_access_key|aws_session_token)\s+)("[^"]*"|'[^']*'|\S+)/g, `$1${R('value')}`],
  // htpasswd -b [-c ...] <file> <user> <password>, or -nb <user> <password> (no file): the last one is the password.
  [/(\bhtpasswd((?:\s+-[A-Za-z]+)+)\s+)("[^"]*"|'[^']*'|\S+)(\s+)("[^"]*"|'[^']*'|\S+)(?:(\s+)("[^"]*"|'[^']*'|\S+))?/g,
    (m, pre, flags, a, s1, b, s2, c) => !/b/.test(flags) ? m : /n/.test(flags) ? pre + a + s1 + R('value') + (s2 ?? '') + (c ?? '')
      : c === undefined ? m : pre + a + s1 + b + s2 + R('value')],
  // Python requests auth=("user", "password").
  [/(\bauth\s*=\s*\(\s*(?:"[^"]*"|'[^']*')\s*,\s*)("[^"]*"|'[^']*')/g, `$1${R('value')}`],
  // A .pgpass line, host:port:database:user:password (port digits or *, exactly five fields): the last field. It ends
  // at whitespace, a quote, a \" or the end (a URL after a location, file:12:5:https://x, is not one: see PG_FIELD).
  [new RegExp(String.raw`(?<![^\s"'=>])(${PG_FIELD}:(?:\d+|\*):${PG_FIELD}:${PG_FIELD}:)(${PG_FIELD})(?![^\s"'\\]|\\(?!"))`, 'g'), `$1${R('value')}`],
  // .netrc: machine <h> | default, then login/account/port pairs, then password <value>.
  [new RegExp(String.raw`((?:\bmachine${SEP}\S+|\bdefault)(?:${SEP}(?:login|account|port)${SEP}\S+)*${SEP}password${SEP})(?!\[REDACTED:)((?:[^\s\\]|\\(?![nrt]))+)`, 'g'),
    `$1${R('value')}`],
  // {"name": "API_KEY", "value": ...} (Kubernetes env, AWS tags, ...) and the YAML form "- name: X\n  value: ...": the
  // sibling value of a secret name. Name before value only (the structured tool_input path also takes value first).
  [new RegExp(String.raw`((?:\\?["'])?\b(?:name|key)(?:\\?["'])?\s*[:=]\s*(\\?["']?)(?:${SECRET_NAME})\2(?:\s*,\s*|(?:\s|\\n)+)(?:\\?["'])?value(?:\\?["'])?\s*[:=]\s*)${VALUE}`, 'gi'),
    (m, pre, _q, value) => keepOr(m, pre, value)],
  // argv arrays: the element after a secret flag ("--token", "x"), also escaped inside a string.
  [new RegExp(String.raw`((\\?")${SECRET_FLAG}\2\s*,\s*)${VALUE}`, 'gi'), (m, pre, _q, value) => keepOr(m, pre, value)],
  // A YAML block (|) or folded (>) scalar under a secret key: every following line indented deeper than the key goes.
  // Lines end at a newline or an escaped \n (inside a JSON or printf string).
  [new RegExp(String.raw`(^|\n|\\n|["'])([ \t]*)((?:- )?(?:[A-Z0-9_-]*(?:${NAMES})[A-Z0-9_-]*|(?:[A-Z0-9]+_)+(?:PASS|PWD|KEY)|PASS|PWD)[ \t]*:[ \t]*)[|>][+-]?\d?[ \t]*(?:#${YAML_LINE})?(?:${YAML_NL}(?:\2[ \t]+${YAML_LINE}|[ \t]*(?=${YAML_NL})))+`, 'gi'),
    (m, nl, indent, key) => nl + indent + key + R('value')],
  // A quoted "auth" key (docker config.json, npm): its value.
  [new RegExp(String.raw`((\\?["'])auth\2\s*:\s*)${VALUE}`, 'gi'), (m, pre, _q, value) => keepOr(m, pre, value)],
  [new RegExp(`${KEY_NAME}\\s*[=:]\\s*${VALUE}`, 'gi'), (m, name, _kw, _q, value) => keepOr(m, name, value)],
  // Environment-style names that are or end in PASS/PWD (DB_PASS=, MYSQL_PWD=, pass=).
  [new RegExp(String.raw`\b((?:[A-Z0-9]+_)+(?:PASS|PWD)|PASS)(\\?["']?)\s*[=:]\s*${VALUE}`, 'gi'), (m, name, _q, value) => keepOr(m, name, value)],
  // A bare pwd= (ODBC Pwd=, pwd=) unless its value is a path or a variable: PWD=/srv/app is the shell's cwd.
  [new RegExp(String.raw`\b(pwd)(\\?["']?)\s*[=:]\s*(?!\\?["']?[/~$.])${VALUE}`, 'gi'), (m, name, _q, value) => keepOr(m, name, value)],
  // Upper-case environment names that are or end in _KEY (OPENAI_KEY=, KEY=); lower case (sort_key=) is left.
  [new RegExp(String.raw`\b(${ENV_KEY})(\\?["']?)\s*[=:]\s*${VALUE}`, 'g'), (m, name, _q, value) => keepOr(m, name, value)],
  // CLI flags, the value after a space or '=' (--pw=X; --password=X is already a key=value above, and a value that is
  // an earlier rule's marker is left). The value may not look like a flag; a bare one ends before a closing quote.
  [new RegExp(String.raw`(${SECRET_FLAG})(\s+|=)(?!\[REDACTED:)("[^"]*"|'[^']*'|(?!-)${WORD})`, 'gi'), `$1$2${R('value')}`],
  // mysql/mariadb family only: -p directly followed by >= 4 non-space characters is the password.
  [/(\b(?:mysql|mariadb)[\w-]*\s(?:[^\n|;&]*?\s)?)-p(\S{4,})/g, `$1-p${R('value')}`],
  // Hex (>= 32) is redacted only after a key-like name or an X- header: bare git SHAs must survive.
  // A session id (session_id, sessionId) is an identifier, not a secret, unless the name also says key, token, ...
  [/(\b[\w-]*(?:key|token|secret|auth|signature|sig|session|cookie|credential|pass)[\w-]*\\?["']?\s*[=:]\s*\\?["']?)[0-9a-f]{32,}(?![0-9a-z])/gi,
    (m, pre) => /session[_-]?id\b/i.test(pre) && !/key|token|secret|auth|sig|cookie|credential|pass/i.test(pre) ? m : pre + R('hex_secret')],
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
