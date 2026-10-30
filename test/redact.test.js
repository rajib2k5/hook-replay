import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, escapeControl, entropy } from '../src/redact.js';

const R = (s, o = {}) => redact(s, { homedir: '/home/fixture', username: 'fixture', ...o });

// One case per DESIGN.md §8 rule. All values are fake.
const rules = [
  ['1 private key', 'k=-----BEGIN RSA PRIVATE KEY-----\nFAKEFAKE\nFAKE\n-----END RSA PRIVATE KEY----- end', 'k=[REDACTED:private_key] end'],
  ['1 private key (unlabelled)', '-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY-----', '[REDACTED:private_key]'],
  ['2 anthropic key', 'use sk-ant-api03-FAKEfakeFAKE now', 'use [REDACTED:api_key] now'],
  ['2 openai key', 'key sk-proj-FAKEfakeFAKEfakeFAKE00 x', 'key [REDACTED:api_key] x'],
  ['2 openai key, no proj', 'sk-FAKEfakeFAKEfakeFAKEfake', '[REDACTED:api_key]'],
  ['3 github token', 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', '[REDACTED:github_token]'],
  ['3 github token (gho)', 'gho_xxxxxxxxxxxxxxxxxxxx', '[REDACTED:github_token]'],
  ['3 github pat', 'github_pat_FAKE0000fake0000FAKE0000xx', '[REDACTED:github_token]'],
  ['4 aws key', 'id AKIAXXXXXXXXFAKEXXXX.', 'id [REDACTED:aws_key].'],
  ['4 aws key (ASIA)', 'ASIAXXXXXXXXFAKEXXXX', '[REDACTED:aws_key]'],
  ['4 slack token', 'xoxb-0000000000-fakefakefake', '[REDACTED:slack_token]'],
  ['4 google key', 'AIzaFAKEfakeFAKEfakeFAKEfakeFAKEfake123', '[REDACTED:google_key]'],
  ['5 jwt', 'eyJmYWtlaGVhZGVy.eyJmYWtlcGF5bG9hZA.ZmFrZXNpZ25hdHVyZQ', '[REDACTED:jwt]'],
  ['6 bearer', 'curl -H "Bearer fakeValue0000"', 'curl -H "Bearer [REDACTED:token]"'],
  ['6 authorization', 'Authorization: fakeValue0000 rest', 'Authorization: [REDACTED:token] rest'],
  ['6 authorization: bearer', 'Authorization: Bearer fakeValue0000 rest', 'Authorization: Bearer [REDACTED:token] rest'],
  ['7 name=value', 'export DB_PASSWORD="fake pass" next', 'export DB_PASSWORD=[REDACTED:value] next'],
  ['7 name: value', 'api_key: fakefake0000', 'api_key: [REDACTED:value]'],
  ['7 single quotes', "MY_SECRET_TOKEN='a b'", 'MY_SECRET_TOKEN=[REDACTED:value]'],
  ['8 userinfo', 'git clone https://bob:fakepw0000@git.example.invalid/r', 'git clone https://[REDACTED:userinfo]@git.example.invalid/r'],
  ['9 email', 'mail alice@example.com now', 'mail [REDACTED:email] now'],
  ['10 home literal', 'cat /home/fixture/.ssh/config', 'cat ~/.ssh/config'],
  ['10 other home', 'cat /home/alice/x and /Users/bob/y', 'cat ~/x and ~/y'],
  ['10 windows home', 'C:\\Users\\carol\\file', '~\\file'],
  ['11 username', 'user fixture in -home-fixture-proj', 'user [user] in -home-[user]-proj'],
  ['12 high entropy', 'seed FAKEentropyQ7wX2mZ9pL4vK8nR3tB6yH1cJ5dG0s end', 'seed [REDACTED:high_entropy] end'],
];
for (const [name, input, want] of rules) test(`rule ${name}`, () => assert.equal(R(input), want));

test('hex SHAs and UUIDs survive', () => {
  const sha = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
  const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const uuid = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';
  assert.equal(R(`${sha} ${sha256} ${uuid}`), `${sha} ${sha256} ${uuid}`);
  assert.ok(entropy(sha256) <= 4.0);
});

test('a short username is not redacted (under 3 chars), and the homedir literal goes first', () => {
  assert.equal(R('ab and /srv/home', { username: 'ab', homedir: '/srv/home' }), 'ab and ~');
});

test('rules apply in order: userinfo before email', () => {
  assert.equal(R('https://u:p@host.example.com'), 'https://[REDACTED:userinfo]@host.example.com');
});

test('escapeControl escapes C0/C1 controls except newline and tab', () => {
  assert.equal(escapeControl('a\x1b[31mred\x07\tb\nc\x9b'), 'a\\x1b[31mred\\x07\tb\nc\\x9b');
});

// Review gaps (each value is fresh and fake, used nowhere else).
const gaps = [
  ['7 JSON-quoted api_key', '{"api_key": "qz7Vapikeyvalue41"}', '{"api_key": [REDACTED:value]}'],
  ['7 JSON-quoted password and db_password', '{"password": "pw-JsonOnly-77", "db_password": "dbpw-JsonOnly-78"}',
    '{"password": [REDACTED:value], "db_password": [REDACTED:value]}'],
  ['7 escaped JSON inside a string', '{\\"secret\\": \\"esc-sekret-0091\\"}', '{\\"secret\\": [REDACTED:value]}'],
  ['flag --password X', 'mytool --password hunter-flag-0042 --verbose', 'mytool --password [REDACTED:value] --verbose'],
  ['flag --password=X', 'mytool --password=hunter-eq-0043 x', 'mytool --password=[REDACTED:value] x'],
  ['flag --api-key X', 'cli --api-key apik-flag-0044', 'cli --api-key [REDACTED:value]'],
  ['flag --token X', 'cli --token tok-flag-0045 run', 'cli --token [REDACTED:value] run'],
  ['flag --secret X', "cli --secret 'sec flag 0046'", 'cli --secret [REDACTED:value]'],
  ['mysql -pXXXX', 'mysql -u root -pMyPw0047 db', 'mysql -u root -p[REDACTED:value] db'],
  ['mariadb-dump -pXXXX', 'mariadb-dump -pAnotherPw48 db', 'mariadb-dump -p[REDACTED:value] db'],
  ['header X-Api-Key', 'curl -H "X-Api-Key: xak-header-0049"', 'curl -H "X-Api-Key: [REDACTED:value]"'],
  ['header Api-Key', 'Api-Key: ak-header-0050 rest', 'Api-Key: [REDACTED:value] rest'],
  ['stripe sk_live', 'STRIPE sk_live_51FakeLiveKey0051abcdEF', 'STRIPE [REDACTED:api_key]'],
  ['stripe sk_test', 'sk_test_51FakeTestKey0052abcdEF', '[REDACTED:api_key]'],
  ['stripe rk_live', 'rk_live_51FakeRestricted0053ab', '[REDACTED:api_key]'],
  ['gitlab glpat', 'token glpat-FakeGitlab0054abcdEFGH end', 'token [REDACTED:gitlab_token] end'],
  ['npm token', 'npm_FakeNpmTokenValue0055abcdefghijklmno x', '[REDACTED:npm_token] x'],
  ['hugging face', 'hf_FakeHuggingFaceToken0056abcdefgh', '[REDACTED:hf_token]'],
  ['hex in key context', 'signing_key=0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c', 'signing_key=[REDACTED:hex_secret]'],
  ['hex in header context', 'X-Hub-Signature: 9a8b7c6d5e4f30211203f4e5d6c7b8a99a8b7c6d', 'X-Hub-Signature: [REDACTED:hex_secret]'],
  ['/root path', 'cat /root/.netrc and /root', 'cat ~/.netrc and ~'],
];
for (const [name, input, want] of gaps) test(`gap: ${name}`, () => assert.equal(R(input), want));

test('a bare git SHA survives (hex is redacted only after a key or header name)', () => {
  const sha = '4b825dc642cb6eb9a060e54bf8d69288fbee4904';
  assert.equal(R(`git checkout ${sha} && git show ${sha}`), `git checkout ${sha} && git show ${sha}`);
});

test('/rootfs and other words starting with root survive', () => {
  assert.equal(R('ls /rootfs/x rootless'), 'ls /rootfs/x rootless');
});

test('username: case-insensitive and inside identifiers (fake user "quokka7")', () => {
  const o = { username: 'quokka7', homedir: '/home/quokka7' };
  assert.equal(R('quokka7_backup QUOKKA7_HOME Quokka7 xquokka7y', o), '[user]_backup [user]_HOME [user] x[user]y');
});

test('a short username (3-5 chars) is redacted only between non-letters', () => {
  const o = { username: 'emu', homedir: '/home/emu' };
  assert.equal(R('emu_dir EMU2 emus lemur', o), '[user]_dir [user]2 emus lemur');
});

// Round-3 review leaks (each value fresh and fake, used nowhere else). The assertion is that the value is gone.
const leaks = [
  ['Authorization: Basic', 'curl -H "Authorization: Basic cjNCYXNpY1VzZXI6cjNCYXNpY1B3ODgwMQ==" https://h.invalid', 'cjNCYXNpY1VzZXI6cjNCYXNpY1B3ODgwMQ'],
  ['Authorization: Digest (comma-separated params)', 'Authorization: Digest username="u", response="r3DigestResp8802"', 'r3DigestResp8802'],
  ['JSON "Authorization": "Basic ..."', '{"Authorization": "Basic r3JsonBasic8803"}', 'r3JsonBasic8803'],
  ['curl -u user:pw', 'curl -u admin:r3CurlUPw8804 https://h.invalid', 'r3CurlUPw8804'],
  ['curl --user=user:pw', 'curl --user=admin:r3CurlUserPw8805 https://h.invalid', 'r3CurlUserPw8805'],
  ['curl --user "user:pw"', 'curl --user "admin:r3CurlQuoted8806" https://h.invalid', 'r3CurlQuoted8806'],
  ['DB_PASS=', 'DB_PASS=r3DbPass8807 ./run', 'r3DbPass8807'],
  ['MYSQL_PWD=', 'MYSQL_PWD=r3MysqlPwd8808 mysql', 'r3MysqlPwd8808'],
  ['PGPASSWORD=', 'PGPASSWORD=r3PgPw8809 psql', 'r3PgPw8809'],
  ['Azure AccountKey=', 'DefaultEndpointsProtocol=https;AccountName=x;AccountKey=r3AzAcctKey8810abc==;EndpointSuffix=core.windows.net', 'r3AzAcctKey8810'],
  ['Azure SharedAccessKey=', 'Endpoint=sb://x.servicebus.windows.net/;SharedAccessKeyName=root;SharedAccessKey=r3AzSasKey8811=', 'r3AzSasKey8811'],
  ['Cookie:', 'curl -H "Cookie: session=r3Cookie8812; theme=dark" https://h.invalid', 'r3Cookie8812'],
  ['Set-Cookie:', 'Set-Cookie: sid=r3SetCookie8813; Path=/; HttpOnly', 'r3SetCookie8813'],
  ['JSON "Cookie": "..."', '{"Cookie": "sid=r3JsonCookie8814"}', 'r3JsonCookie8814'],
  ['sshpass -p', 'sshpass -p r3SshPass8815 ssh host', 'r3SshPass8815'],
  ['sshpass -pX', "sshpass -p'r3SshPassQ8816' ssh host", 'r3SshPassQ8816'],
  ['truncated PEM (BEGIN, no END)', '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1yM1RydW5jODgxNw\nAAAA', 'yM1RydW5jODgxNw'],
  ['escaped quote inside an escaped JSON string', '{\\"password\\": \\"r3Esc\\\\\\"Pw8818\\"}', 'Pw8818'],
  ['URL ?token=', 'https://h.invalid/x?token=r3UrlTok8819&page=2', 'r3UrlTok8819'],
  ['URL &access_token=', 'https://h.invalid/x?a=1&access_token=r3UrlAt8820#frag', 'r3UrlAt8820'],
  ['URL api_key, apikey, key', 'https://h.invalid/?api_key=r3UrlAk8821&apikey=r3UrlAk8822&key=r3UrlKey8823', 'r3UrlAk8821|r3UrlAk8822|r3UrlKey8823'],
  ['URL secret, password', 'https://h.invalid/?secret=r3UrlSec8824&password=r3UrlPw8825', 'r3UrlSec8824|r3UrlPw8825'],
  ['URL sig, signature (SAS)', 'https://a.blob.core.windows.net/c/b?sv=2020&sig=r3UrlSig8826%3D&signature=r3UrlSig8827', 'r3UrlSig8826|r3UrlSig8827'],
];
for (const [name, input, values] of leaks) {
  test(`round 3 leak: ${name}`, () => {
    const out = R(input);
    for (const v of values.split('|')) assert.ok(!out.includes(v), `${v} survives in ${out}`);
    assert.match(out, /\[REDACTED:/);
  });
}

test('the URL query rule leaves the other parameters and the path alone', () => {
  assert.equal(R('https://h.invalid/a/b?page=2&token=r3UrlTok8828&sort=asc'), 'https://h.invalid/a/b?page=2&token=[REDACTED:value]&sort=asc');
});

test('ordinary paths survive the high-entropy rule ("/" is not part of a token)', () => {
  const paths = ['$CLAUDE_PROJECT_DIR/examples/hooks/deny-rm.js', '/usr/lib/node_modules/npm/node_modules/@npmcli/arborist/lib/index.js',
    'src/components/UserProfileCard/UserProfileCardHeader.tsx'];
  for (const p of paths) assert.equal(R(p), p);
});

test('a 40-char base64 secret is still caught by the high-entropy rule, with and without "/"', () => {
  assert.equal(R('seed r3B64Q7wX2mZ9pL4vK8nR3tB6yH1cJ5dG0sA8f end'), 'seed [REDACTED:high_entropy] end');
  assert.equal(R('k wJr3lrXUtnFEMI/K7MDENG/bPxRfiCY8829XKEYz end'), 'k [REDACTED:high_entropy] end');
});

// Round-4 review leaks (red3.mjs; each value fresh and fake, used nowhere else). The value must be gone.
const leaks4 = [
  ['OPENAI_KEY=', 'OPENAI_KEY=r4OpenaiKey9101 node x.js', 'r4OpenaiKey9101'],
  ['bare KEY=', 'KEY=r4BareKey9102 ./run', 'r4BareKey9102'],
  ['FOO_KEY: (YAML)', 'STRIPE_WEBHOOK_KEY: r4YamlKey9116', 'r4YamlKey9116'],
  ['.netrc, one line', 'machine h.invalid login bob password r4Netrc9103', 'r4Netrc9103'],
  ['.netrc, multi-line', 'machine h.invalid\n  login u\n  password r4NetrcMl9104\n', 'r4NetrcMl9104'],
  ['.netrc inside a JSON string', 'machine h.invalid\\n  login u\\n  password r4NetrcEsc9117\\n', 'r4NetrcEsc9117'],
  ['.netrc default entry', 'default login u password r4NetrcDef9118', 'r4NetrcDef9118'],
  ['env pair {"name","value"}', '{"name":"API_KEY","value":"r4K8sVal9105"}', 'r4K8sVal9105'],
  ['env pair {"key","value"} with spaces', '{"key": "DB_PASSWORD", "value": "r4K8sVal9119"}', 'r4K8sVal9119'],
  ['env pair escaped inside a string', '{\\"name\\":\\"GITHUB_TOKEN\\",\\"value\\":\\"r4K8sEsc9120\\"}', 'r4K8sEsc9120'],
  ['env pair in YAML', 'env:\n  - name: DB_PASSWORD\n    value: r4YamlVal9106\n', 'r4YamlVal9106'],
  ['argv array', 'args: ["--token","r4ArgvTok9107","--password","r4ArgvPw9108"]', 'r4ArgvTok9107|r4ArgvPw9108'],
  ['argv array, escaped, with spaces', '[\\"--api-key\\", \\"r4ArgvEsc9121\\"]', 'r4ArgvEsc9121'],
  ['lowercase pwd=', 'Server=db;uid=u;pwd=r4LowPwd9109;', 'r4LowPwd9109'],
  ['ODBC Pwd=', 'Uid=u;Pwd=r4OdbcPwd9110;', 'r4OdbcPwd9110'],
  ['docker login -p', 'docker login -u bob -p r4DockerPw9111 reg.invalid', 'r4DockerPw9111'],
  ['"secrets" array, no spaces', '{"secrets":["r4Arr9112","r4Arr9113"]}', 'r4Arr9112|r4Arr9113'],
  ['"secrets" array with spaces, inside a command', `curl -d '{"secrets": ["r4Arr9114", "r4Arr9115"]}'`, 'r4Arr9114|r4Arr9115'],
  ['"tokens" array, escaped inside a string', '{\\"tokens\\": [\\"r4Arr9122\\", \\"r4Arr9123\\"]}', 'r4Arr9122|r4Arr9123'],
  ['flat object under "credentials"', '{"credentials": {"u": "r4Obj9124", "v": "r4Obj9125"}}', 'r4Obj9124|r4Obj9125'],
  ['a number under a name that ends in a secret word', 'PASSWORD=91267734 api_key: 55120933', '91267734|55120933'],
];
for (const [name, input, values] of leaks4) {
  test(`round 4 leak: ${name}`, () => {
    const out = R(input);
    for (const v of values.split('|')) assert.ok(!out.includes(v), `${v} survives in ${out}`);
    assert.match(out, /\[REDACTED:/);
  });
}

// Round-4 over-redaction: key-context redaction keeps numbers and booleans (unless the name ends in a secret word),
// and a session id is not a secret. Each string must come out unchanged.
const keeps4 = [
  '{"max_tokens": 4096, "input_tokens": 1234, "output_tokens": 77}',
  '{"max_tokens":4096,"stream":true}',
  'usage.input_tokens=1234 tokenCount: 12',
  'PASSWORD_MIN_LENGTH=8 TOKENIZERS_PARALLELISM=false',
  '"secretsEnabled": true, "token_budget": 0.5, "password_reset": null',
  'session_id: 9f1c2e3d4b5a69788796a5b4c3d2e1f0',
  'sessionId=9f1c2e3d4b5a69788796a5b4c3d2e1f0',
  '{"session_id": "123e4567-e89b-12d3-a456-426614174000"}',
  'PWD=/srv/app ls && cd "$PWD"',
  'echo x | docker login --password-stdin reg.invalid',
  'kubectl create secret --token-file /etc/k/t.txt',
  'grep -r password_reset src/ && the password must be long',
  '{"name": "LOG_LEVEL", "value": "debug"}',
  '- name: PASSWORD_MIN_LENGTH\n  value: 8',
];
for (const input of keeps4) test(`round 4 keep: ${JSON.stringify(input).slice(0, 60)}`, () => assert.equal(R(input), input));

// Round-5 review leaks (red4.mjs; each value fresh and fake, used nowhere else). The value must be gone.
const leaks5 = [
  ['YAML block scalar under a secret key', 'db:\n  password: |\n    r5YamlBlk5501\n    r5YamlBlk5502\n  user: x', 'r5YamlBlk5501|r5YamlBlk5502'],
  ['YAML folded scalar under a secret key', 'api_key: >-\n  r5YamlFold5503\nnext: 1', 'r5YamlFold5503'],
  ['aws configure set', 'aws configure set aws_secret_access_key r5AwsCfg5504 --profile p', 'r5AwsCfg5504'],
  ['PGP private key block', '-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBr5Pgp5505\n-----END PGP PRIVATE KEY BLOCK-----', 'r5Pgp5505'],
  ['Slack webhook URL', 'curl -X POST https://hooks.slack.com/services/T0R5H00K/B0R5H00K/r5SlackHook5506 -d x', 'r5SlackHook5506|B0R5H00K'],
  ['.pgpass line', 'echo "db.invalid:5432:*:bob:r5PgPass5507" > ~/.pgpass', 'r5PgPass5507'],
  ['.pgpass line, port *', 'localhost:*:app:u:r5PgPass5508', 'r5PgPass5508'],
  ['htpasswd -b', 'htpasswd -b /etc/h bob r5Htpw5509', 'r5Htpw5509'],
  ['htpasswd -cb', 'htpasswd -cb .htpasswd bob r5Htpw5510', 'r5Htpw5510'],
  ['htpasswd -nb (no file)', 'htpasswd -nb bob r5Htpw5511', 'r5Htpw5511'],
  ['--pw x', 'tool login --pw r5PwFlag5512 --user u', 'r5PwFlag5512'],
  ['{"auth": ...}', '{"auths":{"reg.invalid":{"auth": "r5AuthVal5513"}}}', 'r5AuthVal5513'],
  ['auth=("u","pw")', 'requests.get(u, auth=("bob", "r5PyAuth5514"))', 'r5PyAuth5514'],
  ['; as a URL-parameter separator', 'https://h.invalid/cb?a=1;token=r5Semi5515;b=2', 'r5Semi5515'],
];
for (const [name, input, values] of leaks5) {
  test(`round 5 leak: ${name}`, () => {
    const out = R(input);
    for (const v of values.split('|')) assert.ok(!out.includes(v), `${v} survives in ${out}`);
    assert.match(out, /\[REDACTED:/);
  });
}

// Round-5 over-redaction: a value redacted in a quoted context keeps the closing quote and what follows.
const exact5 = [
  ['X-Api-Key in a quoted header', 'curl -H "X-Api-Key: r5Hdr5516" -H "Accept: x" u', 'curl -H "X-Api-Key: [REDACTED:value]" -H "Accept: x" u'],
  ['X-Api-Key inside a JSON string', '{"h":"X-Api-Key: r5Hdr5517","n":1}', '{"h":"X-Api-Key: [REDACTED:value]","n":1}'],
  ['X-Api-Key escaped inside a string', '{\\"h\\":\\"X-Api-Key: r5Hdr5518\\"}', '{\\"h\\":\\"X-Api-Key: [REDACTED:value]\\"}'],
  ['Bearer at the end of an argv array', '["curl","-H","Authorization: Bearer r5Bear5519"]', '["curl","-H","Authorization: Bearer [REDACTED:token]"]'],
  ['bare Bearer in an argv array', '["Bearer r5Bear5520", "x"]', '["Bearer [REDACTED:token]", "x"]'],
  ['a quote inside a value is still part of it', 'PASSWORD=r5ab"cd5521 next', 'PASSWORD=[REDACTED:value] next'],
  ['YAML block: the rest of the document stays', 'a: 1\nsecret: |\n  r5Blk5522\nb: 2', 'a: 1\nsecret: [REDACTED:value]\nb: 2'],
];
for (const [name, input, want] of exact5) test(`round 5 exact: ${name}`, () => assert.equal(R(input), want));

// Documented limit: a secret in prose, with no name=value, flag or key shape, is not found.
test('round 5 limit (documented): "password hunter2" in prose is not redacted', () => {
  assert.equal(R('blocked: command contains password r5Prose5523'), 'blocked: command contains password r5Prose5523');
});

// Round-6 review (red2.mjs): --pw=X leaked (only --pw X was caught). The value must be gone.
const leaks6 = [
  ['--pw=x', 'mysql --pw=r6PwEq6601 -u root', 'r6PwEq6601'],
  ['--pw="x y"', 'tool --pw="r6PwQ 6602" next', 'r6PwQ 6602'],
  ['--api-key=x', 'tool --api-key=r6ApiEq6603 next', 'r6ApiEq6603'],
];
for (const [name, input, values] of leaks6) {
  test(`round 6 leak: ${name}`, () => {
    const out = R(input);
    for (const v of values.split('|')) assert.ok(!out.includes(v), `${v} survives in ${out}`);
    assert.match(out, /\[REDACTED:/);
  });
}

// Round-6 review: the .pgpass rule redacted the port of a URL in a file:line:col location and ate the backslash of
// \" after a value inside a JSON string. A field with // (a URL) never matches; a backslash is never consumed.
const exact6 = [
  ['--pw=x', 'mysql --pw=r6PwEq6604 -u root', 'mysql --pw=[REDACTED:value] -u root'],
  ['--password=x is redacted once', 'mysql --password=r6PwEq6605 -u x', 'mysql --password=[REDACTED:value] -u x'],
  ['--pw x still', 'tool --pw r6Pw6606 x', 'tool --pw [REDACTED:value] x'],
  ['.pgpass inside an escaped JSON string keeps \\"', String.raw`"{\"c\":\"db:5432:app:alice:r6Pg6607\"}"`,
    String.raw`"{\"c\":\"db:5432:app:alice:[REDACTED:value]\"}"`],
  ['.pgpass in an escaped quote in a command', String.raw`{"command":"echo \"db:5432:app:alice:r6Pg6608\" > ~/.pgpass"}`,
    String.raw`{"command":"echo \"db:5432:app:alice:[REDACTED:value]\" > ~/.pgpass"}`],
  ['--pw=x at the end of a JSON string keeps "}', String.raw`{"c":"mysql --pw=r6Pw6610"}`, String.raw`{"c":"mysql --pw=[REDACTED:value]"}`],
  ['--pw x at the end of a JSON string keeps "}', String.raw`{"c":"mysql --pw r6Pw6611"}`, String.raw`{"c":"mysql --pw [REDACTED:value]"}`],
  ['--pw=x at the end of an escaped string keeps \\"}', String.raw`"{\"c\":\"t --pw=r6Pw6612\"}"`, String.raw`"{\"c\":\"t --pw=[REDACTED:value]\"}"`],
  ['.pgpass with a socket-dir host', '/var/run/postgresql:5432:app:u:r6Pg6609', '/var/run/postgresql:5432:app:u:[REDACTED:value]'],
];
for (const [name, input, want] of exact6) test(`round 6 exact: ${name}`, () => assert.equal(R(input), want));

const keeps6 = [
  'src/a.js:12:5:https://example.com',
  'file:line:col:https://example.com',
  'app.js:12:http://localhost:3000',
  'at f (app.js:12:http://localhost:3000)',
  'db:5432:app:u:https://example.com',
];
for (const input of keeps6) test(`round 6 keep: ${JSON.stringify(input)}`, () => assert.equal(R(input), input));
