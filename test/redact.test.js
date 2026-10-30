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
  ['6 bearer', 'curl -H "Bearer fakeValue0000"', 'curl -H "Bearer [REDACTED:token]'],
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
  ['header X-Api-Key', 'curl -H "X-Api-Key: xak-header-0049"', 'curl -H "X-Api-Key: [REDACTED:value]'],
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
