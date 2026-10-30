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
