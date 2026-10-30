#!/usr/bin/env node
import { main } from '../src/cli.js';
import { makeRedactor } from '../src/redact.js';

// An exception outside main()'s promise chain (a timer, a stream event) would get Node's raw stack, which names the
// install path and prints the message unredacted. Print one redacted line instead; the stack only with
// HOOK_REPLAY_DEBUG=1, also redacted. process.exit runs replay's exit handler, which kills hooks and removes <tmp>.
const crash = (e) => {
  const red = makeRedactor();
  try {
    const msg = e && e.message !== undefined ? e.message : String(e);
    process.stderr.write(`hook-replay: internal error: ${red(msg).split('\n')[0]}\n`);
    if (process.env.HOOK_REPLAY_DEBUG === '1' && e && e.stack) process.stderr.write(red(e.stack) + '\n');
  } catch { /* stderr closed */ }
  process.exit(1);
};
process.on('uncaughtException', crash);
process.on('unhandledRejection', crash);

// main() catches and redacts its own errors; this is the last resort, so it prints no detail.
main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, () => {
  process.stderr.write('hook-replay: internal error (set HOOK_REPLAY_DEBUG=1 for details)\n');
  process.exitCode = 1;
});
