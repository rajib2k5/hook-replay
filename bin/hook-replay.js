#!/usr/bin/env node
import { main } from '../src/cli.js';

// main() catches and redacts its own errors; this is the last resort, so it prints no detail.
main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, () => {
  process.stderr.write('hook-replay: internal error (set HOOK_REPLAY_DEBUG=1 for details)\n');
  process.exitCode = 1;
});
