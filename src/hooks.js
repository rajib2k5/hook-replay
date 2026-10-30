// HookSpec construction: from --hook flags (shell form) or from a settings.json / plugin hooks.json.
import crypto from 'node:crypto';
import { validateMatcher } from './matcher.js';

export const EVENTS = ['PreToolUse', 'PostToolUse', 'Stop'];
export const DEFAULT_HOOK_TIMEOUT_S = 600;

export class UsageError extends Error {}

const hookKey = (h) => crypto.createHash('sha256')
  .update(JSON.stringify([h.event, h.matcher ?? null, h.command, h.args ?? null])).digest('hex').slice(0, 16);

export function hookFromFlags({ hook, event, matcher, hookTimeout, onFailure }) {
  if (!EVENTS.includes(event)) throw new UsageError(`--event must be one of ${EVENTS.join(', ')}`);
  if (event === 'Stop' && matcher !== undefined) throw new UsageError('--matcher cannot be used with --event Stop (Stop has no matcher)');
  if (matcher !== undefined) {
    try { validateMatcher(matcher); } catch (e) { throw new UsageError(e.message); }
  }
  const timeoutS = hookTimeout === undefined ? DEFAULT_HOOK_TIMEOUT_S : Number(hookTimeout);
  if (!(timeoutS > 0)) throw new UsageError('--hook-timeout must be a positive number of seconds');
  const of = onFailure ?? 'continue';
  if (!['continue', 'block'].includes(of)) throw new UsageError('--on-failure must be continue or block');
  const h = { id: 'h1', event, matcher, command: hook, timeoutS, onFailure: of, source: '--hook', ifIgnored: false };
  h.key = hookKey(h);
  return h;
}

export { hookKey };
