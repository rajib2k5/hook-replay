#!/bin/sh
# Example PostToolUse hook for Edit|Write (POSIX sh + grep): after an edit to a *.generated.* file, exit 2 so
# Claude sees the complaint on stderr; after a write to a .env file, add context for Claude. Silent otherwise.
input=$(cat)
file=$(printf '%s' "$input" | grep -o '"file_path":"[^"]*"' | head -n 1 | sed 's/^"file_path":"//; s/"$//')
base=${file##*/}

case "$base" in
  *.generated.*)
    echo "$file is generated; edit its source instead" >&2
    exit 2
    ;;
  .env|*.env)
    printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"A .env file was written; keep secrets out of git."}}'
    ;;
esac
exit 0
