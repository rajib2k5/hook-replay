#!/bin/sh
# Test-only hook: append "<sha256 of transcript_path>\t<stdin>" to $CAPTURE_OUT. Prints nothing.
input=$(cat)
tp=$(printf '%s' "$input" | sed -n 's/.*"transcript_path":"\([^"]*\)".*/\1/p')
h=$(cat "$tp" | sha256sum | cut -d' ' -f1)
printf '%s\t%s\n' "$h" "$input" >> "$CAPTURE_OUT"
