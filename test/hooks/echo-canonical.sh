#!/bin/sh
# Test-only hook: print its stdin with keys sorted and transcript_path replaced by the sha256 of that file's
# bytes. Two runs print the same line iff they got the same payload and the same transcript prefix.
# (A .sh file, so `node --test` does not pick it up as a test.)
exec node -e '
const crypto = require("crypto"); const fs = require("fs");
const sort = (v) => Array.isArray(v) ? v.map(sort)
  : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map(k => [k, sort(v[k])])) : v;
const p = JSON.parse(fs.readFileSync(0, "utf8"));
p.transcript_path = crypto.createHash("sha256").update(fs.readFileSync(p.transcript_path)).digest("hex");
process.stdout.write(JSON.stringify(sort(p)) + "\n");
'
