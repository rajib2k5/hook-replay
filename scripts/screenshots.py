#!/usr/bin/env python3
"""Make the README screenshots (docs/images/*.svg) from real hook-replay runs.

Each shot runs its command through `bash -c` in a neutral demo directory, on the repo's
synthetic fixtures only. The script never reads ~/.claude. After rendering, it checks the SVG
text for private strings and fails if it finds one.

Usage: python3 scripts/screenshots.py      (needs python3, `rich`, node 20+)
"""
import getpass
import html
import io
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from rich.console import Console
from rich.text import Text

REPO = Path(__file__).resolve().parent.parent
DEMO = Path("/tmp/demo-hook-replay")  # own directory: the script only creates and deletes inside it
OUT = REPO / "docs" / "images"
WIDTH = 120  # the report table is 115 characters wide, so 110 would wrap it
MAX_BYTES = 500 * 1024

ASK_ALL = """#!/bin/sh
cat > /dev/null
echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"review every Bash call"}}'
"""

SETTINGS = """{
  "hooks": {
    "PreToolUse": [{ "matcher": "Bash", "hooks": [{ "type": "command", "command": "node \\"/tmp/demo-hook-replay/hooks/deny-rm.js\\"" }] }],
    "PostToolUse": [{ "matcher": "Edit|Write", "hooks": [{ "type": "command", "command": "sh \\"/tmp/demo-hook-replay/hooks/post-generated.sh\\"" }] }],
    "Stop": [{ "hooks": [{ "type": "command", "command": "node \\"/tmp/demo-hook-replay/hooks/stop-claims.js\\"" }] }]
  }
}
"""

DENY_RM = """node bin/hook-replay.js --hook 'node "/tmp/demo-hook-replay/hooks/deny-rm.js"' \\
  --event PreToolUse --matcher Bash --projects-dir projects"""

SHOTS = [
    {
        "file": "01-dry-run.svg",
        "title": "hook-replay: dry run",
        "commands": [
            "node bin/hook-replay.js --help | head -n 7",
            DENY_RM + " --dry-run",
        ],
    },
    {
        "file": "02-table.svg",
        "title": "hook-replay: what the hook would do",
        "commands": [DENY_RM + " \\\n  2>/dev/null | grep -v '^warning:' | sed -n 3,4p"],
    },
    {
        "file": "03-samples.svg",
        "title": "hook-replay: samples to check, secrets redacted",
        "commands": [
            """node bin/hook-replay.js --hook 'sh "/tmp/demo-hook-replay/hooks/review-all.sh"' \\
  --event PreToolUse --matcher Bash --projects-dir projects \\
  --session dddddddd-0000-4000-8000-000000000004 --samples 5 \\
  2>/dev/null | grep -v '^warning:' | sed -n '7p;14,25p'"""
        ],
    },
    {
        "file": "04-latency.svg",
        "title": "hook-replay: latency and isolation",
        "commands": [
            DENY_RM + " \\\n  2>/dev/null | grep -v '^warning:' | sed -n '1p;5p'",
            DENY_RM + " \\\n  2>/dev/null | grep -v '^warning:' | sed -n 3,4p",
        ],
    },
    {
        "file": "05-settings.svg",
        "title": "hook-replay: every hook of a settings file",
        "commands": [
            "grep -o 'command\": \".*[a-z]' settings.json",
            "node bin/hook-replay.js --settings settings.json --projects-dir projects \\\n  2>/dev/null | grep -v '^warning:' | sed -n 3,6p",
        ],
    },
]

# the run environment: nothing from the real user's environment is passed on
ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "HOME": str(DEMO / "home"),
    "USER": "demo",
    "LOGNAME": "demo",
    "LANG": "C.UTF-8",
    "NO_COLOR": "1",
    "TERM": "dumb",
}


def setup():
    """Rebuild the demo directory from the repo's synthetic fixtures."""
    if DEMO.exists():
        shutil.rmtree(DEMO)
    (DEMO / "home").mkdir(parents=True)
    (DEMO / "hooks").mkdir()
    shutil.copytree(REPO / "test" / "fixtures" / "projects", DEMO / "projects")
    shutil.copytree(REPO / "bin", DEMO / "bin")
    shutil.copytree(REPO / "src", DEMO / "src")
    shutil.copy(REPO / "package.json", DEMO / "package.json")
    for f in (REPO / "examples" / "hooks").iterdir():
        shutil.copy(f, DEMO / "hooks" / f.name)
    (DEMO / "hooks" / "review-all.sh").write_text(ASK_ALL)
    (DEMO / "settings.json").write_text(SETTINGS)


def run(command):
    p = subprocess.run(
        ["bash", "-c", command], cwd=DEMO, env=ENV,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120,
    )
    return p.stdout.rstrip("\n")


def render(shot):
    console = Console(record=True, width=WIDTH, file=io.StringIO(),
                      force_terminal=True, color_system="truecolor")
    for command in shot["commands"]:
        console.print(Text("$ ", style="bold green") + Text(command, style="bold"))
        out = Text(run(command) + "\n")
        out.highlight_regex(r"\[REDACTED:[a-z_]+\]", "bold yellow")
        console.print(out)
    path = OUT / shot["file"]
    console.save_svg(str(path), title=shot["title"])
    return path


FORBIDDEN = [
    ("the real username", re.compile(re.escape(getpass.getuser()), re.I)),
    ("/home/ not alice or fixture", re.compile(r"/home/(?!alice\b|fixture\b)")),
    ("@ not example.com", re.compile(r"@(?!example\.com\b)[A-Za-z0-9]")),
    ("ghp_", re.compile(r"ghp_")),
    ("sk-", re.compile(r"sk-")),
    ("AKIA", re.compile(r"AKIA")),
    ("github_pat_", re.compile(r"github_pat_")),
]


def svg_text(path):
    """The visible text of the SVG, one string per <text> element, with nbsp as space."""
    root = ET.parse(path).getroot()
    parts = ["".join(el.itertext()) for el in root.iter() if el.tag.endswith("}text")]
    return [html.unescape(p).replace("\u00a0", " ") for p in parts]


def check(path):
    problems = []
    if path.stat().st_size > MAX_BYTES:
        problems.append(f"{path.name}: {path.stat().st_size} bytes, over {MAX_BYTES}")
    raw = path.read_text()
    lines = svg_text(path)
    # the raw file is checked too, so a string cannot hide in an attribute or the title
    for name, rx in FORBIDDEN:
        for where, hay in (("text", "\n".join(lines)), ("raw", raw)):
            if name.startswith("@") and where == "raw":
                continue  # the CSS in the file has "@font-face"
            m = rx.search(hay)
            if m:
                problems.append(f"{path.name}: forbidden '{name}' in {where}: ...{hay[max(0, m.start()-20):m.end()+20]!r}")
    return problems


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    setup()
    problems = []
    for shot in SHOTS:
        path = render(shot)
        problems += check(path)
        print(f"{path.relative_to(REPO)}  {path.stat().st_size / 1024:.1f} KB")
    if problems:
        print("\n".join(problems), file=sys.stderr)
        sys.exit(1)
    print("forbidden-string check: clean")


if __name__ == "__main__":
    main()
