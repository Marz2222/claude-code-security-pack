"""Install the security pack into Claude Code (Windows, macOS, Linux).

    python install.py            # install / upgrade, then self-test
    python install.py --dry-run  # show what would change, touch nothing
    python install.py --uninstall

What it does:
  1. copies hooks/, tools/, tests/, security.config.json to ~/.claude/security-pack/
     (an existing security.config.json there is kept, never overwritten)
  2. backs up ~/.claude/settings.json to settings.json.bak-<timestamp>
  3. merges two hook entries (idempotent, re-running never duplicates):
       PreToolUse  matcher "*"  -> outbound_guard.py
       PostToolUse matcher "*"  -> injection_scanner.py
  4. runs the regression tests and prints the result

Uses the Python that runs this script as the hook interpreter (absolute path),
so hooks work even when `python` is not on PATH inside Claude Code.
"""
from __future__ import annotations

import datetime
import json
import shutil
import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent
CLAUDE = Path.home() / ".claude"
DEST = CLAUDE / "security-pack"
SETTINGS = CLAUDE / "settings.json"
TAG = "security-pack"  # every command we add contains this path segment


def _cmd(script: str) -> str:
    return f'"{sys.executable}" "{DEST / "hooks" / script}"'


ENTRIES = [
    ("PreToolUse", "*", "outbound_guard.py", 10),
    ("PostToolUse", "*", "injection_scanner.py", 10),
]


def _strip_ours(settings: dict) -> None:
    for event in ("PreToolUse", "PostToolUse"):
        groups = settings.get("hooks", {}).get(event, [])
        for g in groups:
            g["hooks"] = [h for h in g.get("hooks", []) if TAG not in h.get("command", "")]
        settings.get("hooks", {})[event] = [g for g in groups if g.get("hooks")] if groups else groups


def main() -> int:
    dry = "--dry-run" in sys.argv
    uninstall = "--uninstall" in sys.argv
    settings = json.loads(SETTINGS.read_text(encoding="utf-8")) if SETTINGS.exists() else {}

    _strip_ours(settings)
    if not uninstall:
        hooks = settings.setdefault("hooks", {})
        for event, matcher, script, timeout in ENTRIES:
            hooks.setdefault(event, []).append({
                "matcher": matcher,
                "hooks": [{"type": "command", "command": _cmd(script), "timeout": timeout}],
            })

    if dry:
        print(json.dumps(settings.get("hooks", {}), indent=2))
        print("\n(dry run: nothing written)")
        return 0

    if SETTINGS.exists():
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        shutil.copy2(SETTINGS, SETTINGS.with_name(f"settings.json.bak-{stamp}"))
        print(f"backup: {SETTINGS.with_name(f'settings.json.bak-{stamp}')}")

    if uninstall:
        SETTINGS.write_text(json.dumps(settings, indent=2, ensure_ascii=False), encoding="utf-8")
        print("hooks removed from settings.json (files in ~/.claude/security-pack left in place)")
        return 0

    DEST.mkdir(parents=True, exist_ok=True)
    for sub in ("hooks", "tools", "tests"):
        shutil.copytree(SRC / sub, DEST / sub, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("__pycache__"))
    for doc in ("README.md", "INSTALL.md", "MANUAL_INSTALL.md", "SOP.md"):
        if (SRC / doc).exists():
            shutil.copy2(SRC / doc, DEST / doc)
    if not (DEST / "security.config.json").exists():
        shutil.copy2(SRC / "security.config.json", DEST / "security.config.json")
    else:
        print("kept existing security.config.json")

    CLAUDE.mkdir(exist_ok=True)
    SETTINGS.write_text(json.dumps(settings, indent=2, ensure_ascii=False), encoding="utf-8")
    json.loads(SETTINGS.read_text(encoding="utf-8"))  # must still parse
    print(f"installed to {DEST}\nhooks merged into {SETTINGS}")

    rc = 0
    for t in ("test_scanner.py", "test_guard.py"):
        r = subprocess.run([sys.executable, str(DEST / "tests" / t)], capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        print(r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr)
        rc |= r.returncode
    print("SELF-TEST PASSED" if rc == 0 else "SELF-TEST FAILED (see output above)")
    print("Restart Claude Code (or run /hooks) so it loads the new hooks.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
