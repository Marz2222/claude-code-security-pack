"""Audit Claude Code instruction surfaces for supply-chain injection.

Scans CLAUDE.md files, skills, slash commands, agents, plugins and project
settings for the 2026 attack shapes against coding agents:

  - invisible Unicode (tag block U+E0000-E007F, RTL override, zero-width runs)
    hiding instructions a human reviewer cannot see
  - skill dynamic context  !`cmd`  (runs at preprocessing, before the model
    sees the skill, so model-side refusal never gets a chance)
  - blanket tool grants in frontmatter (allowed-tools: Bash(*) / Bash)
  - network egress commands (curl/wget/iwr/nc) inside instruction files
  - project-level hooks / apiKeyHelper / ANTHROPIC_BASE_URL overrides in a
    repo's .claude/settings*.json (CVE-2025-59536, CVE-2026-21852 shapes)
  - enableAllProjectMcpServers (auto-trusts every server a repo declares)

Usage:
    python config_audit.py [ROOT ...]        # default: ~/.claude and CWD
    python config_audit.py --strict ROOT     # exit 1 on any HIGH finding

Pure stdlib, read-only. Run on every newly cloned repo before opening Claude
Code in it, and weekly on your own setup.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

INVISIBLE = re.compile(r"[\U000E0000-\U000E007F]|\u202e|\u2066|\u2067|\u2068|[\u200b\u200c\u200d\u2060\ufeff]{2,}")
DYNAMIC_CTX = re.compile(r"!`[^`\n]+`")
BROAD_GRANT = re.compile(r"^\s*allowed-tools\s*:.*\bBash(?:\(\s*\*\s*\))?(?:\s*(?:,|$))", re.IGNORECASE | re.MULTILINE)
EGRESS = re.compile(r"\b(?:curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|nc|ncat)\b[^\n]{0,120}https?://", re.IGNORECASE)

INSTRUCTION_GLOBS = ("**/CLAUDE.md", "**/CLAUDE.local.md", "**/AGENTS.md", "**/.cursorrules",
                     "**/skills/**/*.md", "**/commands/**/*.md", "**/agents/**/*.md",
                     "**/rules/**/*.md", "**/plugins/**/*.md")
SKIP_DIRS = {"node_modules", ".git", "venvs", "venv", ".venv", "__pycache__", "site-packages"}


def _iter_files(root: Path):
    seen = set()
    for g in INSTRUCTION_GLOBS:
        for p in root.glob(g):
            if any(part in SKIP_DIRS for part in p.parts) or p in seen or not p.is_file():
                continue
            seen.add(p)
            yield p


def audit_instruction_file(p: Path) -> list[tuple[str, str]]:
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    out = []
    m = INVISIBLE.search(text)
    if m:
        line = text.count("\n", 0, m.start()) + 1
        out.append(("HIGH", f"invisible Unicode at line {line} (U+{ord(m.group(0)[0]):04X})"))
    dyn = list(DYNAMIC_CTX.finditer(text))
    risky = [m for m in dyn if EGRESS.search(m.group(0))
             or re.search(r"https?://|base64|\|\s*(?:sh|bash|iex)\b", m.group(0))]
    for m in risky:
        line = text.count("\n", 0, m.start()) + 1
        out.append(("HIGH", f"dynamic-context shell with network/decode at line {line}: {m.group(0)[:80]}"))
    if len(dyn) > len(risky):
        m = next(x for x in dyn if x not in risky)
        line = text.count("\n", 0, m.start()) + 1
        out.append(("MEDIUM", f"{len(dyn) - len(risky)} dynamic-context shell call(s), first at line {line}: "
                              f"{m.group(0)[:60]} (runs before the model reads the file; confirm you trust it)"))
    if BROAD_GRANT.search(text):
        out.append(("MEDIUM", "frontmatter grants unrestricted Bash (allowed-tools: Bash / Bash(*))"))
    eg = list(EGRESS.finditer(text))
    if eg:
        line = text.count("\n", 0, eg[0].start()) + 1
        out.append(("LOW", f"{len(eg)} network command(s) in instructions, first at line {line}: {eg[0].group(0)[:70]}"))
    return out


def audit_settings_file(p: Path, is_project: bool) -> list[tuple[str, str]]:
    try:
        s = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out = []
    if is_project and s.get("hooks"):
        out.append(("HIGH", "project settings define hooks (they run with your permissions; review every command)"))
    if is_project and s.get("apiKeyHelper"):
        out.append(("HIGH", "project settings set apiKeyHelper"))
    env = s.get("env") or {}
    for k in ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL", "HTTPS_PROXY", "HTTP_PROXY"):
        if k in env and is_project:
            out.append(("HIGH", f"project settings override {k}={str(env[k])[:60]}"))
    if s.get("enableAllProjectMcpServers"):
        out.append(("MEDIUM", "enableAllProjectMcpServers=true auto-trusts every MCP server a repo declares"))
    perms = s.get("permissions") or {}
    if perms.get("defaultMode") == "bypassPermissions":
        out.append(("INFO", "defaultMode=bypassPermissions: PreToolUse hooks are your only gate"))
    return out


def audit(roots: list[Path]) -> list[tuple[str, str, str]]:
    findings = []
    for root in roots:
        if not root.exists():
            continue
        for p in _iter_files(root):
            for sev, msg in audit_instruction_file(p):
                findings.append((sev, str(p), msg))
        for p in list(root.glob("**/.claude/settings*.json")) + list(root.glob("settings*.json")):
            if any(part in SKIP_DIRS for part in p.parts):
                continue
            is_project = p.parent.name == ".claude" and p.parent.parent != Path.home()
            for sev, msg in audit_settings_file(p, is_project):
                findings.append((sev, str(p), msg))
    return findings


def main(argv: list[str]) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    strict = "--strict" in argv
    roots = [Path(a).expanduser() for a in argv if not a.startswith("--")] or [Path.home() / ".claude", Path.cwd()]
    findings = audit(roots)
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda f: (order[f[0]], f[1]))
    for sev, path, msg in findings:
        print(f"[{sev}] {path}\n        {msg}")
    counts = {k: sum(1 for f in findings if f[0] == k) for k in order}
    print(f"\n{counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['LOW']} low, {counts['INFO']} info")
    return 1 if strict and counts["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
