"""Outbound content check, shared by safety_guard (PreToolUse).

One job: nothing leaves the machine (email, WhatsApp/Slack/Signal via Beeper,
Discord, social posts) carrying a secret or an invisible-instruction payload.
Covers the message text AND any file it attaches or reads its body from,
including text members inside .zip attachments.

check_outbound_text(text)            -> list[str] problems
check_outbound_files(paths)          -> list[str] problems
outbound_paths_from_command(cmd)     -> list[str] file paths a send command ships
is_outbound_command(cmd)             -> bool

Pure stdlib, no network. Callers decide block vs defer.
"""
from __future__ import annotations

import os
import re
import shlex
import zipfile

from secret_patterns import find_secrets

# Scripts / CLIs that put content on the wire. Substring match on the command.
# Extend via security.config.json -> "outbound_command_markers".
OUTBOUND_COMMAND_MARKERS = [
    "gmail_send", "send_email", "sendmail", "bridge_send", "whatsapp_send",
    "slack_send", "discord_send", "telegram_send", "gh issue comment", "gh pr comment",
]

# MCP tools that send or schedule outbound content. Extend via
# security.config.json -> "outbound_mcp_tools" (exact names) and
# "outbound_mcp_regex" (one regex).
OUTBOUND_MCP_TOOLS = {
    "mcp__beeper__send_message",
    "mcp__gmail__send_email", "mcp__gmail__reply_to_email", "mcp__gmail__reply_all",
    "mcp__gmail__forward_email", "mcp__gmail__draft_email", "mcp__gmail__update_draft",
    "mcp__gmail__send_draft",
    # Claude Code built-ins that publish or message (reach the guard via matcher "*")
    "Artifact", "ArtifactComments", "ArtifactData", "SendMessage", "PushNotification",
    "RemoteTrigger",
    # browser tools that type into or upload to web pages
    "mcp__claude-in-chrome__computer", "mcp__claude-in-chrome__form_input",
    "mcp__claude-in-chrome__file_upload", "mcp__claude-in-chrome__upload_image",
    "mcp__Claude_Browser__computer", "mcp__Claude_Browser__form_input",
}
OUTBOUND_MCP_PATTERN = re.compile(
    r"^mcp__.*(?:send|post|reply|forward|schedule|publish|comment|create_draft|draft_email)",
    re.IGNORECASE)

CONFIG = {}
try:
    import json as _json
    _cfg = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "security.config.json")
    if os.path.isfile(_cfg):
        with open(_cfg, encoding="utf-8") as _fh:
            CONFIG = _json.load(_fh)
        OUTBOUND_COMMAND_MARKERS += [m.lower() for m in CONFIG.get("outbound_command_markers", [])]
        OUTBOUND_MCP_TOOLS |= set(CONFIG.get("outbound_mcp_tools", []))
        if CONFIG.get("outbound_mcp_regex"):
            OUTBOUND_MCP_PATTERN = re.compile(CONFIG["outbound_mcp_regex"], re.IGNORECASE)
except Exception:
    pass  # bad config never disables the defaults

# Flags whose value is a file that gets sent (body or attachment).
_FILE_FLAGS = ("--body-file", "--attach", "--image", "--file", "--text-file", "--html-file")

_TEXT_EXT = {".md", ".txt", ".html", ".htm", ".json", ".csv", ".py", ".toml", ".yaml",
             ".yml", ".env", ".ini", ".cfg", ".js", ".ts", ".ps1", ".sh", ".xml", ".log"}
_MAX_FILE_BYTES = 5_000_000
_MAX_ZIP_MEMBERS = 400

_INVISIBLE = re.compile(r"[\U000E0000-\U000E007F]{3,}|\u202e|[\u200b\u200c\u200d\ufeff]{4,}")
# ![x](https://host/p?data=<40+ chars>): EchoLeak / CamoLeak / CVE-2026-22551 shape.
_MD_IMAGE_EXFIL = re.compile(r"!\[[^\]]*\]\(\s*https?://[^)\s]*\?[^)\s]{40,}\)")
# Filenames that should never ship regardless of content.
_FORBIDDEN_NAMES = re.compile(
    r"(?:^|/)(?:\.env(?:\..*)?|id_rsa|id_ed25519|.*\.pem|.*\.key|credentials\.json|"
    r"token\.json|.*\.kdbx|\.netrc|\.pypirc|settings\.local\.json)$", re.IGNORECASE)


def is_outbound_mcp(tool_name: str) -> bool:
    return tool_name in OUTBOUND_MCP_TOOLS or bool(OUTBOUND_MCP_PATTERN.match(tool_name))


def is_outbound_command(cmd: str) -> bool:
    low = cmd.lower()
    return any(m in low for m in OUTBOUND_COMMAND_MARKERS)


def check_outbound_text(text: str, where: str = "message") -> list[str]:
    problems = []
    for label, sample in find_secrets(text or ""):
        problems.append(f"secret in {where}: {label} {sample}")
    if text and _INVISIBLE.search(text):
        problems.append(f"invisible Unicode (tag chars / RTL override / zero-width run) in {where}")
    if text and _MD_IMAGE_EXFIL.search(text):
        problems.append(f"markdown image with a long query string in {where} "
                        "(zero-click exfil shape: the client fetches the URL on render)")
    return problems


def _check_blob(name: str, data: bytes) -> list[str]:
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        return []
    return check_outbound_text(text, where=name)


def check_outbound_files(paths: list[str]) -> list[str]:
    problems: list[str] = []
    for p in paths:
        norm = p.replace("\\", "/")
        if _FORBIDDEN_NAMES.search(norm):
            problems.append(f"forbidden file type/name attached: {os.path.basename(p)}")
            continue
        if not os.path.isfile(p):
            continue
        ext = os.path.splitext(p)[1].lower()
        try:
            if ext == ".zip":
                with zipfile.ZipFile(p) as z:
                    for info in z.infolist()[:_MAX_ZIP_MEMBERS]:
                        inner = f"{os.path.basename(p)}:{info.filename}"
                        if _FORBIDDEN_NAMES.search(info.filename):
                            problems.append(f"forbidden file inside zip: {inner}")
                            continue
                        if (os.path.splitext(info.filename)[1].lower() in _TEXT_EXT
                                and info.file_size <= _MAX_FILE_BYTES):
                            problems += _check_blob(inner, z.read(info))
            elif ext in _TEXT_EXT and os.path.getsize(p) <= _MAX_FILE_BYTES:
                with open(p, "rb") as fh:
                    problems += _check_blob(os.path.basename(p), fh.read())
        except (zipfile.BadZipFile, OSError) as e:
            problems.append(f"could not inspect {os.path.basename(p)}: {e}")
    return problems


def outbound_paths_from_command(cmd: str) -> list[str]:
    try:
        toks = shlex.split(cmd, posix=True)
    except ValueError:
        toks = cmd.split()
    out = []
    for i, t in enumerate(toks):
        for flag in _FILE_FLAGS:
            if t == flag and i + 1 < len(toks):
                out.append(toks[i + 1])
            elif t.startswith(flag + "="):
                out.append(t.split("=", 1)[1])
    return out
