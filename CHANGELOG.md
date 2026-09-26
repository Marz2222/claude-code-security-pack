# Changelog

## 2026-09-26

- **Every tool is covered.** Both hooks now use matcher `*`. The scanner reads every tool's result (Grep, Write, subagents; before this, only Read, Bash, web and MCP tools). The guard also checks Claude Code's built-in senders (`Artifact`, `ArtifactComments`, `ArtifactData`, `SendMessage`, `PushNotification`, `RemoteTrigger`) and text typed or uploaded through the browser tools.
- **Fixed: attacks after the first line were missed.** The structural analyzer saw JSON-escaped tool output as one run-on line, so an attack on line 2 or later was demoted to log-only. Grep `path:12:` prefixes and diff `+` markers hid attacks the same way. The scanner now retries on the decoded text; a retry can only escalate, never clear.
- **Logs stay clean.** Logs go to `$SECURITY_PACK_LOG_DIR` when it's set. The tests use a temporary folder, so running them never writes fake findings into your real logs.
- The pack's own test files are skipped by the scanner, like its other files.
- 17 new regression tests (44 in total).
- Added a manual install guide and safety notes for AI-assisted installs.

## 2026-09-25

- First release: injection scanner with structural corroboration, outbound guard (secrets, invisible Unicode, markdown-image exfiltration, attachments and zips, network commands), config auditor, operating rules (SOP), 27 regression tests.
