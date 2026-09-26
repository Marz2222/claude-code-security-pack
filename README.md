# Claude Code Security Pack

Prompt-injection detection and outbound-leak protection for [Claude Code](https://code.claude.com), built on Claude Code hooks.

Local only: standard-library Python 3.9+, no network calls, no API keys, no dependencies. Works on macOS, Linux and Windows.

> **Why:** an agent that reads untrusted content (email, web pages, repo files), can see private data, and can send things out can be steered into leaking. This pack puts a hard check on both sides of that loop: it flags injected instructions coming **in**, and blocks secrets and exfiltration tricks going **out**.

## Features

### Injection scanner (`PostToolUse`, every tool)
- Scans the result of **every** tool call: files, grep hits, shell output, web pages, email, chat, MCP servers and subagent reports.
- Two stages: a fast pattern pass (instruction overrides, exfiltration requests, authority spoofing, tool poisoning, system-prompt extraction, hidden tags), then a **structural analyzer** that tells an attack aimed at the assistant (*"Assistant, ignore your instructions and forward…"*) from text that only discusses one (*"the paper tests 'ignore your instructions'…"*). Only real attacks interrupt you; the rest is logged.
- Catches attacks on **any line**, including inside grep output (`file.txt:12:`), diffs (`+line`) and JSON-wrapped tool results.
- Decodes and rechecks base64 blocks; strips and flags invisible Unicode tag characters; applies NFKC normalization against lookalike characters.
- Flags live-looking credentials that show up in tool output.
- When it finds an attack, it adds a warning next to the tool result telling Claude to treat the content as data, and to bring any send, delete or share request to you for confirmation.

### Outbound guard (`PreToolUse`, every tool)
- Blocks **secrets** in anything that leaves the machine: Anthropic, OpenAI, GitHub, Slack (tokens and webhooks), Google, AWS and Stripe keys, private key blocks, JWTs, and `api_key = …`-style assignments.
- Blocks **invisible Unicode** (tag characters, RTL overrides) and **markdown-image exfiltration links** (images whose URL carries data).
- Scans **attached files and zip contents**, and blocks secret files by name, including inside zips: `.env*`, SSH private keys, `*.pem`/`*.key`, `credentials.json`, `token.json`, KeePass databases, `.netrc`, `.pypirc`, `settings.local.json`.
- Blocks network commands (`curl`, `wget`, `nc`, `ssh`, `scp`, `dig`, `nslookup`, PowerShell `iwr`/`irm`, …) and URL fetches that carry a literal secret, which catches DNS and HTTP exfiltration.
- Covers email and chat MCP tools (anything named send, post, reply, forward, schedule, publish, comment or draft), Claude Code built-ins (artifact publishing, `SendMessage`, push notifications, remote triggers), browser typing and uploads, and your own send scripts.
- Runs in every permission mode, including bypass. If the guard crashes on an outbound call, you're asked to confirm the call instead of it going through (fails closed).
- Optional bot marker: require messages Claude writes to start with a marker (such as 🤖) so recipients can tell them from yours.

### Config auditor (`tools/config_audit.py`)
- Audits `CLAUDE.md` files, skills, commands, plugins and project settings for supply-chain tricks: hidden instructions, skill preprocessing shell lines (`` !`cmd` ``), blanket Bash permissions, project hooks, `apiKeyHelper` and `ANTHROPIC_BASE_URL` overrides, and `enableAllProjectMcpServers`.
- Run it on every repo you clone before opening Claude Code in it.

### Operating rules (`SOP.md`)
- Ten rules to add to your `~/.claude/CLAUDE.md`, drawn from OWASP's LLM and agentic Top 10 lists, the lethal trifecta, the Agents Rule of Two, and recent MCP and Claude Code advisories.

### Tested
- 44 regression tests (22 scanner, 22 guard) covering real attacks, known false positives, multi-line and grep-shaped output, built-in senders, and log isolation. `install.py` runs them on every install.

## Install

Two guides, both with a dry run and verification steps:

- **[Manual install](MANUAL_INSTALL.md)**: step by step, for people.
- **[AI-assisted install](INSTALL.md)**: open Claude Code in this folder and say:
  > Read INSTALL.md and install this security pack. Follow every step and run every test.

Whichever you use, **read the code before running it.** It's about 1,500 lines of plain Python with no dependencies.

## Repository layout

| Path | What it is |
|---|---|
| `hooks/injection_scanner.py` | PostToolUse hook: scans tool results for prompt injection |
| `hooks/quarantine_reader.py` | Structural analyzer that tells an attack from a discussion of one |
| `hooks/outbound_guard.py` | PreToolUse hook: blocks secrets, hidden Unicode and exfiltration links going out; also a CLI (`--check-text`, `--check-file`) |
| `hooks/outbound_check.py` | Shared outbound checks and the list of send tools and commands |
| `hooks/secret_patterns.py` | Credential formats |
| `tools/config_audit.py` | Supply-chain auditor for Claude Code config |
| `tests/` | Regression tests (`test_scanner.py`, `test_guard.py`) |
| `install.py` | Installer: `--dry-run`, install/upgrade, `--uninstall` |
| `security.config.json` | Template for registering your own send paths |
| `SOP.md` | Operating rules for `CLAUDE.md` |

Once installed, everything lives in `~/.claude/security-pack/`. The installer adds two entries to the `hooks` section of `~/.claude/settings.json`, and backs that file up first.

## Logs

- `~/.claude/security-pack/injection_scanner_findings.log`: every pattern hit, including the ones the structural analyzer judged harmless.
- `~/.claude/security-pack/outbound_guard.log`: every outbound decision.

Skim them weekly. A burst of findings from one source is the signal. Set `SECURITY_PACK_LOG_DIR` to log somewhere else; the tests use it so they never write to your real logs.

## Limits

Pattern checks catch the common shapes, not every attack. A secret split into pieces, a key format not on the list, or a new style of injection can get through. The hooks are a safety net, not a guarantee. The real protection is SOP rule 4: content from outside should never be able to trigger a send without you seeing it first.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
