# Security policy

This repository is a defensive tool. If you find a way around it (an injection shape the scanner misses, a secret format or send path the guard doesn't catch), please report it privately to the repository owner instead of opening a public issue.

Include:
- the input (the tool result or outbound payload) that gets through,
- which hook you expected to catch it,
- the output of `python3 tests/test_scanner.py` and `python3 tests/test_guard.py`.

Fixes come with a new regression test in `tests/`.

## Scope

- In scope: false negatives in `hooks/`, crashes that let an outbound call through, and supply-chain patterns `tools/config_audit.py` should flag.
- Known limits (see the README): secrets split into pieces, key formats not in `hooks/secret_patterns.py`, and new styles of injection. Report these anyway, since new patterns are welcome.

Never put a real secret in a report. The tests build fake keys at runtime; do the same.
