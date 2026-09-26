"""Secret / credential formats, shared by injection_scanner (inbound) and
safety_guard (outbound). Case-sensitive on purpose: provider prefixes are
fixed-case, and IGNORECASE turned random base64 into "AWS keys".

find_secrets(text) -> list[(label, redacted_sample)]
"""
import re

# (label, pattern). Order: most specific first so a sk-ant- key is not also
# reported as a generic sk- key.
SECRET_PATTERNS = [
    ("anthropic_key", r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}"),
    ("openai_key", r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}"),
    ("openai_key_legacy", r"(?<![A-Za-z0-9_\-])sk-[A-Za-z0-9]{48}(?![A-Za-z0-9])"),
    ("github_token", r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}"),
    ("github_pat", r"github_pat_[A-Za-z0-9_]{80,}"),
    ("slack_token", r"xox[abposr]-[A-Za-z0-9\-]{20,}"),
    ("slack_webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}"),
    ("google_api_key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("aws_access_key", r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    ("stripe_key", r"(?:sk|rk)_live_[A-Za-z0-9]{24,}"),
    ("private_key_block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    ("jwt", r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("assigned_secret", r"(?i:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|bearer|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-/+]{24,}"),
]

_COMPILED = [(label, re.compile(p)) for label, p in SECRET_PATTERNS]

# Documented placeholder values that appear in vendor docs and tutorials.
_KNOWN_EXAMPLES = {
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}


def _redact(s: str) -> str:
    return s[:8] + "…" + f"({len(s)} chars)" if len(s) > 12 else s


def find_secrets(text: str) -> list[tuple[str, str]]:
    """Return [(label, redacted_sample)] for every secret-shaped span in text.
    Samples are redacted so a finding never re-leaks the secret into logs."""
    out: list[tuple[str, str]] = []
    if not text:
        return out
    seen_spans: list[tuple[int, int]] = []
    for label, rx in _COMPILED:
        for m in rx.finditer(text):
            s, e = m.span()
            if any(s < pe and e > ps for ps, pe in seen_spans):
                continue  # already reported by a more specific pattern
            val = m.group(0)
            if any(ex in val for ex in _KNOWN_EXAMPLES) or "EXAMPLE" in val:
                continue
            seen_spans.append((s, e))
            out.append((label, _redact(val)))
            if len(out) >= 10:
                return out
    return out
