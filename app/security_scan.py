"""Security & safety scanner for user-supplied code and secrets."""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict


@dataclass
class Finding:
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    category: str
    line: int
    message: str
    snippet: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# --- Secret detection patterns -------------------------------------------------
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("OpenAI/Anthropic key", re.compile(r"\b(sk-[A-Za-z0-9_\-]{16,}|sk-ant-[A-Za-z0-9_\-]{16,})\b")),
    ("OpenRouter key", re.compile(r"\bsk-or-[A-Za-z0-9_\-]{16,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("AWS access key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("Bearer token", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}\b")),
    ("Generic secret assignment", re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
]

# --- Dangerous code patterns ---------------------------------------------------
CODE_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    ("critical", "command-exec", re.compile(r"\b(os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output)|pty\.spawn)\s*\("),
     "Shell/process execution detected"),
    ("critical", "eval-exec", re.compile(r"\b(eval|exec|compile)\s*\("), "Dynamic code execution detected"),
    ("critical", "reverse-shell", re.compile(r"(?i)(/dev/tcp/|bash\s+-i|nc\s+-e|socket\.socket\(.*\).*connect\()"),
     "Possible reverse shell / raw socket connection"),
    ("high", "destructive-fs", re.compile(r"(?i)\b(rm\s+-rf\s+/|shutil\.rmtree|os\.remove|os\.unlink)\b"),
     "Destructive filesystem operation"),
    ("high", "network-exfil", re.compile(r"(?i)\b(requests\.(?:post|put)|urllib\.request\.urlopen|httpx\.(?:post|put)|curl\s+-[a-z]*d)\b"),
     "Outbound network request that could exfiltrate data"),
    ("high", "base64-obfuscation", re.compile(r"(?i)\bbase64\.(?:b64decode|decodebytes)\b"), "Base64 decoding (possible obfuscation)"),
    ("medium", "dangerous-perms", re.compile(r"os\.chmod\([^)]*0o?777"), "World-writable permissions"),
    ("medium", "pickle-load", re.compile(r"\b(pickle\.loads?|marshal\.loads?|yaml\.load)\s*\("), "Unsafe deserialization"),
    ("medium", "sql-concat", re.compile(r"(?i)(execute|cursor\.execute)\s*\(\s*['\"].*\+"), "SQL built by string concatenation"),
    ("low", "debug-enabled", re.compile(r"(?i)(debug\s*=\s*True|app\.run\([^)]*debug)"), "Debug mode enabled"),
]


def scan_code(text: str) -> list[Finding]:
    """Scan a block of code/text and return security findings."""
    findings: list[Finding] = []
    if not text:
        return findings
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(Finding("high", "secret-exposure", i, f"Hardcoded secret detected: {label}",
                                        _redact(line.strip())[:160]))
        for severity, category, pattern, message in CODE_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(severity, category, i, message, line.strip()[:160]))
    return findings


def _redact(s: str) -> str:
    for label, pattern in SECRET_PATTERNS:
        s = pattern.sub("<redacted>", s)
    return s


def redact_secrets(text: str) -> str:
    return _redact(text or "")


def detect_secrets(text: str) -> list[dict]:
    """Return only secret detections with the raw (unredacted) match for vaulting."""
    out: list[dict] = []
    for i, line in enumerate((text or "").splitlines(), start=1):
        for label, pattern in SECRET_PATTERNS:
            m = pattern.search(line)
            if m:
                out.append({"line": i, "label": label, "match": m.group(0)})
    return out


def risk_level(findings: list[Finding]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    top = 0
    name = "none"
    for f in findings:
        if order.get(f.severity, 0) > top:
            top = order[f.severity]
            name = f.severity
    return name
