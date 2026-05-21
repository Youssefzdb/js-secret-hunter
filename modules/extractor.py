#!/usr/bin/env python3
"""
Secret Extractor — 50+ regex patterns to find real secrets in JS files.
False positive filters:
  - Variable references (config.x, encodeURIComponent(x), typeof x)
  - Charset/alphabet constants (abcdef..., ABCDEF..., base64 alphabet)
  - Cloudflare Turnstile / PoW challenges (_hvc, window._hvc)
  - _0x obfuscated string arrays
  - Short/trivial values
"""
import re
import math
from collections import Counter

# ── Patterns ──────────────────────────────────────────────────────────────────
SECRET_PATTERNS = {
    # High-confidence fixed-format tokens (no false positives possible)
    "AWS Access Key":        r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])',
    "AWS Secret Key":        r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']',
    "Google API Key":        r'AIza[0-9A-Za-z\-_]{35}',
    "Google OAuth":          r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    "Firebase":              r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    "GitHub Token":          r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}',
    "GitHub Classic Token":  r'github_pat_[A-Za-z0-9_]{82}',
    "GitLab Token":          r'glpat-[A-Za-z0-9\-]{20}',
    "Stripe Secret Key":     r'sk_live_[0-9a-zA-Z]{24,}',
    "Stripe Public Key":     r'pk_live_[0-9a-zA-Z]{24,}',
    "Stripe Test Key":       r'sk_test_[0-9a-zA-Z]{24,}',
    "SendGrid API Key":      r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
    "Slack Token":           r'xox[baprs]-[0-9A-Za-z\-]{10,250}',
    "Slack Webhook":         r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
    "Discord Webhook":       r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+',
    "Telegram Bot Token":    r'(?<![A-Za-z0-9])[0-9]{8,10}:[A-Za-z0-9_-]{35,}(?![A-Za-z0-9])',
    "Shopify Token":         r'shpat_[a-fA-F0-9]{32}',
    "NPM Token":             r'npm_[A-Za-z0-9]{36}',
    "Mapbox Token":          r'pk\.eyJ[A-Za-z0-9\.\-_]{30,}',
    "Cloudinary URL":        r'cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[A-Za-z0-9_\-]+',
    "Supabase Key":          r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
    "OpenAI API Key":        r'sk-[A-Za-z0-9]{48}',
    "Anthropic API Key":     r'sk-ant-[A-Za-z0-9\-_]{90,}',
    "DigitalOcean Token":    r'dop_v1_[a-f0-9]{64}',
    "GCP Service Account":   r'"private_key_id":\s*"[a-f0-9]{40}"',
    "Notion Token":          r'secret_[A-Za-z0-9]{43}',

    # Literal string assignments ONLY (value must be in quotes, not a variable)
    "Password in Code":  r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\'<>${}()\s\\]{8,})["\']',
    "Secret in Code":    r'(?i)(?:app_secret|client_secret|secret_key)\s*[=:]\s*["\']([^"\'<>${}()\s\\]{10,})["\']',
    "API Key Generic":   r'(?i)(?:api_key|apikey|api-key)\s*[=:]\s*["\']([^"\'<>${}()\s\\]{16,})["\']',
    "Token in Code":     r'(?i)(?:access_token|auth_token|api_token)\s*[=:]\s*["\']([^"\'<>${}()\s\\]{20,})["\']',
    "Bearer Token":      r'(?i)Authorization["\s]*:\s*["\']?Bearer\s+([A-Za-z0-9\-._~+/]{30,}=*)',

    # Private Keys
    "RSA Private Key":   r'-----BEGIN RSA PRIVATE KEY-----',
    "EC Private Key":    r'-----BEGIN EC PRIVATE KEY-----',
    "PGP Private Key":   r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    "Generic Private Key": r'-----BEGIN PRIVATE KEY-----',
    "SSH Private Key":   r'-----BEGIN OPENSSH PRIVATE KEY-----',

    # JWT — 3-part dot-separated base64
    "JWT Token":         r'eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}',

    # DB URIs — must have credentials (user:pass@host)
    "MongoDB URI":       r'mongodb(?:\+srv)?://[^"\'<>\s@:]+:[^"\'<>\s@]{4,}@[^"\'<>\s/]+',
    "PostgreSQL URI":    r'postgres(?:ql)?://[^"\'<>\s@:]+:[^"\'<>\s@]{4,}@[^"\'<>\s/]+',
    "MySQL URI":         r'mysql://[^"\'<>\s@:]+:[^"\'<>\s@]{4,}@[^"\'<>\s/]+',
    "Redis URI":         r'redis://:?[^"\'<>\s@]{4,}@[^"\'<>\s/]+',

    # URLs with embedded credentials (user:pass@host) — skip CDN/font URLs
    "URL with credentials": r'https?://[A-Za-z0-9._%-]+:[A-Za-z0-9._~!$&\'()*+,;=%-]{4,}@[A-Za-z0-9.\-]+(?:\.[a-z]{2,})',
}

SEVERITY = {
    "AWS Access Key": "CRITICAL", "AWS Secret Key": "CRITICAL",
    "GitHub Token": "CRITICAL", "GitHub Classic Token": "CRITICAL",
    "Stripe Secret Key": "CRITICAL", "OpenAI API Key": "CRITICAL",
    "Anthropic API Key": "CRITICAL", "MongoDB URI": "CRITICAL",
    "PostgreSQL URI": "CRITICAL", "MySQL URI": "CRITICAL",
    "URL with credentials": "CRITICAL", "RSA Private Key": "CRITICAL",
    "EC Private Key": "CRITICAL", "PGP Private Key": "CRITICAL",
    "SSH Private Key": "CRITICAL", "Generic Private Key": "CRITICAL",
    "GCP Service Account": "CRITICAL", "SendGrid API Key": "CRITICAL",
    "Shopify Token": "CRITICAL", "DigitalOcean Token": "CRITICAL",
    "Google API Key": "HIGH", "Firebase": "HIGH",
    "Supabase Key": "HIGH", "JWT Token": "HIGH",
    "Slack Token": "HIGH", "Discord Webhook": "HIGH",
    "Telegram Bot Token": "HIGH", "Password in Code": "HIGH",
    "Secret in Code": "HIGH", "Bearer Token": "HIGH",
    "Mapbox Token": "HIGH",
    "Token in Code": "MEDIUM", "API Key Generic": "MEDIUM",
}

def get_severity(name):
    return SEVERITY.get(name, "MEDIUM")


# ── False Positive Detection ───────────────────────────────────────────────────

# Charset/alphabet constants — sequential runs of printable chars
_CHARSET_PATTERNS = [
    re.compile(r'^abcdefghijklmnopqrstuvwxyz', re.I),
    re.compile(r'^ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'),
    re.compile(r'^[A-Za-z]{26}[A-Za-z]{26}[0-9]{10}'),  # full alphanumeric charset
    re.compile(r'0123456789\+/=?$'),                      # base64 alphabet suffix
]

# Known non-secret variable/code patterns
_CODE_FRAGMENTS = [
    'encodeURIComponent(', '.user_token', '.access_token', 'config.',
    'beamer_config.', 'typeof ', 'undefined', 'function(', 'return ',
    '&&', '||', '));', '));', '+encodeURI', '.ajax(', 'Beamer.',
    'window._hvc', '._hvc', '"algorithm":', '"challenge":', '"maxnumber":',
    '"salt":', 'SHA-256', 'sha-256',
]

# Skip Cloudflare PoW / Turnstile challenge blobs (window._hvc = "eyJ...")
_TURNSTILE_RE = re.compile(r'window\._hvc\s*=')
_POW_JSON_RE  = re.compile(r'\{.*"algorithm"\s*:.*"challenge"\s*:', re.DOTALL)

# Skip _0x obfuscated string array entries
_OBX_RE = re.compile(r'var\s+_0x[0-9a-f]+\s*=\s*\[')


def _shannon_entropy(s: str) -> float:
    """Measure randomness of a string (higher = more likely a real secret)."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_sequential(s: str) -> bool:
    """Detect alphabetically or numerically sequential strings (charset constants)."""
    if len(s) < 20:
        return False
    for pat in _CHARSET_PATTERNS:
        if pat.search(s):
            return True
    # Detect long sequential runs: abcdefg... or ABCDEFG...
    sequential = 0
    for i in range(1, min(len(s), 30)):
        if ord(s[i]) == ord(s[i-1]) + 1:
            sequential += 1
    return sequential >= 15  # 15+ sequential chars = charset constant


def is_false_positive(value: str, context: str = "") -> bool:
    """
    Return True if this value is NOT a real secret.
    context: the surrounding line of code (for extra checks).
    """
    val = value.strip()

    # 1. Too short
    if len(val) < 8:
        return True

    # 2. Code fragments / variable references
    for kw in _CODE_FRAGMENTS:
        if kw in val:
            return True

    # 3. Sequential charset strings (base64 alphabet, etc.)
    if _is_sequential(val):
        return True

    # 4. Cloudflare Turnstile / PoW challenges via window._hvc
    if context:
        if _TURNSTILE_RE.search(context):
            return True
        if _OBX_RE.search(context):
            return True

    # 5. Decoded value looks like PoW JSON (algorithm + challenge)
    # (catch when the raw value is the base64 of a challenge)
    if len(val) > 40:
        try:
            import base64
            decoded = base64.b64decode(val + "==").decode("utf-8", errors="replace")
            if '"algorithm"' in decoded and '"challenge"' in decoded:
                return True
        except Exception:
            pass

    # 6. Placeholder / documentation values
    placeholder_re = re.compile(
        r'(?i)(YOUR_|EXAMPLE|REPLACE|PLACEHOLDER|<[A-Z_]+>|xxx+|000+|test_?key|dummy)',
        re.I
    )
    if placeholder_re.search(val):
        return True

    # 7. URLs without credentials (CDN, fonts, etc.)
    if val.startswith(('http://', 'https://')):
        if '@' not in val:
            return True
        if 'fonts.googleapis.com' in val or 'css2?' in val:
            return True

    # 8. Low entropy for "generic" patterns (real keys are random)
    entropy = _shannon_entropy(val)
    if len(val) >= 20 and entropy < 3.0:
        return True

    return False


# ── Extractor ─────────────────────────────────────────────────────────────────

class SecretExtractor:
    def __init__(self, logger):
        self.log = logger
        self._compiled = {
            name: re.compile(pattern, re.MULTILINE)
            for name, pattern in SECRET_PATTERNS.items()
        }

    def scan(self, url: str, content: str) -> list[dict]:
        findings = []
        seen = set()
        lines = content.splitlines()

        for name, regex in self._compiled.items():
            for match in regex.finditer(content):
                value = (match.group(1) if match.lastindex else match.group(0)).strip()

                # Get surrounding line for context-aware FP checks
                pos = match.start()
                line_num = content[:pos].count('\n') + 1
                context_line = lines[line_num - 1] if line_num <= len(lines) else ""

                if is_false_positive(value, context_line):
                    continue

                key = f"{name}:{value[:60]}"
                if key in seen:
                    continue
                seen.add(key)

                finding = {
                    "type":     name,
                    "severity": get_severity(name),
                    "value":    value[:200],
                    "url":      url,
                    "line":     line_num,
                    "snippet":  context_line.strip()[:120],
                    "decoded":  None,
                }
                findings.append(finding)
                self.log.found(name, get_severity(name), url, line_num)

        return findings
