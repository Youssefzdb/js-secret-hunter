#!/usr/bin/env python3
"""
Secret Extractor — 50+ regex patterns to find secrets in JS files.
Covers: API keys, tokens, passwords, JWTs, private keys, cloud credentials, etc.
"""
import re

SECRET_PATTERNS = {
    # === Cloud & SaaS API Keys ===
    "AWS Access Key":        r'(?i)\bAKIA[0-9A-Z]{16}\b',
    "AWS Secret Key":        r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']',
    "Google API Key":        r'\bAIza[0-9A-Za-z\-_]{35}\b',
    "Google OAuth":          r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    "Firebase FCM":          r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    "GitHub Token":          r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}',
    "GitHub Classic Token":  r'github_pat_[A-Za-z0-9_]{82}',
    "GitLab Token":          r'glpat-[A-Za-z0-9\-]{20}',
    "Stripe Secret Key":     r'\bsk_live_[0-9a-zA-Z]{24,}\b',
    "Stripe Public Key":     r'\bpk_live_[0-9a-zA-Z]{24,}\b',
    "Stripe Test Key":       r'\bsk_test_[0-9a-zA-Z]{24,}\b',
    "SendGrid API Key":      r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
    "Mailgun API Key":       r'\bkey-[0-9a-zA-Z]{32}\b',
    "Mailchimp API Key":     r'\b[0-9a-f]{32}-us[0-9]{1,2}\b',
    "Slack Token":           r'\bxox[baprs]-[0-9A-Za-z\-]{10,250}\b',
    "Slack Webhook":         r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
    "Discord Webhook":       r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+',
    "Telegram Bot Token":    r'\b[0-9]{8,10}:[A-Za-z0-9_-]{35,}\b',
    "Shopify Token":         r'\bshpat_[a-fA-F0-9]{32}\b',
    "Notion Token":          r'\bsecret_[A-Za-z0-9]{43}\b',
    "NPM Token":             r'\bnpm_[A-Za-z0-9]{36}\b',
    "Mapbox Token":          r'\bpk\.eyJ[A-Za-z0-9\.\-_]+\b',
    "Cloudinary URL":        r'cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[A-Za-z0-9_\-]+',
    "Supabase Key":          r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
    "OpenAI API Key":        r'\bsk-[A-Za-z0-9]{48}\b',
    "OpenAI Project Key":    r'\bsk-proj-[A-Za-z0-9\-_]{80,}\b',
    "Anthropic API Key":     r'\bsk-ant-[A-Za-z0-9\-_]{90,}\b',
    "DigitalOcean Token":    r'\bdop_v1_[a-f0-9]{64}\b',
    "GCP Service Account":   r'"private_key_id":\s*"[a-f0-9]{40}"',

    # === Passwords & Generic Secrets (with actual VALUES) ===
    "Password in Code":      r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\'$`{}\s][^"\']{6,}[^"\'$`{}\s])["\']',
    "Secret in Code":        r'(?i)(?<![a-z])(?:app_secret|client_secret|secret_key)\s*[=:]\s*["\']([^"\'$`{}\s][^"\']{8,})["\']',
    "API Key Generic":       r'(?i)(?:api_key|apikey|api-key)\s*[=:]\s*["\']([^"\'$`{}\s][^"\']{15,})["\']',
    "Bearer Token":          r'(?i)Authorization["\s:]+Bearer\s+([A-Za-z0-9\-._~+/]{30,}=*)',

    # === Private Keys & Certificates ===
    "RSA Private Key":       r'-----BEGIN RSA PRIVATE KEY-----',
    "EC Private Key":        r'-----BEGIN EC PRIVATE KEY-----',
    "PGP Private Key":       r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    "Generic Private Key":   r'-----BEGIN PRIVATE KEY-----',
    "SSH Private Key":       r'-----BEGIN OPENSSH PRIVATE KEY-----',

    # === JWT Tokens (real values only — skip template/variable refs) ===
    "JWT Token":             r'\beyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b',

    # === Database & Connection Strings ===
    "MongoDB URI":           r'mongodb(?:\+srv)?://(?!\$)[^\s"\'<>]{10,}',
    "PostgreSQL URI":        r'postgres(?:ql)?://(?!\$)[^\s"\'<>]{10,}',
    "MySQL URI":             r'mysql://(?!\$)[^\s"\'<>]{10,}',
    "Redis URI":             r'redis://(?!\$)[^\s"\'<>@]{6,}@[^\s"\'<>]+',

    # === URLs with Credentials (actual credentials, not variables) ===
    "URL with credentials":  r'https?://[A-Za-z0-9_\-%.]+:[A-Za-z0-9_\-%.@!#$]{4,}@[A-Za-z0-9\-._]+',

    # === Long Encoded Strings (last resort — suspicious only) ===
    "Long Base64 String":    r'(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){15,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/=])',
    "Hex Secret (32+ chars)": r'\b(?<!\.)([a-f0-9]{32,64})\b(?!\.[a-z])',
}

# Severity levels
SEVERITY = {
    "AWS Access Key": "CRITICAL", "AWS Secret Key": "CRITICAL",
    "Google API Key": "HIGH", "GitHub Token": "CRITICAL",
    "GitHub Classic Token": "CRITICAL", "Stripe Secret Key": "CRITICAL",
    "Stripe Test Key": "HIGH",
    "RSA Private Key": "CRITICAL", "EC Private Key": "CRITICAL",
    "PGP Private Key": "CRITICAL", "SSH Private Key": "CRITICAL",
    "Generic Private Key": "CRITICAL",
    "JWT Token": "HIGH", "MongoDB URI": "CRITICAL",
    "PostgreSQL URI": "CRITICAL", "MySQL URI": "CRITICAL",
    "Redis URI": "HIGH",
    "URL with credentials": "CRITICAL", "Password in Code": "HIGH",
    "Secret in Code": "HIGH", "Bearer Token": "HIGH",
    "OpenAI API Key": "CRITICAL", "OpenAI Project Key": "CRITICAL",
    "Anthropic API Key": "CRITICAL",
    "Supabase Key": "HIGH", "Firebase FCM": "HIGH",
    "Slack Token": "HIGH", "Discord Webhook": "HIGH",
    "Telegram Bot Token": "HIGH",
    "SendGrid API Key": "CRITICAL",
    "Shopify Token": "CRITICAL",
    "GCP Service Account": "CRITICAL",
    "DigitalOcean Token": "CRITICAL",
}

# ── False Positive Filters ─────────────────────────────────────────────────────
# Values matching these patterns are skipped (they're variable refs, not real secrets)
FP_PATTERNS = [
    re.compile(r'^\$\{'),                        # ${variable}
    re.compile(r'^process\.env\.'),              # process.env.SECRET
    re.compile(r'^window\.'),                    # window.config.token
    re.compile(r'config\.[a-z_]+$', re.I),       # beamer_config.user_token
    re.compile(r'\.[a-z_]+_token\)?\)?$', re.I), # .user_token), ...
    re.compile(r'\+encodeURIComponent\(', re.I), # concat with encode
    re.compile(r'^encodeURIComponent\(', re.I),
    re.compile(r'^typeof\s', re.I),              # typeof token
    re.compile(r'undefined', re.I),              # "undefined" !== typeof
    re.compile(r'^\s*$'),                        # empty
    re.compile(r'localhost(?::80|:443)?/?$'),    # localhost URLs
    re.compile(r'^https?://fonts\.', re.I),     # Google Fonts
    re.compile(r'^https?://.*googleapis\.com/css', re.I),  # CSS URLs
    re.compile(r'^[a-z_]+\.[a-z_]+$', re.I),    # simple.variable
    re.compile(r'EXAMPLE', re.I),               # documentation examples
    re.compile(r'YOUR_', re.I),                 # YOUR_API_KEY placeholders
    re.compile(r'<[A-Z_]+>', re.I),             # <REPLACE_ME>
    re.compile(r'xxxxxxxxxx', re.I),            # placeholder
    re.compile(r'\.\.\.'),                      # truncated ...
    re.compile(r'^ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop'), # base64 alphabet
]

# Minimum entropy check for generic secrets (avoid short/simple values)
MIN_LENGTH = {
    "Password in Code": 8,
    "Secret in Code": 10,
    "API Key Generic": 16,
    "Long Base64 String": 60,
    "Hex Secret (32+ chars)": 32,
    "Token in Code": 20,
}

# Deduplicate: same (type + value) won't be reported twice per file
def _dedup_key(finding):
    return (finding["type"], finding["value"][:40])


def get_severity(name):
    return SEVERITY.get(name, "MEDIUM")


def _is_false_positive(value: str) -> bool:
    """Return True if the value looks like a variable reference, not a real secret."""
    v = value.strip()
    for pat in FP_PATTERNS:
        if pat.search(v):
            return True
    # Skip if it contains JS operators/syntax (it's code, not a value)
    if any(x in v for x in ['()', '=>', '&&', '||', '!=', '==', '+=', '?', '{', '}']):
        return True
    return False


class SecretExtractor:
    def __init__(self, logger):
        self.log = logger
        self._compiled = {
            name: re.compile(pattern)
            for name, pattern in SECRET_PATTERNS.items()
        }

    def scan(self, url: str, content: str) -> list[dict]:
        findings = []
        seen = set()
        lines = content.splitlines()

        for name, regex in self._compiled.items():
            min_len = MIN_LENGTH.get(name, 0)

            for match in regex.finditer(content):
                value = match.group(1) if match.lastindex else match.group(0)
                value = value.strip()

                # Skip false positives
                if _is_false_positive(value):
                    continue

                # Skip too-short values
                if min_len and len(value) < min_len:
                    continue

                # Deduplicate per (type, value prefix) within same file
                dk = _dedup_key({"type": name, "value": value})
                if dk in seen:
                    continue
                seen.add(dk)

                # Find line number
                pos = match.start()
                line_num = content[:pos].count('\n') + 1
                line_snippet = lines[line_num - 1].strip()[:120] if line_num <= len(lines) else ""

                finding = {
                    "type":     name,
                    "severity": get_severity(name),
                    "value":    value[:200],
                    "url":      url,
                    "line":     line_num,
                    "snippet":  line_snippet,
                    "decoded":  None,
                }
                findings.append(finding)
                self.log.found(name, get_severity(name), url, line_num)

        return findings
