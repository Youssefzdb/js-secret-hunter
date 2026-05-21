#!/usr/bin/env python3
"""
Secret Extractor — 50+ regex patterns to find secrets in JS files.
Covers: API keys, tokens, passwords, JWTs, private keys, cloud credentials, etc.
"""
import re

SECRET_PATTERNS = {
    # === Cloud / Platform API Keys (high confidence — fixed format) ===
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
    "Twilio Account SID":    r'AC[a-zA-Z0-9]{32}',
    "Twilio Auth Token":     r'(?i)twilio.{0,20}["\']([a-f0-9]{32})["\']',
    "SendGrid API Key":      r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
    "Mailgun API Key":       r'key-[0-9a-zA-Z]{32}',
    "Mailchimp API Key":     r'[0-9a-f]{32}-us[0-9]{1,2}',
    "Slack Token":           r'xox[baprs]-[0-9A-Za-z\-]{10,250}',
    "Slack Webhook":         r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
    "Discord Token":         r'(?i)discord.{0,20}["\']([A-Za-z0-9\.\-_]{59,})["\']',
    "Discord Webhook":       r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+',
    "Telegram Bot Token":    r'[0-9]{8,10}:[A-Za-z0-9_-]{35,}',
    "Shopify Token":         r'shpat_[a-fA-F0-9]{32}',
    "Square OAuth Token":    r'sq0atp-[0-9A-Za-z\-_]{22}',
    "PayPal/Braintree":      r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    "Notion Token":          r'secret_[A-Za-z0-9]{43}',
    "NPM Token":             r'npm_[A-Za-z0-9]{36}',
    "Mapbox Token":          r'pk\.eyJ[A-Za-z0-9\.\-_]+',
    "Cloudinary URL":        r'cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[A-Za-z0-9_\-]+',
    "Supabase Key":          r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
    "OpenAI API Key":        r'sk-[A-Za-z0-9]{48}',
    "Anthropic API Key":     r'sk-ant-[A-Za-z0-9\-_]{90,}',
    "DigitalOcean Token":    r'dop_v1_[a-f0-9]{64}',
    "GCP Service Account":   r'"private_key_id":\s*"[a-f0-9]{40}"',

    # === Passwords & Secrets — must be assigned a LITERAL string value ===
    # ✅ matches: password = "abc123!"
    # ❌ skips:   password = someVariable  or  encodeURIComponent(config.password)
    "Password in Code":  r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\'<>${}()\s]{8,})["\']',
    "Secret in Code":    r'(?i)(?:^|[^a-z])(?:secret|secret_key|app_secret)\s*[=:]\s*["\']([^"\'<>${}()\s]{8,})["\']',
    "API Key Generic":   r'(?i)(?:api_key|apikey|api-key)\s*[=:]\s*["\']([^"\'<>${}()\s]{16,})["\']',

    # Token in Code — only match LITERAL string assignments, not variable references
    # ✅ matches: access_token = "eyABC..."  or  token: "abc123xyz"
    # ❌ skips:   encodeURIComponent(config.user_token)  or  += "&token=" + someVar
    "Token in Code":     r'(?i)(?:^|[,;{\s])(?:token|access_token|auth_token|api_token|user_token)\s*[=:]\s*["\']([^"\'<>${}()\s]{20,})["\']',

    "Bearer Token":      r'(?i)Authorization["\s]*:\s*["\']?Bearer\s+([A-Za-z0-9\-._~+/]+=*)',

    # === Private Keys & Certificates ===
    "RSA Private Key":       r'-----BEGIN RSA PRIVATE KEY-----',
    "EC Private Key":        r'-----BEGIN EC PRIVATE KEY-----',
    "PGP Private Key":       r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    "Generic Private Key":   r'-----BEGIN PRIVATE KEY-----',
    "SSH Private Key":       r'-----BEGIN OPENSSH PRIVATE KEY-----',
    "Certificate":           r'-----BEGIN CERTIFICATE-----',

    # === JWT Tokens ===
    "JWT Token":         r'eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}',

    # === Database & Connection Strings ===
    "MongoDB URI":       r'mongodb(?:\+srv)?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+',
    "PostgreSQL URI":    r'postgres(?:ql)?://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+',
    "MySQL URI":         r'mysql://[^\s"\'<>]+:[^\s"\'<>@]+@[^\s"\'<>]+',
    "Redis URI":         r'redis://:?[^\s"\'<>@]+@[^\s"\'<>]+',

    # === URLs with credentials — must have user:pass@host format ===
    # ❌ skip Google Fonts, CDN links, etc.
    "URL with credentials": r'https?://(?!fonts\.googleapis\.com)(?!.*\$\{)[^\s"\'<>@:]+:[^\s"\'<>@/]{4,}@[a-zA-Z0-9\.\-]+',

    # === Encoded Strings (suspicious long blobs only) ===
    # Only flag if it's inside a string literal (surrounded by quotes or assignment)
    "Long Base64 String":     r'(?:["\']|=\s*)["\']?([A-Za-z0-9+/]{80,}={0,2})["\']',
    "Hex Secret (32+ chars)": r'(?i)(?:key|secret|token|hash|salt)\s*[=:]\s*["\']([a-fA-F0-9]{32,64})["\']',
}

# Severity levels
SEVERITY = {
    "AWS Access Key":       "CRITICAL",
    "AWS Secret Key":       "CRITICAL",
    "GitHub Token":         "CRITICAL",
    "GitHub Classic Token": "CRITICAL",
    "Stripe Secret Key":    "CRITICAL",
    "RSA Private Key":      "CRITICAL",
    "EC Private Key":       "CRITICAL",
    "PGP Private Key":      "CRITICAL",
    "SSH Private Key":      "CRITICAL",
    "OpenAI API Key":       "CRITICAL",
    "Anthropic API Key":    "CRITICAL",
    "MongoDB URI":          "CRITICAL",
    "PostgreSQL URI":       "CRITICAL",
    "MySQL URI":            "CRITICAL",
    "URL with credentials": "CRITICAL",
    "Google API Key":       "HIGH",
    "Firebase":             "HIGH",
    "Supabase Key":         "HIGH",
    "JWT Token":            "HIGH",
    "Slack Token":          "HIGH",
    "Discord Token":        "HIGH",
    "Telegram Bot Token":   "HIGH",
    "Password in Code":     "HIGH",
    "Secret in Code":       "HIGH",
    "Bearer Token":         "HIGH",
    "Token in Code":        "MEDIUM",
    "API Key Generic":      "MEDIUM",
    "Long Base64 String":   "LOW",
    "Hex Secret (32+ chars)": "LOW",
}

def get_severity(name):
    return SEVERITY.get(name, "MEDIUM")


# Values to SKIP — variable references, template strings, known false positives
FP_PATTERNS = [
    re.compile(r'encodeURIComponent\('),   # function call wrapping a variable
    re.compile(r'\$\{'),                    # template literal variable
    re.compile(r'config\.[a-zA-Z_]+$'),     # config.someVar reference
    re.compile(r'\+\s*[a-zA-Z_]\w*\s*\)'), # + someVar)
    re.compile(r'^[a-zA-Z_]\w*\.[a-zA-Z_]\w*$'),  # object.property
    re.compile(r'typeof\s+'),               # typeof check
    re.compile(r'^undefined$'),
    re.compile(r'fonts\.googleapis\.com'),
    re.compile(r'^https?://[a-z]+\.[a-z]+\.[a-z]+/css'), # CDN font/CSS URLs
]

def is_false_positive(value: str) -> bool:
    val = value.strip()
    for fp in FP_PATTERNS:
        if fp.search(val):
            return True
    # Skip values that look like code (contain JS operators/keywords)
    if any(kw in val for kw in [
        'encodeURIComponent', 'typeof', 'undefined', 'function(',
        'return ', '.user_token', '.access_token', 'config.',
        '+encodeURI', '));', '&&', '||',
    ]):
        return True
    # Skip very short or clearly non-secret values
    if len(val) < 8:
        return True
    return False


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
                value = match.group(1) if match.lastindex else match.group(0)
                value = value.strip()

                # Skip false positives
                if is_false_positive(value):
                    continue

                # Deduplicate same type+value combo
                key = f"{name}:{value[:60]}"
                if key in seen:
                    continue
                seen.add(key)

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
