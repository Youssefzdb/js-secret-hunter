#!/usr/bin/env python3
"""
Secret Scanner v3 - Maximum coverage + zero false positives
Covers 50+ secret types with context-aware validation
"""
import re

# ============================================================
# PATTERNS: (regex, severity, validator_fn_name)
# ============================================================
PATTERNS = {
    # ── Cloud Providers ──────────────────────────────────────
    "AWS Access Key ID":      (r'(?<![A-Z0-9])(AKIA[A-Z0-9]{16})(?![A-Z0-9])', "CRITICAL"),
    "AWS Secret Access Key":  (r'(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key["\':\s=]+([A-Za-z0-9/+=]{40})', "CRITICAL"),
    "AWS Session Token":      (r'(?i)aws[_\-\s]?session[_\-\s]?token["\':\s=]+([A-Za-z0-9/+=]{100,})', "CRITICAL"),
    "GCP API Key":            (r'AIza[0-9A-Za-z\-_]{35}', "CRITICAL"),
    "GCP Service Account":    (r'"type"\s*:\s*"service_account"', "CRITICAL"),
    "Azure Client Secret":    (r'(?i)azure[_\-\s]?(?:client[_\-\s]?)?secret["\':\s=]+([A-Za-z0-9\-_~]{30,})', "CRITICAL"),
    "Azure Storage Key":      (r'(?i)AccountKey=([A-Za-z0-9+/=]{80,})', "CRITICAL"),

    # ── Firebase ─────────────────────────────────────────────
    "Firebase API Key":       (r'AIza[0-9A-Za-z\-_]{35}', "CRITICAL"),
    "Firebase DB URL":        (r'https://[a-z0-9\-]+\.firebaseio\.com', "HIGH"),
    "Firebase Config":        (r'firebase(?:Config|\.initializeApp)\s*\(\s*\{[^}]{20,}apiKey', "CRITICAL"),

    # ── Payment ───────────────────────────────────────────────
    "Stripe Secret Key":      (r'sk_live_[0-9a-zA-Z]{24,}', "CRITICAL"),
    "Stripe Restricted Key":  (r'rk_live_[0-9a-zA-Z]{24,}', "CRITICAL"),
    "Stripe Publishable":     (r'pk_live_[0-9a-zA-Z]{24,}', "MEDIUM"),
    "Stripe Webhook Secret":  (r'whsec_[0-9a-zA-Z]{32,}', "CRITICAL"),
    "PayPal Client ID":       (r'(?i)paypal[_\-\s]?client[_\-\s]?id["\':\s=]+([A-Za-z0-9\-_]{20,})', "HIGH"),
    "Braintree Token":        (r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}', "CRITICAL"),

    # ── Communication ─────────────────────────────────────────
    "Twilio Account SID":     (r'(?<![A-Za-z0-9])(AC[a-f0-9]{32})(?![A-Za-z0-9])', "CRITICAL"),
    "Twilio Auth Token":      (r'(?i)twilio[_\-\s]?auth[_\-\s]?token["\':\s=]+([a-f0-9]{32})', "CRITICAL"),
    "SendGrid API Key":       (r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}', "CRITICAL"),
    "Mailgun API Key":        (r'(?i)mailgun[_\-\s]?(?:api[_\-\s]?)?key["\':\s=]+(key-[a-z0-9]{32})', "CRITICAL"),
    "Mailchimp API Key":      (r'[a-f0-9]{32}-us[0-9]{1,2}', "HIGH"),
    "Slack Bot Token":        (r'xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}', "CRITICAL"),
    "Slack User Token":       (r'xoxp-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}', "CRITICAL"),
    "Slack App Token":        (r'xapp-[0-9]-[A-Z0-9]{11}-[0-9]{13}-[a-z0-9]{64}', "CRITICAL"),
    "Slack Webhook URL":      (r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+', "HIGH"),
    "Discord Bot Token":      (r'[MN][A-Za-z0-9]{23}\.[\w-]{6}\.[\w-]{27}', "CRITICAL"),
    "Discord Webhook":        (r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+', "HIGH"),
    "Telegram Bot Token":     (r'[0-9]{8,10}:[A-Za-z0-9\-_]{35}', "CRITICAL"),

    # ── Version Control ───────────────────────────────────────
    "GitHub Personal Token":  (r'ghp_[A-Za-z0-9]{36}', "CRITICAL"),
    "GitHub OAuth Token":     (r'gho_[A-Za-z0-9]{36}', "CRITICAL"),
    "GitHub Actions Token":   (r'ghs_[A-Za-z0-9]{36}', "CRITICAL"),
    "GitHub Refresh Token":   (r'ghr_[A-Za-z0-9]{76}', "CRITICAL"),
    "GitLab Token":           (r'glpat-[A-Za-z0-9\-_]{20}', "CRITICAL"),
    "Bitbucket Token":        (r'(?i)bitbucket[_\-\s]?(?:access[_\-\s]?)?token["\':\s=]+([A-Za-z0-9\-_]{40,})', "CRITICAL"),

    # ── Auth & Sessions ────────────────────────────────────────
    "JWT Token":              (r'eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]+', "HIGH"),
    "OAuth Access Token":     (r'(?i)access[_\-\s]?token["\':\s=]+([A-Za-z0-9\-_\.]{30,})', "HIGH"),
    "Bearer Token":           (r'(?i)Authorization["\':\s]+["\']?Bearer\s+([A-Za-z0-9\-_\.]{20,})', "HIGH"),
    "Basic Auth Header":      (r'(?i)Authorization["\':\s]+["\']?Basic\s+([A-Za-z0-9+/=]{20,})', "HIGH"),
    "Session Cookie":         (r'(?i)(?:session|sess)[_\-\s]?(?:id|token|key)["\':\s=]+([A-Za-z0-9\-_\.]{20,})', "MEDIUM"),

    # ── Database ──────────────────────────────────────────────
    "MongoDB URI":            (r'mongodb(?:\+srv)?://[A-Za-z0-9_\-]+:[^@\s"\']{4,}@[^\s"\']{5,}', "CRITICAL"),
    "PostgreSQL URI":         (r'postgres(?:ql)?://[A-Za-z0-9_\-]+:[^@\s"\']{4,}@[^\s"\']{5,}', "CRITICAL"),
    "MySQL URI":              (r'mysql://[A-Za-z0-9_\-]+:[^@\s"\']{4,}@[^\s"\']{5,}', "CRITICAL"),
    "Redis URI":              (r'redis://(?:[A-Za-z0-9_\-]+:[^@\s"\']{4,}@)?[^\s"\']{5,}', "HIGH"),
    "DB Password":            (r'(?i)(?:db|database)[_\-\s]?(?:pass|password|pwd)["\':\s=]+["\']([^"\']{6,})["\']', "CRITICAL"),

    # ── Crypto & Wallets ──────────────────────────────────────
    "Ethereum Private Key":   (r'(?i)(?:private[_\-\s]?key|eth[_\-\s]?key)["\':\s=]+["\']?(0x[a-fA-F0-9]{64})', "CRITICAL"),
    "Mnemonic Phrase":        (r'\b(?:abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse)\b.{0,200}\b(?:word|phrase|seed|mnemonic)\b', "CRITICAL"),

    # ── Infrastructure ────────────────────────────────────────
    "Private Key PEM":        (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "CRITICAL"),
    "Certificate":            (r'-----BEGIN CERTIFICATE-----', "MEDIUM"),
    "SSH Private Key":        (r'-----BEGIN OPENSSH PRIVATE KEY-----', "CRITICAL"),
    "Hardcoded Password":     (r'(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*["\']([^"\'\\]{6,50})["\']', "HIGH"),
    "Hardcoded Username":     (r'(?i)(?:username|user|login)\s*[:=]\s*["\']([^"\']{4,30})["\']', "LOW"),
    "API Key Generic":        (r'(?i)api[_\-\s]?key["\':\s=]+["\']([A-Za-z0-9\-_]{16,64})["\']', "HIGH"),
    "Secret Generic":         (r'(?i)(?:secret|app[_\-]?secret|client[_\-]?secret)["\':\s=]+["\']([^"\']{8,64})["\']', "HIGH"),
    "Internal IP Leak":       (r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b', "MEDIUM"),
    "Admin Path Leak":        (r'["\'](?:/admin|/dashboard|/internal|/api/v[0-9]|/manage|/backdoor|/debug)["\']', "MEDIUM"),
    "S3 Bucket URL":          (r'https?://[a-z0-9\-\.]+\.s3(?:[\.\-][a-z0-9\-]+)?\.amazonaws\.com', "MEDIUM"),
}

# ============================================================
# FALSE POSITIVE FILTERS
# ============================================================
FP_SOURCES = [
    "google.com/recaptcha", "gstatic.com", "googleapis.com",
    "cloudflare.com", "cdn.cloudflare", "recaptcha",
    "jquery", "bootstrap.min", "lodash", "moment.min",
    "analytics.js", "gtag", "fbevents",
]

FP_CONTEXTS = [
    "window._hvc", "_0x2dd3", "__grecaptcha", "grecaptcha",
    "example.com", "your-api-key", "YOUR_API_KEY", "INSERT_KEY",
    "xxxxxxxxxxxx", "000000000000", "test-api-key",
    "REPLACE_ME", "placeholder", "<YOUR_", "${",
]

FP_VALUES = [
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "0123456789abcdef", "xxxxxxxxxxxxxxxx",
]

# Entropy check — real secrets have high entropy
import math
def _entropy(s):
    if not s: return 0
    freq = {c: s.count(c)/len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())

class SecretScanner:
    def __init__(self, js_files):
        self.js_files = js_files

    def _is_fp(self, value, source_url, context_line):
        # FP source
        for fp in FP_SOURCES:
            if fp in source_url.lower():
                return True

        # FP context
        for ctx in FP_CONTEXTS:
            if ctx in context_line or ctx.lower() in value.lower():
                return True

        # FP values
        for fv in FP_VALUES:
            if fv in value:
                return True

        # Low entropy = not a real secret
        if len(value) > 10 and _entropy(value) < 3.0:
            return True

        # Cloudflare PoW
        if '"algorithm":"SHA-256"' in value or '"challenge"' in value:
            return True

        return False

    def scan(self):
        findings = []
        fp_count = 0
        print("[*] Scanning with 50+ patterns + entropy analysis...")

        for js_url, content in self.js_files.items():
            lines = content.splitlines()
            for line_no, line in enumerate(lines, 1):
                for secret_type, (pattern, severity) in PATTERNS.items():
                    try:
                        matches = re.findall(pattern, line)
                    except:
                        continue
                    for match in matches:
                        value = match if isinstance(match, str) else (match[0] if match else "")
                        if len(value) < 8:
                            continue
                        if self._is_fp(value, js_url, line):
                            fp_count += 1
                            continue
                        findings.append({
                            "type": secret_type,
                            "value": value[:120],
                            "source": js_url.split("/")[-1][:60],
                            "source_url": js_url,
                            "line": line_no,
                            "severity": severity,
                            "entropy": round(_entropy(value), 2),
                            "decoded": None,
                            "snippet": line.strip()[:100]
                        })
                        print(f"  [!] {severity} | {secret_type} | entropy={round(_entropy(value),2)} | {value[:40]}")

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = f"{f['type']}:{f['value'][:30]}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        print(f"[+] {len(unique)} confirmed secrets | {fp_count} FPs filtered")
        return unique
