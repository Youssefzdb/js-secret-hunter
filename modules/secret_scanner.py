#!/usr/bin/env python3
"""
Secret Scanner v4 - 60+ patterns, entropy validation, context-aware FP filtering
"""
import re
import math

# ============================================================
# 60+ SECRET PATTERNS
# ============================================================
PATTERNS = {
    # ── AWS ──────────────────────────────────────────────────
    "AWS Access Key ID":        (r'(?<![A-Z0-9])(AKIA[A-Z0-9]{16})(?![A-Z0-9])', "CRITICAL"),
    "AWS Secret Access Key":    (r'(?i)aws.{0,30}secret.{0,30}["\'\s=:]+([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])', "CRITICAL"),
    "AWS Session Token":        (r'(?i)aws.{0,20}session.{0,20}token.{0,10}["\'\s=:]+([A-Za-z0-9/+=]{100,})', "CRITICAL"),
    "AWS MFA Serial":           (r'arn:aws:iam::[0-9]{12}:mfa/', "MEDIUM"),
    "AWS ARN":                  (r'arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s"\']{5,}', "MEDIUM"),

    # ── GCP ──────────────────────────────────────────────────
    "GCP API Key":              (r'\bAIza[0-9A-Za-z\-_]{35}\b', "CRITICAL"),
    "GCP Service Account":      (r'"type"\s*:\s*"service_account"', "CRITICAL"),
    "GCP OAuth2 Client ID":     (r'[0-9]{12}-[0-9a-zA-Z]{32}\.apps\.googleusercontent\.com', "HIGH"),

    # ── Azure ─────────────────────────────────────────────────
    "Azure Client Secret":      (r'(?i)azure.{0,20}(?:client.{0,10})?secret.{0,10}["\'\s=:]+([A-Za-z0-9\-~_.]{30,})', "CRITICAL"),
    "Azure Storage Key":        (r'AccountKey=[A-Za-z0-9+/=]{80,}', "CRITICAL"),
    "Azure SAS Token":          (r'sig=[A-Za-z0-9%+/=]{40,}', "HIGH"),
    "Azure Connection String":  (r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+', "CRITICAL"),

    # ── Firebase ──────────────────────────────────────────────
    "Firebase API Key":         (r'(?i)firebase.{0,20}(?:api.{0,5})?key.{0,10}["\'\s=:]+([A-Za-z0-9\-_]{35,50})', "CRITICAL"),
    "Firebase DB URL":          (r'https://[a-z0-9\-]+\.firebaseio\.com', "HIGH"),
    "Firebase Storage":         (r'gs://[a-z0-9\-]+\.appspot\.com', "HIGH"),

    # ── Stripe ────────────────────────────────────────────────
    "Stripe Secret Key":        (r'\bsk_live_[0-9a-zA-Z]{24,99}\b', "CRITICAL"),
    "Stripe Restricted Key":    (r'\brk_live_[0-9a-zA-Z]{24,99}\b', "CRITICAL"),
    "Stripe Webhook Secret":    (r'\bwhsec_[0-9a-zA-Z]{32,}\b', "CRITICAL"),
    "Stripe Publishable Key":   (r'\bpk_live_[0-9a-zA-Z]{24,99}\b', "MEDIUM"),

    # ── Payment ───────────────────────────────────────────────
    "Braintree Token":          (r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}', "CRITICAL"),
    "Square Access Token":      (r'\bsq0atp-[A-Za-z0-9\-_]{22,}\b', "CRITICAL"),
    "PayPal Client ID":         (r'(?i)paypal.{0,20}client.{0,10}id.{0,10}["\'\s=:]+([A-Za-z0-9\-]{20,})', "HIGH"),
    "Shopify Token":            (r'\bshpat_[a-fA-F0-9]{32}\b', "CRITICAL"),
    "Shopify Secret":           (r'\bshpss_[a-fA-F0-9]{32}\b', "CRITICAL"),

    # ── Communication ─────────────────────────────────────────
    "Twilio Account SID":       (r'(?<![A-Za-z0-9])(AC[a-f0-9]{32})(?![A-Za-z0-9])', "CRITICAL"),
    "Twilio Auth Token":        (r'(?i)twilio.{0,20}(?:auth.{0,5})?token.{0,10}["\'\s=:]+([a-f0-9]{32})', "CRITICAL"),
    "SendGrid API Key":         (r'\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b', "CRITICAL"),
    "Mailgun API Key":          (r'\bkey-[0-9a-zA-Z]{32}\b', "HIGH"),
    "Mailchimp API Key":        (r'\b[a-f0-9]{32}-us[0-9]{1,2}\b', "HIGH"),

    # ── Messaging ─────────────────────────────────────────────
    "Slack Bot Token":          (r'\bxoxb-[0-9]{11,}-[0-9]{11,}-[a-zA-Z0-9]{24}\b', "CRITICAL"),
    "Slack User Token":         (r'\bxoxp-[0-9]{11,}-[0-9]{11,}-[a-zA-Z0-9]{24}\b', "CRITICAL"),
    "Slack App Token":          (r'\bxapp-[0-9]-[A-Z0-9]{11}-[0-9]{13}-[a-z0-9]{64}\b', "CRITICAL"),
    "Slack Webhook URL":        (r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+', "HIGH"),
    "Discord Bot Token":        (r'\b[MN][A-Za-z0-9]{23}\.[\w\-]{6}\.[\w\-]{27}\b', "CRITICAL"),
    "Discord Webhook":          (r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+', "HIGH"),
    "Telegram Bot Token":       (r'\b[0-9]{8,10}:[A-Za-z0-9\-_]{35}\b', "CRITICAL"),
    "PagerDuty Key":            (r'(?i)pagerduty.{0,20}(?:api.{0,5})?key.{0,10}["\'\s=:]+([A-Za-z0-9+]{20,})', "HIGH"),

    # ── Version Control ───────────────────────────────────────
    "GitHub PAT Classic":       (r'\bghp_[A-Za-z0-9]{36}\b', "CRITICAL"),
    "GitHub PAT Fine-Grained":  (r'\bgithub_pat_[A-Za-z0-9_]{82}\b', "CRITICAL"),
    "GitHub OAuth Token":       (r'\bgho_[A-Za-z0-9]{36}\b', "CRITICAL"),
    "GitHub Actions Token":     (r'\bghs_[A-Za-z0-9]{36}\b', "CRITICAL"),
    "GitLab Token":             (r'\bglpat-[A-Za-z0-9\-_]{20}\b', "CRITICAL"),
    "NPM Token":                (r'\bnpm_[A-Za-z0-9]{36}\b', "CRITICAL"),

    # ── Auth ──────────────────────────────────────────────────
    "JWT Token":                (r'\beyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b', "HIGH"),
    "Bearer Token":             (r'(?i)["\']?Authorization["\']?\s*:\s*["\']Bearer\s+([A-Za-z0-9\-_\.]{20,})["\']', "HIGH"),
    "Basic Auth Header":        (r'(?i)["\']?Authorization["\']?\s*:\s*["\']Basic\s+([A-Za-z0-9+/=]{20,})["\']', "HIGH"),
    "OAuth2 Access Token":      (r'(?i)access_token["\'\s=:]+([A-Za-z0-9\-_.~+/]{30,})', "HIGH"),
    "Refresh Token":            (r'(?i)refresh_token["\'\s=:]+([A-Za-z0-9\-_.~+/]{30,})', "HIGH"),
    "Session Secret":           (r'(?i)session.{0,10}secret["\'\s=:]+["\']([^"\']{16,})["\']', "HIGH"),

    # ── Database ──────────────────────────────────────────────
    "MongoDB URI":              (r'mongodb(?:\+srv)?://[A-Za-z0-9_%\-]+:[^@\s"\']{4,}@[^\s"\']{5,}', "CRITICAL"),
    "PostgreSQL URI":           (r'postgres(?:ql)?://[A-Za-z0-9_%\-]+:[^@\s"\']{4,}@[^\s"\']{5,}', "CRITICAL"),
    "MySQL URI":                (r'mysql://[A-Za-z0-9_%\-]+:[^@\s"\']{4,}@[^\s"\']{5,}', "CRITICAL"),
    "Redis URI":                (r'redis://:?[^@\s"\']{4,}@[^\s"\']{5,}', "HIGH"),
    "Elasticsearch URL":        (r'https?://[A-Za-z0-9_%\-]+:[^@\s"\']{4,}@[^\s"\']+:9200', "CRITICAL"),

    # ── Crypto ────────────────────────────────────────────────
    "Private Key PEM":          (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "CRITICAL"),
    "SSH Private Key":          (r'-----BEGIN OPENSSH PRIVATE KEY-----', "CRITICAL"),
    "Ethereum Private Key":     (r'(?i)(?:private.{0,10}key|eth.{0,10}key)["\'\s=:]+["\']?(0x[a-fA-F0-9]{64})', "CRITICAL"),
    "Bitcoin WIF":              (r'\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b', "CRITICAL"),

    # ── Infrastructure ────────────────────────────────────────
    "Hardcoded Password":       (r'(?i)["\']?(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\'\\]{8,50})["\']', "HIGH"),
    "Hardcoded Secret":         (r'(?i)["\']?(?:secret|api_secret|client_secret|app_secret)["\']?\s*[:=]\s*["\']([^"\'\\]{8,80})["\']', "HIGH"),
    "Generic API Key":          (r'(?i)["\']?(?:api_key|apikey|api[_\-]?token)["\']?\s*[:=]\s*["\']([^"\'\\]{16,80})["\']', "HIGH"),
    "S3 Bucket URL":            (r'https?://[a-z0-9\-\.]+\.s3(?:[\.\-][a-z0-9\-]+)?\.amazonaws\.com/[^\s"\']{3,}', "MEDIUM"),
    "Internal IP Exposed":      (r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b', "MEDIUM"),
    "Admin Path Disclosure":    (r'["\'](?:/admin|/dashboard|/internal|/debug|/console|/manage|/backdoor|/shell|/phpmyadmin)["\']', "MEDIUM"),
    "Email Address":            (r'\b[a-zA-Z0-9._%+\-]{3,}@(?!example|test|domain)[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b', "LOW"),
    "Sentry DSN":               (r'https://[a-f0-9]{32}@(?:o\d+\.)?ingest\.sentry\.io/\d+', "HIGH"),
}

# ============================================================
# ENTROPY
# ============================================================
def _entropy(s):
    if not s or len(s) < 4:
        return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((v/len(s)) * math.log2(v/len(s)) for v in freq.values())

# ============================================================
# FALSE POSITIVE FILTERS
# ============================================================
FP_SOURCES_REGEX = [
    r'google\.com/recaptcha', r'gstatic\.com', r'googleapis\.com',
    r'cdn\.cloudflare', r'cloudflareinsights', r'recaptcha',
    r'jquery\.(min|slim)\.js', r'bootstrap\.min\.js',
    r'fontawesome', r'analytics\.js', r'gtag/js', r'fbevents\.js',
]

FP_CONTEXT_SNIPPETS = [
    "_0x", "window._hvc", "__grecaptcha", "grecaptcha", "PLEASE DO NOT COPY",
    "base64Chars", "base64Table", "base64alphabet", "charset=",
    "var _0x", "function _0x", "0x1",
]

FP_PLACEHOLDER_RE = re.compile(
    r'^(?:password|passwd|test|example|sample|dummy|changeme|'
    r'enter.{0,10}password|your.{0,10}(?:key|secret|token|password)|'
    r'replace.{0,5}me|xxx+|\.{3,}|\*+|<[^>]+>|'
    r'\$\{[^}]+\}|%[a-zA-Z_]+%|\{\{[^}]+\}\}|insert.{0,10}here)$',
    re.IGNORECASE
)

# Minimum entropy per pattern type
MIN_ENTROPY = {
    "AWS Access Key ID":     3.5,
    "AWS Secret Access Key": 4.0,
    "Hardcoded Password":    2.5,
    "Hardcoded Secret":      2.5,
    "Generic API Key":       3.0,
    "JWT Token":             3.5,
    "Twilio Account SID":    3.0,
}

import urllib.parse

class SecretScanner:
    def __init__(self, js_files):
        self.js_files = js_files
        self._fp_src_re = [re.compile(p) for p in FP_SOURCES_REGEX]

    def _is_fp_source(self, url):
        return any(r.search(url) for r in self._fp_src_re)

    def _is_fp_context(self, line):
        return any(kw in line for kw in FP_CONTEXT_SNIPPETS)

    def _is_fp_value(self, value, secret_type):
        # Placeholder check
        if FP_PLACEHOLDER_RE.match(value.strip()):
            return True
        # Cloudflare PoW
        if '"algorithm":"SHA-256"' in value or ('"challenge"' in value and '"salt"' in value):
            return True
        # Entropy check
        min_ent = MIN_ENTROPY.get(secret_type, 0)
        if min_ent and _entropy(value) < min_ent:
            return True
        # Twilio SID must be exactly AC + 32 lowercase hex
        if secret_type == "Twilio Account SID":
            if not re.match(r'^AC[a-f0-9]{32}$', value):
                return True
        # JWT: skip Cloudflare PoW JWTs
        if secret_type == "JWT Token":
            try:
                import base64, json
                payload_b64 = value.split(".")[1]
                payload_b64 += "=" * (4 - len(payload_b64) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                if "challenge" in payload and "salt" in payload:
                    return True  # Cloudflare PoW
            except:
                pass
        return False

    def scan(self):
        findings = []
        fp_count = 0
        total_lines = 0
        print(f"[*] Scanning {len(self.js_files)} files with 60+ patterns...")

        for js_url, content in self.js_files.items():
            is_fp_source = self._is_fp_source(js_url)
            lines = content.splitlines()
            total_lines += len(lines)

            for line_no, line in enumerate(lines, 1):
                is_fp_ctx = self._is_fp_context(line)

                for secret_type, (pattern, severity) in PATTERNS.items():
                    try:
                        matches = re.findall(pattern, line)
                    except re.error:
                        continue

                    for match in matches:
                        value = match if isinstance(match, str) else (match[0] if match else "")
                        if not value or len(value) < 6:
                            continue

                        # FP source — only allow CRITICAL patterns
                        if is_fp_source and severity != "CRITICAL":
                            fp_count += 1
                            continue

                        # FP context
                        if is_fp_ctx and severity in ["LOW", "MEDIUM"]:
                            fp_count += 1
                            continue

                        # FP value
                        if self._is_fp_value(value, secret_type):
                            fp_count += 1
                            continue

                        ent = round(_entropy(value), 2)
                        findings.append({
                            "type": secret_type,
                            "value": value[:150],
                            "source": js_url.split("/")[-1][:60],
                            "source_url": js_url,
                            "line": line_no,
                            "severity": severity,
                            "entropy": ent,
                            "decoded": None,
                            "snippet": line.strip()[:120]
                        })
                        sev_icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"⚪"}.get(severity,"")
                        print(f"  {sev_icon} {severity} | {secret_type} (entropy={ent}) | {value[:50]}")

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = f"{f['type']}:{f['value'][:40]}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        SEV_ORDER = ["CRITICAL","HIGH","MEDIUM","LOW"]
        unique.sort(key=lambda x: SEV_ORDER.index(x["severity"]) if x["severity"] in SEV_ORDER else 99)

        print(f"\n[+] Scanned {total_lines:,} lines | {len(unique)} real secrets | {fp_count} FPs filtered")
        return unique
