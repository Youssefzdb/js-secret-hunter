#!/usr/bin/env python3
"""Secret Scanner v2 - With false positive filtering"""
import re

PATTERNS = {
    "AWS Access Key":        (r'AKIA[0-9A-Z]{16}', "CRITICAL"),
    "AWS Secret Key":        (r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']', "CRITICAL"),
    "Google API Key":        (r'AIza[0-9A-Za-z\-_]{35}', "CRITICAL"),
    "Google OAuth":          (r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', "HIGH"),
    "Firebase URL":          (r'https://[a-z0-9\-]+\.firebaseio\.com', "HIGH"),
    "Firebase Key":          (r'(?i)firebase[_\-]?api[_\-]?key["\s:=]+["\']([A-Za-z0-9\-_]{30,50})["\']', "HIGH"),
    "Stripe Secret":         (r'sk_live_[0-9a-zA-Z]{24,}', "CRITICAL"),
    "Stripe Public":         (r'pk_live_[0-9a-zA-Z]{24,}', "MEDIUM"),
    "GitHub Token":          (r'gh[pousr]_[A-Za-z0-9]{36,}', "CRITICAL"),
    "Slack Token":           (r'xox[baprs]-[0-9A-Za-z\-]{10,}', "CRITICAL"),
    "Slack Webhook":         (r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+', "HIGH"),
    "SendGrid":              (r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}', "CRITICAL"),
    "JWT Token":             (r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', "HIGH"),
    "Bearer Token":          (r'(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}', "HIGH"),
    "Hardcoded Password":    (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']', "HIGH"),
    "Hardcoded Secret":      (r'(?i)(?:secret|api_secret|client_secret)\s*[:=]\s*["\']([^"\']{8,})["\']', "HIGH"),
    "Private Key":           (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "CRITICAL"),
    "DB Connection String":  (r'(?i)(?:mongodb|mysql|postgres|redis)://[^\s"\'<>]{10,}', "CRITICAL"),
    "URL with Credentials":  (r'https?://[a-zA-Z0-9_]+:[a-zA-Z0-9_]{4,}@[^\s"\']+', "CRITICAL"),
}

# ===== FALSE POSITIVE FILTERS =====
FALSE_POSITIVE_SOURCES = [
    "recaptcha", "google.com/recaptcha",
    "googleapis.com", "gstatic.com",
    "cloudflare", "cdn.cloudflare",
]

FALSE_POSITIVE_VALUES = [
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
    "0123456789abcdefghijklmnopqrstuvwxyz",
]

FALSE_POSITIVE_CONTEXTS = [
    "window._hvc",     # Cloudflare PoW challenge
    "_0x2dd3",         # JS obfuscation array
    "__grecaptcha",    # reCAPTCHA
    "grecaptcha",
]

# Twilio SID must be exactly 34 chars starting with AC
TWILIO_REAL = re.compile(r'^AC[a-f0-9]{32}$')

class SecretScanner:
    def __init__(self, js_files):
        self.js_files = js_files

    def _is_false_positive(self, finding, source_url, snippet=""):
        value = finding.get("value", "")
        secret_type = finding.get("type", "")

        # Filter known FP sources
        for fp_src in FALSE_POSITIVE_SOURCES:
            if fp_src in source_url.lower():
                # Only allow real high-confidence patterns from these sources
                if secret_type not in ["AWS Access Key", "GitHub Token", "Stripe Secret"]:
                    return True

        # Filter known FP values
        for fp_val in FALSE_POSITIVE_VALUES:
            if value.startswith(fp_val[:20]) or fp_val[:20] in value:
                return True

        # Filter obfuscation context
        for fp_ctx in FALSE_POSITIVE_CONTEXTS:
            if fp_ctx in snippet:
                if secret_type in ["Long Base64 String", "Twilio Account SID"]:
                    return True

        # Twilio SID strict check
        if secret_type == "Twilio Account SID":
            if not TWILIO_REAL.match(value):
                return True

        # Filter Cloudflare SHA-256 challenge (decoded JSON with "algorithm":"SHA-256")
        if secret_type == "Long Base64 String" and "SHA-256" in value:
            return True

        # Filter pure JS charset strings
        if value == "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=":
            return True

        return False

    def scan(self):
        findings = []
        fp_count = 0
        print("[*] Scanning for secrets (v2 — with FP filtering)...")

        for js_url, content in self.js_files.items():
            lines = content.splitlines()
            for line_no, line in enumerate(lines, 1):
                for secret_type, (pattern, severity) in PATTERNS.items():
                    matches = re.findall(pattern, line)
                    for match in matches:
                        value = match if isinstance(match, str) else (match[0] if match else "")
                        if len(value) < 8:
                            continue

                        finding = {
                            "type": secret_type,
                            "value": value[:120],
                            "source": js_url.split("/")[-1][:60],
                            "source_url": js_url,
                            "line": line_no,
                            "severity": severity,
                            "decoded": None,
                            "snippet": line[:80]
                        }

                        if self._is_false_positive(finding, js_url, line):
                            fp_count += 1
                            continue

                        findings.append(finding)
                        print(f"  [!] {severity} | {secret_type}: {value[:50]}")

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = f"{f['type']}:{f['value'][:30]}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        print(f"[+] {len(unique)} real secrets | {fp_count} false positives filtered")
        return unique
