#!/usr/bin/env python3
"""Secret Scanner - Detect credentials and secrets in JS files"""
import re

PATTERNS = {
    # API Keys
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
    "Twilio":                (r'SK[0-9a-fA-F]{32}', "HIGH"),
    "SendGrid":              (r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}', "CRITICAL"),
    "Mailgun":               (r'key-[0-9a-zA-Z]{32}', "HIGH"),
    "JWT Token":             (r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', "HIGH"),
    "Bearer Token":          (r'(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}', "HIGH"),
    "Basic Auth":            (r'(?i)basic\s+[A-Za-z0-9+/=]{20,}', "HIGH"),
    # Passwords/Secrets in code
    "Hardcoded Password":    (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']', "HIGH"),
    "Hardcoded Secret":      (r'(?i)(?:secret|api_secret|client_secret)\s*[:=]\s*["\']([^"\']{8,})["\']', "HIGH"),
    "Private Key":           (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "CRITICAL"),
    # URLs with credentials
    "DB Connection String":  (r'(?i)(?:mongodb|mysql|postgres|redis)://[^\s"\'<>]{10,}', "CRITICAL"),
    "URL with Credentials":  (r'https?://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[^\s"\']+', "CRITICAL"),
    # Base64 suspicious
    "Suspicious Base64":     (r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])', "LOW"),
}

class SecretScanner:
    def __init__(self, js_files):
        self.js_files = js_files  # {url: content}

    def scan(self):
        findings = []
        print("[*] Scanning for secrets...")

        for js_url, content in self.js_files.items():
            for secret_type, (pattern, severity) in PATTERNS.items():
                matches = re.findall(pattern, content)
                for match in matches:
                    value = match if isinstance(match, str) else match[0] if match else ""
                    if len(value) < 4:
                        continue
                    finding = {
                        "type": secret_type,
                        "value": value[:120],
                        "source": js_url.split("/")[-1][:60],
                        "source_url": js_url,
                        "severity": severity,
                        "decoded": None
                    }
                    findings.append(finding)
                    print(f"  [!] {severity} | {secret_type}: {value[:40]}...")

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = f"{f['type']}:{f['value'][:30]}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        print(f"[+] {len(unique)} unique secrets found")
        return unique
