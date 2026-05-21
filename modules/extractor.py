#!/usr/bin/env python3
"""
Secret Extractor — 50+ regex patterns to find secrets in JS files.
Covers: API keys, tokens, passwords, JWTs, private keys, cloud credentials, etc.
"""
import re

SECRET_PATTERNS = {
    # === API Keys ===
    "AWS Access Key":        r'(?i)AKIA[0-9A-Z]{16}',
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
    "HubSpot API Key":       r'(?i)hubspot.{0,20}["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']',
    "Notion Token":          r'secret_[A-Za-z0-9]{43}',
    "Airtable API Key":      r'key[A-Za-z0-9]{14}',
    "NPM Token":             r'npm_[A-Za-z0-9]{36}',
    "Heroku API Key":        r'(?i)heroku.{0,20}["\']([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})["\']',
    "Datadog API Key":       r'(?i)datadog.{0,20}["\']([a-z0-9]{32})["\']',
    "Algolia API Key":       r'(?i)algolia.{0,20}["\']([A-Za-z0-9]{32})["\']',
    "Mapbox Token":          r'pk\.eyJ[A-Za-z0-9\.\-_]+',
    "Cloudinary URL":        r'cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[A-Za-z0-9_\-]+',
    "Supabase Key":          r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
    "OpenAI API Key":        r'sk-[A-Za-z0-9]{48}',
    "Anthropic API Key":     r'sk-ant-[A-Za-z0-9\-_]{90,}',

    # === Passwords & Generic Secrets ===
    "Password in Code":      r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']',
    "Secret in Code":        r'(?i)(?:secret|secret_key|app_secret)\s*[=:]\s*["\']([^"\']{8,})["\']',
    "Token in Code":         r'(?i)(?:token|access_token|auth_token|api_token)\s*[=:]\s*["\']([^"\']{20,})["\']',
    "API Key Generic":       r'(?i)(?:api_key|apikey|api-key)\s*[=:]\s*["\']([^"\']{16,})["\']',
    "Bearer Token":          r'(?i)Bearer\s+([A-Za-z0-9\-._~+/]+=*)',

    # === Private Keys & Certificates ===
    "RSA Private Key":       r'-----BEGIN RSA PRIVATE KEY-----',
    "EC Private Key":        r'-----BEGIN EC PRIVATE KEY-----',
    "PGP Private Key":       r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    "Generic Private Key":   r'-----BEGIN PRIVATE KEY-----',
    "SSH Private Key":       r'-----BEGIN OPENSSH PRIVATE KEY-----',
    "Certificate":           r'-----BEGIN CERTIFICATE-----',

    # === JWT Tokens ===
    "JWT Token":             r'eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}',

    # === Database & Connection Strings ===
    "MongoDB URI":           r'mongodb(?:\+srv)?://[^\s"\'<>]+',
    "PostgreSQL URI":        r'postgres(?:ql)?://[^\s"\'<>]+',
    "MySQL URI":             r'mysql://[^\s"\'<>]+',
    "Redis URI":             r'redis://[^\s"\'<>]+',
    "Database Password":     r'(?i)db_pass(?:word)?\s*[=:]\s*["\']([^"\']+)["\']',

    # === URLs with Credentials ===
    "URL with credentials":  r'https?://[^\s"\'<>@]+:[^\s"\'<>@]+@[^\s"\'<>]+',

    # === Cloud Credentials ===
    "Azure Client Secret":   r'(?i)azure.{0,20}(?:secret|password).{0,20}["\']([A-Za-z0-9~._-]{34,})["\']',
    "GCP Service Account":   r'"private_key_id":\s*"[a-f0-9]{40}"',
    "DigitalOcean Token":    r'dop_v1_[a-f0-9]{64}',

    # === Encoded Strings (suspicious) ===
    "Long Base64 String":    r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{60,}={0,2}(?![A-Za-z0-9+/=])',
    "Hex Secret (32+ chars)":r'\b[a-fA-F0-9]{32,64}\b',
}

# Severity levels
SEVERITY = {
    "AWS Access Key": "CRITICAL", "AWS Secret Key": "CRITICAL",
    "Google API Key": "HIGH", "GitHub Token": "CRITICAL",
    "GitHub Classic Token": "CRITICAL", "Stripe Secret Key": "CRITICAL",
    "RSA Private Key": "CRITICAL", "EC Private Key": "CRITICAL",
    "PGP Private Key": "CRITICAL", "SSH Private Key": "CRITICAL",
    "JWT Token": "HIGH", "MongoDB URI": "CRITICAL",
    "PostgreSQL URI": "CRITICAL", "MySQL URI": "CRITICAL",
    "URL with credentials": "CRITICAL", "Password in Code": "HIGH",
    "Secret in Code": "HIGH", "Bearer Token": "HIGH",
    "OpenAI API Key": "CRITICAL", "Anthropic API Key": "CRITICAL",
    "Supabase Key": "HIGH", "Firebase": "HIGH",
    "Slack Token": "HIGH", "Discord Token": "HIGH",
    "Telegram Bot Token": "HIGH",
}

def get_severity(name):
    return SEVERITY.get(name, "MEDIUM")


class SecretExtractor:
    def __init__(self, logger):
        self.log = logger
        self._compiled = {
            name: re.compile(pattern)
            for name, pattern in SECRET_PATTERNS.items()
        }

    def scan(self, url: str, content: str) -> list[dict]:
        findings = []
        lines = content.splitlines()

        for name, regex in self._compiled.items():
            for match in regex.finditer(content):
                value = match.group(1) if match.lastindex else match.group(0)
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
