#!/usr/bin/env python3
"""
Secret Scanner v4 - Smart false-positive filtering
"""
import re
import base64
import math

# ============================================================
# FALSE POSITIVE FILTERS
# ============================================================

FP_SNIPPET_PATTERNS = [
    re.compile(r'window\._hvc\s*='),
    re.compile(r'var\s+_0x[a-f0-9]+=\['),
    re.compile(r'_0x[a-f0-9]+\['),
    re.compile(r'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'),
    re.compile(r'data:font/'),
    re.compile(r'data:image/'),
    re.compile(r'GTM-[A-Z0-9]{4,8}'),
]

FP_DECODED_KEYWORDS = [
    '"algorithm"', '"challenge"', '"maxnumber"', '"salt"',
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    'SHA-256', 'SHA-512',
]

def calc_entropy(s):
    if not s:
        return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((v/length)*math.log2(v/length) for v in freq.values())

def is_fp_base64(value, snippet=""):
    for pat in FP_SNIPPET_PATTERNS:
        if pat.search(snippet):
            return True
    try:
        decoded = base64.b64decode(value + '==').decode('utf-8', errors='ignore')
        if any(kw in decoded for kw in FP_DECODED_KEYWORDS):
            return True
        printable = sum(1 for c in decoded if c.isprintable()) / max(len(decoded), 1)
        if printable < 0.5 and len(decoded) < 100:
            return True
    except Exception:
        pass
    if calc_entropy(value) < 3.5:
        return True
    return False

def is_fp(pattern_name, value, snippet=""):
    if '_0x' in snippet:
        return True
    min_lengths = {
        "Generic API Key": 20, "Generic Secret": 16,
        "Generic Token": 16, "Generic Password": 8,
        "Long Base64 String": 40,
    }
    if len(value) < min_lengths.get(pattern_name, 0):
        return True
    if "Base64" in pattern_name:
        return is_fp_base64(value, snippet)
    return False

# ============================================================
# PATTERNS
# ============================================================
PATTERNS = {
    "AWS Access Key ID":     (r'(?<![A-Z0-9])(AKIA[A-Z0-9]{16})(?![A-Z0-9])', "CRITICAL"),
    "AWS Secret Access Key": (r'(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key["\':\s=]+([A-Za-z0-9/+=]{40})', "CRITICAL"),
    "GCP API Key":           (r'AIza[0-9A-Za-z\-_]{35}', "CRITICAL"),
    "Azure Storage Key":     (r'(?i)AccountKey=([A-Za-z0-9+/=]{80,})', "CRITICAL"),
    "Stripe Secret Key":     (r'sk_live_[0-9a-zA-Z]{24,}', "CRITICAL"),
    "Stripe Test Key":       (r'sk_test_[0-9a-zA-Z]{24,}', "LOW"),
    "Stripe Webhook":        (r'whsec_[0-9a-zA-Z]{32,}', "CRITICAL"),
    "Stripe Publishable":    (r'pk_live_[0-9a-zA-Z]{24,}', "MEDIUM"),
    "SendGrid API Key":      (r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}', "CRITICAL"),
    "Twilio Account SID":    (r'(?<![A-Za-z0-9])(AC[a-f0-9]{32})(?![A-Za-z0-9])', "CRITICAL"),
    "Twilio Auth Token":     (r'(?i)twilio[_\-\s]?auth[_\-\s]?token["\':\s=]+([a-f0-9]{32})', "CRITICAL"),
    "Slack Bot Token":       (r'xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}', "CRITICAL"),
    "Slack Webhook":         (r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+', "HIGH"),
    "Discord Webhook":       (r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9\-_]+', "HIGH"),
    "GitHub Token":          (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{35,}', "CRITICAL"),
    "GitLab Token":          (r'glpat-[A-Za-z0-9\-_]{20}', "CRITICAL"),
    "MongoDB URI":           (r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s"\']+', "CRITICAL"),
    "PostgreSQL URI":        (r'postgres(?:ql)?://[^:]+:[^@]+@[^\s"\']+', "CRITICAL"),
    "MySQL URI":             (r'mysql://[^:]+:[^@]+@[^\s"\']+', "CRITICAL"),
    "Firebase API Key":      (r'AIza[0-9A-Za-z\-_]{35}', "CRITICAL"),
    "Firebase DB URL":       (r'https://[a-z0-9\-]+\.firebaseio\.com', "HIGH"),
    "JWT Token":             (r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]{10,}', "HIGH"),
    "Private Key":           (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "CRITICAL"),
    "NPM Token":             (r'npm_[A-Za-z0-9]{36}', "CRITICAL"),
    "Heroku API Key":        (r'(?i)heroku[_\-\s]?(?:api[_\-\s]?)?key["\':\s=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', "CRITICAL"),
    "Facebook Access Token": (r'EAA[a-zA-Z0-9]{50,}', "HIGH"),
    "Google OAuth Client":   (r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', "HIGH"),
    "Mailchimp API Key":     (r'[a-f0-9]{32}-us[0-9]{1,2}', "HIGH"),
    "Generic API Key":       (r'(?i)(?:api[_\-]?key|apikey)["\':\s=]+([A-Za-z0-9\-_]{20,45})(?![A-Za-z0-9\-_])', "MEDIUM"),
    "Generic Secret":        (r'(?i)(?:client_secret|app_secret)["\':\s=]+([A-Za-z0-9\-_\.@#]{16,})(?![A-Za-z0-9])', "MEDIUM"),
    "Generic Token":         (r'(?i)(?:auth[_\-]?token|access[_\-]?token)["\':\s=]+([A-Za-z0-9\-_\.]{20,})(?![A-Za-z0-9])', "MEDIUM"),
    "Internal IP":           (r'(?:^|[^0-9])((?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3})(?:[^0-9]|$)', "LOW"),
    "Admin Path":            (r'(?i)/(?:admin|wp-admin|phpmyadmin|cpanel)/[^\s"\']*', "LOW"),
}

BASE64_RE = re.compile(r'(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{60,}={0,2})(?![A-Za-z0-9+/=])')

def scan_base64(content, filename=""):
    results = []
    lines = content.split('\n')
    for ln, line in enumerate(lines, 1):
        for m in BASE64_RE.finditer(line):
            val = m.group(1)
            snip = line.strip()[:120]
            if is_fp_base64(val, snip):
                continue
            decoded_str = "[BINARY]"
            try:
                raw = base64.b64decode(val + '==')
                try:
                    decoded_str = "[BASE64] " + raw.decode('utf-8')[:80]
                except Exception:
                    decoded_str = "[HEX] " + raw.hex()[:40]
            except Exception:
                pass
            results.append({
                "type": "Long Base64 String", "severity": "MEDIUM",
                "file": filename, "line": ln,
                "value": val[:80], "decoded": decoded_str, "snippet": snip
            })
    return results

def scan(content, filename=""):
    findings = []
    lines = content.split('\n')
    for name, (pat, sev) in PATTERNS.items():
        try:
            for m in re.finditer(pat, content, re.MULTILINE):
                val = m.group(1) if m.lastindex else m.group(0)
                ln = content[:m.start()].count('\n') + 1
                snip = lines[ln-1].strip()[:120] if ln <= len(lines) else ""
                if is_fp(name, val, snip):
                    continue
                findings.append({
                    "type": name, "severity": sev,
                    "file": filename, "line": ln,
                    "value": val[:80], "snippet": snip
                })
        except re.error:
            continue
    findings.extend(scan_base64(content, filename))
    return findings
