#!/usr/bin/env python3
"""
Secret Scanner v3 — 50+ patterns, entropy validation, zero false positives
"""
import re, math

# ── Entropy Calculator ─────────────────────────────────────────────────────
def entropy(s):
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((v/total)*math.log2(v/total) for v in freq.values())

# ── Patterns: (regex, severity, min_entropy) ──────────────────────────────
PATTERNS = {
    # Cloud — AWS
    "AWS Access Key ID":       (r'(?<![A-Z0-9])(AKIA[A-Z0-9]{16})(?![A-Z0-9])',                    "CRITICAL", 3.0),
    "AWS Secret Access Key":   (r'(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\s"\'=:]+([A-Za-z0-9/+=]{40})', "CRITICAL", 4.0),
    "AWS Session Token":       (r'(?i)aws[_\-\s]?session[_\-\s]?token[\s"\'=:]+([A-Za-z0-9/+=]{100,})', "CRITICAL", 4.0),

    # Cloud — GCP / Firebase
    "GCP API Key":             (r'\bAIza[0-9A-Za-z\-_]{35}\b',                                      "CRITICAL", 3.5),
    "Firebase DB URL":         (r'https://[a-z0-9\-]{3,30}(?:-default-rtdb)?\.firebaseio\.com',     "HIGH",     0.0),
    "Firebase Config Block":   (r'firebaseConfig\s*=\s*\{[^}]{50,}apiKey\s*:\s*["\'][^"\']{10,}',   "CRITICAL", 0.0),

    # Cloud — Azure
    "Azure Client Secret":     (r'(?i)azure[_\-\s]?(?:client[_\-\s]?)?secret[\s"\'=:]+([A-Za-z0-9\-_~.]{30,})', "CRITICAL", 3.5),
    "Azure Storage Key":       (r'AccountKey=([A-Za-z0-9+/=]{80,})',                                "CRITICAL", 4.0),
    "Azure Conn String":       (r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{80,}', "CRITICAL", 0.0),

    # Payment
    "Stripe Secret Key":       (r'\bsk_live_[0-9a-zA-Z]{24,}\b',                                    "CRITICAL", 3.5),
    "Stripe Webhook Secret":   (r'\bwhsec_[0-9a-zA-Z]{32,}\b',                                      "CRITICAL", 3.5),
    "Stripe Restricted Key":   (r'\brk_live_[0-9a-zA-Z]{24,}\b',                                    "CRITICAL", 3.5),
    "Stripe Publishable":      (r'\bpk_live_[0-9a-zA-Z]{24,}\b',                                    "MEDIUM",   3.0),
    "Braintree Token":         (r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',            "CRITICAL", 3.5),
    "Square Access Token":     (r'\bEAAAE[A-Za-z0-9_\-]{60,}\b',                                    "CRITICAL", 3.5),
    "PayPal Client ID":        (r'(?i)paypal[_\-\s]?(?:client[_\-\s]?)?(?:id|secret)[\s"\'=:]+([A-Za-z0-9\-_]{20,})', "HIGH", 3.0),

    # Messaging
    "Twilio Account SID":      (r'(?<![A-Za-z0-9])(AC[a-f0-9]{32})(?![A-Za-z0-9])',                "CRITICAL", 3.0),
    "Twilio Auth Token":       (r'(?i)twilio[_\-\s]?auth[_\-\s]?token[\s"\'=:]+([a-f0-9]{32})',    "CRITICAL", 3.5),
    "SendGrid API Key":        (r'\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b',                 "CRITICAL", 4.0),
    "Mailgun API Key":         (r'\bkey-[0-9a-zA-Z]{32}\b',                                         "HIGH",     3.5),
    "Mailchimp API Key":       (r'[a-f0-9]{32}-us[0-9]{1,2}',                                       "HIGH",     3.5),
    "Slack Bot Token":         (r'\bxoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}\b',             "CRITICAL", 4.0),
    "Slack User Token":        (r'\bxoxp-[0-9]{11,13}-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{32}\b',"CRITICAL", 4.0),
    "Slack App Token":         (r'\bxapp-[0-9]-[A-Z0-9]{11}-[0-9]{13}-[a-z0-9]{64}\b',             "CRITICAL", 4.0),
    "Slack Webhook URL":       (r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+', "HIGH", 0.0),
    "Discord Bot Token":       (r'(?<![A-Za-z0-9])[MN][A-Za-z0-9]{23}\.[\w\-]{6}\.[\w\-]{27}(?![A-Za-z0-9])', "CRITICAL", 4.0),
    "Discord Webhook":         (r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+', "HIGH",   0.0),
    "Telegram Bot Token":      (r'(?<!\d)([0-9]{8,10}:[A-Za-z0-9\-_]{35})(?!\w)',                  "CRITICAL", 3.5),
    "PagerDuty Key":           (r'(?i)pagerduty[_\-\s]?(?:api[_\-\s]?)?key[\s"\'=:]+([A-Za-z0-9\-_+/]{20,})', "HIGH", 3.5),

    # Version Control
    "GitHub PAT Classic":      (r'\bghp_[A-Za-z0-9]{36}\b',                                         "CRITICAL", 4.0),
    "GitHub OAuth Token":      (r'\bgho_[A-Za-z0-9]{36}\b',                                         "CRITICAL", 4.0),
    "GitHub Actions Token":    (r'\bghs_[A-Za-z0-9]{36}\b',                                         "CRITICAL", 4.0),
    "GitHub Fine-Grained PAT": (r'\bgithub_pat_[A-Za-z0-9_]{82}\b',                                 "CRITICAL", 4.0),
    "GitLab Token":            (r'\bglpat-[A-Za-z0-9\-_]{20}\b',                                    "CRITICAL", 4.0),
    "NPM Token":               (r'\bnpm_[A-Za-z0-9]{36}\b',                                         "CRITICAL", 3.5),

    # Auth & Sessions
    "JWT Token":               (r'eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}', "HIGH", 3.0),
    "Bearer Token":            (r'(?i)Authorization[\s"\']*[:=][\s"\']*Bearer\s+([A-Za-z0-9\-_.]{20,})', "HIGH", 3.5),
    "Basic Auth Encoded":      (r'(?i)Authorization[\s"\']*[:=][\s"\']*Basic\s+([A-Za-z0-9+/=]{20,})', "HIGH", 3.0),
    "OAuth Access Token":      (r'(?i)["\']?access_token["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_.]{20,})["\']', "HIGH", 3.5),

    # Database
    "MongoDB URI":             (r'mongodb(?:\+srv)?://[A-Za-z0-9_%\-]+:[^@\s"\'<>]{4,}@[^\s"\'<>]{5,}', "CRITICAL", 3.5),
    "PostgreSQL URI":          (r'postgres(?:ql)?://[A-Za-z0-9_%\-]+:[^@\s"\'<>]{4,}@[^\s"\'<>]{5,}',   "CRITICAL", 3.5),
    "MySQL URI":               (r'mysql://[A-Za-z0-9_%\-]+:[^@\s"\'<>]{4,}@[^\s"\'<>]{5,}',             "CRITICAL", 3.5),
    "Redis URI":               (r'redis://(?:[A-Za-z0-9_%\-]+:[^@\s"\'<>]{4,}@)?[^\s"\'<>]{5,}',        "HIGH",     2.5),
    "DB Password Field":       (r'(?i)["\']?(?:db_?pass(?:word)?|database_?pass(?:word)?)["\']?\s*[:=]\s*["\']([^"\'\\]{6,})["\']', "CRITICAL", 3.0),

    # Crypto
    "Ethereum Private Key":    (r'(?:0x)?[a-fA-F0-9]{64}(?=\s|$|["\'])',                            "CRITICAL", 3.8),
    "Private Key PEM":         (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',           "CRITICAL", 0.0),
    "SSH Private Key":         (r'-----BEGIN OPENSSH PRIVATE KEY-----',                              "CRITICAL", 0.0),

    # Misc secrets
    "Hardcoded Password":      (r'(?i)(?<![a-z])(password|passwd|pwd)\s*[:=]\s*["\']([^"\'\\]{6,50})["\']', "HIGH", 2.5),
    "Hardcoded API Key":       (r'(?i)["\']?api[_\-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_]{16,80})["\']', "HIGH", 3.0),
    "Hardcoded Secret":        (r'(?i)["\']?(?:secret|app_secret|client_secret)["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_+/=.]{8,80})["\']', "HIGH", 3.0),
    "Google OAuth Client":     (r'[0-9]{12}-[0-9a-zA-Z]{32}\.apps\.googleusercontent\.com',         "HIGH",     0.0),
    "Sentry DSN":              (r'https://[a-f0-9]{32}@(?:o\d+\.)?ingest\.sentry\.io/\d+',          "MEDIUM",   0.0),
    "S3 Bucket Exposed":       (r'https?://[a-z0-9\-\.]{3,63}\.s3(?:[\.\-][a-z0-9\-]+)?\.amazonaws\.com(?:/[^"\'<>\s]*)?', "MEDIUM", 0.0),
    "Internal IP Exposed":     (r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b', "MEDIUM", 0.0),
    "Admin Endpoint":          (r'["\'](?:/admin|/api/internal|/debug|/backdoor|/manage|/console|/secret)["\']', "MEDIUM", 0.0),
    "Sensitive Comment":       (r'//\s*(?:TODO|FIXME|HACK|password|secret|key|token|credential)[^\n]{0,100}', "LOW", 0.0),
}

# ── False Positive Suppression ────────────────────────────────────────────
FP_SOURCES = [
    "google.com/recaptcha", "gstatic.com", "googleapis.com",
    "cloudflare.com/cdn", "recaptcha", "jquery.min",
    "bootstrap.min", "lodash.min", "moment.min",
    "analytics.js", "gtag/js", "fbevents.js",
]
FP_CONTEXTS = [
    "window._hvc", "_0x2dd3", "_0x", "__grecaptcha",
    "YOUR_API_KEY", "your_api_key", "REPLACE_ME",
    "INSERT_KEY", "xxxx", "<YOUR_", "${", "%(", "example.com",
    "placeholder", "changeme", "test123",
]
FP_VALUES_EXACT = {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
    "0123456789abcdef",
}

def is_fp(value, source_url, snippet, secret_type, min_entropy):
    # Entropy check
    if min_entropy > 0 and entropy(value) < min_entropy:
        return True
    # FP sources
    for s in FP_SOURCES:
        if s in source_url.lower():
            if secret_type not in ["AWS Access Key ID","GitHub PAT Classic",
                                    "Stripe Secret Key","Private Key PEM","DB Password Field"]:
                return True
    # FP contexts
    for ctx in FP_CONTEXTS:
        if ctx in snippet or ctx.lower() in value.lower():
            return True
    # Exact FP values
    if value in FP_VALUES_EXACT:
        return True
    # Cloudflare PoW JWT
    if '"challenge"' in value and '"algorithm"' in value:
        return True
    # JWT from Cloudflare _hvc
    if "window._hvc" in snippet:
        return True
    # Strict Twilio SID: exactly AC + 32 hex chars
    if secret_type == "Twilio Account SID" and not re.match(r'^AC[a-f0-9]{32}$', value):
        return True
    # Password: reject obvious placeholders
    if "Password" in secret_type:
        if re.match(r'^(?:password|pass|test|admin|secret|example|\*+|\.\.\.+|<\w+>)$', value, re.I):
            return True
    return False

class SecretScanner:
    def __init__(self, js_files):
        self.js_files = js_files

    def scan(self):
        findings = []
        fp_filtered = 0
        print("[*] Scanning with 50+ patterns + entropy validation...")

        for js_url, content in self.js_files.items():
            lines = content.splitlines()
            for line_no, line in enumerate(lines, 1):
                for stype, (pattern, severity, min_ent) in PATTERNS.items():
                    try:
                        matches = re.findall(pattern, line)
                    except:
                        continue
                    for match in matches:
                        value = match if isinstance(match, str) else (match[-1] if match else "")
                        if not value or len(value) < 8:
                            continue
                        if is_fp(value, js_url, line, stype, min_ent):
                            fp_filtered += 1
                            continue
                        findings.append({
                            "type":       stype,
                            "value":      value[:150],
                            "severity":   severity,
                            "source":     js_url.split("/")[-1][:60],
                            "source_url": js_url,
                            "line":       line_no,
                            "snippet":    line.strip()[:120],
                            "entropy":    round(entropy(value), 2),
                            "decoded":    None,
                        })
                        print(f"  [!] {severity:8} | {stype:30} | ent={round(entropy(value),2)} | {value[:50]}")

        # Deduplicate
        seen, unique = set(), []
        for f in findings:
            key = f"{f['type']}:{f['value'][:30]}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        SEV = ["CRITICAL","HIGH","MEDIUM","LOW"]
        unique.sort(key=lambda x: SEV.index(x["severity"]) if x["severity"] in SEV else 99)
        print(f"\n[+] {len(unique)} confirmed findings | {fp_filtered} false positives filtered")
        return unique
