#!/usr/bin/env python3
"""
Secret Scanner v4 - Smart filtering + zero false positives
Covers 50+ secret types with context-aware validation
"""
import re
import base64
import json

# ============================================================
# FALSE POSITIVE FILTERS
# ============================================================

# Patterns that indicate a Base64 is NOT a secret
FP_CONTEXT_PATTERNS = [
    r'window\._hvc\s*=',           # Cloudflare PoW challenge
    r'window\.__cf_chl',           # Cloudflare challenge
    r'var\s+_0x[0-9a-f]+\s*=\s*\[',  # JS obfuscation array (_0x...)
    r'self\.__next_f',             # Next.js chunk
    r'webpackChunk',               # Webpack bundle
    r'__webpack_require__',        # Webpack internals
    r'bootstrapScripts',           # Next.js bootstrap
    r'data:image/',                # Base64 images
    r'data:font/',                 # Base64 fonts
]

# If decoded Base64 contains these → false positive
FP_DECODED_PATTERNS = [
    r'"algorithm"\s*:\s*"SHA-',    # Cloudflare challenge JSON
    r'"challenge"\s*:',            # Cloudflare challenge JSON
    r'"maxnumber"\s*:',            # Cloudflare PoW params
    r'"salt"\s*:\s*"[a-f0-9]{10,}',# Cloudflare salt
]

# Obfuscated JS variable names (no real secrets here)
OBFUSCATED_JS_PATTERN = re.compile(r'var\s+_0x[0-9a-f]+\s*=\s*\[')

def is_cloudflare_challenge(value: str, snippet: str = "") -> bool:
    """Detect Cloudflare PoW tokens"""
    # Check context
    for pattern in FP_CONTEXT_PATTERNS:
        if re.search(pattern, snippet, re.IGNORECASE):
            return True
    # Try decode and check content
    try:
        decoded = base64.b64decode(value + "==").decode("utf-8", errors="ignore")
        for pattern in FP_DECODED_PATTERNS:
            if re.search(pattern, decoded):
                return True
        # Check if it's valid JSON with CF fields
        try:
            obj = json.loads(decoded)
            if "challenge" in obj and "algorithm" in obj:
                return True
        except:
            pass
    except:
        pass
    return False

def is_obfuscated_js_array(value: str, snippet: str = "") -> bool:
    """Detect obfuscated JS array values (not real secrets)"""
    if OBFUSCATED_JS_PATTERN.search(snippet):
        return True
    # Short random-looking base64 with no real structure
    try:
        decoded = base64.b64decode(value + "==").decode("utf-8", errors="ignore")
        # If decoded is mostly non-printable or random → skip
        printable = sum(1 for c in decoded if c.isprintable())
        if len(decoded) > 0 and printable / len(decoded) < 0.5:
            return True
    except:
        pass
    return False

def is_false_positive(secret_type: str, value: str, snippet: str = "") -> bool:
    """Master false positive checker"""
    if secret_type == "Long Base64 String":
        if is_cloudflare_challenge(value, snippet):
            return True
        if is_obfuscated_js_array(value, snippet):
            return True
    return False


# ============================================================
# PATTERNS: (regex, severity)
# ============================================================
PATTERNS = {
    # Cloud Providers
    "AWS Access Key ID":      (r'(?<![A-Z0-9])(AKIA[A-Z0-9]{16})(?![A-Z0-9])', "CRITICAL"),
    "AWS Secret Access Key":  (r'(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key["\':\s=]+([A-Za-z0-9/+=]{40})', "CRITICAL"),
    "AWS Session Token":      (r'(?i)aws[_\-\s]?session[_\-\s]?token["\':\s=]+([A-Za-z0-9/+=]{100,})', "CRITICAL"),
    "GCP API Key":            (r'AIza[0-9A-Za-z\-_]{35}', "CRITICAL"),
    "GCP Service Account":    (r'"type"\s*:\s*"service_account"', "CRITICAL"),
    "Azure Client Secret":    (r'(?i)azure[_\-\s]?(?:client[_\-\s]?)?secret["\':\s=]+([A-Za-z0-9\-_~]{30,})', "CRITICAL"),
    "Azure Storage Key":      (r'(?i)AccountKey=([A-Za-z0-9+/=]{80,})', "CRITICAL"),
    # Firebase
    "Firebase API Key":       (r'AIza[0-9A-Za-z\-_]{35}', "CRITICAL"),
    "Firebase DB URL":        (r'https://[a-z0-9\-]+\.firebaseio\.com', "HIGH"),
    "Firebase Config":        (r'firebase(?:Config|\.initializeApp)\s*\(\s*\{[^}]{20,}apiKey', "CRITICAL"),
    # Payment
    "Stripe Secret Key":      (r'sk_live_[0-9a-zA-Z]{24,}', "CRITICAL"),
    "Stripe Restricted Key":  (r'rk_live_[0-9a-zA-Z]{24,}', "CRITICAL"),
    "Stripe Publishable":     (r'pk_live_[0-9a-zA-Z]{24,}', "MEDIUM"),
    "Stripe Webhook Secret":  (r'whsec_[0-9a-zA-Z]{32,}', "CRITICAL"),
    "PayPal Client ID":       (r'(?i)paypal[_\-\s]?client[_\-\s]?id["\':\s=]+([A-Za-z0-9\-_]{20,})', "HIGH"),
    "Braintree Token":        (r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}', "CRITICAL"),
    # Communication
    "Twilio Account SID":     (r'(?<![A-Za-z0-9])(AC[a-f0-9]{32})(?![A-Za-z0-9])', "CRITICAL"),
    "Twilio Auth Token":      (r'(?i)twilio[_\-\s]?auth[_\-\s]?token["\':\s=]+([a-f0-9]{32})', "CRITICAL"),
    "SendGrid API Key":       (r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}', "CRITICAL"),
    "Mailgun API Key":        (r'(?i)mailgun[_\-\s]?(?:api[_\-\s]?)?key["\':\s=]+(key-[a-z0-9]{32})', "CRITICAL"),
    "Mailchimp API Key":      (r'[a-f0-9]{32}-us[0-9]{1,2}', "HIGH"),
    "Slack Bot Token":        (r'xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}', "CRITICAL"),
    "Slack App Token":        (r'xapp-[0-9]-[A-Z0-9]{10,}-[0-9]+-[a-f0-9]{64}', "CRITICAL"),
    "Slack Webhook":          (r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+', "CRITICAL"),
    "Discord Token":          (r'(?i)discord[_\-\s]?(?:bot[_\-\s]?)?token["\':\s=]+([A-Za-z0-9\-_\.]{50,})', "CRITICAL"),
    "Discord Webhook":        (r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+', "HIGH"),
    # Version Control
    "GitHub Token":           (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}', "CRITICAL"),
    "GitHub Classic Token":   (r'(?i)github[_\-\s]?(?:access[_\-\s]?)?token["\':\s=]+([a-f0-9]{40})', "CRITICAL"),
    "GitLab Token":           (r'glpat-[A-Za-z0-9\-_]{20}', "CRITICAL"),
    # Auth & Identity
    "JWT Token":              (r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', "HIGH"),
    "OAuth2 Access Token":    (r'(?i)(?:access|bearer)[_\-\s]?token["\':\s=]+([A-Za-z0-9\-_\.]{20,})', "HIGH"),
    "Private Key PEM":        (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "CRITICAL"),
    "Certificate PEM":        (r'-----BEGIN CERTIFICATE-----', "MEDIUM"),
    # Database
    "MongoDB URI":            (r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s"\']+', "CRITICAL"),
    "PostgreSQL URI":         (r'postgres(?:ql)?://[^:]+:[^@]+@[^\s"\']+', "CRITICAL"),
    "MySQL URI":              (r'mysql://[^:]+:[^@]+@[^\s"\']+', "CRITICAL"),
    "Redis URI":              (r'redis://:[^@]+@[^\s"\']+', "HIGH"),
    "Database Password":      (r'(?i)(?:db|database)[_\-\s]?pass(?:word)?["\':\s=]+([^\s"\']{8,})', "HIGH"),
    # Generic Secrets
    "Generic API Key":        (r'(?i)api[_\-\s]?key["\':\s=]+([A-Za-z0-9\-_]{20,})', "MEDIUM"),
    "Generic Secret":         (r'(?i)(?:secret|password|passwd|pwd)["\':\s=]+([^\s"\']{12,})', "MEDIUM"),
    "Generic Token":          (r'(?i)(?:auth|access)[_\-\s]?token["\':\s=]+([A-Za-z0-9\-_\.]{20,})', "MEDIUM"),
    "Basic Auth in URL":      (r'https?://[^:]+:[^@]{6,}@[^\s"\']+', "HIGH"),
    # Long Base64 (filtered aggressively)
    "Long Base64 String":     (r'(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{60,}={0,2})(?![A-Za-z0-9+/=])', "MEDIUM"),
    # Other Services
    "Heroku API Key":         (r'(?i)heroku[_\-\s]?(?:api[_\-\s]?)?key["\':\s=]+([a-f0-9\-]{36})', "HIGH"),
    "Netlify Token":          (r'(?i)netlify[_\-\s]?token["\':\s=]+([A-Za-z0-9\-_]{20,})', "HIGH"),
    "Vercel Token":           (r'(?i)vercel[_\-\s]?token["\':\s=]+([A-Za-z0-9\-_]{20,})', "HIGH"),
    "NPM Token":              (r'//registry\.npmjs\.org/:_authToken=([A-Za-z0-9\-_]{36,})', "CRITICAL"),
    "Docker Hub Token":       (r'(?i)docker[_\-\s]?(?:hub[_\-\s]?)?(?:token|password)["\':\s=]+([A-Za-z0-9\-_\.]{20,})', "HIGH"),
    "OpenAI API Key":         (r'sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}', "CRITICAL"),
    "Anthropic API Key":      (r'sk-ant-[A-Za-z0-9\-_]{40,}', "CRITICAL"),
    "Hugging Face Token":     (r'hf_[A-Za-z0-9]{34,}', "HIGH"),
    "Mapbox Token":           (r'pk\.eyJ1[A-Za-z0-9\-_\.]+', "HIGH"),
    "Algolia API Key":        (r'(?i)algolia[_\-\s]?(?:api[_\-\s]?)?key["\':\s=]+([A-Za-z0-9]{32})', "HIGH"),
    "Sentry DSN":             (r'https://[a-f0-9]{32}@[a-z0-9\.]+\.ingest\.sentry\.io/[0-9]+', "MEDIUM"),
    "Datadog API Key":        (r'(?i)datadog[_\-\s]?(?:api[_\-\s]?)?key["\':\s=]+([a-f0-9]{32})', "HIGH"),
    "New Relic Key":          (r'(?i)new[_\-\s]?relic[_\-\s]?(?:license[_\-\s]?)?key["\':\s=]+([A-Za-z0-9]{40})', "HIGH"),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def scan_content(content: str, source: str = "unknown") -> list:
    """Scan content for secrets, returns list of findings"""
    findings = []
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        for secret_type, (pattern, severity) in PATTERNS.items():
            for match in re.finditer(pattern, line):
                value = match.group(1) if match.lastindex else match.group(0)
                snippet = line.strip()[:120]
                
                # Apply false positive filter
                if is_false_positive(secret_type, value, snippet):
                    continue
                
                findings.append({
                    "type": secret_type,
                    "severity": severity,
                    "file": source,
                    "line": line_num,
                    "value": value[:80] + "..." if len(value) > 80 else value,
                    "snippet": snippet,
                })
    
    return findings

