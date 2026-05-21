# js-secret-hunter v3 🔍

Advanced JavaScript secret scanner for authorized web application penetration testing.

## What it finds (50+ patterns)

| Category | Secrets |
|----------|---------|
| ☁️ Cloud | AWS keys, GCP API keys, Azure secrets, Firebase config |
| 💳 Payment | Stripe (live/webhook), Braintree, Square, PayPal |
| 📨 Messaging | Slack (bot/user/webhook), Discord, Telegram, Twilio, SendGrid |
| 🔑 Auth | JWT tokens, Bearer tokens, OAuth tokens, Basic auth |
| 🗃️ Database | MongoDB, PostgreSQL, MySQL, Redis URIs + credentials |
| 🐙 Git | GitHub PAT (classic + fine-grained), GitLab, NPM tokens |
| 🔐 Crypto | Private keys (RSA/EC/SSH), Ethereum private keys |
| ⚙️ Config | Hardcoded passwords, API keys, secrets, internal IPs, admin paths |

## Features

- **Deep crawl** — follows links, probes 30+ common paths, discovers webpack chunks
- **Source map extraction** — reads original pre-minified source code
- **Webpack chunk discovery** — finds all JS bundles automatically  
- **50+ patterns** with per-pattern entropy validation
- **Zero false positives** — strict FP suppression (Cloudflare, reCAPTCHA, obfuscation arrays)
- **Auto-decode** — Base64, JWT payload, Hex, URL encoding, Unicode escapes, Gzip
- **HTML report** with remediation steps, entropy scores, and source snippets
- **Environment checker** — restricts execution to authorized/lab targets

## Usage

```bash
pip install -r requirements.txt

# Lab / internal target (auto-allowed)
python main.py --url http://192.168.1.100

# HackTheBox / CTF
python main.py --url http://10.10.10.50

# Authorized external target
python main.py --url https://target.com --scope target.com

# Deep scan
python main.py --url https://target.com --scope target.com --depth 5 --output results.html
```

## Environment Checker

| Target | Behavior |
|--------|----------|
| Private IP (10.x / 192.168.x) | ✅ Auto-allowed |
| Lab domain (htb, thm, ctf, lab) | ✅ Auto-allowed |
| `--scope` defined and matches | ✅ Allowed |
| Public IP without scope | ⚠️ Requires explicit authorization confirmation |
| Outside defined scope | ❌ Blocked |

## Requirements

```
requests>=2.28.0
beautifulsoup4>=4.11.0
urllib3>=1.26.0
```
