# 🕵️ JS Secret Hunter

> **Red Team JS Secrets Extraction Tool — by Shadow Core**

Extract all JavaScript files from a target URL, hunt for secrets, API keys, tokens, and encoded strings — then decode/decrypt them automatically.

---

## ⚡ Features

- 🔍 **JS Discovery** — Finds all JS files (external + inline) including webpack chunks, Next.js bundles, CRA builds
- 🔑 **50+ Secret Patterns** — AWS, Google, GitHub, Stripe, Slack, Discord, OpenAI, Telegram, JWT, private keys, passwords, DB URIs, and more
- 🔓 **Auto Decode/Decrypt** — Base64, JWT (header+payload), Hex, URL encoding, Unicode escapes, ROT13, XOR detection
- 📊 **Severity Levels** — CRITICAL / HIGH / MEDIUM / LOW with color-coded output
- 💾 **JSON Report** — Machine-readable output for integration with other tools
- 🕸️ **Deep Crawl** — Follow links across subpages with configurable depth

---

## 📦 Install

```bash
git clone https://github.com/Youssefzdb/js-secret-hunter
cd js-secret-hunter
pip install -r requirements.txt
```

---

## 🚀 Usage

```bash
# Basic scan (single page)
python3 main.py https://target.com

# Deep crawl (follow links, depth 3)
python3 main.py https://target.com --deep --depth 3

# Save JSON report
python3 main.py https://target.com --output report.json

# Verbose mode
python3 main.py https://target.com -v

# Skip decoding (faster)
python3 main.py https://target.com --no-decode
```

---

## 🎯 What It Finds

| Category | Examples |
|----------|---------|
| **Cloud Keys** | AWS, GCP, Azure, DigitalOcean |
| **API Services** | OpenAI, Stripe, Twilio, SendGrid, Mailgun |
| **Dev Platforms** | GitHub, GitLab, NPM, Heroku |
| **Comms** | Slack, Discord, Telegram |
| **Databases** | MongoDB, PostgreSQL, MySQL, Redis URIs |
| **Auth** | JWT tokens, Bearer tokens, OAuth secrets |
| **Crypto** | Private keys (RSA, EC, PGP, SSH), certificates |
| **Generic** | password=, api_key=, secret=, token= |
| **Encoded** | Base64, Hex, URL-encoded, Unicode escapes |

---

## 📋 Output Example

```
[1] Crawling target for JavaScript files...
  📄 https://target.com/static/js/main.abc123.js
  📄 https://target.com/static/js/chunk.456.js

[2] Scanning 2 JS file(s) for secrets...
  🔴 AWS Access Key → main.abc123.js:42
  🟠 JWT Token → chunk.456.js:17

[3] Attempting to decode/decrypt suspicious values...

=== FINDINGS REPORT ===

🔴 CRITICAL (1 findings)
  Type:    AWS Access Key
  File:    https://target.com/static/js/main.abc123.js
  Line:    42
  Value:   AKIAIOSFODNN7EXAMPLE

🟠 HIGH (1 findings)
  Type:    JWT Token
  Value:   eyJhbGciOiJIUzI1NiJ9...
  Decoded:
    [jwt] {"header": {"alg": "HS256"}, "payload": {"sub": "admin", "email": "admin@target.com"}}
```

---

## ⚠️ Legal Disclaimer

This tool is intended **ONLY** for authorized penetration testing, bug bounty programs, and security research on systems you own or have explicit written permission to test.

Unauthorized use against systems you do not own is illegal. The author assumes no responsibility for misuse.

---

**Made with 🖤 by Shadow Core**
