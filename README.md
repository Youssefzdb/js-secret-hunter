# js-secret-hunter 🔍

JavaScript Secret Scanner for authorized web application pentests.

## Features
- Auto-discovery of all JS files (static, dynamic, bundles)
- 20+ secret patterns: AWS, GCP, Firebase, JWT, Stripe, GitHub tokens, DB strings...
- Auto-decode: Base64, JWT, Hex, URL encoding
- Environment checker — blocks unauthorized targets
- HTML report with severity scoring

## Usage
```bash
pip install -r requirements.txt

# Lab/internal target
python main.py --url http://192.168.1.100

# CTF/HackTheBox
python main.py --url http://10.10.10.50

# Authorized external target (with scope)
python main.py --url https://target.com --scope target.com

# With custom output
python main.py --url http://192.168.1.100 --output report.html
```

## Environment Check
- ✅ Private IPs (192.168.x.x, 10.x.x.x, 172.16.x.x) → auto-allowed
- ✅ Lab domains (htb, thm, ctf, lab, local) → auto-allowed
- ✅ Defined scope (--scope) → allowed
- ⚠️ Public IPs → requires explicit authorization confirmation
