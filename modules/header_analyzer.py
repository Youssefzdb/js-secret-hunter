#!/usr/bin/env python3
"""
Header Analyzer - Detect security misconfigurations in HTTP headers
New module in v4
"""
import requests
import urllib3
urllib3.disable_warnings()

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "required": True, "severity": "HIGH",
        "desc": "HSTS missing — site vulnerable to SSL stripping"
    },
    "Content-Security-Policy": {
        "required": True, "severity": "HIGH",
        "desc": "CSP missing — XSS risk increased"
    },
    "X-Content-Type-Options": {
        "required": True, "severity": "MEDIUM",
        "desc": "Missing — MIME sniffing attacks possible"
    },
    "X-Frame-Options": {
        "required": True, "severity": "MEDIUM",
        "desc": "Missing — clickjacking attacks possible"
    },
    "X-XSS-Protection": {
        "required": True, "severity": "LOW",
        "desc": "Missing — legacy browsers unprotected"
    },
    "Referrer-Policy": {
        "required": True, "severity": "LOW",
        "desc": "Missing — referrer info leaks possible"
    },
    "Permissions-Policy": {
        "required": True, "severity": "LOW",
        "desc": "Missing — browser features uncontrolled"
    },
}

DANGEROUS_HEADERS = {
    "Server":            "Reveals server software version",
    "X-Powered-By":     "Reveals backend framework/version",
    "X-AspNet-Version": "Reveals ASP.NET version",
    "X-Generator":      "Reveals CMS/generator",
}

class HeaderAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.findings = []
        self.session = requests.Session()
        self.session.verify = False

    def analyze(self):
        print("[*] Analyzing HTTP security headers...")
        try:
            r = self.session.get(self.target_url, timeout=10)
            headers = r.headers

            # Check missing security headers
            for header, info in SECURITY_HEADERS.items():
                if header not in headers:
                    self.findings.append({
                        "type": f"Missing Header: {header}",
                        "value": "NOT PRESENT",
                        "severity": info["severity"],
                        "source": "HTTP Headers",
                        "source_url": self.target_url,
                        "line": 0,
                        "decoded": None,
                        "snippet": info["desc"]
                    })
                    print(f"  [!] {info['severity']} | Missing: {header}")

            # Check dangerous information-leaking headers
            for header, desc in DANGEROUS_HEADERS.items():
                if header in headers:
                    self.findings.append({
                        "type": f"Info Leak Header: {header}",
                        "value": headers[header],
                        "severity": "MEDIUM",
                        "source": "HTTP Headers",
                        "source_url": self.target_url,
                        "line": 0,
                        "decoded": None,
                        "snippet": desc
                    })
                    print(f"  [!] MEDIUM | Info leak: {header}: {headers[header]}")

            # Check CORS misconfiguration
            cors = headers.get("Access-Control-Allow-Origin", "")
            if cors == "*":
                self.findings.append({
                    "type": "CORS Misconfiguration",
                    "value": "Access-Control-Allow-Origin: *",
                    "severity": "HIGH",
                    "source": "HTTP Headers",
                    "source_url": self.target_url,
                    "line": 0,
                    "decoded": None,
                    "snippet": "Wildcard CORS — any origin can read responses"
                })
                print(f"  [!] HIGH | CORS wildcard detected")

            # Check cookie flags
            cookies = r.cookies
            for cookie in cookies:
                issues = []
                if not cookie.secure:
                    issues.append("no Secure flag")
                if "httponly" not in str(cookie._rest).lower():
                    issues.append("no HttpOnly flag")
                if issues:
                    self.findings.append({
                        "type": "Insecure Cookie",
                        "value": f"{cookie.name}: {', '.join(issues)}",
                        "severity": "MEDIUM",
                        "source": "HTTP Cookies",
                        "source_url": self.target_url,
                        "line": 0,
                        "decoded": None,
                        "snippet": f"Cookie '{cookie.name}' missing security flags"
                    })
                    print(f"  [!] MEDIUM | Insecure cookie: {cookie.name} ({', '.join(issues)})")

        except Exception as e:
            print(f"  [-] Header analysis failed: {e}")

        print(f"[+] Header analysis: {len(self.findings)} issues found")
        return self.findings
