#!/usr/bin/env python3
"""
Endpoint Finder - Extract & probe API endpoints from JS files
New module in v4
"""
import re
import requests
import urllib3
from urllib.parse import urljoin
urllib3.disable_warnings()

class EndpointFinder:
    def __init__(self, base_url, js_files):
        self.base_url = base_url
        self.js_files = js_files
        self.endpoints = []
        self.findings = []
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Security Assessment)",
        })

    def _extract_endpoints(self, content, source_url):
        """Extract API endpoints from JS content"""
        patterns = [
            # REST paths
            r'["\`](/api/v?[0-9]?/?[a-zA-Z0-9_\-/]{2,60})["\`]',
            r'["\`](/v[0-9]+/[a-zA-Z0-9_\-/]{2,60})["\`]',
            # fetch/axios calls
            r'(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["\`]([^"\'`\s]{5,100})',
            # URL construction
            r'url\s*[+:=]\s*["\`]([^"\'`\s]{5,80})',
            r'endpoint\s*[:=]\s*["\`]([^"\'`\s]{5,80})',
            r'baseURL\s*[:=]\s*["\`]([^"\'`\s]{5,80})',
            # GraphQL
            r'(?:query|mutation)\s*\{[^}]{5,200}\}',
        ]

        found = set()
        for pattern in patterns:
            for match in re.findall(pattern, content):
                if isinstance(match, str) and len(match) > 3:
                    # Filter obvious non-endpoints
                    if not any(skip in match for skip in [
                        '.js', '.css', '.png', '.jpg', '.svg', '.ico',
                        'font', 'webpack', 'chunk', 'module', 'require'
                    ]):
                        found.add(match)

        return list(found)

    def _test_endpoint(self, url):
        """Quick test if endpoint is accessible"""
        result = {"url": url, "status": None, "methods": [], "info": ""}
        methods = ["GET", "POST", "OPTIONS"]

        for method in methods:
            try:
                r = self.session.request(method, url, timeout=5,
                                          headers={"Content-Type": "application/json"})
                result["status"] = r.status_code
                if r.status_code not in [404, 400]:
                    result["methods"].append(f"{method}:{r.status_code}")
                    # Check for sensitive data in response
                    resp_text = r.text[:500].lower()
                    if any(kw in resp_text for kw in [
                        "error", "exception", "stack trace", "debug",
                        "password", "token", "secret", "internal server"
                    ]):
                        result["info"] = "⚠️ Sensitive data in response"
            except:
                pass

        return result

    def find(self, probe=False):
        print("[*] Extracting API endpoints from JS...")
        all_endpoints = set()

        for source_url, content in self.js_files.items():
            endpoints = self._extract_endpoints(content, source_url)
            all_endpoints.update(endpoints)

        print(f"[+] Found {len(all_endpoints)} potential endpoints")

        if probe and all_endpoints:
            print("[*] Probing endpoints...")
            for ep in list(all_endpoints)[:30]:
                # Only probe relative paths
                if ep.startswith("/"):
                    full_url = urljoin(self.base_url, ep)
                    result = self._test_endpoint(full_url)
                    if result["methods"]:
                        self.endpoints.append(result)
                        if result["info"]:
                            self.findings.append({
                                "type": "Exposed Endpoint",
                                "value": f"{full_url} [{', '.join(result['methods'])}]",
                                "severity": "MEDIUM",
                                "source": "API Discovery",
                                "source_url": full_url,
                                "line": 0,
                                "decoded": None,
                                "snippet": result["info"]
                            })
                        print(f"  [+] {full_url} → {', '.join(result['methods'])}")

        return self.endpoints, self.findings
