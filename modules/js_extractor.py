#!/usr/bin/env python3
"""JS Extractor - Discover and download all JavaScript files from target"""
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class JSExtractor:
    def __init__(self, base_url, depth=2):
        self.base_url = base_url
        self.depth = depth
        self.domain = urlparse(base_url).netloc
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (Security Assessment)"
        self.session.verify = False
        self.js_files = {}  # url -> content

    def _get_js_from_page(self, url):
        """Extract all JS URLs from a page"""
        js_urls = set()
        try:
            r = self.session.get(url, timeout=10)

            # Find <script src="..."> tags
            soup = BeautifulSoup(r.text, "html.parser")
            for tag in soup.find_all("script"):
                src = tag.get("src", "")
                if src:
                    full_url = urljoin(url, src)
                    js_urls.add(full_url)

            # Find JS references in inline scripts and HTML
            patterns = [
                r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']',
                r'src:\s*["\']([^"\']*\.js)["\']',
                r'loadScript\(["\']([^"\']+)["\']',
            ]
            for pattern in patterns:
                for match in re.findall(pattern, r.text):
                    if match.startswith("http") or match.startswith("/"):
                        full_url = urljoin(url, match)
                        js_urls.add(full_url)

            print(f"  [+] {url}: {len(js_urls)} JS refs found")
        except Exception as e:
            print(f"  [-] Error fetching {url}: {e}")
        return js_urls

    def _download_js(self, js_url):
        """Download JS file content"""
        try:
            # Only download from same domain or known CDNs
            parsed = urlparse(js_url)
            r = self.session.get(js_url, timeout=10)
            if r.status_code == 200 and len(r.text) > 0:
                return r.text
        except:
            pass
        return None

    def extract(self):
        print(f"[*] Extracting JS files from: {self.base_url}")
        js_urls = self._get_js_from_page(self.base_url)

        # Also check common JS bundle paths
        common_paths = [
            "/static/js/main.js", "/assets/js/app.js", "/js/bundle.js",
            "/dist/bundle.js", "/build/static/js/main.chunk.js",
            "/webpack.config.js", "/.env.js", "/config.js", "/env.js"
        ]
        for path in common_paths:
            url = urljoin(self.base_url, path)
            js_urls.add(url)

        print(f"[*] Downloading {len(js_urls)} JS files...")
        for js_url in js_urls:
            content = self._download_js(js_url)
            if content:
                self.js_files[js_url] = content
                size = len(content)
                print(f"  [+] {js_url.split('/')[-1][:50]} ({size:,} bytes)")

        return self.js_files
