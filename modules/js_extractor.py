#!/usr/bin/env python3
"""
JS Extractor v2 - Deep crawling + source maps + webpack chunks
"""
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json

class JSExtractor:
    def __init__(self, base_url, depth=3):
        self.base_url = base_url
        self.depth = depth
        self.domain = urlparse(base_url).netloc
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        })
        self.session.verify = False
        self.js_files = {}

    def _fetch(self, url, timeout=10):
        try:
            r = self.session.get(url, timeout=timeout, allow_redirects=True)
            if r.status_code == 200:
                return r.text
        except:
            pass
        return None

    def _extract_js_urls(self, html, base_url):
        urls = set()
        soup = BeautifulSoup(html, "html.parser")

        # <script src>
        for tag in soup.find_all("script", src=True):
            urls.add(urljoin(base_url, tag["src"]))

        # Inline script references
        patterns = [
            r'["\']([^"\']*?\.js(?:\?[^"\']*)?)["\']',
            r'import\s+[^"\']*["\']([^"\']+\.js)["\']',
            r'require\(["\']([^"\']+\.js)["\']',
            r'src:\s*["\']([^"\']+\.js)["\']',
            r'loadScript\(["\']([^"\']+)["\']',
            r'\.src\s*=\s*["\']([^"\']+\.js)["\']',
        ]
        for p in patterns:
            for match in re.findall(p, html):
                if not match.startswith("http"):
                    match = urljoin(base_url, match)
                urls.add(match)

        return urls

    def _check_sourcemap(self, js_url, js_content):
        """Extract and parse source maps for original source code"""
        sm_url = None
        match = re.search(r'//[#@]\s*sourceMappingURL=(.+)', js_content)
        if match:
            sm_path = match.group(1).strip()
            if not sm_path.startswith("data:"):
                sm_url = urljoin(js_url, sm_path)

        if sm_url:
            print(f"  [+] Source map found: {sm_url}")
            sm_content = self._fetch(sm_url)
            if sm_content:
                try:
                    sm = json.loads(sm_content)
                    # Extract original source contents from sourcesContent
                    sources = sm.get("sourcesContent", [])
                    for i, src in enumerate(sources):
                        if src and len(src) > 50:
                            src_name = sm.get("sources", [f"source_{i}"])[i] if i < len(sm.get("sources",[])) else f"source_{i}"
                            key = f"[SOURCEMAP:{js_url}:{src_name}]"
                            self.js_files[key] = src
                            print(f"    [+] Source: {src_name} ({len(src):,} bytes)")
                except:
                    pass

    def _discover_webpack_chunks(self, html, base_url):
        """Find webpack chunk manifests and load all chunks"""
        chunks = set()

        # Look for webpack runtime chunk patterns
        patterns = [
            r'chunk-[a-f0-9]+\.js',
            r'[0-9]+\.[a-f0-9]+\.chunk\.js',
            r'runtime\.[a-f0-9]+\.js',
            r'vendors\~[a-zA-Z0-9\-\.]+\.js',
            r'main\.[a-f0-9]+\.js',
            r'app\.[a-f0-9]+\.js',
        ]
        for p in patterns:
            for m in re.findall(p, html):
                chunks.add(urljoin(base_url, f"/static/js/{m}"))
                chunks.add(urljoin(base_url, f"/assets/js/{m}"))
                chunks.add(urljoin(base_url, f"/dist/{m}"))

        # webpack manifest
        for manifest_path in ["/asset-manifest.json", "/webpack-manifest.json",
                               "/.well-known/assetlinks.json", "/manifest.json"]:
            manifest = self._fetch(urljoin(base_url, manifest_path))
            if manifest:
                try:
                    data = json.loads(manifest)
                    for v in data.values() if isinstance(data, dict) else []:
                        if isinstance(v, str) and v.endswith(".js"):
                            chunks.add(urljoin(base_url, v))
                except:
                    pass

        return chunks

    def _check_env_files(self, base_url):
        """Try to fetch exposed .env and config files"""
        sensitive_paths = [
            "/.env", "/.env.local", "/.env.production", "/.env.development",
            "/config.js", "/env.js", "/settings.js", "/app.config.js",
            "/config/config.js", "/src/config.js", "/js/config.js",
            "/.git/config", "/robots.txt", "/sitemap.xml",
            "/api/config", "/api/settings", "/api/env",
            "/wp-config.php", "/config.php", "/configuration.php",
        ]
        for path in sensitive_paths:
            url = urljoin(base_url, path)
            content = self._fetch(url)
            if content and len(content) > 10 and len(content) < 500000:
                # Check if it's actually a config file (not 404 page)
                if any(kw in content.lower() for kw in ["key", "secret", "password", "token", "api", "db_", "database"]):
                    self.js_files[f"[CONFIG:{url}]"] = content
                    print(f"  [!] Sensitive file accessible: {url} ({len(content):,} bytes)")

    def extract(self):
        print(f"[*] Deep JS extraction from: {self.base_url}")
        all_js_urls = set()

        # Step 1: Crawl main page + common paths
        pages_to_crawl = [self.base_url]
        common_pages = ["/", "/login", "/register", "/dashboard", "/api", "/admin",
                        "/static", "/assets", "/js", "/app"]
        for p in common_pages:
            pages_to_crawl.append(urljoin(self.base_url, p))

        for page_url in pages_to_crawl[:8]:
            html = self._fetch(page_url)
            if html:
                urls = self._extract_js_urls(html, page_url)
                all_js_urls.update(urls)
                webpack = self._discover_webpack_chunks(html, page_url)
                all_js_urls.update(webpack)

        # Step 2: Common JS file paths
        common_js = [
            "/static/js/main.js", "/assets/js/app.js", "/js/bundle.js",
            "/dist/bundle.js", "/build/static/js/main.chunk.js",
            "/js/app.js", "/js/main.js", "/app.js", "/bundle.js",
            "/dist/app.js", "/public/js/main.js", "/js/index.js",
        ]
        for p in common_js:
            all_js_urls.add(urljoin(self.base_url, p))

        # Step 3: Check exposed config/env files
        self._check_env_files(self.base_url)

        # Step 4: Download JS files + check source maps
        print(f"[*] Downloading {len(all_js_urls)} JS files...")
        for js_url in all_js_urls:
            # Only same domain or CDN
            content = self._fetch(js_url)
            if content and len(content) > 50:
                self.js_files[js_url] = content
                print(f"  [+] {js_url.split('/')[-1][:50]} ({len(content):,} bytes)")
                # Check source maps
                self._check_sourcemap(js_url, content)

        print(f"[+] Total: {len(self.js_files)} JS/source files")
        return self.js_files
