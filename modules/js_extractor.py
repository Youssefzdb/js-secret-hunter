#!/usr/bin/env python3
"""
JS Extractor v3 - Deep crawling + source maps + webpack chunks
+ Smart inline script filtering (no Cloudflare/obfuscated noise)
"""
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json

# ============================================================
# INLINE SCRIPT NOISE FILTERS
# Block script blocks that are known false positive sources
# ============================================================

# If a script block CONTAINS any of these patterns → skip it entirely
NOISE_BLOCK_PATTERNS = [
    re.compile(r'window\._hvc\s*=\s*["\']'),          # Cloudflare PoW
    re.compile(r'window\.__cf_chl'),                    # Cloudflare challenge
    re.compile(r'var\s+_0x[0-9a-fA-F]+\s*=\s*\['),   # JS obfuscation (_0x arrays)
    re.compile(r'self\.__next_f\s*='),                  # Next.js SSR chunks
    re.compile(r'window\.__NUXT__'),                    # Nuxt.js state
    re.compile(r'__webpack_require__\.p\s*='),          # Webpack public path
    re.compile(r'gtag\s*\(\s*["\']config["\']'),        # Google Analytics
    re.compile(r'window\.dataLayer\s*='),               # GTM dataLayer
]

def is_noise_block(script_content: str) -> bool:
    """Return True if the script block is known noise (not worth scanning)"""
    if not script_content or len(script_content.strip()) < 20:
        return True
    for pattern in NOISE_BLOCK_PATTERNS:
        if pattern.search(script_content):
            return True
    return False


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

    def _extract_inline_scripts(self, html, page_url):
        """Extract inline <script> blocks, filtering out noise"""
        soup = BeautifulSoup(html, "html.parser")
        count = 0
        filtered = 0
        for i, tag in enumerate(soup.find_all("script", src=False)):
            content = tag.string or ""
            content = content.strip()
            if not content:
                continue
            if is_noise_block(content):
                filtered += 1
                continue
            key = f"[INLINE:{page_url}#{i}]"
            self.js_files[key] = content
            count += 1
        if filtered > 0:
            print(f"  [~] Filtered {filtered} noise script blocks from {page_url}")
        if count > 0:
            print(f"  [+] Extracted {count} inline scripts from {page_url}")

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
                    sources = sm.get("sourcesContent", [])
                    for i, src in enumerate(sources):
                        if src and len(src) > 50:
                            src_name = sm.get("sources", [f"source_{i}"])[i] if i < len(sm.get("sources", [])) else f"source_{i}"
                            key = f"[SOURCEMAP:{js_url}:{src_name}]"
                            self.js_files[key] = src
                            print(f"    [+] Source: {src_name} ({len(src):,} bytes)")
                except:
                    pass

    def _discover_webpack_chunks(self, js_content, base_url):
        """Try to discover webpack chunk files"""
        chunk_urls = set()
        patterns = [
            r'__webpack_require__\.p\s*\+\s*["\']([^"\']+\.js)["\']',
            r'chunkId\s*\+\s*["\']([^"\']+)["\']',
            r'["\']static/chunks/([^"\']+\.js)["\']',
            r'["\'](_next/static/[^"\']+\.js)["\']',
        ]
        for p in patterns:
            for match in re.findall(p, js_content):
                chunk_url = urljoin(base_url, match)
                chunk_urls.add(chunk_url)
        return chunk_urls

    def extract(self, visited=None, current_url=None, current_depth=0):
        if visited is None:
            visited = set()
        if current_url is None:
            current_url = self.base_url

        if current_url in visited or current_depth > self.depth:
            return

        visited.add(current_url)
        print(f"[*] Crawling: {current_url} (depth={current_depth})")

        html = self._fetch(current_url)
        if not html:
            return

        # Extract inline scripts (with noise filtering)
        self._extract_inline_scripts(html, current_url)

        # Extract JS file URLs
        js_urls = self._extract_js_urls(html, current_url)

        for js_url in js_urls:
            if js_url in visited:
                continue
            if urlparse(js_url).netloc != self.domain:
                continue
            visited.add(js_url)
            print(f"  [+] JS: {js_url}")
            js_content = self._fetch(js_url)
            if js_content:
                self.js_files[js_url] = js_content
                self._check_sourcemap(js_url, js_content)
                chunk_urls = self._discover_webpack_chunks(js_content, js_url)
                for chunk_url in chunk_urls:
                    if chunk_url not in visited:
                        visited.add(chunk_url)
                        chunk_content = self._fetch(chunk_url)
                        if chunk_content:
                            self.js_files[chunk_url] = chunk_content
                            print(f"    [+] Chunk: {chunk_url}")

        # Crawl linked pages
        if current_depth < self.depth:
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.find_all("a", href=True):
                href = urljoin(current_url, a["href"])
                parsed = urlparse(href)
                if parsed.netloc == self.domain and href not in visited:
                    self.extract(visited, href, current_depth + 1)

    def get_all(self):
        return self.js_files
