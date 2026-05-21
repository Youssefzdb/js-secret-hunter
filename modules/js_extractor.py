#!/usr/bin/env python3
"""JS Extractor v3 - Deep crawl + sourcemap + webpack chunk discovery"""
import requests, re, json
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import urllib3
urllib3.disable_warnings()

COMMON_PATHS = [
    "/static/js/main.js", "/static/js/app.js", "/static/js/bundle.js",
    "/assets/js/app.js", "/assets/js/main.js", "/assets/bundle.js",
    "/js/app.js", "/js/main.js", "/js/bundle.js", "/js/index.js",
    "/dist/bundle.js", "/dist/app.js", "/dist/main.js",
    "/build/static/js/main.chunk.js", "/build/static/js/bundle.js",
    "/public/js/app.js", "/vendor/js/app.js",
    "/config.js", "/env.js", "/.env.js", "/settings.js",
    "/api/config", "/api/settings", "/api/env",
    "/robots.txt", "/sitemap.xml",
    "/webpack.config.js", "/next.config.js", "/nuxt.config.js",
    "/.well-known/security.txt",
]

class JSExtractor:
    def __init__(self, base_url, depth=3):
        self.base_url = base_url.rstrip("/")
        self.depth = depth
        self.domain = urlparse(base_url).netloc
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        })
        self.session.verify = False
        self.js_files = {}
        self.visited_pages = set()
        self.sourcemaps = {}

    def _get(self, url, timeout=10):
        try:
            r = self.session.get(url, timeout=timeout, allow_redirects=True)
            if r.status_code == 200:
                return r
        except:
            pass
        return None

    def _extract_js_urls(self, page_url, html):
        js_urls = set()
        try:
            soup = BeautifulSoup(html, "html.parser")

            # <script src>
            for tag in soup.find_all("script", src=True):
                js_urls.add(urljoin(page_url, tag["src"]))

            # Inline script content — look for dynamic imports and references
            for tag in soup.find_all("script"):
                text = tag.string or ""
                for match in re.findall(r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', text):
                    if "/" in match or match.endswith(".js"):
                        js_urls.add(urljoin(page_url, match))

            # data-src, data-main (RequireJS)
            for tag in soup.find_all(attrs={"data-main": True}):
                js_urls.add(urljoin(page_url, tag["data-main"]))

            # HTML comments sometimes reveal paths
            for comment in soup.find_all(string=lambda t: isinstance(t, str) and "<!--" in str(t)):
                for match in re.findall(r'["\']([^"\']*\.js)["\']', str(comment)):
                    js_urls.add(urljoin(page_url, match))

            # Inline references in HTML attributes
            for pattern in [
                r'(?:src|href|content|action)\s*=\s*["\']([^"\']*\.js(?:\?[^"\']*)?)["\']',
                r'require\s*\(["\']([^"\']+)["\']',
                r'import\s+.*?from\s+["\']([^"\']+)["\']',
                r'loadScript\s*\(["\']([^"\']+)["\']',
                r'document\.write\s*\(["\']<script[^>]*src=["\']([^"\']+)',
            ]:
                for match in re.findall(pattern, html, re.IGNORECASE):
                    if match.startswith(("http", "/")):
                        js_urls.add(urljoin(page_url, match))

        except Exception as e:
            pass
        return js_urls

    def _discover_webpack_chunks(self, js_content, base_url):
        """Discover webpack chunk files from main bundle"""
        chunks = set()

        # webpack chunk map: {0:"hash", 1:"hash2"...}
        chunk_maps = re.findall(
            r'\{(?:\d+\s*:\s*["\'][a-f0-9]{8,}["\'],?\s*){2,}\}', js_content
        )
        hashes = re.findall(r'"([a-f0-9]{8,20})"', " ".join(chunk_maps))

        # Common chunk naming patterns
        for i in range(20):
            for pattern in [
                f"/static/js/{i}.chunk.js",
                f"/static/js/{i}.js",
                f"/js/chunk-{i}.js",
                f"/dist/{i}.bundle.js",
            ]:
                chunks.add(urljoin(base_url, pattern))

        # Extract publicPath
        pub_path = re.search(r'__webpack_require__\.p\s*=\s*["\']([^"\']+)["\']', js_content)
        if pub_path:
            base = urljoin(base_url, pub_path.group(1))
            for h in hashes[:10]:
                chunks.add(f"{base}{h}.js")

        return chunks

    def _check_sourcemap(self, js_url, js_content):
        """Check for sourcemap and try to fetch it"""
        sm_match = re.search(r'//[#@]\s*sourceMappingURL=(.+)', js_content)
        if sm_match:
            sm_url_raw = sm_match.group(1).strip()
            if not sm_url_raw.startswith("data:"):
                sm_url = urljoin(js_url, sm_url_raw)
                r = self._get(sm_url)
                if r:
                    try:
                        sm_data = r.json()
                        sources = sm_data.get("sourcesContent", [])
                        source_names = sm_data.get("sources", [])
                        for i, content in enumerate(sources):
                            if content:
                                name = source_names[i] if i < len(source_names) else f"source_{i}"
                                self.sourcemaps[f"[SOURCEMAP:{name}]"] = content
                        if sources:
                            print(f"  [+] SourceMap! {len(sources)} source files extracted from {sm_url}")
                    except:
                        pass

    def _download_js(self, js_url):
        # Only download from same domain or subdomain
        parsed = urlparse(js_url)
        if parsed.netloc and self.domain not in parsed.netloc:
            # Allow known CDNs for secret detection
            cdn_whitelist = ["cdnjs", "unpkg", "jsdelivr", "googleapis", "gstatic", "cloudflare"]
            if not any(cdn in parsed.netloc for cdn in cdn_whitelist):
                return None
        r = self._get(js_url)
        if r and len(r.text) > 10:
            return r.text
        return None

    def _crawl_page(self, url, depth=0):
        if depth > self.depth or url in self.visited_pages:
            return set()
        self.visited_pages.add(url)
        js_urls = set()

        r = self._get(url)
        if not r:
            return js_urls

        js_urls.update(self._extract_js_urls(url, r.text))

        # Also crawl internal links (1 level)
        if depth < 1:
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = urljoin(url, a["href"])
                if urlparse(href).netloc == self.domain and href not in self.visited_pages:
                    js_urls.update(self._crawl_page(href, depth + 1))

        return js_urls

    def extract(self):
        print(f"[*] JS Extractor v3 — Deep scan: {self.base_url}")

        # 1. Crawl main page + linked pages
        js_urls = self._crawl_page(self.base_url)

        # 2. Try common paths
        print(f"[*] Probing {len(COMMON_PATHS)} common paths...")
        for path in COMMON_PATHS:
            js_urls.add(urljoin(self.base_url, path))

        # 3. Download all JS
        print(f"[*] Downloading {len(js_urls)} candidate JS files...")
        chunk_candidates = set()

        for js_url in js_urls:
            content = self._download_js(js_url)
            if content:
                size = len(content)
                fname = js_url.split("/")[-1][:50]
                print(f"  [+] {fname} ({size:,} bytes)")
                self.js_files[js_url] = content

                # Check sourcemaps
                self._check_sourcemap(js_url, content)

                # Discover webpack chunks
                chunks = self._discover_webpack_chunks(content, self.base_url)
                chunk_candidates.update(chunks)

        # 4. Download discovered chunks
        new_chunks = chunk_candidates - set(self.js_files.keys())
        if new_chunks:
            print(f"[*] Probing {len(new_chunks)} webpack chunks...")
            for url in list(new_chunks)[:50]:
                content = self._download_js(url)
                if content:
                    self.js_files[url] = content
                    print(f"  [+] Chunk: {url.split('/')[-1]} ({len(content):,} bytes)")

        # 5. Add sourcemap sources
        self.js_files.update(self.sourcemaps)

        print(f"\n[+] Total: {len(self.js_files)} JS files | {len(self.sourcemaps)} sourcemap sources")
        return self.js_files
