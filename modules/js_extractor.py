#!/usr/bin/env python3
"""
JS Extractor v3 — Deep crawl + source maps + webpack chunks + .env probe
"""
import requests, re, json
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import urllib3
urllib3.disable_warnings()

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.development", "/.env.staging",
    "/config.js", "/env.js", "/settings.js", "/app.config.js", "/runtime-config.js",
    "/js/config.js", "/js/env.js", "/src/config.js", "/public/config.js",
    "/api/config", "/api/env", "/api/settings",
    "/static/js/main.js", "/static/js/app.js", "/static/js/bundle.js",
    "/assets/js/app.js", "/assets/js/main.js",
    "/dist/bundle.js", "/dist/app.js", "/dist/main.js",
    "/build/static/js/main.chunk.js",
    "/_next/static/chunks/main.js", "/_next/static/chunks/pages/_app.js",
    "/wp-config.php", "/configuration.php",
    "/robots.txt", "/.well-known/security.txt",
    "/asset-manifest.json", "/webpack-manifest.json", "/manifest.json",
]

CRAWL_PAGES = [
    "/", "/login", "/register", "/signup", "/dashboard",
    "/about", "/contact", "/pricing", "/api", "/admin",
    "/app", "/home", "/index.html",
]

class JSExtractor:
    def __init__(self, base_url, depth=3):
        self.base_url = base_url.rstrip("/")
        self.depth = depth
        self.domain = urlparse(base_url).netloc
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
            "Accept-Language": "en-US,en;q=0.9",
        })
        self.session.verify = False
        self.js_files = {}
        self.visited = set()

    def _get(self, url, timeout=12):
        try:
            r = self.session.get(url, timeout=timeout, allow_redirects=True)
            if r.status_code == 200 and len(r.text) > 10:
                return r.text
        except:
            pass
        return None

    # ── Extract all JS URLs from a page ──────────────────────────────────
    def _extract_js_urls(self, html, base_url):
        urls = set()
        try:
            soup = BeautifulSoup(html, "html.parser")
            # <script src>
            for tag in soup.find_all("script", src=True):
                urls.add(urljoin(base_url, tag["src"]))
            # data-main (RequireJS)
            for tag in soup.find_all(attrs={"data-main": True}):
                urls.add(urljoin(base_url, tag["data-main"] + ".js"))
            # Inline patterns
            for pattern in [
                r'["\']([^"\']*?\.js(?:\?[^"\']*)?)["\']',
                r'import\s+[^"\']*?["\']([^"\']+\.js)["\']',
                r'require\s*\(["\']([^"\']+\.js)["\']',
                r'loadScript\s*\(["\']([^"\']+)["\']',
                r'\.src\s*=\s*["\']([^"\']+\.js)["\']',
                r'script\.setAttribute\s*\(["\']src["\'],\s*["\']([^"\']+)["\']',
            ]:
                for m in re.findall(pattern, html):
                    if m and not m.startswith("data:"):
                        full = urljoin(base_url, m)
                        if self.domain in urlparse(full).netloc or full.startswith("/"):
                            urls.add(full)
        except:
            pass
        return urls

    # ── Source map extraction ─────────────────────────────────────────────
    def _parse_sourcemap(self, js_url, js_content):
        m = re.search(r'//[#@]\s*sourceMappingURL=(.+)', js_content)
        if not m:
            return
        sm_ref = m.group(1).strip()
        if sm_ref.startswith("data:application/json"):
            try:
                b64 = sm_ref.split(",", 1)[1]
                import base64
                sm_data = json.loads(base64.b64decode(b64))
            except:
                return
        else:
            sm_url = urljoin(js_url, sm_ref)
            sm_raw = self._get(sm_url)
            if not sm_raw:
                return
            try:
                sm_data = json.loads(sm_raw)
            except:
                return

        sources = sm_data.get("sources", [])
        contents = sm_data.get("sourcesContent", [])
        count = 0
        for i, src in enumerate(contents):
            if src and len(src) > 50:
                name = sources[i] if i < len(sources) else f"src_{i}"
                key = f"[MAP:{js_url}|{name}]"
                self.js_files[key] = src
                count += 1
        if count:
            print(f"  [+] SourceMap: {count} original sources from {js_url.split('/')[-1]}")

    # ── Webpack chunk discovery ───────────────────────────────────────────
    def _discover_chunks(self, js_content, base_url):
        chunks = set()
        # chunk hash patterns
        for m in re.findall(r'["\']([a-f0-9]{8,20})["\']', js_content):
            for prefix in ["/static/js/", "/assets/js/", "/dist/"]:
                chunks.add(urljoin(base_url, f"{prefix}{m}.js"))
                chunks.add(urljoin(base_url, f"{prefix}{m}.chunk.js"))
        # numeric chunk IDs
        for m in re.findall(r'(?:chunkId|chunkIds?)\s*[=:]\s*(\d+)', js_content):
            for prefix in ["/static/js/", "/assets/js/"]:
                chunks.add(urljoin(base_url, f"{prefix}{m}.chunk.js"))
        # publicPath
        pp = re.search(r'__webpack_require__\.p\s*=\s*["\']([^"\']+)["\']', js_content)
        if pp:
            for m in re.findall(r'"([a-f0-9]{8,20})"', js_content)[:20]:
                chunks.add(urljoin(base_url, pp.group(1) + m + ".js"))
        return chunks

    # ── Crawl page and return all JS URLs ─────────────────────────────────
    def _crawl(self, url, depth=0):
        if depth > self.depth or url in self.visited:
            return set()
        self.visited.add(url)
        html = self._get(url)
        if not html:
            return set()
        js_urls = self._extract_js_urls(html, url)
        # Crawl internal links one level
        if depth < 1:
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.find_all("a", href=True):
                href = urljoin(url, a["href"])
                if urlparse(href).netloc == self.domain:
                    js_urls |= self._crawl(href, depth + 1)
        return js_urls

    # ── Probe sensitive paths ─────────────────────────────────────────────
    def _probe_sensitive(self):
        print("[*] Probing sensitive paths...")
        for path in SENSITIVE_PATHS:
            url = urljoin(self.base_url, path)
            content = self._get(url)
            if content:
                # Check it's not a 404 page
                has_secret_kw = any(k in content.lower() for k in
                    ["key", "secret", "password", "token", "api", "database", "db_"])
                if has_secret_kw or path.endswith(".js"):
                    self.js_files[f"[PROBE:{url}]"] = content
                    print(f"  [!] Found: {url} ({len(content):,} bytes)")

    # ── Main extract ──────────────────────────────────────────────────────
    def extract(self):
        print(f"[*] JS Extractor v3 — {self.base_url}")

        # 1. Crawl pages
        all_js = set()
        for page in [self.base_url] + [urljoin(self.base_url, p) for p in CRAWL_PAGES]:
            all_js |= self._crawl(page)
        print(f"  [+] Crawl: {len(all_js)} JS URLs found")

        # 2. Download JS + sourcemaps + chunks
        chunk_candidates = set()
        print(f"[*] Downloading JS files...")
        for js_url in all_js:
            content = self._get(js_url)
            if content:
                self.js_files[js_url] = content
                print(f"  [+] {js_url.split('/')[-1][:55]} ({len(content):,} bytes)")
                self._parse_sourcemap(js_url, content)
                chunk_candidates |= self._discover_chunks(content, self.base_url)

        # 3. Download webpack chunks (new only)
        new_chunks = chunk_candidates - set(self.js_files.keys())
        if new_chunks:
            print(f"[*] Probing {len(new_chunks)} webpack chunks...")
            for url in list(new_chunks)[:60]:
                content = self._get(url)
                if content:
                    self.js_files[url] = content
                    print(f"  [+] Chunk: {url.split('/')[-1][:40]} ({len(content):,} bytes)")

        # 4. Probe sensitive files
        self._probe_sensitive()

        total_bytes = sum(len(c) for c in self.js_files.values())
        print(f"\n[+] Total: {len(self.js_files)} sources | {total_bytes:,} bytes")
        return self.js_files
