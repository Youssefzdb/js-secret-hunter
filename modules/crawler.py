#!/usr/bin/env python3
"""
JS Crawler — Discovers and fetches all JavaScript files from a target URL.
Handles: inline scripts, external JS, webpack chunks, Next.js, React builds.
"""
import re
import time
import urllib.parse
from collections import deque

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[-] Missing: pip install requests")
    raise

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}


class JSCrawler:
    def __init__(self, base_url: str, depth: int, timeout: int, logger):
        self.base_url  = base_url.rstrip("/")
        parsed         = urllib.parse.urlparse(base_url)
        self.base_host = parsed.netloc
        self.base_scheme = parsed.scheme
        self.depth     = depth
        self.timeout   = timeout
        self.log       = logger
        self.session   = self._make_session()
        self.js_files  = {}   # {url: content}

    def _make_session(self):
        s = requests.Session()
        s.headers.update(HEADERS)
        retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        s.mount("https://", HTTPAdapter(max_retries=retry))
        s.mount("http://",  HTTPAdapter(max_retries=retry))
        return s

    def _fetch(self, url: str) -> str | None:
        try:
            r = self.session.get(url, timeout=self.timeout, verify=False)
            if r.status_code == 200:
                return r.text
            self.log.debug(f"HTTP {r.status_code} for {url}")
        except requests.exceptions.ConnectionError:
            self.log.debug(f"Connection error: {url}")
        except requests.exceptions.Timeout:
            self.log.debug(f"Timeout: {url}")
        except Exception as e:
            self.log.debug(f"Error fetching {url}: {e}")
        return None

    def _to_absolute(self, href: str, page_url: str) -> str | None:
        try:
            full = urllib.parse.urljoin(page_url, href)
            parsed = urllib.parse.urlparse(full)
            if parsed.scheme in ("http", "https"):
                return full
        except Exception:
            pass
        return None

    def _extract_js_urls(self, html: str, page_url: str) -> list:
        urls = set()

        # Standard <script src="...">
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            href = m.group(1)
            if ".js" in href or href.endswith(".js"):
                url = self._to_absolute(href, page_url)
                if url:
                    urls.add(url)

        # JS references in quotes (webpack, Next.js, CRA)
        for m in re.finditer(r'["\`]([^"\'`\s<>]*\.js(?:\?[^"\'`\s<>]*)?)["\`]', html):
            href = m.group(1)
            if href.startswith("/") or href.startswith("./") or href.startswith("../"):
                url = self._to_absolute(href, page_url)
                if url:
                    urls.add(url)

        # Specific patterns: /_next/static/, /static/js/, /assets/
        for m in re.finditer(r'["\']((/_next/static|/static/js|/assets|/dist|/build)/[^\s"\'<>]+\.js[^\s"\'<>]*)["\']', html):
            url = self._to_absolute(m.group(1), page_url)
            if url:
                urls.add(url)

        return list(urls)

    def _extract_inline_scripts(self, html: str) -> list:
        scripts = []
        for m in re.finditer(r'<script(?:[^>]*)>([\s\S]*?)</script>', html, re.IGNORECASE):
            content = m.group(1).strip()
            if len(content) > 50:  # ignore tiny inline scripts
                scripts.append(content)
        return scripts

    def _extract_links(self, html: str, page_url: str) -> list:
        links = set()
        for m in re.finditer(r'href=["\']([^"\'#?]+)["\']', html, re.IGNORECASE):
            url = self._to_absolute(m.group(1), page_url)
            if url and urllib.parse.urlparse(url).netloc == self.base_host:
                links.add(url)
        return list(links)

    def run(self) -> dict:
        queue         = deque([(self.base_url, 0)])
        pages_visited = set()

        while queue:
            page_url, current_depth = queue.popleft()
            if page_url in pages_visited:
                continue
            pages_visited.add(page_url)

            self.log.debug(f"Visiting: {page_url}")
            html = self._fetch(page_url)
            if not html:
                continue

            # Collect inline scripts
            inline_scripts = self._extract_inline_scripts(html)
            for i, script in enumerate(inline_scripts):
                key = f"[INLINE:{page_url}#{i+1}]"
                if key not in self.js_files:
                    self.js_files[key] = script
                    self.log.debug(f"  📝 Inline script #{i+1} ({len(script)} chars)")

            # Collect external JS files
            js_urls = self._extract_js_urls(html, page_url)
            for js_url in js_urls:
                if js_url not in self.js_files:
                    self.log.info(f"  📄 {js_url.split('?')[0][-80:]}")
                    content = self._fetch(js_url)
                    if content:
                        self.js_files[js_url] = content
                    time.sleep(0.05)  # polite delay

            # Follow links for deeper crawl
            if current_depth < self.depth:
                for link in self._extract_links(html, page_url):
                    if link not in pages_visited:
                        queue.append((link, current_depth + 1))

        return self.js_files
