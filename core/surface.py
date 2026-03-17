import re
import logging
import queue
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse, urlunparse
from bs4 import BeautifulSoup
from typing import List, Set, Dict, Any
from .attack_surface_db import Endpoint
from .js_miner import JSMiner
from .scope_filter import ScopeFilter
from .url_normalizer import URLNormalizer

class SurfaceMapper:
    """
    Scope-Aware Enterprise Crawler.
    Extracts real endpoints and filters via ScopeFilter.
    """
    def __init__(self, http_client, target_url: str, depth=3, max_threads=50):
        self.http = http_client
        self.depth = depth
        self.max_threads = max_threads
        self.visited_urls = set()
        self.endpoints_queue = queue.Queue()
        self.logger = logging.getLogger("vortex.surface")
        self.normalizer = URLNormalizer(target_url)
        self.js_miner = JSMiner(self.normalizer, http_client)
        self.scope_filter = ScopeFilter(target_url)
        
        # Regex for JS endpoint discovery
        self.js_endpoint_patterns = [
            r'fetch\([\'"]([^\'"]+)[\'"]',
            r'axios\.(?:get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]',
            r'\.open\([\'"](?:GET|POST)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]'
        ]

    def normalize_url(self, url: str) -> str:
        """Standardizes URL format: resolves relative paths, removes fragments."""
        try:
            parsed = urlparse(url)
            # Remove fragments
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ""))
        except Exception:
            return url

    def start_crawl(self, start_url: str):
        # 1. Register Root Endpoint Always
        root_url = self.normalize_url(start_url)
        self.logger.info(f"[*] Root endpoint added: {root_url}")
        self._add_endpoint(root_url, "root_registration")

        self.logger.info(f"[*] Starting Discovery on {root_url}")
        
        # 2. Try to parse sitemap.xml
        self._parse_sitemap(root_url)
        
        # 3. Start recursive crawl
        self._recursive_crawl(root_url, 0)

    def _parse_sitemap(self, start_url: str):
        parsed = urlparse(start_url)
        sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
        try:
            resp = self.http.request("GET", sitemap_url)
            if resp and resp.status_code == 200:
                self.logger.info(f"[+] Discovered sitemap.xml at {sitemap_url}")
                root = ET.fromstring(resp.text)
                ns = {'s': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
                for loc in root.findall('.//s:loc', ns):
                    url = self.normalize_url(loc.text)
                    self._add_endpoint(url, "sitemap")
        except Exception as e:
            self.logger.debug(f"Sitemap parsing failed: {e}")

    def _recursive_crawl(self, url: str, current_depth: int):
        if url in self.visited_urls or current_depth > self.depth:
            return
        
        self.visited_urls.add(url)
        try:
            resp = self.http.request("GET", url)
            if not resp or resp.status_code >= 400: return

            soup = BeautifulSoup(resp.text, "html.parser")
            links_count = 0
            forms_count = 0
            
            # 1. HTML Links (a href, link href)
            for tag in soup.find_all(["a", "link"], href=True):
                full_url = self.normalize_url(urljoin(url, tag['href']))
                self._add_endpoint(full_url, "crawler_link")
                links_count += 1
                # Recurse only if in scope
                if self.scope_filter.is_in_scope(full_url):
                    self._recursive_crawl(full_url, current_depth + 1)

            # 2. Script Sources (script src)
            for script in soup.find_all("script", src=True):
                js_url = self.normalize_url(urljoin(url, script['src']))
                self._add_endpoint(js_url, "crawler_script")
                self._mine_js(js_url)

            # 3. Form Actions
            for form in soup.find_all("form"):
                action = self.normalize_url(urljoin(url, form.get("action", "")))
                method = form.get("method", "GET").upper()
                params = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        params.append({'name': name, 'type': 'form', 'value': inp.get("value", "")})
                self._add_endpoint(action, "crawler_form", method, params)
                forms_count += 1

            self.logger.debug(f"Discovery at {url}: Links discovered: {links_count}, Forms discovered: {forms_count}")

        except Exception as e:
            self.logger.error(f"Crawl error on {url}: {e}")

    def _mine_js(self, js_url: str):
        try:
            resp = self.http.request("GET", js_url)
            if resp and resp.status_code == 200:
                self._extract_js_endpoints(resp.text, js_url)
        except: pass

    def _extract_js_endpoints(self, content: str, source_url: str):
        for pattern in self.js_endpoint_patterns:
            matches = re.findall(pattern, content)
            for m in matches:
                full_url = self.normalize_url(urljoin(source_url, m))
                self._add_endpoint(full_url, "js_analysis")

    def _add_endpoint(self, url: str, source: str, method="GET", params=None):
        if params is None: params = []
        ep = Endpoint(url=url, method=method, source=source, params=params)
        self.endpoints_queue.put(ep)
