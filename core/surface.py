from dataclasses import dataclass, field
from typing import List, Set, Dict, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import queue
import threading
import time

@dataclass
class Endpoint:
    url: str
    method: str
    params: List[Dict[str, Any]] = field(default_factory=list)
    
    def get_template_id(self) -> str:
        """
        Generates a unique template ID for deduplication.
        Structure: METHOD:SCHEME://NETLOC/PATH?PARAM_KEYS
        """
        parsed = urlparse(self.url)
        # Sort param names to handle order differences
        param_names = sorted([p['name'] for p in self.params])
        param_str = ",".join(param_names)
        
        # Clean path (remove trailing slash for consistency if needed, but strict is usually safer)
        path = parsed.path
        
        return f"{self.method}:{parsed.scheme}://{parsed.netloc}{path}?{param_str}"

class SurfaceMapper:
    def __init__(self, http_client, depth=2, max_threads=20):
        self.http = http_client
        self.depth = depth
        self.visited_urls: Set[str] = set()
        self.visited_templates: Set[str] = set() # For endpoint deduplication
        self.visited_lock = threading.Lock()
        
        self.endpoints_queue = queue.Queue() # Output queue for scanner
        self.crawl_queue = queue.Queue()     # Internal queue for crawler (url, depth)
        self.scope_domain = ""
        self.max_threads = max_threads

    def start_crawl(self, start_url: str):
        parsed_scope = urlparse(start_url)
        self.scope_domain = parsed_scope.netloc
        
        # Add seed to visited so we don't loop immediately
        with self.visited_lock:
            self.visited_urls.add(start_url)
        self.crawl_queue.put((start_url, 0))
        
        threads = []
        for _ in range(self.max_threads):
            t = threading.Thread(target=self._worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        self.crawl_queue.join()

    def _worker(self):
        while True:
            try:
                item = self.crawl_queue.get(timeout=2)
            except queue.Empty:
                continue

            url, depth = item
            try:
                self._process_url(url, depth)
            finally:
                self.crawl_queue.task_done()

    def _process_url(self, url: str, current_depth: int):
        # 1. Fetch
        try:
            resp = self.http.request("GET", url)
            if not resp:
                return
        except: return

        # 2. Extract Vulnerability Surface -> Smart Deduplication
        self._extract_surface(url, resp)

        # 3. Extract Links -> Send to Crawler
        if current_depth < self.depth:
            self._extract_links(url, resp, current_depth)

    def _extract_surface(self, url: str, resp):
        # 1. URL Parameters
        parsed = urlparse(url)
        query_params = []
        if parsed.query:
            for pair in parsed.query.split('&'):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    query_params.append({'name': k, 'type': 'query', 'value': v})
        
        # Even if no params, we scan the endpoint (headers, etc)
        ep = Endpoint(url=url, method="GET", params=query_params)
        self._add_endpoint_if_new(ep)

        # 2. Forms
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action", ""))
                method = form.get("method", "get").upper()
                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        inputs.append({'name': name, 'type': inp.get("type", "text"), 'value': inp.get("value", "")})
                
                ep = Endpoint(url=action, method=method, params=inputs)
                self._add_endpoint_if_new(ep)
        except:
            pass

    def _add_endpoint_if_new(self, endpoint: Endpoint):
        template_id = endpoint.get_template_id()
        with self.visited_lock:
            if template_id not in self.visited_templates:
                self.visited_templates.add(template_id)
                self.endpoints_queue.put(endpoint)

    def _extract_links(self, base_url: str, resp, current_depth: int):
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link['href']
                full_url = urljoin(base_url, href).split('#')[0]
                
                parsed = urlparse(full_url)
                
                # Scope Check
                if parsed.netloc == self.scope_domain:
                    # Skip static files for CRAWLING (but they might be useful for scanning if directly linked)
                    # We rely on visited check mostly.
                    with self.visited_lock:
                        if full_url not in self.visited_urls:
                            self.visited_urls.add(full_url)
                            self.crawl_queue.put((full_url, current_depth + 1))
        except:
            pass