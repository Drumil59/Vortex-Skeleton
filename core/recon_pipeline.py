import logging
import concurrent.futures
from typing import Dict, Any, List
from urllib.parse import urlparse

class ReconPipeline:
    """
    Automates bug bounty reconnaissance workflows.
    Orchestrates subdomain discovery, asset mapping, and endpoint mining.
    """
    def __init__(self, modules: Dict[str, Any], max_workers: int = 10):
        self.modules = modules
        self.logger = logging.getLogger("ReconPipeline")
        self.max_workers = max_workers

    def _process_subdomain(self, sub: str):
        target_url = f"https://{sub}"
        
        # API Discovery
        if 'api_discovery' in self.modules:
            api_eps = self.modules['api_discovery'].discover(target_url)
            for ep in api_eps: self.modules['db'].add_endpoint(ep)

        # Static & Dynamic Crawling
        visited_urls = []
        if 'static_crawler' in self.modules:
            self.modules['static_crawler'].start_crawl(target_url)
            while not self.modules['static_crawler'].endpoints_queue.empty():
                self.modules['db'].add_endpoint(self.modules['static_crawler'].endpoints_queue.get())
            visited_urls = list(self.modules['static_crawler'].visited_urls)
                
        if 'headless_crawler' in self.modules:
            dyn_eps = self.modules['headless_crawler'].start(target_url)
            for ep in dyn_eps: self.modules['db'].add_endpoint(ep)

        # JS Mining
        if 'js_miner' in self.modules and visited_urls:
            js_files = [url for url in visited_urls if url.endswith(".js")]
            for js_url in js_files:
                js_eps = self.modules['js_miner'].mine(js_url)
                for ep in js_eps: self.modules['db'].add_endpoint(ep)

    def run(self, target_domain: str) -> List[Any]:
        print(f"\n\033[94m[=] INITIATING BUG BOUNTY RECON PIPELINE: {target_domain}\033[0m")
        
        # 1. Subdomain Recon
        subdomains = []
        if 'subdomain_recon' in self.modules:
            print("[*] Stage 1: Subdomain Enumeration...")
            subdomains = self.modules['subdomain_recon'].start(target_domain)
            print(f"[+] Discovered {len(subdomains)} subdomains.")

        # Add base domain if not present
        if target_domain not in subdomains:
            subdomains = list(subdomains) + [target_domain]

        # 2. Asset Discovery & Endpoint Mining
        print(f"[*] Stage 2: Deep Asset Mapping & API Discovery across {len(subdomains)} targets...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self._process_subdomain, sub) for sub in subdomains]
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.logger.error(f"Error processing subdomain: {e}")

        all_endpoints = self.modules['db'].get_all()
        print(f"\n[+] Recon Pipeline Complete. Total unique endpoints: {len(all_endpoints)}")
        return all_endpoints
