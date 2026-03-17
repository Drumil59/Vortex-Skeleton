from typing import List, Dict, Any
import logging
import time

class BugBountyPipeline:
    """
    Enterprise Bug Bounty Automation Pipeline.
    Orchestrates reconnaissance, endpoint discovery, and distributed scanning.
    """
    def __init__(self, modules: Dict[str, Any]):
        self.logger = logging.getLogger("vortex.bugbounty")
        self.modules = modules # Dictionary containing initialized recon/scan modules
        self.stats = {"scanned_domains": 0, "findings": 0}

    def run(self, target_domain: str):
        """Executes the full automated offensive pipeline."""
        print(f"\n\033[94m[=] STARTING BUG BOUNTY PIPELINE: {target_domain}\033[0m")
        
        # 1. Subdomain Enumeration
        print("[*] Stage 1: Subdomain Enumeration")
        if 'subdomain_recon' in self.modules:
            subs = self.modules['subdomain_recon'].start(target_domain)
            print(f"  [+] Discovered {len(subs)} subdomains.")
            if not subs:
                subs = [target_domain]
        else:
            subs = [target_domain]

        # 2. HTTP Probing & Surface Mapping
        print("[*] Stage 2: Surface Mapping (Crawler + API Discovery)")
        for sub in list(subs):
            target_url = f"https://{sub}"
            print(f"[*] Mapping surface for: {target_url}")
            self._map_surface(target_url)

        # 3. Active Scanning (Distributed)
        print("[*] Stage 3: Distributed Vulnerability Scanning")
        self._execute_distributed_scan()

        # 4. Chain Correlation & Triage
        print("[*] Stage 4: AI Attack Path Discovery & Triage")
        self._analyze_attack_paths()

        print("\n\033[92m[+] PIPELINE EXECUTION COMPLETE.\033[0m")

    def _map_surface(self, url: str):
        """Discovers endpoints and populates the attack surface database."""
        try:
            # Static & Browser Crawling
            if 'static_crawler' in self.modules:
                self.modules['static_crawler'].start_crawl(url)
                while not self.modules['static_crawler'].endpoints_queue.empty():
                    ep = self.modules['static_crawler'].endpoints_queue.get()
                    if 'db' in self.modules:
                        self.modules['db'].add_endpoint(ep)
                    self.modules['static_crawler'].endpoints_queue.task_done()
            
            # API Discovery
            if 'api_discovery' in self.modules:
                api_eps = self.modules['api_discovery'].discover(url)
                if 'db' in self.modules:
                    for ep in api_eps:
                        self.modules['db'].add_endpoint(ep)
                if api_eps:
                    print(f"  [+] Discovered {len(api_eps)} API endpoints.")

            # JS Miner for hidden endpoints
            if 'js_miner' in self.modules:
                # Assuming the JS files were added to DB by crawler
                pass
        except Exception as e:
            self.logger.error(f"Error mapping {url}: {e}")

    def _execute_distributed_scan(self):
        """Submits endpoints to the distributed cluster for scanning."""
        if 'db' in self.modules and 'cluster' in self.modules:
            endpoints = self.modules['db'].get_all()
            for ep in endpoints:
                self.modules['cluster'].submit_task("plugin_scan", {"url": ep.url, "method": ep.method, "params": ep.params})

    def _analyze_attack_paths(self):
        """Identifies vulnerability relationships and chains."""
        if 'ai_attack_path' in self.modules and 'evidence' in self.modules:
            chains = self.modules['ai_attack_path'].discover(self.modules['evidence'].items)
            for chain in chains:
                print(f"  [!] Found Attack Chain: {chain}")
