import logging
import concurrent.futures
from typing import List, Any, Dict
from .url_validator import URLValidator
from .scope_filter import ScopeFilter
from .form_analyzer import FormAnalyzer
from .response_analyzer import ResponseAnalyzer
from .request_engine import RequestEngine
from .attack_surface_db import Endpoint

class ScanEngine:
    """
    Context-Aware Offensive Orchestration Engine.
    Implements strict gates: Discovery -> Context Analysis -> Validated Scanning.
    """
    def __init__(self, evidence_store: Any, payload_intelligence: Any = None, cluster: Any = None):
        self.evidence = evidence_store
        self.payload_intel = payload_intelligence
        self.MAX_THREADS = 50
        self.logger = logging.getLogger("vortex.engine")
        self.form_analyzer = FormAnalyzer()
        self.response_analyzer = ResponseAnalyzer()
        self.validator = None
        self.scope_filter = None
        self.stats = {
            "endpoints_discovered": 0,
            "plugins_executed": 0,
            "valid_targets_count": 0
        }

    def run_pipeline(self, target_url: str, modules: Dict[str, Any], recon_mode: bool = False, debug: bool = False):
        self.logger.info(f"[*] INITIATING CONTEXT-AWARE SCAN: {target_url}")
        self.scope_filter = ScopeFilter(target_url)
        self.validator = URLValidator(modules['http'])
        
        # 1. Establish 404 baseline (random path)
        self.validator.establish_baseline(target_url)

        # 2. Surface Mapping & Discovery
        discovered_count = 0
        valid_endpoints = 0
        
        if 'static_crawler' in modules:
            self.logger.info("[*] Phase: Surface Mapping")
            modules['static_crawler'].start_crawl(target_url)
            
            while not modules['static_crawler'].endpoints_queue.empty():
                ep = modules['static_crawler'].endpoints_queue.get()
                discovered_count += 1
                
                # a. Scope Filter
                if not self.scope_filter.is_in_scope(ep.url):
                    if debug: self.logger.debug(f"[DEBUG] Out of scope: {ep.url}")
                    continue

                # b. Validation (Status Code & Soft-404)
                # SPECIAL CASE: Root URL is always valid if reachable
                is_root = ep.url.rstrip('/') == target_url.rstrip('/')
                if is_root or self.validator.validate(ep.url):
                    # c. Context Analysis (The Gate)
                    self._analyze_endpoint_context(ep, modules['http'])
                    
                    # Register in DB
                    modules['db'].add_endpoint(ep)
                    valid_endpoints += 1
                    if debug: self.logger.debug(f"[DEBUG] Valid endpoint added: {ep.url}")
                else:
                    if debug: self.logger.debug(f"[DEBUG] Rejected endpoint (Validation): {ep.url}")

        self.stats["endpoints_discovered"] = discovered_count
        
        # 3. Fallback: Ensure at least root endpoint is scannable
        all_targets = modules['db'].get_all()
        if not all_targets:
            self.logger.warning("[!] No endpoints discovered. Falling back to root target.")
            root_ep = Endpoint(url=target_url, method="GET", source="fallback")
            self._analyze_endpoint_context(root_ep, modules['http'])
            modules['db'].add_endpoint(root_ep)
            all_targets = [root_ep]
            valid_endpoints = 1

        self.stats["valid_targets_count"] = len(all_targets)
        self.logger.info(f"[+] Root endpoint added")
        self.logger.info(f"[+] Links discovered: {discovered_count}")
        self.logger.info(f"[+] Valid endpoints: {len(all_targets)}")
        
        # 4. Active Scanning
        if all_targets:
            self._local_parallel_scan(all_targets, modules)

    def _analyze_endpoint_context(self, endpoint: Any, http: Any):
        """Extracts forms, parameters, and API metadata to establish context."""
        resp = http.request("GET", endpoint.url)
        if resp and resp.status_code == 200:
            endpoint.forms = self.form_analyzer.extract_forms(endpoint.url, resp.text)
            if endpoint.forms:
                endpoint.tags.add("has_forms")
            
            # Simple API detection
            if "application/json" in resp.headers.get("Content-Type", ""):
                endpoint.is_api = True
                endpoint.tags.add("api")

    def _is_valid_attack_surface(self, ep: Any) -> bool:
        """Determines if endpoint has any fuzzeable components."""
        return ep.params or ep.forms or ep.is_api

    def _local_parallel_scan(self, endpoints: List[Any], modules: Dict[str, Any]):
        plugins = modules.get('plugins', [])
        http = modules.get('http')
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.MAX_THREADS) as executor:
            futures = []
            for ep in endpoints:
                # 1. Run Plugins
                for plugin in plugins:
                    if self._should_run_plugin(plugin, ep):
                        futures.append(executor.submit(self._run_plugin_safely, plugin, ep, http))
                
                # 2. Run Template Engine
                if 'template_engine' in modules:
                    futures.append(executor.submit(self._run_templates_safely, modules['template_engine'], ep, http))
            
            concurrent.futures.wait(futures)

    def _should_run_plugin(self, plugin: Any, ep: Any) -> bool:
        """The Context Gate: Ensures plugins only run when appropriate."""
        name = plugin.name.lower()
        
        if "csrf" in name and "has_forms" not in ep.tags:
            return False
        if "sqli" in name and not (ep.params or ep.forms or ep.is_api):
            return False
        if "xss" in name and not (ep.params or ep.forms):
            return False
            
        return True

    def _run_plugin_safely(self, plugin: Any, ep: Any, http: Any):
        try:
            plugin.run(http, ep, self.response_analyzer, self.evidence, self.payload_intel)
            self.stats["plugins_executed"] += 1
        except Exception as e:
            self.logger.error(f"Plugin {plugin.name} failed: {e}")

    def _run_templates_safely(self, engine: Any, ep: Any, http: Any):
        try:
            engine.run(http, ep, self.evidence)
        except Exception as e:
            self.logger.error(f"Template execution failed on {ep.url}: {e}")

    def get_summary(self) -> Dict[str, Any]:
        return {
            "validator_stats": self.validator.stats if self.validator else {},
            "scope_stats": self.scope_filter.stats if self.scope_filter else {},
            "vulnerabilities": len(self.evidence.items),
            "scan_stats": self.stats
        }
