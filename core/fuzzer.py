import logging
import concurrent.futures
from typing import List, Dict, Any
from .attack_surface_db import Endpoint
from .ai_attack_planner import AIAttackPlanner

class FuzzerEngine:
    """
    AI-Guided Offensive Fuzzing Engine.
    Prioritizes high-value parameters using AI recommendations.
    """
    def __init__(self, concurrency: int = 50):
        self.concurrency = concurrency
        self.logger = logging.getLogger("vortex.fuzzer")
        self.ai_planner = AIAttackPlanner()
        
        # AI-Preferred High-Impact Parameters
        self.ai_targets = ["id", "user_id", "admin", "debug", "cmd", "exec", "file", "url", "redirect"]

    def start(self, endpoints: List[Endpoint], http_client) -> List[Endpoint]:
        self.logger.info(f"[*] Starting AI-Guided Parameter Fuzzing on {len(endpoints)} endpoints.")
        discovered_endpoints = []
        
        # AI ANALYSIS: Rank endpoints before fuzzing
        ranked_endpoints = sorted(endpoints, key=lambda x: x.priority, reverse=True)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = []
            for ep in ranked_endpoints:
                # AI Suggestion: If priority is low, only test top targets
                target_params = self.ai_targets if ep.priority < 5 else self.ai_targets + ["token", "session", "cfg"]
                futures.append(executor.submit(self._ai_fuzz_params, ep, http_client, target_params))
                
            for future in concurrent.futures.as_completed(futures):
                try:
                    res = future.result()
                    if res: discovered_endpoints.extend(res)
                except Exception as e:
                    self.logger.debug(f"[AI Fuzzer] Error: {e}")
                    
        return discovered_endpoints

    def _ai_fuzz_params(self, endpoint: Endpoint, http, target_list: List[str]) -> List[Endpoint]:
        found = []
        try:
            baseline = http.request(endpoint.method, endpoint.url)
            if not baseline: return []
        except: return []

        for p in target_list:
            # AI Check: Skip if parameter is likely irrelevant for this endpoint type
            if "static" in endpoint.tags and p not in ["file", "path"]: continue
            
            try:
                canary = f"vortex_ai_{p}"
                params = {p: canary}
                
                resp = http.request(endpoint.method, endpoint.url, params=params if endpoint.method == "GET" else None, data=params if endpoint.method == "POST" else None)
                if not resp: continue
                
                # AI Behavioral Analysis
                if self._is_interesting_behavior(baseline, resp, canary):
                    self.logger.info(f"  [AI] Identified interesting parameter behavior: {p} on {endpoint.url}")
                    new_ep = Endpoint(url=endpoint.url, method=endpoint.method, params=[{'name': p, 'type': 'ai_discovered', 'value': ''}], source="ai_fuzzer", priority=endpoint.priority + 5)
                    found.append(new_ep)
            except: pass
            
        return found

    def _is_interesting_behavior(self, baseline, current, canary) -> bool:
        """AI-heuristic for behavior change."""
        if canary in current.text: return True
        if current.status_code != baseline.status_code: return True
        # Length delta > 10%
        delta = abs(len(current.text) - len(baseline.text))
        if delta > (len(baseline.text) * 0.1): return True
        return False
