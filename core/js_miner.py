import re
import logging
from typing import List, Set
from .attack_surface_db import Endpoint

class JSMiner:
    """
    Advanced JS Mining Engine.
    Scans JS files for API routes, hidden parameters, and network request patterns.
    """
    def __init__(self, normalizer, http_client):
        self.normalizer = normalizer
        self.http = http_client
        self.logger = logging.getLogger("vortex.js_miner")
        
        # Comprehensive Regex for endpoints and JS request patterns
        self.patterns = [
            r'(?:"|\')((?:/|[a-zA-Z]+://)[^"\'\s<>]+)(?:"|\')', # General links
            r'/api/v[0-9]/[a-zA-Z0-9\-/]+',                    # API routes
            r'fetch\([\'"]([^\'"]+)[\'"]',                      # fetch()
            r'axios\.(?:get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]', # axios()
            r'\.open\([\'"](?:GET|POST)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]'   # XMLHttpRequest
        ]

    def mine(self, js_url: str) -> List[Endpoint]:
        """Downloads and scans a JS file for endpoints."""
        discovered = []
        try:
            resp = self.http.request("GET", js_url)
            if not resp or resp.status_code != 200:
                return []

            content = resp.text
            for pattern in self.patterns:
                matches = re.findall(pattern, content)
                for m in matches:
                    normalized = self.normalizer.normalize(m, base_url=js_url)
                    if normalized and self.normalizer.is_http(normalized):
                        if self.normalizer.is_in_scope(normalized):
                            discovered.append(Endpoint(
                                url=normalized,
                                method="GET", # Default guess
                                source="js_miner",
                                tags={"js_discovered"}
                            ))
        except Exception as e:
            self.logger.debug(f"JS mining failed for {js_url}: {e}")
            
        return discovered
