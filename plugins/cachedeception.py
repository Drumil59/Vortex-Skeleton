from .base import BasePlugin
import re
import json
import base64

class CacheDeceptionPlugin(BasePlugin):
    """
    Web Cache Deception.
    Checks if a dynamic page (e.g. /profile) can be accessed with a static extension
    (e.g. /profile/x.css) while retaining private data, potentially tricking caches.
    """
    name = "Web Cache Deception"

    def should_run(self, endpoint):
        return endpoint.method == "GET"

    def run(self, http, endpoint, analyzer, evidence):
        try:
            # 1. Baseline: Get the normal page
            baseline = http.request("GET", endpoint.url)
            if not baseline: return
            
            # If baseline isn't a 200 OK dynamic page, skip
            if baseline.status_code != 200: return

            # 2. Attack: Append /nonexistent.css
            target = f"{endpoint.url.rstrip('/')}/vortex_test.css"
            resp = http.request("GET", target)
            
            if not resp: return

            # Detection conditions:
            # 1. Status is 200 OK (Server ignored the .css suffix and served the page)
            # 2. Content matches the baseline (Dynamic content served)
            # 3. Headers indicate caching might happen (e.g. Cache-Control: public) or missing no-cache
            
            if resp.status_code == 200 and len(resp.text) == len(baseline.text):
                
                # Check for private data markers (heuristic)
                # If the page contains "Welcome, User" or similar, it's critical.
                
                cc = resp.headers.get("Cache-Control", "").lower()
                if "no-cache" not in cc and "no-store" not in cc:
                     evidence.add(
                        plugin=self.name,
                        endpoint=endpoint.url,
                        payload="/vortex_test.css",
                        evidence="Dynamic page served as static asset with loose caching",
                        confidence="MEDIUM",
                        details="CDN might cache this private page."
                    )
        except: pass