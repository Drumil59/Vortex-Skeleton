from .base import BasePlugin
import re
import json
import base64

class HPPPlugin(BasePlugin):
    """
    HTTP Parameter Pollution (HPP).
    Injects duplicate parameters to test for precedence logic flaws.
    """
    name = "HTTP Parameter Pollution"

    def should_run(self, endpoint):
        return len(endpoint.params) > 0

    def run(self, http, endpoint, analyzer, evidence):
        try:
            base_params = {p['name']: p['value'] for p in endpoint.params}
            baseline = self._make_request(http, endpoint, base_params)
            if not baseline: return
        except: return

        for param in endpoint.params:
            # We construct a raw query string or body with duplicates
            # Current HTTPClient might deduplicate dicts, so we handle query params manually if needed.
            # For simplicity in this architecture, we attempt to send a list if supported 
            # or rely on the fact that we are injecting the *name* with the second value.
            
            # Technique: param=val1&param=vortex_polluted
            try:
                # Manual construction for HPP
                pname = param['name']
                
                # Check 1: Override Check
                # We inject a second value. If the response reflects the SECOND value 
                # but valid logic required the FIRST, we have pollution.
                
                # Since we can't easily check logic without knowing the app, 
                # we check for reflection or error.
                
                # We use a trick: param=original&param=polluted
                # This requires raw query manipulation which might be complex here.
                # Instead, we try to create a list which requests usually handles as param=1&param=2
                
                fuzzed = base_params.copy()
                fuzzed[pname] = [param['value'], "vortex_hpp"]
                
                resp = self._make_request(http, endpoint, fuzzed)
                if not resp: continue
                
                if "vortex_hpp" in resp.text:
                     evidence.add(
                        plugin=self.name,
                        endpoint=endpoint.url,
                        parameter=pname,
                        payload=f"{pname}={param['value']}&{pname}=vortex_hpp",
                        evidence="Polluted parameter value reflected (HPP)",
                        confidence="MEDIUM"
                    )

            except: continue

    def _make_request(self, http, endpoint, params):
        if endpoint.method == "POST":
            return http.request("POST", endpoint.url, data=params)
        return http.request("GET", endpoint.url, params=params)