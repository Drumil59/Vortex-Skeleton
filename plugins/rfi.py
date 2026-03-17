from sdk.base_plugin import BasePlugin
import re
import json
import base64

class RFIPlugin(BasePlugin):
    """
    Remote File Inclusion (RFI).
    Distinct from LFI; attempts to load a remote URL.
    """
    name = "Remote File Inclusion (RFI)"
    
    # We use a Google URL as a safe canary. 
    # If the page includes Google's HTML, we have RFI.
    PAYLOAD = "http://www.google.com"

    def should_run(self, endpoint):
        return len(endpoint.params) > 0

    def detect(self, http, endpoint, payload_intel):


        findings = []
        try:
            base_params = {p['name']: p['value'] for p in endpoint.params}
        except: return

        for param in endpoint.params:
            pname = param['name'].lower()
            # Heuristic: Only try parameters that look like file/url inputs
            if not any(x in pname for x in ['file', 'path', 'include', 'page', 'view', 'doc']):
                continue

            fuzzed = base_params.copy()
            fuzzed[param['name']] = self.PAYLOAD
            
            try:
                resp = self._make_request(http, endpoint, fuzzed)
                if not resp: continue
                
                # Check for Google signature
                if "google" in resp.text and "schema.org" in resp.text:
                     findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'parameter': param['name'], 'payload': self.PAYLOAD, 'evidence': "Remote content (Google}) included in response",
                        confidence="CRITICAL"
                    )
            except: continue
        return findings

    def _make_request(self, http, endpoint, params):
        if endpoint.method == "POST":
            return http.request("POST", endpoint.url, data=params)
        return http.request("GET", endpoint.url, params=params)