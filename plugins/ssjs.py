from sdk.base_plugin import BasePlugin
import re
import json
import base64

class SSJSPlugin(BasePlugin):
    """
    Server-Side JavaScript Injection (Node.js).
    """
    name = "Server-Side JS Injection"
    
    # Node.js payloads
    PAYLOADS = [
        "res.end('vortex_ssjs')", 
        "response.end('vortex_ssjs')", 
        "console.log('vortex_ssjs')"
    ]

    def should_run(self, endpoint):
        return len(endpoint.params) > 0

    def detect(self, http, endpoint, payload_intel):


        findings = []
        try:
            base_params = {p['name']: p['value'] for p in endpoint.params}
        except: return

        for param in endpoint.params:
            for payload in self.PAYLOADS:
                fuzzed = base_params.copy()
                fuzzed[param['name']] = payload
                try:
                    resp = self._make_request(http, endpoint, fuzzed)
                    if not resp: continue
                    
                    # If we successfully ended the response with our string, it will be the ONLY content
                    # or at least present.
                    if "vortex_ssjs" in resp.text:
                        findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'parameter': param['name'], 'payload': payload, 'evidence': "Node.js SSJS execution confirmed", 'confidence': "CRITICAL"})
                        break
                except: continue
        return findings

    def _make_request(self, http, endpoint, params):
        if endpoint.method == "POST":
            return http.request("POST", endpoint.url, data=params)
        return http.request("GET", endpoint.url, params=params)