from sdk.base_plugin import BasePlugin
import re
import json
import base64

class HTMLInjectionPlugin(BasePlugin):
    """
    HTML Injection (Content Spoofing).
    Checks if HTML tags are reflected without execution (unlike XSS).
    """
    name = "HTML Injection"
    
    PAYLOAD = "<h1>vortex_header</h1>"
    
    def should_run(self, endpoint):
        return len(endpoint.params) > 0

    def detect(self, http, endpoint, payload_intel):


        findings = []
        try:
            base_params = {p['name']: p['value'] for p in endpoint.params}
        except: return

        for param in endpoint.params:
            fuzzed = base_params.copy()
            fuzzed[param['name']] = self.PAYLOAD
            
            try:
                resp = self._make_request(http, endpoint, fuzzed)
                if not resp: continue
                
                # Check for raw reflection of the H1 tag
                if self.PAYLOAD in resp.text:
                     findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'parameter': param['name'], 'payload': self.PAYLOAD, 'evidence': "HTML Tag reflected (Content Spoofing})",
                        confidence="MEDIUM"
                    )
            except: continue
        return findings

    def _make_request(self, http, endpoint, params):
        if endpoint.method == "POST":
            return http.request("POST", endpoint.url, data=params)
        return http.request("GET", endpoint.url, params=params)


# filename: plugins/deser.py
from sdk.base_plugin import BasePlugin
import re