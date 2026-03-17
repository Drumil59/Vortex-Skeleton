from sdk.base_plugin import BasePlugin
import re
import json
import base64

class XPATHPlugin(BasePlugin):
    """
    XPATH Injection.
    Targets XML databases by manipulating XPATH queries.
    """
    name = "XPATH Injection"
    
    # Payload: ' or '1'='1
    # XPATH: ' or 1=1 or ''='
    PAYLOADS = ["' or '1'='1", "'] | //* | ['", "' or 1=1 or ''='"]

    def should_run(self, endpoint):
        return len(endpoint.params) > 0

    def detect(self, http, endpoint, payload_intel):


        findings = []
        try:
            base_params = {p['name']: p['value'] for p in endpoint.params}
            baseline = self._make_request(http, endpoint, base_params)
            if not baseline: return
        except: return

        for param in endpoint.params:
            for payload in self.PAYLOADS:
                fuzzed = base_params.copy()
                fuzzed[param['name']] = payload
                try:
                    resp = self._make_request(http, endpoint, fuzzed)
                    if not resp: continue
                    
                    # Detection: XPATH errors or logic bypass (length change)
                    if any(x in resp.text for x in self.ERRORS):
                         findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'parameter': param['name'], 'payload': payload, 'evidence': "XPath Error Detected", 'confidence': "HIGH"})
                         break
                except: continue
        return findings

    def _make_request(self, http, endpoint, params):
        if endpoint.method == "POST":
            return http.request("POST", endpoint.url, data=params)
        return http.request("GET", endpoint.url, params=params)