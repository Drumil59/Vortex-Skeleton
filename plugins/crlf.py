from sdk.base_plugin import BasePlugin
import re
import json
import base64

class CRLFPlugin(BasePlugin):
    """
    CRLF Injection (HTTP Response Splitting).
    Injecting newline characters to add malicious headers (Set-Cookie).
    """
    name = "CRLF Injection"
    
    # %0d%0a is \r\n
    PAYLOAD = "vortex%0d%0aSet-Cookie: vortex_crlf=1"

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
                
                # Check headers for the injected cookie
                # Note: Requests library merges headers, so we check existence
                headers = resp.headers
                
                # Usually Set-Cookie is a list or string
                # This is a high-bar check. If the server is vulnerable, 
                # it parses the second line as a header.
                
                cookie_header = headers.get("Set-Cookie", "")
                if "vortex_crlf=1" in str(cookie_header):
                     findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'parameter': param['name'], 'payload': self.PAYLOAD, 'evidence': "Injected Set-Cookie header found via CRLF", 'confidence': "HIGH"})

            except: continue
        return findings

    def _make_request(self, http, endpoint, params):
        if endpoint.method == "POST":
            return http.request("POST", endpoint.url, data=params)
        return http.request("GET", endpoint.url, params=params)