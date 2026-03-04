from .base import BasePlugin
import re
import json
import base64

class FormulaPlugin(BasePlugin):
    """
    CSV / Formula Injection.
    Checks if input starting with = or @ is reflected, risking spreadsheet RCE.
    """
    name = "CSV/Formula Injection"
    
    PAYLOADS = ["=1+1", "@SUM(1+1)"]

    def should_run(self, endpoint):
        return len(endpoint.params) > 0

    def run(self, http, endpoint, analyzer, evidence):
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
                    
                    if resp.status_code == 200 and len(resp.text) > len(baseline.text):
                         evidence.add(
                            plugin=self.name,
                            endpoint=endpoint.url,
                            parameter=param['name'],
                            payload=payload,
                            evidence="CSV Injection payload accepted",
                            confidence="LOW",
                            details="The application accepts formula characters at the start of input."
                        )
                         break
                except: continue

    def _make_request(self, http, endpoint, params):
        if endpoint.method == "POST":
            return http.request("POST", endpoint.url, data=params)
        return http.request("GET", endpoint.url, params=params)