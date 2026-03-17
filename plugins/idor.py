from sdk.base_plugin import BasePlugin
import random
import string
import html

class IDORPlugin(BasePlugin):
    name = "IDOR (Enterprise)"

    def should_run(self, endpoint):
        return len(endpoint.params) > 0

    def detect(self, http, endpoint, payload_intel):


        findings = []
        try:
            base_params = {p['name']: p['value'] for p in endpoint.params}
            baseline = self._make_request(http, endpoint, base_params)
            if not baseline: return
        except: return

        # 1. Parameter Selection
        # Only fuzz potential IDs. We use a strong heuristic list.
        potential_ids = []
        for param in endpoint.params:
            if "id" in param['name'].lower() or "user" in param['name'].lower():
                potential_ids.append(param)
        
        if not potential_ids: return

        # 2. Control Test (Stability Check)
        # We need to know if the endpoint is dynamic (timestamps, random tokens).
        # We repeat the baseline request.
        control = self._make_request(http, endpoint, base_params)
        is_dynamic = self._is_different(baseline, control)

        for param in potential_ids:
            param_name = param['name']
            
            # 3. Strategy: Mutation
            # We try to change the ID.
            # If it's numeric, we increment/decrement.
            # If string, we append/prepend.
            
            orig_val = param['value']
            mutation = None
            
            if str(orig_val).isdigit():
                mutation = str(int(orig_val) + 1)
            else:
                mutation = f"{orig_val}_vortex"

            fuzzed = base_params.copy()
            fuzzed[param_name] = mutation
            
            try:
                resp = self._make_request(http, endpoint, fuzzed)
                if not resp: continue
                
                # 4. Analysis
                
                # Case A: Access Denied / Not Found (Safe)
                # If we get 403, 404, or redirect to login, it's safe.
                if resp.status_code in [403, 404, 401]:
                    continue
                
                # Case B: Identical Response (Unlikely IDOR)
                # If changing ID yields exact same page, the ID is probably ignored or mapped to same resource.
                if not self._is_different(baseline, resp):
                    continue

                # Case C: Valid 200 OK + Different Content
                # This is the Danger Zone.
                # But is it IDOR or just "User Not Found" error page returning 200?
                
                # We check for generic error strings
                error_sigs = ["not found", "does not exist", "invalid", "error", "oops"]
                if any(sig in resp.text.lower() for sig in error_sigs):
                    continue

                # If the endpoint was stable (control test passed), and we see a change,
                # it's likely we accessed a different record.
                confidence = "HIGH" if not is_dynamic else "MEDIUM"
                
                findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'parameter': param_name, 'payload': mutation, 'evidence': "IDOR / Access Control Bypass", 'confidence': confidence, 'details': f"Changed ID resulted in valid 200 OK response with unique content (Length Diff: {len(resp.text}) - len(baseline.text)})."
                )

            except: continue
        return findings

    def _make_request(self, http, endpoint, params):
        if endpoint.method == "POST":
            return http.request(endpoint.method, endpoint.url, data=params)
        return http.request(endpoint.method, endpoint.url, params=params)
    
    def _is_different(self, base, current):
        # 1. Status Code
        if base.status_code != current.status_code: return True
        
        # 2. Length (Dynamic Tolerance)
        # Allow 5% variation
        tolerance = len(base.text) * 0.05
        if abs(len(base.text) - len(current.text)) > tolerance:
            return True
            
        return False