from .base import BasePlugin
import time

class SQLiPlugin(BasePlugin):
    name = "SQL Injection (Enterprise)"

    # Enterprise-Grade Payloads: High Fidelity, Low Noise
    # We focus on arithmetic evaluation and syntax breaking that works across DBs.
    PAYLOADS = [
        # Arithmetic Evaluation (Universal)
        # If '1'='1' works, and '1'='2' fails, we have high confidence.
        # But simply sending ' OR 1=1 is noisy.
        # We use pairs: (Payload, Expected_Result_Type)
        
        # 1. Syntax Breakers (Error Based)
        ("'", "error"),
        ('"', "error"),
        ("\\", "error"), # Backslash often escapes the next quote, causing error
        
        # 2. Boolean Logic (Blind)
        # We test: True Condition vs False Condition
        # If True == Baseline AND False != Baseline -> VULNERABLE
        ("' AND '1'='1", "true"),
        ("' AND '1'='2", "false"),
        ('" AND "1"="1', "true"),
        ('" AND "1"="2', "false")
    ]

    def should_run(self, endpoint):
        return len(endpoint.params) > 0

    def run(self, http, endpoint, analyzer, evidence):
        # 1. Establish Reliable Baseline
        try:
            base_params = {p['name']: p['value'] for p in endpoint.params}
            baseline = self._make_request(http, endpoint, base_params)
            if not baseline or baseline.status_code >= 400: return
        except: return

        # 2. Control Test (Stability Check)
        # We send a benign mutation. If response differs significantly from baseline,
        # the endpoint is dynamic/unstable and we should skip or reduce confidence.
        # We assume standard param is valid. 
        # Note: If valid is 123, we try 123 (no change).
        # To test stability, we just repeat the baseline request.
        
        confirmation = self._make_request(http, endpoint, base_params)
        if not confirmation: return
        
        # If baseline and confirmation differ wildly, abort.
        # Simple length check with small tolerance
        if abs(len(baseline.text) - len(confirmation.text)) > 50:
            return # Unstable endpoint

        for param in endpoint.params:
            if param['type'] in ['submit', 'button', 'image', 'reset']:
                continue

            param_name = param['name']
            
            # STATE: Tracks results for this parameter
            # We need both TRUE and FALSE payloads to work to confirm Blind SQLi
            blind_state = {"true": False, "false": False}

            for payload, check_type in self.PAYLOADS:
                # Optimized: If we already found an error, we can stop for this param
                # unless we want to confirm blind.
                
                fuzzed = base_params.copy()
                fuzzed[param_name] = payload
                
                try:
                    resp = self._make_request(http, endpoint, fuzzed)
                    if not resp: continue
                    
                    # Analysis 1: Error-Based (High Confidence)
                    if check_type == "error":
                        diff = analyzer.diff(baseline, resp)
                        if diff["heuristics"]:
                            # VERIFY: Repeat to ensure error is consistent
                            verify_resp = self._make_request(http, endpoint, fuzzed)
                            if verify_resp and analyzer.diff(baseline, verify_resp)["heuristics"]:
                                evidence.add(
                                    plugin=self.name,
                                    endpoint=endpoint.url,
                                    parameter=param_name,
                                    payload=payload,
                                    evidence=f"Persistent DB Error: {diff['heuristics'][0]}",
                                    confidence="HIGH",
                                    details=f"Database error confirmed on retry."
                                )
                                return # Move to next param/endpoint

                    # Analysis 2: Boolean-Blind (Medium/High Confidence)
                    # This requires correlating two requests (True vs False)
                    if check_type in ["true", "false"]:
                        # Diff against baseline
                        # We use a stricter diff here: 5% length variance tolerance
                        # because 'True' payload should be VERY close to baseline.
                        
                        is_diff = self._is_different(baseline, resp)
                        
                        if check_type == "true" and not is_diff:
                            blind_state["true"] = True
                        elif check_type == "false" and is_diff:
                            blind_state["false"] = True
                        
                        # Check logic
                        if blind_state["true"] and blind_state["false"]:
                            evidence.add(
                                plugin=self.name,
                                endpoint=endpoint.url,
                                parameter=param_name,
                                payload="Boolean Logic Pair",
                                evidence="Blind SQLi Confirmed (True/False logic holds)",
                                confidence="HIGH",
                                details="Response matched baseline for True payload, but differed for False payload."
                            )
                            return

                except Exception: continue

    def _make_request(self, http, endpoint, params):
        if endpoint.method == "POST":
            return http.request(endpoint.method, endpoint.url, data=params)
        return http.request(endpoint.method, endpoint.url, params=params)

    def _is_different(self, base, current):
        # 1. Status Code
        if base.status_code != current.status_code: return True
        
        # 2. Length (Dynamic Tolerance)
        # Allow 2% variation for dynamic content (ads, time, etc)
        tolerance = len(base.text) * 0.02
        if abs(len(base.text) - len(current.text)) > tolerance:
            return True
            
        return False
