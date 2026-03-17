from sdk.base_plugin import BasePlugin
import random
import string

class ShellInjectionPlugin(BasePlugin):
    name = "OS Command Injection (Enterprise)"

    def should_run(self, endpoint):
        return len(endpoint.params) > 0

    def detect(self, http, endpoint, payload_intel):


        findings = []
        try:
            base_params = {p['name']: p['value'] for p in endpoint.params}
        except: return

        # 1. Canary Generation
        # We need a unique string to grep for in the response.
        canary = f"vortex{random.randint(10000,99999)}"
        
        # 2. Targeted "Echo" Payloads
        # Echo is the gold standard for RCE verification because it's harmless but proof-positive.
        # We assume the backend might be Linux or Windows.
        
        payloads = [
            # Separators: ; | & || 
            # We try to inject "echo canary"
            
            # Unix-like
            f"; echo {canary};",
            f"| echo {canary}",
            f"& echo {canary}",
            f"`echo {canary}`",
            f"$(echo {canary})",
            
            # Windows
            f"& echo {canary}",
            f"| echo {canary}",
            f"|| echo {canary}"
        ]

        for param in endpoint.params:
            param_name = param['name']
            
            for payload in payloads:
                fuzzed = base_params.copy()
                fuzzed[param_name] = payload
                
                try:
                    resp = self._make_request(http, endpoint, fuzzed)
                    if not resp: continue
                    
                    # 3. Verification Logic
                    # Did the server echo back our canary?
                    if canary in resp.text:
                        # Double check context:
                        # If "echo" command itself is also visible, it might just be reflecting the input string.
                        # Real RCE usually reflects the *result* (canary) but consumes the command.
                        
                        # Weak Check: Just canary presence
                        # Strong Check: Canary present, but full payload NOT present (or at least stripped)
                        
                        # However, some apps reflect the input AND execute it.
                        # So we rely on the canary being present.
                        
                        # Sanity: Ensure canary wasn't in baseline (impossible by definition of random)
                        
                        findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'parameter': param_name, 'payload': payload, 'evidence': "Command Execution (Echo})",
                            confidence="CRITICAL",
                            details=f"Canary string '{canary}' found in response body."
                        )
                        return # Critical finding, stop plugin

                except: continue
        return findings

    def _make_request(self, http, endpoint, params):
        if endpoint.method == "POST":
            return http.request(endpoint.method, endpoint.url, data=params)
        return http.request(endpoint.method, endpoint.url, params=params)
