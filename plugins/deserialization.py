from sdk.base_plugin import BasePlugin
import re
import json
import base64

class DeserializationPlugin(BasePlugin):
    """
    Insecure Deserialization (Passive & Active).
    Checks for serialized data signatures and attempts basic error triggering.
    """
    name = "Insecure Deserialization"

    # Signatures of serialized objects
    SIGS = {
        "Java": r"rO0AB",  # Base64 encoded Java serialization header
        "PHP": r"O:\d+:\"" # PHP Object pattern e.g. O:4:"User"
    }

    def should_run(self, endpoint):
        return True

    def detect(self, http, endpoint, payload_intel):


        findings = []
        # 1. Passive Check (Look for serialized data in current baseline)
        try:
            resp = http.request(endpoint.method, endpoint.url) # Refresh
            if not resp: return
            
            for lang, pattern in self.SIGS.items():
                if re.search(pattern, resp.text):
                     findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'payload': None, 'evidence': f"Serialized {lang} object detected in response", 'confidence': "MEDIUM", 'details': "Application handles serialized objects."})
        except: pass
        
        # 2. Active Error Check (PHP)
        # Injecting a malformed object often triggers "unserialize()" errors
        if len(endpoint.params) > 0:
            try:
                base_params = {p['name']: p['value'] for p in endpoint.params}
                for param in endpoint.params:
                    fuzzed = base_params.copy()
                    # Inject broken PHP object
                    fuzzed[param['name']] = 'O:4:"Test":1:{s:4:"test";}' 
                    
                    req = self._make_request(http, endpoint, fuzzed)
                    if req and ("unserialize()" in req.text or "PHP Notice" in req.text):
                        findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'parameter': param['name'], 'payload': "PHP Object Injection", 'evidence': "PHP Deserialization error triggered", 'confidence': "HIGH"})
            except: pass
        return findings

    def _make_request(self, http, endpoint, params):
        if endpoint.method == "POST":
            return http.request("POST", endpoint.url, data=params)
        return http.request("GET", endpoint.url, params=params)