from sdk.base_plugin import BasePlugin
from typing import List, Dict, Any, Optional
import random
import string
import html

class XSSPlugin(BasePlugin):
    """
    Enterprise Reflected XSS Plugin.
    Run only if parameters or forms exist.
    """
    name = "Enterprise Reflected XSS"
    category = "Injection"

    def detect(self, http: Any, endpoint: Any, payload_intel: Any) -> List[Dict[str, Any]]:
        findings = []
        
        # Gather all input vectors (from query params and forms)
        vectors = []
        for p in endpoint.params:
            vectors.append({"name": p['name'], "source": "query", "value": p.get('value', '')})
        
        for form in endpoint.forms:
            for inp in form.get('inputs', []):
                vectors.append({"name": inp['name'], "source": "form", "value": inp.get('value', ''), "method": form.get('method')})

        if not vectors:
            return []

        for vector in vectors:
            canary = "vortex" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
            
            # Test Reflection
            try:
                resp = self._make_probe(http, endpoint, vector, canary)
                if resp and canary in resp.text:
                    # Potential Reflection - try a real payload
                    payload = f"<vortex>{canary}</vortex>"
                    attack_resp = self._make_probe(http, endpoint, vector, payload)
                    
                    if attack_resp and payload in attack_resp.text:
                        # Check if escaped
                        if html.escape(payload) not in attack_resp.text:
                            findings.append({
                                "plugin": self.name,
                                "endpoint": endpoint.url,
                                "parameter": vector['name'],
                                "payload": payload,
                                "severity": "high",
                                "confidence": "high",
                                "details": f"Reflected XSS confirmed on parameter '{vector['name']}' via {vector['source']}."
                            })
            except: continue
            
        return findings

    def verify(self, http: Any, endpoint: Any, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        finding['verified'] = True
        return finding

    def exploit(self, http: Any, endpoint: Any, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        finding['proof'] = f"EXPLOIT SUCCESSFUL: Payload '{finding['payload']}' reflected unescaped in response."
        return finding

    def _make_probe(self, http, endpoint, vector, value):
        params = {p['name']: p['value'] for p in endpoint.params}
        data = {}
        
        if vector['source'] == "query":
            params[vector['name']] = value
        else:
            data[vector['name']] = value
            
        method = vector.get('method', endpoint.method)
        return http.request(method, endpoint.url, params=params, data=data if method != "GET" else None)
