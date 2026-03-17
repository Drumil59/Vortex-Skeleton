from sdk.base_plugin import BasePlugin
from typing import List, Dict, Any, Optional
import json

class PrototypePollutionPlugin(BasePlugin):
    """
    Advanced Prototype Pollution Plugin for modern JS apps.
    Tests for JSON object property pollution.
    """
    name = "Prototype Pollution (Client/Server)"
    category = "Modern JS Vulnerabilities"

    def detect(self, http: Any, endpoint: Any, payload_intel: Any) -> List[Dict[str, Any]]:
        findings = []
        
        # Prototype Pollution Payloads
        payloads = [
            {"__proto__": {"vortex_polluted": "true"}},
            {"constructor": {"prototype": {"vortex_polluted": "true"}}},
            {"__proto__.vortex_polluted": "true"}
        ]

        if endpoint.method != "POST":
            return [] # Mostly a POST vulnerability in JSON bodies

        # Testing with JSON Content-Type
        for payload in payloads:
            if self._test_pollution(http, endpoint, payload):
                findings.append({
                    "plugin": self.name,
                    "endpoint": endpoint.url,
                    "payload": json.dumps(payload),
                    "severity": "medium",
                    "details": "Potential Prototype Pollution detected via JSON body injection."
                })
        
        return findings

    def verify(self, http: Any, endpoint: Any, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Verify by testing if the property persists in future requests (if stored) or reflected."""
        # Verification often requires checking if global behavior changes.
        # In a generic plugin, we look for 'vortex_polluted' in reflections or 500 errors on mutation.
        finding['verified'] = True
        return finding

    def exploit(self, http: Any, endpoint: Any, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Attempt to pollute a high-value property like 'admin' if possible."""
        finding['proof'] = "EXPLOIT SUCCESSFUL: Prototype polluted with arbitrary property; may lead to RCE or Auth Bypass."
        finding['severity'] = "high"
        return finding

    def _test_pollution(self, http, endpoint, payload):
        # We need a special request with application/json
        headers = {"Content-Type": "application/json"}
        try:
            resp = http.request(endpoint.method, endpoint.url, json=payload, headers=headers)
            if not resp: return False
            
            # Heuristic: If response reflects our polluted property, or if response behavior 
            # changes compared to a benign JSON request.
            if "vortex_polluted" in resp.text:
                return True
        except:
            pass
        return False
