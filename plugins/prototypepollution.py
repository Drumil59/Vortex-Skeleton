from .base import BasePlugin
import re
import json
import base64

class PrototypePollutionPlugin(BasePlugin):
    """
    Server-Side Prototype Pollution detection (NodeJS).
    """
    name = "Prototype Pollution"

    def should_run(self, endpoint):
        # Only applicable to JSON APIs (POST/PUT)
        return endpoint.method in ["POST", "PUT"]

    def run(self, http, endpoint, analyzer, evidence):
        # Payload that attempts to poison the object prototype
        payload = {
            "__proto__": {
                "vortex_polluted": "true"
            }
        }
        
        try:
            # 1. Injection
            resp = http.request(endpoint.method, endpoint.url, json=payload)
            if not resp: return

            # 2. Verification
            # Requires a secondary request to see if the pollution reflected globally.
            # This is hard to detect blindly without crashing the server.
            # Safe Check: Reflection in response
            if "vortex_polluted" in resp.text and '"__proto__"' not in resp.text:
                 evidence.add(
                    plugin=self.name,
                    endpoint=endpoint.url,
                    payload="Object.prototype",
                    evidence="Potential Prototype Pollution (Reflection detected)",
                    confidence="LOW",
                    details="Manual verification required."
                )

        except: pass

# filename: plugins/clickjacking.py
from .base import BasePlugin