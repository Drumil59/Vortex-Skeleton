from sdk.base_plugin import BasePlugin
import re
import json
import base64

class MethodTamperingPlugin(BasePlugin):
    """
    Checks if access controls can be bypassed by changing HTTP methods.
    """
    name = "HTTP Method Tampering"

    def should_run(self, endpoint):
        return True

    def detect(self, http, endpoint, payload_intel):


        findings = []
        if endpoint.method not in ["GET", "POST"]:
            return

        try:
            # Baseline request
            baseline = http.request(endpoint.method, endpoint.url)
            if not baseline or baseline.status_code != 403: 
                # Only interesting if the resource is protected or restricted
                return 
        except Exception:
            return

        # Try bypassing with HEAD, PUT, or fake methods
        alternatives = ["HEAD", "PUT", "TRACE", "OPTIONS", "INVENTED"]
        
        for method in alternatives:
            try:
                resp = http.request(method, endpoint.url)
                if not resp: continue

                # If we get a 200 OK on a previously 403 Forbidden resource
                if resp.status_code == 200 and baseline.status_code == 403:
                     findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'payload': method, 'evidence': f"Auth bypass via HTTP Method: {method} yielded 200 OK", 'confidence': "HIGH"})
            except Exception:
                continue

# filename: plugins/api.py
        return findings

from sdk.base_plugin import BasePlugin