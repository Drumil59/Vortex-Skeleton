from sdk.base_plugin import BasePlugin
import re
import json
import base64

class HostHeaderInjectionPlugin(BasePlugin):
    """
    Host Header Injection.
    Manipulates the Host header to trigger cache poisoning or link leakage.
    """
    name = "Host Header Injection"
    
    EVIL_HOST = "evil-vortex.com"

    def should_run(self, endpoint):
        return True

    def detect(self, http, endpoint, payload_intel):


        findings = []
        try:
            # Inject Malicious Host
            headers = {"Host": self.EVIL_HOST}
            resp = http.request(endpoint.method, endpoint.url, headers=headers)
            
            if not resp: return
            
            # Check for Reflection
            # 1. Absolute links (e.g. <a href="http://evil-vortex.com/...")
            # 2. Location headers (Redirects)
            
            if self.EVIL_HOST in resp.text or self.EVIL_HOST in resp.headers.get("Location", ""):
                 findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'payload': f"Host: {self.EVIL_HOST}", 'evidence': "Host header reflected in response body or Location header", 'confidence': "MEDIUM", 'details': "Potential for Cache Poisoning or Password Reset poisoning."})

        except: pass


# filename: plugins/ssi.py
        return findings

from sdk.base_plugin import BasePlugin