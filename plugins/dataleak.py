from sdk.base_plugin import BasePlugin
import re
import json
import base64

class DataLeakPlugin(BasePlugin):
    """
    PII & Data Leakage.
    Scans for SSNs, Credit Cards, and Private Keys.
    """
    name = "PII Data Leakage"
    
    PATTERNS = {
        "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
        "Credit Card": r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
        "Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
        "AWS Key": r"AKIA[0-9A-Z]{16}"
    }

    def should_run(self, endpoint):
        return True

    def detect(self, http, endpoint, payload_intel):


        findings = []
        try:
            resp = http.request(endpoint.method, endpoint.url)
            if not resp: return
            
            for ptype, pattern in self.PATTERNS.items():
                matches = re.findall(pattern, resp.text)
                if matches:
                     findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'payload': None, 'evidence': f"Potential {ptype} leaked: {matches[0]}", 'confidence': "HIGH"})
        except: pass
        return findings