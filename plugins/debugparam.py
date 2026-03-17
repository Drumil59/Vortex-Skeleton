from core.analyzer import ResponseAnalyzer
from sdk.base_plugin import BasePlugin
import re
import json
import base64

class DebugParamPlugin(BasePlugin):
    """
    Hidden Debug Parameter Discovery.
    Heuristic check for common developer flags.
    """
    name = "Hidden Debug Parameters"
    
    PARAMS = ["debug", "test", "admin", "admin_mode", "access", "root"]

    def should_run(self, endpoint):
        return True

    def detect(self, http, endpoint, payload_intel):


        findings = []


        analyzer = ResponseAnalyzer()
        try:
            # Baseline
            baseline = http.request(endpoint.method, endpoint.url)
            if not baseline: return

            for p in self.PARAMS:
                # Append to existing URL query
                sep = "&" if "?" in endpoint.url else "?"
                target = f"{endpoint.url}{sep}{p}=true"
                
                resp = http.request(endpoint.method, target)
                if not resp: continue
                
                diff = analyzer.diff(baseline, resp)
                
                # Significant change indicates the parameter is handled
                if diff["status_changed"] or diff["length_changed"]:
                     findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'payload': f"{p}=true", 'evidence': "Hidden parameter caused response change", 'confidence': "MEDIUM", 'diff': diff})

        except: pass
        return findings