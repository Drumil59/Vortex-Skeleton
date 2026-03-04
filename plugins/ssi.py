from .base import BasePlugin
import re
import json
import base64

class SSIPlugin(BasePlugin):
    """
    Server-Side Include (SSI) Injection.
    Targeting .shtml or misconfigured servers to execute commands via HTML comments.
    """
    name = "SSI Injection"
    
    # Payload tries to print the date or file info
    PAYLOAD = '<!--#echo var="DATE_LOCAL" -->'

    def should_run(self, endpoint):
        return len(endpoint.params) > 0

    def run(self, http, endpoint, analyzer, evidence):
        try:
            base_params = {p['name']: p['value'] for p in endpoint.params}
        except: return

        for param in endpoint.params:
            fuzzed = base_params.copy()
            fuzzed[param['name']] = self.PAYLOAD
            
            try:
                resp = self._make_request(http, endpoint, fuzzed)
                if not resp: continue
                
                # Check for regex date pattern or just if the tag disappeared but result appeared?
                # Simplest check: Looking for a date format is hard with regex in simple plugins.
                # However, if the server evaluates it, the PAYLOAD string won't be there, 
                # but the RESULT will. 
                # Better payload for detection: <!--#printenv --> which dumps env vars.
                
                payload_env = '<!--#printenv -->'
                fuzzed[param['name']] = payload_env
                resp_env = self._make_request(http, endpoint, fuzzed)
                
                if resp_env and ("HTTP_USER_AGENT" in resp_env.text or "DOCUMENT_ROOT" in resp_env.text):
                     evidence.add(
                        plugin=self.name,
                        endpoint=endpoint.url,
                        parameter=param['name'],
                        payload=payload_env,
                        evidence="SSI execution confirmed (Environment variables printed)",
                        confidence="CRITICAL"
                    )

            except: continue

    def _make_request(self, http, endpoint, params):
        if endpoint.method == "POST":
            return http.request("POST", endpoint.url, data=params)
        return http.request("GET", endpoint.url, params=params)


# filename: plugins/crlf.py
from .base import BasePlugin