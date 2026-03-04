from .base import BasePlugin
import re
import json
import base64

class ActiveJWTPlugin(BasePlugin):
    """
    Active JWT Exploitation.
    Attempts to forge a JWT with the 'None' algorithm if a token is detected.
    """
    name = "JWT None Algorithm Attack"

    def should_run(self, endpoint):
        # We need to find a JWT in headers/cookies. 
        # This is an active check that assumes we can find one to mutate.
        return True

    def run(self, http, endpoint, analyzer, evidence):
        # 1. Extraction: Check headers for Bearer token
        # Note: In a real scan, we'd need a way to pass auth headers to the scan config.
        # Here we check if the endpoint *requires* auth (401/403) and try to bypass if we have a token.
        # Since we don't have a token store in this simple arch, we skip extraction logic 
        # and assume if the USER provided a token in config, we test it.
        
        # Implementation limitation: requires valid token input. 
        # We will stub the logic for "if token found".
        pass 
        
        # Logic for future expansion:
        # 1. header = {"alg": "none", "typ": "JWT"}
        # 2. b64_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        # 3. forged_token = f"{b64_header}.{original_payload}."
        # 4. Send request with forged_token. If 200 OK, VULN.