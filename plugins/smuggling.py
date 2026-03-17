from sdk.base_plugin import BasePlugin

class RequestSmugglingPlugin(BasePlugin):
    """
    HTTP Request Smuggling Detection (Heuristic).
    Checks for CL.TE and TE.CL signatures.
    """
    name = "HTTP Request Smuggling"

    def should_run(self, endpoint):
        # Run on root or once per domain preferably, but here per endpoint is okay
        return endpoint.method == "GET"

    def detect(self, http, endpoint, payload_intel):


        findings = []
        # This is a passive/active check that requires careful header manipulation.
        # Python 'requests' library often normalizes headers, making this difficult.
        # We will try to send conflicting headers and look for 500 errors or timeouts 
        # which often indicate desync issues in the frontend/backend chain.
        
        try:
            # 1. CL.TE Probe (Content-Length takes precedence?)
            # We are just checking if the server TOLERATES conflicting headers, 
            # which is a prerequisite.
            
            headers = {
                "Transfer-Encoding": "chunked",
                "Content-Length": "3" # Conflicting
            }
            
            # Note: Standard requests lib might override CL. 
            # We use a simple heuristic: Does the server respond abnormally to T-E chunked?
            
            resp = http.request("POST", endpoint.url, headers=headers, data="1\r\nZ\r\n0\r\n\r\n")
            
            if resp and resp.status_code >= 500:
                 findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'payload': "Conflicting CL and TE headers", 'evidence': "Server returned 5xx error to potential smuggling probe", 'confidence': "LOW", 'details': "The server struggled with conflicting Content-Length and Transfer-Encoding headers."})
            
            # 2. TE.CL Probe
            headers2 = {
                "Transfer-Encoding": "chunked",
                # We let requests set CL usually, but we try to malform TE
                "Transfer-Encoding ": "chunked" # Space obfuscation
            }
            
            resp2 = http.request("POST", endpoint.url, headers=headers2, data="0\r\n\r\n")
            if resp2 and resp2.status_code >= 500:
                 findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'payload': "Obfuscated TE header", 'evidence': "Server returned 5xx error to obfuscated Transfer-Encoding", 'confidence': "LOW"})

        except Exception:
            pass
        return findings