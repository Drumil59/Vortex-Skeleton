from .base import BasePlugin
from urllib.parse import urlparse

class CORSPlugin(BasePlugin):
    name = "CORS Misconfiguration (Enterprise)"

    def should_run(self, endpoint):
        return True

    def run(self, http, endpoint, analyzer, evidence):
        try:
            parsed = urlparse(endpoint.url)
            base_domain = parsed.netloc
            evil_origin = "http://evil-vortex.com"
            
            # 1. Attack Request
            headers = {"Origin": evil_origin}
            resp = http.request(endpoint.method, endpoint.url, headers=headers)
            
            if not resp: return

            acao = resp.headers.get("Access-Control-Allow-Origin")
            acac = resp.headers.get("Access-Control-Allow-Credentials")

            # 2. Strict Verification
            # It must reflect OUR origin or be * (if no creds).
            if acao:
                if acao == evil_origin:
                    severity = "MEDIUM"
                    msg = f"Reflected Origin: {evil_origin}"
                    
                    if acac and acac.lower() == "true":
                        severity = "CRITICAL"
                        msg += " + Allow-Credentials: true"

                    evidence.add(
                        plugin=self.name,
                        endpoint=endpoint.url,
                        payload=f"Origin: {evil_origin}",
                        evidence=msg,
                        confidence=severity,
                        details="Server explicitly trusts arbitrary origin."
                    )
                
                elif acao == "*" and acac and acac.lower() == "true":
                    evidence.add(
                        plugin=self.name,
                        endpoint=endpoint.url,
                        payload="Origin: *",
                        evidence="Invalid CORS: Wildcard + Credentials",
                        confidence="LOW",
                        details="Specification violation."
                    )

        except: pass