from .base import BasePlugin
from urllib.parse import urljoin

class XMLRPCPlugin(BasePlugin):
    """
    WordPress XML-RPC Vulnerability Scanner.
    Checks for enabled xmlrpc.php and brute-force amplification potential.
    """
    name = "WordPress XML-RPC"

    def should_run(self, endpoint):
        # Run primarily if we haven't checked this path yet.
        # We assume the user scans the root or we just construct the path.
        return True

    def run(self, http, endpoint, analyzer, evidence):
        # Construct xmlrpc.php URL relative to the current endpoint's root
        # If endpoint is http://example.com/blog/post1 -> check http://example.com/blog/xmlrpc.php
        
        try:
            target = urljoin(endpoint.url, "xmlrpc.php")
            
            # 1. Check Existence
            resp = http.request("GET", target)
            if not resp or resp.status_code != 405: # XMLRPC usually returns 405 Method Not Allowed on GET
                # Some return 200 with "XML-RPC server accepts POST requests only."
                if resp and "XML-RPC server accepts POST requests only" not in resp.text:
                    return

            # 2. Check Functionality (POST)
            # List Methods to verify it's active
            payload = """
            <methodCall>
              <methodName>system.listMethods</methodName>
              <params></params>
            </methodCall>
            """
            
            resp_post = http.request("POST", target, data=payload, headers={"Content-Type": "application/xml"})
            
            if resp_post and resp_post.status_code == 200:
                if "<methodResponse>" in resp_post.text and "system.listMethods" in resp_post.text:
                     evidence.add(
                        plugin=self.name,
                        endpoint=target,
                        payload="system.listMethods",
                        evidence="XML-RPC enabled and system.listMethods is available",
                        confidence="HIGH",
                        details="Attacker can use this for Brute Force Amplification or DDoS."
                    )

        except Exception:
            pass
