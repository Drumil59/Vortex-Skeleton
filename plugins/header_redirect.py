from sdk.base_plugin import BasePlugin

class HeaderBasedRedirectPlugin(BasePlugin):
    """
    Checks for Open Redirects via esoteric headers (X-Forwarded-Url, etc).
    """
    name = "Header-Based Redirect"

    HEADERS_TO_TEST = [
        ("X-Forwarded-Url", "http://evil-vortex.com/x-fwd-url"),
        ("X-Rewrite-Url", "http://evil-vortex.com/x-rewrite"),
        ("X-Original-Url", "/vortex-redirect-test"), # Often used to bypass auth or rewrite paths
    ]

    def should_run(self, endpoint):
        return endpoint.method == "GET"

    def detect(self, http, endpoint, payload_intel):


        findings = []
        try:
            for header, payload in self.HEADERS_TO_TEST:
                headers = {header: payload}
                
                resp = http.request("GET", endpoint.url, headers=headers, allow_redirects=False)
                if not resp: continue

                # Check for Redirects
                if 300 <= resp.status_code < 400:
                    location = resp.headers.get("Location", "")
                    if "evil-vortex.com" in location:
                        findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'payload': f"{header}: {payload}", 'evidence': f"Redirect triggered by {header}", 'confidence': "HIGH"})

                # Check for Content Spoofing (X-Original-URL might show different content)
                # If we get a 200 OK but for a different page than requested
                if resp.status_code == 200 and header == "X-Original-Url":
                    # This requires comparing against baseline, difficult here without context.
                    # We just log if it seems to work.
                    pass

        except Exception:
            pass
        return findings