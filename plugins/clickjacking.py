from .base import BasePlugin

class ClickjackingPlugin(BasePlugin):
    name = "Clickjacking (Enterprise)"

    def should_run(self, endpoint):
        return endpoint.method == "GET"

    def run(self, http, endpoint, analyzer, evidence):
        try:
            resp = http.request("GET", endpoint.url)
            if not resp: return

            # 1. Check Headers
            xfo = resp.headers.get("X-Frame-Options")
            csp = resp.headers.get("Content-Security-Policy")

            vulnerable = True
            if xfo and xfo.upper() in ["DENY", "SAMEORIGIN"]:
                vulnerable = False
            if csp and "frame-ancestors" in csp:
                vulnerable = False

            # 2. Reporting
            if vulnerable:
                evidence.add(
                    plugin=self.name,
                    endpoint=endpoint.url,
                    payload=None,
                    evidence="Page allows framing (Missing XFO/CSP)",
                    confidence="MEDIUM",
                    details="X-Frame-Options and CSP frame-ancestors are missing."
                )
        except: pass
