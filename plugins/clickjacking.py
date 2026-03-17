from sdk.base_plugin import BasePlugin

class ClickjackingPlugin(BasePlugin):
    name = "Clickjacking (Enterprise)"

    def should_run(self, endpoint):
        return endpoint.method == "GET"

    def detect(self, http, endpoint, payload_intel):


        findings = []
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
                findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'payload': None, 'evidence': "Page allows framing (Missing XFO/CSP})",
                    confidence="MEDIUM",
                    details="X-Frame-Options and CSP frame-ancestors are missing."
                )
        except: pass
        return findings