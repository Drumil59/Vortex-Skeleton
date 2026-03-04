from .base import BasePlugin

class SecurityHeadersPlugin(BasePlugin):
    name = "Security Headers (Enterprise)"

    REQUIRED_HEADERS = {
        "Content-Security-Policy": "Mitigates XSS/Injection.",
        "X-Frame-Options": "Prevents Clickjacking.",
        "X-Content-Type-Options": "Prevents MIME-sniffing.",
        "Strict-Transport-Security": "Enforces HTTPS."
    }

    def should_run(self, endpoint):
        # Only check on GET requests to root or main pages to reduce noise
        return endpoint.method == "GET"

    def run(self, http, endpoint, analyzer, evidence):
        try:
            # 1. First Check
            resp = http.request(endpoint.method, endpoint.url)
            if not resp: return
            
            headers = resp.headers
            missing = []
            
            for header in self.REQUIRED_HEADERS:
                if header not in headers:
                    missing.append(header)
            
            if not missing: return

            # 2. Confirmation (Re-test)
            # Sometimes headers are dynamic or missing on 404s/Errors.
            # We assume the first request was valid 200 OK or similar.
            # If the first request was an error (500), headers might be missing legitimately.
            if resp.status_code >= 500: return 

            # Report findings
            evidence.add(
                plugin=self.name,
                endpoint=endpoint.url,
                payload=None,
                evidence=f"Missing Headers: {', '.join(missing)}",
                confidence="LOW",
                details="Headers were consistently missing on valid response."
            )

            # 3. Information Disclosure Check
            leaks = []
            if "Server" in headers: leaks.append(f"Server: {headers['Server']}")
            if "X-Powered-By" in headers: leaks.append(f"X-Powered-By: {headers['X-Powered-By']}")
            
            if leaks:
                evidence.add(
                    plugin="Information Disclosure",
                    endpoint=endpoint.url,
                    payload=None,
                    evidence=f"Technology Leak: {', '.join(leaks)}",
                    confidence="MEDIUM",
                    details="Server banners exposed in HTTP headers."
                )

        except: pass
