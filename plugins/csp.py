from .base import BasePlugin

class CSPWeaknessPlugin(BasePlugin):
    """
    Analyzes Content-Security-Policy (CSP) headers for configuration weaknesses.
    """
    name = "CSP Analysis"

    def should_run(self, endpoint):
        return endpoint.method == "GET"

    def run(self, http, endpoint, analyzer, evidence):
        try:
            resp = http.request("GET", endpoint.url)
            if not resp:
                return

            csp = resp.headers.get("Content-Security-Policy")
            if not csp:
                # Missing CSP is handled by SecurityHeadersPlugin
                return

            weaknesses = []

            # 1. Unsafe Inline (XSS Risk)
            if "'unsafe-inline'" in csp:
                weaknesses.append("'unsafe-inline' detected (Allows inline scripts, XSS risk)")

            # 2. Unsafe Eval (Code Execution Risk)
            if "'unsafe-eval'" in csp:
                weaknesses.append("'unsafe-eval' detected (Allows eval(), code execution risk)")

            # 3. Wildcards (Permissive)
            if " *" in csp or "* " in csp: # Simple check for wildcard domains
                 weaknesses.append("Wildcard '*' usage detected (Overly permissive)")
            
            # 4. Missing object-src (Flash/Plugin XSS)
            if "object-src" not in csp:
                 weaknesses.append("Missing 'object-src' directive (Potential plugin-based XSS)")

            # 5. Missing base-uri
            if "base-uri" not in csp:
                 weaknesses.append("Missing 'base-uri' directive (Potential base tag hijacking)")

            # 6. Data URI allowed
            if "data:" in csp:
                 weaknesses.append("'data:' URI allowed (Potential XSS via data schemes)")

            if weaknesses:
                evidence.add(
                    plugin=self.name,
                    endpoint=endpoint.url,
                    payload=None,
                    evidence="Weak CSP Configuration",
                    confidence="MEDIUM",
                    details="\n".join(weaknesses)
                )

        except Exception:
            pass
