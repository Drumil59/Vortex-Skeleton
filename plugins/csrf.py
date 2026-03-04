from .base import BasePlugin

class CSRFPlugin(BasePlugin):
    name = "CSRF (Enterprise)"

    def should_run(self, endpoint):
        return endpoint.method == "POST"

    def run(self, http, endpoint, analyzer, evidence):
        # We assume endpoint.params contains form inputs
        # We check if any of them look like anti-CSRF tokens.
        
        csrf_tokens = ["csrf", "xsrf", "token", "nonce", "_token"]
        has_token = False
        
        for param in endpoint.params:
            if any(t in param['name'].lower() for t in csrf_tokens):
                has_token = True
                break
        
        if not has_token:
            # Low confidence because it might be an API or use custom headers
            evidence.add(
                plugin=self.name,
                endpoint=endpoint.url,
                payload=None,
                evidence="POST request missing common anti-CSRF tokens",
                confidence="LOW",
                details="Verify manually if cookies are SameSite or if other protections exist."
            )
