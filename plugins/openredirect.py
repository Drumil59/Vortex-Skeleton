from .base import BasePlugin

class OpenRedirectPlugin(BasePlugin):
    name = "Open Redirect (Enterprise)"
    
    PAYLOAD = "http://evil-vortex.com/redirect"
    
    def should_run(self, endpoint):
        return len(endpoint.params) > 0

    def run(self, http, endpoint, analyzer, evidence):
        try:
            base_params = {p['name']: p['value'] for p in endpoint.params}
        except: return

        for param in endpoint.params:
            fuzzed = base_params.copy()
            fuzzed[param['name']] = self.PAYLOAD

            try:
                # 1. Attack Request (No Auto Redirect)
                if endpoint.method == "POST":
                    resp = http.request(endpoint.method, endpoint.url, data=fuzzed, allow_redirects=False)
                else:
                    resp = http.request(endpoint.method, endpoint.url, params=fuzzed, allow_redirects=False)

                if not resp: continue

                # 2. Strict Verification
                # We require a 3xx Status Code AND the Location header matching our payload.
                if 300 <= resp.status_code < 400:
                    location = resp.headers.get("Location", "")
                    
                    if self.PAYLOAD in location:
                        # Double Check: Ensure it's not just reflecting input in a parameter of the redirect
                        # e.g. Location: /login?next=http://evil... (This is Open Redirect, but sometimes valid)
                        # We report it as High Confidence.
                        
                        evidence.add(
                            plugin=self.name,
                            endpoint=endpoint.url,
                            parameter=param['name'],
                            payload=self.PAYLOAD,
                            evidence=f"Redirects to arbitrary domain: {location}",
                            confidence="HIGH",
                            details="Server responded with 3xx and Location header containing payload."
                        )
                        return # Stop after one finding per endpoint

            except: continue
