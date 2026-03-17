from sdk.base_plugin import BasePlugin
from urllib.parse import urlparse, urljoin

class ExposurePlugin(BasePlugin):
    name = "Administrative Exposure (Enterprise)"

    PATHS = [
        "admin/", "dashboard/", "panel/", ".env", ".git/"
    ]

    def should_run(self, endpoint):
        return endpoint.method == "GET"

    def detect(self, http, endpoint, payload_intel):


        findings = []
        parsed = urlparse(endpoint.url)
        path = parsed.path
        if not path.endswith('/'):
            path = path.rsplit('/', 1)[0] + '/'
        base_url = f"{parsed.scheme}://{parsed.netloc}{path}"

        for p in self.PATHS:
            target = urljoin(base_url, p)
            try:
                # 1. Probe
                resp = http.request("GET", target)
                if not resp: continue

                # 2. Strict Verification (No Soft 404s)
                if resp.status_code == 200:
                    # Content Analysis
                    text = resp.text.lower()
                    
                    # Must contain specific keywords to be a "Panel" or "Config"
                    if p == ".env" and "DB_PASSWORD" in resp.text:
                        findings.append({'plugin': self.name, 'endpoint': target, 'evidence': "Dotenv file exposed", 'confidence': "CRITICAL", 'details': "DB_PASSWORD found."})
                    
                    elif p == ".git/" and "repository" in text:
                         findings.append({'plugin': self.name, 'endpoint': target, 'evidence': "Git Repository exposed", 'confidence': "HIGH", 'details': "Git index/config found."})
                    
                    elif "login" in text or "dashboard" in text or "admin" in text:
                        # Soft 404 check: Compare length to a known 404
                        # Quick heuristic: Is it tiny?
                        if len(resp.text) > 500:
                             findings.append({'plugin': self.name, 'endpoint': target, 'evidence': f"Admin Panel exposed: {p}", 'confidence': "MEDIUM", 'details': "Login/Dashboard keywords found."})

            except: continue
        return findings