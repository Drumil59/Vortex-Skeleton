from sdk.base_plugin import BasePlugin
from urllib.parse import urljoin, urlparse

class SensitiveAssetPlugin(BasePlugin):
    """
    Sensitive Asset & File Disclosure Plugin for VORTEX 2.
    
    Detection Strategy:
    1. Discovery: Appends known high-risk file paths to the endpoint's directory.
    2. Signature Matching: Verifies response content against specific signatures to avoid False Positives (Soft 404s).
    3. Noise Control: Limits scanning to a curated list of high-impact assets (e.g., .env, .git, backups).
    """

    name = "Sensitive Asset Exposure"

    # curated list of high-impact files and their expected content signatures
    # filename -> list of required strings (any match counts as detection)
    ASSETS = {
        ".env": ["DB_HOST=", "APP_KEY=", "AWS_ACCESS_KEY_ID=", "DB_PASSWORD="],
        ".git/HEAD": ["ref: refs/", "ref:refs/"],
        ".vscode/sftp.json": ["host", "user", "password"],
        "wp-config.php.bak": ["DB_NAME", "DB_USER", "DB_PASSWORD"],
        "docker-compose.yml": ["version:", "services:", "image:"],
        "robots.txt": ["User-agent:", "Disallow:"],
        "sitemap.xml": ["<urlset", "<loc>"],
        ".DS_Store": [b"\x00\x00\x00\x01Bud1"], # Binary signature
    }

    def should_run(self, endpoint):
        """
        Run on GET requests only. 
        Ideally, this should run once per unique directory, but we check all 
        GET endpoints to ensure coverage of nested paths.
        """
        return endpoint.method.upper() == "GET"

    def detect(self, http, endpoint, payload_intel):


        findings = []
        # Determine the base directory of the current endpoint
        # e.g., http://target.com/admin/login.php -> http://target.com/admin/
        parsed = urlparse(endpoint.url)
        path = parsed.path
        if not path.endswith('/'):
            # Strip filename to get directory
            path = path.rsplit('/', 1)[0] + '/'
        
        base_dir_url = f"{parsed.scheme}://{parsed.netloc}{path}"

        # 1. Iterate through asset list
        for filename, signatures in self.ASSETS.items():
            target_url = urljoin(base_dir_url, filename)

            try:
                # 2. Make Request
                resp = http.request("GET", target_url)

                if not resp:
                    continue

                # 3. Detection Logic
                # Primary Gate: HTTP 200 OK
                if resp.status_code == 200:
                    
                    # Secondary Gate: Content Signature Verification
                    # This prevents False Positives from "Soft 404" pages that return 200 OK
                    # but contain "Page Not Found" text.
                    content_match = False
                    for sig in signatures:
                        # Handle binary signatures for .DS_Store, etc.
                        if isinstance(sig, str):
                            if sig in resp.text:
                                content_match = True
                                break
                        elif isinstance(sig, bytes):
                            if sig in resp.content:
                                content_match = True
                                break

                    if content_match:
                        findings.append({'plugin': self.name, 'endpoint': target_url, 'payload': filename, 'evidence': "Found accessible sensitive file with valid content signature.", 'confidence': "HIGH", 'details': f"Matched signature for {filename}"})
            
            except Exception:
                # Gracefully handle timeouts or connection errors
                continue
        return findings