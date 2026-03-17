from sdk.base_plugin import BasePlugin
from urllib.parse import urlparse, urljoin
import os

class BackupFilePlugin(BasePlugin):
    """
    Fuzzes the current endpoint's filename for common backup extensions.
    Example: index.php -> index.php.bak, index.php~, index.old
    """
    name = "Backup File Discovery"

    EXTENSIONS = [
        ".bak", ".old", ".swp", ".tmp", ".~", ".save", ".backup", ".1"
    ]

    PREFIXES = ["_", "old_", "bak_"]

    def should_run(self, endpoint):
        # Only run on specific files, not directories or root
        parsed = urlparse(endpoint.url)
        path = parsed.path
        if not path or path == "/" or path.endswith("/"):
            return False
        return True

    def detect(self, http, endpoint, payload_intel):


        findings = []
        parsed = urlparse(endpoint.url)
        path = parsed.path
        
        # /dir/file.php -> file.php
        filename = os.path.basename(path)
        dirname = os.path.dirname(path)
        
        # Base URL for the directory
        # e.g., http://target.com/dir/
        base_url = f"{parsed.scheme}://{parsed.netloc}{dirname}/"
        # Ensure dirname ends with / for urljoin if not empty
        if dirname and not dirname.endswith('/'):
            base_url += "/"

        candidates = []

        # 1. Suffix Fuzzing: file.php.bak
        for ext in self.EXTENSIONS:
            candidates.append(filename + ext)

        # 2. Prefix Fuzzing: _file.php
        for pre in self.PREFIXES:
            candidates.append(pre + filename)

        # 3. Extension Replacement: file.bak (if it has an extension)
        if "." in filename:
            name_only, _ = os.path.splitext(filename)
            candidates.append(f"{name_only}.bak")
            candidates.append(f"{name_only}.old")

        for candidate in candidates:
            # Reconstruct URL correctly
            target_url = urljoin(base_url, candidate)
            
            # Avoid re-scanning the original URL (though logic above should prevent it)
            if target_url == endpoint.url:
                continue

            try:
                resp = http.request("GET", target_url)
                if not resp:
                    continue

                # Detection: 200 OK and Content-Length > 0
                # We need to be careful of Soft 404s.
                if resp.status_code == 200:
                    # Heuristic: Compare with original page. 
                    # If content is exactly the same, it might be a soft 404 rewriting to index.
                    # But backup files often ARE the same as original (or source code).
                    
                    # Check Headers: Content-Type usually differs for backups (e.g., text/plain vs text/html)
                    ctype = resp.headers.get("Content-Type", "").lower()
                    
                    # Valid finding if:
                    # 1. Not HTML (likely raw source) OR
                    # 2. Contains PHP/Code tags
                    
                    is_suspicious = False
                    if "application/x-httpd-php" in ctype or "text/plain" in ctype or "application/octet-stream" in ctype:
                        is_suspicious = True
                    elif "<?php" in resp.text or "<%=" in resp.text:
                        is_suspicious = True
                    
                    if is_suspicious:
                        findings.append({'plugin': self.name, 'endpoint': target_url, 'payload': candidate, 'evidence': "Found accessible backup file", 'confidence': "HIGH"})

            except Exception:
                continue
        return findings