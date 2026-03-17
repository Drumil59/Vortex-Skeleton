import hashlib
import logging
import random
import string
from typing import Dict, Set, Any, List
from urllib.parse import urlparse, urljoin

class URLValidator:
    """
    Advanced Endpoint Validation & Fingerprinting Engine.
    Filters out 404s, Soft-404s, and unstable endpoints.
    """
    def __init__(self, http_client):
        self.http = http_client
        self.logger = logging.getLogger("vortex.validator")
        self.invalid_fingerprints: Set[str] = set()
        self.valid_codes = [200, 201, 202, 204, 301, 302, 401, 403]
        self.invalid_codes = [404, 410, 500]
        
        # Stats tracking
        self.stats = {
            "total_checked": 0,
            "valid": 0,
            "skipped_404": 0,
            "skipped_soft_404": 0,
            "rejected": 0
        }
        self.baseline_established = False

    def establish_baseline(self, base_url: str):
        """Sends a request to a random path to establish a 404 baseline."""
        random_path = '/' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        target_url = urljoin(base_url, random_path)
        try:
            resp = self.http.request("GET", target_url)
            if resp:
                fingerprint = self._generate_fingerprint(resp.text)
                self.invalid_fingerprints.add(fingerprint)
                self.logger.info(f"[*] Established 404 baseline for {base_url} (Length: {len(resp.text)})")
                self.baseline_established = True
        except Exception as e:
            self.logger.error(f"Failed to establish baseline: {e}")

    def validate(self, url: str) -> bool:
        """Performs multi-stage validation of an endpoint."""
        self.stats["total_checked"] += 1
        
        # Establish baseline if not yet done for this domain
        if not self.baseline_established:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}/"
            self.establish_baseline(base)

        try:
            resp = self.http.request("GET", url)
            if not resp: 
                self.stats["rejected"] += 1
                return False

            # 1. Strict Status Code Check
            if resp.status_code in self.invalid_codes:
                self.logger.debug(f"Filtering {url}: Status {resp.status_code}")
                self.stats["skipped_404"] += 1
                self.stats["rejected"] += 1
                return False
            
            if resp.status_code not in self.valid_codes:
                self.logger.debug(f"Filtering {url}: Status {resp.status_code} not in valid list")
                self.stats["rejected"] += 1
                return False

            # 2. Soft-404 Detection (Body Hashing)
            content_hash = self._generate_fingerprint(resp.text)
            if content_hash in self.invalid_fingerprints:
                self.logger.debug(f"Filtering {url}: Soft-404 Fingerprint Match")
                self.stats["skipped_soft_404"] += 1
                self.stats["rejected"] += 1
                return False

            # 3. Content Analysis (Common 404 strings)
            error_keywords = ["page not found", "file not found", "404 error", "doesn't exist"]
            if any(k in resp.text.lower() for k in error_keywords) and resp.status_code == 200:
                self.invalid_fingerprints.add(content_hash)
                self.stats["skipped_soft_404"] += 1
                self.stats["rejected"] += 1
                return False

            self.stats["valid"] += 1
            return True
        except Exception as e:
            self.logger.error(f"Validation error for {url}: {e}")
            self.stats["rejected"] += 1
            return False

    def _generate_fingerprint(self, text: str) -> str:
        """Creates a fuzzy fingerprint of the response body."""
        # Simple MD5 of text
        return hashlib.md5(text.encode('utf-8')).hexdigest()
