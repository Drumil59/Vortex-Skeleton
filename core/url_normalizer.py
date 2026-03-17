import logging
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode, urljoin

class URLNormalizer:
    """
    Normalizes URLs and enforces scope filtering.
    """
    def __init__(self, target_url: str):
        parsed = urlparse(target_url)
        self.target_domain = parsed.netloc.lower()
        self.target_scheme = parsed.scheme
        self.logger = logging.getLogger("vortex.normalizer")
        
        # Extensions to ignore for crawling but maybe save as assets
        self.static_extensions = {
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.css', '.woff', '.woff2', '.ttf', '.otf'
        }

    def normalize(self, url: str, base_url: str = None) -> str:
        """Resolves relative paths, removes fragments, and sorts query parameters."""
        try:
            if base_url:
                url = urljoin(base_url, url)
            
            parsed = urlparse(url)
            
            # Remove fragments
            # Sort query parameters for deduplication
            query_params = parse_qsl(parsed.query)
            query_params.sort()
            normalized_query = urlencode(query_params)
            
            # Reconstruct
            return urlunparse((
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path if parsed.path else "/",
                parsed.params,
                normalized_query,
                "" # Fragment removed
            ))
        except Exception as e:
            self.logger.debug(f"Normalization failed for {url}: {e}")
            return ""

    def is_in_scope(self, url: str) -> bool:
        """Checks if URL belongs to the target domain or subdomains."""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        return domain == self.target_domain or domain.endswith('.' + self.target_domain)

    def is_static(self, url: str) -> bool:
        """Checks if the URL points to a static asset."""
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in self.static_extensions)

    def is_http(self, url: str) -> bool:
        """Ensures the scheme is http or https."""
        return urlparse(url).scheme.lower() in ['http', 'https']
