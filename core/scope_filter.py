import logging
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode, urljoin

class ScopeFilter:
    """
    Strict Scope Enforcement Engine.
    Filters out external domains, non-HTTP schemes, and static assets.
    """
    def __init__(self, target_url: str):
        parsed = urlparse(target_url)
        self.target_url = target_url
        self.target_domain = parsed.netloc.lower()
        self.logger = logging.getLogger("vortex.scope")
        
        # Static Asset Extensions
        self.ignored_extensions = {
            '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.otf', '.mp4', '.txt', '.pdf', '.zip', '.gz'
        }
        
        self.stats = {
            "discovered": 0,
            "out_of_scope": 0,
            "static_ignored": 0,
            "invalid_scheme": 0,
            "valid": 0
        }

    def is_in_scope(self, url: str) -> bool:
        """Determines if a URL is within the allowed target scope."""
        self.stats["discovered"] += 1
        
        # 1. Resolve and Normalize
        full_url = self.normalize(url)
        if not full_url:
            return False
            
        parsed = urlparse(full_url)
        
        # 2. Block Non-HTTP Schemes
        if parsed.scheme not in ['http', 'https']:
            self.stats["invalid_scheme"] += 1
            return False
            
        # 3. Check Domain (Target + Subdomains)
        domain = parsed.netloc.lower()
        if not (domain == self.target_domain or domain.endswith('.' + self.target_domain)):
            self.stats["out_of_scope"] += 1
            return False
            
        # 4. Ignore Static Assets
        path = parsed.path.lower()
        if any(path.endswith(ext) for ext in self.ignored_extensions):
            self.stats["static_ignored"] += 1
            return False
            
        self.stats["valid"] += 1
        return True

    def normalize(self, url: str) -> str:
        """Resolves relative paths and standardizes URL format."""
        try:
            # Resolve relative URLs
            full_url = urljoin(self.target_url, url)
            parsed = urlparse(full_url)
            
            # Remove fragments
            # Normalize query: sort parameters
            query_params = parse_qsl(parsed.query)
            query_params.sort()
            normalized_query = urlencode(query_params)
            
            # Reconstruct
            return urlunparse((
                parsed.scheme,
                parsed.netloc.lower(),
                parsed.path if parsed.path else "/",
                parsed.params,
                normalized_query,
                "" # No fragment
            ))
        except:
            return ""
