import hashlib
import json
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
import logging
from report.severity_sorter import SeveritySorter

class FindingDeduplicator:
    """
    Vulnerability Deduplication and Aggregation Engine.
    Ensures findings are unique per (plugin, url, parameter, method).
    """
    def __init__(self):
        self.findings = {}
        self.logger = logging.getLogger("vortex.deduplicator")
        self.raw_count = 0

    def add_finding(self, **kwargs):
        """
        Adds a new finding or merges it into an existing one.
        """
        self.raw_count += 1
        
        plugin = kwargs.get('plugin', 'Unknown')
        url = kwargs.get('endpoint', kwargs.get('url', 'N/A'))
        parameter = kwargs.get('parameter', 'N/A')
        method = kwargs.get('method', 'GET').upper()
        
        normalized_url = self.normalize_url(url)
        
        # Create unique signature
        sig_data = f"{plugin}|{normalized_url}|{parameter}|{method}"
        signature = hashlib.sha256(sig_data.encode()).hexdigest()
        
        if signature in self.findings:
            self._merge_finding(signature, kwargs)
        else:
            self._create_finding(signature, kwargs, normalized_url, method)

    def _create_finding(self, signature, kwargs, normalized_url, method):
        """Initializes a new aggregated finding."""
        payload = kwargs.get('payload')
        plugin_name = kwargs.get('plugin', 'Unknown')
        
        # Determine Severity and Confidence
        severity = kwargs.get('severity')
        if not severity:
            severity = SeveritySorter.get_severity_mapping(plugin_name)
        
        confidence = kwargs.get('confidence', 'HIGH').upper()
        
        finding = {
            'type': plugin_name,
            'severity': severity.upper(),
            'confidence': confidence,
            'details': kwargs.get('details', 'No description available.'),
            'url': normalized_url,
            'method': method,
            'parameter': kwargs.get('parameter', 'N/A'),
            'payloads': [payload] if payload else [],
            'proofs': [kwargs.get('proof')] if kwargs.get('proof') else [],
            'occurrences': 1,
            'raw_data': [kwargs]
        }
        self.findings[signature] = finding

    def _merge_finding(self, signature, kwargs):
        """Merges new detection data into an existing finding."""
        finding = self.findings[signature]
        finding['occurrences'] += 1
        
        payload = kwargs.get('payload')
        if payload and payload not in finding['payloads']:
            finding['payloads'].append(payload)
            
        proof = kwargs.get('proof')
        if proof and proof not in finding['proofs']:
            finding['proofs'].append(proof)
            
        finding['raw_data'].append(kwargs)

    def normalize_url(self, url):
        """
        Normalizes URLs to prevent duplicates based on trivial differences.
        - Removes fragments
        - Sorts query parameters
        - Removes trailing slashes
        """
        try:
            parsed = urlparse(url)
            # 1. Sort Query Parameters
            query_params = parse_qsl(parsed.query)
            query_params.sort()
            normalized_query = urlencode(query_params)
            
            # 2. Strip trailing slash from path
            path = parsed.path.rstrip('/')
            if not path:
                path = ""
                
            # 3. Reconstruct
            new_url = urlunparse((
                parsed.scheme,
                parsed.netloc.lower(),
                path,
                parsed.params,
                normalized_query,
                "" # Remove fragment
            ))
            return new_url
        except Exception:
            return url

    def get_deduplicated_findings(self):
        """Returns the list of aggregated findings."""
        self.logger.info(f"Deduplication complete: {self.raw_count} raw findings -> {len(self.findings)} unique.")
        return list(self.findings.values())
