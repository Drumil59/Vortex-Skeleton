from typing import Any, Dict, List, Optional, Tuple
import logging
import copy

class BasePlugin:
    """
    Standard Offensive Plugin Interface.
    Provides utility methods for parameter gathering and multi-vector injection.
    """
    name = "Base Plugin"
    category = "Generic"
    
    def __init__(self):
        self.logger = logging.getLogger(f"vortex.plugins.{self.name.replace(' ', '_')}")

    def detect(self, http: Any, endpoint: Any, payload_intel: Any) -> List[Dict[str, Any]]:
        """Initial discovery - implemented by sub-classes."""
        return []

    def verify(self, http: Any, endpoint: Any, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Confirm a finding - implemented by sub-classes."""
        return finding

    def exploit(self, http: Any, endpoint: Any, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract proof - implemented by sub-classes."""
        return finding

    def run(self, http: Any, endpoint: Any, analyzer: Any, evidence: Any, payload_intelligence: Any = None):
        """Unified execution workflow."""
        self.logger.debug(f"Executing plugin {self.name} on {endpoint.url}")
        findings = self.detect(http, endpoint, payload_intelligence)
        for finding in findings:
            verified = self.verify(http, endpoint, finding)
            if verified:
                exploited = self.exploit(http, endpoint, verified)
                evidence.add(
                    plugin=self.name,
                    endpoint=endpoint.url,
                    method=exploited.get('method', endpoint.method),
                    parameter=exploited.get('parameter', 'N/A'),
                    severity=exploited.get('severity', 'medium'),
                    payload=exploited.get('payload', ''),
                    proof=exploited.get('proof', ''),
                    details=exploited.get('details', '')
                )

    def _gather_vectors(self, endpoint: Any) -> List[Tuple[str, str, str]]:
        """
        Gathers all potential injection vectors from an endpoint.
        Returns List of (parameter_name, original_value, source_type)
        Sources: 'query', 'form', 'json', 'header', 'cookie'
        """
        vectors = []
        
        # 1. Query Parameters
        for p in endpoint.params:
            if p.get('type') == 'query':
                vectors.append((p['name'], p.get('value', ''), 'query'))
        
        # 2. Form Parameters
        if endpoint.method == "POST":
            for p in endpoint.params:
                if p.get('type') == 'form':
                    vectors.append((p['name'], p.get('value', ''), 'form'))
                    
        # 3. Default Security-Relevant Headers
        vectors.append(("User-Agent", "Mozilla/5.0", "header"))
        vectors.append(("Referer", endpoint.url, "header"))
        vectors.append(("X-Forwarded-For", "127.0.0.1", "header"))
        
        # 4. Cookies (if any discovered)
        # TODO: Pull from workspace session manager if implemented
        
        return vectors

    def _send_payload(self, http: Any, endpoint: Any, vector: Tuple[str, str, str], payload: str) -> Optional[Any]:
        """
        Sends a targeted payload to a specific vector.
        """
        param_name, _, source = vector
        
        # Prepare Request Data
        params = {p['name']: p['value'] for p in endpoint.params if p['type'] == 'query'}
        data = {p['name']: p['value'] for p in endpoint.params if p['type'] == 'form'} if endpoint.method == "POST" else None
        headers = {}
        cookies = {}

        # Inject Payload
        if source == 'query':
            params[param_name] = payload
        elif source == 'form':
            data[param_name] = payload
        elif source == 'header':
            headers[param_name] = payload
        elif source == 'cookie':
            cookies[param_name] = payload

        return http.request(endpoint.method, endpoint.url, params=params, data=data, headers=headers, cookies=cookies)
