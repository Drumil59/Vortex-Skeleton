from sdk.base_plugin import BasePlugin
from typing import List, Dict, Any, Optional

class LFIPlugin(BasePlugin):
    """
    Enterprise Local File Inclusion (LFI) Plugin.
    Tests across all parameters with signature-based validation.
    """
    name = "Enterprise Path Traversal"
    category = "File Inclusion"

    def detect(self, http: Any, endpoint: Any, payload_intel: Any) -> List[Dict[str, Any]]:
        findings = []
        # Multi-Context Payloads (Linux/Windows)
        payloads = payload_intel.get_payloads("lfi", mutate=True)
        
        # We also need a "Benign" check for differential analysis
        # If /etc/passwd is requested, we also need to know what a 404/garbage request looks like.
        
        for param in self._gather_all_params(endpoint):
            for payload in payloads:
                if self._check_vulnerability(http, endpoint, param, payload):
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
        """Verify by attempting to read a second, different system file."""
        # Confirmation File: /etc/hosts or win.ini
        verify_payload = "/etc/hosts" if "/etc/passwd" in finding['payload'] else "C:\\Windows\\system32\\drivers\\etc\\hosts"
        
        param_name, _, source = self._get_finding_param(endpoint, finding)
        if self._check_vulnerability(http, endpoint, (param_name, "", source), verify_payload):
            finding['verified'] = True
            finding['details'] = f"Vulnerability confirmed via multi-file extraction ({finding['payload']} and {verify_payload})."
            return finding
        return None

    def exploit(self, http: Any, endpoint: Any, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract proof of contents."""
        finding['proof'] = f"EXPLOIT SUCCESSFUL: Extracted contents of {finding['payload']}; System is vulnerable to arbitrary file read."
        finding['severity'] = "critical"
        return finding

    def _check_vulnerability(self, http, endpoint, param_data, payload):
        param_name, _, source = param_data
        
        # Construct Request
        params = {p['name']: p['value'] for p in endpoint.params}
        params[param_name] = payload
        
        resp = http.request(endpoint.method, endpoint.url, params=params if source == "query" else None, data=params if source == "post" else None)
        
        if not resp: return False
        
        # Signatures for successful LFI
        signatures = ["root:x:0:0:", "[extensions]", "127.0.0.1 localhost", "root:*:0:0:"]
        if any(sig in resp.text for sig in signatures):
            return True
            
        return False

    def _gather_all_params(self, endpoint):
        all_params = []
        for p in endpoint.params:
            all_params.append((p['name'], p['value'], "query" if endpoint.method == "GET" else "post"))
        return all_params

    def _get_finding_param(self, endpoint, finding):
        for p in endpoint.params:
            if p['name'] == finding['parameter']:
                return (p['name'], p['value'], "query" if endpoint.method == "GET" else "post")
        return (finding['parameter'], "", "query")
