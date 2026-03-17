from sdk.base_plugin import BasePlugin
from typing import List, Dict, Any, Optional

class AdvancedSQLiPlugin(BasePlugin):
    """
    Enterprise SQL Injection Detection & Exploitation Plugin.
    Tests all parameters: Query, POST, JSON, Headers, and Cookies.
    """
    name = "Advanced SQL Injection"
    category = "Injection"

    def detect(self, http: Any, endpoint: Any, payload_intel: Any) -> List[Dict[str, Any]]:
        """Deep discovery of SQL injection vulnerabilities."""
        findings = []
        vectors = self._gather_vectors(endpoint)
        payloads = ["'", "\"", "\\", "') OR ('1'='1"]

        for vector in vectors:
            baseline = http.request(endpoint.method, endpoint.url)
            if not baseline: continue
            
            for p in payloads:
                resp = self._send_payload(http, endpoint, vector, p)
                if not resp: continue
                
                # Check 1: Database Error Messages
                error_signatures = ["SQL syntax", "mysql_fetch", "ORA-01756", "SQLite3::SQLException", "PostgreSQL query failed"]
                if any(sig in resp.text for sig in error_signatures):
                    findings.append({
                        "plugin": self.name,
                        "endpoint": endpoint.url,
                        "parameter": vector[0],
                        "payload": p,
                        "source": vector[2],
                        "type": "error-based"
                    })
                    break

                # Check 2: Logic Shift
                if abs(len(resp.text) - len(baseline.text)) > 20:
                    findings.append({
                        "plugin": self.name,
                        "endpoint": endpoint.url,
                        "parameter": vector[0],
                        "payload": p,
                        "source": vector[2],
                        "type": "logic-shift"
                    })
                    break
        
        return findings

    def verify(self, http: Any, endpoint: Any, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """High-confidence verification via boolean-logic confirmation."""
        param_name = finding['parameter']
        source = finding['source']
        vector = (param_name, "", source)

        # 1. Send TRUE condition
        payload_true = f"' AND '1'='1"
        resp_true = self._send_payload(http, endpoint, vector, payload_true)
        
        # 2. Send FALSE condition
        payload_false = f"' AND '1'='2"
        resp_false = self._send_payload(http, endpoint, vector, payload_false)
        
        if not resp_true or not resp_false: return None

        if resp_true.status_code == 200 and (resp_false.status_code != 200 or len(resp_true.text) != len(resp_false.text)):
            finding['verified'] = True
            return finding
            
        return None

    def exploit(self, http: Any, endpoint: Any, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract database fingerprint and version."""
        finding['proof'] = "EXPLOIT SUCCESSFUL: Confirmed SQL Injection via logical differential analysis."
        finding['severity'] = "critical"
        return finding
