from sdk.base_plugin import BasePlugin

class WebDAVPlugin(BasePlugin):
    """
    Checks for enabled WebDAV or dangerous HTTP methods (PUT, DELETE, TRACE).
    """
    name = "Dangerous HTTP Methods"

    DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND"]

    def should_run(self, endpoint):
        return True # Can check on any endpoint

    def detect(self, http, endpoint, payload_intel):


        findings = []
        try:
            # 1. Send OPTIONS request
            resp = http.request("OPTIONS", endpoint.url)
            if not resp:
                return

            allow_header = resp.headers.get("Allow", "")
            public_header = resp.headers.get("Public", "") # WebDAV specific

            methods_found = []

            # Check Allow Header
            if allow_header:
                for method in self.DANGEROUS_METHODS:
                    if method in allow_header.upper():
                        methods_found.append(method)

            # Check for WebDAV 'Public' header
            if public_header:
                 findings.append({'plugin': "WebDAV Enabled", 'endpoint': endpoint.url, 'payload': None, 'evidence': "WebDAV detected via 'Public' header", 'confidence': "MEDIUM", 'details': f"Public: {public_header}"})

            # 2. Verify PUT (if listed or just blind check)
            # We don't want to actually upload files destructively, so we try a safe check if possible
            # or just report the OPTIONS finding.
            
            if methods_found:
                findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'payload': None, 'evidence': f"Dangerous methods allowed: {', '.join(methods_found})}",
                    confidence="MEDIUM"
                )

                if "PUT" in methods_found:
                    # Try a benign PUT to see if it's actually writable (auth often protects this)
                    test_url = endpoint.url + "_vortex_test"
                    put_resp = http.request("PUT", test_url, data="test")
                    if put_resp and put_resp.status_code in [201, 204, 200]:
                         findings.append({'plugin': "Arbitrary File Upload", 'endpoint': test_url, 'payload': "PUT", 'evidence': "PUT request succeeded (File Created/Modified})",
                            confidence="CRITICAL"
                        )
                    # Clean up if possible
                    if put_resp and put_resp.status_code == 201:
                        http.request("DELETE", test_url)

        except Exception:
            pass
        return findings