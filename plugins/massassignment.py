from .base import BasePlugin

class MassAssignmentPlugin(BasePlugin):
    """
    Tests for Mass Assignment / Insecure Parameter Binding.
    Attempts to inject sensitive parameters into POST/PUT requests.
    """
    name = "Mass Assignment"

    # Sensitive parameters often used in internal logic
    SENSITIVE_PARAMS = [
        "is_admin", "isAdmin", "role", "type", "account_type", 
        "balance", "credits", "permissions", "privileges",
        "verified", "status", "active", "email_verified"
    ]

    # Values to try for injection
    SENSITIVE_VALUES = ["true", "1", "admin", "superuser", "99999"]

    def should_run(self, endpoint):
        # Mass assignment is most common in POST, PUT, PATCH
        return endpoint.method.upper() in ["POST", "PUT", "PATCH"]

    def run(self, http, endpoint, analyzer, evidence):
        try:
            base_params = {p['name']: p['value'] for p in endpoint.params}
        except: return

        # Establish baseline response
        baseline = http.request(endpoint.method, endpoint.url, data=base_params)
        if not baseline: return

        for param_name in self.SENSITIVE_PARAMS:
            # Skip if the parameter is already in the original request
            if any(p['name'].lower() == param_name.lower() for p in endpoint.params):
                continue

            for value in self.SENSITIVE_VALUES:
                fuzzed_params = base_params.copy()
                fuzzed_params[param_name] = value

                try:
                    resp = http.request(endpoint.method, endpoint.url, data=fuzzed_params)
                    if not resp: continue

                    # Detection: If the server accepts the parameter (200 OK)
                    # and the response is significantly different or indicates success.
                    # This is often hard to confirm without a side-channel, but we flag it as an anomaly.
                    if resp.status_code == 200 and len(resp.text) != len(baseline.text):
                        evidence.add(
                            plugin=self.name,
                            endpoint=endpoint.url,
                            payload=f"{param_name}={value}",
                            evidence="Server accepted unexpected sensitive parameter",
                            confidence="LOW",
                            details="The application processed a request containing a potentially sensitive parameter that wasn't in the original form."
                        )
                        break

                except Exception:
                    continue
