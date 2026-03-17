from sdk.base_plugin import BasePlugin

class SSTIPlugin(BasePlugin):
    """
    Server-Side Template Injection (SSTI) Plugin for VORTEX 2.
    """
    
    name = "SSTI (Advanced)"
    
    # Payloads mapped to expected results
    # Supports: Jinja2, Twig, Smarty, Freemarker, Velocity, Mako, ERB
    PAYLOADS = [
        # Basic Math
        ("{{7*7}}", "49"), ("${7*7}", "49"), ("<%= 7*7 %>", "49"), 
        ("#{7*7}", "49"), ("*{7*7}", "49"), ("{{=7*7}}", "49"),
        
        # Complex Math (Avoids false positives)
        ("{{7*'7'}}", "7777777"), ("{{7*'7'}}", "49"), # Some engines eval string mult
        ("${7*7}", "49"), ("${{7*7}}", "49"),
        
        # Engine Specific signatures
        ("{{config}}", "Config"), ("{{settings}}", "Settings"), # Python/Django/Flask
        ("{{self}}", "Object"), # Jinja2
        ("${class.name}", "java.lang"), # Java
        ("#{ 1+1 }", "2"), # Ruby/ERB
        ("a{*comment*}b", "ab"), # Smarty
        ("#set($x=1+1)$x", "2") # Velocity
    ]

    def should_run(self, endpoint):
        return len(endpoint.params) > 0

    def detect(self, http, endpoint, payload_intel):


        findings = []
        try:
            base_params = {p['name']: p['value'] for p in endpoint.params}
            baseline = self._make_request(http, endpoint, base_params)
            if not baseline: return
        except Exception: return

        for param in endpoint.params:
            for payload, expected in self.PAYLOADS:
                fuzzed_params = base_params.copy()
                fuzzed_params[param['name']] = payload
                try:
                    resp = self._make_request(http, endpoint, fuzzed_params)
                    if not resp: continue

                    # Check 1: Expected Result (Math)
                    if expected in resp.text and payload not in resp.text:
                        findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'parameter': param['name'], 'payload': payload, 'evidence': f"Template expression evaluated to '{expected}'", 'confidence': "CRITICAL"})
                        break
                    
                    # Check 2: Error Based
                    if "TemplateSyntaxError" in resp.text or "freemarker.core" in resp.text or "org.apache.velocity" in resp.text:
                         findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'parameter': param['name'], 'payload': payload, 'evidence': "SSTI Error Message Detected", 'confidence': "HIGH"})
                         break

                except Exception: continue
        return findings

    def _make_request(self, http, endpoint, params):
        if endpoint.method.upper() == "POST":
            return http.request(endpoint.method, endpoint.url, data=params)
        return http.request(endpoint.method, endpoint.url, params=params)