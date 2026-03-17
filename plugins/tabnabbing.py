from sdk.base_plugin import BasePlugin
import re
import json
import base64

class TabnabbingPlugin(BasePlugin):
    """
    Reverse Tabnabbing.
    Checks for target="_blank" links missing rel="noopener noreferrer".
    """
    name = "Reverse Tabnabbing"

    def should_run(self, endpoint):
        return endpoint.method == "GET"

    def detect(self, http, endpoint, payload_intel):


        findings = []
        try:
            resp = http.request("GET", endpoint.url)
            if not resp: return

            # Regex for unsafe links
            # <a ... target="_blank" ... > without noopener/noreferrer
            # Simplified check: Find target="_blank" and check if rel is missing in that tag context
            
            if 'target="_blank"' in resp.text:
                # We do a basic check. If "noopener" is NOT in the response, it's definitely vuln.
                # If it IS in the response, we might need closer parsing, but for speed:
                if "noopener" not in resp.text:
                     findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'payload': None, 'evidence': "Unsafe target='_blank' links detected (Missing noopener})",
                        confidence="MEDIUM",
                        details="Allows opened pages to manipulate the parent window."
                    )
        except: pass
        return findings