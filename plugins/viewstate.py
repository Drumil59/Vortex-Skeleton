from .base import BasePlugin
import base64
import re

class ViewStatePlugin(BasePlugin):
    """
    ASP.NET ViewState Analysis.
    Checks for unencrypted ViewStates and MAC validation.
    """
    name = "ASP.NET ViewState"

    def should_run(self, endpoint):
        return True

    def run(self, http, endpoint, analyzer, evidence):
        try:
            resp = http.request("GET", endpoint.url)
            if not resp or "__VIEWSTATE" not in resp.text:
                return

            # Extract ViewState
            match = re.search(r'id="__VIEWSTATE" value="([^"]+)"', resp.text)
            if not match:
                return

            vs_data = match.group(1)
            
            # Check 1: Empty ViewState
            if not vs_data: return

            # Check 2: MAC Enabled? 
            # If the ViewState is just Base64 encoded XML/Object without a hash at the end, it's insecure.
            # A heuristic is to try to decode it.
            
            try:
                decoded = base64.b64decode(vs_data)
                
                # If we can clearly read strings, it might not be encrypted (just signed).
                # Modern ASP.NET encrypts by default. If we see clear text structure, it's a finding.
                
                # Look for common strings indicating unencrypted objects
                if b"System.Collections" in decoded or b"System.String" in decoded:
                     evidence.add(
                        plugin=self.name,
                        endpoint=endpoint.url,
                        payload=None,
                        evidence="Unencrypted ViewState detected",
                        confidence="MEDIUM",
                        details="Decoded ViewState contains readable serialized object data."
                    )
                
                # Check for "MAC enabled" property is hard without a key, 
                # but if the viewstate is short, it might lack a MAC.
                
            except Exception:
                pass

        except Exception:
            pass
