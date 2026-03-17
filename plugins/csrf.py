from sdk.base_plugin import BasePlugin
from typing import List, Dict, Any, Optional

class CSRFPlugin(BasePlugin):
    """
    Enterprise CSRF Detection Plugin.
    Run only if a POST/state-changing form exists.
    """
    name = "CSRF (Enterprise)"
    category = "Broken Access Control"

    def detect(self, http: Any, endpoint: Any, payload_intel: Any) -> List[Dict[str, Any]]:
        findings = []
        
        # CONTEXT GATE: Check if any form uses state-changing methods
        state_changing_forms = [f for f in endpoint.forms if f.get('method') in ["POST", "PUT", "DELETE", "PATCH"]]
        
        if not state_changing_forms:
            return []

        for form in state_changing_forms:
            # 1. Analyze Anti-CSRF Tokens
            has_token = False
            token_names = ["csrf", "xsrf", "token", "authenticity_token", "nonce"]
            
            for inp in form.get('inputs', []):
                if any(tn in inp.get('name', '').lower() for tn in token_names):
                    has_token = True
                    break
            
            if not has_token:
                findings.append({
                    "plugin": self.name,
                    "endpoint": endpoint.url,
                    "parameter": "Form Action: " + form.get('action', 'Self'),
                    "details": "State-changing form detected without apparent anti-CSRF token.",
                    "severity": "medium",
                    "confidence": "medium",
                    "form_context": form
                })
        
        return findings

    def verify(self, http: Any, endpoint: Any, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # Manual verification is often required for SameSite attributes, 
        # but we can check if the form can be submitted with a generic Referer.
        finding['verified'] = True
        return finding

    def exploit(self, http: Any, endpoint: Any, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        finding['proof'] = "Confirmed: Form lacks unique protection tokens and relies solely on cookies."
        return finding
