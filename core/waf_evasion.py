from typing import List, Dict
import urllib.parse

class WAFEvasionEngine:
    """
    Applies mutation techniques to payloads to bypass Web Application Firewalls.
    """
    def __init__(self):
        pass

    def mutate(self, payload: str, techniques: List[str] = None) -> List[str]:
        if not techniques:
            techniques = ["case_mutation", "double_url_encode", "comment_injection"]
            
        mutated_payloads = [payload]
        
        for tech in techniques:
            if tech == "case_mutation":
                mutated_payloads.append(self._case_mutation(payload))
            elif tech == "double_url_encode":
                mutated_payloads.append(self._double_url_encode(payload))
            elif tech == "comment_injection":
                mutated_payloads.append(self._comment_injection(payload))
                
        return list(set(mutated_payloads))

    def _case_mutation(self, payload: str) -> str:
        # e.g. SELECT -> SeLeCt
        mutated = ""
        for i, char in enumerate(payload):
            if char.isalpha():
                if i % 2 == 0:
                    mutated += char.upper()
                else:
                    mutated += char.lower()
            else:
                mutated += char
        return mutated

    def _double_url_encode(self, payload: str) -> str:
        # First encode
        first = urllib.parse.quote(payload)
        # Second encode
        return urllib.parse.quote(first)

    def _comment_injection(self, payload: str) -> str:
        # Simple simulation: split by spaces and inject SQL comments
        return payload.replace(" ", "/**/")
