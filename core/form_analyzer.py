from bs4 import BeautifulSoup
from urllib.parse import urljoin
from typing import List, Dict, Any

class FormAnalyzer:
    """
    Identifies real attack surface in HTML content.
    Extracts forms, inputs, and submission methods.
    """
    @staticmethod
    def extract_forms(url: str, html_content: str) -> List[Dict[str, Any]]:
        forms = []
        soup = BeautifulSoup(html_content, "html.parser")
        
        for form in soup.find_all("form"):
            form_data = {
                "action": urljoin(url, form.get("action", "")),
                "method": form.get("method", "GET").upper(),
                "inputs": []
            }
            
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    form_data["inputs"].append({
                        "name": name,
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", "")
                    })
            
            if form_data["inputs"]:
                forms.append(form_data)
                
        return forms

    @staticmethod
    def has_state_changing_action(endpoint_context: Any) -> bool:
        """Determines if the endpoint is relevant for CSRF/IDOR."""
        return any(f["method"] in ["POST", "PUT", "DELETE", "PATCH"] for f in endpoint_context.forms)
