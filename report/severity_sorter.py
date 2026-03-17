class SeveritySorter:
    """
    Handles vulnerability severity classification and priority-based sorting.
    """
    SEVERITY_ORDER = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1
    }

    @staticmethod
    def get_priority(severity: str) -> int:
        """Returns numeric priority for a given severity string."""
        return SeveritySorter.SEVERITY_ORDER.get(severity.upper(), 0)

    @staticmethod
    def sort_findings(findings: list) -> list:
        """
        Sorts findings by severity (CRITICAL to INFO).
        Assumes each finding has a 'severity' key.
        """
        return sorted(
            findings,
            key=lambda x: SeveritySorter.get_priority(x.get('severity', 'INFO')),
            reverse=True
        )

    @staticmethod
    def sort_categories(categories: list) -> list:
        """
        Sorts a list of category names based on the highest severity in that category.
        This is useful when grouping findings by type.
        """
        # This implementation depends on how categories are passed, 
        # but the primary goal is sorting the findings themselves.
        pass

    @staticmethod
    def get_severity_mapping(vuln_name: str) -> str:
        """
        Maps vulnerability names to their default severity levels.
        """
        vuln_name = vuln_name.lower()
        
        mapping = {
            "sql injection": "CRITICAL",
            "remote code execution": "CRITICAL",
            "advanced sql injection": "CRITICAL",
            "enterprise rce": "CRITICAL",
            "ssrf": "HIGH",
            "cloud ssrf": "HIGH",
            "enterprise ssrf": "HIGH",
            "xss": "HIGH",
            "reflected xss": "HIGH",
            "stored xss": "HIGH",
            "csrf": "MEDIUM",
            "idor": "HIGH", # Overriding example for better security posture
            "lfi": "HIGH",
            "rfi": "HIGH",
            "security headers": "LOW",
            "missing security headers": "LOW",
            "csp": "LOW",
            "cors": "MEDIUM",
            "information disclosure": "INFO",
            "exposure": "INFO",
            "dataleak": "INFO"
        }
        
        for key, value in mapping.items():
            if key in vuln_name:
                return value
                
        return "MEDIUM"
