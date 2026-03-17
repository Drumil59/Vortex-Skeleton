import sys
import json
import logging
from typing import Dict, List, Any

class CICDScanner:
    """
    Handles Vortex integration into CI/CD pipelines.
    Enforces severity thresholds and generates machine-readable reports.
    """
    def __init__(self, fail_on_severity: str = "high"):
        self.fail_on_severity = fail_on_severity.lower()
        self.severity_levels = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        self.logger = logging.getLogger("CICDScanner")

    def evaluate_results(self, triaged_findings: Dict[str, List[Dict[str, Any]]]):
        """
        Determines if the CI build should fail based on findings.
        """
        print("\n\033[94m[=] CI/CD SECURITY GATE EVALUATION\033[0m")
        max_severity_found = "info"
        
        fail_threshold = self.severity_levels.get(self.fail_on_severity, 3)
        
        for sev, items in triaged_findings.items():
            if items and self.severity_levels.get(sev, 0) >= fail_threshold:
                print(f"\033[91m[!] FAILURE: Found {len(items)} vulnerabilities with severity '{sev}' or higher.\033[0m")
                return False # Indicate failure
                
        print("\033[92m[+] SUCCESS: No vulnerabilities found above the failure threshold.\033[0m")
        return True

    def export_json_report(self, triaged_findings: Dict[str, List[Dict[str, Any]]], filepath: str = "vortex_ci_report.json"):
        with open(filepath, 'w') as f:
            json.dump(triaged_findings, f, indent=4)
        print(f"[+] CI JSON Report exported to {filepath}")
