from typing import List, Dict, Any
import logging

class AttackChainEngine:
    """
    Correlates discovered vulnerabilities to identify potential attack chains.
    """
    def __init__(self):
        self.logger = logging.getLogger("AttackChainEngine")

    def generate_chains(self, triaged_findings: Dict[str, List[Dict[str, Any]]]) -> List[str]:
        chains = []
        all_vulns = []
        
        for sev, items in triaged_findings.items():
            all_vulns.extend(items)
            
        titles = [v.get('title', '').lower() for v in all_vulns]
        endpoints = [v.get('endpoint', '').lower() for v in all_vulns]

        # 1. IDOR -> Privilege Escalation
        if any('idor' in t for t in titles) and any('admin' in e or 'user' in e for e in endpoints):
            chains.append("Possible Chain: IDOR detected near administrative endpoints. Attempt Privilege Escalation by modifying object references.")

        # 2. XSS -> Session Hijacking / CSRF Bypass
        if any('xss' in t for t in titles) and any('csrf' in t for t in titles):
            chains.append("Possible Chain: Reflected/Stored XSS found alongside CSRF weakness. Use XSS to bypass CSRF tokens and force state changes.")

        # 3. SSRF -> Internal Pivoting
        if any('ssrf' in t for t in titles):
            chains.append("Possible Chain: SSRF vulnerability detected. Attempt to pivot to internal network (e.g., AWS Metadata, internal admin panels).")
            
        # 4. Open Redirect -> OAuth Token Stealing
        if any('open redirect' in t for t in titles) and any('oauth' in e or 'login' in e for e in endpoints):
            chains.append("Possible Chain: Open Redirect on authentication flow. Attempt to steal OAuth tokens or craft sophisticated phishing links.")

        return chains
