from typing import List, Dict, Any

class AITriageEngine:
    """
    Analyzes scan results, reduces false positives, and prioritizes vulnerabilities.
    Simulates AI/Heuristic evaluation for higher accuracy.
    """
    def __init__(self):
        self.severity_map = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0
        }

    def _determine_severity(self, finding: Dict[str, Any]) -> str:
        title = finding.get('title', '').lower()
        if any(x in title for x in ['sql injection', 'rce', 'command injection', 'ssrf', 'xxe']):
            return 'high'
        elif any(x in title for x in ['xss', 'open redirect', 'csrf', 'idor', 'deserialization']):
            return 'medium'
        return 'low'
        
    def _reduce_false_positives(self, finding: Dict[str, Any]) -> None:
        """
        Heuristics to reduce false positives and adjust confidence.
        """
        title = finding.get('title', '').lower()
        payload = finding.get('payload', '')
        severity = finding.get('severity', 'low')
        
        # Base confidence
        confidence = "Medium"
        
        # 1. Empty Payload Validation
        if not payload and severity in ["high", "medium"]:
            # High severity bugs typically require a specific payload. If none, lower confidence.
            confidence = "Low"
            
        # 2. XSS specific heuristic
        if 'xss' in title:
            if payload and any(c in payload for c in ['<script', 'onerror', 'onload', 'javascript:']):
                confidence = "High"
            else:
                confidence = "Low"
                
        # 3. SQLi specific heuristic
        if 'sql' in title:
            if payload and any(c in payload for c in ["'", '"', '`', 'UNION', 'SELECT', 'SLEEP']):
                confidence = "High"
            else:
                confidence = "Low"
                
        finding['ai_confidence'] = confidence

    def triage(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        print("[*] AI Triage Engine analyzing findings for False Positives...")
        
        triaged_results = {
            "high": [],
            "medium": [],
            "low": []
        }
        
        # Deduplication mechanism to reduce noise
        unique_findings = {}

        for finding in findings:
            severity = finding.get("severity")
            if not severity:
                severity = self._determine_severity(finding)
                finding["severity"] = severity
                
            self._reduce_false_positives(finding)
            
            # If confidence is Low, we downgrade the severity to reduce noise
            if finding.get('ai_confidence') == "Low":
                if severity == "high": finding["severity"] = "medium"
                elif severity == "medium": finding["severity"] = "low"
                elif severity == "low": finding["severity"] = "info"
            
            # Deduplicate by endpoint + title
            dedup_key = f"{finding.get('endpoint')}_{finding.get('title')}"
            if dedup_key not in unique_findings:
                unique_findings[dedup_key] = finding
                
        for finding in unique_findings.values():
            sev = finding.get("severity")
            if sev in ["critical", "high"]:
                triaged_results["high"].append(finding)
            elif sev == "medium":
                triaged_results["medium"].append(finding)
            elif sev == "low":
                triaged_results["low"].append(finding)

        # Sort within buckets
        for sev in triaged_results:
            triaged_results[sev] = sorted(triaged_results[sev], key=lambda x: x.get("endpoint", ""))
            
        return triaged_results

    def print_report(self, triaged_results: Dict[str, List[Dict[str, Any]]]):
        print("\n\033[95m[AI TRIAGE REPORT - FILTERED & PRIORITIZED]\033[0m")
        for severity in ["high", "medium", "low"]:
            items = triaged_results.get(severity, [])
            if items:
                print(f"\n> {severity.upper()} PRIORITY ({len(items)} items):")
                for item in items:
                    title = item.get('title') or item.get('template_id', 'Unknown Vulnerability')
                    conf = item.get('ai_confidence', 'Medium')
                    print(f"  - [{conf} Conf] {title} on {item.get('endpoint')}")
        print("-" * 30)
