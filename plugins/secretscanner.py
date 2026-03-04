from .base import BasePlugin
import re

class SecretScannerPlugin(BasePlugin):
    """
    Scans HTTP response bodies for hardcoded API keys, tokens, and secrets.
    """
    name = "Secret Scanner"

    # Regex patterns for common secrets
    PATTERNS = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
        "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
        "Private Key": r"-----BEGIN [A-Z]+ PRIVATE KEY-----",
        "Generic API Key": r"(?i)(api_key|apikey|secret|token)[\s]*[=:]+[\s]*['\"]([a-zA-Z0-9_\-]{16,})['\"]",
        "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
        "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
        "GitHub Personal Access Token": r"ghp_[0-9a-zA-Z]{36}",
        "Twilio Account SID": r"AC[a-z0-9]{32}"
    }

    def should_run(self, endpoint):
        # Run on all text-based responses (HTML, JS, JSON)
        return True 

    def run(self, http, endpoint, analyzer, evidence):
        try:
            resp = http.request("GET", endpoint.url)
            if not resp or not resp.text:
                return

            # Analyze response body
            for name, pattern in self.PATTERNS.items():
                matches = re.findall(pattern, resp.text)
                if matches:
                    # Deduplicate matches
                    unique_matches = list(set(matches))
                    
                    # For Generic API Key, the regex captures groups, so we flatten/format
                    if name == "Generic API Key":
                        formatted = [f"{m[0]}={m[1]}" if isinstance(m, tuple) else m for m in unique_matches]
                        unique_matches = formatted

                    # Truncate for report if too many
                    report_matches = unique_matches[:5]
                    
                    evidence.add(
                        plugin=self.name,
                        endpoint=endpoint.url,
                        payload=None,
                        evidence=f"Found {name}",
                        confidence="HIGH",
                        details=f"Matches: {', '.join(report_matches)}"
                    )

        except Exception:
            pass
