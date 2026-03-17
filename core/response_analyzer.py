import re
from typing import Dict, Any, Optional

class ResponseAnalyzer:
    """
    Enterprise-grade Response Analysis Engine.
    Performs differential analysis to confirm vulnerability presence.
    """
    def __init__(self):
        self.error_patterns = [
            r"SQL syntax.*?MySQL", r"Warning.*?mysqli_", r"PostgreSQL.*?ERROR",
            r"SQLite/JDBCDriver", r"System\.Data\.SqlClient\.SqlException",
            r"Uncaught.*?Error", r"Invalid.*?parameter"
        ]

    def analyze(self, baseline: Optional[Any], current: Any, payload: str = "") -> Dict[str, Any]:
        """Compares baseline vs current response."""
        result = {
            "reflection": False,
            "error_detected": False,
            "length_delta": 0,
            "status_changed": False
        }
        
        if not current: return result
        
        # 1. Reflection Detection
        if payload and payload in current.text:
            result["reflection"] = True
            
        # 2. Error Detection
        for pattern in self.error_patterns:
            if re.search(pattern, current.text, re.IGNORECASE):
                result["error_detected"] = True
                break
                
        # 3. Baseline Comparison
        if baseline:
            result["length_delta"] = abs(len(current.text) - len(baseline.text))
            result["status_changed"] = current.status_code != baseline.status_code
            
        return result
