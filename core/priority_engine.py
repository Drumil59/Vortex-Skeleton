from .attack_surface_db import Endpoint

class PriorityEngine:
    """
    Prioritizes endpoints for security testing based on high-risk patterns.
    """
    RISK_KEYWORDS = [
        "admin", "login", "auth", "token", "session", "user", 
        "upload", "config", "debug", "test", "v1", "v2", "api"
    ]
    
    PARAM_KEYWORDS = [
        "id", "url", "redirect", "file", "path", "cmd", "exec",
        "key", "password", "secret", "token"
    ]

    def prioritize(self, endpoint: Endpoint) -> int:
        score = 0
        url_lower = endpoint.url.lower()
        
        # 1. Path keywords
        for keyword in self.RISK_KEYWORDS:
            if keyword in url_lower:
                score += 5
        
        # 2. Parameters
        for param in endpoint.params:
            score += 2
            p_name = param.get("name", "").lower()
            for kw in self.PARAM_KEYWORDS:
                if kw in p_name:
                    score += 5
                    
        # 3. Method
        if endpoint.method.upper() in ["POST", "PUT", "DELETE"]:
            score += 5
            
        # 4. Source
        if endpoint.source == "api_discovery":
            score += 10
        elif endpoint.source == "js_miner":
            score += 7
            
        endpoint.priority = score
        return score
