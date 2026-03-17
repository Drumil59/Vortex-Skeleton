import base64
import json
import jwt
from typing import Optional, Dict

class JWTEngine:
    """
    Handles detection and security analysis of JWT tokens.
    """
    def decode_unverified(self, token: str) -> Optional[Dict]:
        try:
            # Manually decode to avoid dependency on specific lib if needed
            # but using PyJWT is cleaner.
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            return {"header": header, "payload": payload}
        except:
            return None

    def check_weak_configs(self, token: str) -> list:
        findings = []
        decoded = self.decode_unverified(token)
        if not decoded:
            return findings

        header = decoded.get("header", {})
        # 1. Algorithm None
        if header.get("alg", "").lower() == "none":
            findings.append("JWT Algorithm 'none' detected.")

        # 2. Check for sensitive info in payload
        payload = decoded.get("payload", {})
        sensitive_keys = ["password", "secret", "key", "admin", "role"]
        for key in sensitive_keys:
            if key in str(payload).lower():
                findings.append(f"Sensitive keyword '{key}' found in JWT payload.")

        return findings
