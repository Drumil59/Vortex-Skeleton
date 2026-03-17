import asyncio
import time
import logging
from typing import Optional, Dict, Any

class TrafficController:
    """
    Handles rate limiting, backoff, and WAF detection to ensure scan stability.
    """
    def __init__(self, max_retries: int = 3, base_delay: float = 1.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.waf_detected = False
        self.logger = logging.getLogger("TrafficController")
        
        self.waf_signatures = [
            "cloudflare", "incapsula", "imperva", "sucuri", "awswaf", "akamai"
        ]

    def detect_waf(self, response_headers: Dict[str, str], response_body: str) -> bool:
        headers_str = str(response_headers).lower()
        body_str = response_body.lower()
        
        for sig in self.waf_signatures:
            if sig in headers_str or (sig in body_str and "block" in body_str):
                self.logger.warning(f"[!] WAF Detected: {sig.upper()}")
                self.waf_detected = True
                return True
        return False

    async def execute_with_backoff(self, request_coro, *args, **kwargs) -> Optional[Any]:
        retries = 0
        while retries <= self.max_retries:
            try:
                # Add adaptive delay if WAF is detected
                if self.waf_detected:
                    await asyncio.sleep(self.base_delay * 2)
                    
                response = await request_coro(*args, **kwargs)
                
                # Check for rate limiting
                if response and hasattr(response, 'status_code') and response.status_code == 429:
                    retries += 1
                    delay = self.base_delay * (2 ** retries)
                    self.logger.info(f"[*] HTTP 429 Rate Limit hit. Backing off for {delay}s...")
                    await asyncio.sleep(delay)
                    continue
                    
                if response and hasattr(response, 'headers') and hasattr(response, 'text'):
                    self.detect_waf(response.headers, response.text)
                    
                return response
                
            except Exception as e:
                retries += 1
                await asyncio.sleep(self.base_delay)
                if retries > self.max_retries:
                    self.logger.error(f"[!] Request failed after {self.max_retries} retries: {e}")
                    return None
        return None
