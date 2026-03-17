import requests
import time
import urllib3
import random
import logging
from typing import Optional, Dict, Any

# Disable SSL Warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HTTPClient:
    """
    Robust Offensive HTTP Client.
    Handles dynamic payload injection into Parameters, JSON, Headers, and Cookies.
    """
    def __init__(self, config):
        self.session = requests.Session()
        self.config = config
        self.logger = logging.getLogger("vortex.http")
        
        if not getattr(config, 'stealth', False):
            self.session.headers.update({
                "User-Agent": getattr(config, 'user_agent', 'Vortex/5.0'),
                "Accept": "*/*"
            })

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Executes an HTTP request with full control over injection points.
        """
        try:
            # Enforce global settings
            kwargs.setdefault('timeout', getattr(self.config, 'timeout', 10))
            kwargs.setdefault('verify', False)
            kwargs.setdefault('allow_redirects', True)

            # Debug logging of the request
            self.logger.debug(f"Request: {method} {url} | Params: {kwargs.get('params')} | Headers: {kwargs.get('headers')} | Cookies: {kwargs.get('cookies')}")

            response = self.session.request(method, url, **kwargs)
            
            # Debug logging of the response
            self.logger.debug(f"Response: {response.status_code} | Length: {len(response.text)}")
            
            return response
        except Exception as e:
            self.logger.debug(f"Request failed to {url}: {e}")
            return None

    def create_budgeted_client(self, endpoint_budget: int = 50):
        return self # Simplified for repair
