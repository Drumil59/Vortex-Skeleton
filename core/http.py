import httpx
import time
import random
import logging
import asyncio
from typing import Optional, Dict, Any

class HTTPClient:
    """
    Robust Offensive HTTP Client using HTTPX.
    Handles dynamic payload injection into Parameters, JSON, Headers, and Cookies.
    Supports both Synchronous and Asynchronous requests.
    """
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger("vortex.http")
        
        # Default headers
        self.default_headers = {
            "Accept": "*/*"
        }
        if not getattr(config, 'stealth', False):
            self.default_headers["User-Agent"] = getattr(config, 'user_agent', 'Vortex/5.0')

        # Initialize httpx Client (Synchronous)
        self.client = httpx.Client(
            headers=self.default_headers,
            verify=False,
            timeout=getattr(self.config, 'timeout', 10),
            follow_redirects=True
        )
        
        # Async Client (Initialized on demand or here)
        self._async_client: Optional[httpx.AsyncClient] = None

    def request(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        """
        Executes a Synchronous HTTP request.
        """
        try:
            if 'allow_redirects' in kwargs:
                kwargs['follow_redirects'] = kwargs.pop('allow_redirects')
            
            self.logger.debug(f"Sync Request: {method} {url}")
            response = self.client.request(method, url, **kwargs)
            return response
        except Exception as e:
            self.logger.debug(f"Sync Request failed to {url}: {e}")
            return None

    async def async_request(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        """
        Executes an Asynchronous HTTP request.
        """
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                headers=self.default_headers,
                verify=False,
                timeout=getattr(self.config, 'timeout', 10),
                follow_redirects=True
            )
        
        try:
            if 'allow_redirects' in kwargs:
                kwargs['follow_redirects'] = kwargs.pop('allow_redirects')
            
            self.logger.debug(f"Async Request: {method} {url}")
            response = await self._async_client.request(method, url, **kwargs)
            return response
        except Exception as e:
            self.logger.debug(f"Async Request failed to {url}: {e}")
            return None

    def create_budgeted_client(self, endpoint_budget: int = 50):
        return self # Simplified for repair

    def close(self):
        """Close both sync and async clients."""
        self.client.close()
        if self._async_client:
            # Note: Closing an async client should be done with await.
            # This is a bit tricky in a sync close() method.
            # In most cases, the context manager in the caller is better.
            pass
            
    async def aclose(self):
        """Asynchronously close the async client."""
        if self._async_client:
            await self._async_client.aclose()
            self._async_client = None
