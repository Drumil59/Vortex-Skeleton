import requests
import time
import urllib3
import random
import ssl
from typing import Optional, Dict
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.poolmanager import PoolManager
from threading import Lock

# Disable SSL Warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class LegacyAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.options |= 0x4 
        try: ctx.minimum_version = ssl.TLSVersion.TLSv1
        except: pass
        try: ctx.set_ciphers('DEFAULT@SECLEVEL=0')
        except: pass 

        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=ctx,
            **pool_kwargs
        )

class HTTPClient:
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
    ]

    def __init__(self, config):
        self.session = requests.Session()
        self.config = config
        
        # New: Request Caching (LRU style or Dict)
        self.cache = {}
        self.cache_lock = Lock()
        
        retries = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        
        adapter = LegacyAdapter(
            max_retries=retries,
            pool_connections=getattr(config, 'threads', 10),
            pool_maxsize=getattr(config, 'threads', 10)
        )
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        if not getattr(config, 'stealth', False):
            self.session.headers.update({
                "User-Agent": config.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Connection": "keep-alive",
            })
        
        if hasattr(config, 'proxy') and config.proxy:
            self.session.proxies.update({
                "http": config.proxy,
                "https": config.proxy
            })

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Standard request with caching support.
        """
        # 1. Check Cache (Only for GET/HEAD with no data)
        if method in ["GET", "HEAD"] and not kwargs.get("data") and not kwargs.get("json"):
            cache_key = f"{method}:{url}:{str(kwargs.get('params', ''))}"
            with self.cache_lock:
                if cache_key in self.cache:
                    return self.cache[cache_key]

        try:
            if getattr(self.config, 'stealth', False):
                time.sleep(random.uniform(1.0, 3.0))
                headers = kwargs.get("headers", {}).copy()
                if "User-Agent" not in headers:
                    headers["User-Agent"] = random.choice(self.USER_AGENTS)
                kwargs["headers"] = headers

            kwargs.setdefault('timeout', self.config.timeout)
            kwargs.setdefault('verify', False)
            
            start = time.time()
            r = self.session.request(method, url, **kwargs)
            r.elapsed_total = time.time() - start
            
            # Cache the response if successful
            if r and 200 <= r.status_code < 300 and method in ["GET", "HEAD"]:
                with self.cache_lock:
                    # Simple size limit for cache
                    if len(self.cache) < 1000:
                        self.cache[cache_key] = r
            
            return r
        except Exception as e:
            return None

    def create_budgeted_client(self, endpoint_budget: int = 25):
        """
        Creates a restricted wrapper around this client that enforces a request budget.
        Used for per-endpoint scanning limits.
        """
        return BudgetedHTTPClient(self, endpoint_budget)


class BudgetedHTTPClient:
    """
    Wrapper that stops requests after a budget is exceeded.
    """
    def __init__(self, parent_client: HTTPClient, budget: int):
        self.parent = parent_client
        self.budget = budget
        self.requests_made = 0
        self.lock = Lock()

    def request(self, method: str, url: str, **kwargs):
        with self.lock:
            if self.requests_made >= self.budget:
                # Budget exceeded, return None to gracefully stop plugins
                return None
            self.requests_made += 1
            
        return self.parent.request(method, url, **kwargs)
