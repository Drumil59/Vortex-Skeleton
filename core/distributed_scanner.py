import json
import logging
from typing import List, Dict, Any, Callable
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from .attack_surface_db import Endpoint

class DistributedScanner:
    """
    Coordinates distributed scanning across multiple worker nodes using Redis as a message broker.
    """
    def __init__(self, redis_url: str = "redis://localhost:6379/0", queue_name: str = "vortex_scan_queue"):
        self.redis_url = redis_url
        self.queue_name = queue_name
        self.logger = logging.getLogger("DistributedScanner")
        
        self.redis_client = None
        if REDIS_AVAILABLE:
            try:
                self.redis_client = redis.from_url(self.redis_url)
                self.redis_client.ping()
            except Exception as e:
                self.logger.warning(f"[!] Could not connect to Redis at {self.redis_url}: {e}")
                self.redis_client = None

    def enqueue_endpoints(self, endpoints: List[Endpoint]):
        if not self.redis_client:
            self.logger.error("Redis is not available. Cannot use distributed scanning.")
            return

        for ep in endpoints:
            data = {
                "url": ep.url,
                "method": ep.method,
                "params": ep.params,
                "source": ep.source,
                "priority": ep.priority
            }
            self.redis_client.lpush(self.queue_name, json.dumps(data))
        
        self.logger.info(f"[+] Enqueued {len(endpoints)} endpoints to {self.queue_name} for distributed scanning.")

    def worker_loop(self, scan_callback: Callable):
        """
        Runs continuously, popping targets from the queue and passing them to the scan_callback.
        """
        import time
        
        if not self.redis_client:
            self.logger.error("Redis is not available.")
            return

        self.logger.info(f"[*] Worker node started. Listening on queue: {self.queue_name}")
        while True:
            try:
                # Blocking pop, waits for 0 means indefinitely
                result = self.redis_client.brpop(self.queue_name, timeout=0)
                if not result:
                    continue
                    
                _, message = result
                data = json.loads(message)
                
                ep = Endpoint(
                    url=data['url'],
                    method=data['method'],
                    params=data['params'],
                    source=data.get('source', 'distributed_worker'),
                    priority=data.get('priority', 0)
                )
                
                # Execute the scan job
                scan_callback(ep)
                
            except Exception as e:
                self.logger.error(f"[!] Distributed worker error: {e}. Retrying in 5 seconds...")
                time.sleep(5)
