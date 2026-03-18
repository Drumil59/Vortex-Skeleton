import asyncio
import httpx
import time
from typing import List, Callable, Any
from .attack_surface_db import Endpoint

class MassScanner:
    def __init__(self, concurrency: int = 50, timeout: int = 10):
        self.concurrency = concurrency
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        self.results = []

    async def fetch(self, client: httpx.AsyncClient, endpoint: Endpoint, callback: Callable):
        async with self.semaphore:
            try:
                start_time = time.time()
                response = await client.request(
                    method=endpoint.method,
                    url=endpoint.url,
                    timeout=self.timeout
                )
                text = response.text
                elapsed = time.time() - start_time
                await callback(endpoint, response, text, elapsed)
            except Exception as e:
                # Log error or handle silently for mass scanning
                pass

    async def run(self, endpoints: List[Endpoint], callback: Callable):
        async with httpx.AsyncClient(verify=False, limits=httpx.Limits(max_connections=self.concurrency)) as client:
            tasks = [self.fetch(client, ep, callback) for ep in endpoints]
            await asyncio.gather(*tasks)

    def start(self, endpoints: List[Endpoint], callback: Callable):
        asyncio.run(self.run(endpoints, callback))
