import asyncio
import aiohttp
import time
from typing import List, Callable, Any
from .attack_surface_db import Endpoint

class MassScanner:
    def __init__(self, concurrency: int = 50, timeout: int = 10):
        self.concurrency = concurrency
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        self.results = []

    async def fetch(self, session: aiohttp.ClientSession, endpoint: Endpoint, callback: Callable):
        async with self.semaphore:
            try:
                start_time = time.time()
                async with session.request(
                    method=endpoint.method,
                    url=endpoint.url,
                    timeout=self.timeout,
                    ssl=False
                ) as response:
                    text = await response.text()
                    elapsed = time.time() - start_time
                    await callback(endpoint, response, text, elapsed)
            except Exception as e:
                # Log error or handle silently for mass scanning
                pass

    async def run(self, endpoints: List[Endpoint], callback: Callable):
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.fetch(session, ep, callback) for ep in endpoints]
            await asyncio.gather(*tasks)

    def start(self, endpoints: List[Endpoint], callback: Callable):
        asyncio.run(self.run(endpoints, callback))
