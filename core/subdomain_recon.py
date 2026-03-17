import aiohttp
import asyncio
import re
from typing import Set

class SubdomainRecon:
    """
    Automatically discovers subdomains of a target using passive techniques.
    """
    def __init__(self, concurrency: int = 20):
        self.concurrency = concurrency

    async def _fetch_crt_sh(self, domain: str, session: aiohttp.ClientSession) -> Set[str]:
        subdomains = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            async with session.get(url, timeout=15) as response:
                if response.status == 200:
                    data = await response.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        if name:
                            for sub in name.split('\n'):
                                if sub.endswith(domain) and not sub.startswith('*'):
                                    subdomains.add(sub.lower())
        except Exception:
            pass 
        return subdomains
        
    async def _fetch_hackertarget(self, domain: str, session: aiohttp.ClientSession) -> Set[str]:
        subdomains = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            async with session.get(url, timeout=15) as response:
                if response.status == 200:
                    text = await response.text()
                    for line in text.splitlines():
                        if ',' in line:
                            sub = line.split(',')[0]
                            if sub.endswith(domain):
                                subdomains.add(sub.lower())
        except Exception:
            pass
        return subdomains

    async def discover(self, domain: str) -> Set[str]:
        print(f"[*] Starting Subdomain Recon for: {domain}")
        subdomains = set()
        
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [
                self._fetch_crt_sh(domain, session),
                self._fetch_hackertarget(domain, session)
            ]
            results = await asyncio.gather(*tasks)
            for res in results:
                subdomains.update(res)
            
        # Basic validation to ensure accuracy (Valid domain regex)
        domain_regex = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
        valid_subdomains = {sub for sub in subdomains if domain_regex.match(sub)}
            
        print(f"[+] Discovered {len(valid_subdomains)} valid subdomains from passive sources.")
        return valid_subdomains

    def start(self, domain: str) -> Set[str]:
        return asyncio.run(self.discover(domain))
