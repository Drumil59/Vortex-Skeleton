import httpx
import asyncio
import re
from typing import Set

class SubdomainRecon:
    """
    Automatically discovers subdomains of a target using passive techniques.
    """
    def __init__(self, concurrency: int = 20):
        self.concurrency = concurrency

    async def _fetch_crt_sh(self, domain: str, client: httpx.AsyncClient) -> Set[str]:
        subdomains = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            response = await client.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    if name:
                        for sub in name.split('\n'):
                            if sub.endswith(domain) and not sub.startswith('*'):
                                subdomains.add(sub.lower())
        except Exception:
            pass 
        return subdomains
        
    async def _fetch_hackertarget(self, domain: str, client: httpx.AsyncClient) -> Set[str]:
        subdomains = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            response = await client.get(url, timeout=15)
            if response.status_code == 200:
                text = response.text
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
        
        limits = httpx.Limits(max_connections=self.concurrency)
        async with httpx.AsyncClient(verify=False, limits=limits) as client:
            tasks = [
                self._fetch_crt_sh(domain, client),
                self._fetch_hackertarget(domain, client)
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
