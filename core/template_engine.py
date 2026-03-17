import os
import yaml
import glob
import aiohttp
import asyncio
from typing import List, Dict, Any
from .attack_surface_db import Endpoint

class TemplateEngine:
    """
    Nuclei-style YAML template scanning engine.
    Loads templates and executes them against discovered endpoints.
    Optimized for execution speed with Semaphores and Connection Pooling.
    """
    def __init__(self, templates_dir: str = "templates/", concurrency: int = 50):
        self.templates_dir = templates_dir
        self.templates = self._load_templates()
        self.concurrency = concurrency

    def _load_templates(self) -> List[Dict[str, Any]]:
        templates = []
        if not os.path.exists(self.templates_dir):
            return templates
            
        for filepath in glob.glob(f"{self.templates_dir}/*.yaml"):
            try:
                with open(filepath, 'r') as f:
                    template = yaml.safe_load(f)
                    if template and 'id' in template and 'request' in template:
                        templates.append(template)
            except Exception as e:
                print(f"[!] Error loading template {filepath}: {e}")
        return templates

    async def _execute_template(self, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, endpoint: Endpoint, template: Dict[str, Any]) -> List[dict]:
        findings = []
        req = template['request']
        payloads = template.get('payloads', [''])
        matchers = template.get('matchers', {})

        for payload in payloads:
            # Build target URL (replace {{payload}} if present)
            target_url = endpoint.url
            if "{{payload}}" in req.get('path', ''):
                if '?' in target_url:
                    base, query = target_url.split('?', 1)
                    target_url = f"{base}{req['path'].replace('{{payload}}', payload)}"
                else:
                    target_url = f"{target_url}{req['path'].replace('{{payload}}', payload)}"

            method = req.get('method', 'GET')
            headers = req.get('headers', {})
            body = req.get('body', '')

            # Inject payload into headers and body if present
            injected_headers = {k: v.replace('{{payload}}', payload) if isinstance(v, str) else v for k, v in headers.items()}
            injected_body = body.replace('{{payload}}', payload) if isinstance(body, str) else body
            
            async with semaphore:
                try:
                    # Passing data if method allows, else params. Using kwargs properly.
                    kwargs = {"timeout": 5, "ssl": False, "headers": injected_headers}
                    if injected_body and method.upper() in ["POST", "PUT", "PATCH"]:
                        kwargs["data"] = injected_body

                    async with session.request(method, target_url, **kwargs) as response:
                        text = await response.text()
                        
                        # Evaluate matchers
                        if matchers.get('type') == 'word':
                            for word in matchers.get('words', []):
                                if word in text:
                                    findings.append({
                                        "template_id": template['id'],
                                        "endpoint": target_url,
                                        "payload": payload,
                                        "severity": template.get("info", {}).get("severity", "medium")
                                    })
                                    break # Found a match for this payload
                        elif matchers.get('type') == 'status':
                            status_codes = matchers.get('status', [])
                            if response.status in status_codes:
                                findings.append({
                                    "template_id": template['id'],
                                    "endpoint": target_url,
                                    "payload": payload,
                                    "severity": template.get("info", {}).get("severity", "medium")
                                })
                except Exception as e:
                    pass
                
        return findings

    async def scan(self, endpoints: List[Endpoint]) -> List[dict]:
        print(f"[*] Starting Template Engine Scan with {len(self.templates)} templates...")
        all_findings = []
        
        # Use connection pooling to increase execution speed
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)
        semaphore = asyncio.Semaphore(self.concurrency)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for ep in endpoints:
                for template in self.templates:
                    tasks.append(self._execute_template(session, semaphore, ep, template))
            
            # Chunk tasks to prevent memory issues with massive lists
            chunk_size = 1000
            for i in range(0, len(tasks), chunk_size):
                chunk = tasks[i:i + chunk_size]
                results = await asyncio.gather(*chunk)
                for r in results:
                    all_findings.extend(r)
                
        print(f"[+] Template scanning completed. Found {len(all_findings)} issues.")
        return all_findings

    def start(self, endpoints: List[Endpoint]) -> List[dict]:
        return asyncio.run(self.scan(endpoints))
