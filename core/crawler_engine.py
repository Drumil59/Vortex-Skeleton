import asyncio
import logging
from typing import List, Set, Dict
from .url_normalizer import URLNormalizer
from .html_crawler import HTMLCrawler
from .js_miner import JSMiner
from .browser_crawler import BrowserCrawler
from .attack_surface_db import Endpoint

class CrawlerEngine:
    """
    Central Orchestration for Multi-Source Discovery.
    Coordinates HTML parsing, JS mining, and Browser rendering.
    """
    def __init__(self, target_url: str, http_client, depth: int = 3):
        self.target_url = target_url
        self.http = http_client
        self.max_depth = depth
        self.logger = logging.getLogger("vortex.crawler")
        
        # Sub-modules
        self.normalizer = URLNormalizer(target_url)
        self.html_crawler = HTMLCrawler(self.normalizer)
        self.js_miner = JSMiner(self.normalizer, http_client)
        self.browser_crawler = BrowserCrawler(self.normalizer)
        
        # State
        self.visited_urls: Set[str] = set()
        self.crawl_queue = []
        self.discovered_endpoints: List[Endpoint] = []
        
        # Summary Stats
        self.stats = {
            "html_links": 0,
            "js_endpoints": 0,
            "forms": 0,
            "browser_requests": 0
        }

    async def start(self):
        """Main execution loop for recursive crawling."""
        self.logger.info(f"[*] INITIATING MULTI-SOURCE CRAWL: {self.target_url}")
        
        # Initial Seed
        start_url = self.normalizer.normalize(self.target_url)
        self.crawl_queue.append((start_url, 0)) # (url, current_depth)

        while self.crawl_queue:
            url, depth = self.crawl_queue.pop(0)
            
            if url in self.visited_urls or depth > self.max_depth:
                continue
            
            self.visited_urls.add(url)
            self.logger.info(f"[*] Crawling (Depth {depth}): {url}")

            # 1. Fetch Page
            resp = self.http.request("GET", url)
            if not resp or resp.status_code >= 400:
                continue

            # 2. HTML Extraction
            to_crawl, eps = self.html_crawler.extract(url, resp.text)
            self.discovered_endpoints.extend(eps)
            self.stats["html_links"] += len([e for e in eps if "form" not in e.tags])
            self.stats["forms"] += len([e for e in eps if "form" in e.tags])

            # 3. JS Mining (for discovered scripts)
            for ep in eps:
                if 'script' in ep.tags:
                    js_eps = self.js_miner.mine(ep.url)
                    self.discovered_endpoints.extend(js_eps)
                    self.stats["js_endpoints"] += len(js_eps)

            # 4. Dynamic Discovery (Browser)
            # Only run browser on actual HTML pages to save resources
            if "text/html" in resp.headers.get("Content-Type", ""):
                dynamic_eps = await self.browser_crawler.crawl(url)
                self.discovered_endpoints.extend(dynamic_eps)
                self.stats["browser_requests"] += len(dynamic_eps)

            # 5. Queue next level
            if depth < self.max_depth:
                for next_url in to_crawl:
                    if next_url not in self.visited_urls:
                        self.crawl_queue.append((next_url, depth + 1))

        self.logger.info("\n" + "="*30)
        self.logger.info("[=] DISCOVERY SUMMARY")
        self.logger.info(f"HTML links discovered: {self.stats['html_links']}")
        self.logger.info(f"JS endpoints discovered: {self.stats['js_endpoints']}")
        self.logger.info(f"Forms discovered: {self.stats['forms']}")
        self.logger.info(f"Browser requests captured: {self.stats['browser_requests']}")
        self.logger.info(f"Total unique endpoints: {len(self.discovered_endpoints)}")
        self.logger.info("="*30)
        
        return self.discovered_endpoints
