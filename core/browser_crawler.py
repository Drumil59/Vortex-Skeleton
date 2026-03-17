import asyncio
import logging
from playwright.async_api import async_playwright
from typing import List, Set
from .attack_surface_db import Endpoint

class BrowserCrawler:
    """
    Dynamic Discovery Engine using Playwright.
    Captures XHR/Fetch requests and dynamic DOM changes.
    """
    def __init__(self, normalizer):
        self.normalizer = normalizer
        self.logger = logging.getLogger("vortex.browser")
        self.intercepted_endpoints = []

    async def crawl(self, url: str):
        """Renders page and intercepts network requests."""
        self.intercepted_endpoints = []
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (X11; Linux x86_64) Vortex/5.0"
                )
                page = await context.new_page()

                # Intercept Network Requests
                page.on("request", self._handle_request)

                await page.goto(url, wait_until="networkidle", timeout=30000)
                
                # Optional: Simulate interactions (click buttons, scroll)
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                await asyncio.sleep(2) # Wait for dynamic content

                await browser.close()
        except Exception as e:
            self.logger.debug(f"Browser crawl failed for {url}: {e}")
            
        return self.intercepted_endpoints

    def _handle_request(self, request):
        """Callback for Playwright request interception."""
        url = request.url
        method = request.method
        
        normalized = self.normalizer.normalize(url)
        if normalized and self.normalizer.is_in_scope(normalized):
            self.intercepted_endpoints.append(Endpoint(
                url=normalized,
                method=method,
                source="browser_interception",
                tags={"dynamic", request.resource_type}
            ))
