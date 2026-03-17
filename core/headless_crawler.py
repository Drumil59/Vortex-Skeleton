import asyncio
from typing import Set, List
from .attack_surface_db import Endpoint

class HeadlessCrawler:
    """
    Advanced crawler using Playwright to render JavaScript, discover dynamic endpoints,
    and detect runtime API calls.
    """
    def __init__(self, headless: bool = True):
        self.headless = headless
        self.visited_urls: Set[str] = set()

    async def crawl(self, start_url: str) -> List[Endpoint]:
        endpoints = []
        seen_requests = set()
        
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            print("[!] Playwright not installed. Falling back to static crawling.")
            return endpoints

        print(f"[*] Starting Headless Crawler on {start_url}")
        
        def handle_request(request):
            req_id = f"{request.method}:{request.url}"
            if req_id not in seen_requests:
                seen_requests.add(req_id)
                endpoints.append(
                    Endpoint(url=request.url, method=request.method, source="headless_crawler", tags={"dynamic_api"})
                )

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()

            # Listen for runtime API calls using the deduplicating handler
            page.on("request", handle_request)

            try:
                await page.goto(start_url, wait_until="networkidle", timeout=15000)
                
                # Extract DOM generated links
                links = await page.evaluate('''() => {
                    return Array.from(document.querySelectorAll('a')).map(a => a.href);
                }''')
                
                for link in links:
                    if link and start_url in link:
                        endpoints.append(Endpoint(url=link, method="GET", source="headless_crawler", tags={"dom_link"}))
                        
                # Extract DOM forms
                forms = await page.evaluate('''() => {
                    return Array.from(document.querySelectorAll('form')).map(f => {
                        return { action: f.action, method: f.method };
                    });
                }''')
                
                for form in forms:
                    if form.get('action'):
                        endpoints.append(Endpoint(url=form['action'], method=form.get('method', 'GET').upper(), source="headless_crawler", tags={"dom_form"}))
                        
            except Exception as e:
                print(f"[!] Headless crawl error on {start_url}: {e}")
                
            await browser.close()
            
        print(f"[+] Headless crawler discovered {len(endpoints)} dynamic endpoints/requests.")
        return endpoints

    def start(self, start_url: str) -> List[Endpoint]:
        return asyncio.run(self.crawl(start_url))
