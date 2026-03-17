import logging
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Tuple
from .attack_surface_db import Endpoint

class HTMLCrawler:
    """
    Extracts endpoints and forms from static HTML content.
    """
    def __init__(self, normalizer):
        self.normalizer = normalizer
        self.logger = logging.getLogger("vortex.html_crawler")

    def extract(self, url: str, html: str) -> Tuple[List[str], List[Endpoint]]:
        """
        Parses HTML to find links and form-based endpoints.
        Returns: (list_of_urls_to_crawl, list_of_discovered_endpoints)
        """
        soup = BeautifulSoup(html, "html.parser")
        urls_to_crawl = []
        endpoints = []

        # 1. Extract Links (a, link, script, iframe, img)
        tags_attrs = {
            'a': 'href',
            'link': 'href',
            'script': 'src',
            'iframe': 'src',
            'img': 'src'
        }

        for tag, attr in tags_attrs.items():
            for element in soup.find_all(tag, **{attr: True}):
                raw_url = element[attr]
                normalized = self.normalizer.normalize(raw_url, base_url=url)
                
                if normalized and self.normalizer.is_http(normalized):
                    if self.normalizer.is_in_scope(normalized):
                        if not self.normalizer.is_static(normalized):
                            urls_to_crawl.append(normalized)
                        
                        endpoints.append(Endpoint(
                            url=normalized,
                            method="GET",
                            source="html_crawler",
                            tags={tag}
                        ))

        # 2. Extract Forms
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            normalized_action = self.normalizer.normalize(action, base_url=url)
            
            if normalized_action and self.normalizer.is_in_scope(normalized_action):
                params = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        params.append({
                            "name": name,
                            "type": inp.get("type", "text"),
                            "value": inp.get("value", "")
                        })
                
                endpoints.append(Endpoint(
                    url=normalized_action,
                    method=method,
                    params=params,
                    source="form_discovery",
                    tags={"form"}
                ))

        return list(set(urls_to_crawl)), endpoints
