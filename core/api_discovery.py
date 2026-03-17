import json
import logging
from urllib.parse import urljoin
from typing import List
from .attack_surface_db import Endpoint
from .graphql_engine import GraphQLEngine

class APIDiscovery:
    """
    Detects and parses API definitions (Swagger/OpenAPI/GraphQL).
    """
    COMMON_API_PATHS = [
        "/swagger.json",
        "/openapi.json",
        "/v1/swagger.json",
        "/v2/swagger.json",
        "/api-docs",
        "/v1/api-docs",
        "/swagger-ui.html",
        "/graphql",
        "/api/graphql",
        "/v1/graphql"
    ]

    def __init__(self, http_client):
        self.http = http_client
        self.graphql_engine = GraphQLEngine(http_client)
        self.logger = logging.getLogger("vortex.api_discovery")

    def discover(self, base_url: str) -> List[Endpoint]:
        endpoints = []
        for path in self.COMMON_API_PATHS:
            target_url = urljoin(base_url, path)
            
            # Use POST for GraphQL detection if it's a known GraphQL path
            if "graphql" in path:
                schema = self.graphql_engine.run_introspection(target_url)
                if schema:
                    self.logger.info(f"[+] Confirmed GraphQL endpoint: {target_url}")
                    endpoints.append(Endpoint(url=target_url, method="POST", source="api_discovery", tags={"graphql"}))
                continue

            resp = self.http.request("GET", target_url)
            if resp and resp.status_code == 200:
                # Handle Swagger/OpenAPI
                if "application/json" in resp.headers.get("Content-Type", ""):
                    try:
                        data = resp.json()
                        if "paths" in data:
                            endpoints.extend(self._parse_swagger(target_url, data))
                    except:
                        pass
        
        return endpoints

    def _parse_swagger(self, source_url: str, data: dict) -> List[Endpoint]:
        endpoints = []
        base_path = data.get("basePath", "")
        paths = data.get("paths", {})
        
        for path, methods in paths.items():
            full_path = base_path + path
            full_url = urljoin(source_url, full_path)
            
            for method, details in methods.items():
                params = []
                for p in details.get("parameters", []):
                    params.append({
                        'name': p.get("name"),
                        'type': p.get("in", "query"),
                        'required': p.get("required", False)
                    })
                
                ep = Endpoint(
                    url=full_url, 
                    method=method.upper(), 
                    params=params, 
                    source="api_discovery",
                    tags={"api"}
                )
                endpoints.append(ep)
                
        return endpoints
