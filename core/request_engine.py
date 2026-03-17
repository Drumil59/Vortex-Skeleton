from typing import Dict, Any, Optional
import json

class RequestEngine:
    """
    Advanced Request Replay & Injection Engine.
    Supports multi-vector fuzzing: Query, Data, JSON, Headers, Cookies.
    """
    def __init__(self, http_client):
        self.http = http_client

    def send_injected(self, endpoint: Any, vector: str, param_name: str, payload: str) -> Optional[Any]:
        """
        Sends a request with a payload injected into a specific vector.
        Vectors: 'query', 'form', 'json', 'header', 'cookie'
        """
        params = {p['name']: p['value'] for p in endpoint.params if p.get('type') == 'query'}
        data = {p['name']: p['value'] for p in endpoint.params if p.get('type') == 'form'}
        json_body = {} # Logic for JSON extraction would go here
        headers = endpoint.headers.copy()
        cookies = {}

        if vector == 'query':
            params[param_name] = payload
        elif vector == 'form':
            data[param_name] = payload
        elif vector == 'header':
            headers[param_name] = payload
        elif vector == 'cookie':
            cookies[param_name] = payload
        elif vector == 'json':
            json_body[param_name] = payload

        return self.http.request(
            method=endpoint.method,
            url=endpoint.url,
            params=params,
            data=data if not json_body else None,
            json=json_body if json_body else None,
            headers=headers,
            cookies=cookies
        )
