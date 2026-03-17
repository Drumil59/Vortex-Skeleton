from typing import Dict, List, Optional

class AuthenticationManager:
    """
    Manages session state, cookies, tokens, and automated login flows.
    """
    def __init__(self):
        self.session_cookies: Dict[str, str] = {}
        self.headers: Dict[str, str] = {}
        self.is_authenticated = False

    def set_jwt_token(self, token: str, prefix: str = "Bearer"):
        self.headers["Authorization"] = f"{prefix} {token}".strip()
        self.is_authenticated = True

    def set_api_key(self, key: str, header_name: str = "X-API-Key"):
        self.headers[header_name] = key
        self.is_authenticated = True

    def set_cookie(self, key: str, value: str):
        self.session_cookies[key] = value
        self.is_authenticated = True

    def get_auth_headers(self) -> Dict[str, str]:
        return self.headers

    def get_auth_cookies(self) -> Dict[str, str]:
        return self.session_cookies

    def inject_auth(self, request_kwargs: dict) -> dict:
        """
        Injects stored authentication headers and cookies into a request configuration.
        """
        if self.is_authenticated:
            # Inject Headers
            req_headers = request_kwargs.get("headers", {})
            req_headers.update(self.headers)
            request_kwargs["headers"] = req_headers
            
            # Inject Cookies
            req_cookies = request_kwargs.get("cookies", {})
            req_cookies.update(self.session_cookies)
            request_kwargs["cookies"] = req_cookies
            
        return request_kwargs
