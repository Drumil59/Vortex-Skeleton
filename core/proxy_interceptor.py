import threading
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib3
import urllib.parse
from .attack_surface_db import Endpoint, AttackSurfaceDB

logger = logging.getLogger("ProxyInterceptor")
urllib3.disable_warnings()

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    # Class-level PoolManager to share connections across all handler instances
    pool_manager = urllib3.PoolManager(maxsize=50, cert_reqs='CERT_NONE')

    def __init__(self, *args, db: AttackSurfaceDB = None, **kwargs):
        self.db = db
        super().__init__(*args, **kwargs)

    def do_GET(self):
        self._intercept_and_forward()

    def do_POST(self):
        self._intercept_and_forward()

    def do_PUT(self):
        self._intercept_and_forward()

    def do_PATCH(self):
        self._intercept_and_forward()

    def do_DELETE(self):
        self._intercept_and_forward()

    def do_OPTIONS(self):
        self._intercept_and_forward()

    def do_HEAD(self):
        self._intercept_and_forward()

    def _intercept_and_forward(self):
        url = self.path
        method = self.command
        
        parsed_url = urllib.parse.urlparse(url)
        params = []
        if parsed_url.query:
            query_dict = urllib.parse.parse_qs(parsed_url.query)
            for k, v in query_dict.items():
                params.append({"name": k, "type": "query", "value": v[0] if v else ""})

        if self.db:
            ep = Endpoint(url=url, method=method, params=params, source="proxy_interceptor")
            self.db.add_endpoint(ep)
            logger.debug(f"[Proxy] Captured request: {method} {url}")
            
        try:
            headers = {}
            for key, value in self.headers.items():
                if key.lower() not in ['proxy-connection', 'host']:
                    headers[key] = value
            
            # Re-inject Host header based on destination
            headers['Host'] = parsed_url.netloc
                
            post_data = None
            if method in ['POST', 'PUT', 'PATCH']:
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > 0:
                    post_data = self.rfile.read(content_length)
                
            response = self.pool_manager.request(
                method=method,
                url=url,
                headers=headers,
                body=post_data,
                preload_content=False,
                timeout=10.0,
                retries=False
            )
            
            self.send_response(response.status)
            for key, value in response.headers.items():
                if key.lower() not in ['transfer-encoding', 'connection']:
                    self.send_header(key, value)
            self.end_headers()
            
            # Stream the response back
            for chunk in response.stream(8192):
                self.wfile.write(chunk)
                
            response.release_conn()

        except Exception as e:
            self.send_error(502, f"Bad Gateway: {str(e)}")


class ProxyInterceptor:
    """
    Burp-style HTTP intercepting proxy.
    Captures traffic and feeds it into the Attack Surface Database.
    Improved with ThreadingHTTPServer for performance.
    """
    def __init__(self, db: AttackSurfaceDB, host: str = "127.0.0.1", port: int = 8080):
        self.db = db
        self.host = host
        self.port = port
        self.server = None
        self.thread = None

    def _handler_factory(self, *args, **kwargs):
        return ProxyHTTPRequestHandler(*args, db=self.db, **kwargs)

    def start(self):
        # Using ThreadingHTTPServer for concurrent request handling
        self.server = ThreadingHTTPServer((self.host, self.port), self._handler_factory)
        self.server.daemon_threads = True # Ensure threads close when main thread exits
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        print(f"[*] Proxy Interceptor running on http://{self.host}:{self.port}")

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            print("[*] Proxy Interceptor stopped.")
