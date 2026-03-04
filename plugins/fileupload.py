from .base import BasePlugin
import io

class FileUploadPlugin(BasePlugin):
    """
    Tests for Insecure File Upload via POST multipart form-data.
    Attempts to upload non-standard extensions or double extensions.
    """
    name = "Insecure File Upload"

    TEST_FILES = [
        ("vortex_test.php.jpg", "<?php echo 'vortex_test'; ?>", "image/jpeg"),
        ("vortex_test.phtml", "<?php echo 'vortex_test'; ?>", "application/x-httpd-php"),
        ("vortex_test.php5", "<?php echo 'vortex_test'; ?>", "application/x-httpd-php"),
        ("vortex_test.txt", "vortex_test", "text/plain")
    ]

    def should_run(self, endpoint):
        # Only run on POST requests that might accept files
        # Check for 'file' or 'upload' in params/url
        return endpoint.method == "POST" and any(x in endpoint.url.lower() or any(x in p['name'].lower() for p in endpoint.params) for x in ['upload', 'file', 'image', 'asset'])

    def run(self, http, endpoint, analyzer, evidence):
        for filename, content, ctype in self.TEST_FILES:
            try:
                # Prepare multipart data
                files = {
                    'file': (filename, io.BytesIO(content.encode()), ctype),
                    'upload': (filename, io.BytesIO(content.encode()), ctype) # Try common parameter names
                }
                
                # We need to know the parameter name for the file. 
                # If not found, we try common ones.
                file_param = 'file'
                for p in endpoint.params:
                    if 'file' in p['name'].lower() or 'upload' in p['name'].lower():
                        file_param = p['name']
                        break
                
                files = {file_param: (filename, io.BytesIO(content.encode()), ctype)}

                resp = http.request("POST", endpoint.url, files=files)
                if not resp: continue

                # Detection: 201 Created or 200 OK with success message
                success_indicators = ["uploaded", "success", "saved", filename]
                if resp.status_code in [200, 201] and any(x in resp.text.lower() for x in success_indicators):
                    # Flag as high if it's a PHP-related extension
                    confidence = "HIGH" if ".php" in filename or ".phtml" in filename else "MEDIUM"
                    
                    evidence.add(
                        plugin=self.name,
                        endpoint=endpoint.url,
                        payload=filename,
                        evidence=f"File upload accepted: {filename}",
                        confidence=confidence,
                        details=f"Status: {resp.status_code}. Possible successful upload of executable extension."
                    )
                    break

            except Exception:
                continue
