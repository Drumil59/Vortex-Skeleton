from sdk.base_plugin import BasePlugin
import re

class S3BucketScanner(BasePlugin):
    """
    Scans for S3 bucket URLs in response content and checks for public access.
    """
    name = "S3 Bucket Exposure"

    # Regex to find s3 buckets
    # Matches:
    # 1. http://bucketname.s3.amazonaws.com
    # 2. http://s3.amazonaws.com/bucketname
    BUCKET_REGEX = r"https?://([a-zA-Z0-9\.\-_]+)\.s3\.amazonaws\.com|https?://s3\.amazonaws\.com/([a-zA-Z0-9\.\-_]+)"

    def should_run(self, endpoint):
        return True

    def detect(self, http, endpoint, payload_intel):


        findings = []
        try:
            resp = http.request("GET", endpoint.url)
            if not resp or not resp.text:
                return

            matches = re.findall(self.BUCKET_REGEX, resp.text)
            
            found_buckets = set()
            for match in matches:
                # Regex returns tuple, filter empty strings
                for group in match:
                    if group:
                        found_buckets.add(group)

            for bucket in found_buckets:
                bucket_url = f"http://{bucket}.s3.amazonaws.com/"
                
                # Check for public listing
                try:
                    bucket_resp = http.request("GET", bucket_url)
                    
                    if bucket_resp and bucket_resp.status_code == 200:
                        if "ListBucketResult" in bucket_resp.text:
                            findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'payload': bucket_url, 'evidence': f"Open S3 Bucket found: {bucket}", 'confidence': "HIGH", 'details': "Bucket listing is enabled (ListObjects})."
                            )
                    elif bucket_resp and bucket_resp.status_code == 403:
                         findings.append({'plugin': self.name, 'endpoint': endpoint.url, 'payload': bucket_url, 'evidence': f"Found S3 Bucket: {bucket} (Access Denied})",
                                confidence="INFO",
                                details="Bucket exists but listing is disabled."
                            )

                except Exception:
                    continue

        except Exception:
            pass
        return findings