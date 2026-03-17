from sdk.base_plugin import BasePlugin
import re
import json
import base64

class JWTWeaknessPlugin(BasePlugin):
    """
    Checks for 'None' algorithm vulnerability in JWT tokens.
    """
    name = "JWT 'None' Algorithm"

    def should_run(self, endpoint):
        # Only relevant if we have seen JWTs in headers (requires sophisticated crawler)
        # OR if we assume headers are passed. For this plugin, we analyze headers.
        return True

    def detect(self, http, endpoint, payload_intel):


        findings = []
        # This plugin usually requires traffic analysis. 
        # Active Check: If we can identify a JWT in the params or cookies.
        pass # Placeholder for advanced logic requiring token extraction


# filename: plugins/proto.py
        return findings

from sdk.base_plugin import BasePlugin