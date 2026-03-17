from sdk.base_plugin import BasePlugin
import re
import json
import base64

class GraphQLPlugin(BasePlugin):
    """
    Detects exposed GraphQL endpoints and Introspection Query risks.
    """
    name = "GraphQL Exposure"

    ENDPOINTS = ["/graphql", "/api/graphql", "/v1/graphql", "/gql"]
    INTROSPECTION_QUERY = """
    query {
      __schema {
        types {
          name
        }
      }
    }
    """

    def should_run(self, endpoint):
        # Only run on base URLs to discover the API
        return endpoint.method == "GET"

    def detect(self, http, endpoint, payload_intel):


        findings = []
        # 1. Discovery
        for path in self.ENDPOINTS:
            target = f"{endpoint.url.rstrip('/')}{path}"
            try:
                # Check for endpoint existence (GET or POST)
                resp = http.request("GET", target)
                if not resp or resp.status_code == 404:
                    # Try POST with empty JSON
                    resp = http.request("POST", target, json={})
                
                if not resp or resp.status_code == 404:
                    continue

                # Signature Check
                if "errors" in resp.text and "message" in resp.text or "data" in resp.text:
                    findings.append({'plugin': self.name, 'endpoint': target, 'payload': None, 'evidence': "GraphQL Endpoint Discovered", 'confidence': "HIGH"})

                    # 2. Introspection Check
                    resp_intro = http.request("POST", target, json={"query": self.INTROSPECTION_QUERY})
                    if resp_intro and "__schema" in resp_intro.text:
                         findings.append({'plugin': "GraphQL Introspection", 'endpoint': target, 'payload': "Introspection Query", 'evidence': "Full Schema Disclosure Enabled", 'confidence': "CRITICAL", 'details': "Attackers can map the entire API surface."})
                    break 

            except Exception:
                continue

# filename: plugins/idor.py
        return findings

from sdk.base_plugin import BasePlugin
import re