import json
from typing import Optional, Dict

class GraphQLEngine:
    """
    Performs security analysis on GraphQL endpoints.
    """
    INTROSPECTION_QUERY = {
        "query": """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            ...InputValue
          }
          interfaces {
            ...TypeRef
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            ...TypeRef
          }
        }
        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """
    }

    def __init__(self, http_client):
        self.http = http_client

    def run_introspection(self, url: str) -> Optional[dict]:
        resp = self.http.request("POST", url, json=self.INTROSPECTION_QUERY)
        if resp and resp.status_code == 200:
            try:
                return resp.json()
            except:
                return None
        return None

    def analyze_schema(self, schema: dict) -> list:
        findings = []
        if not schema:
            return findings
        
        # Example check: Introspection enabled
        findings.append("GraphQL Introspection is enabled.")
        
        # Check for mutation types (could be dangerous)
        data = schema.get("data", {})
        __schema = data.get("__schema", {})
        if __schema.get("mutationType"):
            findings.append(f"GraphQL Mutations detected: {__schema['mutationType'].get('name')}")
            
        return findings
