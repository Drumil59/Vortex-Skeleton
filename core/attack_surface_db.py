from dataclasses import dataclass, field
from typing import List, Dict, Any, Set, Optional
import threading

@dataclass
class Endpoint:
    url: str
    method: str
    params: List[Dict[str, Any]] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list) # Context for CSRF/XSS
    headers: Dict[str, str] = field(default_factory=dict)
    source: str = "unknown"
    priority: int = 0
    tags: Set[str] = field(default_factory=set)
    is_api: bool = False
    is_validated: bool = False

class AttackSurfaceDB:
    """
    Enterprise-grade Attack Surface Database.
    Stores contextual information about every discovered endpoint.
    """
    def __init__(self):
        self.endpoints: Dict[str, Endpoint] = {}
        self.lock = threading.Lock()

    def add_endpoint(self, endpoint: Endpoint):
        key = f"{endpoint.method}:{endpoint.url}"
        with self.lock:
            if key in self.endpoints:
                # Merge parameters and forms if already exists
                existing = self.endpoints[key]
                existing.params.extend([p for p in endpoint.params if p not in existing.params])
                existing.forms.extend([f for f in endpoint.forms if f not in existing.forms])
                existing.tags.update(endpoint.tags)
            else:
                self.endpoints[key] = endpoint

    def get_all(self) -> List[Endpoint]:
        with self.lock:
            return list(self.endpoints.values())
