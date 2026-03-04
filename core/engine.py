import threading
from urllib.parse import urlparse

class ScanEngine:
    def __init__(self, evidence_store):
        self.evidence = evidence_store
        
        # Configuration
        self.MAX_FINDINGS_PER_PLUGIN = 10
        
        # State
        self.plugin_finding_counts = {} # {plugin_name: count}
        self.lock = threading.Lock()
        self.skipped_plugins = set()

    def record_finding(self, plugin_name):
        with self.lock:
            count = self.plugin_finding_counts.get(plugin_name, 0) + 1
            self.plugin_finding_counts[plugin_name] = count
            
            if count == self.MAX_FINDINGS_PER_PLUGIN:
                print(f"[*] Plugin '{plugin_name}' reached saturation ({self.MAX_FINDINGS_PER_PLUGIN} findings), skipping future checks.")
                self.skipped_plugins.add(plugin_name)

    def should_run_plugin(self, plugin, endpoint) -> bool:
        # 1. Saturation Check
        if plugin.name in self.skipped_plugins:
            return False

        # 2. Smart Gating (Heuristics)
        # We can hardcode some logic here or rely on plugin.should_run
        # But centralized logic is easier to manage for orchestration.
        
        # Gating: Static Files
        # Skip heavy attacks on images, css, js unless specific plugins
        path = urlparse(endpoint.url).path.lower()
        if any(path.endswith(ext) for ext in ['.jpg', '.png', '.gif', '.css', '.js', '.woff', '.ico']):
            # Allow only Asset/Leaky plugins
            allowed = ["Sensitive Asset", "Information Disclosure", "PII", "Secret"]
            if not any(a in plugin.name for a in allowed):
                return False

        # Gating: Parameter Requirements
        # Many plugins require parameters. If none, skip.
        needs_params = [
            "SQL Injection", "XSS", "IDOR", "Command Injection", 
            "SSRF", "LFI", "SSTI", "XML External Entity", "Open Redirect"
        ]
        if any(n in plugin.name for n in needs_params) and not endpoint.params:
            return False

        # Gating: Method Requirements
        if "CSRF" in plugin.name and endpoint.method != "POST":
            return False
            
        return True
