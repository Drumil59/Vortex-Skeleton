import json
import time
import os
from typing import Dict, List, Any

class WorkflowManager:
    """
    Manages automated scan workflows, scan history, and multi-target monitoring.
    """
    def __init__(self, history_file: str = "vortex_history.json"):
        self.history_file = history_file
        self.history = self._load_history()

    def _load_history(self) -> List[Dict[str, Any]]:
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []

    def record_scan(self, target: str, scan_type: str, findings_count: int):
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": target,
            "type": scan_type,
            "findings": findings_count
        }
        self.history.append(entry)
        with open(self.history_file, 'w') as f:
            json.dump(self.history, f, indent=4)
        print(f"[*] Scan history updated for {target}.")

    def list_history(self):
        print("\n\033[94m[=] VORTEX SCAN HISTORY\033[0m")
        for entry in self.history[-10:]: # Show last 10
            print(f"[{entry['timestamp']}] {entry['target']} ({entry['type']}) - {entry['findings']} Vulns")
        print("-" * 30)
