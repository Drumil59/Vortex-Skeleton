import os
import json
import time
from typing import Dict, Any

class WorkspaceManager:
    """
    Manages multiple scan projects, isolating targets, evidence, and reports.
    """
    def __init__(self, base_dir: str = "workspaces/"):
        self.base_dir = base_dir
        self.active_workspace = None
        
        if not os.path.exists(self.base_dir):
            os.makedirs(self.base_dir)

    def create_workspace(self, name: str):
        path = os.path.join(self.base_dir, name)
        if not os.path.exists(path):
            os.makedirs(path)
            os.makedirs(os.path.join(path, "reports"))
            os.makedirs(os.path.join(path, "evidence"))
        self.active_workspace = name
        print(f"[*] Workspace '{name}' active.")
        return path

    def get_path(self, sub_path: str = "") -> str:
        if not self.active_workspace:
            self.create_workspace("default")
        return os.path.join(self.base_dir, self.active_workspace, sub_path)

    def save_state(self, state: Dict[str, Any], filename: str = "state.json"):
        path = self.get_path(filename)
        with open(path, 'w') as f:
            json.dump(state, f, indent=4)

    def load_state(self, filename: str = "state.json") -> Dict[str, Any]:
        path = self.get_path(filename)
        if os.path.exists(path):
            with open(path, 'r') as f:
                return json.load(f)
        return {}
