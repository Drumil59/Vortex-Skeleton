from typing import List, Dict, Any
import logging
import json

class AttackGraphEngine:
    """
    Enterprise Attack Graph Engine.
    Models relationships between Subdomains, Endpoints, Parameters, and Vulnerabilities.
    """
    def __init__(self):
        self.logger = logging.getLogger("AttackGraphEngine")
        self.nodes = []
        self.edges = []
        self._node_ids = set()
        self._edge_hashes = set()

    def add_asset_node(self, type: str, label: str, metadata: Dict[str, Any] = None):
        node_id = f"{type}:{label}"
        if node_id not in self._node_ids:
            self._node_ids.add(node_id)
            self.nodes.append({
                "id": node_id,
                "type": type,
                "label": label,
                "metadata": metadata or {}
            })
        return node_id

    def add_finding_node(self, finding: Dict[str, Any]):
        node_id = f"vuln:{finding.get('endpoint')}_{finding.get('title')}"
        if node_id not in self._node_ids:
            self._node_ids.add(node_id)
            self.nodes.append({
                "id": node_id,
                "type": "vulnerability",
                "label": finding.get('title'),
                "endpoint": finding.get('endpoint'),
                "severity": finding.get('severity')
            })
        return node_id

    def add_edge(self, source: str, target: str, relation: str):
        edge_hash = f"{source}->{target}:{relation}"
        if edge_hash not in self._edge_hashes:
            self._edge_hashes.add(edge_hash)
            self.edges.append({"source": source, "target": target, "relation": relation})

    def build_graph(self, triaged_findings: Dict[str, List[Dict[str, Any]]], attack_surface: List[Any] = None):
        """Builds a complete graph of the attack surface and vulnerabilities."""
        # 1. Add Asset Nodes
        if attack_surface:
            for ep in attack_surface:
                # Subdomain Node
                from urllib.parse import urlparse
                domain = urlparse(ep.url).netloc
                sub_id = self.add_asset_node("subdomain", domain)
                
                # Endpoint Node
                ep_id = self.add_asset_node("endpoint", ep.url, {"method": ep.method})
                self.add_edge(sub_id, ep_id, "hosts")
                
                # Parameter Nodes
                for p in ep.params:
                    p_id = self.add_asset_node("parameter", f"{ep.url}?{p['name']}")
                    self.add_edge(ep_id, p_id, "accepts")

        # 2. Add Vulnerability Nodes & Links
        all_vulns = []
        for sev, items in triaged_findings.items():
            all_vulns.extend(items)
            
        for v in all_vulns:
            v_id = self.add_finding_node(v)
            
            # Link Vuln to Endpoint
            ep_url = v.get('endpoint', 'Unknown')
            ep_id = f"endpoint:{ep_url}"
            # Ensure ep_id exists if not in attack_surface
            if ep_id not in self._node_ids:
                self.add_asset_node("endpoint", ep_url)
            self.add_edge(ep_id, v_id, "vulnerable_to")

        # 3. Model Complex Chains (Cross-Vuln edges)
        for i, source_node in enumerate(self.nodes):
            if source_node['type'] != "vulnerability": continue
            
            for j, target_node in enumerate(self.nodes):
                if i == j or target_node['type'] != "vulnerability": continue
                
                t1, e1 = source_node['label'].lower(), source_node.get('endpoint', '').lower()
                t2, e2 = target_node['label'].lower(), target_node.get('endpoint', '').lower()

                if 'xss' in t1 and 'csrf' in t2:
                    self.add_edge(source_node['id'], target_node['id'], "Session/Token Hijacking")
                if 'idor' in t1 and ('admin' in e2 or 'privilege' in t2):
                    self.add_edge(source_node['id'], target_node['id'], "Privilege Escalation")

    def generate_chains(self, triaged_findings: Dict[str, List[Dict[str, Any]]], attack_surface: List[Any] = None) -> List[str]:
        self.build_graph(triaged_findings, attack_surface)
        chains = []
        for edge in self.edges:
            if "Hijacking" in edge['relation'] or "Escalation" in edge['relation']:
                source = next((n for n in self.nodes if n['id'] == edge['source']), None)
                target = next((n for n in self.nodes if n['id'] == edge['target']), None)
                if source and target:
                    chains.append(f"Chain: [{source['label']}] on {source.get('endpoint')} -> ({edge['relation']}) -> [{target['label']}] on {target.get('endpoint')}")
        return list(set(chains))
