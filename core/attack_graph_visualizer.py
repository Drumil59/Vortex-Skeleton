import json
import logging
from typing import Dict, List, Any
try:
    import networkx as nx
    from networkx.readwrite import json_graph
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

class AttackGraphVisualizer:
    """
    Visualizes the attack graph built by AttackGraphEngine.
    Supports exporting to JSON and interactive graph formats.
    """
    def __init__(self, attack_graph_engine):
        self.engine = attack_graph_engine
        self.logger = logging.getLogger("AttackGraphVisualizer")

    def build_networkx_graph(self):
        if not NETWORKX_AVAILABLE:
            self.logger.warning("NetworkX not installed. Visualization limited.")
            return None

        G = nx.DiGraph()
        
        # Add nodes from the engine
        for node in self.engine.nodes:
            G.add_node(node['id'], label=node['label'], type=node.get('type'), endpoint=node.get('endpoint'), severity=node.get('severity'))
            
        # Add edges from the engine
        for edge in self.engine.edges:
            G.add_edge(edge['source'], edge['target'], relation=edge['relation'])
            
        return G

    def export_json(self, filepath: str = "attack_graph_vis.json"):
        G = self.build_networkx_graph()
        if G:
            data = json_graph.node_link_data(G)
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=4)
            print(f"[+] Attack Graph exported to {filepath}")

    def generate_html_report(self, filepath: str = "attack_graph.html"):
        """
        Generates a basic HTML/D3.js visualization.
        In a real implementation, this would template a full D3.js interactive graph.
        """
        G = self.build_networkx_graph()
        if not G: return
        
        data = json_graph.node_link_data(G)
        json_data = json.dumps(data)
        
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vortex Attack Graph</title>
            <script src="https://d3js.org/d3.v6.min.js"></script>
            <style>
                .node {{ stroke: #fff; stroke-width: 1.5px; }}
                .link {{ stroke: #999; stroke-opacity: 0.6; }}
                text {{ font-family: sans-serif; font-size: 10px; }}
            </style>
        </head>
        <body>
            <h1>Vortex Attack Graph Visualization</h1>
            <div id="graph"></div>
            <script>
                const data = {json_data};
                // D3.js code to render the graph would go here
                console.log("Graph Data Loaded:", data);
                document.getElementById('graph').innerText = "Graph data generated with " + data.nodes.length + " nodes. (Interactive D3.js visualization would render here)";
            </script>
        </body>
        </html>
        """
        with open(filepath, 'w') as f:
            f.write(html_template)
        print(f"[+] Interactive Attack Graph generated: {filepath}")
