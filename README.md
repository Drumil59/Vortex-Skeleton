# 🌀 Vortex-Skeleton (V5.0)

**Vortex-Skeleton** is a high-performance, modular offensive security framework designed for **penetration testers, security researchers, and bug bounty hunters**. It implements an elite **context-aware execution engine** that orchestrates complex vulnerability discovery, automated exploitation, and multi-step attack path analysis.

Unlike traditional scanners, Vortex-Skeleton maps the entire attack surface using modern discovery techniques before executing targeted, high-signal vulnerability checks.

---

# 🚀 Core Capabilities

### 🔍 Advanced Discovery & Reconnaissance
*   **Multi-Source Discovery Engine:** Integrates static HTML crawling, **JS Mining**, and **Playwright-based dynamic rendering** to capture endpoints in modern SPAs.
*   **API & GraphQL Discovery:** Automated detection and parsing of **Swagger, OpenAPI, and GraphQL** schemas to expose hidden API surfaces.
*   **Bug Bounty Recon Pipeline:** Full-spectrum reconnaissance mode including subdomain enumeration and automated service probing.

### 🛡️ Context-Aware Offensive Engine
*   **Intelligent Plugin Orchestration:** Dynamically maps vulnerability checks (SQLi, XSS, CSRF, IDOR) to relevant endpoints based on parameters, forms, and headers.
*   **Out-Of-Band (OOB) Detection:** Integrated support for identifying asynchronous vulnerabilities (SSRF, XXE, RCE) via interaction servers (e.g., interactsh).
*   **WAF Evasion & Payload Intelligence:** Modular system for payload mutation and bypass technique integration.

### 🧠 Strategic Analysis & Chaining
*   **AI Attack Path Discovery:** Predictive analysis that correlates low-level findings to identify critical multi-step exploitation chains.
*   **Attack Graph Engine:** Visualizes relationships between assets, endpoints, and vulnerabilities to model complex compromise scenarios.
*   **Distributed Cluster Architecture:** High-concurrency worker pool for large-scale enterprise assessments and mass scanning.

---

# 🏗 System Architecture

```text
Vortex-Skeleton/
├── core/                      
│   ├── engine.py              
│   ├── crawler_engine.py       
│   ├── browser_crawler.py      
│   ├── api_discovery.py        
│   ├── attack_graph.py         
│   ├── ai_attack_path.py       
│   ├── distributed_cluster.py  
│   ├── oob_engine.py           
│   ├── js_miner.py             
│   ├── http.py                 
│   └── ...                    
├── plugins/                    
│   ├── advanced_sqli.py        
│   ├── enterprise_ssrf.py      
│   ├── activejwt.py            
│   ├── xss.py                  
│   ├── idor.py                 
│   └── ...                     
├── sdk/                        
│   └── base_plugin.py          
├── evidence/                   
│   └── store.py               
├── report/                     
│   ├── generator.py            
│   └── severity_sorter.py     
├── risk/                       
│   └── cvss.py                 
├── templates/                  
│   ├── reflected-xss.yaml
│   └── sqli-error.yaml
└── vortex.py                   
```

---

# ⚙ Installation

Vortex-Skeleton requires Python 3.10+ and the Chromium browser engine for dynamic crawling.

```bash
# Clone the repository
git clone https://github.com/Drumil59/Vortex-Skeleton
cd Vortex-Skeleton

# Install Python dependencies
pip install -r requirements.txt

# Setup Playwright for headless browser crawling
playwright install chromium
```

---

# ▶ Usage

Execute the scanner against a target URL:

```bash
python3 vortex.py https://example.com [FLAGS]
```

### Command-Line Arguments:
*   `url` : The target URL (e.g., `https://target-app.com`).
*   `-d, --depth` : Crawling recursion depth (default: 2).
*   `-t, --threads` : Concurrency level (default: 50).
*   `--debug` : Enable verbose logging and internal execution tracking.
*   `--recon` : Activate the full Bug Bounty Reconnaissance Pipeline.

**Example (Enterprise API Scan):**
```bash
python3 vortex.py https://api.enterprise.com --depth 3 --threads 100 --debug
```

---


# 📊 Evidence & Reporting

Vortex generates high-fidelity reports in **Markdown** format, stored within the `workspaces/` directory. Each report includes:
*   **Vulnerability Metadata:** Severity (CVSS), Confidence, and Type.
*   **Affected Resources:** List of endpoints and specific parameters.
*   **Evidence:** Exact HTTP requests, responses, and injected payloads.
*   **Attack Paths:** Predicted chains for high-impact exploitation.

---

# ⚠ Disclaimer

This tool is intended **strictly for authorized security testing and research purposes**. The author and contributors are not responsible for any misuse, unauthorized access, or damage caused by this framework.

---

# 📜 License
This project is licensed under the **MIT License**.
---

# 👨‍💻 Author

Security Research & Development Project focused on **automated vulnerability discovery and penetration testing workflows**.

---

# ⭐ Support

If you find this project useful, consider **starring the repository** to support its development.
