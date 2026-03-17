#!/usr/bin/env python3
import argparse
import sys
import concurrent.futures
import threading
import logging
import queue
from urllib.parse import urlparse
from types import SimpleNamespace

from core.http import HTTPClient
from core.surface import SurfaceMapper
from core.analyzer import ResponseAnalyzer
from core.engine import ScanEngine
from evidence.store import EvidenceStore
from report.generator import Report
from core.payload_intelligence import PayloadIntelligence
from core.url_normalizer import URLNormalizer
from core.attack_surface_db import AttackSurfaceDB
from core.js_miner import JSMiner
from core.api_discovery import APIDiscovery
from core.fuzzer import FuzzerEngine
from core.exploit_engine import ExploitEngine
from core.ai_attack_path import AIAttackPathDiscovery
from core.bugbounty_pipeline import BugBountyPipeline
from core.workspace_manager import WorkspaceManager
from core.workflow_manager import WorkflowManager
from core.oob_engine import OOBEngine

import importlib
import inspect
import os

def load_plugins():
    plugins = []
    plugins_dir = os.path.join(os.path.dirname(__file__), "plugins")
    if not os.path.exists(plugins_dir): return plugins
    if os.path.dirname(__file__) not in sys.path:
        sys.path.insert(0, os.path.dirname(__file__))
    for root, dirs, files in os.walk(plugins_dir):
        for file in files:
            if file.endswith(".py") and not file.startswith("__"):
                rel_path = os.path.relpath(os.path.join(root, file), os.path.dirname(__file__))
                module_name = rel_path.replace(os.sep, '.')[:-3]
                try:
                    module = importlib.import_module(module_name)
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if hasattr(obj, "detect") and obj.__module__ == module_name:
                             if obj.__name__ not in ["BasePlugin"]:
                                plugins.append(obj())
                except Exception as e:
                    logging.debug(f"Failed to load plugin {file}: {e}")
    return plugins

BANNER = """\033[94mVORTEX 5.0 - DEBUG ENABLED\033[0m"""

def main():
    parser = argparse.ArgumentParser(description="VORTEX Offensive Platform")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("-d", "--depth", type=int, default=2)
    parser.add_argument("-t", "--threads", type=int, default=50)
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug output")
    parser.add_argument("--recon", action="store_true", help="Full Bug Bounty Recon")
    args = parser.parse_args()

    # 1. Logging Setup
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s [%(levelname)s] %(message)s')
    logger = logging.getLogger("vortex")
    
    if args.debug:
        logger.info("[!] DEBUG MODE ENABLED - Verbose tracking active.")

    # 2. Initialization
    config = SimpleNamespace(timeout=10, user_agent="Vortex/5.0", threads=args.threads)
    http = HTTPClient(config)
    db = AttackSurfaceDB()
    evidence = EvidenceStore()
    payload_intel = PayloadIntelligence()
    engine = ScanEngine(evidence, payload_intelligence=payload_intel)
    workspace = WorkspaceManager()
    
    workspace.create_workspace(urlparse(args.url).netloc)
    
    normalizer = URLNormalizer(args.url)
    modules = {
        'db': db,
        'http': http,
        'plugins': load_plugins(),
        'exploit_engine': ExploitEngine(http),
        'static_crawler': SurfaceMapper(http, args.url, depth=args.depth),
        'js_miner': JSMiner(normalizer, http),
        'api_discovery': APIDiscovery(http),
        'fuzzer': FuzzerEngine(concurrency=args.threads),
        'ai_attack_path': AIAttackPathDiscovery(),
        'evidence': evidence
    }
    modules['bugbounty_pipeline'] = BugBountyPipeline(modules)

    # 3. Pipeline Execution
    logger.info(f"[*] Starting Vortex Offensive Pipeline against: {args.url}")
    
    # Discovery Phase (Crawler Engine)
    from core.crawler_engine import CrawlerEngine
    import asyncio
    
    crawler = CrawlerEngine(args.url, http, depth=args.depth)
    discovered_eps = asyncio.run(crawler.start())
    
    for ep in discovered_eps:
        db.add_endpoint(ep)
    
    # Validation & Scanning
    engine.run_pipeline(args.url, modules, recon_mode=args.recon, debug=args.debug)

    # 4. Finalizing
    summary = engine.get_summary()
    v_stats = summary['validator_stats']
    
    # Get aggregated findings for reporting
    final_findings = evidence.get_findings()
    
    print("\n" + "="*40)
    print("\033[94m[=] VORTEX SCAN SUMMARY\033[0m")
    print("="*40)
    print(f"Total Endpoints Discovered: {v_stats.get('total_checked', 0)}")
    print(f"Valid Endpoints Scanned:    {v_stats.get('valid', 0)}")
    print(f"Endpoints Filtered (404):   {v_stats.get('skipped_404', 0)}")
    print(f"Endpoints Filtered (Soft):  {v_stats.get('skipped_soft_404', 0)}")
    print(f"Confirmed Vulnerabilities:  {len(final_findings)}")
    print("="*40)

    if args.debug:
        logger.info(f"Total raw findings: {len(evidence.items)}")
        logger.info(f"After deduplication: {len(final_findings)}")

    if len(final_findings) > 0:
        Report.generate_console_report(args.url, final_findings)
    
    if len(final_findings) > 0:
        try:
            choice = input("\nDo you want to save this report to a file? (y/n) ").lower().strip()
            if choice == 'y':
                Report.generate_markdown_report(args.url, final_findings, workspace.get_path(""))
        except EOFError:
            # Handle non-interactive environments
            pass

if __name__ == "__main__":
    main()
