#!/usr/bin/env python3
import argparse
import sys
import concurrent.futures
import threading
import time
import queue
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor

from core.http import HTTPClient
from core.surface import SurfaceMapper
from core.analyzer import ResponseAnalyzer
from core.engine import ScanEngine
from evidence.store import EvidenceStore
from report.generator import Report

# --- PLUGIN IMPORTS ---
from plugins.securityheaders import SecurityHeadersPlugin
from plugins.cors import CORSPlugin
from plugins.openredirect import OpenRedirectPlugin
from plugins.exposure import ExposurePlugin
from plugins.methodtampering import MethodTamperingPlugin
from plugins.graphql import GraphQLPlugin
from plugins.idor import IDORPlugin
from plugins.jwtweakness import JWTWeaknessPlugin
from plugins.prototypepollution import PrototypePollutionPlugin
from plugins.clickjacking import ClickjackingPlugin
from plugins.xxe import XXEPlugin
from plugins.ssrf import SSRFPlugin
from plugins.csrf import CSRFPlugin
from plugins.htmlinjection import HTMLInjectionPlugin
from plugins.deserialization import DeserializationPlugin
from plugins.nosqli import NoSQLiPlugin
from plugins.ldapinjection import LDAPInjectionPlugin
from plugins.hostheaderinjection import HostHeaderInjectionPlugin
from plugins.ssi import SSIPlugin
from plugins.crlf import CRLFPlugin
from plugins.hpp import HPPPlugin
from plugins.ssjs import SSJSPlugin
from plugins.formula import FormulaPlugin
from plugins.debugparam import DebugParamPlugin
from plugins.activejwt import ActiveJWTPlugin
from plugins.xpath import XPATHPlugin
from plugins.rfi import RFIPlugin
from plugins.tabnabbing import TabnabbingPlugin
from plugins.dataleak import DataLeakPlugin
from plugins.cachedeception import CacheDeceptionPlugin
from plugins.sqli import SQLiPlugin
from plugins.xss import XSSPlugin
from plugins.lfi import PathTraversalPlugin
from plugins.assets import SensitiveAssetPlugin
from plugins.ssti import SSTIPlugin
from plugins.shell import ShellInjectionPlugin
from plugins.secretscanner import SecretScannerPlugin
from plugins.backup import BackupFilePlugin
from plugins.webdav import WebDAVPlugin
from plugins.csp import CSPWeaknessPlugin
from plugins.s3bucket import S3BucketScanner
from plugins.massassignment import MassAssignmentPlugin
from plugins.phpwrappers import PHPWrapperPlugin
from plugins.cloudssrf import CloudMetadataPlugin
from plugins.emailinjection import EmailInjectionPlugin
from plugins.fileupload import FileUploadPlugin
from plugins.smuggling import RequestSmugglingPlugin
from plugins.xmlrpc import XMLRPCPlugin
from plugins.viewstate import ViewStatePlugin
from plugins.header_redirect import HeaderBasedRedirectPlugin
from plugins.js_library import LibraryScannerPlugin

BANNER = """
\033[94m
██╗   ██╗ ██████╗ ██████╗ ████████╗███████╗██╗  ██╗
██║   ██║██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
██║   ██║██║   ██║██████╔╝   ██║   █████╗   ╚███╔╝ 
╚██╗ ██╔╝██║   ██║██╔══██╗   ██║   ██╔══╝   ██╔██╗ 
 ╚████╔╝ ╚██████╔╝██║  ██║   ██║   ███████╗██╔╝ ██╗
  ╚═══╝   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
\033[0m
   \033[3m>> VORTEX 2.0: TURBO EDITION (53 VECTORS) <<\033[0m
"""

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="VORTEX 2.0: Turbo VAPT")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Crawl depth (Lower is faster)")
    parser.add_argument("-t", "--threads", type=int, default=75, help="Scan threads (Higher is faster)")
    parser.add_argument("-o", "--output", default=None, help="Report file (Optional)")
    parser.add_argument("-p", "--proxy", help="HTTP Proxy")
    parser.add_argument("--stealth", action="store_true", help="Enable Stealth")
    parser.add_argument("--fast", action="store_true", help="Skip heavy fuzzing (SQLi, XSS, etc.)")
    args = parser.parse_args()

    if args.stealth:
        args.threads = 1
        print("[!] STEALTH ON: Speed throttled.")

    config = SimpleNamespace(
        timeout=10, 
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        proxy=args.proxy,
        stealth=args.stealth,
        threads=args.threads + 20 
    )

    http = HTTPClient(config)
    mapper = SurfaceMapper(http, depth=args.depth, max_threads=20) 
    analyzer = ResponseAnalyzer()
    evidence = EvidenceStore()
    
    # NEW: Initialize Orchestration Engine
    engine = ScanEngine(evidence)
    
    heavy_plugins = ["SQL Injection (Advanced)", "Cross-Site Scripting (XSS)", "Path Traversal", "Command Injection", "SSTI"]
    
    plugins = [
        SecurityHeadersPlugin(), CORSPlugin(), OpenRedirectPlugin(), ExposurePlugin(), 
        MethodTamperingPlugin(), GraphQLPlugin(), IDORPlugin(), JWTWeaknessPlugin(), 
        PrototypePollutionPlugin(), ClickjackingPlugin(), XXEPlugin(), SSRFPlugin(), 
        CSRFPlugin(), HTMLInjectionPlugin(), DeserializationPlugin(), NoSQLiPlugin(), 
        LDAPInjectionPlugin(), HostHeaderInjectionPlugin(), SSIPlugin(), CRLFPlugin(), 
        HPPPlugin(), SSJSPlugin(), FormulaPlugin(), DebugParamPlugin(), ActiveJWTPlugin(), 
        XPATHPlugin(), RFIPlugin(), TabnabbingPlugin(), DataLeakPlugin(), CacheDeceptionPlugin(), 
        SQLiPlugin(), XSSPlugin(), PathTraversalPlugin(), SensitiveAssetPlugin(), SSTIPlugin(), 
        ShellInjectionPlugin(), SecretScannerPlugin(), BackupFilePlugin(), WebDAVPlugin(),
        CSPWeaknessPlugin(), S3BucketScanner(), MassAssignmentPlugin(), PHPWrapperPlugin(),
        CloudMetadataPlugin(), EmailInjectionPlugin(), FileUploadPlugin(), RequestSmugglingPlugin(),
        XMLRPCPlugin(), ViewStatePlugin(), HeaderBasedRedirectPlugin(), LibraryScannerPlugin()
    ]

    if args.fast:
        plugins = [p for p in plugins if p.name not in heavy_plugins]
        print("[!] FAST MODE: Skipping heavy fuzzing plugins.")

    print(f"[*] Starting TURBO Scan on {args.url} with {args.threads} threads...")

    crawling_done = threading.Event()
    
    def run_crawler():
        mapper.start_crawl(args.url)
        crawling_done.set()
    
    crawler_thread = threading.Thread(target=run_crawler)
    crawler_thread.start()

    # Consumer: Scanner
    def scan_worker():
        while True:
            try:
                endpoint = mapper.endpoints_queue.get(timeout=2)
            except queue.Empty:
                if crawling_done.is_set():
                    return
                else:
                    continue
            
            # --- ORCHESTRATION: Gating & Saturation ---
            # 1. Skip if domain scope is invalid (already handled by mapper but double check?)
            # 2. Endpoint Deduplication is handled by SurfaceMapper.
            
            # 3. Create a Budgeted HTTP Wrapper for this Endpoint
            # Limits scan request volume per URL to prevent overload
            endpoint_client = http.create_budgeted_client(endpoint_budget=25) 

            for plugin in plugins:
                # 4. Check Saturation
                if not engine.should_run_plugin(plugin, endpoint):
                    continue

                try:
                    # 5. Run Plugin with limited HTTP client
                    # We capture the evidence count before and after to update engine stats
                    start_findings = len(evidence.items)
                    plugin.run(endpoint_client, endpoint, analyzer, evidence)
                    end_findings = len(evidence.items)
                    
                    if end_findings > start_findings:
                        # Findings were added! Record for saturation
                        for _ in range(end_findings - start_findings):
                            engine.record_finding(plugin.name)
                            
                except Exception: 
                    pass
            
            mapper.endpoints_queue.task_done()
            print(f"\r[+] Scanned: {endpoint.url} [{len(evidence.items)} Vulns]", end="")

    scan_threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=scan_worker)
        t.start()
        scan_threads.append(t)

    crawler_thread.join()
    for t in scan_threads:
        t.join()

    Report.print_terminal(evidence)

    if args.output:
        print("[*] Generating Report...")
        if Report.generate(evidence, args.output):
            print(f"[+] Report saved to {args.output}")

if __name__ == "__main__":
    main()