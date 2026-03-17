import os
import time
from collections import defaultdict
from report.severity_sorter import SeveritySorter

BANNER = """
\033[94m
██╗   ██╗ ██████╗ ██████╗ ████████╗███████╗██╗  ██╗
██║   ██║██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
██║   ██║██║   ██║██████╔╝   ██║   █████╗   ╚███╔╝ 
╚██╗ ██╔╝██║   ██║██╔══██╗   ██║   ██╔══╝   ██╔██╗ 
 ╚████╔╝ ╚██████╔╝██║  ██║   ██║   ███████╗██╔╝ ██╗
  ╚═══╝   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
\033[0m
   \033[3m>> VORTEX-SKELETON (AGGREGATED) <<\033[0m
"""

class Report:
    @staticmethod
    def print_banner():
        print(BANNER)

    @staticmethod
    def generate_console_report(target, findings):
        Report.print_banner()
        
        total_vulns = len(findings)
        print(f"\n[+] Scanned: {target} [{total_vulns} Vulns]")
        print("\n============================================================")
        print("[!] VORTEX VULNERABILITY REPORT (AGGREGATED)")
        print("============================================")

        if not findings:
            print("\n[*] No vulnerabilities discovered.")
            return

        # 1. Group findings by type
        grouped = defaultdict(list)
        for f in findings:
            vuln_type = f['type']
            grouped[vuln_type].append(f)

        # 2. Prepare aggregated data for each category
        aggregated_categories = []
        for vuln_type, items in grouped.items():
            # Get common attributes (severity, confidence, details should be consistent per type)
            first = items[0]
            severity = first.get('severity', 'INFO')
            confidence = first.get('confidence', 'HIGH')
            details = first.get('details', 'No description available.')
            
            # Deduplicate endpoints within category
            unique_endpoints = set()
            for item in items:
                unique_endpoints.add(item['url'])
            
            # Collect all unique payloads and proofs
            all_payloads = []
            for item in items:
                for p in item.get('payloads', []):
                    if p and p not in all_payloads:
                        all_payloads.append(p)
            
            all_proofs = []
            for item in items:
                for p in item.get('proofs', []):
                    if p and p not in all_proofs:
                        all_proofs.append(p)
            
            aggregated_categories.append({
                'type': vuln_type,
                'count': len(unique_endpoints),
                'severity': severity,
                'confidence': confidence,
                'details': details,
                'endpoints': sorted(list(unique_endpoints)),
                'payloads': all_payloads,
                'proofs': all_proofs
            })

        # 3. Sort categories by severity
        sorted_categories = sorted(
            aggregated_categories,
            key=lambda x: SeveritySorter.get_priority(x['severity']),
            reverse=True
        )

        # 4. Print findings
        for cat in sorted_categories:
            print(f"\n[+] {cat['type']} ({cat['count']} findings)")
            print(f"Severity:    {cat['severity']}")
            print(f"Confidence:  {cat['confidence']}")
            print(f"Details:     {cat['details']}")
            
            print("\n```")
            print("Affected Resources:")
            for ep in cat['endpoints']:
                print(f"  - {ep}")
            
            if cat['payloads']:
                print("\nPayload:")
                for p in cat['payloads']:
                    print(f"  {p}")
            
            if cat['proofs']:
                print("\nProof:")
                for p in cat['proofs']:
                    print(f"  {p}")
            print("```")

        print(f"\n[*] Scan Summary: {total_vulns} findings across {len(grouped)} categories.")

    @staticmethod
    def generate_markdown_report(target, findings, workspace_path):
        total_vulns = len(findings)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        md_content = f"# Vortex Vulnerability Report (Aggregated)\n\n"
        md_content += f"**Target:** {target}\n"
        md_content += f"**Date:** {timestamp}\n"
        md_content += f"**Total Unique Findings:** {total_vulns}\n\n"
        md_content += "---\n\n"

        if not findings:
            md_content += "No vulnerabilities discovered.\n"
        else:
            # Group and Sort (reuse logic from console report or keep it separate for flexibility)
            grouped = defaultdict(list)
            for f in findings:
                grouped[f['type']].append(f)
            
            aggregated = []
            for vuln_type, items in grouped.items():
                first = items[0]
                unique_endpoints = sorted(list(set(i['url'] for i in items)))
                all_payloads = []
                for i in items:
                    for p in i.get('payloads', []):
                        if p and p not in all_payloads: all_payloads.append(p)
                
                all_proofs = []
                for i in items:
                    for p in i.get('proofs', []):
                        if p and p not in all_proofs: all_proofs.append(p)

                aggregated.append({
                    'type': vuln_type,
                    'severity': first.get('severity', 'INFO'),
                    'confidence': first.get('confidence', 'HIGH'),
                    'details': first.get('details', 'No description available.'),
                    'endpoints': unique_endpoints,
                    'payloads': all_payloads,
                    'proofs': all_proofs
                })
            
            sorted_agg = sorted(aggregated, key=lambda x: SeveritySorter.get_priority(x['severity']), reverse=True)

            for cat in sorted_agg:
                md_content += f"## {cat['type']} ({len(cat['endpoints'])} findings)\n\n"
                md_content += f"* **Severity:** {cat['severity']}\n"
                md_content += f"* **Confidence:** {cat['confidence']}\n"
                md_content += f"* **Details:** {cat['details']}\n\n"
                
                md_content += "### Affected Resources\n"
                for ep in cat['endpoints']:
                    md_content += f"- {ep}\n"
                
                if cat['payloads']:
                    md_content += "\n### Payloads\n"
                    for p in cat['payloads']:
                        md_content += f"```\n{p}\n```\n"
                
                if cat['proofs']:
                    md_content += "\n### Proof\n"
                    for p in cat['proofs']:
                        md_content += f"{p}\n"
                
                md_content += "\n---\n\n"

        md_content += "## Scan Summary\n\n"
        md_content += f"{total_vulns} findings across {len(grouped)} categories.\n\n"
        md_content += "---\n"

        reports_dir = os.path.join(workspace_path, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        report_file = os.path.join(reports_dir, "report.md")
        
        with open(report_file, "w") as f:
            f.write(md_content)
        
        print(f"\n[+] Report saved to: {report_file}")
