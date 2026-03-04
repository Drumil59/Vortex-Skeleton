import json
import time
from collections import defaultdict

class Report:
    @staticmethod
    def generate(evidence, path):
        """
        Generates a structured JSON report from the collected evidence.
        """
        report_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_findings": len(evidence.items),
            "findings": evidence.items
        }

        try:
            with open(path, "w") as f:
                json.dump(report_data, f, indent=4, default=str)
            print(f"[+] JSON Report saved to {path}")
            return True
        except Exception as e:
            print(f"[!] Error generating report: {e}")
            return False

    @staticmethod
    def print_terminal(evidence):
        """
        Prints an aggregated, professional summary to the terminal.
        Groups findings by vulnerability type (plugin name).
        """
        print("\n" + "="*60)
        print("\033[91m[!] VORTEX VULNERABILITY REPORT (AGGREGATED)\033[0m")
        print("="*60)

        if not evidence.items:
            print("[*] No vulnerabilities discovered.")
            return

        # 1. Group by Plugin Name
        grouped = defaultdict(list)
        for item in evidence.items:
            plugin_name = item.get('plugin', 'Unknown Vulnerability')
            grouped[plugin_name].append(item)

        # 2. Sort keys for consistent output
        sorted_vulnerabilities = sorted(grouped.keys())

        # 3. Iterate and Print
        for vuln_name in sorted_vulnerabilities:
            items = grouped[vuln_name]
            count = len(items)

            # Header: Vulnerability Name
            print(f"\n\033[94m[+] {vuln_name}\033[0m \033[37m({count} findings)\033[0m")

            # Extract common attributes from the first item
            first_item = items[0]
            confidence = first_item.get('confidence', 'MEDIUM')
            
            print(f"    Confidence: {confidence}")

            # Check if 'details' are identical across all items
            first_details = first_item.get('details')
            all_same_details = all(i.get('details') == first_details for i in items)
            
            if all_same_details and first_details:
                print(f"    Details:    {first_details}")

            print("    Affected Resources:")

            # Print Endpoints
            for item in items:
                endpoint = item.get('endpoint')
                parameter = item.get('parameter')
                payload = item.get('payload')
                details = item.get('details')
                proof = item.get('evidence')

                # Bullet line
                line = f"      - {endpoint}"
                if parameter:
                    line += f" (Param: \033[93m{parameter}\033[0m)"
                print(line)

                # Indented Attributes
                if payload:
                    print(f"        Payload:    {payload}")
                
                # If details differ, print them per-item
                if not all_same_details and details:
                    print(f"        Details:    {details}")

                # Print the Evidence/Proof
                if proof:
                    # Truncate if too long to avoid flooding
                    if len(str(proof)) > 100:
                         proof = str(proof)[:97] + "..."
                    print(f"        Proof:      \033[90m{proof}\033[0m")

            print("-" * 40)

        print(f"\n[*] Scan Summary: {len(evidence.items)} total findings across {len(grouped)} categories.")
