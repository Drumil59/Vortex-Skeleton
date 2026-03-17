import os
import re

plugins_dir = "/home/tools/web/old/Vortex-Skeleton/plugins/"
files = [f for f in os.listdir(plugins_dir) if f.endswith(".py") and f != "__init__.py"]

for filename in files:
    filepath = os.path.join(plugins_dir, filename)
    with open(filepath, "r") as f:
        content = f.read()

    # Skip files that already have 'detect'
    if "def detect(" in content:
        continue

    # 1. Update Imports
    content = re.sub(r"from \.?base import BasePlugin", "from sdk.base_plugin import BasePlugin", content)
    content = re.sub(r"from plugins\.base import BasePlugin", "from sdk.base_plugin import BasePlugin", content)

    # 2. Rename Method and Update Parameters
    match = re.search(r"(\s+)def run\(self, http, endpoint, analyzer, evidence\):", content)
    if not match:
        continue

    indent = match.group(1)
    new_method = f"{indent}def detect(self, http, endpoint, payload_intel):"
    
    # Prepare the header of the new method
    method_header = f"{new_method}\n{indent}    findings = []"
    if "analyzer." in content:
        if "ResponseAnalyzer" not in content:
            content = "from core.analyzer import ResponseAnalyzer\n" + content
        method_header += f"\n{indent}    analyzer = ResponseAnalyzer()"
    
    content = content.replace(match.group(0), method_header)

    # 3. Replace evidence.add(...) with findings.append({...})
    # This regex tries to capture the content inside the parentheses of evidence.add
    # It's not perfect for very complex cases but should work for most.
    def replace_evidence(match):
        inner = match.group(1).strip()
        # Clean up inner content: remove newlines and extra spaces for easier processing
        inner_clean = " ".join(inner.split())
        
        parts = []
        # Basic keyword argument parser
        # Split by comma but try to avoid splitting on commas inside strings
        # (Very basic, might fail on complex payloads)
        current_part = ""
        in_string = False
        quote_char = ""
        for char in inner_clean:
            if char in ("'", '"'):
                if not in_string:
                    in_string = True
                    quote_char = char
                elif quote_char == char:
                    in_string = False
                current_part += char
            elif char == ',' and not in_string:
                parts.append(current_part.strip())
                current_part = ""
            else:
                current_part += char
        if current_part:
            parts.append(current_part.strip())
            
        dict_items = []
        has_plugin = False
        has_endpoint = False
        
        for p in parts:
            if '=' in p:
                k, v = p.split('=', 1)
                k = k.strip()
                v = v.strip()
                dict_items.append(f"'{k}': {v}")
                if k == 'plugin': has_plugin = True
                if k == 'endpoint': has_endpoint = True
            else:
                # Positional or unknown? Just add as is if it's not empty
                if p: dict_items.append(f"'item': {p}")

        if not has_plugin:
            dict_items.append("'plugin': self.name")
        if not has_endpoint:
            dict_items.append("'endpoint': endpoint.url")
            
        return f"findings.append({{{', '.join(dict_items)}}})"

    content = re.sub(r"evidence\.add\((.*?)\)", replace_evidence, content, flags=re.DOTALL)

    # 4. Add 'return findings' at the end of the method
    lines = content.split('\n')
    new_lines = []
    in_method = False
    method_indent = ""
    
    for i, line in enumerate(lines):
        if "def detect(" in line:
            in_method = True
            method_indent = re.match(r"\s*", line).group(0)
            new_lines.append(line)
        elif in_method:
            # Check if line is still in method scope
            if line.strip() and not line.startswith(method_indent + "    ") and not line.strip().startswith("#"):
                # We found the end of the method (or class)
                # Before adding the next line, insert return findings
                # But we should back up to avoid empty lines at end of method
                while new_lines and not new_lines[-1].strip():
                    new_lines.pop()
                new_lines.append(method_indent + "    return findings")
                new_lines.append("")
                new_lines.append(line)
                in_method = False
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
            
    if in_method:
        while new_lines and not new_lines[-1].strip():
            new_lines.pop()
        new_lines.append(method_indent + "    return findings")

    with open(filepath, "w") as f:
        f.write('\n'.join(new_lines))

print("Refactoring complete.")
