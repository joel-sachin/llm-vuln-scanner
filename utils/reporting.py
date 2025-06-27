import json
import html

def print_dependency_report(vulnerabilities):
    """Prints a formatted report for found dependency vulnerabilities to the console."""
    # ... (This function remains unchanged)
    if not vulnerabilities:
        print("\n[SUCCESS] No known vulnerabilities found in project dependencies.")
        return
    print("\n[!] VULNERABILITIES FOUND IN DEPENDENCIES [!]")
    print("-" * 50)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "N/A": 4}
    sorted_vulnerabilities = sorted(vulnerabilities, key=lambda x: severity_order.get(x['severity'], 99))
    for vuln in sorted_vulnerabilities:
        print(f"  Package : {vuln['package_name']}=={vuln['version']}")
        print(f"  CVE ID  : {vuln['cve_id']}")
        print(f"  Severity: {vuln['severity']}")
        print(f"  Details : {vuln['description']}")
        print("-" * 50)


def print_code_vulnerability_report(vulnerabilities):
    """Prints a formatted report for found source code vulnerabilities to the console."""
    # ... (This function remains unchanged)
    if not vulnerabilities:
        print("\n[SUCCESS] LLM analysis found no vulnerabilities in the source code.")
        return
    print("\n[!] VULNERABILITIES FOUND IN SOURCE CODE [!]")
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "N/A": 4}
    sorted_vulnerabilities = sorted(vulnerabilities, key=lambda x: severity_order.get(x.get('severity', 'N/A'), 99))
    for vuln in sorted_vulnerabilities:
        print("-" * 50)
        print(f"  File      : {vuln.get('file_name', 'N/A')}")
        print(f"  Line      : {vuln.get('line_number', 'N/A')}")
        print(f"  Severity  : {vuln.get('severity', 'N/A')}")
        print(f"  CWE       : {vuln.get('cwe_id', 'N/A')}")
        print(f"  Vulnerable Code:")
        print(f"    `{vuln.get('vulnerable_code', 'N/A')}`")
        print(f"  Description:")
        print(f"    {vuln.get('description', 'N/A')}")
        print(f"  Mitigation:")
        print(f"    {vuln.get('suggested_mitigation', 'N/A')}")
    print("-" * 50)


def save_json_report(all_findings, output_file):
    """Saves the combined findings to a JSON file."""
    # ... (This function remains unchanged)
    print(f"\n[*] Saving JSON report to {output_file}...")
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(all_findings, f, indent=4)
        print(f"[SUCCESS] Successfully saved report to {output_file}")
    except Exception as e:
        print(f"[!] Error saving JSON report: {e}")


# --- NEW FUNCTION and HTML TEMPLATE ---

def save_html_report(all_findings, output_file):
    """Saves the combined findings to a styled HTML file."""
    print(f"\n[*] Saving HTML report to {output_file}...")
    
    # Simple CSS for styling the report
    html_style = """
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        h2 { color: #555; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .severity-CRITICAL { background-color: #ff4d4d; color: white; }
        .severity-HIGH { background-color: #ff9933; }
        .severity-MEDIUM { background-color: #ffff66; }
        .severity-LOW { background-color: #99ff99; }
        .code { background-color: #eee; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
    </style>
    """
    
    html_body = "<h1>Vulnerability Scan Report</h1>"
    
    # --- Dependency Vulnerabilities Section ---
    html_body += "<h2>Dependency Vulnerabilities</h2>"
    deps = all_findings.get("dependency_vulnerabilities", [])
    if not deps:
        html_body += "<p>No known vulnerabilities found in project dependencies.</p>"
    else:
        html_body += "<table><tr><th>Severity</th><th>Package</th><th>CVE ID</th><th>Description</th></tr>"
        for vuln in deps:
            severity = html.escape(str(vuln.get('severity', 'N/A')))
            html_body += f"""
            <tr>
                <td class="severity-{severity}">{severity}</td>
                <td>{html.escape(vuln.get('package_name', ''))}=={html.escape(vuln.get('version', ''))}</td>
                <td>{html.escape(vuln.get('cve_id', ''))}</td>
                <td>{html.escape(vuln.get('description', ''))}</td>
            </tr>
            """
        html_body += "</table>"
        
    # --- Code Vulnerabilities Section ---
    html_body += "<h2>Source Code Vulnerabilities</h2>"
    code_vulns = all_findings.get("code_vulnerabilities", [])
    if not code_vulns:
        html_body += "<p>LLM analysis found no vulnerabilities in the source code.</p>"
    else:
        html_body += "<table><tr><th>Severity</th><th>File</th><th>Line</th><th>CWE</th><th>Description</th><th>Vulnerable Code</th><th>Mitigation</th></tr>"
        for vuln in code_vulns:
            severity = html.escape(str(vuln.get('severity', 'N/A')))
            html_body += f"""
            <tr>
                <td class="severity-{severity}">{severity}</td>
                <td>{html.escape(vuln.get('file_name', ''))}</td>
                <td>{html.escape(str(vuln.get('line_number', '')))}</td>
                <td>{html.escape(vuln.get('cwe_id', ''))}</td>
                <td>{html.escape(vuln.get('description', ''))}</td>
                <td><span class="code">{html.escape(vuln.get('vulnerable_code', ''))}</span></td>
                <td>{html.escape(vuln.get('suggested_mitigation', ''))}</td>
            </tr>
            """
        html_body += "</table>"

    full_html = f"<!DOCTYPE html><html><head><title>Vulnerability Report</title>{html_style}</head><body>{html_body}</body></html>"
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(full_html)
        print(f"[SUCCESS] Successfully saved report to {output_file}")
    except Exception as e:
        print(f"[!] Error saving HTML report: {e}")