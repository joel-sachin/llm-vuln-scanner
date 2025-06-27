import os
import requests
import re
import time
from packaging.version import parse as parse_version, InvalidVersion
from packaging.specifiers import SpecifierSet, InvalidSpecifier

# NVD API endpoint and settings
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_DELAY_SECONDS = 6

def is_version_affected(package_name, target_version_str, cve_configs):
    """
    Checks if a given package and version is within the vulnerable ranges 
    specified in a CVE's configuration. This is now "product-aware".
    """
    try:
        target_version = parse_version(target_version_str)
    except InvalidVersion:
        print(f"    [!] Could not parse target version: {target_version_str}. Skipping check.")
        return False

    if not cve_configs:
        return False

    for config in cve_configs:
        for node in config.get('nodes', []):
            for cpe_match in node.get('cpeMatch', []):
                if cpe_match.get('vulnerable', False):
                    # --- NEW: Product-Aware Check ---
                    # Parse the CPE string to get the product name.
                    # e.g., "cpe:2.3:a:twistedmatrix:twisted:22.4.0:*:*:*:*:python:*:*"
                    criteria = cpe_match.get('criteria', '')
                    cpe_parts = criteria.split(':')
                    # The product is the 5th part (index 4) in a CPE 2.3 string.
                    if len(cpe_parts) > 4:
                        product_from_cpe = cpe_parts[4]
                        # Only proceed if the product in the CVE matches the package we're scanning.
                        # We check both exact match and if it's a substring (e.g., 'python-requests' contains 'requests')
                        if package_name != product_from_cpe and package_name not in product_from_cpe:
                            continue # Not for this product, skip to the next CPE match.
                    # --- END: Product-Aware Check ---

                    version_start_including = cpe_match.get('versionStartIncluding')
                    version_end_excluding = cpe_match.get('versionEndExcluding')
                    version_start_excluding = cpe_match.get('versionStartExcluding')
                    version_end_including = cpe_match.get('versionEndIncluding')
                    
                    # Check for exact version match in the CPE string itself
                    if len(cpe_parts) > 5 and cpe_parts[5] == target_version_str:
                        return True

                    specifiers = []
                    if version_start_including: specifiers.append(f">={version_start_including}")
                    if version_end_excluding: specifiers.append(f"<{version_end_excluding}")
                    if version_start_excluding: specifiers.append(f">{version_start_excluding}")
                    if version_end_including: specifiers.append(f"<={version_end_including}")
                    
                    if not specifiers:
                        continue

                    try:
                        specifier_set = SpecifierSet(','.join(specifiers))
                        if target_version in specifier_set:
                            return True # Version match confirmed for the correct product!
                    except InvalidSpecifier:
                        continue
    return False

def query_nvd(params):
    """A helper function to query the NVD API and handle responses."""
    try:
        response = requests.get(NVD_API_URL, params=params)
        if response.status_code == 404: return []
        response.raise_for_status()
        return response.json().get('vulnerabilities', [])
    except requests.exceptions.RequestException as e:
        print(f"    [!] Error querying NVD API: {e}")
        return []

def scan_package(package_name, version):
    """ Scans a single package, prioritizing specific searches. """
    all_vulnerabilities = []
    
    # Prioritize a search that includes the package name and "python"
    search_keyword = f"python {package_name}"
    print(f"    -> Searching NVD for '{search_keyword}'...")
    keyword_results = query_nvd({'keywordSearch': search_keyword, 'resultsPerPage': 200})

    if not keyword_results:
        print(f"    [i] No vulnerabilities found for '{package_name}'.")
        return []

    print(f"    [*] Found {len(keyword_results)} potential matches. Filtering for product and version...")
    for item in keyword_results:
        cve = item['cve']
        configurations = cve.get('configurations', [])

        # The check is now product-aware
        if is_version_affected(package_name, version, configurations):
            found_vuln = {
                'cve_id': cve['id'],
                'package_name': package_name,
                'version': version,
                'severity': cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseSeverity', 'N/A'),
                'description': cve['descriptions'][0]['value']
            }
            if found_vuln not in all_vulnerabilities:
                 all_vulnerabilities.append(found_vuln)

    return all_vulnerabilities

def parse_requirements(file_path):
    """ Parses a requirements.txt file to extract package names and versions. """
    dependencies = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if '==' in line and not line.startswith('#'):
                match = re.match(r"([a-zA-Z0-9\-_.]+)==([a-zA-Z0-9\.]+)", line)
                if match:
                    dependencies.append(match.groups())
    return dependencies

def scan(repo_path):
    """ Main entry point for the dependency scanner. """
    requirements_file = os.path.join(repo_path, 'requirements.txt')
    all_vulnerabilities = []

    if not os.path.exists(requirements_file):
        print("    [i] No requirements.txt file found. Skipping dependency scan.")
        return all_vulnerabilities

    print(f"    [*] Found requirements.txt at: {requirements_file}")
    dependencies = parse_requirements(requirements_file)

    if not dependencies:
        print("    [i] No dependencies with exact versions found in requirements.txt.")
        return all_vulnerabilities

    for package_name, version in dependencies:
        vulnerabilities = scan_package(package_name, version)
        if vulnerabilities:
            all_vulnerabilities.extend(vulnerabilities)
        
        print(f"    [*] Waiting {REQUEST_DELAY_SECONDS} seconds before next request...")
        time.sleep(REQUEST_DELAY_SECONDS)
            
    return all_vulnerabilities