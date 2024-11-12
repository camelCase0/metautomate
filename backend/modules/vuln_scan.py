import nmap
import re

def run_nmap_vuln_scan(ip):
    """
    Use Nmap to scan for open ports, service versions, and vulnerabilities.
    """
    # Initialize Nmap scanner
    nm = nmap.PortScanner()
    
    # Run Nmap with service version detection and vulnerability scripts
    nm.scan(ip, arguments="-sV --script vuln")

    scan_results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                service = nm[host][proto][port]['name']
                product = nm[host][proto][port].get('product', 'unknown')
                version = nm[host][proto][port].get('version', 'unknown')
                script_output = nm[host][proto][port].get('script', {})
                
                vulnerabilities = []
                for script_name, output in script_output.items():
                    # Extract CVEs if available in the output
                    cves = re.findall(r'CVE-\d{4}-\d+', output)
                    vulnerabilities.append({"script": script_name, "output": output, "cves": cves})
                
                # Append findings to scan results
                scan_results.append({
                    "ip": host,
                    "port": port,
                    "service": service,
                    "product": product,
                    "version": version,
                    "vulnerabilities": vulnerabilities
                })
                
    return scan_results



