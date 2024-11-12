# import nmap

# def scan_network(ip_range):
#     nm = nmap.PortScanner()
#     nm.scan(ip_range, arguments='-sV -p 21')  # -sV for service version detection
#     scan_results = []

#     for host in nm.all_hosts():
#         for proto in nm[host].all_protocols():
#             for port in nm[host][proto].keys():
#                 service = nm[host][proto][port]['name']
#                 scan_results.append({
#                     "ip": host,
#                     "port": port,
#                     "service": service
#                 })
    
#     return scan_results

import nmap

def run_nmap_scan(ip_range, options):
    """
    Run an Nmap scan on a specified IP range with user-defined options.
    """
    # Initialize Nmap scanner
    nm = nmap.PortScanner()

    # Build Nmap arguments based on user options
    nmap_args = []
    if options.get("service_version"):
        nmap_args.append("-sV")
    if options.get("os_detection"):
        nmap_args.append("-O")
    if options.get("aggressive"):
        nmap_args.append("-A")
    if options.get("tcp_scan"):
        nmap_args.append("-sT")
    if options.get("udp_scan"):
        nmap_args.append("-sU")
    if options.get("ping_scan"):
        nmap_args.append("-sn")
    if options.get("fast_scan"):
        nmap_args.append("-F")
    if options.get("port_range"):
        nmap_args.append(f"-p {options['port_range']}")
    scripts = options.get("scripts", [])
    if scripts:
        script_args = ",".join(scripts)
        nmap_args.append(f"--script {script_args}")
    if options.get("max_rtt_timeout"):
        nmap_args.append(f"--max-rtt-timeout {options['max_rtt_timeout']}")
    if options.get("host_timeout"):
        nmap_args.append(f"--host-timeout {options['host_timeout']}")
    if options.get("retries"):
        nmap_args.append(f"--max-retries {options['retries']}")
    elif options.get("scan_delay"):
        nmap_args.append(f"--scan-delay {options['scan_delay']}")


    # Combine arguments into a single string
    nmap_arguments = " ".join(nmap_args)
    nm.scan(ip_range, arguments=nmap_arguments)

    # Parse and return the results
    scan_results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                result = {
                    "ip": host,
                    "port": port,
                    "protocol": proto,
                    "service": nm[host][proto][port].get("name", ""),
                    "product": nm[host][proto][port].get("product", ""),
                    "version": nm[host][proto][port].get("version", ""),
                    "state": nm[host][proto][port]["state"],
                    "script_output": nm[host][proto][port].get("script", {})
                }
                scan_results.append(result)

    return scan_results
