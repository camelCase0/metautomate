import nmap

SCRIPT_RISK_LEVELS = {
    "INFO": [
        "default",
        "safe",
        "banner",
        "http-title",
        "smtp-commands",
        "imap-capabilities",
        "dns-service-discovery",
        "http-server-header",
        "asn-query",
        "whois-domain",
        "http-headers",
        "ip-geolocation-ipinfodb",
        "ssl-cert",
        "ssl-date",
        "ssl-google-cert-catalog",
        "smtp-capabilities"
    ],
    "LOW": [
        "http-methods",
        "mysql-info",
        "rdp-enum-encryption",
        "imap-ntlm-info",
        "targets-ipv6-multicast-mld",
        "targets-ipv6-multicast-slaac",
        "ntp-info",
        "smtp-strangeport",
        "pop3-brute",
        "smtp-open-relay",
        "http-cors",
        "http-enum",
        "http-cookie-flags",
        "http-robots.txt"
    ],
    "MEDIUM": [
        "ftp-anon",  # Default: No sensitive data or write access
        "nbstat",
        "snmp-info",
        "rpc-grind",
        "http-sql-injection",
        "mysql-users",
        "mongodb-info",
        "redis-info",
        "oracle-enum-users",
        "mysql-dump-hashes",
        "drda-info",
        "mongodb-databases",
        "smb-os-discovery",
        "ftp-brute",
        "http-brute",
        "mysql-brute",
        "smtp-brute",
        "imap-capabilities",
        "smtp-enum-users",
        "http-form-brute",
        "http-errors",
        "http-iis-short-name-brute",
        "dns-brute",
        "dns-srv-enum",
        "ssl-enum-ciphers"
    ],
    "HIGH": [
        "ssh-hostkey",
        "ssl-known-key",
        "smb-vuln-cve-2017-7494",
        "ssl-dh-params",
        "http-backdoor",
        "ftp-proftpd-backdoor",
        "smtp-vuln-cve2011-1720",
        "mysql-vuln-cve2012-2122",
        "rdp-brute",
        "redis-brute",
        "oracle-brute",
        "ssh-brute",
        "sip-brute",
        "snmp-brute",
        "http-xssed",
        "http-vuln-cve2015-1427",
        "ssl-poodle",
        "http-malware-host"
    ],
    "CRITICAL": [
        "vulners",
        "ftp-vsftpd-backdoor",
        "ssl-heartbleed",
        "http-shellshock",
        "smb-vuln-ms17-010",
        "http-vuln-cve2017-5638",
        "http-vuln-cve2021-26855",
        "ssl-v2",
        "tls-ticketbleed",
        "sip-vuln-cve2011-2536",
        "smb-vuln-cve-2012-1182",
        "http-majordomo2-dir-traversal",
        "http-huawei-hg5xx-vuln",
        "http-vuln-cve2013-7091",
        "http-vuln-cve2010-0738"
    ]
}


def classify_script(script_name, script_output=None, context=None):
    """
    Classify a script based on its risk level and dynamically adjust based on context.

    Parameters:
    - script_name (str): The name of the script.
    - script_output (str): The output of the script (optional).
    - context (dict): Additional context for classification (optional).
      Example: {"public_ftp": True, "sensitive_data_found": True}

    Returns:
    - str: Risk level (INFO, LOW, MEDIUM, HIGH, CRITICAL).
    """
    # Base classification
    for level, scripts in SCRIPT_RISK_LEVELS.items():
        if script_name in scripts:
            base_level = level
            break
    else:
        base_level = "INFO"

    # Dynamic adjustments based on context
    if context:
        # Example: Adjust FTP risks if public access is detected
        if script_name == "ftp-anon" and context.get("public_ftp"):
            return "CRITICAL" if context.get("sensitive_data_found") else "HIGH"

        # Adjust HTTP vulnerabilities based on sensitive endpoints
        if script_name.startswith("http-") and context.get("sensitive_endpoint"):
            return "CRITICAL" if "exploit" in script_output.lower() else "HIGH"

        # Adjust for generic sensitive data exposure
        if context.get("sensitive_data_found") and base_level in ["LOW", "MEDIUM"]:
            return "HIGH"

    return base_level

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
                
                script_output = nm[host][proto][port].get("script", {})
                
                context = {
                    "public_ftp": True if "ftp" in nm[host][proto][port].get("name", "") else False,
                    "sensitive_data_found": "password" in script_output.values()
                }
                
                classified_scripts = {
                    script: {
                        "output": output,
                        "risk": classify_script(script, output, context)
                    }
                    for script, output in script_output.items()
                }
                
                result = {
                    "ip": host,
                    "port": port,
                    "protocol": proto,
                    "service": nm[host][proto][port].get("name", ""),
                    "product": nm[host][proto][port].get("product", ""),
                    "version": nm[host][proto][port].get("version", ""),
                    "state": nm[host][proto][port]["state"],
                    "script_output": classified_scripts
                }
                scan_results.append(result)

    return scan_results
