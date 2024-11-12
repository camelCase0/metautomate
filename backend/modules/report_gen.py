def generate_report(vuln_results):
    report = {
        "vulnerable_hosts": []
    }

    for entry in vuln_results:
        report["vulnerable_hosts"].append({
            "ip": entry["ip"],
            "port": entry["port"],
            "service": entry["service"],
            "cve_id": entry.get("cve_id", "N/A"),
            "vulnerability": entry.get("vulnerability", "No known vulnerabilities detected")
        })
    
    return report
