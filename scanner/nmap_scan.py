import nmap
from scanner.cve_lookup import lookup_cves
from scanner.severity import calculate_severity

def run_nmap(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV -T4')

    results = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                service = nm[host][proto][port]

                service_name = service.get("name", "unknown")
                version = service.get("version", "unknown")

                # CVE lookup (best-effort)
                cves = lookup_cves(service_name, version)
                severity = calculate_severity(port, service_name, len(cves))

                results.append({
                    "host": host,
                    "port": port,
                    "state": service.get("state"),
                    "service": service_name,
                    "version": version,
                    "cves": cves,
                    "severity": severity
                })

    return results
