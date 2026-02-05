from scanner.base import BaseScanner
from scanner.headers_scan import HeadersScanner
from scanner.nmap_scan import run_nmap
from scanner.nikto_scan import run_nikto
from scanner.dns_scan import DNSScanner
from scanner.tls_scan import TLSScanner
from scanner.whois_scan import WhoisScanner




class NmapAdapterScanner(BaseScanner):
    name = "nmap"

    def scan(self):
        raw_results = run_nmap(self.target)
        findings = []

        for r in raw_results:
            if r.get("state") != "open":
                continue

            severity = r.get("severity", "low").lower()

            # Baseline normalization
            if r.get("service") == "http":
                severity = "medium"

            findings.append({
                "id": f"OPEN_PORT_{r.get('port')}",
                "title": f"Port {r.get('port')} open ({r.get('service')})",
                "severity": severity.capitalize(),
                "description": (
                    f"Port {r.get('port')} is open running "
                    f"{r.get('service')} {r.get('version', '')}"
                ),
                "evidence": r,
                "recommendation": "Restrict access or close unused services.",
            })

        return findings


class NiktoAdapterScanner(BaseScanner):
    name = "nikto"

    def scan(self):
        results = run_nikto(self.target)
        findings = []

        for v in results.get("vulnerabilities", []):
            findings.append({
                "id": "NIKTO_FINDING",
                "title": "Potential web misconfiguration detected",
                "severity": "medium",
                "description": v.get("msg", "Nikto reported a potential issue."),
                "evidence": v,
                "recommendation": "Review web server configuration and apply hardening.",
            })

        return findings


class ScanOrchestrator:
    def __init__(self, target: str):
        self.target = target
        self.scanners = [
            HeadersScanner,
            NmapAdapterScanner,
            NiktoAdapterScanner,
            DNSScanner,
            TLSScanner,
            WhoisScanner,
        ]

    def run(self):
        results = []

        for scanner_cls in self.scanners:
            scanner = scanner_cls(self.target)
            results.append(scanner.run())

        return {
            "target": self.target,
            "results": results
        }
