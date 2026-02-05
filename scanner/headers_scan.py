import requests
from scanner.base import BaseScanner


class HeadersScanner(BaseScanner):
    name = "headers"

    SECURITY_HEADERS = {
        "Strict-Transport-Security": ("medium", "Enable HSTS to enforce HTTPS."),
        "Content-Security-Policy": ("high", "Define a strict CSP to mitigate XSS."),
        "X-Frame-Options": ("medium", "Prevent clickjacking."),
        "X-Content-Type-Options": ("low", "Set to nosniff."),
        "Referrer-Policy": ("low", "Control referrer leakage."),
        "Permissions-Policy": ("low", "Restrict browser features."),
    }

    def scan(self):
        findings = []
        urls = [
            f"https://{self.target}",
            f"http://{self.target}",
        ]

        response = None
        last_error = None

        for url in urls:
            try:
                response = requests.get(url, timeout=10)
                break
            except Exception as e:
                last_error = e

        if not response:
            return [{
                "id": "HEADERS_SCAN_FAILED",
                "title": "Header scan failed",
                "severity": "info",
                "description": str(last_error),
                "evidence": {},
                "recommendation": "Ensure the target is reachable over HTTP or HTTPS.",
            }]

        headers = response.headers

        for header, (severity, recommendation) in self.SECURITY_HEADERS.items():
            if header not in headers:
                findings.append({
                    "id": f"MISSING_{header.upper().replace('-', '_')}",
                    "title": f"{header} header missing",
                    "severity": severity,
                    "description": f"{header} is not present in HTTP response.",
                    "evidence": {},
                    "recommendation": recommendation,
                })

        for leak in ["Server", "X-Powered-By"]:
            if leak in headers:
                findings.append({
                    "id": f"INFO_DISCLOSURE_{leak.upper()}",
                    "title": f"{leak} header exposed",
                    "severity": "low",
                    "description": f"{leak} header reveals backend details.",
                    "evidence": {leak: headers.get(leak)},
                    "recommendation": f"Remove or obfuscate the {leak} header.",
                })

        return findings
