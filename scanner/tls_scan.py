import socket
import ssl
from datetime import datetime
from scanner.base import BaseScanner


class TLSScanner(BaseScanner):
    name = "tls"

    def scan(self):
        findings = []

        # --------------------
        # HTTPS AVAILABILITY
        # --------------------
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
        except Exception:
            findings.append({
                "id": "HTTPS_NOT_AVAILABLE",
                "title": "HTTPS not available",
                "severity": "high",
                "description": "The server does not support HTTPS on port 443.",
                "evidence": {},
                "recommendation": (
                    "Enable HTTPS using a valid TLS certificate "
                    "to protect data in transit."
                ),
            })
            return findings

        # --------------------
        # CERTIFICATE EXPIRY
        # --------------------
        try:
            not_after = cert.get("notAfter")
            expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry_date - datetime.utcnow()).days

            if days_left < 30:
                findings.append({
                    "id": "CERT_EXPIRING_SOON",
                    "title": "TLS certificate expiring soon",
                    "severity": "medium",
                    "description": f"TLS certificate expires in {days_left} days.",
                    "evidence": {"days_remaining": days_left},
                    "recommendation": (
                        "Renew the TLS certificate before expiration "
                        "to avoid service disruption."
                    ),
                })
        except Exception:
            pass

        # --------------------
        # WEAK TLS PROTOCOLS
        # --------------------
        weak_protocols = []

        for proto, name in [
            (ssl.PROTOCOL_TLSv1, "TLSv1.0"),
            (ssl.PROTOCOL_TLSv1_1, "TLSv1.1"),
        ]:
            try:
                weak_ctx = ssl.SSLContext(proto)
                with socket.create_connection((self.target, 443), timeout=5) as sock:
                    with weak_ctx.wrap_socket(sock, server_hostname=self.target):
                        weak_protocols.append(name)
            except Exception:
                continue

        if weak_protocols:
            findings.append({
                "id": "WEAK_TLS_ENABLED",
                "title": "Weak TLS protocols supported",
                "severity": "medium",
                "description": (
                    "The server supports outdated TLS protocol versions: "
                    + ", ".join(weak_protocols)
                ),
                "evidence": {"protocols": weak_protocols},
                "recommendation": (
                    "Disable TLS 1.0 and 1.1 and allow only TLS 1.2 or newer."
                ),
            })

        return findings
