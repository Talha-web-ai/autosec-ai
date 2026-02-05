import whois
from datetime import datetime
from scanner.base import BaseScanner


def normalize_datetime(dt):
    """
    Normalize datetime to naive UTC for safe comparison.
    """
    if not dt:
        return None
    if isinstance(dt, list):
        dt = dt[0]
    if hasattr(dt, "tzinfo") and dt.tzinfo is not None:
        return dt.replace(tzinfo=None)
    return dt


class WhoisScanner(BaseScanner):
    name = "whois"

    def scan(self):
        findings = []

        try:
            data = whois.whois(self.target)
        except Exception as e:
            return [{
                "id": "WHOIS_LOOKUP_FAILED",
                "title": "WHOIS lookup failed",
                "severity": "info",
                "description": str(e),
                "evidence": {},
                "recommendation": "Ensure the domain is valid and publicly registered.",
            }]

        now = datetime.utcnow()

        # --------------------
        # DOMAIN AGE
        # --------------------
        creation_date = normalize_datetime(data.creation_date)

        if creation_date:
            age_days = (now - creation_date).days

            if age_days < 90:
                findings.append({
                    "id": "DOMAIN_NEW",
                    "title": "Domain is newly registered",
                    "severity": "low",
                    "description": f"Domain was registered {age_days} days ago.",
                    "evidence": {"creation_date": creation_date.isoformat()},
                    "recommendation": (
                        "New domains may face trust and reputation challenges. "
                        "Ensure strong security hygiene."
                    ),
                })

        # --------------------
        # DOMAIN EXPIRY
        # --------------------
        expiration_date = normalize_datetime(data.expiration_date)

        if expiration_date:
            days_left = (expiration_date - now).days

            if days_left < 30:
                findings.append({
                    "id": "DOMAIN_EXPIRING_SOON",
                    "title": "Domain registration expiring soon",
                    "severity": "high",
                    "description": f"Domain expires in {days_left} days.",
                    "evidence": {"expiration_date": expiration_date.isoformat()},
                    "recommendation": (
                        "Renew the domain registration promptly to avoid service disruption."
                    ),
                })

        # --------------------
        # REGISTRAR INFO
        # --------------------
        registrar = data.registrar
        if not registrar:
            findings.append({
                "id": "REGISTRAR_UNKNOWN",
                "title": "Registrar information unavailable",
                "severity": "info",
                "description": "WHOIS did not return registrar details.",
                "evidence": {},
                "recommendation": (
                    "Verify domain registration details with your domain provider."
                ),
            })

        return findings
