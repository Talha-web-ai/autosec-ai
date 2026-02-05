import dns.resolver
from scanner.base import BaseScanner


class DNSScanner(BaseScanner):
    name = "dns"

    def scan(self):
        findings = []

        # --------------------
        # SPF CHECK
        # --------------------
        spf_found = False
        try:
            answers = dns.resolver.resolve(self.target, "TXT")
            for rdata in answers:
                txt = "".join(rdata.strings).lower()
                if txt.startswith("v=spf1"):
                    spf_found = True
                    break
        except Exception:
            pass

        if not spf_found:
            findings.append({
                "id": "SPF_MISSING",
                "title": "SPF record not found",
                "severity": "medium",
                "description": "No SPF record was detected for the domain.",
                "evidence": {},
                "recommendation": (
                    "Add an SPF record to specify authorized mail servers "
                    "and reduce email spoofing risk."
                ),
            })

        # --------------------
        # DMARC CHECK
        # --------------------
        dmarc_policy = None
        try:
            answers = dns.resolver.resolve(f"_dmarc.{self.target}", "TXT")
            for rdata in answers:
                txt = "".join(rdata.strings).lower()
                if txt.startswith("v=dmarc1"):
                    for part in txt.split(";"):
                        if part.strip().startswith("p="):
                            dmarc_policy = part.split("=")[1].strip()
                    break
        except Exception:
            pass

        if not dmarc_policy:
            findings.append({
                "id": "DMARC_MISSING",
                "title": "DMARC record not found",
                "severity": "medium",
                "description": "No DMARC policy was detected for the domain.",
                "evidence": {},
                "recommendation": (
                    "Implement a DMARC policy to prevent email spoofing "
                    "and improve email trust."
                ),
            })
        elif dmarc_policy == "none":
            findings.append({
                "id": "DMARC_WEAK_POLICY",
                "title": "DMARC policy not enforced",
                "severity": "low",
                "description": "DMARC policy is set to monitoring mode (p=none).",
                "evidence": {"policy": dmarc_policy},
                "recommendation": (
                    "Consider enforcing DMARC with p=quarantine or p=reject "
                    "once monitoring is complete."
                ),
            })

        # --------------------
        # DKIM CHECK (best-effort)
        # --------------------
        common_selectors = ["default", "google", "selector1", "selector2"]
        dkim_found = False

        for selector in common_selectors:
            try:
                dns.resolver.resolve(
                    f"{selector}._domainkey.{self.target}", "TXT"
                )
                dkim_found = True
                break
            except Exception:
                continue

        if not dkim_found:
            findings.append({
                "id": "DKIM_NOT_DETECTED",
                "title": "DKIM record not detected",
                "severity": "low",
                "description": (
                    "No DKIM record was detected using common selectors. "
                    "DKIM may still be present under a custom selector."
                ),
                "evidence": {},
                "recommendation": (
                    "Ensure DKIM is configured with your email provider "
                    "to protect message integrity."
                ),
            })

        return findings
