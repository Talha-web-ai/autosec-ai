import subprocess
import json
import re

def analyze(scan_results, nikto_results=None):
    findings = []

    for r in scan_results:
        if r["state"] == "open":
            entry = (
                f"Port {r['port']} running {r['service']} "
                f"({r['version']}), Severity: {r['severity']}."
            )

            if r.get("cves"):
                entry += f" Known CVEs: {[c['id'] for c in r['cves']]}"

            findings.append(entry)

    findings_text = "\n".join(findings)

    prompt = f"""
You are a cybersecurity consultant performing a BASELINE SECURITY CHECKUP.

IMPORTANT CONTEXT:
- This scan focuses on infrastructure exposure, services, and common misconfigurations.
- It does NOT include deep application logic testing or authenticated testing.

INSTRUCTIONS:
- Be honest but professional.
- Do not exaggerate risk.
- If findings are limited, clearly explain WHAT was assessed and WHAT was not.

Respond ONLY in valid JSON.
No markdown. No text outside JSON.

Return exactly:
{{
  "risk_level": "Low | Medium | High",
  "summary": "Explain overall security posture and scan scope in simple language",
  "recommendation": "Concrete next steps and when deeper testing is needed"
}}

Technical Findings:
{findings_text}
"""


    if nikto_results:
        prompt += f"\nNikto Web Scan Results:\n{nikto_results}"

    result = subprocess.run(
        ["ollama", "run", "llama3"],
        input=prompt,
        text=True,
        capture_output=True
    )

    raw = result.stdout.strip()
    match = re.search(r"\{.*\}", raw, re.DOTALL)

    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    # Safe fallback
    return {
        "risk_level": "Medium",
        "summary": raw[:500],
        "recommendation": "Review exposed services, patch vulnerable software, and restrict access."
    }
