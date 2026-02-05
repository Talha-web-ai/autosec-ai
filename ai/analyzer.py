import subprocess
import json
import re


def analyze(findings):
    """
    Perform AI-based risk analysis on unified scanner findings.
    This is a BASELINE external security assessment.
    """

    # --------------------
    # BUILD FINDINGS TEXT
    # --------------------
    if not findings:
        findings_text = "No significant findings were detected."
    else:
        findings_text = "\n".join(
            f"- {f.get('title')} (Severity: {f.get('severity')})"
            for f in findings
        )

    # --------------------
    # AI PROMPT
    # --------------------
    prompt = f"""
You are a cybersecurity consultant performing a BASELINE EXTERNAL SECURITY CHECKUP.

IMPORTANT CONTEXT:
- This assessment only covers publicly exposed services and configurations.
- No exploitation, authentication testing, or business logic testing was performed.
- Absence of findings does NOT imply the system is fully secure.

INSTRUCTIONS:
- Be factual, calm, and professional.
- Do not exaggerate risk.
- Clearly explain WHAT was assessed and WHAT was not.
- Avoid technical jargon where possible.

Respond ONLY in valid JSON.
No markdown. No text outside JSON.

Return exactly:
{{
  "risk_level": "Low | Medium | High",
  "summary": "High-level explanation of the security posture and scan scope",
  "recommendation": "Clear, practical next steps and when deeper testing is needed"
}}

Technical Findings:
{findings_text}
"""

    # --------------------
    # RUN LOCAL LLM
    # --------------------
    try:
        result = subprocess.run(
            ["ollama", "run", "llama3"],
            input=prompt,
            text=True,
            capture_output=True,
            timeout=60
        )
    except Exception:
        return _safe_fallback(findings_text)

    raw_output = result.stdout.strip()

    # --------------------
    # EXTRACT JSON SAFELY
    # --------------------
    match = re.search(r"\{.*\}", raw_output, re.DOTALL)
    if match:
        try:
            parsed = json.loads(match.group())
            if _valid_analysis(parsed):
                return parsed
        except json.JSONDecodeError:
            pass

    return _safe_fallback(findings_text)


# --------------------
# HELPERS
# --------------------

def _valid_analysis(data):
    return (
        isinstance(data, dict)
        and "risk_level" in data
        and "summary" in data
        and "recommendation" in data
    )


def _safe_fallback(findings_text):
    """
    Conservative fallback if AI output is invalid or unavailable.
    """
    return {
        "risk_level": "Medium" if findings_text != "No significant findings were detected." else "Low",
        "summary": (
            "This assessment identified publicly exposed services and configuration "
            "details based on a baseline external security scan."
        ),
        "recommendation": (
            "Review the technical findings, apply recommended hardening steps, "
            "and consider deeper security testing if the system is business-critical."
        ),
    }
