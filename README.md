# 🔐 AutoSec AI

**AutoSec AI** is a lightweight, AI-assisted security checkup tool designed for  
**early-stage startups, indie founders, and small teams** who want to understand
their public security exposure without enterprise complexity.

This tool powers a **baseline security audit service** focused on clarity,
honesty, and actionable recommendations.

---

## 🚀 What AutoSec AI Does

AutoSec AI performs a **baseline external security checkup** and generates
clear, founder-friendly security reports.

It currently includes:

- 🔍 Port & service discovery (Nmap)
- 🌐 Web misconfiguration checks (Nikto)
- 🧠 AI-based risk explanation (local LLM)
- 🛡️ Severity classification (Low / Medium / High)
- 📄 Clean, professional security reports

---

## 🧭 Scope & Philosophy

AutoSec AI is intentionally scoped.

### ✅ It is designed to:
- Identify publicly exposed services
- Detect common misconfigurations
- Highlight known risks and security hygiene issues
- Explain findings in simple, non-alarmist language

### ❌ It does NOT:
- Perform deep application logic testing
- Exploit vulnerabilities
- Replace full penetration testing
- Bypass authentication or access controls

This makes AutoSec AI ideal for:
- MVPs and early-stage SaaS
- Pre-production sanity checks
- Founders shipping fast
- Recurring exposure monitoring

---

## 📄 Sample Output

AutoSec AI generates structured security reports that include:

- Overall risk assessment
- Security context and scope explanation
- Technical findings with severity
- AI-written risk summary
- Clear remediation guidance

The report format is designed to be easily shared with:
- Founders
- Developers
- Technical stakeholders

---

## ⚙️ Installation (Local)

```bash
git clone https://github.com/<your-username>/autosec-ai.git
cd autosec-ai
python -m venv .venv
source .venv/bin/activate
pip install -e .
▶️ Usage
autosec scan example.com
Generated reports are saved under:

reports/scans/<target>/
🔐 Privacy-Friendly by Design
Uses local AI models (via Ollama)

No scan data is sent to third-party services

Suitable for sensitive early-stage projects

🧠 Why AutoSec AI Exists
Many early-stage teams ship quickly but lack visibility into their
security exposure.

AutoSec AI exists to answer one simple question:

“Are we obviously exposed, and what should we fix first?”

📬 Security Checkup Service
AutoSec AI also powers a paid baseline security checkup service.

If you are an early-stage founder and want a quick, honest security assessment
of your public-facing infrastructure, feel free to reach out.

⚠️ Disclaimer
This tool is provided for educational and defensive security purposes only.
Only scan systems you own or have explicit permission to test.