🔐 AutoSec AI

AutoSec AI is a lightweight, analyst-first security assessment engine designed to perform
baseline external security checkups for early-stage startups, indie founders, and small teams.

It helps answer one practical question:

“Are we publicly exposed in obvious ways, and what should we fix first?”

AutoSec AI is not a penetration testing tool.
It is the engine behind a fast, honest, baseline security review service.

🚀 What AutoSec AI Does

AutoSec AI performs a safe, non-intrusive external security assessment of a target’s
public-facing surface and produces structured findings for human review.

It currently assesses:

🔍 Network exposure & services (Nmap)

🌐 Web server misconfigurations (Nikto)

🛡️ HTTP security headers

📧 DNS email security hygiene (SPF, DKIM, DMARC)

🔐 TLS / HTTPS availability & configuration

🧾 WHOIS & domain hygiene

🧠 AI-assisted risk explanation (local, optional)

📄 Structured security reports (Markdown + JSON)

🧭 Scope & Philosophy

AutoSec AI is intentionally scoped.

✅ Designed to:

Identify publicly exposed services

Detect common misconfigurations

Highlight security hygiene gaps

Provide calm, actionable guidance

Support analyst-reviewed security reports

❌ Explicitly does NOT:

Exploit vulnerabilities

Bypass authentication or authorization

Perform deep application logic testing

Replace penetration testing

Perform intrusive or unsafe scans

This makes AutoSec AI ideal for:

Early-stage SaaS & startups

MVP and pre-launch checks

Ongoing exposure monitoring

Founder-friendly security reviews

🔐 Safe by Design

No exploitation

No credentialed testing

No crawling or fuzzing

Public-surface checks only

Designed for defensive, permission-based use

🧠 AI Usage (Important)

AutoSec AI uses local AI models (via Ollama) to assist with:

Explaining risk in plain language

Summarizing findings responsibly

Providing non-alarmist recommendations

AI is never used to:

Detect vulnerabilities

Assign CVSS scores

Make authoritative security claims

AI output is advisory, not authoritative.

📄 Output & Workflow

AutoSec AI supports two primary outputs:

📘 Human-Readable Reports

Clean Markdown reports

Clear scope explanation

Structured findings by scanner

Designed for internal review and refinement

📦 Machine-Readable Output

JSON output mode for automation

Suitable for CI, scripts, or internal tooling

Enables analyst workflows and integrations

Reports are intended to be reviewed and refined by a security analyst before being shared externally.

⚙️ Installation (Local)
git clone https://github.com/<your-username>/autosec-ai.git
cd autosec-ai
python -m venv .venv
source .venv/bin/activate
pip install -e .

▶️ Usage

Run a baseline external scan:

autosec scan example.com


Reports are saved under:

reports/scans/<target>/

🧩 Who This Is For

AutoSec AI is built for:

Security consultants

Startup founders who want clarity, not fear

Small teams without dedicated security staff

Anyone offering or performing baseline security reviews

It is not intended as a self-serve vulnerability scanner for end customers.

🧠 Why AutoSec AI Exists

Most early-stage teams ship fast — and security visibility comes late.

AutoSec AI exists to provide:

Early signal

Honest context

Practical next steps

Without enterprise tooling, noise, or fear-driven reporting.

💼 Security Checkup Service

AutoSec AI powers a paid baseline security checkup service.

If you’re an early-stage founder and want a quick, honest assessment of your
public-facing infrastructure — reviewed by a human — this tool is the engine behind that work.

⚠️ Disclaimer

This tool is provided for educational and defensive security purposes only.

Only scan systems you own or have explicit permission to assess.

AutoSec AI does not guarantee the absence of vulnerabilities and should not be
considered a replacement for professional penetration testing.