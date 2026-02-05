# 🔐 AutoSec AI

**AutoSec AI** is a lightweight, analyst-first security assessment engine for performing  
**baseline external security checkups** on early-stage products and internet-facing systems.

It is designed to help founders and small teams answer one practical question:

> **“Are we publicly exposed in obvious ways, and what should we fix first?”**

AutoSec AI is **not** a penetration testing tool.  
It is the internal engine behind a **fast, honest baseline security review workflow**.

---

## 🚀 What AutoSec AI Does

AutoSec AI performs a **safe, non-intrusive external security assessment** of a target’s
public attack surface and produces structured findings for human review.

It currently checks:

- 🔍 **Network exposure & open services** (Nmap)
- 🌐 **Common web server misconfigurations** (Nikto)
- 🛡️ **HTTP security headers**
- 📧 **DNS email security hygiene** (SPF, DKIM, DMARC)
- 🔐 **TLS / HTTPS availability**
- 🧾 **Domain & WHOIS hygiene**
- 🧠 **AI-assisted risk explanation** (local, optional)
- 📄 **Structured security reports** (Markdown & JSON)

---

## 🧭 Scope & Philosophy

AutoSec AI is intentionally scoped to remain safe, clear, and defensible.

### ✅ Designed to:
- Identify publicly exposed services
- Detect common security misconfigurations
- Highlight security hygiene gaps
- Provide calm, actionable recommendations
- Support analyst-reviewed security reports

### ❌ Explicitly does NOT:
- Exploit vulnerabilities
- Bypass authentication or authorization
- Perform deep application logic testing
- Replace full penetration testing
- Perform intrusive or unsafe scans

This makes AutoSec AI suitable for:
- Early-stage SaaS and startups
- MVP and pre-launch security checks
- Ongoing external exposure monitoring
- Founder-friendly security reviews

---

## 🔐 Safe by Design

- Public-surface checks only
- No exploitation or fuzzing
- No credentialed testing
- No authentication bypass
- Designed for defensive, permission-based use

---

## 🧠 AI Usage

AutoSec AI optionally uses **local AI models (via Ollama)** to assist with:

- Explaining technical findings in plain language
- Summarizing overall risk responsibly
- Providing non-alarmist remediation guidance

AI is **never** used to:
- Discover vulnerabilities
- Assign CVSS scores
- Make authoritative security claims

All AI output is advisory and intended for human review.

---

## 📄 Output & Workflow

AutoSec AI supports two primary outputs:

### 📘 Human-Readable Reports
- Clean Markdown reports
- Clear scope and limitations
- Findings grouped by scanner
- Designed for analyst review and refinement

### 📦 Machine-Readable Output
- JSON output mode for automation
- Suitable for CI pipelines and internal tooling
- Enables structured analyst workflows

> Reports are intended to be **reviewed and edited by a security analyst** before being shared externally.

---

## ⚙️ Installation

```bash
git clone https://github.com/<your-username>/autosec-ai.git
cd autosec-ai
python -m venv .venv
source .venv/bin/activate
pip install -e .

▶️ Usage

Run a baseline external security scan:

autosec scan example.com

Reports are generated under:

reports/scans/<target>/


🧩 Intended Users

AutoSec AI is built for:

Security consultants

Early-stage founders seeking clarity, not fear

Small teams without dedicated security staff

Anyone performing baseline external security reviews

It is not intended as a self-serve vulnerability scanner for end customers.



🧠 Why AutoSec AI Exists

Most early-stage teams move fast and lack visibility into their external security exposure.

AutoSec AI exists to provide:

Early signal

Honest context

Practical next steps

Without enterprise tooling, noise, or fear-driven reporting.


💼 Security Checkup Service

AutoSec AI powers a paid baseline external security checkup service.

If you are an early-stage founder and want a quick, honest assessment of your
public-facing infrastructure — reviewed by a human — this tool is the engine behind that work.


⚠️ Disclaimer

This tool is provided for educational and defensive security purposes only.

Only scan systems you own or have explicit permission to assess.

AutoSec AI does not guarantee the absence of vulnerabilities and should not be
considered a replacement for professional penetration testing.
