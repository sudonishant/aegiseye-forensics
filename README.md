# AegisEye: Premium OSINT & Digital Forensics Toolkit 🛡️🔎

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Cybersecurity Tool](https://img.shields.io/badge/Cybersecurity-Forensics--OSINT-purple.svg)]()
[![Platform Support](https://img.shields.io/badge/Platform-Kali--Linux-red.svg)]()

**AegisEye** is a comprehensive, multi-functional tool designed for digital forensics, open-source intelligence (OSINT), and file analysis. It now includes a read-only email-threat triage path for the SIH 2026 email-forensics use case: it preserves an evidence hash, parses RFC 5322 headers, evaluates authentication results, reconstructs visible relay hops, extracts links and attachments, and produces explainable risk findings plus an HTML forensic report. The existing image, OSINT, network, crypto, and secure-shredding modules remain available.

---

## 📸 Forensic Audit Dashboard Preview
![AegisEye Forensic Dashboard](./assets/aegiseye_dashboard.png)

---

## 🚀 Toolkit Modules & Features
- **🔍 Image Analysis (`image` command):** Audits EXIF data, extracts GPS coordinates, performs Error Level Analysis (ELA) to locate pixel manipulations, and checks for spoofed formats or hidden malware payloads.
- **📞 Phone & Email OSINT (`osint` command):** Checks phone number carriers and email MX records.
- **🛡️ Email Threat Triage (`email` command):** Performs read-only email-header forensics, authentication checks, URL and attachment indicators, relay-path reconstruction, origin candidates, explainable risk scoring, SHA-256 evidence hashing, and HTML reporting.
- **🗑️ File Shredder (`shred` command):** Performs best-effort overwrite passes before deleting a file. This is not a certified sanitization method and cannot guarantee recovery prevention on SSDs, copy-on-write filesystems, snapshots, or backups.
- **🌐 Network Recon (`domain` command):** WHOIS socket queries, active DNS record audits, and SSL certificate health checks.
- **🔑 Cryptography (`crypto` command):** Classifies hash formats and audits password strength entropy.

---

## 🚀 Step-by-Step Installation & Setup

### Step 1: Clone the Repository
Open your terminal and clone the repository:
```bash
git clone https://github.com/sudonishant/aegiseye-forensics.git
cd aegiseye-forensics
```

### Step 2: Setup Virtual Environment
Setting up a Python virtual environment prevents the externally-managed-environment error:
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
Install all required Python packages:
```bash
pip install -r requirements.txt
```

### Step 4: Run Audits

#### 🎮 Interactive TUI Menu Mode
Run the script without any options to launch the interactive TUI menu. You can perform image forensics, email triage, OSINT, secure shredding, and crypto audits from the displayed options:
```bash
python aegiseye.py
```

#### 💻 Direct Command-Line Mode
You can also run specific modules directly using subcommand arguments:
```bash
# General help menu
python aegiseye.py --help

# Scan local image ELA/EXIF
python aegiseye.py image photo.jpg

# Analyze a raw RFC 5322 email and generate an HTML forensic report
python aegiseye.py email evidence/suspicious_email.eml

# Print the complete structured result as JSON
python aegiseye.py email evidence/suspicious_email.eml --json

# Best-effort overwrite and delete (5 passes)
python aegiseye.py shred secret.txt --passes 5
```

The email analyzer is intentionally read-only and local. It reports origin IP candidates and enrichment targets, but it does not claim geolocation or attribution from a single IP; connect an approved intelligence provider before making a location or actor assessment.

---

## 🔌 Model Context Protocol (MCP) Server Integration
AegisEye is integrated as a Custom MCP Server. This allows autonomous incident-response agents such as Claude Code, OpenClaw, or Cursor to call AegisEye tools natively over stdio.

### Exposed MCP Tools
1. `analyze_image(image_path)`: Scans an image for EXIF/GPS, runs ELA pixel-tamper checks, splits RGB channels, and returns a compiled HTML report path.
2. `analyze_email_threat(email_path|raw_email, source_name, report_path)`: Performs read-only email threat triage, returns structured authentication, identity, URL, attachment, relay, origin-candidate, risk, and evidence-hash data, and can write an HTML report.
3. `check_email_osint(email)`: OSINT validator checking domain syntax and active mail server MX records.
4. `check_phone_osint(phone)`: OSINT auditor for carrier information, timezone, and geolocation country mapping.
5. `audit_domain_network(domain, check_whois)`: Network engine checking active DNS, WHOIS registration, and SSL/TLS certificate health status.
6. `crypto_hash_analysis(hash_string, password)`: Identifies cryptographic hash algorithm types or evaluates password entropy.

### Running AegisEye as an MCP Server
To configure and run AegisEye as an MCP server with an agentic client:
```json
{
  "mcpServers": {
    "aegiseye-forensics": {
      "command": "python3",
      "args": ["/absolute/path/to/aegiseye-forensics/aegiseye_mcp.py"]
    }
  }
}
```

### Verification Against Evidence
The `evidence/` directory includes:
- `evidence/clean_evidence.jpg`: Clean system configuration screenshot.
- `evidence/tampered_evidence.jpg`: Manipulated system configuration screenshot.
- `evidence/suspicious_email.eml`: A safe, synthetic raw email fixture containing failed authentication, a mismatched reply domain, a shortened link, a Punycode lookalike, suspicious urgency language, and a macro-enabled attachment name.

You can verify the synthetic email workflow:
```bash
python aegiseye.py email evidence/suspicious_email.eml
python aegiseye.py email evidence/suspicious_email.eml --json
```

For an MCP client, call `analyze_email_threat` with `email_path` for a local `.eml` file or `raw_email` for controlled raw content. The returned JSON is designed for downstream dashboards and case-management workflows.

---

## ⚖️ Forensic Data Integrity & Triage Warning
AegisEye is designed to audit and triage systems during security incidents. To preserve evidence integrity:
1. **Strictly Read-Only Analysis:** The email parser, email-header triage, image ELA, EXIF parser, and certificate audits do not write to or alter the target evidence.
2. **Evidence Hashing:** Email analysis records a SHA-256 hash of the raw input so downstream workflows can verify which evidence was analyzed.
3. **No Single-Signal Attribution:** A relay IP is reported as an origin candidate, not as proof of the sender’s location or identity. Add approved IP/domain intelligence before making a location or attribution assessment.
4. **Best-effort File Deletion:** The shredder attempts multiple overwrite passes before deleting the file. It is not DoD-certified and cannot ensure erasure on SSDs, copy-on-write filesystems, snapshots, backups, or other storage that remaps or preserves data. Do not rely on it as a guaranteed sanitization method; use only when permanent deletion is explicitly intended.
5. **Execution Sandbox:** When integrating with agentic incident-response frameworks, configure local execution block policies to verify destructive actions.

---

## 📖 Complete Setup & Troubleshooting Guide
For advanced debugging, read the [SETUP_GUIDE.md](./SETUP_GUIDE.md).

---

## 📄 License
Distributed under the MIT License.
