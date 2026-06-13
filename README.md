# AegisEye: Premium OSINT & Digital Forensics Toolkit 🛡️🔎

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Cybersecurity Tool](https://img.shields.io/badge/Cybersecurity-Forensics--OSINT-purple.svg)]()
[![Platform Support](https://img.shields.io/badge/Platform-Kali--Linux-red.svg)]()

**AegisEye** is a comprehensive, multi-functional tool designed for digital forensics, open-source intelligence (OSINT), and file analysis. It offers 5 specialized command-line modules that perform advanced static file forensics, visual image tamper checks (Error Level Analysis), network reconnaissance, cryptographic strength auditing, and secure military-grade file shredding.

---

## 📸 Forensic Audit Dashboard Preview
![AegisEye Forensic Dashboard](./assets/aegiseye_dashboard.png)

---

## 🚀 Toolkit Modules & Features
- **🔍 Image Analysis (`image` command):** Audits EXIF data, extracts GPS coordinates, performs Error Level Analysis (ELA) to locate pixel manipulations, and checks for spoofed formats or hidden malware payloads.
- **📞 Phone & Email OSINT (`osint` command):** Checks phone number carriers and email MX records.
- **🗑️ Forensic File Shredder (`shred` command):** Overwrites targets using DoD 5220.22-M military standards to prevent any forensic lab recovery.
- **🌐 Network Recon (`domain` command):** WHOIS socket queries, active DNS record audits, and SSL certificate health checks.
- **🔑 Cryptography (`crypto` command):** Classifies hash formats and audits password strength entropy.

---

## 🚀 Step-by-Step Installation & Setup

### Step 1: Clone the Repository (Download karein)
Open your terminal and clone the repository:
```bash
git clone https://github.com/Neeshant01/aegiseye-forensics.git
cd aegiseye-forensics
```

### Step 2: Setup Virtual Environment (Venv configure karein)
Setting up a python virtual environment prevents the `externally-managed-environment` error:
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies (Packages install karein)
Install all required python packages:
```bash
pip install -r requirements.txt
```

### Step 4: Run Audits (Run karein)

#### 🎮 Interactive TUI Menu Mode (Recommended)
Run the script without any options to launch the interactive TUI menu. You can perform all operations (forensics, OSINT, secure shredding, crypto audits) by entering options `1-9`:
```bash
python aegiseye.py
```

#### 💻 Direct Command-Line CLI Mode
You can also run specific modules directly using subcommand arguments:
```bash
# General Help menu
python aegiseye.py --help

# Scan local image ELA/EXIF
python aegiseye.py image photo.jpg

# Securely wipe a file (5 passes)
python aegiseye.py shred secret.txt --passes 5
```

---

## 📖 Complete Setup & Troubleshooting Guide
For advanced debugging (e.g. fixing PIL/Pillow compiler issues or setting up coordinates maps), read the [SETUP_GUIDE.md](./SETUP_GUIDE.md).

---

## 📄 License
Distributed under the MIT License.
