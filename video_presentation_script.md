# AegisEye: SANS "Find Evil!" Hackathon Demo Video Script
**Format**: 5-Minute Screencast with Audio Narration
**Evidence Target**: `evidence/tampered_evidence.jpg`

---

## ⏱️ Video Timeline & Narration Script

### Section 1: Intro & The Breakout Gap (0:00 - 0:45)
* **Visual**: Show the AegisEye GitHub repository or the generated glassmorphic dashboard mockup image (`assets/aegiseye_dashboard.png`).
* **Narration**:
  > *"Hi everyone, today I'm presenting AegisEye: a Custom Model Context Protocol (MCP) server designed for the SANS SIFT Workstation to close the machine-speed breakout gap.*
  >
  > *With modern threats moving from initial compromise to full domain control in under 8 minutes, human analysts can no longer afford to manually copy-paste flags. AegisEye empowers autonomous incident response agents with a suite of type-safe, read-only digital forensics and OSINT tools, protecting evidence integrity from data spoliation during automated triage."*

---

### Section 2: Interactive TUI & OSINT Demo (0:45 - 1:45)
* **Visual**: Open terminal and execute: `python3 aegiseye.py`
  1. Show the ASCII Banner and the options menu.
  2. Select **Option 2** (Phone OSINT) and lookup a test number.
  3. Select **Option 5** (Domain Audit) and run it against `neeshant.online` to show SSL validity, active DNS records, and raw WHOIS registry queries.
* **Narration**:
  > *"AegisEye operates in two modes. First, the interactive CLI/TUI mode. Here, an analyst can quickly perform passive OSINT checks. For instance, querying email MX mail records or auditing SSL/TLS certs and active DNS records directly using raw Python socket queries. The TUI compiles these into clean, highlighted tables in seconds."*

---

### Section 3: The Image Tampering Forensic Check (1:45 - 2:45)
* **Visual**: Select **Option 1** (Image Forensics) and pass the path: `evidence/tampered_evidence.jpg`.
  Show the terminal progress indicators running:
  `Performing ELA manipulation check...`
  `Scanning binary overlay for stego payloads...`
  *Open* the generated ELA heatmap image (`evidence/tampered_evidence_ela_heatmap.png`) showing the glowing text highlight around the word "True".
* **Narration**:
  > *"Let's look at the core digital forensics engine. In this scenario, we have a suspect configuration screenshot. We run AegisEye's Error Level Analysis or ELA module. ELA resaves the target image at a specific JPEG quality and calculates the pixel difference.*
  >
  > *As you can see on the screen, the generated ELA heatmap shows a high-contrast glowing signature around the edited text, instantly exposing that the screenshot was tampered with to mask system configurations."*

---

### Section 4: The Agent MCP & Self-Correction Demo (2:45 - 4:15)
* **Visual**: Switch terminal to Claude Code or OpenClaw running with the AegisEye MCP server configured (`aegiseye_mcp.py`).
  1. Type the user query:
     > *"Analyze the evidence file `/absolute/path/to/aegiseye-forensics/evidence/tampered_evidence.jpg` and tell me if it's safe."*
  2. Show the agent calling the tool: `analyze_image(image_path="...")`.
  3. Show the JSON output returning ELA details and stego scans.
  4. Show the agent's final reasoning block.
* **Narration**:
  > *"Now, let's see how our Custom MCP Server integrates with an autonomous agent. We configure the client to launch `aegiseye_mcp.py` over stdio.*
  >
  > *When we ask the agent to verify the image, it makes a structured tool call. Notice the **Self-Correction sequence** here: The agent initially observes that the image lacks standard EXIF GPS tags and suggests the file is clean. However, after parsing the ELA heatmap metrics and stego binary results returned by the MCP tool, the agent self-corrects: it identifies that the local compression difference proves pixel modification and alerts the analyst that the evidence is compromised. This is true autonomous reasoning at work."*

---

### Section 5: Conclusion & Security Boundaries (4:15 - 5:00)
* **Visual**: Show the SANS SIFT SRE Architecture flow diagram from the README.
* **Narration**:
  > *"What makes this submission stand out is constraint enforcement. Because the MCP server only exposes read-only functions (like `analyze_image` and `audit_domain_network`) rather than a generic shell execution tool, the agent cannot execute destructive scripts, guaranteeing zero risk of data spoliation.*
  >
  > *AegisEye brings structure, speed, and safety to AI-driven incident response. Thanks for watching, and all setup files are available in the repository!"*

---

## 🛠️ How to Record This Presentation
1. **Tool**: Use OBS Studio or Zoom to record your screen at `1080p` or `4K`.
2. **Terminal Theme**: Use a dark theme (e.g. standard terminal colors or a Kali theme) to make the Rich tables and violet banners pop.
3. **Voice**: Speak clearly at a moderate pace, making sure to highlight the **Self-Correction sequence** (which SANS judges explicitly grade under Criteria 1: Autonomous Execution Quality).
