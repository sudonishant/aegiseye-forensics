# Project Story: AegisEye (Custom MCP Server for OSINT & Digital Forensics)

## About the Project
AegisEye is a premium, autonomous digital forensics and OSINT agent extension built for the SANS **"Find Evil!" Hackathon 2026**. It connects autonomous incident response agents (like Claude Code, OpenClaw, or Cursor) to specialized forensic analysis tools via a custom Model Context Protocol (MCP) server, allowing automated compromise triage at machine speed.

---

## 💡 What Inspired Us
In modern cybersecurity, the speed gap is the most dangerous variable. While offensive AI agents can escalate privileges and gain full domain control in under 60 seconds, human incident responders are often left manually typing command flags or context-switching between EXIF extractors, SSL checkers, and hex editors. 

We were inspired to build a unified forensic cockpit that empowers defensive AI agents with structured, read-only analysis tools. By bridging the SANS SIFT Workstation's capabilities with LLM agentic loops using MCP, we wanted to create an autonomous responder that can triage anomalies, detect pixel-level image tampering, and analyze cryptographic strengths in seconds instead of hours.

---

## 🛠️ How We Built It
AegisEye is built as a modular, full-stack forensic suite:
* **The Forensics Core (Python)**: Utilizes native Python libraries along with `Pillow` and `rich` to run EXIF metadata parsing, RGB channel splitting, steganographic binary scanning, and active WHOIS/DNS/SSL network sockets.
* **The Error Level Analysis (ELA) Engine**: Programmatically resaves images at a specific JPEG quality and calculates the absolute difference against the original canvas. This difference is dynamically enhanced to make pixel-level edits visible.
* **The Custom MCP Server**: Built a lightweight, stdio-based JSON-RPC 2.0 protocol handler that translates LLM queries into type-safe Python function calls (like `analyze_image` or `audit_domain_network`) without requiring external library dependencies.

We model the cracking complexity and entropy strength of audited passwords mathematically. The Shannon Entropy \\( E \\) is computed using:
$$ E = L \times \log_2(R) $$
where \\( L \\) is the character length of the password and \\( R \\) is the size of the character pool (e.g., lowercases, uppercases, numbers, and special characters). 

We also calculate the dynamic enhancement factor for ELA heatmaps:
$$ \text{Scale Factor} = \min\left( \frac{255}{D_{\text{max}}}, S_{\text{default}} \right) $$
where \\( D_{\text{max}} \\) represents the maximum absolute difference between compressed and original pixels, and \\( S_{\text{default}} \\) is the configurable scale cap to prevent background noise amplification.

---

## 🛑 Challenges We Faced
1. **The Spoliation Risk (Evidence Integrity)**: In digital forensics, preserving the original state of evidence is paramount. If an AI agent runs arbitrary shell commands, a single hallucinated `rm` or `>` can overwrite a critical disk or memory capture. We solved this by enforcing a strictly **read-only Custom MCP Server** (Approach 2). The agent only has access to analysis endpoints and cannot execute arbitrary shell instructions.
2. **Context Window Overload**: Raw forensic tool outputs are massive. Dumping a full EXIF tree or binary hex stream into an LLM context instantly degrades reasoning capability. We resolved this by building a **Response Compiler** inside our MCP server that parses raw data into concise, structured JSON payloads, giving the model high-fidelity telemetry without context bloat.

---

## 🎓 What We Learned
Building AegisEye proved that Model Context Protocol (MCP) is the future of automated defense operations. By wrapping standard command-line tools into type-safe, structured functions, we can eliminate model hallucinations and create an execution log trail that human analysts can easily audit. We also learned that splitting analysis into specialized, focused tools is far more accurate than relying on a single general-purpose agent to navigate raw terminals.
