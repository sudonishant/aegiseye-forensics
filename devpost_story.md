# Project Story: AegisEye Forensics — Email Threat Detection & Forensic Intelligence

## About the Project
AegisEye Forensics is a modular Python toolkit and MCP-compatible analysis service designed to help security teams move from **suspicious email to explainable evidence**. For the SIH 2026 email-threat problem, the platform adds read-only email-header triage to the existing image, OSINT, network, cryptographic, and evidence-handling modules.

The proposed workflow ingests a raw RFC 5322 email, preserves an SHA-256 evidence hash, validates visible sender and reply paths, evaluates SPF/DKIM/DMARC results, reconstructs the available `Received` relay chain, extracts URLs and attachments, and generates explainable risk findings with recommended analyst actions. Origin IPs are reported as candidates for approved intelligence enrichment; the platform does not claim geolocation or attribution from a single signal.

---

## What Inspired Us
Email remains a high-value attack surface because a convincing message can combine identity deception, urgent social-engineering language, malicious links, suspicious attachments, and compromised relay infrastructure. Existing filters often stop at “spam” or “not spam,” while investigators need the technical trail behind that decision.

We wanted to build a unified forensic cockpit that helps analysts answer three questions quickly: **Is this message suspicious? How did it travel? What evidence should guide the next action?**

---

## How We Built It
AegisEye is built as a modular, dependency-light Python suite:

- **Email threat core:** standard-library parsing of RFC 5322 messages, sender identity, Reply-To and Return-Path mismatches, authentication results, `Received` headers, relay IP candidates, URL and attachment indicators, urgency cues, explainable risk scoring, and SHA-256 evidence hashing.
- **Forensic reporting:** a dedicated HTML report preserves the analysis context, finding details, recommended actions, relay evidence, and chain-of-custody note without modifying the original message.
- **Existing forensic modules:** Pillow-based image analysis with EXIF/GPS, ELA, steganography and channel checks; phone/email OSINT; DNS/WHOIS/SSL network audits; cryptographic checks; and a controlled file shredder.
- **MCP integration:** a lightweight stdio JSON-RPC server exposes structured tools for email triage, image analysis, OSINT, network audits, and crypto checks so agentic clients can call focused operations rather than execute arbitrary shell commands.

The first email-threat implementation is intentionally conservative. Live geolocation, reputation feeds, domain-age intelligence, and graph storage are extension points for approved providers and institutional deployment. Every enrichment result should be preserved with its source and timestamp.

---

## Challenges and Risk Controls
1. **False positives and spoofed identities:** The analyzer combines multiple independent signals and returns explainable findings instead of relying on a single keyword or IP.
2. **Evidence integrity:** The email path is read-only, records a raw-input SHA-256 hash, and keeps chain-of-custody guidance beside the report.
3. **Privacy and attribution risk:** The local analyzer does not transmit message content or claim a sender’s location. Approved enrichment should be opt-in, masked where possible, retained under policy, and shown with confidence.
4. **Format diversity:** The parser preserves the raw `Received` headers and reports when no reliable IPv4 candidate can be extracted, allowing gateway logs or a future IPv6-aware enrichment module to fill the gap.

---

## What We Learned
A useful cybersecurity tool must not only detect risk; it must make the reasoning inspectable. By returning structured findings, origin candidates, recommendations, and evidence hashes, AegisEye gives analysts a repeatable starting point for triage while leaving high-impact attribution decisions to corroborated intelligence and human review.
