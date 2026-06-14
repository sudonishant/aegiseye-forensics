import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super(NumberedCanvas, self).__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_number(self, page_count):
        if self._pageNumber == 1:
            # Skip page numbering on cover page
            return
        self.saveState()
        self.setFont("Helvetica", 9)
        self.setFillColor(colors.HexColor("#64748b"))
        
        # Header
        self.drawString(54, 750, "AegisEye: Deep Forensic Analysis & OSINT Integration Guide")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 742, 558, 742)
        
        # Footer
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 40, page_text)
        self.drawString(54, 40, "Confidential - SANS Find Evil! Hackathon 2026 Submission")
        self.line(54, 52, 558, 52)
        self.restoreState()

def build_pdf():
    pdf_path = "/home/nishant/Desktop/antigravity/iit/aegiseye-forensics/aegiseye_guide.pdf"
    image_path = "/home/nishant/Desktop/antigravity/iit/aegiseye-forensics/assets/aegiseye_dashboard.png"

    # Setup document
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    # Styles
    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=28,
        leading=34,
        textColor=colors.HexColor("#4c1d95"),
        spaceAfter=15
    )
    
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#0891b2"),
        spaceAfter=30
    )
    
    meta_style = ParagraphStyle(
        'CoverMeta',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569")
    )
    
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#1e1b4b"),
        spaceBefore=18,
        spaceAfter=10,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#4c1d95"),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#334155"),
        spaceAfter=10
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#334155"),
        leftIndent=20,
        firstLineIndent=-10,
        spaceAfter=6
    )

    code_style = ParagraphStyle(
        'Code_Custom',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderColor=colors.HexColor("#e2e8f0"),
        borderWidth=0.5,
        borderPadding=6,
        spaceAfter=10
    )

    story = []

    # ================= PAGE 1: COVER PAGE =================
    story.append(Spacer(1, 150))
    story.append(Paragraph("AegisEye", title_style))
    story.append(Paragraph("Deep Forensic Analysis & Custom MCP Integration Guide", subtitle_style))
    story.append(Spacer(1, 40))
    
    meta_text = """
    <b>Author:</b> Neeshant Nishant<br/>
    <b>Date:</b> June 2026<br/>
    <b>Hackathon:</b> SANS Find Evil! 2026 Submission<br/>
    <b>Architecture:</b> Custom stdio Model Context Protocol (MCP) Server<br/>
    <b>Repository:</b> <font color="#0891b2">github.com/Neeshant01/aegiseye-forensics</font>
    """
    story.append(Paragraph(meta_text, meta_style))
    story.append(PageBreak())

    # ================= PAGE 2: HOW IT WORKS =================
    story.append(Spacer(1, 20))
    story.append(Paragraph("1. AegisEye Architecture & How it Works", h1_style))
    story.append(Paragraph(
        "AegisEye is built as a modular cybersecurity forensics toolkit that interfaces directly with LLMs using the Model Context Protocol (MCP). Instead of granting autonomous AI agents destructive raw terminal execution access (which risks spoliation of forensic evidence), AegisEye wraps specialized, read-only Python code modules into structured JSON-RPC API tools.",
        body_style
    ))
    
    story.append(Paragraph("The Core Analysis Engine:", h2_style))
    story.append(Paragraph(
        "• <b>Error Level Analysis (ELA)</b>: Resaves evidence images at a target compression quality (default 95%) and computes the absolute difference using pixel-by-pixel comparisons. Edited or tampered zones manifest different error levels because they have been compressed a different number of times than the rest of the image.",
        bullet_style
    ))
    story.append(Paragraph(
        "• <b>Steganography Overlay Scanner</b>: Audits image binaries for trailing byte data blocks that are appended after the standard EOF (End-Of-File) markers (like JPEGs <i>FFD9</i>). Stego payloads or malicious binary indicators are extracted dynamically.",
        bullet_style
    ))
    story.append(Paragraph(
        "• <b>Active Network Recon</b>: Triggers WHOIS socket calls, audits active DNS records, and performs live SSL/TLS handshakes to fetch certificate chains, auditing cipher health on suspect domains.",
        bullet_style
    ))
    story.append(Paragraph(
        "• <b>Password Entropy Calculator</b>: Measures Shannon Entropy \\( E = L \\log_2(R) \\) to determine how many bits of information are represented by a credential and calculates cracking complexity timescales.",
        bullet_style
    ))
    
    story.append(Paragraph("JSON-RPC 2.0 stdio Handshake:", h2_style))
    story.append(Paragraph(
        "The server listens on <i>stdin</i> for RPC commands, processes requests, and outputs single-line JSON responses to <i>stdout</i>. Debugging traces are directed exclusively to <i>stderr</i> to prevent polluting the MCP data stream.",
        body_style
    ))
    
    story.append(PageBreak())

    # ================= PAGE 3: USE CASES & INTERACTIVE FLOW =================
    story.append(Spacer(1, 20))
    story.append(Paragraph("2. Primary Use Cases & Deployment", h1_style))
    story.append(Paragraph(
        "AegisEye is designed to solve real-world security triage and open-source intelligence problems:",
        body_style
    ))
    
    story.append(Paragraph("Triage of Media Tampering", h2_style))
    story.append(Paragraph(
        "Security incident response teams can pass server logs containing suspicious configuration screenshots directly to AegisEye. The ELA module automatically highlights visual edits, helping analysts detect spoofed settings or modified evidence files.",
        body_style
    ))

    story.append(Paragraph("OSINT Threat Reconnaissance", h2_style))
    story.append(Paragraph(
        "When analyzing a potential phishing attack, the agent uses AegisEye OSINT tools to verify email MX records and check the domain's registration WHOIS date, exposing newly-registered malicious endpoints instantly.",
        body_style
    ))

    story.append(Paragraph("MCP Configuration Block:", h2_style))
    story.append(Paragraph(
        "To enable AegisEye in an agentic workflow, add the following to your MCP client configuration file (e.g. <i>claude.json</i>):",
        body_style
    ))
    
    mcp_config_text = """{
  "mcpServers": {
    "aegiseye-forensics": {
      "command": "python3",
      "args": ["/absolute/path/to/aegiseye-forensics/aegiseye_mcp.py"]
    }
  }
}"""
    story.append(Paragraph(mcp_config_text.replace("\n", "<br/>").replace(" ", "&nbsp;"), code_style))
    story.append(PageBreak())

    # ================= PAGE 4: FUTURE ROADMAP =================
    story.append(Spacer(1, 20))
    story.append(Paragraph("3. Future Upgrades & Roadmap", h1_style))
    story.append(Paragraph(
        "To scale AegisEye to an enterprise-grade autonomous security defender, we have planned a three-tier roadmap:",
        body_style
    ))

    story.append(Paragraph("1. Neural ELA Classification Models", h2_style))
    story.append(Paragraph(
        "Integrate local, lightweight PyTorch convolutional neural networks (CNNs) directly into the image analysis pipeline. This will allow the agent to classify whether ELA heatmaps show genuine modifications vs. normal JPEG artifacts, reducing false positives to under 1%.",
        body_style
    ))

    story.append(Paragraph("2. MFT & Registry Timelining tools", h2_style))
    story.append(Paragraph(
        "Expose direct MCP tools to read the Master File Table (MFT) and Windows Registry hives from disk images, allowing the agent to reconstruct a chronological system timeline of file activity around an intrusion timestamp.",
        body_style
    ))

    story.append(Paragraph("3. Secure Docker Execution Sandboxing", h2_style))
    story.append(Paragraph(
        "Add a containerized layer where any file analysis or potential stego payload extraction is performed inside an ephemeral, network-isolated Docker sandbox to protect the host SIFT Workstation from zero-day exploits.",
        body_style
    ))
    story.append(PageBreak())

    # ================= PAGE 5: DASHBOARD SHOWCASE =================
    story.append(Spacer(1, 20))
    story.append(Paragraph("4. AegisEye Forensic Dashboard Mockup", h1_style))
    story.append(Paragraph(
        "Below is the premium, glassmorphic UI design mockup of the AegisEye dashboard showing ELA analytics, active log streams, EXIF coordinates, and secure file shredding modules:",
        body_style
    ))
    
    if os.path.exists(image_path):
        story.append(Spacer(1, 10))
        # Letter width is 612pt, margins are 54pt each. Content width = 504pt
        # Image is square, scale to fit content width
        story.append(Image(image_path, width=400, height=400))
    else:
        story.append(Paragraph("[Error: Mockup image assets/aegiseye_dashboard.png not found]", h2_style))

    # Build Document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Successfully generated PDF: {pdf_path}")

if __name__ == "__main__":
    build_pdf()
