import os
from datetime import datetime

class ForensicReporter:
    def __init__(self, target_name):
        self.target_name = target_name
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate(self, data, output_path="aegiseye_report.html"):
        """Generate a premium, responsive HTML report showcasing the forensic results."""
        
        # Count warnings and critical alerts
        warning_count = 0
        critical_count = 0
        
        # Parse stego alerts
        stego_findings_html = ""
        stego_data = data.get("stego", {})
        if stego_data and "findings" in stego_data:
            for f in stego_data["findings"]:
                sev = f["severity"].lower()
                if sev == "critical":
                    critical_count += 1
                else:
                    warning_count += 1
                    
                stego_findings_html += f"""
                <div class="alert-item alert-{sev}">
                    <strong>[{f['severity'].upper()}] {f['type']}:</strong> {f['description']}
                    <p class="remediation-text">💡 {f['remediation']}</p>
                </div>
                """
        else:
            stego_findings_html = "<p class='no-alerts'>🛡️ No suspicious file markers or appended payloads detected.</p>"

        # File metadata
        file_meta = data.get("file_meta", {})
        hashes = data.get("hashes", {})
        
        # EXIF metadata table
        exif_html = ""
        exif_data = data.get("exif", {})
        gps_data = None
        
        if exif_data and "exif" in exif_data and exif_data["exif"]:
            gps_data = exif_data.get("gps")
            exif_html += '<table class="data-table"><thead><tr><th>Property</th><th>Value</th></tr></thead><tbody>'
            for key, val in exif_data["exif"].items():
                exif_html += f"<tr><td><strong>{key}</strong></td><td><code>{val}</code></td></tr>"
            exif_html += '</tbody></table>'
        else:
            exif_html = "<p class='no-data'>No EXIF metadata found in the image file.</p>"

        # GPS coordinates mapping card
        gps_html = ""
        if gps_data:
            gps_html += f"""
            <div class="gps-card">
                <h4>📍 GPS Location Found</h4>
                <p><strong>Latitude:</strong> {gps_data['latitude']}</p>
                <p><strong>Longitude:</strong> {gps_data['longitude']}</p>
                <a href="{gps_data['map_link']}" target="_blank" class="btn">View on Google Maps</a>
            </div>
            """

        # ELA images preview
        ela_data = data.get("ela")
        ela_html = ""
        if ela_data and ela_data.get("success"):
            ela_html += f"""
            <div class="ela-grid">
                <div class="ela-image-box">
                    <h5>Original Image</h5>
                    <img src="file://{os.path.abspath(self.target_name)}" alt="Original" class="forensic-image" />
                </div>
                <div class="ela-image-box">
                    <h5>ELA Heatmap</h5>
                    <img src="file://{ela_data['heatmap_path']}" alt="ELA Heatmap" class="forensic-image" />
                </div>
            </div>
            <div class="ela-explanation">
                <p><strong>Quality Tested:</strong> {ela_data['quality_tested']}% | <strong>Scale Factor:</strong> {round(ela_data['scale_factor_applied'], 2)}x</p>
                <p class="explanation-text">💡 <strong>How to read ELA:</strong> Brighter pixels represent mismatched compression rates. If a specific section (like a face or text) appears significantly brighter than surrounding areas of similar texture, it indicates potential tampering or splicing.</p>
            </div>
            """

        # Color channels preview
        channels_data = data.get("channels")
        channels_html = ""
        if channels_data and channels_data.get("success"):
            channels = channels_data.get("channels", {})
            channels_html += f"""
            <div class="channels-grid">
                <div class="channel-box">
                    <h5>Red Channel</h5>
                    <img src="file://{channels['red']}" alt="Red Channel" class="forensic-image" />
                </div>
                <div class="channel-box">
                    <h5>Green Channel</h5>
                    <img src="file://{channels['green']}" alt="Green Channel" class="forensic-image" />
                </div>
                <div class="channel-box">
                    <h5>Blue Channel</h5>
                    <img src="file://{channels['blue']}" alt="Blue Channel" class="forensic-image" />
                </div>
            </div>
            """

        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AegisEye Forensics Report - {os.path.basename(self.target_name)}</title>
    <style>
        :root {{
            --bg-color: #080c14;
            --card-bg: #111827;
            --text-color: #f3f4f6;
            --text-muted: #9ca3af;
            --border-color: #1f2937;
            --primary: #8b5cf6;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            
            --critical-bg: rgba(239, 68, 68, 0.1);
            --high-bg: rgba(249, 115, 22, 0.1);
            --medium-bg: rgba(234, 179, 8, 0.1);
            --low-bg: rgba(59, 130, 246, 0.1);
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Inter', system-ui, sans-serif;
        }}

        body {{
            background-color: var(--bg-color);
            color: var(--text-color);
            padding: 2rem 1rem;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}

        /* Header */
        header {{
            background: linear-gradient(135deg, #2e1065 0%, #0f172a 100%);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 25px rgba(0, 0, 0, 0.4);
        }}

        .logo {{
            font-size: 2.2rem;
            background: linear-gradient(to right, #a78bfa, #f472b6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 800;
            letter-spacing: -1px;
        }}

        .scan-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
            border-top: 1px dashed var(--border-color);
            padding-top: 1.5rem;
        }}

        .meta-card h5 {{
            color: var(--text-muted);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 4px;
        }}

        .meta-card p {{
            font-size: 1.1rem;
            font-weight: 600;
        }}

        /* Sections */
        section {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.2);
        }}

        h2 {{
            font-size: 1.4rem;
            color: #c084fc;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 8px;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        h3, h4 {{
            margin-bottom: 8px;
        }}

        /* Alerts & Warnings */
        .alert-item {{
            border-left: 4px solid;
            padding: 12px 16px;
            border-radius: 0 6px 6px 0;
            margin-bottom: 12px;
            font-size: 0.95rem;
        }}

        .alert-critical {{ background-color: var(--critical-bg); border-color: var(--critical); color: #fca5a5; }}
        .alert-high {{ background-color: var(--high-bg); border-color: var(--high); color: #fdba74; }}
        .alert-medium {{ background-color: var(--medium-bg); border-color: var(--medium); color: #fde047; }}
        .alert-low {{ background-color: var(--low-bg); border-color: var(--low); color: #93c5fd; }}

        .remediation-text {{
            margin-top: 6px;
            font-size: 0.85rem;
            color: var(--text-color);
        }}

        /* Tables */
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            font-size: 0.9rem;
        }}

        .data-table th, .data-table td {{
            border: 1px solid var(--border-color);
            padding: 8px 12px;
            text-align: left;
        }}

        .data-table th {{
            background-color: rgba(255,255,255,0.03);
            color: var(--text-muted);
        }}

        .data-table tr:nth-child(even) {{
            background-color: rgba(255,255,255,0.01);
        }}

        code {{
            background-color: rgba(255,255,255,0.06);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.85rem;
            word-break: break-all;
        }}

        /* Image Display Grid */
        .ela-grid, .channels-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-top: 10px;
        }}

        .ela-image-box, .channel-box {{
            text-align: center;
            background-color: rgba(0,0,0,0.2);
            padding: 10px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}

        .ela-image-box h5, .channel-box h5 {{
            color: var(--text-muted);
            margin-bottom: 8px;
            text-transform: uppercase;
            font-size: 0.8rem;
        }}

        .forensic-image {{
            max-width: 100%;
            height: auto;
            border-radius: 4px;
            border: 1px solid rgba(255,255,255,0.1);
        }}

        .ela-explanation, .ela-explanation p {{
            margin-top: 15px;
            font-size: 0.9rem;
        }}

        .explanation-text {{
            background-color: rgba(139, 92, 246, 0.05);
            border-left: 3px solid var(--primary);
            padding: 8px 12px;
            border-radius: 0 4px 4px 0;
            color: #d8b4fe;
        }}

        /* Button */
        .btn {{
            display: inline-block;
            background-color: var(--primary);
            color: white;
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 0.9rem;
            font-weight: 600;
            margin-top: 10px;
            transition: background 0.2s;
        }}

        .btn:hover {{
            background-color: #7c3aed;
        }}

        .gps-card {{
            background-color: rgba(255,255,255,0.03);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 1rem;
            margin-top: 10px;
        }}

        /* Footers */
        footer {{
            text-align: center;
            color: var(--text-muted);
            font-size: 0.8rem;
            margin-top: 3rem;
            border-top: 1px solid var(--border-color);
            padding-top: 1.5rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                <div>
                    <span class="logo">AEGISEYE</span>
                    <span style="font-weight: 300; color: var(--text-muted)">| Forensic Audit Report</span>
                </div>
                <div style="font-size: 0.85rem; color: var(--text-muted);">
                    CONFIDENTIAL FORENSIC REPORT
                </div>
            </div>
            
            <div class="scan-meta">
                <div class="meta-card">
                    <h5>File Analyzed</h5>
                    <p>{os.path.basename(self.target_name)}</p>
                </div>
                <div class="meta-card">
                    <h5>Analysis Date</h5>
                    <p>{self.timestamp}</p>
                </div>
                <div class="meta-card">
                    <h5>Format Detect</h5>
                    <p>{file_meta.get('format', 'Unknown')}</p>
                </div>
                <div class="meta-card">
                    <h5>Image Size</h5>
                    <p>{file_meta.get('size', 'Unknown')}</p>
                </div>
            </div>
        </header>

        <!-- Integrity & Hashes -->
        <section>
            <h2>🔑 File Integrity & Forensic Hashing</h2>
            <table class="data-table">
                <thead>
                    <tr><th>Algorithm</th><th>Hash Value</th></tr>
                </thead>
                <tbody>
                    <tr><td><strong>MD5</strong></td><td><code>{hashes.get('md5', '')}</code></td></tr>
                    <tr><td><strong>SHA-1</strong></td><td><code>{hashes.get('sha1', '')}</code></td></tr>
                    <tr><td><strong>SHA-256</strong></td><td><code>{hashes.get('sha256', '')}</code></td></tr>
                </tbody>
            </table>
        </section>

        <!-- Steganography & Payloads -->
        <section>
            <h2>🛡️ Steganography & Malware Scanner</h2>
            {stego_findings_html}
        </section>

        <!-- Error Level Analysis -->
        <section>
            <h2>🔍 Error Level Analysis (ELA) Heatmap</h2>
            {ela_html}
        </section>

        <!-- Color Channels -->
        <section>
            <h2>🎨 RGB Color Channel Extraction</h2>
            {channels_html}
        </section>

        <!-- Metadata & GPS -->
        <section>
            <h2>📍 EXIF Metadata & Location details</h2>
            <div style="display: grid; grid-template-columns: 3fr 1fr; gap: 1.5rem; flex-wrap: wrap;">
                <div>
                    {exif_html}
                </div>
                <div>
                    {gps_html}
                </div>
            </div>
        </section>

        <footer>
            <p>Generated by AegisEye Forensic Toolkit. Unauthorized reproduction prohibited.</p>
        </footer>
    </div>
</body>
</html>
        """

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_template)
            return os.path.abspath(output_path)
        except Exception as e:
            return None
