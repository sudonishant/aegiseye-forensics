import os
import re

class StegoScanner:
    def __init__(self, file_path):
        self.file_path = file_path
        self.signatures = {
            "jpeg": {
                "header": b"\xff\xd8\xff",
                "footer": b"\xff\xd9"
            },
            "png": {
                "header": b"\x89PNG\r\n\x1a\n",
                "footer": b"IEND\xae\x42\x60\x82" # Standard IEND block + CRC
            },
            "gif": {
                "header": b"GIF8",
                "footer": b"\x00\x3b"
            }
        }

    def detect_file_type(self, data):
        """Identify file type by checking header magic bytes."""
        for name, sig in self.signatures.items():
            if data.startswith(sig["header"]):
                return name
        return None

    def scan(self):
        """Scan the file for magic bytes mismatch, overlays, and injected payloads."""
        if not os.path.exists(self.file_path):
            return {"error": "File not found."}

        findings = []
        filename = os.path.basename(self.file_path)
        ext = os.path.splitext(filename)[1].lower().replace(".", "")

        try:
            with open(self.file_path, "rb") as f:
                data = f.read()

            file_size = len(data)
            
            # 1. Check Magic Bytes / Extension Match
            detected_type = self.detect_file_type(data)
            if detected_type:
                # Map extensions
                mapped_ext = "jpg" if detected_type == "jpeg" else detected_type
                cleaned_ext = "jpg" if ext == "jpeg" else ext
                
                if cleaned_ext != mapped_ext:
                    findings.append({
                        "type": "Magic Bytes Spoof",
                        "severity": "Critical",
                        "description": f"File extension is '{ext}', but actual binary header matches '{detected_type}'. This file may be trying to hide its true format.",
                        "remediation": "Do not execute or open this file in trusted environments. Rename it to its true format or inspect in sandbox."
                    })
            else:
                findings.append({
                    "type": "Unknown File Header",
                    "severity": "High",
                    "description": "File has an image extension, but does not start with standard JPEG, PNG, or GIF magic bytes.",
                    "remediation": "Analyze file in a sandboxed environment. File could be a binary executable renamed as an image."
                })

            # 2. Check for Overlay / Appended Data (Steganography)
            if detected_type and detected_type in self.signatures:
                footer = self.signatures[detected_type]["footer"]
                
                # Search footer from the end of the file
                footer_index = data.rfind(footer)
                
                if footer_index != -1:
                    overlay_start = footer_index + len(footer)
                    # For PNG, IEND index could be slightly offset, but let's check if there is substantial data after footer
                    if overlay_start < file_size:
                        overlay_size = file_size - overlay_start
                        
                        # Only report overlays larger than 10 bytes (sometimes minor metadata padding exists)
                        if overlay_size > 15:
                            overlay_data = data[overlay_start:]
                            
                            # Inspect overlay for specific payloads
                            suspicious_strings = []
                            
                            # Look for embedded PHP/script tags
                            if b"<?php" in overlay_data or b"<?=" in overlay_data:
                                suspicious_strings.append("Embedded PHP code")
                            if b"<script>" in overlay_data or b"javascript:" in overlay_data:
                                suspicious_strings.append("Embedded JavaScript/HTML code")
                            if b"eval(" in overlay_data or b"system(" in overlay_data:
                                suspicious_strings.append("Execution function commands (eval/system)")
                            
                            # Look for ZIP header signature (PK\x03\x04)
                            is_zip = b"PK\x03\x04" in overlay_data
                            
                            desc = f"Detected {overlay_size} bytes of extra data appended after the image footer."
                            severity = "Medium"
                            if suspicious_strings:
                                desc += f" Found indicators of: {', '.join(suspicious_strings)}."
                                severity = "Critical"
                            elif is_zip:
                                desc += " Found embedded ZIP/Archive file signature (PK header). This could be a polyglot file."
                                severity = "High"

                            findings.append({
                                "type": "Appended Steganography / Overlay",
                                "severity": severity,
                                "description": desc,
                                "remediation": "Use an extraction tool (like binwalk or foremost) to extract the hidden payload, or strip the appended bytes using file editing tools."
                            })

            return {
                "scanned": True,
                "file_size": file_size,
                "detected_format": detected_type,
                "findings": findings
            }

        except Exception as e:
            return {"error": f"Steganography scan failed: {str(e)}"}
