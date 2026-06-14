#!/usr/bin/env python3
import sys
import json
import os
import traceback
import hashlib

# Add current directory to path so core modules can be imported
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.metadata import MetadataScanner
from core.ela import ELAScanner
from core.stego import StegoScanner
from core.channels import ChannelScanner
from core.osint import OSINTAnalyzer
from core.network import NetworkAuditor
from core.crypto import CryptoToolbox
from core.reporter import ForensicReporter

def log(msg):
    sys.stderr.write(f"[AegisEye-MCP] {msg}\n")
    sys.stderr.flush()

# Tool implementations
def tool_analyze_image(arguments):
    image_path = arguments.get("image_path")
    if not image_path:
        return {"error": "Missing image_path argument"}
    if not os.path.exists(image_path):
        return {"error": f"Image path '{image_path}' does not exist"}

    try:
        results = {}
        # Calculate hashes
        hashes = {}
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        with open(image_path, "rb") as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha256.update(chunk)
        hashes["md5"] = md5.hexdigest()
        hashes["sha256"] = sha256.hexdigest()
        results["hashes"] = hashes

        results["file_meta"] = {
            "format": os.path.splitext(image_path)[1].upper().replace(".", ""),
            "size": f"{round(os.path.getsize(image_path) / 1024, 2)} KB"
        }

        # Metadata
        meta_scanner = MetadataScanner(image_path)
        results["exif"] = meta_scanner.scan()

        # ELA
        ela_scanner = ELAScanner(image_path)
        ela_output = os.path.splitext(image_path)[0] + "_ela_heatmap.png"
        results["ela"] = ela_scanner.analyze(output_path=ela_output)
        results["ela_heatmap_path"] = os.path.abspath(ela_output)

        # Stego
        stego_scanner = StegoScanner(image_path)
        results["stego"] = stego_scanner.scan()

        # Channels & pHash
        channel_scanner = ChannelScanner(image_path)
        results["channels"] = channel_scanner.split_channels()
        results["phash"] = channel_scanner.calculate_ahash()

        # Report compilation
        reporter = ForensicReporter(image_path)
        report_out = os.path.splitext(image_path)[0] + "_report.html"
        report_path = reporter.generate(results, output_path=report_out)
        results["report_path"] = os.path.abspath(report_path)

        return results
    except Exception as e:
        log(f"Error in analyze_image: {traceback.format_exc()}")
        return {"error": str(e)}

def tool_check_email_osint(arguments):
    email = arguments.get("email")
    if not email:
        return {"error": "Missing email argument"}
    try:
        analyzer = OSINTAnalyzer()
        return analyzer.analyze_email(email)
    except Exception as e:
        return {"error": str(e)}

def tool_check_phone_osint(arguments):
    phone = arguments.get("phone")
    if not phone:
        return {"error": "Missing phone argument"}
    try:
        analyzer = OSINTAnalyzer()
        return analyzer.analyze_phone(phone)
    except Exception as e:
        return {"error": str(e)}

def tool_audit_domain_network(arguments):
    domain = arguments.get("domain")
    if not domain:
        return {"error": "Missing domain argument"}
    try:
        auditor = NetworkAuditor(domain)
        ssl_res = auditor.audit_ssl()
        dns_res = auditor.audit_dns()
        whois_res = {}
        if arguments.get("check_whois", False):
            whois_res = auditor.audit_whois()
        
        return {
            "ssl_audit": ssl_res,
            "dns_audit": dns_res,
            "whois_audit": whois_res
        }
    except Exception as e:
        return {"error": str(e)}

def tool_crypto_hash_analysis(arguments):
    hash_str = arguments.get("hash_string")
    password = arguments.get("password")
    
    results = {}
    toolbox = CryptoToolbox()
    if hash_str:
        results["hash_classification"] = toolbox.identify_hash(hash_str)
    if password:
        results["password_strength"] = toolbox.audit_password(password)
        
    if not hash_str and not password:
        return {"error": "Provide either hash_string or password argument"}
        
    return results

TOOLS = {
    "analyze_image": {
        "description": "Examine an image file for metadata (EXIF/GPS), tampering anomalies (Error Level Analysis), and binary steganography overlays.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "image_path": { "type": "string", "description": "Absolute file path to the target image." }
          },
          "required": ["image_path"]
        },
        "handler": tool_analyze_image
    },
    "check_email_osint": {
        "description": "Perform OSINT domain verification, checking MX mail server records and domain syntax viability.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "email": { "type": "string", "description": "Target email address to analyze." }
          },
          "required": ["email"]
        },
        "handler": tool_check_email_osint
    },
    "check_phone_osint": {
        "description": "Audit phone metadata to retrieve carrier identification, country codes, and timezone data.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "phone": { "type": "string", "description": "Target phone number with country code (e.g. +1234567890)." }
          },
          "required": ["phone"]
        },
        "handler": tool_check_phone_osint
    },
    "audit_domain_network": {
        "description": "Audit a domain's network security profile, fetching active DNS records, SSL/TLS certificate health, and WHOIS registration details.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "domain": { "type": "string", "description": "Target domain name (e.g., example.com)." },
            "check_whois": { "type": "boolean", "description": "Whether to query WHOIS registration data (may take longer)." }
          },
          "required": ["domain"]
        },
        "handler": tool_audit_domain_network
    },
    "crypto_hash_analysis": {
        "description": "Classify hash signatures to identify the hashing algorithm (MD5/SHA1/SHA256) or evaluate password entropy strength.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "hash_string": { "type": "string", "description": "Raw cryptographic hash signature string to classify." },
            "password": { "type": "string", "description": "Raw password string to evaluate for entropy strength." }
          }
        },
        "handler": tool_crypto_hash_analysis
    }
}

def main():
    log("AegisEye MCP Server starting up...")
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            request = json.loads(line)
            req_id = request.get("id")
            method = request.get("method")
            
            if method == "initialize":
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": "aegiseye-mcp",
                            "version": "1.0.0"
                        }
                    }
                }
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
                log("Initialized successfully.")
                
            elif method == "notifications/initialized":
                # Notification doesn't need response
                log("Client received initialized status.")
                
            elif method == "tools/list":
                tools_list = []
                for name, info in TOOLS.items():
                    tools_list.append({
                        "name": name,
                        "description": info["description"],
                        "inputSchema": info["inputSchema"]
                    })
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": tools_list
                    }
                }
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
                
            elif method == "tools/call":
                params = request.get("params", {})
                tool_name = params.get("name")
                arguments = params.get("arguments", {})
                
                log(f"Calling tool: {tool_name} with args {arguments}")
                if tool_name in TOOLS:
                    try:
                        result = TOOLS[tool_name]["handler"](arguments)
                        response = {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "content": [
                                    {
                                        "type": "text",
                                        "text": json.dumps(result, indent=2)
                                    }
                                ]
                            }
                        }
                    except Exception as handler_err:
                        log(f"Handler error: {str(handler_err)}")
                        response = {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {
                                "code": -32603,
                                "message": f"Internal error during tool call: {str(handler_err)}"
                            }
                        }
                else:
                    response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32601,
                            "message": f"Tool '{tool_name}' not found"
                        }
                    }
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()

                
            else:
                # Unhandled JSON-RPC method
                if req_id is not None:
                    response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32601,
                            "message": f"Method '{method}' not found"
                        }
                    }
                    sys.stdout.write(json.dumps(response) + "\n")
                    sys.stdout.flush()
                    
        except Exception as e:
            log(f"Error handling request: {str(e)}")
            log(traceback.format_exc())

if __name__ == "__main__":
    main()
