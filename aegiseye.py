#!/usr/bin/env python3
import sys
import os
import argparse
import hashlib
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

# Import our core components
from core.metadata import MetadataScanner
from core.ela import ELAScanner
from core.stego import StegoScanner
from core.channels import ChannelScanner
from core.osint import OSINTAnalyzer
from core.shred import FileShredder
from core.network import NetworkAuditor
from core.crypto import CryptoToolbox
from core.reporter import ForensicReporter

# Initialize Rich Console
console = Console()

BANNER = """
[bold purple]
 ▄▄▄· ▄▄▄▄▄ ▄▄ •  ▪  ▄▄▄ · ▄▄▄▄▄ ▄· ▄▌▄▄▄ .
▐█ ▀█ •██   ▐█ ▀ ▪ ██ ▐█ ▀. •██   ▐█▪██▌▀▄.▀·
▄█▀▀█  ▐█.▪ ▄█ ▀█▄ ▐█·▄▀▀▀█▄ ▐█.▪ ▐█▌▐█▪▐▀▀▪▄
▐█ ▪▐▌ ▐█▌· ▐█▄▪▐█ ▐█▌▐█▄▪▐█ ▐█▌·  ▐█▀·. ▐█▄▄▌
 ▀  ▀  ▀▀▀  ·▀▀▀▀  ▀▀▀ ▀▀▀▀   ▀▀▀   ▀ •   ▀▀▀ 
[/bold purple]
            [bold cyan]AegisEye - OSINT & Digital Forensics Toolkit v1.0.0[/bold cyan]
             [dim]Developed by Nishant Kumar (Neeshant01)[/dim]
"""

def calculate_file_hashes(file_path):
    """Calculate MD5, SHA-1, and SHA-256 hashes of a file."""
    hashes = {}
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        hashes["md5"] = md5.hexdigest()
        hashes["sha1"] = sha1.hexdigest()
        hashes["sha256"] = sha256.hexdigest()
    except Exception as e:
        console.print(f"[red]Failed to compute file hashes:[/red] {str(e)}")
    return hashes

def run_image_forensics(image_path):
    if not os.path.exists(image_path):
        console.print(f"[bold red]Error:[/bold red] File '{image_path}' not found.")
        return

    console.print(Panel(f"[bold green]Starting Digital Image Forensics[/bold green]\n[bold]File:[/bold] {image_path}", border_style="purple"))

    results = {}
    results["hashes"] = calculate_file_hashes(image_path)
    results["file_meta"] = {
        "format": os.path.splitext(image_path)[1].upper().replace(".", ""),
        "size": f"{round(os.path.getsize(image_path) / 1024, 2)} KB"
    }

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # Step 1: EXIF Metadata & GPS
            t1 = progress.add_task(description="Extracting EXIF metadata and GPS coordinates...", total=1)
            meta_scanner = MetadataScanner(image_path)
            results["exif"] = meta_scanner.scan()
            progress.advance(t1)

            # Step 2: Error Level Analysis (ELA)
            t2 = progress.add_task(description="Performing ELA (Error Level Analysis) manipulation check...", total=1)
            ela_scanner = ELAScanner(image_path)
            ela_output = os.path.splitext(image_path)[0] + "_ela_heatmap.png"
            results["ela"] = ela_scanner.analyze(output_path=ela_output)
            progress.advance(t2)

            # Step 3: Steganography & Malware Scanner
            t3 = progress.add_task(description="Scanning file binary overlay for stego payloads...", total=1)
            stego_scanner = StegoScanner(image_path)
            results["stego"] = stego_scanner.scan()
            progress.advance(t3)

            # Step 4: Color Channels Split & pHash
            t4 = progress.add_task(description="Splitting RGB channels and computing perceptual hash...", total=1)
            channel_scanner = ChannelScanner(image_path)
            results["channels"] = channel_scanner.split_channels()
            results["phash"] = channel_scanner.calculate_ahash()
            progress.advance(t4)

            # Step 5: Report compilation
            t5 = progress.add_task(description="Compiling results and writing HTML audit report...", total=1)
            reporter = ForensicReporter(image_path)
            report_out = os.path.splitext(image_path)[0] + "_report.html"
            report_path = reporter.generate(results, output_path=report_out)
            progress.advance(t5)

        console.print(Panel(f"[bold green]✔ Forensic Audit Completed![/bold green]\n\n[bold]HTML Audit Report Saved To:[/bold] \n[underline cyan]{report_path}[/underline cyan]\n\n[bold]ELA Heatmap Saved To:[/bold] \n[cyan]{os.path.abspath(ela_output)}[/cyan]", border_style="green"))

        # Print quick summaries
        stego_findings = results["stego"].get("findings", [])
        if stego_findings:
            table = Table(title="⚠️ Suspicious Steganography Findings", header_style="bold magenta", border_style="red")
            table.add_column("Audit Type", justify="left")
            table.add_column("Severity", justify="center")
            table.add_column("Description", justify="left")
            for f in stego_findings:
                table.add_row(f["type"], f"[bold red]{f['severity']}[/bold red]", f["description"])
            console.print(table)
        else:
            console.print("[green]✔ No suspicious steganography overlay detected in image binary.[/green]")

    except Exception as e:
        console.print(f"[bold red]Audit failed:[/bold red] {str(e)}")

def run_phone_osint(phone_num):
    analyzer = OSINTAnalyzer()
    console.print(Panel(f"[bold green]Starting Phone OSINT Audit[/bold green]\n[bold]Phone Number:[/bold] {phone_num}", border_style="purple"))
    res = analyzer.analyze_phone(phone_num)
    if "error" in res:
        console.print(f"[bold red]Error:[/bold red] {res['error']}")
    else:
        table = Table(title="Phone Metadata Results", border_style="purple")
        table.add_column("Field", style="bold cyan")
        table.add_column("Value")
        table.add_row("Valid Number", "Yes" if res["valid"] else "No")
        table.add_row("Number Type", res["type"])
        table.add_row("Registered Country", res["country"])
        table.add_row("Telecom Carrier", res["carrier"])
        table.add_row("Timezones", ", ".join(res["timezones"]))
        console.print(table)

def run_email_osint(email_addr):
    analyzer = OSINTAnalyzer()
    console.print(Panel(f"[bold green]Starting Email OSINT Audit[/bold green]\n[bold]Email Address:[/bold] {email_addr}", border_style="purple"))
    res = analyzer.analyze_email(email_addr)
    if "error" in res:
        console.print(f"[bold red]Error:[/bold red] {res['error']}")
    else:
        table = Table(title="Email Validation Details", border_style="purple")
        table.add_column("Field", style="bold cyan")
        table.add_column("Value")
        table.add_row("Valid Format", "Yes" if res["valid_format"] else "No")
        table.add_row("Extracted Domain", res["domain"])
        table.add_row("Has Active MX Records", "Yes" if res["has_mx_records"] else "No (Failing / Dead domain)")
        console.print(table)
        
        if res.get("mx_servers"):
            mx_table = Table(title="Active Mail Servers (MX)", border_style="cyan")
            mx_table.add_column("Priority", style="bold yellow")
            mx_table.add_column("Mail Server Address")
            for s in res["mx_servers"]:
                mx_table.add_row(str(s["priority"]), s["server"])
            console.print(mx_table)

def run_file_shred(file_path, passes=3):
    if not os.path.exists(file_path):
        console.print(f"[bold red]Error:[/bold red] File '{file_path}' not found.")
        return

    confirm = console.input(f"[bold red]⚠ WARNING:[/bold red] You are about to securely wipe and shred [bold]{file_path}[/bold]. This process is [bold]IRREVERSIBLE[/bold]. Proceed? (y/N): ")
    if confirm.lower() != 'y':
        console.print("[yellow]Shredding aborted by user.[/yellow]")
        return

    shredder = FileShredder(file_path)
    with console.status("[bold red]Shredding file securely (DoD 5220.22-M)...", spinner="dots"):
        res = shredder.shred(passes=passes)

    if res["success"]:
        console.print(Panel(f"[bold green]✔ File Wiped Successfully![/bold green]\n[bold]Wiped File:[/bold] {res['file_wiped']}\n[bold]Shred passes completed:[/bold] {res['passes_completed']} passes\n[bold]Bytes Overwritten:[/bold] {res['bytes_shredded']} bytes", border_style="green"))
    else:
        console.print(f"[bold red]Shredding failed:[/bold red] {res['error']}")

def run_domain_recon(domain, check_whois=False):
    auditor = NetworkAuditor(domain)
    console.print(Panel(f"[bold green]Starting Domain Audit & Recon[/bold green]\n[bold]Domain Target:[/bold] {auditor.domain}", border_style="purple"))

    # SSL Audit
    with console.status("[bold cyan]Analyzing SSL/TLS Certificate...", spinner="dots"):
        ssl_res = auditor.audit_ssl()
    
    if ssl_res["success"]:
        ssl_table = Table(title="🔒 SSL/TLS Audit Summary", border_style="green")
        ssl_table.add_column("Field", style="bold cyan")
        ssl_table.add_column("Value")
        ssl_table.add_row("Status", ssl_res["status"])
        ssl_table.add_row("Subject DN", ssl_res["subject"])
        ssl_table.add_row("Certificate Issuer", ssl_res["issuer"])
        ssl_table.add_row("Expiry Date", ssl_res["expires_on"])
        ssl_table.add_row("Days Remaining", f"{ssl_res['days_remaining']} days")
        console.print(ssl_table)
    else:
        console.print(f"[bold red]❌ SSL Handshake audit failed:[/bold red] {ssl_res['error']}")

    # DNS Records
    with console.status("[bold cyan]Fetching DNS records...", spinner="dots"):
        dns_res = auditor.get_dns_records()
        
    dns_table = Table(title="🌐 Active DNS Records", border_style="purple")
    dns_table.add_column("Type", style="bold magenta")
    dns_table.add_column("Value")
    for r_type, r_list in dns_res.items():
        if r_list:
            for val in r_list:
                dns_table.add_row(r_type, val)
        else:
            dns_table.add_row(r_type, "[dim]No record found[/dim]")
    console.print(dns_table)

    # WHOIS Database
    if check_whois:
        with console.status("[bold cyan]Querying global WHOIS registries on port 43...", spinner="dots"):
            whois_data = auditor.get_whois()
        
        console.print(Panel(whois_data[:1500] + "\n\n... (WHOIS Output truncated for readability)", title="📋 Raw WHOIS Registry Data", border_style="cyan"))

def run_crypto_tools(args_dict):
    toolbox = CryptoToolbox()
    
    if args_dict.get("hash"):
        h = args_dict["hash"]
        console.print(Panel(f"[bold green]Starting Cryptographic Hash Identifier[/bold green]\n[bold]Hash String:[/bold] {h}", border_style="purple"))
        types = toolbox.identify_hash(h)
        table = Table(title="Hash Classification Findings", border_style="purple")
        table.add_column("Matched Hash Algorithm", style="bold green")
        for t in types:
            table.add_row(t)
        console.print(table)
        
    elif args_dict.get("password"):
        p = args_dict["password"]
        console.print(Panel("[bold green]Starting Password Security Audit[/bold green]", border_style="purple"))
        res = toolbox.audit_password(p)
        
        console.print(f"[bold]Security Status:[/bold] {res['status']}")
        console.print(f"[bold]Shannon Entropy:[/bold] {res['entropy']} bits")
        if "estimated_cracking_time" in res:
            console.print(f"[bold]Estimated Brute-force time:[/bold] {res['estimated_cracking_time']}")
            
        reqs = res.get("requirements", {})
        if reqs:
            req_table = Table(title="Password Policy Scorecard", border_style="cyan")
            req_table.add_column("Requirement", style="bold")
            req_table.add_column("Status", justify="center")
            req_table.add_row("Length >= 12 chars", "[green]✔ Passed[/green]" if reqs["length"] else "[red]✘ Failed[/red]")
            req_table.add_row("Contains Lowercase [a-z]", "[green]✔ Passed[/green]" if reqs["lowercase"] else "[red]✘ Failed[/red]")
            req_table.add_row("Contains Uppercase [A-Z]", "[green]✔ Passed[/green]" if reqs["uppercase"] else "[red]✘ Failed[/red]")
            req_table.add_row("Contains Numbers [0-9]", "[green]✔ Passed[/green]" if reqs["numbers"] else "[red]✘ Failed[/red]")
            req_table.add_row("Contains Special Chars", "[green]✔ Passed[/green]" if reqs["special_chars"] else "[red]✘ Failed[/red]")
            console.print(req_table)
            
        if "remediation" in res:
            console.print(f"\n[bold red]💡 RECOMMENDATION:[/bold red] {res['remediation']}")

    elif args_dict.get("b64_encode"):
        console.print(f"[bold]Base64 Encoded Output:[/bold] {toolbox.encode_base64(args_dict['b64_encode'])}")
    elif args_dict.get("b64_decode"):
        console.print(f"[bold]Base64 Decoded Output:[/bold] {toolbox.decode_base64(args_dict['b64_decode'])}")
    elif args_dict.get("hex_encode"):
        console.print(f"[bold]Hex Encoded Output:[/bold] {toolbox.encode_hex(args_dict['hex_encode'])}")
    elif args_dict.get("hex_decode"):
        console.print(f"[bold]Hex Decoded Output:[/bold] {toolbox.decode_hex(args_dict['hex_decode'])}")

def launch_interactive_menu():
    """Launch the interactive terminal TUI menu system."""
    while True:
        console.clear()
        console.print(BANNER)
        
        menu_table = Table(title="⚡ AegisEye Command Menu ⚡", border_style="purple", box=None)
        menu_table.add_column("Option", style="bold magenta", justify="center")
        menu_table.add_column("Security/OSINT Tool Description", style="bold white")
        
        menu_table.add_row("1", "🔍 Image Forensics (ELA Heatmap, EXIF, Steganography)")
        menu_table.add_row("2", "📞 Phone OSINT (Carrier, Country, Timezone)")
        menu_table.add_row("3", "✉️ Email OSINT (MX Record DNS Checker)")
        menu_table.add_row("4", "🗑️ Forensic File Shredder (DoD 5220.22-M Secure Wipe)")
        menu_table.add_row("5", "🌐 Domain Audit & SSL certificate Recon")
        menu_table.add_row("6", "🔑 Password Strength & Entropy Auditor")
        menu_table.add_row("7", "🔏 Cryptographic Hash Identifier")
        menu_table.add_row("8", "🔄 Base64 / Hex Encoder & Decoder")
        menu_table.add_row("9", "❌ Exit Toolkit")
        
        console.print(Panel(menu_table, border_style="purple"))
        
        choice = console.input("[bold yellow]Enter your choice (1-9): [/bold yellow]").strip()
        
        if choice == "1":
            path = console.input("\n[bold cyan]Enter path to image file: [/bold cyan]").strip()
            run_image_forensics(path)
        elif choice == "2":
            num = console.input("\n[bold cyan]Enter phone number (e.g. +91XXXXXXXXXX): [/bold cyan]").strip()
            run_phone_osint(num)
        elif choice == "3":
            email = console.input("\n[bold cyan]Enter email address: [/bold cyan]").strip()
            run_email_osint(email)
        elif choice == "4":
            path = console.input("\n[bold red]Enter path of file to shred: [/bold red]").strip()
            run_file_shred(path)
        elif choice == "5":
            dom = console.input("\n[bold cyan]Enter target domain (e.g. google.com): [/bold cyan]").strip()
            whois_choice = console.input("[bold cyan]Deep WHOIS registry socket query? (y/N): [/bold cyan]").strip().lower()
            run_domain_recon(dom, check_whois=(whois_choice == 'y'))
        elif choice == "6":
            pwd = console.input("\n[bold cyan]Enter password to audit: [/bold cyan]").strip()
            run_crypto_tools({"password": pwd})
        elif choice == "7":
            h = console.input("\n[bold cyan]Enter hash string to identify: [/bold cyan]").strip()
            run_crypto_tools({"hash": h})
        elif choice == "8":
            console.print("\n[bold]1.[/bold] Base64 Encode | [bold]2.[/bold] Base64 Decode | [bold]3.[/bold] Hex Encode | [bold]4.[/bold] Hex Decode")
            sub_choice = console.input("[bold yellow]Choose conversion (1-4): [/bold yellow]").strip()
            txt = console.input("[bold cyan]Enter text to convert: [/bold cyan]").strip()
            if sub_choice == "1":
                run_crypto_tools({"b64_encode": txt})
            elif sub_choice == "2":
                run_crypto_tools({"b64_decode": txt})
            elif sub_choice == "3":
                run_crypto_tools({"hex_encode": txt})
            elif sub_choice == "4":
                run_crypto_tools({"hex_decode": txt})
        elif choice == "9":
            console.print("\n[bold green]Exiting AegisEye Toolkit. Stay Secure![/bold green]")
            sys.exit(0)
        else:
            console.print("[bold red]Invalid option. Please choose between 1 and 9.[/bold red]")
            
        console.input("\n[dim]Press Enter to return to menu...[/dim]")

def main():
    # If no CLI arguments provided, launch the interactive TUI menu
    if len(sys.argv) == 1:
        launch_interactive_menu()
        sys.exit(0)

    # Otherwise, handle normal argparse subcommands
    console.print(BANNER)
    
    parser = argparse.ArgumentParser(description="AegisEye - Advanced OSINT & Digital Forensics Toolkit")
    subparsers = parser.add_subparsers(dest="command", help="Auditing commands")
    
    # Subcommand 1: Image Forensics
    parser_img = subparsers.add_parser("image", help="Perform Digital Image Forensics (ELA, EXIF, Stego)")
    parser_img.add_argument("path", help="Path to the target image file")
    
    # Subcommand 2: OSINT phone/email
    parser_osint = subparsers.add_parser("osint", help="Perform OSINT checks on Phone numbers or Emails")
    parser_osint.add_argument("-p", "--phone", help="Phone number to check (with country code, e.g. +91XXXXXXXXXX)")
    parser_osint.add_argument("-e", "--email", help="Email address to validate")
    
    # Subcommand 3: Secure Shredder
    parser_shred = subparsers.add_parser("shred", help="Securely shred a file using DoD 5220.22-M standards")
    parser_shred.add_argument("path", help="Path to the file to be wiped")
    parser_shred.add_argument("--passes", type=int, default=3, help="Number of overwrite passes (default: 3)")
    
    # Subcommand 4: Domain Auditor
    parser_dom = subparsers.add_parser("domain", help="Audit network records, WHOIS databases, and SSL certificates")
    parser_dom.add_argument("name", help="Target domain (e.g. google.com)")
    parser_dom.add_argument("--whois", action="store_true", help="Enable deep WHOIS socket query")
    
    # Subcommand 5: Crypto & Obfuscation Toolbox
    parser_cry = subparsers.add_parser("crypto", help="Cryptographic tools (Hash Identification, Passwords, Hex/B64)")
    parser_cry.add_argument("--hash", help="Hash value to identify")
    parser_cry.add_argument("--password", help="Verify password strength")
    parser_cry.add_argument("--b64-encode", help="Encode text to Base64")
    parser_cry.add_argument("--b64-decode", help="Decode Base64 text")
    parser_cry.add_argument("--hex-encode", help="Encode text to Hex")
    parser_cry.add_argument("--hex-decode", help="Decode Hex text")

    args = parser.parse_args()
    
    if args.command == "image":
        run_image_forensics(args.path)
    elif args.command == "osint":
        if args.phone:
            run_phone_osint(args.phone)
        elif args.email:
            run_email_osint(args.email)
    elif args.command == "shred":
        run_file_shred(args.path, passes=args.passes)
    elif args.command == "domain":
        run_domain_recon(args.name, check_whois=args.whois)
    elif args.command == "crypto":
        run_crypto_tools(vars(args))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
