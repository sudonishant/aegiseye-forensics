import ssl
import socket
import datetime
import subprocess
import re

class NetworkAuditor:
    def __init__(self, domain):
        # Strip protocols and paths to get clean domain
        clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        self.domain = clean_domain

    def get_whois(self):
        """Perform raw WHOIS lookup using direct socket connection on port 43 (no third-party library needed)."""
        try:
            # Query IANA first to find the regional register server
            iana_server = "whois.iana.org"
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((iana_server, 43))
            s.send((self.domain + "\r\n").encode())
            
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            s.close()
            
            response_text = response.decode('utf-8', errors='ignore')
            
            # Find the referral server (e.g. "refer: whois.verisign-grs.com")
            referral = re.search(r"refer:\s+(.+)", response_text)
            if not referral:
                # If no referral, try default common registrars or return IANA response
                return response_text[:1000]

            referral_server = referral.group(1).strip()
            
            # Query referral registrar server
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.settimeout(5)
            s2.connect((referral_server, 43))
            s2.send((self.domain + "\r\n").encode())
            
            ref_response = b""
            while True:
                data = s2.recv(4096)
                if not data:
                    break
                ref_response += data
            s2.close()
            
            return ref_response.decode('utf-8', errors='ignore')

        except Exception as e:
            return f"WHOIS Query Failed: {str(e)}"

    def get_dns_records(self):
        """Query standard DNS records (A, MX, TXT, NS) using Kali's host tool."""
        records = {}
        types = ["A", "MX", "TXT", "NS"]
        
        for t in types:
            try:
                result = subprocess.run(
                    ["host", "-t", t, self.domain],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                output = result.stdout.strip()
                if "has no" not in output and "not found" not in output and output:
                    records[t] = output.splitlines()
                else:
                    records[t] = []
            except Exception:
                records[t] = []
                
        return records

    def audit_ssl(self):
        """Fetch and audit SSL/TLS certificate of the domain."""
        context = ssl.create_default_context()
        try:
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
            
            # Parse Dates
            not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            remaining = not_after - datetime.datetime.utcnow()

            # Issuer details
            issuer = ", ".join([item[0][1] for item in cert['issuer']])
            subject = ", ".join([item[0][1] for item in cert['subject']])

            status = "Valid"
            severity = "Low"
            if remaining.days < 0:
                status = "Expired"
                severity = "Critical"
            elif remaining.days < 30:
                status = f"Expiring Soon ({remaining.days} days left)"
                severity = "High"

            return {
                "success": True,
                "status": status,
                "severity": severity,
                "subject": subject,
                "issuer": issuer,
                "expires_on": cert['notAfter'],
                "days_remaining": remaining.days
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"SSL Handshake/Connection failed: {str(e)}",
                "severity": "Medium"
            }
