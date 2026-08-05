import re
import subprocess
import phonenumbers
from phonenumbers import carrier, timezone, geocoder

class OSINTAnalyzer:
    def __init__(self):
        pass

    def analyze_phone(self, phone_str):
        """Analyze a phone number for validation, country, carrier, and timezone."""
        try:
            # Parse number (requires international format like +91...)
            if not phone_str.startswith("+"):
                # If no country code, add a warning or try default parsing
                return {"error": "Phone number must start with '+' and contain a country code (e.g. +91XXXXXXXXXX)."}

            number = phonenumbers.parse(phone_str, None)
            
            is_valid = phonenumbers.is_valid_number(number)
            is_possible = phonenumbers.is_possible_number(number)
            num_type = phonenumbers.number_type(number)
            
            # Map type to string
            type_str = "Unknown"
            if num_type == phonenumbers.PhoneNumberType.MOBILE:
                type_str = "Mobile"
            elif num_type == phonenumbers.PhoneNumberType.FIXED_LINE:
                type_str = "Fixed Line"
            elif num_type == phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE:
                type_str = "Fixed Line or Mobile"

            # Get carrier and location details
            country_name = geocoder.description_for_number(number, "en")
            carrier_name = carrier.name_for_number(number, "en")
            timezones = timezone.time_zones_for_number(number)

            return {
                "valid": is_valid,
                "possible": is_possible,
                "type": type_str,
                "country": country_name or "Unknown",
                "carrier": carrier_name or "Unknown / Landline",
                "timezones": list(timezones) if timezones else []
            }

        except Exception as e:
            return {"error": f"Failed to analyze phone number: {str(e)}"}

    def analyze_email(self, email_str):
        """Analyze email validity, extract domain, and verify MX records."""
        # Standard email regex
        email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if not re.match(email_regex, email_str):
            return {"valid_format": False, "error": "Invalid email address format."}

        domain = email_str.split("@")[1]
        mx_records = []
        has_mx = False

        try:
            # Run 'host -t MX' command to find Mail Server Records (reliable on Linux/Kali)
            result = subprocess.run(
                ["host", "-t", "MX", domain],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            output = result.stdout
            if "mail is handled by" in output:
                has_mx = True
                # Parse lines: e.g. "google.com mail is handled by 10 aspmx.l.google.com."
                for line in output.splitlines():
                    match = re.search(r"handled by (\d+) (.+)", line)
                    if match:
                        mx_records.append({
                            "priority": int(match.group(1)),
                            "server": match.group(2).rstrip(".")
                        })
            else:
                has_mx = False

            return {
                "valid_format": True,
                "email": email_str,
                "domain": domain,
                "has_mx_records": has_mx,
                "mx_servers": mx_records
            }

        except Exception as e:
            # Fallback if host command fails (e.g. on Windows)
            return {
                "valid_format": True,
                "email": email_str,
                "domain": domain,
                "has_mx_records": False,
                "note": f"Could not perform MX DNS query: {str(e)}"
            }
