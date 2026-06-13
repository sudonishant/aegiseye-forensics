import re
import math
import base64

class CryptoToolbox:
    def __init__(self):
        # Dictionary of common weak passwords
        self.common_passwords = [
            "123456", "password", "123456789", "12345678", "12345", 
            "qwerty", "password123", "admin", "letmein", "welcome",
            "1234567", "computer", "security", "hacking", "ninja"
        ]

    def identify_hash(self, hash_str):
        """Identify potential hashing algorithms based on signature format."""
        hash_str = hash_str.strip()
        length = len(hash_str)
        
        # Regex matches
        is_hex = re.match(r"^[a-fA-F0-9]+$", hash_str)
        
        if is_hex:
            if length == 32:
                return ["MD5", "NTLM", "MD4"]
            elif length == 40:
                return ["SHA-1", "MySQL5"]
            elif length == 56:
                return ["SHA-224"]
            elif length == 64:
                return ["SHA-256", "DNSTXT"]
            elif length == 96:
                return ["SHA-384"]
            elif length == 128:
                return ["SHA-512", "Whirlpool"]
        
        if hash_str.startswith(("$2a$", "$2b$", "$2y$")) and length == 60:
            return ["Bcrypt (Blowfish)"]
        
        if hash_str.startswith("$pbkdf2-sha256$") or hash_str.startswith("$pbkdf2$"):
            return ["PBKDF2-SHA256"]
            
        if hash_str.startswith("$5$") or hash_str.startswith("$sha256$"):
            return ["SHA-256 crypt"]
            
        if hash_str.startswith("$6$") or hash_str.startswith("$sha512$"):
            return ["SHA-512 crypt"]

        return ["Unknown Hash Type"]

    def audit_password(self, password):
        """Audit password strength, compute entropy, and estimate cracking complexity."""
        length = len(password)
        if length == 0:
            return {"score": 0, "status": "Empty", "entropy": 0}

        # 1. Dictionary Check
        if password.lower() in self.common_passwords:
            return {
                "score": 1,
                "status": "Extremely Weak (Common Dictionary Password)",
                "entropy": 0,
                "remediation": "This password is in the top 100 most common passwords. Change it immediately!"
            }

        # 2. Character Pools & Complexity
        has_lower = bool(re.search(r"[a-z]", password))
        has_upper = bool(re.search(r"[A-Z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_special = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))

        pool_size = 0
        if has_lower: pool_size += 26
        if has_upper: pool_size += 26
        if has_digit: pool_size += 10
        if has_special: pool_size += 32

        # 3. Calculate Shannon Entropy (bits)
        # E = L * log2(R)
        entropy = length * math.log2(pool_size) if pool_size > 0 else 0
        
        # 4. Determine Status & Scoring
        score = 0
        status = "Weak"
        
        if entropy < 35:
            score = 1
            status = "Weak (Easily brute-forced)"
        elif entropy < 60:
            score = 3
            status = "Medium (Moderate strength)"
        elif entropy < 80:
            score = 4
            status = "Strong (Secure password)"
        else:
            score = 5
            status = "Very Strong (Highly secure)"

        # 5. Estimate Cracking Time (Assuming 10 billion guesses/sec)
        guesses = 2 ** entropy
        cracking_time_seconds = guesses / 1e10
        
        time_unit = "Seconds"
        time_val = cracking_time_seconds
        if time_val > 60:
            time_val /= 60
            time_unit = "Minutes"
            if time_val > 60:
                time_val /= 60
                time_unit = "Hours"
                if time_val > 24:
                    time_val /= 24
                    time_unit = "Days"
                    if time_val > 365:
                        time_val /= 365
                        time_unit = "Years"
                        if time_val > 1000:
                            time_val /= 1000
                            time_unit = "Millennia"

        return {
            "score": score,
            "status": status,
            "entropy": round(entropy, 2),
            "pool_size": pool_size,
            "estimated_cracking_time": f"{round(time_val, 2)} {time_unit}",
            "requirements": {
                "length": length >= 12,
                "uppercase": has_upper,
                "lowercase": has_lower,
                "numbers": has_digit,
                "special_chars": has_special
            }
        }

    def encode_base64(self, text):
        """Encode plain text to Base64."""
        try:
            return base64.b64encode(text.encode()).decode()
        except Exception as e:
            return f"Encoding error: {str(e)}"

    def decode_base64(self, b64_text):
        """Decode Base64 to plain text."""
        try:
            return base64.b64decode(b64_text.encode()).decode(errors='ignore')
        except Exception as e:
            return f"Decoding error: {str(e)}"

    def encode_hex(self, text):
        """Encode plain text to Hexadecimal."""
        try:
            return text.encode().hex()
        except Exception as e:
            return f"Encoding error: {str(e)}"

    def decode_hex(self, hex_text):
        """Decode Hexadecimal to plain text."""
        try:
            return bytes.fromhex(hex_text.strip()).decode(errors='ignore')
        except Exception as e:
            return f"Decoding error: {str(e)}"
