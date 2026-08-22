import json
import tempfile
import unittest
from pathlib import Path

from core.email_threat import EmailThreatAnalyzer
from core.email_reporter import EmailThreatReporter


SAMPLE_EMAIL = """From: Finance Team <billing@trusted.example>
Reply-To: payout@xn--paypa1-9za.example
Return-Path: <mailer@relay.example>
To: analyst@example.org
Subject: URGENT action required: verify payment account
Date: Wed, 20 Aug 2026 10:20:00 +0000
Message-ID: <abc123@relay.example>
Received: from edge.example (203.0.113.10) by mx.example.org;
Received: from suspicious.example (198.51.100.22) by edge.example;
Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=relay.example; dkim=fail header.d=trusted.example; dmarc=fail header.from=trusted.example
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="demo"

--demo
Content-Type: text/plain; charset="utf-8"

Please verify your account immediately at https://bit.ly/urgent-check and confirm payment.
--demo
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.xlsm"

fake attachment bytes
--demo--
"""


class EmailThreatTests(unittest.TestCase):
    def test_analyzer_extracts_risk_signals(self):
        result = EmailThreatAnalyzer(SAMPLE_EMAIL).analyze()
        self.assertEqual(result["authentication"]["spf"], "fail")
        self.assertEqual(result["relay"]["earliest_reliable_ip"], "198.51.100.22")
        self.assertEqual(result["risk"]["level"], "high")
        codes = {finding["code"] for finding in result["findings"]}
        self.assertIn("reply_to_mismatch", codes)
        self.assertIn("shortened_url", codes)
        self.assertIn("suspicious_attachment", codes)
        self.assertEqual(len(result["indicators"]["attachments"]), 1)

    def test_report_is_portable_html(self):
        result = EmailThreatAnalyzer(SAMPLE_EMAIL).analyze()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "report.html"
            path = EmailThreatReporter("sample.eml").generate(result, str(target))
            content = Path(path).read_text(encoding="utf-8")
            self.assertIn("AegisEye Email Threat Report", content)
            self.assertIn(result["evidence"]["raw_email_sha256"], content)
            self.assertIn("Reply-To domain differs", content)

    def test_result_is_json_serializable(self):
        result = EmailThreatAnalyzer(SAMPLE_EMAIL).analyze()
        encoded = json.dumps(result)
        self.assertIn("origin_candidates", encoded)


if __name__ == "__main__":
    unittest.main()
