import html
import tempfile
import unittest
from pathlib import Path

from core.reporter import ForensicReporter


class ForensicReporterTests(unittest.TestCase):
    def test_untrusted_report_values_are_escaped_or_constrained(self):
        payload = '<script>alert("synthetic")</script>'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target_name = root / 'photo"><script>alert("synthetic")</script>.jpg'
            output = root / "report.html"
            data = {
                "file_meta": {"format": payload, "size": payload},
                "hashes": {"md5": payload, "sha1": payload, "sha256": payload},
                "exif": {
                    "exif": {payload: payload},
                    "gps": {
                        "latitude": "1.25",
                        "longitude": "2.5",
                        "map_link": "javascript:alert(1)",
                    },
                },
                "ela": {
                    "success": True,
                    "heatmap_path": str(root / 'heatmap"><script>alert("synthetic")</script>.png'),
                    "quality_tested": 95,
                    "scale_factor_applied": 10.0,
                },
                "channels": {
                    "success": True,
                    "channels": {
                        "red": str(root / "red.png"),
                        "green": str(root / "green.png"),
                        "blue": str(root / "blue.png"),
                    },
                },
            }

            report_path = ForensicReporter(str(target_name)).generate(data, str(output))
            report_html = Path(report_path).read_text(encoding="utf-8")

        self.assertIn(html.escape(payload, quote=True), report_html)
        self.assertNotIn(payload, report_html)
        self.assertNotIn("javascript:alert(1)", report_html)
        self.assertIn("https://www.google.com/maps/search/?api=1&amp;query=1.25,2.5", report_html)
        self.assertIn("%3Cscript%3E", report_html)


if __name__ == "__main__":
    unittest.main()
