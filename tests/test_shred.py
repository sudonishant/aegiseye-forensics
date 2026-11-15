import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.shred import FileShredder


class FileShredderTests(unittest.TestCase):
    def test_overwrite_replaces_original_bytes_instead_of_appending(self):
        original = b"synthetic test data only"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "synthetic.bin"
            target.write_bytes(original)
            bytes_at_unlink = []
            real_remove = os.remove

            def capture_then_remove(path):
                bytes_at_unlink.append(Path(path).read_bytes())
                real_remove(path)

            with patch("core.shred.os.remove", side_effect=capture_then_remove), patch(
                "core.shred.os.urandom", side_effect=lambda size: b"X" * size
            ):
                result = FileShredder(str(target)).shred(passes=1)

            self.assertTrue(result["success"])
            self.assertEqual(bytes_at_unlink, [b"X" * len(original)])
            self.assertFalse(target.exists())

    def test_non_positive_pass_count_does_not_delete_or_modify_file(self):
        original = b"synthetic test data only"
        for passes in (0, -1):
            with self.subTest(passes=passes), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "synthetic.bin"
                target.write_bytes(original)

                result = FileShredder(str(target)).shred(passes=passes)

                self.assertFalse(result["success"])
                self.assertIn("positive integer", result["error"])
                self.assertEqual(target.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
