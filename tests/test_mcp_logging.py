import importlib.util
import io
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


def load_mcp_module_with_stubbed_core():
    symbols = {
        "core.metadata": ["MetadataScanner"],
        "core.ela": ["ELAScanner"],
        "core.stego": ["StegoScanner"],
        "core.channels": ["ChannelScanner"],
        "core.osint": ["OSINTAnalyzer"],
        "core.network": ["NetworkAuditor"],
        "core.crypto": ["CryptoToolbox"],
        "core.reporter": ["ForensicReporter"],
        "core.email_threat": ["EmailThreatAnalyzer"],
        "core.email_reporter": ["EmailThreatReporter"],
    }
    stubs = {}
    for name, classes in symbols.items():
        stub = types.ModuleType(name)
        for class_name in classes:
            setattr(stub, class_name, type(class_name, (), {}))
        stubs[name] = stub

    source = Path(__file__).resolve().parents[1] / "aegiseye_mcp.py"
    spec = importlib.util.spec_from_file_location("aegiseye_mcp_test_instance", source)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, stubs):
        spec.loader.exec_module(module)
    return module


class McpLoggingTests(unittest.TestCase):
    def test_tool_arguments_are_not_written_to_stderr(self):
        module = load_mcp_module_with_stubbed_core()
        module.TOOLS = {
            "crypto_hash_analysis": {"handler": lambda _arguments: {"status": "ok"}}
        }
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "crypto_hash_analysis",
                "arguments": {
                    "password": "synthetic-password-only",
                    "raw_email": "Subject: synthetic fixture only",
                },
            },
        }
        stderr = io.StringIO()
        stdout = io.StringIO()

        with patch("sys.stdin", io.StringIO(json.dumps(request) + "\n")), patch(
            "sys.stderr", stderr
        ), patch("sys.stdout", stdout):
            module.main()

        self.assertIn("Calling tool: crypto_hash_analysis", stderr.getvalue())
        self.assertNotIn("synthetic-password-only", stderr.getvalue())
        self.assertNotIn("Subject: synthetic fixture only", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
