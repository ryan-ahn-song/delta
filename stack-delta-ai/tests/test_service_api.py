import json
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

from stack_delta.api import FIXTURES, analyze_demo, create_server
from stack_delta.service import AnalysisService
from stack_delta.storage import ReportStore


class ServiceTests(unittest.TestCase):
    def test_demo_scores(self):
        with tempfile.TemporaryDirectory() as temp:
            service = AnalysisService(ReportStore(Path(temp) / "test.db"))
            benign = analyze_demo(service, "benign")
            suspicious = analyze_demo(service, "suspicious")
            injection = analyze_demo(service, "prompt_injection")
            self.assertEqual(benign.final_score, 0)
            self.assertGreaterEqual(suspicious.final_score, 15)
            self.assertEqual(injection.decision, "REVIEW REQUIRED")
            self.assertTrue(injection.document.injection_signals)

    def test_http_health_and_demo(self):
        with tempfile.TemporaryDirectory() as temp:
            server = create_server("127.0.0.1", 0, Path(temp) / "api.db", seed=False)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address
            try:
                with urllib.request.urlopen(f"http://{host}:{port}/api/health", timeout=5) as response:
                    health = json.loads(response.read())
                self.assertEqual(health["status"], "ok")
                request = urllib.request.Request(
                    f"http://{host}:{port}/api/analyze/demo",
                    data=json.dumps({"scenario": "benign"}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    report = json.loads(response.read())
                self.assertEqual(report["decision"], "NO MISMATCH OBSERVED")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()

