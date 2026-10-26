import os
import sys
import unittest
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tools.log_aggregator import (
    JSONLogParser,
    TextLogParser,
    NginxLogParser,
    LogAggregator,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "logs"


class TestLogParserIndependentFixtures(unittest.TestCase):
    def setUp(self):
        self.json_parser = JSONLogParser()
        self.text_parser = TextLogParser()
        self.nginx_parser = NginxLogParser()
        self.aggregator = LogAggregator()

    def test_json_parser_with_independent_fixtures(self):
        fixture_path = FIXTURES_DIR / "json_lines.log"
        self.assertTrue(fixture_path.exists(), f"Missing fixture: {fixture_path}")

        with open(fixture_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        self.assertGreaterEqual(len(lines), 4)

        # Entry 1: info
        e0 = self.json_parser.parse(lines[0])
        self.assertIsNotNone(e0)
        self.assertEqual(e0["format"], "json")
        self.assertEqual(e0["level"], "info")
        self.assertEqual(e0["service"], "auth-service")
        self.assertIn("User login successful", e0["message"])
        self.assertEqual(e0["fields"]["user_id"], 1042)

        # Entry 2: warn
        e1 = self.json_parser.parse(lines[1])
        self.assertIsNotNone(e1)
        self.assertEqual(e1["level"], "warn")
        self.assertEqual(e1["service"], "order-engine")

        # Entry 3: error
        e2 = self.json_parser.parse(lines[2])
        self.assertIsNotNone(e2)
        self.assertEqual(e2["level"], "error")
        self.assertEqual(e2["service"], "settlement")
        self.assertEqual(e2["fields"]["code"], "E_TIMEOUT")

    def test_plain_text_parser_with_independent_fixtures(self):
        fixture_path = FIXTURES_DIR / "plain_text.log"
        self.assertTrue(fixture_path.exists(), f"Missing fixture: {fixture_path}")

        with open(fixture_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        self.assertGreaterEqual(len(lines), 4)

        # Entry 0: INFO
        e0 = self.text_parser.parse(lines[0])
        self.assertIsNotNone(e0)
        self.assertEqual(e0["format"], "text")
        self.assertEqual(e0["level"], "info")
        self.assertEqual(e0["service"], "gateway")
        self.assertIsNotNone(e0["timestamp"])

        # Entry 1: WARN
        e1 = self.text_parser.parse(lines[1])
        self.assertIsNotNone(e1)
        self.assertEqual(e1["level"], "warn")
        self.assertEqual(e1["service"], "risk_eval")

        # Entry 2: ERROR
        e2 = self.text_parser.parse(lines[2])
        self.assertIsNotNone(e2)
        self.assertEqual(e2["level"], "error")
        self.assertEqual(e2["service"], "data_feed")

    def test_nginx_parser_with_independent_fixtures(self):
        fixture_path = FIXTURES_DIR / "nginx_access.log"
        self.assertTrue(fixture_path.exists(), f"Missing fixture: {fixture_path}")

        with open(fixture_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        self.assertEqual(len(lines), 4)

        # Line 0: 200 OK with user_alice
        e0 = self.nginx_parser.parse(lines[0])
        self.assertIsNotNone(e0)
        self.assertEqual(e0["format"], "nginx")
        self.assertEqual(e0["level"], "info")
        self.assertEqual(e0["service"], "nginx")
        self.assertEqual(e0["fields"]["remote_addr"], "192.168.10.50")
        self.assertEqual(e0["fields"]["remote_user"], "user_alice")
        self.assertEqual(e0["fields"]["status"], 200)

        # Line 1: 401 Unauthorized -> warn
        e1 = self.nginx_parser.parse(lines[1])
        self.assertIsNotNone(e1)
        self.assertEqual(e1["level"], "warn")
        self.assertEqual(e1["fields"]["status"], 401)

        # Line 2: 304 Not Modified with dash '-' body bytes
        e2 = self.nginx_parser.parse(lines[2])
        self.assertIsNotNone(e2)
        self.assertEqual(e2["fields"]["status"], 304)
        self.assertEqual(e2["fields"]["remote_user"], "user_bob")

        # Line 3: 500 Internal Error -> error
        e3 = self.nginx_parser.parse(lines[3])
        self.assertIsNotNone(e3)
        self.assertEqual(e3["level"], "error")
        self.assertEqual(e3["fields"]["status"], 500)

    def test_malformed_and_unsupported_lines_do_not_crash(self):
        fixture_path = FIXTURES_DIR / "malformed.log"
        self.assertTrue(fixture_path.exists(), f"Missing fixture: {fixture_path}")

        with open(fixture_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        for line in lines:
            # None of the parsers should raise unhandled exceptions
            res_json = self.json_parser.parse(line)
            res_nginx = self.nginx_parser.parse(line)
            res_text = self.text_parser.parse(line)
            # JSON and Nginx should cleanly reject non-conforming lines
            self.assertIsNone(res_json)
            self.assertIsNone(res_nginx)
            # TextLogParser safely captures raw line without crashing
            self.assertIsNotNone(res_text)

    def test_aggregator_routing_and_priority(self):
        # Ensure Nginx lines are correctly classified as nginx, not text
        nginx_fixture = FIXTURES_DIR / "nginx_access.log"
        count = self.aggregator.process_file(str(nginx_fixture))
        self.assertEqual(count, 4)

        formats = [e.get("format") for e in self.aggregator.entries]
        self.assertEqual(formats, ["nginx", "nginx", "nginx", "nginx"])

        summary = self.aggregator.get_summary()
        self.assertEqual(summary["total_entries"], 4)
        self.assertIn("nginx", summary["by_service"])
        self.assertEqual(summary["by_service"]["nginx"], 4)


if __name__ == "__main__":
    unittest.main()
