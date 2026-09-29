#!/usr/bin/env python3
"""Unit tests for report.py parsers.

These guard against the failure mode the structured-output switch was meant to
fix: a tool changing its human-readable format and silently breaking the report.
Run with:  python3 -m unittest discover -s tests   (from the project root)
       or:  python3 tests/test_report.py
"""
import json
import os
import sys
import tempfile
import unittest

# Import report.py from the parent directory regardless of CWD.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import report  # noqa: E402


NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
 <host>
  <ports>
   <port protocol="tcp" portid="22">
     <state state="open"/>
     <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu"/>
   </port>
   <port protocol="tcp" portid="80">
     <state state="open"/>
     <service name="http" product="nginx" version="1.18.0"/>
   </port>
   <port protocol="tcp" portid="443">
     <state state="closed"/>
     <service name="https"/>
   </port>
  </ports>
 </host>
</nmaprun>
"""

NMAP_TXT = """Starting Nmap
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp open  http    nginx 1.18.0
443/tcp closed https
"""

NUCLEI_JSONL = (
    '{"template-id":"tls-version","info":{"name":"TLS","severity":"info"},'
    '"host":"https://x","matched-at":"https://x:443"}\n'
    '{"template-id":"apache-detect","info":{"name":"Apache","severity":"high"},'
    '"matched-at":"http://x/","matcher-name":"apache"}\n'
    'not-json-garbage-line\n'
)

NUCLEI_TXT = (
    "[tls-version] [ssl] [info] https://x:443\n"
    "[apache-detect] [http] [high] http://x/\n"
)

NIKTO_JSON = json.dumps({
    "host": "x",
    "vulnerabilities": [
        {"id": "999", "method": "GET", "url": "/admin/",
         "msg": "Admin login page found"},
        {"id": "1000", "method": "GET", "url": "/",
         "msg": "Missing X-Frame-Options header"},
    ],
})

HEADERS_TXT = """HTTP/1.1 200 OK
Server: nginx/1.18.0
Content-Type: text/html
Connection: keep-alive
"""


def _write(d, name, content):
    with open(os.path.join(d, name), "w") as fh:
        fh.write(content)


class StructuredParsing(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="webenum-test-")
        _write(self.d, "04_nmap.xml", NMAP_XML)
        _write(self.d, "11_nuclei.jsonl", NUCLEI_JSONL)
        _write(self.d, "10_nikto.json", NIKTO_JSON)
        _write(self.d, "05_headers.txt", HEADERS_TXT)

    def test_nmap_xml_only_open_ports(self):
        ports = report.parse_nmap_xml(os.path.join(self.d, "04_nmap.xml"))
        self.assertEqual(len(ports), 2)  # 443 is closed -> excluded
        self.assertEqual(ports[0]["port"], "22")
        self.assertIn("OpenSSH", ports[0]["version"])

    def test_nuclei_jsonl_skips_garbage_and_reads_severity(self):
        f = report.parse_nuclei_jsonl(os.path.join(self.d, "11_nuclei.jsonl"))
        self.assertEqual(len(f), 2)  # garbage line ignored
        sevs = {x["name"]: x["severity"] for x in f}
        self.assertEqual(sevs["apache-detect"], "high")
        self.assertEqual(sevs["tls-version"], "info")

    def test_nikto_json_infers_severity(self):
        f = report.parse_nikto_json(os.path.join(self.d, "10_nikto.json"))
        self.assertEqual(len(f), 2)
        details = {x["detail"]: x["severity"] for x in f}
        # "admin" -> medium, "header"/"missing" -> low
        self.assertEqual(details["Admin login page found /admin/"], "medium")

    def test_parse_results_prefers_structured_and_counts(self):
        data = report.parse_results(self.d)
        c = data["counts"]
        self.assertEqual(c["high"], 1)      # apache
        self.assertEqual(c["medium"], 1)    # nikto admin
        self.assertEqual(len(data["ports"]), 2)
        # findings sorted by severity: highest first
        self.assertEqual(data["findings"][0]["severity"], "high")

    def test_generate_writes_html_and_valid_json(self):
        html_path = report.generate(self.d)
        self.assertTrue(os.path.isfile(html_path))
        json_path = os.path.splitext(html_path)[0] + ".json"
        self.assertTrue(os.path.isfile(json_path))
        with open(json_path) as fh:
            reparsed = json.load(fh)
        self.assertEqual(reparsed["counts"]["high"], 1)
        self.assertEqual(len(reparsed["ports"]), 2)


class TextFallback(unittest.TestCase):
    """When no structured files exist, the text parsers must still work."""

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="webenum-test-")
        _write(self.d, "04_nmap.txt", NMAP_TXT)
        _write(self.d, "11_nuclei.txt", NUCLEI_TXT)

    def test_falls_back_to_text_parsers(self):
        data = report.parse_results(self.d)
        self.assertEqual(len(data["ports"]), 2)  # from text nmap
        names = {f["name"] for f in data["findings"]}
        self.assertIn("apache-detect", names)    # from text nuclei
        self.assertEqual(data["counts"]["high"], 1)


class NiktoSeverity(unittest.TestCase):
    def test_word_boundary_avoids_false_positives(self):
        # "force" must NOT be read as "rce"; a real "RCE" mention must be high.
        self.assertEqual(
            report._nikto_severity("use -c all to force check all dirs"), "info")
        self.assertEqual(
            report._nikto_severity("possible rce via upload"), "high")
        self.assertEqual(
            report._nikto_severity("sql injection in id param"), "high")
        self.assertEqual(
            report._nikto_severity("missing x-frame-options header"), "low")


class HeadersParsing(unittest.TestCase):
    def test_missing_security_headers_flagged(self):
        d = tempfile.mkdtemp(prefix="webenum-test-")
        _write(d, "05_headers.txt", HEADERS_TXT)
        f = report.parse_headers(os.path.join(d, "05_headers.txt"))
        details = " ".join(x["detail"].lower() for x in f)
        self.assertIn("hsts", details)
        self.assertIn("content-security-policy", details)
        # Server header with a version number -> info finding
        self.assertTrue(any(x["severity"] == "info" for x in f))


if __name__ == "__main__":
    unittest.main(verbosity=2)
