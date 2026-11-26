import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from mobile.validate_android_v2rayng import read_safe_json, validate_v2rayng_rules


MOBILE = Path(__file__).resolve().parent / "mobile"
RULE_FILE = MOBILE / "android-v2rayng-claude-routing.json"
PRETTY_FILE = MOBILE / "android-v2rayng-claude-routing.pretty.json"
QR_FILE = MOBILE / "android-v2rayng-claude-routing-qr.png"
# Changing the rule set means regenerating the QR code and updating both digests.
RULE_FILE_SHA256 = "4f365b5e7c34dea8af81ee8a5a0051cec1b677d8edfc48f98fb5d856fdf16adf"
QR_FILE_SHA256 = "6182555efd36d2cb02355f5b7f31fe0624f4abe9c21151cb99104e241777f978"
# Byte-mode capacity of the largest single QR code (version 40, level L).
QR_BYTE_CAPACITY = 2953


class AndroidV2rayNGTests(unittest.TestCase):
    def setUp(self):
        self.rules = read_safe_json(RULE_FILE)

    def test_bundled_minified_and_pretty_rules_validate(self):
        self.assertEqual(validate_v2rayng_rules(self.rules), 13)
        pretty = read_safe_json(PRETTY_FILE)
        self.assertEqual(pretty, self.rules)
        result = subprocess.run(
            [sys.executable, "-B", str(MOBILE / "validate_android_v2rayng.py"), str(RULE_FILE)],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS: 13 rules", result.stdout)
        # The bundled set ends with a domestic direct rule, not a proxy fallback.
        self.assertNotIn("proxy fallback", result.stdout)

    def test_bundled_rule_file_and_qr_code_are_pinned(self):
        data = RULE_FILE.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), RULE_FILE_SHA256)
        self.assertEqual(hashlib.sha256(QR_FILE.read_bytes()).hexdigest(), QR_FILE_SHA256)
        self.assertLessEqual(len(data), QR_BYTE_CAPACITY)

    def run_cli(self, text):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "rules.json"
            path.write_text(text, encoding="utf-8")
            return subprocess.run(
                [sys.executable, "-B", str(MOBILE / "validate_android_v2rayng.py"), str(path)],
                capture_output=True, text=True, timeout=10,
            )

    def test_wrong_field_types_fail_cleanly(self):
        def changed(index, key, value):
            rules = copy.deepcopy(self.rules)
            rules[index][key] = value
            return json.dumps(rules)

        cases = {
            "domain number": changed(6, "domain", 5),
            "domain string": changed(11, "domain", "geosite:cn"),
            "nested domain": changed(6, "domain", [["domain:example.com"]]),
            "ip string": changed(4, "ip", "geoip:private,100.64.0.0/10"),
            "outbound list": changed(6, "outboundTag", ["direct"]),
            "deep nesting": "[" * 200000 + "]" * 200000,
        }
        for label, text in cases.items():
            with self.subTest(case=label):
                result = self.run_cli(text)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertTrue(result.stderr.startswith("FAIL: "), result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_rejects_typo_domain_and_direct_catchall(self):
        bad_typo = copy.deepcopy(self.rules)
        for rule in bad_typo:
            if "domain" in rule and "domain:claudemcpcontent.com" in rule["domain"]:
                rule["domain"].append("domain:claudemcpclient.com")
        with self.assertRaisesRegex(ValueError, "typo domain"):
            validate_v2rayng_rules(bad_typo)

        bad_catchall = copy.deepcopy(self.rules)
        bad_catchall.append({"remarks": "bad", "port": "0-65535", "outboundTag": "direct", "enabled": True})
        with self.assertRaisesRegex(ValueError, "catch-all"):
            validate_v2rayng_rules(bad_catchall)

    def test_rejects_claude_after_cn_direct(self):
        reordered = copy.deepcopy(self.rules)
        claude_idx = next(i for i, r in enumerate(reordered) if "domain:claude.ai" in (r.get("domain") or []))
        cn_idx = next(i for i, r in enumerate(reordered) if "geosite:cn" in (r.get("domain") or []))
        reordered[claude_idx], reordered[cn_idx] = reordered[cn_idx], reordered[claude_idx]
        with self.assertRaisesRegex(ValueError, "precede domestic"):
            validate_v2rayng_rules(reordered)

    def test_mobile_readme_cites_only_public_sources(self):
        text = (MOBILE / "README.md").read_text(encoding="utf-8")
        for marker in ("research-reports", "随包研究资料"):
            with self.subTest(marker=marker):
                self.assertFalse(marker in text, f"mobile/README.md still cites {marker}")


if __name__ == "__main__":
    unittest.main()
