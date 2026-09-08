import base64, json, struct, zlib
import unittest
from bot.vpnurl import admin_payload, encode_vpn_url, guest_payload


class VpnUrlTests(unittest.TestCase):
    def test_qt_compatible_roundtrip(self):
        value = {"hello":"мир","containers":[]}
        url = encode_vpn_url(value)
        encoded = url.removeprefix("vpn://")
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        size = struct.unpack(">I", raw[:4])[0]
        decoded = zlib.decompress(raw[4:])
        self.assertEqual(len(decoded), size)
        self.assertEqual(json.loads(decoded), value)

    def test_guest_payload_keeps_client_port_numeric(self):
        payload = guest_payload("203.0.113.10", "phone", {"port": 443}, "config")
        last_config = json.loads(payload["containers"][0]["awg"]["last_config"])
        self.assertEqual(last_config["port"], 443)
        self.assertIsInstance(last_config["port"], int)

    def test_admin_payload_has_credentials_and_is_not_third_party(self):
        cfg = {
            "port": 54321, "subnet_address": "10.20.30.0", "subnet_cidr": 24,
            "HeaderProtectionKey": "header", "Jc": "6", "Jmin": "10", "Jmax": "50",
            "S1": "76", "S2": "47", "S3": "33", "S4": "12",
            "H1": "1", "H2": "2", "H3": "3", "H4": "4",
            "ContentPaddingAddition": "10-100", "RandomTrailers": "on", "DisableCookies": "on",
            "client_ip": "10.20.30.2/32",
        }
        payload = admin_payload("vpn.example", "root", "secret", 2222, "NL", cfg, "config")
        self.assertEqual(payload["userName"], "root")
        self.assertEqual(payload["password"], "secret")
        self.assertEqual(payload["port"], 2222)
        awg = payload["containers"][0]["awg"]
        self.assertNotIn("isThirdPartyConfig", awg)
        self.assertNotIn("isThirdPartyConfig", json.loads(awg["last_config"]))


if __name__ == "__main__":
    unittest.main()
