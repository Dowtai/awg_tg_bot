import base64, json, struct, zlib
import unittest
from bot.vpnurl import encode_vpn_url, guest_payload


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


if __name__ == "__main__":
    unittest.main()
