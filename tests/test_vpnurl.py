import base64, json, struct, zlib
import unittest
from bot.vpnurl import encode_vpn_url


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


if __name__ == "__main__":
    unittest.main()
