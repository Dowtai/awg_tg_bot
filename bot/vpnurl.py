import base64
import json
import struct
import zlib


def qcompress(data: bytes, level: int = 8) -> bytes:
    """Qt qCompress: big-endian original length followed by a zlib stream."""
    return struct.pack(">I", len(data)) + zlib.compress(data, level)


def encode_vpn_url(payload: dict) -> str:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    return "vpn://" + base64.urlsafe_b64encode(qcompress(raw)).rstrip(b"=").decode()


def guest_payload(host: str, name: str, cfg: dict, native: str) -> dict:
    last = dict(cfg)
    last["config"] = native
    last["isThirdPartyConfig"] = True
    return {
        "containers": [{
            "container": "amnezia-awg2",
            "awg": {"isThirdPartyConfig": True, "last_config": json.dumps(last, separators=(",", ":"))},
            "port": str(cfg["port"]), "transport_proto": "udp",
        }],
        "defaultContainer": "amnezia-awg2",
        "description": name,
        "hostName": host,
    }

