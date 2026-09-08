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


def admin_payload(
    host: str,
    username: str,
    password: str,
    ssh_port: int,
    name: str,
    cfg: dict,
    native: str,
) -> dict:
    """Build an importable Self-Hosted Admin profile for AmneziaVPN.

    Unlike a guest profile, it must not be marked as third-party: the official
    client checks the SSH credentials only after that classification step.
    Keeping ``last_config`` makes the first profile immediately usable as a VPN
    connection as well as an administrative server profile.
    """
    last = dict(cfg)
    last["config"] = native
    awg = {
        key: str(cfg[key])
        for key in (
            "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
            "ContentPaddingAddition", "RandomTrailers", "DisableCookies",
        )
    }
    awg.update({
        "HeaderProtectionKey": cfg["HeaderProtectionKey"],
        "port": str(cfg["port"]),
        "transport_proto": "udp",
        "subnet_address": cfg["subnet_address"],
        "subnet_cidr": str(cfg["subnet_cidr"]),
        "last_config": json.dumps(last, separators=(",", ":")),
    })
    return {
        "description": name,
        "hostName": host,
        "userName": username,
        "password": password,
        "port": int(ssh_port),
        "containers": [{"container": "amnezia-awg2", "awg": awg}],
        "defaultContainer": "amnezia-awg2",
    }
