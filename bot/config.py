from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    token: str
    owner_id: int
    data_dir: Path
    ssh_port: int
    awg_port: int
    endpoint_port: int
    subnet: str
    dns: str
    awg_go_ref: str
    awg_tools_ref: str

    @classmethod
    def from_env(cls) -> "Settings":
        token = os.environ["TELEGRAM_BOT_TOKEN"].strip()
        owner_id = int(os.environ["OWNER_TELEGRAM_ID"])
        data_dir = Path(os.getenv("DATA_DIR", "/data"))
        subnet = os.getenv("AWG_SUBNET", "10.8.1.0/24")
        ipaddress.ip_network(subnet, strict=True)
        return cls(
            token, owner_id, data_dir,
            int(os.getenv("SSH_PORT", "22")),
            int(os.getenv("AWG_PORT", "443")),
            int(os.getenv("AWG_ENDPOINT_PORT", os.getenv("AWG_PORT", "443"))),
            subnet, os.getenv("AWG_DNS", "1.1.1.1"),
            os.getenv("AWG_GO_REF", "master"),
            os.getenv("AWG_TOOLS_REF", "master"),
        )

