from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    token: str
    owner_id: int
    data_dir: Path
    ssh_port: int
    dns: str
    awg_go_ref: str
    awg_tools_ref: str

    @classmethod
    def from_env(cls) -> "Settings":
        token = os.environ["TELEGRAM_BOT_TOKEN"].strip()
        owner_id = int(os.environ["OWNER_TELEGRAM_ID"])
        data_dir = Path(os.getenv("DATA_DIR", "/data"))
        return cls(
            token, owner_id, data_dir,
            int(os.getenv("SSH_PORT", "22")),
            os.getenv("AWG_DNS", "1.1.1.1"),
            os.getenv("AWG_GO_REF", "master"),
            os.getenv("AWG_TOOLS_REF", "v3.1.20260812"),
        )
