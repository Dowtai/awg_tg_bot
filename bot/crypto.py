from pathlib import Path
from cryptography.fernet import Fernet


class Vault:
    def __init__(self, data_dir: Path):
        key_path = data_dir / "master.key"
        if not key_path.exists():
            key_path.write_bytes(Fernet.generate_key())
            key_path.chmod(0o600)
        self.fernet = Fernet(key_path.read_bytes().strip())

    def encrypt(self, value: str) -> bytes:
        return self.fernet.encrypt(value.encode())

    def decrypt(self, value: bytes) -> str:
        return self.fernet.decrypt(value).decode()

