import sqlite3
from contextlib import contextmanager
from pathlib import Path


class Database:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS allowed_users(
                  telegram_id INTEGER PRIMARY KEY, added_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS server(
                  id INTEGER PRIMARY KEY CHECK(id=1), host TEXT NOT NULL, port INTEGER NOT NULL,
                  username TEXT NOT NULL, password_enc BLOB NOT NULL, host_key TEXT,
                  endpoint TEXT NOT NULL, config_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS peers(
                  id INTEGER PRIMARY KEY AUTOINCREMENT, telegram_id INTEGER NOT NULL,
                  name TEXT NOT NULL, address TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL UNIQUE,
                  created_at TEXT DEFAULT CURRENT_TIMESTAMP, revoked_at TEXT
                );
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        finally:
            db.close()

    def allowed(self, telegram_id: int, owner_id: int) -> bool:
        if telegram_id == owner_id:
            return True
        with self.connect() as db:
            return db.execute("SELECT 1 FROM allowed_users WHERE telegram_id=?", (telegram_id,)).fetchone() is not None

