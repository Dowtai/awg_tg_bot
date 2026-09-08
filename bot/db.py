import sqlite3
from contextlib import contextmanager
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS allowed_users(
  telegram_id INTEGER PRIMARY KEY,
  added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS servers(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE COLLATE NOCASE,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  username TEXT NOT NULL,
  password_enc BLOB NOT NULL,
  host_key TEXT,
  endpoint TEXT NOT NULL,
  config_json TEXT NOT NULL,
  admin_profile_issued_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS peers(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  telegram_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  address TEXT NOT NULL,
  public_key TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at TEXT,
  UNIQUE(server_id, address),
  UNIQUE(server_id, public_key)
);
CREATE INDEX IF NOT EXISTS peers_user_active_idx
  ON peers(telegram_id, revoked_at);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _initialize(self):
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "server" in tables:
                self._migrate_single_server(db)
            elif "peers" in tables and "server_id" not in {
                r[1] for r in db.execute("PRAGMA table_info(peers)")
            }:
                db.execute("ALTER TABLE peers RENAME TO peers_legacy")
            db.executescript(SCHEMA)
            server_columns = {r[1] for r in db.execute("PRAGMA table_info(servers)")}
            if "admin_profile_issued_at" not in server_columns:
                db.execute("ALTER TABLE servers ADD COLUMN admin_profile_issued_at TEXT")
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "peers_legacy" in tables:
                server = db.execute("SELECT id FROM servers ORDER BY id LIMIT 1").fetchone()
                if server:
                    db.execute("""
                        INSERT OR IGNORE INTO peers(
                          id,server_id,telegram_id,name,address,public_key,created_at,revoked_at
                        )
                        SELECT id,?,telegram_id,name,address,public_key,created_at,revoked_at
                        FROM peers_legacy
                    """, (server[0],))
                db.execute("DROP TABLE peers_legacy")

    @staticmethod
    def _migrate_single_server(db: sqlite3.Connection):
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "peers" in tables:
            db.execute("ALTER TABLE peers RENAME TO peers_legacy")
        db.execute("ALTER TABLE server RENAME TO server_legacy")
        db.executescript(SCHEMA)
        db.execute("""
            INSERT INTO servers(id,name,host,port,username,password_enc,host_key,endpoint,config_json)
            SELECT id,'default',host,port,username,password_enc,host_key,endpoint,config_json
            FROM server_legacy
        """)
        db.execute("DROP TABLE server_legacy")

    def allowed(self, telegram_id: int, owner_id: int) -> bool:
        if telegram_id == owner_id:
            return True
        with self.connect() as db:
            return db.execute(
                "SELECT 1 FROM allowed_users WHERE telegram_id=?", (telegram_id,)
            ).fetchone() is not None
