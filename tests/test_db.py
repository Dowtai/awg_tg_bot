import sqlite3
import tempfile
import unittest
from pathlib import Path

from bot.db import Database


class DatabaseTests(unittest.TestCase):
    def test_creates_multiserver_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "bot.sqlite3")
            with database.connect() as db:
                columns = {row[1] for row in db.execute("PRAGMA table_info(peers)")}
                self.assertIn("server_id", columns)
                self.assertIsNotNone(db.execute("SELECT name FROM sqlite_master WHERE name='servers'").fetchone())

    def test_migrates_single_server_database(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bot.sqlite3"
            db = sqlite3.connect(path)
            db.executescript("""
                CREATE TABLE server(
                  id INTEGER PRIMARY KEY CHECK(id=1), host TEXT, port INTEGER,
                  username TEXT, password_enc BLOB, host_key TEXT, endpoint TEXT, config_json TEXT
                );
                CREATE TABLE peers(
                  id INTEGER PRIMARY KEY, telegram_id INTEGER, name TEXT, address TEXT UNIQUE,
                  public_key TEXT UNIQUE, created_at TEXT, revoked_at TEXT
                );
                INSERT INTO server VALUES(1,'vpn.example',22,'root',X'00',NULL,'203.0.113.1','{}');
                INSERT INTO peers VALUES(7,42,'phone','10.8.1.2','public','2026-01-01',NULL);
            """)
            db.commit()
            db.close()

            database = Database(path)
            with database.connect() as migrated:
                server = migrated.execute("SELECT id,name FROM servers").fetchone()
                peer = migrated.execute("SELECT id,server_id,telegram_id FROM peers").fetchone()
                self.assertEqual((server["id"], server["name"]), (1, "default"))
                self.assertEqual((peer["id"], peer["server_id"], peer["telegram_id"]), (7, 1, 42))


if __name__ == "__main__":
    unittest.main()
