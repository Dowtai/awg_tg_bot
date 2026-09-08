from __future__ import annotations
import asyncio
import ipaddress
import json
import logging
from datetime import datetime

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes, ConversationHandler, MessageHandler, filters

from .config import Settings
from .crypto import Vault
from .db import Database
from .remote import Credentials, add_peer, install, remove_peer
from .vpnurl import encode_vpn_url, guest_payload

HOST, USER, PASSWORD = range(3)
log = logging.getLogger(__name__)


class Bot:
    def __init__(self, s: Settings):
        self.s, self.db, self.vault = s, Database(s.data_dir / "bot.sqlite3"), Vault(s.data_dir)
        self.install_lock = asyncio.Lock()
        self.peer_lock = asyncio.Lock()

    def owner(self, update: Update) -> bool:
        return bool(update.effective_user and update.effective_user.id == self.s.owner_id)

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        role = "владелец" if self.owner(update) else "пользователь"
        await update.message.reply_text(f"AWG Bot · роль: {role}\n\n/newkey [имя] — новый ключ\n/help — команды")

    async def help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        text = "/newkey [имя] — создать отдельный vpn:// профиль"
        if self.owner(update):
            text += "\n/server — установить/переустановить сервер\n/allow ID — разрешить пользователя\n/deny ID — удалить пользователя и отозвать его ключи\n/users — список разрешённых"
        await update.message.reply_text(text)

    async def server_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self.owner(update): return ConversationHandler.END
        await update.message.reply_text("IP или домен VPS (можно `host:port`):")
        return HOST

    async def server_host(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        raw = update.message.text.strip()
        host, port = raw, self.s.ssh_port
        if raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit(): host, port = raw.rsplit(":", 1); port = int(port)
        context.user_data.update(host=host, port=port)
        await update.message.reply_text("SSH user:")
        return USER

    async def server_user(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        context.user_data["username"] = update.message.text.strip()
        await update.message.reply_text("SSH пароль (сообщение будет удалено):")
        return PASSWORD

    async def server_password(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        password = update.message.text
        try: await update.message.delete()
        except Exception: pass
        if self.install_lock.locked():
            await update.effective_chat.send_message("Установка уже выполняется.")
            return ConversationHandler.END
        status = await update.effective_chat.send_message("Начинаю установку…")
        state = {"text": "Подготовка", "done": False}
        def progress(text): state["text"] = text
        async def ticker():
            while not state["done"]:
                try: await status.edit_text(f"Установка: {state['text']}\nОбновлено: {datetime.now():%H:%M:%S}")
                except Exception: pass
                await asyncio.sleep(10)
        task = asyncio.create_task(ticker())
        c = Credentials(context.user_data["host"], context.user_data["port"], context.user_data["username"], password)
        try:
            async with self.install_lock:
                cfg, host_key = await install(c, {"subnet": self.s.subnet, "port": self.s.awg_port, "dns": self.s.dns,
                    "go_ref": self.s.awg_go_ref, "tools_ref": self.s.awg_tools_ref}, progress)
                with self.db.connect() as db:
                    db.execute("INSERT OR REPLACE INTO server(id,host,port,username,password_enc,host_key,endpoint,config_json) VALUES(1,?,?,?,?,?,?,?)",
                               (c.host,c.port,c.username,self.vault.encrypt(password),host_key,c.host,json.dumps(cfg)))
                    db.execute("UPDATE peers SET revoked_at=CURRENT_TIMESTAMP WHERE revoked_at IS NULL")
                key = await self.issue_key(update.effective_user.id, "owner")
                await status.edit_text("Установка завершена. Интерфейс awg0 проверен.")
                await update.effective_chat.send_message("Администраторский VPN-профиль (управление сервером остаётся в боте):")
                await update.effective_chat.send_message(key)
        except Exception as e:
            log.exception("installation failed")
            await status.edit_text(f"Ошибка установки:\n{str(e)[-3000:]}")
        finally:
            state["done"] = True; task.cancel()
        return ConversationHandler.END

    async def cancel(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text("Отменено."); return ConversationHandler.END

    async def allow(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self.owner(update): return
        try: uid = int(context.args[0])
        except (IndexError, ValueError): await update.message.reply_text("Использование: /allow 123456789"); return
        with self.db.connect() as db: db.execute("INSERT OR IGNORE INTO allowed_users(telegram_id) VALUES(?)", (uid,))
        await update.message.reply_text(f"Разрешён: {uid}")

    async def deny(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self.owner(update): return
        try: uid = int(context.args[0])
        except (IndexError, ValueError): await update.message.reply_text("Использование: /deny 123456789"); return
        if uid == self.s.owner_id: await update.message.reply_text("Нельзя удалить owner."); return
        server = self.load_server()
        with self.db.connect() as db:
            peers = db.execute("SELECT id,public_key FROM peers WHERE telegram_id=? AND revoked_at IS NULL", (uid,)).fetchall()
        if server:
            c, _ = server
            for p in peers: await remove_peer(c, p["public_key"])
        with self.db.connect() as db:
            db.execute("DELETE FROM allowed_users WHERE telegram_id=?", (uid,))
            db.execute("UPDATE peers SET revoked_at=CURRENT_TIMESTAMP WHERE telegram_id=? AND revoked_at IS NULL", (uid,))
        await update.message.reply_text(f"Удалён {uid}; отозвано ключей: {len(peers)}")

    async def users(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self.owner(update): return
        with self.db.connect() as db: rows = db.execute("SELECT telegram_id,added_at FROM allowed_users ORDER BY telegram_id").fetchall()
        text = [f"Owner: {self.s.owner_id}"] + [f"{r['telegram_id']} · {r['added_at']}" for r in rows]
        await update.message.reply_text("\n".join(text))

    def load_server(self):
        with self.db.connect() as db: r = db.execute("SELECT * FROM server WHERE id=1").fetchone()
        if not r: return None
        return Credentials(r["host"],r["port"],r["username"],self.vault.decrypt(r["password_enc"]),r["host_key"]), (json.loads(r["config_json"]),r["endpoint"])

    async def issue_key(self, uid: int, name: str) -> str:
        async with self.peer_lock:
            return await self._issue_key(uid, name)

    async def _issue_key(self, uid: int, name: str) -> str:
        loaded = self.load_server()
        if not loaded: raise RuntimeError("Сервер ещё не настроен: owner должен выполнить /server")
        c, (cfg, endpoint) = loaded
        network = ipaddress.ip_network(cfg["subnet"])
        with self.db.connect() as db:
            used = {ipaddress.ip_address(r[0]) for r in db.execute("SELECT address FROM peers WHERE revoked_at IS NULL")}
        address = next((str(ip) for ip in list(network.hosts())[1:] if ip not in used), None)
        if not address: raise RuntimeError("В VPN-подсети закончились адреса")
        peer = await add_peer(c, cfg, address, f"tg-{uid}-{name}"[:60])
        native = self.native_config(cfg, endpoint, peer)
        fields = {k: str(cfg[k]) for k in ("Jc","Jmin","Jmax","S1","S2","S3","S4","H1","H2","H3","H4","ContentPaddingAddition","RandomTrailers","DisableCookies")}
        fields.update({"HeaderProtectionKey":cfg["header_key"], "client_ip":address+"/32", "client_priv_key":peer["private"],
                       "client_pub_key":peer["public"], "server_pub_key":cfg["server_public"], "psk_key":peer["psk"],
                       "hostName":endpoint,"port":str(self.s.endpoint_port),"transport_proto":"udp","mtu":"1376",
                       "persistent_keep_alive":"25","allowed_ips":["0.0.0.0/0"]})
        payload = guest_payload(endpoint, name, fields, native)
        with self.db.connect() as db:
            db.execute("INSERT INTO peers(telegram_id,name,address,public_key) VALUES(?,?,?,?)", (uid,name,address,peer["public"]))
        return encode_vpn_url(payload)

    def native_config(self, c, endpoint, p):
        params = "\n".join(f"{k} = {c[k]}" for k in ("Jc","Jmin","Jmax","S1","S2","S3","S4","H1","H2","H3","H4","ContentPaddingAddition","RandomTrailers","DisableCookies"))
        return f"""[Interface]\nPrivateKey = {p['private']}\nAddress = {p['address']}/32\nDNS = {c['dns']}\nMTU = 1376\n{params}\nHeaderProtectionKey = {c['header_key']}\n\n[Peer]\nPublicKey = {c['server_public']}\nPresharedKey = {p['psk']}\nEndpoint = {endpoint}:{self.s.endpoint_port}\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"""

    async def newkey(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        uid = update.effective_user.id
        if not self.db.allowed(uid, self.s.owner_id): await update.message.reply_text("Доступ не разрешён."); return
        name = " ".join(context.args).strip() or f"device-{datetime.now():%Y%m%d-%H%M}"
        msg = await update.message.reply_text("Создаю отдельный peer…")
        try:
            key = await self.issue_key(uid, name)
            await msg.edit_text("Готово. Ключ содержит приватные данные — не пересылайте его.")
            await update.message.reply_text(key)
        except Exception as e:
            log.exception("key issue failed"); await msg.edit_text(f"Ошибка: {e}")


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    s = Settings.from_env(); bot = Bot(s); app = Application.builder().token(s.token).build()
    app.add_handler(ConversationHandler(entry_points=[CommandHandler("server", bot.server_start)],
        states={HOST:[MessageHandler(filters.TEXT & ~filters.COMMAND,bot.server_host)], USER:[MessageHandler(filters.TEXT & ~filters.COMMAND,bot.server_user)], PASSWORD:[MessageHandler(filters.TEXT & ~filters.COMMAND,bot.server_password)]},
        fallbacks=[CommandHandler("cancel",bot.cancel)]))
    for command, fn in (("start",bot.start),("help",bot.help),("allow",bot.allow),("deny",bot.deny),("users",bot.users),("newkey",bot.newkey)):
        app.add_handler(CommandHandler(command,fn))
    app.run_polling(allowed_updates=Update.ALL_TYPES)
