from __future__ import annotations
import asyncio
import ipaddress
import json
import logging
import socket
from datetime import datetime

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes, ConversationHandler, MessageHandler, filters

from .config import Settings
from .crypto import Vault
from .db import Database
from .remote import Credentials, add_peer, delete_deployment, install, remove_peer
from .vpnurl import encode_vpn_url, guest_payload

SERVER_NAME, HOST, USER, PASSWORD = range(4)
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
        await update.message.reply_text(f"AWG Bot · роль: {role}\n\n/newkey [имя] — новый ключ\n/servers — серверы\n/help — команды")

    async def help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        text = "/newkey [имя] — выбрать сервер и создать vpn:// профиль\n/servers — список серверов"
        if self.owner(update):
            text += "\n/server — добавить сервер\n/delserver — удалить сервер\n/cancel — прервать настройку\n/allow ID — разрешить пользователя\n/deny ID — удалить пользователя и отозвать его ключи\n/users — список разрешённых"
        await update.message.reply_text(text)

    async def server_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self.owner(update): return ConversationHandler.END
        for key in ("server_name", "host", "port", "username"):
            context.user_data.pop(key, None)
        await update.message.reply_text("Название сервера (например, Netherlands):")
        return SERVER_NAME

    async def server_name(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        name = update.message.text.strip()
        if not name or len(name) > 40:
            await update.message.reply_text("Название должно содержать от 1 до 40 символов:")
            return SERVER_NAME
        with self.db.connect() as db:
            exists = db.execute("SELECT 1 FROM servers WHERE name=? COLLATE NOCASE", (name,)).fetchone()
        if exists:
            await update.message.reply_text("Сервер с таким названием уже существует. Введите другое:")
            return SERVER_NAME
        context.user_data["server_name"] = name
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
                cfg, host_key = await install(c, {"dns": self.s.dns, "go_ref": self.s.awg_go_ref,
                    "tools_ref": self.s.awg_tools_ref}, progress)
                endpoint_ip = await asyncio.to_thread(socket.gethostbyname, c.host)
                with self.db.connect() as db:
                    cursor = db.execute("INSERT INTO servers(name,host,port,username,password_enc,host_key,endpoint,config_json) VALUES(?,?,?,?,?,?,?,?)",
                               (context.user_data["server_name"],c.host,c.port,c.username,self.vault.encrypt(password),host_key,endpoint_ip,json.dumps(cfg)))
                    server_id = cursor.lastrowid
                key = await self.issue_key(update.effective_user.id, "owner", server_id)
                await status.edit_text(f"Установка завершена. Сервер: {context.user_data['server_name']}\nUDP-порт: {cfg['port']}\nПодсеть: {cfg['subnet']}")
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
        with self.db.connect() as db:
            peers = db.execute("SELECT id,server_id,public_key FROM peers WHERE telegram_id=? AND revoked_at IS NULL", (uid,)).fetchall()
        for p in peers:
            loaded = self.load_server(p["server_id"])
            if loaded:
                c, (cfg, _) = loaded
                await remove_peer(c, cfg, p["public_key"])
        with self.db.connect() as db:
            db.execute("DELETE FROM allowed_users WHERE telegram_id=?", (uid,))
            db.execute("UPDATE peers SET revoked_at=CURRENT_TIMESTAMP WHERE telegram_id=? AND revoked_at IS NULL", (uid,))
        await update.message.reply_text(f"Удалён {uid}; отозвано ключей: {len(peers)}")

    async def users(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self.owner(update): return
        with self.db.connect() as db: rows = db.execute("SELECT telegram_id,added_at FROM allowed_users ORDER BY telegram_id").fetchall()
        text = [f"Owner: {self.s.owner_id}"] + [f"{r['telegram_id']} · {r['added_at']}" for r in rows]
        await update.message.reply_text("\n".join(text))

    async def servers(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self.db.allowed(update.effective_user.id, self.s.owner_id):
            await update.message.reply_text("Доступ не разрешён.")
            return
        with self.db.connect() as db:
            rows = db.execute("SELECT id,name,host,config_json FROM servers ORDER BY name COLLATE NOCASE").fetchall()
        if not rows:
            await update.message.reply_text("Серверов пока нет. Owner должен выполнить /server.")
            return
        lines = []
        for row in rows:
            cfg = json.loads(row["config_json"])
            lines.append(f"{row['name']} · {row['host']} · UDP {cfg['port']} · {cfg['subnet']}")
        await update.message.reply_text("\n".join(lines))

    async def delserver(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self.owner(update):
            return
        with self.db.connect() as db:
            servers = db.execute("SELECT id,name FROM servers ORDER BY name COLLATE NOCASE").fetchall()
        if not servers:
            await update.message.reply_text("Серверов нет.")
            return
        keyboard = [[InlineKeyboardButton(row["name"], callback_data=f"delserver:{row['id']}")] for row in servers]
        await update.message.reply_text("Какой сервер удалить?", reply_markup=InlineKeyboardMarkup(keyboard))

    async def delserver_selected(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        if query.from_user.id != self.s.owner_id:
            await query.edit_message_text("Операция доступна только owner.")
            return
        server_id = int(query.data.split(":", 1)[1])
        with self.db.connect() as db:
            server = db.execute("SELECT name FROM servers WHERE id=?", (server_id,)).fetchone()
        if not server:
            await query.edit_message_text("Сервер уже удалён.")
            return
        keyboard = [[
            InlineKeyboardButton("Удалить безвозвратно", callback_data=f"confirmdel:{server_id}"),
            InlineKeyboardButton("Отмена", callback_data="canceldel"),
        ]]
        await query.edit_message_text(
            f"Удалить сервер «{server['name']}», его контейнер на VPS и все выданные ключи?",
            reply_markup=InlineKeyboardMarkup(keyboard),
        )

    async def delserver_confirmed(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        if query.from_user.id != self.s.owner_id:
            await query.edit_message_text("Операция доступна только owner.")
            return
        server_id = int(query.data.split(":", 1)[1])
        with self.db.connect() as db:
            row = db.execute("SELECT name FROM servers WHERE id=?", (server_id,)).fetchone()
        loaded = self.load_server(server_id)
        if not row or not loaded:
            await query.edit_message_text("Сервер уже удалён.")
            return
        await query.edit_message_text(f"Удаляю сервер «{row['name']}»…")
        try:
            credentials, (cfg, _) = loaded
            await delete_deployment(credentials, cfg)
            with self.db.connect() as db:
                db.execute("DELETE FROM servers WHERE id=?", (server_id,))
            await query.edit_message_text(f"Сервер «{row['name']}» и связанные ключи удалены.")
        except Exception as error:
            log.exception("server deletion failed")
            await query.edit_message_text(f"Не удалось удалить сервер: {error}")

    async def delserver_cancelled(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        await query.edit_message_text("Удаление отменено.")

    def load_server(self, server_id: int):
        with self.db.connect() as db: r = db.execute("SELECT * FROM servers WHERE id=?", (server_id,)).fetchone()
        if not r: return None
        endpoint = r["endpoint"]
        try:
            ipaddress.ip_address(endpoint)
        except ValueError:
            endpoint = socket.gethostbyname(endpoint)
            with self.db.connect() as db:
                db.execute("UPDATE servers SET endpoint=? WHERE id=?", (endpoint, server_id))
        return Credentials(r["host"],r["port"],r["username"],self.vault.decrypt(r["password_enc"]),r["host_key"]), (json.loads(r["config_json"]),endpoint)

    async def issue_key(self, uid: int, name: str, server_id: int) -> str:
        async with self.peer_lock:
            return await self._issue_key(uid, name, server_id)

    async def _issue_key(self, uid: int, name: str, server_id: int) -> str:
        loaded = self.load_server(server_id)
        if not loaded: raise RuntimeError("Выбранный сервер не найден")
        c, (cfg, endpoint) = loaded
        network = ipaddress.ip_network(cfg["subnet"])
        with self.db.connect() as db:
            used = {ipaddress.ip_address(r[0]) for r in db.execute("SELECT address FROM peers WHERE server_id=? AND revoked_at IS NULL", (server_id,))}
        address = next((str(ip) for ip in list(network.hosts())[1:] if ip not in used), None)
        if not address: raise RuntimeError("В VPN-подсети закончились адреса")
        peer = await add_peer(c, cfg, address, f"tg-{uid}-{name}"[:60])
        native = self.native_config(cfg, endpoint, peer)
        fields = {k: str(cfg[k]) for k in ("Jc","Jmin","Jmax","S1","S2","S3","S4","H1","H2","H3","H4","ContentPaddingAddition","RandomTrailers","DisableCookies")}
        fields.update({"HeaderProtectionKey":cfg["header_key"], "client_ip":address+"/32", "client_priv_key":peer["private"],
                       "client_pub_key":peer["public"], "server_pub_key":cfg["server_public"], "psk_key":peer["psk"],
                       "hostName":endpoint,"port":int(cfg["port"]),"transport_proto":"udp","mtu":"1376",
                       "persistent_keep_alive":"25","allowed_ips":["0.0.0.0/0"]})
        payload = guest_payload(endpoint, name, fields, native)
        with self.db.connect() as db:
            db.execute("INSERT INTO peers(server_id,telegram_id,name,address,public_key) VALUES(?,?,?,?,?)", (server_id,uid,name,address,peer["public"]))
        return encode_vpn_url(payload)

    def native_config(self, c, endpoint, p):
        params = "\n".join(f"{k} = {c[k]}" for k in ("Jc","Jmin","Jmax","S1","S2","S3","S4","H1","H2","H3","H4","ContentPaddingAddition","RandomTrailers","DisableCookies"))
        return f"""[Interface]\nPrivateKey = {p['private']}\nAddress = {p['address']}/32\nDNS = {c['dns']}\nMTU = 1376\n{params}\nHeaderProtectionKey = {c['header_key']}\n\n[Peer]\nPublicKey = {c['server_public']}\nPresharedKey = {p['psk']}\nEndpoint = {endpoint}:{c['port']}\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"""

    async def newkey(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        uid = update.effective_user.id
        if not self.db.allowed(uid, self.s.owner_id): await update.message.reply_text("Доступ не разрешён."); return
        name = " ".join(context.args).strip() or f"device-{datetime.now():%Y%m%d-%H%M}"
        with self.db.connect() as db:
            servers = db.execute("SELECT id,name FROM servers ORDER BY name COLLATE NOCASE").fetchall()
        if not servers:
            await update.message.reply_text("Серверов пока нет. Owner должен выполнить /server.")
            return
        keyboard = [[InlineKeyboardButton(row["name"], callback_data=f"newkey:{row['id']}")] for row in servers]
        message = await update.message.reply_text("Выберите сервер:", reply_markup=InlineKeyboardMarkup(keyboard))
        context.user_data.setdefault("pending_keys", {})[message.message_id] = name

    async def newkey_server(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        uid = query.from_user.id
        if not self.db.allowed(uid, self.s.owner_id):
            await query.edit_message_text("Доступ не разрешён.")
            return
        try:
            server_id = int(query.data.split(":", 1)[1])
        except (ValueError, IndexError):
            await query.edit_message_text("Некорректный сервер.")
            return
        pending = context.user_data.setdefault("pending_keys", {})
        name = pending.pop(query.message.message_id, f"device-{datetime.now():%Y%m%d-%H%M}")
        await query.edit_message_text("Создаю отдельный peer…")
        try:
            key = await self.issue_key(uid, name, server_id)
            await query.edit_message_text("Готово. Ключ содержит приватные данные — не пересылайте его.")
            await query.message.reply_text(key)
        except Exception as e:
            log.exception("key issue failed"); await query.edit_message_text(f"Ошибка: {e}")


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    s = Settings.from_env(); bot = Bot(s); app = Application.builder().token(s.token).build()
    app.add_handler(ConversationHandler(entry_points=[CommandHandler("server", bot.server_start)],
        states={SERVER_NAME:[MessageHandler(filters.TEXT & ~filters.COMMAND,bot.server_name)], HOST:[MessageHandler(filters.TEXT & ~filters.COMMAND,bot.server_host)], USER:[MessageHandler(filters.TEXT & ~filters.COMMAND,bot.server_user)], PASSWORD:[MessageHandler(filters.TEXT & ~filters.COMMAND,bot.server_password)]},
        fallbacks=[CommandHandler("cancel",bot.cancel)], allow_reentry=True))
    app.add_handler(CallbackQueryHandler(bot.newkey_server, pattern=r"^newkey:\d+$"))
    app.add_handler(CallbackQueryHandler(bot.delserver_selected, pattern=r"^delserver:\d+$"))
    app.add_handler(CallbackQueryHandler(bot.delserver_confirmed, pattern=r"^confirmdel:\d+$"))
    app.add_handler(CallbackQueryHandler(bot.delserver_cancelled, pattern=r"^canceldel$"))
    for command, fn in (("start",bot.start),("help",bot.help),("allow",bot.allow),("deny",bot.deny),("users",bot.users),("servers",bot.servers),("delserver",bot.delserver),("newkey",bot.newkey)):
        app.add_handler(CommandHandler(command,fn))
    app.run_polling(allowed_updates=Update.ALL_TYPES)
