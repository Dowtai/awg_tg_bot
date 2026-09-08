from __future__ import annotations
import asyncio
import base64
import hashlib
import ipaddress
import json
import shlex
import textwrap
import threading
from dataclasses import dataclass
from typing import Callable

import paramiko


REMOTE_DIR = "/opt/awg-bot"
CONTAINER = "awg-bot-server"


@dataclass
class Credentials:
    host: str
    port: int
    username: str
    password: str
    host_key: str | None = None


def fingerprint(key: paramiko.PKey) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


class ExpectedHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected: str | None):
        self.expected = expected
    def missing_host_key(self, client, hostname, key):
        actual = fingerprint(key)
        if self.expected and actual != self.expected:
            raise paramiko.SSHException(f"SSH host key changed: expected {self.expected}, got {actual}")
        client._host_keys.add(hostname, key.get_name(), key)


def connect(c: Credentials) -> tuple[paramiko.SSHClient, str]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(ExpectedHostKeyPolicy(c.host_key))
    client.connect(c.host, port=c.port, username=c.username, password=c.password,
                   look_for_keys=False, allow_agent=False, timeout=20, banner_timeout=20)
    transport = client.get_transport()
    assert transport is not None
    return client, fingerprint(transport.get_remote_server_key())


def run(client: paramiko.SSHClient, command: str, *, stdin: str | None = None, timeout=1800) -> str:
    inp, out, err = client.exec_command(command, timeout=timeout)
    if stdin is not None:
        inp.write(stdin)
        inp.channel.shutdown_write()
    stdout, stderr = out.read().decode(errors="replace"), err.read().decode(errors="replace")
    code = out.channel.recv_exit_status()
    if code:
        raise RuntimeError((stderr or stdout or f"command exited {code}").strip()[-3000:])
    return stdout.strip()


def sudo_run(client: paramiko.SSHClient, password: str, script: str, timeout=1800) -> str:
    return run(client, "sudo -S -p '' sh -s", stdin=password + "\n" + script + "\n", timeout=timeout)


def _random_params(client: paramiko.SSHClient, password: str) -> dict:
    keys = sudo_run(client, password, "docker run --rm alpine sh -c 'apk add --no-cache wireguard-tools >/dev/null && wg genkey && wg genkey'")
    private, header_key = keys.splitlines()
    public = sudo_run(client, password, f"printf %s {shlex.quote(private)} | docker run --rm -i alpine sh -c 'apk add --no-cache wireguard-tools >/dev/null && wg pubkey'")
    nums = run(client, "od -An -N16 -tu4 /dev/urandom").split()
    return {"server_private": private, "server_public": public, "header_key": header_key,
            "H1": str(int(nums[0]) or 101), "H2": str(int(nums[1]) or 102),
            "H3": str(int(nums[2]) or 103), "H4": str(int(nums[3]) or 104)}


def install_sync(c: Credentials, settings: dict, progress: Callable[[str], None]) -> tuple[dict, str]:
    progress("Подключение по SSH")
    client, host_key = connect(c)
    try:
        progress("Проверка ОС и sudo")
        sudo_run(client, c.password, "true")
        progress("Установка Docker")
        install = """set -eu
if ! command -v docker >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y docker.io
fi
systemctl enable --now docker 2>/dev/null || true
mkdir -p /opt/awg-bot/data
chmod 700 /opt/awg-bot/data
"""
        sudo_run(client, c.password, install)
        progress("Генерация серверных параметров")
        p = _random_params(client, c.password)
        subnet = ipaddress.ip_network(settings["subnet"])
        server_ip = str(next(subnet.hosts()))
        config = {**p, "subnet": settings["subnet"], "server_ip": server_ip,
                  "port": settings["port"], "dns": settings["dns"],
                  "Jc": "6", "Jmin": "10", "Jmax": "50",
                  "S1": "76", "S2": "47", "S3": "33", "S4": "12",
                  "ContentPaddingAddition": "10-100", "RandomTrailers": "on", "DisableCookies": "on"}
        dockerfile = textwrap.dedent(f"""
          FROM golang:1.24-alpine AS go
          RUN apk add --no-cache git make
          RUN git clone --depth 1 --branch {settings['go_ref']} https://github.com/amnezia-vpn/amneziawg-go /src
          WORKDIR /src
          RUN go build -trimpath -ldflags='-s -w' -o /amneziawg-go .
          FROM alpine:3.22
          RUN apk add --no-cache bash git make build-base linux-headers iproute2 iptables openresolv dumb-init
          RUN git clone --depth 1 --branch {settings['tools_ref']} https://github.com/amnezia-vpn/amneziawg-tools /tools && make -C /tools/src && make -C /tools/src install && rm -rf /tools
          COPY --from=go /amneziawg-go /usr/local/bin/amneziawg-go
          COPY start.sh /start.sh
          RUN chmod +x /start.sh
          ENTRYPOINT ["/usr/bin/dumb-init","--","/start.sh"]
        """).strip() + "\n"
        start = textwrap.dedent("""
          #!/bin/bash
          set -euo pipefail
          export WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
          awg-quick up /data/awg0.conf
          trap 'awg-quick down /data/awg0.conf || true' EXIT TERM INT
          awg show awg0
          tail -f /dev/null & wait $!
        """).strip() + "\n"
        conf = render_server_config(config)
        progress("Загрузка конфигурации на VPS")
        for path, body in (("Dockerfile", dockerfile), ("start.sh", start), ("data/awg0.conf", conf)):
            encoded = base64.b64encode(body.encode()).decode()
            sudo_run(client, c.password, f"printf %s {shlex.quote(encoded)} | base64 -d > {REMOTE_DIR}/{path}")
        sudo_run(client, c.password, f"chmod 600 {REMOTE_DIR}/data/awg0.conf")
        progress("Сборка AmneziaWG 3.1 (может занять несколько минут)")
        sudo_run(client, c.password, f"cd {REMOTE_DIR} && docker build --pull -t awg-bot-server .", timeout=1800)
        progress("Запуск VPN-контейнера")
        sudo_run(client, c.password, "sysctl -w net.ipv4.ip_forward=1 >/dev/null; "
                    "printf 'net.ipv4.ip_forward=1\\n' > /etc/sysctl.d/99-awg-bot.conf; "
                    f"docker rm -f {CONTAINER} >/dev/null 2>&1 || true; "
                    f"docker run -d --name {CONTAINER} --restart unless-stopped --privileged "
                    f"--network host -v {REMOTE_DIR}/data:/data awg-bot-server")
        progress("Проверка интерфейса и UDP-порта")
        sudo_run(client, c.password, f"for i in $(seq 1 20); do docker exec {CONTAINER} awg show awg0 >/dev/null 2>&1 && exit 0; sleep 1; done; docker logs {CONTAINER}; exit 1")
        return config, host_key
    finally:
        client.close()


async def install(c: Credentials, settings: dict, progress: Callable[[str], None]):
    return await asyncio.to_thread(install_sync, c, settings, progress)


def render_server_config(c: dict, peers: str = "") -> str:
    return f"""[Interface]
Address = {c['server_ip']}/{ipaddress.ip_network(c['subnet']).prefixlen}
ListenPort = {c['port']}
PrivateKey = {c['server_private']}
MTU = 1376
Jc = {c['Jc']}
Jmin = {c['Jmin']}
Jmax = {c['Jmax']}
S1 = {c['S1']}
S2 = {c['S2']}
S3 = {c['S3']}
S4 = {c['S4']}
H1 = {c['H1']}
H2 = {c['H2']}
H3 = {c['H3']}
H4 = {c['H4']}
HeaderProtectionKey = {c['header_key']}
ContentPaddingAddition = {c['ContentPaddingAddition']}
RandomTrailers = {c['RandomTrailers']}
DisableCookies = {c['DisableCookies']}
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -s {c['subnet']} -o $(ip route show default | awk '{{print $5; exit}}') -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -s {c['subnet']} -o $(ip route show default | awk '{{print $5; exit}}') -j MASQUERADE
{peers}"""


_locks: dict[str, threading.Lock] = {}


def add_peer_sync(c: Credentials, server: dict, address: str, name: str) -> dict:
    lock = _locks.setdefault(c.host, threading.Lock())
    with lock:
        client, _ = connect(c)
        try:
            private = sudo_run(client, c.password, f"docker exec {CONTAINER} awg genkey")
            public = sudo_run(client, c.password, f"printf %s {shlex.quote(private)} | docker exec -i {CONTAINER} awg pubkey")
            psk = sudo_run(client, c.password, f"docker exec {CONTAINER} awg genpsk")
            block = f"\n# bot:{name}\n[Peer]\nPublicKey = {public}\nPresharedKey = {psk}\nAllowedIPs = {address}/32\n"
            encoded = base64.b64encode(block.encode()).decode()
            sudo_run(client, c.password, f"printf %s {shlex.quote(encoded)} | base64 -d >> {REMOTE_DIR}/data/awg0.conf; "
                        f"docker exec {CONTAINER} bash -lc 'awg syncconf awg0 <(awg-quick strip /data/awg0.conf)'")
            return {"private": private, "public": public, "psk": psk, "address": address}
        finally:
            client.close()


async def add_peer(c, server, address, name):
    return await asyncio.to_thread(add_peer_sync, c, server, address, name)


def remove_peer_sync(c: Credentials, public: str):
    client, _ = connect(c)
    try:
        sudo_run(client, c.password, f"docker exec {CONTAINER} awg set awg0 peer {shlex.quote(public)} remove")
        # Persist by removing the matching Peer stanza using a small container-side awk program.
        script = """awk -v key="$1" 'BEGIN{RS=""; ORS="\n\n"} index($0, "PublicKey = " key) == 0' /data/awg0.conf > /data/awg0.new && mv /data/awg0.new /data/awg0.conf && chmod 600 /data/awg0.conf"""
        enc = base64.b64encode(script.encode()).decode()
        sudo_run(client, c.password, f"printf %s {shlex.quote(enc)} | base64 -d | docker exec -i {CONTAINER} sh -s -- {shlex.quote(public)}")
    finally:
        client.close()


async def remove_peer(c, public):
    return await asyncio.to_thread(remove_peer_sync, c, public)
