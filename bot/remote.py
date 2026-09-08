from __future__ import annotations
import asyncio
import base64
import hashlib
import ipaddress
import json
import re
import secrets
import shlex
import textwrap
import threading
from dataclasses import dataclass
from typing import Callable

import paramiko


LEGACY_REMOTE_DIR = "/opt/awg-bot"
LEGACY_CONTAINER = "awg-bot-server"


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


def _free_port(client: paramiko.SSHClient) -> int:
    listeners = run(client, "ss -H -lun 2>/dev/null || true")
    used = {int(value) for value in re.findall(r":(\d{1,5})(?:\s|$)", listeners)}
    choices = list(range(50000, 60000))
    secrets.SystemRandom().shuffle(choices)
    for port in choices:
        if port not in used:
            return port
    raise RuntimeError("На VPS нет свободного UDP-порта в диапазоне 50000–59999")


def _free_subnet(client: paramiko.SSHClient, password: str) -> ipaddress.IPv4Network:
    output = run(client, "ip -4 route show || true") + "\n" + sudo_run(
        client, password,
        "docker network inspect $(docker network ls -q) --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null || true",
    )
    occupied = []
    for value in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}", output):
        try:
            occupied.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            pass
    candidates = (
        [ipaddress.ip_network(f"10.{second}.{third}.0/24")
         for second in range(0, 256) for third in range(0, 256)]
        + [ipaddress.ip_network(f"172.{second}.{third}.0/24")
           for second in range(16, 32) for third in range(0, 256)]
        + [ipaddress.ip_network(f"192.168.{third}.0/24") for third in range(0, 256)]
    )
    secrets.SystemRandom().shuffle(candidates)
    for candidate in candidates:
        if not any(candidate.overlaps(network) for network in occupied):
            return candidate
    raise RuntimeError("Не удалось подобрать свободную приватную /24-подсеть")


def remote_dir(server: dict) -> str:
    return server.get("remote_dir", LEGACY_REMOTE_DIR)


def container_name(server: dict) -> str:
    return server.get("container", LEGACY_CONTAINER)


def interface_name(server: dict) -> str:
    return server.get("interface", "awg0")


def config_path(server: dict) -> str:
    return f"{remote_dir(server)}/data/{interface_name(server)}.conf"


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
  apt-get install -y docker.io iproute2
fi
if ! command -v ss >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y iproute2
fi
systemctl enable --now docker 2>/dev/null || true
"""
        sudo_run(client, c.password, install)
        progress("Генерация серверных параметров")
        p = _random_params(client, c.password)
        port = _free_port(client)
        subnet = _free_subnet(client, c.password)
        server_ip = str(next(subnet.hosts()))
        deployment_id = secrets.token_hex(4)
        iface = f"awg{deployment_id[:5]}"
        config = {**p, "subnet": str(subnet), "server_ip": server_ip,
                  "port": port, "dns": settings["dns"],
                  "deployment_id": deployment_id,
                  "remote_dir": f"/opt/awg-bot/{deployment_id}",
                  "container": f"awg-bot-{deployment_id}", "interface": iface,
                  "Jc": "6", "Jmin": "10", "Jmax": "50",
                  "S1": "76", "S2": "47", "S3": "33", "S4": "12",
                  "ContentPaddingAddition": "10-100", "RandomTrailers": "on", "DisableCookies": "on"}
        dockerfile = textwrap.dedent(f"""
          FROM golang:1.25.12-alpine AS go
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
        start = textwrap.dedent(f"""
          #!/bin/bash
          set -euo pipefail
          export WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
          awg-quick up /data/{iface}.conf
          trap 'awg-quick down /data/{iface}.conf || true' EXIT TERM INT
          awg show {iface}
          tail -f /dev/null & wait $!
        """).strip() + "\n"
        conf = render_server_config(config)
        progress("Загрузка конфигурации на VPS")
        root = remote_dir(config)
        sudo_run(client, c.password, f"mkdir -p {root}/data; chmod 700 {root}/data")
        for path, body in (("Dockerfile", dockerfile), ("start.sh", start), (f"data/{iface}.conf", conf)):
            encoded = base64.b64encode(body.encode()).decode()
            sudo_run(client, c.password, f"printf %s {shlex.quote(encoded)} | base64 -d > {root}/{path}")
        sudo_run(client, c.password, f"chmod 600 {config_path(config)}")
        progress("Сборка AmneziaWG 3.1 (может занять несколько минут)")
        sudo_run(client, c.password, f"cd {root} && docker build --pull -t {container_name(config)} .", timeout=1800)
        progress("Запуск VPN-контейнера")
        sudo_run(client, c.password, "sysctl -w net.ipv4.ip_forward=1 >/dev/null; "
                    "printf 'net.ipv4.ip_forward=1\\n' > /etc/sysctl.d/99-awg-bot.conf; "
                    f"docker rm -f {container_name(config)} >/dev/null 2>&1 || true; "
                    f"docker run -d --name {container_name(config)} --restart unless-stopped --privileged "
                    f"--network host -v {root}/data:/data {container_name(config)}")
        progress("Проверка интерфейса и UDP-порта")
        sudo_run(client, c.password, f"for i in $(seq 1 20); do docker exec {container_name(config)} awg show {iface} >/dev/null 2>&1 && exit 0; sleep 1; done; docker logs {container_name(config)}; exit 1")
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
PostUp = iptables -I INPUT -p udp --dport {c['port']} -j ACCEPT; iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -s {c['subnet']} -o $(ip route show default | awk '{{print $5; exit}}') -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport {c['port']} -j ACCEPT; iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -s {c['subnet']} -o $(ip route show default | awk '{{print $5; exit}}') -j MASQUERADE
{peers}"""


_locks: dict[str, threading.Lock] = {}


def add_peer_sync(c: Credentials, server: dict, address: str, name: str) -> dict:
    lock = _locks.setdefault(c.host, threading.Lock())
    with lock:
        client, _ = connect(c)
        try:
            container = container_name(server)
            iface = interface_name(server)
            path = config_path(server)
            private = sudo_run(client, c.password, f"docker exec {container} awg genkey")
            public = sudo_run(client, c.password, f"printf %s {shlex.quote(private)} | docker exec -i {container} awg pubkey")
            psk = sudo_run(client, c.password, f"docker exec {container} awg genpsk")
            block = f"\n# bot:{name}\n[Peer]\nPublicKey = {public}\nPresharedKey = {psk}\nAllowedIPs = {address}/32\n"
            encoded = base64.b64encode(block.encode()).decode()
            sudo_run(client, c.password, f"printf %s {shlex.quote(encoded)} | base64 -d >> {path}; "
                        f"docker exec {container} bash -lc 'awg syncconf {iface} <(awg-quick strip /data/{iface}.conf)'")
            return {"private": private, "public": public, "psk": psk, "address": address}
        finally:
            client.close()


async def add_peer(c, server, address, name):
    return await asyncio.to_thread(add_peer_sync, c, server, address, name)


def remove_peer_sync(c: Credentials, server: dict, public: str):
    client, _ = connect(c)
    try:
        container = container_name(server)
        iface = interface_name(server)
        sudo_run(client, c.password, f"docker exec {container} awg set {iface} peer {shlex.quote(public)} remove")
        # Persist by removing the matching Peer stanza using a small container-side awk program.
        script = f"""awk -v key="$1" 'BEGIN{{RS=""; ORS="\n\n"}} index($0, "PublicKey = " key) == 0' /data/{iface}.conf > /data/{iface}.new && mv /data/{iface}.new /data/{iface}.conf && chmod 600 /data/{iface}.conf"""
        enc = base64.b64encode(script.encode()).decode()
        sudo_run(client, c.password, f"printf %s {shlex.quote(enc)} | base64 -d | docker exec -i {container} sh -s -- {shlex.quote(public)}")
    finally:
        client.close()


async def remove_peer(c, server, public):
    return await asyncio.to_thread(remove_peer_sync, c, server, public)
