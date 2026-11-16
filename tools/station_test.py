#!/usr/bin/env python3
"""Read-only local test for the P1000/P1500 Plus station (Quectel TTLV over TCP 6607)."""
from __future__ import annotations

import base64
import hashlib
import json
import socket
import struct
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parent.parent
SECRET = json.loads((ROOT / ".secrets" / "authkey.json").read_text(encoding="utf-8"))
KEY = base64.b64decode(SECRET["authKey"])
AUTHKEY_B64 = SECRET["authKey"]
HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.100"
PORT = 6607

CMD_P2, CMD_P3, CMD_P4, CMD_P5 = 28722, 28723, 28724, 28725
CMD_PING, CMD_PONG, CMD_HB = 28727, 28728, 28729
CMD_READ, CMD_WRITE, CMD_REPORT, CMD_ACK = 17, 19, 20, 28726

READ_TAGS = [2, 8, 9, 6, 31, 7, 28, 27, 14, 12, 11, 5, 4, 3, 1, 34, 20, 100, 43, 44, 46, 10]
READ_PAYLOAD = b"".join(struct.pack(">H", t) for t in READ_TAGS)


def stuff(frame: bytes) -> bytes:
    out = bytearray(frame[:2])
    body = frame[2:]
    for i, b in enumerate(body):
        out.append(b)
        if b == 0xAA and i + 1 < len(body) and body[i + 1] in (0x55, 0xAA):
            out.append(0x55)
    return bytes(out)


def destuff(buf: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(buf):
        out.append(buf[i])
        if buf[i] == 0xAA and i + 1 < len(buf) and buf[i + 1] == 0x55:
            i += 1
        i += 1
    return bytes(out)


def pad(data: bytes) -> bytes:
    p = padding.PKCS7(128).padder()
    return p.update(data) + p.finalize()


def unpad(data: bytes) -> bytes:
    u = padding.PKCS7(128).unpadder()
    return u.update(data) + u.finalize()


def aes_enc(data: bytes, iv: bytes) -> bytes:
    e = Cipher(algorithms.AES(KEY), modes.CBC(iv)).encryptor()
    return e.update(pad(data)) + e.finalize()


def aes_dec(data: bytes, iv: bytes) -> bytes:
    d = Cipher(algorithms.AES(KEY), modes.CBC(iv)).decryptor()
    return unpad(d.update(data) + d.finalize())


_pid = 0


def build(cmd: int, payload: bytes = b"", encrypt: bool = False, iv: bytes | None = None) -> bytes:
    global _pid
    if encrypt and payload:
        payload = aes_enc(payload, iv)
    _pid = (_pid % 65533) + 1
    body = struct.pack(">H", _pid) + struct.pack(">H", cmd) + payload
    chk = sum(body) & 0xFF
    return stuff(b"\xAA\xAA" + struct.pack(">H", len(body) + 1) + bytes([chk]) + body)


class FrameReader:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.raw = b""
        self.clean = b""

    def _feed(self, data: bytes):
        self.raw += data
        out = bytearray()
        i = 0
        while i < len(self.raw):
            b = self.raw[i]
            if b == 0xAA:
                if i + 1 >= len(self.raw):
                    break
                out.append(b)
                if self.raw[i + 1] == 0x55:
                    i += 2
                else:
                    i += 1
            else:
                out.append(b)
                i += 1
        self.raw = self.raw[i:]
        self.clean += bytes(out)

    def read(self, timeout: float = 1.0):
        self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(4096)
        except socket.timeout:
            return None
        if not data:
            raise ConnectionError("closed by peer")
        self._feed(data)
        k = self.clean.find(b"\xAA\xAA")
        if k < 0 or k + 4 > len(self.clean):
            return None
        length = struct.unpack(">H", self.clean[k + 2:k + 4])[0]
        total = k + 4 + length
        if total > len(self.clean):
            return None
        frame = self.clean[k:total]
        self.clean = self.clean[total:]
        chk = frame[4]
        body = frame[5:]
        if (sum(body) & 0xFF) != chk:
            return None
        pid = struct.unpack(">H", body[0:2])[0]
        cmd = struct.unpack(">H", body[2:4])[0]
        return cmd, pid, body[4:]


def ttlv_decode(buf: bytes, depth: int = 0):
    fields = []
    i = 0

    def read_num(pos: int):
        c = buf[pos]
        pos += 1
        sign = (c >> 7) & 1
        dec = (c >> 3) & 0xF
        n = (c & 7) + 1
        v = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
        if sign:
            v = -v
        return (v / (10 ** dec) if dec else v), pos

    while i + 2 <= len(buf):
        h = struct.unpack(">H", buf[i:i + 2])[0]
        i += 2
        tag, typ = (h >> 3) & 0x1FFF, h & 7
        if typ in (0, 1):
            fields.append((tag, "bool", typ == 1))
        elif typ == 2:
            v, i = read_num(i)
            fields.append((tag, "num", v))
        elif typ in (3, 5):
            if i + 2 > len(buf):
                break
            ln = struct.unpack(">H", buf[i:i + 2])[0]
            i += 2
            val = buf[i:i + ln]
            i += ln
            try:
                fields.append((tag, "bin", val.decode("ascii")))
            except UnicodeDecodeError:
                fields.append((tag, "bin", val.hex()))
        elif typ == 4:
            if i + 2 > len(buf):
                break
            cnt = struct.unpack(">H", buf[i:i + 2])[0]
            i += 2
            sub = []
            for _ in range(cnt):
                if i + 2 > len(buf):
                    break
                h2 = struct.unpack(">H", buf[i:i + 2])[0]
                i += 2
                t2, ty2 = (h2 >> 3) & 0x1FFF, h2 & 7
                if ty2 in (0, 1):
                    sub.append((t2, "bool", ty2 == 1))
                elif ty2 == 2:
                    v, i = read_num(i)
                    sub.append((t2, "num", v))
                elif ty2 in (3, 5):
                    ln = struct.unpack(">H", buf[i:i + 2])[0]
                    i += 2
                    sub.append((t2, "bin", buf[i:i + ln].hex()))
                    i += ln
                else:
                    break
            fields.append((tag, "struct", sub))
        else:
            break
    return fields


def load_names():
    path = ROOT / "tsl_p11uve.json"
    if not path.exists():
        return {}
    j = json.loads(path.read_text(encoding="utf-8"))
    props = (j.get("data") or {}).get("properties") or []
    names = {}
    for p in props:
        pid = p.get("id")
        if pid is not None:
            names[int(pid)] = p.get("code") or p.get("name") or str(pid)
    return names


NAMES = load_names()


def show(fields, prefix=""):
    for tag, typ, val in fields:
        name = NAMES.get(tag, f"tag{tag}")
        if typ == "struct":
            print(f"{prefix}{tag} {name}:")
            for t2, ty2, v2 in val:
                print(f"{prefix}  {t2} {ty2}={v2}")
        else:
            print(f"{prefix}{tag} {name} = {val}")


def main():
    s = socket.create_connection((HOST, PORT), timeout=8)
    s.settimeout(8)
    reader = FrameReader(s)
    print(f"connected {HOST}:{PORT}")
    s.sendall(build(CMD_P2))
    nonce = None
    iv = None
    encrypted = False
    deadline = time.time() + 15
    while time.time() < deadline and nonce is None:
        item = reader.read(2)
        if not item:
            continue
        cmd, pid, payload = item
        print(f"<- cmd={cmd} len={len(payload)}")
        if cmd == CMD_P3:
            fields = ttlv_decode(payload)
            show(fields, "  ")
            nonce = next((v for t, ty, v in fields if ty == "bin"), None)
            if not nonce:
                print("no nonce")
                return 1
            iv = nonce.encode()
            token = hashlib.sha256((KEY.hex() + ";" + nonce).encode()).hexdigest()
            p4 = struct.pack(">H", (2 << 3) | 3) + struct.pack(">H", len(token)) + token.encode()
            s.sendall(build(CMD_P4, p4))
            print("[>] p4 sent")
    if nonce is None:
        print("no p3")
        return 1

    deadline = time.time() + 15
    result = None
    while time.time() < deadline and result is None:
        item = reader.read(2)
        if not item:
            continue
        cmd, pid, payload = item
        print(f"<- cmd={cmd} len={len(payload)}")
        if cmd == CMD_P5:
            fields = ttlv_decode(payload)
            show(fields, "  ")
            result = next((v for t, ty, v in fields if ty == "num"), None)
    if result not in (0, 2):
        print(f"login failed: {result}")
        return 1
    print(f"login ok: {result}, enabling AES")
    encrypted = True

    def send(cmd, payload=b"", enc=True):
        s.sendall(build(cmd, payload, encrypt=enc, iv=iv))

    send(CMD_WRITE, b"\x03\x22\x00\x03")  # tag100 = 3
    send(CMD_READ, READ_PAYLOAD)
    send(CMD_HB, b"\x00\x0a\x00\x1e\x00\x12\x00\x01")
    print("[>] subscribe + read + heartbeat sent")

    last_read = time.time()
    end = time.time() + 30
    while time.time() < end:
        item = reader.read(1)
        if time.time() - last_read > 12:
            send(CMD_WRITE, b"\x03\x22\x00\x03")
            send(CMD_READ, READ_PAYLOAD)
            send(CMD_HB, b"\x00\x0a\x00\x1e\x00\x12\x00\x01")
            last_read = time.time()
        if not item:
            continue
        cmd, pid, payload = item
        if cmd == CMD_PING:
            s.sendall(build(CMD_PONG))
            print("[<] ping -> pong")
        elif cmd == CMD_ACK:
            print(f"[<] ack {payload.hex()}")
        elif cmd == CMD_REPORT:
            try:
                pt = aes_dec(payload, iv)
            except Exception as e:
                print(f"[!] decrypt failed: {e} raw={payload.hex()}")
                continue
            fields = ttlv_decode(pt)
            print(f"[report] {time.strftime('%H:%M:%S')}")
            show(fields, "  ")
        else:
            print(f"[<] cmd={cmd} len={len(payload)} payload={payload[:32].hex()}")
    s.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
