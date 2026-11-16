#!/usr/bin/env python3
"""Prove local write control: toggle the station LED, then turn it off."""
from __future__ import annotations

import hashlib
import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import station_test as st

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.100"


def handshake(sock):
    reader = st.FrameReader(sock)
    sock.sendall(st.build(st.CMD_P2))
    nonce = None
    deadline = time.time() + 15
    while time.time() < deadline and nonce is None:
        item = reader.read(2)
        if not item:
            continue
        cmd, pid, payload = item
        if cmd == st.CMD_P3:
            fields = st.ttlv_decode(payload)
            nonce = next((v for t, ty, v in fields if ty == "bin"), None)
            token = hashlib.sha256((st.KEY.hex() + ";" + nonce).encode()).hexdigest()
            p4 = struct.pack(">H", (2 << 3) | 3) + struct.pack(">H", len(token)) + token.encode()
            sock.sendall(st.build(st.CMD_P4, p4))
    if not nonce:
        raise RuntimeError("no nonce")
    iv = nonce.encode()
    result = None
    deadline = time.time() + 15
    while time.time() < deadline and result is None:
        item = reader.read(2)
        if not item:
            continue
        cmd, pid, payload = item
        if cmd == st.CMD_P5:
            fields = st.ttlv_decode(payload)
            result = next((v for t, ty, v in fields if ty == "num"), None)
    if result not in (0, 2):
        raise RuntimeError(f"login failed: {result}")
    return reader, iv


def send(sock, iv, tag, value, is_bool=False):
    if is_bool:
        payload = struct.pack(">H", (tag << 3) | (1 if value else 0))
    else:
        payload = struct.pack(">H", (tag << 3) | 2) + bytes([0]) + bytes([value & 0xFF])
    sock.sendall(st.build(st.CMD_WRITE, payload, encrypt=True, iv=iv))


def main():
    s = socket.create_connection((HOST, st.PORT), timeout=8)
    reader, iv = handshake(s)
    print("connected + logged in")

    for label, value in (("LED High", 1), ("LED Off", 0)):
        send(s, iv, 10, value)
        print(f"[>] tag10 = {value} ({label})")
        end = time.time() + 3
        while time.time() < end:
            item = reader.read(1)
            if not item:
                continue
            cmd, pid, payload = item
            if cmd == st.CMD_PING:
                s.sendall(st.build(st.CMD_PONG))
            elif cmd == st.CMD_ACK:
                print(f"[<] ack {payload.hex()}")
            elif cmd == st.CMD_REPORT:
                try:
                    pt = st.aes_dec(payload, iv)
                except Exception as e:
                    print(f"[!] decrypt failed: {e}")
                    continue
                fields = st.ttlv_decode(pt)
                st.show(fields, "  ")
            else:
                print(f"[<] cmd={cmd} len={len(payload)}")
    s.close()


if __name__ == "__main__":
    main()
