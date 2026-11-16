#!/usr/bin/env python3
"""Find a Quectel/Acceleronix station on the local network (UDP 6606)."""
from __future__ import annotations

import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import station


def build_probe() -> bytes:
    body = struct.pack(">H", 1) + struct.pack(">H", 28720)
    frame = b"\xAA\xAA" + struct.pack(">H", len(body) + 1) + bytes([sum(body) & 0xFF]) + body
    out = bytearray(frame[:2])
    body = frame[2:]
    for index, byte in enumerate(body):
        out.append(byte)
        if byte == 0xAA and index + 1 < len(body) and body[index + 1] in (0x55, 0xAA):
            out.append(0x55)
    return bytes(out)


def local_broadcast() -> str | None:
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("8.8.8.8", 80))
        ip = probe.getsockname()[0]
        probe.close()
        return ip.rsplit(".", 1)[0] + ".255"
    except OSError:
        return None


def main() -> int:
    targets = {"255.255.255.255"}
    broadcast = local_broadcast()
    if broadcast:
        targets.add(broadcast)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("", 0))
    sock.settimeout(2)
    for target in targets:
        sock.sendto(build_probe(), (target, 6606))
    print("probe sent to", ", ".join(sorted(targets)))

    found = 0
    reader = station._FrameReader()
    end = time.time() + 6
    while time.time() < end:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            break
        reader.feed(data)
        while True:
            frame = reader.pop()
            if frame is None:
                break
            cmd, _pid, payload = frame
            if cmd != 28721:
                continue
            fields = station.ttlv_decode(payload)
            values = {tag: value for tag, _typ, value in fields}
            pk = values.get(3)
            dk = values.get(4)
            ip = values.get(5) or addr[0]
            port = values.get(6) or 6607
            print(f"[station] ip={ip} pk={pk} dk={dk} port={port}")
            found += 1
    sock.close()
    if not found:
        print("no station found; check Wi-Fi and that the station is on the same LAN", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
