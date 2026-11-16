#!/usr/bin/env python3
"""Quectel/Acceleronix TTLV client for P1000/P1500 Plus stations (TCP 6607)."""
from __future__ import annotations

import base64
import hashlib
import logging
import socket
import struct
import threading
import time
from typing import Callable

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

log = logging.getLogger("station")

MAX_FRAME = 8192
MAX_BUFFER = 64 * 1024

CMD_P2 = 28722
CMD_P3 = 28723
CMD_P4 = 28724
CMD_P5 = 28725
CMD_PING = 28727
CMD_PONG = 28728
CMD_HB = 28729
CMD_READ = 17
CMD_READ_RESP = 18
CMD_WRITE = 19
CMD_REPORT = 20
CMD_ACK = 28726

# Tags 6-9 are STRUCTs with per-port power (see tsl_p11uve.json).
READ_TAGS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 20, 27, 28, 31, 34, 43, 44, 46, 100]

INITIAL_STATE = {
    "online": False,
    "link": "down",
    "battery": None,
    "remain_time": None,
    "remain_charging_time": None,
    "input_w": None,
    "output_w": None,
    "ac_input_w": None,
    "dc_input_w": None,
    "temp_c": None,
    "ac_switch": None,
    "usb_switch": None,
    "dc_switch": None,
    "ac_out_w": None,
    "ac_out_v": None,
    "usb1_w": None,
    "usb2_w": None,
    "typec1_w": None,
    "typec2_w": None,
    "dc_out_w": None,
    "dc_out_v": None,
    "dc_out_a": None,
    "led": None,
    "frequency": None,
    "voltage_setting": None,
    "inverter_version": None,
    "bms_version": None,
    "charge_limit": None,
    "last_report": 0.0,
}


def _pad(data: bytes) -> bytes:
    p = padding.PKCS7(128).padder()
    return p.update(data) + p.finalize()


def _unpad(data: bytes) -> bytes:
    u = padding.PKCS7(128).unpadder()
    return u.update(data) + u.finalize()


def _stuff(frame: bytes) -> bytes:
    """Escape AA followed by AA/55 because AA AA is the frame delimiter."""
    out = bytearray(frame[:2])
    body = frame[2:]
    for i, byte in enumerate(body):
        out.append(byte)
        if byte == 0xAA and i + 1 < len(body) and body[i + 1] in (0x55, 0xAA):
            out.append(0x55)
    return bytes(out)


class _FrameReader:
    def __init__(self) -> None:
        self.raw = b""
        self.clean = b""

    def feed(self, data: bytes) -> None:
        self.raw += data
        out = bytearray()
        i = 0
        while i < len(self.raw):
            byte = self.raw[i]
            if byte == 0xAA:
                if i + 1 >= len(self.raw):
                    break
                out.append(byte)
                i += 2 if self.raw[i + 1] == 0x55 else 1
            else:
                out.append(byte)
                i += 1
        self.raw = self.raw[i:]
        self.clean += bytes(out)
        if len(self.clean) > MAX_BUFFER:
            log.warning("frame buffer overflow, dropping %d bytes", len(self.clean))
            self.clean = b""

    def pop(self) -> tuple[int, int, bytes] | None:
        start = self.clean.find(b"\xAA\xAA")
        if start < 0 or start + 4 > len(self.clean):
            return None
        length = struct.unpack(">H", self.clean[start + 2:start + 4])[0]
        if length < 5 or length > MAX_FRAME:
            log.warning("bad frame length %d, resyncing", length)
            self.clean = self.clean[start + 2:]
            return None
        total = start + 4 + length
        if total > len(self.clean):
            return None
        frame = self.clean[start:total]
        self.clean = self.clean[total:]
        if (sum(frame[5:]) & 0xFF) != frame[4]:
            log.warning("bad frame checksum")
            return None
        pid = struct.unpack(">H", frame[5:7])[0]
        cmd = struct.unpack(">H", frame[7:9])[0]
        return cmd, pid, frame[9:]


def _read_number(buf: bytes, pos: int, end: int) -> tuple[float | int, int]:
    if pos >= end:
        raise ValueError("truncated number")
    control = buf[pos]
    pos += 1
    sign = (control >> 7) & 1
    decimals = (control >> 3) & 0xF
    nbytes = (control & 7) + 1
    if pos + nbytes > end:
        raise ValueError("truncated number body")
    value = int.from_bytes(buf[pos:pos + nbytes], "big")
    pos += nbytes
    if sign:
        value = -value
    return (value / (10 ** decimals) if decimals else value), pos


def _decode_one(
    buf: bytes, pos: int, end: int
) -> tuple[tuple[int, str, object] | None, int]:
    if pos + 2 > end:
        return None, pos
    header = struct.unpack(">H", buf[pos:pos + 2])[0]
    pos += 2
    tag, typ = (header >> 3) & 0x1FFF, header & 7
    if typ in (0, 1):
        return (tag, "bool", typ == 1), pos
    if typ == 2:
        value, pos = _read_number(buf, pos, end)
        return (tag, "num", value), pos
    if typ in (3, 5):
        if pos + 2 > end:
            raise ValueError("truncated binary header")
        length = struct.unpack(">H", buf[pos:pos + 2])[0]
        pos += 2
        if pos + length > end:
            raise ValueError("truncated binary body")
        value = buf[pos:pos + length]
        pos += length
        try:
            text = value.decode("ascii")
        except UnicodeDecodeError:
            text = value.hex()
        return (tag, "bin", text), pos
    if typ == 4:
        if pos + 2 > end:
            raise ValueError("truncated struct header")
        count = struct.unpack(">H", buf[pos:pos + 2])[0]
        pos += 2
        sub: list[tuple[int, str, object]] = []
        for _ in range(count):
            field, pos = _decode_one(buf, pos, end)
            if field is None:
                raise ValueError("truncated struct member")
            sub.append(field)
        return (tag, "struct", sub), pos
    raise ValueError(f"unknown TTLV type {typ}")


def _decode_fields(
    buf: bytes, pos: int, end: int
) -> tuple[list[tuple[int, str, object]], int]:
    fields: list[tuple[int, str, object]] = []
    while pos + 2 <= end:
        field, pos = _decode_one(buf, pos, end)
        if field is None:
            break
        fields.append(field)
    return fields, pos


def ttlv_decode(buf: bytes) -> list[tuple[int, str, object]]:
    fields, _ = _decode_fields(buf, 0, len(buf))
    return fields


POWER_LIMITS = {
    "input_w": 3000,
    "output_w": 3000,
    "ac_input_w": 3000,
    "dc_input_w": 1000,
    "ac_out_w": 2400,
    "usb1_w": 150,
    "usb2_w": 150,
    "typec1_w": 150,
    "typec2_w": 150,
    "dc_out_w": 300,
}


class StationClient:
    def __init__(
        self,
        host: str,
        port: int,
        authkey_b64: str,
        on_state: Callable[[dict], None],
        on_event: Callable[[str, dict], None] | None = None,
        stale_after: float = 90.0,
    ) -> None:
        self.host = host
        self.port = port
        self.key = base64.b64decode(authkey_b64)
        self.on_state = on_state
        self.on_event = on_event
        self.stale_after = stale_after
        self.state = dict(INITIAL_STATE)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._reader = _FrameReader()
        self._iv: bytes | None = None
        self._pid = 0
        self._backoff = 1.0

    def start(self) -> None:
        threading.Thread(target=self._run, name="station", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        self._close()

    def _close(self) -> None:
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._connect_and_loop()
            except Exception as exc:
                if not self._stop.is_set():
                    log.warning("station connection lost: %s", exc)
                    self._set_online(False)
                    self._set_link("down")
            if self._stop.wait(self._backoff):
                break
            self._backoff = min(self._backoff * 2, 30)

    def _connect_and_loop(self) -> None:
        log.info("connecting to %s:%s", self.host, self.port)
        self._set_link("connecting")
        sock = socket.create_connection((self.host, self.port), timeout=8)
        sock.settimeout(1.0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self._sock = sock
        self._reader = _FrameReader()
        self._handshake()
        self._set_link("up")
        self._backoff = 1.0
        self._set_online(True)
        self._keepalive()
        last_keepalive = time.monotonic()
        last_data = time.monotonic()
        last_report = time.monotonic()
        while not self._stop.is_set():
            if time.monotonic() - last_report > self.stale_after:
                raise ConnectionError("no telemetry reports from station")
            if time.monotonic() - last_keepalive >= 10:
                self._keepalive()
                last_keepalive = time.monotonic()
            frame = self._read_frame()
            if frame is None:
                if time.monotonic() - last_data > self.stale_after:
                    raise ConnectionError("no telemetry from station")
                if self.state["online"] and time.time() - self.state["last_report"] > 60:
                    self._set_online(False)
                continue
            last_data = time.monotonic()
            cmd, _pid, payload = frame
            if cmd == CMD_PING:
                self._send(CMD_PONG, b"", encrypt=False)
            elif cmd in (CMD_REPORT, CMD_READ_RESP):
                last_report = time.monotonic()
                self._handle_report(payload)
            elif cmd == CMD_ACK:
                log.debug("write ack")
            elif cmd == CMD_P5:
                log.debug("unexpected p5")
        self._close()

    def _handshake(self) -> None:
        self._send(CMD_P2, b"", encrypt=False)
        nonce = None
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            frame = self._read_frame()
            if frame and frame[0] == CMD_P3:
                fields = ttlv_decode(frame[2])
                nonce = next((value for tag, typ, value in fields if typ == "bin"), None)
                break
        if not nonce:
            raise RuntimeError("no nonce from station")
        self._iv = nonce.encode()
        token = hashlib.sha256((self.key.hex() + ";" + nonce).encode()).hexdigest()
        payload = struct.pack(">H", (2 << 3) | 3) + struct.pack(">H", len(token)) + token.encode()
        self._send(CMD_P4, payload, encrypt=False)
        result = None
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            frame = self._read_frame()
            if frame and frame[0] == CMD_P5:
                fields = ttlv_decode(frame[2])
                result = next((value for tag, typ, value in fields if typ == "num"), None)
                break
        if result not in (0, 2):
            raise RuntimeError(
                f"login rejected: {result} (a re-bound station rotates the authKey; "
                f"run tools/get_authkey.py)"
                if result == -1
                else f"login rejected: {result}"
            )
        log.info("logged in, result=%s", result)

    def _keepalive(self) -> None:
        # The station stops streaming when the subscribe triple is not re-asserted
        # inside its 30 s heartbeat window; 20 s was already too slow on some units,
        # so this runs well under 12 s.
        self._send(CMD_WRITE, struct.pack(">H", (100 << 3) | 2) + b"\x00\x03")
        self._send(CMD_READ, b"".join(struct.pack(">H", tag) for tag in READ_TAGS))
        self._send(CMD_HB, b"\x00\x0a\x00\x1e\x00\x12\x00\x01")

    def _send(self, cmd: int, payload: bytes = b"", encrypt: bool = True) -> None:
        sock = self._sock
        if sock is None:
            raise ConnectionError("not connected")
        if encrypt and payload:
            if self._iv is None:
                raise RuntimeError("encryption key is not ready")
            payload = self._encrypt(payload)
        self._pid = (self._pid % 65533) + 1
        body = struct.pack(">H", self._pid) + struct.pack(">H", cmd) + payload
        frame = b"\xAA\xAA" + struct.pack(">H", len(body) + 1) + bytes([sum(body) & 0xFF]) + body
        sock.sendall(_stuff(frame))

    def _encrypt(self, data: bytes) -> bytes:
        enc = Cipher(algorithms.AES(self.key), modes.CBC(self._iv)).encryptor()
        return enc.update(_pad(data)) + enc.finalize()

    def _decrypt(self, data: bytes) -> bytes:
        dec = Cipher(algorithms.AES(self.key), modes.CBC(self._iv)).decryptor()
        return _unpad(dec.update(data) + dec.finalize())

    def _read_frame(self) -> tuple[int, int, bytes] | None:
        frame = self._reader.pop()
        if frame is not None:
            return frame
        sock = self._sock
        if sock is None:
            raise ConnectionError("not connected")
        try:
            data = sock.recv(4096)
        except socket.timeout:
            return None
        if not data:
            raise ConnectionError("station closed the connection")
        self._reader.feed(data)
        return self._reader.pop()

    def _handle_report(self, payload: bytes) -> None:
        if self._iv is None:
            return
        try:
            plain = self._decrypt(payload)
        except Exception as exc:
            log.warning("decrypt failed: %s", exc)
            return
        try:
            fields = ttlv_decode(plain)
        except (ValueError, IndexError, struct.error) as exc:
            log.warning("bad report payload (%d bytes): %s", len(payload), exc)
            return
        with self._lock:
            for tag, typ, value in fields:
                self._apply(tag, typ, value)
            self.state["last_report"] = time.time()
            self.state["online"] = True
            snapshot = dict(self.state)
        try:
            self.on_state(snapshot)
        except Exception:
            log.exception("state callback failed")
        if self.on_event:
            self.on_event("report", snapshot)

    def _apply(self, tag: int, typ: str, value: object) -> None:
        if typ == "struct":
            if tag == 6:
                for sub_tag, _sub_typ, sub_value in value:  # type: ignore[union-attr]
                    if sub_tag == 2:
                        self._store("ac_out_w", sub_value)
                    elif sub_tag == 3:
                        self.state["ac_out_v"] = sub_value
            elif tag == 7:
                for sub_tag, _sub_typ, sub_value in value:  # type: ignore[union-attr]
                    if sub_tag == 2:
                        self._store("usb1_w", sub_value)
                    elif sub_tag == 3:
                        self._store("usb2_w", sub_value)
            elif tag == 8:
                for sub_tag, _sub_typ, sub_value in value:  # type: ignore[union-attr]
                    if sub_tag == 2:
                        self._store("typec1_w", sub_value)
                    elif sub_tag == 5:
                        self._store("typec2_w", sub_value)
            elif tag == 9:
                for sub_tag, _sub_typ, sub_value in value:  # type: ignore[union-attr]
                    if sub_tag == 2:
                        self._store("dc_out_w", sub_value)
                    elif sub_tag == 3:
                        self.state["dc_out_v"] = sub_value
                    elif sub_tag == 4:
                        self.state["dc_out_a"] = sub_value
            return
        mapping = {
            1: "battery",
            2: "remain_time",
            3: "remain_charging_time",
            4: "input_w",
            5: "output_w",
            10: "led",
            11: "ac_input_w",
            12: "dc_input_w",
            14: "temp_c",
            20: "charge_limit",
            27: "frequency",
            28: "voltage_setting",
            31: "inverter_version",
            34: "bms_version",
            43: "ac_switch",
            44: "usb_switch",
            46: "dc_switch",
        }
        key = mapping.get(tag)
        if key:
            self._store(key, value)

    def _store(self, key: str, value: object) -> None:
        """Drop physically impossible bursts instead of storing them.

        The firmware occasionally reports kilowatts on an idle USB port; the vendor
        app shows the same spikes, so this filters the station's output, not ours.
        """
        limit = POWER_LIMITS.get(key)
        if limit is not None and isinstance(value, (int, float)) and (value < 0 or value > limit):
            log.warning("dropping implausible %s=%s", key, value)
            return
        self.state[key] = value

    def _set_online(self, online: bool) -> None:
        with self._lock:
            self.state["online"] = online
            snapshot = dict(self.state)
        self.on_state(snapshot)

    def _set_link(self, kind: str) -> None:
        """down: no socket; connecting: socket open, handshake running; up: logged in."""
        with self._lock:
            self.state["link"] = kind
            snapshot = dict(self.state)
        self.on_state(snapshot)
