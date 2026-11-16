#!/usr/bin/env python3
"""Wonderfree cloud poller for attributes the station does not expose on LAN."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

log = logging.getLogger("cloud")

USER_DOMAIN = "E.SP.4294967410"
APP_SECRET = "3aRNUwWahjyANa7WfBK2wCCkxCexB6nXxKJwXxfePvzf"
ATTRS_URL = "/v2/binding/enduserapi/getDeviceBusinessAttributes"
LOGIN_URL = "/v2/enduser/enduserapi/emailPwdLogin"


def _aes_cbc_b64(plaintext: str, key: str, iv: str) -> str:
    padder = padding.PKCS7(128).padder()
    data = padder.update(plaintext.encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode())).encryptor()
    return base64.encodebytes(enc.update(data) + enc.finalize()).decode()


def _headers(token: str | None = None) -> dict[str, str]:
    headers = {
        "X-Q-Language": "en",
        "quec-random-url": str(uuid.uuid4()),
        "app-info": "[Pixel][Google][raven][33]",
    }
    if token:
        headers["Authorization"] = token
    return headers


def _request(url: str, token: str | None = None, data: bytes | None = None,
             content_type: str | None = None) -> tuple[int, str]:
    req = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET")
    for key, value in _headers(token).items():
        req.add_header(key, value)
    if content_type:
        req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


class CloudPoller:
    def __init__(self, root: Path, cfg: dict, on_attrs) -> None:
        self.root = root
        self.cfg = cfg
        self.on_attrs = on_attrs
        self.creds = json.loads((root / ".secrets" / "cloud.json").read_text(encoding="utf-8"))
        station = json.loads((root / ".secrets" / "authkey.json").read_text(encoding="utf-8"))
        self.base = self.creds.get("base") or station.get("base") or "https://iot-api.quecteleu.com"
        self.pk = station["pk"]
        self.dk = station["dk"]
        self.token: str | None = None
        self.stop_event = threading.Event()

    def start(self) -> None:
        threading.Thread(target=self._run, name="cloud", daemon=True).start()

    def stop(self) -> None:
        self.stop_event.set()

    def _run(self) -> None:
        backoff = 1
        while not self.stop_event.is_set():
            try:
                if not self.token:
                    self.token = self._login()
                attrs = self._fetch_attrs()
                if attrs is not None:
                    self.on_attrs(attrs, time.time())
                    log.debug("cloud attrs: %s", {k: attrs[k] for k in (14, 20, 28) if k in attrs})
                backoff = 1
                if self.stop_event.wait(self.cfg.get("cloud_poll_seconds", 300)):
                    break
            except urllib.error.URLError as exc:
                log.warning("cloud network error: %s", exc)
                if self.stop_event.wait(backoff):
                    break
                backoff = min(backoff * 2, 900)
            except Exception as exc:
                log.warning("cloud poll failed: %s", exc)
                self.token = None
                if self.stop_event.wait(backoff):
                    break
                backoff = min(backoff * 2, 900)

    def _login(self) -> str | None:
        email = self.creds.get("email", "")
        password = self.creds.get("password", "")
        if not email or not password:
            raise RuntimeError("cloud credentials are empty")
        rnd = "".join(secrets.choice(
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") for _ in range(16))
        md5u = hashlib.md5(rnd.encode()).hexdigest().upper()
        key = md5u[8:24]
        iv = key[8:16] + key[0:8]
        encpwd = _aes_cbc_b64(password, key, iv)
        signature = hashlib.sha256((email + encpwd + rnd + APP_SECRET).encode()).hexdigest()
        fields = {
            "pwd": encpwd,
            "email": email,
            "random": rnd,
            "userDomain": USER_DOMAIN,
            "signature": signature,
        }
        status, body = _request(
            self.base + LOGIN_URL,
            data=urllib.parse.urlencode(fields).encode(),
            content_type="application/x-www-form-urlencoded",
        )
        if status != 200:
            raise RuntimeError(f"login HTTP {status}")
        payload = json.loads(body)
        token = ((payload.get("data") or {}).get("accessToken") or {}).get("token")
        if not token:
            raise RuntimeError("login response has no token")
        log.info("cloud login ok")
        return token

    def _fetch_attrs(self) -> dict[int, object] | None:
        url = self.base + ATTRS_URL + "?" + urllib.parse.urlencode({"pk": self.pk, "dk": self.dk})
        status, body = _request(url, token=self.token)
        if status in (401, 403):
            log.info("cloud token expired")
            self.token = None
            return None
        if status != 200:
            raise RuntimeError(f"attrs HTTP {status}")
        payload = json.loads(body)
        code = payload.get("code")
        if code not in (None, 0, 200):
            raise RuntimeError(f"attrs API code {code}: {payload.get('msg')}")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise RuntimeError("attrs response has no data")
        attrs: dict[int, object] = {}
        for item in data.get("customizeTslInfo") or []:
            ab_id = item.get("abId")
            if ab_id is None:
                continue
            attrs[int(ab_id)] = item.get("resourceValce", item.get("resourceValue"))
        if not attrs:
            raise RuntimeError("attrs response is empty")
        return attrs
