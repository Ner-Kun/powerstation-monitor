#!/usr/bin/env python3
"""One-time Wonderfree cloud login: fetch the station authKey and product TSL.

Credentials come from QUECTEL_EMAIL / QUECTEL_PASSWORD. The authKey is written
to .secrets/authkey.json and never printed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parent.parent
SECRETS = ROOT / ".secrets"
SECRETS.mkdir(parents=True, exist_ok=True)

BASES = [
    "https://iot-api.quecteleu.com",
    "https://iot-api.acceleronix.io",
]
USER_DOMAIN = "E.SP.4294967410"
APP_SECRET = "3aRNUwWahjyANa7WfBK2wCCkxCexB6nXxKJwXxfePvzf"


def aes_cbc_b64(plaintext: str, key: str, iv: str) -> str:
    padder = padding.PKCS7(128).padder()
    data = padder.update(plaintext.encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode())).encryptor()
    return base64.encodebytes(enc.update(data) + enc.finalize()).decode()


def headers(token: str | None = None) -> dict[str, str]:
    h = {
        "X-Q-Language": "en",
        "quec-random-url": str(uuid.uuid4()),
        "app-info": "[Pixel][Google][raven][33]",
    }
    if token:
        h["Authorization"] = token
    return h


def request(url: str, *, data: bytes | None = None, token: str | None = None,
            content_type: str | None = None) -> tuple[int, str]:
    req = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET")
    for key, value in headers(token).items():
        req.add_header(key, value)
    if content_type:
        req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def api_message(body: str) -> str:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return body[:200]
    return f"code={payload.get('code')} msg={payload.get('msg')}"


def login(base: str, email: str, password: str) -> str | None:
    rnd = "".join(secrets.choice(
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") for _ in range(16))
    md5u = hashlib.md5(rnd.encode()).hexdigest().upper()
    key = md5u[8:24]
    iv = key[8:16] + key[0:8]
    encpwd = aes_cbc_b64(password, key, iv)
    signature = hashlib.sha256((email + encpwd + rnd + APP_SECRET).encode()).hexdigest()
    fields = {
        "pwd": encpwd,
        "email": email,
        "random": rnd,
        "userDomain": USER_DOMAIN,
        "signature": signature,
    }
    status, body = request(
        base + "/v2/enduser/enduserapi/emailPwdLogin",
        data=urllib.parse.urlencode(fields).encode(),
        content_type="application/x-www-form-urlencoded",
    )
    print(f"[login] {base} HTTP {status}")
    if status != 200:
        print(f"[login] {api_message(body)}")
        return None
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        print("[login] response is not JSON")
        return None
    token = ((payload.get("data") or {}).get("accessToken") or {}).get("token")
    if not token:
        print(f"[login] {api_message(body)}")
    return token


def get_devices(base: str, token: str) -> list[dict]:
    url = base + "/v2/binding/enduserapi/userDeviceList?" + urllib.parse.urlencode(
        {"pageNumber": "1", "pageSize": "50"})
    status, body = request(url, token=token)
    print(f"[devices] HTTP {status}")
    if status != 200:
        return []
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return []
    data = payload.get("data") or {}
    if isinstance(data, dict):
        return data.get("list") or []
    if isinstance(data, list):
        return data
    return []


def get_authkey(base: str, token: str, pk: str, dk: str) -> str | None:
    url = base + "/v2/binding/enduserapi/regenerateAuthKey"
    attempts = [
        ("json", url, json.dumps({"pk": pk, "dk": dk}).encode(), "application/json"),
        ("form", url, urllib.parse.urlencode({"pk": pk, "dk": dk}).encode(),
         "application/x-www-form-urlencoded"),
        ("form-product", url,
         urllib.parse.urlencode({"productKey": pk, "deviceKey": dk}).encode(),
         "application/x-www-form-urlencoded"),
        ("query", url + "?" + urllib.parse.urlencode({"pk": pk, "dk": dk}), None, None),
        ("query-product", url + "?" + urllib.parse.urlencode(
            {"productKey": pk, "deviceKey": dk}), None, None),
    ]
    for name, url, data, ctype in attempts:
        status, body = request(url, data=data, token=token, content_type=ctype)
        print(f"[authKey:{name}] HTTP {status}")
        if status != 200:
            print(f"[authKey:{name}] {api_message(body)}")
            continue
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            print(f"[authKey:{name}] response is not JSON")
            continue
        data_obj = payload.get("data") or payload
        key = data_obj.get("authKey") or data_obj.get("authkey")
        if key:
            return key
        print(f"[authKey:{name}] {api_message(body)}")
    return None


def get_tsl(base: str, token: str, pk: str) -> dict | None:
    url = base + "/v2/binding/enduserapi/productTSL?" + urllib.parse.urlencode({"pk": pk})
    status, body = request(url, token=token)
    print(f"[tsl] HTTP {status}")
    if status != 200:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch the station authKey from Wonderfree cloud")
    parser.add_argument("--pk", default=os.environ.get("QUECTEL_PK", ""),
                        help="productKey (optional if the account has one device)")
    parser.add_argument("--dk", default=os.environ.get("QUECTEL_DK", ""),
                        help="deviceKey/MAC (optional if the account has one device)")
    args = parser.parse_args()
    email = os.environ.get("QUECTEL_EMAIL", "").strip()
    password = os.environ.get("QUECTEL_PASSWORD", "")
    if not email or not password:
        print("QUECTEL_EMAIL / QUECTEL_PASSWORD are not set", file=sys.stderr)
        return 2

    token = None
    base = BASES[0]
    for candidate in BASES:
        token = login(candidate, email, password)
        if token:
            base = candidate
            break
    if not token:
        print("login failed on all regions", file=sys.stderr)
        return 1

    devices = get_devices(base, token)
    if not devices:
        print("no devices in the account", file=sys.stderr)
        return 1

    target = None
    for device in devices:
        pk = device.get("pk") or device.get("productKey")
        dk = device.get("dk") or device.get("deviceKey")
        name = device.get("deviceName") or device.get("name")
        print(f"[device] pk={pk} dk={dk} name={name}")
        if args.pk and args.dk and pk == args.pk and str(dk).lower().replace(":", "") == args.dk.lower().replace(":", ""):
            target = device
    if target is None:
        if len(devices) == 1 and not args.pk and not args.dk:
            target = devices[0]
        else:
            print("pass --pk and --dk (see the list above)", file=sys.stderr)
            return 2

    pk = target.get("pk") or target.get("productKey")
    dk = str(target.get("dk") or target.get("deviceKey")).lower().replace(":", "")
    authkey = get_authkey(base, token, pk, dk)
    if not authkey:
        authkey = target.get("authKey") or target.get("authkey")
        if authkey:
            print("[authKey] falling back to the copy from userDeviceList")
    if not authkey:
        return 1

    tsl = get_tsl(base, token, pk)
    out = {
        "pk": pk,
        "dk": dk,
        "base": base,
        "authKey": authkey,
        "deviceName": target.get("deviceName") or target.get("name"),
    }
    (SECRETS / "authkey.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    os.chmod(SECRETS / "authkey.json", 0o600)
    if tsl:
        (ROOT / f"tsl_{pk}.json").write_text(json.dumps(tsl, indent=2), encoding="utf-8")
    print(f"[ok] authKey saved ({len(authkey)} chars), tsl={'yes' if tsl else 'no'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
