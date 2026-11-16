#!/usr/bin/env python3
"""One-time: verify cloud temperature access and store Wonderfree credentials."""
from __future__ import annotations

import json
import os
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import get_authkey as ga


def main() -> int:
    email = os.environ.get("QUECTEL_EMAIL", "").strip()
    password = os.environ.get("QUECTEL_PASSWORD", "")
    if not email or not password:
        print("QUECTEL_EMAIL / QUECTEL_PASSWORD are not set", file=sys.stderr)
        return 2

    station = json.loads((ga.SECRETS / "authkey.json").read_text(encoding="utf-8"))
    pk, dk = station["pk"], station["dk"]

    token = None
    base = ga.BASES[0]
    for candidate in ga.BASES:
        token = ga.login(candidate, email, password)
        if token:
            base = candidate
            break
    if not token:
        print("login failed", file=sys.stderr)
        return 1

    url = base + "/v2/binding/enduserapi/getDeviceBusinessAttributes?" + urllib.parse.urlencode(
        {"pk": pk, "dk": dk}
    )
    status, body = ga.request(url, token=token)
    print(f"[attrs] HTTP {status}")
    if status != 200:
        print(body[:800])
        return 1

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        print(body[:800])
        return 1

    payload = data.get("data") or {}
    attrs = payload.get("customizeTslInfo") or []
    print(f"[attrs] {len(attrs)} entries")
    found = []
    for item in attrs:
        ab_id = item.get("abId")
        if ab_id in (10, 14, 20, 28, 43, 46):
            value = item.get("resourceValce", item.get("resourceValue"))
            print(f"[attr] abId={ab_id} code={item.get('resourceCode')} value={value}")
            found.append(ab_id)

    cloud = {"email": email, "password": password, "base": base}
    target = ga.SECRETS / "cloud.json"
    target.write_text(json.dumps(cloud, indent=2), encoding="utf-8")
    os.chmod(target, 0o600)
    print(f"[ok] credentials saved to {target} (temp attr found: {14 in found})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
