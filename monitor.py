#!/usr/bin/env python3
"""Station monitor: local telemetry, alerts, SSE API and PWA."""
from __future__ import annotations

import json
import logging
import queue
import signal
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from cloud import CloudPoller
from station import StationClient

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
log = logging.getLogger("monitor")


def load_config() -> dict:
    with (ROOT / "config.json").open(encoding="utf-8") as fh:
        return json.load(fh)


def load_authkey(path: str) -> str:
    data = json.loads((ROOT / path).read_text(encoding="utf-8"))
    return data["authKey"]


def fmt_duration(hours: float | None) -> str:
    if hours is None:
        return "—"
    total_min = max(0, int(round(hours * 60)))
    days, rem = divmod(total_min, 1440)
    h, m = divmod(rem, 60)
    if days:
        return f"{days} д {h} год"
    if h:
        return f"{h} год {m} хв"
    return f"{m} хв"


def cloud_json_field(value, key: str):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return None
    if isinstance(value, dict):
        return value.get(key)
    return None


class PowerTracker:
    """Tracks whether grid input covers the load; a short surge is not an outage."""

    def __init__(
        self,
        min_input_w: float,
        min_output_w: float,
        margin_w: float,
        margin_pct: float,
        initial_seconds: float,
        battery_seconds: float,
        grid_seconds: float,
    ) -> None:
        self.min_input_w = min_input_w
        self.min_output_w = min_output_w
        self.margin_w = margin_w
        self.margin_pct = margin_pct
        self.initial_seconds = initial_seconds
        self.battery_seconds = battery_seconds
        self.grid_seconds = grid_seconds
        self.state: str | None = None  # "grid" | "battery"
        self.bad_since: float | None = None
        self.good_since: float | None = None

    def update(self, input_w: float, output_w: float, now: float) -> str | None:
        if output_w <= self.min_output_w:
            return self.state
        shortfall = output_w - input_w
        threshold = max(self.margin_w, output_w * self.margin_pct)
        bad = input_w < self.min_input_w or shortfall > threshold
        good = input_w >= self.min_input_w and shortfall <= threshold

        if self.state is None:
            if bad:
                self.good_since = None
                if self.bad_since is None:
                    self.bad_since = now
                elif now - self.bad_since >= self.initial_seconds:
                    self.state = "battery"
                    self.bad_since = None
            elif good:
                self.bad_since = None
                if self.good_since is None:
                    self.good_since = now
                elif now - self.good_since >= self.initial_seconds:
                    self.state = "grid"
                    self.good_since = None
            return self.state

        if bad:
            self.good_since = None
            if self.state != "battery":
                if self.bad_since is None:
                    self.bad_since = now
                elif now - self.bad_since >= self.battery_seconds:
                    self.state = "battery"
                    self.bad_since = None
        elif good:
            self.bad_since = None
            if self.state != "grid":
                if self.good_since is None:
                    self.good_since = now
                elif now - self.good_since >= self.grid_seconds:
                    self.state = "grid"
                    self.good_since = None
        return self.state


class AlertEngine:
    def __init__(self, cfg: dict, publish) -> None:
        self.cfg = cfg
        self.publish = publish
        self.initialized = False
        self.startup_until = 0.0
        self.startup_on_battery = False
        self.startup_alerted = False
        self.last_grid: bool | None = None
        self.last_charging = False
        self.not_charging_since: float | None = None
        self.not_charging_alerted = False
        self.low_battery_alerted: set[int] = set()
        self.offline_since: float | None = None
        self.offline_alerted = False

    def update(self, state: dict) -> None:
        now = time.monotonic()
        grid = state.get("grid")
        charging = bool(state.get("charging"))
        battery = state.get("battery")
        online = bool(state.get("online"))
        output_w = state.get("output_w") or 0

        if not self.initialized:
            if online and battery is not None:
                self.initialized = True
                self.startup_until = now + 10
                self.startup_on_battery = grid is False and output_w > 5
                self.last_grid = grid
                self.last_charging = charging
                self.not_charging_since = None
                self.not_charging_alerted = False
            return

        if now < self.startup_until:
            self.last_grid = grid
            self.last_charging = charging
            return

        if self.startup_on_battery and not self.startup_alerted:
            self.startup_alerted = True
            self.startup_on_battery = False
            if grid is False and output_w > 5:
                self._alert_grid_lost(state)

        grid_returned_now = False
        if grid is not None and self.last_grid is not None:
            if self.last_grid and not grid:
                self._alert_grid_lost(state)
            elif not self.last_grid and grid:
                self._alert_grid_back(state)
                grid_returned_now = True
        elif grid is False and self.last_grid is None and output_w > 5:
            self._alert_grid_lost(state)
        self.last_grid = grid

        if (
            charging
            and not self.last_charging
            and battery is not None
            and battery < 99
            and not grid_returned_now
            and grid is True
        ):
            self._alert(
                "Заряджання почалося",
                f"Заряд {battery:.0f}%, вхід {state.get('ac_input_w') or 0:.0f} Вт.",
                3,
                ["electric_plug"],
            )
        self.last_charging = charging

        threshold = float(self.cfg["not_charging_battery_pct"])
        if (
            online
            and grid
            and not charging
            and battery is not None
            and battery < threshold
        ):
            if self.not_charging_since is None:
                self.not_charging_since = now
            elif (
                not self.not_charging_alerted
                and now - self.not_charging_since >= self.cfg["not_charging_seconds"]
            ):
                self.not_charging_alerted = True
                self._alert(
                    "Світло є, але станція не заряджається",
                    (
                        f"Заряд {battery:.0f}%, вхід {state.get('input_w') or 0:.0f} Вт, "
                        f"заряджання {state.get('ac_input_w') or 0:.0f} Вт. "
                        f"Так уже {int(self.cfg['not_charging_seconds'] // 60)} хв."
                    ),
                    4,
                    ["warning", "battery"],
                )
        else:
            self.not_charging_since = None
            self.not_charging_alerted = False

        if battery is not None:
            levels = (int(self.cfg["low_battery_pct"]), 10, 5)
            crossed = [
                level for level in levels
                if battery <= level and level not in self.low_battery_alerted
            ]
            if crossed:
                self.low_battery_alerted.update(crossed)
                remaining = state.get("remaining_h")
                suffix = f", приблизно {fmt_duration(remaining)}" if remaining else ""
                self._alert(
                    "Мало заряду",
                    f"Залишилося {battery:.0f}%{suffix}.",
                    4,
                    ["battery", "warning"],
                )
            for level in levels:
                if battery > level + 5:
                    self.low_battery_alerted.discard(level)

        if not online:
            if self.offline_since is None:
                self.offline_since = now
            elif not self.offline_alerted and now - self.offline_since >= 30:
                self.offline_alerted = True
                if state.get("link") == "up":
                    self._alert(
                        "Станція не надсилає дані",
                        "З'єднання зі станцією є, але телеметрії немає. Найчастіше "
                        "станція втратила зв'язок з хмарою Quectel — перевір її інтернет. "
                        "Не помогло — вимкни станцію і ввімкни знову.",
                        4,
                        ["warning"],
                    )
                else:
                    self._alert(
                        "Станція не відповідає",
                        "Немає зв'язку зі станцією. Перевір Wi-Fi і живлення.",
                        4,
                        ["warning"],
                    )
        else:
            self.offline_since = None
            self.offline_alerted = False

    def _alert_grid_lost(self, state: dict) -> None:
        battery = state.get("battery")
        battery_text = f"Заряд {battery:.0f}%, " if battery is not None else ""
        remaining = state.get("remaining_h")
        remaining_text = (
            f"залишилося приблизно {fmt_duration(remaining)}." if remaining else "запас невідомий."
        )
        self._alert(
            "Станція на батареї",
            (
                f"Вхід {state.get('input_w') or 0:.0f} Вт, вихід {state.get('output_w') or 0:.0f} Вт. "
                f"Батарея розряджається. Якщо світло є — зарядник не тягне "
                f"(низька/висока напруга). {battery_text}{remaining_text}"
            ),
            5,
            ["rotating_light", "battery"],
        )

    def _alert_grid_back(self, state: dict) -> None:
        message = f"Вхід {state.get('input_w') or 0:.0f} Вт, заряд {state.get('battery') or 0:.0f}%."
        if state.get("charging"):
            message += " Заряджання триває."
        self._alert("Станція знову на мережі", message, 3, ["electric_plug"])

    def _alert(self, title: str, message: str, priority: int, tags: list[str]) -> None:
        self.publish(
            {
                "title": title,
                "message": message,
                "priority": priority,
                "tags": tags,
            }
        )


class History:
    def __init__(self, path: Path, interval: int, retention_days: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL").fetchone()
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS samples (
                ts INTEGER PRIMARY KEY,
                battery REAL,
                input_w REAL,
                output_w REAL,
                ac_input_w REAL,
                temp_c REAL,
                grid INTEGER,
                remaining_h REAL
            )
            """
        )
        self.conn.commit()
        self.lock = threading.Lock()
        self.interval = interval
        self.retention_days = retention_days
        self.last_insert = 0.0
        self.last_prune = 0.0
        self._pending = 0
        self._last_commit = 0.0

    def add(self, state: dict) -> None:
        now = time.time()
        with self.lock:
            if now - self.last_insert < self.interval:
                return
            self.last_insert = now
            self.conn.execute(
                "INSERT OR REPLACE INTO samples (ts, battery, input_w, output_w, ac_input_w, temp_c, grid, remaining_h) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    int(now),
                    state.get("battery"),
                    state.get("input_w"),
                    state.get("output_w"),
                    state.get("ac_input_w"),
                    state.get("temp_c"),
                    None if state.get("grid") is None else int(bool(state.get("grid"))),
                    state.get("remaining_h"),
                ),
            )
            self._pending += 1
            if self._pending >= 6 or now - self._last_commit >= 60:
                self.conn.commit()
                self._pending = 0
                self._last_commit = now
        if now - self.last_prune > 3600:
            self.last_prune = now
            self.prune()

    def prune(self) -> None:
        cutoff = int(time.time()) - self.retention_days * 86400
        with self.lock:
            self.conn.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))
            self.conn.commit()
            self._pending = 0
            self._last_commit = time.time()

    def query(self, hours: int) -> list[dict]:
        cutoff = int(time.time()) - hours * 3600
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT CAST(ts / 60 AS INTEGER) * 60 AS bucket,
                       AVG(battery), AVG(input_w), AVG(output_w), AVG(ac_input_w),
                       AVG(temp_c), MAX(grid)
                FROM samples
                WHERE ts >= ?
                GROUP BY bucket
                ORDER BY bucket
                """,
                (cutoff,),
            ).fetchall()
        return [
            {
                "ts": row[0],
                "battery": row[1],
                "input_w": row[2],
                "output_w": row[3],
                "ac_input_w": row[4],
                "temp_c": row[5],
                "grid": None if row[6] is None else bool(row[6]),
            }
            for row in rows
        ]

    def close(self) -> None:
        with self.lock:
            self.conn.commit()
            self.conn.close()


class StateStore:
    def __init__(self) -> None:
        self.state: dict = {}
        self.lock = threading.Lock()
        self.subscribers: set[queue.Queue] = set()

    def update(self, state: dict) -> None:
        with self.lock:
            self.state = state

    def get(self) -> dict:
        with self.lock:
            return dict(self.state)

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=100)
        with self.lock:
            self.subscribers.add(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self.lock:
            self.subscribers.discard(q)

    def broadcast(self, event: str, data: dict) -> None:
        with self.lock:
            subscribers = list(self.subscribers)
        payload = (event, data)
        for q in subscribers:
            try:
                q.put_nowait(payload)
            except queue.Full:
                try:
                    q.get_nowait()
                    q.put_nowait(payload)
                except (queue.Empty, queue.Full):
                    pass


def publish_ntfy(cfg: dict, alert: dict) -> None:
    body = json.dumps(
        {
            "topic": cfg["ntfy_topic"],
            "title": alert["title"],
            "message": alert["message"],
            "priority": alert.get("priority", 3),
            "tags": alert.get("tags", []),
        }
    ).encode("utf-8")
    req = urllib.request.Request(cfg["ntfy_url"], data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        log.warning("ntfy publish failed: %s", exc)


def derive_state(
    state: dict,
    cfg: dict,
    power_state: str | None,
    cloud: dict[int, object] | None = None,
    cloud_updated_at: float = 0.0,
    cloud_device_at: float = 0.0,
) -> dict:
    now = time.time()
    cloud = cloud or {}
    last_report = state.get("last_report") or 0
    online = bool(state.get("online")) and (now - last_report <= cfg["telemetry_timeout_seconds"])
    battery = state.get("battery")
    input_w = state.get("input_w") or 0
    output_w = state.get("output_w") or 0
    # The station sometimes reports a kilowatt burst on an idle port. The per-port
    # breakdown stays sane, so prefer it when the total does not add up.
    port_w = [
        value
        for value in (
            state.get("ac_out_w"),
            state.get("usb1_w"),
            state.get("usb2_w"),
            state.get("typec1_w"),
            state.get("typec2_w"),
            state.get("dc_out_w"),
        )
        if isinstance(value, (int, float))
    ]
    if port_w and output_w > sum(port_w) + max(150.0, sum(port_w) * 0.6):
        output_w = sum(port_w)
    ac_input_w = state.get("ac_input_w") or 0
    dc_input_w = state.get("dc_input_w") or 0
    charging = ac_input_w >= 5 or dc_input_w >= 5
    grid_present = True if power_state == "grid" else False if power_state == "battery" else None
    battery_discharging = power_state == "battery"
    battery_load_w = max(output_w - input_w, 0) if output_w > 0 else 0

    temp = state.get("temp_c")
    temp_source = "station" if temp is not None else None
    # The cloud keeps serving the last uploaded value forever, so only trust it
    # while the station itself was heard from recently.
    cloud_fresh = cloud_device_at > 0 and (now - cloud_device_at <= cfg.get("cloud_stale_seconds", 900))
    if temp is None and cloud_fresh and cloud.get(14) is not None:
        temp = cloud[14]
        temp_source = "cloud"
    charge_limit = state.get("charge_limit")
    if charge_limit is None:
        charge_limit = cloud.get(20)
    voltage_setting = state.get("voltage_setting")
    if voltage_setting is None:
        voltage_setting = cloud.get(28)
    led = state.get("led")
    if led is None:
        led = cloud.get(10)
    ac_out_w = state.get("ac_out_w")
    if ac_out_w is None:
        ac_out_w = cloud_json_field(cloud.get(6), "ac1_output")
    dc_out_w = state.get("dc_out_w")
    if dc_out_w is None:
        dc_out_w = cloud_json_field(cloud.get(9), "car1_output")
    inverter_version = state.get("inverter_version")
    if inverter_version is None:
        inverter_version = cloud.get(31)
    bms_version = state.get("bms_version")
    if bms_version is None:
        bms_version = cloud.get(34)
    frequency = state.get("frequency")
    if frequency is None:
        frequency = cloud.get(27)

    if not online:
        remaining_h = None
        remaining_kind = "unknown"
        remaining_text = "—"
    elif battery_discharging and battery is not None and battery_load_w > 5:
        remaining_h = cfg["capacity_wh"] * (battery / 100.0) * cfg["efficiency"] / battery_load_w
        remaining_kind = "discharge"
        remaining_text = fmt_duration(remaining_h)
    elif charging:
        remaining_h = None
        remaining_kind = "charging"
        remaining_text = "заряджається"
    elif power_state == "grid":
        remaining_h = None
        remaining_kind = "grid"
        remaining_text = "на мережі"
    else:
        remaining_h = None
        remaining_kind = "unknown"
        remaining_text = "—"

    if not online:
        status = "offline"
        status_text = "Немає даних" if state.get("link") != "up" else "Станція не надсилає дані"
    elif battery_discharging:
        status = "on_battery"
        status_text = "На батареї"
    elif (
        power_state == "grid"
        and not charging
        and battery is not None
        and battery < cfg["not_charging_battery_pct"]
    ):
        status = "not_charging"
        status_text = "Світло є, заряджання немає"
    elif battery is not None and battery >= 99:
        status = "full"
        status_text = "Повний заряд"
    elif power_state == "grid":
        status = "grid"
        status_text = "Мережа є"
    else:
        status = "unknown"
        status_text = "Невідомо"

    result = dict(state)
    result.update(
        {
            "online": online,
            "grid": grid_present,
            "battery_load_w": battery_load_w,
            "charging": charging,
            "input_w": input_w,
            "output_w": output_w,
            "status": status,
            "status_text": status_text,
            "link": state.get("link"),
            "remaining_h": remaining_h,
            "remaining_kind": remaining_kind,
            "remaining_text": remaining_text,
            "temp_c": temp,
            "temp_source": temp_source,
            "charge_limit": charge_limit,
            "voltage_setting": voltage_setting,
            "led": led,
            "ac_out_w": ac_out_w,
            "dc_out_w": dc_out_w,
            "inverter_version": inverter_version,
            "bms_version": bms_version,
            "frequency": frequency,
            "cloud_updated_at": cloud_updated_at,
            "cloud_last_seen": cloud_device_at or None,
            "updated_at": now,
        }
    )
    return result


def make_handler(store: StateStore, history: History, publish):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, fmt, *args):
            log.debug("%s - %s", self.address_string(), fmt % args)

        def do_POST(self):
            if urlparse(self.path).path == "/api/test-alert":
                publish(
                    {
                        "title": "Тест сповіщення",
                        "message": "Якщо ти це бачиш, сповіщення працюють.",
                        "priority": 3,
                        "tags": ["white_check_mark"],
                    }
                )
                return self._json({"ok": True})
            self.send_error(404)

        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/events":
                return self._sse()
            if path == "/api/state":
                return self._json(store.get())
            if path == "/api/history":
                hours = 24
                try:
                    hours = max(1, min(168, int(parse_qs(parsed.query).get("hours", ["24"])[0])))
                except ValueError:
                    pass
                return self._json({"points": history.query(hours)})
            if path == "/api/health":
                state = store.get()
                return self._json({"ok": True, "status": state.get("status"), "online": state.get("online")})
            return self._static(path)

        def _json(self, data):
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _static(self, path: str):
            rel = "index.html" if path in ("", "/") else path.lstrip("/")
            target = (WEB / rel).resolve()
            try:
                target.relative_to(WEB.resolve())
            except ValueError:
                self.send_error(404)
                return
            if not target.is_file():
                self.send_error(404)
                return
            body = target.read_bytes()
            content_type = {
                ".html": "text/html; charset=utf-8",
                ".json": "application/json; charset=utf-8",
                ".js": "application/javascript; charset=utf-8",
                ".svg": "image/svg+xml",
                ".png": "image/png",
                ".css": "text/css; charset=utf-8",
            }.get(target.suffix.lower(), "application/octet-stream")
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header(
                "Cache-Control",
                "no-cache" if target.name in ("index.html", "sw.js") else "max-age=3600",
            )
            self.end_headers()
            self.wfile.write(body)

        def _sse(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            self.connection.settimeout(60)
            self.wfile.write(b"retry: 3000\n\n")
            self.wfile.flush()
            q = store.subscribe()
            try:
                self.wfile.write(
                    b"event: state\ndata: "
                    + json.dumps(store.get(), ensure_ascii=False).encode("utf-8")
                    + b"\n\n"
                )
                self.wfile.flush()
                while True:
                    try:
                        event, data = q.get(timeout=15)
                    except queue.Empty:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                        continue
                    self.wfile.write(
                        f"event: {event}\ndata: ".encode("utf-8")
                        + json.dumps(data, ensure_ascii=False).encode("utf-8")
                        + b"\n\n"
                    )
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                store.unsubscribe(q)

    return Handler


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stdout,
    )
    if not (ROOT / "config.json").is_file():
        print("config.json is missing: copy config.example.json and set station_host", file=sys.stderr)
        return 2
    cfg = load_config()
    try:
        authkey = load_authkey(cfg["authkey_file"])
    except (OSError, KeyError, ValueError):
        print(f"no authKey in {cfg['authkey_file']}: run tools/get_authkey.py first", file=sys.stderr)
        return 2
    store = StateStore()
    history = History(ROOT / cfg["history_db"], cfg["history_interval_seconds"], cfg["history_retention_days"])
    power = PowerTracker(
        cfg["power_min_input_w"],
        cfg["power_min_output_w"],
        cfg["power_margin_w"],
        cfg["power_margin_pct"],
        cfg["power_initial_seconds"],
        cfg["power_battery_seconds"],
        cfg["power_grid_seconds"],
    )

    outbox: queue.Queue = queue.Queue(maxsize=50)

    def publish(alert: dict) -> None:
        log.info("alert: %s — %s", alert["title"], alert["message"])
        store.broadcast("alert", alert)
        try:
            outbox.put_nowait(alert)
        except queue.Full:
            log.warning("ntfy queue full, alert dropped")

    def ntfy_worker() -> None:
        while True:
            alert = outbox.get()
            try:
                publish_ntfy(cfg, alert)
            except Exception:
                log.exception("ntfy publish failed")

    threading.Thread(target=ntfy_worker, name="ntfy", daemon=True).start()
    alerts = AlertEngine(cfg, publish)
    latest_station: dict = {}
    latest_cloud = {"attrs": {}, "updated_at": 0.0, "device_at": 0.0}
    latest_power = {"state": None}
    latest_lock = threading.Lock()
    recompute_lock = threading.Lock()

    def recompute() -> None:
        with recompute_lock:
            with latest_lock:
                station = dict(latest_station)
                cloud = dict(latest_cloud["attrs"])
                cloud_at = latest_cloud["updated_at"]
                cloud_device_at = latest_cloud["device_at"]
                power_state = latest_power["state"]
            derived = derive_state(station, cfg, power_state, cloud, cloud_at, cloud_device_at)
            alerts.update(derived)
            store.update(derived)
            store.broadcast("state", derived)
            history.add(derived)

    def on_state(state: dict) -> None:
        with latest_lock:
            latest_station.update(state)
            latest_power["state"] = power.update(
                state.get("input_w") or 0,
                state.get("output_w") or 0,
                time.monotonic(),
            )
        recompute()

    def on_cloud(attrs: dict, fetched_at: float, device_at: float) -> None:
        with latest_lock:
            latest_cloud["attrs"] = attrs
            latest_cloud["updated_at"] = fetched_at
            latest_cloud["device_at"] = device_at
        recompute()

    client = StationClient(
        cfg["station_host"],
        cfg["station_port"],
        authkey,
        on_state,
        stale_after=cfg.get("station_stale_seconds", 90),
    )
    client.start()

    cloud_poller = None
    if cfg.get("cloud_enabled", True) and (ROOT / ".secrets" / "cloud.json").exists():
        cloud_poller = CloudPoller(ROOT, cfg, on_cloud)
        cloud_poller.start()

    server = ThreadingHTTPServer(
        (cfg["http_host"], cfg["http_port"]), make_handler(store, history, publish)
    )
    server.daemon_threads = True
    log.info("HTTP on %s:%s", cfg["http_host"], cfg["http_port"])

    def stop(_signum=None, _frame=None):
        log.info("stopping")
        client.stop()
        if cloud_poller:
            cloud_poller.stop()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        stop()
    finally:
        server.server_close()
        history.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
