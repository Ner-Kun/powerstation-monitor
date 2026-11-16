#!/usr/bin/env python3
"""Windows tray client for the local station monitor."""
from __future__ import annotations

import ctypes
import json
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

import pystray
from PIL import Image, ImageDraw
from winotify import Notification

CONFIG_PATH = Path(__file__).with_name("config.json")
BASE = (
    json.loads(CONFIG_PATH.read_text(encoding="utf-8"))["base_url"]
    if CONFIG_PATH.exists()
    else "http://192.168.1.50:8765"
)
COLORS = {
    "grid": (56, 217, 150),
    "full": (56, 217, 150),
    "on_battery": (255, 92, 108),
    "not_charging": (255, 184, 77),
    "offline": (143, 163, 196),
    "unknown": (143, 163, 196),
}
state: dict = {}
state_lock = threading.Lock()
stop = threading.Event()
icon: pystray.Icon | None = None


def tray_image(status: str) -> Image.Image:
    color = COLORS.get(status, COLORS["unknown"])
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse((4, 4, 60, 60), fill=color)
    draw.polygon([(36, 10), (20, 38), (31, 38), (28, 54), (46, 24), (35, 24)], fill=(10, 15, 26))
    return img


def notify(title: str, message: str) -> None:
    try:
        Notification(app_id="Station Monitor", title=title, msg=message, duration="short").show()
    except Exception:
        pass


def tooltip(s: dict) -> str:
    if not s:
        return "Станція: немає даних"
    return (
        f"{s.get('status_text', 'Станція')} | "
        f"{round(s.get('battery') or 0)}% | "
        f"вхід {round(s.get('input_w') or 0)} Вт | "
        f"вихід {round(s.get('output_w') or 0)} Вт"
    )


def set_state(s: dict) -> None:
    global state
    with state_lock:
        state = s
    if icon is not None:
        icon.icon = tray_image(s.get("status", "unknown"))
        icon.title = tooltip(s)


def open_panel() -> None:
    webbrowser.open(BASE + "/")


def show_status() -> None:
    with state_lock:
        s = dict(state)
    notify("Станція", tooltip(s))


def quit_app() -> None:
    stop.set()
    if icon is not None:
        icon.stop()


def parse_sse(resp) -> None:
    event = None
    for raw in resp:
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            payload = line[5:].strip()
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if event == "state":
                set_state(data)
            elif event == "alert":
                notify(data.get("title", "Станція"), data.get("message", ""))
        elif line == "":
            event = None


def stream_loop() -> None:
    backoff = 1
    while not stop.is_set():
        started = time.monotonic()
        try:
            req = urllib.request.Request(BASE + "/events")
            with urllib.request.urlopen(req, timeout=30) as resp:
                parse_sse(resp)
            if time.monotonic() - started > 5:
                backoff = 1
            elif stop.wait(backoff):
                break
            else:
                backoff = min(backoff * 2, 30)
        except (urllib.error.URLError, TimeoutError, OSError):
            set_state({"status": "offline", "status_text": "Немає зв’язку з сервером"})
            if stop.wait(backoff):
                break
            backoff = min(backoff * 2, 30)


def main() -> None:
    global icon
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    mutex = kernel32.CreateMutexW(None, False, "Local\\StationMonitorTray")
    if ctypes.get_last_error() == 183:
        return
    icon = pystray.Icon(
        "station",
        tray_image("offline"),
        "Станція: підключення…",
        pystray.Menu(
            pystray.MenuItem("Відкрити панель", lambda: open_panel(), default=True),
            pystray.MenuItem("Показати статус", lambda: show_status()),
            pystray.MenuItem("Завершити", lambda: quit_app()),
        ),
    )
    threading.Thread(target=stream_loop, name="sse", daemon=True).start()
    icon.run()


if __name__ == "__main__":
    main()
