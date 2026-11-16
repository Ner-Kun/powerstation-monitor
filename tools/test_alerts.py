#!/usr/bin/env python3
"""Exercise the alert state machine with synthetic states."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import monitor

cfg = json.loads((Path(__file__).resolve().parent.parent / "config.json").read_text(encoding="utf-8"))
cfg["not_charging_seconds"] = 0.15
cfg["grid_off_seconds"] = 0.05
cfg["telemetry_timeout_seconds"] = 0.1

alerts: list[dict] = []
engine = monitor.AlertEngine(cfg, alerts.append)


def state(**overrides):
    base = {
        "online": True,
        "grid": True,
        "charging": False,
        "battery": 90,
        "input_w": 300,
        "output_w": 400,
        "ac_input_w": 0,
        "remaining_h": 4.0,
    }
    base.update(overrides)
    return base


engine.update(state(battery=100))
engine.startup_until = 0
time.sleep(0.02)

engine.update(state(battery=90))
time.sleep(0.18)
engine.update(state(battery=90))

engine.update(state(grid=False, battery=89))
engine.update(state(grid=True, battery=89, ac_input_w=200, charging=True))

engine.update(state(grid=True, battery=15, ac_input_w=200, charging=True))
engine.update(state(grid=True, battery=15, ac_input_w=0, charging=False))

engine.update(state(online=False))
time.sleep(0.12)
engine.update(state(online=False))

print(json.dumps(alerts, ensure_ascii=False, indent=2))
