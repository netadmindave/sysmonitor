"""Shared configuration, logging, database and state helpers."""
import datetime as dt
import os
import shutil
import sqlite3
import threading

import yaml

VERSION = "1.0.0"
CONFIG_PATH = os.environ.get("SYSMONITOR_CONFIG", "/config/config.yaml")
DEFAULT_CONFIG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.default.yaml")

SEV = {"ok": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
LEVEL_NAMES = {"emerg": 0, "alert": 1, "crit": 2, "critical": 2, "err": 3, "error": 3,
               "warning": 4, "warn": 4, "notice": 5, "info": 6, "debug": 7}

CFG = {}
STATE = {}                  # latest poller results, shared between threads (whole values replaced)
STATE_LOCK = threading.Lock()


def load_config():
    if not os.path.exists(CONFIG_PATH):
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        shutil.copy(DEFAULT_CONFIG, CONFIG_PATH)
        log("main", f"no config found; wrote default to {CONFIG_PATH} (edit it and restart)")
    with open(CONFIG_PATH) as f:
        CFG.clear()
        CFG.update(yaml.safe_load(f) or {})
    return CFG


def log(component, msg):
    print(f"[sysmonitor {dt.datetime.now():%Y-%m-%d %H:%M:%S} {component}] {msg}", flush=True)


def connect():
    c = sqlite3.connect(CFG["db"], timeout=30, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    return c


def iso(ts):
    """Timezone-aware ISO timestamp (what Home Assistant expects for timestamp sensors)."""
    return dt.datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds") if ts else None


def worst(severities):
    best = "ok"
    for s in severities:
        if SEV.get(s, 0) > SEV[best]:
            best = s
    return best


def set_state(key, value):
    with STATE_LOCK:
        STATE[key] = value


def get_state(key, default=None):
    with STATE_LOCK:
        return STATE.get(key, default)
