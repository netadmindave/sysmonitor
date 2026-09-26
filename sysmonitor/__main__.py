"""SysMonitor entry point: python -m sysmonitor"""
import asyncio
import datetime as dt
import os
import queue
import signal
import sys
import threading
import time

from croniter import croniter

from . import digest, logs, pollers, publish, store
from .common import CFG, VERSION, connect, load_config, log, set_state


class Scheduler(threading.Thread):
    def __init__(self, mqtt):
        super().__init__(daemon=True, name="scheduler")
        self.mqtt = mqtt
        self.poll_netsentry_now = threading.Event()

    def run(self):
        c = connect()
        per_rule = {r["id"]: r["resolve_after_min"] for r in CFG.get("rules") or [] if r.get("resolve_after_min")}
        resolve_min = (CFG.get("issues") or {}).get("resolve_after_min", 60)
        pub_every = (CFG.get("mqtt") or {}).get("publish_every_s", 60)

        def poll(name, fn):
            try:
                data, issues = fn()
                set_state(name, data)
                if data is not None or issues:
                    store.sync_poller(c, name, issues)
            except Exception as e:
                log("poll", f"{name} failed: {e}")

        def publish_now():
            if self.mqtt:
                self.mqtt.publish(publish.snapshot(c))

        def prune():
            days = CFG.get("retention_days", 14)
            cut = time.time() - days * 86400
            c.execute("DELETE FROM events WHERE ts<?", (cut,))
            c.execute("DELETE FROM templates WHERE last_seen<?", (cut,))
            c.execute("DELETE FROM issues WHERE status='resolved' AND resolved_at<?", (time.time() - 30 * 86400,))
            c.execute("DELETE FROM digests WHERE ts<?", (time.time() - 90 * 86400,))
            c.commit()
            c.execute("PRAGMA optimize")

        tasks = [  # name, seconds, function
            ["netsentry", 300, lambda: poll("netsentry", pollers.netsentry)],
            ["unraid", 60, lambda: poll("unraid", pollers.unraid)],
            ["host", 60, lambda: poll("host", pollers.host)],
            ["docker", 300, lambda: poll("docker", pollers.docker)],
            ["sources", 60, lambda: store.sync_poller(c, "sources", pollers.silent_sources(c))],
            ["resolve", 60, lambda: store.resolve_stale(c, resolve_min, per_rule)],
            ["publish", pub_every, publish_now],
            ["prune", 3600, prune],
        ]
        for t in tasks:
            t.append(0)                                   # next run: immediately
        d = CFG.get("digest") or {}
        crons = {k: d.get(k) for k in ("hourly", "daily", "weekly") if d.get(k)}
        nxt = {k: croniter(v, dt.datetime.now()).get_next(float) for k, v in crons.items()}
        for k, v in crons.items():
            log("scheduler", f"{k} digest: '{v}', next {dt.datetime.fromtimestamp(nxt[k]):%Y-%m-%d %H:%M}")

        while True:
            now = time.time()
            if self.poll_netsentry_now.is_set():
                self.poll_netsentry_now.clear()
                tasks[0][3] = 0
                tasks[6][3] = min(tasks[6][3], now + 5)
            for t in tasks:
                if now >= t[3]:
                    try:
                        t[2]()
                    except Exception as e:
                        log("scheduler", f"{t[0]} failed: {e}")
                    t[3] = now + t[1]
            for k in list(nxt):
                if now >= nxt[k]:
                    threading.Thread(target=self._digest, args=(k,), daemon=True).start()
                    nxt[k] = croniter(crons[k], dt.datetime.now()).get_next(float)
            time.sleep(2)

    def _digest(self, kind):
        try:
            digest.run(kind)
            if self.mqtt:
                c = connect()
                self.mqtt.publish(publish.snapshot(c))
                c.close()
        except Exception as e:
            log("digest", f"{kind} failed: {e}")


def main():
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    load_config()
    log("main", f"SysMonitor {VERSION} starting")
    os.makedirs(os.path.dirname(CFG["db"]) or ".", exist_ok=True)
    c = connect()
    store.init(c)
    c.close()

    q = queue.Queue(maxsize=int((CFG.get("syslog") or {}).get("queue_max", 100000)))
    logs.Ingestor(q).start()

    mqtt = None
    if (CFG.get("mqtt") or {}).get("host"):
        mqtt = publish.Mqtt()
        mqtt.start()
    else:
        log("main", "MQTT not configured; Home Assistant entities disabled (HTTP API still available)")

    sched = Scheduler(mqtt)
    sched.start()
    publish.start_http(q, sched.poll_netsentry_now.set)

    if os.environ.get("RUN_DIGEST_ON_START", "false").lower() == "true":
        threading.Thread(target=sched._digest, args=("daily",), daemon=True).start()

    asyncio.run(logs.serve_syslog(q))


if __name__ == "__main__":
    main()
