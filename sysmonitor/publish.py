"""Home Assistant integration (MQTT discovery) and the HTTP API."""
import html
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from . import store
from .common import CFG, SEV, VERSION, connect, get_state, iso, log, worst


# ---------------------------------------------------------------- snapshot
def snapshot(c):
    now = time.time()
    issues = store.open_issues(c)
    counted = [i for i in issues if SEV.get(i["severity"], 0) > 0]
    by_sev = {s: sum(1 for i in counted if i["severity"] == s) for s in ("critical", "high", "medium", "low")}
    per_src = {r[0]: r[1] for r in c.execute(
        "SELECT src_ip, count(*) FROM events WHERE ts>=? GROUP BY src_ip", (now - 3600,))}
    sources = [{"name": r["name"], "ip": r["ip"], "last_seen": iso(r["last_seen"]),
                "minutes_ago": round((now - r["last_seen"]) / 60), "events_1h": per_src.get(r["ip"], 0)}
               for r in c.execute("SELECT * FROM sources ORDER BY last_seen DESC LIMIT 30")]
    ns = dict(get_state("netsentry") or {})
    ns.pop("names", None)
    return {
        "generated": iso(now),
        "status": worst(i["severity"] for i in counted),
        "issue_counts": by_sev,
        "issues": [{"severity": i["severity"], "title": i["title"], "category": i["category"],
                    "source": i["source"], "count": i["count"], "detail": (i["detail"] or "")[:200],
                    "since": iso(i["first_seen"]), "last": iso(i["last_seen"])} for i in issues],
        "log_rate": round(c.execute("SELECT count(*) FROM events WHERE ts>=?", (now - 300,)).fetchone()[0] / 5, 1),
        "errors_1h": c.execute("SELECT count(*) FROM events WHERE ts>=? AND level<=3", (now - 3600,)).fetchone()[0],
        "sources": sources,
        "netsentry": ns or None,
        "unraid": get_state("unraid"),
        "host": get_state("host"),
        "docker": get_state("docker"),
        "digest": get_state("digest"),
    }


# ---------------------------------------------------------------- MQTT
def _na(v):
    return "None" if v is None else v        # "None" = unknown in Home Assistant MQTT


def _entities():
    """(object_id, component, name, icon, unit, device_class, state_class, fn(snapshot) -> (state, attrs))"""
    ns = lambda s: s.get("netsentry") or {}
    ur = lambda s: s.get("unraid") or {}
    hs = lambda s: s.get("host") or {}
    dk = lambda s: s.get("docker") or {}
    return [
        ("status", "sensor", "Status", "mdi:shield-check", None, None, None,
         lambda s: (s["status"], {"issue_counts": s["issue_counts"], "top_issues": s["issues"][:5]})),
        ("open_issues", "sensor", "Open issues", "mdi:alert-circle-outline", None, None, "measurement",
         lambda s: (len([i for i in s["issues"] if i["severity"] != "info"]), {"issues": s["issues"][:25]})),
        ("problem", "binary_sensor", "Problem", None, None, "problem", None,
         lambda s: ("ON" if SEV.get(s["status"], 0) >= 3 else "OFF", {"status": s["status"]})),
        ("log_rate", "sensor", "Log rate", "mdi:text-box-multiple-outline", "events/min", None, "measurement",
         lambda s: (s["log_rate"], {})),
        ("errors_last_hour", "sensor", "Errors last hour", "mdi:alert-octagon-outline", None, None, "measurement",
         lambda s: (s["errors_1h"], {})),
        ("log_sources", "sensor", "Log sources", "mdi:server-network", None, None, "measurement",
         lambda s: (sum(1 for x in s["sources"] if x["minutes_ago"] <= 60), {"sources": s["sources"]})),
        ("netsentry_severity", "sensor", "NetSentry severity", "mdi:radar", None, None, None,
         lambda s: (_na(ns(s).get("severity")), {k: ns(s).get(k) for k in (
             "report_time", "report_file", "summary", "findings", "new_hosts", "hosts_up", "open_ports",
             "kev_services")})),
        ("netsentry_last_scan", "sensor", "NetSentry last scan", "mdi:radar", None, "timestamp", None,
         lambda s: (_na(ns(s).get("scan_time")), {})),
        ("array", "sensor", "Array", "mdi:harddisk", None, None, None,
         lambda s: (_na(ur(s).get("state")), {k: ur(s).get(k) for k in (
             "version", "disks", "zfs_pools", "sync_errors", "invalid_disks", "last_parity_check")})),
        ("cpu_temperature", "sensor", "CPU temperature", None, "°C", "temperature", "measurement",
         lambda s: (_na(hs(s).get("cpu_temp")), {})),
        ("load", "sensor", "Load", "mdi:gauge", None, None, "measurement",
         lambda s: (_na(hs(s).get("load1")), {"cpus": hs(s).get("cpus")})),
        ("memory_used", "sensor", "Memory used", "mdi:memory", "%", None, "measurement",
         lambda s: (_na(hs(s).get("mem_used_pct")), {})),
        ("container_updates", "sensor", "Container updates", "mdi:update", None, None, "measurement",
         lambda s: (_na(len(dk(s)["updates"]) if "updates" in dk(s) else None), {"updates": dk(s).get("updates")})),
        ("containers_down", "sensor", "Containers down", "mdi:docker", None, None, "measurement",
         lambda s: (_na(len(dk(s)["down"]) + len(dk(s)["unhealthy"]) if "down" in dk(s) else None),
                    {"down": dk(s).get("down"), "unhealthy": dk(s).get("unhealthy"), "running": dk(s).get("running")})),
        ("digest", "sensor", "Digest", "mdi:robot-outline", None, "timestamp", None,
         lambda s: (_na(iso((s.get("digest") or {}).get("ts"))),
                    {"kind": (s.get("digest") or {}).get("kind"), "text": (s.get("digest") or {}).get("text")})),
    ]


class Mqtt:
    def __init__(self):
        import paho.mqtt.client as mqtt
        m = CFG["mqtt"]
        self.base = m.get("base_topic", "sysmonitor")
        self.prefix = m.get("discovery_prefix", "homeassistant")
        self.avail = f"{self.base}/availability"
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=m.get("client_id", "sysmonitor"))
        if m.get("username"):
            self.client.username_pw_set(m["username"], os.environ.get(m.get("password_env", "MQTT_PASSWORD")))
        self.client.will_set(self.avail, "offline", retain=True)
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = lambda *a: log("mqtt", "disconnected; will retry")
        self.host, self.port = m["host"], int(m.get("port", 1883))
        self.connected = False

    def start(self):
        self.client.connect_async(self.host, self.port, keepalive=60)
        self.client.reconnect_delay_set(min_delay=5, max_delay=120)
        self.client.loop_start()

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        if reason_code.is_failure:
            log("mqtt", f"connection refused: {reason_code}")
            return
        device = {"identifiers": ["sysmonitor"], "name": "SysMonitor", "manufacturer": "netadmindave",
                  "model": "SysMonitor", "sw_version": VERSION}
        for oid, comp, name, icon, unit, dclass, sclass, _ in _entities():
            cfg = {"name": name, "unique_id": f"sysmonitor_{oid}", "device": device,
                   "state_topic": f"{self.base}/{oid}/state",
                   "json_attributes_topic": f"{self.base}/{oid}/attributes",
                   "availability_topic": self.avail}
            if icon:
                cfg["icon"] = icon
            if unit:
                cfg["unit_of_measurement"] = unit
            if dclass:
                cfg["device_class"] = dclass
            if sclass:
                cfg["state_class"] = sclass
            client.publish(f"{self.prefix}/{comp}/sysmonitor/{oid}/config", json.dumps(cfg), retain=True)
        client.publish(self.avail, "online", retain=True)
        self.connected = True
        log("mqtt", f"connected to {self.host}:{self.port}; published {len(_entities())} entities")

    def publish(self, snap):
        if not self.connected:
            return
        for oid, _, _, _, _, _, _, fn in _entities():
            try:
                state, attrs = fn(snap)
            except Exception as e:
                log("mqtt", f"{oid}: {e}")
                continue
            self.client.publish(f"{self.base}/{oid}/state", str(state), retain=True)
            self.client.publish(f"{self.base}/{oid}/attributes", json.dumps(attrs, default=str), retain=True)


# ---------------------------------------------------------------- HTTP
class _Handler(BaseHTTPRequestHandler):
    server_version = "SysMonitor"
    queue = None
    on_netsentry = None

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else (
            json.dumps(body, default=str, indent=1).encode() if ctype == "application/json" else body.encode())
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    allowed = None

    def _denied(self):
        if _Handler.allowed and not _Handler.allowed(self.client_address[0]):
            self._send(403, {"error": "forbidden"})
            return True
        return False

    def do_GET(self):
        if self._denied():
            return
        u = urlparse(self.path)
        if u.path == "/healthz":
            return self._send(200, {"ok": True})
        c = connect()
        try:
            if u.path == "/api/status":
                return self._send(200, snapshot(c))
            if u.path == "/api/issues":
                q = "SELECT * FROM issues" + ("" if parse_qs(u.query).get("all") else " WHERE status='open'")
                return self._send(200, [dict(r) for r in c.execute(q + " ORDER BY last_seen DESC LIMIT 500")])
            if u.path == "/api/digest":
                r = c.execute("SELECT * FROM digests ORDER BY ts DESC LIMIT 1").fetchone()
                return self._send(200, dict(r) if r else {})
            d = CFG.get("reports_dir", "/data/reports")
            if u.path == "/api/reports":
                files = sorted(os.listdir(d), reverse=True) if os.path.isdir(d) else []
                return self._send(200, files)
            if u.path.startswith("/reports/"):
                p = os.path.join(d, os.path.basename(u.path))
                if os.path.isfile(p):
                    return self._send(200, open(p, encoding="utf-8").read(), "text/markdown")
                return self._send(404, {"error": "not found"})
            if u.path == "/":
                return self._send(200, _page(snapshot(c)), "text/html")
            return self._send(404, {"error": "not found"})
        finally:
            c.close()

    def do_POST(self):
        if self._denied():
            return
        if urlparse(self.path).path != "/ingest":
            return self._send(404, {"error": "not found"})
        ip = self.client_address[0]
        h = CFG.get("http") or {}
        token = os.environ.get(h.get("ingest_token_env", "INGEST_TOKEN"))
        exempt = set(h.get("token_exempt") or ["127.0.0.1", "::1"])
        if token and ip not in exempt and self.headers.get("X-SysMonitor-Token") != token:
            return self._send(401, {"error": "bad token"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        except ValueError:
            return self._send(400, {"error": "invalid JSON"})
        items = body if isinstance(body, list) else [body]
        n = 0
        for it in items[:1000]:
            if not isinstance(it, dict):
                continue
            if it.get("source") == "netsentry" and "severity" in it:   # NetSentry's webhook
                it = {"source": "NetSentry", "app": "netsentry",
                      "level": {"critical": 2, "high": 3, "medium": 4}.get(it["severity"], 6),
                      "message": it.get("title", "NetSentry report")}
                if _Handler.on_netsentry:
                    _Handler.on_netsentry()
            if "message" not in it:
                continue
            _Handler.queue.put((it, ip, time.time()))
            n += 1
        return self._send(200, {"accepted": n})


def _page(s):
    e = html.escape
    rows = "".join(f"<tr><td>{e(i['severity'])}</td><td>{e(i['title'])}</td><td>{e(str(i['source']))}</td>"
                   f"<td>{i['count']}</td><td>{e(str(i['last'])[:16])}</td></tr>" for i in s["issues"])
    dg = (s.get("digest") or {}).get("text") or "No digest yet."
    return f"""<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>SysMonitor</title><style>body{{font:15px system-ui;margin:1.5em;max-width:60em}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #ccc;padding:.3em;text-align:left}}
pre{{white-space:pre-wrap;background:#f4f4f4;padding:1em}}</style>
<h1>SysMonitor: {e(s['status'].upper())}</h1>
<p>{s['log_rate']} events/min, {s['errors_1h']} errors in the last hour. Updated {e(s['generated'])}.</p>
<h2>Open issues</h2><table><tr><th>Severity</th><th>Issue</th><th>Source</th><th>Count</th><th>Last</th></tr>
{rows or '<tr><td colspan=5>None</td></tr>'}</table>
<h2>Digest</h2><pre>{e(dg)}</pre>
<p><a href="/api/status">/api/status</a> · <a href="/api/issues">/api/issues</a> · <a href="/api/reports">/api/reports</a></p>"""


def start_http(q, on_netsentry):
    from .logs import _allowed_checker
    _Handler.allowed = _allowed_checker("http")
    _Handler.queue = q
    _Handler.on_netsentry = on_netsentry
    h = CFG.get("http") or {}
    srv = ThreadingHTTPServer((h.get("bind", "0.0.0.0"), int(h.get("port", 8514))), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True, name="http").start()
    log("http", f"listening on port {h.get('port', 8514)}")
    return srv
