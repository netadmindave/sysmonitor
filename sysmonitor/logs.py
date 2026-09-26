"""Syslog reception, parsing, pattern templates and the rules engine."""
import asyncio
import collections
import hashlib
import ipaddress
import queue
import re
import threading
import time

from . import store
from .common import CFG, LEVEL_NAMES, connect, get_state, log

# ---------------------------------------------------------------- parsing
PRI = re.compile(r"^<(\d{1,3})>")
R5424 = re.compile(r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[.*?\])+) ?(.*)$", re.S)
R3164 = re.compile(r"^([A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d) (\S+) ([^:\[\s]+)(?:\[(\d+)\])?: ?(.*)$", re.S)
R3164_NOHOST = re.compile(r"^([A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d) ([^:\[\s]+)(?:\[(\d+)\])?: ?(.*)$", re.S)
CEF_KV = re.compile(r"(\w+)=((?:\\=|[^=])*?)(?=\s+\w+=|\s*$)")
# Nginx Proxy Manager "proxy" log format
NPM = re.compile(r'\] (\S+) (\S+) (\d{3}) - (\S+) (\S+) (\S+) "([^"]*)" \[Client ([^\]]+)\]')
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
NORMALIZE = [
    (re.compile(r'"[^"]*"'), '"<str>"'),
    (re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b", re.I), "<mac>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"\b[0-9a-f]{8,}\b", re.I), "<hex>"),
    (re.compile(r"\d+"), "<n>"),
]


def _nil(v):
    return None if v in (None, "-") else v


def parse_cef(ev):
    i = ev["msg"].find("CEF:")
    parts = ev["msg"][i + 4:].split("|", 7)
    if len(parts) < 8:
        return
    _, vendor, product, _, sig, name, sev, ext = parts
    f = {"cef_vendor": vendor, "cef_product": product, "cef_sig": sig, "cef_name": name, "cef_severity": sev}
    for k, v in CEF_KV.findall(ext):
        f[k] = v.replace("\\=", "=").strip()
    ev["fields"].update(f)
    if ev["app"] in (None, "CEF"):
        ev["app"] = re.sub(r"\W+", "-", product).strip("-").lower() or "cef"
    try:
        s = int(sev)
        ev["level"] = 2 if s >= 9 else 3 if s >= 7 else 4 if s >= 4 else 6
    except ValueError:
        pass
    ev["msg"] = f"{name} {ext}"[:1000]


def parse(raw, src_ip):
    """Parse one syslog message. Tolerant: anything unrecognised is kept as the raw message."""
    s = raw.strip()
    ev = {"src_ip": src_ip, "host": None, "app": None, "level": 6, "facility": 1, "msg": s, "fields": {}}
    m = PRI.match(s)
    if m:
        pri = int(m.group(1))
        ev["level"], ev["facility"] = pri % 8, pri // 8
        s = s[m.end():]
    if (m := R5424.match(s)):
        _, host, app, _, _, sd, msg = m.groups()
        ev.update(host=_nil(host), app=_nil(app), msg=(msg or "").lstrip("\ufeff") or sd)
    elif (m := R3164.match(s)):
        _, host, app, _, msg = m.groups()
        ev.update(host=host, app=app, msg=msg)
    elif (m := R3164_NOHOST.match(s)):
        _, app, _, msg = m.groups()
        ev.update(app=app, msg=msg)
    else:
        ev["msg"] = s
    if ev["app"] == "CEF":
        ev["msg"] = "CEF:" + ev["msg"]
    if "CEF:" in ev["msg"][:200]:
        parse_cef(ev)
    if (m := NPM.search(ev["msg"])):
        ev["fields"].update(status=m.group(3), method=m.group(4), scheme=m.group(5), vhost=m.group(6),
                            uri=m.group(7), client=m.group(8))
        ev["app"] = ev["app"] or "npm"
        ev["level"] = 4 if m.group(3).startswith("5") else 6
    return ev


def template(ev):
    t = ev["msg"][:400]
    for rx, rep in NORMALIZE:
        t = rx.sub(rep, t)
    return t[:300]


# ---------------------------------------------------------------- rules
class _Safe(dict):
    def __missing__(self, k):
        return "?"


class Rule:
    def __init__(self, d):
        self.id = d["id"]
        self.match = re.compile(d["match"], re.I) if d.get("match") else None
        self.app = re.compile(d["app"], re.I) if d.get("app") else None
        self.source = re.compile(d["source"], re.I) if d.get("source") else None
        self.fields = {k: re.compile(str(v), re.I) for k, v in (d.get("fields") or {}).items()}
        self.max_level = d.get("max_level")
        self.threshold = int(d.get("threshold", 1))
        self.window = float(d.get("window_min", 10)) * 60
        self.group_by = d.get("group_by") or ["source"]
        self.category = d.get("category", "logs")
        self.severity = d.get("severity", "medium")
        self.title = d.get("title", "{rule} on {source}")
        self.resolve_after_min = d.get("resolve_after_min")

    def matches(self, ev):
        if self.max_level is not None and ev["level"] > int(self.max_level):
            return False
        if self.app and not self.app.search(ev.get("app") or ""):
            return False
        if self.source and not self.source.search(ev.get("source") or ""):
            return False
        for k, rx in self.fields.items():
            if not rx.search(str(ev["fields"].get(k, ""))):
                return False
        return not self.match or bool(self.match.search(ev["msg"]))

    def group(self, ev):
        g = {}
        for k in self.group_by:
            if k == "source":
                g[k] = ev.get("source")
            elif k == "app":
                g[k] = ev.get("app")
            elif k == "ip":
                g[k] = next((ip for ip in IPV4.findall(ev["msg"]) if ip != ev["src_ip"]), "?")
            elif k.startswith("field:"):
                g[k[6:]] = ev["fields"].get(k[6:], "?")
        return g


class Engine:
    def __init__(self, rules):
        self.rules = [Rule(r) for r in rules or []]
        self.windows = collections.defaultdict(collections.deque)
        self._last_prune = time.time()

    def process(self, ev, now):
        first, hits = None, []
        for r in self.rules:
            if not r.matches(ev):
                continue
            first = first or r.id
            g = r.group(ev)
            key = r.id + ":" + "|".join(str(v) for v in g.values())
            dq = self.windows[key]
            dq.append(now)
            while dq and dq[0] < now - r.window:
                dq.popleft()
            if len(dq) >= r.threshold:
                hits.append((key, r, g, len(dq)))
        if now - self._last_prune > 600:
            longest = max((r.window for r in self.rules), default=600)
            for k in [k for k, dq in self.windows.items() if not dq or dq[-1] < now - longest]:
                del self.windows[k]
            self._last_prune = now
        return first, hits


# ---------------------------------------------------------------- ingest
class Ingestor(threading.Thread):
    """Single writer: parses queued messages, applies rules, stores events and issues."""

    def __init__(self, q):
        super().__init__(daemon=True, name="ingestor")
        self.q = q
        sc = CFG.get("syslog") or {}
        self.engine = Engine(CFG.get("rules"))
        self.drop = [re.compile(p, re.I) for p in sc.get("drop") or []]
        self.names = {s["ip"]: s["name"] for s in sc.get("sources") or [] if s.get("ip") and s.get("name")}
        self.errors = 0

    def source_name(self, ip, host):
        if ip in self.names:
            return self.names[ip]
        ns = (get_state("netsentry") or {}).get("names") or {}
        return ns.get(ip) or host or ip

    def run(self):
        self.conn = connect()
        if store.meta_get(self.conn, "first_event_ts") is None:
            store.meta_set(self.conn, "first_event_ts", time.time())
            self.conn.commit()
        batch, last = [], time.time()
        while True:
            try:
                batch.append(self.q.get(timeout=1))
            except queue.Empty:
                pass
            if batch and (len(batch) >= 500 or time.time() - last >= 1):
                self.flush(batch)
                batch, last = [], time.time()

    def flush(self, batch):
        for item in batch:
            try:
                self.handle(*item)
            except Exception as e:
                self.errors += 1
                if self.errors < 20 or self.errors % 1000 == 0:
                    log("ingest", f"failed to process message ({e}): {str(item)[:200]}")
        self.conn.commit()

    def handle(self, raw, ip, ts):
        c = self.conn
        if isinstance(raw, dict):         # HTTP ingest: already structured
            lvl = raw.get("level", 6)
            ev = {"src_ip": ip, "host": raw.get("source"), "app": raw.get("app") or "http",
                  "level": LEVEL_NAMES.get(str(lvl).lower(), lvl) if not isinstance(lvl, int) else lvl,
                  "facility": 1, "msg": str(raw.get("message", ""))[:2000], "fields": raw.get("fields") or {}}
            if not isinstance(ev["level"], int):
                ev["level"] = 6
            source = raw.get("source") or self.source_name(ip, None)
        else:
            ev = parse(raw, ip)
            source = self.source_name(ip, ev["host"])
        ev["source"] = source
        src = f"http:{source}" if isinstance(raw, dict) else ip     # one key per sender for counts
        c.execute("""INSERT INTO sources (ip, name, first_seen, last_seen, count) VALUES (?,?,?,?,1)
                     ON CONFLICT(ip) DO UPDATE SET name=excluded.name, last_seen=excluded.last_seen,
                     count=count+1""", (src, source, ts, ts))
        if any(rx.search(ev["msg"]) for rx in self.drop):
            return
        tpl = template(ev)
        tid = hashlib.sha1(f"{source}|{ev['app']}|{tpl}".encode()).hexdigest()[:16]
        c.execute("""INSERT INTO templates (id, template, example, source, app, level, first_seen, last_seen, count)
                     VALUES (?,?,?,?,?,?,?,?,1) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,
                     count=count+1, level=MIN(level, excluded.level)""",
                  (tid, tpl, ev["msg"][:500], source, ev["app"], ev["level"], ts, ts))
        rule_id, hits = self.engine.process(ev, ts)
        c.execute("""INSERT INTO events (ts, src_ip, source, app, level, facility, template_id, rule_id, msg)
                     VALUES (?,?,?,?,?,?,?,?,?)""",
                  (ts, src, source, ev["app"], ev["level"], ev["facility"], tid, rule_id, ev["msg"][:2000]))
        for key, r, g, n in hits:
            title = r.title.format_map(_Safe({**g, "rule": r.id, "source": source, "app": ev.get("app") or "",
                                             "count": n}))
            status = store.upsert_issue(c, key, rule_id=r.id, origin="log", category=r.category,
                                        severity=r.severity, title=title, detail=ev["msg"][:300],
                                        source=source, hits=1, initial_count=n, now=ts)
            if status in ("opened", "reopened"):
                log("rules", f"{status}: [{r.severity}] {title}")


# ---------------------------------------------------------------- network listeners
PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]


def _allowed_checker(section="syslog"):
    nets = [ipaddress.ip_network(n, strict=False)
            for n in (CFG.get(section) or {}).get("allowed_sources", PRIVATE)]

    def ok(ip):
        try:
            a = ipaddress.ip_address(ip.split("%")[0])
            if a.version == 6 and a.ipv4_mapped:
                a = a.ipv4_mapped
            return any(a in n for n in nets)
        except ValueError:
            return False
    return ok


class Counters:
    dropped = 0
    rejected = 0


def _enqueue(q, item):
    try:
        q.put_nowait(item)
    except queue.Full:
        Counters.dropped += 1


class _UDP(asyncio.DatagramProtocol):
    def __init__(self, q, allowed):
        self.q, self.allowed = q, allowed

    def datagram_received(self, data, addr):
        ip = addr[0]
        if not self.allowed(ip):
            Counters.rejected += 1
            return
        msg = data.decode("utf-8", "replace").strip()
        if msg:
            _enqueue(self.q, (msg, ip, time.time()))


async def serve_syslog(q):
    sc = CFG.get("syslog") or {}
    allowed = _allowed_checker()
    loop = asyncio.get_running_loop()
    bind = sc.get("bind", "0.0.0.0")
    udp_port, tcp_port = int(sc.get("udp_port", 5514)), int(sc.get("tcp_port", 5514))
    await loop.create_datagram_endpoint(lambda: _UDP(q, allowed), local_addr=(bind, udp_port))

    async def handle(reader, writer):
        ip = (writer.get_extra_info("peername") or ("?",))[0]
        if not allowed(ip):
            Counters.rejected += 1
            writer.close()
            return
        buf = b""
        try:
            while (data := await reader.read(65536)):
                buf += data
                while buf:
                    m = re.match(rb"(\d{1,6}) ", buf)          # RFC 6587 octet counting
                    if m:
                        n, start = int(m.group(1)), m.end()
                        if len(buf) < start + n:
                            break
                        msg, buf = buf[start:start + n], buf[start + n:]
                    else:                                      # newline framing
                        i = buf.find(b"\n")
                        if i < 0:
                            break
                        msg, buf = buf[:i], buf[i + 1:]
                    if msg.strip():
                        _enqueue(q, (msg.decode("utf-8", "replace").strip(), ip, time.time()))
                if len(buf) > 1_000_000:
                    buf = b""
        finally:
            writer.close()

    server = await asyncio.start_server(handle, bind, tcp_port)
    log("syslog", f"listening on udp/{udp_port} and tcp/{tcp_port}")
    async with server:
        await server.serve_forever()
