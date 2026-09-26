"""Read-only pollers. Each returns (data_for_dashboard, issues) and never changes anything."""
import glob
import http.client
import json
import os
import re
import socket
import sqlite3
import time

from .common import CFG, iso


# ---------------------------------------------------------------- NetSentry
def _section(text, header):
    m = re.search(rf"^## {header}\s*\n(.*?)(?=^## |\n---\n|\Z)", text, re.S | re.M)
    return m.group(1).strip() if m else ""


def netsentry():
    d = (CFG.get("netsentry") or {}).get("data_dir")
    if not d or not os.path.isdir(d):
        return None, []
    out = {"available": True}
    issues = []
    dbp = os.path.join(d, "netsentry.db")
    if os.path.exists(dbp):
        c = sqlite3.connect(f"file:{dbp}?mode=ro", uri=True, timeout=10)
        c.row_factory = sqlite3.Row
        scans = [r[0] for r in c.execute("SELECT ts FROM scans ORDER BY ts DESC LIMIT 2")]
        if scans:
            cur = scans[0]
            cols = {r[1] for r in c.execute("PRAGMA table_info(hosts)")}
            name_expr = "COALESCE(unifi_name, hostname, ip)" if "unifi_name" in cols else "COALESCE(hostname, ip)"
            out["scan_ts"] = cur
            out["scan_time"] = iso(cur)
            out["hosts_up"] = c.execute("SELECT count(DISTINCT ip) FROM hosts WHERE last_seen=?", (cur,)).fetchone()[0]
            out["open_ports"] = c.execute("SELECT count(*) FROM ports WHERE last_seen=?", (cur,)).fetchone()[0]
            out["names"] = {r[0]: r[1] for r in c.execute(
                f"SELECT ip, {name_expr} FROM hosts WHERE ip IS NOT NULL ORDER BY last_seen")}
            if len(scans) > 1:
                out["new_hosts"] = [{"ip": r[0], "name": r[1]} for r in c.execute(
                    f"SELECT ip, {name_expr} FROM hosts WHERE first_seen=?", (cur,))]
            else:
                out["new_hosts"] = []
            stale_h = (CFG.get("netsentry") or {}).get("stale_hours", 36)
            if time.time() - cur > stale_h * 3600:
                issues.append({"key": "netsentry:stale", "severity": "low", "category": "netsentry",
                               "title": f"NetSentry has not completed a scan since {iso(cur)[:16]}",
                               "source": "NetSentry"})
            if out["new_hosts"]:
                names = ", ".join(f"{h['name']} ({h['ip']})" for h in out["new_hosts"][:5])
                issues.append({"key": "netsentry:new_hosts", "severity": "medium", "category": "netsentry",
                               "title": f"{len(out['new_hosts'])} new device(s) on the network",
                               "detail": names, "source": "NetSentry"})
        c.close()

    reports = sorted(glob.glob(os.path.join(d, "reports", "netsentry-*-full.md")), key=os.path.getmtime)
    if reports:
        path = reports[-1]
        text = open(path, encoding="utf-8", errors="replace").read()
        m = re.search(r"SEVERITY:\s*(ok|low|medium|high|critical)", text, re.I)
        sev = m.group(1).lower() if m else "unknown"
        findings = re.findall(r"^\*\*(.+?)\*\*", _section(text, "Findings"), re.M)
        kev = re.search(r"services with a KEV match: (\d+)", text)
        out.update(severity=sev, report_file=os.path.basename(path), report_time=iso(os.path.getmtime(path)),
                   summary=re.sub(r"\s+", " ", _section(text, "Summary"))[:600], findings=findings[:10],
                   kev_services=int(kev.group(1)) if kev else None)
        if sev in ("high", "critical"):
            issues.append({"key": "netsentry:report", "severity": sev, "category": "netsentry",
                           "title": f"NetSentry report: {sev}, {len(findings)} finding(s)",
                           "detail": "; ".join(findings[:5]), "source": "NetSentry"})
    return out, issues


# ---------------------------------------------------------------- Unraid
def _ini(path):
    """Unraid's emhttp .ini files: key="value" lines, optional ["section"] headers."""
    sections, cur = {}, {}
    sections[""] = cur
    with open(path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if line.startswith("["):
                cur = sections.setdefault(line.strip('[]"'), {})
            elif "=" in line:
                k, v = line.split("=", 1)
                cur[k.strip()] = v.strip().strip('"')
    return sections


def unraid():
    u = CFG.get("unraid") or {}
    d = u.get("emhttp_dir")
    out, issues = {}, []
    if d and os.path.exists(os.path.join(d, "var.ini")):
        var = _ini(os.path.join(d, "var.ini"))[""]
        out.update(version=var.get("version"), state=var.get("mdState"), sync_errors=int(var.get("sbSyncErrs") or 0),
                   invalid_disks=int(var.get("mdNumInvalid") or 0), last_parity_check=iso(float(var["sbSynced"]))
                   if (var.get("sbSynced") or "0").isdigit() and var.get("sbSynced") != "0" else None)
        if var.get("mdState") and var["mdState"] != "STARTED":
            issues.append({"key": "unraid:array_state", "severity": "high", "category": "storage",
                           "title": f"Unraid array is {var['mdState']}", "source": "Unraid"})
        if out["sync_errors"]:
            issues.append({"key": "unraid:sync_errors", "severity": "low", "category": "storage",
                           "title": f"Last parity check reported {out['sync_errors']} sync errors",
                           "source": "Unraid"})
        disks = []
        dpath = os.path.join(d, "disks.ini")
        if os.path.exists(dpath):
            for name, s in _ini(dpath).items():
                if not name or not s.get("status"):
                    continue
                status = s["status"]
                if status.startswith("DISK_NP"):          # empty slot
                    continue
                temp = s.get("temp")
                rot = s.get("rotational") == "1"
                disk = {"name": name, "device": s.get("device"), "status": status, "type": s.get("type"),
                        "temp": int(temp) if (temp or "").isdigit() else None,
                        "errors": int(s.get("numErrors") or 0), "fs": s.get("fsType")}
                disks.append(disk)
                if status != "DISK_OK":
                    issues.append({"key": f"unraid:disk:{name}", "severity": "high", "category": "storage",
                                   "title": f"Unraid {name} ({disk['device'] or 'no device'}) is {status}",
                                   "source": "Unraid"})
                if disk["errors"]:
                    issues.append({"key": f"unraid:errors:{name}", "severity": "medium", "category": "storage",
                                   "title": f"Unraid {name} has {disk['errors']} read/write errors",
                                   "source": "Unraid"})
                limit = (u.get("disk_temp_warn") or {}).get("hdd" if rot else "ssd", 50 if rot else 65)
                if disk["temp"] is not None and disk["temp"] >= limit:
                    issues.append({"key": f"unraid:temp:{name}", "severity": "medium", "category": "storage",
                                   "title": f"Unraid {name} at {disk['temp']}°C (limit {limit}°C)",
                                   "source": "Unraid"})
        out["disks"] = disks

    pools = []
    for p in sorted(glob.glob("/proc/spl/kstat/zfs/*/state")):
        pool = p.split("/")[-2]
        state = open(p).read().strip()
        pools.append({"pool": pool, "state": state})
        if state != "ONLINE":
            issues.append({"key": f"zfs:{pool}", "severity": "critical" if state in ("FAULTED", "UNAVAIL") else "high",
                           "category": "storage", "title": f"ZFS pool {pool} is {state}", "source": "Unraid"})
    if pools:
        out["zfs_pools"] = pools
    return (out or None), issues


def host():
    """CPU temperature, load and memory of the machine the container runs on."""
    h = CFG.get("host") or {}
    out, issues = {}, []
    for hw in glob.glob("/sys/class/hwmon/hwmon*"):
        try:
            name = open(os.path.join(hw, "name")).read().strip()
        except OSError:
            continue
        if name in ("k10temp", "coretemp", "zenpower"):
            try:
                out["cpu_temp"] = round(int(open(os.path.join(hw, "temp1_input")).read()) / 1000, 1)
            except (OSError, ValueError):
                pass
            break
    try:
        out["load1"] = float(open("/proc/loadavg").read().split()[0])
        out["cpus"] = os.cpu_count()
    except OSError:
        pass
    try:
        mem = {l.split(":")[0]: int(l.split()[1]) for l in open("/proc/meminfo")}
        out["mem_used_pct"] = round(100 * (1 - mem["MemAvailable"] / mem["MemTotal"]), 1)
    except (OSError, KeyError, ValueError):
        pass
    limit = h.get("cpu_temp_warn", 85)
    if out.get("cpu_temp") is not None and out["cpu_temp"] >= limit:
        issues.append({"key": "host:cpu_temp", "severity": "high", "category": "hardware",
                       "title": f"CPU at {out['cpu_temp']}°C (limit {limit}°C)", "source": "Host"})
    if out.get("mem_used_pct", 0) >= h.get("mem_warn_pct", 95):
        issues.append({"key": "host:memory", "severity": "medium", "category": "hardware",
                       "title": f"Memory {out['mem_used_pct']}% used", "source": "Host"})
    return (out or None), issues


# ---------------------------------------------------------------- Docker
class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=15)
        self.sock_path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(15)
        s.connect(self.sock_path)
        self.sock = s


def _docker_get(sock, path):
    """GET only: SysMonitor never changes containers."""
    conn = _UnixHTTP(sock)
    try:
        conn.request("GET", path)
        r = conn.getresponse()
        return json.loads(r.read())
    finally:
        conn.close()


def _norm_image(img):
    last = img.rsplit("/", 1)[-1]
    return img if ":" in last or "@" in last else img + ":latest"


def docker():
    dc = CFG.get("docker") or {}
    u = CFG.get("unraid") or {}
    sock = dc.get("socket")
    ignore = set(dc.get("ignore") or [])
    out, issues = {}, []
    containers = []
    if sock and os.path.exists(sock):
        for c in _docker_get(sock, "/containers/json?all=1"):
            name = (c.get("Names") or ["?"])[0].lstrip("/")
            status = c.get("Status", "")
            containers.append({"name": name, "image": c.get("Image", ""), "state": c.get("State"),
                               "status": status, "unhealthy": "(unhealthy)" in status})
    autostart = None
    af = u.get("autostart_file")
    if af and os.path.isfile(af):
        autostart = {l.split()[0] for l in open(af) if l.strip()}
    for c in containers:
        if c["name"] in ignore:
            continue
        expected_up = c["name"] in autostart if autostart is not None else True
        if c["state"] != "running" and expected_up:
            issues.append({"key": f"docker:down:{c['name']}", "severity": "medium", "category": "containers",
                           "title": f"Container {c['name']} is {c['state']}", "detail": c["status"],
                           "source": "Docker"})
        if c["unhealthy"]:
            issues.append({"key": f"docker:unhealthy:{c['name']}", "severity": "high", "category": "containers",
                           "title": f"Container {c['name']} is unhealthy", "detail": c["status"],
                           "source": "Docker"})
    updates = []
    uf = u.get("update_status_file")
    if uf and os.path.isfile(uf):
        try:
            status = json.load(open(uf))
        except ValueError:
            status = {}
        by_image = {}
        for c in containers:
            by_image.setdefault(_norm_image(c["image"]), []).append(c["name"])
        for img, s in status.items():
            if not isinstance(s, dict):
                continue
            loc, rem = s.get("local"), s.get("remote")
            if loc and rem and loc != rem:
                names = by_image.get(_norm_image(img))
                if containers and not names:
                    continue                          # image no longer used by any container
                updates.append({"image": img, "containers": names or []})
    if containers:
        out["containers"] = containers
        out["running"] = sum(c["state"] == "running" for c in containers)
        out["down"] = [c["name"] for c in containers if c["state"] != "running" and c["name"] not in ignore
                       and (autostart is None or c["name"] in autostart)]
        out["unhealthy"] = [c["name"] for c in containers if c["unhealthy"]]
    if uf:
        out["updates"] = updates
    return (out or None), issues


# ---------------------------------------------------------------- log sources
def silent_sources(conn):
    """Configured sources that should send logs regularly but have gone quiet."""
    issues, now = [], time.time()
    for s in (CFG.get("syslog") or {}).get("sources") or []:
        every = s.get("expect_every_min")
        if not every:
            continue
        r = conn.execute("SELECT last_seen FROM sources WHERE ip=?", (s["ip"],)).fetchone()
        last = r[0] if r else None
        if last is None or last < now - every * 60:
            when = f"since {iso(last)[:16]}" if last else "yet"
            issues.append({"key": f"source:silent:{s['ip']}", "severity": s.get("severity", "medium"),
                           "category": "logging", "title": f"No logs from {s.get('name', s['ip'])} {when}",
                           "source": s.get("name", s["ip"])})
    return issues
