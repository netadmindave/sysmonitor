"""Hourly / daily / weekly digests. Code gathers the facts; the model only summarises and recommends."""
import json
import os
import re
import time

import requests

from . import store
from .common import CFG, get_state, iso, log, set_state

LEARNING_HOURS = 24
PROMPT = """You are the operations assistant for a home lab. You receive a factual snapshot of logs, \
open issues and system status and write a short digest for a Home Assistant dashboard. You cannot \
change anything; you only recommend. The owner decides and acts.

Rules:
- Use only the data provided. Name hosts and services as they appear. Never invent events, versions or numbers.
- Overall status is decided by code, not by you; do not restate or change it.
- Prioritise: what needs action first, what is merely noteworthy, what can be ignored.
- New log patterns are only interesting if they indicate a problem; say so if they look benign.
- If everything is quiet, say so in one sentence and give no recommendations.
- Keep it short: this is read on a phone.

Output Markdown in exactly this shape:
## Summary
2-3 sentences.
## Recommendations
Up to {n} bullets: action - reason (evidence).
"""
TRENDS = "\n## Trends\nUp to 5 bullets comparing this period with what is normal for these sources.\n"


def snapshot(c, hours):
    since = time.time() - hours * 3600
    q = lambda sql, *a: [dict(r) for r in c.execute(sql, a)]
    first = float(store.meta_get(c, "first_event_ts", time.time()))
    learning = time.time() - first < LEARNING_HOURS * 3600
    snap = {
        "period_hours": hours,
        "events": c.execute("SELECT count(*) FROM events WHERE ts>=?", (since,)).fetchone()[0],
        "errors": c.execute("SELECT count(*) FROM events WHERE ts>=? AND level<=3", (since,)).fetchone()[0],
        "by_source": q("SELECT source, count(*) AS events, sum(level<=3) AS errors, sum(level=4) AS warnings "
                       "FROM events WHERE ts>=? GROUP BY source ORDER BY events DESC LIMIT 15", since),
        "rule_hits": q("SELECT rule_id, source, count(*) AS hits FROM events WHERE ts>=? AND rule_id IS NOT NULL "
                       "GROUP BY rule_id, source ORDER BY hits DESC LIMIT 15", since),
        "top_error_patterns": q(
            "SELECT t.source, t.app, t.template, count(e.id) AS n, min(e.level) AS level FROM events e "
            "JOIN templates t ON t.id=e.template_id WHERE e.ts>=? AND e.level<=4 "
            "GROUP BY e.template_id ORDER BY n DESC LIMIT 12", since),
        "open_issues": [{k: i[k] for k in ("severity", "title", "source", "count", "detail")}
                        | {"since": iso(i["first_seen"])} for i in store.open_issues(c)[:15]],
        "resolved_in_period": c.execute("SELECT count(*) FROM issues WHERE resolved_at>=?", (since,)).fetchone()[0],
    }
    if not learning:
        snap["new_log_patterns"] = q(
            "SELECT source, app, level, template, count FROM templates WHERE first_seen>=? "
            "ORDER BY level, count DESC LIMIT 15", since)
    else:
        snap["note"] = "Still learning normal log patterns (first 24 h), so new-pattern detection is off."
    ns = get_state("netsentry")
    if ns:
        snap["netsentry"] = {k: ns.get(k) for k in ("severity", "report_time", "summary", "findings",
                                                    "new_hosts", "hosts_up", "kev_services")}
    dk = get_state("docker")
    if dk:
        snap["containers"] = {"down": dk.get("down"), "unhealthy": dk.get("unhealthy"),
                              "updates": [u["image"] for u in dk.get("updates") or []]}
    ur = get_state("unraid")
    if ur:
        snap["unraid"] = {k: ur.get(k) for k in ("state", "sync_errors", "zfs_pools")}
    hs = get_state("host")
    if hs:
        snap["host"] = hs
    return snap


def fallback_text(snap):
    lines = ["## Summary",
             f"{snap['events']} log events and {snap['errors']} errors in the last {snap['period_hours']} h; "
             f"{len(snap['open_issues'])} open issue(s). (AI summary unavailable.)", "## Open issues"]
    lines += [f"- [{i['severity']}] {i['title']}" for i in snap["open_issues"][:10]] or ["- none"]
    return "\n".join(lines)


def run(kind="hourly"):
    hours = {"hourly": 1, "daily": 24, "weekly": 168}[kind]
    c = store_conn()
    snap = snapshot(c, hours)
    o = CFG.get("ollama") or {}
    text = None
    if o.get("url") and o.get("model"):
        prompt = PROMPT.format(n=3 if kind == "hourly" else 6) + (TRENDS if kind != "hourly" else "")
        try:
            r = requests.post(f"{o['url']}/api/chat", timeout=o.get("timeout_s", 600), json={
                "model": o["model"], "stream": False, "think": o.get("think", False),
                "options": {"num_ctx": o.get("num_ctx", 16384), "temperature": 0.2},
                "messages": [{"role": "system", "content": prompt},
                             {"role": "user", "content": f"{kind} snapshot:\n" + json.dumps(snap, default=str)[:40000]}]})
            r.raise_for_status()
            text = re.sub(r"<think>.*?</think>", "", r.json()["message"]["content"] or "", flags=re.S).strip()
        except Exception as e:
            log("digest", f"Ollama request failed ({e}); using fallback text")
    text = text or fallback_text(snap)
    now = time.time()
    c.execute("INSERT OR REPLACE INTO digests (ts, kind, text) VALUES (?,?,?)", (now, kind, text))
    c.commit()
    if kind != "hourly":
        d = CFG.get("reports_dir", "/data/reports")
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, f"sysmonitor-{time.strftime('%Y%m%d-%H%M')}-{kind}.md")
        with open(path, "w") as f:
            f.write(f"# SysMonitor {kind} report, {iso(now)}\n\n{text}\n")
    set_state("digest", {"ts": now, "kind": kind, "text": text})
    log("digest", f"{kind} digest written ({len(text)} chars)")
    c.close()
    return text


def store_conn():
    from .common import connect
    return connect()
