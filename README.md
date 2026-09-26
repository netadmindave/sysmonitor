# SysMonitor

One container that collects your home lab's logs and status and turns them into a short list of
issues, AI-written digests and a Home Assistant dashboard. Recommendations only: SysMonitor never
changes anything on the systems it watches.

```
syslog (UDP/TCP 5514) ─┐
HTTP /ingest ──────────┼─> parse -> rules -> issues ─┐
NetSentry db + reports ┤                             ├─> MQTT discovery -> Home Assistant
Unraid array, ZFS ─────┤   status pollers ───────────┤   HTTP API + web page (8514)
Docker, host temps ────┘                             └─> hourly / daily / weekly AI digests (Ollama)
```

## What it does
- **Syslog server** on UDP and TCP 5514: RFC 3164 and 5424, UniFi CEF (IDS/IPS alerts),
  Nginx Proxy Manager access logs (status, client, host parsed out). Senders are named from your
  config, then from NetSentry's device inventory.
- **Rules** (`config.yaml`) turn matching lines into **issues**: repeated login failures, IDS alerts,
  disk I/O errors, OOM kills, kernel traces, WAN failover, reverse-proxy 401/403 floods and 5xx
  bursts, error bursts. Issues close themselves after a quiet period.
- **New-pattern detection**: every message is reduced to a template; after a 24-hour learning period,
  templates a source has never produced before are handed to the digest.
- **Status pollers**: NetSentry's latest scan and report, Unraid array and disk state, ZFS pool
  health, CPU temperature, load and memory, containers that should be running but aren't,
  unhealthy containers, and container image updates (from Unraid's own update check).
- **Silent sources**: a sender that should log every N minutes and stops becomes an issue.
- **Digests**: Ollama summarises the period and recommends up to 3 (hourly) or 6 (daily/weekly)
  actions. Overall status is computed by code, never by the model. Without Ollama, digests fall back
  to a plain issue list. Daily and weekly digests are also saved to `/data/reports`.
- **Home Assistant**: 15 entities via MQTT discovery under one device, "SysMonitor". A ready-made
  dashboard and notification automations are in `ha/`.

## Network: host or br0
The template uses host networking, which works everywhere. On a server with VLANs you may prefer
giving SysMonitor its own address on `br0` (Network Type "Custom: br0", fixed IP): it then stops
listening on every Unraid interface, and firewall rules can target it precisely. In that case:
- enable **Host access to custom networks** (so Unraid and host-network containers can reach it),
- set `ollama.url` to the Unraid IP instead of 127.0.0.1,
- point Unraid's remote syslog at SysMonitor's IP; it will arrive from Unraid's own address,
- add senders that post without a token (e.g. NetSentry's webhook, which comes from Unraid's IP)
  to `http.token_exempt`,
- allow SysMonitor to reach your MQTT broker (and anything posting to `/ingest` to reach it) in
  your firewall if they are on another VLAN.

## Install on Unraid
Install **SysMonitor** from the Apps tab, or copy the template from
https://github.com/netadmindave/unraid-sysmonitor into `/boot/config/plugins/dockerMan/templates-user/`
and use Docker → Add Container. The container is named `SysMonitor` (Docker names are case-sensitive).

On first start it writes `/mnt/user/appdata/sysmonitor/config/config.yaml`. It works out of the
box as a syslog server; edit the config to add MQTT, name your sources, and tune rules, then restart.

Template mappings (all read-only except config and data):
| Container path | Host path | Purpose |
|---|---|---|
| /config, /data | appdata/sysmonitor/... | config, database, reports |
| /netsentry | /mnt/user/appdata/netsentry/data | NetSentry integration (optional) |
| /unraid/emhttp | /var/local/emhttp | array and disk state |
| /unraid/unraid-update-status.json | /var/lib/docker/unraid-update-status.json | image updates |
| /unraid/unraid-autostart | /var/lib/docker/unraid-autostart | which containers should be running |
| /var/run/docker.sock | /var/run/docker.sock | container state (see security note) |

If one of the two files under `/var/lib/docker` doesn't exist on your server yet, remove that mapping;
Docker would otherwise create an empty folder in its place.

## Sending logs
Replace `SYSMONITOR_IP` with your Unraid address. Snippets are in `sources/`.
- **Unraid itself**: Settings → Syslog Server → remote syslog server `127.0.0.1` (host network) or
  SysMonitor's own IP (br0), port `5514`.
- **UniFi gateway**: in UniFi Network settings, enable remote syslog / SIEM forwarding to
  `SYSMONITOR_IP:5514`. Include security (IDS/IPS) events; firewall logs are very noisy, so add
  `drop` patterns if you enable them.
- **Linux hosts, Proxmox, LXC containers**: `sources/rsyslog-forward.conf`.
- **Nginx Proxy Manager**: `sources/npm-server_proxy.conf` sends access logs, which power the
  401/403 and 5xx rules. Check it took effect: NPM should appear under Log sources.
- **Home Assistant errors**: Node-RED function in `sources/node-red-ha-errors.js`.
- **NetSentry**: set NetSentry's `notify.webhook` to `http://SYSMONITOR_IP:8514/ingest` (127.0.0.1 on
  host network) so SysMonitor refreshes the moment a scan finishes.
- **Anything else**: `POST /ingest` with JSON `{"source", "app", "level", "message"}` (or a list).

## Home Assistant
1. MQTT: set `mqtt.host`, `mqtt.username` and the `MQTT_PASSWORD` variable to a login on your broker
   (an existing one works; a dedicated user is tidier). The "SysMonitor" device appears automatically.
2. Dashboard: `ha/dashboard.yaml` (core cards only).
3. Notifications: `ha/automations.yaml` (high/critical alert that updates in place and clears itself,
   weekly round-up) using Home Assistant's built-in notifications, with optional phone pushes.
4. Optional: `ha/recorder.yaml` keeps large, frequently changing attributes out of the HA database.

## HTTP
`http://SYSMONITOR_IP:8514/` status page · `/api/status` · `/api/issues` (`?all=1` includes resolved) ·
`/api/digest` · `/api/reports` · `/reports/<file>` · `POST /ingest`.
Requests are limited to `http.allowed_sources`; set `INGEST_TOKEN` to require the
`X-SysMonitor-Token` header on `/ingest` from anything not listed in `http.token_exempt`.

## Security notes
- The Docker socket gives full control of Docker even when mapped read-only; SysMonitor only issues
  GET requests, but remove the mapping if you'd rather not grant it. Everything else still works.
- Syslog is unauthenticated by design; `syslog.allowed_sources` limits who can send.
- Only private address ranges are allowed by default. Tighten both allowlists to your actual senders.

## Development
Pushing to `main` builds `ghcr.io/netadmindave/sysmonitor:latest`; a weekly rebuild picks up
base-image security fixes.

## License
MIT.
