// Node-RED: forward Home Assistant errors and warnings to SysMonitor.
// Flow: [events: all, event type "system_log_event"] -> [this function] -> [http request:
//        method POST, URL http://SYSMONITOR_IP:8514/ingest, return: a parsed JSON object]
// Set SYSMONITOR_TOKEN as an environment variable on the function node (same value as INGEST_TOKEN).
const e = (msg.payload && msg.payload.event) || msg.payload || {};
const text = Array.isArray(e.message) ? e.message.join(" ") : String(e.message || "");
msg.headers = { "Content-Type": "application/json", "X-SysMonitor-Token": env.get("SYSMONITOR_TOKEN") || "" };
msg.payload = {
  source: "Home Assistant",
  app: e.name || "homeassistant",
  level: String(e.level || "error").toLowerCase(),
  message: (e.source ? `${e.source[0]}: ` : "") + text.slice(0, 2000)
};
return msg;
