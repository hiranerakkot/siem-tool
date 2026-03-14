import express from "express";
import cors from "cors";
import { WebSocketServer } from "ws";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";

const app = express();
app.use(cors());
app.use(express.json());

const mitreTechniques = JSON.parse(readFileSync(new URL("./data/mitre-techniques.json", import.meta.url)));
const threatIntelFeed = JSON.parse(readFileSync(new URL("./data/threat-feed.json", import.meta.url)));

const state = {
  agents: [
    {
      id: "win-agent-01",
      hostname: "WIN10-SALES",
      ipAddress: "10.0.10.21",
      os: "Windows 10",
      status: "online",
      lastSeen: new Date().toISOString()
    },
    {
      id: "win-agent-02",
      hostname: "WIN11-FINANCE",
      ipAddress: "10.0.10.22",
      os: "Windows 11",
      status: "online",
      lastSeen: new Date().toISOString()
    }
  ],
  logs: [],
  rules: [
    {
      id: "rule-1",
      name: "Multiple failed logins",
      condition: "eventType == failed_login && count(ipAddress, 5m) > 5",
      severity: "high",
      enabled: true
    }
  ],
  incidents: []
};

const server = createServer(app);
const wss = new WebSocketServer({ server });

function sendWs(type, payload) {
  const message = JSON.stringify({ type, payload, ts: new Date().toISOString() });
  wss.clients.forEach((client) => {
    if (client.readyState === 1) {
      client.send(message);
    }
  });
}

function applyMitreMapping(log) {
  const mapping = mitreTechniques[log.eventType];
  if (!mapping) {
    return null;
  }

  return {
    ...mapping,
    matchReason: `Mapped from eventType=${log.eventType}`
  };
}

function checkThreatIntel(log) {
  return threatIntelFeed.filter((ioc) => {
    const haystack = JSON.stringify(log).toLowerCase();
    return haystack.includes(ioc.indicator.toLowerCase().replace("hxxp", "http"));
  });
}

function evaluateRules(log) {
  const alerts = [];
  for (const rule of state.rules) {
    if (!rule.enabled) continue;

    if (rule.name === "Multiple failed logins" && log.eventType === "failed_login") {
      const fiveMinAgo = Date.now() - 5 * 60 * 1000;
      const matchingLogs = state.logs.filter(
        (item) =>
          item.ipAddress === log.ipAddress &&
          item.eventType === "failed_login" &&
          new Date(item.timestamp).getTime() >= fiveMinAgo
      );

      if (matchingLogs.length >= 5) {
        alerts.push({
          alertId: `alert-${Date.now()}`,
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          message: `Potential brute-force from ${log.ipAddress}`,
          timestamp: new Date().toISOString()
        });
      }
    }
  }

  return alerts;
}

app.get("/health", (_, res) => {
  res.json({ status: "ok", service: "siem-backend" });
});

app.get("/api/agents", (_, res) => {
  res.json(state.agents);
});

app.post("/api/agents/heartbeat", (req, res) => {
  const { id, hostname, ipAddress, os } = req.body;
  if (!id || !hostname) {
    return res.status(400).json({ error: "id and hostname are required" });
  }

  const existing = state.agents.find((agent) => agent.id === id);
  if (existing) {
    existing.lastSeen = new Date().toISOString();
    existing.status = "online";
    existing.hostname = hostname;
    existing.ipAddress = ipAddress ?? existing.ipAddress;
    existing.os = os ?? existing.os;
  } else {
    state.agents.push({
      id,
      hostname,
      ipAddress: ipAddress ?? "unknown",
      os: os ?? "windows",
      status: "online",
      lastSeen: new Date().toISOString()
    });
  }

  sendWs("agent.heartbeat", { id, hostname });
  return res.json({ success: true });
});

app.get("/api/logs", (_, res) => {
  res.json(state.logs.slice(-200).reverse());
});

app.post("/api/logs", (req, res) => {
  const incoming = req.body;
  if (!incoming.agentId || !incoming.eventType || !incoming.message) {
    return res.status(400).json({ error: "agentId, eventType and message are required" });
  }

  const normalizedLog = {
    id: `log-${Date.now()}`,
    timestamp: incoming.timestamp ?? new Date().toISOString(),
    ...incoming,
    mitre: applyMitreMapping(incoming),
    threatMatches: checkThreatIntel(incoming)
  };

  state.logs.push(normalizedLog);
  if (state.logs.length > 5000) {
    state.logs.shift();
  }

  const alerts = evaluateRules(normalizedLog);
  if (alerts.length > 0) {
    for (const alert of alerts) {
      const incident = {
        id: `inc-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        status: "open",
        owner: "SOC Tier 1",
        createdAt: new Date().toISOString(),
        alert,
        evidenceLogId: normalizedLog.id,
        workflow: [
          { step: "triage", status: "pending" },
          { step: "containment", status: "pending" },
          { step: "eradication", status: "pending" },
          { step: "recovery", status: "pending" }
        ]
      };
      state.incidents.push(incident);
      sendWs("incident.created", incident);
    }
  }

  sendWs("log.ingested", normalizedLog);
  return res.status(201).json({ stored: true, alertsGenerated: alerts.length });
});

app.get("/api/rules", (_, res) => {
  res.json(state.rules);
});

app.post("/api/rules", (req, res) => {
  const { name, condition, severity, enabled = true } = req.body;
  if (!name || !condition || !severity) {
    return res.status(400).json({ error: "name, condition, severity are required" });
  }

  const rule = {
    id: `rule-${Date.now()}`,
    name,
    condition,
    severity,
    enabled
  };
  state.rules.push(rule);
  sendWs("rule.created", rule);

  return res.status(201).json(rule);
});

app.patch("/api/incidents/:id", (req, res) => {
  const incident = state.incidents.find((item) => item.id === req.params.id);
  if (!incident) {
    return res.status(404).json({ error: "Incident not found" });
  }

  const { status, owner, workflow } = req.body;
  if (status) incident.status = status;
  if (owner) incident.owner = owner;
  if (workflow) incident.workflow = workflow;

  sendWs("incident.updated", incident);
  return res.json(incident);
});

app.get("/api/incidents", (_, res) => {
  res.json(state.incidents.slice(-200).reverse());
});

app.get("/api/mitre/mappings", (_, res) => {
  res.json(mitreTechniques);
});

app.get("/api/threat-intel", (_, res) => {
  res.json(threatIntelFeed);
});

wss.on("connection", (socket) => {
  socket.send(JSON.stringify({ type: "bootstrap", payload: { message: "Connected to SIEM realtime channel" } }));
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`SIEM backend listening on port ${PORT}`);
});
