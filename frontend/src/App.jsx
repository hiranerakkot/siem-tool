import { useEffect, useMemo, useState } from "react";
import Panel from "./components/Panel";

const API_BASE = "http://localhost:4000";
const WS_URL = "ws://localhost:4000";

async function fetchJson(path) {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    throw new Error(`Request failed for ${path}`);
  }
  return response.json();
}

export default function App() {
  const [agents, setAgents] = useState([]);
  const [logs, setLogs] = useState([]);
  const [rules, setRules] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [threatFeed, setThreatFeed] = useState([]);
  const [wsStatus, setWsStatus] = useState("connecting");

  useEffect(() => {
    Promise.all([
      fetchJson("/api/agents"),
      fetchJson("/api/logs"),
      fetchJson("/api/rules"),
      fetchJson("/api/incidents"),
      fetchJson("/api/threat-intel")
    ])
      .then(([agentsData, logsData, rulesData, incidentsData, threatData]) => {
        setAgents(agentsData);
        setLogs(logsData);
        setRules(rulesData);
        setIncidents(incidentsData);
        setThreatFeed(threatData);
      })
      .catch((error) => {
        console.error(error);
      });
  }, []);

  useEffect(() => {
    const socket = new WebSocket(WS_URL);
    socket.onopen = () => setWsStatus("connected");
    socket.onclose = () => setWsStatus("disconnected");

    socket.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.type === "log.ingested") {
        setLogs((prev) => [message.payload, ...prev].slice(0, 200));
      }
      if (message.type === "incident.created") {
        setIncidents((prev) => [message.payload, ...prev].slice(0, 200));
      }
      if (message.type === "agent.heartbeat") {
        setAgents((prev) =>
          prev.map((agent) =>
            agent.id === message.payload.id ? { ...agent, lastSeen: new Date().toISOString(), status: "online" } : agent
          )
        );
      }
      if (message.type === "rule.created") {
        setRules((prev) => [message.payload, ...prev]);
      }
    };

    return () => socket.close();
  }, []);

  const mitreCoverage = useMemo(() => {
    const mapped = logs.filter((item) => item.mitre);
    return {
      mappedCount: mapped.length,
      totalCount: logs.length,
      techniques: [...new Set(mapped.map((item) => item.mitre?.techniqueId))]
    };
  }, [logs]);

  return (
    <div className="layout">
      <header>
        <h1>SIEM Operations Dashboard</h1>
        <p>
          SOC visibility for 1 SIEM server + 2 Windows agents · WebSocket status: <strong>{wsStatus}</strong>
        </p>
      </header>

      <div className="grid">
        <Panel title="Endpoint / Agent Management">
          <table>
            <thead>
              <tr>
                <th>Agent ID</th>
                <th>Hostname</th>
                <th>OS</th>
                <th>Status</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((agent) => (
                <tr key={agent.id}>
                  <td>{agent.id}</td>
                  <td>{agent.hostname}</td>
                  <td>{agent.os}</td>
                  <td>{agent.status}</td>
                  <td>{new Date(agent.lastSeen).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>

        <Panel title="MITRE ATT&CK Coverage">
          <p>
            Logs with mapped ATT&CK technique: {mitreCoverage.mappedCount}/{mitreCoverage.totalCount}
          </p>
          <div className="chips">
            {mitreCoverage.techniques.length > 0 ? (
              mitreCoverage.techniques.map((technique) => <span key={technique}>{technique}</span>)
            ) : (
              <span>No mappings yet</span>
            )}
          </div>
        </Panel>

        <Panel title="Real-Time Log Stream">
          <div className="log-stream">
            {logs.map((log) => (
              <article key={log.id}>
                <strong>{log.eventType}</strong> [{log.agentId}] - {log.message}
                <div className="muted">
                  {new Date(log.timestamp).toLocaleString()}
                  {log.mitre ? ` · ${log.mitre.techniqueId} ${log.mitre.name}` : ""}
                </div>
              </article>
            ))}
          </div>
        </Panel>

        <Panel title="Custom Alert Rules">
          <ul>
            {rules.map((rule) => (
              <li key={rule.id}>
                <strong>{rule.name}</strong> ({rule.severity}) - {rule.condition}
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="Threat Intelligence Feed">
          <ul>
            {threatFeed.map((item) => (
              <li key={item.id}>
                <strong>{item.indicator}</strong> [{item.type}] - {item.threat} ({item.confidence})
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="Incident Response Workflow">
          {incidents.length === 0 ? (
            <p>No open incidents.</p>
          ) : (
            incidents.map((incident) => (
              <article key={incident.id} className="incident">
                <h3>{incident.alert.ruleName}</h3>
                <p>Status: {incident.status}</p>
                <p>Owner: {incident.owner}</p>
                <p>Workflow: {incident.workflow.map((step) => `${step.step}:${step.status}`).join(" → ")}</p>
              </article>
            ))
          )}
        </Panel>
      </div>
    </div>
  );
}
