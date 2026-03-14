# SIEM Tool (React + Node.js + WebSocket)

This project provides a starter SIEM web application for your setup:
- **1 SIEM server**
- **2 Windows agents**
- **Real-time agent log ingestion into SIEM**

## Dashboard Design You Need

The included dashboard has six operational panels that match must-have SOC workflows:
1. **MITRE ATT&CK Mapping** (log-to-technique mapping + coverage visibility)
2. **Agent / Endpoint Management** (health + last-seen of Windows agents)
3. **Real-time Log Stream** (WebSocket pushed logs)
4. **Custom Alert Rules** (rule list and backend rule engine)
5. **Threat Intelligence Feed** (IOC list + IOC matching during ingestion)
6. **Incident Response Workflow** (open incidents and response stages)

## Architecture

- **Backend**: Express API + `ws` WebSocket server (`backend/server.js`)
- **Frontend**: React (Vite) dashboard (`frontend/src/App.jsx`)
- **Agent ingestion**: `POST /api/logs`
- **Agent heartbeat**: `POST /api/agents/heartbeat`

## Quick Start

```bash
npm run install:all
npm run dev:backend
npm run dev:frontend
```

Then open `http://localhost:5173`.

## API examples for Windows agents

Heartbeat:
```bash
curl -X POST http://localhost:4000/api/agents/heartbeat \
  -H "Content-Type: application/json" \
  -d '{
    "id":"win-agent-01",
    "hostname":"WIN10-SALES",
    "ipAddress":"10.0.10.21",
    "os":"Windows 10"
  }'
```

Log push:
```bash
curl -X POST http://localhost:4000/api/logs \
  -H "Content-Type: application/json" \
  -d '{
    "agentId":"win-agent-01",
    "eventType":"failed_login",
    "message":"Multiple bad password attempts for Administrator",
    "ipAddress":"185.243.112.44",
    "user":"Administrator"
  }'
```

This triggers:
- ATT&CK mapping (`T1110` for `failed_login`)
- Threat intel match (if IOC exists)
- Alert/incident generation (when rule conditions are met)

## Notes

- WebSocket endpoint: `ws://localhost:4000`
- API base URL: `http://localhost:4000`
- In-memory storage is used for demo purposes.
