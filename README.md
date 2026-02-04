# Wireshark AI Agent (GitHub Pages Ready)

Static frontend that uploads PCAPs to a parser backend and then sends the structured summary to a local LLM API for analysis. Built with Vite + React and deployable on GitHub Pages, plus a free-tier backend on Render.

## Why this architecture?

**Browser-only AI (fully client-side)**
- Pros: zero server cost, fully offline, no traffic data leaves the device.
- Cons: large models are heavy, slower inference, memory limits, and updates require shipping new builds.

**Frontend + API (local LLM + parser backend)**
- Pros: use full-size models, leverage Wireshark/tshark on the backend, easier updates, and faster parsing.
- Cons: you must run local services, manage CORS, and ensure secure access.

**Browser parsing vs backend parsing**
- Browser parsing: works offline and avoids a backend but is limited in performance and feature completeness.
- Backend parsing: can use tshark/pyshark or Wireshark tooling and handle big captures reliably.

## Quick start (frontend)

```bash
npm install
npm run dev
```

## Deployment (GitHub Pages)

```bash
npm run build
```

Push `dist/` to GitHub Pages (or use your preferred deploy action). The Vite `base` is set to `./` so it can be hosted from a repo subpath.

## Backend (Render free tier)

This repo includes a FastAPI + Scapy parser backend under `server/`.

### Option A: Render Blueprint (recommended)
1. Connect this repo to Render.
2. Render will detect `render.yaml` and create the service automatically.
3. Once deployed, copy the public Render URL (e.g. `https://your-service.onrender.com`).

### Option B: Manual Render setup
1. Create a new Web Service on Render.
2. Environment: `Docker`.
3. Dockerfile path: `server/Dockerfile`
4. Docker context: `server`
5. Health check path: `/health`

The parser endpoint will be:
`https://YOUR-RENDER-URL/api/pcap/parse`

## Configure your endpoints

The UI lets you configure:
- **Parser API URL** (multipart upload, field name `pcap`)
- **LLM provider** (`OpenAI-compatible` or `Ollama`)
- **LLM endpoint** and **model**

These settings are saved in `localStorage`.

Note: GitHub Pages is served over HTTPS. Browsers block calls from HTTPS pages to HTTP endpoints, so your LLM endpoint should be HTTPS (or use a secure tunnel like Cloudflare Tunnel/ngrok for local models).

## Expected Parser API response (JSON)

The frontend is resilient to missing fields, but it works best with the following shape:

```json
{
  "summary": {
    "capture_start": "2026-02-03T11:02:00Z",
    "capture_end": "2026-02-03T11:12:30Z",
    "packet_count": 12345,
    "total_bytes": 9876543,
    "unique_hosts": 42,
    "protocols": [
      { "name": "TCP", "count": 9000 },
      { "name": "UDP", "count": 2000 }
    ],
    "top_talkers": [
      { "ip": "192.168.1.10", "bytes": 1234567 }
    ],
    "alerts": [
      "High DNS NXDOMAIN rate",
      "Repeated TCP SYN retries"
    ]
  },
  "flows": [
    {
      "src": "192.168.1.10:52344",
      "dst": "8.8.8.8:53",
      "protocol": "UDP",
      "bytes": 40000
    }
  ]
}
```

## LLM API expectations

**OpenAI-compatible** endpoint:
- `POST /v1/chat/completions`
- Expects `model` and `messages`
- Response should include `choices[0].message.content`

**Ollama** endpoint:
- `POST /api/chat`
- Expects `model` and `messages`
- Response should include `message.content`

## Next steps

If you want, I can add:
- A sample parser backend (FastAPI + tshark)
- A GitHub Actions deploy workflow
- A Wireshark filter suggestion sidebar
