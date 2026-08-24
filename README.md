# Automated Code Security Scanner

A full-stack MERN + Python microservice application that scans code snippets for security vulnerabilities and generates a detailed risk report.

![Stack](https://img.shields.io/badge/stack-MERN%20%2B%20FastAPI-informational)
![Docker](https://img.shields.io/badge/infra-Docker%20Compose-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Architecture

```
┌─────────────┐     POST /api/scan      ┌──────────────────┐
│             │ ──────────────────────► │                  │
│   React     │                         │  Node.js + Express│
│  Frontend   │ ◄────────────────────── │  API Gateway     │
│  (Vite)     │     GET /api/scan/:id   │                  │
└─────────────┘                         └────────┬─────────┘
                                                  │ BullMQ
                                                  │ (Redis)
                                                  ▼
                                         ┌──────────────────┐
                                         │  BullMQ Worker   │
                                         │                  │
                                         └────────┬─────────┘
                                                  │ POST /analyze
                                                  ▼
                                         ┌──────────────────┐
                                         │  Python FastAPI  │
                                         │  ML Microservice │
                                         └──────────────────┘
                                                  │
                                                  ▼
                                         ┌──────────────────┐
                                         │    MongoDB       │
                                         │  (scan results)  │
                                         └──────────────────┘
```

## Features

- Detects **7 vulnerability classes**: SQL Injection, XSS, Hardcoded Secrets, Command Injection, Insecure Deserialization, Insecure Randomness, Path Traversal
- **Async job queue** via BullMQ — scan submission is non-blocking, frontend polls for results
- **Risk score** (0–100) calculated from severity-weighted findings
- Per-finding **fix suggestions** and flagged code snippets
- **Rate limited** API (20 req/min per IP)
- Fully containerised with Docker Compose — one command to run

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, Vite, Tailwind CSS |
| API Gateway | Node.js, Express, Mongoose |
| Job Queue | BullMQ, Redis |
| ML Service | Python, FastAPI, regex heuristics |
| Database | MongoDB |
| Infrastructure | Docker, Docker Compose |

## Getting Started

**Prerequisites:** Docker Desktop

```bash
git clone <repo-url>
cd scanner
docker compose up --build
```

| Service | URL |
|---|---|
| Frontend | http://localhost:5173 |
| Node API | http://localhost:4000 |
| Python ML | http://localhost:8000 |

## API Reference

### POST /api/scan
Submit a code snippet for analysis.

```json
// Request
{ "code": "SELECT * FROM users WHERE id = " + userId }

// Response 202
{ "scanId": "uuid-here", "status": "pending" }
```

### GET /api/scan/:id
Poll for scan results.

```json
{
  "scanId": "uuid",
  "status": "completed",
  "riskScore": 75,
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "severity": "High",
      "line": 3,
      "description": "...",
      "suggestedFix": "...",
      "snippet": "..."
    }
  ]
}
```

## Planned Enhancements

- Git repository URL scanning (clone + multi-file analysis)
- JWT authentication and per-user scan history
- CodeBERT-based semantic vulnerability detection
- Syntax-highlighted code editor (Monaco/CodeMirror)
- PDF / JSON report export
- Support for additional languages (Java, Go, Rust)
