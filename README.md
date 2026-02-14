# DevTerm Server

Server edition with background tasks, async processing, and WebSocket support.

## Installation

```bash
pip install devterm-server
```

## Usage

```bash
# Start the server
devterm-server
```

Then access http://localhost:8000

## Features

- **FastAPI** - Modern async web framework
- **Background Tasks** - Long-running tasks without blocking
- **Job Queue** - Track task status with job IDs
- **WebSocket** - Real-time communication at `/ws`
- **All API endpoints** from DevTerm API

## API Endpoints

- `POST /api/json/format` - Format JSON
- `POST /api/jobs/json-format` - Background JSON formatting
- `GET /api/jobs/{job_id}` - Get job status
- `WS /ws` - WebSocket endpoint
