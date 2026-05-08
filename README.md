# CVE Search Engine (API + Frontend)

## Run (single server)

1. `task server`
2. Open `http://localhost:8080`

The server exposes:

- `GET /api/health`
- `GET /api/search?q=<query>&top=<n>`
- `GET /api/baseline?q=<query>&top=<n>&order=published|cvss|none&field=description|product|all` (requires Postgres)

## Baseline DB (optional)

1. `task db-up`
2. `task db-load`

Then `/api/baseline` will be enabled.
