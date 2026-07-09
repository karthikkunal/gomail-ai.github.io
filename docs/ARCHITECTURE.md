# GoMail AI Architecture

## MVP

- Frontend: Vite React SOC dashboard
- Backend: FastAPI analysis API
- Analysis: local deterministic pipeline
- Reports: generated Markdown/JSON

## Future production architecture

- Frontend: Next.js or React
- API: Go/Gin for core multi-tenant service
- AI engine: Python FastAPI workers
- Queue: Redis/RQ/Celery
- DB: PostgreSQL
- Storage: S3/R2
- Sandbox: Playwright in isolated Docker network
- OSINT: URLHaus, AbuseIPDB, OTX, ThreatFox, VirusTotal free tier, OpenPhish feeds
- Enterprise connectors: Defender, Splunk, Sentinel, CrowdStrike via customer-owned credentials
