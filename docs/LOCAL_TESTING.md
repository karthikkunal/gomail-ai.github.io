# Local Testing Guide

1. Start backend: `cd backend && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt && uvicorn app.main:app --reload --port 8000`
2. Start frontend: `cd frontend && npm install && npm run dev`
3. Open `http://localhost:5173`
4. Upload `backend/samples/sample_phish.eml`
5. Review risk score, IOCs, MITRE mapping, OSINT pivots and report.

## Troubleshooting

- If upload fails, confirm backend is running: `curl http://localhost:8000/health`
- If frontend cannot call backend, check browser console and `VITE_API_BASE`.
- GitHub Pages cannot run backend. Use local/Docker or Render/Railway.
