# GoMail AI Full-Stack MVP

AI-assisted phishing/email investigation platform for local testing.

## What this MVP does

- Upload `.eml`, `.txt`, `.pdf`, `.docx`, `.png`, `.jpg`, `.jpeg`
- Extract text, URLs, domains, IPs, emails, hashes
- Parse email headers from `.eml`
- Basic SPF/DKIM/DMARC/header heuristic checks
- Image OCR placeholder + QR extraction fallback notes
- Local risk scoring and verdict: `benign`, `suspicious`, `malicious`
- SOC/SIEM-style dashboard frontend
- Investigation timeline, IOC table, MITRE mapping, recommendations
- Markdown/JSON report download
- Free OSINT pivot links for URLHaus, VirusTotal, AbuseIPDB, OTX, ThreatFox, crt.sh

## Important truth

This is a **safe local MVP**. It does not execute malware. It does not provide paid Defender/Splunk/CrowdStrike/XDR API access. Those integrations require customer-owned credentials later.

## Quick start

### 1) Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

API will run at:

```text
http://localhost:8000
```

### 2) Frontend

Open a new terminal:

```bash
cd frontend
npm install
npm run dev
```

Frontend will run at:

```text
http://localhost:5173
```

### 3) Test

Upload:

```text
backend/samples/sample_phish.eml
```

## Docker quick start

```bash
docker compose up --build
```

Frontend: `http://localhost:5173`  
Backend: `http://localhost:8000`

## GitHub push

```bash
git init
git branch -M main
git add .
git commit -m "Initial GoMail AI full-stack MVP"
git remote add origin https://github.com/YOUR_USERNAME/gomail-ai.git
git push -u origin main
```

## Suggested deployment

- GitHub Pages: use only for public website/docs.
- Render/Railway/Fly.io: host backend + frontend.
- Local Docker: best for sandbox/OCR/testing.
